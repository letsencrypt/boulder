//go:build go1.27

package mtpublisher

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/jmhodges/clock"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/db"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/trees/checkpoint"
	"github.com/letsencrypt/boulder/trees/cosignature"
	"github.com/letsencrypt/boulder/trees/mirror"
	"github.com/letsencrypt/boulder/trees/subtree"
	"github.com/letsencrypt/boulder/trees/tilestore"
)

// MirrorConfig configures the mirror the publisher submits to and the source
// log it mirrors to obtain the mirror's cosignature. The source log's tilestore
// backend is passed to New separately.
type MirrorConfig struct {
	// BaseURL is the mirror's tlog-mirror submission base URL, e.g.
	// "http://127.0.0.1:4700".
	BaseURL string
	// Name is the mirror cosigner's key name, used to verify its cosignatures.
	Name string
	// VerifierKey is the base64 of the mirror's 1312-byte ML-DSA-44 public key.
	// There is no tlog-mirror endpoint to fetch a cosigner's key, so it is
	// configured out of band.
	VerifierKey string
	// SourceOrigin is the origin of the source log.
	SourceOrigin string
	// SourceVerifierKey is a c2sp.org/signed-note verifier key for the source
	// log's checkpoint signature.
	SourceVerifierKey string
}

// MTPublisher mirrors the MTC issuance log to a tlog-mirror and records the
// mirror's validated cosignature on each checkpoint that lacks one.
type MTPublisher struct {
	db           *db.WrappedMap
	interval     time.Duration
	mtcLogID     string
	mirrorID     string
	mirrorURL    string
	srcOrigin    string
	srcStore     *tilestore.Store
	srcVerifiers note.Verifiers
	verifier     *cosignature.MLDSACosignatureVerifier
	httpClient   *http.Client
	clk          clock.Clock
	log          blog.Logger
}

// New returns a new *MTPublisher. srcBackend is the tilestore backend holding
// the source log named by mc.SourceOrigin (an fs backend in tests, an S3
// backend pointed at MinIO in deployment).
func New(dbMap *db.WrappedMap, interval time.Duration, mtcLogID, mirrorID string, mc MirrorConfig, srcBackend tilestore.Backend, clk clock.Clock, log blog.Logger) (*MTPublisher, error) {
	if interval <= 0 {
		return nil, fmt.Errorf("interval must be positive, got %s", interval)
	}
	if mtcLogID == "" {
		return nil, errors.New("mtcLogID must not be empty")
	}
	if mirrorID == "" {
		return nil, errors.New("mirrorID must not be empty")
	}
	if mc.BaseURL == "" || mc.Name == "" || mc.VerifierKey == "" || mc.SourceOrigin == "" || mc.SourceVerifierKey == "" {
		return nil, errors.New("all mirror config fields must be set")
	}
	if srcBackend == nil {
		return nil, errors.New("source backend must not be nil")
	}
	pubBytes, err := base64.StdEncoding.DecodeString(mc.VerifierKey)
	if err != nil {
		return nil, fmt.Errorf("decoding mirror verifier key: %w", err)
	}
	pub, err := mldsa.NewPublicKey(mldsa.MLDSA44(), pubBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing mirror verifier key: %w", err)
	}
	verifier, err := cosignature.NewMLDSACosignatureVerifier(mc.Name, pub)
	if err != nil {
		return nil, fmt.Errorf("building mirror verifier: %w", err)
	}
	srcVerifier, err := note.NewVerifier(mc.SourceVerifierKey)
	if err != nil {
		return nil, fmt.Errorf("parsing source log verifier key: %w", err)
	}
	return &MTPublisher{
		db:           dbMap,
		interval:     interval,
		mtcLogID:     mtcLogID,
		mirrorID:     mirrorID,
		mirrorURL:    mc.BaseURL,
		srcOrigin:    mc.SourceOrigin,
		srcStore:     tilestore.New(srcBackend, mc.SourceOrigin),
		srcVerifiers: note.VerifierList(srcVerifier),
		verifier:     verifier,
		httpClient:   &http.Client{Timeout: 30 * time.Second},
		clk:          clk,
		log:          log,
	}, nil
}

type checkpointEntry struct {
	ID              int64  `db:"id"`
	MTCLogID        string `db:"mtcLogID"`
	TreeSize        int64  `db:"treeSize"`
	RootHash        []byte `db:"rootHash"`
	MirrorSignature []byte `db:"mirrorSignature"`
}

func (p *MTPublisher) publish(ctx context.Context) error {
	var latest checkpointEntry
	err := p.db.SelectOne(ctx, &latest,
		"SELECT id, mtcLogID, treeSize, rootHash, mirrorSignature FROM checkpoints WHERE mtcLogID = ? ORDER BY treeSize DESC LIMIT 1",
		p.mtcLogID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("selecting the latest checkpoint: %w", err)
	}
	if latest.MirrorSignature != nil {
		return nil
	}

	// The source log we mirror must be the tree this checkpoint describes;
	// otherwise we would record a cosignature over a different tree.
	tree, err := p.srcStore.Tree(ctx)
	if err != nil {
		return fmt.Errorf("reading source tree: %w", err)
	}
	if tree.N != latest.TreeSize || !bytes.Equal(tree.Hash[:], latest.RootHash) {
		return fmt.Errorf("source log (size %d) does not match checkpoint %d (size %d): refusing to cosign a different tree",
			tree.N, latest.ID, latest.TreeSize)
	}

	// Mirror the source log to the mirror and validate the cosignature it
	// returns before persisting it.
	cosig, err := mirrorLog(ctx, p.httpClient, p.mirrorURL, p.srcOrigin, p.srcStore, p.srcVerifiers, p.verifier)
	if err != nil {
		return fmt.Errorf("obtaining cosignature for checkpoint %d (%s size %d): %w", latest.ID, latest.MTCLogID, latest.TreeSize, err)
	}

	_, err = p.db.ExecContext(ctx,
		"UPDATE checkpoints SET mirrorID = ?, mirrorSignature = ? WHERE id = ? AND mtcLogID = ?",
		p.mirrorID, cosig, latest.ID, p.mtcLogID)
	if err != nil {
		return fmt.Errorf("recording cosignature on checkpoint %d (%s size %d): %w", latest.ID, latest.MTCLogID, latest.TreeSize, err)
	}
	p.log.Infof("Recorded mirror cosignature on checkpoint %d (%s size %d)", latest.ID, latest.MTCLogID, latest.TreeSize)
	return nil
}

// Start attempts to cosign the latest checkpoint at each interval until ctx is
// cancelled.
func (p *MTPublisher) Start(ctx context.Context) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		err := p.publish(ctx)
		if err != nil {
			p.log.Errf("Cosigning pass failed: %s", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// maxResponse bounds a mirror response body; mirror responses are tiny.
const maxResponse = 1 << 20

// mirrorLog runs the tlog-mirror submission flow for the source log src against
// the mirror at baseURL: it verifies the source checkpoint with srcVerifiers,
// negotiates add-checkpoint, uploads entries until the mirror catches up to the
// checkpoint, validates the returned cosignature with verifier, and returns the
// validated timestamped_signature to persist.
func mirrorLog(ctx context.Context, client *http.Client, baseURL, origin string, src *tilestore.Store, srcVerifiers note.Verifiers, verifier *cosignature.MLDSACosignatureVerifier) ([]byte, error) {
	signed, err := src.ReadCheckpoint(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading source checkpoint: %w", err)
	}
	if signed == nil {
		return nil, errors.New("source log has no checkpoint to mirror")
	}
	// Refuse to mirror a checkpoint that does not verify or does not describe
	// the tree we would upload from. Without this a stale bucket checkpoint,
	// such as one behind entries the log has written but not yet checkpointed,
	// surfaces as a confusing conflict loop at the mirror instead of an error
	// here.
	cp, _, err := checkpoint.Open(signed, srcVerifiers)
	if err != nil {
		return nil, fmt.Errorf("verifying source checkpoint: %w", err)
	}
	if cp.Origin != origin {
		return nil, fmt.Errorf("source checkpoint origin %q, want %q", cp.Origin, origin)
	}
	tree, err := src.Tree(ctx)
	if err != nil {
		return nil, fmt.Errorf("reading source tree: %w", err)
	}
	if cp.Tree != tree {
		return nil, fmt.Errorf("source checkpoint (size %d) does not match the source tree (size %d)", cp.Tree.N, tree.N)
	}
	reader := src.HashReader(ctx, tree)

	// add-checkpoint: register the checkpoint, discovering the mirror's current
	// size from a size conflict if our guess is wrong.
	oldSize := int64(0)
	for {
		var proof []tlog.Hash
		if oldSize > 0 {
			proof, err = tlog.ProveTree(tree.N, oldSize, reader)
			if err != nil {
				return nil, fmt.Errorf("consistency proof %d->%d: %w", oldSize, tree.N, err)
			}
		}
		body, err := mirror.AddCheckpointRequest{OldSize: oldSize, Proof: proof, Checkpoint: signed}.Marshal()
		if err != nil {
			return nil, fmt.Errorf("marshaling add-checkpoint: %w", err)
		}
		status, respBody, err := post(ctx, client, baseURL+"/add-checkpoint", body)
		if err != nil {
			return nil, err
		}
		if status == http.StatusOK {
			break
		}
		if status != http.StatusConflict {
			return nil, fmt.Errorf("add-checkpoint: unexpected status %d", status)
		}
		size, err := mirror.ParseSize(respBody)
		if err != nil {
			return nil, fmt.Errorf("parsing size conflict: %w", err)
		}
		if size <= oldSize {
			return nil, fmt.Errorf("mirror reported non-advancing size %d at old size %d", size, oldSize)
		}
		oldSize = size
	}

	// add-entries: upload from the mirror's current size to our checkpoint size,
	// resuming from the advertised next entry on a partial accept.
	uploadStart := oldSize
	for {
		body, err := buildAddEntries(ctx, src, origin, uploadStart, tree.N, reader)
		if err != nil {
			return nil, err
		}
		status, respBody, err := post(ctx, client, baseURL+"/add-entries", body)
		if err != nil {
			return nil, err
		}
		switch status {
		case http.StatusOK:
			return validateCosignature(signed, respBody, verifier)
		case http.StatusAccepted:
			info, err := mirror.ParseMirrorInfo(respBody)
			if err != nil {
				return nil, fmt.Errorf("parsing mirror-info: %w", err)
			}
			if info.NextEntry <= uploadStart {
				return nil, fmt.Errorf("mirror did not advance past %d", uploadStart)
			}
			uploadStart = info.NextEntry
		default:
			return nil, fmt.Errorf("add-entries: unexpected status %d", status)
		}
	}
}

// buildAddEntries assembles the add-entries body for [uploadStart, uploadEnd),
// reading each canonical package's entries from src and its subtree consistency
// proof from reader.
func buildAddEntries(ctx context.Context, src *tilestore.Store, origin string, uploadStart, uploadEnd int64, reader tlog.HashReader) ([]byte, error) {
	var packages []mirror.EntryPackage
	for _, p := range mirror.EntryPackages(uploadStart, uploadEnd) {
		entries, err := src.ReadEntries(ctx, p.EntriesStart, p.End, uploadEnd)
		if err != nil {
			return nil, err
		}
		proof, err := subtree.ConsistencyProof(p.SubtreeStart, p.End, uploadEnd, reader)
		if err != nil {
			return nil, fmt.Errorf("subtree proof [%d,%d): %w", p.SubtreeStart, p.End, err)
		}
		packages = append(packages, mirror.EntryPackage{Entries: entries, Proof: proof})
	}
	body, err := mirror.AddEntriesRequest{
		Origin:      origin,
		UploadStart: uploadStart,
		UploadEnd:   uploadEnd,
		Packages:    packages,
	}.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshaling add-entries: %w", err)
	}
	return body, nil
}

// validateCosignature checks the mirror's cosignature line against verifier by
// opening the cosigned checkpoint note, and returns the timestamped_signature.
// note.Open performs the ML-DSA verification; a forged or wrong cosignature
// makes it fail here rather than being persisted.
func validateCosignature(signed, line []byte, verifier *cosignature.MLDSACosignatureVerifier) ([]byte, error) {
	cosigned := append(bytes.Clone(signed), line...)
	n, err := note.Open(cosigned, note.VerifierList(verifier))
	if err != nil {
		return nil, fmt.Errorf("validating mirror cosignature: %w", err)
	}
	sig, ok := cosignature.Cosignature(n, verifier)
	if !ok {
		return nil, errors.New("mirror cosignature not present after validation")
	}
	return sig, nil
}

func post(ctx context.Context, client *http.Client, url string, body []byte) (int, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/octet-stream")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("posting to %s: %w", url, err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse))
	if err != nil {
		return 0, nil, fmt.Errorf("reading response from %s: %w", url, err)
	}
	return resp.StatusCode, got, nil
}
