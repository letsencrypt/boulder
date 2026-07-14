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
	"sync"
	"time"

	"github.com/jmhodges/clock"
	"github.com/prometheus/client_golang/prometheus"
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

// SourceConfig locates and authenticates the source log the publisher
// mirrors. The log's tilestore backend is passed to New separately.
type SourceConfig struct {
	// Origin is the source log's checkpoint origin.
	Origin string
	// VerifierKey is a c2sp.org/signed-note verifier key for the source log's
	// checkpoint signature.
	VerifierKey string
}

// MirrorConfig configures one tlog-mirror the publisher submits to.
type MirrorConfig struct {
	// ID is the mirror's OID relative to 1.3.6.1.4.1. It is recorded in the
	// checkpoints table when this mirror's cosignature completes the quorum.
	ID string
	// BaseURL is the mirror's tlog-mirror submission base URL, e.g.
	// "http://127.0.0.1:4700".
	BaseURL string
	// Name is the mirror cosigner's key name, used to verify its cosignatures.
	Name string
	// VerifierKey is the base64 of the mirror's 1312-byte ML-DSA-44 public key.
	// There is no tlog-mirror endpoint to fetch a cosigner's key, so it is
	// configured out of band.
	VerifierKey string
	// Tier1 mirrors count toward the cosignature quorum. A tier-2 mirror is
	// kept up to date and monitored, but issuance never waits for it, which
	// suits a mirror warming up from nothing or one that is chronically slow.
	Tier1 bool
}

// mirrorState is one mirror's runtime state. The mutable fields are touched
// only by the mirror's own goroutine.
type mirrorState struct {
	cfg      MirrorConfig
	verifier *cosignature.MLDSACosignatureVerifier

	// committedSize is the largest checkpoint size the mirror is known to
	// have committed, and cosig is its cosignature over that checkpoint. Both
	// start empty on every publisher start: a mirror re-issues a cosignature
	// for a tree it already holds, so the state rebuilds in one pass.
	committedSize int64
	cosig         []byte
}

// MTPublisher keeps every configured mirror caught up with the MTC issuance
// log and records one mirror cosignature on each checkpoint once a quorum of
// tier-1 mirrors has committed it. The MTCA waits for that recorded
// cosignature before sequencing the next batch, so the quorum decides how
// many mirrors hold a tree before certificates referencing it circulate.
type MTPublisher struct {
	db           *db.WrappedMap
	interval     time.Duration
	mtcLogID     string
	srcOrigin    string
	srcStore     *tilestore.Store
	srcVerifiers note.Verifiers
	mirrors      []*mirrorState
	quorum       int
	uploadBodies *bodyMemo
	httpClient   *http.Client
	clk          clock.Clock
	log          blog.Logger

	// quorumCommitted holds the tier-1 mirror IDs that have committed the
	// checkpoint row quorumCheckpoint. It is in-memory only: after a restart
	// every mirror loop re-reports within one pass and the set re-forms.
	quorumMu         sync.Mutex
	quorumCheckpoint int64
	quorumCommitted  map[string]bool

	committedSize  *prometheus.GaugeVec
	sizeLag        *prometheus.GaugeVec
	lastCommit     *prometheus.GaugeVec
	tier1Committed prometheus.Gauge
	passErrors     *prometheus.CounterVec
}

// New returns a new *MTPublisher. srcBackend is the tilestore backend holding
// the source log named by source.Origin (an fs backend in tests, an S3 backend
// pointed at MinIO in deployment). quorum is how many tier-1 mirrors must
// commit a checkpoint before its cosignature is recorded, from 1 to the number
// of tier-1 mirrors.
func New(dbMap *db.WrappedMap, interval time.Duration, mtcLogID string, source SourceConfig, mirrors []MirrorConfig, quorum int, srcBackend tilestore.Backend, stats prometheus.Registerer, clk clock.Clock, log blog.Logger) (*MTPublisher, error) {
	if interval <= 0 {
		return nil, fmt.Errorf("interval must be positive, got %s", interval)
	}
	if mtcLogID == "" {
		return nil, errors.New("mtcLogID must not be empty")
	}
	if source.Origin == "" || source.VerifierKey == "" {
		return nil, errors.New("all source config fields must be set")
	}
	if srcBackend == nil {
		return nil, errors.New("source backend must not be nil")
	}
	srcVerifier, err := note.NewVerifier(source.VerifierKey)
	if err != nil {
		return nil, fmt.Errorf("parsing source log verifier key: %w", err)
	}

	if len(mirrors) == 0 {
		return nil, errors.New("at least one mirror must be configured")
	}
	states := make([]*mirrorState, 0, len(mirrors))
	seen := make(map[string]bool)
	tier1 := 0
	for _, mc := range mirrors {
		if mc.ID == "" || mc.BaseURL == "" || mc.Name == "" || mc.VerifierKey == "" {
			return nil, fmt.Errorf("all config fields for mirror %q must be set", mc.ID)
		}
		if seen[mc.ID] {
			return nil, fmt.Errorf("duplicate mirror ID %q", mc.ID)
		}
		seen[mc.ID] = true
		if mc.Tier1 {
			tier1++
		}
		pubBytes, err := base64.StdEncoding.DecodeString(mc.VerifierKey)
		if err != nil {
			return nil, fmt.Errorf("decoding verifier key for mirror %q: %w", mc.ID, err)
		}
		pub, err := mldsa.NewPublicKey(mldsa.MLDSA44(), pubBytes)
		if err != nil {
			return nil, fmt.Errorf("parsing verifier key for mirror %q: %w", mc.ID, err)
		}
		verifier, err := cosignature.NewMLDSACosignatureVerifier(mc.Name, pub)
		if err != nil {
			return nil, fmt.Errorf("building verifier for mirror %q: %w", mc.ID, err)
		}
		states = append(states, &mirrorState{cfg: mc, verifier: verifier})
	}
	if quorum < 1 || quorum > tier1 {
		return nil, fmt.Errorf("quorum %d must be from 1 to the number of tier-1 mirrors (%d)", quorum, tier1)
	}

	committedSize := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mtpublisher_mirror_committed_tree_size",
		Help: "Largest source checkpoint tree size each mirror has committed.",
	}, []string{"mirror"})
	sizeLag := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mtpublisher_mirror_size_lag",
		Help: "Entries between the latest checkpoint and each mirror's committed tree.",
	}, []string{"mirror"})
	lastCommit := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "mtpublisher_mirror_last_commit_timestamp_seconds",
		Help: "Unix time of each mirror's most recent commit.",
	}, []string{"mirror"})
	tier1Committed := prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mtpublisher_tier1_committed",
		Help: "Tier-1 mirrors that have committed the current checkpoint. Alert when this cannot reach the configured quorum.",
	})
	passErrors := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "mtpublisher_mirror_pass_errors",
		Help: "Failed cosigning passes per mirror.",
	}, []string{"mirror"})
	stats.MustRegister(committedSize, sizeLag, lastCommit, tier1Committed, passErrors)

	return &MTPublisher{
		db:             dbMap,
		interval:       interval,
		mtcLogID:       mtcLogID,
		srcOrigin:      source.Origin,
		srcStore:       tilestore.New(srcBackend, source.Origin),
		srcVerifiers:   note.VerifierList(srcVerifier),
		mirrors:        states,
		quorum:         quorum,
		uploadBodies:   &bodyMemo{},
		httpClient:     &http.Client{Timeout: 30 * time.Second},
		clk:            clk,
		log:            log,
		committedSize:  committedSize,
		sizeLag:        sizeLag,
		lastCommit:     lastCommit,
		tier1Committed: tier1Committed,
		passErrors:     passErrors,
	}, nil
}

type checkpointEntry struct {
	ID              int64  `db:"id"`
	MTCLogID        string `db:"mtcLogID"`
	TreeSize        int64  `db:"treeSize"`
	RootHash        []byte `db:"rootHash"`
	MirrorSignature []byte `db:"mirrorSignature"`
}

// publishMirror runs one pass for one mirror: it brings the mirror up to the
// latest MTCA-signed checkpoint when it is behind, refreshes the mirror's
// metrics, and reports the commit toward the quorum.
func (p *MTPublisher) publishMirror(ctx context.Context, m *mirrorState) error {
	var latest checkpointEntry
	err := p.db.SelectOne(ctx, &latest,
		"SELECT id, mtcLogID, treeSize, rootHash, mirrorSignature FROM checkpoints WHERE mtcLogID = ? AND mtcaSignature IS NOT NULL ORDER BY treeSize DESC LIMIT 1",
		p.mtcLogID)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("selecting the latest checkpoint: %w", err)
	}
	p.noteCheckpoint(&latest)

	if m.committedSize < latest.TreeSize {
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
		cosig, err := mirrorLog(ctx, p.httpClient, m.cfg.BaseURL, p.srcOrigin, p.srcStore, p.srcVerifiers, m.verifier, p.uploadBodies)
		if err != nil {
			return fmt.Errorf("obtaining cosignature from mirror %s for checkpoint %d (%s size %d): %w",
				m.cfg.ID, latest.ID, latest.MTCLogID, latest.TreeSize, err)
		}
		m.committedSize = latest.TreeSize
		m.cosig = cosig
		p.lastCommit.WithLabelValues(m.cfg.ID).Set(float64(p.clk.Now().Unix()))
	}
	p.committedSize.WithLabelValues(m.cfg.ID).Set(float64(m.committedSize))
	p.sizeLag.WithLabelValues(m.cfg.ID).Set(float64(latest.TreeSize - m.committedSize))

	return p.record(ctx, &latest, m)
}

// noteCheckpoint resets the quorum bookkeeping when latest is a checkpoint we
// have not tracked yet, so the tier-1 gauge falls to zero as soon as any
// mirror pass observes a new checkpoint. Checkpoint ids are auto-increment,
// so a smaller id is a stale read by a slower goroutine, never a new
// checkpoint, and the reset is forward-only.
func (p *MTPublisher) noteCheckpoint(latest *checkpointEntry) {
	p.quorumMu.Lock()
	defer p.quorumMu.Unlock()
	if latest.ID > p.quorumCheckpoint {
		p.quorumCheckpoint = latest.ID
		p.quorumCommitted = make(map[string]bool)
		p.tier1Committed.Set(0)
	}
}

// record counts m's commit toward the quorum on latest and writes the
// checkpoint's one stored cosignature when the quorum is reached. A commit
// only counts when latest is the checkpoint the bookkeeping currently tracks,
// so a slow goroutine holding a stale row cannot inflate a newer quorum. The
// write is guarded on mirrorSignature IS NULL, so a replay after a restart or
// a race between mirror goroutines is a no-op.
func (p *MTPublisher) record(ctx context.Context, latest *checkpointEntry, m *mirrorState) error {
	if !m.cfg.Tier1 || m.committedSize != latest.TreeSize {
		return nil
	}
	p.quorumMu.Lock()
	if p.quorumCheckpoint != latest.ID {
		p.quorumMu.Unlock()
		return nil
	}
	p.quorumCommitted[m.cfg.ID] = true
	committed := len(p.quorumCommitted)
	p.quorumMu.Unlock()
	p.tier1Committed.Set(float64(committed))
	if latest.MirrorSignature != nil || committed < p.quorum {
		return nil
	}

	res, err := p.db.ExecContext(ctx,
		"UPDATE checkpoints SET mirrorID = ?, mirrorSignature = ? WHERE id = ? AND mtcLogID = ? AND mirrorSignature IS NULL",
		m.cfg.ID, m.cosig, latest.ID, p.mtcLogID)
	if err != nil {
		return fmt.Errorf("recording cosignature on checkpoint %d (%s size %d): %w", latest.ID, latest.MTCLogID, latest.TreeSize, err)
	}
	rows, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("recording cosignature on checkpoint %d: %w", latest.ID, err)
	}
	if rows == 1 {
		p.log.Infof("Recorded mirror %s cosignature on checkpoint %d (%s size %d) after %d tier-1 commits (quorum %d)",
			m.cfg.ID, latest.ID, latest.MTCLogID, latest.TreeSize, committed, p.quorum)
	}
	return nil
}

// publish runs one pass for every mirror, sequentially. Tests drive it
// directly. Start runs the same passes concurrently.
func (p *MTPublisher) publish(ctx context.Context) error {
	var errs []error
	for _, m := range p.mirrors {
		err := p.publishMirror(ctx, m)
		if err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// Start runs one polling loop per mirror until ctx is cancelled.
func (p *MTPublisher) Start(ctx context.Context) {
	var wg sync.WaitGroup
	for _, m := range p.mirrors {
		wg.Go(func() {
			p.mirrorLoop(ctx, m)
		})
	}
	wg.Wait()
}

func (p *MTPublisher) mirrorLoop(ctx context.Context, m *mirrorState) {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		err := p.publishMirror(ctx, m)
		if err != nil {
			p.passErrors.WithLabelValues(m.cfg.ID).Inc()
			p.log.Errf("Cosigning pass for mirror %s failed: %s", m.cfg.ID, err)
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

// maxUploadPackages caps the entry packages in one add-entries request,
// bounding request size and memory when a mirror is far behind, such as one
// warming up from nothing. The mirror commits each request's packages and
// returns its next entry, and the upload loop resumes from there.
const maxUploadPackages = 16

// bodyMemo is a one-slot cache of the most recently built ticketless
// add-entries body, shared by every mirror goroutine. In steady state all
// mirrors upload the identical interval, so the first arrival builds the body
// (the bundle reads, the proofs, the marshaling) and the rest reuse it.
//
// One slot keyed (start, end) with no invalidation is safe because the log is
// append-only and its size strictly increases: an interval names one immutable
// body forever, so a stale slot can only miss, never serve wrong bytes. Two
// goroutines missing at once both build and one write wins. The cached slice is
// shared, so callers must not modify it. Ticketed follow-ups are specific to
// one mirror's resumption state and bypass the memo.
type bodyMemo struct {
	mu    sync.Mutex
	start int64
	end   int64
	body  []byte
}

// get returns the body for [start, end), calling build on a miss and keeping
// the result for the next caller.
func (c *bodyMemo) get(start, end int64, build func() ([]byte, error)) ([]byte, error) {
	c.mu.Lock()
	if c.body != nil && c.start == start && c.end == end {
		body := c.body
		c.mu.Unlock()
		return body, nil
	}
	c.mu.Unlock()

	body, err := build()
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.start = start
	c.end = end
	c.body = body
	c.mu.Unlock()
	return body, nil
}

// mirrorLog runs the tlog-mirror submission flow for the source log src against
// the mirror at baseURL: it verifies the source checkpoint with srcVerifiers,
// negotiates add-checkpoint, uploads entries until the mirror catches up to the
// checkpoint, validates the returned cosignature with verifier, and returns the
// validated timestamped_signature to persist. memo dedups ticketless request
// bodies with any concurrent uploads to other mirrors.
func mirrorLog(ctx context.Context, client *http.Client, baseURL, origin string, src *tilestore.Store, srcVerifiers note.Verifiers, verifier *cosignature.MLDSACosignatureVerifier, memo *bodyMemo) ([]byte, error) {
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

	// add-entries: upload from the mirror's current size to our checkpoint
	// size, at most maxUploadPackages per request, resuming from the
	// advertised next entry and echoing the mirror's resumption ticket.
	uploadStart := oldSize
	var ticket []byte
	for {
		build := func() ([]byte, error) {
			return buildAddEntries(ctx, src, origin, uploadStart, tree.N, ticket, reader)
		}
		var body []byte
		if len(ticket) == 0 {
			body, err = memo.get(uploadStart, tree.N, build)
		} else {
			// A ticketed follow-up is specific to this mirror's resumption
			// state, so it bypasses the memo.
			body, err = build()
		}
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
			ticket = info.Ticket
		default:
			return nil, fmt.Errorf("add-entries: unexpected status %d", status)
		}
	}
}

// buildAddEntries assembles an add-entries body for [uploadStart, uploadEnd)
// carrying at most maxUploadPackages of the canonical packages, a legal prefix
// of the sequence. Each package's entries are read from src and its subtree
// consistency proof from reader. ticket is the resumption ticket from the
// mirror's last mirror-info response, empty on the first request.
func buildAddEntries(ctx context.Context, src *tilestore.Store, origin string, uploadStart, uploadEnd int64, ticket []byte, reader tlog.HashReader) ([]byte, error) {
	var packages []mirror.EntryPackage
	// EntryPackageAt walks the canonical sequence by index. Materializing the
	// whole sequence with EntryPackages would allocate one Package per 256
	// remaining entries just to use the first maxUploadPackages of them.
	for i := int64(0); i < maxUploadPackages; i++ {
		pkg, ok := mirror.EntryPackageAt(uploadStart, uploadEnd, i)
		if !ok {
			break
		}
		entries, err := src.ReadEntries(ctx, pkg.EntriesStart, pkg.End, uploadEnd)
		if err != nil {
			return nil, err
		}
		proof, err := subtree.ConsistencyProof(pkg.SubtreeStart, pkg.End, uploadEnd, reader)
		if err != nil {
			return nil, fmt.Errorf("subtree proof [%d,%d): %w", pkg.SubtreeStart, pkg.End, err)
		}
		packages = append(packages, mirror.EntryPackage{Entries: entries, Proof: proof})
	}
	body, err := mirror.AddEntriesRequest{
		Origin:      origin,
		UploadStart: uploadStart,
		UploadEnd:   uploadEnd,
		Ticket:      ticket,
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
