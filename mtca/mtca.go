//go:build go1.27

package mtca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/mldsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"path"
	"sync"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jmhodges/clock"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/borp"
	"github.com/letsencrypt/boulder/db"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
	mtcapb "github.com/letsencrypt/boulder/mtca/proto"
	"github.com/letsencrypt/boulder/trees/checkpoint"
	"github.com/letsencrypt/boulder/trees/cosignature"
	"github.com/letsencrypt/boulder/trees/entry"
	"github.com/letsencrypt/boulder/trees/issuancelog"
	"github.com/letsencrypt/boulder/trees/pubkey"
	"github.com/letsencrypt/boulder/trees/tiles"
	"github.com/letsencrypt/boulder/trees/treedb"
)

var ErrIssuanceLogAlreadyInitialized = errors.New("issuance log already initialized")
var ErrCheckpointNotReady = errors.New("not ready - no mirror signature")
var ErrCheckpointChanged = errors.New("served checkpoint is not the one this MTCA last wrote")

var _ mtcapb.MTCAServer = &mtca{}

// New creates a new MTCA service.
func New(
	issuer *issuance.Issuer,
	profiles map[string]*issuance.Profile,
	logID issuancelog.ID,
	sequencingPeriod time.Duration,
	dbMap *borp.DbMap,
	s3c simpleS3,
	logger blog.Logger,
	clk clock.Clock,
) (*mtca, error) {
	certCAID, err := getCAID(issuer.Cert.Certificate)
	if err != nil {
		return nil, err
	}
	if certCAID != logID.CAID {
		return nil, fmt.Errorf("configured CA ID %q does not match issuer certificate CA ID %q", logID.CAID, certCAID)
	}

	if sequencingPeriod == 0 {
		return nil, errors.New("sequencingPeriod must be non-zero")
	}

	m := &mtca{
		issuer:        issuer,
		profiles:      profiles,
		logID:         logID,
		pool:          &pool{maxSize: 100},
		checkpointKey: path.Join(logID.TilePrefix(), "checkpoint"),

		sequencingPeriod: sequencingPeriod,

		db:  initDB(dbMap),
		s3c: s3c,
		log: logger,
		clk: clk,
	}

	cosigner, err := cosignature.NewCosigner(logID.CAID, logID.Origin(), issuer.Signer)
	if err != nil {
		return nil, fmt.Errorf("creating CA cosigner: %s", err)
	}
	m.cosigner = cosigner

	pubKey, ok := issuer.Signer.Public().(*mldsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("issuer public key is %T, must be ML-DSA-44", issuer.Signer.Public())
	}
	verifier, err := cosignature.NewVerifier(logID.CAID, pubKey)
	if err != nil {
		return nil, fmt.Errorf("creating CA verifier: %s", err)
	}
	m.verifier = verifier

	return m, nil
}

type mtca struct {
	mtcapb.UnimplementedMTCAServer

	issuer   *issuance.Issuer
	profiles map[string]*issuance.Profile
	logID    issuancelog.ID
	// checkpointKey is the key of the log's <prefix>/checkpoint in tile
	// storage, per c2sp.org/tlog-tiles.
	checkpointKey string
	cosigner      *cosignature.Cosigner
	verifier      *cosignature.Verifier

	// servedCheckpointETag guards writes of the checkpoint served from tile
	// storage. It holds the ETag from the last read or write. It is used to
	// ensure that writeCheckpoint replaces only the checkpoint this MTCA last
	// saw. It is empty until the first serve, which adopts the ETag of an
	// earlier checkpoint of ours if one is served.
	servedCheckpointETag string

	pool *pool

	// frontier contains all the tiles on the right edge of the tree.
	// It will be used to accumulate entries for writing to storage.
	// Not safe for concurrent reading and writing.
	frontier *tiles.Frontier

	sequencingPeriod time.Duration

	// TODO: factor our sa.InitWrappedDb() so we get metrics and other goodies.
	// TODO: decide whether we want to route this through the SA or an SA-like object,
	// or keep a direct DB connection from the MTCA.
	db  *db.WrappedMap
	s3c simpleS3
	log blog.Logger
	clk clock.Clock
}

// simpleS3 matches the subset of the s3.Client interface which we use, to allow
// simpler mocking in tests.
type simpleS3 interface {
	PutObject(ctx context.Context, params *s3.PutObjectInput, optFns ...func(*s3.Options)) (*s3.PutObjectOutput, error)
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	Bucket() string
}

func getCAID(issuerCert *x509.Certificate) (string, error) {
	testingTrustAnchorIDOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 1}
	for _, attribute := range issuerCert.Subject.Names {
		if attribute.Type.Equal(testingTrustAnchorIDOID) {
			caID, ok := attribute.Value.(string)
			if !ok {
				return "", fmt.Errorf("invalid trust anchor attribute type %T", attribute.Value)
			}
			return caID, nil
		}
	}

	return "", fmt.Errorf("issuer subject %q did not contain trust anchor ID OID %q",
		issuerCert.Subject, testingTrustAnchorIDOID)
}

func initDB(dbMap *borp.DbMap) *db.WrappedMap {
	dbMap.AddTableWithName(treedb.CheckpointModel{}, "checkpoints").SetKeys(true, "ID")
	return db.NewWrappedMap(dbMap)
}

// InitLog creates the database metadata for a new, empty log: one checkpoint and the row
// in `latestCheckpoint` that refers to it. Should only be run once in a log's lifetime.
func (m *mtca) InitLog(ctx context.Context) error {
	candidate := &tiles.Frontier{}

	err := candidate.AppendEntry(&entry.MTCLogEntry{}, &pubkey.MTCPublicKey{})
	if err != nil {
		return err
	}

	rootHash := candidate.RootHash()

	var caSig []byte
	var signedNote []byte
	_, err = db.WithTransaction(ctx, m.db, func(tx db.Executor) (any, error) {
		var numLatestCheckpoints int64
		err := tx.SelectOne(ctx, &numLatestCheckpoints, "SELECT COUNT(*) FROM latestCheckpoint WHERE mtcLogID = ?",
			m.logID.String())
		if err != nil {
			return nil, fmt.Errorf("getting latestCheckpoint: %s", err)
		}

		var numCheckpoints int64
		err = tx.SelectOne(ctx, &numCheckpoints, "SELECT COUNT(*) FROM checkpoints WHERE mtcLogID = ?",
			m.logID.String())
		if err != nil {
			return nil, fmt.Errorf("getting checkpoints: %s", err)
		}

		if numCheckpoints > 0 || numLatestCheckpoints > 0 {
			if numLatestCheckpoints == 1 {
				return nil, ErrIssuanceLogAlreadyInitialized
			}

			return nil, fmt.Errorf("initializing issuance log for %s: already has %d checkpoints and %d latestCheckpoint rows",
				m.logID.String(), numCheckpoints, numLatestCheckpoints)
		}

		firstCheckpoint := &treedb.CheckpointModel{
			MTCLogID: m.logID.String(),
			TreeSize: candidate.TreeSize(),
			RootHash: rootHash[:],
		}

		caSig, signedNote, err = m.signCheckpoint(firstCheckpoint)
		if err != nil {
			return nil, err
		}

		firstCheckpoint.MTCASignature = caSig

		err = tx.Insert(ctx, firstCheckpoint)
		if err != nil {
			return nil, err
		}

		_, err = tx.ExecContext(ctx, "INSERT INTO latestCheckpoint (id, mtcLogID) VALUES (?, ?)",
			firstCheckpoint.ID, m.logID.String())
		if err != nil {
			return nil, fmt.Errorf("inserting latestCheckpoint: %s", err)
		}

		return nil, nil
	})
	if err != nil {
		if errors.Is(err, ErrIssuanceLogAlreadyInitialized) {
			// The DB thinks the log is initialized; make sure the tiles are there.
			err2 := m.Preflight(ctx)
			if err2 != nil {
				return fmt.Errorf("DB is initialized but Preflight returns: %s", err2)
			}
			return err
		}
		return err
	}

	err = candidate.Publish(ctx, m.s3c, m.logID.TilePrefix())
	if err != nil {
		return err
	}

	m.frontier = candidate

	_, err = treedb.New(m.db).LatestCheckpoint(ctx, m.logID.String())
	if err != nil {
		return fmt.Errorf("fetching first checkpoint: %s", err)
	}

	err = m.serveCheckpoint(ctx, tlog.Tree{N: candidate.TreeSize(), Hash: rootHash}, signedNote)
	if errors.Is(err, ErrCheckpointChanged) {
		return fmt.Errorf("initializing issuance log for %s: a checkpoint is already served at s3://%s/%s, refusing to replace it: %w",
			m.logID.String(), m.s3c.Bucket(), m.checkpointKey, err)
	}
	return err
}

// Preflight gets the latest checkpoint from the database, reads the
// corresponding frontier tiles from storage, and serves the checkpoint, in case
// a previous process stopped between publishing tiles and serving. It must be
// called on startup, before Loop().
func (m *mtca) Preflight(ctx context.Context) error {
	latest, err := treedb.New(m.db).LatestCheckpoint(ctx, m.logID.String())
	if err != nil {
		return err
	}
	frontier, err := tiles.LoadFrontier(ctx, m.s3c, latest.TreeSize, m.logID.TilePrefix())
	if err != nil {
		return err
	}

	tileBasedHash := frontier.RootHash()
	if !bytes.Equal(latest.RootHash, tileBasedHash[:]) {
		return fmt.Errorf("state mismatch: at tree size %d, DB contains RootHash %s, but frontier tiles calculate %s",
			latest.TreeSize,
			base64.StdEncoding.EncodeToString(latest.RootHash[:]),
			tileBasedHash)
	}

	m.frontier = frontier

	tree := tlog.Tree{N: latest.TreeSize, Hash: tlog.Hash(latest.RootHash)}
	signedNote, err := m.checkpointNote(tree, latest.MTCASignature)
	if err != nil {
		return err
	}
	return m.serveCheckpoint(ctx, tree, signedNote)
}

type pool struct {
	sync.RWMutex
	entries []pendingEntry
	maxSize int
}

// pendingEntry represents a pending entry in the pool, along with a channel to notify a pending RPC.
type pendingEntry struct {
	mtcle *entry.MTCLogEntry
	mtcpk *pubkey.MTCPublicKey
	ch    chan<- int64
}

func (p *pool) take() []pendingEntry {
	p.Lock()
	defer p.Unlock()
	ret := p.entries
	p.entries = nil
	return ret
}

func (p *pool) len() int {
	p.RLock()
	defer p.RUnlock()
	return len(p.entries)
}

func (p *pool) append(e pendingEntry) error {
	p.Lock()
	defer p.Unlock()
	if len(p.entries) >= p.maxSize {
		return fmt.Errorf("pool is full")
	}
	p.entries = append(p.entries, e)
	return nil
}

// Issue requests a TBSCertificateLogEntry be issued and returns after it's been sequenced into the log
// and a new checkpoint signed by the CA. It does not wait for a mirror cosignature.
//
// Safe for concurrent calls. Implements a gRPC method.
func (m *mtca) Issue(ctx context.Context, req *mtcapb.IssueRequest) (*mtcapb.IssueResponse, error) {
	key, err := x509.ParsePKIXPublicKey(req.Pubkey)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %s", err)
	}

	profile, ok := m.profiles[req.Profile]
	if !ok {
		return nil, fmt.Errorf("unrecognized profile name: %q", req.Profile)
	}

	notBefore, notAfter := profile.GenerateValidity(m.clk.Now())

	dnsNames, ipAddresses, err := identifier.FromProtoSlice(req.Identifiers).ToValues()
	if err != nil {
		return nil, err
	}

	// Placeholder serial; will be omitted from the TBSCertificateLogEntry.
	serial := [18]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18}

	lintCertBytes, _, err := m.issuer.Prepare(profile, &issuance.IssuanceRequest{
		PublicKey:   issuance.MarshalablePublicKey{PublicKey: key},
		Serial:      issuance.HexMarshalableBytes(serial[:]),
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		DNSNames:    dnsNames,
		IPAddresses: ipAddresses,
	})
	if err != nil {
		return nil, fmt.Errorf("preparing x509 certificate: %s", err)
	}

	mtcle, err := entry.FromX509(lintCertBytes, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("generating MTCLogEntry: %s", err)
	}

	mtcpk, err := pubkey.FromCryptoPubkey(key)
	if err != nil {
		return nil, fmt.Errorf("generating MTCPubkey: %s", err)
	}

	// We'll get notification of sequencing on this channel. Buffer it so `sequence()` doesn't
	// block if this method has already returned (e.g. due to timeout).
	ch := make(chan int64, 1)
	err = m.pool.append(pendingEntry{
		mtcle: mtcle,
		mtcpk: mtcpk,
		ch:    ch,
	})
	if err != nil {
		return nil, err
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case entryIndex := <-ch:
		if entryIndex < 0 {
			return nil, errors.New("error during sequencing")
		}
		return &mtcapb.IssueResponse{
			MtcLogID:      m.logID.String(),
			MtcEntryIndex: entryIndex,
		}, nil
	}
}

// Loop periodically sequences all entries in the pool and sends notifications to the waiting RPCs.
//
// Must be called after Preflight() returns success.
//
// At process shutdown, this context should be canceled _after_ GracefulStop returns. That ensures
// there are no inflight RPCs from clients, which in turn ensures that we have sequenced everything
// had in the pool.
func (m *mtca) Loop(ctx context.Context) {
	since := time.Now()
	ticker := time.NewTicker(m.sequencingPeriod)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			err := m.sequence(ctx)
			if err != nil {
				if !errors.Is(err, ErrCheckpointNotReady) {
					m.log.Errf("sequencing: %s", err)
				} else if time.Since(since) > 10*m.sequencingPeriod {
					m.log.Errf("after %s: %s", time.Since(since).Round(time.Millisecond), err)
				}
				continue
			}
			since = time.Now()
		case <-ctx.Done():
			// Given the structure of main(), this context will only be cancelled once
			// GracefulStop has finished. That means all in-flight RPCs have returned,
			// which in turn means that their certificate requests were sequenced (or
			// they timed out, in which case emitting this error is appropriate).
			poolSize := m.pool.len()
			if poolSize != 0 {
				m.log.Errf("shouldn't happen: pool has %d entries left after Loop() context canceled. ungraceful stop?", poolSize)
			}
			return
		}
	}
}

// sequence takes all entries from the pool, writes them to tile storage, signs
// a new checkpoint, stores the checkpoint signature, serves the checkpoint, and
// notifies waiting RPCs.
//
// If the pool is empty, no sequencing happens.
// If the pool is non-empty, but the previous checkpoint doesn't have a mirror signature,
// returns an error that wraps ErrCheckpointNotReady (without taking entries from the pool).
// This is expected to be a common occurrence.
//
// Each entry in the pool will get a notification on its channel: either the index at which
// it was sequenced, or -1 if there was an error during sequencing.
//
// Must only be called after Preflight() returns success.
func (m *mtca) sequence(ctx context.Context) error {
	if m.frontier == nil {
		return fmt.Errorf("call mtca.Preflight() before sequencing")
	}

	if m.pool.len() == 0 {
		return nil
	}

	latest, err := treedb.New(m.db).LatestCheckpoint(ctx, m.logID.String())
	if err != nil {
		return err
	}

	if !latest.Mirrored() {
		return fmt.Errorf("temporary: checkpoint ID %d (tree size %d): %w",
			latest.ID, latest.TreeSize, ErrCheckpointNotReady)
	}

	// Pull the contents of the pool.
	entries := m.pool.take()
	if len(entries) == 0 {
		return nil
	}

	// Since we've taken ownership of the previously-pooled entries, make sure we notify
	// the waiting RPCs of either a success or a failure.
	defer func() {
		for _, e := range entries {
			e.ch <- -1
		}
	}()

	candidate := m.frontier.Clone()

	// Add leaves to the candidate.
	for _, e := range entries {
		err = candidate.AppendEntry(e.mtcle, e.mtcpk)
		if err != nil {
			return err
		}
	}

	newRootHash := candidate.RootHash()

	// Log each leaf along with the root hash it will be included in.
	for i, e := range entries {
		m.log.AuditInfo("issuing", map[string]any{
			"TBSCertificateLogEntry": hex.EncodeToString(e.mtcle.TBS()),
			"entryIndex":             latest.TreeSize + int64(i),
			"mtcLogID":               m.logID.String(),
			"newRootHash":            newRootHash.String(),
		})
	}

	// First stage to a pending area. After signing and storing to the DB
	// (but before publishing a new checkpoint signed note), we will flush
	// to the live location. This ensures we've persisted the tiles before
	// committing to a tree hash by signing it.
	err = candidate.Stage(ctx, m.s3c, m.logID.TilePrefix())
	if err != nil {
		return fmt.Errorf("staging candidate tiles: %s", err)
	}

	newCheckpoint := &treedb.CheckpointModel{
		ID:              0,
		MTCLogID:        m.logID.String(),
		MTCASignature:   nil,
		MirrorID:        nil,
		MirrorSignature: nil,
		TreeSize:        candidate.TreeSize(),
		RootHash:        newRootHash[:],
	}

	err = newCheckpoint.Valid()
	if err != nil {
		return fmt.Errorf("validating checkpoint: %s", err)
	}

	// Precommit to the new checkpoint. This will allow us to do recovery if we crash between signing
	// the new checkpoint and writing it to the database.
	//
	// TODO: crash recovery. When MTCA starts up, if there is a checkpoint with no MTCA signature, MTCA
	// should check for staged tiles. Assuming the staged tiles and the checkpoint are consistent with
	// the previous, signed, checkpoint, MTCA should try to re-sign the checkpoint and proceed from there.
	//
	// Note: Insert() updates the ID field of its parameter due to SetKeys(true, "ID")
	err = m.db.Insert(ctx, newCheckpoint)
	if err != nil {
		return err
	}

	var caSig []byte
	var signedNote []byte
	_, err = db.WithTransaction(ctx, m.db, func(tx db.Executor) (any, error) {
		var latestID int64
		// Lock the latestCheckpoint to make sure there is no concurrent signer/writer, avoiding signing a split view.
		// The FOR UPDATE does the heavy lifting here.
		// https://mariadb.com/docs/server/reference/sql-statements/data-manipulation/selecting-data/for-update
		err := tx.SelectOne(ctx, &latestID,
			`SELECT id from latestCheckpoint WHERE mtcLogID = ? FOR UPDATE`,
			m.logID.String())
		if err != nil {
			return nil, err
		}
		if latestID != latest.ID {
			return nil, fmt.Errorf("latestCheckpoint changed during sequencing from %d to %d. multiple writers?",
				latest.ID, latestID)
		}

		// Note that we're doing HSM work while holding a database lock. That's intentional; the database lock
		// is to prevent the possibility of a concurrent signer on the same tree.
		caSig, signedNote, err = m.signCheckpoint(newCheckpoint)
		if err != nil {
			return nil, err
		}

		result, err := tx.ExecContext(ctx, "UPDATE checkpoints SET mtcaSignature = ? WHERE mtcLogID = ? AND id = ?",
			caSig, m.logID.String(), newCheckpoint.ID)
		if err != nil {
			return nil, fmt.Errorf("updating checkpoint: %s", err)
		}
		rowsAffected, err := result.RowsAffected()
		if err != nil {
			return nil, fmt.Errorf("updating checkpoint, getting rows affected: %s", err)
		}
		if rowsAffected != 1 {
			return nil, fmt.Errorf("updating checkpoint: %d rows updated, rolling back", rowsAffected)
		}

		result, err = tx.ExecContext(ctx, "UPDATE latestCheckpoint SET id = ? WHERE mtcLogID = ? AND id = ?",
			newCheckpoint.ID, m.logID.String(), latestID)
		if err != nil {
			return nil, fmt.Errorf("updating latestCheckpoint: %s", err)
		}
		rowsAffected, err = result.RowsAffected()
		if err != nil {
			return nil, fmt.Errorf("updating latestCheckpoint, getting rows affected: %s", err)
		}
		if rowsAffected != 1 {
			return nil, fmt.Errorf("updating latestCheckpoint: %d rows updated, rolling back", rowsAffected)
		}

		return nil, nil
	})
	if err != nil {
		return err
	}

	m.frontier = candidate

	// Write the tiles to a live serving location.
	//
	// TODO(#8902): This should include indefinite retries on error. We've committed to the
	// tree hash by signing it, so nothing can make progress until we've published the tiles.
	err = m.frontier.Publish(ctx, m.s3c, m.logID.TilePrefix())
	if err != nil {
		return fmt.Errorf("publishing tiles: %s", err)
	}

	// Notify waiting RPCs.
	for i, e := range entries {
		e.ch <- latest.TreeSize + int64(i)
	}
	// Empty out the entries list so the deferred error path doesn't try to notify them.
	entries = nil

	// Serve the new checkpoint.
	return m.serveCheckpoint(ctx, tlog.Tree{N: candidate.TreeSize(), Hash: newRootHash}, signedNote)
}

// signCheckpoint signs c and returns the raw MTCA signature to store and the
// verified checkpoint carrying it.
func (m *mtca) signCheckpoint(c *treedb.CheckpointModel) ([]byte, []byte, error) {
	err := c.Valid()
	if err != nil {
		return nil, nil, fmt.Errorf("validating checkpoint: %s", err)
	}

	if len(c.MTCASignature) > 0 {
		return nil, nil, errors.New("already MTCA-signed")
	}
	if len(c.MirrorSignature) > 0 {
		return nil, nil, errors.New("already mirror-signed")
	}

	tree := tlog.Tree{N: c.TreeSize, Hash: tlog.Hash(c.RootHash)}
	timestampedCosignature, err := m.cosigner.CosignCheckpoint(tree)
	if err != nil {
		return nil, nil, fmt.Errorf("signing checkpoint: %s", err)
	}
	mtcaSignature, err := cosignature.RawSignature(timestampedCosignature)
	if err != nil {
		return nil, nil, err
	}
	signedNote, err := m.checkpointNote(tree, mtcaSignature)
	if err != nil {
		return nil, nil, err
	}
	return mtcaSignature, signedNote, nil
}

// checkpointNote assembles the checkpoint of tree from its note text and the
// MTCA's cosignature line carrying mtcaSignature, and verifies it.
func (m *mtca) checkpointNote(tree tlog.Tree, mtcaSignature []byte) ([]byte, error) {
	caCosignatureLine, err := cosignature.SignatureLine(m.verifier.Name(), m.verifier.KeyHash(), 0, mtcaSignature)
	if err != nil {
		return nil, fmt.Errorf("checkpoint of tree size %d MTCA signature: %s", tree.N, err)
	}

	// Assemble the signed checkpoint note.
	signedNote, err := (&checkpoint.Checkpoint{Origin: m.logID.Origin(), Tree: tree}).SignedNote(caCosignatureLine)
	if err != nil {
		return nil, err
	}

	// Verify the checkpoint note.
	_, _, err = checkpoint.Open(signedNote, m.verifier)
	if err != nil {
		return nil, fmt.Errorf("verifying checkpoint of tree size %d: %s", tree.N, err)
	}
	return signedNote, nil
}

// serveCheckpoint writes signedNote, the verified checkpoint of tree, to tile
// storage. It must be called only after the tiles the tree covers are
// published.
func (m *mtca) serveCheckpoint(ctx context.Context, tree tlog.Tree, signedNote []byte) error {
	etag, err := m.writeCheckpoint(ctx, signedNote, m.servedCheckpointETag)
	if errors.Is(err, ErrCheckpointChanged) {
		// The served checkpoint may be an earlier one of ours, from before a
		// restart or from a failed pass whose write succeeded but never
		// responded.
		served, servedETag, readErr := m.readCheckpoint(ctx)
		if readErr != nil {
			return fmt.Errorf("serving checkpoint of tree size %d: %w", tree.N, readErr)
		}
		cp, _, openErr := checkpoint.Open(served, m.verifier)
		if openErr != nil || cp.Tree.N > tree.N {
			// It is not, so another process is writing checkpoints for this
			// log, or the checkpoint was deleted.
			return fmt.Errorf("serving checkpoint of tree size %d: %w", tree.N, err)
		}
		etag, err = m.writeCheckpoint(ctx, signedNote, servedETag)
	}
	if err != nil {
		return fmt.Errorf("serving checkpoint of tree size %d: %w", tree.N, err)
	}
	m.servedCheckpointETag = etag
	return nil
}

// readCheckpoint returns the served checkpoint and its ETag, or nil and an
// empty string when none is served yet.
func (m *mtca) readCheckpoint(ctx context.Context) ([]byte, string, error) {
	bucket := m.s3c.Bucket()
	out, err := m.s3c.GetObject(ctx, &s3.GetObjectInput{Bucket: &bucket, Key: &m.checkpointKey})
	if err != nil {
		respErr, ok := errors.AsType[*awshttp.ResponseError](err)
		if ok && respErr.HTTPStatusCode() == http.StatusNotFound {
			// Nothing is served yet. A new log has no checkpoint until InitLog
			// writes one.
			return nil, "", nil
		}
		return nil, "", fmt.Errorf("reading s3://%s/%s: %w", bucket, m.checkpointKey, err)
	}
	defer out.Body.Close()

	served, err := io.ReadAll(out.Body)
	if err != nil {
		return nil, "", fmt.Errorf("reading s3://%s/%s: %w", bucket, m.checkpointKey, err)
	}
	if out.ETag == nil {
		// This should never happen. Every read returns the ETag.
		return nil, "", fmt.Errorf("reading s3://%s/%s: no ETag", bucket, m.checkpointKey)
	}
	return served, *out.ETag, nil
}

// writeCheckpoint stores signedNote as the served checkpoint and returns its
// new ETag. When prevETag is empty it creates the checkpoint, otherwise it
// replaces the checkpoint whose ETag is prevETag. It returns
// ErrCheckpointChanged when a checkpoint is already served but prevETag is
// empty, or when the served checkpoint's ETag is not prevETag, including when
// none is served.
func (m *mtca) writeCheckpoint(ctx context.Context, signedNote []byte, prevETag string) (string, error) {
	bucket := m.s3c.Bucket()
	contentType := "text/plain; charset=utf-8"
	cacheControl := "no-store"
	input := &s3.PutObjectInput{
		Bucket:       &bucket,
		Key:          &m.checkpointKey,
		ContentType:  &contentType,
		CacheControl: &cacheControl,
		Body:         bytes.NewReader(signedNote),
	}
	if prevETag == "" {
		star := "*"
		input.IfNoneMatch = &star
	} else {
		input.IfMatch = &prevETag
	}

	out, err := m.s3c.PutObject(ctx, input)
	if err != nil {
		respErr, ok := errors.AsType[*awshttp.ResponseError](err)
		if ok && (respErr.HTTPStatusCode() == http.StatusPreconditionFailed || respErr.HTTPStatusCode() == http.StatusNotFound) {
			// The served checkpoint is not the one prevETag describes, or none
			// is served.
			return "", fmt.Errorf("writing s3://%s/%s: %w", bucket, m.checkpointKey, ErrCheckpointChanged)
		}
		return "", fmt.Errorf("writing s3://%s/%s: %w", bucket, m.checkpointKey, err)
	}

	if out.ETag == nil {
		// This should never happen. Every write returns the new ETag.
		return "", fmt.Errorf("writing s3://%s/%s: no ETag in response", bucket, m.checkpointKey)
	}
	return *out.ETag, nil
}
