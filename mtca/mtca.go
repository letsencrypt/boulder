//go:build go1.27

package mtca

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/asn1"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/letsencrypt/borp"

	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/db"
	"github.com/letsencrypt/boulder/issuance"
	blog "github.com/letsencrypt/boulder/log"
	mtcapb "github.com/letsencrypt/boulder/mtca/proto"
	"github.com/letsencrypt/boulder/trees/cosigned"
)

var ErrIssuanceLogAlreadyInitialized = errors.New("issuance log already initialized")
var ErrCheckpointNotReady = errors.New("not ready - no mirror signature")

var _ mtcapb.MTCAServer = &mtca{}

// New creates a new MTCA service.
func New(issuer *issuance.Issuer, sequencingPeriod time.Duration, dbMap *borp.DbMap, logger blog.Logger) (*mtca, error) {
	mtcaID, err := getMTCAID(issuer.Cert.Certificate)
	if err != nil {
		return nil, err
	}

	if sequencingPeriod == 0 {
		return nil, errors.New("sequencingPeriod must be non-zero")
	}

	return &mtca{
		issuer: issuer,
		mtcaID: mtcaID,
		// TODO: collect this from config
		logNumber: 44,
		pool:      &pool{maxSize: 100},

		sequencingPeriod: sequencingPeriod,

		db:  initDB(dbMap),
		log: logger,
	}, nil
}

type mtca struct {
	mtcapb.UnimplementedMTCAServer

	issuer    *issuance.Issuer
	mtcaID    string
	logNumber uint16

	sequencingPeriod time.Duration

	// TODO: factor our sa.InitWrappedDb() so we get metrics and other goodies.
	// TODO: decide whether we want to route this through the SA or an SA-like object,
	// or keep a direct DB connection from the MTCA.
	db  *db.WrappedMap
	log blog.Logger

	pool *pool
}

func getMTCAID(issuerCert *x509.Certificate) (string, error) {
	testingTrustAnchorIDOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 1}
	for _, attribute := range issuerCert.Subject.Names {
		if attribute.Type.Equal(testingTrustAnchorIDOID) {
			mtcaID, ok := attribute.Value.(string)
			if !ok {
				return "", fmt.Errorf("invalid trust anchor attribute type %T", attribute.Value)
			}
			return mtcaID, nil
		}
	}

	return "", fmt.Errorf("issuer subject %q did not contain trust anchor ID OID %q",
		issuerCert.Subject, testingTrustAnchorIDOID)
}

func initDB(dbMap *borp.DbMap) *db.WrappedMap {
	dbMap.AddTableWithName(checkpoint{}, "checkpoints").SetKeys(true, "ID")
	return db.NewWrappedMap(dbMap)
}

// InitLog creates the database metadata for a new, empty log: one checkpoint and the row
// in `latestCheckpoint` that refers to it. Should only be run once in a log's lifetime.
func (m *mtca) InitLog(ctx context.Context) error {
	_, err := db.WithTransaction(ctx, m.db, func(tx db.Executor) (any, error) {
		var numLatestCheckpoints int64
		err := tx.SelectOne(ctx, &numLatestCheckpoints, "SELECT COUNT(*) FROM latestCheckpoint WHERE mtcLogID = ?",
			m.mtcLogID())
		if err != nil {
			return nil, fmt.Errorf("getting latestCheckpoint: %s", err)
		}

		var numCheckpoints int64
		err = tx.SelectOne(ctx, &numCheckpoints, "SELECT COUNT(*) FROM checkpoints WHERE mtcLogID = ?",
			m.mtcLogID())
		if err != nil {
			return nil, fmt.Errorf("getting checkpoints: %s", err)
		}

		if numCheckpoints > 0 || numLatestCheckpoints > 0 {
			if numLatestCheckpoints == 1 {
				return nil, ErrIssuanceLogAlreadyInitialized
			}

			return nil, fmt.Errorf("initializing issuance log for %s: already has %d checkpoints and %d latestCheckpoint rows",
				m.mtcLogID(), numCheckpoints, numLatestCheckpoints)
		}

		// null_entry has empty extensions and a MTCLogEntryType of 0. Since extensions can be up to 2^16 long
		// there's two bytes of length prefix. Since MTCLogEntryType can have up to 2^16 values, it's also two bytes.
		// All the bytes are zero: empty extensions, null_entry type is enum value zero.
		// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-log-entries
		// To calculate the Merkle Tree Hash of a single-entry list, we prepend 0x00 (as compared with 0x01 when hashing
		// two nodes). So five zeroes total.
		// https://www.rfc-editor.org/info/rfc9162/#name-definition-of-the-merkle-tr
		nullEntry := []byte{0, 0, 0, 0, 0}
		rootHash := sha256.Sum256(nullEntry)

		firstCheckpoint := checkpoint{
			MTCLogID: m.mtcLogID(),
			TreeSize: 1,
			RootHash: rootHash[:],
		}

		message, err := m.cosignedMessage(&firstCheckpoint)
		if err != nil {
			return nil, err
		}

		sig, err := m.sign(message)
		if err != nil {
			return nil, err
		}

		firstCheckpoint.MTCASignature = sig

		err = tx.Insert(ctx, &firstCheckpoint)
		if err != nil {
			return nil, err
		}

		_, err = tx.ExecContext(ctx, "INSERT INTO latestCheckpoint (id, mtcLogID) VALUES (?, ?)",
			firstCheckpoint.ID, m.mtcLogID())
		if err != nil {
			return nil, fmt.Errorf("inserting latestCheckpoint: %s", err)
		}

		return nil, nil
	})
	if err != nil {
		return err
	}

	_, err = m.latestCheckpoint(ctx)
	if err != nil {
		return fmt.Errorf("fetching first checkpoint: %s", err)
	}

	return err
}

type pool struct {
	sync.RWMutex
	entries []entry
	maxSize int
}

// entry represents an entry in the pool, along with a channel to notify a pending RPC.
type entry struct {
	pubkey      []byte
	identifiers []*corepb.Identifier
	ch          chan<- int64
}

func (p *pool) take() []entry {
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

func (p *pool) append(e entry) error {
	p.Lock()
	defer p.Unlock()
	if len(p.entries) >= p.maxSize {
		return fmt.Errorf("pool is full")
	}
	p.entries = append(p.entries, e)
	return nil
}

// mtcLogID returns the string-formatted relative OID for this log.
// The .0. arc relative to the MTCA ID contains log numbers.
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#ca-ids
func (m *mtca) mtcLogID() string {
	return fmt.Sprintf("%s.0.%d", m.mtcaID, m.logNumber)
}

// Issue requests a TBSCertificateLogEntry be issued and returns after it's been sequenced into the log
// and a new checkpoint signed by the CA. It does not wait for a mirror cosignature.
func (m *mtca) Issue(ctx context.Context, req *mtcapb.IssueRequest) (*mtcapb.IssueResponse, error) {
	// We'll get notification of sequencing on this channel. Buffer it so `sequence()` doesn't
	// block if this method has already returned (e.g. due to timeout).
	ch := make(chan int64, 1)
	err := m.pool.append(entry{
		pubkey:      req.Pubkey,
		identifiers: req.Identifiers,
		ch:          ch,
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
			MtcLogID:      m.mtcLogID(),
			MtcEntryIndex: entryIndex,
		}, nil
	}
}

// Loop periodically sequences all entries in the pool and sends notifications to the waiting RPCs.
//
// At process shutdown, this context should be canceled _after_ GracefulStop returns. That ensures
// there are no inflight RPCs from clients, which in turn ensures that we have sequenced everything
// had in the pool.
func (m *mtca) Loop(ctx context.Context) {
	go m.fakePublisher(ctx)

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

// fakePublisher simulates the role of the mtpublisher by finding checkpoints with no
// mirrorSignature and writing a fake signature to them.
//
// TODO: remove once a real publisher is available in integration.
func (m *mtca) fakePublisher(ctx context.Context) {
	ticker := time.NewTicker(37 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			latest, err := m.latestCheckpoint(ctx)
			if err != nil {
				m.log.Errf("getting latest checkpoint for fake publisher: %s", err)
				continue
			}
			_, err = m.db.ExecContext(ctx, `
				UPDATE checkpoints SET mirrorID = ?, mirrorSignature = ?
				WHERE id = ? AND mtcLogID = ?`,
				"fake mirror ID", []byte("fake mirror signature"),
				latest.ID, m.mtcLogID())
			if err != nil {
				m.log.Errf("updating latest checkpoint with fake signature: %s", err)
				continue
			}
		case <-ctx.Done():
			return
		}
	}
}

// sequence takes all entries from the pool, simulates writing them to tile storage, signs
// and stores a new checkpoint, and notifies waiting RPCs.
//
// If the pool is empty, nothing happens.
// If the pool is non-empty, but the previous checkpoint doesn't have a mirror signature,
// returns an error that wraps ErrCheckpointNotReady (without taking entries from the pool).
// This is expected to be a common occurrence.
//
// Each entry in the pool will get a notification on its channel: either the index at which
// it was sequenced, or -1 if there was an error during sequencing.
func (m *mtca) sequence(ctx context.Context) error {
	if m.pool.len() == 0 {
		return nil
	}

	latest, err := m.latestCheckpoint(ctx)
	if err != nil {
		return err
	}

	if !latest.mirrored() {
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

	// Simulate writing to tile storage
	latestTreeSize := latest.TreeSize
	var entryIndexes []int64
	for range entries {
		entryIndexes = append(entryIndexes, latestTreeSize)
		latestTreeSize++
	}

	// TODO: calculate new root hash for real
	var newRootHash [sha256.Size]byte
	rand.Read(newRootHash[:])

	newCheckpoint := checkpoint{
		ID:              0,
		MTCLogID:        m.mtcLogID(),
		MTCASignature:   nil,
		MirrorID:        "",
		MirrorSignature: nil,
		TreeSize:        latestTreeSize,
		RootHash:        newRootHash[:],
	}

	message, err := m.cosignedMessage(&newCheckpoint)
	if err != nil {
		return err
	}

	// Precommit to the new checkpoint. This will allow us to do recovery if we crash between signing
	// the new checkpoint and writing it to the database.
	//
	// TODO: crash recovery. When MTCA starts up, if there is a checkpoint with no MTCA signature, MTCA
	// should check for staged tiles. Assuming the staged tiles and the checkpoint are consistent with
	// the previous, signed, checkpoint, MTCA should try to re-sign the checkpoint and proceed from there.
	//
	// Note: Insert() updates the ID field of its parameter due to SetKeys(true, "ID")
	err = m.db.Insert(ctx, &newCheckpoint)
	if err != nil {
		return err
	}

	_, err = db.WithTransaction(ctx, m.db, func(tx db.Executor) (any, error) {
		var latestID int64
		// Lock the latestCheckpoint to make sure there is no concurrent signer/writer, avoiding signing a split view.
		// The FOR UPDATE does the heavy lifting here.
		// https://mariadb.com/docs/server/reference/sql-statements/data-manipulation/selecting-data/for-update
		err := tx.SelectOne(ctx, &latestID,
			`SELECT id from latestCheckpoint WHERE mtcLogID = ? FOR UPDATE`,
			m.mtcLogID())
		if err != nil {
			return nil, err
		}
		if latestID != latest.ID {
			return nil, fmt.Errorf("latestCheckpoint changed during sequencing from %d to %d. multiple writers?",
				latest.ID, latestID)
		}

		// Note that we're doing HSM work while holding a database lock. That's intentional; the database lock
		// is to prevent the possibility of a concurrent signer on the same tree.
		sig, err := m.sign(message)
		if err != nil {
			return nil, err
		}

		result, err := tx.ExecContext(ctx, "UPDATE checkpoints SET mtcaSignature = ? WHERE mtcLogID = ? AND id = ?",
			sig, m.mtcLogID(), newCheckpoint.ID)
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
			newCheckpoint.ID, m.mtcLogID(), latestID)
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

	// Notify waiting RPCs.
	for i, e := range entries {
		e.ch <- entryIndexes[i]
	}
	// Empty out the entries list so the deferred error path doesn't try to notify them.
	entries = nil

	return nil
}

// checkpoint represents the database storage of a checkpoint and associated signatures.
//
// For signing, the TreeSize and RootHash fields are incorporated into a `cosigned.Message`.
type checkpoint struct {
	ID              int64  `db:"id"`
	MTCLogID        string `db:"mtcLogID"`
	MTCASignature   []byte `db:"mtcaSignature"`
	MirrorID        string `db:"mirrorID"`
	MirrorSignature []byte `db:"mirrorSignature"`
	TreeSize        int64  `db:"treeSize"`
	RootHash        []byte `db:"rootHash"`
}

func (c *checkpoint) valid() error {
	if len(c.MTCLogID) == 0 {
		return errors.New("MTCLogID is empty")
	}
	if c.TreeSize == 0 {
		return errors.New("TreeSize is 0")
	}
	if len(c.RootHash) == 0 {
		return errors.New("RootHash is empty")
	}
	if len(c.RootHash) != sha256.Size {
		return fmt.Errorf("RootHash is %d bytes", len(c.RootHash))
	}

	return nil
}

func (c *checkpoint) mirrored() bool {
	return len(c.MTCASignature) > 0 && len(c.MirrorSignature) > 0
}

// String returns a string that is reasonable to print in logs, omitting the (large) signatures.
func (c *checkpoint) String() string {
	caSig := "empty"
	if len(c.MTCASignature) > 0 {
		caSig = "non-empty"
	}
	mirrorSig := "empty"
	if len(c.MirrorSignature) > 0 {
		mirrorSig = "non-empty"
	}
	return fmt.Sprintf("ID:%d MTCLogID:%s MTCASignature:%s MirrorID:%s MirrorSignature:%s TreeSize:%d RootHash:%x",
		c.ID, c.MTCLogID, caSig, c.MirrorID, mirrorSig, c.TreeSize, c.RootHash)
}

func (m *mtca) latestCheckpoint(ctx context.Context) (*checkpoint, error) {
	var latest checkpoint
	err := m.db.SelectOne(ctx, &latest,
		`SELECT id, checkpoints.mtcLogID, mtcaSignature, mirrorID,
		        mirrorSignature, treeSize, rootHash
		 FROM latestCheckpoint JOIN checkpoints
		 USING(id)
		 WHERE latestCheckpoint.mtcLogID = ? AND
		       checkpoints.mtcLogID = ?`,
		m.mtcLogID(),
		m.mtcLogID())
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("getting latest checkpoint for %q: issuance log DB is not initialized", m.mtcLogID())
		}
		return nil, fmt.Errorf("getting latest checkpoint for %q: %w", m.mtcLogID(), err)
	}

	return &latest, nil
}

func (m *mtca) cosignedMessage(c *checkpoint) (*cosigned.Message, error) {
	err := c.valid()
	if err != nil {
		return nil, fmt.Errorf("validating checkpoint: %s", err)
	}

	if len(c.MTCASignature) > 0 {
		return nil, errors.New("already MTCA-signed")
	}
	if len(c.MirrorSignature) > 0 {
		return nil, errors.New("already mirror-signed")
	}

	return &cosigned.Message{
		CosignerName: fmt.Sprintf("oid/1.3.6.1.4.1.%s", m.mtcaID),
		Timestamp:    0,
		LogOrigin:    fmt.Sprintf("oid/1.3.6.1.4.1.%s", m.mtcLogID()),
		Start:        0,
		End:          uint64(c.TreeSize),
		SubtreeHash:  [32]byte(c.RootHash),
	}, nil
}

// sign marshals a *cosigned.Message and signs its bytes.
//
// Returns the signature bytes.
func (m *mtca) sign(message *cosigned.Message) ([]byte, error) {
	marshaled, err := message.Marshal()
	if err != nil {
		return nil, err
	}

	return m.issuer.Signer.Sign(nil, marshaled, nil)
}
