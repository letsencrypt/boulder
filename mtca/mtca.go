//go:build go1.27

package mtca

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"time"

	"github.com/letsencrypt/borp"
	"github.com/letsencrypt/boulder/blog"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/db"
	"github.com/letsencrypt/boulder/issuance"
	mtcapb "github.com/letsencrypt/boulder/mtca/proto"
	"github.com/letsencrypt/boulder/trees/cosigned"
)

var _ mtcapb.MTCAServer = &mtca{}

// New creates a new MTCA service.
func New(issuer *issuance.Issuer, dbMap *borp.DbMap, logger blog.Logger) *mtca {
	var mtcaID string
	testingTrustAnchorIDOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 44363, 47, 1}
	for _, attribute := range issuer.Cert.Subject.Names {
		if attribute.Type.Equal(testingTrustAnchorIDOID) {
			mtcaID, _ = attribute.Value.(string)
			break
		}
	}

	dbMap.AddTableWithName(checkpoint{}, "checkpoints").SetKeys(true, "ID")

	return &mtca{
		log:    logger,
		db:     db.NewWrappedMap(dbMap),
		issuer: issuer,
		mtcaID: mtcaID,
		// TODO: collect this from config
		logNumber: 0,
		pool:      &pool{maxSize: 100},
	}
}

// InitLog creates the database metadata for a new, empty log: one checkpoint and the row
// in `latestCheckpoint` that refers to it. Should only be run once in a log's lifetime.
func (m *mtca) InitLog(ctx context.Context) error {
	var numResults int64
	err := m.db.SelectOne(ctx, &numResults, "SELECT COUNT(*) FROM checkpoints WHERE mtcLogID = ?",
		m.mtcLogID())
	if err != nil {
		return err
	}
	if numResults > 0 {
		return fmt.Errorf("%d checkpoints already exist for %s", numResults, m.mtcLogID())
	}

	err = m.db.SelectOne(ctx, &numResults, "SELECT COUNT(*) FROM latestCheckpoint WHERE mtcLogID = ?",
		m.mtcLogID())
	if err != nil {
		return err
	}
	if numResults > 0 {
		return fmt.Errorf("%d latestCheckpoint rows for %s", numResults, m.mtcLogID())
	}

	// null_entry has empty extensions and a MerkleTreeCertEntryType of 0. Since extensions can be up to 2^16 long
	// there's two bytes of length prefix. Since MerkleTreeCertEntryType can have up to 2^16 values, it's also two bytes.
	// All the bytes are zero: empty extensions, null_entry type is enum value zero.
	// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-log-entries
	// To calculate the Merkle Tree Hash of a single-entry list, we prepend 0x00 (as compared with 0x01 when hashing
	// two nodes). So five zeroes total.
	// https://www.rfc-editor.org/info/rfc9162/#name-definition-of-the-merkle-tr
	nullEntry := []byte{0, 0, 0, 0, 0}
	rootHash := sha256.Sum256(nullEntry)

	firstCheckpoint := checkpoint{
		MTCLogID:        m.mtcLogID(),
		MTCASignature:   nil,
		MirrorID:        "",
		MirrorSignature: nil,
		TreeSize:        1,
		RootHash:        rootHash[:],
	}

	err = m.db.Insert(ctx, &firstCheckpoint)
	if err != nil {
		return err
	}

	err = m.signCheckpoint(ctx, &firstCheckpoint)
	if err != nil {
		return err
	}

	rowsUpdated, err := m.db.Update(ctx, &firstCheckpoint)
	if err != nil {
		return err
	}
	if rowsUpdated != 1 {
		return fmt.Errorf("%d rows updated for checkpoint", rowsUpdated)
	}

	_, err = m.db.ExecContext(ctx, "INSERT INTO latestCheckpoint (id, mtcLogID) VALUES (?, ?)",
		firstCheckpoint.ID, m.mtcLogID())

	return err
}

type mtca struct {
	mtcapb.UnimplementedMTCAServer

	issuer    *issuance.Issuer
	mtcaID    string
	logNumber uint16

	db  *db.WrappedMap
	log blog.Logger

	pool *pool

	sequencingMu sync.Mutex
}

type entry struct {
	pubkey      []byte
	identifiers []*corepb.Identifier
	ch          chan<- int64
}

type pool struct {
	sync.Mutex
	entries []entry
	maxSize int
}

func (p *pool) take() []entry {
	p.Lock()
	defer p.Unlock()
	ret := p.entries
	p.entries = nil
	return ret
}

func (p *pool) len() int {
	p.Lock()
	defer p.Unlock()
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

func (m *mtca) Issue(ctx context.Context, req *mtcapb.IssueRequest) (*mtcapb.IssueResponse, error) {
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

	ticker := time.NewTicker(300 * time.Millisecond)
	for {
		select {
		case <-ticker.C:
			err := m.sequence(ctx)
			if err != nil {
				m.log.Error(ctx, "sequencing", err)
				continue
			}
		case <-ctx.Done():
			poolSize := m.pool.len()
			if poolSize != 0 {
				err := fmt.Errorf("pool has %d entries left. ungraceful stop?", poolSize)
				m.log.Error(ctx, "shutting down loop", err)
			}
			return
		}
	}
}

// TODO: remove once a real publisher is available in integration.
func (m *mtca) fakePublisher(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	for {
		select {
		case <-ticker.C:
			latest, err := m.latest(ctx)
			if err != nil {
				m.log.Error(ctx, "getting latest checkpoint for fake publisher", err)
				continue
			}
			latest.MirrorID = "fake fake"
			latest.MirrorSignature = []byte("fake fake")
			_, err = m.db.Update(ctx, latest)
			if err != nil {
				m.log.Error(ctx, "updating latest checkpoint with fake signature", err)
				continue
			}
		case <-ctx.Done():
			return
		}
	}
}

func (m *mtca) sequence(ctx context.Context) error {
	latest, err := m.latest(ctx)
	if err != nil {
		return err
	}

	if !latest.SequencingReady() {
		return fmt.Errorf("temporary: latest checkpoint (%d) not ready", latest.TreeSize)
	}

	m.sequencingMu.Lock()
	defer m.sequencingMu.Unlock()
	entries := m.pool.take()

	if len(entries) == 0 {
		return nil
	}

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

	// Precommit to the new checkpoint. This will allow us to do recovery if we crash between signing
	// the new checkpoint and writing it to the database.
	//
	// Note: Insert() updates the ID field of its parameter due to SetKeys(true, "ID")
	return m.db.Insert(ctx, &newCheckpoint)

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

		// Note that we're doing HSM work while holding a database lock. That's intentional.
		err = m.signCheckpoint(ctx, &newCheckpoint)
		if err != nil {
			return nil, err
		}

		rowsUpdated, err := tx.Update(ctx, &newCheckpoint)
		if err != nil {
			return nil, err
		}
		if rowsUpdated == 0 {
			return nil, errors.New("no rows updated")
		}

		result, err := tx.ExecContext(ctx, "UPDATE latestCheckpoint SET id = ? WHERE mtcLogID = ? AND id = ?",
			newCheckpoint.ID, m.mtcLogID(), latestID)
		if err != nil {
			return nil, fmt.Errorf("updating latestCheckpoint: %s", err)
		}
		rowsAffected, err := result.RowsAffected()
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

	// Notify waiting RPCs. If there's no listener on the channel, don't block.
	for i, e := range entries {
		select {
		case e.ch <- entryIndexes[i]:
		default:
		}
	}

	return nil
}

type checkpoint struct {
	ID              int64
	MTCLogID        string
	MTCASignature   []byte
	MirrorID        string
	MirrorSignature []byte
	TreeSize        int64
	RootHash        []byte
}

func (c *checkpoint) Valid() error {
	if c.ID == 0 {
		return errors.New("ID is 0")
	}
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

func (c *checkpoint) Equals(other *checkpoint) bool {
	return reflect.DeepEqual(c, other)
}

func (c *checkpoint) SequencingReady() bool {
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

func (m *mtca) latest(ctx context.Context) (*checkpoint, error) {
	var latestCheckpoint checkpoint
	err := m.db.SelectOne(ctx, &latestCheckpoint,
		`SELECT id, checkpoints.mtcLogID, mtcaSignature, mirrorID,
		        mirrorSignature, treeSize, rootHash
		 FROM latestCheckpoint JOIN checkpoints
		 USING(id)
		 WHERE latestCheckpoint.mtcLogID = ? AND
		       checkpoints.mtcLogID = ?`,
		m.mtcLogID(),
		m.mtcLogID())
	if err != nil {
		return nil, fmt.Errorf("getting latest checkpoint for %q: %w", m.mtcLogID(), err)
	}

	return &latestCheckpoint, nil
}

func (m *mtca) signCheckpoint(ctx context.Context, c *checkpoint) error {
	err := c.Valid()
	if err != nil {
		return fmt.Errorf("validating checkpoint: %s", err)
	}

	if len(c.MTCASignature) > 0 {
		return errors.New("already MTCA-signed")
	}
	if len(c.MirrorSignature) > 0 {
		return errors.New("already mirror-signed")
	}

	message := cosigned.Message{
		CosignerName: "oid/1.3.6.1.4.1." + m.mtcaID,
		Timestamp:    0,
		LogOrigin:    "oid/1.3.6.1.4.1." + m.mtcLogID(),
		Start:        0,
		End:          uint64(c.TreeSize),
		SubtreeHash:  [32]byte(c.RootHash),
	}

	marshaled, err := message.Marshal()
	if err != nil {
		return err
	}

	sig, err := m.issuer.Signer.Sign(nil, marshaled, nil)
	if err != nil {
		return err
	}

	c.MTCASignature = sig

	return err
}
