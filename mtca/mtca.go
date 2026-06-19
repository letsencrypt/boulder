//go:build go1.27

package mtca

import (
	"context"
	"crypto/sha256"
	"encoding/asn1"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"time"

	"github.com/letsencrypt/borp"
	corepb "github.com/letsencrypt/boulder/core/proto"
	"github.com/letsencrypt/boulder/db"
	"github.com/letsencrypt/boulder/issuance"
	mtcapb "github.com/letsencrypt/boulder/mtca/proto"
	"golang.org/x/crypto/cryptobyte"
)

var _ mtcapb.MTCAServer = &mtca{}

func New(issuer *issuance.Issuer, dbMap *borp.DbMap) *mtca {
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
		db:     db.NewWrappedMap(dbMap),
		issuer: issuer,
		mtcaID: mtcaID,
		// TODO: collect this from config
		logNumber: 0,
		pool:      &pool{maxSize: 100},
	}
}

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

	rootHash := sha256.Sum256([]byte("fake input"))

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

	db *db.WrappedMap

	maxPoolSize int
	pool        *pool

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

func (p *pool) close() {
	p.maxSize = 0
}

func (p *pool) empty() bool {
	return len(p.entries) == 0
}

func (p *pool) append(e entry) error {
	p.Lock()
	defer p.Unlock()
	if p.maxSize == 0 {
		return fmt.Errorf("pool is closed")
	}
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

func (m *mtca) tableName() string {
	return strings.Replace(m.mtcLogID(), ".", "_", -1)
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

// Drain waits until any in-progress sequencing is done.
//
// It should be called after the gRPC server has stopped accepting new requests.
func (m *mtca) Drain() {
	m.pool.close()
	for {
		m.sequencingMu.Lock()
		if m.pool.empty() {
			return
		}
		m.sequencingMu.Unlock()
		time.Sleep(10 * time.Millisecond)
	}
}

func (m *mtca) Loop(ctx context.Context) {
	ticker := time.NewTicker(1000 * time.Millisecond)
	for {
		select {
		case <-ticker.C:
			err := m.sequence(ctx)
			if err != nil {
				fmt.Printf("sequencing: %s\n", err)
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
		return fmt.Errorf("latest checkpoint (%d) not ready for sequencing",
			latest.TreeSize)
	}

	m.sequencingMu.Lock()
	defer m.sequencingMu.Unlock()
	entries := m.pool.take()
	if len(entries) == 0 {
		// sequence an empty entry
		entries = append(entries, entry{})
	}

	latestTreeSize := latest.TreeSize
	for _, e := range entries {
		if e.ch != nil {
			e.ch <- latestTreeSize
		}
		latestTreeSize++
	}

	// XXX: calculate new root hash
	newRootHash := latest.RootHash
	newRootHash[0]++
	newCheckpoint := checkpoint{
		ID:              0,
		MTCLogID:        m.mtcLogID(),
		MTCASignature:   nil,
		MirrorID:        "",
		MirrorSignature: nil,
		TreeSize:        latestTreeSize,
		RootHash:        newRootHash,
	}

	m.precommit(ctx, latest, &newCheckpoint)

	_, err = db.WithTransaction(ctx, m.db, func(tx db.Executor) (any, error) {
		var latestID int64
		// Lock the latestCheckpoint to make sure there is no concurrent writer, avoiding signing a split view.
		// The FOR UPDATE does the heavy lifting here.
		err := tx.SelectOne(ctx, &latestID,
			`SELECT id from latestCheckpoint WHERE mtcLogID = ? FOR UPDATE`,
			m.mtcLogID())
		if err != nil {
			return nil, err
		}
		if latestID != latest.ID {
			return nil, fmt.Errorf("latestCheckpoint changed during sequencing from %d to %d. multiple writers?")
		}

		err = m.signCheckpoint(ctx, &newCheckpoint)
		if err != nil {
			return nil, err
		}

		rowsUpdated, err := tx.Update(ctx, newCheckpoint)
		if err != nil {
			return nil, err
		}
		if rowsUpdated == 0 {
			return nil, errors.New("no rows updated")
		}

		tx.ExecContext(ctx, "UPDATE latestCheckpoint SET id = ? WHERE mtcLogID = ?",
			newCheckpoint.ID, m.mtcLogID())

		return nil, nil
	})

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
		return errors.New("RootHash is %d bytes")
	}

	return nil
}

func (c *checkpoint) Equals(other *checkpoint) bool {
	return reflect.DeepEqual(c, other)
}

func (c *checkpoint) SequencingReady() bool {
	return len(c.MTCASignature) > 0 && len(c.MirrorSignature) > 0
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
		return nil, fmt.Errorf("getting latest checkpoint from %s for %q: %w",
			m.tableName(), m.mtcLogID(), err)
	}

	return &latestCheckpoint, nil
}

// precommit writes `new` to the database, provided the highest previous checkpoint is exactly equal to `prev`.
//
// `new` must be unsigned and have a greater tree size than `prev`.
// `prev` must have both a CA signature and a mirror signature.
//
// Modifies `new` to set the ID field based on what was written to the database.
func (m *mtca) precommit(ctx context.Context, prev, new *checkpoint) error {
	if len(new.MTCASignature) > 0 {
		return errors.New("tried to insert unsigned checkpoint, but it was already CA-signed")
	}
	if prev.TreeSize >= new.TreeSize {
		return fmt.Errorf("tried to insert unsigned checkpoint, but previous one has larger tree size")
	}
	if len(prev.MTCASignature) == 0 {
		return errors.New("tried to insert unsigned checkpoint, but the previous one was also unsigned")
	}
	if len(prev.MirrorSignature) == 0 {
		return errors.New("tried to insert unsigned checkpoint, but the previous one had no mirror signature")
	}

	latest, err := m.latest(ctx)
	if err != nil {
		return err
	}

	if !prev.Equals(latest) {
		return fmt.Errorf("appending new checkpoint state: prev != latest (prev: %#v; latest: %#v)",
			prev, latest)
	}

	// Insert updates the ID field.
	return m.db.Insert(ctx, new)
}

// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#section-5.3.1
type cosignedMessage struct {
	Label        [12]byte
	CosignerName string
	Timestamp    uint64
	LogOrigin    string
	Start        uint64
	End          uint64
	HashValue    [sha256.Size]byte
}

// opaque HashValue[HASH_SIZE];

//	struct {
//	    uint8 label[12] = "subtree/v1\n\0";
//	    opaque cosigner_name<1..2^8-1>;
//	    uint64 timestamp;
//	    opaque log_origin<1..2^8-1>;
//	    uint64 start;
//	    uint64 end;
//	    HashValue subtree_hash;
//	} CosignedMessage;
func (message *cosignedMessage) Marshal() []byte {
	message.Label = [12]byte{'s', 'u', 'b', 't', 'r', 'e', 'e',
		'/', 'v', '1', '\n', 0}

	var b cryptobyte.Builder
	b.AddBytes(message.Label[:])
	b.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes([]byte(message.CosignerName))
	})
	b.AddUint64(message.Timestamp)
	b.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes([]byte(message.LogOrigin))
	})
	b.AddUint64(message.Start)
	b.AddUint64(message.End)
	b.AddBytes(message.HashValue[:])

	return b.BytesOrPanic()
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

	message := cosignedMessage{
		CosignerName: "oid/1.3.6.1.4.1." + m.mtcaID,
		Timestamp:    0,
		LogOrigin:    "oid/1.3.6.1.4.1." + m.mtcLogID(),
		Start:        0,
		End:          uint64(c.TreeSize),
		HashValue:    [32]byte(c.RootHash),
	}

	sig, err := m.issuer.Signer.Sign(nil, message.Marshal(), nil)
	if err != nil {
		return err
	}

	c.MTCASignature = sig

	return err
}
