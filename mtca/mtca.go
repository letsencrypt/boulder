//go:build go1.27

package mtca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/asn1"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/bs3"
	"github.com/letsencrypt/boulder/db"
	"github.com/letsencrypt/boulder/identifier"
	"github.com/letsencrypt/boulder/issuance"
	mtcapb "github.com/letsencrypt/boulder/mtca/proto"
	"github.com/letsencrypt/boulder/trees/cosigned"
	"github.com/letsencrypt/boulder/trees/entry"
	"github.com/letsencrypt/boulder/trees/tiles"

	"github.com/letsencrypt/borp"
	blog "github.com/letsencrypt/boulder/log"
)

var _ mtcapb.MTCAServer = &mtca{}

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

// New creates a new MTCA service.
func New(
	issuer *issuance.Issuer,
	profile *issuance.Profile,
	dbMap *borp.DbMap,
	s3c *bs3.Client,
	logger blog.Logger,
	clk clock.Clock,
) (*mtca, error) {
	mtcaID, err := getMTCAID(issuer.Cert.Certificate)
	if err != nil {
		return nil, err
	}

	return &mtca{
		log:     logger,
		clk:     clk,
		db:      initDB(dbMap),
		s3c:     s3c,
		issuer:  issuer,
		profile: profile,
		mtcaID:  mtcaID,
		// TODO: collect this from config
		logNumber: 0,
		pool:      &pool{maxSize: 100},
	}, nil
}

func initDB(dbMap *borp.DbMap) *db.WrappedMap {
	dbMap.AddTableWithName(checkpoint{}, "checkpoints").SetKeys(true, "ID")
	return db.NewWrappedMap(dbMap)
}

var ErrIssuanceLogAlreadyInitialized = errors.New("issuance log already initialized")
var ErrCheckpointNotReady = errors.New("not ready - no mirror signature")

// InitLog creates the database metadata for a new, empty log: one checkpoint and the row
// in `latestCheckpoint` that refers to it. Should only be run once in a log's lifetime.
func (m *mtca) InitLog(ctx context.Context) error {
	_, err := m.latest(ctx)
	if err == nil {
		return ErrIssuanceLogAlreadyInitialized
	}

	var numLatestCheckpoints int64
	err = m.db.SelectOne(ctx, &numLatestCheckpoints, "SELECT COUNT(*) FROM latestCheckpoint WHERE mtcLogID = ?",
		m.mtcLogID())
	if err != nil {
		return fmt.Errorf("getting latestCheckpoint: %s", err)
	}

	var numCheckpoints int64
	err = m.db.SelectOne(ctx, &numCheckpoints, "SELECT COUNT(*) FROM checkpoints WHERE mtcLogID = ?",
		m.mtcLogID())
	if err != nil {
		return fmt.Errorf("getting checkpoints: %s", err)
	}

	if numCheckpoints > 0 || numLatestCheckpoints > 0 {
		return fmt.Errorf("initializing issuance log for %s: already has %d checkpoints and %d latestCheckpoint rows",
			m.mtcLogID(), numCheckpoints, numLatestCheckpoints)
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

	err = tiles.WriteEntries(ctx, m.s3c, 0, []entry.MerkleTreeCertEntry{entry.MerkleTreeCertEntry{}})
	if err != nil {
		return err
	}

	_, err = db.WithTransaction(ctx, m.db, func(tx db.Executor) (any, error) {
		sig, err := m.signCheckpoint(&firstCheckpoint)
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

	_, err = m.latest(ctx)
	if err != nil {
		return fmt.Errorf("fetching first checkpoint: %s", err)
	}

	return err
}

// Preflight fetches the latest checkpoint and the latest entry tile tile,
// to check that everything is working before starting up the sequencing loop.
func (m *mtca) Preflight(ctx context.Context) error {
	latestCheckpoint, err := m.latest(ctx)
	if err != nil {
		return err
	}
	_, err = tiles.GetEntry(ctx, m.s3c, latestCheckpoint.TreeSize-1, latestCheckpoint.TreeSize)
	if err != nil {
		return err
	}
	m.log.Infof("started, tree size %d", latestCheckpoint.TreeSize)
	return nil
}

type mtca struct {
	mtcapb.UnimplementedMTCAServer

	issuer    *issuance.Issuer
	profile   *issuance.Profile
	mtcaID    string
	logNumber uint16

	db  *db.WrappedMap
	s3c *bs3.Client
	log blog.Logger
	clk clock.Clock

	pool *pool

	sequencingMu sync.Mutex
}

type pendingEntry struct {
	mtce entry.MerkleTreeCertEntry
	ch   chan<- int64
}

type pool struct {
	sync.Mutex
	entries []pendingEntry
	maxSize int
}

func (p *pool) take() []pendingEntry {
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

func (p *pool) append(e pendingEntry) error {
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
	key, err := x509.ParsePKIXPublicKey(req.Pubkey)
	if err != nil {
		return nil, err
	}

	notBefore, notAfter := m.profile.GenerateValidity(m.clk.Now())

	dnsNames, ipAddresses, err := identifier.FromProtoSlice(req.Identifiers).ToValues()
	if err != nil {
		return nil, err
	}

	// Placeholder serial; will be omitted from the TBSCertificateLogEntry.
	serial := [18]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18}

	lintCertBytes, _, err := m.issuer.Prepare(m.profile, &issuance.IssuanceRequest{
		PublicKey:   issuance.MarshalablePublicKey{PublicKey: key},
		Serial:      issuance.HexMarshalableBytes(serial[:]),
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		DNSNames:    dnsNames,
		IPAddresses: ipAddresses,

		IncludeCTPoison: false,
		CommonName:      "",
		SubjectKeyId:    issuance.HexMarshalableBytes{},
	})

	mtce, err := entry.FromX509(lintCertBytes, crypto.SHA256)
	if err != nil {
		return nil, err
	}

	ch := make(chan int64, 1)
	err = m.pool.append(pendingEntry{
		mtce: mtce,
		ch:   ch,
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
func (m *mtca) Loop(ctx context.Context, sequencingPeriod time.Duration) {
	if sequencingPeriod <= 0 {
		sequencingPeriod = 100 * time.Millisecond
	}

	go m.fakePublisher(ctx)

	since := time.Now()
	ticker := time.NewTicker(sequencingPeriod)
	for {
		select {
		case <-ticker.C:
			err := m.sequence(ctx)
			if err != nil {
				if !errors.Is(err, ErrCheckpointNotReady) {
					m.log.Errf("sequencing: %s", err)
				} else if time.Since(since) > 10*sequencingPeriod {
					m.log.Errf("after %s: %s", time.Since(since).Round(time.Millisecond), err)
				}
				continue
			}
			since = time.Now()
		case <-ctx.Done():
			poolSize := m.pool.len()
			if poolSize != 0 {
				m.log.Errf("shutting down loop: pool has %d entries left. ungraceful stop?", poolSize)
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
	for {
		select {
		case <-ticker.C:
			latest, err := m.latest(ctx)
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

func (m *mtca) sequence(ctx context.Context) error {
	if m.pool.len() == 0 {
		return nil
	}

	latest, err := m.latest(ctx)
	if err != nil {
		return err
	}

	if !latest.sequencingReady() {
		return fmt.Errorf("temporary: checkpoint ID %d (tree size %d): %w",
			latest.ID, latest.TreeSize, ErrCheckpointNotReady)
	}

	m.sequencingMu.Lock()
	defer m.sequencingMu.Unlock()

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

	// Write leaves
	var mtces []entry.MerkleTreeCertEntry
	for _, e := range entries {
		mtces = append(mtces, e.mtce)
	}
	err = tiles.WriteEntries(ctx, m.s3c, latest.TreeSize, mtces)
	if err != nil {
		return err
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
		TreeSize:        latest.TreeSize + int64(len(mtces)),
		RootHash:        newRootHash[:],
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
		sig, err := m.signCheckpoint(&newCheckpoint)
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
		e.ch <- latest.TreeSize + int64(i)
	}
	// Empty out the entries list so the deferred error path doesn't try to notify them.
	entries = nil

	return nil
}

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

func (c *checkpoint) sequencingReady() bool {
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
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("getting latest checkpoint for %q: issuance log DB is not initialized", m.mtcLogID())
		}
		return nil, fmt.Errorf("getting latest checkpoint for %q: %w", m.mtcLogID(), err)
	}

	return &latestCheckpoint, nil
}

// signCheckpoint signs the checkpoint contents and returns the signature bytes.
func (m *mtca) signCheckpoint(c *checkpoint) ([]byte, error) {
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

	message := cosigned.Message{
		CosignerName: fmt.Sprintf("oid/1.3.6.1.4.1.%s", m.mtcaID),
		Timestamp:    0,
		LogOrigin:    fmt.Sprintf("oid/1.3.6.1.4.1.%s", m.mtcLogID()),
		Start:        0,
		End:          uint64(c.TreeSize),
		SubtreeHash:  [32]byte(c.RootHash),
	}

	marshaled, err := message.Marshal()
	if err != nil {
		return nil, err
	}

	return m.issuer.Signer.Sign(nil, marshaled, nil)
}
