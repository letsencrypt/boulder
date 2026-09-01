//go:build go1.27

package mtpublisher

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/privatekey"
	"github.com/letsencrypt/boulder/trees/cosignature"
	"github.com/letsencrypt/boulder/trees/issuancelog"
	"github.com/letsencrypt/boulder/trees/treedb"
)

const (
	mtcLogID = "44947.4.1.0.44"
	mirrorID = "32473.9"
)

var testLogID = issuancelog.ID{CAID: "44947.4.1", LogNumber: 44}

type mockTreeDB struct {
	latestCheckpoint *treedb.CheckpointModel
}

func newMockDB(mtcLogID string) *mockTreeDB {
	var rootHash [32]byte
	return &mockTreeDB{
		latestCheckpoint: &treedb.CheckpointModel{
			ID:       1,
			RootHash: rootHash[:],
			TreeSize: 1,
			MTCLogID: mtcLogID,
		},
	}
}

func (m *mockTreeDB) LatestCheckpoint(ctx context.Context, mtcLogID string) (*treedb.CheckpointModel, error) {
	return m.latestCheckpoint, nil
}

func (m *mockTreeDB) AddMirrorSignature(ctx context.Context, id int64, mirrorID string, mirrorSignature []byte, mtcLogID string) error {
	if m.latestCheckpoint.ID != id {
		return fmt.Errorf("test assumption error: tried to add mirror signature for the wrong ID")
	}
	if m.latestCheckpoint.MTCLogID != mtcLogID {
		return fmt.Errorf("test assumption error: tried to add mirror signature for the wrong MTCLogID (%s vs %s)", m.latestCheckpoint.MTCLogID, mtcLogID)
	}
	m.latestCheckpoint.MirrorID = &mirrorID
	m.latestCheckpoint.MirrorSignature = mirrorSignature
	return nil
}

func insertCheckpoint(t *testing.T, mockDB *mockTreeDB, logID string, treeSize int64) {
	t.Helper()

	mockDB.latestCheckpoint = &treedb.CheckpointModel{
		ID:            mockDB.latestCheckpoint.ID + 1,
		MTCLogID:      logID,
		MTCASignature: []byte("mtca-signature"),
		TreeSize:      treeSize,
		RootHash:      make([]byte, 32),
	}
}

func lacksCosignature(mockDB *mockTreeDB) bool {
	return mockDB.latestCheckpoint.MirrorID == nil && len(mockDB.latestCheckpoint.MirrorSignature) == 0
}

// testKey returns a deterministic ML-DSA-44 key so the test can verify the
// cosignatures the publisher stores.
func testKey(t *testing.T) *mldsa.PrivateKey {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed)
	if err != nil {
		t.Fatalf("NewPrivateKey: %s", err)
	}
	return key
}

// TestCosign checks that the mirror's cosignature line verifies through
// trees/cosignature and yields the timestamped_signature it encodes.
func TestCosign(t *testing.T) {
	key := testKey(t)
	p, err := New(nil, time.Second, testLogID, mirrorID, privatekey.NewDeterministicSigner(key), key.PublicKey(), blog.NewMock())
	if err != nil {
		t.Fatalf("New: %s", err)
	}

	line, err := p.cosign(tlog.Tree{N: 512})
	if err != nil {
		t.Fatalf("cosign: %s", err)
	}
	if !strings.HasPrefix(line, "— oid/1.3.6.1.4.1."+mirrorID+" ") || !strings.HasSuffix(line, "\n") {
		t.Errorf("line %q is not a cosignature line for the mirror", line)
	}

	verifier, err := cosignature.NewVerifier(mirrorID, key.PublicKey())
	if err != nil {
		t.Fatalf("NewVerifier: %s", err)
	}
	text := p.origin + "\n512\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"
	timestampedSignature, err := cosignature.TimestampedSignature([]byte(text), line, verifier)
	if err != nil {
		t.Fatalf("TimestampedSignature: %s", err)
	}
	_, err = cosignature.RawSignature(timestampedSignature)
	if err != nil {
		t.Errorf("RawSignature: %s", err)
	}

	_, err = p.cosign(tlog.Tree{})
	if err == nil {
		t.Error("cosign with an empty tree = nil error, want error")
	}
}

func TestPublish(t *testing.T) {
	key := testKey(t)
	p, err := New(nil, time.Second, testLogID, mirrorID, privatekey.NewDeterministicSigner(key), key.PublicKey(), blog.NewMock())
	if err != nil {
		t.Fatalf("New: %s", err)
	}

	mockDB := newMockDB(mtcLogID)
	p.treedb = mockDB

	// A pass over an empty table is a no-op.
	err = p.Publish(t.Context())
	if err != nil {
		t.Fatalf("p.Publish() on an empty table: %s", err)
	}

	// The latest checkpoint, which we expect to be cosigned by p.Publish().
	insertCheckpoint(t, mockDB, mtcLogID, 512)

	err = p.Publish(t.Context())
	if err != nil {
		t.Fatalf("p.Publish(): %s", err)
	}

	cosigned, err := mockDB.LatestCheckpoint(context.Background(), mtcLogID)
	if err != nil {
		t.Fatal(err)
	}

	// Check that the latest checkpoint was cosigned, and the others were
	// untouched.
	if cosigned.MirrorID == nil || *cosigned.MirrorID != mirrorID {
		t.Errorf("mirrorID = %v, want %q", cosigned.MirrorID, mirrorID)
	}
	if len(cosigned.MirrorSignature) != mldsa.MLDSA44SignatureSize {
		t.Fatalf("latest checkpoint's mirrorSignature is %d bytes, want %d", len(cosigned.MirrorSignature), mldsa.MLDSA44SignatureSize)
	}

	verifier, err := cosignature.NewVerifier(mirrorID, key.PublicKey())
	if err != nil {
		t.Fatalf("NewVerifier: %s", err)
	}
	text := "oid/1.3.6.1.4.1." + mtcLogID + "\n512\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"
	timestampedSignature := append(make([]byte, 8), cosigned.MirrorSignature...)
	if !verifier.Verify([]byte(text), timestampedSignature) {
		t.Error("stored mirror cosignature does not verify against the checkpoint text")
	}
}

// TestPublishRejectsMismatchedKey checks that a cosignature that fails to
// verify against the configured public key is not stored.
func TestPublishRejectsMismatchedKey(t *testing.T) {
	otherSeed := make([]byte, 32)
	for i := range otherSeed {
		otherSeed[i] = byte(255 - i)
	}
	otherKey, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), otherSeed)
	if err != nil {
		t.Fatalf("NewPrivateKey: %s", err)
	}

	p, err := New(nil, time.Second, testLogID, mirrorID, privatekey.NewDeterministicSigner(testKey(t)), otherKey.PublicKey(), blog.NewMock())
	if err != nil {
		t.Fatalf("New: %s", err)
	}

	mockDB := newMockDB(mtcLogID)
	p.treedb = mockDB

	insertCheckpoint(t, mockDB, mtcLogID, 512)

	err = p.Publish(t.Context())
	if err == nil {
		t.Error("publish with a mismatched public key = nil error, want error")
	}
	if !lacksCosignature(mockDB) {
		t.Error("cosignature was stored despite failing verification")
	}
}

func TestPublishWhenLatestAlreadySigned(t *testing.T) {
	key := testKey(t)
	p, err := New(nil, time.Second, testLogID, mirrorID, privatekey.NewDeterministicSigner(key), key.PublicKey(), blog.NewMock())
	if err != nil {
		t.Fatalf("New: %s", err)
	}

	mockDB := newMockDB(mtcLogID)
	p.treedb = mockDB

	// Insert a checkpoint that is already cosigned, which must be left
	// untouched.
	insertCheckpoint(t, mockDB, mtcLogID, 512)
	existing := "existing.cosigner"
	mockDB.latestCheckpoint.MirrorID = &existing
	mockDB.latestCheckpoint.MirrorSignature = []byte("already-signed-bruh")

	err = p.Publish(t.Context())
	if err != nil {
		t.Fatalf("p.Publish(): %s", err)
	}

	// The latest checkpoint was already cosigned, so the pass must leave it untouched.
	if !bytes.Equal(mockDB.latestCheckpoint.MirrorSignature, []byte("already-signed-bruh")) {
		t.Errorf("MirrorSignature: got %x, want %x", mockDB.latestCheckpoint.MirrorSignature, []byte("already-signed-bruh"))
	}
	if mockDB.latestCheckpoint.MirrorID == nil || *mockDB.latestCheckpoint.MirrorID != "existing.cosigner" {
		t.Errorf("MirrorID: got %v, want %s", mockDB.latestCheckpoint.ID, "existing.cosigner")
	}
}
