//go:build go1.27

package mtpublisher

import (
	"context"
	"crypto/mldsa"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/db"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/privatekey"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/test/vars"
	"github.com/letsencrypt/boulder/trees/cosignature"
)

const (
	mtcLogID = "44947.4.1.0.44"
	mirrorID = "32473.9"
)

func setupDB(t *testing.T) *db.WrappedMap {
	t.Helper()

	dbMap, err := sa.DBMapForTest(vars.DBConnMTCMeta_44947_4_1_0_44FullPerms)
	if err != nil {
		t.Fatalf("opening mtcmeta dbMap: %s", err)
	}
	truncate := func(ctx context.Context) error {
		_, err := dbMap.ExecContext(ctx, "TRUNCATE TABLE checkpoints")
		if err != nil {
			return err
		}
		_, err = dbMap.ExecContext(ctx, "TRUNCATE TABLE latestCheckpoint")
		return err
	}
	err = truncate(t.Context())
	if err != nil {
		t.Fatalf("truncating tables: %s", err)
	}
	t.Cleanup(func() {
		err := truncate(context.Background())
		if err != nil {
			t.Logf("cleaning up tables: %s", err)
		}
	})
	return dbMap
}

// setLatest points latestCheckpoint at the checkpoint with the given id, as the
// sequencer does when it adopts a checkpoint.
func setLatest(t *testing.T, dbMap *db.WrappedMap, logID string, id int64) {
	t.Helper()
	_, err := dbMap.ExecContext(t.Context(),
		"REPLACE INTO latestCheckpoint (mtcLogID, id) VALUES (?, ?)", logID, id)
	if err != nil {
		t.Fatalf("pointing latestCheckpoint at %d: %s", id, err)
	}
}

func insertCheckpoint(t *testing.T, dbMap *db.WrappedMap, logID string, treeSize int64) int64 {
	t.Helper()

	res, err := dbMap.ExecContext(t.Context(),
		"INSERT INTO checkpoints (mtcLogID, mtcaSignature, treeSize, rootHash) VALUES (?, ?, ?, ?)",
		logID, []byte("mtca-signature"), treeSize, make([]byte, 32))
	if err != nil {
		t.Fatalf("inserting checkpoint (%s size %d): %s", logID, treeSize, err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("reading insert id: %s", err)
	}
	return id
}

func lacksCosignature(t *testing.T, dbMap *db.WrappedMap, id int64) bool {
	t.Helper()
	var count int64
	err := dbMap.SelectOne(t.Context(), &count,
		"SELECT COUNT(*) FROM checkpoints WHERE id = ? AND mirrorID IS NULL AND mirrorSignature IS NULL", id)
	if err != nil {
		t.Fatalf("querying checkpoint %d: %s", id, err)
	}
	return count == 1
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
	p, err := New(nil, time.Second, mtcLogID, mirrorID, privatekey.NewDeterministicSigner(key), key.PublicKey(), blog.NewMock())
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
	timestampedSignature, err := cosignature.TimestampedSignature(text, line, verifier)
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
	dbMap := setupDB(t)
	key := testKey(t)
	p, err := New(dbMap, time.Second, mtcLogID, mirrorID, privatekey.NewDeterministicSigner(key), key.PublicKey(), blog.NewMock())
	if err != nil {
		t.Fatalf("New: %s", err)
	}

	// A pass over an empty table is a no-op.
	err = p.publish(t.Context())
	if err != nil {
		t.Fatalf("p.publish() on an empty table: %s", err)
	}

	// An older checkpoint that is not cosigned, which must be left untouched.
	olderCheckpointID := insertCheckpoint(t, dbMap, mtcLogID, 256)

	// The latest checkpoint, which we expect to be cosigned by p.publish().
	latestCheckpointID := insertCheckpoint(t, dbMap, mtcLogID, 512)
	setLatest(t, dbMap, mtcLogID, latestCheckpointID)

	// A checkpoint for another log that was somehow inserted into this table,
	// which must be left untouched thanks to the mtcLogID guard.
	otherLogCheckpointID := insertCheckpoint(t, dbMap, "44947.4.2.0.99", 1024)

	// A precommitted checkpoint the CA has not signed yet, which must be left
	// untouched because latestCheckpoint does not reference it, even though its
	// tree is the largest.
	res, err := dbMap.ExecContext(t.Context(),
		"INSERT INTO checkpoints (mtcLogID, treeSize, rootHash) VALUES (?, ?, ?)",
		mtcLogID, int64(2048), make([]byte, 32))
	if err != nil {
		t.Fatalf("inserting precommitted checkpoint: %s", err)
	}
	precommitID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("reading insert id: %s", err)
	}

	err = p.publish(t.Context())
	if err != nil {
		t.Fatalf("p.publish(): %s", err)
	}

	type row struct {
		MirrorID  string `db:"mirrorID"`
		MirrorSig []byte `db:"mirrorSignature"`
	}
	var cosigned row
	err = dbMap.SelectOne(t.Context(), &cosigned, "SELECT mirrorID, mirrorSignature FROM checkpoints WHERE id = ?", latestCheckpointID)
	if err != nil {
		t.Fatalf("selecting the latest checkpoint: %s", err)
	}

	// Check that the latest checkpoint was cosigned, and the others were
	// untouched.
	if cosigned.MirrorID != mirrorID {
		t.Errorf("mirrorID = %q, want %q", cosigned.MirrorID, mirrorID)
	}
	if len(cosigned.MirrorSig) != mldsa.MLDSA44SignatureSize {
		t.Fatalf("latest checkpoint's mirrorSignature is %d bytes, want %d", len(cosigned.MirrorSig), mldsa.MLDSA44SignatureSize)
	}

	verifier, err := cosignature.NewVerifier(mirrorID, key.PublicKey())
	if err != nil {
		t.Fatalf("NewVerifier: %s", err)
	}
	text := "oid/1.3.6.1.4.1." + mtcLogID + "\n512\n" + base64.StdEncoding.EncodeToString(make([]byte, 32)) + "\n"
	timestampedSignature := append(make([]byte, 8), cosigned.MirrorSig...)
	if !verifier.Verify([]byte(text), timestampedSignature) {
		t.Error("stored mirror cosignature does not verify against the checkpoint text")
	}
	if !lacksCosignature(t, dbMap, olderCheckpointID) {
		t.Error("older checkpoint was cosigned, only the latest should be")
	}
	if !lacksCosignature(t, dbMap, otherLogCheckpointID) {
		t.Errorf("another log's checkpoint (id=%d) was cosigned, despite the mtcLogID guard", otherLogCheckpointID)
	}
	if !lacksCosignature(t, dbMap, precommitID) {
		t.Error("precommitted checkpoint was cosigned before the CA signed it")
	}
}

// TestPublishRejectsMismatchedKey checks that a cosignature that fails to
// verify against the configured public key is not stored.
func TestPublishRejectsMismatchedKey(t *testing.T) {
	dbMap := setupDB(t)

	otherSeed := make([]byte, 32)
	for i := range otherSeed {
		otherSeed[i] = byte(255 - i)
	}
	otherKey, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), otherSeed)
	if err != nil {
		t.Fatalf("NewPrivateKey: %s", err)
	}

	p, err := New(dbMap, time.Second, mtcLogID, mirrorID, privatekey.NewDeterministicSigner(testKey(t)), otherKey.PublicKey(), blog.NewMock())
	if err != nil {
		t.Fatalf("New: %s", err)
	}

	id := insertCheckpoint(t, dbMap, mtcLogID, 512)
	setLatest(t, dbMap, mtcLogID, id)

	err = p.publish(t.Context())
	if err == nil {
		t.Error("publish with a mismatched public key = nil error, want error")
	}
	if !lacksCosignature(t, dbMap, id) {
		t.Error("cosignature was stored despite failing verification")
	}
}

func TestPublishWhenLatestAlreadySigned(t *testing.T) {
	dbMap := setupDB(t)
	key := testKey(t)
	p, err := New(dbMap, time.Second, mtcLogID, mirrorID, privatekey.NewDeterministicSigner(key), key.PublicKey(), blog.NewMock())
	if err != nil {
		t.Fatalf("New: %s", err)
	}

	// Insert a checkpoint that is already cosigned, which must be left
	// untouched.
	res, err := dbMap.ExecContext(t.Context(),
		"INSERT INTO checkpoints (mtcLogID, mtcaSignature, treeSize, rootHash, mirrorID, mirrorSignature) VALUES (?, ?, ?, ?, ?, ?)",
		mtcLogID, []byte("mtca-signature"), int64(512), make([]byte, 32), "existing.cosigner", []byte("already-signed-bruh"))
	if err != nil {
		t.Fatalf("inserting cosigned checkpoint: %s", err)
	}
	cosignedID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("reading insert id: %s", err)
	}
	setLatest(t, dbMap, mtcLogID, cosignedID)

	// Insert an older (non-latest) checkpoint that is not cosigned, which must
	// be left untouched.
	olderID := insertCheckpoint(t, dbMap, mtcLogID, 256)

	err = p.publish(t.Context())
	if err != nil {
		t.Fatalf("p.publish(): %s", err)
	}

	// The latest checkpoint is already cosigned, so the pass must leave both
	// checkpoints untouched.
	if !lacksCosignature(t, dbMap, olderID) {
		t.Error("older checkpoint was cosigned, the pass should have stopped at the signed latest")
	}
	var mirrorCosignature []byte
	err = dbMap.SelectOne(t.Context(), &mirrorCosignature, "SELECT mirrorSignature FROM checkpoints WHERE mtcLogID = ? AND treeSize = 512", mtcLogID)
	if err != nil {
		t.Fatalf("selecting the cosigned checkpoint: %s", err)
	}
	if string(mirrorCosignature) != "already-signed-bruh" {
		t.Errorf("existing cosignature was replaced: %q", mirrorCosignature)
	}
}
