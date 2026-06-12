package mtpublisher

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/jmhodges/clock"

	"github.com/letsencrypt/boulder/db"
	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/test/vars"
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
	_, err = dbMap.ExecContext(t.Context(), "TRUNCATE TABLE checkpoints")
	if err != nil {
		t.Fatalf("truncating checkpoints: %s", err)
	}
	t.Cleanup(func() {
		_, err := dbMap.ExecContext(context.Background(), "TRUNCATE TABLE checkpoints")
		if err != nil {
			t.Logf("cleaning up checkpoints: %s", err)
		}
	})
	return dbMap
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

func TestPublish(t *testing.T) {
	dbMap := setupDB(t)
	p, err := New(dbMap, time.Second, mtcLogID, mirrorID, clock.NewFake(), blog.NewMock())
	if err != nil {
		t.Fatalf("New: %s", err)
	}

	// When there are no checkpoints at all, p.publish() should return without
	// error.
	err = p.publish(t.Context())
	if err != nil {
		t.Fatalf("p.publish() on an empty table: %s", err)
	}

	// An older checkpoint that is not cosigned, which must be left untouched.
	olderCheckpointID := insertCheckpoint(t, dbMap, mtcLogID, 256)

	// The latest checkpoint, which we expect to be cosigned by p.publish().
	latestCheckpointID := insertCheckpoint(t, dbMap, mtcLogID, 512)

	// A checkpoint for another log that was somehow inserted into this table,
	// which must be left untouched thanks to the mtcLogID guard.
	otherLogID := insertCheckpoint(t, dbMap, "44947.4.2.0.99", 1024)

	err = p.publish(t.Context())
	if err != nil {
		t.Fatalf("p.publish(): %s", err)
	}

	// Fetch the latest checkpoint.
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
	if len(cosigned.MirrorSig) != 8+ed25519.SignatureSize {
		t.Errorf("latest checkpoint's mirrorSignature is %d bytes, want %d", len(cosigned.MirrorSig), 8+ed25519.SignatureSize)
	}
	if !lacksCosignature(t, dbMap, olderCheckpointID) {
		t.Error("older checkpoint was cosigned, only the latest should be")
	}
	if !lacksCosignature(t, dbMap, otherLogID) {
		t.Errorf("otherLogID checkpoint (id=%d), despite guard on mtcLogID", otherLogID)
	}
}

func TestPublishWhenLatestAlreadySigned(t *testing.T) {
	dbMap := setupDB(t)
	p, err := New(dbMap, time.Second, mtcLogID, mirrorID, clock.NewFake(), blog.NewMock())
	if err != nil {
		t.Fatalf("New: %s", err)
	}

	// Insert a checkpoint that is already cosigned, which must be left
	// untouched.
	_, err = dbMap.ExecContext(t.Context(),
		"INSERT INTO checkpoints (mtcLogID, mtcaSignature, treeSize, rootHash, mirrorID, mirrorSignature) VALUES (?, ?, ?, ?, ?, ?)",
		mtcLogID, []byte("mtca-signature"), int64(512), make([]byte, 32), "existing.cosigner", []byte("already-signed-bruh"))
	if err != nil {
		t.Fatalf("inserting cosigned checkpoint: %s", err)
	}

	// Insert an older (non-latest) checkpoint that is not cosigned, which must
	// be left untouched.
	olderID := insertCheckpoint(t, dbMap, mtcLogID, 256)

	err = p.publish(t.Context())
	if err != nil {
		t.Fatalf("p.publish(): %s", err)
	}

	// The latest checkpoint is already cosigned and the older checkpoint is left untouched.
	if !lacksCosignature(t, dbMap, olderID) {
		t.Error("older checkpoint was cosigned, the pass should have stopped at the signed latest")
	}
	var cosignature []byte
	err = dbMap.SelectOne(t.Context(), &cosignature, "SELECT mirrorSignature FROM checkpoints WHERE mtcLogID = ? AND treeSize = 512", mtcLogID)
	if err != nil {
		t.Fatalf("selecting the cosigned checkpoint: %s", err)
	}
	if string(cosignature) != "already-signed-bruh" {
		t.Errorf("existing cosignature was replaced: %q", cosignature)
	}
}
