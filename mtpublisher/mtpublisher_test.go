package mtpublisher

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/jmhodges/clock"

	blog "github.com/letsencrypt/boulder/log"
	"github.com/letsencrypt/boulder/sa"
	"github.com/letsencrypt/boulder/test/vars"
)

func TestCosignPending(t *testing.T) {
	ctx := context.Background()

	dbMap, err := sa.DBMapForTest(vars.DBConnMTCMeta_44947_4_1_0_44FullPerms)
	if err != nil {
		t.Fatalf("opening mtcmeta dbMap: %s", err)
	}
	_, err = dbMap.ExecContext(ctx, "TRUNCATE TABLE checkpoints")
	if err != nil {
		t.Fatalf("truncating checkpoints: %s", err)
	}
	t.Cleanup(func() {
		_, err := dbMap.ExecContext(ctx, "TRUNCATE TABLE checkpoints")
		if err != nil {
			t.Logf("cleaning up checkpoints: %s", err)
		}
	})

	const (
		mtcLogID = "44947.4.1.0.44"
		mirrorID = "32473.9"
	)
	rootHash := make([]byte, 32)

	// A checkpoint awaiting a cosignature.
	res, err := dbMap.ExecContext(ctx,
		"INSERT INTO checkpoints (mtcLogID, mtcaSignature, treeSize, rootHash) VALUES (?, ?, ?, ?)",
		mtcLogID, []byte("mtca-signature"), int64(256), rootHash)
	if err != nil {
		t.Fatalf("inserting pending checkpoint: %s", err)
	}
	pendingID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("reading insert id: %s", err)
	}

	// A checkpoint that is already cosigned, which must be left untouched.
	_, err = dbMap.ExecContext(ctx,
		"INSERT INTO checkpoints (mtcLogID, mtcaSignature, treeSize, rootHash, mirrorID, mirrorSignature) VALUES (?, ?, ?, ?, ?, ?)",
		mtcLogID, []byte("mtca-signature"), int64(512), rootHash, "existing.cosigner", []byte("existing-signature"))
	if err != nil {
		t.Fatalf("inserting cosigned checkpoint: %s", err)
	}

	// A pending checkpoint from another log, that somehow got inserted in this table, which must be left untouched.
	res, err = dbMap.ExecContext(ctx,
		"INSERT INTO checkpoints (mtcLogID, mtcaSignature, treeSize, rootHash) VALUES (?, ?, ?, ?)",
		"44947.4.2.0.99", []byte("other-log-mtca-signature"), int64(256), rootHash)
	if err != nil {
		t.Fatalf("inserting other-log pending checkpoint: %s", err)
	}
	otherLogID, err := res.LastInsertId()
	if err != nil {
		t.Fatalf("reading insert id: %s", err)
	}

	p, err := New(dbMap, time.Second, mtcLogID, mirrorID, clock.NewFake(), blog.NewMock())
	if err != nil {
		t.Fatalf("New: %s", err)
	}
	err = p.cosignPending(ctx)
	if err != nil {
		t.Fatalf("cosignPending: %s", err)
	}

	type row struct {
		MirrorID  string `db:"mirrorID"`
		MirrorSig []byte `db:"mirrorSignature"`
	}

	// The pending checkpoint now carries our mirrorID and a 72-byte cosignature.
	var cosigned []row
	_, err = dbMap.Select(ctx, &cosigned, "SELECT mirrorID, mirrorSignature FROM checkpoints WHERE id = ?", pendingID)
	if err != nil {
		t.Fatalf("selecting the pending checkpoint: %s", err)
	}
	if len(cosigned) != 1 {
		t.Fatalf("found %d rows for the pending checkpoint, want 1", len(cosigned))
	}
	if cosigned[0].MirrorID != mirrorID {
		t.Errorf("mirrorID = %q, want %q", cosigned[0].MirrorID, mirrorID)
	}
	if len(cosigned[0].MirrorSig) != 8+ed25519.SignatureSize {
		t.Errorf("mirrorSignature is %d bytes, want %d", len(cosigned[0].MirrorSig), 8+ed25519.SignatureSize)
	}

	// The already-cosigned checkpoint keeps its original cosignature.
	var existing []row
	_, err = dbMap.Select(ctx, &existing, "SELECT mirrorID, mirrorSignature FROM checkpoints WHERE mirrorID = ?", "existing.cosigner")
	if err != nil {
		t.Fatalf("selecting the cosigned checkpoint: %s", err)
	}
	if len(existing) != 1 || string(existing[0].MirrorSig) != "existing-signature" {
		t.Errorf("already-cosigned checkpoint was modified: %+v", existing)
	}

	// The somehow inserted pending checkpoint from another log is left untouched.
	var stillPendingOtherLog int64
	err = dbMap.SelectOne(ctx, &stillPendingOtherLog,
		"SELECT COUNT(*) FROM checkpoints WHERE id = ? AND mirrorID IS NULL AND mirrorSignature IS NULL",
		otherLogID)
	if err != nil {
		t.Fatalf("checking the other-log checkpoint: %s", err)
	}
	if stillPendingOtherLog != 1 {
		t.Errorf("other-log checkpoint was cosigned despite mtcLogID guard (id=%d)", otherLogID)
	}
}
