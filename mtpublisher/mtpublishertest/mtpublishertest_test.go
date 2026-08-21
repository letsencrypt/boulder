//go:build go1.27

package mtpublishertest

import (
	"crypto/mldsa"
	"testing"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/privatekey"
	"github.com/letsencrypt/boulder/trees/checkpoint"
	"github.com/letsencrypt/boulder/trees/cosignature"
)

const (
	mtcLogID = "44947.4.1.0.44"
	mirrorID = "32473.9"
)

// testMirror returns a LocalMirror and the deterministic key it cosigns with.
func testMirror(t *testing.T) (*TestMirror, *mldsa.PrivateKey) {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed)
	if err != nil {
		t.Fatalf("NewPrivateKey: %s", err)
	}
	mirror, err := NewTestMirror(mirrorID, "oid/1.3.6.1.4.1."+mtcLogID, privatekey.NewDeterministicSigner(key))
	if err != nil {
		t.Fatalf("NewTestMirror: %s", err)
	}
	return mirror, key
}

// TestLocalMirrorCosign checks that the mirror's raw cosignature verifies
// through trees/cosignature.
func TestLocalMirrorCosign(t *testing.T) {
	mirror, key := testMirror(t)

	if mirror.ID() != mirrorID {
		t.Errorf("ID() = %q, want %q", mirror.ID(), mirrorID)
	}

	cp := &checkpoint.Checkpoint{Origin: "oid/1.3.6.1.4.1." + mtcLogID, Tree: tlog.Tree{N: 512}}
	raw, err := mirror.Cosign(t.Context(), cp, nil)
	if err != nil {
		t.Fatalf("Cosign: %s", err)
	}

	verifier, err := cosignature.NewVerifier(mirrorID, key.PublicKey())
	if err != nil {
		t.Fatalf("NewVerifier: %s", err)
	}
	_, err = verifier.SignatureLine(cp.Origin, cp.Tree, raw)
	if err != nil {
		t.Errorf("SignatureLine rejected the mirror's cosignature: %s", err)
	}
}

// TestLocalMirrorCosignRejects checks that the mirror only cosigns checkpoints
// of its own log.
func TestLocalMirrorCosignRejects(t *testing.T) {
	mirror, _ := testMirror(t)

	_, err := mirror.Cosign(t.Context(), &checkpoint.Checkpoint{Origin: "oid/1.3.6.1.4.1.32473.999", Tree: tlog.Tree{N: 512}}, nil)
	if err == nil {
		t.Error("Cosign with another log's checkpoint = nil error, want error")
	}
}
