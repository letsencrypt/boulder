//go:build go1.27

package cosignature

import (
	"crypto/mldsa"
	"testing"

	"github.com/letsencrypt/boulder/trees/checkpoint"
	"golang.org/x/mod/sumdb/note"
)

// TestVerifyCheckpointIgnoresUnknownSignatures covers signed-note's "verifiers
// MUST ignore signatures from unknown keys" with a two-cosigner note opened by
// one verifier, the shape of every real exchange.
func TestVerifyCheckpointIgnoresUnknownSignatures(t *testing.T) {
	known := newCosigner(t)

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(255 - i)
	}
	otherKey, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed)
	if err != nil {
		t.Fatalf("NewPrivateKey: %s", err)
	}
	unknown, err := NewMLDSACosigner("other.test/m2", otherKey, fixedClock())
	if err != nil {
		t.Fatalf("NewMLDSACosigner: %s", err)
	}

	signed, err := note.Sign(&note.Note{Text: exampleCheckpoint}, known, unknown)
	if err != nil {
		t.Fatalf("note.Sign: %s", err)
	}

	v := newVerifier(t)
	cp, n, err := checkpoint.Verify(signed, note.VerifierList(v))
	if err != nil {
		t.Fatalf("VerifyCheckpoint: %s", err)
	}
	if cp.Origin != "example.com/behind-the-sofa" {
		t.Errorf("Origin = %q, want %q", cp.Origin, "example.com/behind-the-sofa")
	}
	if len(n.Sigs) != 1 || n.Sigs[0].Name != cosignerName {
		t.Fatalf("Sigs = %+v, want only the known cosigner's", n.Sigs)
	}
	if len(n.UnverifiedSigs) != 1 || n.UnverifiedSigs[0].Name != "other.test/m2" {
		t.Errorf("UnverifiedSigs = %+v, want the unknown cosigner's", n.UnverifiedSigs)
	}
}
