//go:build go1.27

package cosignature

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/letsencrypt/boulder/privatekey"
	"github.com/letsencrypt/boulder/trees/checkpoint"
	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// exampleCheckpoint is a canonical tlog-checkpoint note body the cosignature
// tests sign and verify over.
const exampleHashB64 = "CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I="

// exampleCheckpoint is a tlog-checkpoint note body, including the trailing
// newline and no signature lines.
const exampleCheckpoint = "example.com/behind-the-sofa\n20852163\n" + exampleHashB64 + "\n"

const cosignerID = "32473.9"
const cosignerName = oidPrefix + cosignerID

// testSigner returns a deterministic signer over a fixed-seed ML-DSA-44 key,
// so cosignature tests are reproducible.
func testSigner(t *testing.T) crypto.Signer {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	key, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed)
	if err != nil {
		t.Fatalf("NewPrivateKey: %s", err)
	}
	return privatekey.NewDeterministicSigner(key)
}

func testPubKey(t *testing.T) *mldsa.PublicKey {
	t.Helper()
	publicKey, ok := testSigner(t).Public().(*mldsa.PublicKey)
	if !ok {
		t.Fatal("testSigner's public key is not ML-DSA")
	}
	return publicKey
}

func newVerifier(t *testing.T) *Verifier {
	t.Helper()
	v, err := NewVerifier(cosignerID, testPubKey(t))
	if err != nil {
		t.Fatalf("NewVerifier: %s", err)
	}
	return v
}

// TestKeyID pins keyIDFor to SHA-256(name || 0x0A || 0x06 || pubkey)[:4],
// derived independently from the spec text. No published vector ships a key and
// ID together, and an internal round-trip cannot catch a shared misreading.
func TestKeyID(t *testing.T) {
	pub := testPubKey(t)

	h := sha256.New()
	h.Write([]byte(cosignerName))
	h.Write([]byte{0x0A, 0x06})
	h.Write(pub.Bytes())
	expect := binary.BigEndian.Uint32(h.Sum(nil)[:4])

	got := keyIDFor(cosignerName, pub)
	if got != expect {
		t.Errorf("keyIDFor = %#x, want %#x", got, expect)
	}

	v := newVerifier(t)
	if v.KeyHash() != expect {
		t.Errorf("KeyHash() = %#x, want %#x", v.KeyHash(), expect)
	}
	if v.Name() != cosignerName {
		t.Errorf("Name() = %q, want %q", v.Name(), cosignerName)
	}
}

func TestVerifyRejectsMalformedInput(t *testing.T) {
	v := newVerifier(t)
	for _, length := range []int{0, 7, 8, timestampedSignatureSize - 1, timestampedSignatureSize + 1} {
		if v.Verify([]byte(exampleCheckpoint), make([]byte, length)) {
			t.Errorf("Verify accepted a %d-byte signature", length)
		}
	}

	if v.Verify([]byte("not a checkpoint"), make([]byte, timestampedSignatureSize)) {
		t.Error("Verify accepted malformed checkpoint text")
	}
}

func TestNewVerifierRejects(t *testing.T) {
	pub := testPubKey(t)
	for _, id := range []string{"", "has space", "32473..2", "32473.x", ".32473", "32473.", "32473.02"} {
		_, err := NewVerifier(id, pub)
		if err == nil {
			t.Errorf("NewVerifier(%q) = nil error, want error", id)
		}
	}

	// An ML-DSA-65 key is the wrong size for an ML-DSA-44 cosigner.
	wrong, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("GenerateKey(MLDSA65): %s", err)
	}
	_, err = NewVerifier(cosignerID, wrong.PublicKey())
	if err == nil {
		t.Error("NewVerifier with a non-ML-DSA-44 key = nil error, want error")
	}
}

// TestVerifyRejectsOversizeTimestamp checks that even a correctly-signed
// timestamped_signature is rejected when its timestamp exceeds the spec's
// 2^63-1 bound.
func TestVerifyRejectsOversizeTimestamp(t *testing.T) {
	signer := testSigner(t)
	v := newVerifier(t)
	parsed, err := checkpoint.Unmarshal([]byte(exampleCheckpoint))
	if err != nil {
		t.Fatalf("Unmarshal: %s", err)
	}

	timestamped := func(ts uint64) []byte {
		message, err := marshalCheckpointMessage(cosignerName, ts, parsed.Origin, parsed.Tree.N, parsed.Tree.Hash)
		if err != nil {
			t.Fatalf("marshalCheckpointMessage: %s", err)
		}
		signature, err := signer.Sign(nil, message, nil)
		if err != nil {
			t.Fatalf("Sign: %s", err)
		}
		out := make([]byte, timestampedSignatureSize)
		binary.BigEndian.PutUint64(out[:8], ts)
		copy(out[8:], signature)
		return out
	}

	for _, ts := range []uint64{1 << 63, ^uint64(0)} {
		if v.Verify([]byte(exampleCheckpoint), timestamped(ts)) {
			t.Errorf("Verify accepted timestamp %d > 2^63-1", ts)
		}
	}
	// The boundary value 2^63-1 is conformant and must verify.
	if !v.Verify([]byte(exampleCheckpoint), timestamped(1<<63-1)) {
		t.Error("Verify rejected the boundary timestamp 2^63-1")
	}
}

// TestVerifyCheckpointErrors checks that each VerifyCheckpoint failure names
// the check that rejected it.
func TestVerifyCheckpointErrors(t *testing.T) {
	v := newVerifier(t)
	parsed, err := checkpoint.Unmarshal([]byte(exampleCheckpoint))
	if err != nil {
		t.Fatalf("Unmarshal: %s", err)
	}

	oversize := make([]byte, timestampedSignatureSize)
	binary.BigEndian.PutUint64(oversize[:8], 1<<63)

	cases := []struct {
		name            string
		tree            tlog.Tree
		signature       []byte
		expectSubstring string
	}{
		{"Short signature", parsed.Tree, make([]byte, 10), "10 bytes"},
		{"Oversize timestamp", parsed.Tree, oversize, "2^63-1"},
		{"Empty tree", tlog.Tree{N: 0, Hash: parsed.Tree.Hash}, make([]byte, timestampedSignatureSize), "non-positive end"},
		{"Garbage signature", parsed.Tree, make([]byte, timestampedSignatureSize), "verifying cosignature"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := v.VerifyCheckpoint(parsed.Origin, tc.tree, tc.signature)
			if err == nil {
				t.Fatal("VerifyCheckpoint = nil error, want error")
			}
			if !strings.Contains(err.Error(), tc.expectSubstring) {
				t.Errorf("VerifyCheckpoint = %s, want substring %q", err, tc.expectSubstring)
			}
		})
	}
}

func TestOriginFor(t *testing.T) {
	origin, err := originFor("32473.2.0.42")
	if err != nil {
		t.Fatalf("originFor: %s", err)
	}
	if origin != "oid/1.3.6.1.4.1.32473.2.0.42" {
		t.Errorf("originFor = %q, want %q", origin, "oid/1.3.6.1.4.1.32473.2.0.42")
	}

	_, err = originFor("32473..2")
	if err == nil {
		t.Error("originFor with a malformed log ID = nil error, want error")
	}
}

// TestCosignerRoundTrip covers the cosigner round trip: an MTC cosigner derives
// its name and origin from the CA and log IDs (mtc-tlog's own examples), and
// its timestamped_signature carries a zero timestamp, verifies through the note
// verifier against the matching checkpoint text, and reassembles into a
// signature line that opens.
func TestCosignerRoundTrip(t *testing.T) {
	ca, err := NewCosigner("32473.2", "32473.2.0.42", testSigner(t))
	if err != nil {
		t.Fatalf("NewCosigner: %s", err)
	}
	if ca.Origin() != "oid/1.3.6.1.4.1.32473.2.0.42" {
		t.Errorf("Origin() = %q, want %q", ca.Origin(), "oid/1.3.6.1.4.1.32473.2.0.42")
	}

	text := ca.origin + "\n20852163\n" + exampleHashB64 + "\n"
	parsed, err := checkpoint.Unmarshal([]byte(text))
	if err != nil {
		t.Fatalf("checkpoint.Unmarshal: %s", err)
	}

	signature, err := ca.CosignCheckpoint(parsed.Tree)
	if err != nil {
		t.Fatalf("CosignCheckpoint: %s", err)
	}
	if len(signature) != timestampedSignatureSize {
		t.Fatalf("CosignCheckpoint returned %d bytes, want %d", len(signature), timestampedSignatureSize)
	}
	if binary.BigEndian.Uint64(signature[:8]) != 0 {
		t.Errorf("timestamp = %d, want 0", binary.BigEndian.Uint64(signature[:8]))
	}

	v, err := NewVerifier("32473.2", testPubKey(t))
	if err != nil {
		t.Fatalf("NewVerifier: %s", err)
	}
	if !v.Verify([]byte(text), signature) {
		t.Error("Verify rejected an MTC checkpoint cosignature")
	}
	err = v.VerifyCheckpoint(ca.Origin(), parsed.Tree, signature)
	if err != nil {
		t.Errorf("VerifyCheckpoint rejected an MTC checkpoint cosignature: %s", err)
	}

	// The cosignature binds the origin and tree: a change to any of them must
	// fail verification.
	err = v.VerifyCheckpoint(ca.Origin(), tlog.Tree{N: parsed.Tree.N + 1, Hash: parsed.Tree.Hash}, signature)
	if err == nil {
		t.Error("VerifyCheckpoint accepted a cosignature over a different tree size")
	}
	tamperedHash := parsed.Tree.Hash
	tamperedHash[0] ^= 1
	err = v.VerifyCheckpoint(ca.Origin(), tlog.Tree{N: parsed.Tree.N, Hash: tamperedHash}, signature)
	if err == nil {
		t.Error("VerifyCheckpoint accepted a cosignature over a different root hash")
	}
	err = v.VerifyCheckpoint("oid/1.3.6.1.4.1.32473.2.0.43", parsed.Tree, signature)
	if err == nil {
		t.Error("VerifyCheckpoint accepted a cosignature over a different origin")
	}

	line := signatureLineFor(ca.name, ca.keyID, signature)
	if !strings.HasPrefix(line, noteSignatureLinePrefix+ca.name+" ") {
		t.Errorf("line %q has unexpected prefix", line)
	}

	extracted, err := TimestampedSignature([]byte(text), line, v)
	if err != nil {
		t.Fatalf("TimestampedSignature on a reassembled note: %s", err)
	}
	if !v.Verify([]byte(text), extracted) {
		t.Error("Verify rejected an extracted cosignature")
	}
	rebuilt := signatureLineFor(ca.name, ca.keyID, extracted)
	if rebuilt != line {
		t.Errorf("signatureLineFor = %q, want %q", rebuilt, line)
	}
}

func TestCosignerRejects(t *testing.T) {
	signer := testSigner(t)

	for _, id := range []string{"", "has space", "32473..2", "32473.x", ".32473", "32473.", "32473.02"} {
		_, err := NewCosigner(id, "32473.2.0.42", signer)
		if err == nil {
			t.Errorf("NewCosigner with cosigner ID %q = nil error, want error", id)
		}
		_, err = NewCosigner("32473.2", id, signer)
		if err == nil {
			t.Errorf("NewCosigner with log ID %q = nil error, want error", id)
		}
	}

	// An ML-DSA-65 key has an mldsa public key of the wrong size.
	wrong, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("GenerateKey(MLDSA65): %s", err)
	}
	_, err = NewCosigner("32473.2", "32473.2.0.42", wrong)
	if err == nil {
		t.Error("NewCosigner with an ML-DSA-65 key = nil error, want error")
	}

	// An Ed25519 key is not an mldsa public key at all.
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %s", err)
	}
	_, err = NewCosigner("32473.2", "32473.2.0.42", edKey)
	if err == nil {
		t.Error("NewCosigner with an Ed25519 key = nil error, want error")
	}

	ca, err := NewCosigner("32473.2", "32473.2.0.42", signer)
	if err != nil {
		t.Fatalf("NewCosigner: %s", err)
	}
	_, err = ca.CosignCheckpoint(tlog.Tree{N: -1})
	if err == nil {
		t.Error("CosignCheckpoint with a negative tree size = nil error, want error")
	}

	// An empty tree [0, 0) is not a valid subtree.
	_, err = ca.CosignCheckpoint(tlog.Tree{N: 0})
	if err == nil {
		t.Error("CosignCheckpoint with an empty tree = nil error, want error")
	}
}

// shortSigner is a crypto.Signer with a valid ML-DSA-44 public key that returns
// a truncated signature, standing in for a misbehaving external signer such as
// an HSM wrapper.
type shortSigner struct {
	pubKey *mldsa.PublicKey
}

func (s shortSigner) Public() crypto.PublicKey {
	return s.pubKey
}

func (s shortSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return []byte("short"), nil
}

func TestCosignerRejectsShortSignature(t *testing.T) {
	ca, err := NewCosigner("32473.2", "32473.2.0.42", shortSigner{pubKey: testPubKey(t)})
	if err != nil {
		t.Fatalf("NewCosigner: %s", err)
	}
	_, err = ca.CosignCheckpoint(tlog.Tree{N: 1})
	if err == nil {
		t.Error("CosignCheckpoint with a truncated signature = nil error, want error")
	}
}

// errSigner is a crypto.Signer with a valid ML-DSA-44 public key whose Sign
// always fails, standing in for an unavailable external signer such as an HSM.
type errSigner struct {
	pubKey *mldsa.PublicKey
}

func (s errSigner) Public() crypto.PublicKey {
	return s.pubKey
}

func (s errSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("signer unavailable")
}

func TestCosignerPropagatesSignerError(t *testing.T) {
	ca, err := NewCosigner("32473.2", "32473.2.0.42", errSigner{pubKey: testPubKey(t)})
	if err != nil {
		t.Fatalf("NewCosigner: %s", err)
	}
	_, err = ca.CosignCheckpoint(tlog.Tree{N: 1})
	if err == nil {
		t.Error("CosignCheckpoint with a failing signer = nil error, want error")
	}
}

// TestRawSignature checks that RawSignature returns the trailing signature
// bytes and refuses lengths and timestamps that certificates cannot carry.
func TestRawSignature(t *testing.T) {
	timestampedSignature := make([]byte, timestampedSignatureSize)
	for i := range timestampedSignature[8:] {
		timestampedSignature[8+i] = byte(i)
	}
	signature, err := RawSignature(timestampedSignature)
	if err != nil {
		t.Fatalf("RawSignature: %s", err)
	}
	if !bytes.Equal(signature, timestampedSignature[8:]) {
		t.Error("RawSignature did not return the trailing signature bytes")
	}

	_, err = RawSignature(timestampedSignature[:10])
	if err == nil {
		t.Error("RawSignature with a short input = nil error, want error")
	}

	nonzero := bytes.Clone(timestampedSignature)
	nonzero[7] = 1
	_, err = RawSignature(nonzero)
	if err == nil {
		t.Error("RawSignature with a non-zero timestamp = nil error, want error")
	}
}

// TestTimestampedSignature checks that the extracted timestamped_signature
// verifies on its own, and that extraction errors for a verifier that did not
// sign.
func TestTimestampedSignature(t *testing.T) {
	ca, err := NewCosigner("32473.2", "32473.2.0.42", testSigner(t))
	if err != nil {
		t.Fatalf("NewCosigner: %s", err)
	}
	text := ca.origin + "\n20852163\n" + exampleHashB64 + "\n"
	parsed, err := checkpoint.Unmarshal([]byte(text))
	if err != nil {
		t.Fatalf("checkpoint.Unmarshal: %s", err)
	}
	cosigned, err := ca.CosignCheckpoint(parsed.Tree)
	if err != nil {
		t.Fatalf("CosignCheckpoint: %s", err)
	}
	line := signatureLineFor(ca.name, ca.keyID, cosigned)

	v, err := NewVerifier("32473.2", testPubKey(t))
	if err != nil {
		t.Fatalf("NewVerifier: %s", err)
	}
	timestampedSignature, err := TimestampedSignature([]byte(text), line, v)
	if err != nil {
		t.Fatalf("TimestampedSignature for the cosigner that signed the note: %s", err)
	}
	if !v.Verify([]byte(text), timestampedSignature) {
		t.Fatal("Verify rejected an extracted cosignature")
	}

	other, err := NewVerifier(cosignerID, testPubKey(t))
	if err != nil {
		t.Fatalf("NewVerifier: %s", err)
	}
	_, err = TimestampedSignature([]byte(text), line, other)
	if err == nil {
		t.Error("TimestampedSignature for a cosigner that did not sign the note = nil error, want error")
	}
}

// TestTimestampedSignatureRejectsForeignFormat checks that a signature line
// whose body is not keyID || timestamped_signature (such as x/mod's standard
// 64-byte Ed25519 form) fails verification even when its name and key ID match
// the verifier's.
func TestTimestampedSignatureRejectsForeignFormat(t *testing.T) {
	v := newVerifier(t)
	idSignature := make([]byte, keyIDSize+64)
	binary.BigEndian.PutUint32(idSignature[:keyIDSize], v.KeyHash())
	line := noteSignatureLinePrefix + v.Name() + " " + base64.StdEncoding.EncodeToString(idSignature) + "\n"
	_, err := TimestampedSignature([]byte(exampleCheckpoint), line, v)
	if err == nil {
		t.Error("TimestampedSignature with a 64-byte signature body = nil error, want error")
	}
}

// TestOpenIgnoresUnknownSignatures covers signed-note's "verifiers MUST ignore
// signatures from unknown keys" with a note cosigned for one log by two MTC
// cosigners and opened by one verifier, the shape of every real exchange.
func TestOpenIgnoresUnknownSignatures(t *testing.T) {
	known, err := NewCosigner("32473.2", "32473.2.0.42", testSigner(t))
	if err != nil {
		t.Fatalf("NewCosigner: %s", err)
	}

	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(255 - i)
	}
	otherKey, err := mldsa.NewPrivateKey(mldsa.MLDSA44(), seed)
	if err != nil {
		t.Fatalf("NewPrivateKey: %s", err)
	}
	unknown, err := NewCosigner("32473.9", "32473.2.0.42", privatekey.NewDeterministicSigner(otherKey))
	if err != nil {
		t.Fatalf("NewCosigner: %s", err)
	}

	text := known.origin + "\n20852163\n" + exampleHashB64 + "\n"
	parsed, err := checkpoint.Unmarshal([]byte(text))
	if err != nil {
		t.Fatalf("checkpoint.Unmarshal: %s", err)
	}
	knownSignature, err := known.CosignCheckpoint(parsed.Tree)
	if err != nil {
		t.Fatalf("CosignCheckpoint: %s", err)
	}
	knownLine := signatureLineFor(known.name, known.keyID, knownSignature)
	unknownSignature, err := unknown.CosignCheckpoint(parsed.Tree)
	if err != nil {
		t.Fatalf("CosignCheckpoint: %s", err)
	}
	unknownLine := signatureLineFor(unknown.name, unknown.keyID, unknownSignature)
	signed := []byte(text + "\n" + knownLine + unknownLine)

	v, err := NewVerifier("32473.2", testPubKey(t))
	if err != nil {
		t.Fatalf("NewVerifier: %s", err)
	}
	cp, n, err := checkpoint.Open(signed, note.VerifierList(v))
	if err != nil {
		t.Fatalf("checkpoint.Open: %s", err)
	}
	if cp.Origin != known.origin {
		t.Errorf("Origin = %q, want %q", cp.Origin, known.origin)
	}
	if len(n.Sigs) != 1 || n.Sigs[0].Name != known.name {
		t.Fatalf("Sigs = %+v, want only the known cosigner's", n.Sigs)
	}
	if len(n.UnverifiedSigs) != 1 || n.UnverifiedSigs[0].Name != unknown.name {
		t.Errorf("UnverifiedSigs = %+v, want the unknown cosigner's", n.UnverifiedSigs)
	}
}
