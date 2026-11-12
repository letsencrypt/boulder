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
	"time"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/core/reloid"
	"github.com/letsencrypt/boulder/must"
	"github.com/letsencrypt/boulder/privatekey"
	"github.com/letsencrypt/boulder/trees/checkpoint"
	"github.com/letsencrypt/boulder/trees/subtree"
)

// exampleCheckpoint is a canonical tlog-checkpoint note body the cosignature
// tests sign and verify over.
const exampleHashB64 = "CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I="

// exampleCheckpoint is a tlog-checkpoint note body, including the trailing
// newline and no signature lines.
const exampleCheckpoint = "example.com/behind-the-sofa\n20852163\n" + exampleHashB64 + "\n"

var (
	cosignerID   = must.Do(reloid.FromString("32473.9"))
	cosignerName = oidPrefix + cosignerID.String()

	// caID is the cosigner ID of the CA operating the log the tests cosign.
	caID = must.Do(reloid.FromString("32473.2"))
)

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

// signedNote joins checkpoint text and signature lines into a signed note.
func signedNote(text string, lines ...[]byte) []byte {
	return append([]byte(text+"\n"), bytes.Join(lines, nil)...)
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
	_, err := NewVerifier(nil, pub)
	if err == nil {
		t.Error("NewVerifier with a nil cosigner ID = nil error, want error")
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

// TestVerifyRejects checks that Verify rejects a malformed signature and a
// malformed checkpoint.
func TestVerifyRejects(t *testing.T) {
	v := newVerifier(t)

	oversize := make([]byte, timestampedSignatureSize)
	binary.BigEndian.PutUint64(oversize[:8], 1<<63)
	emptyTree := strings.Replace(exampleCheckpoint, "\n20852163\n", "\n0\n", 1)

	cases := []struct {
		name      string
		noteText  string
		signature []byte
	}{
		{"Short signature", exampleCheckpoint, make([]byte, 10)},
		{"Oversize timestamp", exampleCheckpoint, oversize},
		{"Empty tree", emptyTree, make([]byte, timestampedSignatureSize)},
		{"Garbage signature", exampleCheckpoint, make([]byte, timestampedSignatureSize)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if v.Verify([]byte(tc.noteText), tc.signature) {
				t.Error("Verify = true, want false")
			}
		})
	}
}

func TestCosignerNegativeTime(t *testing.T) {
	ca, err := NewCosigner(caID, "oid/1.3.6.1.4.1.32473.2.0.42", testSigner(t))
	if err != nil {
		t.Fatalf("NewCosigner: %s", err)
	}
	_, err = ca.CosignCheckpoint(tlog.Tree{}, time.Unix(-1, 0))
	if err == nil {
		t.Errorf("CosignCheckpoint with negative timestamp: got %v, want error", err)
	}
}

// TestCosignerRoundTrip covers the cosigner round trip: an MTC cosigner derives
// its name and origin from the CA and log IDs (mtc-tlog's own examples),
// verifies through the note verifier against the matching checkpoint text, and
// reassembles into a signature line that opens.
func TestCosignerRoundTrip(t *testing.T) {
	ca, err := NewCosigner(caID, "oid/1.3.6.1.4.1.32473.2.0.42", testSigner(t))
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

	signatureLine, err := ca.CosignCheckpoint(parsed.Tree, time.Now())
	if err != nil {
		t.Fatalf("CosignCheckpoint: %s", err)
	}

	if !strings.HasPrefix(string(signatureLine), noteSignatureLinePrefix+ca.name+" ") {
		t.Errorf("line %q has unexpected prefix", signatureLine)
	}

	v, err := NewVerifier(caID, testPubKey(t))
	if err != nil {
		t.Fatalf("NewVerifier: %s", err)
	}

	// The cosignature binds the origin and tree: a change to any of them must
	// fail verification.
	_, _, err = checkpoint.Open(signedNote(ca.origin+"\n20852164\n"+exampleHashB64+"\n", signatureLine), v)
	if err == nil {
		t.Error("Verifier accepted a cosignature over a different tree size")
	}
	tamperedHash := parsed.Tree.Hash
	tamperedHash[0] ^= 1
	_, _, err = checkpoint.Open(signedNote(
		ca.origin+"\n20852163\n"+base64.StdEncoding.EncodeToString(tamperedHash[:])+"\n",
		signatureLine), v)
	if err == nil {
		t.Error("Verifier accepted a cosignature over a different root hash")
	}

	_, _, err = checkpoint.Open(signedNote(
		"oid/1.3.6.1.4.1.32473.2.0.43\n20852163\n"+exampleHashB64+"\n",
		signatureLine), v)
	if err == nil {
		t.Error("Verifier accepted a cosignature over a different origin")
	}

	_, n, err := checkpoint.Open(signedNote(text, signatureLine), v)
	if err != nil {
		t.Fatalf("checkpoint.Open on a valid note: %s", err)
	}
	extracted, err := v.CheckpointCosignature(n)
	if err != nil {
		t.Fatalf("CheckpointCosignature: %s", err)
	}
	rebuilt, err := ca.SignatureLine(extracted.Timestamp, extracted.Signature)
	if err != nil {
		t.Fatalf("SignatureLine: %s", err)
	}
	if !bytes.Equal(rebuilt, signatureLine) {
		t.Errorf("SignatureLine = %q, want %q", rebuilt, signatureLine)
	}
}

func TestCosignerRejects(t *testing.T) {
	signer := testSigner(t)

	_, err := NewCosigner(nil, "oid/1.3.6.1.4.1.32473.2.0.42", signer)
	if err == nil {
		t.Error("NewCosigner with a nil cosigner ID = nil error, want error")
	}
	_, err = NewCosigner(caID, "", signer)
	if err == nil {
		t.Error("NewCosigner with an empty origin = nil error, want error")
	}
	_, err = NewCosigner(caID, "oid/1.3.6.1.4.1.32473.2.0.42 ", signer)
	if err == nil {
		t.Error("NewCosigner with a space in the origin = nil error, want error")
	}

	// An ML-DSA-65 key has an mldsa public key of the wrong size.
	wrong, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("GenerateKey(MLDSA65): %s", err)
	}
	_, err = NewCosigner(caID, "oid/1.3.6.1.4.1.32473.2.0.42", wrong)
	if err == nil {
		t.Error("NewCosigner with an ML-DSA-65 key = nil error, want error")
	}

	// An Ed25519 key is not an mldsa public key at all.
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %s", err)
	}
	_, err = NewCosigner(caID, "oid/1.3.6.1.4.1.32473.2.0.42", edKey)
	if err == nil {
		t.Error("NewCosigner with an Ed25519 key = nil error, want error")
	}

	ca, err := NewCosigner(caID, "oid/1.3.6.1.4.1.32473.2.0.42", signer)
	if err != nil {
		t.Fatalf("NewCosigner: %s", err)
	}
	_, err = ca.CosignCheckpoint(tlog.Tree{N: -1}, time.Now())
	if err == nil {
		t.Error("CosignCheckpoint with a negative tree size = nil error, want error")
	}

	_, err = ca.CosignSubtree(-1, 1, tlog.Hash{})
	if err == nil {
		t.Error("CosignSubtree with a negative start = nil error, want error")
	}
	_, err = ca.CosignSubtree(1, 3, tlog.Hash{})
	if err == nil {
		t.Error("CosignSubtree with a start that is not a multiple of the subtree's width = nil error, want error")
	}
}

// TestCosignSubtree checks that a subtree verifies over its own message, and
// that an empty subtree and an empty subtree can be signed.
func TestCosignSubtree(t *testing.T) {
	ca, err := NewCosigner(caID, "oid/1.3.6.1.4.1.32473.2.0.42", testSigner(t))
	if err != nil {
		t.Fatalf("NewCosigner: %s", err)
	}
	text := ca.origin + "\n20852163\n" + exampleHashB64 + "\n"
	parsed, err := checkpoint.Unmarshal([]byte(text))
	if err != nil {
		t.Fatalf("checkpoint.Unmarshal: %s", err)
	}

	signature, err := ca.CosignSubtree(1024, 1536, parsed.Tree.Hash)
	if err != nil {
		t.Fatalf("CosignSubtree: %s", err)
	}
	v, err := NewVerifier(caID, testPubKey(t))
	if err != nil {
		t.Fatalf("NewVerifier: %s", err)
	}
	if !v.VerifySubtreeSignature(ca.origin, 1024, 1536, parsed.Tree.Hash, signature) {
		t.Error("VerifySubtreeSignature rejected the subtree signature")
	}

	emptyHash := subtree.MTH(nil)
	signature, err = ca.CosignSubtree(4, 4, emptyHash)
	if err != nil {
		t.Fatalf("CosignSubtree over an empty subtree: %s", err)
	}
	if !v.VerifySubtreeSignature(ca.origin, 4, 4, emptyHash, signature) {
		t.Error("VerifySubtreeSignature rejected the empty subtree signature")
	}

	signature, err = ca.CosignSubtree(0, 0, emptyHash)
	if err != nil {
		t.Fatalf("CosignSubtree over an empty subtree: %s", err)
	}
	if !v.VerifySubtreeSignature(ca.origin, 0, 0, emptyHash, signature) {
		t.Error("VerifySubtreeSignature rejected the empty subtree signature")
	}
}

func TestCosignCheckpoint(t *testing.T) {
	ca, err := NewCosigner(caID, "oid/1.3.6.1.4.1.32473.2.0.42", testSigner(t))
	if err != nil {
		t.Fatalf("NewCosigner: %s", err)
	}
	v, err := NewVerifier(caID, testPubKey(t))
	if err != nil {
		t.Fatalf("NewVerifier: %s", err)
	}

	timestamp := time.Unix(123456789, 0)
	emptyHash := subtree.MTH(nil)
	signatureLine, err := ca.CosignCheckpoint(tlog.Tree{N: 0, Hash: emptyHash}, timestamp)
	if err != nil {
		t.Fatalf("CosignCheckpoint over an empty tree: %s", err)
	}
	_, _, err = checkpoint.Open(signedNote(ca.origin+"\n0\n"+emptyHash.String()+"\n", signatureLine), v)
	if err != nil {
		t.Errorf("checkpoint.Open(): got %v, want nil err", err)
	}
}

// TestVerifySubtreeSignatureRejects checks that a subtree signature is bound
// to its subtree's start and that only a valid subtree verifies.
func TestVerifySubtreeSignatureRejects(t *testing.T) {
	ca, err := NewCosigner(caID, "oid/1.3.6.1.4.1.32473.2.0.42", testSigner(t))
	if err != nil {
		t.Fatalf("NewCosigner: %s", err)
	}
	hash := tlog.Hash{1, 2, 3}
	signature, err := ca.CosignSubtree(1024, 1536, hash)
	if err != nil {
		t.Fatalf("CosignSubtree: %s", err)
	}
	v, err := NewVerifier(caID, testPubKey(t))
	if err != nil {
		t.Fatalf("NewVerifier: %s", err)
	}

	cases := []struct {
		name       string
		origin     string
		start, end int64
		hash       tlog.Hash
		signature  []byte
	}{
		{"Different start", ca.origin, 0, 1536, hash, signature},
		{"Invalid subtree", ca.origin, 1025, 1536, hash, signature},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if v.VerifySubtreeSignature(tc.origin, tc.start, tc.end, tc.hash, tc.signature) {
				t.Error("VerifySubtreeSignature = true, want false")
			}
		})
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
	ca, err := NewCosigner(caID, "oid/1.3.6.1.4.1.32473.2.0.42", shortSigner{pubKey: testPubKey(t)})
	if err != nil {
		t.Fatalf("NewCosigner: %s", err)
	}
	_, err = ca.CosignCheckpoint(tlog.Tree{N: 1}, time.Now())
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
	ca, err := NewCosigner(caID, "oid/1.3.6.1.4.1.32473.2.0.42", errSigner{pubKey: testPubKey(t)})
	if err != nil {
		t.Fatalf("NewCosigner: %s", err)
	}
	_, err = ca.CosignCheckpoint(tlog.Tree{N: 1}, time.Now())
	if err == nil {
		t.Error("CosignCheckpoint with a failing signer = nil error, want error")
	}
}

// TestCheckpointCosignature checks that the cosignature extracted from an
// opened note carries the raw signature.
func TestCheckpointCosignature(t *testing.T) {
	ca, err := NewCosigner(caID, "oid/1.3.6.1.4.1.32473.2.0.42", testSigner(t))
	if err != nil {
		t.Fatalf("NewCosigner: %s", err)
	}
	text := ca.origin + "\n20852163\n" + exampleHashB64 + "\n"
	parsed, err := checkpoint.Unmarshal([]byte(text))
	if err != nil {
		t.Fatalf("checkpoint.Unmarshal: %s", err)
	}

	timestamp := time.Unix(123456789, 0)
	signatureLine, err := ca.CosignCheckpoint(parsed.Tree, timestamp)
	if err != nil {
		t.Fatalf("CosignCheckpoint: %s", err)
	}

	v, err := NewVerifier(caID, testPubKey(t))
	if err != nil {
		t.Fatalf("NewVerifier: %s", err)
	}
	_, n, err := checkpoint.Open(signedNote(text, signatureLine), v)
	if err != nil {
		t.Fatalf("checkpoint.Open for the cosigner that signed the note: %s", err)
	}
	extracted, err := v.CheckpointCosignature(n)
	if err != nil {
		t.Fatalf("CheckpointCosignature: %s", err)
	}
	if extracted.Timestamp != 123456789 {
		t.Errorf("CheckpointCosignature timestamp = %d, want 123456789", extracted.Timestamp)
	}
	if !bytes.Equal(extracted.Line, signatureLine) {
		t.Errorf("CheckpointCosignature signature = %q, want %q", extracted.Line, signatureLine)
	}

	// "TWF=" has a padding bit set, so it decodes but is not canonical base64.
	nonCanonical := &note.Note{Text: text, Sigs: []note.Signature{{Name: v.keyName, Hash: v.keyID, Base64: "TWF="}}}
	_, err = v.CheckpointCosignature(nonCanonical)
	if err == nil {
		t.Fatal("CheckpointCosignature accepted a non-canonical signature line")
	}
	if !strings.Contains(err.Error(), "not canonical base64") {
		t.Errorf("CheckpointCosignature with a non-canonical signature line: %s", err)
	}
}

// TestCheckpointCosignatureTimestamped checks that CheckpointCosignature
// returns the cosigner's line and timestamp.
func TestCheckpointCosignatureTimestamped(t *testing.T) {
	ca, err := NewCosigner(caID, "oid/1.3.6.1.4.1.32473.2.0.42", testSigner(t))
	if err != nil {
		t.Fatalf("NewCosigner: %s", err)
	}
	text := ca.origin + "\n20852163\n" + exampleHashB64 + "\n"
	parsed, err := checkpoint.Unmarshal([]byte(text))
	if err != nil {
		t.Fatalf("checkpoint.Unmarshal: %s", err)
	}
	message, err := marshalCheckpointMessage(ca.name, 1_700_000_000, ca.origin, parsed.Tree.N, parsed.Tree.Hash)
	if err != nil {
		t.Fatalf("marshalCheckpointMessage: %s", err)
	}
	signature, err := testSigner(t).Sign(nil, message, nil)
	if err != nil {
		t.Fatalf("Sign: %s", err)
	}
	line, err := ca.SignatureLine(1_700_000_000, signature)
	if err != nil {
		t.Fatalf("SignatureLine: %s", err)
	}

	v, err := NewVerifier(caID, testPubKey(t))
	if err != nil {
		t.Fatalf("NewVerifier: %s", err)
	}
	_, n, err := checkpoint.Open(signedNote(text, line), v)
	if err != nil {
		t.Fatalf("checkpoint.Open for the cosigner that signed the note: %s", err)
	}
	got, err := v.CheckpointCosignature(n)
	if err != nil {
		t.Fatalf("CheckpointCosignature: %s", err)
	}
	if !bytes.Equal(got.Line, line) {
		t.Errorf("CheckpointCosignature line = %q, want the cosigner's line %q", got.Line, line)
	}
	if got.Timestamp != 1_700_000_000 {
		t.Errorf("CheckpointCosignature timestamp = %d, want 1700000000", got.Timestamp)
	}
}

func TestSignatureLineSignatureLen(t *testing.T) {
	ca, err := NewCosigner(caID, "oid/1.3.6.1.4.1.32473.2.0.42", testSigner(t))
	if err != nil {
		t.Fatalf("NewCosigner: %s", err)
	}
	_, err = ca.SignatureLine(123456789, []byte("abced"))
	if err == nil || !strings.Contains(err.Error(), "signature is 5 bytes") {
		t.Errorf("SignatureLine with short signature: got %v, want error containing 'signature is 5 bytes'", err)
	}
}
