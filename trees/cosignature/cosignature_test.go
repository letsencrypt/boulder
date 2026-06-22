//go:build go1.27

package cosignature

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"github.com/letsencrypt/boulder/trees/checkpoint"
	"golang.org/x/mod/sumdb/note"
)

const cosignerName = "mirror.test/m1"

// exampleCheckpoint is a canonical tlog-checkpoint note body the cosignature
// tests sign and verify over.
const exampleHashB64 = "CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I="
const exampleCheckpoint = "example.com/behind-the-sofa\n20852163\n" + exampleHashB64 + "\n"

// fixedClock returns a fake clock set to a representative cosignature
// timestamp.
func fixedClock() clock.Clock {
	clk := clock.NewFake()
	clk.Set(time.Unix(1679315147, 0))
	return clk
}

// testKey returns a deterministic ML-DSA-44 key, so cosignature tests are
// reproducible.
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

func testPub(t *testing.T) *mldsa.PublicKey {
	t.Helper()
	return testKey(t).PublicKey()
}

func newCosigner(t *testing.T) *MLDSACosigner {
	t.Helper()
	c, err := NewMLDSACosigner(cosignerName, testKey(t), fixedClock())
	if err != nil {
		t.Fatalf("NewMLDSACosigner: %s", err)
	}
	return c
}

func newVerifier(t *testing.T) *MLDSACosignatureVerifier {
	t.Helper()
	v, err := NewMLDSACosignatureVerifier(cosignerName, testPub(t))
	if err != nil {
		t.Fatalf("NewMLDSACosignatureVerifier: %s", err)
	}
	return v
}

// TestCosignatureKeyID derives SHA-256(name || 0x0A || 0x06 || pubkey)[:4]
// independently from the spec text. No published vector ships a key and ID
// together, and an internal round-trip cannot catch a shared misreading.
func TestCosignatureKeyID(t *testing.T) {
	pub := testPub(t)

	h := sha256.New()
	h.Write([]byte(cosignerName))
	h.Write([]byte{0x0A, 0x06})
	h.Write(pub.Bytes())
	expect := binary.BigEndian.Uint32(h.Sum(nil)[:4])

	got := CosignatureKeyID(cosignerName, pub)
	if got != expect {
		t.Errorf("CosignatureKeyID = %#x, want %#x", got, expect)
	}

	c := newCosigner(t)
	if c.KeyHash() != expect {
		t.Errorf("KeyHash() = %#x, want %#x", c.KeyHash(), expect)
	}
	if c.Name() != cosignerName {
		t.Errorf("Name() = %q, want %q", c.Name(), cosignerName)
	}
}

// TestSignIsDeterministic: cosigning the same checkpoint twice yields identical
// bytes, so a persisted cosignature and a re-derived one always match.
func TestSignIsDeterministic(t *testing.T) {
	c := newCosigner(t)
	a, err := c.Sign([]byte(exampleCheckpoint))
	if err != nil {
		t.Fatalf("Sign: %s", err)
	}
	b, err := c.Sign([]byte(exampleCheckpoint))
	if err != nil {
		t.Fatalf("Sign: %s", err)
	}
	if string(a) != string(b) {
		t.Error("Sign produced different bytes for the same checkpoint")
	}
}

// TestCosignRoundTrip cosigns, parses the resulting note signature line by
// hand, and verifies it, checking the wire layout of the timestamped signature.
func TestCosignRoundTrip(t *testing.T) {
	c := newCosigner(t)
	v := newVerifier(t)

	line, err := c.Cosign([]byte(exampleCheckpoint))
	if err != nil {
		t.Fatalf("Cosign: %s", err)
	}
	if !strings.HasPrefix(line, noteSigPrefix+cosignerName+" ") {
		t.Errorf("line %q has unexpected prefix", line)
	}
	if !strings.HasSuffix(line, "\n") {
		t.Errorf("line %q is missing a trailing newline", line)
	}

	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) != 3 || fields[1] != cosignerName {
		t.Fatalf("line fields = %q, want [— %s <sig>]", fields, cosignerName)
	}
	idSig, err := base64.StdEncoding.DecodeString(fields[2])
	if err != nil {
		t.Fatalf("decoding signature: %s", err)
	}
	if len(idSig) != 4+timestampedSigSize {
		t.Fatalf("signature is %d bytes, want %d", len(idSig), 4+timestampedSigSize)
	}
	gotID := binary.BigEndian.Uint32(idSig[:4])
	if gotID != c.KeyHash() {
		t.Errorf("embedded key ID = %d, want %d", gotID, c.KeyHash())
	}
	ts := binary.BigEndian.Uint64(idSig[4:12])
	if ts != 1679315147 {
		t.Errorf("embedded timestamp = %d, want 1679315147", ts)
	}

	if !v.Verify([]byte(exampleCheckpoint), idSig[4:]) {
		t.Fatal("Verify rejected a valid cosignature")
	}
	if v.Verify([]byte("example.com/other\n1\n"+exampleHashB64+"\n"), idSig[4:]) {
		t.Error("Verify accepted a cosignature over the wrong checkpoint")
	}
}

// TestCosignerNoteRoundTrip drives the cosigner and verifier through the real
// note.Sign/note.Open, confirming MLDSACosigner is a usable note.Signer and
// MLDSACosignatureVerifier a usable note.Verifier.
func TestCosignerNoteRoundTrip(t *testing.T) {
	signed, err := note.Sign(&note.Note{Text: exampleCheckpoint}, newCosigner(t))
	if err != nil {
		t.Fatalf("note.Sign: %s", err)
	}
	v := newVerifier(t)
	n, err := note.Open(signed, note.VerifierList(v))
	if err != nil {
		t.Fatalf("note.Open: %s", err)
	}
	if n.Text != exampleCheckpoint {
		t.Errorf("note text = %q, want %q", n.Text, exampleCheckpoint)
	}
	if len(n.Sigs) != 1 || n.Sigs[0].Name != cosignerName {
		t.Errorf("Sigs = %+v, want one from %q", n.Sigs, cosignerName)
	}
}

func TestVerifyRejectsMalformedSig(t *testing.T) {
	v := newVerifier(t)
	for _, length := range []int{0, 7, 8, timestampedSigSize - 1, timestampedSigSize + 1} {
		if v.Verify([]byte(exampleCheckpoint), make([]byte, length)) {
			t.Errorf("Verify accepted a %d-byte signature", length)
		}
	}
}

func TestCosignRefusesNonCanonical(t *testing.T) {
	c := newCosigner(t)
	cases := []struct {
		name string
		body string
	}{
		{"Not a checkpoint", "not a checkpoint"},
		{"Leading zero size", "example.com/log\n01\n" + exampleHashB64 + "\n"},
		{"No trailing newline", "example.com/log\n1\n" + exampleHashB64},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.Cosign([]byte(tc.body))
			if err == nil {
				t.Error("Cosign = nil error, want error")
			}
		})
	}
}

func TestConstructorsRejectBadKey(t *testing.T) {
	// An ML-DSA-65 key is the wrong size for an ML-DSA-44 cosigner.
	wrong, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("GenerateKey(MLDSA65): %s", err)
	}
	_, err = NewMLDSACosigner(cosignerName, wrong, clock.NewFake())
	if err == nil {
		t.Error("NewMLDSACosigner with a non-ML-DSA-44 key = nil error, want error")
	}
	_, err = NewMLDSACosignatureVerifier(cosignerName, wrong.PublicKey())
	if err == nil {
		t.Error("NewMLDSACosignatureVerifier with a non-ML-DSA-44 key = nil error, want error")
	}
}

// TestConstructorsRejectBadName enforces signed-note's key name rules. The
// constructors are the only gate since Cosign builds lines by hand.
func TestConstructorsRejectBadName(t *testing.T) {
	key := testKey(t)
	pub := testPub(t)
	for _, name := range []string{
		"",
		"has space",
		"has\ttab",
		"has+plus",
		"bad\xffutf8",
		strings.Repeat("a", 256),
	} {
		_, err := NewMLDSACosigner(name, key, clock.NewFake())
		if err == nil {
			t.Errorf("NewMLDSACosigner(%q) = nil error, want error", name)
		}
		_, err = NewMLDSACosignatureVerifier(name, pub)
		if err == nil {
			t.Errorf("NewMLDSACosignatureVerifier(%q) = nil error, want error", name)
		}
	}
}

// TestVerifyRejectsOversizeTimestamp: even a correctly-signed
// timestamped_signature is rejected when its timestamp exceeds the spec's
// 2^63-1 bound.
func TestVerifyRejectsOversizeTimestamp(t *testing.T) {
	key := testKey(t)
	v := newVerifier(t)
	parsed, err := checkpoint.Parse(exampleCheckpoint)
	if err != nil {
		t.Fatalf("ParseCheckpoint: %s", err)
	}

	timestamped := func(ts uint64) []byte {
		msg, err := marshalCosignedMessage(cosignerName, ts, parsed.Origin, parsed.Tree.N, parsed.Tree.Hash)
		if err != nil {
			t.Fatalf("marshalCosignedMessage: %s", err)
		}
		mlsig, err := key.SignDeterministic(msg, &mldsa.Options{})
		if err != nil {
			t.Fatalf("Sign: %s", err)
		}
		out := make([]byte, timestampedSigSize)
		binary.BigEndian.PutUint64(out[:8], ts)
		copy(out[8:], mlsig)
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

// TestSignRejectsPreEpochClock: a pre-epoch clock would wrap into the forbidden
// timestamp range, so Sign must refuse.
func TestSignRejectsPreEpochClock(t *testing.T) {
	clk := clock.NewFake()
	clk.Set(time.Unix(-1, 0))
	c, err := NewMLDSACosigner(cosignerName, testKey(t), clk)
	if err != nil {
		t.Fatalf("NewMLDSACosigner: %s", err)
	}
	_, err = c.Sign([]byte(exampleCheckpoint))
	if err == nil {
		t.Error("Sign with a pre-epoch clock = nil error, want error")
	}
}

// TestCosignatureLine: a stored blob plus name and public key must reproduce
// the original signature line byte for byte, and the reassembled note must
// open.
func TestCosignatureLine(t *testing.T) {
	pub := testPub(t)
	c := newCosigner(t)

	// The blob a consumer would have persisted.
	blob, err := c.Sign([]byte(exampleCheckpoint))
	if err != nil {
		t.Fatalf("Sign: %s", err)
	}
	want, err := c.Cosign([]byte(exampleCheckpoint))
	if err != nil {
		t.Fatalf("Cosign: %s", err)
	}

	got, err := CosignatureLine(cosignerName, pub, blob)
	if err != nil {
		t.Fatalf("CosignatureLine: %s", err)
	}
	if got != want {
		t.Errorf("CosignatureLine = %q, want %q", got, want)
	}

	// The reassembled signed note opens against the matching verifier.
	v := newVerifier(t)
	signed := []byte(exampleCheckpoint + "\n" + got)
	n, err := note.Open(signed, note.VerifierList(v))
	if err != nil {
		t.Fatalf("note.Open of a reassembled note: %s", err)
	}
	_, ok := Cosignature(n, v)
	if !ok {
		t.Error("Cosignature = false for a reassembled note")
	}
}

func TestCosignatureLineRejects(t *testing.T) {
	pub := testPub(t)
	wrong, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("GenerateKey(MLDSA65): %s", err)
	}
	good := make([]byte, timestampedSigSize)

	oversize := make([]byte, timestampedSigSize)
	binary.BigEndian.PutUint64(oversize[:8], 1<<63)

	cases := []struct {
		name   string
		signer string
		pub    *mldsa.PublicKey
		sig    []byte
	}{
		{"Bad name", "has space", pub, good},
		{"Wrong key type", cosignerName, wrong.PublicKey(), good},
		{"Short signature", cosignerName, pub, good[:10]},
		{"Oversize timestamp", cosignerName, pub, oversize},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := CosignatureLine(tc.signer, tc.pub, tc.sig)
			if err == nil {
				t.Error("want error")
			}
		})
	}
}

// TestCosignature: the blob extracted from an opened note must verify on its
// own.
func TestCosignature(t *testing.T) {
	signed, err := note.Sign(&note.Note{Text: exampleCheckpoint}, newCosigner(t))
	if err != nil {
		t.Fatalf("note.Sign: %s", err)
	}
	v := newVerifier(t)
	n, err := note.Open(signed, note.VerifierList(v))
	if err != nil {
		t.Fatalf("note.Open: %s", err)
	}

	blob, ok := Cosignature(n, v)
	if !ok {
		t.Fatal("Cosignature = false for the cosigner that signed the note")
	}
	if !v.Verify([]byte(exampleCheckpoint), blob) {
		t.Fatal("Verify rejected an extracted cosignature")
	}

	other, err := NewMLDSACosignatureVerifier("other.test/x", testPub(t))
	if err != nil {
		t.Fatalf("NewMLDSACosignatureVerifier: %s", err)
	}
	_, dup := Cosignature(n, other)
	if dup {
		t.Error("Cosignature = true for a cosigner that did not sign the note")
	}
}

// TestCosignatureRejectsForeignFormat: a signature verified by x/mod's standard
// signer (alg 0x01, 64-byte payload) is not a timestamped_signature, so
// Cosignature must refuse it even though the note opened.
func TestCosignatureRejectsForeignFormat(t *testing.T) {
	skey, vkey, err := note.GenerateKey(rand.Reader, "log.example")
	if err != nil {
		t.Fatalf("GenerateKey: %s", err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatalf("NewSigner: %s", err)
	}
	signed, err := note.Sign(&note.Note{Text: exampleCheckpoint}, signer)
	if err != nil {
		t.Fatalf("note.Sign: %s", err)
	}
	verifier, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatalf("NewVerifier: %s", err)
	}
	n, err := note.Open(signed, note.VerifierList(verifier))
	if err != nil {
		t.Fatalf("note.Open: %s", err)
	}

	if len(n.Sigs) != 1 {
		t.Fatalf("Sigs = %+v, want the standard signer's verified signature", n.Sigs)
	}
	_, ok := Cosignature(n, verifier)
	if ok {
		t.Error("Cosignature = true for a non-cosignature-format signature")
	}
}
