package tlog

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"strings"
	"testing"
	"time"

	"github.com/jmhodges/clock"
	"golang.org/x/mod/sumdb/note"
)

const cosignerName = "mirror.test/m1"

// exampleCheckpoint is a tlog-checkpoint note body, including the trailing
// newline and no signature lines.
const exampleCheckpoint = "example.com/behind-the-sofa\n20852163\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n"

// fixedClock returns a fake clock set to the example cosignature timestamp.
func fixedClock() clock.Clock {
	clk := clock.NewFake()
	clk.Set(time.Unix(1679315147, 0))
	return clk
}

func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func newCosigner(t *testing.T) *Ed25519Cosigner {
	t.Helper()
	c, err := NewEd25519Cosigner(cosignerName, testKey(t), fixedClock())
	if err != nil {
		t.Fatalf("NewEd25519Cosigner: %s", err)
	}
	return c
}

// TestCosignatureKeyID derives SHA-256(name || 0x0A || 0x04 || pubkey)[:4]
// independently from the spec text; no published vector ships a key and ID
// together, and an internal round-trip cannot catch a shared misreading.
func TestCosignatureKeyID(t *testing.T) {
	pub := testKey(t).Public().(ed25519.PublicKey)

	h := sha256.New()
	h.Write([]byte(cosignerName))
	h.Write([]byte{0x0A, 0x04})
	h.Write(pub)
	expect := binary.BigEndian.Uint32(h.Sum(nil)[:4])

	if got := CosignatureKeyID(cosignerName, pub); got != expect {
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

func TestCosignMessageFormat(t *testing.T) {
	got := string(cosignatureMessage(1679315147, []byte(exampleCheckpoint)))
	want := "cosignature/v1\ntime 1679315147\n" + exampleCheckpoint
	if got != want {
		t.Errorf("cosignatureMessage = %q, want %q", got, want)
	}
}

// TestCosignRoundTrip cosigns, parses the resulting note signature line by hand,
// and verifies it, checking the wire layout of the timestamped signature.
func TestCosignRoundTrip(t *testing.T) {
	pub := testKey(t).Public().(ed25519.PublicKey)
	c := newCosigner(t)

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
	if len(idSig) != 4+8+ed25519.SignatureSize {
		t.Fatalf("signature is %d bytes, want %d", len(idSig), 4+8+ed25519.SignatureSize)
	}
	gotID := binary.BigEndian.Uint32(idSig[:4])
	if gotID != CosignatureKeyID(cosignerName, pub) {
		t.Errorf("embedded key ID = %d, want %d", gotID, CosignatureKeyID(cosignerName, pub))
	}

	ts, ok := VerifyCosignature(pub, []byte(exampleCheckpoint), idSig[4:])
	if !ok {
		t.Fatal("VerifyCosignature rejected a valid cosignature")
	}
	if ts != 1679315147 {
		t.Errorf("timestamp = %d, want 1679315147", ts)
	}
	_, ok = VerifyCosignature(pub, []byte("example.com/other\n1\nAAAA\n"), idSig[4:])
	if ok {
		t.Error("VerifyCosignature accepted a cosignature over the wrong checkpoint")
	}
}

// TestCosignerNoteRoundTrip drives the cosigner and verifier through the real
// note.Sign/note.Open, confirming Ed25519Cosigner is a usable note.Signer and
// CosignatureVerifier a usable note.Verifier.
func TestCosignerNoteRoundTrip(t *testing.T) {
	pub := testKey(t).Public().(ed25519.PublicKey)

	signed, err := note.Sign(&note.Note{Text: exampleCheckpoint}, newCosigner(t))
	if err != nil {
		t.Fatalf("note.Sign: %s", err)
	}
	v, err := NewCosignatureVerifier(cosignerName, pub)
	if err != nil {
		t.Fatalf("NewCosignatureVerifier: %s", err)
	}
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

func TestCosignedBy(t *testing.T) {
	pub := testKey(t).Public().(ed25519.PublicKey)
	signed, err := note.Sign(&note.Note{Text: exampleCheckpoint}, newCosigner(t))
	if err != nil {
		t.Fatalf("note.Sign: %s", err)
	}
	v, err := NewCosignatureVerifier(cosignerName, pub)
	if err != nil {
		t.Fatalf("NewCosignatureVerifier: %s", err)
	}
	n, err := note.Open(signed, note.VerifierList(v))
	if err != nil {
		t.Fatalf("note.Open: %s", err)
	}

	if !CosignedBy(n, v) {
		t.Error("CosignedBy = false for the cosigner that signed the note")
	}
	other, err := NewCosignatureVerifier("other.test/x", pub)
	if err != nil {
		t.Fatalf("NewCosignatureVerifier: %s", err)
	}
	if CosignedBy(n, other) {
		t.Error("CosignedBy = true for a cosigner that did not sign the note")
	}
}

func TestVerifyCosignatureRejectsMalformedSig(t *testing.T) {
	pub := testKey(t).Public().(ed25519.PublicKey)
	for _, length := range []int{0, 7, 8, 8 + ed25519.SignatureSize - 1, 8 + ed25519.SignatureSize + 1} {
		_, ok := VerifyCosignature(pub, []byte(exampleCheckpoint), make([]byte, length))
		if ok {
			t.Errorf("VerifyCosignature accepted a %d-byte signature", length)
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
		_, err := c.Cosign([]byte(tc.body))
		if err == nil {
			t.Errorf("Cosign(%s) = nil error, want error", tc.name)
		}
	}
}

func TestConstructorsRejectBadKey(t *testing.T) {
	_, err := NewEd25519Cosigner(cosignerName, ed25519.PrivateKey("short"), clock.NewFake())
	if err == nil {
		t.Error("NewEd25519Cosigner with a short key = nil error, want error")
	}
	_, err = NewCosignatureVerifier(cosignerName, ed25519.PublicKey("short"))
	if err == nil {
		t.Error("NewCosignatureVerifier with a short key = nil error, want error")
	}
}

// TestConstructorsRejectBadName enforces signed-note's key name rules; the
// constructors are the only gate since Cosign builds lines by hand.
func TestConstructorsRejectBadName(t *testing.T) {
	key := testKey(t)
	pub := key.Public().(ed25519.PublicKey)
	for _, name := range []string{
		"",
		"has space",
		"has\ttab",
		"has+plus",
		"bad\xffutf8",
	} {
		_, err := NewEd25519Cosigner(name, key, clock.NewFake())
		if err == nil {
			t.Errorf("NewEd25519Cosigner(%q) = nil error, want error", name)
		}
		_, err = NewCosignatureVerifier(name, pub)
		if err == nil {
			t.Errorf("NewCosignatureVerifier(%q) = nil error, want error", name)
		}
	}
}

// TestVerifyCosignatureRejectsOversizeTimestamp: even a correctly-signed
// timestamped_signature is rejected when its timestamp exceeds the spec's
// 2^63-1 bound.
func TestVerifyCosignatureRejectsOversizeTimestamp(t *testing.T) {
	key := testKey(t)
	pub := key.Public().(ed25519.PublicKey)

	for _, ts := range []uint64{1 << 63, ^uint64(0)} {
		sig := ed25519.Sign(key, cosignatureMessage(ts, []byte(exampleCheckpoint)))
		timestamped := make([]byte, 8+ed25519.SignatureSize)
		binary.BigEndian.PutUint64(timestamped[:8], ts)
		copy(timestamped[8:], sig)

		_, ok := VerifyCosignature(pub, []byte(exampleCheckpoint), timestamped)
		if ok {
			t.Errorf("VerifyCosignature accepted timestamp %d > 2^63-1", ts)
		}
	}

	// The boundary value 2^63-1 is conformant and must verify.
	ts := uint64(1<<63 - 1)
	sig := ed25519.Sign(key, cosignatureMessage(ts, []byte(exampleCheckpoint)))
	timestamped := make([]byte, 8+ed25519.SignatureSize)
	binary.BigEndian.PutUint64(timestamped[:8], ts)
	copy(timestamped[8:], sig)
	got, ok := VerifyCosignature(pub, []byte(exampleCheckpoint), timestamped)
	if !ok || got != ts {
		t.Errorf("VerifyCosignature(ts=2^63-1) = (%d, %v), want (%d, true)", got, ok, ts)
	}
}

// TestSignRejectsPreEpochClock: a pre-epoch clock would wrap into the
// forbidden timestamp range, so Sign must refuse.
func TestSignRejectsPreEpochClock(t *testing.T) {
	clk := clock.NewFake()
	clk.Set(time.Unix(-1, 0))
	c, err := NewEd25519Cosigner(cosignerName, testKey(t), clk)
	if err != nil {
		t.Fatalf("NewEd25519Cosigner: %s", err)
	}
	_, err = c.Sign([]byte(exampleCheckpoint))
	if err == nil {
		t.Error("Sign with a pre-epoch clock = nil error, want error")
	}
}

// TestCosignatureLine: a stored blob plus name and public key must
// reproduce the original signature line byte for byte, and the reassembled
// note must open.
func TestCosignatureLine(t *testing.T) {
	key := testKey(t)
	pub := key.Public().(ed25519.PublicKey)
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
	v, err := NewCosignatureVerifier(cosignerName, pub)
	if err != nil {
		t.Fatalf("NewCosignatureVerifier: %s", err)
	}
	signed := []byte(exampleCheckpoint + "\n" + got)
	n, err := note.Open(signed, note.VerifierList(v))
	if err != nil {
		t.Fatalf("note.Open of a reassembled note: %s", err)
	}
	if !CosignedBy(n, v) {
		t.Error("CosignedBy = false for a reassembled note")
	}
}

func TestCosignatureLineRejects(t *testing.T) {
	pub := testKey(t).Public().(ed25519.PublicKey)
	good := make([]byte, 8+ed25519.SignatureSize)

	oversize := make([]byte, 8+ed25519.SignatureSize)
	binary.BigEndian.PutUint64(oversize[:8], 1<<63)

	cases := []struct {
		name   string
		signer string
		pub    ed25519.PublicKey
		sig    []byte
	}{
		{"Bad name", "has space", pub, good},
		{"Short key", cosignerName, pub[:5], good},
		{"Short signature", cosignerName, pub, good[:10]},
		{"Oversize timestamp", cosignerName, pub, oversize},
	}
	for _, tc := range cases {
		_, err := CosignatureLine(tc.signer, tc.pub, tc.sig)
		if err == nil {
			t.Errorf("%s: want error", tc.name)
		}
	}
}

// TestCosignature: the blob extracted from an opened note must verify on
// its own.
func TestCosignature(t *testing.T) {
	pub := testKey(t).Public().(ed25519.PublicKey)
	signed, err := note.Sign(&note.Note{Text: exampleCheckpoint}, newCosigner(t))
	if err != nil {
		t.Fatalf("note.Sign: %s", err)
	}
	v, err := NewCosignatureVerifier(cosignerName, pub)
	if err != nil {
		t.Fatalf("NewCosignatureVerifier: %s", err)
	}
	n, err := note.Open(signed, note.VerifierList(v))
	if err != nil {
		t.Fatalf("note.Open: %s", err)
	}

	blob, ok := Cosignature(n, v)
	if !ok {
		t.Fatal("Cosignature = false for the cosigner that signed the note")
	}
	ts, ok := VerifyCosignature(pub, []byte(exampleCheckpoint), blob)
	if !ok {
		t.Fatal("VerifyCosignature rejected an extracted cosignature")
	}
	if ts != 1679315147 {
		t.Errorf("timestamp = %d, want 1679315147", ts)
	}

	other, err := NewCosignatureVerifier("other.test/x", pub)
	if err != nil {
		t.Fatalf("NewCosignatureVerifier: %s", err)
	}
	_, ok = Cosignature(n, other)
	if ok {
		t.Error("Cosignature = true for a cosigner that did not sign the note")
	}
}

// TestCosignatureRejectsForeignFormat: a signature verified by x/mod's
// standard signer (alg 0x01, 64-byte payload) satisfies CosignedBy but is
// not a timestamped_signature, so Cosignature must refuse it.
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
	n, err := note.Open([]byte(signed), note.VerifierList(verifier))
	if err != nil {
		t.Fatalf("note.Open: %s", err)
	}

	if !CosignedBy(n, verifier) {
		t.Error("CosignedBy = false for the standard signer that signed the note")
	}
	if _, ok := Cosignature(n, verifier); ok {
		t.Error("Cosignature = true for a non-cosignature-format signature")
	}
}
