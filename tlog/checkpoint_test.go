package tlog

import (
	"crypto/ed25519"
	"crypto/rand"
	"slices"
	"testing"

	"golang.org/x/mod/sumdb/note"
)

const exampleHashB64 = "CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I="

func TestParseCheckpointRoundTrip(t *testing.T) {
	cases := []struct {
		name       string
		text       string
		origin     string
		size       int64
		extensions []string
	}{
		{
			name:   "No extensions",
			text:   "example.com/log\n20852163\n" + exampleHashB64 + "\n",
			origin: "example.com/log",
			size:   20852163,
		},
		{
			name:       "With extensions",
			text:       "example.com/log\n20852163\n" + exampleHashB64 + "\nfoo extension\nbar extension\n",
			origin:     "example.com/log",
			size:       20852163,
			extensions: []string{"foo extension", "bar extension"},
		},
		{
			name:   "Zero size",
			text:   "example.com/log\n0\n" + exampleHashB64 + "\n",
			origin: "example.com/log",
			size:   0,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := ParseCheckpoint(tc.text)
			if err != nil {
				t.Fatalf("ParseCheckpoint: %s", err)
			}
			if c.Origin != tc.origin {
				t.Errorf("Origin = %q, want %q", c.Origin, tc.origin)
			}
			if c.Tree.N != tc.size {
				t.Errorf("Tree.N = %d, want %d", c.Tree.N, tc.size)
			}
			if !slices.Equal(c.Extensions, tc.extensions) {
				t.Errorf("Extensions = %v, want %v", c.Extensions, tc.extensions)
			}
			got := c.String()
			if got != tc.text {
				t.Errorf("String() = %q, want %q", got, tc.text)
			}
		})
	}
}

func TestParseCheckpointRejects(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{"No trailing newline", "example.com/log\n1\n" + exampleHashB64},
		{"Too few lines", "example.com/log\n1\n"},
		{"Empty origin", "\n1\n" + exampleHashB64 + "\n"},
		{"Leading zero size", "example.com/log\n01\n" + exampleHashB64 + "\n"},
		{"Negative size", "example.com/log\n-1\n" + exampleHashB64 + "\n"},
		{"Non-numeric size", "example.com/log\nx\n" + exampleHashB64 + "\n"},
		{"Bad base64 hash", "example.com/log\n1\n!!!notbase64!!!\n"},
		{"Non-canonical base64 hash", "example.com/log\n1\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2J=\n"},
		{"Short hash", "example.com/log\n1\nAAAA\n"},
		{"Empty extension line", "example.com/log\n1\n" + exampleHashB64 + "\n\n"},
		// signed-note bans ASCII control characters other than newline;
		// ParseCheckpoint must enforce it itself because it gates Sign on
		// raw bodies that never pass through note.Open.
		{"Carriage return in origin", "example.com/log\r\n1\n" + exampleHashB64 + "\n"},
		{"Control character in origin", "example.com/\x01log\n1\n" + exampleHashB64 + "\n"},
		{"Invalid UTF-8 in origin", "example.com/\xff\n1\n" + exampleHashB64 + "\n"},
		{"Control character in extension", "example.com/log\n1\n" + exampleHashB64 + "\next\x01ension\n"},
		{"Carriage return in extension", "example.com/log\n1\n" + exampleHashB64 + "\nextension\r\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseCheckpoint(tc.text)
			if err == nil {
				t.Error("ParseCheckpoint = nil error, want error")
			}
		})
	}
}

// TestCheckpointMarshal covers the validating serialization path for
// hand-constructed Checkpoints, which String deliberately does not validate.
func TestCheckpointMarshal(t *testing.T) {
	valid, err := ParseCheckpoint(exampleCheckpoint)
	if err != nil {
		t.Fatalf("ParseCheckpoint: %s", err)
	}

	t.Run("Valid", func(t *testing.T) {
		got, err := valid.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %s", err)
		}
		if got != valid.String() {
			t.Errorf("Marshal = %q, want %q", got, valid.String())
		}
	})

	cases := []struct {
		name   string
		mutate func(Checkpoint) Checkpoint
	}{
		{"Empty origin", func(c Checkpoint) Checkpoint { c.Origin = ""; return c }},
		{"Newline in origin", func(c Checkpoint) Checkpoint { c.Origin = "two\nlines"; return c }},
		{"Carriage return in origin", func(c Checkpoint) Checkpoint { c.Origin = "cr\rorigin"; return c }},
		{"Invalid UTF-8 in origin", func(c Checkpoint) Checkpoint { c.Origin = "bad\xff"; return c }},
		{"Negative tree size", func(c Checkpoint) Checkpoint { c.Tree.N = -1; return c }},
		{"Empty extension", func(c Checkpoint) Checkpoint { c.Extensions = []string{""}; return c }},
		{"Newline in extension", func(c Checkpoint) Checkpoint { c.Extensions = []string{"two\nlines"}; return c }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.mutate(valid).Marshal()
			if err == nil {
				t.Error("Marshal = nil error, want error")
			}
		})
	}
}

func TestVerifyCheckpoint(t *testing.T) {
	key := testKey(t)
	pub := key.Public().(ed25519.PublicKey)

	c, err := NewEd25519Cosigner(cosignerName, key, fixedClock())
	if err != nil {
		t.Fatalf("NewEd25519Cosigner: %s", err)
	}
	signed, err := note.Sign(&note.Note{Text: exampleCheckpoint}, c)
	if err != nil {
		t.Fatalf("note.Sign: %s", err)
	}
	v, err := NewCosignatureVerifier(cosignerName, pub)
	if err != nil {
		t.Fatalf("NewCosignatureVerifier: %s", err)
	}

	t.Run("Valid", func(t *testing.T) {
		cp, n, err := VerifyCheckpoint(signed, note.VerifierList(v))
		if err != nil {
			t.Fatalf("VerifyCheckpoint: %s", err)
		}
		if cp.Origin != "example.com/behind-the-sofa" {
			t.Errorf("Origin = %q, want %q", cp.Origin, "example.com/behind-the-sofa")
		}
		if cp.Tree.N != 20852163 {
			t.Errorf("Tree.N = %d, want %d", cp.Tree.N, 20852163)
		}
		if len(n.Sigs) != 1 {
			t.Errorf("len(Sigs) = %d, want 1", len(n.Sigs))
		}
	})

	t.Run("Wrong key", func(t *testing.T) {
		otherKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
		otherV, err := NewCosignatureVerifier(cosignerName, otherKey.Public().(ed25519.PublicKey))
		if err != nil {
			t.Fatalf("NewCosignatureVerifier: %s", err)
		}
		_, _, err = VerifyCheckpoint(signed, note.VerifierList(otherV))
		if err == nil {
			t.Error("VerifyCheckpoint with wrong key = nil error, want error")
		}
	})
}

// TestVerifyCheckpointRejectsNonCheckpointBody covers the branch where the note
// signature verifies but its body does not parse as a checkpoint.
func TestVerifyCheckpointRejectsNonCheckpointBody(t *testing.T) {
	skey, vkey, err := note.GenerateKey(rand.Reader, "log.example")
	if err != nil {
		t.Fatalf("GenerateKey: %s", err)
	}
	signer, err := note.NewSigner(skey)
	if err != nil {
		t.Fatalf("NewSigner: %s", err)
	}
	signed, err := note.Sign(&note.Note{Text: "not a checkpoint\n"}, signer)
	if err != nil {
		t.Fatalf("note.Sign: %s", err)
	}
	verifier, err := note.NewVerifier(vkey)
	if err != nil {
		t.Fatalf("NewVerifier: %s", err)
	}
	_, _, err = VerifyCheckpoint(signed, note.VerifierList(verifier))
	if err == nil {
		t.Error("VerifyCheckpoint of a verified non-checkpoint note = nil error, want error")
	}
}

// TestVerifyCheckpointIgnoresUnknownSignatures covers signed-note's
// "verifiers MUST ignore signatures from unknown keys" with a two-cosigner
// note opened by one verifier, the shape of every real exchange.
func TestVerifyCheckpointIgnoresUnknownSignatures(t *testing.T) {
	key := testKey(t)
	pub := key.Public().(ed25519.PublicKey)

	known, err := NewEd25519Cosigner(cosignerName, key, fixedClock())
	if err != nil {
		t.Fatalf("NewEd25519Cosigner: %s", err)
	}
	otherKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	unknown, err := NewEd25519Cosigner("other.test/m2", otherKey, fixedClock())
	if err != nil {
		t.Fatalf("NewEd25519Cosigner: %s", err)
	}
	signed, err := note.Sign(&note.Note{Text: exampleCheckpoint}, known, unknown)
	if err != nil {
		t.Fatalf("note.Sign: %s", err)
	}

	v, err := NewCosignatureVerifier(cosignerName, pub)
	if err != nil {
		t.Fatalf("NewCosignatureVerifier: %s", err)
	}
	cp, n, err := VerifyCheckpoint(signed, note.VerifierList(v))
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
	if !CosignedBy(n, v) {
		t.Error("CosignedBy = false for the known cosigner")
	}
	blob, ok := Cosignature(n, v)
	if !ok {
		t.Fatal("Cosignature = false for the known cosigner")
	}
	if _, ok := VerifyCosignature(pub, []byte(exampleCheckpoint), blob); !ok {
		t.Error("extracted cosignature does not verify")
	}
}
