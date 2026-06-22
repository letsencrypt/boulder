package checkpoint

import (
	"crypto/rand"
	"slices"
	"testing"

	"golang.org/x/mod/sumdb/note"
)

const exampleHashB64 = "CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I="

// exampleCheckpoint is a tlog-checkpoint note body, including the trailing
// newline and no signature lines.
const exampleCheckpoint = "example.com/behind-the-sofa\n20852163\n" + exampleHashB64 + "\n"

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
		{
			// tlog-checkpoint OR-3: clients MUST NOT assume the origin follows
			// the schema-less-URL recommendation, so spaces and plus signs
			// (banned only in signature-line key names) must be accepted here.
			name:   "Origin not following the URL recommendation",
			text:   "a space and + plus/log\n20852163\n" + exampleHashB64 + "\n",
			origin: "a space and + plus/log",
			size:   20852163,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Parse(tc.text)
			if err != nil {
				t.Fatalf("Parse: %s", err)
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
		// 2^63 overflows the int64 tree sizes used throughout the package; the
		// checkpoint format itself allows a uint64.
		{"Tree size at the int64 ceiling", "example.com/log\n9223372036854775808\n" + exampleHashB64 + "\n"},
		{"Bad base64 hash", "example.com/log\n1\n!!!notbase64!!!\n"},
		{"Non-canonical base64 hash", "example.com/log\n1\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2J=\n"},
		{"Short hash", "example.com/log\n1\nAAAA\n"},
		{"Empty extension line", "example.com/log\n1\n" + exampleHashB64 + "\n\n"},
		// signed-note bans ASCII control characters other than newline. Parse
		// must enforce it itself because it gates Sign on raw bodies that never
		// pass through note.Open.
		{"Carriage return in origin", "example.com/log\r\n1\n" + exampleHashB64 + "\n"},
		{"Invalid UTF-8 in origin", "example.com/\xff\n1\n" + exampleHashB64 + "\n"},
		{"Control character in extension", "example.com/log\n1\n" + exampleHashB64 + "\next\x01ension\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse(tc.text)
			if err == nil {
				t.Error("Parse = nil error, want error")
			}
		})
	}
}

// TestCheckpointMarshal covers the validating serialization path for
// hand-constructed Checkpoints, which String deliberately does not validate.
func TestCheckpointMarshal(t *testing.T) {
	valid, err := Parse(exampleCheckpoint)
	if err != nil {
		t.Fatalf("Parse: %s", err)
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

// TestVerifyCheckpoint covers Verify's open-then-parse happy path and its
// rejection of a note no trusted key signed, using a generic note signer
// (independent of the ML-DSA cosigner, which is exercised under go1.27).
func TestVerifyCheckpoint(t *testing.T) {
	skey, vkey, err := note.GenerateKey(rand.Reader, "example.com/behind-the-sofa")
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

	t.Run("Valid", func(t *testing.T) {
		cp, n, err := Verify(signed, note.VerifierList(verifier))
		if err != nil {
			t.Fatalf("Verify: %s", err)
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
		_, otherVkey, err := note.GenerateKey(rand.Reader, "example.com/behind-the-sofa")
		if err != nil {
			t.Fatalf("GenerateKey: %s", err)
		}
		otherV, err := note.NewVerifier(otherVkey)
		if err != nil {
			t.Fatalf("NewVerifier: %s", err)
		}
		_, _, err = Verify(signed, note.VerifierList(otherV))
		if err == nil {
			t.Error("Verify with wrong key = nil error, want error")
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
	_, _, err = Verify(signed, note.VerifierList(verifier))
	if err == nil {
		t.Error("Verify of a verified non-checkpoint note = nil error, want error")
	}
}
