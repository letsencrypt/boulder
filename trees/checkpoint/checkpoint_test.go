package checkpoint

import (
	"crypto/rand"
	"slices"
	"testing"

	"golang.org/x/mod/sumdb/note"
)

// exampleCheckpoint is a canonical tlog-checkpoint note body the cosignature
// tests sign and verify over.
const exampleHashB64 = "CsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I="

// emptyTreeHashB64 is the RFC 6962 empty-tree hash, SHA-256 of the empty
// string, which is the only valid root hash for tree size 0.
const emptyTreeHashB64 = "47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="

// exampleCheckpoint is a tlog-checkpoint note body, including the trailing
// newline and no signature lines.
const exampleCheckpoint = "example.com/behind-the-sofa\n20852163\n" + exampleHashB64 + "\n"

func TestCheckpointUnmarshalRoundTrip(t *testing.T) {
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
			text:   "example.com/log\n0\n" + emptyTreeHashB64 + "\n",
			origin: "example.com/log",
			size:   0,
		},
		{
			// tlog-checkpoint: clients MUST NOT assume the origin follows the
			// schema-less-URL recommendation, so spaces and plus signs (banned
			// only in signature-line key names) must be accepted here.
			name:   "Origin not following the URL recommendation",
			text:   "a space and + plus/log\n20852163\n" + exampleHashB64 + "\n",
			origin: "a space and + plus/log",
			size:   20852163,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, err := Unmarshal(tc.text)
			if err != nil {
				t.Fatalf("Unmarshal: %s", err)
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
			got, err := c.Marshal()
			if err != nil {
				t.Fatalf("Marshal: %s", err)
			}
			if got != tc.text {
				t.Errorf("Marshal = %q, want %q", got, tc.text)
			}
		})
	}
}

func TestCheckpointUnmarshalRejects(t *testing.T) {
	cases := []struct {
		name string
		text string
	}{
		{"No trailing newline", "example.com/log\n1\n" + exampleHashB64},
		{"Too few lines", "example.com/log\n1\n"},
		{"Empty origin", "\n1\n" + exampleHashB64 + "\n"},
		{"Leading zero size", "example.com/log\n01\n" + exampleHashB64 + "\n"},
		{"Negative size", "example.com/log\n-1\n" + exampleHashB64 + "\n"},
		{"Plus-signed size", "example.com/log\n+1\n" + exampleHashB64 + "\n"},
		{"Minus-signed zero size", "example.com/log\n-0\n" + exampleHashB64 + "\n"},
		{"Non-numeric size", "example.com/log\nx\n" + exampleHashB64 + "\n"},
		{"Size above int64", "example.com/log\n9223372036854775808\n" + exampleHashB64 + "\n"},
		{"Signed note instead of a bare body", "example.com/log\n1\n" + exampleHashB64 + "\n\n— key AAAA\n"},
		{"Bad base64 hash", "example.com/log\n1\n!!!notbase64!!!\n"},
		{"Non-canonical base64 hash", "example.com/log\n1\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2J=\n"},
		{"Carriage return in hash", "example.com/log\n1\nCsUY\rapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I=\n"},
		{"Unpadded hash", "example.com/log\n1\nCsUYapGGPo4dkMgIAUqom/Xajj7h2fB2MPA3j2jxq2I\n"},
		{"Short hash", "example.com/log\n1\nAAAA\n"},
		{"Empty extension line", "example.com/log\n1\n" + exampleHashB64 + "\n\n"},
		{"Carriage return in origin", "example.com/log\r\n1\n" + exampleHashB64 + "\n"},
		{"Invalid UTF-8 in origin", "example.com/\xff\n1\n" + exampleHashB64 + "\n"},
		{"Control character in extension", "example.com/log\n1\n" + exampleHashB64 + "\next\x01ension\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Unmarshal(tc.text)
			if err == nil {
				t.Error("Unmarshal = nil error, want error")
			}
		})
	}
}

// TestCheckpointMarshal covers Marshal's validation of hand-constructed
// Checkpoints, which bypass Unmarshal's checks.
func TestCheckpointMarshal(t *testing.T) {
	valid, err := Unmarshal(exampleCheckpoint)
	if err != nil {
		t.Fatalf("Unmarshal: %s", err)
	}

	t.Run("Valid", func(t *testing.T) {
		got, err := valid.Marshal()
		if err != nil {
			t.Fatalf("Marshal: %s", err)
		}
		if got != exampleCheckpoint {
			t.Errorf("Marshal = %q, want %q", got, exampleCheckpoint)
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
			mutated := tc.mutate(*valid)
			_, err := mutated.Marshal()
			if err == nil {
				t.Error("Marshal = nil error, want error")
			}
		})
	}
}

// TestOpenCheckpoint covers Open's happy path and its rejection of a note no
// trusted key signed, using a generic note signer.
func TestOpenCheckpoint(t *testing.T) {
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
		cp, n, err := Open(signed, note.VerifierList(verifier))
		if err != nil {
			t.Fatalf("Open: %s", err)
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
		_, _, err = Open(signed, note.VerifierList(otherV))
		if err == nil {
			t.Error("Open with wrong key = nil error, want error")
		}
	})
}

// TestOpenRejectsNonCheckpointBody covers the branch where the note signature
// verifies but its body does not parse as a checkpoint.
func TestOpenRejectsNonCheckpointBody(t *testing.T) {
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
	_, _, err = Open(signed, note.VerifierList(verifier))
	if err == nil {
		t.Error("Open of a verified non-checkpoint note = nil error, want error")
	}
}
