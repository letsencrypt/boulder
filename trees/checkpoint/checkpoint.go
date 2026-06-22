package checkpoint

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// Checkpoint is a tlog-checkpoint note body. To produce a body to sign, build
// one and call String, or Marshal if you want the fields checked. To consume a
// body, take one back from Parse or Verify. A hand-built value carries no
// guarantees until you Marshal it. A value from Parse or Verify already
// satisfies the tlog-checkpoint rules.
//
// https://c2sp.org/tlog-checkpoint
type Checkpoint struct {
	// Origin names the log.
	Origin string
	Tree   tlog.Tree
	// Extensions are the optional trailing note lines after the root hash, in
	// order. Leave nil when there are none.
	Extensions []string
}

// String returns the canonical note body to sign. The trailing newline is
// included and no signature lines are. It does not validate c. Call Marshal
// when you want the fields checked first.
func (c Checkpoint) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%d\n%s\n", c.Origin, c.Tree.N, c.Tree.Hash)
	for _, e := range c.Extensions {
		b.WriteString(e)
		b.WriteByte('\n')
	}
	return b.String()
}

// validNoteLine reports whether s can appear as one line of a signed note:
// valid UTF-8 with no ASCII control characters (per signed-note), including no
// newline, since s is a single line.
func validNoteLine(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 {
			return false
		}
	}
	return true
}

// Marshal returns the same body as String but first checks c against the
// tlog-checkpoint rules, returning an error if a field is out of range.
func (c Checkpoint) Marshal() (string, error) {
	if c.Origin == "" {
		return "", errors.New("empty checkpoint origin")
	}
	if !validNoteLine(c.Origin) {
		return "", errors.New("checkpoint origin contains a control character or invalid UTF-8")
	}
	if c.Tree.N < 0 {
		return "", fmt.Errorf("negative checkpoint tree size %d", c.Tree.N)
	}
	for _, e := range c.Extensions {
		if e == "" {
			return "", errors.New("empty checkpoint extension line")
		}
		if !validNoteLine(e) {
			return "", errors.New("checkpoint extension line contains a control character or invalid UTF-8")
		}
	}
	return c.String(), nil
}

// Parse turns a note body into a Checkpoint. The body must be the note text
// only, with no signature lines. For a signed note, use Verify.
func Parse(text string) (Checkpoint, error) {
	if !strings.HasSuffix(text, "\n") {
		return Checkpoint{}, errors.New("checkpoint does not end in newline")
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) < 3 {
		return Checkpoint{}, errors.New("checkpoint has too few lines")
	}

	origin := lines[0]
	if origin == "" {
		return Checkpoint{}, errors.New("empty checkpoint origin")
	}
	// note.Open already enforces the character rules, but a cosigner gates signing
	// on Parse of a raw body that never reaches note.Open, so Parse enforces them
	// too, refusing bodies no conformant note parser accepts.
	if !validNoteLine(origin) {
		return Checkpoint{}, errors.New("checkpoint origin contains a control character or invalid UTF-8")
	}

	n, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil || n < 0 || strconv.FormatInt(n, 10) != lines[1] {
		return Checkpoint{}, errors.New("malformed checkpoint tree size")
	}

	hb, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(hb) != tlog.HashSize || base64.StdEncoding.EncodeToString(hb) != lines[2] {
		return Checkpoint{}, errors.New("malformed checkpoint root hash")
	}
	var hash tlog.Hash
	copy(hash[:], hb)

	extensions := lines[3:]
	for _, e := range extensions {
		if e == "" {
			return Checkpoint{}, errors.New("empty checkpoint extension line")
		}
		if !validNoteLine(e) {
			return Checkpoint{}, errors.New("checkpoint extension line contains a control character or invalid UTF-8")
		}
	}
	// Normalize to nil so parsed values compare equal to hand-built ones.
	if len(extensions) == 0 {
		extensions = nil
	}

	return Checkpoint{Origin: origin, Tree: tlog.Tree{N: n, Hash: hash}, Extensions: extensions}, nil
}

// Verify opens a signed checkpoint note against verifiers and parses its body.
// Pass the full signed note, not just the body. A nil error means the note
// opened with at least one recognized signature, not that every verifier signed,
// so a checkpoint missing an expected cosignature still verifies. The returned
// *note.Note lists the verified signatures in n.Sigs. The caller applies its own
// policy to them: a real one is a valid log signature (possibly any of several
// keys across a rotation) plus the required cosignatures, not a flat
// all-must-sign rule. On error both returns are zero.
//
// Known upstream divergence: note.Open skips a duplicate (name, key ID)
// signature before verifying it, so a note carrying a valid and an invalid
// signature from the same known key opens, against signed-note's SHOULD reject.
func Verify(signedNote []byte, verifiers note.Verifiers) (Checkpoint, *note.Note, error) {
	n, err := note.Open(signedNote, verifiers)
	if err != nil {
		return Checkpoint{}, nil, err
	}
	c, err := Parse(n.Text)
	if err != nil {
		return Checkpoint{}, nil, err
	}
	return c, n, nil
}
