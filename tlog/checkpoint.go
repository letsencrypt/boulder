package tlog

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/mod/sumdb/note"
	xtlog "golang.org/x/mod/sumdb/tlog"
)

// Checkpoint is a parsed tlog-checkpoint note body. Hand-constructed values
// are unvalidated; serialize them with Marshal. ParseCheckpoint only returns
// values satisfying the tlog-checkpoint rules.
type Checkpoint struct {
	Origin     string
	Tree       xtlog.Tree
	Extensions []string
}

// String returns the tlog-checkpoint note body, including the trailing
// newline and no signature lines. It does not validate c; producers should
// use Marshal.
func (c Checkpoint) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%d\n%s\n", c.Origin, c.Tree.N, c.Tree.Hash)
	for _, e := range c.Extensions {
		b.WriteString(e)
		b.WriteByte('\n')
	}
	return b.String()
}

// Marshal validates c against the structural tlog-checkpoint rules and
// returns the canonical note body; the encoding rules hold by construction
// in String.
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

// validNoteLine reports whether s can appear as one line of a signed note:
// valid UTF-8 with no ASCII control characters (per signed-note), including
// no newline, since s is a single line.
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

// ParseCheckpoint parses a tlog-checkpoint note body. It rejects
// non-canonical encodings such as a leading-zero tree size, so parsing then
// String round-trips exactly. Tree sizes at or above 2^63 are rejected as
// unrepresentable in the int64 sizes used throughout.
func ParseCheckpoint(text string) (Checkpoint, error) {
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
	// note.Open enforces the character rules on notes it parses, but
	// ParseCheckpoint also gates Ed25519Cosigner.Sign on raw bodies, which
	// would otherwise cosign bodies no conformant note parser accepts.
	if !validNoteLine(origin) {
		return Checkpoint{}, errors.New("checkpoint origin contains a control character or invalid UTF-8")
	}

	n, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil || n < 0 || strconv.FormatInt(n, 10) != lines[1] {
		return Checkpoint{}, errors.New("malformed checkpoint tree size")
	}

	hb, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(hb) != xtlog.HashSize || base64.StdEncoding.EncodeToString(hb) != lines[2] {
		return Checkpoint{}, errors.New("malformed checkpoint root hash")
	}
	var hash xtlog.Hash
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
	if len(extensions) == 0 {
		extensions = nil
	}

	return Checkpoint{Origin: origin, Tree: xtlog.Tree{N: n, Hash: hash}, Extensions: extensions}, nil
}

// VerifyCheckpoint opens a signed checkpoint note against the given verifiers
// and parses its body. It returns the opened note so the caller can inspect
// which signatures verified.
//
// Known upstream divergence: note.Open skips a duplicate (name, key ID)
// signature before verifying it, so a note carrying a valid and an invalid
// signature from the same known key opens, against signed-note's SHOULD
// reject.
func VerifyCheckpoint(signedNote []byte, verifiers note.Verifiers) (Checkpoint, *note.Note, error) {
	n, err := note.Open(signedNote, verifiers)
	if err != nil {
		return Checkpoint{}, nil, err
	}
	c, err := ParseCheckpoint(n.Text)
	if err != nil {
		return Checkpoint{}, nil, err
	}
	return c, n, nil
}
