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

// Checkpoint represents a tlog-checkpoint note body.
//
// https://c2sp.org/tlog-checkpoint
type Checkpoint struct {
	Origin     string
	Tree       tlog.Tree
	Extensions []string
}

// String returns the note body of the checkpoint. Unlike Marshal, it does not
// validate the checkpoint fields. Call Marshal to validate the fields before
// serializing.
//
// https://c2sp.org/tlog-checkpoint
func (c Checkpoint) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%d\n%s\n", c.Origin, c.Tree.N, c.Tree.Hash)
	for _, ext := range c.Extensions {
		b.WriteString(ext)
		b.WriteByte('\n')
	}
	return b.String()
}

// validNoteLine reports whether s is a valid signed-note line: UTF-8 with no
// control character below U+0020.
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

// Marshal returns the note body, first checking the checkpoint against the
// tlog-checkpoint rules. It returns an error if the checkpoint is invalid.
//
//   - https://c2sp.org/tlog-checkpoint
//   - https://c2sp.org/signed-note
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
	for _, ext := range c.Extensions {
		if ext == "" {
			return "", errors.New("empty checkpoint extension line")
		}
		if !validNoteLine(ext) {
			return "", errors.New("checkpoint extension line contains a control character or invalid UTF-8")
		}
	}
	return c.String(), nil
}

// Parse parses a checkpoint note body. It must not have any signature lines.
// For a signed note, use Open.
//
//   - https://c2sp.org/tlog-checkpoint
//   - https://c2sp.org/signed-note
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
	if !validNoteLine(origin) {
		return Checkpoint{}, errors.New("checkpoint origin contains a control character or invalid UTF-8")
	}

	size, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil || size < 0 || strconv.FormatInt(size, 10) != lines[1] {
		return Checkpoint{}, errors.New("malformed checkpoint tree size")
	}

	hashBytes, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil || len(hashBytes) != tlog.HashSize || base64.StdEncoding.EncodeToString(hashBytes) != lines[2] {
		return Checkpoint{}, errors.New("malformed checkpoint root hash")
	}
	var hash tlog.Hash
	copy(hash[:], hashBytes)

	extensions := lines[3:]
	for _, ext := range extensions {
		if ext == "" {
			return Checkpoint{}, errors.New("empty checkpoint extension line")
		}
		if !validNoteLine(ext) {
			return Checkpoint{}, errors.New("checkpoint extension line contains a control character or invalid UTF-8")
		}
	}
	return Checkpoint{Origin: origin, Tree: tlog.Tree{N: size, Hash: hash}, Extensions: extensions}, nil
}

// Open opens a signed checkpoint note and parses its body. An error is returned
// if the note is not valid or the signature is not verified by one of the
// verifiers.
//
// https://c2sp.org/signed-note
func Open(signedNote []byte, verifiers note.Verifiers) (Checkpoint, *note.Note, error) {
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
