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

// Checkpoint represents a tlog-checkpoint note text.
//
// https://c2sp.org/tlog-checkpoint
type Checkpoint struct {
	Origin     string
	Tree       tlog.Tree
	Extensions []string
}

// checkNoteLine reports why line cannot be a signed-note line, or nil.
// signed-note requires note text to be valid UTF-8 with no ASCII control
// characters (those below U+0020) other than newline, and a single line cannot
// contain the newline.
func checkNoteLine(line string) error {
	if !utf8.ValidString(line) {
		return errors.New("not valid UTF-8")
	}
	for _, r := range line {
		if r < 0x20 {
			return errors.New("contains an ASCII control character")
		}
	}
	return nil
}

// Marshal returns the note text, first checking the checkpoint against the
// tlog-checkpoint rules. It returns an error if the checkpoint is invalid.
//
//   - https://c2sp.org/tlog-checkpoint
//   - https://c2sp.org/signed-note
func (c *Checkpoint) Marshal() (string, error) {
	if c.Origin == "" {
		return "", errors.New("empty checkpoint origin")
	}
	err := checkNoteLine(c.Origin)
	if err != nil {
		return "", fmt.Errorf("checkpoint origin: %w", err)
	}
	if c.Tree.N < 0 {
		return "", fmt.Errorf("negative checkpoint tree size %d", c.Tree.N)
	}
	for _, ext := range c.Extensions {
		if ext == "" {
			return "", errors.New("empty checkpoint extension line")
		}
		err := checkNoteLine(ext)
		if err != nil {
			return "", fmt.Errorf("checkpoint extension line: %w", err)
		}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "%s\n%d\n%s\n", c.Origin, c.Tree.N, c.Tree.Hash)
	for _, ext := range c.Extensions {
		b.WriteString(ext)
		b.WriteByte('\n')
	}
	return b.String(), nil
}

// Unmarshal parses a checkpoint note text. The text must not have any signature
// lines. For a signed note, use Open.
//
//   - https://c2sp.org/tlog-checkpoint
//   - https://c2sp.org/signed-note
func Unmarshal(text string) (*Checkpoint, error) {
	if !strings.HasSuffix(text, "\n") {
		return nil, errors.New("checkpoint does not end in newline")
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	if len(lines) < 3 {
		return nil, fmt.Errorf("checkpoint has %d lines, want at least 3", len(lines))
	}

	origin := lines[0]
	if origin == "" {
		return nil, errors.New("empty checkpoint origin")
	}
	err := checkNoteLine(origin)
	if err != nil {
		return nil, fmt.Errorf("checkpoint origin: %w", err)
	}

	size, err := strconv.ParseInt(lines[1], 10, 64)
	if err != nil {
		return nil, fmt.Errorf("checkpoint tree size: %w", err)
	}
	if size < 0 {
		return nil, fmt.Errorf("negative checkpoint tree size %d", size)
	}
	if strconv.FormatInt(size, 10) != lines[1] {
		return nil, errors.New("checkpoint tree size has a leading zero or sign")
	}

	hashBytes, err := base64.StdEncoding.DecodeString(lines[2])
	if err != nil {
		return nil, fmt.Errorf("checkpoint root hash: %w", err)
	}
	if len(hashBytes) != tlog.HashSize {
		return nil, fmt.Errorf("checkpoint root hash is %d bytes, want %d", len(hashBytes), tlog.HashSize)
	}
	if base64.StdEncoding.EncodeToString(hashBytes) != lines[2] {
		return nil, errors.New("checkpoint root hash is not canonical base64")
	}
	var hash tlog.Hash
	copy(hash[:], hashBytes)

	extensions := lines[3:]
	for _, ext := range extensions {
		if ext == "" {
			return nil, errors.New("empty checkpoint extension line")
		}
		err := checkNoteLine(ext)
		if err != nil {
			return nil, fmt.Errorf("checkpoint extension line: %w", err)
		}
	}
	return &Checkpoint{Origin: origin, Tree: tlog.Tree{N: size, Hash: hash}, Extensions: extensions}, nil
}

// Open opens a signed checkpoint note and parses its text. An error is returned
// if the note is not valid or the signature is not verified by one of the
// verifiers.
//
// https://c2sp.org/signed-note
func Open(signedNote []byte, verifiers note.Verifiers) (*Checkpoint, *note.Note, error) {
	n, err := note.Open(signedNote, verifiers)
	if err != nil {
		return nil, nil, err
	}
	c, err := Unmarshal(n.Text)
	if err != nil {
		return nil, nil, err
	}
	return c, n, nil
}
