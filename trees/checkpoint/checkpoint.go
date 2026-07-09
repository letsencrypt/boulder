package checkpoint

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/mod/sumdb/note"
	"golang.org/x/mod/sumdb/tlog"
)

// emptyTreeHash is MTH({}), the RFC 6962 section 2.1 hash of the empty tree:
// SHA-256 of the empty string.
var emptyTreeHash = tlog.Hash(sha256.Sum256(nil))

// Checkpoint represents a tlog-checkpoint note text.
//
// https://c2sp.org/tlog-checkpoint
type Checkpoint struct {
	Origin     string
	Tree       tlog.Tree
	Extensions []string
}

// checkNoteLine returns an error if line cannot be used as a single line of a
// signed note, nil otherwise. https://c2sp.org/signed-note requires note text
// to be valid UTF-8 with no ASCII control characters (those below U+0020) other
// than newline.
func checkNoteLine(line string) error {
	switch {
	case !utf8.ValidString(line):
		return errors.New("not valid UTF-8")

	case strings.ContainsRune(line, '\n'):
		return errors.New("contains a newline")

	case strings.ContainsFunc(line, func(r rune) bool { return r < 0x20 }):
		return errors.New("contains an ASCII control character")

	default:
		return nil
	}
}

// validate returns an error if the checkpoint's fields violate the
// tlog-checkpoint requirements, nil otherwise.
func (c *Checkpoint) validate() error {
	if c.Origin == "" {
		return errors.New("empty checkpoint origin")
	}
	err := checkNoteLine(c.Origin)
	if err != nil {
		return fmt.Errorf("validating checkpoint origin: %w", err)
	}
	if c.Tree.N < 0 {
		return fmt.Errorf("negative checkpoint tree size %d", c.Tree.N)
	}
	if c.Tree.N == 0 && c.Tree.Hash != emptyTreeHash {
		return errors.New("checkpoint root hash for tree size 0 is not the RFC 6962 empty-tree hash")
	}
	for _, ext := range c.Extensions {
		if ext == "" {
			return errors.New("empty checkpoint extension line")
		}
		err := checkNoteLine(ext)
		if err != nil {
			return fmt.Errorf("validating checkpoint extension line: %w", err)
		}
	}
	return nil
}

// Marshal returns the note text, first checking the checkpoint against the
// tlog-checkpoint requirements. It returns an error if the checkpoint is
// invalid.
//
//   - https://c2sp.org/tlog-checkpoint
//   - https://c2sp.org/signed-note
func (c *Checkpoint) Marshal() (string, error) {
	err := c.validate()
	if err != nil {
		return "", err
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

	c := &Checkpoint{Origin: lines[0], Tree: tlog.Tree{N: size, Hash: hash}, Extensions: lines[3:]}
	return c, c.validate()
}

// Open opens a signed checkpoint note and parses its text. An error is returned
// if the note is not valid or the signature is not verified by one of the
// verifiers.
//
//   - https://c2sp.org/tlog-checkpoint
//   - https://c2sp.org/signed-note
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
