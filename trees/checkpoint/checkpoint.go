package checkpoint

import (
	"bytes"
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

// checkNoteText returns an error if text cannot be a signed note's text, nil
// otherwise. https://c2sp.org/signed-note requires note text to be valid UTF-8
// with no ASCII control characters (those below U+0020) other than newline.
func checkNoteText(text []byte) error {
	switch {
	case !utf8.Valid(text):
		return errors.New("not valid UTF-8")

	case bytes.ContainsFunc(text, func(r rune) bool { return r < 0x20 && r != '\n' }):
		return errors.New("contains an ASCII control character other than newline")

	default:
		return nil
	}
}

// checkNoteField returns an error if field contains a newline, the note's line
// delimiter, nil otherwise.
func checkNoteField(field string) error {
	if strings.ContainsRune(field, '\n') {
		return errors.New("contains a newline")
	}
	return nil
}

// validate returns an error if the checkpoint's fields violate the
// tlog-checkpoint requirements, nil otherwise.
func (c *Checkpoint) validate() error {
	if c.Origin == "" {
		return errors.New("empty checkpoint origin")
	}
	err := checkNoteField(c.Origin)
	if err != nil {
		return fmt.Errorf("validating checkpoint origin: %w", err)
	}
	if c.Tree.N < 0 {
		return fmt.Errorf("negative checkpoint tree size %d", c.Tree.N)
	}
	for _, ext := range c.Extensions {
		if ext == "" {
			return errors.New("empty checkpoint extension line")
		}
		err := checkNoteField(ext)
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
func (c *Checkpoint) Marshal() ([]byte, error) {
	err := c.validate()
	if err != nil {
		return nil, err
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "%s\n%d\n%s\n", c.Origin, c.Tree.N, c.Tree.Hash)
	for _, ext := range c.Extensions {
		b.WriteString(ext)
		b.WriteByte('\n')
	}
	noteText := b.Bytes()
	err = checkNoteText(noteText)
	if err != nil {
		return nil, fmt.Errorf("validating checkpoint note text: %w", err)
	}
	return noteText, nil
}

// signedNote returns the checkpoint as a signed note: the note text followed by
// the given signature line(s).
func (c *Checkpoint) signedNote(signatureLines ...[]byte) ([]byte, error) {
	text, err := c.Marshal()
	if err != nil {
		return nil, err
	}
	assembled := append(text, '\n')
	for _, line := range signatureLines {
		assembled = append(assembled, line...)
	}
	return assembled, nil
}

// SignedNoteForMirror returns the checkpoint as a signed note carrying the MTCA
// cosignature line, for submission to a mirror.
func (c *Checkpoint) SignedNoteForMirror(caCosignatureLine []byte) ([]byte, error) {
	if len(caCosignatureLine) == 0 {
		return nil, errors.New("missing MTCA cosignature line")
	}
	return c.signedNote(caCosignatureLine)
}

// SignedNoteForSignSubtree returns the checkpoint as a signed note carrying the
// cosignature lines the mirror returned from add-entries.
func (c *Checkpoint) SignedNoteForSignSubtree(mirrorCosignatureLines []byte) ([]byte, error) {
	if len(mirrorCosignatureLines) == 0 {
		return nil, errors.New("missing mirror cosignature lines")
	}
	return c.signedNote(mirrorCosignatureLines)
}

// SignedNoteForServing returns the checkpoint as a signed note carrying the
// MTCA and mirror cosignature lines, for serving at the checkpoint path.
func (c *Checkpoint) SignedNoteForServing(caCosignatureLine, mirrorCosignatureLine []byte) ([]byte, error) {
	if len(caCosignatureLine) == 0 {
		return nil, errors.New("missing MTCA cosignature line")
	}
	if len(mirrorCosignatureLine) == 0 {
		return nil, errors.New("missing mirror cosignature line")
	}
	return c.signedNote(caCosignatureLine, mirrorCosignatureLine)
}

// Unmarshal parses a checkpoint note text. The text must not have any signature
// lines. For a signed note, use Open.
//
//   - https://c2sp.org/tlog-checkpoint
//   - https://c2sp.org/signed-note
func Unmarshal(noteText []byte) (*Checkpoint, error) {
	err := checkNoteText(noteText)
	if err != nil {
		return nil, fmt.Errorf("validating checkpoint note text: %w", err)
	}
	text := string(noteText)
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
// if signedNote is not a well-formed note, if its signature lines are not
// exactly one verified signature per verifier and nothing else
// (note.InvalidSignatureError for a rejected one), or if the note's text is not
// a well-formed checkpoint.
//
//   - https://c2sp.org/tlog-checkpoint
//   - https://c2sp.org/signed-note
func Open(signedNote []byte, verifiers ...note.Verifier) (*Checkpoint, *note.Note, error) {
	n, err := note.Open(signedNote, note.VerifierList(verifiers...))
	if err != nil {
		return nil, nil, err
	}
	// n.Sigs holds one verified signature per signing key in verifiers, so its
	// length is the number of verifiers whose key signed the note.
	if len(n.Sigs) != len(verifiers) {
		return nil, nil, fmt.Errorf("%d of %d verifiers signed the note", len(n.Sigs), len(verifiers))
	}
	// note.Open ignores signatures from unknown keys and repeated signatures
	// from known ones, so the lines themselves are counted as well.
	signatureLines := bytes.Count(signedNote[len(n.Text)+1:], []byte("\n"))
	if signatureLines != len(verifiers) {
		return nil, nil, fmt.Errorf("note has %d signature lines, want %d", signatureLines, len(verifiers))
	}
	c, err := Unmarshal([]byte(n.Text))
	if err != nil {
		return nil, nil, err
	}
	return c, n, nil
}
