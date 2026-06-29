package cosigned

import (
	"bytes"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/tlog"
)

// Message is the cosigned_message wire struct a cosigner signs over. A
// whole-tree checkpoint cosignature sets Start to 0, End to the tree size, and
// a non-zero Timestamp. A subtree cosignature sets Start to the first leaf
// index and Timestamp to 0.
//
//	struct {
//	    uint8  label[12] = "subtree/v1\n\0";
//	    opaque cosigner_name<1..2^8-1>;
//	    uint64 timestamp;
//	    opaque log_origin<1..2^8-1>;
//	    uint64 start;
//	    uint64 end;
//	    opaque subtree_hash[HASH_SIZE];
//	} Message;
//
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#section-5.3.1
type Message struct {
	CosignerName string
	Timestamp    uint64
	LogOrigin    string
	Start        uint64
	End          uint64
	SubtreeHash  tlog.Hash
}

// subtreeLabel is the fixed 12-byte domain-separation label that begins every
// Message: "subtree/v1" followed by 0x0A and 0x00.
const subtreeLabel = "subtree/v1\n\x00"

// Marshal returns the wire encoding to sign or verify over. CosignerName and
// LogOrigin must each be 1 to 255 bytes. It does not check that a subtree
// (Start > 0) carries a zero Timestamp. Enforce that before calling.
func (m *Message) Marshal() ([]byte, error) {
	if len(m.CosignerName) < 1 || len(m.CosignerName) > 255 {
		return nil, fmt.Errorf("cosigner name must be 1 to 255 bytes, got %d", len(m.CosignerName))
	}
	if len(m.LogOrigin) < 1 || len(m.LogOrigin) > 255 {
		return nil, fmt.Errorf("log origin must be 1 to 255 bytes, got %d", len(m.LogOrigin))
	}

	var b cryptobyte.Builder
	b.AddBytes([]byte(subtreeLabel))
	b.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes([]byte(m.CosignerName))
	})
	b.AddUint64(m.Timestamp)
	b.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes([]byte(m.LogOrigin))
	})
	b.AddUint64(m.Start)
	b.AddUint64(m.End)
	b.AddBytes(m.SubtreeHash[:])
	return b.Bytes()
}

// Unmarshal parses input and overwrites the receiver on success, leaving it
// untouched on any error.
func (m *Message) Unmarshal(input []byte) error {
	var out Message

	s := cryptobyte.String(input)
	var label []byte
	if !s.ReadBytes(&label, len(subtreeLabel)) {
		return errors.New("truncated label")
	}
	if !bytes.Equal(label, []byte(subtreeLabel)) {
		return errors.New("label is not subtree/v1")
	}

	var cosignerName cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&cosignerName) {
		return errors.New("truncated cosigner_name")
	}
	if len(cosignerName) < 1 {
		return errors.New("empty cosigner_name")
	}
	out.CosignerName = string(cosignerName)

	if !s.ReadUint64(&out.Timestamp) {
		return errors.New("truncated timestamp")
	}

	var logOrigin cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&logOrigin) {
		return errors.New("truncated log_origin")
	}
	if len(logOrigin) < 1 {
		return errors.New("empty log_origin")
	}
	out.LogOrigin = string(logOrigin)

	if !s.ReadUint64(&out.Start) {
		return errors.New("truncated start")
	}
	if !s.ReadUint64(&out.End) {
		return errors.New("truncated end")
	}

	var subtreeHash []byte
	if !s.ReadBytes(&subtreeHash, len(out.SubtreeHash)) {
		return errors.New("truncated subtree hash")
	}
	copy(out.SubtreeHash[:], subtreeHash)

	if !s.Empty() {
		return errors.New("trailing bytes")
	}

	*m = out
	return nil
}
