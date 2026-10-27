// Package cosigned implements CosignedMessage from
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#section-5.3.1.
package cosigned

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"math"

	"golang.org/x/crypto/cryptobyte"
)

// Message represents a CosignedMessage from
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#section-5.3.1.
type Message struct {
	CosignerName string
	Timestamp    uint64
	LogOrigin    string
	Start        int64
	End          int64
	SubtreeHash  [sha256.Size]byte
}

const subtreeLabel = "subtree/v1\n\x00"

// Marshal encodes the Message as bytes.
//
// It errors if cosigner_name or log_origin are too long or too short. It does not validate semantic constraints,
// like start < end.
//
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#section-5.3.1
// opaque HashValue[HASH_SIZE];
//
//	struct {
//	    uint8 label[12] = "subtree/v1\n\0";
//	    opaque cosigner_name<1..2^8-1>;
//	    uint64 timestamp;
//	    opaque log_origin<1..2^8-1>;
//	    uint64 start;
//	    uint64 end;
//	    HashValue subtree_hash;
//	} CosignedMessage;
func (message *Message) Marshal() ([]byte, error) {
	if len(message.CosignerName) < 1 || len(message.CosignerName) > 255 {
		return nil, fmt.Errorf("invalid cosigner_name length %d", len(message.CosignerName))
	}
	if len(message.LogOrigin) < 1 || len(message.LogOrigin) > 255 {
		return nil, fmt.Errorf("invalid log_origin length %d", len(message.LogOrigin))
	}

	if message.Start < 0 {
		return nil, fmt.Errorf("negative start %d", message.Start)
	}
	if message.End < 0 {
		return nil, fmt.Errorf("negative end %d", message.End)
	}

	var b cryptobyte.Builder
	b.AddBytes([]byte(subtreeLabel))
	b.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes([]byte(message.CosignerName))
	})
	b.AddUint64(message.Timestamp)
	b.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes([]byte(message.LogOrigin))
	})
	b.AddUint64(uint64(message.Start))
	b.AddUint64(uint64(message.End))
	b.AddBytes(message.SubtreeHash[:])

	return b.Bytes()
}

// Unmarshal unmarshals the input bytes and returns a *Message.
func Unmarshal(input []byte) (*Message, error) {
	var out Message

	s := cryptobyte.String(input)
	var label []byte
	if !s.ReadBytes(&label, len(subtreeLabel)) {
		return nil, errors.New("invalid label")
	}
	if !bytes.Equal(label, []byte(subtreeLabel)) {
		return nil, errors.New("label was not subtree/v1")
	}

	var cosignerName cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&cosignerName) {
		return nil, errors.New("invalid cosigner_name")
	}
	if len(cosignerName) < 1 {
		return nil, errors.New("empty cosigner_name")
	}
	out.CosignerName = string(cosignerName)

	if !s.ReadUint64(&out.Timestamp) {
		return nil, errors.New("invalid timestamp")
	}

	var logOrigin cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&logOrigin) {
		return nil, errors.New("invalid log_origin")
	}
	if len(logOrigin) < 1 {
		return nil, errors.New("empty log_origin")
	}
	out.LogOrigin = string(logOrigin)

	var start, end uint64
	if !s.ReadUint64(&start) {
		return nil, errors.New("invalid start")
	}
	if start > math.MaxInt64 {
		return nil, fmt.Errorf("start %d out of range", start)
	}
	out.Start = int64(start)

	if !s.ReadUint64(&end) {
		return nil, errors.New("invalid end")
	}
	if end > math.MaxInt64 {
		return nil, fmt.Errorf("end %d out of range", end)
	}
	out.End = int64(end)

	var subtreeHash []byte
	if !s.ReadBytes(&subtreeHash, len(out.SubtreeHash)) {
		return nil, errors.New("invalid subtree hash")
	}
	copy(out.SubtreeHash[:], subtreeHash)

	if !s.Empty() {
		return nil, errors.New("trailing bytes")
	}

	return &out, nil
}
