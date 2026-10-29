// Package cosigned implements CosignedSubtree from
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#section-5.3.1.
package cosigned

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"

	"github.com/letsencrypt/boulder/trees"
)

// Subtree represents a CosignedSubtree from
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#section-5.3.1.
type Subtree struct {
	CosignerName string
	Timestamp    uint64
	LogOrigin    string
	Start        uint64
	End          uint64
	SubtreeHash  [sha256.Size]byte
}

const subtreeLabel = "subtree/v1\n\x00"

// Marshal encodes the Subtree as bytes.
//
// It errors if cosigner_name or log_origin are not valid names. It does not validate semantic constraints,
// like [start, end) being a valid subtree.
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
//	} CosignedSubtree;
func (subtree *Subtree) Marshal() ([]byte, error) {
	err := trees.CheckName(subtree.CosignerName)
	if err != nil {
		return nil, fmt.Errorf("invalid cosigner_name: %w", err)
	}
	err = trees.CheckName(subtree.LogOrigin)
	if err != nil {
		return nil, fmt.Errorf("invalid log_origin: %w", err)
	}

	var b cryptobyte.Builder
	b.AddBytes([]byte(subtreeLabel))
	b.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes([]byte(subtree.CosignerName))
	})
	b.AddUint64(subtree.Timestamp)
	b.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes([]byte(subtree.LogOrigin))
	})
	b.AddUint64(subtree.Start)
	b.AddUint64(subtree.End)
	b.AddBytes(subtree.SubtreeHash[:])

	return b.Bytes()
}

// Unmarshal unmarshals the input bytes and returns a *Subtree.
func Unmarshal(input []byte) (*Subtree, error) {
	var out Subtree

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
	err := trees.CheckName(string(cosignerName))
	if err != nil {
		return nil, fmt.Errorf("invalid cosigner_name: %w", err)
	}
	out.CosignerName = string(cosignerName)

	if !s.ReadUint64(&out.Timestamp) {
		return nil, errors.New("invalid timestamp")
	}

	var logOrigin cryptobyte.String
	if !s.ReadUint8LengthPrefixed(&logOrigin) {
		return nil, errors.New("invalid log_origin")
	}
	err = trees.CheckName(string(logOrigin))
	if err != nil {
		return nil, fmt.Errorf("invalid log_origin: %w", err)
	}
	out.LogOrigin = string(logOrigin)

	if !s.ReadUint64(&out.Start) {
		return nil, errors.New("invalid start")
	}

	if !s.ReadUint64(&out.End) {
		return nil, errors.New("invalid end")
	}

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
