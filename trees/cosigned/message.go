// Package cosigned implements CosignedSubtree from
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#section-5.3.1.
package cosigned

import (
	"crypto/sha256"
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
	Start        int64
	End          int64
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

	if subtree.Start < 0 || subtree.Start > trees.MaxSize {
		return nil, fmt.Errorf("start is out of range: %d", subtree.Start)
	}
	if subtree.End < 0 || subtree.End > trees.MaxSize {
		return nil, fmt.Errorf("end is out of range: %d", subtree.End)
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
	b.AddUint64(uint64(subtree.Start))
	b.AddUint64(uint64(subtree.End))
	b.AddBytes(subtree.SubtreeHash[:])

	return b.Bytes()
}
