// Package cosigned implements CosignedSubtree from
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#section-5.3.1.
package cosigned

import (
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/cryptobyte"

	"github.com/letsencrypt/boulder/trees"
	"github.com/letsencrypt/boulder/trees/subtree"
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
// It errors if cosigner_name or log_origin are not valid names, if [start, end)
// is not a valid subtree, if end exceeds trees.MaxSize, or if a nonzero
// timestamp is paired with a nonzero start. Constraints that depend on the
// cosigner's view of the log are the caller's to check.
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
func (s *Subtree) Marshal() ([]byte, error) {
	err := trees.CheckName(s.CosignerName)
	if err != nil {
		return nil, fmt.Errorf("invalid cosigner_name: %w", err)
	}
	err = trees.CheckName(s.LogOrigin)
	if err != nil {
		return nil, fmt.Errorf("invalid log_origin: %w", err)
	}
	if !subtree.Valid(s.Start, s.End) {
		return nil, fmt.Errorf("invalid subtree [%d, %d)", s.Start, s.End)
	}
	if s.End > trees.MaxSize {
		return nil, fmt.Errorf("end is out of range: %d", s.End)
	}
	if s.Timestamp != 0 && s.Start != 0 {
		return nil, fmt.Errorf("timestamp %d requires start 0, got %d", s.Timestamp, s.Start)
	}

	var b cryptobyte.Builder
	b.AddBytes([]byte(subtreeLabel))
	b.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes([]byte(s.CosignerName))
	})
	b.AddUint64(s.Timestamp)
	b.AddUint8LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes([]byte(s.LogOrigin))
	})
	b.AddUint64(uint64(s.Start)) //nolint:gosec // G115: the subtree.Valid check above leaves 0 <= start <= end.
	b.AddUint64(uint64(s.End))   //nolint:gosec // G115: the subtree.Valid check above leaves 0 <= start <= end.
	b.AddBytes(s.SubtreeHash[:])

	return b.Bytes()
}
