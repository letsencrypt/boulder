// Package cosigned implements CosignedMessage from
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#section-5.3.1.
package cosigned

import (
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/cryptobyte"

	"github.com/letsencrypt/boulder/trees"
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

	if message.Start < 0 || message.Start > trees.MaxSize {
		return nil, fmt.Errorf("start is out of range: %d", message.Start)
	}
	if message.End < 0 || message.End > trees.MaxSize {
		return nil, fmt.Errorf("end is out of range: %d", message.End)
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
