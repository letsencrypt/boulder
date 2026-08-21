//go:build go1.27

package mtpublisher

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/letsencrypt/boulder/trees/mirror"
	"github.com/letsencrypt/boulder/trees/subtree"
	"github.com/letsencrypt/boulder/trees/tiles"
	"golang.org/x/mod/sumdb/tlog"
)

// simpleS3 matches the subset of the bs3.Client interface which we use, to
// allow simpler mocking in tests.
type simpleS3 interface {
	GetObject(ctx context.Context, params *s3.GetObjectInput, optFns ...func(*s3.Options)) (*s3.GetObjectOutput, error)
	Bucket() string
}

// Source builds consistency proofs and entry packages from the log's tile
// storage. In the future, when we want to support multiple mirrors, we may want
// to improve Source to memoize the tiles, consistency proofs, and entry
// packages built for the latest tree, purging the memo when the tree changes.
type Source struct {
	s3c        simpleS3
	tilePrefix string
}

// NewSource returns a Source over the tiles stored in s3c under tilePrefix.
func NewSource(s3c simpleS3, tilePrefix string) *Source {
	return &Source{s3c: s3c, tilePrefix: tilePrefix}
}

// hashReaderForTree returns a HashReader that reads tree's hashes from the
// log's tiles.
func (s *Source) hashReaderForTree(ctx context.Context, tree tlog.Tree) tlog.HashReader {
	return tlog.TileHashReader(tree, tiles.NewTileReader(ctx, s.s3c, s.tilePrefix))
}

// consistencyProof returns the RFC 6962 consistency proof from oldSize to tree.
func (s *Source) consistencyProof(ctx context.Context, tree tlog.Tree, oldSize int64) ([]tlog.Hash, error) {
	return tlog.ProveTree(tree.N, oldSize, s.hashReaderForTree(ctx, tree))
}

// entryPackage returns the marshaled entry package covering p, proven against
// tree.
func (s *Source) entryPackage(ctx context.Context, tree tlog.Tree, p mirror.Package) ([]byte, error) {
	entries, err := tiles.EntriesForPackage(ctx, s.s3c, p.EntriesStart, p.End, tree.N, s.tilePrefix)
	if err != nil {
		return nil, err
	}
	proof, err := subtree.ConsistencyProof(p.SubtreeStart, p.End, tree.N, s.hashReaderForTree(ctx, tree))
	if err != nil {
		return nil, fmt.Errorf("proving subtree [%d, %d): %s", p.SubtreeStart, p.End, err)
	}
	return mirror.EntryPackage(entries, proof)
}
