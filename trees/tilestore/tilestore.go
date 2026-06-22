// Package tilestore reads and writes a tlog-tiles log over a pluggable
// key-to-bytes Backend. It owns the tlog-tiles layout (entry bundles, Merkle
// hash tiles, the checkpoint) and the tree-extension logic. A Backend only
// stores and retrieves opaque objects by key.
//
// A Store is scoped to one log (one origin) and is a single-writer: Append must
// not run concurrently with itself for a given origin. Reads are safe to run
// concurrently with each other.
package tilestore

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"sync"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/trees/subtree"
	"github.com/letsencrypt/boulder/trees/tile"
)

// ErrNotExist is returned (or wrapped) by a Backend's Get when the key is
// absent.
var ErrNotExist = errors.New("tilestore: object does not exist")

// Backend is opaque key-to-bytes storage: one object per key, keyed by
// slash-separated paths. Put overwrites. Get returns ErrNotExist (wrapped is
// fine) when the key is absent. A Backend must be safe for concurrent use. The
// one-object-per-key shape is deliberately minimal. Do not add batching or
// parallelism here. Put it above the Backend or inside a specific
// implementation.
type Backend interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Put(ctx context.Context, key string, data []byte) error
}

// Store is one tlog-tiles log over a Backend.
type Store struct {
	backend Backend
	prefix  string

	// appendMu serializes Append within one process. The Store is still a
	// single-writer per origin: this guards against an in-process bug, not a
	// second writer in another process.
	appendMu sync.Mutex
}

// New returns a Store for origin backed by b. The Store owns the tree state, so
// a caller never tracks size or root itself.
func New(b Backend, origin string) *Store {
	return &Store{backend: b, prefix: url.PathEscape(origin)}
}

// stateKey holds the Store's authoritative tree state (size and root). It is an
// internal object, not part of the served tlog-tiles layout, and is rejected by
// Fetch.
const stateKey = "state"

func (s *Store) key(rel string) string {
	return s.prefix + "/" + rel
}

// Tree returns the Store's current tree head (size and root), or the empty tree
// if nothing has been appended yet.
func (s *Store) Tree(ctx context.Context) (tlog.Tree, error) {
	b, err := s.backend.Get(ctx, s.key(stateKey))
	if errors.Is(err, ErrNotExist) {
		return tlog.Tree{Hash: subtree.Hash(nil)}, nil
	}
	if err != nil {
		return tlog.Tree{}, err
	}
	if len(b) != 8+tlog.HashSize {
		return tlog.Tree{}, fmt.Errorf("malformed tree state: %d bytes", len(b))
	}
	var tree tlog.Tree
	tree.N = int64(binary.BigEndian.Uint64(b[:8])) //nolint:gosec // G115: written by writeState from a non-negative size.
	copy(tree.Hash[:], b[8:])
	return tree, nil
}

// tileReader is a tlog.TileReader over the Backend. SaveTiles is a no-op: tiles
// are persisted by Append, not by the verifying reader.
type tileReader struct {
	ctx context.Context
	s   *Store
}

func (r tileReader) Height() int { return tile.Height }

func (r tileReader) ReadTiles(tiles []tlog.Tile) ([][]byte, error) {
	out := make([][]byte, len(tiles))
	for i, t := range tiles {
		data, err := r.s.backend.Get(r.ctx, r.s.key(tile.Path(t)))
		if err != nil {
			return nil, fmt.Errorf("reading tile %s: %w", tile.Path(t), err)
		}
		out[i] = data
	}
	return out, nil
}

func (r tileReader) SaveTiles(tiles []tlog.Tile, data [][]byte) {}

func (s *Store) tiles(ctx context.Context) tlog.TileReader {
	return tileReader{ctx: ctx, s: s}
}

// HashReader returns a HashReader that checks tiles against tree.Hash. Pass the
// tree you trust, from a verified checkpoint or from Tree.
func (s *Store) HashReader(ctx context.Context, tree tlog.Tree) tlog.HashReader {
	return tlog.TileHashReader(tree, s.tiles(ctx))
}

// readEntryBundle returns the entries in the entry bundle at index n with the
// given width (the number of entries the bundle holds: tile.Width for a full
// bundle, fewer for the partial bundle at the tree's right edge).
func (s *Store) readEntryBundle(ctx context.Context, n int64, width int) ([][]byte, error) {
	data, err := s.backend.Get(ctx, s.key(tile.EntryBundlePath(n, width)))
	if err != nil {
		return nil, err
	}
	return tile.ParseEntryBundle(data)
}

// ReadEntries returns the raw entry bytes for indices [start, end) in a tree of
// size treeSize. Use ReadLeaves over the same range when you want the leaf
// hashes instead of the bytes.
func (s *Store) ReadEntries(ctx context.Context, treeSize, start, end int64) ([][]byte, error) {
	if start < 0 || end < start || end > treeSize {
		return nil, fmt.Errorf("range [%d, %d) out of bounds for a tree of size %d", start, end, treeSize)
	}
	if start == end {
		return nil, nil
	}
	out := make([][]byte, 0, end-start)
	for b := start / tile.Width; b <= (end-1)/tile.Width; b++ {
		bundleStart := b * tile.Width
		width := min(tile.Width, int(treeSize-bundleStart))
		bundle, err := s.readEntryBundle(ctx, b, width)
		if err != nil {
			return nil, err
		}
		for i := max(start, bundleStart); i < min(end, bundleStart+int64(width)); i++ {
			out = append(out, bundle[i-bundleStart])
		}
	}
	return out, nil
}

// ReadLeaves returns the leaf hashes (RecordHash of each entry) for indices
// [start, end) in a tree of size treeSize. Use ReadEntries over the same range
// when you want the entry bytes instead of the hashes.
func (s *Store) ReadLeaves(ctx context.Context, treeSize, start, end int64) ([]tlog.Hash, error) {
	entries, err := s.ReadEntries(ctx, treeSize, start, end)
	if err != nil {
		return nil, err
	}
	out := make([]tlog.Hash, len(entries))
	for i, e := range entries {
		out[i] = tlog.RecordHash(e)
	}
	return out, nil
}

// WriteCheckpoint stores signed as the log's checkpoint note. It does not sign
// or validate the bytes.
func (s *Store) WriteCheckpoint(ctx context.Context, signed []byte) error {
	return s.backend.Put(ctx, s.key("checkpoint"), signed)
}

// ReadCheckpoint returns the stored checkpoint note bytes, or nil with no error
// when the log has none yet.
func (s *Store) ReadCheckpoint(ctx context.Context) ([]byte, error) {
	b, err := s.backend.Get(ctx, s.key("checkpoint"))
	if errors.Is(err, ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// Fetch serves a monitoring GET. resource is "checkpoint" or a tlog-tiles path.
// Fetch owns the allow-listing and path validation. It returns ErrNotExist for
// a missing object and for anything outside the allow-list, including the
// internal state object.
func (s *Store) Fetch(ctx context.Context, resource string) ([]byte, error) {
	if resource != "checkpoint" {
		_, err := tile.ParsePath(resource)
		if err != nil {
			return nil, ErrNotExist
		}
	}
	return s.backend.Get(ctx, s.key(resource))
}

// extendReader serves stored hashes during an Append. Indices below oldCount
// (the stored-hash count of the old tree) come from old, the verifying reader
// over the already-written tiles. The rest come from added, the hashes computed
// so far in this Append, where stored-hash index oldCount+k is added[k]. added
// is read through a pointer so the reader sees it grow as the loop appends.
func extendReader(oldCount int64, old tlog.HashReader, added *[]tlog.Hash) tlog.HashReaderFunc {
	return func(indexes []int64) ([]tlog.Hash, error) {
		out := make([]tlog.Hash, len(indexes))
		var oldIndexes []int64
		var oldPos []int
		for i, x := range indexes {
			if x < oldCount {
				oldIndexes = append(oldIndexes, x)
				oldPos = append(oldPos, i)
			} else {
				out[i] = (*added)[x-oldCount]
			}
		}
		if len(oldIndexes) > 0 {
			hs, err := old.ReadHashes(oldIndexes)
			if err != nil {
				return nil, err
			}
			for j, p := range oldPos {
				out[p] = hs[j]
			}
		}
		return out, nil
	}
}

// writeEntryBundles rewrites the entry bundles spanning the appended range. The
// first bundle may already hold entries below oldSize, which are read back and
// prepended so the bundle stays complete. Superseded partial bundles are left
// in place at their narrower width, which the Backend's Get/Put contract cannot
// remove. They share no key with the grown bundle and are never read again.
func (s *Store) writeEntryBundles(ctx context.Context, oldSize int64, entries [][]byte) error {
	newSize := oldSize + int64(len(entries))
	for b := oldSize / tile.Width; b <= (newSize-1)/tile.Width; b++ {
		bundleStart := b * tile.Width
		bundleEnd := min((b+1)*tile.Width, newSize)

		var bundle [][]byte
		if bundleStart < oldSize {
			existing, err := s.readEntryBundle(ctx, b, int(oldSize-bundleStart))
			if err != nil {
				return err
			}
			bundle = append(bundle, existing...)
		}
		for i := max(oldSize, bundleStart); i < bundleEnd; i++ {
			bundle = append(bundle, entries[i-oldSize])
		}

		var data []byte
		for _, e := range bundle {
			var err error
			data, err = tile.AppendEntry(data, e)
			if err != nil {
				return err
			}
		}
		err := s.backend.Put(ctx, s.key(tile.EntryBundlePath(b, int(bundleEnd-bundleStart))), data)
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) writeState(ctx context.Context, tree tlog.Tree) error {
	buf := make([]byte, 8+tlog.HashSize)
	binary.BigEndian.PutUint64(buf[:8], uint64(tree.N)) //nolint:gosec // G115: tree size is non-negative.
	copy(buf[8:], tree.Hash[:])
	return s.backend.Put(ctx, s.key(stateKey), buf)
}

// Append adds entries to the end of the log and returns the new tree. atSize
// must equal the current tree size, a self-consistency check rather than a
// cross-process compare-and-set. A mismatch is refused. Append serializes with
// itself through an internal lock, but the Store is still a single-writer per
// origin: that lock guards one process, not several, and two processes both
// appending at the same atSize corrupt the log.
func (s *Store) Append(ctx context.Context, atSize int64, entries [][]byte) (tlog.Tree, error) {
	s.appendMu.Lock()
	defer s.appendMu.Unlock()

	old, err := s.Tree(ctx)
	if err != nil {
		return tlog.Tree{}, err
	}
	if atSize != old.N {
		return tlog.Tree{}, fmt.Errorf("append at size %d, but the tree is size %d", atSize, old.N)
	}
	if len(entries) == 0 {
		return old, nil
	}
	oldSize := old.N
	newSize := oldSize + int64(len(entries))

	oldCount := tlog.StoredHashCount(oldSize)
	oldReader := tlog.TileHashReader(old, s.tiles(ctx))
	var added []tlog.Hash
	r := extendReader(oldCount, oldReader, &added)

	for i, e := range entries {
		n := oldSize + int64(i)
		hashes, err := tlog.StoredHashesForRecordHash(n, tlog.RecordHash(e), r)
		if err != nil {
			return tlog.Tree{}, fmt.Errorf("hashing entry %d: %w", n, err)
		}
		added = append(added, hashes...)
	}

	root, err := tlog.TreeHash(newSize, r)
	if err != nil {
		return tlog.Tree{}, err
	}

	err = s.writeEntryBundles(ctx, oldSize, entries)
	if err != nil {
		return tlog.Tree{}, err
	}
	for _, t := range tlog.NewTiles(tile.Height, oldSize, newSize) {
		data, err := tlog.ReadTileData(t, r)
		if err != nil {
			return tlog.Tree{}, err
		}
		err = s.backend.Put(ctx, s.key(tile.Path(t)), data)
		if err != nil {
			return tlog.Tree{}, err
		}
	}

	tree := tlog.Tree{N: newSize, Hash: root}
	err = s.writeState(ctx, tree)
	if err != nil {
		return tlog.Tree{}, err
	}
	return tree, nil
}
