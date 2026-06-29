// Package tilestore stores a c2sp.org/tlog-tiles log over a pluggable
// key-to-bytes Backend. The Store owns the tlog-tiles layout (entry bundles,
// Merkle hash tiles, the checkpoint) and the logic that grows the tree.
//
// A Store manages one log and is single-writer: only one process may append
// to a given log. Reads may run concurrently with each other.
//
// https://c2sp.org/tlog-tiles
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

// ErrNotExist is the error, possibly wrapped, that a Backend's Get returns
// when no object has the requested key.
var ErrNotExist = errors.New("tilestore: object does not exist")

// Backend is opaque key-to-bytes storage: one object per slash-separated key.
// Put overwrites. Get returns an error matching ErrNotExist for an absent
// key. Implementations must be safe for concurrent use. Batching and
// parallelism belong above the interface or inside an implementation.
type Backend interface {
	Get(ctx context.Context, key string) ([]byte, error)
	Put(ctx context.Context, key string, data []byte) error
}

// Store reads and writes one tlog-tiles log over a Backend.
type Store struct {
	backend Backend
	prefix  string

	// appendMu serializes Append within this process. It does not make the
	// log multi-writer: a second process appending to the same log can still
	// corrupt it.
	appendMu sync.Mutex
}

// New returns a Store for the log named origin, backed by b.
func New(b Backend, origin string) *Store {
	return &Store{backend: b, prefix: url.PathEscape(origin)}
}

// stateKey names the object holding the authoritative tree size and root. It
// is not part of the tlog-tiles layout, and Fetch does not serve it.
const stateKey = "state"

func (s *Store) key(rel string) string {
	return s.prefix + "/" + rel
}

// Tree returns the log's current size and root hash. An empty log returns
// size zero and the hash of the empty string.
func (s *Store) Tree(ctx context.Context) (tlog.Tree, error) {
	b, err := s.backend.Get(ctx, s.key(stateKey))
	if errors.Is(err, ErrNotExist) {
		return tlog.Tree{Hash: subtree.HashLeaves(nil)}, nil
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

// tileReader is a tlog.TileReader over the Backend. TileHashReader hands each
// tile set to SaveTiles once it has authenticated it, and ReadTiles serves
// repeat reads from saved instead of the Backend. A cached tile can never go
// stale: tile objects are immutable per path, because a grown partial tile
// gets a new width-qualified path.
type tileReader struct {
	ctx context.Context
	s   *Store

	mu    sync.Mutex
	saved map[string][]byte
}

func (r *tileReader) Height() int { return tile.Height }

func (r *tileReader) ReadTiles(tiles []tlog.Tile) ([][]byte, error) {
	out := make([][]byte, len(tiles))
	for i, t := range tiles {
		path := tile.Path(t)
		r.mu.Lock()
		data, ok := r.saved[path]
		r.mu.Unlock()
		if !ok {
			var err error
			data, err = r.s.backend.Get(r.ctx, r.s.key(path))
			if err != nil {
				return nil, fmt.Errorf("reading tile %s: %w", path, err)
			}
		}
		out[i] = data
	}
	return out, nil
}

func (r *tileReader) SaveTiles(tiles []tlog.Tile, data [][]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for i, t := range tiles {
		r.saved[tile.Path(t)] = data[i]
	}
}

func (s *Store) tiles(ctx context.Context) tlog.TileReader {
	return &tileReader{ctx: ctx, s: s, saved: make(map[string][]byte)}
}

// HashReader returns a tlog.HashReader that reads stored hashes from the log's
// tiles, verifying every tile against tree.Hash. Pass a tree you trust, from a
// verified checkpoint or from Tree. The reader caches the tiles it has
// verified for its lifetime, so reuse one reader across related reads.
func (s *Store) HashReader(ctx context.Context, tree tlog.Tree) tlog.HashReader {
	return tlog.TileHashReader(tree, s.tiles(ctx))
}

// readEntryBundle reads and decodes entry bundle n, stored at the path for the
// given width.
func (s *Store) readEntryBundle(ctx context.Context, n int64, width int) ([][]byte, error) {
	data, err := s.backend.Get(ctx, s.key(tile.EntryBundlePath(n, width)))
	if err != nil {
		return nil, err
	}
	return tile.ParseEntryBundle(data)
}

// ReadEntries returns the raw entry bytes for indices [start, end) in a tree
// of size treeSize. treeSize must be a size this log reached through Append,
// such as the current size from Tree or the size of a checkpoint over this
// log: the bundle at a tree's right edge is stored at a width keyed to that
// size, and a read at any other size misses it.
func (s *Store) ReadEntries(ctx context.Context, start, end, treeSize int64) ([][]byte, error) {
	if start < 0 || end < start || end > treeSize {
		return nil, fmt.Errorf("range [%d, %d) out of bounds for a tree of size %d", start, end, treeSize)
	}
	if start == end {
		return nil, nil
	}
	out := make([][]byte, 0, end-start)
	first, last := tile.BundleRange(start, end)
	for b := first; b <= last; b++ {
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
// [start, end) in a tree of size treeSize, under the same treeSize contract as
// ReadEntries.
func (s *Store) ReadLeaves(ctx context.Context, start, end, treeSize int64) ([]tlog.Hash, error) {
	entries, err := s.ReadEntries(ctx, start, end, treeSize)
	if err != nil {
		return nil, err
	}
	out := make([]tlog.Hash, len(entries))
	for i, e := range entries {
		out[i] = tlog.RecordHash(e)
	}
	return out, nil
}

// WriteCheckpoint stores signed as the log's checkpoint. It does not sign or
// validate the bytes.
func (s *Store) WriteCheckpoint(ctx context.Context, signed []byte) error {
	return s.backend.Put(ctx, s.key("checkpoint"), signed)
}

// ReadCheckpoint returns the stored checkpoint bytes, or nil with no error
// when the log has no checkpoint yet.
func (s *Store) ReadCheckpoint(ctx context.Context) ([]byte, error) {
	b, err := s.backend.Get(ctx, s.key("checkpoint"))
	if errors.Is(err, ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// Fetch returns the object a tlog-tiles monitoring GET for resource should
// serve: "checkpoint", a hash tile path, or an entry bundle path. Anything
// else, including the internal state object, gets ErrNotExist, the same as a
// missing object.
func (s *Store) Fetch(ctx context.Context, resource string) ([]byte, error) {
	if resource != "checkpoint" {
		_, err := tile.ParsePath(resource)
		if err != nil {
			return nil, ErrNotExist
		}
	}
	return s.backend.Get(ctx, s.key(resource))
}

// extendReader returns a HashReader for the transitional tree an Append
// builds, part stored and part new. Stored-hash indices below oldCount come
// from old, the verifying reader over the already-written tiles. Index
// oldCount+k is (*added)[k], a hash computed earlier in this Append. added is
// a pointer so the reader sees the slice grow as Append fills it.
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

// writeEntryBundles writes the entry bundles covering [oldSize,
// oldSize+len(entries)). When the first bundle already holds entries
// below oldSize, they are read back and kept, so the grown bundle stays
// complete. A superseded partial bundle stays in place under its old
// width-qualified key: a Backend cannot delete, and those objects are what
// keeps ReadEntries at an earlier tree size working.
func (s *Store) writeEntryBundles(ctx context.Context, oldSize int64, entries [][]byte) error {
	newSize := oldSize + int64(len(entries))
	first, last := tile.BundleRange(oldSize, newSize)
	for b := first; b <= last; b++ {
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

// Append adds entries to the end of the log and returns the new tree. It
// refuses an atSize that does not equal the current tree size. That check
// catches a caller out of step with the log, not a second writer: the log is
// single-writer, and two processes appending at the same size corrupt it.
// Entries and tiles are written before the tree state, so a failed Append
// never advances the tree, and retrying at the same size is safe.
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
