package tilestore_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"testing"

	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/trees/subtree"
	"github.com/letsencrypt/boulder/trees/tile"
	"github.com/letsencrypt/boulder/trees/tilestore"
	"github.com/letsencrypt/boulder/trees/tilestore/fs"
)

const testOrigin = "example.com/log"

func entries(start, n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = fmt.Appendf(nil, "entry-%d", start+i)
	}
	return out
}

// inmem is an in-memory tlog.HashReader used to compute a reference tree
// independently of the Store.
type inmem []tlog.Hash

func (m inmem) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
	for i, x := range indexes {
		out[i] = m[x]
	}
	return out, nil
}

// reference builds the tree for all entries in an in-memory reader, returning
// the reader and the resulting tree, computed without the Store.
func reference(t *testing.T, all [][]byte) (inmem, tlog.Tree) {
	t.Helper()
	var r inmem
	for i, e := range all {
		hashes, err := tlog.StoredHashes(int64(i), e, r)
		if err != nil {
			t.Fatalf("StoredHashes: %s", err)
		}
		r = append(r, hashes...)
	}
	root, err := tlog.TreeHash(int64(len(all)), r)
	if err != nil {
		t.Fatalf("TreeHash: %s", err)
	}
	return r, tlog.Tree{N: int64(len(all)), Hash: root}
}

// backendTiles is a tlog.TileReader over a raw Backend, reading the tiles a
// Store wrote for an origin. It lets a vanilla TileHashReader verify those
// tiles independently of the Store's own reader.
type backendTiles struct {
	ctx     context.Context
	backend tilestore.Backend
	prefix  string
}

func (b backendTiles) Height() int { return tile.Height }

func (b backendTiles) ReadTiles(tiles []tlog.Tile) ([][]byte, error) {
	out := make([][]byte, len(tiles))
	for i, t := range tiles {
		data, err := b.backend.Get(b.ctx, b.prefix+"/"+tile.Path(t))
		if err != nil {
			return nil, err
		}
		out[i] = data
	}
	return out, nil
}

func (b backendTiles) SaveTiles(tiles []tlog.Tile, data [][]byte) {}

// faultyBackend wraps a Backend and fails the Put whose 1-based number equals
// failAt (0 disables), to exercise a commit that dies partway through.
type faultyBackend struct {
	inner  tilestore.Backend
	puts   int
	failAt int
}

func (f *faultyBackend) Get(ctx context.Context, key string) ([]byte, error) {
	return f.inner.Get(ctx, key)
}

func (f *faultyBackend) Put(ctx context.Context, key string, data []byte) error {
	f.puts++
	if f.failAt != 0 && f.puts == f.failAt {
		return errors.New("injected put failure")
	}
	return f.inner.Put(ctx, key, data)
}

// TestAppendAndVerify appends in two batches spanning more than one tile width,
// checks the resulting tree against an independent reference, and confirms the
// on-disk tiles reconstruct and verify against the returned root.
func TestAppendAndVerify(t *testing.T) {
	s := tilestore.New(fs.New(t.TempDir()), testOrigin)
	all := entries(0, 300)

	_, err := s.Append(t.Context(), 0, all[:100])
	if err != nil {
		t.Fatalf("Append first batch: %s", err)
	}
	tree, err := s.Append(t.Context(), 100, all[100:])
	if err != nil {
		t.Fatalf("Append second batch: %s", err)
	}

	_, ref := reference(t, all)
	if tree.N != ref.N || tree.Hash != ref.Hash {
		t.Fatalf("tree = {%d, %x}, want {%d, %x}", tree.N, tree.Hash, ref.N, ref.Hash)
	}

	// The verifying reader checks every tile against tree.Hash as it reads, so
	// a matching TreeHash with no error proves the persisted tiles are correct.
	got, err := tlog.TreeHash(tree.N, s.HashReader(t.Context(), tree))
	if err != nil {
		t.Fatalf("TreeHash over the store: %s", err)
	}
	if got != tree.Hash {
		t.Errorf("reconstructed root = %x, want %x", got, tree.Hash)
	}
}

// TestAppendAlignmentGuard confirms Append refuses a batch that does not start
// at the current tree size rather than silently corrupting the tree.
func TestAppendAlignmentGuard(t *testing.T) {
	s := tilestore.New(fs.New(t.TempDir()), testOrigin)
	_, err := s.Append(t.Context(), 0, entries(0, 100))
	if err != nil {
		t.Fatalf("Append: %s", err)
	}

	// A stale offset (re-appending from 0) must be refused.
	_, err = s.Append(t.Context(), 0, entries(100, 50))
	if err == nil {
		t.Error("Append at stale size 0 (tree is 100) succeeded, want error")
	}
	// A gap must be refused.
	_, err = s.Append(t.Context(), 150, entries(150, 50))
	if err == nil {
		t.Error("Append at gapped size 150 (tree is 100) succeeded, want error")
	}
	// The correct offset works.
	tree, err := s.Append(t.Context(), 100, entries(100, 50))
	if err != nil {
		t.Fatalf("Append at the correct size: %s", err)
	}
	if tree.N != 150 {
		t.Errorf("tree.N = %d, want 150", tree.N)
	}
}

// TestDifferentialAgainstXmod cross-checks the Store against x/mod across sizes
// that straddle tile boundaries: the root must match a flat reference, every
// stored Merkle tile must equal what x/mod's ReadTileData produces, and a
// vanilla TileHashReader over the stored tiles must reconstruct the root.
func TestDifferentialAgainstXmod(t *testing.T) {
	prefix := url.PathEscape(testOrigin)
	for _, size := range []int{1, 2, 255, 256, 257, 511, 512, 513, 1000} {
		t.Run(fmt.Sprintf("size=%d", size), func(t *testing.T) {
			backend := fs.New(t.TempDir())
			s := tilestore.New(backend, testOrigin)
			all := entries(0, size)
			tree, err := s.Append(t.Context(), 0, all)
			if err != nil {
				t.Fatalf("Append: %s", err)
			}

			ref, refTree := reference(t, all)
			if tree.N != refTree.N || tree.Hash != refTree.Hash {
				t.Fatalf("tree {%d, %x} != reference {%d, %x}", tree.N, tree.Hash, refTree.N, refTree.Hash)
			}

			// Every stored Merkle tile equals x/mod's ReadTileData over the
			// reference, so the path mapping and the extend-reader agree byte
			// for byte, not just at the root.
			for _, tl := range tlog.NewTiles(tile.Height, 0, int64(size)) {
				want, err := tlog.ReadTileData(tl, ref)
				if err != nil {
					t.Fatalf("ReadTileData(%s): %s", tile.Path(tl), err)
				}
				got, err := backend.Get(t.Context(), prefix+"/"+tile.Path(tl))
				if err != nil {
					t.Fatalf("Get(%s): %s", tile.Path(tl), err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("tile %s differs from x/mod", tile.Path(tl))
				}
			}

			// A vanilla TileHashReader over the stored tiles reconstructs the
			// root.
			vanilla := tlog.TileHashReader(tree, backendTiles{ctx: t.Context(), backend: backend, prefix: prefix})
			got, err := tlog.TreeHash(tree.N, vanilla)
			if err != nil {
				t.Fatalf("TreeHash over stored tiles: %s", err)
			}
			if got != tree.Hash {
				t.Errorf("reconstructed root %x != %x", got, tree.Hash)
			}
		})
	}
}

// TestCorruptionNeverYieldsValidProof pins the end-to-end safety property at
// the API the publisher uses: tampering with a stored tile must either fail the
// proof build or yield a proof that does not verify against the true root. It
// must never produce a passing proof. This holds regardless of where x/mod's
// reader happens to verify, which is the subtlety the leaf-read finding
// exposed.
func TestCorruptionNeverYieldsValidProof(t *testing.T) {
	backend := fs.New(t.TempDir())
	s := tilestore.New(backend, testOrigin)
	all := entries(0, 300)
	tree, err := s.Append(t.Context(), 0, all)
	if err != nil {
		t.Fatalf("Append: %s", err)
	}

	const start, end = 256, 264 // a subtree in the ragged right edge
	trueLeaves := make([]tlog.Hash, 0, end-start)
	for i := start; i < end; i++ {
		trueLeaves = append(trueLeaves, tlog.RecordHash(all[i]))
	}
	trueNode := subtree.Hash(trueLeaves)

	// Tamper with the tile holding those leaves.
	prefix := url.PathEscape(testOrigin)
	key := prefix + "/" + tile.Path(tlog.Tile{H: tile.Height, L: 0, N: 1, W: 300 - tile.Width})
	data, err := backend.Get(t.Context(), key)
	if err != nil {
		t.Fatalf("Get: %s", err)
	}
	data[0] ^= 0xff
	err = backend.Put(t.Context(), key, data)
	if err != nil {
		t.Fatalf("Put: %s", err)
	}

	proof, err := subtree.ConsistencyProof(start, end, tree.N, s.HashReader(t.Context(), tree))
	if err != nil {
		return // build failed: the tampering was caught
	}
	if subtree.VerifyConsistency(start, end, tree.N, proof, trueNode, tree.Hash) {
		t.Error("a proof built over a tampered tile verified against the true root")
	}
}

// TestIncrementalMatchesBulk confirms that appending in varied batches produces
// byte-identical Merkle tiles and the same tree as a single bulk append,
// pinning the extend-reader's behavior across batch boundaries.
func TestIncrementalMatchesBulk(t *testing.T) {
	all := entries(0, 500)

	bulkBackend := fs.New(t.TempDir())
	bulkTree, err := tilestore.New(bulkBackend, testOrigin).Append(t.Context(), 0, all)
	if err != nil {
		t.Fatalf("bulk Append: %s", err)
	}

	incBackend := fs.New(t.TempDir())
	inc := tilestore.New(incBackend, testOrigin)
	at := 0
	var incTree tlog.Tree
	for _, n := range []int{1, 99, 156, 1, 243} { // crosses tile boundaries unevenly
		incTree, err = inc.Append(t.Context(), int64(at), all[at:at+n])
		if err != nil {
			t.Fatalf("incremental Append at %d: %s", at, err)
		}
		at += n
	}
	if incTree != bulkTree {
		t.Fatalf("incremental tree {%d,%x} != bulk {%d,%x}", incTree.N, incTree.Hash, bulkTree.N, bulkTree.Hash)
	}

	prefix := url.PathEscape(testOrigin)
	for _, tl := range tlog.NewTiles(tile.Height, 0, 500) {
		key := prefix + "/" + tile.Path(tl)
		a, err := bulkBackend.Get(t.Context(), key)
		if err != nil {
			t.Fatalf("bulk Get %s: %s", tile.Path(tl), err)
		}
		b, err := incBackend.Get(t.Context(), key)
		if err != nil {
			t.Fatalf("incremental Get %s: %s", tile.Path(tl), err)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("tile %s differs between bulk and incremental", tile.Path(tl))
		}
	}
}

// TestAppendErrorLeavesStateIntact confirms a commit that dies partway through
// does not advance the tree state, and that retrying recovers, pinning the
// state-written-last invariant the recovery design depends on.
func TestAppendErrorLeavesStateIntact(t *testing.T) {
	faulty := &faultyBackend{inner: fs.New(t.TempDir())}
	s := tilestore.New(faulty, testOrigin)

	base, err := s.Append(t.Context(), 0, entries(0, 100))
	if err != nil {
		t.Fatalf("baseline Append: %s", err)
	}

	// Fail the second Put of the next Append, well before the state object that
	// Append writes last.
	faulty.failAt = faulty.puts + 2
	_, err = s.Append(t.Context(), 100, entries(100, 200))
	if err == nil {
		t.Fatal("Append succeeded despite an injected failure")
	}

	tree, err := s.Tree(t.Context())
	if err != nil {
		t.Fatalf("Tree: %s", err)
	}
	if tree != base {
		t.Fatalf("after a failed Append, tree = {%d,%x}, want baseline {%d,%x}", tree.N, tree.Hash, base.N, base.Hash)
	}

	// Retrying the same batch recovers and produces the correct tree.
	faulty.failAt = 0
	retried, err := s.Append(t.Context(), 100, entries(100, 200))
	if err != nil {
		t.Fatalf("retry Append: %s", err)
	}
	_, ref := reference(t, entries(0, 300))
	if retried.N != ref.N || retried.Hash != ref.Hash {
		t.Fatalf("recovered tree {%d,%x} != reference {%d,%x}", retried.N, retried.Hash, ref.N, ref.Hash)
	}
}

// TestReadLeaves recovers leaf hashes across an entry-bundle boundary and
// checks them against RecordHash of the original entries.
func TestReadLeaves(t *testing.T) {
	s := tilestore.New(fs.New(t.TempDir()), testOrigin)
	all := entries(0, 300)
	tree, err := s.Append(t.Context(), 0, all)
	if err != nil {
		t.Fatalf("Append: %s", err)
	}

	const start, end = 10, 270 // crosses the 256-entry bundle boundary
	leaves, err := s.ReadLeaves(t.Context(), tree.N, start, end)
	if err != nil {
		t.Fatalf("ReadLeaves: %s", err)
	}
	if len(leaves) != end-start {
		t.Fatalf("got %d leaves, want %d", len(leaves), end-start)
	}
	for i, h := range leaves {
		want := tlog.RecordHash(all[start+i])
		if h != want {
			t.Fatalf("leaf %d = %x, want %x", start+i, h, want)
		}
	}
}

// TestReadEntries reads ranges that span the bundle boundary and the partial
// last bundle.
func TestReadEntries(t *testing.T) {
	s := tilestore.New(fs.New(t.TempDir()), testOrigin)
	all := entries(0, 300)
	_, err := s.Append(t.Context(), 0, all)
	if err != nil {
		t.Fatalf("Append: %s", err)
	}

	// A range crossing the 256-entry bundle boundary.
	got, err := s.ReadEntries(t.Context(), 300, 250, 260)
	if err != nil {
		t.Fatalf("ReadEntries: %s", err)
	}
	if len(got) != 10 || string(got[0]) != "entry-250" || string(got[9]) != "entry-259" {
		t.Fatalf("ReadEntries(250,260) = len %d, [0]=%q, [9]=%q", len(got), got[0], got[len(got)-1])
	}

	// The whole tree, including the partial last bundle.
	full, err := s.ReadEntries(t.Context(), 300, 0, 300)
	if err != nil {
		t.Fatalf("ReadEntries all: %s", err)
	}
	if len(full) != 300 || string(full[256]) != "entry-256" {
		t.Fatalf("ReadEntries(0,300) = len %d, [256]=%q", len(full), full[256])
	}
}

// TestRecovery confirms a fresh Store over the same Backend recovers the tree
// state written by Append.
func TestRecovery(t *testing.T) {
	b := fs.New(t.TempDir())

	first := tilestore.New(b, testOrigin)
	empty, err := first.Tree(t.Context())
	if err != nil {
		t.Fatalf("Tree before append: %s", err)
	}
	if empty.N != 0 || empty.Hash != subtree.Hash(nil) {
		t.Errorf("empty tree = {%d, %x}, want {0, %x}", empty.N, empty.Hash, subtree.Hash(nil))
	}
	tree, err := first.Append(t.Context(), 0, entries(0, 300))
	if err != nil {
		t.Fatalf("Append: %s", err)
	}

	recovered, err := tilestore.New(b, testOrigin).Tree(t.Context())
	if err != nil {
		t.Fatalf("Tree after reopen: %s", err)
	}
	if recovered != tree {
		t.Errorf("recovered tree = {%d, %x}, want {%d, %x}", recovered.N, recovered.Hash, tree.N, tree.Hash)
	}
}

// TestCheckpointAndFetch covers checkpoint read/write and the serving paths.
func TestCheckpointAndFetch(t *testing.T) {
	s := tilestore.New(fs.New(t.TempDir()), testOrigin)
	_, err := s.Append(t.Context(), 0, entries(0, 300))
	if err != nil {
		t.Fatalf("Append: %s", err)
	}

	none, err := s.ReadCheckpoint(t.Context())
	if err != nil || none != nil {
		t.Fatalf("ReadCheckpoint before write = (%q, %v), want (nil, nil)", none, err)
	}
	cp := []byte("example.com/log\n300\n...\n")
	err = s.WriteCheckpoint(t.Context(), cp)
	if err != nil {
		t.Fatalf("WriteCheckpoint: %s", err)
	}
	got, err := s.ReadCheckpoint(t.Context())
	if err != nil || string(got) != string(cp) {
		t.Fatalf("ReadCheckpoint = (%q, %v), want (%q, nil)", got, err, cp)
	}

	served, err := s.Fetch(t.Context(), "checkpoint")
	if err != nil || string(served) != string(cp) {
		t.Fatalf("Fetch checkpoint = (%q, %v)", served, err)
	}
	// A real tile path serves; the internal state object and junk do not.
	tilePath := tile.EntryBundlePath(0, tile.Width)
	_, err = s.Fetch(t.Context(), tilePath)
	if err != nil {
		t.Errorf("Fetch %q: %s", tilePath, err)
	}
	_, err = s.Fetch(t.Context(), "state")
	if err == nil {
		t.Error("Fetch state succeeded, want rejection")
	}
	_, err = s.Fetch(t.Context(), "not-a-resource")
	if err == nil {
		t.Error("Fetch junk succeeded, want rejection")
	}
}

// TestSubtreeProofOverStore builds a subtree consistency proof through the
// Store's HashReader and verifies it, exercising the read path together with
// the subtree package.
func TestSubtreeProofOverStore(t *testing.T) {
	s := tilestore.New(fs.New(t.TempDir()), testOrigin)
	all := entries(0, 300)
	tree, err := s.Append(t.Context(), 0, all)
	if err != nil {
		t.Fatalf("Append: %s", err)
	}

	const start, end = 128, 256
	proof, err := subtree.ConsistencyProof(start, end, tree.N, s.HashReader(t.Context(), tree))
	if err != nil {
		t.Fatalf("ConsistencyProof: %s", err)
	}
	leaves, err := s.ReadLeaves(t.Context(), tree.N, start, end)
	if err != nil {
		t.Fatalf("ReadLeaves: %s", err)
	}
	nodeHash := subtree.Hash(leaves)
	if !subtree.VerifyConsistency(start, end, tree.N, proof, nodeHash, tree.Hash) {
		t.Error("VerifyConsistency rejected a proof built from the store")
	}
}
