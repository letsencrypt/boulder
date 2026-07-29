package tiles

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"testing"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/tlog"

	"github.com/letsencrypt/boulder/bs3/bs3test"
	"github.com/letsencrypt/boulder/trees/entry"
	"github.com/letsencrypt/boulder/trees/subtree"
)

func TestPath(t *testing.T) {
	type testCase struct {
		name   string
		coords tlog.Tile
		want   string
	}

	// Note: our code always ignores H; we leave it unset
	testCases := []testCase{
		{"zero one", tlog.Tile{L: -1, N: 0, W: 1}, "tile/entries/000.p/1"},
		{"zero 255", tlog.Tile{L: -1, N: 0, W: 255}, "tile/entries/000.p/255"},
		{"zero 256", tlog.Tile{L: -1, N: 0, W: 256}, "tile/entries/000"},
		{"ten 1000", tlog.Tile{L: -1, N: 10, W: 256}, "tile/entries/010"},
		{"example", tlog.Tile{L: -1, N: 1234067, W: 256}, "tile/entries/x001/x234/067"},
		{"example partial", tlog.Tile{L: -1, N: 1234067, W: 6}, "tile/entries/x001/x234/067.p/6"},
		{"level 2 zero one", tlog.Tile{L: 2, N: 0, W: 1}, "tile/2/000.p/1"},
		{"level 2 zero 255", tlog.Tile{L: 2, N: 0, W: 255}, "tile/2/000.p/255"},
		{"level 2 zero 256", tlog.Tile{L: 2, N: 0, W: 256}, "tile/2/000"},
		{"level 2 ten 1000", tlog.Tile{L: 2, N: 10, W: 256}, "tile/2/010"},
		{"level 2 example", tlog.Tile{L: 2, N: 1234067, W: 256}, "tile/2/x001/x234/067"},
		{"level 2 example partial", tlog.Tile{L: 2, N: 1234067, W: 6}, "tile/2/x001/x234/067.p/6"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := tilePath(tc.coords)
			if p != tc.want {
				t.Errorf("tilePath(%#v): got %s, want %s",
					tc.coords, p, tc.want)
			}
		})
	}
}

// testEntryBody returns the marshaled MTCLogEntry bytes for index i: empty
// extensions, type tbs_cert_entry, and a unique value with length varying by
// index (not a real TBSCertificateLogEntry).
func testEntryBody(i int) []byte {
	return fmt.Appendf(nil, "\x00\x00\x00\x01entry-%d-%s", i, bytes.Repeat([]byte{'x'}, i%37))
}

// bundledEntry returns a body with length framing (entry bundle format).
func bundledEntry(body []byte) []byte {
	b := cryptobyte.NewBuilder(nil)
	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(body)
	})
	return b.BytesOrPanic()
}

// testEntry returns a unique MTCLogEntry for index `i`.
func testEntry(i int) *entry.MTCLogEntry {
	mtcle, _, err := entry.NewBundleReader(bundledEntry(testEntryBody(i))).ReadEntry()
	if err != nil {
		panic(err)
	}
	return mtcle
}

// appendEntries appends test entries [start, end) to `f`, flushing every
// `flushEvery“ appends and once at the end.
func appendEntries(t *testing.T, f *Frontier, fs3 *bs3test.FakeS3, start, end int, prefix string, flushEvery int) {
	t.Helper()
	for i := start; i < end; i++ {
		err := f.AppendEntry(testEntry(i))
		if err != nil {
			t.Fatalf("AppendEntry(%d): %s", i, err)
		}
		if (i+1)%flushEvery == 0 {
			err := f.Publish(t.Context(), fs3, prefix)
			if err != nil {
				t.Fatalf("Flush after %d entries: %s", i+1, err)
			}
		}
	}
	err := f.Publish(t.Context(), fs3, prefix)
	if err != nil {
		t.Fatalf("final Flush: %s", err)
	}
}

// buildFrontier appends `n` test entries to a new Frontier, flushing every
// `flushEvery` appends and once at the end.
func buildFrontier(t *testing.T, fs3 *bs3test.FakeS3, n int, prefix string, flushEvery int) *Frontier {
	t.Helper()
	f := &Frontier{}
	appendEntries(t, f, fs3, 0, n, prefix, flushEvery)
	return f
}

// parseEntries splits an entries tile body into MTCLogEntry bytes
func parseEntries(t *testing.T, body []byte) [][]byte {
	t.Helper()
	var out [][]byte
	in := cryptobyte.String(body)
	for len(in) > 0 {
		var mtcleBytes cryptobyte.String
		if !in.ReadUint16LengthPrefixed(&mtcleBytes) {
			t.Fatalf("bad length")
		}
		out = append(out, mtcleBytes)
	}
	return out
}

func TestGetTile(t *testing.T) {
	fs3 := bs3test.New()
	gzipStr := "gzip"

	gz := func(data []byte) []byte {
		var buf bytes.Buffer
		w := gzip.NewWriter(&buf)
		_, err := w.Write(data)
		if err != nil {
			t.Fatal(err)
		}
		err = w.Close()
		if err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}

	raw := []byte("raw tile bytes")

	t.Run("missing tile", func(t *testing.T) {
		_, err := getTile(t.Context(), fs3, tlog.Tile{L: -1, N: 99, W: 1}, "")
		if err == nil {
			t.Errorf("getTile of nonexistent tile: got nil, want error")
		}
	})

	t.Run("no content encoding", func(t *testing.T) {
		fs3.Objects["tile/0/000.p/1"] = bs3test.StoredObject{Data: raw}
		got, err := getTile(t.Context(), fs3, tlog.Tile{L: 0, N: 0, W: 1}, "")
		if err != nil {
			t.Fatalf("getTile: %s", err)
		}
		if !bytes.Equal(got, raw) {
			t.Errorf("getTile: got %q, want %q", got, raw)
		}
	})

	t.Run("gzip", func(t *testing.T) {
		fs3.Objects["tile/entries/000.p/1"] = bs3test.StoredObject{Data: gz([]byte("compressed tile bytes")), ContentEncoding: &gzipStr}
		got, err := getTile(t.Context(), fs3, tlog.Tile{L: -1, N: 0, W: 1}, "")
		if err != nil {
			t.Fatalf("getTile: %s", err)
		}
		if !bytes.Equal(got, []byte("compressed tile bytes")) {
			t.Errorf("getTile: got %q, want %q", got, "compressed tile bytes")
		}
	})

	t.Run("corrupt gzip", func(t *testing.T) {
		fs3.Objects["tile/entries/000.p/2"] = bs3test.StoredObject{Data: []byte("not gzip"), ContentEncoding: &gzipStr}
		_, err := getTile(t.Context(), fs3, tlog.Tile{L: -1, N: 0, W: 2}, "")
		if err == nil {
			t.Errorf("getTile of corrupt gzip body: got nil, want error")
		}
	})

	t.Run("prefix", func(t *testing.T) {
		fs3.Objects["pre/tile/entries/000.p/3"] = bs3test.StoredObject{Data: gz([]byte("prefixed")), ContentEncoding: &gzipStr}
		got, err := getTile(t.Context(), fs3, tlog.Tile{L: -1, N: 0, W: 3}, "pre/")
		if err != nil {
			t.Fatalf("getTile with prefix: %s", err)
		}
		if !bytes.Equal(got, []byte("prefixed")) {
			t.Errorf("getTile: got %q, want %q", got, "prefixed")
		}
		_, err = getTile(t.Context(), fs3, tlog.Tile{L: -1, N: 0, W: 3}, "")
		if err == nil {
			t.Errorf("getTile without prefix of prefixed tile: got nil, want error")
		}
	})
}

// TestRoundTrip builds a Frontier, writes it, reads it, and checks for equality.
func TestRoundTrip(t *testing.T) {
	sizes := []int{1, 2, 100, 255, 256, 257, 511, 512, 513, 767, 768, 1000}
	for _, n := range sizes {
		t.Run(fmt.Sprintf("size %d", n), func(t *testing.T) {
			fs3 := bs3test.New()
			prefix := "p/"
			f := buildFrontier(t, fs3, n, prefix, 100)

			loaded, err := LoadFrontier(t.Context(), fs3, int64(n), prefix)
			if err != nil {
				t.Fatalf("Load(%d): %s", n, err)
			}
			if !reflect.DeepEqual(f, loaded) {
				t.Errorf("Load(%d): loaded frontier differs from flushed frontier:\ngot  %#v\nwant %#v",
					n, loaded, f)
			}
		})
	}
}

// TestStorageCorrectness verifies every tile written to storage against
// hashes computed in the test.
//
// Entry tiles must contain the appended entries, and the hash at each level
// must equal the MTH of all entries that the hash represents.
//
// Partway through, it simulates a restart: it reloads the frontier from
// storage and continues appending on the loaded frontier. The storage
// checks below therefore also check that appending to partial tiles
// loaded from storage works properly.
func TestStorageCorrectness(t *testing.T) {
	// Enough for three levels of hash tiles (n > 256*256).
	const n = 66000
	const reloadAt = 33333
	prefix := "tree/"

	bodies := make([][]byte, n)
	leafHashes := make([]tlog.Hash, n)
	for i := range bodies {
		bodies[i] = testEntryBody(i)
		leafHashes[i] = tlog.RecordHash(bodies[i])
	}

	fs3 := bs3test.New()
	buildFrontier(t, fs3, reloadAt, prefix, 999)

	f, err := LoadFrontier(t.Context(), fs3, reloadAt, prefix)
	if err != nil {
		t.Fatalf("Load at %d: %s", reloadAt, err)
	}
	appendEntries(t, f, fs3, reloadAt, n, prefix, 999)

	if f.TreeSize() != n {
		t.Errorf("TreeSize: got %d, want %d", f.TreeSize(), n)
	}

	// Verify the entry tiles.
	for tileIndex := 0; tileIndex*256 < n; tileIndex++ {
		width := min(256, n-tileIndex*256)
		coords := tlog.Tile{L: -1, N: int64(tileIndex), W: width}
		body, err := getTile(t.Context(), fs3, coords, prefix)
		if err != nil {
			t.Fatalf("reading entry tile %d: %s", tileIndex, err)
		}
		got := parseEntries(t, body)
		want := bodies[tileIndex*256 : tileIndex*256+width]
		if !reflect.DeepEqual(got, want) {
			t.Errorf("entry tile %d: entries don't match appended entries", tileIndex)
		}
	}

	// Verify the hash tiles. Read each tile that we expect to exist at final size.
	// For each hash in a tile, directly calculate the MTH of the leaves it represents
	// and compare.
	level := 0
	for layerSize := n; layerSize > 0; layerSize /= 256 {
		for tileIndex := 0; tileIndex*256 < layerSize; tileIndex++ {
			width := min(256, layerSize-tileIndex*256)
			coords := tlog.Tile{L: level, N: int64(tileIndex), W: width}
			body, err := getTile(t.Context(), fs3, coords, prefix)
			if err != nil {
				t.Fatalf("reading hash tile L=%d N=%d: %s", level, tileIndex, err)
			}
			if len(body) != width*tlog.HashSize {
				t.Fatalf("hash tile L=%d N=%d: got %d bytes, want %d", level, tileIndex, len(body), width*tlog.HashSize)
			}
			leavesPerHash := 1 << (8 * level)
			i := 0
			for got := range slices.Chunk(body, tlog.HashSize) {
				leafStart := (tileIndex*256 + i) * leavesPerHash
				leafEnd := leafStart + leavesPerHash
				want := subtree.MTH(leafHashes[leafStart:leafEnd])
				if !bytes.Equal(got, want[:]) {
					t.Errorf("hash tile L=%d N=%d index %d: got %s, want %s",
						level, tileIndex, i, base64.StdEncoding.EncodeToString(got), want)
				}
				i++
			}
		}
		level++
	}

	rootHash := f.RootHash()
	want, err := base64.StdEncoding.DecodeString("+AWMUCk19n0KCYumG1DKQ4dW3hcS8C/ygvZB7mP5NOU=")
	if err != nil {
		t.Fatal(err)
	}
	calculated := subtree.MTH(leafHashes)
	if !bytes.Equal(calculated[:], want) {
		t.Errorf("test assumptions failed: MTH(leafHashes) = %s, want %s", calculated, want)
	}
	if !bytes.Equal(rootHash[:], want) {
		t.Errorf("f.RootHash(): got %s, want %s", rootHash, want)
	}

	// Load and check equality with the in-memory copy one last time.
	loaded, err := LoadFrontier(t.Context(), fs3, n, prefix)
	if err != nil {
		t.Fatalf("Load: %s", err)
	}
	if !reflect.DeepEqual(f, loaded) {
		t.Errorf("Load: loaded frontier differs from flushed frontier")
	}
}

func TestLoadBadHashTile(t *testing.T) {
	fs3 := bs3test.New()
	buildFrontier(t, fs3, 1, "", 100)

	// Corrupt the level-0 hash tile so its length no longer matches its width.
	o := fs3.Objects["tile/0/000.p/1"]
	o.Data = o.Data[:len(o.Data)-1]
	fs3.Objects["tile/0/000.p/1"] = o

	_, err := LoadFrontier(t.Context(), fs3, 1, "")
	if err == nil {
		t.Errorf("Load with truncated hash tile: got nil, want error")
	}
}

// TestLoadBadEntryTile checks that Load rejects entry tiles whose contents
// don't parse as MTCLogEntries or don't match the tile width.
func TestLoadBadEntryTile(t *testing.T) {
	// A single validly-bundled test entry.
	bundled := bundledEntry(testEntryBody(0))

	testCases := []struct {
		name string
		body []byte
	}{
		{"garbage framing", []byte{0xff}},
		{"truncated entry", bundled[:len(bundled)-1]},
		{"unknown entry type", append([]byte{0x00, 0x04, 0x00, 0x00, 0x00, 0x02}, bundled...)},
		{"fewer entries than width", bundled},
		{"more entries than width", bytes.Repeat(bundled, 3)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fs3 := bs3test.New()
			buildFrontier(t, fs3, 2, "", 100)

			// Replace the entry tile with the bad body (uncompressed, so no
			// ContentEncoding).
			fs3.Objects["tile/entries/000.p/2"] = bs3test.StoredObject{Data: tc.body}

			_, err := LoadFrontier(t.Context(), fs3, 2, "")
			if err == nil {
				t.Errorf("Load with %s in entry tile: got nil, want error", tc.name)
			}
		})
	}
}

func TestLoadEmptyTree(t *testing.T) {
	_, err := LoadFrontier(t.Context(), bs3test.New(), 0, "")
	if err == nil {
		t.Errorf("Load(0): got nil, want error")
	}
}

// TestAppendMaxSizeEntry checks that a 65535-byte MTCLogEntry can be written.
func TestAppendMaxSizeEntry(t *testing.T) {
	body := append([]byte{0x00, 0x00, 0x00, 0x01}, bytes.Repeat([]byte{'v'}, 0xFFFF-4)...)
	mtcle, _, err := entry.NewBundleReader(bundledEntry(body)).ReadEntry()
	if err != nil {
		t.Fatalf("parsing max-size entry: %s", err)
	}

	f := &Frontier{}
	err = f.AppendEntry(mtcle)
	if err != nil {
		t.Fatalf("AppendEntry(65535-byte entry): %s", err)
	}
	err = f.Publish(t.Context(), bs3test.New(), "")
	if err != nil {
		t.Fatalf("Flush: %s", err)
	}
	if f.TreeSize() != 1 {
		t.Errorf("TreeSize: got %d, want 1", f.TreeSize())
	}
}

func TestFlushEmptyTree(t *testing.T) {
	f := &Frontier{}
	err := f.Publish(t.Context(), bs3test.New(), "")
	if err == nil {
		t.Errorf("Flush of empty tree: got nil, want error")
	}
}

// TestFlushClean checks the dirtyLevel behavior. After a Flush,
// a re-Flush should write nothing.
func TestFlushClean(t *testing.T) {
	fs3 := bs3test.New()
	f := buildFrontier(t, fs3, 10, "", 100)

	objectsBefore := len(fs3.Objects)
	err := f.Publish(t.Context(), fs3, "")
	if err != nil {
		t.Fatalf("second Flush: %s", err)
	}
	if len(fs3.Objects) != objectsBefore {
		t.Errorf("second Flush wrote %d objects, want 0", len(fs3.Objects)-objectsBefore)
	}
}

// TestRootHash checks RootHash against an MTH computed directly over the
// leaf hashes at a variety of interesting sizes, including sizes that are
// three tiles high.
func TestRootHash(t *testing.T) {
	n := 65792
	const checkAllUpTo = 600
	spotSizes := map[int]bool{65535: true, 65536: true, 65537: true, 65791: true, 65792: true}

	var leafHashes []tlog.Hash
	f := &Frontier{}
	for i := 0; i < n; i++ {
		mtcle := testEntry(i)
		leafHashes = append(leafHashes, tlog.RecordHash(testEntryBody(i)))

		err := f.AppendEntry(mtcle)
		if err != nil {
			t.Fatalf("AppendEntry(%d): %s", i, err)
		}

		n := i + 1
		if n <= checkAllUpTo || spotSizes[n] {
			if got, want := f.RootHash(), subtree.MTH(leafHashes); got != want {
				t.Errorf("RootHash at size %d: got %s, want %s", n, got, want)
			}
		}
	}
}

func TestWriteTileThatAlreadyExists(t *testing.T) {
	fs3 := bs3test.New()
	coords := tlog.Tile{L: 0, N: 0, W: 1}
	body := bytes.Repeat([]byte{'h'}, tlog.HashSize)

	err := writeTile(t.Context(), fs3, "", coords, body, false)
	if err != nil {
		t.Fatalf("first writeTile: %s", err)
	}

	err = writeTile(t.Context(), fs3, "", coords, body, false)
	if !errors.Is(err, ErrTileExists) {
		t.Errorf("second writeTile: got %s, want ErrTileExists", err)
	}
}

// TestClone checks that a cloned Frontier shares no mutable state with the
// original: growing the clone across a full-tile boundary must leave the
// original unchanged, and appending the same entries to the original must
// produce an identical tree that publishes identical tiles.
func TestClone(t *testing.T) {
	// Append more than one full tile's worth of entries, to exercise
	// fullHashesTiles and fullEntryTiles.
	frontier := &Frontier{}
	for i := 0; i < 260; i++ {
		err := frontier.AppendEntry(testEntry(i))
		if err != nil {
			t.Fatalf("AppendEntry(%d): %s", i, err)
		}
	}

	clonedAt := frontier.TreeSize()

	candidate := frontier.Clone()
	if !reflect.DeepEqual(frontier, candidate) {
		t.Fatalf("clone differs from original:\ngot  %#v\nwant %#v", candidate, frontier)
	}

	rootBefore := frontier.RootHash()

	// Add another full tile's worth of entries.
	const growTo = 520
	for i := clonedAt; i < growTo; i++ {
		err := candidate.AppendEntry(testEntry(int(i)))
		if err != nil {
			t.Fatalf("AppendEntry(%d) to clone: %s", i, err)
		}
	}

	gotTreeSize := frontier.TreeSize()
	if gotTreeSize != clonedAt {
		t.Errorf("original TreeSize after appending to clone: got %d, want %d", gotTreeSize, clonedAt)
	}

	gotRootHash := frontier.RootHash()
	if gotRootHash != rootBefore {
		t.Errorf("original RootHash after appending to clone: got %s, want %s", gotRootHash, rootBefore)
	}

	// Append the same entries to the original and check for equality.
	for i := clonedAt; i < growTo; i++ {
		err := frontier.AppendEntry(testEntry(int(i)))
		if err != nil {
			t.Fatalf("AppendEntry(%d) to original: %s", i, err)
		}
	}
	if !reflect.DeepEqual(frontier, candidate) {
		t.Errorf("after identical appends, original differs from clone:\ngot  %#v\nwant %#v", frontier, candidate)
	}

	// Published tiles must be the same, too.
	fs3f, fs3c := bs3test.New(), bs3test.New()
	err := frontier.Publish(t.Context(), fs3f, "")
	if err != nil {
		t.Fatalf("publishing original: %s", err)
	}
	err = candidate.Publish(t.Context(), fs3c, "")
	if err != nil {
		t.Fatalf("publishing clone: %s", err)
	}
	if !reflect.DeepEqual(fs3f.Objects, fs3c.Objects) {
		t.Errorf("original and clone published different tiles")
	}
}
