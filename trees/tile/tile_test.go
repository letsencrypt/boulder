package tile

import (
	"bytes"
	"strings"
	"testing"

	"golang.org/x/mod/sumdb/tlog"
)

func TestTilePath(t *testing.T) {
	t.Run("Vectors", func(t *testing.T) {
		cases := []struct {
			name   string
			tile   tlog.Tile
			expect string
		}{
			{"Level zero tile", tlog.Tile{H: 8, L: 0, N: 0, W: 256}, "tile/0/000"},
			{"Large index", tlog.Tile{H: 8, L: 0, N: 1234067, W: 256}, "tile/0/x001/x234/067"},
			{"Partial tile", tlog.Tile{H: 8, L: 1, N: 1, W: 1}, "tile/1/001.p/1"},
			{"Entry bundle", tlog.Tile{H: 8, L: -1, N: 0, W: 256}, "tile/entries/000"},
			{"Partial entry bundle", tlog.Tile{H: 8, L: -1, N: 273, W: 112}, "tile/entries/273.p/112"},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got := Path(tc.tile)
				if got != tc.expect {
					t.Errorf("Path(%+v) = %q, want %q", tc.tile, got, tc.expect)
				}
				parsed, err := ParsePath(got)
				if err != nil {
					t.Fatalf("ParsePath(%q): %s", got, err)
				}
				if parsed != tc.tile {
					t.Errorf("ParsePath(%q) = %+v, want %+v", got, parsed, tc.tile)
				}
			})
		}
	})

	// Every tile x/mod/sumdb/tlog computes for a tree must round-trip through
	// Path and ParsePath.
	t.Run("NewTiles round-trip", func(t *testing.T) {
		tiles := tlog.NewTiles(Height, 0, 70000)
		if len(tiles) == 0 {
			t.Fatal("NewTiles returned no tiles for a non-empty tree")
		}
		for _, tile := range tiles {
			parsed, err := ParsePath(Path(tile))
			if err != nil {
				t.Fatalf("ParsePath(%q): %s", Path(tile), err)
			}
			if parsed != tile {
				t.Errorf("round-trip of %+v = %+v", tile, parsed)
			}
		}
	})

	t.Run("Rejects unknown prefix", func(t *testing.T) {
		_, err := ParsePath("not/a/tile")
		if err == nil {
			t.Error("ParsePath(\"not/a/tile\") = nil error, want error")
		}
	})

	// The wire format has no height field, so a non-Height tile (e.g. the zero
	// value) cannot round-trip and must be rejected at the source.
	t.Run("Rejects non-Height input", func(t *testing.T) {
		for _, tile := range []tlog.Tile{
			{H: 0, L: 0, N: 5, W: 256},
			{H: 4, L: 0, N: 5, W: 16},
			{H: 16, L: 0, N: 5, W: 65536},
		} {
			func() {
				defer func() {
					r := recover()
					if r == nil {
						t.Errorf("Path(%+v) returned without panicking", tile)
					}
				}()
				_ = Path(tile)
			}()
		}
	})

	// c2sp.org/tlog-tiles: L MUST be in [0, 63]. x/mod's parser does not
	// enforce the upper bound, so we enforce it ourselves on both sides.
	t.Run("Rejects L out of range", func(t *testing.T) {
		for _, tile := range []tlog.Tile{
			{H: 8, L: 64, N: 0, W: 256},
			{H: 8, L: 70, N: 0, W: 256},
			{H: 8, L: -2, N: 0, W: 256},
		} {
			func() {
				defer func() {
					r := recover()
					if r == nil {
						t.Errorf("Path(%+v) returned without panicking", tile)
					}
				}()
				_ = Path(tile)
			}()
		}
		// ParsePath rejects tile/64/000 even though x/mod's parser would accept
		// it.
		_, err := ParsePath("tile/64/000")
		if err == nil {
			t.Error("ParsePath(\"tile/64/000\") = nil error, want error")
		}
	})

	// c2sp.org/tlog-tiles: a partial width is between 1 and 255. W == Width is
	// the full tile. Out-of-range widths would format into paths no conformant
	// parser accepts, so Path refuses them the same way it refuses bad H and L.
	t.Run("Rejects W or N out of range", func(t *testing.T) {
		for _, tile := range []tlog.Tile{
			{H: 8, L: 0, N: 0, W: 0},
			{H: 8, L: 0, N: 0, W: -3},
			{H: 8, L: 0, N: 0, W: 257},
			{H: 8, L: -1, N: 0, W: 300},
			{H: 8, L: 0, N: -1, W: 256},
		} {
			func() {
				defer func() {
					r := recover()
					if r == nil {
						t.Errorf("Path(%+v) returned without panicking", tile)
					}
				}()
				_ = Path(tile)
			}()
		}
	})

	// Without the digits-only level check, x/mod's "data" marker would let the
	// non-spec alias tile/data/<N> parse as an entry bundle.
	t.Run("Rejects non-spec paths", func(t *testing.T) {
		for _, path := range []string{
			"tile/data/000",
			"tile/data/000.p/5",
			"tile/-1/000",
			"tile//000",
			"tile/0/000.p/0",
			"tile/0/000.p/256",
			"tile/entries/000.p/256",
		} {
			_, err := ParsePath(path)
			if err == nil {
				t.Errorf("ParsePath(%q) = nil error, want error", path)
			}
		}
	})

	// Errors must name the caller's path, not the rewritten x/mod form.
	t.Run("Error names the original path", func(t *testing.T) {
		_, err := ParsePath("tile/01/000")
		if err == nil {
			t.Fatal("ParsePath(\"tile/01/000\") = nil error, want error")
		}
		if !strings.Contains(err.Error(), `"tile/01/000"`) {
			t.Errorf("error %q does not name the original path", err)
		}
	})
}

func TestEntryBundleRoundTrip(t *testing.T) {
	entries := [][]byte{{}, {0x01}, []byte("hello"), bytes.Repeat([]byte{0xab}, 1000)}
	var bundle []byte
	for _, e := range entries {
		var err error
		bundle, err = AppendEntry(bundle, e)
		if err != nil {
			t.Fatalf("AppendEntry: %s", err)
		}
	}

	got, err := ParseEntryBundle(bundle)
	if err != nil {
		t.Fatalf("ParseEntryBundle: %s", err)
	}
	if len(got) != len(entries) {
		t.Fatalf("ParseEntryBundle returned %d entries, want %d", len(got), len(entries))
	}
	for i := range entries {
		if !bytes.Equal(got[i], entries[i]) {
			t.Errorf("entry %d = %x, want %x", i, got[i], entries[i])
		}
	}
}

// TestParseEntryBundleCopies confirms parsed entries do not alias the input
// buffer, so mutating the buffer afterward cannot corrupt them.
func TestParseEntryBundleCopies(t *testing.T) {
	bundle, err := AppendEntry(nil, []byte("entry"))
	if err != nil {
		t.Fatalf("AppendEntry: %s", err)
	}
	got, err := ParseEntryBundle(bundle)
	if err != nil {
		t.Fatalf("ParseEntryBundle: %s", err)
	}
	for i := range bundle {
		bundle[i] = 0xff
	}
	if !bytes.Equal(got[0], []byte("entry")) {
		t.Errorf("parsed entry changed after mutating the bundle: %x", got[0])
	}
}

func TestParseEntryBundleRejects(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"Truncated length prefix", []byte{0x00}},
		// Length says 5, only 1 byte follows
		{"Truncated entry", []byte{0x00, 0x05, 0x01}},
		// A bundle is the entry form of a tile of width 1..Width, and
		// tlog-tiles says empty tiles MUST NOT be served, so an empty bundle is
		// not a valid resource.
		{"Empty bundle", nil},
		{"Empty bundle (non-nil)", []byte{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ParseEntryBundle(tc.data)
			if err == nil {
				t.Error("ParseEntryBundle = nil error, want error")
			}
		})
	}
}

// TestParseEntryBundleEntryCount pins the tlog-tiles bundle width bounds: a
// full bundle of Width entries parses, one more entry is rejected.
func TestParseEntryBundleEntryCount(t *testing.T) {
	var bundle []byte
	var err error
	for range Width {
		bundle, err = AppendEntry(bundle, []byte{0xaa})
		if err != nil {
			t.Fatalf("AppendEntry: %s", err)
		}
	}

	got, err := ParseEntryBundle(bundle)
	if err != nil {
		t.Fatalf("ParseEntryBundle of a full bundle: %s", err)
	}
	if len(got) != Width {
		t.Fatalf("ParseEntryBundle returned %d entries, want %d", len(got), Width)
	}

	bundle, err = AppendEntry(bundle, []byte{0xbb})
	if err != nil {
		t.Fatalf("AppendEntry: %s", err)
	}
	_, err = ParseEntryBundle(bundle)
	if err == nil {
		t.Errorf("ParseEntryBundle of a %d-entry bundle = nil error, want error", Width+1)
	}
}

func TestAppendEntryRejectsOversize(t *testing.T) {
	_, err := AppendEntry(nil, make([]byte, 65536))
	if err == nil {
		t.Error("AppendEntry of a 65536-byte entry = nil error, want error")
	}
}
