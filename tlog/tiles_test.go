package tlog

import (
	"strings"
	"testing"

	xtlog "golang.org/x/mod/sumdb/tlog"
)

func TestTilePath(t *testing.T) {
	t.Run("Vectors", func(t *testing.T) {
		cases := []struct {
			tile   xtlog.Tile
			expect string
		}{
			{xtlog.Tile{H: 8, L: 0, N: 0, W: 256}, "tile/0/000"},
			{xtlog.Tile{H: 8, L: 0, N: 1234067, W: 256}, "tile/0/x001/x234/067"},
			{xtlog.Tile{H: 8, L: 1, N: 1, W: 1}, "tile/1/001.p/1"},
			{xtlog.Tile{H: 8, L: -1, N: 0, W: 256}, "tile/entries/000"},
			{xtlog.Tile{H: 8, L: -1, N: 273, W: 112}, "tile/entries/273.p/112"},
		}
		for _, tc := range cases {
			got := TilePath(tc.tile)
			if got != tc.expect {
				t.Errorf("TilePath(%+v) = %q, want %q", tc.tile, got, tc.expect)
			}
			parsed, err := ParseTilePath(got)
			if err != nil {
				t.Fatalf("ParseTilePath(%q): %s", got, err)
			}
			if parsed != tc.tile {
				t.Errorf("ParseTilePath(%q) = %+v, want %+v", got, parsed, tc.tile)
			}
		}
	})

	// Every tile x/mod/sumdb/tlog computes for a tree must round-trip through
	// TilePath and ParseTilePath.
	t.Run("NewTiles round-trip", func(t *testing.T) {
		tiles := xtlog.NewTiles(TileHeight, 0, 70000)
		if len(tiles) == 0 {
			t.Fatal("NewTiles returned no tiles for a non-empty tree")
		}
		for _, tile := range tiles {
			parsed, err := ParseTilePath(TilePath(tile))
			if err != nil {
				t.Fatalf("ParseTilePath(%q): %s", TilePath(tile), err)
			}
			if parsed != tile {
				t.Errorf("round-trip of %+v = %+v", tile, parsed)
			}
		}
	})

	t.Run("Rejects unknown prefix", func(t *testing.T) {
		_, err := ParseTilePath("not/a/tile")
		if err == nil {
			t.Error("ParseTilePath(\"not/a/tile\") = nil error, want error")
		}
	})

	// The wire format has no height field, so a non-TileHeight tile (e.g.
	// the zero value) cannot round-trip and must be rejected at the source.
	t.Run("Rejects non-TileHeight input", func(t *testing.T) {
		for _, tile := range []xtlog.Tile{
			{H: 0, L: 0, N: 5, W: 256},
			{H: 4, L: 0, N: 5, W: 16},
			{H: 16, L: 0, N: 5, W: 65536},
		} {
			func() {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("TilePath(%+v) returned without panicking", tile)
					}
				}()
				_ = TilePath(tile)
			}()
		}
	})

	// c2sp.org/tlog-tiles: L MUST be in [0, 63]. x/mod's parser does not
	// enforce the upper bound, so we enforce it ourselves on both sides.
	t.Run("Rejects L out of range", func(t *testing.T) {
		for _, tile := range []xtlog.Tile{
			{H: 8, L: 64, N: 0, W: 256},
			{H: 8, L: 70, N: 0, W: 256},
			{H: 8, L: -2, N: 0, W: 256},
		} {
			func() {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("TilePath(%+v) returned without panicking", tile)
					}
				}()
				_ = TilePath(tile)
			}()
		}
		// ParseTilePath rejects tile/64/000 even though x/mod's parser
		// would accept it.
		_, err := ParseTilePath("tile/64/000")
		if err == nil {
			t.Error("ParseTilePath(\"tile/64/000\") = nil error, want error")
		}
	})

	// c2sp.org/tlog-tiles: a partial width is between 1 and 255; W ==
	// TileWidth is the full tile. Out-of-range widths would format into
	// paths no conformant parser accepts, so TilePath refuses them the same
	// way it refuses bad H and L.
	t.Run("Rejects W or N out of range", func(t *testing.T) {
		for _, tile := range []xtlog.Tile{
			{H: 8, L: 0, N: 0, W: 0},
			{H: 8, L: 0, N: 0, W: -3},
			{H: 8, L: 0, N: 0, W: 257},
			{H: 8, L: -1, N: 0, W: 300},
			{H: 8, L: 0, N: -1, W: 256},
		} {
			func() {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("TilePath(%+v) returned without panicking", tile)
					}
				}()
				_ = TilePath(tile)
			}()
		}
	})

	// Without the digits-only level check, x/mod's "data" marker would let
	// the non-spec alias tile/data/<N> parse as an entry bundle.
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
			_, err := ParseTilePath(path)
			if err == nil {
				t.Errorf("ParseTilePath(%q) = nil error, want error", path)
			}
		}
	})

	// Errors must name the caller's path, not the rewritten x/mod form.
	t.Run("Error names the original path", func(t *testing.T) {
		_, err := ParseTilePath("tile/01/000")
		if err == nil {
			t.Fatal("ParseTilePath(\"tile/01/000\") = nil error, want error")
		}
		if !strings.Contains(err.Error(), `"tile/01/000"`) {
			t.Errorf("error %q does not name the original path", err)
		}
	})
}
