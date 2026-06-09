package tlog

import (
	"fmt"
	"strings"

	xtlog "golang.org/x/mod/sumdb/tlog"
)

// TileHeight is the tlog-tiles tile height: tiles span subtrees of height 8.
const TileHeight = 8

// TilePath returns the tlog-tiles path for t relative to a log prefix, such
// as "tile/0/x001/x234/067" for a Merkle tile or "tile/entries/000" for an
// entry bundle.
//
// The wire format encodes neither the height nor out-of-range coordinates,
// so a tile that cannot round-trip through ParseTilePath panics rather than
// silently naming a different tile: t.H must be TileHeight, t.L in [-1, 63]
// (-1 is x/mod's entry bundle sentinel; the spec caps L at 63), t.W in
// [1, TileWidth] (the spec caps partial widths at 255), and t.N must be
// non-negative.
func TilePath(t xtlog.Tile) string {
	if t.H != TileHeight {
		panic(fmt.Sprintf("tlog.TilePath: tile height is %d, want %d", t.H, TileHeight))
	}
	if t.L < -1 || t.L > 63 {
		panic(fmt.Sprintf("tlog.TilePath: tile level %d out of range [-1, 63]", t.L))
	}
	if t.W < 1 || t.W > TileWidth {
		panic(fmt.Sprintf("tlog.TilePath: tile width %d out of range [1, %d]", t.W, TileWidth))
	}
	if t.N < 0 {
		panic(fmt.Sprintf("tlog.TilePath: negative index %d", t.N))
	}

	var b strings.Builder
	if t.L == -1 {
		b.WriteString("tile/entries/")
	} else {
		fmt.Fprintf(&b, "tile/%d/", t.L)
	}
	// The index is zero-padded 3-digit groups separated by "/", with "x"
	// prefixing every group except the last.
	var groups []string
	for n := t.N; ; n /= 1000 {
		groups = append(groups, fmt.Sprintf("%03d", n%1000))
		if n < 1000 {
			break
		}
	}
	for i := len(groups) - 1; i > 0; i-- {
		b.WriteString("x")
		b.WriteString(groups[i])
		b.WriteString("/")
	}
	b.WriteString(groups[0])
	if t.W != TileWidth {
		fmt.Fprintf(&b, ".p/%d", t.W)
	}
	return b.String()
}

// ParseTilePath parses a tlog-tiles path produced by TilePath into a
// height-TileHeight tlog.Tile (the spec encoding has no height field).
// x/mod's parser enforces canonicality by re-serializing and comparing; on
// top of that, the level must be plain ASCII digits (x/mod would accept its
// internal "data" marker, aliasing tile/data/<N> to an entry bundle) and at
// most 63 per the spec.
func ParseTilePath(path string) (xtlog.Tile, error) {
	rest, ok := strings.CutPrefix(path, "tile/entries/")
	if ok {
		t, err := xtlog.ParseTilePath(fmt.Sprintf("tile/%d/data/%s", TileHeight, rest))
		if err != nil {
			// Name the caller's path, not the rewritten height-qualified one.
			return xtlog.Tile{}, fmt.Errorf("malformed tile path %q", path)
		}
		return t, nil
	}
	rest, ok = strings.CutPrefix(path, "tile/")
	if !ok {
		return xtlog.Tile{}, fmt.Errorf("malformed tile path %q", path)
	}
	level, _, ok := strings.Cut(rest, "/")
	if !ok || level == "" || strings.ContainsFunc(level, func(r rune) bool { return r < '0' || r > '9' }) {
		return xtlog.Tile{}, fmt.Errorf("malformed tile path %q", path)
	}
	t, err := xtlog.ParseTilePath(fmt.Sprintf("tile/%d/%s", TileHeight, rest))
	if err != nil {
		return xtlog.Tile{}, fmt.Errorf("malformed tile path %q", path)
	}
	// x/mod has no upper bound on L; the spec caps it at 63.
	if t.L > 63 {
		return xtlog.Tile{}, fmt.Errorf("tile level %d exceeds spec maximum 63", t.L)
	}
	return t, nil
}
