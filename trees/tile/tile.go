package tile

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"strings"

	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/mod/sumdb/tlog"
)

// Height is the tlog-tiles tile height. Pass it as the height argument to x/mod
// tile APIs such as tlog.NewTiles and tlog.TileHashReader.
const Height = 8

// Width is the entry count of a full bundle and the hash count of a full tile,
// 2^Height. Use it to find bundle boundaries: bundle b covers entries [b*Width,
// (b+1)*Width), and the right-edge bundle holds the remainder.
const Width = 1 << Height

// Path returns the tlog-tiles resource path for t relative to a log prefix,
// such as "tile/0/x001/x234/067" for a Merkle tile or "tile/entries/000" for an
// entry bundle. Pass a tile that came from x/mod (tlog.NewTiles or
// tlog.ReadTiles), not one you assembled by hand. For an entry bundle, prefer
// EntryBundlePath over building the level -1 tile yourself.
//
// Path panics on a tile it cannot represent, which signals a bug in the code
// producing tiles, not bad caller input.
func Path(t tlog.Tile) string {
	if t.H != Height {
		panic(fmt.Sprintf("tlog.Path: tile height is %d, want %d", t.H, Height))
	}
	if t.L < -1 || t.L > 63 {
		panic(fmt.Sprintf("tlog.Path: tile level %d out of range [-1, 63]", t.L))
	}
	if t.W < 1 || t.W > Width {
		panic(fmt.Sprintf("tlog.Path: tile width %d out of range [1, %d]", t.W, Width))
	}
	if t.N < 0 {
		panic(fmt.Sprintf("tlog.Path: negative index %d", t.N))
	}

	var b strings.Builder
	if t.L == -1 {
		b.WriteString("tile/entries/")
	} else {
		fmt.Fprintf(&b, "tile/%d/", t.L)
	}
	// Encode the index as zero-padded 3-digit groups joined by "/", with "x"
	// prefixing every group but the last.
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
	if t.W != Width {
		fmt.Fprintf(&b, ".p/%d", t.W)
	}
	return b.String()
}

// ParsePath validates and parses a tlog-tiles path into a height-Height
// tlog.Tile (the spec encoding carries no height). Reach for it when the path
// is untrusted, such as an incoming HTTP resource. It errors on anything
// non-canonical that Path would not have produced.
func ParsePath(path string) (tlog.Tile, error) {
	rest, ok := strings.CutPrefix(path, "tile/entries/")
	if ok {
		t, err := tlog.ParseTilePath(fmt.Sprintf("tile/%d/data/%s", Height, rest))
		if err != nil {
			// Name the caller's path, not the rewritten height-qualified one.
			return tlog.Tile{}, fmt.Errorf("malformed tile path %q", path)
		}
		return t, nil
	}
	rest, ok = strings.CutPrefix(path, "tile/")
	if !ok {
		return tlog.Tile{}, fmt.Errorf("malformed tile path %q", path)
	}
	level, _, ok := strings.Cut(rest, "/")
	if !ok || level == "" || strings.ContainsFunc(level, func(r rune) bool { return r < '0' || r > '9' }) {
		return tlog.Tile{}, fmt.Errorf("malformed tile path %q", path)
	}
	t, err := tlog.ParseTilePath(fmt.Sprintf("tile/%d/%s", Height, rest))
	if err != nil {
		return tlog.Tile{}, fmt.Errorf("malformed tile path %q", path)
	}
	// x/mod has no upper bound on L. The spec caps it at 63.
	if t.L > 63 {
		return tlog.Tile{}, fmt.Errorf("tile level %d exceeds spec maximum 63", t.L)
	}
	return t, nil
}

// EntryBundlePath returns the tlog-tiles path for the entry bundle at index n.
// Use it instead of building the level -1 tlog.Tile yourself. width is the
// bundle's entry count: Width for a full bundle, fewer only for the partial
// right-edge bundle.
func EntryBundlePath(n int64, width int) string {
	return Path(tlog.Tile{H: Height, L: -1, N: n, W: width})
}

// AppendEntry returns bundle with entry appended in the tlog-tiles bundle
// codec. Pass an empty bundle for the first entry. It errors when entry exceeds
// 65535 bytes. It does not count entries, so honoring the Width cap is yours to
// do. ParseEntryBundle enforces it on read.
func AppendEntry(bundle, entry []byte) ([]byte, error) {
	if len(entry) > math.MaxUint16 {
		return nil, fmt.Errorf("entry of %d bytes exceeds the %d-byte limit", len(entry), math.MaxUint16)
	}
	b := cryptobyte.NewBuilder(bundle)
	b.AddUint16LengthPrefixed(func(child *cryptobyte.Builder) {
		child.AddBytes(entry)
	})
	return b.Bytes()
}

// ParseEntryBundle decodes a bundle written by AppendEntry into its entries,
// each a fresh copy that does not alias data. It errors on a truncated entry,
// on more than Width entries, and on an empty bundle.
func ParseEntryBundle(data []byte) ([][]byte, error) {
	var entries [][]byte
	s := cryptobyte.String(data)
	for !s.Empty() {
		if len(entries) == Width {
			return nil, fmt.Errorf("entry bundle has more than %d entries", Width)
		}
		var entry cryptobyte.String
		if !s.ReadUint16LengthPrefixed(&entry) {
			return nil, errors.New("truncated entry")
		}
		entries = append(entries, bytes.Clone(entry))
	}
	if len(entries) == 0 {
		return nil, errors.New("empty entry bundle")
	}
	return entries, nil
}
