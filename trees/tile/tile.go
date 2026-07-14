// Package tile implements the resource layer of c2sp.org/tlog-tiles: the paths
// that name Merkle hash tiles and entry bundles, and the byte encoding of
// entry bundles.
//
// https://c2sp.org/tlog-tiles
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

// Height is the tile height, which tlog-tiles fixes at 8.
const Height = 8

// Width is 2^Height: the hash count of a full tile and the entry count of a
// full entry bundle.
const Width = 1 << Height

// Path returns the tlog-tiles path naming t, such as "tile/0/x001/x234/067",
// or "tile/entries/000" for an entry bundle (level -1). A partial tile carries
// a ".p/<width>" suffix. Path panics when t has no spec path: height other
// than Height, level outside [-1, 63], width outside [1, Width], or a
// negative index. Such a tile is a bug in its producer, not input to
// validate.
func Path(t tlog.Tile) string {
	if t.H != Height {
		panic(fmt.Sprintf("tile.Path: tile height is %d, want %d", t.H, Height))
	}
	if t.L < -1 || t.L > 63 {
		panic(fmt.Sprintf("tile.Path: tile level %d out of range [-1, 63]", t.L))
	}
	if t.W < 1 || t.W > Width {
		panic(fmt.Sprintf("tile.Path: tile width %d out of range [1, %d]", t.W, Width))
	}
	if t.N < 0 {
		panic(fmt.Sprintf("tile.Path: negative index %d", t.N))
	}

	var b strings.Builder
	if t.L == -1 {
		b.WriteString("tile/entries/")
	} else {
		fmt.Fprintf(&b, "tile/%d/", t.L)
	}
	// The index is written as zero-padded three-digit groups, most significant
	// first, each but the last prefixed with "x".
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

// ParsePath parses an untrusted tlog-tiles path into a tile of height Height,
// which the path does not carry. It accepts exactly the strings Path produces:
// even a non-canonical spelling of valid coordinates (a zero-padded level, an
// index group without its "x") is an error.
func ParsePath(path string) (tlog.Tile, error) {
	// Both branches rewrite the path into x/mod's form, which carries the
	// height and names entry bundles "data", and let tlog.ParseTilePath parse
	// it. That parser re-marshals the result and rejects a mismatch, which is
	// what rules out non-canonical spellings.
	rest, ok := strings.CutPrefix(path, "tile/entries/")
	if ok {
		t, err := tlog.ParseTilePath(fmt.Sprintf("tile/%d/data/%s", Height, rest))
		if err != nil {
			// Report the caller's path, not the rewritten one.
			return tlog.Tile{}, fmt.Errorf("malformed tile path %q", path)
		}
		return t, nil
	}
	rest, ok = strings.CutPrefix(path, "tile/")
	if !ok {
		return tlog.Tile{}, fmt.Errorf("malformed tile path %q", path)
	}
	// Require a numeric level before rewriting. Without this, x/mod's "data"
	// marker would accept the non-spec path tile/data/<N> as an entry bundle.
	level, _, ok := strings.Cut(rest, "/")
	if !ok || level == "" || strings.ContainsFunc(level, func(r rune) bool { return r < '0' || r > '9' }) {
		return tlog.Tile{}, fmt.Errorf("malformed tile path %q", path)
	}
	t, err := tlog.ParseTilePath(fmt.Sprintf("tile/%d/%s", Height, rest))
	if err != nil {
		return tlog.Tile{}, fmt.Errorf("malformed tile path %q", path)
	}
	// x/mod accepts any level. The spec stops at 63.
	if t.L > 63 {
		return tlog.Tile{}, fmt.Errorf("tile level %d exceeds spec maximum 63", t.L)
	}
	return t, nil
}

// EntryBundlePath returns the tlog-tiles path naming entry bundle n with the
// given width: Width for a full bundle, or the entry count of the partial
// bundle at the tree's right edge.
func EntryBundlePath(n int64, width int) string {
	return Path(tlog.Tile{H: Height, L: -1, N: n, W: width})
}

// BundleRange returns the indices of the first and last entry bundles holding
// the entries [start, end). The range must be non-empty.
func BundleRange(start, end int64) (first, last int64) {
	return start / Width, (end - 1) / Width
}

// AppendEntry appends entry to bundle. tlog-tiles encodes a bundle as a
// sequence of big-endian uint16 length-prefixed entries, so an entry over
// 65535 bytes is an error. AppendEntry does not count entries. The Width cap
// is enforced by ParseEntryBundle on read.
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

// ParseEntryBundle decodes a bundle into its entries, each a copy sharing no
// memory with data. A truncated entry, more than Width entries, or an empty
// bundle is an error: a bundle holds the entries of a tile, whose width is 1
// to Width.
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
