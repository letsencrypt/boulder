package tlog

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// TileWidth is the number of entries in a full entry bundle and the number of
// hashes in a full tile: 2^TileHeight.
const TileWidth = 1 << TileHeight

// AppendEntry appends entry to an entry bundle with a big-endian uint16
// length prefix, per tlog-tiles, erroring if entry exceeds 65535 bytes.
// Bundles hold at most TileWidth entries; counting them on every append
// would be quadratic, so the cap is the caller's to respect, and
// ParseEntryBundle enforces it on read.
func AppendEntry(bundle, entry []byte) ([]byte, error) {
	if len(entry) > math.MaxUint16 {
		return nil, fmt.Errorf("entry of %d bytes exceeds the %d-byte limit", len(entry), math.MaxUint16)
	}
	bundle = binary.BigEndian.AppendUint16(bundle, uint16(len(entry))) //nolint:gosec // G115: len(entry) is bounded by the math.MaxUint16 check above.
	return append(bundle, entry...), nil
}

// ParseEntryBundle splits an entry bundle into its entries, each a copy. A
// bundle is the entry form of a tile of width 1 through TileWidth, so it
// must hold at least one entry ("Empty tiles MUST NOT be served") and at
// most TileWidth.
func ParseEntryBundle(data []byte) ([][]byte, error) {
	var entries [][]byte
	for len(data) > 0 {
		if len(entries) == TileWidth {
			return nil, fmt.Errorf("entry bundle has more than %d entries", TileWidth)
		}
		if len(data) < 2 {
			return nil, errors.New("truncated entry length prefix")
		}
		n := int(binary.BigEndian.Uint16(data))
		data = data[2:]
		if len(data) < n {
			return nil, errors.New("truncated entry")
		}
		entries = append(entries, bytes.Clone(data[:n]))
		data = data[n:]
	}
	if len(entries) == 0 {
		return nil, errors.New("empty entry bundle")
	}
	return entries, nil
}
