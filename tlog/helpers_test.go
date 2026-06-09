package tlog

import (
	"fmt"
	"testing"

	xtlog "golang.org/x/mod/sumdb/tlog"
)

// seqLeaves returns n distinct entries for round-trip tests.
func seqLeaves(n int) [][]byte {
	entries := make([][]byte, n)
	for i := range entries {
		entries[i] = []byte{byte(i), byte(i >> 8), byte(i >> 16)}
	}
	return entries
}

// leafHashes returns the RFC 6962 leaf hashes of the given entries.
func leafHashes(entries [][]byte) []xtlog.Hash {
	hs := make([]xtlog.Hash, len(entries))
	for i, e := range entries {
		hs[i] = xtlog.RecordHash(e)
	}
	return hs
}

// memHashReader is an in-memory tlog.HashReader indexed by stored hash index.
type memHashReader []xtlog.Hash

func (m memHashReader) ReadHashes(indexes []int64) ([]xtlog.Hash, error) {
	out := make([]xtlog.Hash, len(indexes))
	for i, x := range indexes {
		if x < 0 || x >= int64(len(m)) {
			return nil, fmt.Errorf("stored hash index %d out of range [0, %d)", x, len(m))
		}
		out[i] = m[x]
	}
	return out, nil
}

// buildHashReader builds an in-memory HashReader over the given entries by
// accumulating their stored hashes in storage order.
func buildHashReader(t *testing.T, entries [][]byte) memHashReader {
	t.Helper()
	var m memHashReader
	for n, e := range entries {
		hashes, err := xtlog.StoredHashes(int64(n), e, m)
		if err != nil {
			t.Fatalf("StoredHashes(%d): %s", n, err)
		}
		m = append(m, hashes...)
	}
	return m
}
