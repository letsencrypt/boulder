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

// leafHashes returns the RFC 6962 leaf hashes of the provided entries.
func leafHashes(entries [][]byte) []xtlog.Hash {
	hs := make([]xtlog.Hash, len(entries))
	for i, e := range entries {
		hs[i] = xtlog.RecordHash(e)
	}
	return hs
}

// inmemHashReader is an in-memory tlog.HashReader indexed by stored hash index.
type inmemHashReader []xtlog.Hash

func (m inmemHashReader) ReadHashes(indexes []int64) ([]xtlog.Hash, error) {
	out := make([]xtlog.Hash, len(indexes))
	for i, x := range indexes {
		if x < 0 || x >= int64(len(m)) {
			return nil, fmt.Errorf("stored hash index %d out of range [0, %d)", x, len(m))
		}
		out[i] = m[x]
	}
	return out, nil
}

func buildHashReader(t *testing.T, entries [][]byte) inmemHashReader {
	t.Helper()

	var m inmemHashReader
	for n, e := range entries {
		hashes, err := xtlog.StoredHashes(int64(n), e, m)
		if err != nil {
			t.Fatalf("StoredHashes(%d): %s", n, err)
		}
		m = append(m, hashes...)
	}
	return m
}
