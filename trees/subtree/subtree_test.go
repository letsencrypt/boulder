package subtree

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"slices"
	"testing"

	"golang.org/x/mod/sumdb/tlog"
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
func leafHashes(entries [][]byte) []tlog.Hash {
	hs := make([]tlog.Hash, len(entries))
	for i, e := range entries {
		hs[i] = tlog.RecordHash(e)
	}
	return hs
}

// mth implements MTH(D[start:end]) from RFC 9162 section 2.1.1.
func mth(leaves []tlog.Hash) tlog.Hash {
	switch len(leaves) {
	case 0:
		return tlog.Hash(sha256.Sum256(nil))
	case 1:
		return leaves[0]
	default:
		// RFC 6962: split at the largest power of two smaller than n.
		k := 1 << (bits.Len(uint(len(leaves)-1)) - 1) //nolint:gosec // G115: the default case means len(leaves) >= 2, so len(leaves)-1 is positive.
		return tlog.NodeHash(mth(leaves[:k]), mth(leaves[k:]))
	}
}

// inmemHashReader is an in-memory tlog.HashReader indexed by stored hash index.
type inmemHashReader []tlog.Hash

func (m inmemHashReader) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	out := make([]tlog.Hash, len(indexes))
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
		hashes, err := tlog.StoredHashes(int64(n), e, m)
		if err != nil {
			t.Fatalf("StoredHashes(%d): %s", n, err)
		}
		m = append(m, hashes...)
	}
	return m
}
func TestValidSubtree(t *testing.T) {
	cases := []struct {
		name   string
		start  int64
		end    int64
		expect bool
	}{
		// Valid
		{"Single leaf", 0, 1, true},
		{"Start 0 aligns to any size", 0, 14, true},
		{"Aligned size-2 block", 2, 4, true},
		{"Single leaf at an odd offset", 3, 4, true},
		{"Aligned size-4 block", 4, 8, true},
		{"Aligned size-4 block, start a higher multiple of size", 8, 12, true},
		{"Non-power-of-two size, start aligned to BIT_CEIL", 8, 13, true},
		{"Start 0 aligns to the 2^63 ceiling", 0, math.MaxInt64, true},
		// Invalid
		{"Misaligned start", 1, 3, false},
		{"Misaligned start, higher offset", 7, 9, false},
		{"Empty", 4, 4, false},
		{"Inverted", 5, 4, false},
		{"Nonzero start can't align to the 2^63 ceiling", 1, math.MaxInt64, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := valid(tc.start, tc.end)
			if got != tc.expect {
				t.Errorf("Valid(%d, %d) = %v, want %v", tc.start, tc.end, got, tc.expect)
			}
		})
	}
}

// TestMTHAppendixVector pins mth to the accumulated digest in the MTC draft
// appendix C.1 Subtree Hashes for every valid subtree up to size 130, which the
// draft's reference implementation also reproduces.
func TestMTHAppendixVector(t *testing.T) {
	want := "94a95384a8c69acea9b50d035a58285b3a777cb7a724005faa5e1f1e1190007f"
	entries := make([][]byte, 130)
	for i := range entries {
		entries[i] = []byte{byte(i)}
	}
	leaves := leafHashes(entries)

	h := sha256.New()
	for end := int64(1); end <= 130; end++ {
		for start := int64(0); start < end; start++ {
			if !valid(start, end) {
				continue
			}
			subtree := mth(leaves[start:end])
			fmt.Fprintf(h, "[%d, %d) %s\n", start, end, hex.EncodeToString(subtree[:]))
		}
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		t.Errorf("subtree hash accumulator:\n got  %s\n want %s", got, want)
	}
}

// TestMTHMatchesTreeHash checks mth against x/mod/sumdb/tlog's TreeHash. It
// also validates the in-memory HashReader the proof tests rely on.
func TestMTHMatchesTreeHash(t *testing.T) {
	for n := 1; n <= 32; n++ {
		entries := seqLeaves(n)
		want, err := tlog.TreeHash(int64(n), buildHashReader(t, entries))
		if err != nil {
			t.Fatalf("TreeHash(%d): %s", n, err)
		}
		got := mth(leafHashes(entries))
		if got != want {
			t.Errorf("mth(%d leaves) = %x, want %x from x/mod TreeHash", n, got, want)
		}
	}
}

// TestSubtreeProofExamples covers the generate and verify round trip for the
// two worked examples in the MTC draft, which are small enough to be
// human-readable and have published expected proofs.
func TestSubtreeProofExamples(t *testing.T) {
	leaves := leafHashes(seqLeaves(14))
	reader := buildHashReader(t, seqLeaves(14))
	root := mth(leaves)
	mthAt := func(start, end int64) tlog.Hash {
		return mth(leaves[start:end])
	}

	cases := []struct {
		name   string
		start  int64
		end    int64
		expect []tlog.Hash
	}{
		{"Aligned size-4 block", 4, 8, []tlog.Hash{mthAt(0, 4), mthAt(8, 14)}},
		{"Ragged subtree at an odd offset", 8, 13, []tlog.Hash{mthAt(12, 13), mthAt(13, 14), mthAt(8, 12), mthAt(0, 8)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proof, err := ConsistencyProof(tc.start, tc.end, 14, reader)
			if err != nil {
				t.Fatalf("ConsistencyProof(%d, %d, 14): %s", tc.start, tc.end, err)
			}
			if !slices.Equal(proof, tc.expect) {
				t.Errorf("ConsistencyProof(%d, %d, 14) = %x, want %x", tc.start, tc.end, proof, tc.expect)
			}
			if !VerifyConsistency(tc.start, tc.end, 14, proof, mthAt(tc.start, tc.end), root) {
				t.Errorf("VerifyConsistency(%d, %d, 14) rejected a valid proof", tc.start, tc.end)
			}
		})
	}
}

// TestSubtreeConsistencyProofAppendixVector pins ConsistencyProof to the
// accumulated digest in MTC draft appendix C.3 Subtree Consistency Proofs,
// covering every valid subtree of every tree up to size 130. It also runs each
// generated proof through VerifyConsistency, pinning the verifier's accept path
// across the full range, including the start > 0 proofs that x/mod/sumdb/tlog's
// CheckTree (prefix-only) cannot oracle.
func TestSubtreeConsistencyProofAppendixVector(t *testing.T) {
	want := "c586ebbb73a5621baf2140095d87dde934e3b6503a562a1a5215b8209edd083d"
	entries := make([][]byte, 130)
	for i := range entries {
		entries[i] = []byte{byte(i)}
	}
	leaves := leafHashes(entries)
	reader := buildHashReader(t, entries)

	h := sha256.New()
	for n := int64(0); n <= 130; n++ {
		root := mth(leaves[:n])
		for end := int64(1); end <= n; end++ {
			for start := int64(0); start < end; start++ {
				if !valid(start, end) {
					continue
				}
				proof, err := ConsistencyProof(start, end, n, reader)
				if err != nil {
					t.Fatalf("ConsistencyProof(%d, %d, %d): %s", start, end, n, err)
				}
				node := mth(leaves[start:end])
				if !VerifyConsistency(start, end, n, proof, node, root) {
					t.Errorf("VerifyConsistency(%d, %d, %d) rejected a valid proof", start, end, n)
				}
				fmt.Fprintf(h, "[%d, %d) %d", start, end, n)
				for _, p := range proof {
					fmt.Fprintf(h, " %s", hex.EncodeToString(p[:]))
				}
				h.Write([]byte{'\n'})
			}
		}
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		t.Errorf("subtree consistency proof accumulator:\n got  %s\n want %s", got, want)
	}
}

func TestSubtreeConsistencyProofRejectsBadInput(t *testing.T) {
	reader := buildHashReader(t, seqLeaves(14))
	cases := []struct {
		name  string
		start int64
		end   int64
		size  int64
	}{
		{"Misaligned subtree", 1, 3, 14},
		{"End past tree size", 0, 5, 4},
		{"Empty interval", 4, 4, 14},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ConsistencyProof(tc.start, tc.end, tc.size, reader)
			if err == nil {
				t.Errorf("ConsistencyProof(%s) = nil error, want error", tc.name)
			}
		})
	}
}

// failingHashReader fails every read.
type failingHashReader struct{}

func (failingHashReader) ReadHashes([]int64) ([]tlog.Hash, error) {
	return nil, errors.New("read failed")
}

func TestSubtreeConsistencyProofPropagatesReadError(t *testing.T) {
	_, err := ConsistencyProof(4, 8, 14, failingHashReader{})
	if err == nil {
		t.Error("ConsistencyProof with a failing reader = nil error, want error")
	}
}

// shortHashReader returns one fewer hash than was requested.
type shortHashReader struct {
	inner tlog.HashReader
}

func (s shortHashReader) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	hashes, err := s.inner.ReadHashes(indexes)
	if err != nil || len(hashes) == 0 {
		return hashes, err
	}
	return hashes[:len(hashes)-1], nil
}

func TestSubtreeConsistencyProofShortReader(t *testing.T) {
	reader := shortHashReader{inner: buildHashReader(t, seqLeaves(7))}
	_, err := ConsistencyProof(0, 4, 7, reader)
	if err == nil {
		t.Error("ConsistencyProof with a short HashReader = nil error, want error")
	}
}

// countingHashReader counts ReadHashes calls, to check read batching.
type countingHashReader struct {
	inner tlog.HashReader
	calls int
}

func (c *countingHashReader) ReadHashes(indexes []int64) ([]tlog.Hash, error) {
	c.calls++
	return c.inner.ReadHashes(indexes)
}

// TestSubtreeConsistencyProofBatchesReads checks that each emitted proof hash
// costs at most one ReadHashes call.
func TestSubtreeConsistencyProofBatchesReads(t *testing.T) {
	reader := &countingHashReader{inner: buildHashReader(t, seqLeaves(14))}

	// 	ConsistencyProof(4, 8, 14) emits two proof hashes: MTH(0, 4), a perfect
	// 	sibling, and MTH(8, 14), a ragged sibling that requires two stored
	// 	hashes, [8,12) + [12,14), to compute.
	proof, err := ConsistencyProof(4, 8, 14, reader)
	if err != nil {
		t.Fatalf("ConsistencyProof(4, 8, 14): %s", err)
	}

	// Batching should fold each emitted hash's reads into one ReadHashes, so
	// the call count stays at or below len(proof). Without it, MTH(8, 14)'s two
	// stored hashes would cost an extra call.
	if reader.calls > len(proof) {
		t.Errorf("ReadHashes calls = %d, want at most %d (one per emitted hash)", reader.calls, len(proof))
	}
}

func TestVerifySubtreeConsistencyRejectsBadInput(t *testing.T) {
	leaves := leafHashes(seqLeaves(14))
	reader := buildHashReader(t, seqLeaves(14))
	root := mth(leaves)
	node := mth(leaves[8:13])
	proof, err := ConsistencyProof(8, 13, 14, reader)
	if err != nil {
		t.Fatalf("ConsistencyProof(8, 13, 14): %s", err)
	}

	cases := []struct {
		name  string
		start int64
		end   int64
		n     int64
		proof []tlog.Hash
	}{
		{"Misaligned subtree", 1, 3, 14, proof},
		{"End past tree size", 8, 13, 12, proof},
		{"Empty proof where one is required", 8, 13, 14, nil},
		{"Over-long proof", 8, 13, 14, append(slices.Clone(proof), proof...)},
		{"Too short proof", 8, 13, 14, proof[:len(proof)-1]},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if VerifyConsistency(tc.start, tc.end, tc.n, tc.proof, node, root) {
				t.Errorf("VerifyConsistency accepted inconsistent input: %s", tc.name)
			}
		})
	}
}

// TestVerifySubtreeConsistencyMatchesXtlogCheckTree independently verifies
// VerifyConsistency against x/mod/sumdb/tlog's CheckTree, which implements the
// same algorithm but only for prefix subtrees [0, end).
func TestVerifySubtreeConsistencyMatchesXtlogCheckTree(t *testing.T) {
	agree := func(t *testing.T, end, n int64, proof []tlog.Hash, subRoot, root tlog.Hash, label string) bool {
		t.Helper()

		ours := VerifyConsistency(0, end, n, proof, subRoot, root)
		theirs := tlog.CheckTree(proof, n, root, end, subRoot) == nil
		if ours != theirs {
			t.Errorf("(0, %d, %d) %s: VerifyConsistency=%v, CheckTree=%v", end, n, label, ours, theirs)
		}
		return ours
	}

	for n := int64(2); n <= 33; n++ {
		entries := seqLeaves(int(n))
		reader := buildHashReader(t, entries)
		leaves := leafHashes(entries)
		root := mth(leaves)
		for end := int64(1); end < n; end++ {
			subRoot := mth(leaves[:end])
			proof, err := ConsistencyProof(0, end, n, reader)
			if err != nil {
				t.Fatalf("ConsistencyProof(0, %d, %d): %s", end, n, err)
			}

			if !agree(t, end, n, proof, subRoot, root, "valid") {
				t.Errorf("(0, %d, %d) both verifiers rejected a valid proof", end, n)
			}

			for i := range proof {
				bad := slices.Clone(proof)
				bad[i][0] ^= 0xff
				agree(t, end, n, bad, subRoot, root, fmt.Sprintf("corrupt proof[%d]", i))
			}
			badSub := subRoot
			badSub[0] ^= 0xff
			agree(t, end, n, proof, badSub, root, "corrupt subtree root")
			badRoot := root
			badRoot[0] ^= 0xff
			agree(t, end, n, proof, subRoot, badRoot, "corrupt tree root")
		}
	}
}

func TestVerifySubtreeConsistencyRejectsMismatchedProof(t *testing.T) {
	leaves := leafHashes(seqLeaves(14))
	reader := buildHashReader(t, seqLeaves(14))
	root := mth(leaves)
	mthAt := func(start, end int64) tlog.Hash {
		return mth(leaves[start:end])
	}

	proof, err := ConsistencyProof(8, 13, 14, reader)
	if err != nil {
		t.Fatalf("ConsistencyProof(8, 13, 14): %s", err)
	}
	if !VerifyConsistency(8, 13, 14, proof, mthAt(8, 13), root) {
		t.Fatal("valid proof for [8, 13) of size-14 tree was rejected")
	}

	otherEntries := make([][]byte, 14)
	for i := range otherEntries {
		otherEntries[i] = []byte{0xa1, byte(i)}
	}
	rootAt13 := mth(leafHashes(seqLeaves(13)))
	otherRoot := mth(leafHashes(otherEntries))

	cases := []struct {
		name     string
		start    int64
		end      int64
		n        int64
		node     tlog.Hash
		treeRoot tlog.Hash
	}{
		{"Incorrect subtree coordinates", 4, 8, 14, mthAt(4, 8), root},
		{"Incorrect tree size (smaller)", 8, 13, 13, mthAt(8, 13), rootAt13},
		{"Incorrect tree root", 8, 13, 14, mthAt(8, 13), otherRoot},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if VerifyConsistency(tc.start, tc.end, tc.n, proof, tc.node, tc.treeRoot) {
				t.Errorf("incorrectly verified the [8,13)/size-14 proof against %s", tc.name)
			}
		})
	}
}

// TestSubtreeRoundTrip covers the generate and verify round trip and checks
// that the verifier rejects tampering.
func TestSubtreeRoundTrip(t *testing.T) {
	for n := int64(1); n <= 48; n++ {
		entries := seqLeaves(int(n))
		leaves := leafHashes(entries)
		reader := buildHashReader(t, entries)
		root := mth(leaves)

		for start := int64(0); start < n; start++ {
			for end := start + 1; end <= n; end++ {
				if !valid(start, end) {
					continue
				}
				node := mth(leaves[start:end])
				proof, err := ConsistencyProof(start, end, n, reader)
				if err != nil {
					t.Fatalf("ConsistencyProof(%d, %d, %d): %s", start, end, n, err)
				}
				if !VerifyConsistency(start, end, n, proof, node, root) {
					t.Errorf("(%d, %d, %d) rejected the valid proof", start, end, n)
				}

				// Flipping a byte in any proof hash must result in a rejection.
				for i := range proof {
					bad := slices.Clone(proof)
					bad[i][0] ^= 0xff
					if VerifyConsistency(start, end, n, bad, node, root) {
						t.Errorf("(%d, %d, %d) accepted a proof with hash %d corrupted", start, end, n, i)
					}
				}
				// Flipping a byte in the node hash must result in a rejection.
				badNode := node
				badNode[0] ^= 0xff
				if VerifyConsistency(start, end, n, proof, badNode, root) {
					t.Errorf("(%d, %d, %d) accepted a corrupted node hash", start, end, n)
				}
				// Flipping a byte in the root hash must result in a rejection.
				badRoot := root
				badRoot[0] ^= 0xff
				if VerifyConsistency(start, end, n, proof, node, badRoot) {
					t.Errorf("(%d, %d, %d) accepted a corrupted root hash", start, end, n)
				}
			}
		}
	}
}
