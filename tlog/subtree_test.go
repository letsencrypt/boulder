package tlog

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/big"
	"slices"
	"testing"

	xtlog "golang.org/x/mod/sumdb/tlog"
)

// validSubtreeRef is the MTC-draft validity rule computed in arbitrary
// precision, independent of the package's int64 bit math: start must be a
// multiple of BIT_CEIL(end-start), the smallest power of two greater than
// or equal to the size.
func validSubtreeRef(start, end int64) bool {
	if start < 0 || start >= end {
		return false
	}
	bitCeil := big.NewInt(1)
	for bitCeil.Cmp(big.NewInt(end-start)) < 0 {
		bitCeil.Lsh(bitCeil, 1)
	}
	return new(big.Int).Mod(big.NewInt(start), bitCeil).Sign() == 0
}

// largestPow2LessThanRef returns the largest power of two strictly less than n
// (n > 1) in arbitrary precision.
func largestPow2LessThanRef(n int64) *big.Int {
	p := big.NewInt(1)
	for new(big.Int).Lsh(p, 1).Cmp(big.NewInt(n)) < 0 {
		p.Lsh(p, 1)
	}
	return p
}

// TestSubtreeBitMathMatchesSpec checks the int64 bit math against an
// arbitrary-precision reference in the large and overflow region the math/bits
// forms were introduced to handle. Small sizes are already covered transitively
// by the SubtreeHash vector and round-trip tests.
func TestSubtreeBitMathMatchesSpec(t *testing.T) {
	for _, n := range []int64{1 << 40, 1 << 61, 1 << 62, (1 << 62) + 1, math.MaxInt64 - 1, math.MaxInt64} {
		got := big.NewInt(largestPowerOfTwoSmallerThan(n))
		want := largestPow2LessThanRef(n)
		if got.Cmp(want) != 0 {
			t.Errorf("largestPowerOfTwoSmallerThan(%d) = %s, want %s", n, got, want)
		}
	}

	sizes := []int64{1 << 40, 1 << 61, 1 << 62, (1 << 62) + 1, math.MaxInt64}
	for _, size := range sizes {
		candidates := []int64{0, 1, size - 1, size, size + 1}
		if size <= math.MaxInt64/8 {
			candidates = append(candidates, 8*size, 8*size+1)
		}
		for _, start := range candidates {
			if start < 0 || start > math.MaxInt64-size {
				continue
			}
			end := start + size
			got := ValidSubtree(start, end)
			want := validSubtreeRef(start, end)
			if got != want {
				t.Errorf("ValidSubtree(%d, %d) = %v, want %v (size %d)", start, end, got, want, size)
			}
		}
	}
}

// failingHashReader is a tlog.HashReader whose every read fails, used to check
// that read errors propagate out of proof generation.
type failingHashReader struct{}

func (failingHashReader) ReadHashes([]int64) ([]xtlog.Hash, error) {
	return nil, errors.New("read failed")
}

// countingHashReader counts ReadHashes calls, to check read batching.
type countingHashReader struct {
	inner xtlog.HashReader
	calls int
}

func (c *countingHashReader) ReadHashes(indexes []int64) ([]xtlog.Hash, error) {
	c.calls++
	return c.inner.ReadHashes(indexes)
}

func TestValidSubtree(t *testing.T) {
	cases := []struct {
		start, end int64
		expect     bool
	}{
		{0, 1, true},
		{3, 4, true},
		{4, 8, true},
		{8, 12, true},
		{8, 13, true},
		{0, 14, true},
		{2, 4, true},
		{1, 3, false},
		{7, 9, false},
		{4, 4, false},
		{5, 4, false},
		// Large intervals must terminate (no overflow hang) and stay correct:
		// start 0 is always aligned, a non-zero start is not aligned to a 2^63
		// ceil.
		{0, math.MaxInt64, true},
		{1, math.MaxInt64, false},
	}
	for _, tc := range cases {
		got := ValidSubtree(tc.start, tc.end)
		if got != tc.expect {
			t.Errorf("ValidSubtree(%d, %d) = %v, want %v", tc.start, tc.end, got, tc.expect)
		}
	}
}

// TestSubtreeProofExamples checks the two worked examples from the MTC draft:
// the subtree consistency proofs for [4, 8) and [8, 13) in a tree of size 14.
func TestSubtreeProofExamples(t *testing.T) {
	leaves := leafHashes(seqLeaves(14))
	r := buildHashReader(t, seqLeaves(14))
	root := SubtreeHash(leaves)
	mth := func(start, end int64) xtlog.Hash { return SubtreeHash(leaves[start:end]) }

	cases := []struct {
		start, end int64
		expect     []xtlog.Hash
	}{
		{4, 8, []xtlog.Hash{mth(0, 4), mth(8, 14)}},
		{8, 13, []xtlog.Hash{mth(12, 13), mth(13, 14), mth(8, 12), mth(0, 8)}},
	}
	for _, tc := range cases {
		proof, err := SubtreeConsistencyProof(tc.start, tc.end, 14, r)
		if err != nil {
			t.Fatalf("SubtreeConsistencyProof(%d, %d, 14): %s", tc.start, tc.end, err)
		}
		if !slices.Equal(proof, tc.expect) {
			t.Errorf("SubtreeConsistencyProof(%d, %d, 14) = %x, want %x", tc.start, tc.end, proof, tc.expect)
		}
		if !VerifySubtreeConsistency(tc.start, tc.end, 14, proof, mth(tc.start, tc.end), root) {
			t.Errorf("VerifySubtreeConsistency(%d, %d, 14) rejected a valid proof", tc.start, tc.end)
		}
	}
}

// TestSubtreeProofIsConsistencyProof checks the draft identity SUBTREE_PROOF(0,
// end, D_n) = PROOF(end, D_n) by verifying the start=0 subtree proof with the
// x/mod/sumdb/tlog consistency verifier.
func TestSubtreeProofIsConsistencyProof(t *testing.T) {
	for n := int64(2); n <= 33; n++ {
		entries := seqLeaves(int(n))
		r := buildHashReader(t, entries)
		root := SubtreeHash(leafHashes(entries))
		for end := int64(1); end < n; end++ {
			proof, err := SubtreeConsistencyProof(0, end, n, r)
			if err != nil {
				t.Fatalf("SubtreeConsistencyProof(0, %d, %d): %s", end, n, err)
			}
			subRoot := SubtreeHash(leafHashes(entries)[:end])
			err = xtlog.CheckTree(proof, n, root, end, subRoot)
			if err != nil {
				t.Errorf("CheckTree for subtree proof (0, %d, %d): %s", end, n, err)
			}
		}
	}
}

// TestVerifySubtreeConsistencyRejectsBadInput covers the input gate that
// protects add-entries against adversarial proofs.
func TestVerifySubtreeConsistencyRejectsBadInput(t *testing.T) {
	leaves := leafHashes(seqLeaves(14))
	r := buildHashReader(t, seqLeaves(14))
	root := SubtreeHash(leaves)
	node := SubtreeHash(leaves[8:13])
	proof, err := SubtreeConsistencyProof(8, 13, 14, r)
	if err != nil {
		t.Fatalf("SubtreeConsistencyProof(8, 13, 14): %s", err)
	}

	cases := []struct {
		name          string
		start, end, n int64
		proof         []xtlog.Hash
	}{
		{"End past tree size", 8, 13, 12, proof},
		{"Misaligned subtree", 1, 3, 14, proof},
		{"Empty proof where one is required", 8, 13, 14, nil},
		{"Over-long proof", 8, 13, 14, append(slices.Clone(proof), proof...)},
	}
	for _, tc := range cases {
		if VerifySubtreeConsistency(tc.start, tc.end, tc.n, tc.proof, node, root) {
			t.Errorf("VerifySubtreeConsistency accepted bad input: %s", tc.name)
		}
	}
}

// TestSubtreeConsistencyProofRejectsBadInput covers the generation-side input
// gate.
func TestSubtreeConsistencyProofRejectsBadInput(t *testing.T) {
	r := buildHashReader(t, seqLeaves(14))
	cases := []struct {
		name             string
		start, end, size int64
	}{
		{"Misaligned subtree", 1, 3, 14},
		{"End past tree size", 0, 5, 4},
		{"Empty interval", 4, 4, 14},
	}
	for _, tc := range cases {
		_, err := SubtreeConsistencyProof(tc.start, tc.end, tc.size, r)
		if err == nil {
			t.Errorf("SubtreeConsistencyProof(%s) = nil error, want error", tc.name)
		}
	}
}

// TestSubtreeConsistencyProofPropagatesReadError checks that a HashReader error
// surfaces from generation rather than being swallowed.
func TestSubtreeConsistencyProofPropagatesReadError(t *testing.T) {
	_, err := SubtreeConsistencyProof(4, 8, 14, failingHashReader{})
	if err == nil {
		t.Error("SubtreeConsistencyProof with a failing reader = nil error, want error")
	}
}

// TestSubtreeConsistencyProofBatchesReads: each emitted proof hash costs at
// most one ReadHashes call, even spanning several perfect subtrees. The
// bound is one-sided so more aggressive batching cannot fail it.
func TestSubtreeConsistencyProofBatchesReads(t *testing.T) {
	r := &countingHashReader{inner: buildHashReader(t, seqLeaves(14))}
	proof, err := SubtreeConsistencyProof(4, 8, 14, r)
	if err != nil {
		t.Fatalf("SubtreeConsistencyProof(4, 8, 14): %s", err)
	}
	if r.calls > len(proof) {
		t.Errorf("ReadHashes calls = %d, want at most %d (one per emitted hash)", r.calls, len(proof))
	}
}

func TestSubtreeRoundTrip(t *testing.T) {
	for n := int64(1); n <= 48; n++ {
		entries := seqLeaves(int(n))
		leaves := leafHashes(entries)
		r := buildHashReader(t, entries)
		root := SubtreeHash(leaves)

		for start := int64(0); start < n; start++ {
			for end := start + 1; end <= n; end++ {
				if !ValidSubtree(start, end) {
					continue
				}
				node := SubtreeHash(leaves[start:end])
				proof, err := SubtreeConsistencyProof(start, end, n, r)
				if err != nil {
					t.Fatalf("SubtreeConsistencyProof(%d, %d, %d): %s", start, end, n, err)
				}

				if !VerifySubtreeConsistency(start, end, n, proof, node, root) {
					t.Errorf("VerifySubtreeConsistency(%d, %d, %d) rejected a valid proof", start, end, n)
				}
				if node != root && VerifySubtreeConsistency(start, end, n, proof, root, root) {
					t.Errorf("VerifySubtreeConsistency(%d, %d, %d) accepted a wrong subtree hash", start, end, n)
				}
				if len(proof) > 0 {
					bad := slices.Clone(proof)
					bad[0][0] ^= 0xff
					if VerifySubtreeConsistency(start, end, n, bad, node, root) {
						t.Errorf("VerifySubtreeConsistency(%d, %d, %d) accepted a tampered proof", start, end, n)
					}
				}
			}
		}
	}
}

// TestSubtreeHashVectors checks SubtreeHash against the RFC 6962 reference
// Merkle Tree Hash roots for trees of size 0 through 8.
func TestSubtreeHashVectors(t *testing.T) {
	entryHexes := []string{
		"",
		"00",
		"10",
		"2021",
		"3031",
		"40414243",
		"5051525354555657",
		"606162636465666768696a6b6c6d6e6f",
	}
	entries := make([][]byte, len(entryHexes))
	for i, h := range entryHexes {
		var err error
		entries[i], err = hex.DecodeString(h)
		if err != nil {
			t.Fatalf("decoding entry %q: %s", h, err)
		}
	}
	leaves := leafHashes(entries)
	expect := []string{
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		"6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
		"fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
		"aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
		"d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
		"4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
		"76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
		"ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
		"5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
	}
	for size := 0; size <= 8; size++ {
		got := SubtreeHash(leaves[:size])
		if hex.EncodeToString(got[:]) != expect[size] {
			t.Errorf("SubtreeHash(size %d) = %x, want %s", size, got, expect[size])
		}
	}
}

// TestTreeHashMatchesOracle checks that the in-memory HashReader feeds
// tlog.TreeHash the same roots SubtreeHash computes, validating the test
// scaffolding used by the subtree generation tests.
func TestTreeHashMatchesOracle(t *testing.T) {
	for n := 1; n <= 32; n++ {
		entries := seqLeaves(n)
		got, err := xtlog.TreeHash(int64(n), buildHashReader(t, entries))
		if err != nil {
			t.Fatalf("TreeHash(%d): %s", n, err)
		}
		want := SubtreeHash(leafHashes(entries))
		if got != want {
			t.Errorf("TreeHash(%d) = %x, want %x", n, got, want)
		}
	}
}

// TestSubtreeHashSpecVector pins SubtreeHash to the accumulated vector in
// the MTC draft appendix "Subtree Hashes" (draft revision 0b45981): every
// valid subtree to size 130, leaf i the single byte i, rolled into one
// SHA-256. It also pins ValidSubtree via the iteration gate.
func TestSubtreeHashSpecVector(t *testing.T) {
	const want = "94a95384a8c69acea9b50d035a58285b3a777cb7a724005faa5e1f1e1190007f"
	entries := make([][]byte, 130)
	for i := range entries {
		entries[i] = []byte{byte(i)}
	}
	leaves := leafHashes(entries)

	h := sha256.New()
	for end := int64(1); end <= 130; end++ {
		for start := int64(0); start < end; start++ {
			if !ValidSubtree(start, end) {
				continue
			}
			subtree := SubtreeHash(leaves[start:end])
			fmt.Fprintf(h, "[%d, %d) %s\n", start, end, hex.EncodeToString(subtree[:]))
		}
	}
	got := hex.EncodeToString(h.Sum(nil))
	if got != want {
		t.Errorf("subtree hash accumulator:\n got  %s\n want %s", got, want)
	}
}

// TestSubtreeConsistencyProofSpecVector pins SubtreeConsistencyProof to the
// accumulated vector in the MTC draft appendix "Subtree Consistency Proofs"
// (draft revision 0b45981): every valid subtree of every tree to size 130,
// rolled into one SHA-256.
func TestSubtreeConsistencyProofSpecVector(t *testing.T) {
	const want = "c586ebbb73a5621baf2140095d87dde934e3b6503a562a1a5215b8209edd083d"
	entries := make([][]byte, 130)
	for i := range entries {
		entries[i] = []byte{byte(i)}
	}
	r := buildHashReader(t, entries)

	h := sha256.New()
	for n := int64(0); n <= 130; n++ {
		for end := int64(1); end <= n; end++ {
			for start := int64(0); start < end; start++ {
				if !ValidSubtree(start, end) {
					continue
				}
				proof, err := SubtreeConsistencyProof(start, end, n, r)
				if err != nil {
					t.Fatalf("SubtreeConsistencyProof(%d, %d, %d): %s", start, end, n, err)
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

// shortHashReader violates the HashReader contract by returning fewer
// hashes than requested.
type shortHashReader struct{}

func (shortHashReader) ReadHashes(indexes []int64) ([]xtlog.Hash, error) {
	return nil, nil
}

func TestSubtreeConsistencyProofShortReader(t *testing.T) {
	// [0, 4) of a tree of size 8 forces a rangeHash over [4, 8), which asks
	// the reader for at least one stored hash.
	_, err := SubtreeConsistencyProof(0, 4, 8, shortHashReader{})
	if err == nil {
		t.Error("SubtreeConsistencyProof with a short HashReader = nil error, want error")
	}
}
