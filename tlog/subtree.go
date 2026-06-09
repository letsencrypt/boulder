package tlog

import (
	"crypto/sha256"
	"fmt"
	"math/bits"

	xtlog "golang.org/x/mod/sumdb/tlog"
)

// SubtreeHash returns the RFC 6962 Merkle Tree Hash over leaves treated as an
// independent list. The leaves must correspond to a ValidSubtree range for the
// result to be a meaningful subtree hash; SubtreeHash does not check that.
func SubtreeHash(leaves []xtlog.Hash) xtlog.Hash {
	switch len(leaves) {
	case 0:
		return xtlog.Hash(sha256.Sum256(nil))
	case 1:
		return leaves[0]
	}
	k := largestPowerOfTwoSmallerThan(int64(len(leaves)))
	return xtlog.NodeHash(SubtreeHash(leaves[:k]), SubtreeHash(leaves[k:]))
}

// largestPowerOfTwoSmallerThan returns the largest power of two strictly less
// than n, for n > 1.
func largestPowerOfTwoSmallerThan(n int64) int64 {
	return int64(1) << (bits.Len64(uint64(n-1)) - 1) //nolint:gosec // G115: n > 1, so n-1 is positive.
}

// ValidSubtree reports whether [start, end) is a valid subtree per the MTC
// draft: 0 <= start < end and start is a multiple of BIT_CEIL(end - start).
// Callers must separately check end <= tree size.
func ValidSubtree(start, end int64) bool {
	if start < 0 || start >= end {
		return false
	}
	// BIT_CEIL(end-start) is 2^Len64(end-start-1), and start is a multiple
	// of 2^k exactly when its low k bits are zero; testing trailing zeros
	// avoids materializing 2^k, which overflows for sizes near 2^63.
	return start == 0 || bits.TrailingZeros64(uint64(start)) >= bits.Len64(uint64(end-start-1)) //nolint:gosec // G115: 0 < start < end here, so both conversions are of non-negative values.
}

// rangeHash returns MTH(D[lo:hi)), the RFC 6962 Merkle Tree Hash over the leaves
// in [lo, hi) as an independent list, read through r. It decomposes [lo, hi)
// into its maximal aligned perfect subtrees and reads all of their roots in a
// single ReadHashes call before folding them together.
func rangeHash(lo, hi int64, r xtlog.HashReader) (xtlog.Hash, error) {
	indexes := perfectSubtreeIndexes(lo, hi, nil)
	hashes, err := r.ReadHashes(indexes)
	if err != nil {
		return xtlog.Hash{}, err
	}
	// r is caller-supplied; folding without this check would index out of
	// range on a reader returning a short slice.
	if len(hashes) != len(indexes) {
		return xtlog.Hash{}, fmt.Errorf("ReadHashes returned %d hashes for %d indexes", len(hashes), len(indexes))
	}
	h, _ := foldRangeHash(lo, hi, hashes)
	return h, nil
}

// perfectSubtree reports whether [lo, hi) is an aligned perfect subtree
// (power-of-two size, start aligned to that size), and if so its level.
func perfectSubtree(lo, hi int64) (level int, ok bool) {
	size := hi - lo
	if bits.OnesCount64(uint64(size)) != 1 || lo&(size-1) != 0 { //nolint:gosec // G115: callers pass lo < hi, so size is positive.
		return 0, false
	}
	return bits.TrailingZeros64(uint64(size)), true //nolint:gosec // G115: callers pass lo < hi, so size is positive.
}

// perfectSubtreeIndexes appends, in left-to-right order, the stored hash
// index of each subtree in the maximal aligned perfect decomposition of
// [lo, hi).
func perfectSubtreeIndexes(lo, hi int64, indexes []int64) []int64 {
	level, ok := perfectSubtree(lo, hi)
	if ok {
		return append(indexes, xtlog.StoredHashIndex(level, lo>>level))
	}
	k := largestPowerOfTwoSmallerThan(hi - lo)
	indexes = perfectSubtreeIndexes(lo, lo+k, indexes)
	return perfectSubtreeIndexes(lo+k, hi, indexes)
}

// foldRangeHash folds subtree roots, in the order perfectSubtreeIndexes lists
// them, into MTH(D[lo:hi)). It returns the hash and the unconsumed remainder.
func foldRangeHash(lo, hi int64, hashes []xtlog.Hash) (xtlog.Hash, []xtlog.Hash) {
	_, ok := perfectSubtree(lo, hi)
	if ok {
		return hashes[0], hashes[1:]
	}
	k := largestPowerOfTwoSmallerThan(hi - lo)
	left, rest := foldRangeHash(lo, lo+k, hashes)
	right, rest := foldRangeHash(lo+k, hi, rest)
	return xtlog.NodeHash(left, right), rest
}

// SubtreeConsistencyProof returns SUBTREE_PROOF(start, end, D_n) for the tree of
// size treeSize, reading stored hashes through r, per the MTC draft. [start,
// end) must be a valid subtree with end <= treeSize.
func SubtreeConsistencyProof(start, end, treeSize int64, r xtlog.HashReader) ([]xtlog.Hash, error) {
	if !ValidSubtree(start, end) || end > treeSize {
		return nil, fmt.Errorf("[%d, %d) is not a valid subtree of a tree of size %d", start, end, treeSize)
	}
	var proof []xtlog.Hash
	err := subtreeSubProof(start, end, 0, treeSize, true, r, &proof)
	if err != nil {
		return nil, err
	}
	return proof, nil
}

// subtreeSubProof implements SUBTREE_SUBPROOF(start, end, D_n, b) from the draft,
// where start and end are relative to the current subtree of size n rooted at
// absolute offset base, appending emitted hashes to proof.
func subtreeSubProof(start, end, base, n int64, known bool, r xtlog.HashReader, proof *[]xtlog.Hash) error {
	if start == 0 && end == n {
		if known {
			return nil
		}
		h, err := rangeHash(base, base+n, r)
		if err != nil {
			return err
		}
		*proof = append(*proof, h)
		return nil
	}
	k := largestPowerOfTwoSmallerThan(n)
	switch {
	case end <= k:
		err := subtreeSubProof(start, end, base, k, known, r, proof)
		if err != nil {
			return err
		}
		return appendRangeHash(base+k, base+n, r, proof)
	case k <= start:
		err := subtreeSubProof(start-k, end-k, base+k, n-k, known, r, proof)
		if err != nil {
			return err
		}
		return appendRangeHash(base, base+k, r, proof)
	default:
		// start < k < end implies start == 0 for a valid subtree (draft case
		// 3); SubtreeConsistencyProof's gate enforces validity.
		err := subtreeSubProof(0, end-k, base+k, n-k, false, r, proof)
		if err != nil {
			return err
		}
		return appendRangeHash(base, base+k, r, proof)
	}
}

func appendRangeHash(lo, hi int64, r xtlog.HashReader, proof *[]xtlog.Hash) error {
	h, err := rangeHash(lo, hi, r)
	if err != nil {
		return err
	}
	*proof = append(*proof, h)
	return nil
}

// VerifySubtreeConsistency verifies a subtree consistency proof for the subtree
// [start, end) of a tree of size n, given the subtree hash nodeHash and the tree
// root rootHash, following the "Verifying a Subtree Consistency Proof" procedure
// in the MTC draft.
func VerifySubtreeConsistency(start, end, n int64, proof []xtlog.Hash, nodeHash, rootHash xtlog.Hash) bool {
	if !ValidSubtree(start, end) || end > n {
		return false
	}

	fn, sn, tn := start, end-1, n-1
	if sn == tn {
		for fn != sn {
			fn >>= 1
			sn >>= 1
			tn >>= 1
		}
	} else {
		for fn != sn && sn&1 == 1 {
			fn >>= 1
			sn >>= 1
			tn >>= 1
		}
	}

	var fr, sr xtlog.Hash
	var rest []xtlog.Hash
	if fn == sn {
		fr, sr = nodeHash, nodeHash
		rest = proof
	} else {
		if len(proof) == 0 {
			return false
		}
		fr, sr = proof[0], proof[0]
		rest = proof[1:]
	}

	for _, c := range rest {
		if tn == 0 {
			return false
		}
		if sn&1 == 1 || sn == tn {
			if fn < sn {
				fr = xtlog.NodeHash(c, fr)
			}
			sr = xtlog.NodeHash(c, sr)
			for sn&1 == 0 {
				fn >>= 1
				sn >>= 1
				tn >>= 1
			}
		} else {
			sr = xtlog.NodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
		tn >>= 1
	}
	return tn == 0 && fr == nodeHash && sr == rootHash
}
