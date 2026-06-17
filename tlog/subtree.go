package tlog

import (
	"crypto/sha256"
	"fmt"
	"math/bits"

	xtlog "golang.org/x/mod/sumdb/tlog"
)

// largestPowerOfTwoSmallerThan returns the largest power of two strictly less
// than n, for n > 1. n <= 1 results in a panic.
func largestPowerOfTwoSmallerThan(n int64) int64 {
	if n <= 1 {
		panic(fmt.Sprintf("n must be > 1, got %d", n))
	}
	return int64(1) << (bits.Len64(uint64(n-1)) - 1) //nolint:gosec // G115: n > 1, so n-1 is positive.
}

// SubtreeHash returns the RFC 6962 section 2.1 Merkle Tree Hash over leaves
// treated as an independent list. Note: callers must ensure the leaves
// correspond to a ValidSubtree range.
func SubtreeHash(leaves []xtlog.Hash) xtlog.Hash {
	switch len(leaves) {
	case 0:
		// The hash of an empty list is the hash of an empty string.
		return xtlog.Hash(sha256.Sum256(nil))
	case 1:
		// The hash of a list with one entry is just the leaf hash.
		return leaves[0]
	}

	// Split the list into two subtree roots, the left being a "perfect" subtree
	// and the right being the remainder which may or may not be perfect.
	k := largestPowerOfTwoSmallerThan(int64(len(leaves)))

	// Hash the two subtree roots together as SHA-256(0x01 || left || right).
	return xtlog.NodeHash(SubtreeHash(leaves[:k]), SubtreeHash(leaves[k:]))
}

// ValidSubtree reports whether [start, end) is a valid subtree per the MTC
// draft section 4.1 Definition of a Subtree: 0 <= start < end and start is a
// multiple of BIT_CEIL(end - start).
func ValidSubtree(start, end int64) bool {
	if start < 0 || start >= end {
		// A subtree must have 0 <= start < end.
		return false
	}
	// bitCeil is BIT_CEIL(end-start). A multiple of a power of two has its low
	// bits zero, so start & (bitCeil-1) == 0 becomes our validity test.
	bitCeil := uint64(1) << bits.Len64(uint64(end-start-1)) //nolint:gosec // G115: start < end, so end-start-1 is non-negative.
	return uint64(start)&(bitCeil-1) == 0
}

// perfectSubtree reports whether [lo, hi) is an aligned perfect subtree
// (power-of-two size, start aligned to that size), and if so its level.
func perfectSubtree(lo, hi int64) (level int, ok bool) {
	if lo < 0 || lo >= hi || hi < 0 {
		panic(fmt.Sprintf("invalid range [%d, %d)", lo, hi))
	}
	size := hi - lo
	if bits.OnesCount64(uint64(size)) != 1 || lo&(size-1) != 0 { //nolint:gosec // G115: callers pass lo < hi, so size is positive.
		return 0, false
	}
	return bits.TrailingZeros64(uint64(size)), true //nolint:gosec // G115: callers pass lo < hi, so size is positive.
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

// perfectSubtreeIndexes appends, in left-to-right order, the stored hash index
// of each subtree in the maximal aligned perfect decomposition of [lo, hi).
func perfectSubtreeIndexes(lo, hi int64, indexes []int64) []int64 {
	level, ok := perfectSubtree(lo, hi)
	if ok {
		return append(indexes, xtlog.StoredHashIndex(level, lo>>level))
	}
	k := largestPowerOfTwoSmallerThan(hi - lo)
	indexes = perfectSubtreeIndexes(lo, lo+k, indexes)
	return perfectSubtreeIndexes(lo+k, hi, indexes)
}

// rangeHash returns MTH(D[lo:hi)), the RFC 6962 section 2.1 Merkle Tree Hash
// over the leaves in [lo, hi) as an independent list, read through the provided
// reader. It decomposes [lo, hi) into its maximal aligned perfect subtrees and
// reads all of their roots in a single ReadHashes call before folding them
// together.
func rangeHash(lo, hi int64, reader xtlog.HashReader) (xtlog.Hash, error) {
	indexes := perfectSubtreeIndexes(lo, hi, nil)
	hashes, err := reader.ReadHashes(indexes)
	if err != nil {
		return xtlog.Hash{}, err
	}
	if len(hashes) != len(indexes) {
		// Reader returned a slice shorter or larger than the requested indexes.
		// Avoid panicking on the fold.
		return xtlog.Hash{}, fmt.Errorf("ReadHashes returned %d hashes for %d indexes", len(hashes), len(indexes))
	}
	h, _ := foldRangeHash(lo, hi, hashes)
	return h, nil
}

func appendRangeHash(lo, hi int64, reader xtlog.HashReader, proof []xtlog.Hash) ([]xtlog.Hash, error) {
	h, err := rangeHash(lo, hi, reader)
	if err != nil {
		return nil, err
	}
	return append(proof, h), nil
}

// subtreeSubProof implements SUBTREE_SUBPROOF(start, end, D_n, b) from the MTC
// draft section 4.4.1 Generating a Subtree Consistency Proof, detailed further
// in the draft's Appendix B.4. start and end are relative to the current
// subtree D_n of size n rooted at absolute offset base, and known is the
// draft's b flag. It reads stored hashes through the provided reader and
// returns proof with the hashes it emits appended.
func subtreeSubProof(start, end, base, n int64, known bool, reader xtlog.HashReader, proof []xtlog.Hash) ([]xtlog.Hash, error) {
	if start == 0 && end == n {
		// [start, end) now covers this whole node D_n, the SUBTREE_SUBPROOF
		// base case. known decides whether the proof carries it.
		if known {
			// The verifier already has this node, so emit nothing.
			return proof, nil
		}

		// The verifier doesn't have it, so emit its hash MTH(D_n).
		h, err := rangeHash(base, base+n, reader)
		if err != nil {
			return nil, err
		}
		return append(proof, h), nil
	}

	// [start, end) covers only part of this node, so split at k. The switch
	// routes by where the subtree falls (left child, right child, or straddle)
	// and names the other child as the sibling the shared tail appends.
	k := largestPowerOfTwoSmallerThan(n)
	var err error
	var siblingLo int64
	var siblingHi int64
	switch {
	case end <= k:
		// The subtree fits in the left child. Recurse there, with the right
		// child [k, n) as the sibling.
		proof, err = subtreeSubProof(start, end, base, k, known, reader, proof)
		siblingLo = base + k
		siblingHi = base + n
	case k <= start:
		// The subtree fits in the right child. Recurse there (shifting
		// coordinates by k), with the left child [0, k) as the sibling.
		proof, err = subtreeSubProof(start-k, end-k, base+k, n-k, known, reader, proof)
		siblingLo = base
		siblingHi = base + k
	default:
		// The subtree straddles the split (start < k < end), which a valid
		// subtree only does when start == 0. Recurse on the right child's
		// prefix [0, end-k), no longer a node the verifier knows (known =
		// false), with the left child [0, k) as the sibling.
		proof, err = subtreeSubProof(0, end-k, base+k, n-k, false, reader, proof)
		siblingLo = base
		siblingHi = base + k
	}
	if err != nil {
		return nil, err
	}
	return appendRangeHash(siblingLo, siblingHi, reader, proof)
}

// SubtreeConsistencyProof returns SUBTREE_PROOF(start, end, D_n) for the tree
// of size treeSize, reading stored hashes through the provided reader, per the
// MTC draft section 4.4.1 Generating a Subtree Consistency Proof, detailed
// further in the draft's Appendix B.4. [start, end) must be a valid subtree
// with end <= treeSize.
func SubtreeConsistencyProof(start, end, treeSize int64, reader xtlog.HashReader) ([]xtlog.Hash, error) {
	if !ValidSubtree(start, end) || end > treeSize {
		return nil, fmt.Errorf("[%d, %d) is not a valid subtree of a tree of size %d", start, end, treeSize)
	}
	return subtreeSubProof(start, end, 0, treeSize, true, reader, nil)
}

// VerifySubtreeConsistency reports whether proof shows that the subtree [start,
// end), whose hash is nodeHash, sits at those positions in the tree of size n
// with root rootHash. It follows the procedure in MTC draft section 4.4.3,
// detailed further in the draft's Appendix B.5.
func VerifySubtreeConsistency(start, end, n int64, proof []xtlog.Hash, nodeHash, rootHash xtlog.Hash) bool {
	if !ValidSubtree(start, end) || end > n {
		return false
	}

	// fn, sn, tn track the subtree's first leaf, its last leaf, and the tree's
	// last leaf. Right-shifting a cursor climbs one level.
	fn := start
	sn := end - 1
	tn := n - 1

	// Skip the levels that need no proof hash. The branch turns on whether the
	// subtree's right edge meets the tree's right edge (sn == tn) or not.
	if sn == tn {
		// A flush subtree has no outside sibling to fold on the way up to
		// nodeHash, so climb every level.
		for fn != sn {
			fn >>= 1
			sn >>= 1
			tn >>= 1
		}
	} else {
		// An interior subtree eventually meets an outside sibling, so climb
		// only while sn is a right child.
		for fn != sn && sn&1 == 1 {
			fn >>= 1
			sn >>= 1
			tn >>= 1
		}
	}

	// fr and sr climb together from a shared seed: fr rebuilds the subtree
	// hash, sr the tree root.
	var fr xtlog.Hash
	var sr xtlog.Hash
	var rest []xtlog.Hash
	if fn == sn {
		// A single node: the seed is its hash, nodeHash.
		fr = nodeHash
		sr = nodeHash
		rest = proof
	} else {
		// The subtree is larger, so the seed is proof[0], the largest perfect
		// subtree flush with its right edge.
		if len(proof) == 0 {
			return false
		}
		fr = proof[0]
		sr = proof[0]
		rest = proof[1:]
	}

	for _, c := range rest {
		if tn == 0 {
			// The proof has more hashes than the tree has levels.
			return false
		}
		if sn&1 == 1 || sn == tn {
			if fn < sn {
				// fr only folds while fn < sn. Freezing it at fn == sn is what
				// makes the final fr == nodeHash check meaningful.
				fr = xtlog.NodeHash(c, fr)
			}
			sr = xtlog.NodeHash(c, sr)
			// At the ragged right edge (sn == tn) the just-merged node is
			// shorter than its left sibling, so skip its empty levels here,
			// consuming no proof hash, until sn is odd again.
			for sn&1 == 0 {
				fn >>= 1
				sn >>= 1
				tn >>= 1
			}
		} else {
			// c is the node's right sibling, outside the subtree, so it extends
			// sr toward the root.
			sr = xtlog.NodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
		tn >>= 1
	}
	return tn == 0 && fr == nodeHash && sr == rootHash
}
