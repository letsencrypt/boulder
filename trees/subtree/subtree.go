package subtree

import (
	"crypto/sha256"
	"fmt"
	"math/bits"

	"golang.org/x/mod/sumdb/tlog"
)

// largestPowerOfTwoSmallerThan returns the largest power of two strictly less
// than n, for n > 1. n <= 1 results in a panic.
func largestPowerOfTwoSmallerThan(n int64) int64 {
	if n <= 1 {
		panic(fmt.Sprintf("n must be > 1, got %d", n))
	}
	return int64(1) << (bits.Len64(uint64(n-1)) - 1) //nolint:gosec // G115: n > 1, so n-1 is positive.
}

// HashLeaves returns MTH(D[start:end]), the RFC 9162 section 2.1.1 Merkle Tree
// Hash of the provided leaf hashes. Pass a subtree's leaves to get that
// subtree's hash. The inputs must be leaf hashes (HASH(0x00 || entry), as
// produced by tlog.RecordHash).
//
// https://datatracker.ietf.org/doc/html/rfc9162#section-2.1.1
func HashLeaves(leaves []tlog.Hash) tlog.Hash {
	switch len(leaves) {
	case 0:
		// The hash of an empty list is the hash of an empty string.
		return tlog.Hash(sha256.Sum256(nil))
	case 1:
		// The hash of a list with one entry is just the leaf hash.
		return leaves[0]
	default:
		// Split the list into two subtree roots, the left being a "complete" subtree
		// and the right being the remainder which may or may not be complete.

		// Cases 0 and 1 return above, so len(leaves) >= 2 here.
		k := largestPowerOfTwoSmallerThan(int64(len(leaves)))

		// Combine the two parts' roots as SHA-256(0x01 || left || right).
		return tlog.NodeHash(HashLeaves(leaves[:k]), HashLeaves(leaves[k:]))
	}
}

// valid reports whether [start, end) is a valid subtree per the MTC draft
// section 4.1 Definition of a Subtree: 0 <= start < end and start is a multiple
// of BIT_CEIL(end - start).
func valid(start, end int64) bool {
	if start < 0 || start >= end {
		// A subtree must have 0 <= start < end.
		return false
	}
	// start must be a multiple of BIT_CEIL(end-start). bits.Len64(x) is the bit
	// width of x, so 1<<bits.Len64(x) is the smallest power of two strictly
	// above x, an exclusive ceiling. BIT_CEIL(x) is inclusive, the smallest
	// power of two at least x, so we apply it to end-start-1.
	bitCeil := uint64(1) << bits.Len64(uint64(end-start-1)) //nolint:gosec // G115: the start >= end check above leaves end-start positive, so end-start-1 is non-negative.

	// bitCeil-1 masks the bits below bitCeil, so start & (bitCeil-1) is zero
	// exactly when start is a multiple of bitCeil.
	return uint64(start)&(bitCeil-1) == 0
}

// completeSubtree reports whether [start, end) is a complete subtree (a valid
// subtree with a power-of-two size), and if so its level.
func completeSubtree(start, end int64) (level int, ok bool) {
	size := end - start
	if !valid(start, end) || bits.OnesCount64(uint64(size)) != 1 { //nolint:gosec // G115: valid ensures start < end, so size is positive.
		return 0, false
	}
	return bits.TrailingZeros64(uint64(size)), true //nolint:gosec // G115: valid ensures start < end, so size is positive.
}

// splitPoint returns where to split the subtree [start, end) into a complete
// subtree on the left and a possibly ragged one on the right. This is the mid
// in draft-ietf-plants-merkle-tree-certs section 4.5.1.
func splitPoint(start, end int64) int64 {
	return start + largestPowerOfTwoSmallerThan(end-start)
}

// combineSubtreeRoots combines subtree roots, in the order
// completeSubtreeIndexes lists them, into MTH(D[start:end]). It returns the
// hash and the unconsumed remainder.
func combineSubtreeRoots(start, end int64, hashes []tlog.Hash) (tlog.Hash, []tlog.Hash) {
	_, ok := completeSubtree(start, end)
	if ok {
		return hashes[0], hashes[1:]
	}
	// completeSubtree accepts single leaves, and the input is always a valid
	// subtree (end > start), so end-start >= 2 here.
	mid := splitPoint(start, end)
	left, rest := combineSubtreeRoots(start, mid, hashes)
	right, rest := combineSubtreeRoots(mid, end, rest)
	return tlog.NodeHash(left, right), rest
}

// completeSubtreeIndexes splits [start, end) into the largest power-of-two
// subtrees the tree already keeps a single stored hash for, and appends each
// one's stored hash index left to right.
func completeSubtreeIndexes(start, end int64) []int64 {
	level, ok := completeSubtree(start, end)
	if ok {
		return []int64{tlog.StoredHashIndex(level, start>>level)}
	}
	// completeSubtree accepts single leaves, and the input is always a valid
	// subtree (end > start), so end-start >= 2 here.
	mid := splitPoint(start, end)
	return append(completeSubtreeIndexes(start, mid), completeSubtreeIndexes(mid, end)...)
}

// hashSubtree returns the hash of the subtree [start, end), MTH(D[start:end])
// from RFC 9162 section 2.1.1. It splits [start, end) into the largest
// power-of-two subtrees the tree already keeps a single stored hash for, reads
// those hashes through the provided reader in a single ReadHashes call, and
// combines them.
func hashSubtree(start, end int64, reader tlog.HashReader) (tlog.Hash, error) {
	indexes := completeSubtreeIndexes(start, end)
	hashes, err := reader.ReadHashes(indexes)
	if err != nil {
		return tlog.Hash{}, err
	}
	if len(hashes) != len(indexes) {
		// Reader returned a slice shorter or larger than the requested indexes.
		// Avoid panicking when we combine them.
		return tlog.Hash{}, fmt.Errorf("ReadHashes returned %d hashes for %d indexes", len(hashes), len(indexes))
	}
	h, _ := combineSubtreeRoots(start, end, hashes)
	return h, nil
}

// subtreeSubProof implements SUBTREE_SUBPROOF(start, end, D_n, b) from the MTC
// draft section 4.4.1 Generating a Subtree Consistency Proof, detailed further
// in the draft's Appendix B.4. start and end are relative to the current
// subtree D_n of size n rooted at absolute offset base, and known is the
// draft's b flag. It reads stored hashes through the provided reader and
// returns proof with the hashes it emits appended.
func subtreeSubProof(start, end, base, n int64, known bool, reader tlog.HashReader, proof []tlog.Hash) ([]tlog.Hash, error) {
	if start == 0 && end == n {
		// [start, end) now covers this whole node D_n, the SUBTREE_SUBPROOF
		// base case. known decides whether the proof carries it.
		if known {
			// The verifier already has this node, so emit nothing.
			return proof, nil
		}

		// The verifier doesn't have it, so emit its hash MTH(D_n).
		h, err := hashSubtree(base, base+n, reader)
		if err != nil {
			return nil, err
		}
		return append(proof, h), nil
	}

	// [start, end) covers only part of this node, so split at k. The switch
	// routes by where the subtree falls (left child, right child, or straddle)
	// and names the other child as the sibling the shared tail appends.

	// At n == 1, [start, end) can only be [0, 1) (0 <= start < end <= n), which has
	// start == 0 and end == n, matching the base case above. So n >= 2 here.
	k := largestPowerOfTwoSmallerThan(n)
	var err error
	var siblingStart int64
	var siblingEnd int64
	switch {
	case end <= k:
		// The subtree fits in the left child. Recurse there, with the right
		// child [k, n) as the sibling.
		proof, err = subtreeSubProof(start, end, base, k, known, reader, proof)
		siblingStart = base + k
		siblingEnd = base + n
	case k <= start:
		// The subtree fits in the right child. Recurse there (shifting
		// coordinates by k), with the left child [0, k) as the sibling.
		proof, err = subtreeSubProof(start-k, end-k, base+k, n-k, known, reader, proof)
		siblingStart = base
		siblingEnd = base + k
	default:
		// The subtree straddles the split (start < k < end), which a valid
		// subtree only does when start == 0. Recurse on the right child's
		// prefix [0, end-k), no longer a node the verifier knows (known =
		// false), with the left child [0, k) as the sibling.
		proof, err = subtreeSubProof(0, end-k, base+k, n-k, false, reader, proof)
		siblingStart = base
		siblingEnd = base + k
	}
	if err != nil {
		return nil, err
	}
	h, err := hashSubtree(siblingStart, siblingEnd, reader)
	if err != nil {
		return nil, err
	}
	return append(proof, h), nil
}

// ConsistencyProof returns SUBTREE_PROOF(start, end, D_n) for the tree of size
// treeSize, reading stored hashes through the provided reader, per the MTC
// draft section 4.4.1 Generating a Subtree Consistency Proof, detailed further
// in the draft's Appendix B.4. [start, end) must be a valid subtree with end <=
// treeSize.
//
//   - https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#section-4.4.1
//   - https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#appendix-B.4
func ConsistencyProof(start, end, treeSize int64, reader tlog.HashReader) ([]tlog.Hash, error) {
	if !valid(start, end) || end > treeSize {
		return nil, fmt.Errorf("[%d, %d) is not a valid subtree of a tree of size %d", start, end, treeSize)
	}
	return subtreeSubProof(start, end, 0, treeSize, true, reader, nil)
}

// VerifyConsistency reports whether proof shows that the subtree [start, end),
// whose hash is nodeHash, sits at those positions in the tree of size n with
// root rootHash. It follows the procedure in MTC draft section 4.4.3, detailed
// further in the draft's Appendix B.5.
//
//   - https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#section-4.4.3
//   - https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#appendix-B.5
func VerifyConsistency(start, end, n int64, proof []tlog.Hash, nodeHash, rootHash tlog.Hash) bool {
	if !valid(start, end) || end > n {
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
		// A flush subtree has no outside sibling to combine on the way up to
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
	var fr tlog.Hash
	var sr tlog.Hash
	var rest []tlog.Hash
	if fn == sn {
		// A single node: the seed is its hash, nodeHash.
		fr = nodeHash
		sr = nodeHash
		rest = proof
	} else {
		// The subtree is larger, so the seed is proof[0], the largest complete
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
				// fr only combines while fn < sn. Freezing it at fn == sn is
				// what makes the final fr == nodeHash check meaningful.
				fr = tlog.NodeHash(c, fr)
			}
			sr = tlog.NodeHash(c, sr)
			// At the ragged right edge (sn == tn) the just-combined node is
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
			sr = tlog.NodeHash(sr, c)
		}
		fn >>= 1
		sn >>= 1
		tn >>= 1
	}
	return tn == 0 && fr == nodeHash && sr == rootHash
}
