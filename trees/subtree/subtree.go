package subtree

import (
	"crypto/sha256"
	"fmt"
	"math/bits"

	"golang.org/x/mod/sumdb/tlog"
)

type Subtree struct {
	Start int64
	End   int64
}

// Valid reports whether [start, end) is a valid subtree per the MTC draft
// section 4.1 Definition of a Subtree: 0 <= start <= end and start is a multiple
// of BIT_CEIL(end - start).
func Valid(start, end int64) bool {
	if start < 0 || start > end {
		// A subtree must have 0 <= start <= end.
		return false
	}
	if start == end {
		// BIT_CEIL(0) is 1, so any start aligns.
		return true
	}
	// start must be a multiple of BIT_CEIL(end-start). bits.Len64(x) is the bit
	// width of x, so 1<<bits.Len64(x) is the smallest power of two strictly
	// above x, an exclusive ceiling. BIT_CEIL(x) is inclusive, the smallest
	// power of two at least x, so we apply it to end-start-1.
	bitCeil := uint64(1) << bits.Len64(uint64(end-start-1)) //nolint:gosec // G115: the checks above mean that end-start is positive, so end-start-1 is non-negative.

	// bitCeil-1 masks the bits below bitCeil, so start & (bitCeil-1) is zero
	// exactly when start is a multiple of bitCeil.
	return uint64(start)&(bitCeil-1) == 0
}

// contains returns true if and only if start ≤ entryIndex < end.
func contains(entryIndex, start, end int64) bool {
	return start <= entryIndex && entryIndex < end
}

// completeSubtree reports whether [start, end) is a complete subtree (a valid
// subtree with a power-of-two size), and if so its level.
func completeSubtree(start, end int64) (level int, ok bool) {
	size := end - start
	if !Valid(start, end) || bits.OnesCount64(uint64(size)) != 1 { //nolint:gosec // G115: Valid ensures start <= end, so size is non-negative.
		return 0, false
	}
	return bits.TrailingZeros64(uint64(size)), true //nolint:gosec // G115: Valid ensures start <= end, so size is non-negative.
}

// splitPoint returns where to split the subtree [start, end) into a complete
// subtree on the left and a possibly ragged one on the right. This is the mid
// in draft-ietf-plants-merkle-tree-certs section 4.5.1.
func splitPoint(start, end int64) int64 {
	if end-start <= 1 {
		panic(fmt.Sprintf("splitPoint: end-start must be > 1, got %d", end-start))
	}
	return start + int64(1)<<(bits.Len64(uint64(end-start-1))-1) //nolint:gosec // G115: end-start > 1, so end-start-1 is positive.
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
	// non-empty subtree, so end-start >= 2 here.
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
	// non-empty subtree, so end-start >= 2 here.
	mid := splitPoint(start, end)
	return append(completeSubtreeIndexes(start, mid), completeSubtreeIndexes(mid, end)...)
}

// HashSubtree returns the hash of the subtree [start, end), MTH(D[start:end])
// from RFC 9162 section 2.1.1. It splits [start, end) into the largest
// power-of-two subtrees the tree already keeps a single stored hash for, reads
// those hashes through the provided reader in a single ReadHashes call, and
// combines them. It errors if [start, end) is not a valid subtree. The hash of
// an empty subtree is the hash of an empty string, MTH({}) from the same
// section.
func HashSubtree(start, end int64, reader tlog.HashReader) (tlog.Hash, error) {
	if !Valid(start, end) {
		return tlog.Hash{}, fmt.Errorf("[%d, %d) is not a valid subtree", start, end)
	}
	if start == end {
		return tlog.Hash(sha256.Sum256(nil)), nil
	}
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

// subtreeSubProof implements the draft's SUBTREE_SUBPROOF from section 4.4.1
// Generating a Subtree Consistency Proof (Appendix B.4), with the target
// subtree [start, end) and the node [windowStart, windowEnd) it sits in given
// as absolute leaf positions. known is the draft's b flag. It reads stored
// hashes through the provided reader and returns proof with the hashes it emits
// appended.
func subtreeSubProof(start, end, windowStart, windowEnd int64, known bool, reader tlog.HashReader, proof []tlog.Hash) ([]tlog.Hash, error) {
	if start == windowStart && end == windowEnd {
		// [start, end) covers the whole node, the SUBTREE_SUBPROOF base case.
		// known decides whether the proof carries it.
		if known {
			// The verifier already has this node, so emit nothing.
			return proof, nil
		}

		// The verifier doesn't have it, so emit the node's hash.
		h, err := HashSubtree(windowStart, windowEnd, reader)
		if err != nil {
			return nil, err
		}
		return append(proof, h), nil
	}

	// [start, end) covers only part of the node, so split the node at splitPoint.
	// The switch routes by where the subtree falls (left child, right child, or
	// straddle) and names the other child as the sibling. The hash of the sibling
	// will be appended to `proof` and returned.

	// A one-leaf node has only itself as a subtree, which hits the base case
	// above, so the node has >= 2 leaves here.
	split := splitPoint(windowStart, windowEnd)
	var err error
	var siblingStart int64
	var siblingEnd int64
	switch {
	case end <= split:
		// The subtree is in the left child [windowStart, split). The right child
		// is the sibling.
		proof, err = subtreeSubProof(start, end, windowStart, split, known, reader, proof)
		siblingStart = split
		siblingEnd = windowEnd
	case split <= start:
		// The subtree is in the right child [split, windowEnd). The left child is
		// the sibling.
		proof, err = subtreeSubProof(start, end, split, windowEnd, known, reader, proof)
		siblingStart = windowStart
		siblingEnd = split
	default:
		// The subtree straddles the split (start < split < end), which a valid
		// subtree only does when start == windowStart. Recurse into the right
		// child, no longer a node the verifier knows (known = false). The left
		// child is the sibling.
		proof, err = subtreeSubProof(split, end, split, windowEnd, false, reader, proof)
		siblingStart = windowStart
		siblingEnd = split
	}
	if err != nil {
		return nil, err
	}
	h, err := HashSubtree(siblingStart, siblingEnd, reader)
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
	if !Valid(start, end) || end > treeSize {
		return nil, fmt.Errorf("[%d, %d) is not a valid subtree of a tree of size %d", start, end, treeSize)
	}
	if start == end {
		// SUBTREE_PROOF(start, start, D_n) = {}
		return nil, nil
	}
	return subtreeSubProof(start, end, 0, treeSize, true, reader, nil)
}

// InclusionProof returns a Subtree Inclusion Proof.
//
// The range [start, end) must be a valid subtree with end <= treeSize.
//
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-subtree-inclusion-proofs
func InclusionProof(entryIndex, start, end int64, reader tlog.HashReader) ([]tlog.Hash, error) {
	if !Valid(start, end) {
		return nil, fmt.Errorf("subtree [%d, %d) not valid", start, end)
	}
	if !contains(entryIndex, start, end) {
		return nil, fmt.Errorf("entryIndex %d not in subtree [%d, %d)", entryIndex, start, end)
	}
	offset := start
	// `tlog.ProveRecord` operates over a Merkle Tree, so we give it a HashReader
	// that acts as if the subtree is a Merkle Tree unto itself.
	offsetHashReader := func(hashIndexes []int64) ([]tlog.Hash, error) {
		var newHashIndexes []int64
		for _, i := range hashIndexes {
			level, n := tlog.SplitStoredHashIndex(i)
			// Node `n` in the subtree will be found at a larger (or equal)
			// index in the whole Merkle Tree.
			n += offset >> level
			newHashIndexes = append(newHashIndexes, tlog.StoredHashIndex(level, n))
		}
		return reader.ReadHashes(newHashIndexes)
	}
	return tlog.ProveRecord(
		end-start,
		entryIndex-start,
		tlog.HashReaderFunc(offsetHashReader))
}

// VerifyConsistency reports whether proof shows that the subtree [start, end),
// whose hash is nodeHash, sits at those positions in the tree of size n with
// root rootHash. It follows the procedure in MTC draft section 4.4.3, detailed
// further in the draft's Appendix B.5.
//
//   - https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#section-4.4.3
//   - https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#appendix-B.5
func VerifyConsistency(start, end, n int64, proof []tlog.Hash, nodeHash, rootHash tlog.Hash) bool {
	if !Valid(start, end) || end > n {
		return false
	}
	if start == end {
		return len(proof) == 0 && nodeHash == MTH(nil)
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
		// nodeHash, so climb to the subtree root.
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
	// hash, sr the root hash.
	var fr tlog.Hash
	var sr tlog.Hash
	var rest []tlog.Hash
	if fn == sn {
		// A single node: the seed is its hash, nodeHash.
		fr = nodeHash
		sr = nodeHash
		rest = proof
	} else {
		// The subtree is larger than a single node, so the seed is proof[0],
		// the largest complete subtree flush with its right edge.
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
				// fr only combines while fn < sn. Once fn == sn, we've finished
				// with nodes below the subtree root and fr should have its
				// final value.
				fr = tlog.NodeHash(c, fr)
			}
			sr = tlog.NodeHash(c, sr)
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

// HashFromProof returns a subtree hash given an entry hash and an inclusion proof across a subtree of some Merkle tree.
//
// https://ietf-plants-wg.github.io/merkle-tree-certs/draft-ietf-plants-merkle-tree-certs.html#name-evaluating-a-subtree-inclus
func HashFromProof(entryHash tlog.Hash, proof []tlog.Hash, entryIndex, start, end int64) (tlog.Hash, error) {
	if !Valid(start, end) {
		return tlog.Hash{}, fmt.Errorf("invalid subtree: [%d, %d)", start, end)
	}
	if !contains(entryIndex, start, end) {
		return tlog.Hash{}, fmt.Errorf("entryIndex %d not in [%d, %d)", entryIndex, start, end)
	}

	result, err := hashFromProof(entryHash, proof, entryIndex-start, end-start)
	if err != nil {
		return tlog.Hash{}, fmt.Errorf("evaluating MTCProof of length %d, for entryIndex %d, within subtree [%d, %d): %s",
			len(proof), entryIndex, start, end, err)
	}
	return result, nil
}

// hashFromProof calculates the expected hash across a Merkle tree.
func hashFromProof(entryHash tlog.Hash, proof []tlog.Hash, entryIndex, treesize int64) (tlog.Hash, error) {
	currentHash := entryHash
	// These represent the index of nodes within the current layer of the conceptual Merkle tree
	// (not to be confused with a level of tile storage).
	currentNode, lastNode := entryIndex, treesize-1

	for _, proofHash := range proof {
		if lastNode == 0 {
			return tlog.Hash{}, fmt.Errorf("too many hashes in proof evaluation")
		}

		if currentNode&1 == 1 || currentNode == lastNode {
			currentHash = tlog.NodeHash(proofHash, currentHash)

			for currentNode&1 == 0 {
				// Move up levels in the Merkle tree by right-shifting these indices
				currentNode >>= 1
				lastNode >>= 1
			}

		} else {
			currentHash = tlog.NodeHash(currentHash, proofHash)
		}

		// Move up one level in the Merkle tree
		currentNode >>= 1
		lastNode >>= 1
	}

	if lastNode != 0 {
		return tlog.Hash{}, fmt.Errorf("too few hashes in proof evaluation")
	}
	return currentHash, nil
}

// MTH emits the Merkle Tree Hash of its inputs, as defined in RFC 9162 section 2.1.1.
//
// https://www.rfc-editor.org/info/rfc9162/#name-definition-of-the-merkle-tr
func MTH(leaves []tlog.Hash) tlog.Hash {
	switch len(leaves) {
	case 0:
		return tlog.Hash(sha256.Sum256(nil))
	case 1:
		return leaves[0]
	default:
		// RFC 6962: split at the largest power of two smaller than n.
		k := 1 << (bits.Len(uint(len(leaves)-1)) - 1)
		return tlog.NodeHash(MTH(leaves[:k]), MTH(leaves[k:]))
	}
}

// FindCoveringSubtrees calculates two subtrees to efficiently cover an
// arbitrary interval from `start` to `end`. It will always return at least one
// non-zero subtree (i.e. covering a single entry) or an error.
//
// https://www.ietf.org/archive/id/draft-ietf-plants-merkle-tree-certs-08.html#section-4.5.1-4
func FindCoveringSubtrees(start, end int64) (subtrees []Subtree, err error) {
	if start < 0 || end < 0 {
		return []Subtree{}, fmt.Errorf("start and end must be positive")
	}

	if start > end {
		return []Subtree{}, fmt.Errorf("start must be less than end")
	}

	if (end - start) <= 1 {
		return []Subtree{{Start: start, End: end}, {Start: end, End: end}}, nil
	}

	lastIndex := (end - 1)
	splitIndex := bits.Len64(uint64(start^lastIndex)) - 1 //nolint:gosec // G115: the three checks above ensure these values are positive
	mask := int64(1<<splitIndex) - 1
	midIndex := lastIndex &^ mask

	leftHeight := bits.Len64(uint64(^start & mask)) //nolint:gosec // G115: the same three checks at start of function
	leftStart := start & ^((1 << leftHeight) - 1)

	_, ok := completeSubtree(leftStart, midIndex)
	if !ok {
		return []Subtree{}, fmt.Errorf("failed to find complete left subtree")
	}

	// the subtree on the right of `mid` may not be complete, but should be valid.
	if !Valid(midIndex, end) {
		return []Subtree{}, fmt.Errorf("failed to find valid right subtree")
	}
	return []Subtree{{Start: leftStart, End: midIndex}, {Start: midIndex, End: end}}, nil
}
