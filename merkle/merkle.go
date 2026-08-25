// Package merkle implements the RFC 6962 Merkle tree: the hash construction Certificate
// Transparency uses, with inclusion proofs that show one entry is in the log and consistency
// proofs that show the log only ever appended.
//
// It deliberately knows nothing about bundles or claims. It operates on leaf bytes, so it can be
// checked against the specification's own known answers rather than only against itself, and so a
// second implementation in another language can be compared against it entry for entry. The mapping
// from a claim to its leaf bytes lives with the chain profile that uses this package.
//
// It is public because a producer emitting the loomseal-merkle-v1 profile needs exactly these
// operations to build a root and the proofs that accompany a disclosure. The verifier does not
// depend on a producer having used this code: every proof it emits is checkable from the
// specification alone.
//
// The two domain separators are the point of the construction. A leaf is hashed with a leading
// 0x00 and an interior node with a leading 0x01, so no leaf can ever be reinterpreted as a node.
// Without them a tree admits a second preimage: an attacker presents an interior node's two child
// hashes as if they were a single leaf's content and proves membership of an entry the log never
// held.
//
// These are reference implementations, tuned for being obviously correct rather than fast. Root holds
// every leaf in memory, and InclusionProof and ConsistencyProof recompute subtree roots at each step
// rather than descending a precomputed tree, so producing a proof for every entry of an n leaf log
// costs O(n^2) hashing. That is deliberate: this package exists to be checkable against the
// specification's own known answers and comparable entry for entry with another language, not to be
// the engine a large producer builds its log with. A producer disclosing windows from a log of real
// size should keep a persistent tree and serve proofs from it. Verification is unaffected: it folds a
// single supplied path and is already linear in that path's length.
package merkle

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// Hash separators, fixed by RFC 6962 section 2.1.
const (
	// leafPrefix precedes a leaf's data in its hash.
	leafPrefix = 0x00
	// nodePrefix precedes a node's two child hashes in its hash.
	nodePrefix = 0x01
)

// HashSize is the length in bytes of every hash this package produces.
const HashSize = sha256.Size

// LeafHash returns the hash of one leaf's data, SHA-256 over the leaf separator and the data.
func LeafHash(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{leafPrefix})
	h.Write(data)
	return h.Sum(nil)
}

// NodeHash returns the hash of an interior node, SHA-256 over the node separator and its two child
// hashes in order. Order matters: swapping the children names a different tree.
func NodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{nodePrefix})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// EmptyRoot returns the root of a log holding nothing, SHA-256 over no input. RFC 6962 fixes this
// value rather than leaving an empty log undefined, so a verifier can tell an empty log from a
// missing one.
func EmptyRoot() []byte {
	h := sha256.New()
	return h.Sum(nil)
}

// splitPoint returns k, the largest power of two strictly less than n, which is where RFC 6962
// divides a tree of n leaves. It is not n/2: the left subtree is always a complete power-of-two
// tree and the right holds the remainder, which is what lets a log append without reshaping what
// it already published. n must be greater than one.
func splitPoint(n int64) int64 {
	k := int64(1)
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// Root returns the Merkle tree hash over leaves, in order. An empty list gives EmptyRoot.
func Root(leaves [][]byte) []byte {
	n := int64(len(leaves))
	switch n {
	case 0:
		return EmptyRoot()
	case 1:
		return LeafHash(leaves[0])
	}
	k := splitPoint(n)
	return NodeHash(Root(leaves[:k]), Root(leaves[k:]))
}

// InclusionProof returns the audit path for the leaf at index m in a log of the given leaves: the
// sibling hashes, lowest first, that a verifier folds with the leaf to reach the root. It errors
// when the index is outside the log.
func InclusionProof(m int64, leaves [][]byte) ([][]byte, error) {
	n := int64(len(leaves))
	if m < 0 || m >= n {
		return nil, fmt.Errorf("%w: leaf %d is outside a log of %d", ErrRange, m, n)
	}
	return inclusionPath(m, leaves), nil
}

// inclusionPath is the recursive audit path of RFC 6962 section 2.1.1. The path for a single leaf
// is empty; otherwise the leaf sits in one half and the whole other half's root is the sibling.
func inclusionPath(m int64, leaves [][]byte) [][]byte {
	n := int64(len(leaves))
	if n == 1 {
		return nil
	}
	k := splitPoint(n)
	if m < k {
		return append(inclusionPath(m, leaves[:k]), Root(leaves[k:]))
	}
	return append(inclusionPath(m-k, leaves[k:]), Root(leaves[:k]))
}

// VerifyInclusion reports whether leafData sits at index in a log of size leaves whose root is the
// given root, according to the audit path.
//
// It folds the path rather than rebuilding the tree, because that is all a relying party can do: it
// holds one entry and its path, never the log. The index and size drive the folding, so a path that
// is correct for a different position does not verify at this one.
func VerifyInclusion(leafData []byte, index, size int64, path [][]byte, root []byte) bool {
	if index < 0 || size < 1 || index >= size {
		return false
	}
	for _, p := range path {
		if len(p) != HashSize {
			return false
		}
	}
	// fn and sn track the node's index and the rightmost index at the current level, which is what
	// says whether a node is a left child, a right child, or the odd node carried up a level.
	fn, sn := index, size-1
	computed := LeafHash(leafData)
	for _, p := range path {
		if sn == 0 {
			// The path is longer than the tree is tall, so it cannot be this log's path.
			return false
		}
		if fn&1 == 1 || fn == sn {
			computed = NodeHash(p, computed)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			computed = NodeHash(computed, p)
		}
		fn >>= 1
		sn >>= 1
	}
	// A path that stops short of the root leaves sn above zero, which is a proof for a smaller tree
	// than the one claimed.
	return sn == 0 && bytes.Equal(computed, root)
}

// ConsistencyProof returns the proof that a log of first leaves is a prefix of the given leaves:
// the hashes a verifier folds to recompute both roots. It errors when first is outside the log.
func ConsistencyProof(first int64, leaves [][]byte) ([][]byte, error) {
	n := int64(len(leaves))
	if first < 1 || first > n {
		return nil, fmt.Errorf("%w: cannot prove a prefix of %d against a log of %d", ErrRange,
			first, n)
	}
	if first == n {
		return nil, nil
	}
	return subProof(first, leaves, true), nil
}

// subProof is SUBPROOF of RFC 6962 section 2.1.2. complete says the prefix is exactly the subtree
// being described, in which case its root is already known to the verifier and is not sent.
func subProof(m int64, leaves [][]byte, complete bool) [][]byte {
	n := int64(len(leaves))
	if m == n {
		if complete {
			return nil
		}
		return [][]byte{Root(leaves)}
	}
	k := splitPoint(n)
	if m <= k {
		return append(subProof(m, leaves[:k], complete), Root(leaves[k:]))
	}
	return append(subProof(m-k, leaves[k:], false), Root(leaves[:k]))
}

// VerifyConsistency reports whether a log that had firstSize leaves with root firstRoot grew into
// one with secondSize leaves and root secondRoot by appending only.
//
// This is the property a hash chain cannot state on its own. A chain proves that what it holds is
// self-consistent, and a rewritten log is self-consistent too. A consistency proof recomputes the
// old root from the new tree, so a log that changed or dropped anything it had already published
// cannot produce one.
func VerifyConsistency(firstSize, secondSize int64, firstRoot, secondRoot []byte, proof [][]byte) bool {
	if firstSize < 0 || secondSize < 0 || firstSize > secondSize {
		return false
	}
	for _, p := range proof {
		if len(p) != HashSize {
			return false
		}
	}
	if firstSize == secondSize {
		// Nothing was appended, so the roots must simply agree and there is nothing to fold.
		return len(proof) == 0 && bytes.Equal(firstRoot, secondRoot)
	}
	if firstSize == 0 {
		// RFC 6962 defines a consistency proof only for a prefix of one or more entries, so this case
		// is a judgment call, and it is refused. Every log trivially extends the empty log, which means
		// such a proof establishes nothing while looking like evidence; accepting it would let a
		// producer answer "prove you only appended" with a proof that proves nothing. A relying party
		// with no earlier checkpoint has nothing to compare and should not be calling this at all.
		return false
	}
	if len(proof) == 0 {
		return false
	}

	// A prefix that ends on a complete subtree has its own root as the first hash the verifier
	// already holds; otherwise the proof supplies it. Shifting past the low one bits finds that
	// boundary.
	fn, sn := firstSize-1, secondSize-1
	for fn&1 == 1 {
		fn >>= 1
		sn >>= 1
	}
	var fr, sr []byte
	rest := proof
	if fn != 0 {
		fr, sr = proof[0], proof[0]
		rest = proof[1:]
	} else {
		fr, sr = firstRoot, firstRoot
	}

	for _, p := range rest {
		if sn == 0 {
			return false
		}
		if fn&1 == 1 || fn == sn {
			fr = NodeHash(p, fr)
			sr = NodeHash(p, sr)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			sr = NodeHash(sr, p)
		}
		fn >>= 1
		sn >>= 1
	}
	return sn == 0 && bytes.Equal(fr, firstRoot) && bytes.Equal(sr, secondRoot)
}

// Sum256Hex returns the hex SHA-256 of data. It is here so callers that build a claim digest use the
// same hashing as the tree rather than reaching for their own.
func Sum256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
