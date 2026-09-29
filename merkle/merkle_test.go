package merkle

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
)

// leaves returns n deterministic leaves, the same scheme the cross-implementation vectors use so a
// second implementation can be compared against this one entry for entry.
func leaves(n int64) [][]byte {
	out := make([][]byte, 0, n)
	for i := int64(0); i < n; i++ {
		out = append(out, []byte(fmt.Sprintf("leaf-%d", i)))
	}
	return out
}

// TestEmptyRootIsTheSpecifiedConstant pins the empty log's root to the value RFC 6962 fixes, the
// SHA-256 of no input. It is a known answer from outside this package, so it catches a construction
// that is merely self-consistent.
func TestEmptyRootIsTheSpecifiedConstant(t *testing.T) {
	t.Parallel()
	const want = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got := hex.EncodeToString(EmptyRoot()); got != want {
		t.Errorf("EmptyRoot() = %s, want %s", got, want)
	}
}

// TestSplitPointIsTheLargestPowerOfTwoBelowN pins the tree's division point. It is not n/2, and
// getting it wrong yields a tree that verifies against itself while disagreeing with every other
// RFC 6962 implementation, which is the failure this test exists to prevent.
func TestSplitPointIsTheLargestPowerOfTwoBelowN(t *testing.T) {
	t.Parallel()
	tests := []struct {
		N    int64
		Want int64
	}{
		{N: 2, Want: 1}, {N: 3, Want: 2}, {N: 4, Want: 2}, {N: 5, Want: 4},
		{N: 7, Want: 4}, {N: 8, Want: 4}, {N: 9, Want: 8}, {N: 16, Want: 8},
		{N: 17, Want: 16},
	}
	for _, test := range tests {
		if got := splitPoint(test.N); got != test.Want {
			t.Errorf("splitPoint(%d) = %d, want %d", test.N, got, test.Want)
		}
	}
}

// TestLeafAndNodeAreDomainSeparated proves a leaf and a node never share a hash for the same bytes.
// Without the 0x00 and 0x01 prefixes an attacker can present an interior node's two children as a
// single leaf's content and prove membership of an entry the log never held.
func TestLeafAndNodeAreDomainSeparated(t *testing.T) {
	t.Parallel()
	left, right := LeafHash([]byte("a")), LeafHash([]byte("b"))
	node := NodeHash(left, right)
	// The same bytes the node hashed, offered as a leaf, must not produce the node's hash.
	forged := LeafHash(append(append([]byte{}, left...), right...))
	if bytes.Equal(node, forged) {
		t.Error("a leaf over a node's children hashes to the node, so the tree is not domain separated")
	}
}

// TestInclusionRoundTrip verifies every leaf of every log size from one to nine: the generated audit
// path must verify against the independently computed root.
func TestInclusionRoundTrip(t *testing.T) {
	t.Parallel()
	for n := int64(1); n <= 9; n++ {
		root := Root(leaves(n))
		for m := int64(0); m < n; m++ {
			path, err := InclusionProof(m, leaves(n))
			if err != nil {
				t.Fatalf("InclusionProof(%d, %d) error = %v", m, n, err)
			}
			if !VerifyInclusion(leaves(n)[m], m, n, path, root) {
				t.Errorf("leaf %d of %d does not verify against its own root", m, n)
			}
		}
	}
}

// TestInclusionRejectsForgeries checks the proof is load bearing: a corrupted path element, a
// wrong index, a wrong leaf, a wrong root, and a truncated path must each fail.
func TestInclusionRejectsForgeries(t *testing.T) {
	t.Parallel()
	const n, m = int64(7), int64(3)
	all := leaves(n)
	root := Root(all)
	path, err := InclusionProof(m, all)
	if err != nil {
		t.Fatalf("InclusionProof() error = %v", err)
	}
	if !VerifyInclusion(all[m], m, n, path, root) {
		t.Fatal("the honest proof does not verify, so the negative cases prove nothing")
	}

	corrupt := make([][]byte, len(path))
	copy(corrupt, path)
	flipped := append([]byte{}, corrupt[0]...)
	flipped[0] ^= 0x01
	corrupt[0] = flipped

	tests := []struct {
		Name string
		Got  bool
	}{
		{Name: "corrupted path element", Got: VerifyInclusion(all[m], m, n, corrupt, root)},
		{Name: "wrong leaf index", Got: VerifyInclusion(all[m], m+1, n, path, root)},
		{Name: "different leaf data", Got: VerifyInclusion([]byte("not-a-leaf"), m, n, path, root)},
		{Name: "wrong root", Got: VerifyInclusion(all[m], m, n, path, LeafHash([]byte("other")))},
		{Name: "truncated path", Got: VerifyInclusion(all[m], m, n, path[:len(path)-1], root)},
		{Name: "index outside the log", Got: VerifyInclusion(all[m], n, n, path, root)},
		{Name: "empty path against a multi-leaf root", Got: VerifyInclusion(all[m], m, n, nil, root)},
	}
	for _, test := range tests {
		if test.Got {
			t.Errorf("%s verified, want refused", test.Name)
		}
	}
}

// TestInclusionBindsToTheRootNotTheDeclaredSize records what an inclusion proof actually guarantees,
// because the distinction decides how a caller must use it.
//
// Folding binds the leaf, its index, and the path to a root. The declared size only chooses the
// shape of the fold, and for some positions two sizes fold identically: leaf 3 of a seven leaf log
// folds exactly as leaf 3 of an eight leaf log, so declaring the wrong size still reaches the same
// root. That is not a forgery, because the root is the signed value; a caller who takes both the
// root and the size from the signed head cannot be misled. Where the shape does differ, as at leaf
// 6, a wrong size fails outright.
func TestInclusionBindsToTheRootNotTheDeclaredSize(t *testing.T) {
	t.Parallel()
	seven := leaves(7)
	root7 := Root(seven)

	shapeSame, err := InclusionProof(3, seven)
	if err != nil {
		t.Fatalf("InclusionProof() error = %v", err)
	}
	if !VerifyInclusion(seven[3], 3, 8, shapeSame, root7) {
		t.Error("leaf 3 folds the same way at either size, so it should still reach the same root")
	}

	shapeDiffers, err := InclusionProof(6, seven)
	if err != nil {
		t.Fatalf("InclusionProof() error = %v", err)
	}
	if VerifyInclusion(seven[6], 6, 8, shapeDiffers, root7) {
		t.Error("leaf 6 folds differently at size 8, so the wrong size must fail")
	}
}

// TestConsistencyRoundTrip verifies every prefix of every log size from one to nine: a log that
// only appended must be able to prove it.
func TestConsistencyRoundTrip(t *testing.T) {
	t.Parallel()
	for n := int64(2); n <= 9; n++ {
		second := Root(leaves(n))
		for m := int64(1); m < n; m++ {
			first := Root(leaves(m))
			proof, err := ConsistencyProof(m, leaves(n))
			if err != nil {
				t.Fatalf("ConsistencyProof(%d, %d) error = %v", m, n, err)
			}
			if !VerifyConsistency(m, n, first, second, proof) {
				t.Errorf("append-only growth from %d to %d does not verify", m, n)
			}
		}
	}
}

// TestConsistencyCatchesARewrittenLog is the append-only property, the single case this proof
// exists for. A log that changed an entry it had already published cannot produce a consistency
// proof from its old root, however well formed the new log is on its own.
func TestConsistencyCatchesARewrittenLog(t *testing.T) {
	t.Parallel()
	const m, n = int64(3), int64(7)
	honest := leaves(n)
	oldRoot := Root(leaves(m))

	// Rewrite an entry the log had already published, then build a proof from the rewritten log.
	rewritten := make([][]byte, len(honest))
	copy(rewritten, honest)
	rewritten[1] = []byte("leaf-1-tampered")
	newRoot := Root(rewritten)
	proof, err := ConsistencyProof(m, rewritten)
	if err != nil {
		t.Fatalf("ConsistencyProof() error = %v", err)
	}
	if VerifyConsistency(m, n, oldRoot, newRoot, proof) {
		t.Error("a log that rewrote a published entry produced a passing consistency proof")
	}

	// Dropping the tail is the other half of the same guarantee: a shortened log cannot claim the
	// longer one as its own history.
	shortened := honest[:n-2]
	shortRoot := Root(shortened)
	if VerifyConsistency(n, int64(len(shortened)), Root(honest), shortRoot, nil) {
		t.Error("a truncated log verified as an append-only extension")
	}
}

// TestConsistencyEdgeSizes covers the boundaries the folding logic special cases: an unchanged log,
// growth from the empty log, and a missing proof where one is required.
func TestConsistencyEdgeSizes(t *testing.T) {
	t.Parallel()
	root := Root(leaves(4))
	if !VerifyConsistency(4, 4, root, root, nil) {
		t.Error("an unchanged log does not verify as consistent with itself")
	}
	if VerifyConsistency(4, 4, root, LeafHash([]byte("x")), nil) {
		t.Error("an unchanged size with a different root verified")
	}
	// A prefix of zero entries is refused rather than treated as trivially true: it would look like
	// evidence while proving nothing. The independent implementation makes the same choice, so the
	// two verifiers cannot disagree on a case the RFC leaves open.
	if VerifyConsistency(0, 5, EmptyRoot(), Root(leaves(5)), nil) {
		t.Error("a prefix of zero entries verified, which proves nothing and must be refused")
	}
	if VerifyConsistency(2, 5, Root(leaves(2)), Root(leaves(5)), nil) {
		t.Error("a required consistency proof was accepted as absent")
	}
	if VerifyConsistency(5, 2, Root(leaves(5)), Root(leaves(2)), nil) {
		t.Error("a shrinking log verified")
	}
}

// TestProofBoundsAreRejected pins the index guards on proof generation. Both guards are
// disjunctions, so a run that only ever exercises in-range indexes leaves the whole guard
// free to rot into a conjunction that admits everything.
func TestProofBoundsAreRejected(t *testing.T) {
	t.Parallel()
	leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	tests := []struct {
		Name string
		Err  error
	}{
		{Name: "inclusion below range", Err: inclusionErr(-1, leaves)},
		{Name: "inclusion at size", Err: inclusionErr(3, leaves)},
		{Name: "inclusion far past size", Err: inclusionErr(9, leaves)},
		{Name: "consistency below one", Err: consistencyErr(0, leaves)},
		{Name: "consistency past size", Err: consistencyErr(4, leaves)},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			if !errors.Is(test.Err, ErrRange) {
				t.Errorf("error mismatch: got %v, want %v", test.Err, ErrRange)
			}
		})
	}
	// The boundary indexes on the legal side must keep working.
	if _, err := InclusionProof(0, leaves); err != nil {
		t.Errorf("inclusion at 0: %v", err)
	}
	if _, err := InclusionProof(2, leaves); err != nil {
		t.Errorf("inclusion at size-1: %v", err)
	}
	if _, err := ConsistencyProof(1, leaves); err != nil {
		t.Errorf("consistency at 1: %v", err)
	}
	if _, err := ConsistencyProof(3, leaves); err != nil {
		t.Errorf("consistency at size: %v", err)
	}
}

// inclusionErr returns only the error of InclusionProof, for table brevity.
func inclusionErr(m int64, leaves [][]byte) error {
	_, err := InclusionProof(m, leaves)
	return err
}

// consistencyErr returns only the error of ConsistencyProof, for table brevity.
func consistencyErr(first int64, leaves [][]byte) error {
	_, err := ConsistencyProof(first, leaves)
	return err
}

// TestVerifyInclusionBounds pins the index guards of the relying-party fold, which can
// be handed any coordinates by an untrusted bundle.
func TestVerifyInclusionBounds(t *testing.T) {
	t.Parallel()
	all := leaves(4)
	root := Root(all)
	path, err := InclusionProof(0, all)
	if err != nil {
		t.Fatalf("InclusionProof: %v", err)
	}
	leaf := all[0]
	tests := []struct {
		Name        string
		Index, Size int64
		Want        bool
	}{
		{Name: "valid coordinates", Index: 0, Size: 4, Want: true},
		{Name: "negative index", Index: -1, Size: 4},
		{Name: "zero size", Index: 0, Size: 0},
		{Name: "index at size", Index: 4, Size: 4},
		{Name: "index past size", Index: 9, Size: 4},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			if got := VerifyInclusion(leaf, test.Index, test.Size, path, root); got != test.Want {
				t.Errorf("VerifyInclusion(%d, %d) = %t, want %t", test.Index, test.Size, got,
					test.Want)
			}
		})
	}
}

// TestVerifyConsistencyBounds pins the size guards of the relying-party consistency
// fold, which an untrusted bundle can hand any coordinates.
func TestVerifyConsistencyBounds(t *testing.T) {
	t.Parallel()
	all := leaves(4)
	root := Root(all)
	oldRoot := Root(all[:2])
	proof, err := ConsistencyProof(2, all)
	if err != nil {
		t.Fatalf("ConsistencyProof: %v", err)
	}
	tests := []struct {
		Name          string
		First, Second int64
		Want          bool
	}{
		{Name: "valid growth", First: 2, Second: 4, Want: true},
		{Name: "negative first size", First: -1, Second: 4},
		{Name: "negative second size", First: 2, Second: -1},
		{Name: "shrinking log", First: 4, Second: 2},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			got := VerifyConsistency(test.First, test.Second, oldRoot, root, proof)
			if got != test.Want {
				t.Errorf("VerifyConsistency(%d, %d) = %t, want %t", test.First, test.Second,
					got, test.Want)
			}
		})
	}
}
