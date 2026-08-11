package merkle

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// katPath is the vector file an independent implementation produced from RFC 6962 alone, without
// reference to this package. Checking against it is what separates being correct from being merely
// self-consistent: two implementations that agree only with themselves can be wrong the same way.
const katPath = "../reference/merkle_kat/kat.json"

// kat is the vector file's shape.
type kat struct {
	// EmptyRoot is the Merkle tree hash of a log holding nothing.
	EmptyRoot string `json:"empty_root"`
	// Roots maps a decimal tree size to the tree's root hash.
	Roots map[string]string `json:"roots"`
	// Inclusion holds one audit path per leaf per tree size.
	Inclusion []katInclusion `json:"inclusion"`
	// Consistency holds one proof per prefix per tree size.
	Consistency []katConsistency `json:"consistency"`
}

// katInclusion is one expected audit path.
type katInclusion struct {
	// TreeSize is the log size the path was generated against.
	TreeSize int64 `json:"tree_size"`
	// LeafIndex is the position the path proves.
	LeafIndex int64 `json:"leaf_index"`
	// Path is the expected sibling hashes, lowest first.
	Path []string `json:"path"`
	// Root is the tree root the path folds to.
	Root string `json:"root"`
}

// katConsistency is one expected consistency proof.
type katConsistency struct {
	// FirstSize and SecondSize are the prefix and the grown log.
	FirstSize  int64 `json:"first_size"`
	SecondSize int64 `json:"second_size"`
	// Proof is the expected proof hashes.
	Proof []string `json:"proof"`
	// FirstRoot and SecondRoot are the roots at those sizes.
	FirstRoot  string `json:"first_root"`
	SecondRoot string `json:"second_root"`
}

// loadKAT reads the independent vectors.
func loadKAT(t *testing.T) kat {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean(katPath))
	if err != nil {
		t.Fatalf("read vectors: %v", err)
	}
	var k kat
	if err := json.Unmarshal(raw, &k); err != nil {
		t.Fatalf("parse vectors: %v", err)
	}
	if len(k.Inclusion) == 0 || len(k.Consistency) == 0 {
		t.Fatal("vector file carries no proofs")
	}
	return k
}

// hexes decodes a list of hex hashes.
func hexes(t *testing.T, in []string) [][]byte {
	t.Helper()
	out := make([][]byte, 0, len(in))
	for _, s := range in {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatalf("decode %q: %v", s, err)
		}
		out = append(out, b)
	}
	return out
}

// TestRootsMatchIndependentVectors checks every tree root against the independent implementation.
// The roots are where a wrong split point shows up: an implementation that divides at n/2 instead of
// the largest power of two below n still produces correct roots at every power of two, so only the
// sizes between them, three, five, six, seven, and nine, catch it.
func TestRootsMatchIndependentVectors(t *testing.T) {
	t.Parallel()
	k := loadKAT(t)
	if got := hex.EncodeToString(EmptyRoot()); got != k.EmptyRoot {
		t.Errorf("empty root = %s, want %s", got, k.EmptyRoot)
	}
	for size, want := range k.Roots {
		n, err := strconv.ParseInt(size, 10, 64)
		if err != nil {
			t.Fatalf("vector has a non-numeric size %q", size)
		}
		if got := hex.EncodeToString(Root(leaves(n))); got != want {
			t.Errorf("root of %d leaves = %s, want %s", n, got, want)
		}
	}
}

// TestInclusionProofsMatchIndependentVectors checks that this package generates byte-identical audit
// paths to the independent implementation, and that each one verifies. Generating the same proof is
// the stronger claim: two verifiers can accept each other's proofs while producing different ones.
func TestInclusionProofsMatchIndependentVectors(t *testing.T) {
	t.Parallel()
	k := loadKAT(t)
	for _, v := range k.Inclusion {
		all := leaves(v.TreeSize)
		got, err := InclusionProof(v.LeafIndex, all)
		if err != nil {
			t.Fatalf("InclusionProof(%d, %d) error = %v", v.LeafIndex, v.TreeSize, err)
		}
		if len(got) != len(v.Path) {
			t.Errorf("leaf %d of %d: path has %d elements, want %d",
				v.LeafIndex, v.TreeSize, len(got), len(v.Path))
			continue
		}
		for i := range got {
			if hex.EncodeToString(got[i]) != v.Path[i] {
				t.Errorf("leaf %d of %d: path element %d = %s, want %s",
					v.LeafIndex, v.TreeSize, i, hex.EncodeToString(got[i]), v.Path[i])
			}
		}
		// The other implementation's own path must verify here too, so acceptance is mutual.
		root, err := hex.DecodeString(v.Root)
		if err != nil {
			t.Fatalf("decode root: %v", err)
		}
		if !VerifyInclusion(all[v.LeafIndex], v.LeafIndex, v.TreeSize, hexes(t, v.Path), root) {
			t.Errorf("leaf %d of %d: the independent proof does not verify here",
				v.LeafIndex, v.TreeSize)
		}
	}
}

// TestConsistencyProofsMatchIndependentVectors checks proof-for-proof agreement on append-only
// growth, and that the independent implementation's proofs verify here.
func TestConsistencyProofsMatchIndependentVectors(t *testing.T) {
	t.Parallel()
	k := loadKAT(t)
	for _, v := range k.Consistency {
		got, err := ConsistencyProof(v.FirstSize, leaves(v.SecondSize))
		if err != nil {
			t.Fatalf("ConsistencyProof(%d, %d) error = %v", v.FirstSize, v.SecondSize, err)
		}
		if len(got) != len(v.Proof) {
			t.Errorf("%d->%d: proof has %d elements, want %d",
				v.FirstSize, v.SecondSize, len(got), len(v.Proof))
			continue
		}
		for i := range got {
			if hex.EncodeToString(got[i]) != v.Proof[i] {
				t.Errorf("%d->%d: proof element %d = %s, want %s",
					v.FirstSize, v.SecondSize, i, hex.EncodeToString(got[i]), v.Proof[i])
			}
		}
		first, err := hex.DecodeString(v.FirstRoot)
		if err != nil {
			t.Fatalf("decode first root: %v", err)
		}
		second, err := hex.DecodeString(v.SecondRoot)
		if err != nil {
			t.Fatalf("decode second root: %v", err)
		}
		if !VerifyConsistency(v.FirstSize, v.SecondSize, first, second, hexes(t, v.Proof)) {
			t.Errorf("%d->%d: the independent proof does not verify here", v.FirstSize, v.SecondSize)
		}
	}
}
