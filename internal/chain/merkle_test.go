package chain_test

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/kordloom/loomseal/internal/bundle"
	"github.com/kordloom/loomseal/internal/merkle"
	"github.com/kordloom/loomseal/internal/verify"
	"github.com/kordloom/loomseal/jcs"
	"github.com/kordloom/loomseal/seal"
)

// treeLog is a producer's whole log: the claim objects, in order, that the tree is built over.
type treeLog struct {
	// installID is the producer's install, hashed into every leaf.
	installID string
	// claims are the log's entries as JSON objects.
	claims []map[string]any
}

// newTreeLog builds a log of n deterministic claims.
func newTreeLog(installID string, n int) *treeLog {
	l := &treeLog{installID: installID}
	for i := 0; i < n; i++ {
		l.claims = append(l.claims, map[string]any{
			"type": "switchtender.audit/1",
			"at":   fmt.Sprintf("2026-08-11T10:%02d:00Z", i),
			"payload": map[string]any{
				"actor": "alice", "method": "POST", "path": fmt.Sprintf("/v1/runs/%d", i),
			},
		})
	}
	return l
}

// leafData builds one claim's leaf bytes exactly as the profile specifies: the canonical object of
// the domain, the install, and the claim digest over the claim's content.
func (l *treeLog) leafData(t *testing.T, claim map[string]any) []byte {
	t.Helper()
	content := map[string]any{}
	for k, v := range claim {
		if k == "chain" || k == "inclusion" {
			continue
		}
		content[k] = v
	}
	canonical, err := jcs.Serialize(content)
	if err != nil {
		t.Fatalf("canonicalize claim: %v", err)
	}
	leaf, err := jcs.Serialize(map[string]any{
		"domain":     bundle.ProfileMerkle,
		"install_id": l.installID,
		"claim":      "sha256:" + merkle.Sum256Hex(canonical),
	})
	if err != nil {
		t.Fatalf("canonicalize leaf: %v", err)
	}
	return leaf
}

// leaves returns every leaf of the log, in order.
func (l *treeLog) leaves(t *testing.T) [][]byte {
	t.Helper()
	out := make([][]byte, 0, len(l.claims))
	for _, c := range l.claims {
		out = append(out, l.leafData(t, c))
	}
	return out
}

// bundleFor assembles and signs a bundle disclosing the leaves at the given indexes, optionally
// carrying a consistency proof from fromSize. It returns the signed document.
func (l *treeLog) bundleFor(t *testing.T, priv ed25519.PrivateKey, indexes []int, fromSize int) []byte {
	t.Helper()
	all := l.leaves(t)
	size := int64(len(all))
	root := merkle.Root(all)

	claims := make([]any, 0, len(indexes))
	for _, idx := range indexes {
		path, err := merkle.InclusionProof(int64(idx), all)
		if err != nil {
			t.Fatalf("InclusionProof(%d): %v", idx, err)
		}
		c := map[string]any{}
		for k, v := range l.claims[idx] {
			c[k] = v
		}
		c["chain"] = map[string]any{
			"seq":  int64(idx + 1),
			"prev": "",
			"link": hex.EncodeToString(merkle.LeafHash(all[idx])),
		}
		c["inclusion"] = map[string]any{"path": hexAll(path)}
		claims = append(claims, c)
	}

	chain := map[string]any{
		"profile": bundle.ProfileMerkle,
		"keyed":   false,
		"params":  map[string]any{"install_id": l.installID},
		"head":    map[string]any{"seq": size, "link": hex.EncodeToString(root)},
	}
	if fromSize > 0 {
		proof, err := merkle.ConsistencyProof(int64(fromSize), all)
		if err != nil {
			t.Fatalf("ConsistencyProof(%d): %v", fromSize, err)
		}
		chain["consistency"] = map[string]any{
			"from_size": int64(fromSize),
			"from_root": hex.EncodeToString(merkle.Root(all[:fromSize])),
			"path":      hexAll(proof),
		}
	}

	pub := priv.Public().(ed25519.PublicKey)
	doc := map[string]any{
		"loomseal":   bundle.Version,
		"bundle_id":  "lsb_tree",
		"created_at": "2026-08-11T12:00:00Z",
		"producer": map[string]any{
			"product": "switchtender", "product_version": "v-test",
			"install_id": l.installID,
			"public_key": base64Std(pub), "key_id": seal.KeyID(pub),
		},
		"subject":    map[string]any{"type": "run", "id": "run_demo"},
		"chain":      chain,
		"claims":     claims,
		"signatures": []any{},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	signed, err := seal.SignBundle(raw, priv)
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	return signed
}

// hexAll hex encodes a list of hashes.
func hexAll(in [][]byte) []any {
	out := make([]any, 0, len(in))
	for _, h := range in {
		out = append(out, hex.EncodeToString(h))
	}
	return out
}

// base64Std encodes a key the way the format specifies.
func base64Std(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var sb strings.Builder
	for i := 0; i < len(b); i += 3 {
		var n uint32
		rem := len(b) - i
		n |= uint32(b[i]) << 16
		if rem > 1 {
			n |= uint32(b[i+1]) << 8
		}
		if rem > 2 {
			n |= uint32(b[i+2])
		}
		sb.WriteByte(alphabet[(n>>18)&63])
		sb.WriteByte(alphabet[(n>>12)&63])
		if rem > 1 {
			sb.WriteByte(alphabet[(n>>6)&63])
		} else {
			sb.WriteByte('=')
		}
		if rem > 2 {
			sb.WriteByte(alphabet[n&63])
		} else {
			sb.WriteByte('=')
		}
	}
	return sb.String()
}

// testKey returns a deterministic signing key.
func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// TestMerkleSparseDisclosureVerifies is the profile's reason to exist: a bundle disclosing two
// non-contiguous claims out of a longer log verifies end to end through the real verifier, which the
// linear profiles cannot do because they require contiguity.
func TestMerkleSparseDisclosureVerifies(t *testing.T) {
	t.Parallel()
	priv := testKey(t)
	log := newTreeLog("in_test", 6)
	signed := log.bundleFor(t, priv, []int{1, 4}, 0)

	rep := verify.Run(signed, verify.Options{})
	if !rep.OK {
		t.Fatalf("sparse tree bundle did not verify: %v", rep.Problems)
	}
	if rep.ChainProfile != bundle.ProfileMerkle {
		t.Errorf("chain profile = %q, want %q", rep.ChainProfile, bundle.ProfileMerkle)
	}
	if !rep.ChainOK || !rep.HeadMatched {
		t.Errorf("chain ok=%v head matched=%v, want both true", rep.ChainOK, rep.HeadMatched)
	}
	if rep.ClaimsChecked != 2 {
		t.Errorf("claims checked = %d, want 2", rep.ClaimsChecked)
	}
	// The size is the whole log's, not the window's, which is the fact a reader needs to know how
	// much history the two disclosed claims were proved against.
	if rep.TreeSize != 6 {
		t.Errorf("tree size = %d, want 6", rep.TreeSize)
	}
	if rep.InclusionProofs != 2 {
		t.Errorf("inclusion proofs = %d, want 2", rep.InclusionProofs)
	}
	if rep.ConsistencyOK || rep.ConsistencyFrom != 0 {
		t.Errorf("consistency ok=%v from=%d, want a bundle carrying no proof to report neither",
			rep.ConsistencyOK, rep.ConsistencyFrom)
	}
	if want := "signed, chained (tree of 6)"; rep.Level != want {
		t.Errorf("level = %q, want %q", rep.Level, want)
	}
}

// TestMerkleConsistencyProvesAppendOnly checks a bundle carrying a consistency proof verifies, which
// is the statement a linear chain cannot make: the log grew from an earlier root by appending only.
func TestMerkleConsistencyProvesAppendOnly(t *testing.T) {
	t.Parallel()
	priv := testKey(t)
	log := newTreeLog("in_test", 6)
	signed := log.bundleFor(t, priv, []int{0, 5}, 4)

	rep := verify.Run(signed, verify.Options{})
	if !rep.OK {
		t.Fatalf("bundle with a consistency proof did not verify: %v", rep.Problems)
	}
	if !rep.ConsistencyOK || rep.ConsistencyFrom != 4 {
		t.Errorf("consistency ok=%v from=%d, want true from 4", rep.ConsistencyOK,
			rep.ConsistencyFrom)
	}
	// Append-only growth answers a different question from whether the bundle is intact, so the
	// report says it in words rather than leaving it to a reader to infer from a proof count.
	if want := "signed, chained (tree of 6, append-only from 4)"; rep.Level != want {
		t.Errorf("level = %q, want %q", rep.Level, want)
	}
}

// TestMerkleRejectsForgeries drives every attack the profile is meant to refuse through the real
// verifier: a tampered claim, a forged audit path, a wrong leaf index, a consistency proof over a
// rewritten log, and an install id that is not the signer's.
func TestMerkleRejectsForgeries(t *testing.T) {
	t.Parallel()
	priv := testKey(t)

	tests := []struct {
		Name string
		Want string
		// Mutate edits the parsed bundle before it is re-signed, so the signature is always valid and
		// only the profile's own checks can catch the forgery.
		Mutate func(doc map[string]any)
	}{
		{
			Name: "claim content altered",
			Want: "leaf hash does not recompute",
			Mutate: func(doc map[string]any) {
				c := doc["claims"].([]any)[0].(map[string]any)
				c["payload"].(map[string]any)["path"] = "/v1/evil"
			},
		},
		{
			Name: "audit path element flipped",
			Want: "does not prove membership",
			Mutate: func(doc map[string]any) {
				c := doc["claims"].([]any)[0].(map[string]any)
				p := c["inclusion"].(map[string]any)["path"].([]any)
				p[0] = strings.Repeat("ab", 32)
			},
		},
		{
			Name: "leaf index moved",
			Want: "does not prove membership",
			Mutate: func(doc map[string]any) {
				c := doc["claims"].([]any)[0].(map[string]any)
				c["chain"].(map[string]any)["seq"] = int64(3)
			},
		},
		{
			Name: "seq past the tree size",
			Want: "past the tree size",
			Mutate: func(doc map[string]any) {
				c := doc["claims"].([]any)[0].(map[string]any)
				c["chain"].(map[string]any)["seq"] = int64(99)
			},
		},
		{
			Name: "install id is not the signer's",
			Want: "not the producer's install",
			Mutate: func(doc map[string]any) {
				doc["chain"].(map[string]any)["params"].(map[string]any)["install_id"] = "in_other"
			},
		},
		{
			Name: "claim carries a previous link",
			Want: "previous link",
			Mutate: func(doc map[string]any) {
				c := doc["claims"].([]any)[0].(map[string]any)
				c["chain"].(map[string]any)["prev"] = strings.Repeat("cd", 32)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			log := newTreeLog("in_test", 6)
			signed := log.bundleFor(t, priv, []int{1, 4}, 0)

			var doc map[string]any
			if err := json.Unmarshal(signed, &doc); err != nil {
				t.Fatalf("Unmarshal: %v", err)
			}
			test.Mutate(doc)
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			// Re-sign so the signature is genuine over the altered bundle: the forgery must be caught
			// by the profile's own checks, not by a broken signature.
			resigned, err := seal.SignBundle(raw, priv)
			if err != nil {
				t.Fatalf("SignBundle: %v", err)
			}
			rep := verify.Run(resigned, verify.Options{})
			if rep.OK {
				t.Fatalf("the verifier accepted %s", test.Name)
			}
			joined := strings.Join(rep.Problems, " ")
			if !strings.Contains(joined, test.Want) {
				t.Errorf("problems = %q, want something naming %q", joined, test.Want)
			}
		})
	}
}

// TestMerkleConsistencyCatchesARewrite proves the append-only guarantee through the real verifier: a
// producer that rewrote an entry it had already published cannot present a consistency proof from the
// old root, however well formed its new log is.
func TestMerkleConsistencyCatchesARewrite(t *testing.T) {
	t.Parallel()
	priv := testKey(t)
	honest := newTreeLog("in_test", 6)
	honestOld := merkle.Root(honest.leaves(t)[:4])

	// Rewrite an entry inside the already-published prefix, then build an honest bundle over the
	// rewritten log and swap in the root the world saw before the rewrite.
	rewritten := newTreeLog("in_test", 6)
	rewritten.claims[1]["payload"].(map[string]any)["path"] = "/v1/rewritten"
	signed := rewritten.bundleFor(t, priv, []int{0, 5}, 4)

	var doc map[string]any
	if err := json.Unmarshal(signed, &doc); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	doc["chain"].(map[string]any)["consistency"].(map[string]any)["from_root"] =
		hex.EncodeToString(honestOld)
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	resigned, err := seal.SignBundle(raw, priv)
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}

	rep := verify.Run(resigned, verify.Options{})
	if rep.OK {
		t.Fatal("a log that rewrote a published entry proved append-only growth")
	}
	joined := strings.Join(rep.Problems, " ")
	if !strings.Contains(joined, "appending") {
		t.Errorf("problems = %q, want the append-only failure named", joined)
	}
}
