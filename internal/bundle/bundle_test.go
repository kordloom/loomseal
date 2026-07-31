package bundle

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

// base returns a minimal valid unchained bundle as a value tree.
func base() map[string]any {
	keyID := "sha256:" + strings.Repeat("ab", 32)
	return map[string]any{
		"loomseal":   "0.1",
		"bundle_id":  "lsb_test",
		"created_at": "2026-07-27T12:00:00Z",
		"producer": map[string]any{
			"product":         "switchtender",
			"product_version": "0.4.0",
			"install_id":      "in_1",
			"public_key":      base64.StdEncoding.EncodeToString(make([]byte, 32)),
			"key_id":          keyID,
		},
		"subject": map[string]any{"type": "url", "id": "https://example.com"},
		"claims": []any{map[string]any{
			"type":    "switchtender.audit/1",
			"at":      "2026-07-27T12:00:00Z",
			"payload": map[string]any{"target_id": "tg_1"},
		}},
		"signatures": []any{map[string]any{
			"key_id": keyID,
			"alg":    "ed25519",
			"sig":    base64.StdEncoding.EncodeToString(make([]byte, 64)),
		}},
	}
}

// mustJSON marshals a value tree or fails the test.
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

// producerOf returns the producer submap for mutation.
func producerOf(m map[string]any) map[string]any {
	p, _ := m["producer"].(map[string]any)
	return p
}

// claimOf returns the first claim submap for mutation.
func claimOf(m map[string]any) map[string]any {
	c, _ := m["claims"].([]any)
	first, _ := c[0].(map[string]any)
	return first
}

func TestParse(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Mutate func(m map[string]any)
		Want   error
	}{{ // Test 0: The base bundle is valid.
		Mutate: func(m map[string]any) {},
	}, { // Test 1: Unknown top-level fields are rejected.
		Mutate: func(m map[string]any) { m["extra"] = 1 }, Want: ErrParse,
	}, { // Test 2: A wrong format version is rejected.
		Mutate: func(m map[string]any) { m["loomseal"] = "0.2" }, Want: ErrSchema,
	}, { // Test 3: An empty bundle_id is rejected.
		Mutate: func(m map[string]any) { m["bundle_id"] = "" }, Want: ErrSchema,
	}, { // Test 4: A malformed created_at is rejected.
		Mutate: func(m map[string]any) { m["created_at"] = "yesterday" }, Want: ErrSchema,
	}, { // Test 5: A wrong-size public key is rejected.
		Mutate: func(m map[string]any) {
			producerOf(m)["public_key"] = base64.StdEncoding.EncodeToString(make([]byte, 16))
		}, Want: ErrSchema,
	}, { // Test 6: A malformed producer key_id is rejected.
		Mutate: func(m map[string]any) { producerOf(m)["key_id"] = "abc" }, Want: ErrSchema,
	}, { // Test 7: An unknown subject type is rejected.
		Mutate: func(m map[string]any) {
			m["subject"] = map[string]any{"type": "planet", "id": "x"}
		}, Want: ErrSchema,
	}, { // Test 8: A bundle without claims is rejected.
		Mutate: func(m map[string]any) { m["claims"] = []any{} }, Want: ErrSchema,
	}, { // Test 9: A malformed claim type is rejected.
		Mutate: func(m map[string]any) { claimOf(m)["type"] = "SwitchTender.Audit" }, Want: ErrSchema,
	}, { // Test 10: A non-object payload is rejected.
		Mutate: func(m map[string]any) { claimOf(m)["payload"] = []any{1} }, Want: ErrSchema,
	}, { // Test 11: A malformed evidence digest is rejected.
		Mutate: func(m map[string]any) {
			claimOf(m)["evidence"] = []any{map[string]any{"role": "snapshot", "digest": "sha256:short"}}
		}, Want: ErrSchema,
	}, { // Test 12: An unknown chain profile is rejected.
		Mutate: func(m map[string]any) {
			m["chain"] = map[string]any{
				"profile": "mystery-v9", "keyed": false,
				"head": map[string]any{"seq": 1, "link": strings.Repeat("ab", 32)},
			}
		}, Want: ErrSchema,
	}, { // Test 13: A chain head with a bad link is rejected.
		Mutate: func(m map[string]any) {
			m["chain"] = map[string]any{
				"profile": ProfileV1, "keyed": false,
				"head": map[string]any{"seq": 1, "link": "nope"},
			}
		}, Want: ErrSchema,
	}, { // Test 14: Claim chain coordinates below one are rejected.
		Mutate: func(m map[string]any) {
			claimOf(m)["chain"] = map[string]any{"seq": 0, "link": strings.Repeat("ab", 32)}
		}, Want: ErrSchema,
	}, { // Test 15: An unknown anchor type is rejected.
		Mutate: func(m map[string]any) {
			m["anchors"] = []any{map[string]any{
				"type": "carrier-pigeon", "seq": 1, "link": strings.Repeat("ab", 32),
				"at": "2026-07-27T12:00:00Z", "ref": "x",
			}}
		}, Want: ErrSchema,
	}, { // Test 16: A bundle without signatures is rejected.
		Mutate: func(m map[string]any) { m["signatures"] = []any{} }, Want: ErrSchema,
	}, { // Test 17: A wrong signature algorithm is rejected.
		Mutate: func(m map[string]any) {
			s, _ := m["signatures"].([]any)
			first, _ := s[0].(map[string]any)
			first["alg"] = "rsa"
		}, Want: ErrSchema,
	}, { // Test 18: A wrong-size signature is rejected.
		Mutate: func(m map[string]any) {
			s, _ := m["signatures"].([]any)
			first, _ := s[0].(map[string]any)
			first["sig"] = base64.StdEncoding.EncodeToString(make([]byte, 63))
		}, Want: ErrSchema,
	}, { // Test 19: An incomplete verdict is rejected.
		Mutate: func(m map[string]any) {
			claimOf(m)["verdict"] = map[string]any{"policy": "p/1"}
		}, Want: ErrSchema,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			m := base()
			test.Mutate(m)
			_, err := Parse(mustJSON(t, m))
			if !errors.Is(err, test.Want) {
				t.Errorf("error mismatch: got %v, want %v", err, test.Want)
			}
		})
	}
}

// Test that trailing data after the bundle document is rejected.
func TestParseTrailingData(t *testing.T) {
	t.Parallel()
	raw := append(mustJSON(t, base()), []byte(" {}")...)
	if _, err := Parse(raw); !errors.Is(err, ErrParse) {
		t.Errorf("error mismatch: got %v, want %v", err, ErrParse)
	}
}

// Test that CanonicalUnsigned empties signatures and is independent of member order.
func TestCanonicalUnsigned(t *testing.T) {
	t.Parallel()
	a := []byte(`{"b":1,"a":2,"signatures":[{"key_id":"x"}]}`)
	c := []byte(`{"signatures":[],"a":2,"b":1}`)
	gotA, err := CanonicalUnsigned(a)
	if err != nil {
		t.Fatalf("canonicalize a: %v", err)
	}
	gotC, err := CanonicalUnsigned(c)
	if err != nil {
		t.Fatalf("canonicalize c: %v", err)
	}
	if diff := cmp.Diff(string(gotC), string(gotA)); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
	if want := `{"a":2,"b":1,"signatures":[]}`; string(gotA) != want {
		t.Errorf("canonical form mismatch: got %s, want %s", gotA, want)
	}
}

// TestAnchorValidate pins every rule an anchor record has to satisfy.
//
// An anchor is the part of a bundle that says the chain existed at a point in time. A malformed one
// that parsed anyway would let a producer attach something that looks like external corroboration
// and is not, which is worse than carrying no anchor at all.
func TestAnchorValidate(t *testing.T) {
	t.Parallel()
	good := Anchor{
		Type: "rfc3161", Seq: 1, Link: strings.Repeat("ab", 32),
		At: "2026-07-27T15:00:00Z", Ref: "https://freetsa.org/tsr",
	}
	if err := good.validate(0); err != nil {
		t.Fatalf("a well-formed anchor was rejected: %v", err)
	}
	withProof := good
	withProof.Proof = base64.StdEncoding.EncodeToString([]byte("token bytes"))
	if err := withProof.validate(0); err != nil {
		t.Errorf("an anchor carrying a valid proof was rejected: %v", err)
	}

	tests := []struct {
		Name   string
		Mutate func(a *Anchor)
	}{
		{Name: "unknown type", Mutate: func(a *Anchor) { a.Type = "carrier-pigeon" }},
		{Name: "empty type", Mutate: func(a *Anchor) { a.Type = "" }},
		{Name: "sequence below one", Mutate: func(a *Anchor) { a.Seq = 0 }},
		{Name: "negative sequence", Mutate: func(a *Anchor) { a.Seq = -5 }},
		{Name: "link is not a hash", Mutate: func(a *Anchor) { a.Link = "nope" }},
		{Name: "empty link", Mutate: func(a *Anchor) { a.Link = "" }},
		{Name: "no reference to check", Mutate: func(a *Anchor) { a.Ref = "" }},
		{Name: "proof is not base64", Mutate: func(a *Anchor) { a.Proof = "!!! not base64 !!!" }},
		{Name: "time is not RFC 3339", Mutate: func(a *Anchor) { a.At = "last Tuesday" }},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			bad := good
			test.Mutate(&bad)
			if err := bad.validate(3); err == nil {
				t.Error("an invalid anchor validated")
			} else if !errors.Is(err, ErrSchema) {
				t.Errorf("error = %v, want ErrSchema so the caller can tell a schema fault apart", err)
			}
		})
	}
}

// TestKeyIDShape pins the producer fingerprint an operator publishes and a relying party pins.
func TestKeyIDShape(t *testing.T) {
	t.Parallel()
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for i := range pub {
		pub[i] = byte(i)
	}
	id := KeyID(pub)
	if !strings.HasPrefix(id, "sha256:") || len(id) != len("sha256:")+64 {
		t.Errorf("KeyID = %q, want sha256: followed by 64 hex characters", id)
	}
	if KeyID(pub) != id {
		t.Error("KeyID is not stable, so a published fingerprint would stop matching")
	}
	other := make(ed25519.PublicKey, len(pub))
	copy(other, pub)
	other[31] ^= 0xff
	if KeyID(other) == id {
		t.Error("two different keys share a fingerprint, so pinning one accepts the other")
	}
}
