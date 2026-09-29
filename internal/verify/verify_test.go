package verify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/kordloom/loomseal/internal/chain"
	"github.com/kordloom/loomseal/seal"
)

// at is the fixed claim time used throughout the verification tests.
const at = "2026-07-27T12:00:00Z"

// snapContent is the evidence artifact the fixtures reference.
var snapContent = []byte("hello world")

// testKey returns a deterministic ed25519 key for fixtures.
func testKey() ed25519.PrivateKey {
	return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
}

// digestOf returns the sha256: digest of content.
func digestOf(content []byte) string {
	sum := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// auditClaim builds one switchtender.audit claim without chain coordinates.
func auditClaim(actor string) map[string]any {
	return map[string]any{
		"type": "switchtender.audit/1", "at": at,
		"payload": map[string]any{"actor": actor, "method": "POST", "path": "/api/runs"},
	}
}

// signedBundle builds a two-claim loomseal-chain-v1 bundle with one anchor and one
// evidence digest, applies mutate to the tree when given, signs, and returns the document.
func signedBundle(t *testing.T, mutate func(m map[string]any)) []byte {
	t.Helper()
	priv := testKey()
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("public key type")
	}

	c1 := auditClaim("amy")
	c1["evidence"] = []any{map[string]any{
		"role": "snapshot", "digest": digestOf(snapContent), "media_type": "text/html",
	}}
	link1, err := chain.LinkV1(nil, "in_1", 1, "", c1)
	if err != nil {
		t.Fatalf("link 1: %v", err)
	}
	c1["chain"] = map[string]any{"seq": 1, "prev": "", "link": link1}

	c2 := auditClaim("bo")
	link2, err := chain.LinkV1(nil, "in_1", 2, link1, c2)
	if err != nil {
		t.Fatalf("link 2: %v", err)
	}
	c2["chain"] = map[string]any{"seq": 2, "prev": link1, "link": link2}

	m := map[string]any{
		"loomseal":   "0.1",
		"bundle_id":  "lsb_test",
		"created_at": at,
		"producer": map[string]any{
			"product":         "test",
			"product_version": "1",
			"install_id":      "in_1",
			"public_key":      base64Std(pub),
			"key_id":          seal.KeyID(pub),
		},
		"subject": map[string]any{"type": "url", "id": "https://example.com"},
		"chain": map[string]any{
			"profile": "loomseal-chain-v1", "keyed": false,
			"params": map[string]any{"install_id": "in_1"},
			"head":   map[string]any{"seq": 2, "link": link2},
		},
		"claims": []any{c1, c2},
		"anchors": []any{map[string]any{
			"type": "git", "seq": 2, "link": link2, "at": at,
			"ref":   "https://github.com/acme/anchors/commit/abc",
			"proof": "dG9r",
		}},
	}
	if mutate != nil {
		mutate(m)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signed, err := seal.SignBundle(raw, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

// base64Std encodes bytes with standard base64 without pulling the import into every test.
func base64Std(b []byte) string {
	return string(mustJSONString(b))
}

// mustJSONString reuses encoding/json's base64 encoding of byte slices.
func mustJSONString(b []byte) []byte {
	quoted, _ := json.Marshal(b)
	return bytes.Trim(quoted, `"`)
}

// evidenceDir writes the snapshot artifact into a fresh directory.
func evidenceDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "snap.html"), snapContent, 0o600); err != nil {
		t.Fatalf("write evidence: %v", err)
	}
	return dir
}

// Test the full happy path: signed, fully chained, anchored, evidence verified.
func TestRunVerified(t *testing.T) {
	t.Parallel()
	pub, _ := testKey().Public().(ed25519.PublicKey)
	got := Run(signedBundle(t, nil), Options{EvidenceDir: evidenceDir(t)})
	want := &Report{
		OK:                  true,
		Level:               "signed, chained (full), anchored by reference",
		BundleID:            "lsb_test",
		Producer:            "test 1",
		Subject:             "url https://example.com",
		KeyID:               seal.KeyID(pub),
		SignatureOK:         true,
		ChainPresent:        true,
		ChainProfile:        "loomseal-chain-v1",
		ChainMode:           chain.ModeFull,
		ChainOK:             true,
		HeadMatched:         true,
		ClaimsChecked:       2,
		AnchorsMatched:      1,
		AnchorProofsCarried: 1,
		EvidenceVerified:    1,
	}
	if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
}

// Test that tampering after signing fails the signature.
func TestRunTamperedPayload(t *testing.T) {
	t.Parallel()
	signed := signedBundle(t, nil)
	tampered := bytes.Replace(signed, []byte("amy"), []byte("amx"), 1)
	got := Run(tampered, Options{})
	if got.OK || got.SignatureOK {
		t.Errorf("tampered bundle verified: ok %t signature_ok %t", got.OK, got.SignatureOK)
	}
}

// Test the fingerprint pin in both directions.
func TestRunFingerprint(t *testing.T) {
	t.Parallel()
	pub, _ := testKey().Public().(ed25519.PublicKey)
	signed := signedBundle(t, nil)

	got := Run(signed, Options{Fingerprint: seal.KeyID(pub)})
	if !got.OK || got.FingerprintMatch == nil || !*got.FingerprintMatch {
		t.Errorf("matching pin did not verify: %+v", got.Problems)
	}

	got = Run(signed, Options{Fingerprint: "sha256:" + strings.Repeat("00", 32)})
	if got.OK || got.FingerprintMatch == nil || *got.FingerprintMatch {
		t.Error("mismatched pin verified")
	}
}

// Test that a chain broken before signing keeps the signature but fails the chain.
func TestRunBrokenChain(t *testing.T) {
	t.Parallel()
	signed := signedBundle(t, func(m map[string]any) {
		claims, _ := m["claims"].([]any)
		second, _ := claims[1].(map[string]any)
		coords, _ := second["chain"].(map[string]any)
		coords["prev"] = strings.Repeat("ee", 32)
	})
	got := Run(signed, Options{})
	if got.OK || !got.SignatureOK || got.ChainOK {
		t.Errorf("broken chain outcome: ok %t signature_ok %t chain_ok %t", got.OK,
			got.SignatureOK, got.ChainOK)
	}
}

// Test that an anchor pointing nowhere fails while a carried proof is still counted.
func TestRunAnchorMismatch(t *testing.T) {
	t.Parallel()
	signed := signedBundle(t, func(m map[string]any) {
		anchors, _ := m["anchors"].([]any)
		first, _ := anchors[0].(map[string]any)
		first["link"] = strings.Repeat("ee", 32)
	})
	got := Run(signed, Options{})
	if got.OK || got.AnchorsMatched != 0 || got.AnchorProofsCarried != 1 {
		t.Errorf("anchor outcome: ok %t matched %d carried %d", got.OK, got.AnchorsMatched,
			got.AnchorProofsCarried)
	}
}

// Test that an anchor matching only a declared head beyond the bundled claims does not earn
// the anchored conformance word: the head link is unverified, so the anchor binds nothing.
func TestRunAnchorToDeclaredHead(t *testing.T) {
	t.Parallel()
	invented := strings.Repeat("de", 32)
	signed := signedBundle(t, func(m map[string]any) {
		c, _ := m["chain"].(map[string]any)
		c["head"] = map[string]any{"seq": 99, "link": invented}
		anchors, _ := m["anchors"].([]any)
		first, _ := anchors[0].(map[string]any)
		first["seq"] = 99
		first["link"] = invented
	})
	got := Run(signed, Options{})
	if !got.OK {
		t.Fatalf("bundle did not verify: %v", got.Problems)
	}
	if got.Level != "signed, chained (full)" {
		t.Errorf("level %q, want %q", got.Level, "signed, chained (full)")
	}
	if got.HeadMatched {
		t.Errorf("head matched %t, want false", got.HeadMatched)
	}
	if got.AnchorsMatched != 0 || got.AnchorsToDeclaredHead != 1 {
		t.Errorf("anchor counts: matched %d, to declared head %d", got.AnchorsMatched,
			got.AnchorsToDeclaredHead)
	}
}

// Test that a keyed chain verifies structurally.
func TestRunKeyedStructural(t *testing.T) {
	t.Parallel()
	signed := signedBundle(t, func(m map[string]any) {
		c, _ := m["chain"].(map[string]any)
		c["keyed"] = true
	})
	got := Run(signed, Options{})
	if !got.OK || got.ChainMode != chain.ModeStructural {
		t.Errorf("keyed outcome: ok %t mode %q problems %v", got.OK, got.ChainMode, got.Problems)
	}
	if got.Level != "signed, chained (structural), anchored by reference" {
		t.Errorf("level %q", got.Level)
	}
}

// Test that no evidence directory leaves digests referenced, not verified.
func TestRunEvidenceReferenced(t *testing.T) {
	t.Parallel()
	got := Run(signedBundle(t, nil), Options{})
	if !got.OK || got.EvidenceReferenced != 1 || got.EvidenceVerified != 0 {
		t.Errorf("evidence outcome: ok %t referenced %d verified %d", got.OK,
			got.EvidenceReferenced, got.EvidenceVerified)
	}
}

// Test that an unknown claim type is reported without failing verification.
func TestRunUnknownClaimType(t *testing.T) {
	t.Parallel()
	priv := testKey()
	pub, _ := priv.Public().(ed25519.PublicKey)
	m := map[string]any{
		"loomseal":   "0.1",
		"bundle_id":  "lsb_plain",
		"created_at": at,
		"producer": map[string]any{
			"product": "test", "product_version": "1", "install_id": "in_1",
			"public_key": base64Std(pub), "key_id": seal.KeyID(pub),
		},
		"subject": map[string]any{"type": "url", "id": "https://example.com"},
		"claims": []any{map[string]any{
			"type": "acme.thing/1", "at": at, "payload": map[string]any{"x": 1},
		}},
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signed, err := seal.SignBundle(raw, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	got := Run(signed, Options{})
	if !got.OK || got.Level != "signed" {
		t.Errorf("outcome: ok %t level %q problems %v", got.OK, got.Level, got.Problems)
	}
	if diff := cmp.Diff([]string{"acme.thing/1"}, got.UnknownClaimTypes); diff != "" {
		t.Errorf("unknown types (-want +got):\n%s", diff)
	}
}

// Test that a producer key_id contradicting the embedded key fails.
func TestRunKeyIDMismatch(t *testing.T) {
	t.Parallel()
	signed := signedBundle(t, func(m map[string]any) {
		p, _ := m["producer"].(map[string]any)
		p["key_id"] = "sha256:" + strings.Repeat("00", 32)
	})
	got := Run(signed, Options{})
	if got.OK || got.SignatureOK {
		t.Error("bundle with contradicting key_id verified")
	}
}

// Test that unparseable input is a failed verification, not a crash.
func TestRunGarbage(t *testing.T) {
	t.Parallel()
	got := Run([]byte("{"), Options{})
	if got.OK || got.Level != "not verified" || len(got.Problems) == 0 {
		t.Errorf("garbage outcome: %+v", got)
	}
}
