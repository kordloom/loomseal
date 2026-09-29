package verify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/kordloom/loomseal/internal/bundle"
	"github.com/kordloom/loomseal/internal/chain"
	"github.com/kordloom/loomseal/jcs"
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
		AnchoredThroughSeq:  2,
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

// Test that an anchor pointing nowhere fails and its carried proof is not counted: a proof over a
// coordinate this verifier could not confirm attests nothing about the bundle, so it is not opened.
func TestRunAnchorMismatch(t *testing.T) {
	t.Parallel()
	signed := signedBundle(t, func(m map[string]any) {
		anchors, _ := m["anchors"].([]any)
		first, _ := anchors[0].(map[string]any)
		first["link"] = strings.Repeat("ee", 32)
	})
	got := Run(signed, Options{})
	if got.OK || got.AnchorsMatched != 0 || got.AnchorProofsCarried != 0 {
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

// TestMeasureUnanchored checks how far the anchors reach and what they leave uncovered. The
// span past the last anchored position is the part a compromised producer key could rewrite,
// so a verified bundle that leaves a wide one is weaker evidence than one that leaves none.
func TestMeasureUnanchored(t *testing.T) {
	t.Parallel()
	claim := func(seq int64, at, link string) bundle.Claim {
		return bundle.Claim{At: at, Chain: &bundle.Coords{Seq: seq, Link: link}}
	}
	tests := []struct {
		WantWindow  string
		Claims      []bundle.Claim
		Anchors     []bundle.Anchor
		WantThrough int64
		WantClaims  int
	}{{ // Test 0: The anchor covers the newest claim, so nothing is left uncovered.
		Claims: []bundle.Claim{
			claim(1, "2026-07-31T10:00:00Z", "aa"),
			claim(2, "2026-07-31T11:00:00Z", "bb"),
		},
		Anchors:     []bundle.Anchor{{Seq: 2, Link: "bb"}},
		WantThrough: 2,
	}, { // Test 1: Two claims land after the anchor, spanning four hours.
		Claims: []bundle.Claim{
			claim(1, "2026-07-31T10:00:00Z", "aa"),
			claim(2, "2026-07-31T12:00:00Z", "bb"),
			claim(3, "2026-07-31T14:00:00Z", "cc"),
		},
		Anchors:     []bundle.Anchor{{Seq: 1, Link: "aa"}},
		WantThrough: 1,
		WantClaims:  2,
		WantWindow:  "4h0m0s",
	}, { // Test 2: The furthest matching anchor wins when several are present.
		Claims: []bundle.Claim{
			claim(1, "2026-07-31T10:00:00Z", "aa"),
			claim(2, "2026-07-31T11:00:00Z", "bb"),
			claim(3, "2026-07-31T11:30:00Z", "cc"),
		},
		Anchors:     []bundle.Anchor{{Seq: 1, Link: "aa"}, {Seq: 2, Link: "bb"}},
		WantThrough: 2,
		WantClaims:  1,
		WantWindow:  "30m0s",
	}, { // Test 3: An anchor whose link does not match is not counted as coverage.
		Claims:  []bundle.Claim{claim(1, "2026-07-31T10:00:00Z", "aa")},
		Anchors: []bundle.Anchor{{Seq: 1, Link: "wrong"}},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			verified := map[int64]string{}
			for _, c := range test.Claims {
				verified[c.Chain.Seq] = c.Chain.Link
			}
			r := &Report{}
			r.measureUnanchored(&bundle.Bundle{Claims: test.Claims, Anchors: test.Anchors}, verified)
			got := []any{r.AnchoredThroughSeq, r.UnanchoredClaims, r.UnanchoredWindow}
			want := []any{test.WantThrough, test.WantClaims, test.WantWindow}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// swatchSalt returns a deterministic salt for a redactable field in the tests.
func swatchSalt(name string) string { return "swatch-test-salt-" + name }

// swatchDigest computes a LoomSwatch field commitment the way a producer and the verifier both do.
func swatchDigest(t *testing.T, name string, value any) string {
	t.Helper()
	b, err := jcs.Serialize([]any{swatchSalt(name), name, value})
	if err != nil {
		t.Fatalf("serialize disclosure: %v", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// swatchBundle builds and signs a one-claim loomseal-chain-v1 bundle committing title and salary as
// an _sd set, disclosing the named fields.
func swatchBundle(t *testing.T, reveal ...string) []byte {
	t.Helper()
	priv := testKey()
	pub, _ := priv.Public().(ed25519.PublicKey)
	fields := []struct {
		name  string
		value any
	}{{"title", "Engineer"}, {"salary", 185000}}
	revealed := map[string]bool{}
	for _, r := range reveal {
		revealed[r] = true
	}
	var digs []string
	var disc []any
	for _, f := range fields {
		digs = append(digs, swatchDigest(t, f.name, f.value))
		if revealed[f.name] {
			disc = append(disc, map[string]any{"salt": swatchSalt(f.name), "name": f.name, "value": f.value})
		}
	}
	sort.Strings(digs)
	sd := make([]any, len(digs))
	for i, d := range digs {
		sd[i] = d
	}
	// The link is computed over the claim without its chain and disclosures, matching the verifier.
	content := map[string]any{
		"type": "example.person/1", "at": at,
		"payload": map[string]any{"record": "employment", "_sd": sd},
	}
	link, err := chain.LinkV1(nil, "in_1", 1, "", content)
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	content["chain"] = map[string]any{"seq": 1, "prev": "", "link": link}
	if len(disc) > 0 {
		content["disclosures"] = disc
	}
	m := map[string]any{
		"loomseal": "0.1", "bundle_id": "lsb_swatch", "created_at": at,
		"producer": map[string]any{
			"product": "test", "product_version": "1", "install_id": "in_1",
			"public_key": base64Std(pub), "key_id": seal.KeyID(pub),
		},
		"subject": map[string]any{"type": "url", "id": "https://example.com"},
		"chain": map[string]any{
			"profile": "loomseal-chain-v1", "keyed": false,
			"params": map[string]any{"install_id": "in_1"},
			"head":   map[string]any{"seq": 1, "link": link},
		},
		"claims": []any{content},
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

// Test that a holder can withhold a disclosed field after signing without breaking the bundle, which
// is the whole point of selective disclosure: the signature covers the committed _sd set, never the
// disclosures.
func TestRunSwatchWithholdAfterSigning(t *testing.T) {
	t.Parallel()

	// Test 0: Both fields disclosed.
	full := swatchBundle(t, "title", "salary")
	got := Run(full, Options{})
	if !got.OK || got.FieldsRevealed != 2 || got.FieldsRedacted != 0 {
		t.Fatalf("full disclosure: ok %t revealed %d redacted %d problems %v", got.OK,
			got.FieldsRevealed, got.FieldsRedacted, got.Problems)
	}

	// Test 1: The holder withholds salary after signing, without re-signing. It must still verify.
	var doc map[string]any
	if err := json.Unmarshal(full, &doc); err != nil {
		t.Fatal(err)
	}
	claim := doc["claims"].([]any)[0].(map[string]any)
	var kept []any
	for _, d := range claim["disclosures"].([]any) {
		if d.(map[string]any)["name"] != "salary" {
			kept = append(kept, d)
		}
	}
	claim["disclosures"] = kept
	withheld, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	got = Run(withheld, Options{})
	if !got.OK || !got.SignatureOK || got.FieldsRevealed != 1 || got.FieldsRedacted != 1 {
		t.Fatalf("withheld: ok %t signature %t revealed %d redacted %d problems %v", got.OK,
			got.SignatureOK, got.FieldsRevealed, got.FieldsRedacted, got.Problems)
	}

	// Test 2: A disclosed value edited after signing fails the disclosure check while the signature
	// and chain still verify.
	forged := []byte(strings.Replace(string(full), "185000", "1", 1))
	got = Run(forged, Options{})
	if got.OK || !got.SignatureOK || !got.ChainOK {
		t.Fatalf("forged: ok %t signature %t chain %t", got.OK, got.SignatureOK, got.ChainOK)
	}
}

// Test that a counterparty can attach a counter-signature after the producer signed, without
// re-signing, and that the attestation binds the role: changing it after the fact fails.
func TestRunAttestationAfterSigning(t *testing.T) {
	t.Parallel()
	signed := swatchBundle(t) // a signed one-claim loomseal-chain-v1 bundle with a link

	var doc map[string]any
	if err := json.Unmarshal(signed, &doc); err != nil {
		t.Fatal(err)
	}
	claim := doc["claims"].([]any)[0].(map[string]any)
	link := claim["chain"].(map[string]any)["link"].(string)

	cpriv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	cpub, _ := cpriv.Public().(ed25519.PublicKey)
	preimage, err := jcs.Serialize(map[string]any{"loomseal": "attestation/1", "link": link, "role": "counterparty"})
	if err != nil {
		t.Fatal(err)
	}
	sig := ed25519.Sign(cpriv, preimage)
	claim["attestations"] = []any{map[string]any{
		"key_id": seal.KeyID(cpub), "public_key": base64Std(cpub), "alg": "ed25519",
		"role": "counterparty", "sig": base64Std(sig),
	}}

	// Test 0: producer signature untouched, counterparty attestation verifies.
	withAtt, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	got := Run(withAtt, Options{})
	if !got.OK || !got.SignatureOK || got.AttestationsVerified != 1 {
		t.Fatalf("attested: ok %t signature %t verified %d problems %v", got.OK, got.SignatureOK,
			got.AttestationsVerified, got.Problems)
	}

	// Test 1: the role is changed after signing; the attestation no longer verifies, the producer
	// signature still does.
	claim["attestations"].([]any)[0].(map[string]any)["role"] = "auditor"
	forged, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	got = Run(forged, Options{})
	if got.OK || !got.SignatureOK {
		t.Fatalf("forged attestation: ok %t signature %t", got.OK, got.SignatureOK)
	}
}

// TestRunAnchorHeadLinkWrongSeq pins the declared-head anchor gate as a conjunction: an
// anchor carrying the head's link under a different sequence matches nothing and must be
// reported as a problem, not credited to the declared head.
func TestRunAnchorHeadLinkWrongSeq(t *testing.T) {
	t.Parallel()
	invented := strings.Repeat("de", 32)
	signed := signedBundle(t, func(m map[string]any) {
		c, _ := m["chain"].(map[string]any)
		c["head"] = map[string]any{"seq": 99, "link": invented}
		anchors, _ := m["anchors"].([]any)
		first, _ := anchors[0].(map[string]any)
		first["seq"] = 50
		first["link"] = invented
	})
	got := Run(signed, Options{})
	if got.AnchorsMatched != 0 || got.AnchorsToDeclaredHead != 0 {
		t.Errorf("anchor counts: matched %d, to declared head %d, want 0 and 0",
			got.AnchorsMatched, got.AnchorsToDeclaredHead)
	}
	if !problemContains(got, "does not match") {
		t.Errorf("problems %v do not mention the unmatched anchor", got.Problems)
	}
}

// TestRunSwatchIncompleteDisclosure pins the disclosure shape guard: an entry that lost
// its value is reported as incomplete, not folded into the digest comparison where it
// would surface as a misleading mismatch.
func TestRunSwatchIncompleteDisclosure(t *testing.T) {
	t.Parallel()
	full := swatchBundle(t, "title")
	var doc map[string]any
	if err := json.Unmarshal(full, &doc); err != nil {
		t.Fatal(err)
	}
	claim := doc["claims"].([]any)[0].(map[string]any)
	first := claim["disclosures"].([]any)[0].(map[string]any)
	delete(first, "value")
	broken, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	got := Run(broken, Options{})
	if got.OK {
		t.Fatalf("incomplete disclosure verified: %v", got.Problems)
	}
	if !problemContains(got, "incomplete") {
		t.Errorf("problems %v do not name the incomplete disclosure", got.Problems)
	}
}

// TestRunGuardArms pins three guards at the arm my other tests leave open: a counterparty
// key that decodes to the wrong length, a disclosure that lost only its salt, and the
// proofs-validated flag on a bundle whose anchor carries no proof, which must never read
// as validated.
func TestRunGuardArms(t *testing.T) {
	t.Parallel()

	// Test 0: a short counterparty key is a named problem, not a computed key id.
	signed := swatchBundle(t)
	var doc map[string]any
	if err := json.Unmarshal(signed, &doc); err != nil {
		t.Fatal(err)
	}
	claim := doc["claims"].([]any)[0].(map[string]any)
	claim["attestations"] = []any{map[string]any{
		"key_id":     "sha256:" + strings.Repeat("ab", 32),
		"public_key": base64Std(make([]byte, 16)), "alg": "ed25519",
		"role": "counterparty", "sig": base64Std(make([]byte, 64)),
	}}
	raw, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	got := Run(raw, Options{})
	if got.OK || got.AttestationsVerified != 0 {
		t.Errorf("short counterparty key: ok %t verified %d", got.OK, got.AttestationsVerified)
	}
	if !problemContains(got, "32 byte") {
		t.Errorf("problems %v do not name the key size", got.Problems)
	}

	// Test 1: a disclosure that lost only its salt is incomplete on its own.
	full := swatchBundle(t, "title")
	if err := json.Unmarshal(full, &doc); err != nil {
		t.Fatal(err)
	}
	claim = doc["claims"].([]any)[0].(map[string]any)
	first := claim["disclosures"].([]any)[0].(map[string]any)
	first["salt"] = ""
	raw, err = json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	got = Run(raw, Options{})
	if got.OK || !problemContains(got, "incomplete") {
		t.Errorf("saltless disclosure: ok %t problems %v", got.OK, got.Problems)
	}

	// Test 2: an anchor without a proof never reads as proofs validated.
	bare := signedBundle(t, func(m map[string]any) {
		anchors, _ := m["anchors"].([]any)
		first, _ := anchors[0].(map[string]any)
		delete(first, "proof")
	})
	got = Run(bare, Options{})
	if !got.OK {
		t.Fatalf("proofless anchor did not verify: %v", got.Problems)
	}
	if got.AnchorProofsCarried != 0 || got.AnchorProofsValidated {
		t.Errorf("carried %d validated %t, want 0 and false", got.AnchorProofsCarried,
			got.AnchorProofsValidated)
	}
}
