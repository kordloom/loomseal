// Regression tests for three weaknesses an adversarial review found. Each test encodes one: it
// failed on the verifier that had the weakness and passes on the verifier that fixed it, so the
// weakness cannot return unnoticed.
//
// Build the bundles through the real seal primitives or by signing a hand-built document with the
// same CanonicalUnsigned transform the verifier uses, so every input is a document a producer
// could actually emit and sign, not a straw man.
package verify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kordloom/loomseal/internal/bundle"
	"github.com/kordloom/loomseal/internal/bundletest"
	"github.com/kordloom/loomseal/jcs"
)

// rtKey returns a deterministic ed25519 key from one repeated seed byte.
func rtKey(seed byte) (ed25519.PrivateKey, ed25519.PublicKey) {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(s)
	return priv, priv.Public().(ed25519.PublicKey)
}

// rtSign signs the document raw (which must carry "signatures":[]) over the real CanonicalUnsigned
// transform and splices the signature in without reordering any key, so the member order the attack
// relies on survives into the signed bytes.
func rtSign(t *testing.T, raw string, priv ed25519.PrivateKey) []byte {
	t.Helper()
	canon, err := bundle.CanonicalUnsigned([]byte(raw))
	if err != nil {
		t.Fatalf("CanonicalUnsigned: %v", err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	sigs := `[{"key_id":"` + bundle.KeyID(pub) + `","alg":"ed25519","sig":"` +
		base64.StdEncoding.EncodeToString(ed25519.Sign(priv, canon)) + `"}]`
	out := strings.Replace(raw, `"signatures":[]`, `"signatures":`+sigs, 1)
	if !strings.Contains(out, `"sig"`) {
		t.Fatal("signature splice failed; the document must contain \"signatures\":[]")
	}
	return []byte(out)
}

// switchTenderLink recomputes a switchtender-audit-v1 link exactly as the profile defines it:
// SHA-256 over the RFC 8785 canonical object of the committed fields.
func switchTenderLink(seq int64, at, actor, method, path, prev string) string {
	b, err := jcs.Serialize(map[string]any{
		"seq": seq, "at": at, "actor": actor, "method": method, "path": path, "prev": prev,
	})
	if err != nil {
		panic(err)
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// TestRedteamCaseFoldKeysForgeSwitchTenderLink proves a parser differential in the switchtender
// link recompute. The Go verifier recomputes the link from the switchTenderPayload struct, and
// encoding/json resolves a JSON member to a struct field by a case-insensitive match that also
// folds non-ASCII (so "Actor", "ACTOR" and "actor" all land on the Actor field), taking the last
// occurrence. Every other JSON reader, and the Python reference verifier, reads the canonical
// lowercase member.
//
// So a single claim can carry actor/method/path a reader sees (here intruder / DELETE / /api/prod)
// and Actor/Method/Path the Go link recompute hashes (release-token / POST / /api/runs). With the
// link set over the capitalized values, the Go verifier recomputes a match and prints VERIFIED,
// chained (full), over a payload whose visible actor, method and path it never hashed. The Python
// verifier recomputes over the lowercase members and reports "link does not recompute", so the two
// shipped verifiers reach opposite verdicts on the same bytes, which the spec says a deterministic
// format cannot tolerate.
//
// Fix: recompute the link from the raw canonical members (exact keys), as checkV1 and checkMerkle
// already do, rather than from a case-folding struct decode.
func TestRedteamCaseFoldKeysForgeSwitchTenderLink(t *testing.T) {
	priv, pub := rtKey(0x31)
	at := "2026-07-27T15:00:00Z"
	link := switchTenderLink(1, at, "release-token", "POST", "/api/runs", "")
	doc := `{"loomseal":"0.1","bundle_id":"lsb_cf","created_at":"` + at + `",
"producer":{"product":"switchtender","product_version":"1.0.0","install_id":"in_cf",` +
		`"public_key":"` + base64.StdEncoding.EncodeToString(pub) + `","key_id":"` +
		bundle.KeyID(pub) + `"},
"subject":{"type":"run","id":"r1"},
"chain":{"profile":"switchtender-audit-v1","keyed":false,"head":{"seq":1,"link":"` + link + `"}},
"claims":[{"type":"switchtender.audit/1","at":"` + at + `",` +
		`"payload":{"actor":"intruder","method":"DELETE","path":"/api/prod",` +
		`"Actor":"release-token","Method":"POST","Path":"/api/runs"},` +
		`"chain":{"seq":1,"prev":"","link":"` + link + `"}}],
"signatures":[]}`
	signed := rtSign(t, doc, priv)

	// What any ordinary JSON consumer reads from the signed bundle.
	var m map[string]any
	if err := json.Unmarshal(signed, &m); err != nil {
		t.Fatal(err)
	}
	p := m["claims"].([]any)[0].(map[string]any)["payload"].(map[string]any)
	if p["actor"] != "intruder" || p["method"] != "DELETE" || p["path"] != "/api/prod" {
		t.Fatalf("setup: the visible payload is not the attacker's values: %v", p)
	}

	r := Run(signed, Options{Fingerprint: bundle.KeyID(pub)})
	if r.OK {
		t.Errorf("a switchtender claim whose visible actor/method/path are %q/%q/%q verified, because "+
			"the link was recomputed from case-folded duplicate members (Actor/Method/Path) no reader "+
			"sees; the Python reference verifier rejects the same bytes, so the two disagree. level=%q",
			p["actor"], p["method"], p["path"], r.Level)
	}
}

// TestRedteamKeyedChainEarnsProofVerified proves that a keyed loomseal-chain-v1 bundle reaches the
// strongest anchored verdict, "anchored (proof verified)", over a link the verifier never bound to
// the claim content.
//
// A keyed chain is verified structurally only: the verifier checks prev-to-link continuity and
// never recomputes a link, because the chain key is secret. So a producer writes any link beside
// any payload. Here the single claim's link is set to the value a genuine RFC 3161 token in the
// testdata attests, which is the hash of an unrelated switchtender entry, not an HMAC of this
// claim's invented payload. The anchor matches that link by coordinate and the token verifies over
// it, so the verifier awards level 3 "anchored (proof verified)", which the format defines as "an
// anchor with a verified offline proof binds the chain outside the producer". Nothing bound this
// chain outside the producer: the producer chose which anchored link to paste next to a payload the
// verifier cannot check. A holder of a real timestamp token can thus launder it onto a fabricated
// keyed entry and reach the top verdict.
//
// Fix: a keyed (structural-only) chain must not earn the proof-verified anchored level, since the
// verifier never tied the anchored link to the claim it is printed beside.
func TestRedteamKeyedChainEarnsProofVerified(t *testing.T) {
	// anchoredLink is the link the stored freetsa token attests; see testdata/vectors/generate.go.
	const anchoredLink = "4e03f42f52842aa7f4f086d13a210a6856f6a0abadea183e257d3c7554e2211c"
	tokenB64, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "rfc3161-token.b64"))
	if err != nil {
		t.Fatalf("read token fixture: %v", err)
	}
	proof := strings.TrimSpace(string(tokenB64))

	priv, pub := rtKey(0x77)
	doc := `{"loomseal":"0.1","bundle_id":"lsb_launder","created_at":"2026-10-04T00:00:00Z",
"producer":{"product":"switchtender","product_version":"9.9.9","install_id":"in_launder",` +
		`"public_key":"` + base64.StdEncoding.EncodeToString(pub) + `","key_id":"` +
		bundle.KeyID(pub) + `"},
"subject":{"type":"fleet","id":"demo-yard"},
"chain":{"profile":"loomseal-chain-v1","keyed":true,"params":{"install_id":"in_launder"},` +
		`"head":{"seq":1,"link":"` + anchoredLink + `"}},
"claims":[{"type":"switchtender.audit/1","at":"2026-07-01T00:00:00Z",` +
		`"payload":{"actor":"invented","method":"POST","path":"/api/approve-everything"},` +
		`"chain":{"seq":1,"prev":"","link":"` + anchoredLink + `"}}],
"anchors":[{"type":"rfc3161","seq":1,"link":"` + anchoredLink + `","at":"2026-07-27T15:00:00Z",` +
		`"ref":"https://freetsa.org/tsr","proof":"` + proof + `"}],
"signatures":[]}`
	signed := rtSign(t, doc, priv)

	r := Run(signed, Options{Fingerprint: bundle.KeyID(pub)})
	if strings.Contains(r.Level, "anchored (proof verified)") {
		t.Errorf("a keyed (structural-only) chain reached %q; the anchored link %s is the hash of an "+
			"unrelated entry and was never bound to this claim's payload, so the proof-verified "+
			"anchored level is unearned", r.Level, anchoredLink)
	}
}

// TestRedteamPythonMissesAlteredArtifact proves a Go/Python verdict disagreement on evidence. The
// Go verifier gained an ALTERED check (audit finding 1, v1.2.0): an artifact sitting at its
// declared location whose bytes do not hash to the sealed digest fails the bundle. The Python
// reference verifier never received that fix; it only does a content-addressed lookup, so an
// altered artifact is counted as "missing" and the bundle still verifies.
//
// The two implementations are presented as co-equal and cross-checked in CI, so a relying party who
// runs `python3 loomverify.py bundle.json evidence/` is told VERIFIED over a tampered artifact the
// Go CLI rejects. The test skips only when the Python interpreter or its dependency genuinely
// cannot run, so a skip is never mistaken for a pass.
//
// Fix: port the altered-artifact detection (location-aware digest mismatch, within-dir guard) to
// reference/loomverify.py so it fails a bundle whose artifact is present but altered.
func TestRedteamPythonMissesAlteredArtifact(t *testing.T) {
	dir := t.TempDir()
	ev, err := bundletest.Evidence(dir, "artifact.txt", []byte("the real approval, as sealed"))
	if err != nil {
		t.Fatal(err)
	}
	b := bundletest.Builder{Claims: []bundletest.Claim{{Evidence: []map[string]any{ev}}}}
	raw, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	bp := filepath.Join(dir, "bundle.loomseal.json")
	if err := os.WriteFile(bp, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	// Alter the artifact in place at the location the bundle names.
	altered := []byte("TAMPERED approval body")
	if err := os.WriteFile(filepath.Join(dir, "artifact.txt"), altered, 0o600); err != nil {
		t.Fatal(err)
	}

	// The Go verifier must reject it: this is the behavior Python has to match.
	goR := Run(raw, Options{EvidenceDir: dir})
	if goR.OK || goR.EvidenceMismatched == 0 {
		t.Fatalf("setup: the Go verifier did not flag the altered artifact: ok=%v mismatched=%d",
			goR.OK, goR.EvidenceMismatched)
	}

	script := filepath.Join("..", "..", "reference", "loomverify.py")
	out, err := exec.Command("python3", script, bp, dir).CombinedOutput()
	if err != nil && len(out) == 0 {
		t.Skipf("python reference verifier not runnable in this environment: %v", err)
	}
	var pyR map[string]any
	if jerr := json.Unmarshal(out, &pyR); jerr != nil {
		t.Skipf("python reference verifier did not return JSON (missing cryptography dep?): %s",
			strings.TrimSpace(string(out)))
	}
	if ok, _ := pyR["ok"].(bool); ok {
		t.Errorf("the python reference verifier reported VERIFIED over an artifact present at its "+
			"declared location with bytes that do not match the sealed digest; the Go verifier "+
			"rejects the same bundle (ALTERED). evidence=%v", pyR["evidence"])
	}
}
