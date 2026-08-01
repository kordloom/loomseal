//go:build ignore

// Command generate writes the LoomSeal conformance vectors and their manifest. Run it from the
// repository root with `go run testdata/vectors/generate.go`. Every bundle is deterministic: a
// fixed key and fixed timestamps mean the output is byte-for-byte stable across runs, so the
// checked-in vectors change only when the format does. The manifest declares, for each vector,
// whether it must verify and, when it must not, which verification check fails and why. Any
// LoomSeal verifier in any language can drive itself from this manifest.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/kordloom/loomseal/seal"
)

// dir is where the vectors and manifest are written, relative to the repository root.
const dir = "testdata/vectors"

// installID is the fixed producing installation for every vector.
const installID = "in_vectors"

// at is the fixed claim and bundle time for every vector.
const at = "2026-07-27T15:00:00Z"

// atNanos carries sub-microsecond digits, the precision a Linux clock hands a producer and the
// precision no Python or JavaScript time type can hold. It exists so a verifier that parses the
// claim time and re-serializes it, rather than hashing the stored bytes, fails the suite.
const atNanos = "2026-07-27T15:00:00.123456789Z"

// Chain profile names, duplicated here so the generator needs no internal imports.
const (
	profileV1           = "loomseal-chain-v1"
	profileSwitchTender = "switchtender-audit-v1"
)

// manifest is the top-level conformance document.
type manifest struct {
	// Description says what the file is.
	Description string `json:"description"`
	// Vectors are the individual test bundles.
	Vectors []vector `json:"vectors"`
}

// vector is one conformance case.
type vector struct {
	// Name identifies the case.
	Name string `json:"name"`
	// File is the bundle file name within this directory.
	File string `json:"file"`
	// MustVerify is whether a conformant verifier must report the bundle verified.
	MustVerify bool `json:"must_verify"`
	// Level is the expected conformance wording when MustVerify is true.
	Level string `json:"level,omitempty"`
	// FailingCheck names the verification step that must fail when MustVerify is false: one of
	// parse, signature, chain, or anchor.
	FailingCheck string `json:"failing_check,omitempty"`
	// Why explains the case in one sentence.
	Why string `json:"why"`
}

// state carries the signing key and the accumulating manifest.
type state struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	man  manifest
}

func main() {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub, _ := priv.Public().(ed25519.PublicKey)
	s := &state{priv: priv, pub: pub}
	s.man.Description = "LoomSeal v0.1 conformance vectors. Each entry declares whether the " +
		"bundle must verify, and when it must not, which check fails and why. A verifier is " +
		"conformant when it agrees with every entry."

	s.positives()
	s.negatives()

	if err := s.write(); err != nil {
		fmt.Fprintln(os.Stderr, "generate:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %d vectors and manifest to %s\n", len(s.man.Vectors), dir)
}

// positives emits every vector that must verify.
func (s *state) positives() {
	// Signed only, no chain declared.
	m := s.base()
	delete(m["claims"].([]any)[0].(map[string]any), "chain")
	s.add("signed-only", true, "signed", "",
		"A bundle with no chain reaches the signed level and no further.", s.sign(m))

	// Signed and fully chained under the generic unkeyed profile.
	s.add("signed-chained-full", true, "signed, chained (full)", "",
		"An unkeyed loomseal-chain-v1 chain with the head tied to the newest claim.",
		s.sign(s.v1(2, false)))

	// Signed, chained, and anchored by reference on the head that ties to the newest claim.
	m = s.v1(2, false)
	head := m["chain"].(map[string]any)["head"].(map[string]any)
	m["anchors"] = []any{gitAnchor(head["seq"].(int64), head["link"].(string))}
	s.add("signed-chained-anchored", true, "signed, chained (full), anchored by reference", "",
		"An anchor whose coordinates match the verified head earns the anchored level.",
		s.sign(m))

	// Keyed chain verifies structurally only.
	m = s.keyed(2)
	s.add("keyed-structural", true, "signed, chained (structural)", "",
		"A keyed chain verifies as structural: continuity holds, links are not recomputed.",
		s.sign(m))

	// Head ahead of the bundled claims: a window into a longer chain.
	m = s.v1(1, false)
	m["chain"].(map[string]any)["head"] = map[string]any{
		"seq": int64(500), "link": strings.Repeat("ab", 32),
	}
	s.add("windowed-head", true, "signed, chained (full)", "",
		"A head beyond the claims is a window; its link is unverified and it is not anchored.",
		s.sign(m))

	// Anchor that matches only the unverified declared head does not earn the anchored level.
	m = s.v1(1, false)
	m["chain"].(map[string]any)["head"] = map[string]any{
		"seq": int64(500), "link": strings.Repeat("ab", 32),
	}
	m["anchors"] = []any{gitAnchor(500, strings.Repeat("ab", 32))}
	s.add("anchor-only-declared-head", true, "signed, chained (full)", "",
		"An anchor matching only a head beyond the claims is reported but not counted as anchored.",
		s.sign(m))

	// Shipped SwitchTender construction.
	s.add("switchtender-audit", true, "signed, chained (full)", "",
		"The shipped SwitchTender profile recomputes every link.", s.sign(s.switchTender()))

	// Sub-microsecond claim time. A verifier that parses the time into its language's own type and
	// formats it back loses digits wherever that type is not nanosecond-capable, and reports an
	// intact bundle as a broken chain. Hashing the stored bytes is what makes this verify.
	// A real timestamp token over this vector's own link. A verifier that carries proofs without
	// opening them reports this at the weaker "by reference" level and fails the suite.
	s.add("switchtender-audit-anchored-proof", true, "signed, chained (full), anchored (proof verified)", "",
		"An rfc3161 anchor carrying a real timestamp token verifies offline against the link it "+
			"attests to, with no network and no trust in the producer.",
		s.sign(s.switchTenderProof()))

	s.add("switchtender-audit-nanosecond-at", true, "signed, chained (full)", "",
		"A claim time carrying sub-microsecond digits verifies, because the profile hashes the "+
			"stored time bytes rather than parsing and re-serializing them.",
		s.sign(s.switchTenderNanos()))

	// Unknown claim type still verifies and is reported as unknown.
	m = s.v1(1, false)
	claim := m["claims"].([]any)[0].(map[string]any)
	claim["type"] = "acme.widget/1"
	s.relinkV1(m, false)
	s.add("unknown-claim-type", true, "signed, chained (full)", "",
		"A claim type outside the registry verifies and is noted, never failed.", s.sign(m))

	// A well-formed surrogate pair in a string is valid.
	m = s.v1(1, false)
	claim = m["claims"].([]any)[0].(map[string]any)
	claim["payload"].(map[string]any)["note"] = "grin \U0001F600"
	s.relinkV1(m, false)
	s.add("valid-surrogate-pair", true, "signed, chained (full)", "",
		"An astral character encodes as a surrogate pair and verifies.", s.sign(m))

	// Evidence referenced but not supplied is reported, not verified, and does not fail.
	m = s.v1(1, false)
	claim = m["claims"].([]any)[0].(map[string]any)
	claim["evidence"] = []any{map[string]any{
		"role": "snapshot", "digest": "sha256:" + strings.Repeat("cd", 32),
		"media_type": "text/html",
	}}
	s.relinkV1(m, false)
	s.add("evidence-referenced", true, "signed, chained (full)", "",
		"Evidence not supplied to the verifier is referenced, never counted as verified.",
		s.sign(m))
}

// negatives emits every vector that must fail, naming the failing check.
func (s *state) negatives() {
	// Tampered payload breaks the signature.
	signed := s.sign(s.v1(1, false))
	signed = []byte(strings.Replace(string(signed), "/api/runs", "/api/evil", 1))
	s.add("tampered-payload", false, "", "signature",
		"A byte changed after signing fails the producer signature.", signed)

	// Duplicate top-level key is not canonicalizable.
	signed = s.sign(s.v1(1, false))
	signed = []byte(strings.Replace(string(signed), `{"bundle_id"`,
		`{"subject":{"id":"x","type":"url"},"bundle_id"`, 1))
	s.add("duplicate-top-level-key", false, "", "parse",
		"A repeated object key has no canonical form and is rejected.", signed)

	// Lone high surrogate escape.
	signed = s.sign(s.v1(1, false))
	signed = []byte(strings.Replace(string(signed), "release-token", `release\uD800token`, 1))
	s.add("lone-high-surrogate", false, "", "parse",
		"A lone high surrogate escape is invalid and is rejected, not coerced.", signed)

	// Lone low surrogate escape.
	signed = s.sign(s.v1(1, false))
	signed = []byte(strings.Replace(string(signed), "release-token", `release\uDFFFtoken`, 1))
	s.add("lone-low-surrogate", false, "", "parse",
		"A lone low surrogate escape is invalid and is rejected, not coerced.", signed)

	// Raw invalid UTF-8 bytes.
	signed = s.sign(s.v1(1, false))
	signed = []byte(strings.Replace(string(signed), "release-token", "release\xed\xa0\x80token", 1))
	s.add("raw-invalid-utf8", false, "", "parse",
		"Invalid UTF-8 input is rejected, not coerced to the replacement character.", signed)

	// Non-integer number in a payload.
	signed = s.sign(s.v1(1, false))
	signed = []byte(strings.Replace(string(signed), `"path":"/api/runs"`,
		`"path":"/api/runs","ratio":1.5`, 1))
	s.add("non-integer-number", false, "", "parse",
		"A fractional number is outside the integer profile and is rejected.", signed)

	// Number beyond 2^53.
	signed = s.sign(s.v1(1, false))
	signed = []byte(strings.Replace(string(signed), `"path":"/api/runs"`,
		`"path":"/api/runs","big":9007199254740993`, 1))
	s.add("number-exceeds-2p53", false, "", "parse",
		"An integer beyond 2^53 does not round-trip through an IEEE double and is rejected.", signed)

	// Broken chain continuity: second claim's prev does not match the first link.
	m := s.v1(2, false)
	m["claims"].([]any)[1].(map[string]any)["chain"].(map[string]any)["prev"] = strings.Repeat("00", 32)
	s.add("chain-broken-prev", false, "", "chain",
		"A prev link that does not match the prior link breaks continuity.", s.sign(m))

	// Head behind the newest claim.
	m = s.v1(2, false)
	m["chain"].(map[string]any)["head"] = map[string]any{"seq": int64(1),
		"link": strings.Repeat("11", 32)}
	s.add("head-behind-claims", false, "", "chain",
		"A head sequence behind the newest claim is a broken chain.", s.sign(m))

	// Head sequence equals the newest claim but the link differs.
	m = s.v1(2, false)
	m["chain"].(map[string]any)["head"].(map[string]any)["link"] = strings.Repeat("22", 32)
	s.add("head-wrong-link", false, "", "chain",
		"A head at the newest sequence must carry that claim's link.", s.sign(m))

	// Non-contiguous sequence numbers.
	m = s.v1(2, false)
	claims := m["claims"].([]any)
	second := claims[1].(map[string]any)
	second["chain"].(map[string]any)["seq"] = int64(5)
	s.relinkV1(m, false)
	// Restore the gap the relink just closed by forcing a non-following sequence again.
	second["chain"].(map[string]any)["seq"] = int64(5)
	m["chain"].(map[string]any)["head"].(map[string]any)["seq"] = int64(5)
	s.add("noncontiguous-seq", false, "", "chain",
		"Claims must be contiguous in sequence; a gap is a broken chain.", s.sign(m))

	// Anchor matches no claim and no head.
	m = s.v1(1, false)
	m["anchors"] = []any{gitAnchor(999, strings.Repeat("ee", 32))}
	s.add("anchor-matches-nothing", false, "", "anchor",
		"An anchor whose coordinates match nothing in the bundle fails.", s.sign(m))

	// Wrong format version.
	m = s.v1(1, false)
	m["loomseal"] = "0.2"
	s.add("wrong-version", false, "", "parse",
		"A verifier speaks one format version and rejects others.", s.sign(m))

	// Producer key_id does not match the embedded public key.
	m = s.v1(1, false)
	m["producer"].(map[string]any)["key_id"] = "sha256:" + strings.Repeat("00", 32)
	s.add("producer-keyid-mismatch", false, "", "signature",
		"The producer key_id must be the digest of the embedded public key.", s.sign(m))

	// Signature alg rewritten after signing. Emptying signatures before signing leaves alg
	// outside the signed bytes, so this edit costs an attacker nothing and the ed25519
	// signature still checks out. A verifier that picked its algorithm by reading alg would
	// follow the attacker; one that treats alg as a label rejects the bundle.
	s.add("signature-alg-rewritten", false, "", "signature",
		"alg is outside the signed bytes, so a verifier rejects a foreign value rather than "+
			"dispatching on it.", rewriteAlg(s.sign(s.v1(1, false)), "rsa-pss-sha256"))
}

// rewriteAlg edits the first signature entry's alg in an already-signed bundle, the way an
// attacker in the middle would. The signature stays valid because alg is not covered by it.
func rewriteAlg(signed []byte, alg string) []byte {
	var m map[string]any
	if err := json.Unmarshal(signed, &m); err != nil {
		panic(err)
	}
	sigs, ok := m["signatures"].([]any)
	if !ok || len(sigs) == 0 {
		panic("signed bundle carries no signatures")
	}
	first, ok := sigs[0].(map[string]any)
	if !ok {
		panic("signature entry is not an object")
	}
	first["alg"] = alg
	out, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return out
}

// base builds a minimal signed-ready bundle map with one generic claim and no chain.
func (s *state) base() map[string]any {
	return map[string]any{
		"loomseal":   "0.1",
		"bundle_id":  "lsb_vectors",
		"created_at": at,
		"producer": map[string]any{
			"product":         "vectors",
			"product_version": "0.1.0",
			"install_id":      installID,
			"public_key":      base64.StdEncoding.EncodeToString(s.pub),
			"key_id":          seal.KeyID(s.pub),
		},
		"subject": map[string]any{"type": "fleet", "id": "demo-yard"},
		"claims": []any{map[string]any{
			"type": "switchtender.audit/1", "at": at,
			"payload": map[string]any{"actor": "release-token", "method": "POST", "path": "/api/runs"},
		}},
		"signatures": []any{},
	}
}

// v1 builds an unkeyed or keyed-flag loomseal-chain-v1 bundle with n contiguous claims.
func (s *state) v1(n int, keyed bool) map[string]any {
	m := s.base()
	claims := make([]any, n)
	for i := 0; i < n; i++ {
		c := map[string]any{
			"type": "switchtender.audit/1", "at": at,
			"payload": map[string]any{"actor": "release-token", "method": "POST", "path": "/api/runs"},
		}
		claims[i] = c
	}
	m["claims"] = claims
	s.relinkV1(m, keyed)
	return m
}

// relinkV1 recomputes every loomseal-chain-v1 link and the head for the bundle's claims.
func (s *state) relinkV1(m map[string]any, keyed bool) {
	claims := m["claims"].([]any)
	prev := ""
	var lastLink string
	var lastSeq int64
	for i, c := range claims {
		claim := c.(map[string]any)
		seq := int64(i + 1)
		if existing, ok := claim["chain"].(map[string]any); ok {
			if sq, ok := existing["seq"].(int64); ok {
				seq = sq
			}
		}
		link, err := seal.LinkV1(nil, installID, seq, prev, stripChain(claim))
		if err != nil {
			panic(err)
		}
		claim["chain"] = map[string]any{"seq": seq, "prev": prev, "link": link}
		prev = link
		lastLink = link
		lastSeq = seq
	}
	m["chain"] = map[string]any{
		"profile": profileV1, "keyed": keyed,
		"params": map[string]any{"install_id": installID},
		"head":   map[string]any{"seq": lastSeq, "link": lastLink},
	}
}

// keyed builds a keyed loomseal-chain-v1 bundle whose links thread but are not recomputable.
func (s *state) keyed(n int) map[string]any {
	m := s.v1(n, true)
	claims := m["claims"].([]any)
	prev := ""
	var lastLink string
	var lastSeq int64
	for i, c := range claims {
		claim := c.(map[string]any)
		seq := int64(i + 1)
		link := strings.Repeat(fmt.Sprintf("%02x", i+1), 32)
		claim["chain"] = map[string]any{"seq": seq, "prev": prev, "link": link}
		prev = link
		lastLink = link
		lastSeq = seq
	}
	m["chain"] = map[string]any{
		"profile": profileV1, "keyed": true,
		"params": map[string]any{"install_id": installID},
		"head":   map[string]any{"seq": lastSeq, "link": lastLink},
	}
	return m
}

// switchTender builds a shipped SwitchTender chain with one recomputable link.
func (s *state) switchTender() map[string]any {
	m := s.base()
	link := switchTenderLink(1, at, "release-token", "POST", "/api/runs", "")
	claim := m["claims"].([]any)[0].(map[string]any)
	claim["chain"] = map[string]any{"seq": int64(1), "prev": "", "link": link}
	m["chain"] = map[string]any{
		"profile": profileSwitchTender, "keyed": false,
		"head": map[string]any{"seq": int64(1), "link": link},
	}
	return m
}

// anchoredLink is the link a real RFC 3161 token in testdata attests to. A timestamp is signed over
// a specific value, so the vector is built around the token rather than the other way round.
const anchoredLink = "77c95e0459eef7970de647dfd263004d23b2c9a44b7feb10a24940bd695a05d3"

// switchTenderProof builds a bundle anchored by a real timestamp token, so a verifier that carries
// proofs without opening them fails the suite.
func (s *state) switchTenderProof() map[string]any {
	m := s.base()
	claim := m["claims"].([]any)[0].(map[string]any)
	link := switchTenderLink(1, at, "release-token", "POST", "/api/runs", "")
	if link != anchoredLink {
		panic("the timestamp fixture no longer matches this vector's link: " + link)
	}
	claim["chain"] = map[string]any{"seq": int64(1), "prev": "", "link": link}
	m["chain"] = map[string]any{
		"profile": profileSwitchTender, "keyed": false,
		"head": map[string]any{"seq": int64(1), "link": link},
	}
	raw, err := os.ReadFile(filepath.Join("testdata", "vectors", "rfc3161-token.b64"))
	if err != nil {
		panic(err)
	}
	m["anchors"] = []any{map[string]any{
		"type": "rfc3161", "seq": int64(1), "link": link,
		"at": at, "ref": "https://freetsa.org/tsr", "proof": strings.TrimSpace(string(raw)),
	}}
	return m
}

// switchTenderNanos builds the shipped SwitchTender chain with a sub-microsecond claim time.
func (s *state) switchTenderNanos() map[string]any {
	m := s.base()
	claim := m["claims"].([]any)[0].(map[string]any)
	claim["at"] = atNanos
	link := switchTenderLink(1, atNanos, "release-token", "POST", "/api/runs", "")
	claim["chain"] = map[string]any{"seq": int64(1), "prev": "", "link": link}
	m["chain"] = map[string]any{
		"profile": profileSwitchTender, "keyed": false,
		"head": map[string]any{"seq": int64(1), "link": link},
	}
	return m
}

// stripChain returns a copy of the claim without its chain member, as the v1 link digest wants.
func stripChain(claim map[string]any) map[string]any {
	out := make(map[string]any, len(claim))
	for k, v := range claim {
		if k == "chain" {
			continue
		}
		out[k] = v
	}
	return out
}

// switchTenderLink recomputes a switchtender-audit-v1 link.
func switchTenderLink(seq int64, atStr, actor, method, path, prev string) string {
	fields := []string{strconv.FormatInt(seq, 10), atStr, actor, method, path, prev}
	b, err := json.Marshal(fields)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// parseUnixNano converts an RFC 3339 time to Unix nanoseconds.
func parseUnixNano(sVal string) int64 {
	tv, err := time.Parse(time.RFC3339Nano, sVal)
	if err != nil {
		panic(err)
	}
	return tv.UnixNano()
}

// gitAnchor builds a git anchor record at the given coordinates.
func gitAnchor(seq int64, link string) map[string]any {
	return map[string]any{
		"type": "git", "seq": seq, "link": link, "at": "2026-07-01T00:00:00Z",
		"ref": "https://github.com/example/anchors/commit/abc123",
	}
}

// sign marshals and signs a bundle map, returning the signed document bytes.
func (s *state) sign(m map[string]any) []byte {
	raw, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	out, err := seal.SignBundle(raw, s.priv)
	if err != nil {
		panic(err)
	}
	return out
}

// add records one vector and writes its bundle file.
func (s *state) add(name string, mustVerify bool, level, failing, why string, data []byte) {
	file := name + ".loomseal.json"
	if err := os.WriteFile(filepath.Join(dir, file), data, 0o600); err != nil {
		panic(err)
	}
	s.man.Vectors = append(s.man.Vectors, vector{
		Name: name, File: file, MustVerify: mustVerify, Level: level,
		FailingCheck: failing, Why: why,
	})
}

// write emits the manifest, with vectors sorted by name for a stable diff.
func (s *state) write() error {
	sort.Slice(s.man.Vectors, func(i, j int) bool {
		return s.man.Vectors[i].Name < s.man.Vectors[j].Name
	})
	out, err := json.MarshalIndent(s.man, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return os.WriteFile(filepath.Join(dir, "manifest.json"), out, 0o600)
}
