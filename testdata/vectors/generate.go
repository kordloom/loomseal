//go:build ignore

// Command generate writes the LoomSeal conformance vectors and their manifest. Run it from the
// repository root with `go run testdata/vectors/generate.go`. Every bundle is deterministic: a
// fixed key and fixed timestamps mean the output is byte-for-byte stable across runs, so the
// checked-in vectors change only when the format does. The manifest declares, for each vector,
// whether it must verify and, when it must not, which verification check fails and why. Any
// LoomSeal verifier in any language can drive itself from this manifest.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/kordloom/loomseal/internal/bundle"
	"github.com/kordloom/loomseal/jcs"
	"github.com/kordloom/loomseal/merkle"
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
	// parse, signature, chain, anchor, span, disclosure, attestation, install, record, or
	// unsupported.
	FailingCheck string `json:"failing_check,omitempty"`
	// Why explains the case in one sentence.
	Why string `json:"why"`
	// Unchecked lists, as "claim N member", every member a switchtender-audit-v1 link does not commit
	// that a verifier must report unchecked in a bundle that must verify. Empty means none may be.
	Unchecked []string `json:"unchecked,omitempty"`
	// Redacted lists, the same way, every such member a verifier must report redacted.
	Redacted []string `json:"redacted,omitempty"`
	// Legacy lists, the same way, every record body a verifier must report verified under the
	// legacy unkeyed digest form. Empty means none may be.
	Legacy []string `json:"legacy,omitempty"`
}

// presentationManifest is the conformance document for holder presentations.
type presentationManifest struct {
	// Description says what the file is.
	Description string `json:"description"`
	// Vectors are the individual presentation cases.
	Vectors []presentationVector `json:"vectors"`
}

// presentationVector is one presentation conformance case. Audience and nonce are the caller's
// expectations, so the same file can appear more than once under different pins.
type presentationVector struct {
	// Name identifies the case.
	Name string `json:"name"`
	// File is the presentation file name within this directory.
	File string `json:"file"`
	// ExpectAudience is the audience the verifier is told to require, empty to skip the pin.
	ExpectAudience string `json:"expect_audience,omitempty"`
	// ExpectNonce is the challenge the verifier is told to require, empty to skip the pin.
	ExpectNonce string `json:"expect_nonce,omitempty"`
	// MustVerify is whether a conformant verifier must report the presentation verified.
	MustVerify bool `json:"must_verify"`
	// Why explains the case in one sentence.
	Why string `json:"why"`
}

// state carries the signing key and the accumulating manifests.
type state struct {
	priv    ed25519.PrivateKey
	pub     ed25519.PublicKey
	man     manifest
	presMan presentationManifest
}

// holderKey returns the deterministic ed25519 key that signs presentation vectors, distinct from the
// producer and counterparty keys.
func holderKey() (ed25519.PrivateKey, ed25519.PublicKey) {
	priv := ed25519.NewKeyFromSeed(bytesRepeat(11))
	pub, _ := priv.Public().(ed25519.PublicKey)
	return priv, pub
}

// bytesRepeat returns a 32-byte seed of one repeated value.
func bytesRepeat(b byte) []byte {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = b
	}
	return seed
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
	s.merkleNegatives()
	s.spans()
	s.records()
	s.tampers()
	s.hardening()
	s.presentations()

	if err := s.write(); err != nil {
		fmt.Fprintln(os.Stderr, "generate:", err)
		os.Exit(1)
	}
	if err := s.writePresentations(); err != nil {
		fmt.Fprintln(os.Stderr, "generate:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %d vectors, %d presentations, and manifests to %s\n",
		len(s.man.Vectors), len(s.presMan.Vectors), dir)
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

	// Shipped SwitchTender construction bound to the producer install. The install id is carried in
	// the claim payload and folded into the link, so the link cannot be lifted into another install's
	// bundle without breaking any third-party anchor over it.
	s.add("switchtender-audit-bound-install", true, "signed, chained (full)", "",
		"A switchtender-audit-v1 entry that carries install_id folds it into its link and binds the "+
			"entry to the producer, which an entry omitting it does not.",
		s.sign(s.switchTenderBound()))

	// The shape SwitchTender ships today: chain.params.install_id stamped, entries not yet folding
	// the id. The param is inert metadata to this profile, so the entries are pre-binding and hash
	// as they always did, and adopting per-entry binding invalidates no receipt already published.
	m = s.switchTender()
	m["chain"].(map[string]any)["params"] = map[string]any{"install_id": installID}
	s.add("switchtender-params-only", true, "signed, chained (full)", "",
		"A switchtender-audit-v1 chain that stamps chain.params.install_id without folding it into "+
			"its links verifies as pre-binding: the param is not part of this profile's link, so a "+
			"producer adopting per-entry binding keeps every receipt it already published.", s.sign(m))

	// A real timestamp token on a declared head that leads the claims. The proof is valid but attests
	// a link tied to no bundled claim, so a verifier reports it and awards no anchored level.
	s.add("anchor-declared-head-proof", true, "signed, chained (full)", "",
		"An rfc3161 proof on a declared head beyond the bundled claims is not opened and earns no "+
			"anchored level, because the link it attests is tied to nothing the verifier confirmed.",
		s.sign(s.switchTenderDeclaredHeadProof()))

	// Sub-microsecond claim time. A verifier that parses the time into its language's own type and
	// formats it back loses digits wherever that type is not nanosecond-capable, and reports an
	// intact bundle as a broken chain. Hashing the stored bytes is what makes this verify.
	// A real timestamp token over this vector's own link. A verifier that carries proofs without
	// opening them reports this at the weaker "by reference" level and fails the suite.
	s.add("switchtender-audit-anchored-proof", true, "signed, chained (full), anchored (proof verified)", "",
		"An rfc3161 anchor carrying a real timestamp token verifies offline against the link it "+
			"attests to, with no network and no trust in the producer.",
		s.sign(s.switchTenderProof()))

	// The tree profile. Sparse disclosure is the property no linear profile has: these bundles carry
	// a subset of a longer log's leaves, which the contiguity rule would otherwise refuse.
	s.add("merkle-sparse", true, "signed, chained (tree of 6)", "",
		"A tree bundle disclosing two non-contiguous leaves of a six leaf log verifies, because each "+
			"one folds through its audit path to the root the signed head names.",
		s.sign(s.merkleBundle(6, []int{1, 4}, 0)))

	s.add("merkle-single-leaf", true, "signed, chained (tree of 1)", "",
		"A log of one leaf verifies with an empty audit path, which is the correct and only path at "+
			"that size.",
		s.sign(s.merkleBundle(1, []int{0}, 0)))

	s.add("merkle-right-edge", true, "signed, chained (tree of 9)", "",
		"A leaf on the right edge of a nine leaf log verifies, where the tree is least regular and a "+
			"fold that mishandles the odd node fails.",
		s.sign(s.merkleBundle(9, []int{6}, 0)))

	s.add("merkle-consistency", true, "signed, chained (tree of 6, append-only from 4)", "",
		"A consistency proof from an earlier root verifies, proving the log grew by appending only, "+
			"which a hash chain cannot state on its own.",
		s.sign(s.merkleBundle(6, []int{0, 5}, 4)))

	// An anchor on the root a verified consistency proof starts from. Both verifiers must match it:
	// the reference verifier once refused it as matching nothing while the Go verifier accepted it,
	// and no vector carried the shape, so the disagreement surfaced only on a producer's receipt.
	m = s.merkleBundle(6, []int{0, 5}, 4)
	cons := m["chain"].(map[string]any)["consistency"].(map[string]any)
	m["anchors"] = []any{gitAnchor(4, cons["from_root"].(string))}
	s.add("merkle-anchor-on-consistency-root", true,
		"signed, chained (tree of 6, append-only from 4), anchored by reference", "",
		"An anchor on the root a verified consistency proof starts from matches, because the proof "+
			"shows the log grew from exactly the root the anchor fixed.", s.sign(m))

	s.add("merkle-consistency-power-of-two", true, "signed, chained (tree of 9, append-only from 8)", "",
		"A consistency proof whose earlier size is a power of two verifies. That case seeds the old "+
			"root rather than reading it from the proof, and an implementation that expects it in the "+
			"proof rejects a valid bundle.",
		s.sign(s.merkleBundle(9, []int{2}, 8)))

	s.add("switchtender-audit-json-escapes", true, "signed, chained (full)", "",
		"A recorded path carrying &, <, > and U+2028 verifies, because the profile serializes with "+
			"RFC 8785 rather than an encoder that escapes those characters for HTML.",
		s.sign(s.switchTenderEscapes()))

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

	// LoomSwatch selective disclosure: two of three redactable fields revealed, one withheld. The
	// link commits the _sd set, so the withheld field stays committed and the record verifies.
	s.add("swatch-selective", true, "signed, chained (full)", "",
		"A loomseal-chain-v1 claim commits three redactable fields as an _sd set and discloses two; "+
			"each disclosure hashes to a committed digest and the withheld field stays sealed.",
		s.sign(s.swatchBundle("title", "start_date")))

	// LoomSwatch with every field withheld still verifies: the committed _sd set stands alone.
	s.add("swatch-fully-redacted", true, "signed, chained (full)", "",
		"A claim that discloses none of its redactable fields still verifies; the _sd set is "+
			"committed by the link and nothing is revealed.",
		s.sign(s.swatchBundle()))

	// A claim counter-signed by a second party. The attestation signs the claim's link and role, and
	// verifies against the counterparty key, turning a self-asserted claim into a two-party one.
	s.add("attested-claim", true, "signed, chained (full)", "",
		"A loomseal-chain-v1 claim carrying a counterparty attestation over its link verifies; the "+
			"counter-signature is checked against the signer's own key and reported as vouched.",
		s.sign(s.attestedBundle()))

	// An attestation carrying its signing time: the time is inside the signed bytes, which is
	// what lets an external approver's sign-off say when it happened, tamper-evidently.
	m = s.v1(1, false)
	tc := m["claims"].([]any)[0].(map[string]any)
	tPriv, tPub := counterpartyKey()
	tc["attestations"] = []any{attestationAt(tPriv, tPub,
		tc["chain"].(map[string]any)["link"].(string), "approver", "2026-08-30T12:00:00Z")}
	s.add("attestation-with-time", true, "signed, chained (full)", "",
		"An attestation whose at member is set carries the signing time inside the signed bytes; "+
			"altering the time after the fact breaks the counter-signature.", s.sign(m))

	// A witness countersigns the chain head after the producer signed: the exact artifact a
	// hosted witness mints and the custody record re-anchoring needs, living inside the format.
	s.add("head-attested", true, "signed, chained (full)", "",
		"A head-level attestation added after signing verifies over the chain head and is "+
			"reported as vouching for it; the producer signature is untouched because the "+
			"member is stripped from its preimage.",
		mutateSigned(s.sign(s.v1(2, false)), func(m map[string]any) {
			hPriv, hPub := counterpartyKey()
			head := m["chain"].(map[string]any)["head"].(map[string]any)
			m["attestations"] = []any{headAttestation(hPriv, hPub,
				head["link"].(string), head["seq"], "witness", "2026-08-30T12:00:00Z")}
		}))
	// Evidence packaging never enters the commitment: the same claim with present and location
	// toggled after signing still recomputes its link, in both hashing profiles.
	m = s.v1(1, false)
	claim = m["claims"].([]any)[0].(map[string]any)
	claim["evidence"] = []any{map[string]any{
		"role": "snapshot", "digest": "sha256:" + strings.Repeat("cd", 32),
		"media_type": "text/html", "present": true, "location": "evidence/snap.html",
	}}
	s.relinkV1(m, false)
	s.add("chain-v1-evidence-packaging", true, "signed, chained (full)", "",
		"An evidence entry's present and location are packaging details outside the committed "+
			"content, so a chain-v1 link recomputes whatever way this copy packages its evidence.",
		s.sign(m))

	// The same property in the tree profile. The comment above says packaging stays outside the
	// commitment "in both hashing profiles", and until now only one of them had a vector proving it,
	// so a mirror could allowlist the three members every other merkle vector happens to carry and
	// still pass the whole corpus.
	s.add("merkle-evidence-packaging", true, "signed, chained (tree of 4)", "",
		"An evidence entry's present and location are packaging details outside the committed "+
			"content, so a merkle leaf recomputes whatever way this copy packages its evidence. "+
			"Every other member of the entry, the digest included, is inside the leaf.",
		s.sign(s.merkleBundleShaped(4, []int{1}, 0, func(log []map[string]any) {
			log[1]["evidence"] = []any{map[string]any{
				"role": "snapshot", "digest": "sha256:" + strings.Repeat("cd", 32),
				"media_type": "text/html", "present": true, "location": "evidence/snap.html",
			}}
		})))

	s.add("head-attestation-role-swapped", false, "", "attestation",
		"A head attestation whose role is rewritten after signing fails, because the role sits "+
			"inside the signed preimage.",
		mutateSigned(s.sign(s.v1(2, false)), func(m map[string]any) {
			hPriv, hPub := counterpartyKey()
			head := m["chain"].(map[string]any)["head"].(map[string]any)
			att := headAttestation(hPriv, hPub, head["link"].(string), head["seq"],
				"witness", "")
			att["role"] = "auditor"
			m["attestations"] = []any{att}
		}))

	// Selective disclosure and counterparty attestation compose on one claim: each is an independent
	// member outside the link, so a redactable, counter-signed claim verifies.
	m = s.swatchBundle("title")
	sc := m["claims"].([]any)[0].(map[string]any)
	scPriv, scPub := counterpartyKey()
	sc["attestations"] = []any{attestation(scPriv, scPub,
		sc["chain"].(map[string]any)["link"].(string), "counterparty")}
	s.add("swatch-attested", true, "signed, chained (full)", "",
		"A claim that is both selectively disclosable and counter-signed verifies, since disclosures "+
			"and attestations are independent members outside the link.", s.sign(m))

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

	// A loomseal-chain-v1 chain whose params.install_id is not the producer's. The link commits to
	// the id, so a copier restating the producer block cannot make it match without breaking the link.
	// The Go verifier enforced this; the reference verifier did not, so the two disagreed here until
	// this vector locked it. It is the linear equivalent of merkle-foreign-install.
	m = s.v1(1, false)
	m["chain"].(map[string]any)["params"].(map[string]any)["install_id"] = "in_someone_else"
	s.add("foreign-install-linear", false, "", "chain",
		"A loomseal-chain-v1 chain whose params.install_id is not the producer's is refused, which is "+
			"what stops one install from restating another's producer block over its links.", s.sign(m))

	// A bound SwitchTender entry re-signed under a different producer install, the receipt-lifting
	// shape. The folded install_id no longer matches the producer, and a copier who instead rewrites
	// the payload id to match breaks the link, so the lift is caught either way.
	m = s.switchTenderBound()
	m["producer"].(map[string]any)["install_id"] = "in_someone_else"
	s.add("switchtender-foreign-install", false, "", "chain",
		"A bound switchtender-audit-v1 entry whose folded install_id is not the producer's is refused, "+
			"which is what stops a published receipt from being lifted into another install's bundle.",
		s.sign(m))

	// chain.params.install_id set to something other than the producer. It is informational in this
	// profile, so a disagreeing param is refused rather than silently ignored, closing the trap where
	// a third-party producer sets it and assumes it binds anything.
	m = s.switchTender()
	m["chain"].(map[string]any)["params"] = map[string]any{"install_id": "in_someone_else"}
	s.add("switchtender-params-disagrees", false, "", "chain",
		"A switchtender-audit-v1 chain.params.install_id that is not the producer's is refused: the "+
			"param is informational and the per-claim install_id is what binds.", s.sign(m))

	// Install ids minted from a key. The switchtender profile mints an install id from the install's
	// first key, so the signing key and the id it names match by construction. A different key
	// presenting a minted id is a rotation or another install's history re-signed, which the bundle
	// alone cannot tell apart, so it is refused until the relying party pairs the key with the install.
	other := ed25519.NewKeyFromSeed(bytesRepeat(21)).Public().(ed25519.PublicKey)
	s.add("switchtender-install-minted-from-producer-key", true, "", "",
		"A switchtender-audit-v1 install id minted from the producer's own key verifies unpinned.",
		s.sign(s.switchTenderBoundAs(mintedInstallID(s.pub))))
	s.add("switchtender-install-legacy-from-producer-key", true, "", "",
		"A switchtender-audit-v1 install id in the legacy form, the producer key's first six bytes, "+
			"verifies unpinned.", s.sign(s.switchTenderBoundAs(legacyInstallID(s.pub))))
	s.add("switchtender-install-minted-from-another-key", false, "", "install",
		"A switchtender-audit-v1 install id minted from another key is refused: it is a key rotation "+
			"or another install's history re-signed, and only the relying party can accept a rotation, "+
			"by pinning the key and naming the install.", s.sign(s.switchTenderBoundAs(mintedInstallID(other))))
	s.add("switchtender-install-legacy-from-another-key", false, "", "install",
		"A switchtender-audit-v1 install id in the legacy form minted from another key is refused for "+
			"the same reason.", s.sign(s.switchTenderBoundAs(legacyInstallID(other))))

	// A window that opens past sequence one with no prev link. Its first claim recomputes as though
	// it were genesis, so only the window-genesis rule catches that it names no predecessor.
	m = s.v1(1, false)
	m["claims"].([]any)[0].(map[string]any)["chain"].(map[string]any)["seq"] = int64(5)
	s.relinkV1(m, false)
	s.add("window-open-no-prev", false, "", "chain",
		"A linear window opening at seq 5 with an empty prev is refused: a slice of a longer chain "+
			"must link to the entry before it, or it is claiming to be unrooted at an arbitrary point.",
		s.sign(m))

	// A disclosed value edited after signing. Disclosures sit outside the link and the signature, so
	// the chain still verifies and the signature still checks; only the disclosure hash catches it.
	forged := s.sign(s.swatchBundle("title", "salary"))
	forged = []byte(strings.Replace(string(forged), `"value":185000`, `"value":1`, 1))
	s.add("swatch-forged-value", false, "", "disclosure",
		"A disclosed field whose value was changed after signing no longer hashes to its committed "+
			"digest, so selective disclosure fails while the signature and chain still verify.", forged)

	// A disclosure for a field the producer never committed. It matches no digest in the _sd set.
	m = s.swatchBundle("title")
	claim := m["claims"].([]any)[0].(map[string]any)
	claim["disclosures"] = append(claim["disclosures"].([]any), map[string]any{
		"salt": "loomseal-vector-salt-ghost", "name": "clearance", "value": "top-secret",
	})
	s.add("swatch-foreign-disclosure", false, "", "disclosure",
		"A disclosure for a field absent from the committed _sd set matches no digest and fails, so a "+
			"holder cannot invent a field the producer never committed.", s.sign(m))

	// An _sd set on a switchtender-audit-v1 chain, whose fixed-field link does not commit it. Refused
	// rather than checked into a false sense of binding.
	m = s.switchTender()
	claim = m["claims"].([]any)[0].(map[string]any)
	claim["payload"].(map[string]any)["_sd"] = []any{swatchDigest("loomseal-vector-salt-x", "x", "y")}
	s.add("swatch-wrong-profile", false, "", "disclosure",
		"Selective disclosure on switchtender-audit-v1 is refused, because that profile's fixed-field "+
			"link does not commit the _sd set.", s.sign(m))

	// An attestation whose role was changed after it was signed. The signature covers the link and
	// role, so a changed role no longer verifies, while the producer signature is untouched.
	m = s.attestedBundle()
	m["claims"].([]any)[0].(map[string]any)["attestations"].([]any)[0].(map[string]any)["role"] = "auditor"
	s.add("attestation-role-swapped", false, "", "attestation",
		"A counterparty attestation whose role was changed after signing no longer verifies, because "+
			"the counter-signature binds the role as well as the link.", s.sign(m))

	// An attestation whose key_id does not match its own public key. It cannot be trusted to name its
	// signer and is refused.
	m = s.attestedBundle()
	m["claims"].([]any)[0].(map[string]any)["attestations"].([]any)[0].(map[string]any)["key_id"] =
		"sha256:" + strings.Repeat("00", 32)
	s.add("attestation-keyid-mismatch", false, "", "attestation",
		"A counterparty attestation whose key_id is not the digest of its public key is refused, so "+
			"it cannot misname its signer.", s.sign(m))

	// Wrong format version.
	m = s.v1(1, false)
	m["loomseal"] = "0.2"
	s.add("wrong-version", false, "", "unsupported",
		"A loomseal version this verifier does not implement is refused as unsupported without "+
			"judging the signature. Fail closed, but never worded as a verification failure.", s.sign(m))

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

	// Strict parsing pinned from every side: nothing unspecified rides inside an accepted
	// bundle, and the surfaces outside the signed bytes are exactly where member strictness is
	// the only guard.
	s.add("unknown-envelope-member", false, "", "parse",
		"A bundle member the schema does not define fails at parse. Strict rejection of the "+
			"unknown is the design: nothing unspecified rides inside an accepted bundle.",
		mutateSigned(s.sign(s.v1(1, false)), func(m map[string]any) {
			m["extra"] = true
		}))
	s.add("unknown-claim-member", false, "", "parse",
		"A claim member the schema does not define fails at parse, before the signature is "+
			"examined.",
		mutateSigned(s.sign(s.v1(1, false)), func(m map[string]any) {
			m["claims"].([]any)[0].(map[string]any)["extra"] = "x"
		}))
	s.add("signature-unknown-member", false, "", "parse",
		"An unknown member inside a signature object fails at parse. Signature objects sit "+
			"outside the signed bytes, so member strictness is the only thing keeping unsigned "+
			"data out of them.",
		mutateSigned(s.sign(s.v1(1, false)), func(m map[string]any) {
			m["signatures"].([]any)[0].(map[string]any)["note"] = "rider"
		}))
	s.add("signature-foreign-keyid", false, "", "signature",
		"A signatures entry naming a key the producer block does not hold fails the bundle. The "+
			"array sits outside the signed bytes, so a foreign entry is a rider nothing vouches "+
			"for, and it must not travel inside a green verdict.",
		mutateSigned(s.sign(s.v1(1, false)), func(m map[string]any) {
			m["signatures"] = append(m["signatures"].([]any), map[string]any{
				"key_id": "sha256:" + strings.Repeat("ab", 32), "alg": "ed25519",
				"sig": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 64)),
			})
		}))
	// The format requires at least one producer entry to verify, not the first. These three pin
	// the order independence a verifier owes that rule. The Go verifier once checked entry zero
	// alone, so a genuine signature sitting second was refused while the Python reference accepted
	// it, and the two shipped verifiers reached opposite verdicts on the same bytes.
	garbageProducerEntry := func(m map[string]any) map[string]any {
		return map[string]any{
			"key_id": m["producer"].(map[string]any)["key_id"], "alg": "ed25519",
			"sig": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 64)),
		}
	}
	s.add("signature-second-entry-verifies", true, "signed, chained (full)", "",
		"A bundle whose first producer entry does not verify and whose second does is verified: "+
			"the rule is that at least one producer entry verifies, in any position.",
		mutateSigned(s.sign(s.v1(2, false)), func(m map[string]any) {
			m["signatures"] = append([]any{garbageProducerEntry(m)}, m["signatures"].([]any)...)
		}))
	s.add("signature-first-entry-verifies", true, "signed, chained (full)", "",
		"A bundle whose first producer entry verifies and whose second does not is verified, "+
			"since the entry behind the genuine one names the producer key and rides no foreign key.",
		mutateSigned(s.sign(s.v1(2, false)), func(m map[string]any) {
			m["signatures"] = append(m["signatures"].([]any), garbageProducerEntry(m))
		}))
	s.add("signature-no-entry-verifies", false, "", "signature",
		"A bundle carrying two producer entries, neither of which verifies, fails at the "+
			"signature step: more entries earn nothing unless one of them is genuine.",
		mutateSigned(s.sign(s.v1(2, false)), func(m map[string]any) {
			m["signatures"] = []any{garbageProducerEntry(m), garbageProducerEntry(m)}
		}))
	// A token that does not parse is a failed anchor, not a missing one: the bundle carried a
	// proof and the proof is garbage, which must never read the same as carrying no proof at all.
	m = s.switchTenderProof()
	anch := m["anchors"].([]any)[0].(map[string]any)
	tok, err := base64.StdEncoding.DecodeString(anch["proof"].(string))
	if err != nil {
		panic(err)
	}
	tok[len(tok)/2] ^= 0xFF
	anch["proof"] = base64.StdEncoding.EncodeToString(tok)
	s.add("anchor-corrupt-token", false, "", "anchor",
		"An rfc3161 proof that does not open as a timestamp token fails the anchor check: a "+
			"carried proof that is garbage must never grade the same as no proof.", s.sign(m))

	s.add("unknown-chain-profile", false, "", "unsupported",
		"A chain profile this verifier does not implement is refused as unsupported, a "+
			"fail-closed verdict distinct from verification failure, so a legitimate newer "+
			"bundle never reads as forged.",
		mutateSigned(s.sign(s.v1(1, false)), func(m map[string]any) {
			m["chain"].(map[string]any)["profile"] = "acme-chain-v9"
		}))

	// The one positive in this block: an unknown subject type is vocabulary, not structure. The
	// bundle verifies and the type is reported, which is what lets a Governed evidence pack name
	// a subject this release never heard of.
	subj := s.v1(1, false)
	subj["subject"] = map[string]any{"type": "control", "id": "CC8.1"}
	s.add("subject-unknown-type", true, "signed, chained (full)", "",
		"A subject type outside the known vocabulary is reported and never failed: subject "+
			"types are informational, and a frozen verifier must not call a newer producer's "+
			"subject a schema error.", s.sign(subj))
}

// mutateSigned applies fn to the decoded signed document and re-marshals it, for vectors that
// exercise post-signing tampering and strictness. Go's json.Marshal orders keys, so the output
// is deterministic.
func mutateSigned(signed []byte, fn func(map[string]any)) []byte {
	var m map[string]any
	if err := json.Unmarshal(signed, &m); err != nil {
		panic(err)
	}
	fn(m)
	out, err := json.Marshal(m)
	if err != nil {
		panic(err)
	}
	return out
}

// spanEntry describes one claim in a span vector chain.
type spanEntry struct {
	// kind is "audit" or "span".
	kind string
	// at is the claim time.
	at string
	// beat is the span claim's beat number.
	beat int64
	// count is the span claim's declared entry count.
	count int64
}

// spanBundle builds an unkeyed loomseal-chain-v1 bundle from entries and anchors its head, so
// the spanned conformance word is reachable.
func (s *state) spanBundle(entries []spanEntry) map[string]any {
	m := s.base()
	claims := make([]any, len(entries))
	for i, e := range entries {
		var c map[string]any
		if e.kind == "span" {
			c = map[string]any{
				"type": "loomseal.span/1", "at": e.at,
				"payload": map[string]any{
					"stream": "chain", "cadence_s": int64(60), "beat": e.beat, "count": e.count,
				},
			}
		} else {
			c = map[string]any{
				"type": "switchtender.audit/1", "at": e.at,
				"payload": map[string]any{
					"actor": "release-token", "method": "POST", "path": "/api/runs",
				},
			}
		}
		claims[i] = c
	}
	m["claims"] = claims
	s.relinkV1(m, false)
	head := m["chain"].(map[string]any)["head"].(map[string]any)
	m["anchors"] = []any{gitAnchor(head["seq"].(int64), head["link"].(string))}
	return m
}

// spans emits the population attestation vectors: valid, gapped, adopted mid-life, and the two
// contradictions the profile must fail.
// merkleNegatives emits the tree profile vectors a conformant verifier must refuse. Each one is a
// forgery a producer could attempt, and each is signed, so only the profile's own checks catch it.
func (s *state) merkleNegatives() {
	// A claim whose content was altered after the tree was built. Its leaf no longer hashes to the
	// link the bundle carries.
	m := s.merkleBundle(6, []int{1, 4}, 0)
	claim := m["claims"].([]any)[0].(map[string]any)
	claim["payload"].(map[string]any)["path"] = "/api/evil"
	s.add("merkle-claim-altered", false, "", "chain",
		"A claim edited after the tree was built no longer hashes to its own leaf, so the leaf does "+
			"not recompute.", s.sign(m))

	// An audit path element replaced. The fold no longer reaches the signed root.
	m = s.merkleBundle(6, []int{1, 4}, 0)
	claim = m["claims"].([]any)[0].(map[string]any)
	claim["inclusion"].(map[string]any)["path"].([]any)[0] = strings.Repeat("ab", 32)
	s.add("merkle-bad-inclusion-path", false, "", "chain",
		"An audit path with a substituted sibling does not fold to the root the head names.",
		s.sign(m))

	// A leaf presented at a position it does not occupy.
	m = s.merkleBundle(6, []int{1, 4}, 0)
	claim = m["claims"].([]any)[0].(map[string]any)
	claim["chain"].(map[string]any)["seq"] = int64(3)
	s.add("merkle-wrong-leaf-index", false, "", "chain",
		"A claim moved to another position does not prove membership at that position.", s.sign(m))

	// A sequence past the tree the head declares.
	m = s.merkleBundle(6, []int{1, 4}, 0)
	claim = m["claims"].([]any)[0].(map[string]any)
	claim["chain"].(map[string]any)["seq"] = int64(99)
	s.add("merkle-seq-past-tree", false, "", "chain",
		"A claim naming a position past the tree size is outside the log the head attests.",
		s.sign(m))

	// An install id that is not the signer's. Without this check a second producer re-signs another
	// install's leaves, root, and timestamp token and every other check passes.
	m = s.merkleBundle(6, []int{1, 4}, 0)
	m["chain"].(map[string]any)["params"].(map[string]any)["install_id"] = "in_someone_else"
	s.add("merkle-foreign-install", false, "", "chain",
		"A tree whose leaves bind an install other than the producer's is refused, which is what "+
			"stops one producer from re-signing another's log and anchor.", s.sign(m))

	// A per-entry previous link, which a tree has no place for.
	m = s.merkleBundle(6, []int{1, 4}, 0)
	claim = m["claims"].([]any)[0].(map[string]any)
	claim["chain"].(map[string]any)["prev"] = strings.Repeat("cd", 32)
	s.add("merkle-claim-with-prev", false, "", "chain",
		"A tree claim carrying a previous link implies a linear chain that is not being verified.",
		s.sign(m))

	// A consistency proof over a log that rewrote an entry it had already published. This is the
	// append-only guarantee and the reason the proof exists.
	//
	// The rewritten entry is deliberately one the bundle does not disclose, so every disclosed leaf
	// still recomputes and folds to the head root. Only the consistency proof can catch this, which
	// is what the vector is for: a bundle that failed on a leaf hash instead would pass the suite
	// while leaving the append-only check untested.
	honestLeaves := make([][]byte, 0, 4)
	for _, c := range merkleLog(6)[:4] {
		honestLeaves = append(honestLeaves, merkleLeafData(c))
	}
	rewrittenLog := merkleLog(6)
	rewrittenLog[2]["payload"].(map[string]any)["path"] = "/api/rewritten"
	rewrittenLeaves := make([][]byte, 0, 6)
	for _, c := range rewrittenLog {
		rewrittenLeaves = append(rewrittenLeaves, merkleLeafData(c))
	}
	proof, perr := merkle.ConsistencyProof(4, rewrittenLeaves)
	if perr != nil {
		panic(perr)
	}
	disclosed := make([]any, 0, 2)
	for _, idx := range []int{0, 5} {
		path, ierr := merkle.InclusionProof(int64(idx), rewrittenLeaves)
		if ierr != nil {
			panic(ierr)
		}
		c := map[string]any{}
		for k, v := range rewrittenLog[idx] {
			c[k] = v
		}
		c["chain"] = map[string]any{
			"seq": int64(idx + 1), "prev": "",
			"link": hex.EncodeToString(merkle.LeafHash(rewrittenLeaves[idx])),
		}
		c["inclusion"] = map[string]any{"path": hexList(path)}
		disclosed = append(disclosed, c)
	}
	m = s.base()
	m["claims"] = disclosed
	m["chain"] = map[string]any{
		"profile": bundle.ProfileMerkle,
		"keyed":   false,
		"params":  map[string]any{"install_id": installID},
		"head": map[string]any{
			"seq": int64(6), "link": hex.EncodeToString(merkle.Root(rewrittenLeaves)),
		},
		"consistency": map[string]any{
			"from_size": int64(4),
			// The root the world saw before the rewrite, which this log can no longer reproduce.
			"from_root": hex.EncodeToString(merkle.Root(honestLeaves)),
			"path":      hexList(proof),
		},
	}
	s.add("merkle-consistency-rewritten", false, "", "chain",
		"A log that changed an entry it had already published cannot produce a consistency proof "+
			"from the root the world saw before the change. Every disclosed leaf here still "+
			"recomputes, so only the append-only check catches it.", s.sign(m))
}

func (s *state) spans() {
	valid := []spanEntry{
		{kind: "audit", at: "2026-07-27T15:00:10Z"},
		{kind: "span", at: "2026-07-27T15:01:00Z", beat: 1, count: 1},
		{kind: "audit", at: "2026-07-27T15:01:30Z"},
		{kind: "audit", at: "2026-07-27T15:01:40Z"},
		{kind: "span", at: "2026-07-27T15:02:00Z", beat: 2, count: 2},
	}
	s.add("span-valid", true,
		"signed, chained (full), anchored by reference, spanned", "",
		"Two beats whose counts recompute from the sequence numbers earn the spanned level.",
		s.sign(s.spanBundle(valid)))

	gapped := make([]spanEntry, len(valid))
	copy(gapped, valid)
	gapped[4].at = "2026-07-27T15:04:00Z"
	s.add("span-gap", true,
		"signed, chained (full), anchored by reference, spanned", "",
		"Beats further apart than the declared cadence are a reported gap, never a hidden one "+
			"and never a failure.",
		s.sign(s.spanBundle(gapped)))

	s.add("span-mid-adoption", true,
		"signed, chained (full), anchored by reference, spanned", "",
		"A chain adopting the profile mid-life attests its entire prior population at beat 1.",
		s.sign(s.spanBundle([]spanEntry{
			{kind: "audit", at: "2026-07-27T15:00:10Z"},
			{kind: "audit", at: "2026-07-27T15:00:20Z"},
			{kind: "audit", at: "2026-07-27T15:00:30Z"},
			{kind: "span", at: "2026-07-27T15:01:00Z", beat: 1, count: 3},
		})))

	falseCount := make([]spanEntry, len(valid))
	copy(falseCount, valid)
	falseCount[4].count = 1
	s.add("span-false-count", false, "", "span",
		"A count that does not match the sequence numbers is a signed false statement and fails.",
		s.sign(s.spanBundle(falseCount)))

	missingBeat := make([]spanEntry, len(valid))
	copy(missingBeat, valid)
	missingBeat[4].beat = 3
	s.add("span-missing-beat", false, "", "span",
		"A beat number that skips is a deleted window and fails.",
		s.sign(s.spanBundle(missingBeat)))
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

// hardening emits the vectors that pin the red-team fixes: a keyed chain earns no anchored wording,
// a reserved records member on a non-record claim still verifies, and a case variant of a bound
// member is refused rather than folded onto its struct field. Every one is checked by all three
// shipped verifiers through the manifest, which is how Go, Python, and the browser build are held
// to the same verdict on the same bytes.
func (s *state) hardening() {
	// A keyed chain carrying an anchor over its head. It verifies structurally, and the anchor
	// matches by coordinate, but a keyed link is never recomputed, so the verifier never tied the
	// anchored link to the claim content and grants no anchored wording. Before the fix this reached
	// "anchored by reference", which let a real token be laundered onto an invented keyed entry.
	ka := s.v1(1, true)
	head := ka["chain"].(map[string]any)["head"].(map[string]any)
	ka["anchors"] = []any{gitAnchor(head["seq"].(int64), head["link"].(string))}
	s.add("keyed-anchored-structural", true, "signed, chained (structural)", "",
		"A keyed chain verifies structurally only, so an anchor over its head is matched and reported "+
			"but earns no anchored wording: the verifier never recomputed the link to tie it to the "+
			"claim content.", s.sign(ka))

	// A switchtender.audit/1 claim whose payload carries a reserved records member on a claim that
	// is no record. The member is not part of the link and no record check reads it, so the bundle
	// verifies with the member reported unchecked. It pins that reserving these member names does not
	// fail a conforming bundle that happens to carry one.
	rm := s.switchTender()
	rmClaim := rm["claims"].([]any)[0].(map[string]any)
	rmPayload := rmClaim["payload"].(map[string]any)
	rmPayload["reason_text"] = "a plain operator note, not a disclosed record"
	s.add("record-member-on-nonrecord", true, "signed, chained (full)", "",
		"A reserved disclosed-records member on a non-record claim is an ordinary payload member the "+
			"link does not commit, so a conforming bundle carrying one still verifies, with the member "+
			"reported unchecked.", s.sign(rm))
	s.expect("record-member-on-nonrecord", []string{"claim 0 reason_text"}, nil)

	s.casefoldSwitchTender()
	s.casefoldSpan()
	s.casefoldEnvelope()
}

// casefoldSwitchTender plants, for each bound field of the switchtender profile, a case variant
// that holds the honest value while the exact member holds a lie. A verifier that folds the two
// onto one struct field reads the honest value and reaches VERIFIED over a record no reader sees; a
// verifier that reads the exact member recomputes the link over the lie and refuses the bundle.
func (s *state) casefoldSwitchTender() {
	honest := map[string]string{
		"actor": "release-token", "method": "POST", "path": "/api/runs",
		"actor_type": "interactive", "on_behalf_of": "u_admin",
		"content_digest": "sha256:" + strings.Repeat("ab", 32), "install_id": installID,
	}
	optional := map[string]bool{"actor_type": true, "on_behalf_of": true, "content_digest": true,
		"install_id": true}
	for _, mem := range []string{"actor", "method", "path", "actor_type", "on_behalf_of",
		"content_digest", "install_id"} {
		payload := map[string]any{"actor": honest["actor"], "method": honest["method"],
			"path": honest["path"]}
		if optional[mem] {
			payload[mem] = honest[mem]
		}
		link := switchTenderLinkFields(1, at, "", payload)
		lie := "forged-" + mem
		if mem == "install_id" {
			lie = "in_forged"
		}
		payload[mem] = lie
		payload[swapCase(mem)] = honest[mem]
		m := s.base()
		claim := m["claims"].([]any)[0].(map[string]any)
		claim["payload"] = payload
		claim["chain"] = map[string]any{"seq": int64(1), "prev": "", "link": link}
		m["chain"] = map[string]any{"profile": profileSwitchTender, "keyed": false,
			"head": map[string]any{"seq": int64(1), "link": link}}
		s.add("casefold-switchtender-"+strings.ReplaceAll(mem, "_", "-"), false, "", "chain",
			"The bound member "+mem+" is read from the exact canonical key, so a case variant holding "+
				"the honest value does not fold onto it and the link recomputes over the lie.",
			s.sign(m))
	}
}

// casefoldSpan plants a case variant of each span field. A span payload is not covered by the
// switchtender link, so folding beat or count onto a struct field from a case variant let the span
// check pass over a population the record does not state. Reading the exact member fails the check.
func (s *state) casefoldSpan() {
	auditLink := switchTenderLinkFields(1, at, "",
		map[string]any{"actor": "release-token", "method": "POST", "path": "/api/runs"})
	spanAt := "2026-07-27T15:01:00Z"
	spanLink := switchTenderLinkFields(2, spanAt, auditLink, map[string]any{})
	honest := map[string]any{"stream": "chain", "cadence_s": int64(60), "beat": int64(1),
		"count": int64(1)}
	lies := map[string]any{"stream": "other", "cadence_s": int64(0), "beat": int64(0),
		"count": int64(999)}
	for _, mem := range []string{"stream", "cadence_s", "beat", "count"} {
		sp := map[string]any{}
		for k, v := range honest {
			sp[k] = v
		}
		sp[mem] = lies[mem]
		sp[swapCase(mem)] = honest[mem]
		m := s.base()
		audit := map[string]any{"type": "switchtender.audit/1", "at": at,
			"payload": map[string]any{"actor": "release-token", "method": "POST", "path": "/api/runs"},
			"chain":   map[string]any{"seq": int64(1), "prev": "", "link": auditLink}}
		span := map[string]any{"type": "loomseal.span/1", "at": spanAt, "payload": sp,
			"chain": map[string]any{"seq": int64(2), "prev": auditLink, "link": spanLink}}
		m["claims"] = []any{audit, span}
		m["chain"] = map[string]any{"profile": profileSwitchTender, "keyed": false,
			"head": map[string]any{"seq": int64(2), "link": spanLink}}
		s.add("casefold-span-"+strings.ReplaceAll(mem, "_", "-"), false, "", "span",
			"The span field "+mem+" is read from the exact canonical key, so a case variant holding a "+
				"value that would pass does not fold onto it and the span check sees the lie.",
			s.sign(m))
	}

	// The same read under loomseal-chain-v1, whose link commits the whole claim, so no path binds the
	// span members and only the exact read stands between the record and a folded value. The honest
	// cadence sits under a long s, which folds onto the s of cadence_s and sorts after it, so a reader
	// that folds case and keeps the last member it meets would read the honest value.
	m := s.spanBundle([]spanEntry{
		{kind: "audit", at: "2026-07-27T15:00:10Z"},
		{kind: "span", at: "2026-07-27T15:01:00Z", beat: 1, count: 1},
	})
	span := m["claims"].([]any)[1].(map[string]any)["payload"].(map[string]any)
	span["cadence_\u017f"] = span["cadence_s"]
	span["cadence_s"] = int64(0)
	s.relinkV1(m, false)
	head := m["chain"].(map[string]any)["head"].(map[string]any)
	m["anchors"] = []any{gitAnchor(head["seq"].(int64), head["link"].(string))}
	s.add("casefold-span-cadence-s-chain-v1", false, "", "span",
		"Under a profile whose link commits the whole claim, the span field cadence_s is still read "+
			"from its exact key, so a variant that folds onto it does not stand in for it.",
		s.sign(m))
}

// casefoldEnvelope plants a case variant of an envelope member at three positions a verdict reads:
// a producer field, a signature field, and a claim's chain coordinates. The exact-member check
// refuses each at parse, rather than folding it onto a struct field.
func (s *state) casefoldEnvelope() {
	// producer.install_id, with a case variant beside it.
	pm := s.switchTender()
	pm["producer"].(map[string]any)["Install_ID"] = installID
	s.add("casefold-producer-install-id", false, "", "parse",
		"A case variant of producer.install_id is refused at parse rather than folded onto the "+
			"install_id field.", s.sign(pm))

	// A claim's chain seq, with a case variant beside it, signed so the only fault is the member.
	cm := s.switchTender()
	cm["claims"].([]any)[0].(map[string]any)["chain"].(map[string]any)["Seq"] = int64(1)
	s.add("casefold-coords-seq", false, "", "parse",
		"A case variant of a claim's chain seq is refused at parse rather than folded onto the seq "+
			"coordinate.", s.sign(cm))

	// signature.key_id, added after signing because the signatures array sits outside the signed
	// bytes, so the bundle is validly signed and the only fault is the member.
	sm := mutateSigned(s.sign(s.switchTender()), func(m map[string]any) {
		sig := m["signatures"].([]any)[0].(map[string]any)
		sig["Key_ID"] = sig["key_id"]
	})
	s.add("casefold-signature-key-id", false, "", "parse",
		"A case variant of a signature's key_id is refused at parse rather than folded onto the "+
			"key_id field.", sm)

	// The chain head's seq, with a case variant beside it, signed so the only fault is the member.
	hm := s.switchTender()
	hm["chain"].(map[string]any)["head"].(map[string]any)["Seq"] = int64(1)
	s.add("casefold-head-seq", false, "", "parse",
		"A case variant of the chain head's seq is refused at parse rather than folded onto the "+
			"coordinate the head match reads.", s.sign(hm))

	// A head-level attestation's key_id, added after signing because head attestations sit outside
	// the signed bytes, so the bundle is validly signed and the only fault is the member.
	am := mutateSigned(s.sign(s.v1(2, false)), func(m map[string]any) {
		hPriv, hPub := counterpartyKey()
		head := m["chain"].(map[string]any)["head"].(map[string]any)
		att := headAttestation(hPriv, hPub, head["link"].(string), head["seq"], "witness",
			"2026-08-30T12:00:00Z")
		att["Key_ID"] = att["key_id"]
		m["attestations"] = []any{att}
	})
	s.add("casefold-head-attestation-key-id", false, "", "parse",
		"A case variant of a head attestation's key_id is refused at parse rather than folded onto "+
			"the key the attestation is checked against.", am)
}

// switchTenderLinkFields recomputes a switchtender-audit-v1 link over the exact bound members a
// payload carries, matching the verifier: seq, at, actor, method, path, prev, plus the four
// optional fields when present as a non-empty string.
func switchTenderLinkFields(seq int64, atStr, prev string, payload map[string]any) string {
	fields := map[string]any{"seq": seq, "at": atStr, "prev": prev,
		"actor": memberOrEmpty(payload, "actor"), "method": memberOrEmpty(payload, "method"),
		"path": memberOrEmpty(payload, "path")}
	for _, k := range []string{"actor_type", "on_behalf_of", "content_digest", "install_id"} {
		if v, ok := payload[k].(string); ok && v != "" {
			fields[k] = v
		}
	}
	b, err := jcs.Serialize(fields)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// memberOrEmpty returns a payload member or the empty string, matching the verifier's read.
func memberOrEmpty(payload map[string]any, key string) any {
	if v, ok := payload[key]; ok {
		return v
	}
	return ""
}

// swapCase flips the ASCII case of every letter, turning a member name into the case variant that a
// case-insensitive struct decode folds back onto it.
func swapCase(s string) string {
	b := []byte(s)
	for i := range b {
		switch {
		case b[i] >= 'a' && b[i] <= 'z':
			b[i] -= 32
		case b[i] >= 'A' && b[i] <= 'Z':
			b[i] += 32
		}
	}
	return string(b)
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
		link, err := seal.LinkV1(nil, installID, seq, prev, seal.ClaimContent(claim))
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

// switchTenderEscapes builds a chain whose recorded path carries the characters encoding/json
// escapes for HTML and RFC 8785 does not.
//
// A verifier reaching for its language's default JSON encoder recomputes a different link for this
// claim and reports an honest chain as broken. The entry is append-only, so every later bundle
// covering it fails the same way and the only escape is to truncate the trail past it. No earlier
// vector contained one of these characters, which is how the disagreement went unnoticed.
func (s *state) switchTenderEscapes() map[string]any {
	m := s.base()
	const path = "/api/runs/prod&staging<x>\u2028y"
	link := switchTenderLink(1, at, "release-token", "POST", path, "")
	claim := m["claims"].([]any)[0].(map[string]any)
	claim["chain"] = map[string]any{"seq": int64(1), "prev": "", "link": link}
	if p, ok := claim["payload"].(map[string]any); ok {
		p["path"] = path
	}
	m["chain"] = map[string]any{
		"profile": profileSwitchTender, "keyed": false,
		"head": map[string]any{"seq": int64(1), "link": link},
	}
	return m
}

// anchoredLink is the link a real RFC 3161 token in testdata attests to. A timestamp is signed over
// a specific value, so the vector is built around the token rather than the other way round.
const anchoredLink = "4e03f42f52842aa7f4f086d13a210a6856f6a0abadea183e257d3c7554e2211c"

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

// switchTenderLink recomputes a switchtender-audit-v1 link with no install binding, the pre-binding
// form every legacy chain carries.
func switchTenderLink(seq int64, atStr, actor, method, path, prev string) string {
	return switchTenderLinkBound(seq, atStr, actor, method, path, prev, "")
}

// switchTenderLinkBound recomputes a switchtender-audit-v1 link: SHA-256 over the canonical JSON
// object of the claim's fields, so a field added later is committed without revising the profile. The
// install id is folded in when non-empty, which is how a chain binds its links to the producer.
func switchTenderLinkBound(seq int64, atStr, actor, method, path, prev, install string) string {
	// Serialized with the JCS encoder, not encoding/json. encoding/json escapes &, <, >, U+2028,
	// and U+2029 for embedding in HTML; RFC 8785 emits them raw. A vector built with the escaping
	// encoder would have written the wrong answer into the file that defines what correct means.
	fields := map[string]any{
		"seq": seq, "at": atStr, "actor": actor, "method": method, "path": path, "prev": prev,
	}
	if install != "" {
		fields["install_id"] = install
	}
	b, err := jcs.Serialize(fields)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// switchTenderBound builds a shipped SwitchTender chain that binds its link to the producer install,
// the form new producers emit. The install id is carried in the claim payload and folded into the
// link, so an entry that omits it stays unchanged while a bound entry cannot be lifted.
func (s *state) switchTenderBound() map[string]any {
	m := s.base()
	link := switchTenderLinkBound(1, at, "release-token", "POST", "/api/runs", "", installID)
	claim := m["claims"].([]any)[0].(map[string]any)
	claim["payload"].(map[string]any)["install_id"] = installID
	claim["chain"] = map[string]any{"seq": int64(1), "prev": "", "link": link}
	m["chain"] = map[string]any{
		"profile": profileSwitchTender, "keyed": false,
		"head": map[string]any{"seq": int64(1), "link": link},
	}
	return m
}

// switchTenderBoundAs builds the bound SwitchTender chain of switchTenderBound for another install
// id, carried on the producer and folded into the link, so the chain itself is well formed.
func (s *state) switchTenderBoundAs(install string) map[string]any {
	m := s.base()
	m["producer"].(map[string]any)["install_id"] = install
	link := switchTenderLinkBound(1, at, "release-token", "POST", "/api/runs", "", install)
	claim := m["claims"].([]any)[0].(map[string]any)
	claim["payload"].(map[string]any)["install_id"] = install
	claim["chain"] = map[string]any{"seq": int64(1), "prev": "", "link": link}
	m["chain"] = map[string]any{
		"profile": profileSwitchTender, "keyed": false,
		"head": map[string]any{"seq": int64(1), "link": link},
	}
	return m
}

// mintedInstallID is the install id the switchtender profile mints from a key: in_ and the first 32
// hex digits of the key's SHA-256.
func mintedInstallID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "in_" + hex.EncodeToString(sum[:16])
}

// legacyInstallID is the legacy switchtender install id, in_ and the hex of the key's first six bytes.
func legacyInstallID(pub ed25519.PublicKey) string {
	return "in_" + hex.EncodeToString(pub[:6])
}

// switchTenderDeclaredHeadProof pushes the head of the anchored-proof bundle beyond the disclosed
// claim, so the real timestamp token sits on a declared head the bundle cannot tie to a claim. The
// proof stays cryptographically valid, but a verifier must not open it or award an anchored level.
func (s *state) switchTenderDeclaredHeadProof() map[string]any {
	m := s.switchTenderProof()
	m["chain"].(map[string]any)["head"] = map[string]any{"seq": int64(500), "link": anchoredLink}
	anchor := m["anchors"].([]any)[0].(map[string]any)
	anchor["seq"] = int64(500)
	return m
}

// parseUnixNano converts an RFC 3339 time to Unix nanoseconds.
func parseUnixNano(sVal string) int64 {
	tv, err := time.Parse(time.RFC3339Nano, sVal)
	if err != nil {
		panic(err)
	}
	return tv.UnixNano()
}

// swatchDigest computes a LoomSwatch field commitment: SHA-256 over the JCS canonical array of the
// salt, the field name, and the value, hex encoded. It matches what the verifier recomputes.
func swatchDigest(salt, name string, value any) string {
	b, err := jcs.Serialize([]any{salt, name, value})
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// swatchField is one redactable field for a LoomSwatch vector.
type swatchField struct {
	name  string
	value any
}

// swatchBundle builds a loomseal-chain-v1 bundle whose single claim commits three redactable fields
// as a sorted _sd digest set in its payload and discloses the named subset. The link commits the _sd
// set, not the disclosures, so the same claim verifies whichever fields are revealed.
func (s *state) swatchBundle(reveal ...string) map[string]any {
	fields := []swatchField{
		{"title", "Senior Platform Engineer"},
		{"salary", int64(185000)},
		{"start_date", "2021-03-01"},
	}
	revealSet := map[string]bool{}
	for _, r := range reveal {
		revealSet[r] = true
	}
	var digests []string
	var disc []any
	for _, f := range fields {
		salt := "loomseal-vector-salt-" + f.name
		digests = append(digests, swatchDigest(salt, f.name, f.value))
		if revealSet[f.name] {
			disc = append(disc, map[string]any{"salt": salt, "name": f.name, "value": f.value})
		}
	}
	sort.Strings(digests)
	sd := make([]any, len(digests))
	for i, d := range digests {
		sd[i] = d
	}
	m := s.base()
	claim := m["claims"].([]any)[0].(map[string]any)
	claim["type"] = "example.person/1"
	claim["payload"] = map[string]any{"record": "employment", "_sd": sd}
	if len(disc) > 0 {
		claim["disclosures"] = disc
	}
	s.relinkV1(m, false)
	return m
}

// counterpartyKey returns a second deterministic ed25519 key, distinct from the producer, used to
// counter-sign claims in attestation vectors.
func counterpartyKey() (ed25519.PrivateKey, ed25519.PublicKey) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(200 - i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub, _ := priv.Public().(ed25519.PublicKey)
	return priv, pub
}

// attestation builds a counter-signature over a claim's link and role, the way a counterparty and the
// verifier both compute it.
func attestation(priv ed25519.PrivateKey, pub ed25519.PublicKey, link, role string) map[string]any {
	return attestationAt(priv, pub, link, role, "")
}

// attestationAt counter-signs the domain-tagged attestation object, carrying the signed time when
// at is set, so an approver's sign-off time travels inside the signature.
// headAttestation counter-signs the domain-tagged head object, binding link, seq, role, and the
// signed time when carried.
func headAttestation(priv ed25519.PrivateKey, pub ed25519.PublicKey, link string, seq any, role, at string) map[string]any {
	obj := map[string]any{"loomseal": "head-attestation/1", "link": link, "seq": seq, "role": role}
	if at != "" {
		obj["at"] = at
	}
	preimage, err := jcs.Serialize(obj)
	if err != nil {
		panic(err)
	}
	sig := ed25519.Sign(priv, preimage)
	out := map[string]any{
		"key_id":     seal.KeyID(pub),
		"public_key": base64.StdEncoding.EncodeToString(pub),
		"alg":        "ed25519",
		"role":       role,
		"sig":        base64.StdEncoding.EncodeToString(sig),
	}
	if at != "" {
		out["at"] = at
	}
	return out
}

func attestationAt(priv ed25519.PrivateKey, pub ed25519.PublicKey, link, role, at string) map[string]any {
	obj := map[string]any{"loomseal": "attestation/1", "link": link, "role": role}
	if at != "" {
		obj["at"] = at
	}
	preimage, err := jcs.Serialize(obj)
	if err != nil {
		panic(err)
	}
	sig := ed25519.Sign(priv, preimage)
	out := map[string]any{
		"key_id":     seal.KeyID(pub),
		"public_key": base64.StdEncoding.EncodeToString(pub),
		"alg":        "ed25519",
		"role":       role,
		"sig":        base64.StdEncoding.EncodeToString(sig),
	}
	if at != "" {
		out["at"] = at
	}
	return out
}

// attestedBundle builds a loomseal-chain-v1 bundle whose claim carries a valid counterparty
// counter-signature over its link.
func (s *state) attestedBundle() map[string]any {
	m := s.v1(1, false)
	claim := m["claims"].([]any)[0].(map[string]any)
	link := claim["chain"].(map[string]any)["link"].(string)
	cpriv, cpub := counterpartyKey()
	claim["attestations"] = []any{attestation(cpriv, cpub, link, "counterparty")}
	return m
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

// expect records which disclosed members a verifier must report unchecked and redacted in a vector
// that must verify.
func (s *state) expect(name string, unchecked, redacted []string) {
	for i := range s.man.Vectors {
		if s.man.Vectors[i].Name == name {
			s.man.Vectors[i].Unchecked = unchecked
			s.man.Vectors[i].Redacted = redacted
			return
		}
	}
	panic("expect: no vector named " + name)
}

// expectLegacy records which record bodies a verifier must report verified under the legacy
// unkeyed digest form in a vector that must verify.
func (s *state) expectLegacy(name string, legacy []string) {
	for i := range s.man.Vectors {
		if s.man.Vectors[i].Name == name {
			s.man.Vectors[i].Legacy = legacy
			return
		}
	}
	panic("expectLegacy: no vector named " + name)
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

// presentations emits the holder presentation conformance vectors: a valid one checked under several
// pins, plus tampering and a corrupted holder signature.
func (s *state) presentations() {
	s.presMan.Description = "LoomSeal v0.1 presentation conformance vectors. Each entry declares the " +
		"audience and nonce the verifier requires and whether the presentation must verify under " +
		"them. A verifier is conformant when it agrees with every entry."

	inner := s.sign(s.v1(1, false))
	hpriv, _ := holderKey()
	valid, err := seal.Present(inner, hpriv, "acme-verifier", "chal-1", at)
	if err != nil {
		panic(err)
	}
	vf := s.writePresentationFile("present-valid", valid)
	s.addPresentation("present-valid", vf, "acme-verifier", "chal-1", true,
		"A presentation bound to the verifier and nonce it declares verifies under those pins.")
	s.addPresentation("present-no-pins", vf, "", "", true,
		"The same presentation with no pins verifies: the pins are the caller's to require.")
	s.addPresentation("present-wrong-audience", vf, "someone-else", "chal-1", false,
		"The same presentation fails when the verifier requires a different audience, which is what "+
			"stops it being replayed to another verifier.")
	s.addPresentation("present-stale-nonce", vf, "acme-verifier", "old-nonce", false,
		"The same presentation fails against a stale challenge, which is what stops a replay.")

	tampered := []byte(strings.Replace(string(valid), "/api/runs", "/api/evil", 1))
	tf := s.writePresentationFile("present-tampered-bundle", tampered)
	s.addPresentation("present-tampered-bundle", tf, "acme-verifier", "chal-1", false,
		"A presentation whose embedded bundle was changed fails: the bundle no longer verifies and its "+
			"digest no longer matches the holder signature.")

	var pm map[string]any
	if err := json.Unmarshal(valid, &pm); err != nil {
		panic(err)
	}
	sig := pm["sig"].(string)
	first := "A"
	if strings.HasPrefix(sig, "A") {
		first = "B"
	}
	pm["sig"] = first + sig[1:]
	badSig, err := json.Marshal(pm)
	if err != nil {
		panic(err)
	}
	bf := s.writePresentationFile("present-bad-holder-sig", badSig)
	s.addPresentation("present-bad-holder-sig", bf, "acme-verifier", "chal-1", false,
		"A presentation whose holder signature was altered does not verify.")

	// A member whose name differs from a presentation member only in case is refused, never folded
	// onto the member a reader sees. Beside audience it holds the same value, so only the name is at
	// fault. In the holder it holds the signed key id under a Kelvin sign, which folds onto the k of
	// key_id, while key_id itself holds another, so a reader folding case would check a key the
	// document does not show.
	var cf map[string]any
	if err := json.Unmarshal(valid, &cf); err != nil {
		panic(err)
	}
	cf["Audience"] = cf["audience"]
	folded, err := json.Marshal(cf)
	if err != nil {
		panic(err)
	}
	ff := s.writePresentationFile("present-casefold-audience", folded)
	s.addPresentation("present-casefold-audience", ff, "acme-verifier", "chal-1", false,
		"A presentation carrying Audience beside audience is refused at parse: member names are "+
			"matched exactly, so the variant is not read as the audience a reader sees.")
	var kf map[string]any
	if err := json.Unmarshal(valid, &kf); err != nil {
		panic(err)
	}
	holder := kf["holder"].(map[string]any)
	holder["\u212aey_id"] = holder["key_id"]
	holder["key_id"] = "sha256:" + strings.Repeat("00", 32)
	folded, err = json.Marshal(kf)
	if err != nil {
		panic(err)
	}
	kff := s.writePresentationFile("present-casefold-holder-key-id", folded)
	s.addPresentation("present-casefold-holder-key-id", kff, "acme-verifier", "chal-1", false,
		"A holder carrying the signed key id under a name that folds onto key_id is refused at parse, "+
			"rather than checked in place of the key_id the document shows.")
}

// writePresentationFile writes one presentation document and returns its file name.
func (s *state) writePresentationFile(name string, data []byte) string {
	file := name + ".loomseal-presentation.json"
	if err := os.WriteFile(filepath.Join(dir, file), data, 0o600); err != nil {
		panic(err)
	}
	return file
}

// addPresentation records one presentation conformance case, referencing an already-written file.
func (s *state) addPresentation(name, file, audience, nonce string, mustVerify bool, why string) {
	s.presMan.Vectors = append(s.presMan.Vectors, presentationVector{
		Name: name, File: file, ExpectAudience: audience, ExpectNonce: nonce,
		MustVerify: mustVerify, Why: why,
	})
}

// writePresentations emits the presentation manifest, vectors sorted by name for a stable diff.
func (s *state) writePresentations() error {
	sort.Slice(s.presMan.Vectors, func(i, j int) bool {
		return s.presMan.Vectors[i].Name < s.presMan.Vectors[j].Name
	})
	out, err := json.MarshalIndent(s.presMan, "", "  ")
	if err != nil {
		return err
	}
	out = append(out, '\n')
	return os.WriteFile(filepath.Join(dir, "presentations.json"), out, 0o600)
}

// merkleLeafData builds one claim's leaf bytes under loomseal-merkle-v1: the canonical object of the
// domain, the install, and the claim digest over the claim's content.
func merkleLeafData(claim map[string]any) []byte {
	content := map[string]any{}
	for k, v := range claim {
		if k == "chain" || k == "inclusion" || k == "disclosures" || k == "attestations" {
			continue
		}
		content[k] = v
	}
	if ev, ok := content["evidence"].([]any); ok {
		stripped := make([]any, 0, len(ev))
		for _, e := range ev {
			obj := e.(map[string]any)
			cp := map[string]any{}
			for k, v := range obj {
				if k != "present" && k != "location" {
					cp[k] = v
				}
			}
			stripped = append(stripped, cp)
		}
		content["evidence"] = stripped
	}
	canonical, err := jcs.Serialize(content)
	if err != nil {
		panic("canonicalize claim: " + err.Error())
	}
	leaf, err := jcs.Serialize(map[string]any{
		"domain":     bundle.ProfileMerkle,
		"install_id": installID,
		"claim":      "sha256:" + merkle.Sum256Hex(canonical),
	})
	if err != nil {
		panic("canonicalize leaf: " + err.Error())
	}
	return leaf
}

// merkleLog returns n deterministic claim objects, the whole log a tree is built over.
func merkleLog(n int) []map[string]any {
	out := make([]map[string]any, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, map[string]any{
			"type": "switchtender.audit/1", "at": at,
			"payload": map[string]any{
				"actor": "release-token", "method": "POST",
				"path": fmt.Sprintf("/api/runs/%d", i),
			},
		})
	}
	return out
}

// merkleBundle builds a tree bundle over a log of size, disclosing the leaves at the given indexes
// and, when fromSize is above zero, carrying a consistency proof from that earlier size.
func (s *state) merkleBundle(size int, disclose []int, fromSize int) map[string]any {
	return s.merkleBundleShaped(size, disclose, fromSize, nil)
}

// merkleBundleShaped builds a tree bundle whose log is adjusted before its leaves are computed, so a
// vector can place members inside the committed content rather than only around it. Without a hook
// here every merkle vector's claims carry the same three members, and the profile's handling of any
// other member goes unexercised.
func (s *state) merkleBundleShaped(size int, disclose []int, fromSize int,
	shape func(log []map[string]any)) map[string]any {
	log := merkleLog(size)
	if shape != nil {
		shape(log)
	}
	leaves := make([][]byte, 0, size)
	for _, c := range log {
		leaves = append(leaves, merkleLeafData(c))
	}
	root := merkle.Root(leaves)

	claims := make([]any, 0, len(disclose))
	for _, idx := range disclose {
		path, err := merkle.InclusionProof(int64(idx), leaves)
		if err != nil {
			panic(err)
		}
		c := map[string]any{}
		for k, v := range log[idx] {
			c[k] = v
		}
		c["chain"] = map[string]any{
			"seq": int64(idx + 1), "prev": "",
			"link": hex.EncodeToString(merkle.LeafHash(leaves[idx])),
		}
		c["inclusion"] = map[string]any{"path": hexList(path)}
		claims = append(claims, c)
	}

	chain := map[string]any{
		"profile": bundle.ProfileMerkle,
		"keyed":   false,
		"params":  map[string]any{"install_id": installID},
		"head": map[string]any{
			"seq": int64(size), "link": hex.EncodeToString(root),
		},
	}
	if fromSize > 0 {
		proof, err := merkle.ConsistencyProof(int64(fromSize), leaves)
		if err != nil {
			panic(err)
		}
		chain["consistency"] = map[string]any{
			"from_size": int64(fromSize),
			"from_root": hex.EncodeToString(merkle.Root(leaves[:fromSize])),
			"path":      hexList(proof),
		}
	}

	m := s.base()
	m["chain"] = chain
	m["claims"] = claims
	return m
}

// hexList hex encodes a proof's hashes for a bundle.
func hexList(in [][]byte) []any {
	out := make([]any, 0, len(in))
	for _, h := range in {
		out = append(out, hex.EncodeToString(h))
	}
	return out
}

// recordRun is the run every record vector is a receipt for.
const recordRun = "run_vectors"

// recordSpec is the run's spec as SwitchTender discloses it: the canonical redacted bytes its
// decisions and its outcome commit by digest, carried as a string so nothing re-serializes them.
const recordSpec = `{"command":"deploy","tool":"bash"}`

// recordReason is the approver's reason. It carries the characters encoding/json escapes for HTML
// and RFC 8785 does not, so a verifier that canonicalizes with its language's default encoder
// recomputes a different commitment and fails an honest receipt.
const recordReason = "approved after the change review & the on-call <sign-off>"

// records emits the vectors for the records a switchtender.audit/1 claim discloses beside the
// fields its link commits: approval decisions, corrections to a decision's reason, the reasons
// they commit, the run's outcome, and the run's spec. Every altered vector is re-signed with the
// producer's own key, which is the threat the record check exists for: the signature holds and
// every link recomputes, because no disclosed member is part of the link, and only the commitments
// catch the edit.
func (s *state) records() {
	s.add("switchtender-record-reason", true, "signed, chained (full)", "",
		"A decision body that reproduces its entry's keyed content digest, a reason that opens the "+
			"commitment the body carries, and a spec that hashes to the digest the decision "+
			"committed all verify.", s.sign(s.recordReceipt(recordDisclosure{Reason: "text"})))

	m := s.recordReceipt(recordDisclosure{Reason: "text"})
	recordPayload(m, 1)["reason_text"] = "approved by the change board"
	s.add("switchtender-record-reason-altered", false, "", "record",
		"A receipt whose disclosed reason was changed and re-signed by the producer keeps its "+
			"signature and every link, and still fails, because the text no longer opens the "+
			"commitment the decision body carries.", s.sign(m))

	s.add("switchtender-record-reason-redacted", true, "signed, chained (full)", "",
		"A reason the holder marked redacted verifies and is reported as withheld, with the "+
			"category the holder claims: its text and random value are absent, its commitment stays "+
			"unopened, and nothing commits the marker or the category, so neither is vouched for.",
		s.sign(s.recordReceipt(recordDisclosure{Reason: "redacted"})))
	s.expect("switchtender-record-reason-redacted", nil, []string{"claim 1 reason_redacted"})

	s.add("switchtender-record-reason-withheld", true, "signed, chained (full)", "",
		"A decision body that commits a reason the receipt does not disclose verifies, with the "+
			"reason reported as committed and not disclosed.",
		s.sign(s.recordReceipt(recordDisclosure{Reason: "withheld"})))

	s.add("switchtender-record-correction", true, "signed, chained (full)", "",
		"A correction appended to a decision's reason reproduces its own entry's content digest, "+
			"and its text opens the commitment bound to the correction's id.",
		s.sign(s.recordReceipt(recordDisclosure{Reason: "text", Correction: true})))

	m = s.recordReceipt(recordDisclosure{Reason: "text", Correction: true})
	recordPayload(m, 2)["reason_text"] = "the reason was misstated, the window is approved"
	s.add("switchtender-record-correction-altered", false, "", "record",
		"A receipt whose disclosed correction text was changed and re-signed fails, because the "+
			"text no longer opens the commitment the correction body carries.", s.sign(m))

	m = s.recordReceipt(recordDisclosure{Reason: "text"})
	recordPayload(m, 1)["decision_body"].(map[string]any)["verdict"] = "rejected"
	s.add("switchtender-record-decision-altered", false, "", "record",
		"A receipt whose disclosed decision body was changed and re-signed fails, because the body "+
			"no longer reproduces the content digest its entry committed and the link fixed.",
		s.sign(m))

	m = s.recordReceipt(recordDisclosure{Reason: "text"})
	recordPayload(m, 2)["spec_body"] = `{"command":"deploy --force","tool":"bash"}`
	s.add("switchtender-record-spec-altered", false, "", "record",
		"A receipt whose disclosed spec was changed and re-signed fails, because it no longer "+
			"hashes to the spec digest the verified decision committed.", s.sign(m))

	s.add("switchtender-record-unkeyed", true, "signed, chained (full)", "",
		"A decision recorded before nonces carries the unkeyed content digest and an empty nonce, "+
			"and its body verifies against the SHA-256 of its canonical bytes, reported as legacy, "+
			"since nothing before it in the bundle is keyed.",
		s.sign(s.recordReceipt(recordDisclosure{Unkeyed: true})))
	s.expectLegacy("switchtender-record-unkeyed", []string{"claim 1 decision_body"})

	s.add("switchtender-record-unkeyed-after-keyed", false, "", "record",
		"A decision under the unkeyed content digest after an entry under the keyed form fails: the "+
			"producer was keying its digests by then, so the entry is not one from before nonces, and "+
			"an unkeyed digest lets anyone holding the bundle confirm a guess of the body.",
		s.sign(s.recordReceipt(recordDisclosure{Unkeyed: true, KeyedCreation: true})))

	m = s.recordReceipt(recordDisclosure{NoDecision: true})
	plain := recordPayload(m, 0)
	plain["decision_body"] = "approved by the change board"
	plain["decision_nonce"] = "not a nonce"
	plain["reason_text"] = "a note the request carried"
	plain["spec_body"] = `{"command":"something else"}`
	plain["Outcome_body"] = "a name that differs from a record member only in case"
	s.add("switchtender-record-names-off-record", true, "signed, chained (full)", "",
		"Record member names on a claim whose committed method and path make it no record are "+
			"ordinary members, whatever they hold: a bundle that used them as plain fields before "+
			"records existed verifies as it always did, with each reported unchecked.", s.sign(m))
	s.expect("switchtender-record-names-off-record", []string{"claim 0 Outcome_body",
		"claim 0 decision_body", "claim 0 decision_nonce", "claim 0 reason_text",
		"claim 0 spec_body"}, nil)

	m = s.v1(1, false)
	plain = m["claims"].([]any)[0].(map[string]any)["payload"].(map[string]any)
	plain["decision_body"] = "approved by the change board"
	plain["reason_text"] = "a note the request carried"
	plain["outcome_nonce"] = "not a nonce"
	s.relinkV1(m, false)
	s.add("switchtender-record-names-chain-v1", true, "signed, chained (full)", "",
		"The same names on a claim that is no record, under a profile whose link commits the whole "+
			"claim, are committed members like any other and verify.", s.sign(m))

	m = s.recordReceipt(recordDisclosure{Unkeyed: true})
	recordPayload(m, 1)["reason_text"] = recordReason
	recordPayload(m, 1)["reason_random"] = hex.EncodeToString(recordBytes("random decision"))
	s.add("switchtender-record-reason-uncommitted", false, "", "record",
		"A reason disclosed beside a decision body that commits none fails: it is text the chain "+
			"never fixed, and a reader must not be shown it as part of the record.", s.sign(m))

	s.add("switchtender-outcome-exact", true, "signed, chained (full)", "",
		"An outcome committed under the exact form reproduces its entry's digest from the bytes "+
			"carried, and the spec beside it hashes to the spec digest the outcome names.",
		s.sign(s.recordReceipt(recordDisclosure{NoDecision: true})))

	m = s.recordReceipt(recordDisclosure{NoDecision: true})
	recordPayload(m, 1)["outcome_body"] = recordOutcomeText("failed")
	s.add("switchtender-outcome-exact-altered", false, "", "record",
		"A receipt whose exact-form outcome was changed and re-signed fails, because the bytes "+
			"carried no longer reproduce the digest the entry committed and the link fixed.", s.sign(m))

	s.add("switchtender-outcome-legacy", true, "signed, chained (full)", "",
		"An outcome committed under an older form, over the producer's own redaction of the "+
			"record, verifies as carried and unchecked, never as verified, and the spec beside it "+
			"has nothing verified to be held against.",
		s.sign(s.recordReceipt(recordDisclosure{NoDecision: true, LegacyOutcome: true})))
	s.expect("switchtender-outcome-legacy",
		[]string{"claim 1 outcome_body", "claim 1 outcome_nonce", "claim 1 spec_body"}, nil)

	m = s.recordReceipt(recordDisclosure{NoDecision: true})
	recordPayload(m, 1)["spec_body"] = `{"command":"deploy --force","tool":"bash"}`
	s.add("switchtender-outcome-spec-altered", false, "", "record",
		"A receipt with no decision whose disclosed spec was changed and re-signed fails, because "+
			"the spec no longer hashes to the spec digest the verified outcome names.", s.sign(m))

	s.add("switchtender-record-specs-agree", true, "signed, chained (full)", "",
		"A decision that commits a spec digest and an exact-form outcome that names the same digest "+
			"verify with no spec disclosed: the two committed digests agree, which is the receipt "+
			"of one run.", s.sign(s.recordReceipt(recordDisclosure{Reason: "text", NoSpec: true})))

	s.add("switchtender-record-specs-disagree", false, "", "record",
		"A decision that commits one spec digest beside an exact-form outcome of the same run that "+
			"names another fails with no spec disclosed: a run's decision and outcome name one "+
			"spec, and leaving the optional spec_body out does not hide that.",
		s.sign(s.recordReceipt(recordDisclosure{Reason: "text", NoSpec: true,
			OutcomeSpec: specDigestOf(`{"command":"deploy --force --prod","tool":"bash"}`)})))

	run := recordPayloads(recordDisclosure{Reason: "text", NoSpec: true})
	run = append(run[:2:2], append(recordOtherRunPayloads(), run[2])...)
	m = s.switchTenderChainOf(run)
	m["subject"] = map[string]any{"type": "host", "id": "vectors-host"}
	s.add("switchtender-record-specs-two-runs", true, "signed, chained (full)", "",
		"The records of two runs share one bundle, each run's decision and outcome naming that "+
			"run's own spec, with no spec disclosed. A decision is held only against the outcomes of "+
			"its own run, named by its body's run_id and by the run segment of the outcome's path, "+
			"so two runs with different specs verify.", s.sign(m))
}

// recordDisclosure shapes the receipt recordReceipt builds.
type recordDisclosure struct {
	// Reason is how the decision's reason travels: text, redacted, withheld, or empty for a
	// decision recorded without one.
	Reason string
	// Correction adds an entry correcting the decision's reason.
	Correction bool
	// Unkeyed records the decision with the unkeyed content digest of an entry written before
	// nonces, which also predates reasons.
	Unkeyed bool
	// NoDecision leaves the decision out, a run that needed no approval.
	NoDecision bool
	// LegacyOutcome commits the outcome under the older keyed form, over the canonical record rather
	// than the exact bytes carried.
	LegacyOutcome bool
	// KeyedCreation commits the request that created the run under the keyed form, so every entry
	// after it postdates the keyed form.
	KeyedCreation bool
	// NoSpec leaves spec_body off the outcome claim, a receipt that discloses no spec.
	NoSpec bool
	// OutcomeSpec is the spec digest the outcome record names, or empty for the run's own spec.
	OutcomeSpec string
}

// recordReceipt builds a SwitchTender run receipt on switchtender-audit-v1 from the payloads
// recordPayloads shapes. Each link recomputes from its payload's bound fields, so only the
// disclosed members can disagree with what the chain committed.
func (s *state) recordReceipt(d recordDisclosure) map[string]any {
	return s.switchTenderChainOf(recordPayloads(d))
}

// recordPayloads shapes the claim payloads of a SwitchTender run receipt, in chain order: the
// request that created the run, the approval decision unless the run needed none, an optional
// correction to its reason, and the outcome, which carries the spec and the outcome record.
func recordPayloads(d recordDisclosure) []map[string]any {
	specDigest := specDigestOf(recordSpec)

	decision := map[string]any{"run_id": recordRun, "verdict": "approved", "spec_digest": specDigest}
	decisionPayload := map[string]any{
		"actor": "ops-admin", "actor_type": "session", "on_behalf_of": "ops-admin",
		"method": "DECISION", "path": "/runs/" + recordRun + "/decision/approved",
	}
	if d.Unkeyed {
		decisionPayload["content_digest"] = unkeyedRecordDigest(decision)
		decisionPayload["decision_nonce"] = ""
	} else {
		random := hex.EncodeToString(recordBytes("random decision"))
		decision["decision_id"] = "aud_decision"
		decision["reason_commitment"] = reasonCommitment("aud_decision", random, recordReason)
		decision["separation_of_duties"] = map[string]any{
			"required": true, "requester": "dev-lead", "decider": "ops-admin",
			"independent": true, "result": "satisfied",
		}
		nonce := recordBytes("nonce decision")
		decisionPayload["content_digest"] = keyedRecordDigest(nonce, decision)
		decisionPayload["decision_nonce"] = hex.EncodeToString(nonce)
		switch d.Reason {
		case "text":
			decisionPayload["reason_text"] = recordReason
			decisionPayload["reason_random"] = random
		case "redacted":
			decisionPayload["reason_redacted"] = "personal_data"
		}
	}
	decisionPayload["decision_body"] = decision

	payloads := []map[string]any{{
		"actor": "deploy-bot", "actor_type": "agent", "on_behalf_of": "dev-lead",
		"method": "POST", "path": "/v1/runs",
	}}
	if d.KeyedCreation {
		payloads[0]["content_digest"] = keyedRecordDigest(recordBytes("nonce request"),
			map[string]any{"command": "deploy", "tool": "bash"})
	}
	if !d.NoDecision {
		payloads = append(payloads, decisionPayload)
	}

	if d.Correction {
		const correctionText = "approved after the change review, with the rollback plan attached"
		random := hex.EncodeToString(recordBytes("random correction"))
		correction := map[string]any{
			"run_id": recordRun, "decision_id": "aud_decision", "correction_id": "aud_correction",
			"reason_commitment": reasonCommitment("aud_correction", random, correctionText),
		}
		nonce := recordBytes("nonce correction")
		path := "/runs/" + recordRun + "/decisions/aud_decision/corrections/aud_correction"
		payloads = append(payloads, map[string]any{
			"actor": "ops-admin", "actor_type": "session", "on_behalf_of": "ops-admin",
			"method": "REASON", "path": path, "content_digest": keyedRecordDigest(nonce, correction),
			"correction_body": correction, "correction_nonce": hex.EncodeToString(nonce),
			"reason_text": correctionText, "reason_random": random,
		})
	}

	outcomeSpec := d.OutcomeSpec
	if outcomeSpec == "" {
		outcomeSpec = specDigest
	}
	outcomeText := recordOutcomeTextNaming("succeeded", outcomeSpec)
	nonce := recordBytes("nonce outcome")
	digest := exactRecordDigest(nonce, []byte(outcomeText))
	if d.LegacyOutcome {
		var outcome map[string]any
		if err := json.Unmarshal([]byte(outcomeText), &outcome); err != nil {
			panic(err)
		}
		digest = keyedRecordDigest(nonce, outcome)
	}
	outcomePayload := map[string]any{
		"actor": "system:dispatcher", "actor_type": "system", "on_behalf_of": "deploy-bot",
		"method": "RUN", "path": "/runs/" + recordRun + "/outcome/succeeded",
		"content_digest": digest,
		"outcome_body":   outcomeText, "outcome_nonce": hex.EncodeToString(nonce),
	}
	if !d.NoSpec {
		outcomePayload["spec_body"] = recordSpec
	}
	return append(payloads, outcomePayload)
}

// recordOtherRun is a second run whose records share a bundle with recordRun's.
const recordOtherRun = "run_vectors_other"

// recordOtherSpec is recordOtherRun's spec, which differs from recordRun's.
const recordOtherSpec = `{"command":"migrate","tool":"bash"}`

// recordOtherRunPayloads shapes recordOtherRun's approval decision and its exact-form outcome, both
// naming recordOtherSpec's digest, with no reason and no spec disclosed.
func recordOtherRunPayloads() []map[string]any {
	specDigest := specDigestOf(recordOtherSpec)
	decision := map[string]any{
		"run_id": recordOtherRun, "decision_id": "aud_decision_other", "verdict": "approved",
		"spec_digest": specDigest,
	}
	decisionNonce := recordBytes("nonce decision other")
	outcomeText, err := jcs.Serialize(map[string]any{
		"run_id": recordOtherRun, "status": "succeeded", "exit_code": int64(0),
		"spec_digest": specDigest,
	})
	if err != nil {
		panic(err)
	}
	outcomeNonce := recordBytes("nonce outcome other")
	return []map[string]any{{
		"actor": "ops-admin", "actor_type": "session", "on_behalf_of": "ops-admin",
		"method": "DECISION", "path": "/runs/" + recordOtherRun + "/decision/approved",
		"content_digest": keyedRecordDigest(decisionNonce, decision),
		"decision_body":  decision, "decision_nonce": hex.EncodeToString(decisionNonce),
	}, {
		"actor": "system:dispatcher", "actor_type": "system", "on_behalf_of": "deploy-bot",
		"method": "RUN", "path": "/runs/" + recordOtherRun + "/outcome/succeeded",
		"content_digest": exactRecordDigest(outcomeNonce, outcomeText),
		"outcome_body":   string(outcomeText), "outcome_nonce": hex.EncodeToString(outcomeNonce),
	}}
}

// specDigestOf is sha256: and the hex SHA-256 of a spec text's UTF-8 bytes.
func specDigestOf(spec string) string {
	sum := sha256.Sum256([]byte(spec))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// recordOutcomeText is the run's outcome record naming the run's own spec, as a producer fixes it
// before committing: reduced to canonical bytes once, so the bytes committed under the exact form
// are the bytes disclosed.
func recordOutcomeText(status string) string {
	return recordOutcomeTextNaming(status, specDigestOf(recordSpec))
}

// recordOutcomeTextNaming is the run's outcome record naming the spec digest given, in the
// canonical bytes a producer commits under the exact form.
func recordOutcomeTextNaming(status, specDigest string) string {
	text, err := jcs.Serialize(map[string]any{
		"run_id": recordRun, "status": status, "exit_code": int64(0), "spec_digest": specDigest,
	})
	if err != nil {
		panic(err)
	}
	return string(text)
}

// exactRecordDigest computes the exact-form content digest a producer commits a disclosed text
// under: sha256e:, the hex SHA-256 of the nonce, and the hex HMAC-SHA256 of the text's bytes keyed
// by the nonce.
func exactRecordDigest(nonce, text []byte) string {
	nonceSum := sha256.Sum256(nonce)
	mac := hmac.New(sha256.New, nonce)
	mac.Write(text)
	return "sha256e:" + hex.EncodeToString(nonceSum[:]) + ":" + hex.EncodeToString(mac.Sum(nil))
}

// switchTenderChainOf builds a switchtender-audit-v1 bundle whose claims carry the payloads in
// order, each linked over its bound fields to the one before it.
func (s *state) switchTenderChainOf(payloads []map[string]any) map[string]any {
	times := make([]string, len(payloads))
	for i := range times {
		times[i] = at
	}
	return s.switchTenderChainAt(payloads, times)
}

// switchTenderChainAt is switchTenderChainOf with each claim's time given.
func (s *state) switchTenderChainAt(payloads []map[string]any, times []string) map[string]any {
	m := s.base()
	m["subject"] = map[string]any{"type": "run", "id": recordRun}
	claims := make([]any, 0, len(payloads))
	prev := ""
	for i, p := range payloads {
		seq := int64(i + 1)
		link := switchTenderPayloadLink(seq, times[i], prev, p)
		claims = append(claims, map[string]any{
			"type": "switchtender.audit/1", "at": times[i], "payload": p,
			"chain": map[string]any{"seq": seq, "prev": prev, "link": link},
		})
		prev = link
	}
	m["claims"] = claims
	m["chain"] = map[string]any{
		"profile": profileSwitchTender, "keyed": false,
		"head": map[string]any{"seq": int64(len(payloads)), "link": prev},
	}
	return m
}

// switchTenderPayloadLink recomputes a switchtender-audit-v1 link from a payload the way a verifier
// does: actor, method, and path always, and actor_type, on_behalf_of, content_digest, and
// install_id when the payload carries them. A disclosed member is never part of it.
func switchTenderPayloadLink(seq int64, atStr, prev string, payload map[string]any) string {
	fields := map[string]any{
		"seq": seq, "at": atStr, "prev": prev,
		"actor": payload["actor"], "method": payload["method"], "path": payload["path"],
	}
	for _, key := range []string{"actor_type", "on_behalf_of", "content_digest", "install_id"} {
		if v, _ := payload[key].(string); v != "" {
			fields[key] = v
		}
	}
	b, err := jcs.Serialize(fields)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// recordPayload returns the payload of claim i of a record receipt, so a vector can alter one
// disclosed member before re-signing.
func recordPayload(m map[string]any, i int) map[string]any {
	return m["claims"].([]any)[i].(map[string]any)["payload"].(map[string]any)
}

// recordBytes returns 32 deterministic bytes for a label, standing in for the random nonce or
// value a producer draws, so the vectors stay byte-stable across runs.
func recordBytes(label string) []byte {
	sum := sha256.Sum256([]byte("loomseal vectors " + label))
	return sum[:]
}

// keyedRecordDigest computes the keyed content digest SwitchTender commits a record under:
// sha256s:, the hex SHA-256 of the nonce, and the hex HMAC-SHA256 of the record's canonical bytes
// keyed by the nonce.
func keyedRecordDigest(nonce []byte, record map[string]any) string {
	canonical, err := jcs.Serialize(record)
	if err != nil {
		panic(err)
	}
	nonceSum := sha256.Sum256(nonce)
	mac := hmac.New(sha256.New, nonce)
	mac.Write(canonical)
	return "sha256s:" + hex.EncodeToString(nonceSum[:]) + ":" + hex.EncodeToString(mac.Sum(nil))
}

// unkeyedRecordDigest computes the unkeyed content digest an entry recorded before nonces carries:
// sha256: and the hex SHA-256 of the record's canonical bytes.
func unkeyedRecordDigest(record map[string]any) string {
	canonical, err := jcs.Serialize(record)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// reasonCommitment computes the hiding commitment to a reason: sha256: and the hex SHA-256 of the
// canonical object {"event", "random", "reason"}.
func reasonCommitment(event, random, text string) string {
	canonical, err := jcs.Serialize(map[string]any{"event": event, "random": random, "reason": text})
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// memberDeclaration is the part of schema/claim-members.json the tamper vectors are generated from.
type memberDeclaration struct {
	// Records identifies the kinds of record a switchtender.audit/1 claim can be.
	Records struct {
		// Kinds are the record kinds by name, each a committed method and a path pattern.
		Kinds map[string]struct {
			// Method is the committed method.
			Method string `json:"method"`
			// Path is the committed path's pattern.
			Path string `json:"path"`
		} `json:"kinds"`
	} `json:"records"`
	// SwitchTender names the members a switchtender-audit-v1 link commits.
	SwitchTender struct {
		// Bound are the members the link commits.
		Bound []string `json:"bound"`
	} `json:"switchtender-audit-v1"`
	// Types declares each claim type's members.
	Types map[string]map[string]struct {
		// State is checked, unchecked, or redacted.
		State string `json:"state"`
		// Unchecked says when a member declared checked is unchecked instead.
		Unchecked string `json:"unchecked"`
		// With names the member this one travels with.
		With string `json:"with"`
		// Records names the record kinds whose claims read the member.
		Records []string `json:"records"`
	} `json:"types"`
}

// recordKindOf names the record kind a switchtender.audit/1 payload is by the declaration alone:
// its committed method, and its committed path segment by segment, a {name} segment matching any
// non-empty one. It returns empty for a claim that is no record.
func (d memberDeclaration) recordKindOf(payload map[string]any) string {
	method, _ := payload["method"].(string)
	path, _ := payload["path"].(string)
	for name, kind := range d.Records.Kinds {
		if method != kind.Method {
			continue
		}
		if kind.Path == "" {
			return name
		}
		want, got := strings.Split(kind.Path, "/"), strings.Split(path, "/")
		if len(want) != len(got) {
			continue
		}
		match := true
		for i, w := range want {
			placeholder := strings.HasPrefix(w, "{") && strings.HasSuffix(w, "}")
			if (placeholder && got[i] == "") || (!placeholder && w != got[i]) {
				match = false
			}
		}
		if match {
			return name
		}
	}
	return ""
}

// reads reports whether a verifier reads member, by its exact name, on a claim of claimType with
// payload under switchtender-audit-v1: a record member on a claim of its own record's kind, and a
// span member on a span claim, whose members its path binds.
func (d memberDeclaration) reads(claimType, member string, payload map[string]any) bool {
	decl, ok := d.Types[claimType][member]
	switch {
	case !ok:
		return false
	case claimType == "loomseal.span/1":
		return true
	case len(decl.Records) > 0:
		return slices.Contains(decl.Records, d.recordKindOf(payload))
	}
	return false
}

// tamperBase is an honest bundle a tamper vector alters one member of.
type tamperBase struct {
	// build returns a fresh copy of the bundle map.
	build func() map[string]any
	// older reports that the base commits its outcome under an older digest form, so the members
	// declared unchecked under that condition are unchecked in it.
	older bool
}

// tampers generates, from schema/claim-members.json, one vector for every member a
// switchtender-audit-v1 link does not commit: an honest bundle carrying the member, altered and
// re-signed with the producer's own key, the threat the declaration exists for. A member declared
// checked must fail, a member declared unchecked or redacted must verify with the bundle's every
// such member reported so, and a member declared checked but unchecked under a condition also gets
// a vector where the condition holds. The vectors are generated rather than written by hand, so a
// member added to the declaration is tested by the next generator run, and the drift check fails
// any checkout whose vectors were not regenerated.
func (s *state) tampers() {
	raw, err := os.ReadFile("schema/claim-members.json")
	if err != nil {
		panic(err)
	}
	var decl memberDeclaration
	if err := json.Unmarshal(raw, &decl); err != nil {
		panic(err)
	}
	bases := map[string][]tamperBase{
		"switchtender.audit/1": {
			{build: func() map[string]any {
				return s.recordReceipt(recordDisclosure{Reason: "text", Correction: true})
			}},
			{build: func() map[string]any { return s.recordReceipt(recordDisclosure{Reason: "redacted"}) }},
			{build: func() map[string]any {
				return s.recordReceipt(recordDisclosure{NoDecision: true, LegacyOutcome: true})
			}, older: true},
		},
		"loomseal.span/1":         {{build: s.switchTenderSpans}},
		"loomseal.agentrun/1":     {{build: s.typedBuilder("loomseal.agentrun/1")}},
		"whodar.knowledge-risk/1": {{build: s.typedBuilder("whodar.knowledge-risk/1")}},
	}
	types := make([]string, 0, len(decl.Types))
	for t := range decl.Types {
		types = append(types, t)
	}
	sort.Strings(types)
	for _, t := range types {
		members := make([]string, 0, len(decl.Types[t]))
		for m := range decl.Types[t] {
			members = append(members, m)
		}
		sort.Strings(members)
		for _, member := range members {
			older := []bool{false}
			if d := decl.Types[t][member]; d.Unchecked != "" ||
				(d.With != "" && decl.Types[t][d.With].Unchecked != "") {
				older = append(older, true)
			}
			for _, cond := range older {
				s.tamper(decl, t, member, bases[t], cond)
			}
			s.tamperCase(decl, t, member, bases[t], caseVariantName(member), "case")
			if variant, ok := foldVariantName(member); ok {
				s.tamperCase(decl, t, member, bases[t], variant, "fold")
			}
		}
	}
}

// caseVariantName returns member with its first letter in upper case: a different name to an exact
// reader, and the same name to one that folds case, as encoding/json does onto a struct field.
func caseVariantName(member string) string {
	return strings.ToUpper(member[:1]) + member[1:]
}

// foldVariantName returns member with its first s or k replaced by the one non-ASCII letter that
// folds onto it, the long s or the Kelvin sign, and reports false for a member with neither. It
// pins that every verifier folds the way the format says, beyond ASCII capitals.
func foldVariantName(member string) (string, bool) {
	for i, c := range member {
		switch c {
		case 's':
			return member[:i] + "\u017f" + member[i+1:], true
		case 'k':
			return member[:i] + "\u212a" + member[i+1:], true
		}
	}
	return "", false
}

// tamperCase emits the vector for one member's case variant: the first base carrying the member,
// with a member whose name differs from it only in case planted beside it, holding an altered
// value, and re-signed. A claim whose check reads the member must fail, since a reader folding case
// would take the variant for it. On any other claim the variant is one more member, reported
// unchecked.
func (s *state) tamperCase(decl memberDeclaration, claimType, member string, bases []tamperBase,
	variant, suffix string) {
	for _, base := range bases {
		m := base.build()
		for i, c := range m["claims"].([]any) {
			claim := c.(map[string]any)
			payload := claim["payload"].(map[string]any)
			value, ok := payload[member]
			if claim["type"] != claimType || !ok {
				continue
			}
			payload[variant] = alter(copyValue(value))
			name := "tamper-" + strings.NewReplacer(".", "-", "/", "-").Replace(claimType) + "-" +
				member + "-" + suffix
			why := fmt.Sprintf("Claim %d carries %q beside %s, a name that differs from it only "+
				"in case, planted by the producer and re-signed, and ", i, variant, member)
			if decl.reads(claimType, member, payload) {
				failing := "record"
				if claimType == "loomseal.span/1" {
					failing = "span"
				}
				s.add(name, false, "", failing, why+"fails, since a reader folding case would take "+
					"one for the other.", s.sign(m))
				return
			}
			unchecked, redacted := tamperExpectations(decl, m, base.older)
			s.add(name, true, "signed, chained (full)", "", why+"verifies with it reported "+
				"unchecked, since nothing reads the member on this claim.", s.sign(m))
			s.expect(name, unchecked, redacted)
			return
		}
	}
	panic("tamperCase: no base carries " + claimType + " " + member)
}

// tamper emits the vector for one member under one condition: the first base carrying the member
// under that condition, the member altered, re-signed.
func (s *state) tamper(decl memberDeclaration, claimType, member string, bases []tamperBase,
	older bool) {
	for _, base := range bases {
		if base.older != older {
			continue
		}
		m := base.build()
		claims := m["claims"].([]any)
		for i, c := range claims {
			claim := c.(map[string]any)
			payload := claim["payload"].(map[string]any)
			if claim["type"] != claimType {
				continue
			}
			value, ok := payload[member]
			if !ok {
				continue
			}
			payload[member] = alter(value)
			name := "tamper-" + strings.NewReplacer(".", "-", "/", "-").Replace(claimType) + "-" + member
			if older {
				name += "-older"
			}
			unchecked, redacted := tamperExpectations(decl, m, base.older)
			state := effectiveState(decl, claimType, member, base.older)
			why := fmt.Sprintf("Claim %d's %s, altered and re-signed by the producer, ", i, member)
			switch state {
			case "checked":
				failing := "record"
				if claimType == "loomseal.span/1" {
					failing = "span"
				}
				s.add(name, false, "", failing, why+"fails the commitment it is checked against.",
					s.sign(m))
			default:
				s.add(name, true, "signed, chained (full)", "", why+"verifies with the member "+
					"reported "+state+", as schema/claim-members.json declares.", s.sign(m))
				s.expect(name, unchecked, redacted)
			}
			return
		}
	}
	panic("tamper: no base carries " + claimType + " " + member)
}

// effectiveState is a member's declared state in a base: a member declared checked but unchecked
// under a condition is unchecked where the condition holds, and a member travels in the state of
// the one it travels with.
func effectiveState(decl memberDeclaration, claimType, member string, older bool) string {
	d := decl.Types[claimType][member]
	if d.With != "" {
		return effectiveState(decl, claimType, d.With, older)
	}
	if older && d.Unchecked != "" {
		return "unchecked"
	}
	return d.State
}

// tamperExpectations lists, as "claim N member", every member of the bundle's claims a verifier
// must report unchecked and redacted, from the declaration alone, never from what a verifier does.
func tamperExpectations(decl memberDeclaration, m map[string]any, older bool) (unchecked,
	redacted []string) {
	bound := map[string]bool{}
	for _, name := range decl.SwitchTender.Bound {
		bound[name] = true
	}
	for i, c := range m["claims"].([]any) {
		claim := c.(map[string]any)
		claimType, _ := claim["type"].(string)
		names := make([]string, 0)
		for name := range claim["payload"].(map[string]any) {
			if !bound[name] {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		payload := claim["payload"].(map[string]any)
		kind := decl.recordKindOf(payload)
		for _, name := range names {
			entry := fmt.Sprintf("claim %d %s", i, name)
			member, declared := decl.Types[claimType][name]
			state := effectiveState(decl, claimType, name, older)
			switch {
			case !declared:
				state = "unchecked"
			case len(member.Records) > 0 && !slices.Contains(member.Records, kind):
				state = "unchecked"
			}
			switch state {
			case "unchecked":
				unchecked = append(unchecked, entry)
			case "redacted":
				redacted = append(redacted, entry)
			}
		}
	}
	return unchecked, redacted
}

// alter changes a value in a way that keeps its shape: the last hex digit of a hex string flipped,
// the last letter of any other string moved one along, an integer increased, a boolean negated,
// and an object or array changed in its first altered member, so a verifier that checks the value
// cannot pass it for a format reason rather than a commitment.
func alter(v any) any {
	switch t := v.(type) {
	case string:
		b := []byte(t)
		for i := len(b) - 1; i >= 0; i-- {
			if c, ok := nextChar(b[i]); ok {
				b[i] = c
				return string(b)
			}
		}
		return t + "x"
	case int64:
		return t + 1
	case int:
		return t + 1
	case bool:
		return !t
	case map[string]any:
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if _, isString := t[k].(string); isString {
				t[k] = alter(t[k])
				return t
			}
		}
		if len(keys) > 0 {
			t[keys[0]] = alter(t[keys[0]])
		}
		return t
	case []any:
		if len(t) > 0 {
			t[0] = alter(t[0])
		}
		return t
	}
	return v
}

// copyValue returns a deep copy of a decoded JSON value, so altering the copy leaves the original.
func copyValue(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = copyValue(e)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = copyValue(e)
		}
		return out
	}
	return v
}

// nextChar returns a different character of the same kind for a lowercase letter or a digit, so a
// hex digit stays a hex digit and a hex value stays well formed.
func nextChar(c byte) (byte, bool) {
	switch {
	case c == '9', c == 'f', c == 'z':
		return c - 1, true
	case c >= '0' && c <= '8', c >= 'a' && c <= 'y':
		return c + 1, true
	}
	return 0, false
}

// switchTenderSpans builds a switchtender-audit-v1 chain carrying two span beats the way
// SwitchTender writes them: the members beside the link, and the same values in the path the link
// commits.
func (s *state) switchTenderSpans() map[string]any {
	beat := func(n, count int64) map[string]any {
		return map[string]any{
			"actor": "span", "method": "SPAN",
			"path":   fmt.Sprintf("/span/%d?count=%d&cadence_s=60", n, count),
			"stream": "chain", "cadence_s": int64(60), "beat": n, "count": count,
		}
	}
	m := s.switchTenderChainAt([]map[string]any{
		{"actor": "release-token", "method": "POST", "path": "/api/runs"},
		beat(1, 1),
		{"actor": "release-token", "method": "POST", "path": "/api/runs"},
		beat(2, 1),
	}, []string{"2026-07-27T15:00:00Z", "2026-07-27T15:00:10Z", "2026-07-27T15:00:20Z",
		"2026-07-27T15:00:30Z"})
	for _, i := range []int{1, 3} {
		m["claims"].([]any)[i].(map[string]any)["type"] = "loomseal.span/1"
	}
	return m
}

// typedBuilder returns a builder of switchTenderTyped for a claim type.
func (s *state) typedBuilder(claimType string) func() map[string]any {
	return func() map[string]any { return s.switchTenderTyped(claimType) }
}

// switchTenderTyped builds a switchtender-audit-v1 chain with one claim of a registered type whose
// members such a link does not commit.
func (s *state) switchTenderTyped(claimType string) map[string]any {
	payloads := map[string]map[string]any{
		"loomseal.agentrun/1": {"session": "sess_vectors", "tool": "shell", "args": "make release",
			"outcome": "succeeded"},
		"whodar.knowledge-risk/1": {"finding": "single maintainer", "topics_scored": int64(4),
			"critical": int64(1)},
	}
	p := map[string]any{"actor": "release-token", "method": "POST", "path": "/api/runs"}
	for k, v := range payloads[claimType] {
		p[k] = v
	}
	m := s.switchTenderChainOf([]map[string]any{p})
	m["claims"].([]any)[0].(map[string]any)["type"] = claimType
	return m
}
