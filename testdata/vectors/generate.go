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
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
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
	// parse, signature, chain, anchor, or span.
	FailingCheck string `json:"failing_check,omitempty"`
	// Why explains the case in one sentence.
	Why string `json:"why"`
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
	log := merkleLog(size)
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
