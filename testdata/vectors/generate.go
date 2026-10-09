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
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	mathrand "math/rand/v2"
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
	// Level is the expected conformance wording: the level achieved when MustVerify is true, and
	// otherwise "not verified", or "unsupported" for a bundle the verifier does not implement. A
	// failing report never names a level it reached partway.
	Level string `json:"level,omitempty"`
	// FailingCheck names the verification step that must fail when MustVerify is false: one of
	// parse, signature, chain, anchor, span, disclosure, attestation, install, record, evidence,
	// or unsupported.
	FailingCheck string `json:"failing_check,omitempty"`
	// Why explains the case in one sentence.
	Why string `json:"why"`
	// Evidence is whether a verifier is given this directory as its evidence directory for the
	// case. A verifier that cannot read evidence, such as the browser build, skips such a case.
	Evidence bool `json:"evidence,omitempty"`
	// UnknownSubjectType is the subject type a verifier must report as outside its vocabulary in a
	// bundle that must verify. Empty means the type is in the vocabulary and none may be reported.
	UnknownSubjectType string `json:"unknown_subject_type,omitempty"`
	// Unchecked lists, as "claim N member", every member a switchtender-audit-v1 link does not commit
	// that a verifier must report unchecked in a bundle that must verify. Empty means none may be.
	Unchecked []string `json:"unchecked,omitempty"`
	// Redacted lists, the same way, every such member a verifier must report redacted.
	Redacted []string `json:"redacted,omitempty"`
	// Legacy lists, the same way, every record body a verifier must report verified under the
	// legacy unkeyed digest form. Empty means none may be.
	Legacy []string `json:"legacy,omitempty"`
	// SpanCoverage is the coverage line a verifier must report for a bundle that must verify, such
	// as "2/4 windows attested". Empty means the bundle carries no span claims.
	SpanCoverage string `json:"span_coverage,omitempty"`
	// SpanLongestGap is the longest gap a verifier must report, in whole seconds such as "150s".
	// Empty means no gap may be reported.
	SpanLongestGap string `json:"span_longest_gap,omitempty"`
	// SpanGaps lists, in order, every gap line a verifier must report. Empty means none may be.
	SpanGaps []string `json:"span_gaps,omitempty"`
	// AnchorAttestations lists, in order, the line a verifier must report for each timestamp token
	// it verified: the token's genTime to the second, "by", and the signer named by the rule
	// FORMAT.md states. Empty means none may be reported.
	AnchorAttestations []string `json:"anchor_attestations,omitempty"`
	// AnchorProofsUnopened is how many carried proofs a verifier must report as of a type it cannot
	// open offline. A verifier is held to it on every vector that carries it, whether or not the
	// bundle must verify, and to zero on a vector that must verify and does not carry it.
	AnchorProofsUnopened *int `json:"anchor_proofs_unopened,omitempty"`
	// AnchorProofsOnDeclaredHead is how many proofs a verifier must report on anchors that match
	// only the unverified declared head, held the same way as AnchorProofsUnopened.
	AnchorProofsOnDeclaredHead *int `json:"anchor_proofs_on_declared_head,omitempty"`
}

// presentationManifest is the conformance document for holder presentations.
type presentationManifest struct {
	// Description says what the file is.
	Description string `json:"description"`
	// Vectors are the individual presentation cases.
	Vectors []presentationVector `json:"vectors"`
}

// presentationVector is one presentation conformance case. Audience and nonce are the caller's
// expectations, so the same file can appear more than once under different pins. An absent
// expectation is none, and one present and empty is an expectation supplied empty, which an entry
// point able to tell the two apart refuses.
type presentationVector struct {
	// Name identifies the case.
	Name string `json:"name"`
	// File is the presentation file name within this directory.
	File string `json:"file"`
	// ExpectAudience is the audience the verifier is told to require, nil to skip the pin.
	ExpectAudience *string `json:"expect_audience,omitempty"`
	// ExpectNonce is the challenge the verifier is told to require, nil to skip the pin.
	ExpectNonce *string `json:"expect_nonce,omitempty"`
	// MustVerify is whether a conformant verifier must report the presentation verified.
	MustVerify bool `json:"must_verify"`
	// FailingCheck names the first check, in the order FORMAT.md's "Presentations" section gives,
	// that a presentation which must not verify fails: expectation, parse, unsupported, bundle,
	// presentation, audience, or nonce.
	FailingCheck string `json:"failing_check,omitempty"`
	// RoutesAsBundle marks a document an entry point taking either kind of document reads as a
	// bundle, because it is not a JSON object whose loomseal_presentation member is a string.
	RoutesAsBundle bool `json:"routes_as_bundle,omitempty"`
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
	s.subjects()
	s.evidence()
	s.agreement()
	s.times()
	s.genTimes()
	s.tokenStructure()
	s.derRules()
	s.derTags()
	s.readOrder()
	s.unopenedProofs()
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
	s.expectOnDeclaredHead("anchor-declared-head-proof", 1)

	// Sub-microsecond claim time. A verifier that parses the time into its language's own type and
	// formats it back loses digits wherever that type is not nanosecond-capable, and reports an
	// intact bundle as a broken chain. Hashing the stored bytes is what makes this verify.
	// A real timestamp token over this vector's own link. A verifier that carries proofs without
	// opening them reports this at the weaker "by reference" level and fails the suite.
	s.add("switchtender-audit-anchored-proof", true, "signed, chained (full), anchored (proof verified)", "",
		"An rfc3161 anchor carrying a real timestamp token verifies offline against the link it "+
			"attests to, with no network and no trust in the producer.",
		s.sign(s.switchTenderProof()))
	// The fixture's subject carries an emailAddress and a description, types RFC 4514 has no short
	// name for, so both are written in dotted form with their values in hexadecimal.
	s.expectAttested("switchtender-audit-anchored-proof", "2026-08-10T04:57:09Z by ST=Bayern,C=DE,"+
		"L=Wuerzburg,1.2.840.113549.1.9.1=#1615627573696c657a6173406d61696c626f782e6f7267,"+
		"CN=www.freetsa.org,2.5.4.13=#0c6d54686973206365727469666963617465206469676974616c6c7920"+
		"7369676e7320646f63756d656e747320616e642074696d65207374616d70207265717565737473206d61"+
		"6465207573696e672074686520667265657473612e6f7267206f6e6c696e65207365727669636573,"+
		"OU=TSA,O=Free TSA")

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
	// follow the attacker; one that treats alg as a label rejects the bundle. Every shipped
	// verifier refuses the foreign alg as one it does not implement, before judging the
	// signature, so the level it reports is the unsupported word.
	s.add("signature-alg-rewritten", false, "unsupported", "signature",
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
	s.expectSubject("subject-unknown-type", "control")
}

// knownSubjectTypes is the subject vocabulary FORMAT.md states. It is written here rather than read
// from a verifier, so the vectors hold every verifier to the specification, not to each other.
var knownSubjectTypes = []string{"url", "fleet", "repo", "agent", "host", "run", "org"}

// subjects emits one verifying bundle per known subject type, each expecting no unknown subject in
// the report. Every member of the vocabulary is pinned, so a verifier whose list lacks any one of
// them reports it unknown and fails its vector.
func (s *state) subjects() {
	for _, typ := range knownSubjectTypes {
		m := s.v1(1, false)
		m["subject"] = map[string]any{"type": typ, "id": "known-" + typ}
		name := "subject-known-" + typ
		s.add(name, true, "signed, chained (full)", "",
			"The subject type "+typ+" is in the vocabulary FORMAT.md states, so a verifier reports "+
				"no unknown subject type for it.", s.sign(m))
	}
}

// evidenceAlteredFile is the artifact the evidence vector locates, written beside the vectors with
// bytes that differ from the ones its claim sealed.
const evidenceAlteredFile = "evidence-altered-snapshot.html"

// evidence emits a record receipt whose first claim locates an artifact that no longer matches its
// sealed digest, checked with this directory as the evidence directory. Every other check passes,
// and the evidence check records its problem without stopping, so the case pins that a failure
// found last still leaves the level "not verified" and lists no disclosed member, in a verifier
// that stops at its first failure and in one that runs every check.
func (s *state) evidence() {
	altered := []byte("<p>snapshot, altered after sealing</p>\n")
	if err := os.WriteFile(filepath.Join(dir, evidenceAlteredFile), altered, 0o600); err != nil {
		panic(err)
	}
	sealed := sha256.Sum256([]byte("<p>snapshot as sealed</p>\n"))
	m := s.recordReceipt(recordDisclosure{Reason: "text", Correction: true})
	claim, _ := m["claims"].([]any)[0].(map[string]any)
	claim["evidence"] = []any{map[string]any{
		"role": "snapshot", "digest": "sha256:" + hex.EncodeToString(sealed[:]),
		"media_type": "text/html", "location": evidenceAlteredFile,
	}}
	name := "evidence-altered-record"
	s.add(name, false, "", "evidence",
		"An artifact at its declared location whose bytes no longer hash to the sealed digest fails "+
			"the bundle, which then reports no level and no disclosed member, though every check "+
			"before the evidence check passed.", s.sign(m))
	s.man.Vectors[len(s.man.Vectors)-1].Evidence = true
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

// maxCadenceS is the widest cadence a span claim may declare, the seconds in a 366-day year.
const maxCadenceS = 366 * 24 * 60 * 60

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
	// cadence is the span claim's declared cadence in seconds. Zero means 60.
	cadence int64
	// members replaces span payload members with values of any JSON type.
	members map[string]any
}

// spanBundle builds an unkeyed loomseal-chain-v1 bundle from entries and anchors its head, so
// the spanned conformance word is reachable.
func (s *state) spanBundle(entries []spanEntry) map[string]any {
	m := s.base()
	claims := make([]any, len(entries))
	for i, e := range entries {
		var c map[string]any
		if e.kind == "span" {
			cadence := e.cadence
			if cadence == 0 {
				cadence = 60
			}
			payload := map[string]any{
				"stream": "chain", "cadence_s": cadence, "beat": e.beat, "count": e.count,
			}
			for name, v := range e.members {
				payload[name] = v
			}
			c = map[string]any{"type": "loomseal.span/1", "at": e.at, "payload": payload}
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

// spans emits the population attestation vectors: valid, gapped, adopted mid-life, the two
// contradictions the profile must fail, and the gap measurement at its edges, pinned down to the
// coverage line and each gap's wording so the three verifiers measure a gap one way.
func (s *state) spans() {
	const spanned = "signed, chained (full), anchored by reference, spanned"
	valid := []spanEntry{
		{kind: "audit", at: "2026-07-27T15:00:10Z"},
		{kind: "span", at: "2026-07-27T15:01:00Z", beat: 1, count: 1},
		{kind: "audit", at: "2026-07-27T15:01:30Z"},
		{kind: "audit", at: "2026-07-27T15:01:40Z"},
		{kind: "span", at: "2026-07-27T15:02:00Z", beat: 2, count: 2},
	}
	// secondBeatAt returns the valid chain with its second beat moved to at, at the cadence given
	// to both beats when it is not zero.
	secondBeatAt := func(at string, cadence int64) []spanEntry {
		moved := make([]spanEntry, len(valid))
		copy(moved, valid)
		moved[4].at = at
		moved[1].cadence, moved[4].cadence = cadence, cadence
		return moved
	}
	s.add("span-valid", true, spanned, "",
		"Two beats whose counts recompute from the sequence numbers earn the spanned level.",
		s.sign(s.spanBundle(valid)))
	s.expectSpan("span-valid", "2/2 windows attested", "")

	s.add("span-gap", true, spanned, "",
		"Beats further apart than the declared cadence are a reported gap, never a hidden one "+
			"and never a failure.",
		s.sign(s.spanBundle(secondBeatAt("2026-07-27T15:04:00Z", 0))))
	s.expectSpan("span-gap", "2/4 windows attested", "180s",
		"unattested window of 180s between beat 1 (2026-07-27T15:01:00Z) and beat 2 "+
			"(2026-07-27T15:04:00Z)")

	s.add("span-mid-adoption", true, spanned, "",
		"A chain adopting the profile mid-life attests its entire prior population at beat 1.",
		s.sign(s.spanBundle([]spanEntry{
			{kind: "audit", at: "2026-07-27T15:00:10Z"},
			{kind: "audit", at: "2026-07-27T15:00:20Z"},
			{kind: "audit", at: "2026-07-27T15:00:30Z"},
			{kind: "span", at: "2026-07-27T15:01:00Z", beat: 1, count: 3},
		})))
	s.expectSpan("span-mid-adoption", "1/1 windows attested", "")

	// The gap measurement at its edges. At a 60s cadence the scheduling slack is the one second
	// floor, so an interval of 61s is on time and any wider one is a gap. At a 600s cadence the
	// slack is the proportional 6s, so 606s is on time and 607s is a gap. A gap of two and a half
	// cadences counts three windows, since halves round up, so two were missed.
	s.add("span-slack-edge", true, spanned, "",
		"A beat landing exactly one scheduling slack past its cadence is on time: the slack is a "+
			"hundredth of the cadence and never under a second, and the edge is inclusive.",
		s.sign(s.spanBundle(secondBeatAt("2026-07-27T15:02:01Z", 0))))
	s.expectSpan("span-slack-edge", "2/2 windows attested", "")

	s.add("span-slack-past", true, spanned, "",
		"A beat landing one second past the scheduling slack is a reported gap even though no "+
			"whole window was missed, so the gap list and the window count answer different "+
			"questions.",
		s.sign(s.spanBundle(secondBeatAt("2026-07-27T15:02:02Z", 0))))
	s.expectSpan("span-slack-past", "2/2 windows attested", "62s",
		"unattested window of 62s between beat 1 (2026-07-27T15:01:00Z) and beat 2 "+
			"(2026-07-27T15:02:02Z)")

	s.add("span-jitter", true, spanned, "",
		"A beat half a second late at a one minute cadence is a timer firing late, inside the "+
			"slack, and not a gap. Beat times are read to the microsecond.",
		s.sign(s.spanBundle(secondBeatAt("2026-07-27T15:02:00.500Z", 0))))
	s.expectSpan("span-jitter", "2/2 windows attested", "")

	s.add("span-slack-proportional", true, spanned, "",
		"At a ten minute cadence the scheduling slack is six seconds, a hundredth of the cadence, "+
			"so a beat six seconds late is on time.",
		s.sign(s.spanBundle(secondBeatAt("2026-07-27T15:11:06Z", 600))))
	s.expectSpan("span-slack-proportional", "2/2 windows attested", "")

	s.add("span-slack-proportional-past", true, spanned, "",
		"At a ten minute cadence a beat seven seconds late is one second past the slack and is a "+
			"reported gap.",
		s.sign(s.spanBundle(secondBeatAt("2026-07-27T15:11:07Z", 600))))
	s.expectSpan("span-slack-proportional-past", "2/2 windows attested", "607s",
		"unattested window of 607s between beat 1 (2026-07-27T15:01:00Z) and beat 2 "+
			"(2026-07-27T15:11:07Z)")

	s.add("span-half-window", true, spanned, "",
		"A gap of two and a half cadences counts three windows, because halves round up, so two "+
			"windows were missed and the duration is written in whole seconds.",
		s.sign(s.spanBundle(secondBeatAt("2026-07-27T15:03:30Z", 0))))
	s.expectSpan("span-half-window", "2/4 windows attested", "150s",
		"unattested window of 150s between beat 1 (2026-07-27T15:01:00Z) and beat 2 "+
			"(2026-07-27T15:03:30Z)")

	// Beat times are read to the microsecond with finer digits dropped, and a gap's duration rounds
	// to the whole second with halves up while the beat times beside it drop their fraction. A beat
	// a tenth of a microsecond past the slack edge is therefore on time, a gap of 62.5s reads 63s,
	// and one of 62.4999995s reads 62s because the half microsecond was dropped before rounding.
	s.add("span-sub-microsecond", true, spanned, "",
		"A beat a tenth of a microsecond past the slack edge is on time, because beat times are "+
			"read to the microsecond with finer digits dropped.",
		s.sign(s.spanBundle(secondBeatAt("2026-07-27T15:02:01.0000001Z", 0))))
	s.expectSpan("span-sub-microsecond", "2/2 windows attested", "")

	s.add("span-round-half-up", true, spanned, "",
		"A gap of 62.5s reads 63s, because a duration rounds to the nearest whole second with "+
			"halves up, while the beat time beside it drops its fraction and reads 15:02:02.",
		s.sign(s.spanBundle(secondBeatAt("2026-07-27T15:02:02.5Z", 0))))
	s.expectSpan("span-round-half-up", "2/2 windows attested", "63s",
		"unattested window of 63s between beat 1 (2026-07-27T15:01:00Z) and beat 2 "+
			"(2026-07-27T15:02:02Z)")

	s.add("span-round-below-half", true, spanned, "",
		"A gap of 62.4999995s reads 62s: the beat time is read to the microsecond first, which "+
			"leaves 62.499999s, and that rounds down.",
		s.sign(s.spanBundle(secondBeatAt("2026-07-27T15:02:02.4999995Z", 0))))
	s.expectSpan("span-round-below-half", "2/2 windows attested", "62s",
		"unattested window of 62s between beat 1 (2026-07-27T15:01:00Z) and beat 2 "+
			"(2026-07-27T15:02:02Z)")

	// The arithmetic is exact. Beats centuries apart are measured as they are, never clamped,
	// and a cadence is bounded so that no quantity the measurement forms leaves a signed 64-bit
	// count of microseconds.
	s.add("span-centuries", true, spanned, "",
		"Beats centuries apart are a gap measured exactly, with every missed window counted, "+
			"never clamped to a largest duration.",
		s.sign(s.spanBundle(secondBeatAt("2400-01-01T00:00:00Z", 0))))
	s.expectSpan("span-centuries", "2/196405020 windows attested", "11784301140s",
		"unattested window of 11784301140s between beat 1 (2026-07-27T15:01:00Z) and beat 2 "+
			"(2400-01-01T00:00:00Z)")

	s.add("span-cadence-max", true, spanned, "",
		"A cadence of 31622400 seconds, a 366-day year, is the widest a span claim may declare, "+
			"and a gap of centuries at it is measured exactly.",
		s.sign(s.spanBundle(secondBeatAt("2400-01-01T00:00:00Z", maxCadenceS))))
	s.expectSpan("span-cadence-max", "2/374 windows attested", "11784301140s",
		"unattested window of 11784301140s between beat 1 (2026-07-27T15:01:00Z) and beat 2 "+
			"(2400-01-01T00:00:00Z)")

	s.add("span-cadence-past-max", false, "", "span",
		"A cadence one second wider than a 366-day year is outside the range the format allows "+
			"and fails the span check.",
		s.sign(s.spanBundle(secondBeatAt("2026-07-27T15:02:00Z", maxCadenceS+1))))

	s.add("span-cadence-huge", false, "", "span",
		"A cadence of ten billion seconds is inside the integer range but outside the cadence "+
			"range, so it fails the span check rather than overflowing a verifier's arithmetic.",
		s.sign(s.spanBundle(secondBeatAt("2026-07-27T15:04:00Z", 10_000_000_000))))

	// A cadence of 2^58 seconds is past the integer range, so the bundle fails to parse, and a
	// verifier that measured it anyway in microseconds or nanoseconds would wrap to a zero cadence
	// and divide by it.
	signed := s.sign(s.spanBundle(secondBeatAt("2026-07-27T15:04:00Z", 0)))
	signed = []byte(strings.Replace(string(signed), `"cadence_s":60`,
		`"cadence_s":288230376151711744`, 1))
	s.add("span-cadence-wraps", false, "", "parse",
		"A cadence of 2^58 seconds is outside the integer profile and is rejected, and no "+
			"verifier may crash measuring it, though it wraps to zero in microseconds.", signed)

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

	// A JSON true or false is not a number, though a language that counts booleans as integers
	// would read true as 1 and false as 0. Each value below would pass if read that way: a cadence
	// of 1 is in range, beat 1 is the first beat, and no entry lies between the two beats of the
	// last vector, so its chain shows a count of 0.
	boolCadence := make([]spanEntry, len(valid))
	copy(boolCadence, valid)
	boolCadence[1].members = map[string]any{"cadence_s": true}
	boolCadence[4].members = map[string]any{"cadence_s": true}
	s.add("span-cadence-bool", false, "", "span",
		"A cadence of true is not an integer and fails the span check, never read as 1.",
		s.sign(s.spanBundle(boolCadence)))

	boolBeat := make([]spanEntry, len(valid))
	copy(boolBeat, valid)
	boolBeat[1].members = map[string]any{"beat": true}
	s.add("span-beat-bool", false, "", "span",
		"A beat of true is not an integer and fails the span check, never read as beat 1.",
		s.sign(s.spanBundle(boolBeat)))

	s.add("span-count-bool", false, "", "span",
		"A count of false is not an integer and fails the span check, never read as 0.",
		s.sign(s.spanBundle([]spanEntry{
			{kind: "audit", at: "2026-07-27T15:00:10Z"},
			{kind: "span", at: "2026-07-27T15:01:00Z", beat: 1, count: 1},
			{kind: "span", at: "2026-07-27T15:02:00Z", beat: 2,
				members: map[string]any{"count": false}},
		})))
}

// times emits the vectors that pin the one time form the format allows, the RFC 3339 date-time
// production narrowed to UTC: YYYY-MM-DDTHH:MM:SS, an optional fraction after a period, and Z,
// with the year from 0001 to 9999 and every field in range. Each refused time is planted where a
// verifier reads it, inside honestly linked and signed bytes, so only the time rule refuses the
// bundle, and every one is refused at parse under every profile.
//
//nolint:funlen // One vector per time form and position, listed in one place.
func (s *state) times() {
	// claimTime is one claim time on a one-claim loomseal-chain-v1 bundle.
	type claimTime struct {
		// name is the vector's name and the stem of its file.
		name string
		// at is the claim's time.
		at string
		// ok is whether the bundle must verify.
		ok bool
		// why is the vector's description in the manifest.
		why string
	}
	for _, c := range []claimTime{{
		name: "time-fraction", at: "2026-07-27T15:00:00.123456789Z", ok: true,
		why: "A claim time with a nine-digit fraction after a period is in the one form and " +
			"verifies.",
	}, {
		name: "time-fraction-twelve-digits", at: "2026-07-27T15:00:00.123456789012Z", ok: true,
		why: "A fraction of any length is in the one form and verifies. A verifier reads it to " +
			"the whole microsecond and drops the finer digits, never rounding them.",
	}, {
		name: "time-year-0001", at: "0001-01-01T00:00:00Z", ok: true,
		why: "The first instant of year 0001 is the earliest time the format allows and verifies.",
	}, {
		name: "time-year-9999", at: "9999-12-31T23:59:59.999999999Z", ok: true,
		why: "The last instant of year 9999 is the latest time the format allows and verifies.",
	}, {
		name: "time-offset", at: "2026-07-27T15:00:00+00:00",
		why: "A claim time carrying a numeric offset, even +00:00, is refused at parse: every " +
			"time is UTC and ends in Z.",
	}, {
		name: "time-offset-nonzero", at: "2026-07-27T17:00:00+02:00",
		why: "A claim time carrying a nonzero numeric offset is refused at parse, although RFC " +
			"3339 allows it, because every time ends in Z.",
	}, {
		name: "time-space-separator", at: "2026-07-27 15:00:00Z",
		why: "A claim time with a space between the date and the time is refused at parse, " +
			"although a general date parser reads it.",
	}, {
		name: "time-lowercase-t", at: "2026-07-27t15:00:00Z",
		why: "A claim time with a lower case t between the date and the time is refused at parse.",
	}, {
		name: "time-lowercase-z", at: "2026-07-27T15:00:00z",
		why: "A claim time ending in a lower case z is refused at parse.",
	}, {
		name: "time-year-0000", at: "0000-01-01T00:00:00Z",
		why: "A claim time in year 0000 is refused at parse: the first year allowed is 0001.",
	}, {
		name: "time-leap-second", at: "2016-12-31T23:59:60Z",
		why: "A claim time written as a leap second, second 60, is refused at parse.",
	}, {
		name: "time-day-out-of-range", at: "2026-02-30T15:00:00Z",
		why: "A claim time on February 30 is refused at parse, because the day is not in its " +
			"month.",
	}, {
		name: "time-hour-24", at: "2026-07-27T24:00:00Z",
		why: "A claim time at hour 24 is refused at parse, because the hour is below 24.",
	}, {
		name: "time-no-zone", at: "2026-07-27T15:00:00",
		why: "A claim time with no Z is refused at parse, because a time names its zone.",
	}} {
		m := s.v1(1, false)
		m["claims"].([]any)[0].(map[string]any)["at"] = c.at
		s.relinkV1(m, false)
		if c.ok {
			s.add(c.name, true, "signed, chained (full)", "", c.why, s.sign(m))
			continue
		}
		s.add(c.name, false, "", "parse", c.why, s.sign(m))
	}

	// The same forms on a span beat, where a verifier also measures the time, and on a
	// switchtender-audit-v1 claim, whose link hashes it verbatim. Each is refused at parse, before
	// any profile reads it, so no profile can read a time another refuses.
	for _, c := range []struct {
		// name is the vector's name and the stem of its file.
		name string
		// at is the first beat's time.
		at string
	}{
		{name: "time-span-offset", at: "2026-07-27T15:01:00+00:00"},
		{name: "time-span-space-separator", at: "2026-07-27 15:01:00Z"},
		{name: "time-span-year-0000", at: "0000-07-27T15:01:00Z"},
	} {
		s.add(c.name, false, "", "parse",
			"A span beat at "+c.at+" is refused at parse, as any claim time outside the one form "+
				"is, so no verifier measures it.",
			s.sign(s.spanBundle([]spanEntry{
				{kind: "audit", at: "2026-07-27T15:00:10Z"},
				{kind: "span", at: c.at, beat: 1, count: 1},
				{kind: "span", at: "2026-07-27T15:02:00Z", beat: 2},
			})))
	}
	for _, c := range []struct {
		// name is the vector's name and the stem of its file.
		name string
		// at is the claim's time.
		at string
	}{
		{name: "time-switchtender-offset", at: "2026-07-27T15:00:00+00:00"},
		{name: "time-switchtender-space-separator", at: "2026-07-27 15:00:00Z"},
		{name: "time-switchtender-year-0000", at: "0000-07-27T15:00:00Z"},
	} {
		m := s.base()
		claim := m["claims"].([]any)[0].(map[string]any)
		claim["at"] = c.at
		link := switchTenderLink(1, c.at, "release-token", "POST", "/api/runs", "")
		claim["chain"] = map[string]any{"seq": int64(1), "prev": "", "link": link}
		m["chain"] = map[string]any{
			"profile": profileSwitchTender, "keyed": false,
			"head": map[string]any{"seq": int64(1), "link": link},
		}
		s.add(c.name, false, "", "parse",
			"A switchtender-audit-v1 claim at "+c.at+", hashed verbatim into an honest link, is "+
				"refused at parse, as under every other profile.", s.sign(m))
	}

	// Every other time member, each refused at parse by the same rule.
	m := s.base()
	m["created_at"] = "2026-07-27T15:00:00+00:00"
	s.relinkV1(m, false)
	s.add("time-created-at-offset", false, "", "parse",
		"A created_at carrying a numeric offset, even +00:00, is refused at parse.", s.sign(m))
	m = s.base()
	m["created_at"] = "0000-07-27T15:00:00Z"
	s.relinkV1(m, false)
	s.add("time-created-at-year-0000", false, "", "parse",
		"A created_at in year 0000 is refused at parse.", s.sign(m))
	m = s.v1(1, false)
	a := gitAnchor(1, m["chain"].(map[string]any)["head"].(map[string]any)["link"].(string))
	a["at"] = "2026-07-01T00:00:00+00:00"
	m["anchors"] = []any{a}
	s.add("time-anchor-offset", false, "", "parse",
		"An anchor at carrying a numeric offset is refused at parse.", s.sign(m))

	m = s.v1(1, false)
	claim := m["claims"].([]any)[0].(map[string]any)
	link := claim["chain"].(map[string]any)["link"].(string)
	cPriv, cPub := counterpartyKey()
	claim["attestations"] = []any{attestationAt(cPriv, cPub, link, "approver",
		"2026-08-30T12:00:00+00:00")}
	s.add("time-attestation-offset", false, "", "parse",
		"An attestation whose signed at carries a numeric offset is refused at parse.", s.sign(m))
	m = s.v1(1, false)
	claim = m["claims"].([]any)[0].(map[string]any)
	att := attestation(cPriv, cPub, claim["chain"].(map[string]any)["link"].(string), "approver")
	att["at"] = ""
	claim["attestations"] = []any{att}
	s.add("time-attestation-empty", false, "", "parse",
		"An attestation carrying an empty at is refused at parse rather than read as one that "+
			"carries no time, although its signature covers no time and would verify.", s.sign(m))
	s.add("time-head-attestation-empty", false, "", "parse",
		"A head attestation carrying an empty at is refused at parse rather than read as one that "+
			"carries no time.",
		mutateSigned(s.sign(s.v1(2, false)), func(m map[string]any) {
			hPriv, hPub := counterpartyKey()
			head := m["chain"].(map[string]any)["head"].(map[string]any)
			att := headAttestation(hPriv, hPub, head["link"].(string), head["seq"], "witness", "")
			att["at"] = ""
			m["attestations"] = []any{att}
		}))
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

	// A switchtender-audit-v1 chain declared keyed. The profile is unkeyed, so a reader that took
	// the flag would check continuity only and never recompute a link. The second vector alters the
	// payload after its link was computed, which is the edit that reading would let through.
	sk := s.switchTender()
	sk["chain"].(map[string]any)["keyed"] = true
	s.add("switchtender-keyed", false, "", "chain",
		"A switchtender-audit-v1 chain declared keyed fails the chain check, because the profile "+
			"is unkeyed and every link must be recomputed.", s.sign(sk))
	sk = s.switchTender()
	sk["chain"].(map[string]any)["keyed"] = true
	sk["claims"].([]any)[0].(map[string]any)["payload"].(map[string]any)["path"] = "/api/evil"
	s.add("switchtender-keyed-altered", false, "", "chain",
		"A switchtender-audit-v1 claim altered after its link was computed fails, although the "+
			"chain declares itself keyed to avoid the recompute.", s.sign(sk))

	s.casefoldSwitchTender()
	s.casefoldSpan()
	s.casefoldEnvelope()
}

// agreement emits the vectors that hold every shipped verifier to one verdict where a lenient
// reader would reach another: documents the schema forbids by member type or value, null where the
// schema defines no null, base64 broken across lines, inputs built to crash a verifier rather than
// reach a verdict, nesting at and past the bound, and a span claim under the tree profile. Each
// signed vector carries a valid producer signature over the fault, so only the rule under test can
// refuse it.
//
//nolint:funlen // One vector per divergence, listed in one place.
func (s *state) agreement() {
	// schemaCase is one schema-forbidden value planted inside the signed bytes of a one-claim
	// loomseal-chain-v1 bundle.
	type schemaCase struct {
		// name is the vector's name and the stem of its file.
		name string
		// why is the vector's description in the manifest.
		why string
		// mutate plants the fault in the bundle before it is signed.
		mutate func(m map[string]any)
	}
	deepLink := strings.Repeat("ab", 32)
	schemaCases := []schemaCase{{
		name: "anchor-unknown-type",
		why: "An anchor type outside the vocabulary the format defines is refused at parse, " +
			"never reported as anchored by reference.",
		mutate: func(m map[string]any) {
			head := m["chain"].(map[string]any)["head"].(map[string]any)
			a := gitAnchor(head["seq"].(int64), head["link"].(string))
			a["type"] = "blockchain"
			m["anchors"] = []any{a}
		},
	}, {
		name: "anchor-empty-ref",
		why:  "An anchor with an empty ref locates nothing and is refused at parse.",
		mutate: func(m map[string]any) {
			head := m["chain"].(map[string]any)["head"].(map[string]any)
			a := gitAnchor(head["seq"].(int64), head["link"].(string))
			a["ref"] = ""
			m["anchors"] = []any{a}
		},
	}, {
		name: "anchor-bad-at",
		why:  "An anchor time that is not RFC 3339 is refused at parse.",
		mutate: func(m map[string]any) {
			head := m["chain"].(map[string]any)["head"].(map[string]any)
			a := gitAnchor(head["seq"].(int64), head["link"].(string))
			a["at"] = "yesterday"
			m["anchors"] = []any{a}
		},
	}, {
		name:   "bundle-id-empty",
		why:    "An empty bundle_id is refused at parse.",
		mutate: func(m map[string]any) { m["bundle_id"] = "" },
	}, {
		name:   "subject-empty-id",
		why:    "An empty subject id is refused at parse.",
		mutate: func(m map[string]any) { m["subject"].(map[string]any)["id"] = "" },
	}, {
		name:   "producer-empty-product",
		why:    "An empty producer product is refused at parse.",
		mutate: func(m map[string]any) { m["producer"].(map[string]any)["product"] = "" },
	}, {
		name:   "created-at-malformed",
		why:    "A created_at that is not RFC 3339 is refused at parse.",
		mutate: func(m map[string]any) { m["created_at"] = "yesterday" },
	}, {
		name: "created-at-one-digit-hour",
		why: "A created_at with a one-digit hour is not RFC 3339 and is refused at parse, " +
			"although a general date parser reads it.",
		mutate: func(m map[string]any) { m["created_at"] = "2026-07-27T1:00:00Z" },
	}, {
		name: "created-at-comma-fraction",
		why: "A created_at with a comma before its fractional second is not RFC 3339 and is " +
			"refused at parse.",
		mutate: func(m map[string]any) { m["created_at"] = "2026-07-27T15:00:00,5Z" },
	}, {
		name:   "created-at-offset-hour-24",
		why:    "A created_at whose offset hour is 24 is not RFC 3339 and is refused at parse.",
		mutate: func(m map[string]any) { m["created_at"] = "2026-07-27T15:00:00+24:00" },
	}, {
		name:   "created-at-offset-minute-60",
		why:    "A created_at whose offset minute is 60 is not RFC 3339 and is refused at parse.",
		mutate: func(m map[string]any) { m["created_at"] = "2026-07-27T15:00:00+23:60" },
	}, {
		name: "payload-string",
		why:  "A claim payload that is not a JSON object is refused at parse.",
		mutate: func(m map[string]any) {
			m["claims"].([]any)[0].(map[string]any)["payload"] = "not an object"
		},
	}, {
		name: "evidence-empty-role",
		why:  "An evidence entry with an empty role is refused at parse.",
		mutate: func(m map[string]any) {
			m["claims"].([]any)[0].(map[string]any)["evidence"] = []any{map[string]any{
				"role": "", "digest": "sha256:" + deepLink,
			}}
		},
	}, {
		name: "evidence-present-string",
		why:  "An evidence present flag that is not a boolean is refused at parse.",
		mutate: func(m map[string]any) {
			m["claims"].([]any)[0].(map[string]any)["evidence"] = []any{map[string]any{
				"role": "snapshot", "digest": "sha256:" + deepLink, "present": "yes",
			}}
		},
	}, {
		name:   "keyed-zero",
		why:    "A chain keyed flag written as a number is refused at parse, never read as false.",
		mutate: func(m map[string]any) { m["chain"].(map[string]any)["keyed"] = int64(0) },
	}, {
		name:   "keyed-string",
		why:    "A chain keyed flag written as a string is refused at parse, never read as true.",
		mutate: func(m map[string]any) { m["chain"].(map[string]any)["keyed"] = "yes" },
	}, {
		name: "seq-true",
		why: "A sequence number written as a boolean is refused at parse, never hashed as a " +
			"number.",
		mutate: func(m map[string]any) {
			m["claims"].([]any)[0].(map[string]any)["chain"].(map[string]any)["seq"] = true
			m["chain"].(map[string]any)["head"].(map[string]any)["seq"] = true
		},
	}, {
		name: "seq-zero",
		why:  "A sequence number below one is refused at parse.",
		mutate: func(m map[string]any) {
			m["claims"].([]any)[0].(map[string]any)["chain"].(map[string]any)["seq"] = int64(0)
		},
	}, {
		name: "prev-null",
		why: "A prev written as null is refused at parse rather than read as the empty string " +
			"and recomputed as genesis.",
		mutate: func(m map[string]any) {
			m["claims"].([]any)[0].(map[string]any)["chain"].(map[string]any)["prev"] = nil
		},
	}, {
		name: "public-key-line-break",
		why: "A producer public_key whose base64 carries a line break is refused at parse, " +
			"because a decoder that skips line breaks would give one key many spellings.",
		mutate: func(m map[string]any) {
			p := m["producer"].(map[string]any)
			key := p["public_key"].(string)
			p["public_key"] = key[:10] + "\n" + key[10:]
		},
	}, {
		name: "inclusion-under-linear",
		why: "An inclusion proof on a claim under a linear profile is refused at parse rather " +
			"than ignored, because a reader who sees a proof assumes some verifier checked it.",
		mutate: func(m map[string]any) {
			m["claims"].([]any)[0].(map[string]any)["inclusion"] = map[string]any{"path": []any{}}
		},
	}, {
		name: "consistency-under-linear",
		why: "A consistency proof under a linear profile is refused at parse rather than " +
			"ignored.",
		mutate: func(m map[string]any) {
			head := m["chain"].(map[string]any)["head"].(map[string]any)
			m["chain"].(map[string]any)["consistency"] = map[string]any{
				"from_size": int64(1), "from_root": head["link"], "path": []any{},
			}
		},
	}, {
		name: "anchor-proof-not-base64",
		why: "An anchor proof that is not base64 is refused at parse, never reported as " +
			"anchored by reference.",
		mutate: func(m map[string]any) {
			head := m["chain"].(map[string]any)["head"].(map[string]any)
			a := gitAnchor(head["seq"].(int64), head["link"].(string))
			a["proof"] = "!!!!"
			m["anchors"] = []any{a}
		},
	}, {
		name: "anchor-proof-line-break",
		why: "An anchor proof whose base64 carries a line break is refused at parse rather " +
			"than decoded by skipping the break.",
		mutate: func(m map[string]any) {
			head := m["chain"].(map[string]any)["head"].(map[string]any)
			a := gitAnchor(head["seq"].(int64), head["link"].(string))
			a["proof"] = "AAAA\nAAAA"
			m["anchors"] = []any{a}
		},
	}, {
		name: "params-number",
		why: "A chain params member that is not a string is refused at parse, because the " +
			"schema types every params value as a string.",
		mutate: func(m map[string]any) {
			m["chain"].(map[string]any)["params"].(map[string]any)["extra"] = int64(5)
		},
	}, {
		name: "params-null",
		why: "A chain params member written as null is refused at parse rather than read as " +
			"the empty string.",
		mutate: func(m map[string]any) {
			m["chain"].(map[string]any)["params"].(map[string]any)["extra"] = nil
		},
	}}
	for _, c := range schemaCases {
		m := s.v1(1, false)
		c.mutate(m)
		s.add(c.name, false, "", "parse", c.why, s.sign(m))
	}
	s.typeSweep()

	// The same class of fault on a bundle that declares no chain.
	m := s.base()
	delete(m["claims"].([]any)[0].(map[string]any), "at")
	s.add("claim-without-at", false, "", "parse",
		"A claim with no at is refused at parse.", s.sign(m))

	m = s.base()
	delete(m["claims"].([]any)[0].(map[string]any), "type")
	s.add("claim-without-type", false, "", "parse",
		"A claim with no type is refused at parse.", s.sign(m))

	m = s.base()
	m["claims"].([]any)[0].(map[string]any)["payload"] = []any{int64(1)}
	s.add("payload-array", false, "", "parse",
		"A claim payload written as an array is refused at parse.", s.sign(m))

	m = s.base()
	m["claims"].([]any)[0].(map[string]any)["chain"] = map[string]any{
		"seq": int64(1), "prev": "", "link": deepLink,
	}
	s.add("coords-without-chain", false, "", "parse",
		"Chain coordinates on a claim of a bundle that declares no chain are refused at parse, "+
			"because unchained claims are unproved by construction.", s.sign(m))

	m = s.base()
	m["subject"] = "a string"
	s.add("subject-string", false, "", "parse",
		"A subject that is not an object is refused at parse, with a verdict and never a crash.",
		s.sign(m))

	m = s.base()
	m["claims"] = []any{int64(1)}
	s.add("claim-number", false, "", "parse",
		"A claim that is not an object is refused at parse, with a verdict and never a crash.",
		s.sign(m))

	// Faults outside the signed bytes, planted after signing so the signature stays valid.
	s.add("signature-line-break", false, "", "parse",
		"A signature whose base64 carries a line break is refused at parse.",
		mutateSigned(s.sign(s.v1(1, false)), func(m map[string]any) {
			sig := m["signatures"].([]any)[0].(map[string]any)
			text := sig["sig"].(string)
			sig["sig"] = text[:20] + "\r\n" + text[20:]
		}))

	// A counterparty key broken across lines. The attestation's signature is genuine, so only the
	// base64 rule refuses it.
	m = s.attestedBundle()
	att := m["claims"].([]any)[0].(map[string]any)["attestations"].([]any)[0].(map[string]any)
	key := att["public_key"].(string)
	att["public_key"] = key[:12] + "\n" + key[12:]
	s.add("attestation-key-line-break", false, "", "attestation",
		"A counterparty attestation whose public_key carries a line break inside its base64 is "+
			"refused rather than decoded by skipping the break.", s.sign(m))

	// A claim attestation signature broken across lines.
	m = s.attestedBundle()
	att = m["claims"].([]any)[0].(map[string]any)["attestations"].([]any)[0].(map[string]any)
	text := att["sig"].(string)
	att["sig"] = text[:20] + "\n" + text[20:]
	s.add("attestation-sig-line-break", false, "", "attestation",
		"A counterparty attestation whose sig carries a line break inside its base64 is refused "+
			"rather than decoded by skipping the break.", s.sign(m))

	// A head attestation's key and signature broken across lines, added after signing as a
	// witness adds one. Its signature over the head is genuine, so only the base64 rule refuses
	// it.
	headAttested := func(edit func(att map[string]any)) []byte {
		return mutateSigned(s.sign(s.v1(2, false)), func(m map[string]any) {
			hPriv, hPub := counterpartyKey()
			head := m["chain"].(map[string]any)["head"].(map[string]any)
			att := headAttestation(hPriv, hPub, head["link"].(string), head["seq"], "witness",
				"2026-08-30T12:00:00Z")
			edit(att)
			m["attestations"] = []any{att}
		})
	}
	s.add("head-attestation-key-line-break", false, "", "attestation",
		"A head attestation whose public_key carries a line break inside its base64 is refused "+
			"rather than decoded by skipping the break.",
		headAttested(func(att map[string]any) {
			key := att["public_key"].(string)
			att["public_key"] = key[:12] + "\n" + key[12:]
		}))
	s.add("head-attestation-sig-line-break", false, "", "attestation",
		"A head attestation whose sig carries a line break inside its base64 is refused rather "+
			"than decoded by skipping the break.",
		headAttested(func(att map[string]any) {
			sig := att["sig"].(string)
			att["sig"] = sig[:20] + "\r\n" + sig[20:]
		}))

	// Signing times that a general date parser reads but RFC 3339 does not allow. The time is
	// inside the counter-signed bytes, so the signatures are genuine and only the time rule
	// refuses them.
	m = s.v1(1, false)
	tc := m["claims"].([]any)[0].(map[string]any)
	tPriv, tPub := counterpartyKey()
	tc["attestations"] = []any{attestationAt(tPriv, tPub,
		tc["chain"].(map[string]any)["link"].(string), "approver", "2026-08-30T1:00:00Z")}
	s.add("attestation-at-one-digit-hour", false, "", "parse",
		"An attestation whose signed at has a one-digit hour is refused at parse, because the "+
			"time is not in the one form the format allows.", s.sign(m))
	s.add("head-attestation-at-one-digit-hour", false, "", "parse",
		"A head attestation whose signed at has a one-digit hour is refused at parse, because the "+
			"time is not in the one form the format allows.",
		mutateSigned(s.sign(s.v1(2, false)), func(m map[string]any) {
			hPriv, hPub := counterpartyKey()
			head := m["chain"].(map[string]any)["head"].(map[string]any)
			m["attestations"] = []any{headAttestation(hPriv, hPub, head["link"].(string),
				head["seq"], "witness", "2026-08-30T1:00:00Z")}
		}))

	s.add("attestation-null", false, "", "parse",
		"A null entry in a claim's attestations is refused at parse rather than read as an empty "+
			"attestation.",
		mutateSigned(s.sign(s.v1(1, false)), func(m map[string]any) {
			m["claims"].([]any)[0].(map[string]any)["attestations"] = []any{nil}
		}))

	s.add("disclosure-null", false, "", "parse",
		"A null entry in a claim's disclosures is refused at parse rather than read as an empty "+
			"disclosure.",
		mutateSigned(s.sign(s.v1(1, false)), func(m map[string]any) {
			m["claims"].([]any)[0].(map[string]any)["disclosures"] = []any{nil}
		}))

	s.add("attestations-string", false, "", "parse",
		"A head attestations member that is not an array is refused at parse, with a verdict and "+
			"never a crash.",
		mutateSigned(s.sign(s.v1(1, false)), func(m map[string]any) {
			m["attestations"] = "witness"
		}))

	// A \u escape whose digits are not hex. The edit is textual because no serializer emits it.
	signed := s.sign(s.v1(1, false))
	signed = []byte(strings.Replace(string(signed), `"lsb_vectors"`, `"lsb_\uzzzz"`, 1))
	s.add("escape-invalid-hex", false, "", "parse",
		"A \\u escape whose digits are not hex is refused at parse, with a verdict and never a "+
			"crash.", signed)

	// Nesting. A conforming verifier holds a document nested bundle.MaxDepth levels deep and
	// refuses a deeper one at parse, counting each array or object as one level.
	m = s.v1(1, false)
	m["claims"].([]any)[0].(map[string]any)["payload"].(map[string]any)["deep"] = nested(3000)
	s.relinkV1(m, false)
	s.add("nesting-3000-deep", true, "signed, chained (full)", "",
		"A payload nested 3000 levels deep verifies, because it is within the nesting bound and "+
			"a verifier must reach a verdict rather than exhaust its stack.", s.sign(m))

	m = s.v1(1, false)
	m["claims"].([]any)[0].(map[string]any)["payload"].(map[string]any)["deep"] =
		nested(bundle.MaxDepth - envelopeDepth)
	s.relinkV1(m, false)
	s.add("nesting-at-bound", true, "signed, chained (full)", "",
		fmt.Sprintf("A document nested exactly %d levels deep verifies: the bound is inclusive, "+
			"and a verifier holds it whatever its own stack.", bundle.MaxDepth), s.sign(m))

	// An integer literal thousands of digits long, which a reader converting it before checking
	// its range may fail on rather than refuse.
	signed = s.sign(s.v1(1, false))
	signed = []byte(strings.Replace(string(signed), `"path":"/api/runs"`,
		`"path":"/api/runs","big":`+strings.Repeat("9", 5000), 1))
	s.add("number-5000-digits", false, "", "parse",
		"An integer literal of 5000 digits is refused as beyond 2^53, with a verdict and never a "+
			"crash.", signed)

	// One level past the bound, honestly linked and signed, so the bound alone refuses it.
	m = s.v1(1, false)
	m["claims"].([]any)[0].(map[string]any)["payload"].(map[string]any)["deep"] =
		nested(bundle.MaxDepth + 1 - envelopeDepth)
	s.relinkV1(m, false)
	s.add("nesting-past-bound", false, "", "parse",
		fmt.Sprintf("A document nested %d levels deep is refused at parse, one level past the "+
			"bound, before any recursive reader sees it.", bundle.MaxDepth+1), s.sign(m))

	// A span claim under the tree profile. The leaf and the root are honest, so only the rule that
	// the tree profile carries no span claims can refuse it.
	s.add("merkle-span-claim", false, "", "span",
		"A span claim in a tree bundle is refused rather than checked, because a tree has no "+
			"per-entry predecessor and no contiguous beats for the coverage check to run over.",
		s.sign(s.merkleBundleShaped(1, []int{0}, 0, func(log []map[string]any) {
			log[0]["type"] = "loomseal.span/1"
			log[0]["payload"] = map[string]any{
				"stream": "chain", "cadence_s": int64(60), "beat": int64(1), "count": int64(0),
			}
		})))
}

// typeCase is one member position the schema types, planted with a value of another JSON type.
type typeCase struct {
	// name is the vector's name and the stem of its file.
	name string
	// build returns the honest unsigned bundle the value is planted in before signing.
	build func() map[string]any
	// signed returns the honest signed document the value is planted in, for a member the
	// producer signature does not cover. Exactly one of build and signed is set.
	signed func() []byte
	// value is the wrongly typed value planted at path.
	value any
	// path walks from the bundle to the member: a string names an object member and an int an
	// array element.
	path []any
}

// typeSweep emits one vector for each member position the schema types as a string, an integer,
// or an array of hashes, each holding a value of another JSON type inside otherwise honest bytes.
// A reader that skipped the type check would read the value as something no other verifier
// reads, so every conformant verifier refuses each one at parse. A position some other vector
// already pins, such as keyed, seq, present, or the subject itself, is not repeated here.
//
//nolint:funlen // One row per member position, listed in one place.
func (s *state) typeSweep() {
	str, num := any(int64(5)), any(true)
	hashes := []any{int64(5)}
	plain := func() map[string]any { return s.v1(1, false) }
	judged := func() map[string]any {
		m := s.v1(1, false)
		c := m["claims"].([]any)[0].(map[string]any)
		c["evidence"] = []any{map[string]any{
			"role": "snapshot", "digest": "sha256:" + strings.Repeat("cd", 32),
			"media_type": "text/html", "present": true, "location": "evidence/snap.html",
		}}
		c["verdict"] = map[string]any{
			"policy": "release-gate/1", "policy_digest": "sha256:" + strings.Repeat("ab", 32),
			"inputs_digest": "sha256:" + strings.Repeat("ef", 32), "decision": "pass",
			"detail": "every gate held",
		}
		s.relinkV1(m, false)
		return m
	}
	disclosed := func() map[string]any { return s.swatchBundle("title") }
	attested := func() map[string]any {
		m := s.v1(1, false)
		c := m["claims"].([]any)[0].(map[string]any)
		priv, pub := counterpartyKey()
		c["attestations"] = []any{attestationAt(priv, pub,
			c["chain"].(map[string]any)["link"].(string), "approver", "2026-08-30T12:00:00Z")}
		return m
	}
	anchored := func() map[string]any {
		m := s.v1(1, false)
		head := m["chain"].(map[string]any)["head"].(map[string]any)
		m["anchors"] = []any{gitAnchor(head["seq"].(int64), head["link"].(string))}
		return m
	}
	tree := func() map[string]any { return s.merkleBundle(6, []int{1, 4}, 4) }
	witnessed := func() []byte {
		return mutateSigned(s.sign(s.v1(2, false)), func(m map[string]any) {
			priv, pub := counterpartyKey()
			head := m["chain"].(map[string]any)["head"].(map[string]any)
			m["attestations"] = []any{headAttestation(priv, pub, head["link"].(string),
				head["seq"], "witness", "2026-08-30T12:00:00Z")}
		})
	}
	signedPlain := func() []byte { return s.sign(s.v1(1, false)) }
	claim := func(rest ...any) []any { return append([]any{"claims", 0}, rest...) }
	linkedMembers := map[string]bool{"type": true, "at": true, "evidence": true, "verdict": true}
	cases := []typeCase{
		{"type-loomseal", plain, nil, str, []any{"loomseal"}},
		{"type-bundle-id", plain, nil, str, []any{"bundle_id"}},
		{"type-created-at", plain, nil, str, []any{"created_at"}},
		{"type-producer-product", plain, nil, str, []any{"producer", "product"}},
		{"type-producer-product-version", plain, nil, str, []any{"producer", "product_version"}},
		{"type-producer-install-id", plain, nil, str, []any{"producer", "install_id"}},
		{"type-producer-public-key", plain, nil, str, []any{"producer", "public_key"}},
		{"type-producer-key-id", plain, nil, str, []any{"producer", "key_id"}},
		{"type-subject-type", plain, nil, str, []any{"subject", "type"}},
		{"type-subject-id", plain, nil, str, []any{"subject", "id"}},
		{"type-chain-profile", plain, nil, str, []any{"chain", "profile"}},
		{"type-head-prev", plain, nil, str, []any{"chain", "head", "prev"}},
		{"type-head-link", plain, nil, str, []any{"chain", "head", "link"}},
		{"type-claim-type", plain, nil, str, claim("type")},
		{"type-claim-at", plain, nil, str, claim("at")},
		{"type-claim-seq", plain, nil, num, claim("chain", "seq")},
		{"type-claim-prev", plain, nil, str, claim("chain", "prev")},
		{"type-claim-link", plain, nil, str, claim("chain", "link")},
		{"type-evidence-role", judged, nil, str, claim("evidence", 0, "role")},
		{"type-evidence-digest", judged, nil, str, claim("evidence", 0, "digest")},
		{"type-evidence-media-type", judged, nil, str, claim("evidence", 0, "media_type")},
		{"type-evidence-location", judged, nil, str, claim("evidence", 0, "location")},
		{"type-verdict-policy", judged, nil, str, claim("verdict", "policy")},
		{"type-verdict-policy-digest", judged, nil, str, claim("verdict", "policy_digest")},
		{"type-verdict-inputs-digest", judged, nil, str, claim("verdict", "inputs_digest")},
		{"type-verdict-decision", judged, nil, str, claim("verdict", "decision")},
		{"type-verdict-detail", judged, nil, str, claim("verdict", "detail")},
		{"type-disclosure-salt", disclosed, nil, str, claim("disclosures", 0, "salt")},
		{"type-disclosure-name", disclosed, nil, str, claim("disclosures", 0, "name")},
		{"type-attestation-key-id", attested, nil, str, claim("attestations", 0, "key_id")},
		{"type-attestation-public-key", attested, nil, str, claim("attestations", 0, "public_key")},
		{"type-attestation-alg", attested, nil, str, claim("attestations", 0, "alg")},
		{"type-attestation-role", attested, nil, str, claim("attestations", 0, "role")},
		{"type-attestation-sig", attested, nil, str, claim("attestations", 0, "sig")},
		{"type-attestation-at", attested, nil, str, claim("attestations", 0, "at")},
		{"type-head-attestation-key-id", nil, witnessed, str, []any{"attestations", 0, "key_id"}},
		{"type-head-attestation-public-key", nil, witnessed, str,
			[]any{"attestations", 0, "public_key"}},
		{"type-head-attestation-alg", nil, witnessed, str, []any{"attestations", 0, "alg"}},
		{"type-head-attestation-role", nil, witnessed, str, []any{"attestations", 0, "role"}},
		{"type-head-attestation-sig", nil, witnessed, str, []any{"attestations", 0, "sig"}},
		{"type-head-attestation-at", nil, witnessed, str, []any{"attestations", 0, "at"}},
		{"type-anchor-type", anchored, nil, str, []any{"anchors", 0, "type"}},
		{"type-anchor-seq", anchored, nil, num, []any{"anchors", 0, "seq"}},
		{"type-anchor-link", anchored, nil, str, []any{"anchors", 0, "link"}},
		{"type-anchor-at", anchored, nil, str, []any{"anchors", 0, "at"}},
		{"type-anchor-ref", anchored, nil, str, []any{"anchors", 0, "ref"}},
		{"type-anchor-proof", anchored, nil, str, []any{"anchors", 0, "proof"}},
		{"type-signature-key-id", nil, signedPlain, str, []any{"signatures", 0, "key_id"}},
		{"type-signature-alg", nil, signedPlain, str, []any{"signatures", 0, "alg"}},
		{"type-signature-sig", nil, signedPlain, str, []any{"signatures", 0, "sig"}},
		{"type-consistency-from-size", tree, nil, num, []any{"chain", "consistency", "from_size"}},
		{"type-consistency-from-root", tree, nil, str, []any{"chain", "consistency", "from_root"}},
		{"type-consistency-path", tree, nil, hashes, []any{"chain", "consistency", "path"}},
		{"type-inclusion-path", tree, nil, hashes, claim("inclusion", "path")},
	}
	for _, c := range cases {
		kind := "number"
		switch c.value.(type) {
		case bool:
			kind = "boolean"
		case []any:
			kind = "array holding a number"
		}
		why := fmt.Sprintf("%s holds a JSON %s, a type the schema does not allow there, so it "+
			"is refused at parse rather than read as another type.", pathLabel(c.path), kind)
		var data []byte
		if c.build != nil {
			m := c.build()
			setPath(m, c.path, c.value)
			// A member inside a claim's committed content is relinked over, so the chain still
			// recomputes and the type rule is the only one that refuses the bundle.
			if len(c.path) > 2 && c.path[0] == "claims" && linkedMembers[c.path[2].(string)] {
				s.relinkV1(m, false)
			}
			data = s.sign(m)
		} else {
			data = mutateSigned(c.signed(), func(m map[string]any) { setPath(m, c.path, c.value) })
		}
		s.add(c.name, false, "", "parse", why, data)
	}
}

// setPath stores v at the member path names inside m, where a string step names an object member
// and an int step an array element. It panics when the path runs through a member or an element
// the document does not have, because a vector planted anywhere else would not test the member
// it names.
func setPath(m map[string]any, path []any, v any) {
	var cur any = m
	for i, step := range path {
		last := i == len(path)-1
		switch k := step.(type) {
		case string:
			obj := cur.(map[string]any)
			if last {
				obj[k] = v
				return
			}
			cur = obj[k]
		case int:
			arr := cur.([]any)
			if last {
				arr[k] = v
				return
			}
			cur = arr[k]
		default:
			panic(fmt.Sprintf("setPath: step %v is neither a member nor an index", step))
		}
	}
}

// pathLabel words a member path for a manifest description, such as claims[0].chain.seq.
func pathLabel(path []any) string {
	var b strings.Builder
	for _, step := range path {
		switch k := step.(type) {
		case string:
			if b.Len() > 0 {
				b.WriteByte('.')
			}
			b.WriteString(k)
		case int:
			fmt.Fprintf(&b, "[%d]", k)
		}
	}
	return b.String()
}

// envelopeDepth is the nesting a bundle's envelope takes above a payload member: the bundle, its
// claims, the claim, and its payload.
const envelopeDepth = 4

// nested returns an array nested depth levels deep with an empty array at the bottom. The bottom
// is a non-nil slice, which every serializer writes as [] rather than null.
func nested(depth int) []any {
	v := []any{}
	for i := 1; i < depth; i++ {
		v = []any{v}
	}
	return v
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

// genTimes emits the vectors that pin how a verifier reads a timestamp token's genTime and compares
// it: in the one form RFC 3161 gives it, and to the whole microsecond on both sides of each
// comparison, the claim time against genTime with the five-minute skew and genTime against the
// signer certificate's validity window. Each token is minted over the vector's own link by a fixed
// authority key, so only the time decides the verdict.
//
//nolint:funlen // One vector per genTime form and comparison, listed in one place.
func (s *state) genTimes() {
	yearEnd := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	notAfter := time.Date(2026, 7, 27, 15, 1, 0, 0, time.UTC)
	for _, c := range []struct {
		// name is the vector's name and the stem of its file.
		name string
		// claimAt is the anchored claim's time.
		claimAt string
		// genTime is the value in the token's genTime slot.
		genTime asn1.RawValue
		// trailing are DER elements the TSTInfo carries after genTime.
		trailing [][]byte
		// notAfter is the end of the authority certificate's validity window.
		notAfter time.Time
		// ok is whether the bundle must verify.
		ok bool
		// attested is genTime to the second, as a verifier reports it, for a bundle that must
		// verify.
		attested string
		// why is the vector's description in the manifest.
		why string
	}{{
		name: "anchor-gen-time-fraction-inside-skew", claimAt: "2026-07-27T15:00:00.7Z",
		genTime: generalizedTime("20260727145500.8Z"), notAfter: yearEnd, ok: true,
		attested: "2026-07-27T14:55:00Z",
		why: "A token signed 299.9 seconds before the claim it covers is inside the five-minute " +
			"skew and verifies, because a verifier reads the genTime fraction rather than " +
			"cutting it to the second.",
	}, {
		name: "anchor-gen-time-fraction-outside-skew", claimAt: "2026-07-27T15:00:00.7Z",
		genTime: generalizedTime("20260727145500.6Z"), notAfter: yearEnd,
		why: "A token signed 300.1 seconds before the claim it covers predates the entry by more " +
			"than the five-minute skew and fails the anchor check.",
	}, {
		name: "anchor-gen-time-sub-microsecond-claim", claimAt: "2026-07-27T15:00:00.0000005Z",
		genTime: generalizedTime("20260727145500Z"), notAfter: yearEnd, ok: true,
		attested: "2026-07-27T14:55:00Z",
		why: "A token signed exactly five minutes before a claim whose time carries half a " +
			"microsecond verifies, because every verifier reads the claim time to the whole " +
			"microsecond and drops the finer digits.",
	}, {
		name: "anchor-gen-time-sub-microsecond-not-after", claimAt: at,
		genTime: generalizedTime("20260727150100.0000005Z"), notAfter: notAfter, ok: true,
		attested: "2026-07-27T15:01:00Z",
		why: "A token whose genTime lies half a microsecond past its certificate's last valid " +
			"second verifies, because every verifier reads genTime to the whole microsecond and " +
			"drops the finer digits.",
	}, {
		name: "anchor-gen-time-past-not-after", claimAt: at,
		genTime: generalizedTime("20260727150100.5Z"), notAfter: notAfter,
		why: "A token whose genTime lies half a second past its certificate's last valid second " +
			"was signed outside the certificate's life and fails the anchor check.",
	}, {
		name: "anchor-gen-time-offset", claimAt: at,
		genTime: generalizedTime("20260727160100+0100"), notAfter: yearEnd,
		why: "A token whose genTime carries a numeric offset fails the anchor check, although an " +
			"ASN.1 GeneralizedTime may carry one, because RFC 3161 requires a genTime ending in Z.",
	}, {
		name: "anchor-gen-time-trailing-zero", claimAt: at,
		genTime: generalizedTime("20260727150100.50Z"), notAfter: yearEnd,
		why: "A token whose genTime fraction ends in a zero fails the anchor check, because RFC " +
			"3161 requires trailing zeros to be omitted.",
	}, {
		name: "anchor-gen-time-utc-time-then-generalized", claimAt: at,
		genTime: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagUTCTime,
			Bytes: []byte("260727150100Z")},
		trailing: [][]byte{mustMarshal(generalizedTime("20260727150100Z"))},
		notAfter: yearEnd,
		why: "A token whose genTime slot holds a UTCTime fails the anchor check, although a valid " +
			"GeneralizedTime follows it in the TSTInfo, because genTime is the fifth TSTInfo " +
			"member and a verifier never searches further along for one.",
	}, {
		name: "anchor-gen-time-utc-time-tag", claimAt: at,
		genTime: asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagUTCTime,
			Bytes: []byte("20260727150100Z")},
		notAfter: yearEnd,
		why: "A token whose genTime slot holds well-formed genTime text under the UTCTime tag " +
			"fails the anchor check, because genTime must be a universal GeneralizedTime.",
	}} {
		s.tokenVector(c.name, c.claimAt, c.ok, c.why, func(link string) string {
			info := tstInfoDER(sha256Imprint(link), c.genTime, c.trailing...)
			return timestampToken(info, c.notAfter)
		})
		if c.ok {
			s.expectAttested(c.name, c.attested+" by CN="+vectorAuthority)
		}
	}
}

// tokenStructure emits the vectors that pin how a verifier reads a timestamp token's TSTInfo: as a
// SEQUENCE whose members sit at fixed positions. One token's imprint uses SHA-384 while a SHA-256
// imprint of the right link trails the TSTInfo, so a verifier that searched for any SHA-256 imprint
// would accept a token whose own imprint it cannot check. Another carries a well-formed TSTInfo
// under a SET tag.
func (s *state) tokenStructure() {
	yearEnd := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	why := "A token whose message imprint uses SHA-384 fails the anchor check, although a " +
		"SHA-256 imprint of the right link follows genTime in the TSTInfo, because the message " +
		"imprint is the third TSTInfo member and must be SHA-256."
	s.tokenVector("anchor-imprint-trailing-sha256", at, false, why, func(link string) string {
		raw, err := hex.DecodeString(link)
		if err != nil {
			panic(err)
		}
		sum := sha512.Sum384(raw)
		own := tsaImprint{Algorithm: tsaAlgorithm{oidSHA384}, Digest: sum[:]}
		info := tstInfoDER(own, generalizedTime("20260727150100Z"),
			mustMarshal(sha256Imprint(link)))
		return timestampToken(info, yearEnd)
	})
	why = "A token whose TSTInfo is encoded under a SET tag rather than a SEQUENCE fails the " +
		"anchor check, although its members are all in place."
	s.tokenVector("anchor-tst-info-not-sequence", at, false, why, func(link string) string {
		info := tstInfoDER(sha256Imprint(link), generalizedTime("20260727150100Z"))
		info[0] = 0x31
		return timestampToken(info, yearEnd)
	})
}

// derRules emits the vectors that pin how a verifier reads a timestamp token as DER: one token per
// rule, each minted over the vector's own link and signed over whatever its encoding became, so
// the rule alone decides the verdict. Every one fails the anchor check, except the two RSA tokens
// that pin the RSA path agreeing when nothing is wrong.
//
//nolint:funlen // One vector per DER rule, listed in one place.
func (s *state) derRules() {
	ed := edTokenSigner()
	rsaSigner := rsaTokenSigner()
	odd := rsaMultiPrime(2049, 2049)
	rsaKey := rsaVectorKey(2048, 2048, 65537)
	even := &rsaRaw{pub: &rsaKey.PublicKey, exp: privateExp(rsaKey)}
	for _, c := range []struct {
		// name is the vector's name and the stem of its file.
		name string
		// signer signs the token; nil means the Ed25519 authority.
		signer *tokenSigner
		// mutate changes the token's tree before it is encoded and signed.
		mutate func(t *tokenTree)
		// ok is whether the bundle must verify.
		ok bool
		// attested is the line a verifier reports for a token that verifies; empty means
		// vectorAttested.
		attested string
		// why is the vector's description in the manifest.
		why string
	}{{
		name: "anchor-der-length-long-form",
		mutate: func(t *tokenTree) {
			t.n["genTime"].header = func(tag byte, c []byte) []byte {
				return append([]byte{tag, 0x81, byte(len(c))}, c...)
			}
		},
		why: "A token whose genTime length is written in the long form although it is below 128 " +
			"fails the anchor check, because DER writes every length in its shortest form.",
	}, {
		name: "anchor-der-length-leading-zero",
		mutate: func(t *tokenTree) {
			t.n["cert"].header = func(tag byte, c []byte) []byte {
				return append([]byte{tag, 0x83, 0x00, byte(len(c) >> 8), byte(len(c))}, c...)
			}
		},
		why: "A token whose signer certificate length is written in three octets, the first of " +
			"them zero, fails the anchor check, because DER writes every length in its shortest " +
			"form.",
	}, {
		name: "anchor-der-length-nine-octets",
		mutate: func(t *tokenTree) {
			t.n["cert"].header = func(tag byte, c []byte) []byte {
				return append([]byte{tag, 0x89, 0x01, 0, 0, 0, 0, 0, 0, byte(len(c) >> 8),
					byte(len(c))}, c...)
			}
		},
		why: "A token whose signer certificate length is written in nine octets, a value that is " +
			"the true length plus 2^64, fails the anchor check, because a length has at most " +
			"four octets, and a reader that kept nine in a 64-bit integer would read the true " +
			"length.",
	}, {
		name: "anchor-der-length-indefinite",
		mutate: func(t *tokenTree) {
			t.n["imprint"].header = func(tag byte, c []byte) []byte {
				return append(append([]byte{tag, 0x80}, c...), 0x00, 0x00)
			}
		},
		why: "A token whose message imprint has an indefinite length fails the anchor check, " +
			"because DER lengths are definite.",
	}, {
		name: "anchor-der-length-overrun",
		mutate: func(t *tokenTree) {
			t.n["genTime"].header = func(tag byte, c []byte) []byte {
				return append([]byte{tag, byte(len(c) + 1)}, c...)
			}
		},
		why: "A token whose genTime length runs one octet past the end of its TSTInfo fails the " +
			"anchor check, because every element lies wholly inside its container.",
	}, {
		name: "anchor-der-high-tag-number",
		mutate: func(t *tokenTree) {
			tst := t.n["tst"]
			tst.kids = append(tst.kids, &derNode{header: func(byte, []byte) []byte {
				return []byte{0x1f, 0x01, 0x00}
			}})
		},
		why: "A token whose TSTInfo carries, after genTime, an element whose identifier uses the " +
			"high tag number form fails the anchor check, although no verifier interprets that " +
			"member, because every element in a token has a one-octet identifier.",
	}, {
		name: "anchor-der-trailing-after-token",
		mutate: func(t *tokenTree) {
			t.trailing = []byte{0x05, 0x00}
		},
		why: "A token followed by another element fails the anchor check, because nothing may " +
			"follow the ContentInfo.",
	}, {
		name: "anchor-der-trailing-in-explicit",
		mutate: func(t *tokenTree) {
			w := t.n["ciWrap"]
			w.kids = append(w.kids, &derNode{tag: 0x05})
		},
		why: "A token whose ContentInfo [0] holds an element after the SignedData fails the " +
			"anchor check, because an explicit tag holds exactly one element.",
	}, {
		name: "anchor-der-trailing-in-econtent",
		mutate: func(t *tokenTree) {
			tst := t.n["tst"]
			t.n["eContent"].fill = func() []byte {
				return append(tst.encode(), 0x05, 0x00)
			}
		},
		why: "A token whose eContent OCTET STRING holds an element after the TSTInfo fails the " +
			"anchor check, because the OCTET STRING holds exactly the DER TSTInfo, which the " +
			"signed attributes commit to.",
	}, {
		name: "anchor-der-malformed-unread-member",
		mutate: func(t *tokenTree) {
			tst := t.n["tst"]
			tst.kids = append(tst.kids, &derNode{tag: 0x30, header: func(_ byte, _ []byte) []byte {
				return []byte{0x30, 0x05, 0x02, 0x01}
			}})
		},
		why: "A token whose TSTInfo carries, after genTime, an element whose length runs past " +
			"the TSTInfo fails the anchor check, although no verifier interprets that member, " +
			"because a token is DER throughout.",
	}, {
		name: "anchor-der-integer-empty",
		mutate: func(t *tokenTree) {
			t.n["tstSerial"].val = []byte{}
		},
		why: "A token whose TSTInfo serial number is an INTEGER with no content octets fails the " +
			"anchor check, because a DER INTEGER has at least one.",
	}, {
		name: "anchor-der-integer-non-minimal",
		mutate: func(t *tokenTree) {
			t.n["tstVersion"].val = []byte{0x00, 0x01}
		},
		why: "A token whose TSTInfo version is the INTEGER 1 written as 00 01 fails the anchor " +
			"check, because DER writes an INTEGER in its shortest form.",
	}, {
		name: "anchor-der-version-over-64-bits",
		mutate: func(t *tokenTree) {
			t.n["tstVersion"].val = []byte{0x01, 0, 0, 0, 0, 0, 0, 0, 0}
		},
		why: "A token whose TSTInfo version needs nine octets fails the anchor check, because a " +
			"version must fit a signed 64-bit integer.",
	}, {
		name: "anchor-der-oid-empty",
		mutate: func(t *tokenTree) {
			t.n["policy"].val = []byte{}
		},
		why: "A token whose TSTInfo policy is an OBJECT IDENTIFIER with no content octets fails " +
			"the anchor check.",
	}, {
		name: "anchor-der-oid-non-minimal",
		mutate: func(t *tokenTree) {
			p := t.n["policy"]
			p.val = append([]byte{p.val[0], 0x80}, p.val[1:]...)
		},
		why: "A token whose TSTInfo policy pads a subidentifier with a leading 0x80 octet fails " +
			"the anchor check, because DER writes each subidentifier in its shortest form.",
	}, {
		name: "anchor-der-oid-truncated",
		mutate: func(t *tokenTree) {
			p := t.n["policy"]
			p.val = append(slices.Clone(p.val[:len(p.val)-1]), p.val[len(p.val)-1]|0x80)
		},
		why: "A token whose TSTInfo policy ends inside a subidentifier fails the anchor check.",
	}, {
		name: "anchor-der-signed-attrs-primitive",
		mutate: func(t *tokenTree) {
			t.n["attrs"].tag = 0x80
		},
		why: "A token whose signed attributes carry a primitive [0] identifier fails the anchor " +
			"check, because the signed attributes are a constructed [0], and a verifier compares " +
			"the whole identifier octet.",
	}, {
		name: "anchor-der-sid-constructed",
		mutate: func(t *tokenTree) {
			inner := derElement(0x04, tokenSKI)
			t.n["ski"].val = inner
			t.n["sid"] = &derNode{tag: 0xa0, val: inner}
			t.n["si"].kids[1] = t.n["sid"]
		},
		why: "A token whose signer identifier is a constructed [0] fails the anchor check, " +
			"although its content equals the signer certificate's subject key identifier, " +
			"because a subject key identifier is a primitive [0].",
	}, {
		name: "anchor-der-critical-not-ff",
		mutate: func(t *tokenTree) {
			t.n["ekuCritical"].val = []byte{0x01}
		},
		why: "A token whose signer certificate marks an extension critical with the BOOLEAN octet " +
			"0x01 fails the anchor check, because DER writes TRUE as 0xFF.",
	}, {
		name: "anchor-der-critical-false-encoded",
		mutate: func(t *tokenTree) {
			t.n["ekuCritical"].val = []byte{0x00}
		},
		why: "A token whose signer certificate writes an extension's critical flag as FALSE fails " +
			"the anchor check, because DER never encodes a default value.",
	}, {
		name: "anchor-cert-time-utc-no-seconds",
		mutate: func(t *tokenTree) {
			t.n["notAfter"].val = []byte("2701010000Z")
		},
		why: "A token whose signer certificate's notAfter is a UTCTime without seconds fails the " +
			"anchor check, because DER and RFC 5280 write a UTCTime as YYMMDDhhmmssZ.",
	}, {
		name: "anchor-cert-time-utc-offset",
		mutate: func(t *tokenTree) {
			t.n["notAfter"].val = []byte("270101010000+0100")
		},
		why: "A token whose signer certificate's notAfter is a UTCTime with a numeric offset " +
			"fails the anchor check, because DER and RFC 5280 end a UTCTime in Z.",
	}, {
		name: "anchor-cert-time-generalized-fraction",
		mutate: func(t *tokenTree) {
			t.n["notAfter"].tag = 0x18
			t.n["notAfter"].val = []byte("20270101000000.5Z")
		},
		why: "A token whose signer certificate's notAfter is a GeneralizedTime with a fraction " +
			"fails the anchor check, because RFC 5280 writes it as YYYYMMDDhhmmssZ.",
	}, {
		name: "anchor-cert-time-year-0000",
		mutate: func(t *tokenTree) {
			t.n["notBefore"].tag = 0x18
			t.n["notBefore"].val = []byte("00000101000000Z")
		},
		why: "A token whose signer certificate's notBefore is in year 0000 fails the anchor " +
			"check, because a certificate time has the ranges a bundle time has.",
	}, {
		name: "anchor-cert-not-version-3",
		mutate: func(t *tokenTree) {
			tbs := t.n["tbs"]
			tbs.kids = tbs.kids[1:]
		},
		why: "A token whose signer certificate carries no version member fails the anchor check, " +
			"because the signer must be a version 3 certificate.",
	}, {
		name: "anchor-cert-duplicate-extension",
		mutate: func(t *tokenTree) {
			exts := t.n["exts"]
			exts.kids = append(exts.kids, t.n["ekuExt"])
		},
		why: "A token whose signer certificate carries its extended key usage extension twice " +
			"fails the anchor check, because no extension may appear twice.",
	}, {
		name: "anchor-cert-key-unused-bits",
		mutate: func(t *tokenTree) {
			k := t.n["spkiKey"]
			k.val = append([]byte{0x01}, k.val[1:]...)
		},
		why: "A token whose signer key BIT STRING declares unused bits fails the anchor check, " +
			"because a key is whole octets.",
	}, {
		name: "anchor-cert-ed25519-parameters",
		mutate: func(t *tokenTree) {
			alg := t.n["spkiAlg"]
			alg.kids = append(alg.kids, &derNode{tag: 0x05})
		},
		why: "A token whose Ed25519 signer key carries algorithm parameters fails the anchor " +
			"check, because RFC 8410 requires them absent.",
	}, {
		name: "anchor-signature-algorithm-key-mismatch",
		mutate: func(t *tokenTree) {
			t.n["sigAlgOID"].val = oidBytes(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2})
		},
		why: "A token whose Ed25519 signature is labeled ecdsa-with-SHA256 fails the anchor " +
			"check, because the signature algorithm must match the signer key, and a verifier " +
			"never checks a signature under a scheme the signer did not name.",
	}, {
		name: "anchor-ec-p256", signer: ecTokenSigner(false, false), ok: true,
		why: "A token signed by a P-256 ECDSA authority whose key is an uncompressed point " +
			"verifies.",
	}, {
		name: "anchor-ec-signature-trailing", signer: ecTokenSigner(false, false),
		mutate: func(t *tokenTree) {
			t.signatureSuffix = []byte{0x00}
		},
		why: "A token whose valid ECDSA signature is followed by one more octet fails the " +
			"anchor check, because an ECDSA signature is exactly one SEQUENCE of two INTEGERs.",
	}, {
		name: "anchor-ec-compressed-point", signer: ecTokenSigner(true, false),
		why: "A token whose ECDSA signer key is a compressed point fails the anchor check, " +
			"because a verifier reads only the uncompressed form.",
	}, {
		name: "anchor-ec-unsupported-curve", signer: ecTokenSigner(false, true),
		why: "A token whose ECDSA signer key is on secp256k1 fails the anchor check, because a " +
			"verifier reads keys on P-224, P-256, P-384, and P-521 only.",
	}, {
		name: "anchor-rsa-pkcs1", signer: rsaSigner, ok: true,
		why: "A token signed by a 2048-bit RSA authority with sha256WithRSAEncryption verifies.",
	}, {
		name: "anchor-rsa-bare-key-algorithm", signer: rsaSigner, ok: true,
		mutate: func(t *tokenTree) {
			t.n["sigAlgOID"].val = oidBytes(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1})
		},
		why: "A token whose RSA signature algorithm names only rsaEncryption verifies, checked " +
			"with the signer's SHA-256 digest.",
	}, {
		name: "anchor-rsa-key-1023-bits", signer: rsaSmallSigner(),
		why: "A token whose RSA signer key has a 1023-bit modulus fails the anchor check, because " +
			"a verifier reads RSA keys of at least 1024 bits.",
	}, {
		name: "anchor-rsa-signature-short", signer: rsaSigner,
		mutate: func(t *tokenTree) {
			t.shortSignature = true
		},
		why: "A token whose RSA signature drops a leading zero octet, so it is shorter than the " +
			"modulus, fails the anchor check, because RFC 8017 requires the signature to be as " +
			"long as the modulus.",
	}, {
		name: "anchor-der-tag-class",
		mutate: func(t *tokenTree) {
			t.n["tstVersion"].tag = 0x82
		},
		why: "A token whose TSTInfo version is written under the context-specific class with the " +
			"INTEGER's tag number fails the anchor check, because a verifier compares the whole " +
			"identifier octet, class included.",
	}, {
		name: "anchor-rsa-key-16384-bits", ok: true,
		signer: rsaMultiPrime(16384, 16384).pkcs1Signer(digestInfoSHA256),
		why: "A token signed by an RSA authority whose modulus is 16384 bits, the longest a " +
			"verifier reads, verifies.",
	}, {
		name:   "anchor-rsa-key-16385-bits",
		signer: rsaMultiPrime(16385, 16385).pkcs1Signer(digestInfoSHA256),
		why: "A token whose valid signature is made with an RSA modulus of 16385 bits fails the " +
			"anchor check, because a verifier reads RSA keys of at most 16384 bits.",
	}, {
		name: "anchor-rsa-exponent-over-31-bits", signer: rsaWideExponentSigner(),
		why: "A token whose valid signature is made with the RSA public exponent 2^32-5 fails " +
			"the anchor check, because a verifier reads RSA exponents from 3 to 2^31-1.",
	}, {
		name: "anchor-rsa-key-parameters-absent", signer: rsaSigner,
		mutate: func(t *tokenTree) {
			alg := t.n["spkiAlg"]
			alg.kids = alg.kids[:1]
		},
		why: "A token whose RSA signer key names rsaEncryption without the NULL parameters fails " +
			"the anchor check, because RFC 3279 writes them as NULL.",
	}, {
		name: "anchor-rsa-key-trailing", signer: rsaSigner,
		mutate: func(t *tokenTree) {
			k := t.n["spkiKey"]
			k.val = append(slices.Clone(k.val), 0x05, 0x00)
		},
		why: "A token whose RSA key BIT STRING holds another element after the key SEQUENCE " +
			"fails the anchor check, because the BIT STRING holds exactly one SEQUENCE.",
	}, {
		name: "anchor-rsa-key-extra-member", signer: rsaSigner,
		mutate: func(t *tokenTree) {
			k := t.n["spkiKey"]
			k.val = append([]byte{0}, rsaKeyWith(k.val[1:], 0x02, 0x01, 0x05)...)
		},
		why: "A token whose RSA key SEQUENCE holds the INTEGER 5 after the modulus and the " +
			"exponent fails the anchor check, because the key holds only those two.",
	}, {
		name: "anchor-rsa-key-extra-octets", signer: rsaSigner,
		mutate: func(t *tokenTree) {
			k := t.n["spkiKey"]
			k.val = append([]byte{0}, rsaKeyWith(k.val[1:], 0xff, 0xff, 0xff)...)
		},
		why: "A token whose RSA key SEQUENCE holds three octets that are not DER after the " +
			"modulus and the exponent fails the anchor check, because the key holds only those " +
			"two, and nothing inside it goes unread.",
	}, {
		name: "anchor-cert-ed25519-key-33-octets",
		mutate: func(t *tokenTree) {
			k := t.n["spkiKey"]
			k.val = append(slices.Clone(k.val), 0x00)
		},
		why: "A token whose Ed25519 signer key is its true 32 octets followed by a zero octet " +
			"fails the anchor check, because an Ed25519 key is exactly 32 octets.",
	}, {
		name: "anchor-cert-no-timestamping-usage",
		mutate: func(t *tokenTree) {
			t.n["eku"].kids = []*derNode{derOID(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 1})}
		},
		why: "A token whose signer certificate's extended key usage lists only serverAuth fails " +
			"the anchor check, because the signer must be marked for timestamping.",
	}, {
		name: "anchor-cert-ski-trailing",
		mutate: func(t *tokenTree) {
			ski := t.n["ski"]
			t.n["skiValue"].fill = func() []byte { return append(ski.encode(), 0x05, 0x00) }
		},
		why: "A token whose signer certificate's subject key identifier value holds another " +
			"element after the identifier fails the anchor check, because the value holds " +
			"exactly one OCTET STRING.",
	}, {
		name: "anchor-no-message-digest",
		mutate: func(t *tokenTree) {
			attrs := t.n["attrs"]
			attrs.kids = attrs.kids[:1]
		},
		why: "A token whose signed attributes carry no messageDigest attribute fails the anchor " +
			"check, because the signature then covers nothing that names the TSTInfo.",
	}, {
		name: "anchor-imprint-sha384-algorithm",
		mutate: func(t *tokenTree) {
			t.n["imprint"].kids[0] = derSeq(0x30, derOID(oidSHA384))
		},
		why: "A token whose message imprint holds the SHA-256 of the right link but names " +
			"SHA-384 fails the anchor check, because the imprint must use SHA-256.",
	}, {
		name: "anchor-two-signers",
		mutate: func(t *tokenTree) {
			infos := t.n["signerInfos"]
			infos.kids = append(infos.kids, t.n["si"])
		},
		why: "A token whose signerInfos holds the authority's valid SignerInfo twice fails the " +
			"anchor check, because a token has exactly one signer.",
	}, {
		name: "anchor-der-null-content", signer: rsaSigner,
		mutate: func(t *tokenTree) {
			t.n["spkiAlg"].kids[1].val = []byte{0x00}
		},
		why: "A token whose RSA signer key parameters are a NULL holding one octet fails the " +
			"anchor check, because a DER NULL has no content octets.",
	}, {
		name: "anchor-rsa-modulus-even", signer: rsaEvenModulusSigner(),
		why: "A token whose valid signature is made with an even RSA modulus of 1025 bits fails " +
			"the anchor check, because an RSA modulus is odd.",
	}, {
		name: "anchor-rsa-exponent-one", signer: rsaExponentOneSigner(),
		why: "A token whose RSA public exponent is 1, so its valid signature is its own encoded " +
			"message, fails the anchor check, because the exponent is at least 3.",
	}, {
		name: "anchor-rsa-exponent-even", signer: rsaExponentFourSigner(),
		why: "A token whose valid signature is made with the RSA public exponent 4 fails the " +
			"anchor check, because the exponent is odd.",
	}, {
		name: "anchor-rsa-signature-not-below-modulus", signer: odd.pkcs1Signer(digestInfoSHA256),
		mutate: func(t *tokenTree) {
			t.rewriteSignature = func(sig []byte) []byte {
				v := new(big.Int).SetBytes(sig)
				return v.Add(v, odd.pub.N).FillBytes(make([]byte, len(sig)))
			}
		},
		why: "A token whose RSA signature is a valid signature plus the modulus, written in as " +
			"many octets as the modulus, fails the anchor check, because RFC 8017 requires the " +
			"signature to be below the modulus.",
	}, {
		name: "anchor-rsa-digest-info-without-null",
		signer: odd.pkcs1Signer([]byte{0x30, 0x2f, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
			0x65, 0x03, 0x04, 0x02, 0x01, 0x04, 0x20}),
		why: "A token whose PKCS #1 v1.5 signature encodes the SHA-256 DigestInfo without its NULL " +
			"parameters fails the anchor check, because a verifier compares the whole encoding " +
			"with the one RFC 8017 writes.",
	}, {
		name: "anchor-rsa-pss", signer: odd.pssSigner(pssForm{salt: 32}), ok: true,
		why: "A token signed with RSASSA-PSS over SHA-256 with a 32-octet salt, under a 2049-bit " +
			"modulus whose encoded message is one octet shorter than the signature, verifies.",
	}, {
		name: "anchor-rsa-pss-salt-20", signer: odd.pssSigner(pssForm{salt: 20}),
		why: "A token whose RSASSA-PSS signature is valid with a 20-octet salt fails the anchor " +
			"check, because a verifier reads PSS with a salt as long as the SHA-256 digest.",
	}, {
		name: "anchor-rsa-pss-other-digest", signer: odd.pssSigner(pssForm{salt: 32, other: true}),
		why: "A token whose well-formed RSASSA-PSS signature covers other attributes than the " +
			"token carries fails the anchor check.",
	}, {
		name: "anchor-rsa-pss-trailer", signer: odd.pssSigner(pssForm{salt: 32, trailer: 0xbb}),
		why: "A token whose RSASSA-PSS encoding ends in 0xbb rather than 0xbc, and is otherwise " +
			"right, fails the anchor check.",
	}, {
		name: "anchor-rsa-pss-top-bit", signer: even.pssSigner(pssForm{salt: 32, topBit: true}),
		why: "A token whose RSASSA-PSS encoding under a 2048-bit modulus sets its leftmost bit, " +
			"which a 2047-bit encoding leaves clear, and is otherwise right, fails the anchor " +
			"check.",
	}, {
		name: "anchor-rsa-pss-leading-octet", signer: odd.pssSigner(pssForm{salt: 32, lead: true}),
		why: "A token whose RSASSA-PSS signature under a 2049-bit modulus recovers a right " +
			"encoding behind a leading octet of 1, where a zero octet belongs, fails the anchor " +
			"check.",
	}, {
		name: "anchor-signature-algorithm-rsa-key-mismatch", signer: rsaSigner,
		mutate: func(t *tokenTree) {
			t.n["sigAlgOID"].val = oidBytes(asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2})
		},
		why: "A token whose RSA signature is labeled ecdsa-with-SHA256 fails the anchor check, " +
			"because the signature algorithm must match the signer key.",
	}, {
		name: "anchor-signature-algorithm-ec-key-mismatch", signer: ecTokenSigner(false, false),
		mutate: func(t *tokenTree) {
			t.n["sigAlgOID"].val = oidBytes(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11})
		},
		why: "A token whose ECDSA signature is labeled sha256WithRSAEncryption fails the anchor " +
			"check, because the signature algorithm must match the signer key.",
	}, {
		name: "anchor-signature-invalid",
		mutate: func(t *tokenTree) {
			t.rewriteSignature = func(sig []byte) []byte {
				sig = slices.Clone(sig)
				sig[0] ^= 0x01
				return sig
			}
		},
		why: "A token whose Ed25519 signature has one bit changed fails the anchor check.",
	}, {
		name: "anchor-imprint-other-link",
		mutate: func(t *tokenTree) {
			sum := sha256.Sum256([]byte("another link"))
			t.n["imprint"].kids[1].val = sum[:]
		},
		why: "A token whose SHA-256 message imprint is of another value than the anchored link " +
			"fails the anchor check, because the token attests to that value and no other.",
	}, {
		name: "anchor-no-certificates",
		mutate: func(t *tokenTree) {
			sd := t.n["signedData"]
			sd.kids = slices.DeleteFunc(slices.Clone(sd.kids), func(k *derNode) bool {
				return k == t.n["certs"]
			})
		},
		why: "A token that carries no certificates fails the anchor check, because its signature " +
			"can only be checked against a certificate it carries.",
	}, {
		name: "anchor-no-signers",
		mutate: func(t *tokenTree) {
			t.n["signerInfos"].kids = []*derNode{}
		},
		why: "A token whose signerInfos SET is empty fails the anchor check, because a token has " +
			"exactly one signer.",
	}, {
		name: "anchor-message-digest-mismatch",
		mutate: func(t *tokenTree) {
			t.n["md"].fill = func() []byte {
				sum := sha256.Sum256([]byte("another TSTInfo"))
				return sum[:]
			}
		},
		why: "A token whose messageDigest attribute is the digest of other octets than its " +
			"eContent fails the anchor check, although its signature over the attributes is valid.",
	}, {
		name: "anchor-message-digest-two-values",
		mutate: func(t *tokenTree) {
			v := t.n["mdValues"]
			v.kids = append(v.kids, t.n["md"])
		},
		why: "A token whose messageDigest attribute holds the right digest twice fails the anchor " +
			"check, because its SET holds exactly one OCTET STRING.",
	}, {
		name: "anchor-digest-algorithm-sha1",
		mutate: func(t *tokenTree) {
			t.n["siDigest"].kids[0] = derOID(asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26})
			eContent := t.n["eContent"]
			t.n["md"].fill = func() []byte {
				sum := sha1.Sum(eContent.fill())
				return sum[:]
			}
		},
		why: "A token whose signer digests the eContent with SHA-1, consistently and under a " +
			"valid signature, fails the anchor check, because the digest is SHA-256, SHA-384 or " +
			"SHA-512.",
	}, {
		name: "anchor-signer-not-carried",
		mutate: func(t *tokenTree) {
			t.n["sid"].kids[1] = derInt(8)
		},
		why: "A token whose signer identifier names serial number 8 under the right issuer, while " +
			"it carries only the certificate with serial number 7, fails the anchor check, " +
			"because a verifier never checks a signature against a certificate the signer " +
			"identifier does not name.",
	}, {
		name: "anchor-content-type-not-signed-data",
		mutate: func(t *tokenTree) {
			t.n["contentType"].val = oidBytes(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1})
		},
		why: "A token whose ContentInfo names id-data rather than signedData fails the anchor " +
			"check.",
	}, {
		name: "anchor-econtent-type-not-tst-info",
		mutate: func(t *tokenTree) {
			t.n["eContentType"].val = oidBytes(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1})
		},
		why: "A token whose encapsulated content names id-data rather than id-ct-TSTInfo fails " +
			"the anchor check.",
	}, {
		name: "anchor-cert-not-yet-valid",
		mutate: func(t *tokenTree) {
			t.n["notBefore"].val = []byte("260727150200Z")
		},
		why: "A token whose genTime, 15:01:00, falls a minute before its signer certificate's " +
			"notBefore fails the anchor check, because the certificate was not yet valid when it " +
			"signed.",
	}, {
		name: "anchor-validity-utc-year-pivot", ok: true,
		mutate: func(t *tokenTree) {
			t.n["notBefore"].val = []byte("500101000000Z")
			t.n["notAfter"].val = []byte("491231235959Z")
		},
		why: "A token whose signer certificate is valid from the UTCTime 500101000000Z, read as " +
			"1950, to 491231235959Z, read as 2049, verifies, because a two-digit year from 50 " +
			"to 99 is 19YY and one below 50 is 20YY.",
	}, {
		name: "anchor-cert-time-wrong-tag",
		mutate: func(t *tokenTree) {
			t.n["notAfter"].tag = 0x13
		},
		why: "A token whose signer certificate's notAfter holds UTCTime text under the " +
			"PrintableString tag fails the anchor check, because a validity time is a UTCTime " +
			"or a GeneralizedTime.",
	}, {
		name: "anchor-cert-eku-trailing",
		mutate: func(t *tokenTree) {
			eku := t.n["eku"]
			t.n["ekuExt"].kids[2].fill = func() []byte { return append(eku.encode(), 0x05, 0x00) }
		},
		why: "A token whose signer certificate's extended key usage value holds another element " +
			"after the SEQUENCE of purposes fails the anchor check, because the value holds " +
			"exactly one SEQUENCE.",
	}, {
		name: "anchor-cert-extensions-trailing",
		mutate: func(t *tokenTree) {
			w := t.n["extsWrap"]
			w.kids = append(slices.Clone(w.kids), &derNode{tag: 0x05})
		},
		why: "A token whose signer certificate's [3] holds another element after the SEQUENCE of " +
			"extensions fails the anchor check, because an explicit tag holds exactly one element.",
	}, {
		name: "anchor-cert-version-trailing",
		mutate: func(t *tokenTree) {
			w := t.n["certVersion"]
			w.kids = append(slices.Clone(w.kids), &derNode{tag: 0x05})
		},
		why: "A token whose signer certificate's [0] holds another element after the version " +
			"INTEGER fails the anchor check, because an explicit tag holds exactly one element.",
	}, {
		name: "anchor-der-oid-huge-arc",
		mutate: func(t *tokenTree) {
			t.n["imprint"].kids[0].kids[0].val = hugeArc()
		},
		why: "A token whose message imprint hash algorithm is an OBJECT IDENTIFIER under 1.2 " +
			"with one subidentifier of 3,000 octets fails the anchor check, and never faults " +
			"a verifier, because no subidentifier a verifier reads exceeds 2^31-1.",
	}, {
		name: "anchor-der-oid-huge-arc-content-type",
		mutate: func(t *tokenTree) {
			t.n["contentType"].val = hugeArc()
		},
		why: "A token whose contentType has one subidentifier of 3,000 octets fails the anchor " +
			"check without a verifier fault.",
	}, {
		name: "anchor-der-oid-huge-arc-econtent-type",
		mutate: func(t *tokenTree) {
			t.n["eContentType"].val = hugeArc()
		},
		why: "A token whose eContentType has one subidentifier of 3,000 octets fails the anchor " +
			"check without a verifier fault.",
	}, {
		name: "anchor-der-oid-huge-arc-digest-algorithm",
		mutate: func(t *tokenTree) {
			t.n["siDigest"].kids[0].val = hugeArc()
		},
		why: "A token whose SignerInfo digestAlgorithm has one subidentifier of 3,000 octets " +
			"fails the anchor check without a verifier fault.",
	}, {
		name: "anchor-der-oid-huge-arc-signature-algorithm",
		mutate: func(t *tokenTree) {
			t.n["sigAlgOID"].val = hugeArc()
		},
		why: "A token whose signatureAlgorithm has one subidentifier of 3,000 octets fails the " +
			"anchor check without a verifier fault.",
	}, {
		name: "anchor-der-oid-huge-arc-key-algorithm",
		mutate: func(t *tokenTree) {
			t.n["spkiAlg"].kids[0].val = hugeArc()
		},
		why: "A token whose signer key's algorithm has one subidentifier of 3,000 octets fails " +
			"the anchor check without a verifier fault.",
	}, {
		name: "anchor-der-oid-huge-arc-curve", signer: ecTokenSigner(false, false),
		mutate: func(t *tokenTree) {
			t.n["spkiAlg"].kids[1].val = hugeArc()
		},
		why: "A token whose ECDSA signer key names a curve with one subidentifier of 3,000 " +
			"octets fails the anchor check without a verifier fault.",
	}, {
		name: "anchor-der-oid-huge-arc-extension-twice",
		mutate: func(t *tokenTree) {
			ext := func() *derNode {
				return derSeq(0x30, &derNode{tag: 0x06, val: hugeArc()},
					&derNode{tag: 0x04, val: []byte{0x05, 0x00}})
			}
			exts := t.n["exts"]
			exts.kids = append(slices.Clone(exts.kids), ext(), ext())
		},
		why: "A token whose signer certificate carries twice an extension whose extnID has one " +
			"subidentifier of 3,000 octets fails the anchor check without a verifier fault.",
	}, {
		name: "anchor-der-oid-huge-arc-extension-critical",
		mutate: func(t *tokenTree) {
			exts := t.n["exts"]
			exts.kids = append(slices.Clone(exts.kids), derSeq(0x30,
				&derNode{tag: 0x06, val: hugeArc()}, &derNode{tag: 0x01, val: []byte{0x01}},
				&derNode{tag: 0x04, val: []byte{0x05, 0x00}}))
		},
		why: "A token whose signer certificate marks critical, with the BOOLEAN octet 0x01, an " +
			"extension whose extnID has one subidentifier of 3,000 octets fails the anchor " +
			"check without a verifier fault.",
	}, {
		name: "anchor-der-oid-arc-over-31-bits",
		mutate: func(t *tokenTree) {
			t.n["policy"].val = oidBytes(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 1 << 31})
		},
		why: "A token whose policy is 1.3.6.1.4.1.2147483648 fails the anchor check, because no " +
			"subidentifier a verifier reads exceeds 2^31-1, the bound Go's encoding/asn1 holds " +
			"one to.",
	}, {
		name: "anchor-der-oid-arc-31-bits", ok: true,
		mutate: func(t *tokenTree) {
			t.n["policy"].val = oidBytes(asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 1<<31 - 1})
		},
		why: "A token whose policy is 1.3.6.1.4.1.2147483647 verifies, because a subidentifier " +
			"of 2^31-1 is within the bound.",
	}, {
		name: "anchor-der-oid-extension-non-minimal",
		mutate: func(t *tokenTree) {
			exts := t.n["exts"]
			exts.kids = append(slices.Clone(exts.kids), derSeq(0x30,
				&derNode{tag: 0x06, val: []byte{0x55, 0x1d, 0x80, 0x0f}},
				&derNode{tag: 0x04, val: []byte{0x03, 0x02, 0x07, 0x80}}))
		},
		why: "A token whose signer certificate carries an extension no verifier interprets, " +
			"whose extnID pads a subidentifier with 0x80, fails the anchor check, because every " +
			"extnID is read and DER writes each subidentifier in its shortest form.",
	}, {
		name: "anchor-der-oid-key-purpose-non-minimal",
		mutate: func(t *tokenTree) {
			eku := t.n["eku"]
			eku.kids = append(slices.Clone(eku.kids), &derNode{tag: 0x06,
				val: []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x80, 0x02}})
		},
		why: "A token whose signer certificate lists, after id-kp-timeStamping, a key purpose " +
			"that pads a subidentifier with 0x80 fails the anchor check, because every key " +
			"purpose is read.",
	}, {
		name: "anchor-der-oid-attribute-type-non-minimal",
		mutate: func(t *tokenTree) {
			attrs := t.n["attrs"]
			attrs.kids = append(slices.Clone(attrs.kids), derSeq(0x30,
				&derNode{tag: 0x06, val: []byte{0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09,
					0x80, 0x05}},
				derSeq(0x31, &derNode{tag: 0x17, val: []byte("260727150100Z")})))
		},
		why: "A token whose signed attributes carry, after the messageDigest, an attribute whose " +
			"type pads a subidentifier with 0x80 fails the anchor check, because every signed " +
			"attribute's type is read.",
	}, {
		name: "anchor-der-signed-data-version-non-minimal",
		mutate: func(t *tokenTree) {
			t.n["signedData"].kids[0].val = []byte{0x00, 0x03}
		},
		why: "A token whose SignedData version is the INTEGER 3 written as 00 03 fails the " +
			"anchor check, because DER writes an INTEGER in its shortest form.",
	}, {
		name: "anchor-der-signer-info-version-non-minimal",
		mutate: func(t *tokenTree) {
			t.n["si"].kids[0].val = []byte{0x00, 0x01}
		},
		why: "A token whose SignerInfo version is the INTEGER 1 written as 00 01 fails the " +
			"anchor check, because DER writes an INTEGER in its shortest form.",
	}, {
		name: "anchor-der-trailing-in-econtent-explicit",
		mutate: func(t *tokenTree) {
			w := t.n["signedData"].kids[2].kids[1]
			w.kids = append(slices.Clone(w.kids), &derNode{tag: 0x05})
		},
		why: "A token whose eContent [0] holds a NULL after the OCTET STRING fails the anchor " +
			"check, because an explicit tag holds exactly one element.",
	}, {
		name: "anchor-cert-extra-version-non-minimal",
		mutate: func(t *tokenTree) {
			extra := newTokenTree(ed, "00")
			extra.n["certSerial"].val = []byte{0x08}
			extra.n["certVersion"].kids[0].val = []byte{0x00, 0x02}
			t.n["certs"].kids = append(slices.Clone(t.n["certs"].kids), extra.n["cert"])
		},
		why: "A token that carries, after its signer certificate, a second certificate whose " +
			"version is the INTEGER 2 written as 00 02 fails the anchor check, because every " +
			"carried certificate is read, whichever one signed.",
	}, {
		name: "anchor-cert-extra-serial-non-minimal",
		mutate: func(t *tokenTree) {
			extra := newTokenTree(ed, "00")
			extra.n["certSerial"].val = []byte{0x00, 0x08}
			t.n["certs"].kids = append(slices.Clone(t.n["certs"].kids), extra.n["cert"])
		},
		why: "A token that carries, after its signer certificate, a second certificate whose " +
			"serial number is the INTEGER 8 written as 00 08 fails the anchor check, because " +
			"every carried certificate is read, whichever one signed.",
	}, {
		name: "anchor-rsa-modulus-non-minimal", signer: rsaSigner,
		mutate: func(t *tokenTree) {
			t.n["spkiKey"].val = rsaKeyBits(&rsaKey.PublicKey, func(k *derNode) {
				k.kids[0].val = append([]byte{0x00}, k.kids[0].val...)
			})
		},
		why: "A token whose RSA signer key writes its modulus with a second leading zero octet " +
			"fails the anchor check, because DER writes an INTEGER in its shortest form.",
	}, {
		name: "anchor-rsa-modulus-negative", signer: rsaSigner,
		mutate: func(t *tokenTree) {
			t.n["spkiKey"].val = rsaKeyBits(&rsaKey.PublicKey, func(k *derNode) {
				size := len(rsaKey.N.Bytes()) + 1
				neg := new(big.Int).Lsh(big.NewInt(1), uint(8*size))
				k.kids[0].val = neg.Sub(neg, rsaKey.N).FillBytes(make([]byte, size))
			})
		},
		why: "A token whose RSA signer key writes its modulus as the negative INTEGER -n, in its " +
			"shortest form, fails the anchor check, although Go's crypto/rsa verifies the " +
			"signature made with n under it, because the modulus must be positive.",
	}, {
		name: "anchor-rsa-exponent-non-minimal", signer: rsaSigner,
		mutate: func(t *tokenTree) {
			t.n["spkiKey"].val = rsaKeyBits(&rsaKey.PublicKey, func(k *derNode) {
				k.kids[1].val = append([]byte{0x00}, k.kids[1].val...)
			})
		},
		why: "A token whose RSA signer key writes its public exponent 65537 as 00 01 00 01 " +
			"fails the anchor check, because DER writes an INTEGER in its shortest form.",
	}, {
		name: "anchor-signer-name-rfc4514", ok: true,
		mutate: func(t *tokenTree) {
			t.n["tbs"].kids[5] = rdnName(
				[]*derNode{rdnAttr(asn1.ObjectIdentifier{2, 5, 4, 6}, 0x13, "DE")},
				[]*derNode{rdnAttr(asn1.ObjectIdentifier{2, 5, 4, 10}, 0x0c, "Acme, Inc."),
					rdnAttr(asn1.ObjectIdentifier{2, 5, 4, 11}, 0x0c, "Time+Stamp")},
				[]*derNode{rdnAttr(oidEmailAddress, 0x16, "tsa@example.org")},
				[]*derNode{rdnAttr(asn1.ObjectIdentifier{2, 5, 4, 7}, 0x0c, " W\u00fcrzburg")},
				[]*derNode{rdnAttr(asn1.ObjectIdentifier{2, 5, 4, 8}, 0x1e,
					"\x00B\x00a\x00y\x00e\x00r\x00n")},
				[]*derNode{rdnAttr(asn1.ObjectIdentifier{0, 9, 2342, 19200300, 100, 1, 25}, 0x16,
					"example")},
				[]*derNode{rdnAttr(asn1.ObjectIdentifier{2, 5, 4, 3}, 0x0c,
					"#1 TSA; <\"x\"> \\ \x1b\u0085 ")},
			)
		},
		attested: "2026-07-27T15:01:00Z by " +
			`CN=\#1 TSA\; \<\"x\"\> \\ \1b\c2\85\ ,DC=example,` +
			"ST=#1e0c00420061007900650072006e," + `L=\ W` + "\u00fc" + "rzburg," +
			"1.2.840.113549.1.9.1=#160f747361406578616d706c652e6f7267," +
			`O=Acme\, Inc.+OU=Time\+Stamp,C=DE`,
		why: "A token whose signer certificate's subject holds a multi-valued RDN, an " +
			"emailAddress, a BMPString, and text that RFC 4514 escapes verifies, and every " +
			"verifier names its signer by the one rule FORMAT.md states.",
	}, {
		name: "anchor-signer-name-values-as-hex", ok: true,
		mutate: func(t *tokenTree) {
			t.n["tbs"].kids[5] = rdnName(
				[]*derNode{rdnAttr(asn1.ObjectIdentifier{2, 5, 4, 5}, 0x13, "42")},
				[]*derNode{rdnAttr(asn1.ObjectIdentifier{2, 5, 4, 10}, 0x13, "Acm\xe9")},
				[]*derNode{rdnAttr(asn1.ObjectIdentifier{2, 5, 4, 11}, 0x0c, "\xff")},
				[]*derNode{derSeq(0x30, derOID(asn1.ObjectIdentifier{2, 5, 4, 3}),
					derSeq(0x2c, &derNode{tag: 0x0c, val: []byte("TSA")}))},
			)
		},
		attested: "2026-07-27T15:01:00Z by CN=#2c050c03545341,OU=#0c01ff,O=#130441636de9," +
			"2.5.4.5=#13023432",
		why: "A token whose signer certificate's subject holds a constructed UTF8String, a " +
			"UTF8String that is not UTF-8, a PrintableString that is not ASCII, and a type " +
			"RFC 4514 has no short name for verifies, and every verifier writes each of those " +
			"values in hexadecimal.",
	}, {
		name: "anchor-signer-name-empty", ok: true,
		mutate: func(t *tokenTree) {
			t.n["tbs"].kids[5] = rdnName()
		},
		attested: "2026-07-27T15:01:00Z by #3000",
		why: "A token whose signer certificate's subject is an empty SEQUENCE verifies, and " +
			"every verifier names its signer by the hexadecimal of the subject's encoding.",
	}, {
		name: "anchor-signer-name-not-a-name", ok: true,
		mutate: func(t *tokenTree) {
			t.n["tbs"].kids[5] = derSeq(0x30, derInt(1))
		},
		attested: "2026-07-27T15:01:00Z by #3003020101",
		why: "A token whose signer certificate's subject is a SEQUENCE holding an INTEGER " +
			"verifies, and every verifier names its signer by the hexadecimal of the " +
			"subject's encoding.",
	}, {
		name: "anchor-signer-name-rdn-not-a-set", ok: true,
		mutate: func(t *tokenTree) {
			t.n["tbs"].kids[5] = derSeq(0x30, derSeq(0x30,
				rdnAttr(asn1.ObjectIdentifier{2, 5, 4, 3}, 0x0c, "TSA")))
		},
		attested: "2026-07-27T15:01:00Z by #300e300c300a06035504030c03545341",
		why: "A token whose signer certificate's subject holds an RDN written as a SEQUENCE " +
			"rather than a SET verifies, and every verifier names its signer by the " +
			"hexadecimal of the subject's encoding.",
	}, {
		name: "anchor-signer-name-attribute-not-a-sequence", ok: true,
		mutate: func(t *tokenTree) {
			t.n["tbs"].kids[5] = derSeq(0x30, derSeq(0x31, derSeq(0x31,
				derOID(asn1.ObjectIdentifier{2, 5, 4, 3}),
				&derNode{tag: 0x0c, val: []byte("TSA")})))
		},
		attested: "2026-07-27T15:01:00Z by #300e310c310a06035504030c03545341",
		why: "A token whose signer certificate's subject holds an attribute written as a SET " +
			"rather than a SEQUENCE verifies, and every verifier names its signer by the " +
			"hexadecimal of the subject's encoding.",
	}, {
		name: "anchor-signer-name-type-not-an-oid", ok: true,
		mutate: func(t *tokenTree) {
			t.n["tbs"].kids[5] = rdnName([]*derNode{derSeq(0x30,
				&derNode{tag: 0x86, val: oidBytes(asn1.ObjectIdentifier{2, 5, 4, 3})},
				&derNode{tag: 0x0c, val: []byte("TSA")})})
		},
		attested: "2026-07-27T15:01:00Z by #300e310c300a86035504030c03545341",
		why: "A token whose signer certificate's subject names an attribute type under the " +
			"identifier 0x86 verifies, and every verifier names its signer by the hexadecimal " +
			"of the subject's encoding.",
	}, {
		name: "anchor-signer-name-two-values", ok: true,
		mutate: func(t *tokenTree) {
			t.n["tbs"].kids[5] = rdnName([]*derNode{derSeq(0x30,
				derOID(asn1.ObjectIdentifier{2, 5, 4, 3}), &derNode{tag: 0x0c, val: []byte("TSA")},
				&derNode{tag: 0x0c, val: []byte("X")})})
		},
		attested: "2026-07-27T15:01:00Z by #3011310f300d06035504030c035453410c0158",
		why: "A token whose signer certificate's subject holds an attribute with two values " +
			"verifies, and every verifier names its signer by the hexadecimal of the subject's " +
			"encoding.",
	}, {
		name: "anchor-signer-name-empty-rdn", ok: true,
		mutate: func(t *tokenTree) {
			t.n["tbs"].kids[5] = rdnName([]*derNode{})
		},
		attested: "2026-07-27T15:01:00Z by #30023100",
		why: "A token whose signer certificate's subject holds an RDN with no attributes " +
			"verifies, and every verifier names its signer by the hexadecimal of the subject's " +
			"encoding.",
	}, {
		name: "anchor-signer-name-type-non-minimal", ok: true,
		mutate: func(t *tokenTree) {
			t.n["tbs"].kids[5] = rdnName([]*derNode{derSeq(0x30,
				&derNode{tag: 0x06, val: []byte{0x55, 0x04, 0x80, 0x03}},
				&derNode{tag: 0x0c, val: []byte("TSA")})})
		},
		attested: "2026-07-27T15:01:00Z by #300f310d300b0604550480030c03545341",
		why: "A token whose signer certificate's subject names an attribute type that pads a " +
			"subidentifier with 0x80 verifies, because nothing decides a verdict from the " +
			"subject, and every verifier names its signer by the hexadecimal of the subject's " +
			"encoding.",
	}, {
		name: "anchor-signer-name-bidi-embedding", ok: true,
		mutate: func(t *tokenTree) {
			t.n["tbs"].kids[5] = rdnName([]*derNode{rdnAttr(asn1.ObjectIdentifier{2, 5, 4, 3}, 0x0c,
				"a\u202ab\u202bc\u202cd\u202de\u202ef\u202fg")})
		},
		attested: "2026-07-27T15:01:00Z by " +
			`CN=a\e2\80\aab\e2\80\abc\e2\80\acd\e2\80\ade\e2\80\aef` + "\u202fg",
		why: "A token whose signer's common name carries each bidirectional embedding and override, " +
			"U+202A to U+202E, verifies, and every verifier writes each in hexadecimal, so a " +
			"subject cannot use them to reorder how the line naming its signer displays, and " +
			"writes U+202F as itself.",
	}, {
		name: "anchor-signer-name-bidi-isolate", ok: true,
		mutate: func(t *tokenTree) {
			t.n["tbs"].kids[5] = rdnName([]*derNode{rdnAttr(asn1.ObjectIdentifier{2, 5, 4, 3}, 0x0c,
				"\u2065a\u2066b\u2067c\u2068d\u2069e\u206a")})
		},
		attested: "2026-07-27T15:01:00Z by CN=\u2065" +
			`a\e2\81\a6b\e2\81\a7c\e2\81\a8d\e2\81\a9e` + "\u206a",
		why: "A token whose signer's common name carries each bidirectional isolate, U+2066 to " +
			"U+2069, verifies, and every verifier writes each in hexadecimal and writes U+2065 and " +
			"U+206A as themselves.",
	}, {
		name: "anchor-signer-name-bidi-mark", ok: true,
		mutate: func(t *tokenTree) {
			t.n["tbs"].kids[5] = rdnName([]*derNode{rdnAttr(asn1.ObjectIdentifier{2, 5, 4, 3}, 0x0c,
				"\u200da\u200eb\u200fc\u2010d\u061be\u061cf\u061d")})
		},
		attested: "2026-07-27T15:01:00Z by CN=\u200d" + `a\e2\80\8eb\e2\80\8fc` + "\u2010d\u061b" +
			`e\d8\9cf` + "\u061d",
		why: "A token whose signer's common name carries the bidirectional marks U+200E, U+200F " +
			"and U+061C verifies, and every verifier writes each in hexadecimal and writes U+200D, " +
			"U+2010, U+061B and U+061D as themselves.",
	}, {
		name: "anchor-signer-name-line-separator", ok: true,
		mutate: func(t *tokenTree) {
			t.n["tbs"].kids[5] = rdnName([]*derNode{rdnAttr(asn1.ObjectIdentifier{2, 5, 4, 3}, 0x0c,
				"a\u2027b\u2028c\u2029d")})
		},
		attested: "2026-07-27T15:01:00Z by CN=a\u2027" + `b\e2\80\a8c\e2\80\a9d`,
		why: "A token whose signer's common name carries the line separator U+2028 and the " +
			"paragraph separator U+2029 verifies, and every verifier writes each in hexadecimal, " +
			"so a subject cannot break the line naming its signer, and writes U+2027 as itself.",
	}, {
		name: "anchor-der-serial-21-octets", ok: true,
		mutate: func(t *tokenTree) {
			t.n["tstSerial"].val = append([]byte{0x00}, bytes.Repeat([]byte{0xff}, 20)...)
		},
		why: "A token whose TSTInfo serial number is 2^160-1, 21 octets with the zero octet DER " +
			"writes before a high bit, verifies, because RFC 3161 has a verifier accept a serial " +
			"of up to 160 bits.",
	}, {
		name: "anchor-der-serial-22-octets",
		mutate: func(t *tokenTree) {
			t.n["tstSerial"].val = append([]byte{0x00}, bytes.Repeat([]byte{0xff}, 21)...)
		},
		why: "A token whose TSTInfo serial number is 2^168-1, 22 octets, fails the anchor check, " +
			"because a serial has at most the 21 octets a 160-bit value takes.",
	}} {
		signer := c.signer
		if signer == nil {
			signer = ed
		}
		s.tokenVector(c.name, at, c.ok, c.why, func(link string) string {
			t := newTokenTree(signer, link)
			if c.mutate != nil {
				c.mutate(t)
			}
			return t.encode()
		})
		if c.ok {
			attested := c.attested
			if attested == "" {
				attested = vectorAttested
			}
			s.expectAttested(c.name, attested)
		}
	}
}

// derTags emits one vector per member a verifier reads by a fixed identifier, each a token whose
// one member carries another identifier and is otherwise intact, signed over what its encoding
// became. A constructed member loses its constructed bit and a primitive one moves to the
// context-specific class, so the walk reads the token as well formed and only the comparison of
// the whole identifier octet at that one member refuses it. Each fails the anchor check.
//
//nolint:funlen // One vector per member, listed in one place.
func (s *state) derTags() {
	ed := edTokenSigner()
	rsaSigner := rsaTokenSigner()
	rsaKey := rsaVectorKey(2048, 2048, 65537)
	// node names a member by where it sits in a token's tree.
	type node func(t *tokenTree) *derNode
	named := func(name string) node { return func(t *tokenTree) *derNode { return t.n[name] } }
	kid := func(parent node, i int) node {
		return func(t *tokenTree) *derNode { return parent(t).kids[i] }
	}
	// replace swaps the member at parent's kids[i] for a retagged copy, for a member the tree
	// shares with another position the token must keep intact.
	replace := func(parent node, i int) func(t *tokenTree) {
		return func(t *tokenTree) {
			p := parent(t)
			kids := slices.Clone(p.kids)
			old := kids[i]
			kids[i] = &derNode{tag: retag(old.tag), header: func(byte, []byte) []byte {
				full := old.encode()
				return append([]byte{retag(full[0])}, full[1:]...)
			}}
			p.kids = kids
		}
	}
	rsaKeyMember := func(edit func(k *derNode)) func(t *tokenTree) {
		return func(t *tokenTree) { t.n["spkiKey"].val = rsaKeyBits(&rsaKey.PublicKey, edit) }
	}
	for _, c := range []struct {
		// name is the vector name's suffix after anchor-der-tag-.
		name string
		// member says, in the vector's description, which member is retagged.
		member string
		// at is the member retagged in place, when mutate is nil.
		at node
		// mutate retags the member when it cannot be retagged in place.
		mutate func(t *tokenTree)
		// signer signs the token; nil means the Ed25519 authority.
		signer *tokenSigner
		// from is the member's own identifier octet.
		from byte
	}{
		{name: "content-info", member: "ContentInfo SEQUENCE", at: named("ci"), from: 0x30},
		{name: "content-type", member: "contentType", at: named("contentType"), from: 0x06},
		{name: "content-info-content", member: "ContentInfo [0]", at: named("ciWrap"),
			from: 0xa0},
		{name: "signed-data", member: "SignedData SEQUENCE", at: named("signedData"),
			from: 0x30},
		{name: "signed-data-version", member: "SignedData version",
			at: kid(named("signedData"), 0), from: 0x02},
		{name: "digest-algorithms", member: "digestAlgorithms SET",
			at: kid(named("signedData"), 1), from: 0x31},
		{name: "encap-content-info", member: "encapContentInfo SEQUENCE",
			at: kid(named("signedData"), 2), from: 0x30},
		{name: "econtent-type", member: "eContentType", at: named("eContentType"), from: 0x06},
		{name: "econtent-explicit", member: "eContent [0]",
			at: kid(kid(named("signedData"), 2), 1), from: 0xa0},
		{name: "econtent", member: "eContent OCTET STRING", at: named("eContent"), from: 0x04},
		{name: "signer-infos", member: "signerInfos SET", at: named("signerInfos"), from: 0x31},
		{name: "signer-info", member: "SignerInfo SEQUENCE", at: named("si"), from: 0x30},
		{name: "signer-info-version", member: "SignerInfo version", at: kid(named("si"), 0),
			from: 0x02},
		{name: "sid", member: "signer identifier SEQUENCE", at: named("sid"), from: 0x30},
		{name: "sid-issuer", member: "signer identifier's issuer",
			mutate: replace(named("sid"), 0), from: 0x30},
		{name: "sid-serial", member: "signer identifier's serial number",
			mutate: replace(named("sid"), 1), from: 0x02},
		{name: "digest-algorithm", member: "digestAlgorithm SEQUENCE", at: named("siDigest"),
			from: 0x30},
		{name: "digest-algorithm-oid", member: "digestAlgorithm OBJECT IDENTIFIER",
			at: kid(named("siDigest"), 0), from: 0x06},
		{name: "signature-algorithm", member: "signatureAlgorithm SEQUENCE",
			at: kid(named("si"), 4), from: 0x30},
		{name: "signature-algorithm-oid", member: "signatureAlgorithm OBJECT IDENTIFIER",
			at: named("sigAlgOID"), from: 0x06},
		{name: "signature", member: "signature OCTET STRING", at: named("sig"), from: 0x04},
		{name: "signed-attribute", member: "messageDigest attribute SEQUENCE",
			at: kid(named("attrs"), 1), from: 0x30},
		{name: "signed-attribute-type", member: "messageDigest attribute type",
			at: kid(kid(named("attrs"), 1), 0), from: 0x06},
		{name: "signed-attribute-values", member: "messageDigest attribute's SET of values",
			at: named("mdValues"), from: 0x31},
		{name: "message-digest", member: "messageDigest OCTET STRING", at: named("md"),
			from: 0x04},
		{name: "policy", member: "TSTInfo policy", at: named("policy"), from: 0x06},
		{name: "message-imprint", member: "messageImprint SEQUENCE", at: named("imprint"),
			from: 0x30},
		{name: "imprint-algorithm", member: "messageImprint hashAlgorithm SEQUENCE",
			at: kid(named("imprint"), 0), from: 0x30},
		{name: "imprint-algorithm-oid", member: "messageImprint hashAlgorithm OBJECT IDENTIFIER",
			at: kid(kid(named("imprint"), 0), 0), from: 0x06},
		{name: "imprint-digest", member: "messageImprint hashedMessage",
			at: kid(named("imprint"), 1), from: 0x04},
		{name: "tst-serial", member: "TSTInfo serial number", at: named("tstSerial"),
			from: 0x02},
		{name: "certificate", member: "signer certificate SEQUENCE", at: named("cert"),
			from: 0x30},
		{name: "tbs-certificate", member: "tbsCertificate SEQUENCE", at: named("tbs"),
			from: 0x30},
		{name: "certificate-version", member: "certificate version INTEGER",
			at: kid(named("certVersion"), 0), from: 0x02},
		{name: "certificate-serial", member: "certificate serial number",
			mutate: replace(named("tbs"), 1), from: 0x02},
		{name: "certificate-signature-algorithm", member: "certificate signature SEQUENCE",
			at: kid(named("tbs"), 2), from: 0x30},
		{name: "certificate-issuer", member: "certificate issuer SEQUENCE",
			mutate: replace(named("tbs"), 3), from: 0x30},
		{name: "validity", member: "certificate validity SEQUENCE", at: kid(named("tbs"), 4),
			from: 0x30},
		{name: "subject", member: "certificate subject SEQUENCE",
			mutate: replace(named("tbs"), 5), from: 0x30},
		{name: "subject-public-key-info", member: "subjectPublicKeyInfo SEQUENCE",
			at: named("spki"), from: 0x30},
		{name: "extensions", member: "SEQUENCE of extensions", at: named("exts"), from: 0x30},
		{name: "extension", member: "extended key usage extension SEQUENCE",
			at: named("ekuExt"), from: 0x30},
		{name: "extension-id", member: "extended key usage extnID",
			at: kid(named("ekuExt"), 0), from: 0x06},
		{name: "extension-value", member: "extended key usage extnValue",
			at: kid(named("ekuExt"), 2), from: 0x04},
		{name: "subject-key-identifier", member: "subject key identifier OCTET STRING",
			at: named("ski"), from: 0x04},
		{name: "key-purposes", member: "SEQUENCE of key purposes", at: named("eku"),
			from: 0x30},
		{name: "key-purpose", member: "id-kp-timeStamping key purpose",
			at: kid(named("eku"), 0), from: 0x06},
		{name: "public-key-algorithm", member: "public key AlgorithmIdentifier SEQUENCE",
			at: named("spkiAlg"), from: 0x30},
		{name: "public-key-algorithm-oid", member: "public key algorithm OBJECT IDENTIFIER",
			at: kid(named("spkiAlg"), 0), from: 0x06},
		{name: "public-key", member: "subjectPublicKey BIT STRING", at: named("spkiKey"),
			from: 0x03},
		{name: "elliptic-curve", member: "ECDSA key's curve OBJECT IDENTIFIER",
			at: kid(named("spkiAlg"), 1), signer: ecTokenSigner(false, false), from: 0x06},
		{name: "ecdsa-signature", member: "ECDSA signature SEQUENCE", from: 0x30,
			signer: ecTokenSigner(false, false), mutate: func(t *tokenTree) {
				t.rewriteSignature = func(sig []byte) []byte {
					out := slices.Clone(sig)
					out[0] = retag(out[0])
					return out
				}
			}},
		{name: "ecdsa-signature-value", member: "ECDSA signature's first INTEGER", from: 0x02,
			signer: ecTokenSigner(false, false), mutate: func(t *tokenTree) {
				t.rewriteSignature = func(sig []byte) []byte {
					out := slices.Clone(sig)
					out[2] = retag(out[2])
					return out
				}
			}},
		{name: "rsa-parameters", member: "RSA key's NULL parameters",
			at: kid(named("spkiAlg"), 1), signer: rsaSigner, from: 0x05},
		{name: "rsa-key", member: "RSA key SEQUENCE", signer: rsaSigner, from: 0x30,
			mutate: rsaKeyMember(func(k *derNode) { k.tag = retag(k.tag) })},
		{name: "rsa-modulus", member: "RSA modulus", signer: rsaSigner, from: 0x02,
			mutate: rsaKeyMember(func(k *derNode) { k.kids[0].tag = retag(k.kids[0].tag) })},
		{name: "rsa-exponent", member: "RSA public exponent", signer: rsaSigner, from: 0x02,
			mutate: rsaKeyMember(func(k *derNode) { k.kids[1].tag = retag(k.kids[1].tag) })},
	} {
		signer := c.signer
		if signer == nil {
			signer = ed
		}
		why := fmt.Sprintf("A token whose %s is written under the identifier 0x%02x rather than "+
			"0x%02x fails the anchor check, because a verifier compares the whole identifier "+
			"octet of every member it reads, class and constructed bit included.", c.member,
			retag(c.from), c.from)
		s.tokenVector("anchor-der-tag-"+c.name, at, false, why, func(link string) string {
			t := newTokenTree(signer, link)
			if c.mutate != nil {
				c.mutate(t)
			} else {
				n := c.at(t)
				if n.tag != c.from {
					panic(fmt.Sprintf("derTags %s: member is 0x%02x, want 0x%02x", c.name, n.tag,
						c.from))
				}
				n.tag = retag(n.tag)
			}
			return t.encode()
		})
	}
}

// readOrder emits the vectors that pin the order FORMAT.md's verification step 1 reads a bundle
// in: the document as JSON, then its version, then the number profile, then every member's name,
// type and null, then each value's rule. A version other than 0.1 is unsupported whatever else the
// bundle carries, and a bundle with no version, or one that is not a string, is refused at parse.
// Each fault rides beside one a later step refuses, so a verifier that read them in another order
// reaches another verdict.
//
//nolint:funlen // One vector per pair of faults, listed in one place.
func (s *state) readOrder() {
	// withLiteral places a literal in the first claim's payload of a signed bundle, as text, since
	// no Go value marshals to a literal outside the number profile or to one JSON does not define.
	withLiteral := func(signed []byte, literal string) []byte {
		out := strings.Replace(string(signed), `"path":"/api/runs"`,
			`"path":"/api/runs","n":`+literal, 1)
		if out == string(signed) {
			panic("readOrder: no payload path to place a number beside")
		}
		return []byte(out)
	}
	signed := s.sign(s.v1(1, false))
	s.add("version-missing", false, "", "parse",
		"A bundle with no loomseal member declares no format version and is refused at parse, not "+
			"as unsupported: a later format is announced by another string in that member, so no "+
			"newer verifier reads this document either.",
		mutateSigned(signed, func(m map[string]any) { delete(m, "loomseal") }))
	s.add("version-missing-unknown-member", false, "", "parse",
		"A bundle with no loomseal member that also carries a member the schema does not define is "+
			"refused at parse for the missing version, which a verifier reads before any member's "+
			"name.",
		mutateSigned(signed, func(m map[string]any) {
			delete(m, "loomseal")
			m["description"] = "a document from before versions"
		}))
	s.add("version-not-a-string", false, "", "parse",
		"A loomseal member holding the number 1 rather than a string declares no format version "+
			"and is refused at parse.",
		mutateSigned(signed, func(m map[string]any) { m["loomseal"] = 1 }))

	// later declares version 0.2 and adds one fault a version 0.1 bundle is refused at parse for.
	later := func(fault func(m map[string]any)) []byte {
		return mutateSigned(signed, func(m map[string]any) {
			m["loomseal"] = "0.2"
			fault(m)
		})
	}
	s.add("wrong-version-unknown-member", false, "", "unsupported",
		"A bundle declaring a version this verifier does not implement is unsupported although it "+
			"also carries a member the schema does not define, because the version is read first "+
			"and a later version may define new members.",
		later(func(m map[string]any) { m["description"] = "a member a later version defines" }))
	s.add("wrong-version-unknown-claim-member", false, "", "unsupported",
		"A bundle declaring a version this verifier does not implement is unsupported although a "+
			"claim carries a member the schema does not define, because the version is read before "+
			"any member's name.",
		later(func(m map[string]any) { m["claims"].([]any)[0].(map[string]any)["extra"] = "x" }))
	s.add("wrong-version-wrong-type", false, "", "unsupported",
		"A bundle declaring a version this verifier does not implement is unsupported although its "+
			"bundle_id is a number, because a later version may give a member another type.",
		later(func(m map[string]any) { m["bundle_id"] = 7 }))
	s.add("wrong-version-null-member", false, "", "unsupported",
		"A bundle declaring a version this verifier does not implement is unsupported although its "+
			"anchors member is null, because the version is read before any member's value.",
		later(func(m map[string]any) { m["anchors"] = nil }))
	s.add("wrong-version-attestation-time", false, "", "unsupported",
		"A bundle declaring a version this verifier does not implement is unsupported although a "+
			"head attestation carries a time in no form this format reads, because a later version "+
			"may write times another way.",
		later(func(m map[string]any) {
			m["attestations"] = []any{map[string]any{"role": "witness", "at": "yesterday"}}
		}))
	laterSigned := mutateSigned(signed, func(m map[string]any) { m["loomseal"] = "0.2" })
	s.add("wrong-version-non-integer-number", false, "", "unsupported",
		"A bundle declaring a version this verifier does not implement is unsupported although it "+
			"carries a fractional number, because a later version may widen the number profile.",
		withLiteral(laterSigned, "1.5"))
	s.add("wrong-version-long-integer", false, "", "unsupported",
		"A bundle declaring a version this verifier does not implement is unsupported although it "+
			"carries an integer of twenty digits, because a later version may widen the number "+
			"profile.",
		withLiteral(laterSigned, "12345678901234567890"))
	// NaN, Infinity, -Infinity, and a digit outside ASCII are not JSON, and some JSON readers
	// accept them. A document carrying one is refused at parse whatever version it declares,
	// because a verifier reads the version only from a document that is JSON.
	for _, c := range []struct {
		// name is the vector's name and the stem of its file.
		name string
		// literal is the text placed where a value belongs.
		literal string
		// what names the literal in the description.
		what string
	}{
		{name: "wrong-version-nan", literal: "NaN", what: "NaN"},
		{name: "wrong-version-infinity", literal: "Infinity", what: "Infinity"},
		{name: "wrong-version-negative-infinity", literal: "-Infinity", what: "-Infinity"},
		{name: "wrong-version-non-ascii-digit", literal: "1\u0661",
			what: "1 followed by the Arabic-Indic digit one"},
	} {
		s.add(c.name, false, "", "parse",
			"A bundle declaring a version this verifier does not implement is refused at parse, "+
				"not judged unsupported, when it carries "+c.what+" where a value belongs: "+
				"that is not JSON, so no verifier reads its version.",
			withLiteral(laterSigned, c.literal))
	}
	s.add("number-twenty-digits", false, "", "parse",
		"An integer literal of twenty digits is outside the integer profile and is refused at "+
			"parse, before any verifier converts it.",
		withLiteral(signed, "12345678901234567890"))

	// A chain profile this verifier does not implement is found by the value rules, after the
	// number profile and every member's name and type have held.
	m := s.v1(1, false)
	m["chain"].(map[string]any)["profile"] = "x-chain-v9"
	unknownProfile := s.sign(m)
	s.add("unknown-chain-profile-non-integer-number", false, "", "parse",
		"A version 0.1 bundle carrying a fractional number is refused at parse even beside a chain "+
			"profile this verifier does not implement, because the number profile is fixed for the "+
			"version and is held before the value rules that find the profile unknown.",
		withLiteral(unknownProfile, "1.5"))
	s.add("unknown-chain-profile-unknown-member", false, "", "parse",
		"A version 0.1 bundle whose claim carries a member the schema does not define is refused at "+
			"parse even beside a chain profile this verifier does not implement, because every "+
			"member's name is held before the value rules that find the profile unknown.",
		mutateSigned(unknownProfile, func(m map[string]any) {
			m["claims"].([]any)[0].(map[string]any)["extra"] = "x"
		}))
}

// unopenedProofs emits the vectors that pin how a verifier counts a carried proof of a type it
// cannot open offline: such a proof alone, one of each such type, never one on the unverified
// declared head, and never a proof it opened, whether that proof held or failed. A token that fails
// is pinned at zero on the failing vectors that reach each way a token fails after it is counted as
// carried, so a verifier calling a failed token unopenable fails them.
func (s *state) unopenedProofs() {
	opaque := base64.StdEncoding.EncodeToString([]byte("a commit a relying party fetches"))
	m := s.v1(2, false)
	head := m["chain"].(map[string]any)["head"].(map[string]any)
	g := gitAnchor(head["seq"].(int64), head["link"].(string))
	g["proof"] = opaque
	m["anchors"] = []any{g}
	s.add("anchor-proof-unopened", true, "signed, chained (full), anchored by reference", "",
		"A git anchor carrying a proof verifies by reference, and a verifier reports that proof as "+
			"one of a type it cannot open offline, carried and not checked.", s.sign(m))
	s.expectUnopened("anchor-proof-unopened", 1)

	// Every type a verifier matches by coordinates only carries a proof, so a verifier that counts
	// some of those types and not the others, or counts a bundle once however many it carries,
	// reports the wrong number.
	m = s.v1(2, false)
	head = m["chain"].(map[string]any)["head"].(map[string]any)
	m["anchors"] = referenceAnchors(head["seq"].(int64), head["link"].(string))
	s.add("anchor-proof-unopened-git-https-rekor", true,
		"signed, chained (full), anchored by reference", "",
		"A git, an https, and a rekor anchor over the verified head, each carrying a proof, verify "+
			"by reference, and a verifier reports all three proofs as of a type it cannot open "+
			"offline.", s.sign(m))
	s.expectUnopened("anchor-proof-unopened-git-https-rekor", 3)

	// The same three proofs on a declared head beyond the bundled claims are never unopened: the
	// link they attest is tied to nothing the verifier confirmed, so they are proofs on the
	// declared head whatever their type.
	m = s.v1(1, false)
	m["chain"].(map[string]any)["head"] = map[string]any{
		"seq": int64(500), "link": strings.Repeat("ab", 32),
	}
	m["anchors"] = referenceAnchors(500, strings.Repeat("ab", 32))
	s.add("anchor-declared-head-proof-git-https-rekor", true, "signed, chained (full)", "",
		"A git, an https, and a rekor anchor over a declared head beyond the bundled claims, each "+
			"carrying a proof, earn no anchored level, and a verifier reports their proofs as on "+
			"the declared head and none as of a type it cannot open.", s.sign(m))
	s.expectUnopened("anchor-declared-head-proof-git-https-rekor", 0)
	s.expectOnDeclaredHead("anchor-declared-head-proof-git-https-rekor", 3)

	m = s.v1(1, false)
	link := m["chain"].(map[string]any)["head"].(map[string]any)["link"].(string)
	g = gitAnchor(1, link)
	g["proof"] = opaque
	m["anchors"] = []any{map[string]any{
		"type": "rfc3161", "seq": int64(1), "link": link, "at": "2026-07-27T15:01:00Z",
		"ref": "https://tsa.example/tsr", "proof": newTokenTree(edTokenSigner(), link).encode(),
	}, g}
	s.add("anchor-proof-unopened-beside-verified", true,
		"signed, chained (full), anchored (proof verified)", "",
		"A bundle carrying a timestamp token that verifies and a git anchor's proof over the same "+
			"link reports one proof of a type the verifier cannot open, and never counts the token "+
			"it opened among them.", s.sign(m))
	s.expectAttested("anchor-proof-unopened-beside-verified", vectorAttested)
	s.expectUnopened("anchor-proof-unopened-beside-verified", 1)

	// The git anchor is read first and the failing token last, so a verifier that stops at the first
	// failed anchor and one that reads every anchor have both counted the git proof.
	m = s.v1(1, false)
	link = m["chain"].(map[string]any)["head"].(map[string]any)["link"].(string)
	g = gitAnchor(1, link)
	g["proof"] = opaque
	failed := newTokenTree(edTokenSigner(), link)
	failed.rewriteSignature = func(sig []byte) []byte {
		sig = slices.Clone(sig)
		sig[0] ^= 0x01
		return sig
	}
	m["anchors"] = []any{g, map[string]any{
		"type": "rfc3161", "seq": int64(1), "link": link, "at": "2026-07-27T15:01:00Z",
		"ref": "https://tsa.example/tsr", "proof": failed.encode(),
	}}
	s.add("anchor-proof-unopened-before-failed", false, "", "anchor",
		"A bundle carrying a git anchor's proof and then a timestamp token whose signature has one "+
			"bit changed fails the anchor check, and a verifier reports one proof of a type it "+
			"cannot open, the git anchor's, and never counts the token it opened and saw fail.",
		s.sign(m))
	s.expectUnopened("anchor-proof-unopened-before-failed", 1)
	// A token opened and failed is never unopenable: one whose signature does not verify, one that
	// does not open as a timestamp token, and one that verifies but predates the entry it covers.
	for _, name := range []string{
		"anchor-signature-invalid", "anchor-corrupt-token", "anchor-gen-time-fraction-outside-skew",
	} {
		s.expectUnopened(name, 0)
	}
}

// retag is the identifier a derTags member is written under in place of tag: a constructed
// identifier without its constructed bit, and a primitive one in the context-specific class.
func retag(tag byte) byte {
	if tag&0x20 != 0 {
		return tag &^ 0x20
	}
	return tag | 0x80
}

// oidEmailAddress is the PKCS #9 emailAddress attribute type, which RFC 4514 has no short name
// for.
var oidEmailAddress = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

// hugeArc is the content of an OBJECT IDENTIFIER under 1.2 whose third subidentifier runs 3,000
// octets, far past the 2^31-1 a verifier reads and past the 4300 decimal digits Python converts.
func hugeArc() []byte {
	return append(append([]byte{0x2a}, bytes.Repeat([]byte{0xff}, 2999)...), 0x7f)
}

// rdnName is a Name node whose relative distinguished names hold the given attributes, in order.
func rdnName(rdns ...[]*derNode) *derNode {
	n := &derNode{tag: 0x30, kids: []*derNode{}}
	for _, attrs := range rdns {
		n.kids = append(n.kids, derSeq(0x31, attrs...))
	}
	return n
}

// rdnAttr is an attribute node: the type oid and a primitive value of the given identifier whose
// content is the octets of text.
func rdnAttr(oid asn1.ObjectIdentifier, tag byte, text string) *derNode {
	return derSeq(0x30, derOID(oid), &derNode{tag: tag, val: []byte(text)})
}

// rsaKeyBits is the content of the subjectPublicKey BIT STRING that holds pub, after edit has
// changed the node of the key SEQUENCE, whose members are the modulus and the exponent.
func rsaKeyBits(pub *rsa.PublicKey, edit func(key *derNode)) []byte {
	content := func(v any) []byte {
		var raw asn1.RawValue
		if _, err := asn1.Unmarshal(mustMarshal(v), &raw); err != nil {
			panic(err)
		}
		return raw.Bytes
	}
	key := derSeq(0x30, &derNode{tag: 0x02, val: content(pub.N)},
		&derNode{tag: 0x02, val: content(big.NewInt(int64(pub.E)))})
	edit(key)
	return append([]byte{0}, key.encode()...)
}

// vectorAuthority is the common name of the authority every minted token names as its signer.
const vectorAuthority = "LoomSeal conformance vector timestamp authority"

// vectorAttested is the line a verifier reports for a minted token whose genTime is
// 20260727150100Z and whose signer is the vector authority.
const vectorAttested = "2026-07-27T15:01:00Z by CN=" + vectorAuthority

// tokenSKI is the subject key identifier every minted authority certificate carries.
var tokenSKI = []byte{0x4c, 0x53, 0x01, 0x02}

// derNode is one element of a token the generator builds. It is encoded on demand, so a vector
// can change any element's encoding while the message digest and the signature still cover
// whatever the token became.
type derNode struct {
	// tag is the identifier octet.
	tag byte
	// kids are the members of a constructed element.
	kids []*derNode
	// val is the content of a primitive element.
	val []byte
	// fill, when set, computes the content at encode time.
	fill func() []byte
	// header, when set, writes the whole encoding from the identifier and the content.
	header func(tag byte, content []byte) []byte
}

// encode writes the node as DER, or as its header function writes it.
func (n *derNode) encode() []byte {
	var c []byte
	switch {
	case n.fill != nil:
		c = n.fill()
	case n.kids != nil:
		for _, k := range n.kids {
			c = append(c, k.encode()...)
		}
	default:
		c = n.val
	}
	if n.header != nil {
		return n.header(n.tag, c)
	}
	return derElement(n.tag, c)
}

// derElement writes one DER element with its length in the shortest form.
func derElement(tag byte, c []byte) []byte {
	switch {
	case len(c) < 0x80:
		return append([]byte{tag, byte(len(c))}, c...)
	case len(c) < 0x100:
		return append([]byte{tag, 0x81, byte(len(c))}, c...)
	}
	return append([]byte{tag, 0x82, byte(len(c) >> 8), byte(len(c))}, c...)
}

// derSeq is a constructed node with the given identifier and members.
func derSeq(tag byte, kids ...*derNode) *derNode {
	return &derNode{tag: tag, kids: kids}
}

// derOID is an OBJECT IDENTIFIER node.
func derOID(oid asn1.ObjectIdentifier) *derNode {
	return &derNode{tag: 0x06, val: oidBytes(oid)}
}

// oidBytes is the DER content of oid.
func oidBytes(oid asn1.ObjectIdentifier) []byte {
	return mustMarshal(oid)[2:]
}

// derInt is an INTEGER node holding v.
func derInt(v int64) *derNode {
	return &derNode{tag: 0x02, val: mustMarshal(v)[2:]}
}

// tokenSigner is an authority a minted token is signed by: its subjectPublicKeyInfo, the
// signature algorithm it names, and how it signs the signed attributes.
type tokenSigner struct {
	// spki builds the subjectPublicKeyInfo node.
	spki func() *derNode
	// sigAlg is the signature algorithm the signer info names.
	sigAlg asn1.ObjectIdentifier
	// sign signs the signed attributes, given as the SET the signature covers.
	sign func(signed []byte) []byte
}

// edTokenSigner is the fixed Ed25519 conformance vector authority.
func edTokenSigner() *tokenSigner {
	priv := ed25519.NewKeyFromSeed(bytesRepeat(23))
	return &tokenSigner{
		spki: func() *derNode {
			return derSeq(0x30, derSeq(0x30, derOID(oidEd25519)),
				&derNode{tag: 0x03, val: append([]byte{0}, priv.Public().(ed25519.PublicKey)...)})
		},
		sigAlg: oidEd25519,
		sign:   func(signed []byte) []byte { return ed25519.Sign(priv, signed) },
	}
}

// rsaVectorKey derives an RSA key of the given modulus size and public exponent from a fixed
// seed, so the vectors are the same on every run.
func rsaVectorKey(bits int, seed uint64, exponent int64) *rsa.PrivateKey {
	rng := mathrand.New(mathrand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	prime := func(n int) *big.Int {
		for {
			b := make([]byte, (n+7)/8)
			for i := range b {
				b[i] = byte(rng.Uint32())
			}
			p := new(big.Int).SetBytes(b)
			p.SetBit(p, n-1, 1)
			p.SetBit(p, n-2, 1)
			p.SetBit(p, 0, 1)
			for i := p.BitLen() - 1; i >= n; i-- {
				p.SetBit(p, i, 0)
			}
			if p.ProbablyPrime(32) {
				return p
			}
		}
	}
	e := big.NewInt(exponent)
	for {
		p, q := prime(bits/2), prime(bits-bits/2)
		n := new(big.Int).Mul(p, q)
		phi := new(big.Int).Mul(new(big.Int).Sub(p, big.NewInt(1)),
			new(big.Int).Sub(q, big.NewInt(1)))
		d := new(big.Int).ModInverse(e, phi)
		if n.BitLen() != bits || d == nil {
			continue
		}
		key := &rsa.PrivateKey{PublicKey: rsa.PublicKey{N: n, E: int(exponent)}, D: d,
			Primes: []*big.Int{p, q}}
		key.Precompute()
		return key
	}
}

// rsaKeyWith rewrites an RSAPublicKey SEQUENCE so that extra follows the modulus and the
// exponent inside it.
func rsaKeyWith(key []byte, extra ...byte) []byte {
	var seq asn1.RawValue
	if rest, err := asn1.Unmarshal(key, &seq); err != nil || len(rest) != 0 {
		panic(fmt.Sprintf("RSA key: %v", err))
	}
	return derElement(0x30, append(slices.Clone(seq.Bytes), extra...))
}

// rsaSPKI is the subjectPublicKeyInfo node of an RSA public key.
func rsaSPKI(pub *rsa.PublicKey) *derNode {
	key := mustMarshal(struct {
		N *big.Int
		E int
	}{pub.N, pub.E})
	return derSeq(0x30, derSeq(0x30, derOID(oidRSAEncryption), &derNode{tag: 0x05}),
		&derNode{tag: 0x03, val: append([]byte{0}, key...)})
}

// rsaTokenSigner is a fixed 2048-bit RSA authority signing with sha256WithRSAEncryption.
func rsaTokenSigner() *tokenSigner {
	priv := rsaVectorKey(2048, 2048, 65537)
	return &tokenSigner{
		spki:   func() *derNode { return rsaSPKI(&priv.PublicKey) },
		sigAlg: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11},
		sign: func(signed []byte) []byte {
			sum := sha256.Sum256(signed)
			sig, err := rsa.SignPKCS1v15(nil, priv, crypto.SHA256, sum[:])
			if err != nil {
				panic(err)
			}
			return sig
		},
	}
}

// rsaRaw is an RSA key the generator signs with by its own arithmetic, for keys Go's crypto/rsa
// will not sign with. Each signature it makes is valid under the public key it carries, so the
// key alone decides how a verifier treats the token.
type rsaRaw struct {
	// pub is the public key the authority certificate carries.
	pub *rsa.PublicKey
	// exp raises a message representative to the private exponent, or returns nil when this key
	// cannot sign that representative, so the token is minted again with another serial.
	exp func(m *big.Int) *big.Int
}

// digestInfoSHA256 is the PKCS #1 v1.5 DigestInfo prefix for SHA-256, NULL parameters included.
var digestInfoSHA256 = []byte{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
	0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20}

// pkcs1Signer signs with sha256WithRSAEncryption, writing prefix as the DigestInfo before the
// digest.
func (k *rsaRaw) pkcs1Signer(prefix []byte) *tokenSigner {
	return &tokenSigner{
		spki:   func() *derNode { return rsaSPKI(k.pub) },
		sigAlg: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11},
		sign: func(signed []byte) []byte {
			sum := sha256.Sum256(signed)
			size := (k.pub.N.BitLen() + 7) / 8
			em := make([]byte, size)
			em[1] = 0x01
			info := append(slices.Clone(prefix), sum[:]...)
			for i := 2; i < size-len(info)-1; i++ {
				em[i] = 0xff
			}
			copy(em[size-len(info):], info)
			return k.raise(em, size)
		},
	}
}

// pssForm is how a PSS signature is encoded: its salt length, and the one fault it carries, if
// any.
type pssForm struct {
	// salt is the salt length in octets.
	salt int
	// other signs other attributes than the token carries, in an otherwise well-formed encoding.
	other bool
	// trailer, when not zero, replaces the 0xbc octet that ends the encoding.
	trailer byte
	// topBit sets the encoding's leftmost bit, which its length in bits leaves clear.
	topBit bool
	// lead writes the encoding with one more octet in front, of value 1, for a modulus whose
	// encoding is one octet shorter than its signature.
	lead bool
}

// pssSigner signs with RSASSA-PSS over SHA-256 and MGF1 over SHA-256, with a fixed salt, by the
// encoding RFC 8017 gives, altered as form says.
func (k *rsaRaw) pssSigner(form pssForm) *tokenSigner {
	return &tokenSigner{
		spki:   func() *derNode { return rsaSPKI(k.pub) },
		sigAlg: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10},
		sign: func(signed []byte) []byte {
			if form.other {
				signed = append(slices.Clone(signed), 0x00)
			}
			mHash := sha256.Sum256(signed)
			salt := bytes.Repeat([]byte{0x5a}, form.salt)
			h := sha256.Sum256(slices.Concat(make([]byte, 8), mHash[:], salt))
			emBits := k.pub.N.BitLen() - 1
			emLen := (emBits + 7) / 8
			db := make([]byte, emLen-sha256.Size-1)
			db[len(db)-form.salt-1] = 0x01
			copy(db[len(db)-form.salt:], salt)
			mask := mgf1SHA256(h[:], len(db))
			for i := range db {
				db[i] ^= mask[i]
			}
			db[0] &= 0xff >> (8*emLen - emBits)
			trailer := byte(0xbc)
			if form.trailer != 0 {
				trailer = form.trailer
			}
			em := slices.Concat(db, h[:], []byte{trailer})
			if form.topBit {
				em[0] |= 0x80
			}
			if form.lead {
				em = append([]byte{0x01}, em...)
			}
			return k.raise(em, (k.pub.N.BitLen()+7)/8)
		},
	}
}

// raise turns an encoded message into a signature of size octets, or returns nil when the key
// cannot sign it, the encoded message not being below the modulus among the reasons.
func (k *rsaRaw) raise(em []byte, size int) []byte {
	m := new(big.Int).SetBytes(em)
	if m.Cmp(k.pub.N) >= 0 {
		return nil
	}
	sig := k.exp(m)
	if sig == nil {
		return nil
	}
	return sig.FillBytes(make([]byte, size))
}

// mgf1SHA256 expands seed to length octets with MGF1 over SHA-256.
func mgf1SHA256(seed []byte, length int) []byte {
	var out []byte
	for counter := uint32(0); len(out) < length; counter++ {
		sum := sha256.Sum256(append(slices.Clone(seed), byte(counter>>24), byte(counter>>16),
			byte(counter>>8), byte(counter)))
		out = append(out, sum[:]...)
	}
	return out[:length]
}

// privateExp is the private operation of a two-prime key made by rsaVectorKey.
func privateExp(priv *rsa.PrivateKey) func(m *big.Int) *big.Int {
	return func(m *big.Int) *big.Int { return new(big.Int).Exp(m, priv.D, priv.N) }
}

// rsaSmallSigner is an authority whose RSA modulus is 1023 bits. Go's crypto/rsa will not sign
// with a key that small, so the PKCS #1 v1.5 signature is computed directly, and it is a valid
// signature: only the key size rule refuses the token.
func rsaSmallSigner() *tokenSigner {
	priv := rsaVectorKey(1023, 1023, 65537)
	return (&rsaRaw{pub: &priv.PublicKey, exp: privateExp(priv)}).pkcs1Signer(digestInfoSHA256)
}

// rsaWideExponentSigner is an authority whose RSA public exponent is 2^32-5, a prime past the
// 2^31-1 bound. Go's crypto/rsa will not sign with that exponent, so the signature is computed
// directly, and it is a valid signature: only the exponent bound refuses the token.
func rsaWideExponentSigner() *tokenSigner {
	priv := rsaVectorKey(2048, 4096, 1<<32-5)
	return (&rsaRaw{pub: &priv.PublicKey, exp: privateExp(priv)}).pkcs1Signer(digestInfoSHA256)
}

// rsaExponentOneSigner is an authority whose RSA public exponent is 1, under which a signature is
// its own encoded message, so the signature is valid and only the exponent's lower bound refuses
// the token.
func rsaExponentOneSigner() *tokenSigner {
	priv := rsaVectorKey(2048, 2048, 65537)
	k := &rsaRaw{pub: &rsa.PublicKey{N: priv.N, E: 1}, exp: func(m *big.Int) *big.Int { return m }}
	return k.pkcs1Signer(digestInfoSHA256)
}

// rsaExponentFourSigner is an authority whose RSA modulus is a 1024-bit prime p with p = 3 mod 4
// and whose public exponent is 4. A message representative that is a square mod p has a fourth
// root, m^(((p+1)/4)^2), and the token is minted again until its representative is a square, so
// the signature is valid and only the rule that the exponent is odd refuses the token.
func rsaExponentFourSigner() *tokenSigner {
	v := newVectorRand(4)
	p := v.prime(1024, true)
	one := big.NewInt(1)
	half := new(big.Int).Rsh(new(big.Int).Sub(p, one), 1)
	quarter := new(big.Int).Rsh(new(big.Int).Add(p, one), 2)
	root := new(big.Int).Mul(quarter, quarter)
	k := &rsaRaw{pub: &rsa.PublicKey{N: p, E: 4}, exp: func(m *big.Int) *big.Int {
		if new(big.Int).Exp(m, half, p).Cmp(one) != 0 {
			return nil
		}
		return new(big.Int).Exp(m, root, p)
	}}
	return k.pkcs1Signer(digestInfoSHA256)
}

// rsaEvenModulusSigner is an authority whose RSA modulus is twice a 1024-bit prime p, an even
// number of 1025 bits. A signature s with s = m mod 2 and s = m^d mod p is valid under 65537,
// because an odd power keeps the parity, so only the rule that the modulus is odd refuses the
// token.
func rsaEvenModulusSigner() *tokenSigner {
	v := newVectorRand(1025)
	p := v.prime(1024, false)
	one := big.NewInt(1)
	d := new(big.Int).ModInverse(big.NewInt(65537), new(big.Int).Sub(p, one))
	n := new(big.Int).Lsh(p, 1)
	k := &rsaRaw{pub: &rsa.PublicKey{N: n, E: 65537}, exp: func(m *big.Int) *big.Int {
		sp := new(big.Int).Exp(m, d, p)
		if sp.Bit(0) != m.Bit(0) {
			sp.Add(sp, p)
		}
		return sp
	}}
	return k.pkcs1Signer(digestInfoSHA256)
}

// rsaMultiPrime is an RSA key whose modulus is exactly bits long, the product of 512-bit primes
// and one last prime sized to fit, with the public exponent 65537. A key this long takes many
// minutes to derive from two primes, while many small primes take moments, and a signature made
// with them through the Chinese remainder theorem is an ordinary valid signature under the
// modulus and 65537.
func rsaMultiPrime(bits int, seed uint64) *rsaRaw {
	v := newVectorRand(seed)
	one := big.NewInt(1)
	var primes []*big.Int
	n := big.NewInt(1)
	for bits-n.BitLen() > 1024 {
		p := v.prime(512, false)
		if !slices.ContainsFunc(primes, func(q *big.Int) bool { return q.Cmp(p) == 0 }) {
			primes = append(primes, p)
			n.Mul(n, p)
		}
	}
	lo := new(big.Int).Lsh(one, uint(bits-1))
	lo.Add(lo, new(big.Int).Sub(n, one)).Div(lo, n)
	hi := new(big.Int).Lsh(one, uint(bits))
	hi.Sub(hi, one).Div(hi, n)
	primes = append(primes, v.primeBetween(lo, hi, false))
	n.Mul(n, primes[len(primes)-1])
	if n.BitLen() != bits {
		panic(fmt.Sprintf("multi-prime modulus is %d bits, want %d", n.BitLen(), bits))
	}
	e := big.NewInt(65537)
	return &rsaRaw{pub: &rsa.PublicKey{N: n, E: 65537}, exp: func(m *big.Int) *big.Int {
		s := new(big.Int)
		for _, p := range primes {
			sp := new(big.Int).Exp(m, new(big.Int).ModInverse(e, new(big.Int).Sub(p, one)), p)
			rest := new(big.Int).Div(n, p)
			s.Add(s, sp.Mul(sp, rest).Mul(sp, new(big.Int).ModInverse(rest, p)))
		}
		return s.Mod(s, n)
	}}
}

// vectorRand draws the numbers vector keys are made from, from a fixed seed, so the keys are the
// same on every run.
type vectorRand struct {
	// rng is the seeded source.
	rng *mathrand.Rand
}

// newVectorRand returns a source seeded with seed.
func newVectorRand(seed uint64) *vectorRand {
	return &vectorRand{rng: mathrand.New(mathrand.NewPCG(seed, seed^0x9e3779b97f4a7c15))}
}

// below returns a number from zero up to, but not including, limit.
func (v *vectorRand) below(limit *big.Int) *big.Int {
	b := make([]byte, (limit.BitLen()+7)/8+8)
	for i := range b {
		b[i] = byte(v.rng.Uint32())
	}
	return new(big.Int).Mod(new(big.Int).SetBytes(b), limit)
}

// prime returns a prime of exactly bits bits for which 65537 is coprime with p-1, and with
// p = 3 mod 4 when threeMod4 is set.
func (v *vectorRand) prime(bits int, threeMod4 bool) *big.Int {
	lo := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
	hi := new(big.Int).Lsh(big.NewInt(1), uint(bits))
	return v.primeBetween(lo, hi.Sub(hi, big.NewInt(1)), threeMod4)
}

// primeBetween returns a prime from lo to hi for which 65537 is coprime with p-1, and with
// p = 3 mod 4 when threeMod4 is set.
func (v *vectorRand) primeBetween(lo, hi *big.Int, threeMod4 bool) *big.Int {
	one := big.NewInt(1)
	span := new(big.Int).Sub(hi, lo)
	for {
		p := new(big.Int).Add(lo, v.below(span))
		p.SetBit(p, 0, 1)
		if threeMod4 {
			p.SetBit(p, 1, 1)
		}
		gcd := new(big.Int).GCD(nil, nil, big.NewInt(65537), new(big.Int).Sub(p, one))
		if p.Cmp(hi) <= 0 && gcd.Cmp(one) == 0 && p.ProbablyPrime(32) {
			return p
		}
	}
}

// weierstrass is a short Weierstrass curve y^2 = x^3 + ax + b over the field of p, with base point
// (gx, gy) of order n, enough to sign deterministically with a curve crypto/ecdsa does not offer.
type weierstrass struct {
	// p is the field prime.
	p *big.Int
	// a is the curve's linear coefficient.
	a *big.Int
	// n is the order of the base point.
	n *big.Int
	// gx and gy are the base point's coordinates.
	gx, gy *big.Int
	// size is the length of a coordinate in octets.
	size int
}

// add returns the sum of two affine points, with nil as the point at infinity.
func (c *weierstrass) add(x1, y1, x2, y2 *big.Int) (*big.Int, *big.Int) {
	if x1 == nil {
		return x2, y2
	}
	if x2 == nil {
		return x1, y1
	}
	var l *big.Int
	if x1.Cmp(x2) == 0 {
		if new(big.Int).Mod(new(big.Int).Add(y1, y2), c.p).Sign() == 0 {
			return nil, nil
		}
		num := new(big.Int).Add(new(big.Int).Mul(big.NewInt(3), new(big.Int).Mul(x1, x1)), c.a)
		den := new(big.Int).ModInverse(new(big.Int).Mul(big.NewInt(2), y1), c.p)
		l = new(big.Int).Mul(num, den)
	} else {
		den := new(big.Int).ModInverse(new(big.Int).Mod(new(big.Int).Sub(x2, x1), c.p), c.p)
		l = new(big.Int).Mul(new(big.Int).Sub(y2, y1), den)
	}
	l.Mod(l, c.p)
	x3 := new(big.Int).Sub(new(big.Int).Sub(new(big.Int).Mul(l, l), x1), x2)
	x3.Mod(x3, c.p)
	y3 := new(big.Int).Sub(new(big.Int).Mul(l, new(big.Int).Sub(x1, x3)), y1)
	y3.Mod(y3, c.p)
	return x3, y3
}

// mul returns k times the base point.
func (c *weierstrass) mul(k *big.Int) (*big.Int, *big.Int) {
	var rx, ry *big.Int
	ax, ay := c.gx, c.gy
	for i := 0; i < k.BitLen(); i++ {
		if k.Bit(i) == 1 {
			rx, ry = c.add(rx, ry, ax, ay)
		}
		ax, ay = c.add(ax, ay, ax, ay)
	}
	return rx, ry
}

// sign returns a DER ECDSA signature over digest with private scalar d, its nonce derived from
// d and digest so that the vectors are the same on every run.
func (c *weierstrass) sign(d *big.Int, digest []byte) []byte {
	e := new(big.Int).SetBytes(digest)
	seed := sha512.Sum512(append(d.Bytes(), digest...))
	k := new(big.Int).Mod(new(big.Int).SetBytes(seed[:]), new(big.Int).Sub(c.n, big.NewInt(1)))
	k.Add(k, big.NewInt(1))
	rx, _ := c.mul(k)
	r := new(big.Int).Mod(rx, c.n)
	s := new(big.Int).Mul(r, d)
	s.Add(s, e)
	s.Mul(s, new(big.Int).ModInverse(k, c.n))
	s.Mod(s, c.n)
	return mustMarshal(struct{ R, S *big.Int }{r, s})
}

// hexInt reads a hexadecimal constant.
func hexInt(h string) *big.Int {
	v, ok := new(big.Int).SetString(h, 16)
	if !ok {
		panic(h)
	}
	return v
}

// ecTokenSigner is an ECDSA authority with a fixed scalar, signing ecdsa-with-SHA256 with a
// deterministic nonce. The P-256 form writes its key as a compressed point, and the secp256k1 form
// is a key on that curve; each signature is valid, so only the key form or the curve refuses it.
func ecTokenSigner(compressed, otherCurve bool) *tokenSigner {
	c := &weierstrass{
		p:    hexInt("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff"),
		a:    big.NewInt(-3),
		n:    hexInt("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
		gx:   hexInt("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
		gy:   hexInt("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
		size: 32,
	}
	curve := asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	if otherCurve {
		c = &weierstrass{
			p:    hexInt("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f"),
			a:    big.NewInt(0),
			n:    hexInt("fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
			gx:   hexInt("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
			gy:   hexInt("483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
			size: 32,
		}
		curve = asn1.ObjectIdentifier{1, 3, 132, 0, 10}
	}
	scalar := sha256.Sum256([]byte("LoomSeal conformance vector ECDSA authority"))
	d := new(big.Int).Mod(new(big.Int).SetBytes(scalar[:]), c.n)
	x, y := c.mul(d)
	point := append(append([]byte{4}, x.FillBytes(make([]byte, c.size))...),
		y.FillBytes(make([]byte, c.size))...)
	if compressed {
		point = append([]byte{byte(2 + y.Bit(0))}, point[1:1+c.size]...)
	}
	return &tokenSigner{
		spki: func() *derNode {
			return derSeq(0x30, derSeq(0x30, derOID(oidECPublicKey), derOID(curve)),
				&derNode{tag: 0x03, val: append([]byte{0}, point...)})
		},
		sigAlg: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2},
		sign: func(signed []byte) []byte {
			sum := sha256.Sum256(signed)
			return c.sign(d, sum[:])
		},
	}
}

// tokenTree is a minted token as a tree of named nodes, so a vector can change one element.
type tokenTree struct {
	// n holds the token's named nodes.
	n map[string]*derNode
	// signer signs the signed attributes.
	signer *tokenSigner
	// trailing is appended after the ContentInfo.
	trailing []byte
	// shortSignature drops the signature's leading octet, choosing a TSTInfo serial that makes it
	// zero.
	shortSignature bool
	// signatureSuffix is appended to the signature.
	signatureSuffix []byte
	// rewriteSignature, when set, replaces the signature with what it returns.
	rewriteSignature func(sig []byte) []byte
}

// newTokenTree builds a token over link: a TSTInfo with genTime 20260727150100Z, an authority
// certificate valid through 2026 and marked for timestamping, and one signer info naming it by
// issuer and serial.
//
//nolint:funlen // The whole token, element by element, so a vector can name any of them.
func newTokenTree(signer *tokenSigner, link string) *tokenTree {
	t := &tokenTree{n: map[string]*derNode{}, signer: signer}
	n := t.n
	imprint := sha256Imprint(link)
	n["tstVersion"] = derInt(1)
	n["policy"] = derOID(oidTSAPolicy)
	n["imprint"] = derSeq(0x30, derSeq(0x30, derOID(oidSHA256)),
		&derNode{tag: 0x04, val: imprint.Digest})
	n["tstSerial"] = derInt(42)
	n["genTime"] = &derNode{tag: 0x18, val: []byte("20260727150100Z")}
	n["tst"] = derSeq(0x30, n["tstVersion"], n["policy"], n["imprint"], n["tstSerial"],
		n["genTime"])
	tst := n["tst"]
	n["eContent"] = &derNode{tag: 0x04, fill: tst.encode}

	n["spki"] = signer.spki()
	n["spkiAlg"], n["spkiKey"] = n["spki"].kids[0], n["spki"].kids[1]
	name := derSeq(0x30, derSeq(0x31, derSeq(0x30, derOID(asn1.ObjectIdentifier{2, 5, 4, 3}),
		&derNode{tag: 0x0c, val: []byte(vectorAuthority)})))
	n["notBefore"] = &derNode{tag: 0x17, val: []byte("260101000000Z")}
	n["notAfter"] = &derNode{tag: 0x17, val: []byte("270101000000Z")}
	n["ekuCritical"] = &derNode{tag: 0x01, val: []byte{0xff}}
	n["eku"] = derSeq(0x30, derOID(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8}))
	eku := n["eku"]
	n["ekuExt"] = derSeq(0x30, derOID(asn1.ObjectIdentifier{2, 5, 29, 37}), n["ekuCritical"],
		&derNode{tag: 0x04, fill: eku.encode})
	n["ski"] = &derNode{tag: 0x04, val: tokenSKI}
	ski := n["ski"]
	n["skiValue"] = &derNode{tag: 0x04, fill: ski.encode}
	n["exts"] = derSeq(0x30, n["ekuExt"], derSeq(0x30, derOID(asn1.ObjectIdentifier{2, 5, 29, 14}),
		n["skiValue"]))
	n["issuer"] = name
	n["certSerial"] = derInt(7)
	n["certVersion"] = derSeq(0xa0, derInt(2))
	n["extsWrap"] = derSeq(0xa3, n["exts"])
	n["tbs"] = derSeq(0x30, n["certVersion"], n["certSerial"],
		derSeq(0x30, derOID(oidEd25519)), name, derSeq(0x30, n["notBefore"], n["notAfter"]),
		name, n["spki"], n["extsWrap"])
	certKey := ed25519.NewKeyFromSeed(bytesRepeat(29))
	tbs := n["tbs"]
	n["cert"] = derSeq(0x30, tbs, derSeq(0x30, derOID(oidEd25519)), &derNode{tag: 0x03,
		fill: func() []byte { return append([]byte{0}, ed25519.Sign(certKey, tbs.encode())...) }})
	cert := n["cert"]

	eContent := n["eContent"]
	n["md"] = &derNode{tag: 0x04, fill: func() []byte {
		sum := sha256.Sum256(eContent.fill())
		return sum[:]
	}}
	n["mdValues"] = derSeq(0x31, n["md"])
	n["attrs"] = derSeq(0xa0,
		derSeq(0x30, derOID(oidContentType), derSeq(0x31, derOID(oidTSTInfo))),
		derSeq(0x30, derOID(oidMessageDigest), n["mdValues"]))
	n["sid"] = derSeq(0x30,
		&derNode{header: func(byte, []byte) []byte { return n["issuer"].encode() }},
		&derNode{header: func(byte, []byte) []byte { return n["certSerial"].encode() }})
	n["sigAlgOID"] = derOID(signer.sigAlg)
	n["sig"] = &derNode{tag: 0x04}
	n["siDigest"] = derSeq(0x30, derOID(oidSHA256))
	n["si"] = derSeq(0x30, derInt(1), n["sid"], n["siDigest"], n["attrs"],
		derSeq(0x30, n["sigAlgOID"]), n["sig"])
	n["signerInfos"] = derSeq(0x31, n["si"])
	n["eContentType"] = derOID(oidTSTInfo)
	n["certs"] = derSeq(0xa0, cert)
	n["signedData"] = derSeq(0x30, derInt(3), derSeq(0x31, derSeq(0x30, derOID(oidSHA256))),
		derSeq(0x30, n["eContentType"], derSeq(0xa0, eContent)), n["certs"], n["signerInfos"])
	n["ciWrap"] = derSeq(0xa0, n["signedData"])
	n["contentType"] = derOID(oidSignedData)
	n["ci"] = derSeq(0x30, n["contentType"], n["ciWrap"])
	return t
}

// encode signs the token as its tree now stands and returns it base64 encoded. The signature
// covers the signed attributes as encoded, with their [0] identifier rewritten as a SET.
func (t *tokenTree) encode() string {
	sign := func() []byte {
		attrs := t.n["attrs"].encode()
		return t.signer.sign(append([]byte{0x31}, attrs[1:]...))
	}
	sig := sign()
	for serial := int64(43); sig == nil; serial++ {
		t.n["tstSerial"].val = mustMarshal(serial)[2:]
		sig = sign()
	}
	t.n["sig"].val = sig
	for serial := int64(43); t.shortSignature; serial++ {
		t.n["tstSerial"].val = mustMarshal(serial)[2:]
		if sig := sign(); sig[0] == 0 {
			t.n["sig"].val = sig[1:]
			break
		}
	}
	t.n["sig"].val = append(t.n["sig"].val, t.signatureSuffix...)
	if t.rewriteSignature != nil {
		t.n["sig"].val = t.rewriteSignature(t.n["sig"].val)
	}
	return base64.StdEncoding.EncodeToString(append(t.n["ci"].encode(), t.trailing...))
}

// tokenVector adds a signed one-claim chain-v1 bundle whose claim is at claimAt and whose one
// rfc3161 anchor carries the token mint returns for the head link. A bundle that must verify is
// expected at the proof-verified anchored level, and one that must not is expected to fail the
// anchor check.
func (s *state) tokenVector(name, claimAt string, ok bool, why string, mint func(string) string) {
	m := s.v1(1, false)
	m["claims"].([]any)[0].(map[string]any)["at"] = claimAt
	s.relinkV1(m, false)
	link := m["chain"].(map[string]any)["head"].(map[string]any)["link"].(string)
	m["anchors"] = []any{map[string]any{
		"type": "rfc3161", "seq": int64(1), "link": link, "at": "2026-07-27T15:01:00Z",
		"ref": "https://tsa.example/tsr", "proof": mint(link),
	}}
	if ok {
		s.add(name, true, "signed, chained (full), anchored (proof verified)", "", why, s.sign(m))
		return
	}
	s.add(name, false, "", "anchor", why, s.sign(m))
}

// OIDs the minted timestamp tokens carry.
var (
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidContentType   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidEd25519       = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidTSAPolicy     = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 99999, 1}
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidECPublicKey   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
)

// tsaAlgorithm is an AlgorithmIdentifier with no parameters.
type tsaAlgorithm struct {
	// Algorithm is the algorithm's OID.
	Algorithm asn1.ObjectIdentifier
}

// tsaImprint is the hash a token attests to.
type tsaImprint struct {
	// Algorithm is the hash function.
	Algorithm tsaAlgorithm
	// Digest is the hash of the anchored link's raw bytes.
	Digest []byte
}

// tstInfoDER encodes the TSTInfo an authority signs: version 1, a fixed policy, imprint, serial
// number 42, and genTime written as given, followed by trailing, which are already DER encoded.
func tstInfoDER(imprint tsaImprint, genTime asn1.RawValue, trailing ...[]byte) []byte {
	elems := append([][]byte{
		mustMarshal(1), mustMarshal(oidTSAPolicy), mustMarshal(imprint),
		mustMarshal(big.NewInt(42)), mustMarshal(genTime),
	}, trailing...)
	return mustMarshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence,
		IsCompound: true, Bytes: bytes.Join(elems, nil)})
}

// sha256Imprint is the SHA-256 message imprint of link's raw bytes.
func sha256Imprint(link string) tsaImprint {
	raw, err := hex.DecodeString(link)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(raw)
	return tsaImprint{Algorithm: tsaAlgorithm{oidSHA256}, Digest: sum[:]}
}

// generalizedTime wraps text as a universal GeneralizedTime value.
func generalizedTime(text string) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagGeneralizedTime,
		Bytes: []byte(text)}
}

// tsaAttribute is one signed attribute.
type tsaAttribute struct {
	// Type names the attribute.
	Type asn1.ObjectIdentifier
	// Values is the SET holding its one value.
	Values asn1.RawValue
}

// tsaIssuerSerial names the signer certificate by its issuer and serial.
type tsaIssuerSerial struct {
	// Issuer is the certificate's raw issuer name.
	Issuer asn1.RawValue
	// Serial is the certificate's serial number.
	Serial *big.Int
}

// tsaSignerInfo is the authority's one signature over the TSTInfo.
type tsaSignerInfo struct {
	// Version is the structure version.
	Version int
	// SID names the signer certificate.
	SID tsaIssuerSerial
	// DigestAlgorithm is the hash over the TSTInfo the signed attributes commit to.
	DigestAlgorithm tsaAlgorithm
	// SignedAttrs are the signed attributes under their implicit [0] tag.
	SignedAttrs asn1.RawValue
	// SignatureAlgorithm is the signature scheme.
	SignatureAlgorithm tsaAlgorithm
	// Signature is the ed25519 signature over the signed attributes as a SET.
	Signature []byte
}

// tsaEncap wraps the DER TSTInfo.
type tsaEncap struct {
	// Type names the payload, TSTInfo.
	Type asn1.ObjectIdentifier
	// Content is the TSTInfo in an OCTET STRING under an explicit [0] tag.
	Content asn1.RawValue
}

// tsaSignedData is the CMS SignedData a token carries.
type tsaSignedData struct {
	// Version is the structure version.
	Version int
	// DigestAlgorithms is the SET of digests used.
	DigestAlgorithms asn1.RawValue
	// Encap holds the TSTInfo.
	Encap tsaEncap
	// Certificates carries the authority certificate under an implicit [0] tag.
	Certificates asn1.RawValue
	// SignerInfos is the SET holding the one signer.
	SignerInfos asn1.RawValue
}

// tsaContentInfo is the outer CMS wrapper.
type tsaContentInfo struct {
	// Type names the content, SignedData.
	Type asn1.ObjectIdentifier
	// Content is the SignedData under an explicit [0] tag.
	Content asn1.RawValue
}

// timestampToken mints an RFC 3161 token, base64 encoded, that signs info, a DER TSTInfo. A fixed
// ed25519 authority key signs it, holding a certificate valid from the start of 2026 to notAfter
// and marked for timestamping, so the bytes are the same on every run.
func timestampToken(info []byte, notAfter time.Time) string {
	priv := ed25519.NewKeyFromSeed(bytesRepeat(23))
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(7),
		Subject:      pkix.Name{CommonName: vectorAuthority},
		NotBefore:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
	}
	certDER, err := x509.CreateCertificate(nil, tmpl, tmpl, priv.Public(), priv)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		panic(err)
	}
	infoDigest := sha256.Sum256(info)
	attrs := mustMarshal(derSet(
		mustMarshal(tsaAttribute{Type: oidContentType,
			Values: derSet(mustMarshal(oidTSTInfo))}),
		mustMarshal(tsaAttribute{Type: oidMessageDigest,
			Values: derSet(mustMarshal(infoDigest[:]))}),
	))
	sid := tsaIssuerSerial{
		Issuer: asn1.RawValue{FullBytes: cert.RawIssuer}, Serial: cert.SerialNumber,
	}
	signer := mustMarshal(tsaSignerInfo{
		Version:            1,
		SID:                sid,
		DigestAlgorithm:    tsaAlgorithm{oidSHA256},
		SignedAttrs:        asn1.RawValue{FullBytes: append([]byte{0xA0}, attrs[1:]...)},
		SignatureAlgorithm: tsaAlgorithm{oidEd25519},
		Signature:          ed25519.Sign(priv, attrs),
	})
	signed := mustMarshal(tsaSignedData{
		Version:          3,
		DigestAlgorithms: derSet(mustMarshal(tsaAlgorithm{oidSHA256})),
		Encap: tsaEncap{Type: oidTSTInfo, Content: asn1.RawValue{
			Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: mustMarshal(info)}},
		Certificates: asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true,
			Bytes: certDER},
		SignerInfos: derSet(signer),
	})
	token := mustMarshal(tsaContentInfo{Type: oidSignedData, Content: asn1.RawValue{
		Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: signed}})
	return base64.StdEncoding.EncodeToString(token)
}

// derSet wraps already encoded elements, given in DER order, as an ASN.1 SET.
func derSet(elems ...[]byte) asn1.RawValue {
	return asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSet, IsCompound: true,
		Bytes: bytes.Join(elems, nil)}
}

// mustMarshal DER encodes v, panicking on a value the encoder cannot hold.
func mustMarshal(v any) []byte {
	out, err := asn1.Marshal(v)
	if err != nil {
		panic(err)
	}
	return out
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

// referenceAnchors builds a git, an https, and a rekor anchor at the given coordinates, one of each
// type a verifier matches by coordinates only, and gives each an opaque proof of its own.
func referenceAnchors(seq int64, link string) []any {
	g := gitAnchor(seq, link)
	g["proof"] = base64.StdEncoding.EncodeToString([]byte("a commit a relying party fetches"))
	return []any{g, map[string]any{
		"type": "https", "seq": seq, "link": link, "at": "2026-07-01T00:00:00Z",
		"ref":   "https://producer.example/loomseal/head.json",
		"proof": base64.StdEncoding.EncodeToString([]byte("a published head a relying party fetches")),
	}, map[string]any{
		"type": "rekor", "seq": seq, "link": link, "at": "2026-07-01T00:00:00Z",
		"ref":   "https://rekor.example/api/v1/log/entries/0001",
		"proof": base64.StdEncoding.EncodeToString([]byte("a log entry a relying party fetches")),
	}}
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

// add records one vector and writes its bundle file. A vector that must not verify declares the
// level a failed bundle reports, because a failed bundle achieved none: "unsupported" when the
// verifier does not implement what the bundle declares, and "not verified" otherwise. It follows
// from the failing check unless the caller states it, as the one vector refused as unsupported
// under the signature check does.
func (s *state) add(name string, mustVerify bool, level, failing, why string, data []byte) {
	file := name + ".loomseal.json"
	if err := os.WriteFile(filepath.Join(dir, file), data, 0o600); err != nil {
		panic(err)
	}
	if !mustVerify && level == "" {
		level = "not verified"
		if failing == "unsupported" {
			level = "unsupported"
		}
	}
	s.man.Vectors = append(s.man.Vectors, vector{
		Name: name, File: file, MustVerify: mustVerify, Level: level,
		FailingCheck: failing, Why: why,
	})
}

// expectSubject records the subject type a verifier must report as outside its vocabulary in a
// vector that must verify.
func (s *state) expectSubject(name, unknown string) {
	for i := range s.man.Vectors {
		if s.man.Vectors[i].Name == name {
			s.man.Vectors[i].UnknownSubjectType = unknown
			return
		}
	}
	panic("expectSubject: no vector named " + name)
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

// expectSpan records the coverage line, the longest gap, and the gap lines a verifier must report
// for a vector that must verify, so every verifier is held to one measurement of a gap.
func (s *state) expectSpan(name, coverage, longest string, gaps ...string) {
	for i := range s.man.Vectors {
		if s.man.Vectors[i].Name == name {
			s.man.Vectors[i].SpanCoverage = coverage
			s.man.Vectors[i].SpanLongestGap = longest
			s.man.Vectors[i].SpanGaps = gaps
			return
		}
	}
	panic("expectSpan: no vector named " + name)
}

// expectAttested records the line a verifier must report for each timestamp token it verifies in
// a vector that must verify, so every verifier names a token's signer by one rule.
func (s *state) expectAttested(name string, lines ...string) {
	for i := range s.man.Vectors {
		if s.man.Vectors[i].Name == name {
			s.man.Vectors[i].AnchorAttestations = lines
			return
		}
	}
	panic("expectAttested: no vector named " + name)
}

// expectUnopened records how many carried proofs a verifier must report as of a type it cannot open
// offline in a vector, zero included, so the count is held whether or not the bundle verifies.
func (s *state) expectUnopened(name string, n int) {
	for i := range s.man.Vectors {
		if s.man.Vectors[i].Name == name {
			s.man.Vectors[i].AnchorProofsUnopened = &n
			return
		}
	}
	panic("expectUnopened: no vector named " + name)
}

// expectOnDeclaredHead records how many proofs a verifier must report on anchors that match only
// the unverified declared head in a vector, zero included.
func (s *state) expectOnDeclaredHead(name string, n int) {
	for i := range s.man.Vectors {
		if s.man.Vectors[i].Name == name {
			s.man.Vectors[i].AnchorProofsOnDeclaredHead = &n
			return
		}
	}
	panic("expectOnDeclaredHead: no vector named " + name)
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
	// The expectations every case but the mismatched and empty ones requires.
	aud, chal := supplied("acme-verifier"), supplied("chal-1")
	vf := s.writePresentationFile("present-valid", valid)
	s.addPresentation("present-valid", vf, aud, chal, "",
		"A presentation bound to the verifier and nonce it declares verifies under those pins.")
	s.addPresentation("present-no-pins", vf, nil, nil, "",
		"The same presentation with no pins verifies: the pins are the caller's to require.")
	s.addPresentation("present-wrong-audience", vf, supplied("someone-else"), chal, "audience",
		"The same presentation fails when the verifier requires a different audience, which is what "+
			"stops it being replayed to another verifier.")
	s.addPresentation("present-stale-nonce", vf, aud, supplied("old-nonce"), "nonce",
		"The same presentation fails against a stale challenge, which is what stops a replay.")
	s.addPresentation("present-empty-audience", vf, supplied(""), chal, "expectation",
		"An expected audience supplied empty is refused before anything is verified, by every entry "+
			"point that can tell it from an absent one, rather than read as no expectation.")
	s.addPresentation("present-empty-nonce", vf, aud, supplied(""), "expectation",
		"An expected nonce supplied empty is refused before anything is verified, by every entry "+
			"point that can tell it from an absent one, rather than read as no expectation and the "+
			"replay defense skipped.")

	tampered := []byte(strings.Replace(string(valid), "/api/runs", "/api/evil", 1))
	tf := s.writePresentationFile("present-tampered-bundle", tampered)
	s.addPresentation("present-tampered-bundle", tf, aud, chal, "bundle",
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
	s.addPresentation("present-bad-holder-sig", bf, aud, chal, "presentation",
		"A presentation whose holder signature was altered does not verify.")

	// A presentation counts its own level above the bundle it carries, so a bundle at the nesting
	// bound, which verifies alone, cannot be presented: the presentation is one level past it.
	deep := s.v1(1, false)
	deep["claims"].([]any)[0].(map[string]any)["payload"].(map[string]any)["deep"] =
		nested(bundle.MaxDepth - envelopeDepth)
	s.relinkV1(deep, false)
	deepPres, err := seal.Present(s.sign(deep), hpriv, "acme-verifier", "chal-1", at)
	if err != nil {
		panic(err)
	}
	df := s.writePresentationFile("present-past-bound", deepPres)
	s.addBundleRouted("present-past-bound", df,
		"A presentation nested one level past the bound is refused at parse, although the bundle "+
			"it carries is within the bound and verifies alone. No verifier reads it far enough "+
			"to find its version, so one taking either kind of document reads it as a bundle.")

	// An integer beyond 2^53 inside the presented bundle has no canonical form, so the bundle the
	// holder signature covers cannot be computed and the presentation is refused at parse.
	big := []byte(strings.Replace(string(valid), `"path":"/api/runs"`,
		`"path":"/api/runs","big":9007199254740993`, 1))
	gf := s.writePresentationFile("present-number-exceeds-2p53", big)
	s.addPresentation("present-number-exceeds-2p53", gf, aud, chal, "parse",
		"A presentation whose bundle carries an integer beyond 2^53 is refused at parse, with a "+
			"verdict and never a crash.")

	// A fractional number inside the presented bundle. A verifier recognizes a presentation by its
	// version member before it holds any number to the profile, so this one is routed to the
	// presentation checks like any other and refused there.
	frac := []byte(strings.Replace(string(valid), `"path":"/api/runs"`,
		`"path":"/api/runs","ratio":1.5`, 1))
	nf := s.writePresentationFile("present-non-integer-number", frac)
	s.addPresentation("present-non-integer-number", nf, aud, chal, "parse",
		"A presentation whose bundle carries a fractional number is recognized as a presentation "+
			"by every verifier and refused by the presentation checks.")

	// A holder key and a holder signature broken across lines. Each is otherwise genuine, so only
	// the base64 rule refuses them.
	lineBroken := func(name string, edit func(p map[string]any), why string) {
		var p map[string]any
		if err := json.Unmarshal(valid, &p); err != nil {
			panic(err)
		}
		edit(p)
		out, err := json.Marshal(p)
		if err != nil {
			panic(err)
		}
		s.addPresentation(name, s.writePresentationFile(name, out), aud, chal, "presentation",
			why)
	}
	lineBroken("present-holder-key-line-break", func(p map[string]any) {
		holder := p["holder"].(map[string]any)
		key := holder["public_key"].(string)
		holder["public_key"] = key[:12] + "\n" + key[12:]
	}, "A presentation whose holder public_key carries a line break inside its base64 is "+
		"refused rather than decoded by skipping the break.")
	lineBroken("present-sig-line-break", func(p map[string]any) {
		sig := p["sig"].(string)
		p["sig"] = sig[:20] + "\r\n" + sig[20:]
	}, "A presentation whose holder signature carries a line break inside its base64 is "+
		"refused rather than decoded by skipping the break.")

	// Creation times that a general date parser reads but RFC 3339 does not allow, signed by the
	// holder, so only the time rule refuses them.
	for _, c := range []struct {
		// name is the vector's name and the stem of its file.
		name string
		// createdAt is the presentation's signed creation time.
		createdAt string
		// why is the vector's description in the manifest.
		why string
	}{{
		name: "present-created-at-one-digit-hour", createdAt: "2026-07-27T1:00:00Z",
		why: "A presentation whose created_at has a one-digit hour is refused, because the " +
			"time is not RFC 3339.",
	}, {
		name: "present-created-at-comma-fraction", createdAt: "2026-07-27T15:00:00,5Z",
		why: "A presentation whose created_at has a comma before its fractional second is " +
			"refused, because the time is not RFC 3339.",
	}, {
		name: "present-created-at-offset", createdAt: "2026-07-27T15:00:00+00:00",
		why: "A presentation whose created_at carries a numeric offset, even +00:00, is refused, " +
			"because a time ends in Z.",
	}, {
		name: "present-created-at-lowercase-z", createdAt: "2026-07-27T15:00:00z",
		why: "A presentation whose created_at ends in a lower case z is refused, because the " +
			"time ends in an upper case Z.",
	}} {
		pres, err := seal.Present(inner, hpriv, "acme-verifier", "chal-1", c.createdAt)
		if err != nil {
			panic(err)
		}
		s.addPresentation(c.name, s.writePresentationFile(c.name, pres), aud, chal,
			"presentation", c.why)
	}

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
	s.addPresentation("present-casefold-audience", ff, aud, chal, "parse",
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
	s.addPresentation("present-casefold-holder-key-id", kff, aud, chal, "parse",
		"A holder carrying the signed key id under a name that folds onto key_id is refused at parse, "+
			"rather than checked in place of the key_id the document shows.")
	s.presentationReadOrder(inner, valid)
}

// presentationReadOrder emits the vectors that pin the order FORMAT.md's "Presentations" section
// reads a presentation in, the order a bundle is read in: the document as JSON, then its version,
// then the number profile, then every member's name and type. A version other than 0.1 is
// unsupported whatever else the presentation carries, and a document that is not JSON, or that
// carries no string version, is refused at parse, read as a bundle by an entry point taking
// either kind of document. It also pins a presentation whose bundle alone fails.
//
//nolint:funlen // One vector per case, listed in one place.
func (s *state) presentationReadOrder(inner, valid []byte) {
	aud, chal := supplied("acme-verifier"), supplied("chal-1")
	// edit rewrites one member of the valid presentation. The holder signature does not cover the
	// version member, so only the change it makes is at fault.
	edit := func(fn func(p map[string]any)) []byte {
		var p map[string]any
		if err := json.Unmarshal(valid, &p); err != nil {
			panic(err)
		}
		fn(p)
		out, err := json.Marshal(p)
		if err != nil {
			panic(err)
		}
		return out
	}
	// inPayload places a literal in the presented bundle's first claim payload, as text, since no
	// Go value marshals to a literal outside the number profile or to one JSON does not define.
	inPayload := func(doc []byte, literal string) []byte {
		out := strings.Replace(string(doc), `"path":"/api/runs"`,
			`"path":"/api/runs","n":`+literal, 1)
		if out == string(doc) {
			panic("presentationReadOrder: no payload path to place a literal beside")
		}
		return []byte(out)
	}
	later := edit(func(p map[string]any) { p["loomseal_presentation"] = "0.2" })
	for _, c := range []struct {
		// name is the vector's name and the stem of its file.
		name string
		// doc is the presentation document.
		doc []byte
		// failing is the check it fails first.
		failing string
		// why is the vector's description in the manifest.
		why string
	}{{
		name: "present-version-later", doc: later, failing: "unsupported",
		why: "A presentation declaring a version this verifier does not implement is " +
			"unsupported, not judged, as a bundle under another version is.",
	}, {
		name: "present-version-empty", failing: "unsupported",
		doc: edit(func(p map[string]any) { p["loomseal_presentation"] = "" }),
		why: "A presentation whose version is the empty string declares a version other than " +
			"0.1, so it is routed to the presentation checks like any other and is unsupported.",
	}, {
		name: "present-version-later-unknown-member", failing: "unsupported",
		doc: edit(func(p map[string]any) {
			p["loomseal_presentation"] = "0.2"
			p["context"] = "a member a later version defines"
		}),
		why: "A presentation declaring a version this verifier does not implement is " +
			"unsupported although it carries a member the presentation format does not name, " +
			"because the version is read before any member's name.",
	}, {
		name: "present-version-later-non-integer-number", failing: "unsupported",
		doc: inPayload(later, "1.5"),
		why: "A presentation declaring a version this verifier does not implement is " +
			"unsupported although its bundle carries a fractional number, because the version " +
			"is read before the number profile is held.",
	}, {
		name: "present-no-bundle", failing: "parse",
		doc: edit(func(p map[string]any) { delete(p, "bundle") }),
		why: "A presentation that carries no bundle member presents nothing and is refused at " +
			"parse.",
	}} {
		s.addPresentation(c.name, s.writePresentationFile(c.name, c.doc), aud, chal, c.failing,
			c.why)
	}

	// A bundle that fails alone, presented under a holder signature that holds, so only the
	// embedded bundle's own verdict fails the presentation.
	broken := []byte(strings.Replace(string(inner), "/api/runs", "/api/evil", 1))
	hpriv, _ := holderKey()
	brokenPres, err := seal.Present(broken, hpriv, "acme-verifier", "chal-1", at)
	if err != nil {
		panic(err)
	}
	s.addPresentation("present-bundle-fails",
		s.writePresentationFile("present-bundle-fails", brokenPres), aud, chal, "bundle",
		"A presentation whose holder signature verifies over a bundle that does not verify fails "+
			"on the bundle, which is checked on its own terms before the holder signature.")

	// Documents that carry no string version, or are not JSON, are read as bundles by an entry
	// point taking either kind of document, and refused at parse either way.
	for _, c := range []struct {
		// name is the vector's name and the stem of its file.
		name string
		// doc is the document.
		doc []byte
		// why is the vector's description in the manifest.
		why string
	}{{
		name: "present-version-missing",
		doc:  edit(func(p map[string]any) { delete(p, "loomseal_presentation") }),
		why: "A presentation with no loomseal_presentation member declares no version and is " +
			"refused at parse, by the presentation checks and as a bundle alike.",
	}, {
		name: "present-version-not-a-string",
		doc:  edit(func(p map[string]any) { p["loomseal_presentation"] = 1 }),
		why: "A loomseal_presentation member holding the number 1 declares no version, so the " +
			"document is refused at parse, by the presentation checks and as a bundle alike.",
	}, {
		name: "present-bundle-nan", doc: inPayload(valid, "NaN"),
		why: "A presentation whose bundle carries NaN is not JSON, so no verifier finds its " +
			"version: it is read as a bundle and refused at parse, by the presentation checks " +
			"too.",
	}, {
		name: "present-version-later-nan", doc: inPayload(later, "NaN"),
		why: "A presentation declaring a version this verifier does not implement and carrying " +
			"NaN is not JSON, so it is refused at parse rather than judged unsupported.",
	}} {
		s.addBundleRouted(c.name, s.writePresentationFile(c.name, c.doc), c.why)
	}
}

// supplied returns an expectation the verifier is told to require, an empty one included.
func supplied(v string) *string {
	return &v
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
// A case with no failing check must verify, and every other one names the check it fails first.
func (s *state) addPresentation(name, file string, audience, nonce *string, failing, why string) {
	s.presMan.Vectors = append(s.presMan.Vectors, presentationVector{
		Name: name, File: file, ExpectAudience: audience, ExpectNonce: nonce,
		MustVerify: failing == "", FailingCheck: failing, Why: why,
	})
}

// addBundleRouted records a presentation case whose document is not a JSON object carrying a
// string presentation version, so an entry point taking either kind of document reads it as a
// bundle. Read either way it is refused at parse.
func (s *state) addBundleRouted(name, file string, why string) {
	aud, chal := supplied("acme-verifier"), supplied("chal-1")
	s.addPresentation(name, file, aud, chal, "parse", why)
	s.presMan.Vectors[len(s.presMan.Vectors)-1].RoutesAsBundle = true
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

	// An outcome record is a string inside the bundle, so the bundle's nesting bound never counts
	// its brackets. A verifier reading a record for its spec digest must measure the depth without
	// recursion before it parses, or a record built to exhaust a stack ends the run with no
	// verdict. The deeper record comes first: a reader whose stack grew to hold it keeps no margin
	// for the second, which is the order that exhausted the browser build's stack.
	deep := func(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }
	s.add("switchtender-outcome-deep", true, "signed, chained (full)", "",
		"Outcome records nested 20000 and 5000 levels deep reproduce their entries' digests and "+
			"verify. Each is past the depth an outcome record is read to, so neither names a spec "+
			"digest, and the spec beside each is unchecked rather than a reason for a verifier to "+
			"stop without a verdict.",
		s.sign(s.recordReceipt(recordDisclosure{
			NoDecision: true, OutcomeTexts: []string{deep(20000), deep(5000)},
		})))
	s.expect("switchtender-outcome-deep", []string{"claim 1 spec_body", "claim 2 spec_body"}, nil)

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
	// OutcomeTexts, when set, are the bytes of one outcome record each, in place of the single
	// succeeded record, each committed under the exact form in its own entry.
	OutcomeTexts []string
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
	outcomeTexts := d.OutcomeTexts
	if len(outcomeTexts) == 0 {
		outcomeTexts = []string{recordOutcomeTextNaming("succeeded", outcomeSpec)}
	}
	nonce := recordBytes("nonce outcome")
	for _, outcomeText := range outcomeTexts {
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
		payloads = append(payloads, outcomePayload)
	}
	return payloads
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
