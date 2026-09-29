// Package verify runs the full LoomSeal verification procedure over one bundle and
// produces a report. Every failed check records a problem; a bundle is verified only when
// no problems remain. The package never contacts the network.
package verify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/kordloom/loomseal/internal/bundle"
	"github.com/kordloom/loomseal/internal/chain"
	"github.com/kordloom/loomseal/internal/rfc3161"
)

// knownClaimTypes is the registry of claim types this verifier understands. Unknown types
// are reported, never failed, so newer producers stay verifiable.
// Reserved rows stay out until something emits them: a type in this set reads as "checked
// against a registry entry", and claiming that for a type nothing produces is a false statement
// in every report that mentions it.
var knownClaimTypes = map[string]bool{
	"switchtender.audit/1": true,
	"loomseal.span/1":      true,
	"loomseal.agentrun/1":  true,
}

// Options carries the caller's verification inputs.
type Options struct {
	// EvidenceDir is a directory of evidence artifacts to check against the bundle's
	// digests. Empty means no artifacts were supplied.
	EvidenceDir string
	// Fingerprint, when set, requires the producer key to match this sha256: fingerprint.
	Fingerprint string
}

// Report is the outcome of one verification run.
type Report struct {
	// OK reports whether every check passed.
	OK bool `json:"ok"`
	// Unsupported reports that the bundle declares a version, profile, or algorithm this
	// verifier does not implement. Fail-closed, and distinct from a verification failure.
	Unsupported bool `json:"unsupported,omitempty"`
	// UnknownSubjectType carries a subject type outside the known vocabulary. Informational:
	// subject types are vocabulary, not structure, and never fail a bundle.
	UnknownSubjectType string `json:"unknown_subject_type,omitempty"`
	// Level is the conformance wording achieved, such as "signed, chained (structural)".
	Level string `json:"level"`
	// BundleID echoes the bundle's identifier.
	BundleID string `json:"bundle_id,omitempty"`
	// Producer echoes the producing product and version.
	Producer string `json:"producer,omitempty"`
	// Subject echoes what the claims are about.
	Subject string `json:"subject,omitempty"`
	// KeyID is the producer key fingerprint computed from the embedded public key.
	KeyID string `json:"key_id,omitempty"`
	// SignatureOK reports whether a producer signature verified over the canonical bundle.
	SignatureOK bool `json:"signature_ok"`
	// FingerprintMatch reports the pin comparison when a fingerprint was supplied.
	FingerprintMatch *bool `json:"fingerprint_match,omitempty"`
	// ChainPresent reports whether the bundle declares a chain.
	ChainPresent bool `json:"chain_present"`
	// ChainProfile is the declared chain profile.
	ChainProfile string `json:"chain_profile,omitempty"`
	// ChainMode is "full" or "structural" when the chain verified.
	ChainMode string `json:"chain_mode,omitempty"`
	// ChainOK reports whether the chain verified.
	ChainOK bool `json:"chain_ok"`
	// HeadMatched reports whether the declared head tied to the newest bundled claim.
	HeadMatched bool `json:"head_matched"`
	// ClaimsChecked is how many chained claims were checked.
	ClaimsChecked int `json:"claims_checked"`
	// TreeSize is how many leaves sit in the log the signed head names, set only under the tree
	// profile. It is the size of the whole log, not of the window this bundle discloses, so a
	// reader sees how much history the disclosed claims were proved against.
	TreeSize int64 `json:"tree_size,omitempty"`
	// InclusionProofs is how many audit paths were folded and reproduced the head's root, one per
	// disclosed claim. Set only under the tree profile, which is the only one that carries proofs.
	InclusionProofs int `json:"inclusion_proofs,omitempty"`
	// ConsistencyFrom is the earlier log size this bundle proved the log grew from by appending
	// only. Zero when the bundle carried no consistency proof.
	ConsistencyFrom int64 `json:"consistency_from,omitempty"`
	// ConsistencyOK reports whether that proof verified. A bundle without one proves nothing about
	// append-only growth, which is why the field is absent rather than false there.
	ConsistencyOK bool `json:"consistency_ok,omitempty"`
	// AnchorsMatched is how many anchors matched a coordinate the verifier checked: a bundled
	// claim, or the head when it tied to the newest claim.
	AnchorsMatched int `json:"anchors_matched"`
	// AnchorsToDeclaredHead is how many anchors matched only a declared head that lies beyond
	// the bundled claims. That head's link is unverified here, so such an anchor binds nothing
	// this verifier confirmed and does not earn the anchored conformance word.
	AnchorsToDeclaredHead int `json:"anchors_to_declared_head,omitempty"`
	// AnchorProofsCarried is how many anchors embed a proof blob. Only anchors matching a coordinate
	// this verifier confirmed are counted; a proof on a declared head that leads the claims is not.
	AnchorProofsCarried int `json:"anchor_proofs_carried"`
	// AnchorProofsOnDeclaredHead is how many proofs sit on an anchor matching only a declared head
	// beyond the bundled claims. Such a proof attests a link tied to nothing this verifier confirmed,
	// so it is reported but never verified or counted toward the anchored conformance word.
	AnchorProofsOnDeclaredHead int `json:"anchor_proofs_on_declared_head,omitempty"`
	// AnchorProofsValidated reports whether every carried proof was checked and held.
	AnchorProofsValidated bool `json:"anchor_proofs_validated"`
	// AnchorProofsVerified is how many embedded proofs were cryptographically checked against the
	// link they anchor. An rfc3161 proof is signed by a timestamp authority over the link itself, so
	// it is checked offline with nothing but the bundle. Anchors of other types are confirmed by
	// fetching what they point at, which this verifier does not do.
	AnchorProofsVerified int `json:"anchor_proofs_verified,omitempty"`
	// AnchorAttestations describes each verified proof: when the authority signed, and who it was.
	// Whether that authority is worth trusting is the relying party's call, not this verifier's.
	AnchorAttestations []string `json:"anchor_attestations,omitempty"`
	// AnchoredThroughSeq is the highest chain position an anchor pinned outside the producer's
	// reach. Claims past it rest on the producer's key alone.
	AnchoredThroughSeq int64 `json:"anchored_through_seq,omitempty"`
	// UnanchoredClaims is how many bundled claims sit past AnchoredThroughSeq.
	UnanchoredClaims int `json:"unanchored_claims,omitempty"`
	// AttestationAge is how long the bundle sat between its newest verified attestation and the
	// moment it was assembled.
	//
	// It is reported whenever a proof verifies, including when nothing follows the anchor. The
	// claim-to-claim span goes quiet in exactly the case worth catching: cut the entries above an
	// anchor and delete the anchors that covered them, and the bundle comes out with no unanchored
	// claims at all, reading cleaner than the honest one it replaced. This number does not go
	// quiet. A trail anchored on a schedule shows minutes or hours here; one showing months was
	// either not anchored for months or was cut back to an old anchor, and both deserve a question.
	AttestationAge string `json:"attestation_age,omitempty"`
	// UnanchoredWindow is the span from the last anchored claim to the newest bundled claim,
	// which is how long a compromised producer key had to rewrite history undetected. A verified
	// bundle with a wide window is weaker evidence than one with a narrow window.
	UnanchoredWindow string `json:"unanchored_window,omitempty"`
	// EvidenceVerified is how many evidence digests matched a supplied artifact.
	EvidenceVerified int `json:"evidence_verified"`
	// EvidenceMissing is how many digests had no artifact in the supplied directory.
	EvidenceMissing int `json:"evidence_missing"`
	// EvidenceReferenced is how many digests were not checked because no directory was
	// supplied.
	EvidenceReferenced int `json:"evidence_referenced"`
	// UnknownClaimTypes lists claim types outside this verifier's registry.
	UnknownClaimTypes []string `json:"unknown_claim_types,omitempty"`
	// DisclosuresPresent reports whether any claim carries selectively disclosable fields, an _sd set.
	DisclosuresPresent bool `json:"disclosures_present,omitempty"`
	// FieldsRevealed is how many redactable fields were disclosed and checked against their commitment.
	FieldsRevealed int `json:"fields_revealed,omitempty"`
	// FieldsRedacted is how many redactable fields were committed but withheld by the holder.
	FieldsRedacted int `json:"fields_redacted,omitempty"`
	// RevealedFields names the disclosed fields, so a reader sees what was shown without the values
	// having to be echoed into the report.
	RevealedFields []string `json:"revealed_fields,omitempty"`
	// AttestationsPresent reports whether any claim carries a counter-signature from a party other
	// than the producer.
	AttestationsPresent bool `json:"attestations_present,omitempty"`
	// AttestationsVerified is how many counter-signatures were checked and held.
	AttestationsVerified int `json:"attestations_verified,omitempty"`
	// HeadAttestationsPresent reports whether the bundle carries head-level counter-signatures.
	HeadAttestationsPresent bool `json:"head_attestations_present,omitempty"`
	// HeadAttestationsVerified is how many head-level counter-signatures held.
	HeadAttestationsVerified int `json:"head_attestations_verified,omitempty"`
	// HeadAttestors lists each verified head attestation as role and key, with its signed time
	// when carried.
	HeadAttestors []string `json:"head_attestors,omitempty"`
	// Attestors lists each verified counter-signer as its role and key fingerprint, so a reader can
	// decide whether the vouching party is worth trusting.
	Attestors []string `json:"attestors,omitempty"`
	// SpanPresent reports whether the bundle carries loomseal.span/1 population attestations.
	SpanPresent bool `json:"span_present"`
	// SpanOK reports whether every span check passed. Meaningful only when SpanPresent.
	SpanOK bool `json:"span_ok"`
	// SpanBeats is how many span claims the bundle carries.
	SpanBeats int `json:"span_beats,omitempty"`
	// SpanCountsVerified is how many span counts were recomputed from sequence numbers and held.
	SpanCountsVerified int `json:"span_counts_verified,omitempty"`
	// SpanCountsCarried is how many span counts could not be recomputed because the previous beat
	// sits outside the bundle's window. A carried count is reported, never trusted.
	SpanCountsCarried int `json:"span_counts_carried,omitempty"`
	// SpanCoverage words the population coverage, such as "2/4 windows attested".
	SpanCoverage string `json:"span_coverage,omitempty"`
	// SpanGaps describes each unattested window wider than the declared cadence.
	SpanGaps []string `json:"span_gaps,omitempty"`
	// SpanLongestGap is the widest unattested window between consecutive beats.
	SpanLongestGap string `json:"span_longest_gap,omitempty"`
	// Problems lists every failed check. Empty means verified.
	Problems []string `json:"problems,omitempty"`
}

// problem records one failed check.
func (r *Report) problem(format string, args ...any) {
	r.Problems = append(r.Problems, fmt.Sprintf(format, args...))
}

// Run verifies raw under the options and always returns a report; a bundle that cannot be
// parsed is a failed verification, not a crash.
func Run(raw []byte, opts Options) *Report {
	r := &Report{}
	b, err := bundle.Parse(raw)
	if err != nil {
		if errors.Is(err, bundle.ErrUnsupported) {
			r.Unsupported = true
			r.problem("%v", err)
			r.Level = "unsupported"
			return r
		}
		r.problem("parse: %v", err)
		r.Level = "not verified"
		return r
	}
	r.BundleID = b.BundleID
	r.Producer = b.Producer.Product + " " + b.Producer.ProductVersion
	r.Subject = b.Subject.Type + " " + b.Subject.ID

	r.checkSignature(raw, b, opts.Fingerprint)
	if !bundle.SubjectTypes[b.Subject.Type] {
		r.UnknownSubjectType = b.Subject.Type
	}
	r.checkClaimTypes(b)
	r.checkChain(raw, b)
	r.checkDisclosures(raw, b)
	r.checkAttestations(b)
	r.checkHeadAttestations(b)
	r.checkAnchors(b)
	r.checkSpan(b)
	r.checkEvidence(b, opts.EvidenceDir)

	r.OK = len(r.Problems) == 0
	r.Level = r.level()
	return r
}

// checkSignature verifies the producer key self-description, the signature over the
// canonical unsigned bundle, and the optional fingerprint pin.
func (r *Report) checkSignature(raw []byte, b *bundle.Bundle, pin string) {
	canonical, err := bundle.CanonicalUnsigned(raw)
	if err != nil {
		r.problem("canonicalize: %v", err)
		return
	}
	pub, err := base64.StdEncoding.DecodeString(b.Producer.PublicKey)
	if err != nil {
		r.problem("producer public_key: %v", err)
		return
	}
	r.KeyID = bundle.KeyID(pub)
	if r.KeyID != b.Producer.KeyID {
		r.problem("producer key_id does not match the embedded public key")
		return
	}
	// The producer block holds exactly one key, so every entry in signatures must name it. The
	// array sits outside the signed bytes, which is what lets the producer sign at all, and that
	// same fact means a foreign entry is a rider nothing vouches for: accepted, it would travel
	// inside a green verdict. Attestation is the defined path for counter-signatures.
	var sig *bundle.Signature
	for i := range b.Signatures {
		if b.Signatures[i].KeyID != b.Producer.KeyID {
			r.problem("signature %d names a key the producer block does not hold", i)
			return
		}
		if sig == nil {
			sig = &b.Signatures[i]
		}
	}
	if sig == nil {
		r.problem("no signature by the producer key")
		return
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sig.Sig)
	if err != nil {
		r.problem("signature: %v", err)
		return
	}
	if !ed25519.Verify(pub, canonical, sigBytes) {
		r.problem("signature does not verify over the canonical bundle")
		return
	}
	r.SignatureOK = true
	if pin != "" {
		match := r.KeyID == pin
		r.FingerprintMatch = &match
		if !match {
			r.problem("producer key %s does not match pinned fingerprint %s", r.KeyID, pin)
		}
	}
}

// checkClaimTypes records claim types outside the registry.
func (r *Report) checkClaimTypes(b *bundle.Bundle) {
	seen := map[string]bool{}
	for _, c := range b.Claims {
		if !knownClaimTypes[c.Type] && !seen[c.Type] {
			seen[c.Type] = true
			r.UnknownClaimTypes = append(r.UnknownClaimTypes, c.Type)
		}
	}
	sort.Strings(r.UnknownClaimTypes)
}

// checkChain verifies the declared chain when one is present.
func (r *Report) checkChain(raw []byte, b *bundle.Bundle) {
	if b.Chain == nil {
		return
	}
	r.ChainPresent = true
	r.ChainProfile = b.Chain.Profile
	res, err := chain.Verify(raw, b)
	if err != nil {
		r.problem("chain: %v", err)
		return
	}
	r.ChainOK = true
	r.ChainMode = res.Mode
	r.ClaimsChecked = res.Claims
	r.HeadMatched = res.HeadMatched
	// Zero under a linear profile, which carries no tree and no proofs, so these stay out of the
	// report rather than reading as an empty tree.
	r.TreeSize = res.TreeSize
	r.InclusionProofs = res.InclusionProofs
	r.ConsistencyFrom = res.ConsistencyFrom
	r.ConsistencyOK = res.ConsistencyOK
}

// checkAnchors matches every anchor's coordinates against the coordinates the verifier
// checked. A bundled claim always counts. The declared head counts only when it tied to the
// newest claim; a head beyond the claims is unverified, so an anchor that matches only it is
// reported separately and does not earn the anchored conformance word.
func (r *Report) checkAnchors(b *bundle.Bundle) {
	if len(b.Anchors) == 0 {
		return
	}
	if b.Chain == nil {
		r.problem("anchors present without a chain declaration")
		return
	}
	verified := map[int64]string{}
	// claimAt records when each anchored position says it happened, so an attestation can be held
	// against it. A timestamp authority signs a hash somebody hands it, and that hash cannot exist
	// before the entry it covers.
	claimAt := map[int64]time.Time{}
	for _, c := range b.Claims {
		if c.Chain != nil {
			verified[c.Chain.Seq] = c.Chain.Link
			if at, err := time.Parse(time.RFC3339, c.At); err == nil {
				claimAt[c.Chain.Seq] = at
			}
		}
	}
	if r.HeadMatched {
		verified[b.Chain.Head.Seq] = b.Chain.Head.Link
	}
	// A root a verified consistency proof starts from is a coordinate this verifier recomputed, so an
	// anchor over it matches. That pairing is the strongest statement the format makes about
	// truncation: the anchor fixed the root at a time the producer did not control, and the proof
	// shows the log there is now grew from exactly it, which refutes a loss rather than merely
	// failing to reach an anchor. Treating such an anchor as matching nothing would throw away the
	// best evidence a bundle can carry.
	if c := b.Chain.Consistency; c != nil && r.ConsistencyOK {
		verified[c.FromSize] = c.FromRoot
	}
	head := b.Chain.Head
	var newestAttestation time.Time
	for i, a := range b.Anchors {
		matched := false
		switch {
		case verified[a.Seq] == a.Link && a.Link != "":
			r.AnchorsMatched++
			matched = true
		case !r.HeadMatched && a.Seq == head.Seq && a.Link == head.Link:
			r.AnchorsToDeclaredHead++
			if a.Proof != "" {
				r.AnchorProofsOnDeclaredHead++
			}
		default:
			r.problem("anchor %d (%s) does not match any bundled claim or the declared head", i,
				a.Type)
		}
		// A proof is only opened when its anchor matched a coordinate this verifier confirmed. A proof
		// over a declared head that leads the claims attests a link tied to nothing in the bundle, so
		// verifying it would let an anchor on an unverified head reach "anchored (proof verified)",
		// which is the strongest word the format issues. It is reported separately and never counted.
		if !matched || a.Proof == "" {
			continue
		}
		r.AnchorProofsCarried++
		// A carried proof used to be counted and never opened, so a bundle holding a real signed
		// timestamp was reported at the same strength as one holding a URL. The format has always
		// said an rfc3161 proof is checkable offline; this is where that becomes true.
		if a.Type != "rfc3161" {
			continue
		}
		token, derr := base64.StdEncoding.DecodeString(a.Proof)
		if derr != nil {
			r.problem("anchor %d proof is not base64: %v", i, derr)
			continue
		}
		res, verr := rfc3161.Verify(token, a.Link)
		if verr != nil {
			r.problem("anchor %d proof does not verify: %v", i, verr)
			continue
		}
		// An attestation earlier than the entry it covers is not evidence, it is a contradiction.
		// The token commits to a link, and that link is the hash of a claim carrying its own time,
		// so an authority cannot honestly have signed it first. Without this a producer running
		// their own authority could sign any hash with any date and still reach the strongest
		// verdict the format issues.
		if at, ok := claimAt[a.Seq]; ok && res.Time.Before(at.Add(-anchorClockSkew)) {
			r.problem("anchor %d attests %s over entry %d, which the bundle says happened at %s: "+
				"a timestamp cannot precede the entry it covers", i,
				res.Time.UTC().Format(time.RFC3339), a.Seq, at.UTC().Format(time.RFC3339))
			continue
		}
		r.AnchorProofsVerified++
		if res.Time.After(newestAttestation) {
			newestAttestation = res.Time
		}
		r.AnchorAttestations = append(r.AnchorAttestations,
			res.Time.Format(time.RFC3339)+" by "+res.Signer)
	}
	// True only when every proof the bundle carries was opened and held. A bundle carrying a proof
	// this verifier cannot check must not be reported as validated.
	r.AnchorProofsValidated = r.AnchorProofsCarried > 0 &&
		r.AnchorProofsVerified == r.AnchorProofsCarried
	r.measureAttestationAge(b, newestAttestation)
	r.measureUnanchored(b, verified)
}

// anchorClockSkew is how far an authority's clock may sit behind the producer's before an
// attestation is read as predating the entry it covers. Both clocks are real and neither is
// authoritative over the other, so a small allowance keeps honest installs from being called liars.
const anchorClockSkew = 5 * time.Minute

// measureAttestationAge records how long the bundle sat between its newest verified attestation and
// the moment it was assembled.
func (r *Report) measureAttestationAge(b *bundle.Bundle, newest time.Time) {
	if newest.IsZero() {
		return
	}
	created, err := time.Parse(time.RFC3339, b.CreatedAt)
	if err != nil {
		return
	}
	if gap := created.Sub(newest); gap > 0 {
		r.AttestationAge = gap.Round(time.Second).String()
	}
}

// measureUnanchored records how far the anchors reach and what they leave uncovered. An anchor
// fixes history only up to the position it names, so the claims after the last anchored position
// are the ones a compromised producer key could still rewrite. Reporting the span turns a verdict
// that reads as a yes or no into one that says how much the yes is worth.
func (r *Report) measureUnanchored(b *bundle.Bundle, verified map[int64]string) {
	var through int64
	for _, a := range b.Anchors {
		if verified[a.Seq] == a.Link && a.Link != "" && a.Seq > through {
			through = a.Seq
		}
	}
	if through == 0 {
		return
	}
	r.AnchoredThroughSeq = through
	var anchoredAt, newestAt time.Time
	for _, c := range b.Claims {
		if c.Chain == nil {
			continue
		}
		at, err := time.Parse(time.RFC3339, c.At)
		if err != nil {
			continue
		}
		if c.Chain.Seq == through {
			anchoredAt = at
		}
		if c.Chain.Seq > through {
			r.UnanchoredClaims++
			if at.After(newestAt) {
				newestAt = at
			}
		}
	}
	if !anchoredAt.IsZero() && !newestAt.IsZero() && newestAt.After(anchoredAt) {
		r.UnanchoredWindow = newestAt.Sub(anchoredAt).Round(time.Second).String()
	}
}

// checkEvidence hashes every regular file under dir and compares the bundle's evidence
// digests against them. Without a directory every digest is referenced, not checked.
func (r *Report) checkEvidence(b *bundle.Bundle, dir string) {
	if dir == "" {
		for _, c := range b.Claims {
			r.EvidenceReferenced += len(c.Evidence)
		}
		return
	}
	supplied := map[string]bool{}
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		digest, err := hashFile(path)
		if err != nil {
			return err
		}
		supplied[digest] = true
		return nil
	})
	if err != nil {
		r.problem("evidence directory: %v", err)
		return
	}
	for _, c := range b.Claims {
		for _, e := range c.Evidence {
			if supplied[e.Digest] {
				r.EvidenceVerified++
			} else {
				r.EvidenceMissing++
			}
		}
	}
}

// hashFile streams a file into a SHA-256 hasher and returns its sha256: digest. Evidence artifacts
// are arbitrary user files, so the whole file is never held in memory at once.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// chainWording says what the chain verification established, in the terms the declared profile
// works in. A linear profile is worded by the mode it reached, because the question there is
// whether links were recomputed or only followed. A tree recomputes everything, so "full" would
// tell a reader nothing; what it established is membership in a log of a stated size, plus
// append-only growth when a consistency proof folded.
func (r *Report) chainWording() string {
	if r.ChainProfile != bundle.ProfileMerkle {
		return r.ChainMode
	}
	wording := fmt.Sprintf("tree of %d", r.TreeSize)
	if r.ConsistencyOK {
		wording += fmt.Sprintf(", append-only from %d", r.ConsistencyFrom)
	}
	return wording
}

// level words the conformance achieved.
func (r *Report) level() string {
	if !r.SignatureOK {
		return "not verified"
	}
	level := "signed"
	if r.ChainPresent && r.ChainOK {
		level += ", chained (" + r.chainWording() + ")"
	}
	anchored := r.AnchorProofsVerified > 0 || r.AnchorsMatched > 0
	switch {
	case r.AnchorProofsVerified > 0:
		// A proof checked here needed no network and no trust in the producer, which is a stronger
		// statement than a reference a relying party still has to go and confirm.
		level += ", anchored (proof verified)"
	case r.AnchorsMatched > 0:
		level += ", anchored by reference"
	}
	// Spanned sits above anchored: a population commitment is only worth the anchoring under it.
	if anchored && r.SpanPresent && r.SpanOK {
		level += ", spanned"
	}
	return level
}
