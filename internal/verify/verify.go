// Package verify runs the full LoomSeal verification procedure over one bundle and
// produces a report. Every failed check records a problem; a bundle is verified only when
// no problems remain. The package never contacts the network.
package verify

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"

	"github.com/kordloom/loomseal/internal/bundle"
	"github.com/kordloom/loomseal/internal/chain"
)

// knownClaimTypes is the registry of claim types this verifier understands. Unknown types
// are reported, never failed, so newer producers stay verifiable.
var knownClaimTypes = map[string]bool{
	"switchtender.audit/1": true,
	"switchtender.run/1":   true,
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
	// AnchorsMatched is how many anchors matched a coordinate the verifier checked: a bundled
	// claim, or the head when it tied to the newest claim.
	AnchorsMatched int `json:"anchors_matched"`
	// AnchorsToDeclaredHead is how many anchors matched only a declared head that lies beyond
	// the bundled claims. That head's link is unverified here, so such an anchor binds nothing
	// this verifier confirmed and does not earn the anchored conformance word.
	AnchorsToDeclaredHead int `json:"anchors_to_declared_head,omitempty"`
	// AnchorProofsCarried is how many anchors embed a proof blob.
	AnchorProofsCarried int `json:"anchor_proofs_carried"`
	// AnchorProofsValidated is false in this version: proofs are carried, not validated,
	// and the relying party confirms anchor refs out of band.
	AnchorProofsValidated bool `json:"anchor_proofs_validated"`
	// EvidenceVerified is how many evidence digests matched a supplied artifact.
	EvidenceVerified int `json:"evidence_verified"`
	// EvidenceMissing is how many digests had no artifact in the supplied directory.
	EvidenceMissing int `json:"evidence_missing"`
	// EvidenceReferenced is how many digests were not checked because no directory was
	// supplied.
	EvidenceReferenced int `json:"evidence_referenced"`
	// UnknownClaimTypes lists claim types outside this verifier's registry.
	UnknownClaimTypes []string `json:"unknown_claim_types,omitempty"`
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
		r.problem("parse: %v", err)
		r.Level = "not verified"
		return r
	}
	r.BundleID = b.BundleID
	r.Producer = b.Producer.Product + " " + b.Producer.ProductVersion
	r.Subject = b.Subject.Type + " " + b.Subject.ID

	r.checkSignature(raw, b, opts.Fingerprint)
	r.checkClaimTypes(b)
	r.checkChain(raw, b)
	r.checkAnchors(b)
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
	var sig *bundle.Signature
	for i := range b.Signatures {
		if b.Signatures[i].KeyID == b.Producer.KeyID {
			sig = &b.Signatures[i]
			break
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
	for _, c := range b.Claims {
		if c.Chain != nil {
			verified[c.Chain.Seq] = c.Chain.Link
		}
	}
	if r.HeadMatched {
		verified[b.Chain.Head.Seq] = b.Chain.Head.Link
	}
	head := b.Chain.Head
	for i, a := range b.Anchors {
		switch {
		case verified[a.Seq] == a.Link && a.Link != "":
			r.AnchorsMatched++
		case !r.HeadMatched && a.Seq == head.Seq && a.Link == head.Link:
			r.AnchorsToDeclaredHead++
		default:
			r.problem("anchor %d (%s) does not match any bundled claim or the declared head", i,
				a.Type)
		}
		if a.Proof != "" {
			r.AnchorProofsCarried++
		}
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
		content, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(content)
		supplied["sha256:"+hex.EncodeToString(sum[:])] = true
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

// level words the conformance achieved.
func (r *Report) level() string {
	if !r.SignatureOK {
		return "not verified"
	}
	level := "signed"
	if r.ChainPresent && r.ChainOK {
		level += ", chained (" + r.ChainMode + ")"
	}
	if r.AnchorsMatched > 0 {
		level += ", anchored by reference"
	}
	return level
}
