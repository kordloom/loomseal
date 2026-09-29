package verify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/kordloom/loomseal/internal/bundle"
	"github.com/kordloom/loomseal/jcs"
)

// PresentationVersion is the only presentation format version this verifier speaks.
const PresentationVersion = "0.1"

// Presentation is a holder's wrapper around a bundle, binding the bundle it presents to one verifier
// and one challenge so it cannot be replayed elsewhere. The holder signs it with a key the holder
// controls; how that key maps to a real-world identity is a trust-establishment concern outside this
// format.
type Presentation struct {
	// Version is the presentation format version, always "0.1".
	Version string `json:"loomseal_presentation"`
	// CreatedAt is the RFC 3339 UTC time the holder assembled the presentation.
	CreatedAt string `json:"created_at"`
	// Audience identifies the verifier the holder is presenting to.
	Audience string `json:"audience"`
	// Nonce is the challenge the verifier issued, echoed here so a presentation cannot be replayed.
	Nonce string `json:"nonce"`
	// Holder describes the key that signed this presentation.
	Holder PresentationHolder `json:"holder"`
	// Bundle is the presented bundle, exactly as the holder chose to disclose it.
	Bundle json.RawMessage `json:"bundle"`
	// Sig is the base64 ed25519 holder signature over the canonical binding of audience, bundle
	// digest, created_at, and nonce.
	Sig string `json:"sig"`
}

// PresentationHolder is the key that signed a presentation.
type PresentationHolder struct {
	// KeyID is sha256: over the raw public key.
	KeyID string `json:"key_id"`
	// PublicKey is the raw 32-byte ed25519 public key, base64 standard encoding.
	PublicKey string `json:"public_key"`
	// Alg is the signature algorithm, always ed25519.
	Alg string `json:"alg"`
}

// PresentationOptions carries the caller's expectations for a presentation.
type PresentationOptions struct {
	// Audience, when set, requires the presentation to be addressed to it.
	Audience string
	// Nonce, when set, requires the presentation to echo it.
	Nonce string
	// Bundle carries the options for verifying the embedded bundle.
	Bundle Options
}

// PresentationReport is the outcome of verifying a presentation.
type PresentationReport struct {
	// OK reports whether the presentation held, the bundle verified, and any pins matched.
	OK bool `json:"ok"`
	// PresentationOK reports whether the holder signature verified over the presented bundle.
	PresentationOK bool `json:"presentation_ok"`
	// HolderKeyID is the holder key fingerprint computed from the embedded public key.
	HolderKeyID string `json:"holder_key_id,omitempty"`
	// Audience echoes who the presentation was addressed to.
	Audience string `json:"audience,omitempty"`
	// Nonce echoes the challenge the presentation carried.
	Nonce string `json:"nonce,omitempty"`
	// CreatedAt echoes when the presentation was assembled.
	CreatedAt string `json:"created_at,omitempty"`
	// AudienceMatch reports the audience comparison when an expected audience was supplied.
	AudienceMatch *bool `json:"audience_match,omitempty"`
	// NonceMatch reports the nonce comparison when an expected nonce was supplied.
	NonceMatch *bool `json:"nonce_match,omitempty"`
	// Bundle is the verdict on the embedded bundle.
	Bundle *Report `json:"bundle,omitempty"`
	// Problems lists every failed check. Empty means the presentation held.
	Problems []string `json:"problems,omitempty"`
}

// problem records one failed presentation check.
func (p *PresentationReport) problem(format string, args ...any) {
	p.Problems = append(p.Problems, fmt.Sprintf(format, args...))
}

// LooksLikePresentation reports whether raw is a presentation rather than a bundle, by the presence
// of the presentation version member. It lets one command accept either document.
func LooksLikePresentation(raw []byte) bool {
	var probe struct {
		Version string `json:"loomseal_presentation"`
	}
	return json.Unmarshal(raw, &probe) == nil && probe.Version != ""
}

// RunPresentation verifies raw as a presentation and always returns a report; a document that cannot
// be parsed is a failed verification, not a crash.
func RunPresentation(raw []byte, opts PresentationOptions) *PresentationReport {
	r := &PresentationReport{}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var p Presentation
	if err := dec.Decode(&p); err != nil {
		r.problem("parse: %v", err)
		return r
	}
	if _, err := dec.Token(); !errorsIsEOF(err) {
		r.problem("parse: trailing data after presentation")
		return r
	}
	if p.Version != PresentationVersion {
		r.problem("presentation version %q, want %q", p.Version, PresentationVersion)
		return r
	}
	r.Audience, r.Nonce, r.CreatedAt = p.Audience, p.Nonce, p.CreatedAt

	// Verify the embedded bundle on its own terms first.
	r.Bundle = Run(p.Bundle, opts.Bundle)

	// The holder signature binds the exact presented bundle, the verifier, the challenge, and the
	// time, so a presentation cannot be replayed to another verifier or with a stale challenge.
	bundleCanon, err := jcs.Canonicalize(p.Bundle)
	if err != nil {
		r.problem("canonicalize bundle: %v", err)
	} else if err := r.checkHolderSignature(p, bundleCanon); err != nil {
		r.problem("%v", err)
	}

	if opts.Audience != "" {
		match := p.Audience == opts.Audience
		r.AudienceMatch = &match
		if !match {
			r.problem("presentation audience %q does not match the expected %q", p.Audience,
				opts.Audience)
		}
	}
	if opts.Nonce != "" {
		match := p.Nonce == opts.Nonce
		r.NonceMatch = &match
		if !match {
			r.problem("presentation nonce does not match the expected challenge")
		}
	}

	r.OK = len(r.Problems) == 0 && r.PresentationOK && r.Bundle != nil && r.Bundle.OK
	return r
}

// checkHolderSignature verifies the holder key self-description and the signature over the canonical
// binding.
func (r *PresentationReport) checkHolderSignature(p Presentation, bundleCanon []byte) error {
	if p.Holder.Alg != "ed25519" {
		return fmt.Errorf("holder alg %q, want ed25519", p.Holder.Alg)
	}
	pub, err := base64.StdEncoding.DecodeString(p.Holder.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("holder public_key is not a 32 byte ed25519 key")
	}
	r.HolderKeyID = bundle.KeyID(pub)
	if r.HolderKeyID != p.Holder.KeyID {
		return fmt.Errorf("holder key_id does not match the embedded public key")
	}
	if _, err := time.Parse(time.RFC3339, p.CreatedAt); err != nil {
		return fmt.Errorf("presentation created_at: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(p.Sig)
	if err != nil {
		return fmt.Errorf("holder signature is not base64: %v", err)
	}
	preimage, err := bundle.PresentationSigningInput(p.Audience, p.Nonce, p.CreatedAt, bundleCanon)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, preimage, sig) {
		return fmt.Errorf("holder signature does not verify over the presented bundle")
	}
	r.PresentationOK = true
	return nil
}

// errorsIsEOF reports whether err is io.EOF, kept local so this file needs no extra import churn.
func errorsIsEOF(err error) bool { return err == io.EOF }
