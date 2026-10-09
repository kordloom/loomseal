package verify

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"

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

// PresentationOptions carries the caller's expectations for a presentation. An empty field is no
// expectation, so a caller holding a value a user supplied runs it through CheckExpectation first,
// as the command line does for --audience and --nonce.
type PresentationOptions struct {
	// Audience, when set, requires the presentation to be addressed to it.
	Audience string
	// Nonce, when set, requires the presentation to echo it.
	Nonce string
	// Bundle carries the options for verifying the embedded bundle.
	Bundle Options
}

// CheckExpectation refuses an expected audience or nonce the caller supplied empty. A caller who
// passed one meant to compare, and an empty value read as no expectation would skip the comparison,
// which for the nonce is the whole replay defense. A caller with no expectation supplies none.
func CheckExpectation(expected string) error {
	if expected == "" {
		return ErrExpectation
	}
	return nil
}

// PresentationReport is the outcome of verifying a presentation.
type PresentationReport struct {
	// OK reports whether the presentation held, the bundle verified, and any pins matched.
	OK bool `json:"ok"`
	// PresentationOK reports whether the holder signature verified over the presented bundle.
	PresentationOK bool `json:"presentation_ok"`
	// Unsupported reports that the presentation declares a version this verifier does not
	// implement, so nothing in it was judged.
	Unsupported bool `json:"unsupported,omitempty"`
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

// Members a presentation and its holder carry, matched by exact name. A member outside them, a case
// variant of a known one included, is refused rather than folded onto the known one: every value
// the verdict reads is then the one a reader of the document sees, and the reference verifier,
// which reads members by exact name, reaches the same verdict on the same bytes.
var (
	// presentationMembers are the members of a presentation.
	presentationMembers = []string{"audience", "bundle", "created_at", "holder",
		"loomseal_presentation", "nonce", "sig"}
	// holderMembers are the members of a presentation's holder.
	holderMembers = []string{"alg", "key_id", "public_key"}
)

// LooksLikePresentation reports whether raw is a presentation rather than a bundle: a JSON
// document, read as a bundle is read, whose object carries the presentation version member under
// its exact name with a string value, an empty one included. It lets one command accept either
// document, and every document it routes to the presentation checks is one they read a version
// from.
func LooksLikePresentation(raw []byte) bool {
	if bundle.CheckDepth(raw, bundle.MaxDepth) != nil {
		return false
	}
	tree, err := jcs.Parse(raw)
	if err != nil {
		return false
	}
	obj, _ := tree.(map[string]any)
	_, ok := obj["loomseal_presentation"].(string)
	return ok
}

// readPresentation reads a presentation in the order FORMAT.md's "Presentations" section gives, the
// order a bundle is read in: the document as JSON within the nesting bound, then its version, then
// the number profile, then every member by its exact name and type. A version other than 0.1 is
// unsupported whatever else the document carries. The presented bundle is carried forward as its
// canonical bytes, which are what the holder signature covers and what the bundle's own signature
// is checked over.
func readPresentation(raw []byte) (Presentation, error) {
	if err := bundle.CheckDepth(raw, bundle.MaxDepth); err != nil {
		return Presentation{}, err
	}
	tree, err := jcs.Parse(raw)
	if err != nil {
		return Presentation{}, err
	}
	obj, ok := tree.(map[string]any)
	if !ok {
		return Presentation{}, fmt.Errorf("a presentation is a JSON object")
	}
	if err := checkPresentationVersion(obj); err != nil {
		return Presentation{}, err
	}
	if err := jcs.CheckNumbers(tree); err != nil {
		return Presentation{}, err
	}
	if name, found := unknownMember(obj, presentationMembers); found {
		return Presentation{}, fmt.Errorf("presentation carries an unknown member %q", name)
	}
	holder := map[string]any{}
	if h, present := obj["holder"]; present {
		if holder, ok = h.(map[string]any); !ok {
			return Presentation{}, fmt.Errorf("presentation holder is not an object")
		}
		if name, found := unknownMember(holder, holderMembers); found {
			return Presentation{}, fmt.Errorf("presentation holder carries an unknown member %q", name)
		}
	}
	var p Presentation
	for _, f := range []struct {
		// from is the object holding the member.
		from map[string]any
		// name is the member's exact name.
		name string
		// into is the field the member's text is read into.
		into *string
	}{
		{obj, "loomseal_presentation", &p.Version}, {obj, "created_at", &p.CreatedAt},
		{obj, "audience", &p.Audience}, {obj, "nonce", &p.Nonce}, {obj, "sig", &p.Sig},
		{holder, "key_id", &p.Holder.KeyID}, {holder, "public_key", &p.Holder.PublicKey},
		{holder, "alg", &p.Holder.Alg},
	} {
		v, present := f.from[f.name]
		if !present {
			continue
		}
		text, ok := v.(string)
		if !ok {
			return Presentation{}, fmt.Errorf("presentation member %s is not a string", f.name)
		}
		*f.into = text
	}
	b, present := obj["bundle"]
	if !present {
		return Presentation{}, fmt.Errorf("presentation carries no bundle member")
	}
	if p.Bundle, err = jcs.Serialize(b); err != nil {
		return Presentation{}, fmt.Errorf("presentation bundle: %w", err)
	}
	return p, nil
}

// checkPresentationVersion reads the loomseal_presentation member of a parsed presentation, as the
// bundle package reads a bundle's loomseal member. A document without it, or with a value that is
// not a string, declares no presentation version and is refused at parse. A string other than
// PresentationVersion is unsupported, and nothing else in the document is judged.
func checkPresentationVersion(obj map[string]any) error {
	v, present := obj["loomseal_presentation"]
	if !present {
		return fmt.Errorf("presentation carries no loomseal_presentation member, so it declares " +
			"no format version")
	}
	version, ok := v.(string)
	if !ok {
		return fmt.Errorf("presentation member loomseal_presentation is not a string")
	}
	if version != PresentationVersion {
		return fmt.Errorf("%w: loomseal_presentation version %q, this verifier implements %q",
			ErrUnsupportedPresentation, version, PresentationVersion)
	}
	return nil
}

// unknownMember returns the lowest-named member of obj outside allowed, so a refusal names the same
// member on every run.
func unknownMember(obj map[string]any, allowed []string) (string, bool) {
	var extra []string
	for name := range obj {
		if !slices.Contains(allowed, name) {
			extra = append(extra, name)
		}
	}
	if len(extra) == 0 {
		return "", false
	}
	sort.Strings(extra)
	return extra[0], true
}

// RunPresentation verifies raw as a presentation and always returns a report; a document that cannot
// be parsed is a failed verification, not a crash. The checks run in the order FORMAT.md gives:
// the presentation is read, the embedded bundle is verified, then the holder signature, then each
// expectation the caller supplied. Each problem is named by the check that found it, as the
// reference verifier names it.
func RunPresentation(raw []byte, opts PresentationOptions) *PresentationReport {
	r := &PresentationReport{}
	p, err := readPresentation(raw)
	if err != nil {
		if errors.Is(err, ErrUnsupportedPresentation) {
			r.Unsupported = true
			r.problem("%v", err)
			return r
		}
		r.problem("parse: %v", err)
		return r
	}
	r.Audience, r.Nonce, r.CreatedAt = p.Audience, p.Nonce, p.CreatedAt

	// Verify the embedded bundle on its own terms first.
	r.Bundle = Run(p.Bundle, opts.Bundle)

	// The holder signature binds the exact presented bundle, the verifier, the challenge, and the
	// time, so a presentation cannot be replayed to another verifier or with a stale challenge.
	if err := r.checkHolderSignature(p); err != nil {
		r.problem("presentation: %v", err)
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
// binding. The presented bundle is already in canonical form, as readPresentation serialized it.
func (r *PresentationReport) checkHolderSignature(p Presentation) error {
	if p.Holder.Alg != "ed25519" {
		return fmt.Errorf("holder alg %q, want ed25519", p.Holder.Alg)
	}
	pub, err := bundle.DecodeBase64(p.Holder.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return fmt.Errorf("holder public_key is not a 32 byte ed25519 key")
	}
	r.HolderKeyID = bundle.KeyID(pub)
	if r.HolderKeyID != p.Holder.KeyID {
		return fmt.Errorf("holder key_id does not match the embedded public key")
	}
	if _, err := bundle.ParseTime(p.CreatedAt); err != nil {
		return fmt.Errorf("created_at: %v", err)
	}
	sig, err := bundle.DecodeBase64(p.Sig)
	if err != nil {
		return fmt.Errorf("holder signature is not base64: %v", err)
	}
	preimage, err := bundle.PresentationSigningInput(p.Audience, p.Nonce, p.CreatedAt, p.Bundle)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, preimage, sig) {
		return fmt.Errorf("holder signature does not verify over the presented bundle")
	}
	r.PresentationOK = true
	return nil
}
