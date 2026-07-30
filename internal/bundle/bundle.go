// Package bundle defines the LoomSeal bundle document, its strict parser, and the
// canonical-unsigned transform signatures are computed over. The rules here mirror the
// published JSON schema; a document that fails them is not a LoomSeal bundle.
package bundle

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/kordloom/loomseal/internal/jcs"
)

// Version is the only bundle format version this verifier speaks.
const Version = "0.1"

// Chain profile names fixed by the spec.
const (
	// ProfileSwitchTender is the shipped SwitchTender unkeyed audit chain construction.
	ProfileSwitchTender = "switchtender-audit-v1"
	// ProfileV1 is the generic construction new producers use.
	ProfileV1 = "loomseal-chain-v1"
)

// Bundle is one portable proof document.
type Bundle struct {
	// Version is the format version, always "0.1".
	Version string `json:"loomseal"`
	// BundleID is the producer-assigned identifier for this bundle.
	BundleID string `json:"bundle_id"`
	// CreatedAt is the RFC 3339 UTC time the bundle was assembled.
	CreatedAt string `json:"created_at"`
	// Producer identifies who emitted the bundle and with which key.
	Producer Producer `json:"producer"`
	// Subject is what the claims are about.
	Subject Subject `json:"subject"`
	// Chain declares the chain profile and head when the bundle is chained.
	Chain *Chain `json:"chain,omitempty"`
	// Claims are the attested records, oldest first.
	Claims []Claim `json:"claims"`
	// Anchors are external anchor records binding chain links outside the producer.
	Anchors []Anchor `json:"anchors,omitempty"`
	// Signatures are producer signatures over the canonical unsigned bundle.
	Signatures []Signature `json:"signatures"`
}

// Producer identifies the emitting product installation and its signing key.
type Producer struct {
	// Product is the emitting product name, such as switchtender.
	Product string `json:"product"`
	// ProductVersion is the emitting product's version.
	ProductVersion string `json:"product_version"`
	// InstallID is the producing installation's identifier.
	InstallID string `json:"install_id"`
	// PublicKey is the raw 32-byte ed25519 public key, base64 standard encoding.
	PublicKey string `json:"public_key"`
	// KeyID is sha256: over the raw public key bytes.
	KeyID string `json:"key_id"`
}

// Subject is the thing the claims describe.
type Subject struct {
	// Type is the subject kind: url, fleet, or repo.
	Type string `json:"type"`
	// ID names the subject, such as the watched URL.
	ID string `json:"id"`
}

// Chain declares how claims are linked.
type Chain struct {
	// Profile names the link construction, one of the spec's chain profiles.
	Profile string `json:"profile"`
	// Keyed reports whether links are HMACs a third party cannot recompute.
	Keyed bool `json:"keyed"`
	// Params carries profile parameters such as install_id.
	Params map[string]string `json:"params,omitempty"`
	// Head is the newest chain coordinates the producer attests.
	Head Coords `json:"head"`
}

// Coords fixes an entry's position and link in the chain.
type Coords struct {
	// Seq is the 1-based position in the chain.
	Seq int64 `json:"seq"`
	// Prev is the previous entry's link, empty for the first entry.
	Prev string `json:"prev,omitempty"`
	// Link is this entry's link value, lowercase hex.
	Link string `json:"link"`
}

// Claim is one attested record.
type Claim struct {
	// Type is the namespaced claim type, such as switchtender.audit/1.
	Type string `json:"type"`
	// At is the RFC 3339 time the claimed event happened.
	At string `json:"at"`
	// Payload is the type-specific claim body, owned by the emitting product.
	Payload json.RawMessage `json:"payload"`
	// Evidence lists digests of the artifacts behind the claim.
	Evidence []Evidence `json:"evidence,omitempty"`
	// Verdict is the deterministic policy judgment recorded at detection time.
	Verdict *Verdict `json:"verdict,omitempty"`
	// Chain is this claim's position in the declared chain.
	Chain *Coords `json:"chain,omitempty"`
}

// Evidence references one artifact by content digest.
type Evidence struct {
	// Role says what the artifact is to the claim, such as snapshot.
	Role string `json:"role"`
	// Digest is sha256: over the artifact bytes.
	Digest string `json:"digest"`
	// MediaType is the artifact's media type when known.
	MediaType string `json:"media_type,omitempty"`
	// Present reports whether the artifact travels beside the bundle.
	Present bool `json:"present,omitempty"`
	// Location hints where a traveling artifact sits relative to the bundle.
	Location string `json:"location,omitempty"`
}

// Verdict is a recorded policy decision.
type Verdict struct {
	// Policy names the policy and version that judged the claim.
	Policy string `json:"policy"`
	// PolicyDigest is sha256: over the policy definition.
	PolicyDigest string `json:"policy_digest,omitempty"`
	// InputsDigest is sha256: over the judgment inputs.
	InputsDigest string `json:"inputs_digest,omitempty"`
	// Decision is the policy outcome, such as pass or notify.
	Decision string `json:"decision"`
	// Detail is the human-readable judgment detail.
	Detail string `json:"detail,omitempty"`
}

// Anchor records one external anchoring of a chain link.
type Anchor struct {
	// Type is the anchor kind: rfc3161, git, https, or rekor.
	Type string `json:"type"`
	// Seq is the anchored entry's chain position.
	Seq int64 `json:"seq"`
	// Link is the anchored link value.
	Link string `json:"link"`
	// At is when the anchor was placed.
	At string `json:"at"`
	// Ref locates the anchor, such as a commit URL or timestamp authority.
	Ref string `json:"ref"`
	// Proof is an embedded proof blob, base64, currently an RFC 3161 token.
	Proof string `json:"proof,omitempty"`
}

// Signature is one producer signature.
type Signature struct {
	// KeyID is sha256: over the raw public key that made the signature.
	KeyID string `json:"key_id"`
	// Alg is the signature algorithm, always ed25519.
	Alg string `json:"alg"`
	// Sig is the base64 ed25519 signature over the canonical unsigned bundle.
	Sig string `json:"sig"`
}

// Validation patterns for digests, links, and claim types.
var (
	reDigest    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	reLink      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	reClaimType = regexp.MustCompile(`^[a-z][a-z0-9_-]*\.[a-z][a-z0-9_-]*/[0-9]+$`)
)

// Allowed enum values from the schema.
var (
	subjectTypes = map[string]bool{"url": true, "fleet": true, "repo": true}
	profiles     = map[string]bool{ProfileSwitchTender: true, ProfileV1: true}
	anchorTypes  = map[string]bool{"rfc3161": true, "git": true, "https": true, "rekor": true}
)

// Parse decodes raw strictly, rejecting unknown fields and trailing data, then validates
// the structural rules the schema fixes.
func Parse(raw []byte) (*Bundle, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var b Bundle
	if err := dec.Decode(&b); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParse, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing data after bundle", ErrParse)
	}
	if err := b.validate(); err != nil {
		return nil, err
	}
	return &b, nil
}

// validate enforces the schema's structural rules.
func (b *Bundle) validate() error {
	if b.Version != Version {
		return fmt.Errorf("%w: loomseal version %q, want %q", ErrSchema, b.Version, Version)
	}
	if b.BundleID == "" {
		return fmt.Errorf("%w: bundle_id is empty", ErrSchema)
	}
	if err := checkTime("created_at", b.CreatedAt); err != nil {
		return err
	}
	if err := b.Producer.validate(); err != nil {
		return err
	}
	if !subjectTypes[b.Subject.Type] {
		return fmt.Errorf("%w: subject type %q", ErrSchema, b.Subject.Type)
	}
	if b.Subject.ID == "" {
		return fmt.Errorf("%w: subject id is empty", ErrSchema)
	}
	if b.Chain != nil {
		if err := b.Chain.validate(); err != nil {
			return err
		}
	}
	if len(b.Claims) == 0 {
		return fmt.Errorf("%w: bundle has no claims", ErrSchema)
	}
	for i := range b.Claims {
		if err := b.Claims[i].validate(i); err != nil {
			return err
		}
	}
	for i, a := range b.Anchors {
		if err := a.validate(i); err != nil {
			return err
		}
	}
	if len(b.Signatures) == 0 {
		return fmt.Errorf("%w: bundle has no signatures", ErrSchema)
	}
	for i, s := range b.Signatures {
		if err := s.validate(i); err != nil {
			return err
		}
	}
	return nil
}

// validate enforces producer rules, including the key encoding.
func (p Producer) validate() error {
	if p.Product == "" || p.ProductVersion == "" || p.InstallID == "" {
		return fmt.Errorf("%w: producer fields are incomplete", ErrSchema)
	}
	key, err := base64.StdEncoding.DecodeString(p.PublicKey)
	if err != nil {
		return fmt.Errorf("%w: producer public_key is not base64: %w", ErrSchema, err)
	}
	if len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: producer public_key is %d bytes, want %d", ErrSchema, len(key),
			ed25519.PublicKeySize)
	}
	if !reDigest.MatchString(p.KeyID) {
		return fmt.Errorf("%w: producer key_id %q is not a sha256 digest", ErrSchema, p.KeyID)
	}
	return nil
}

// validate enforces chain declaration rules.
func (c Chain) validate() error {
	if !profiles[c.Profile] {
		return fmt.Errorf("%w: unknown chain profile %q", ErrSchema, c.Profile)
	}
	return c.Head.validate("chain head")
}

// validate enforces coordinate rules.
func (c Coords) validate(what string) error {
	if c.Seq < 1 {
		return fmt.Errorf("%w: %s seq %d, want at least 1", ErrSchema, what, c.Seq)
	}
	if !reLink.MatchString(c.Link) {
		return fmt.Errorf("%w: %s link is not 64 hex characters", ErrSchema, what)
	}
	if c.Prev != "" && !reLink.MatchString(c.Prev) {
		return fmt.Errorf("%w: %s prev is not empty or 64 hex characters", ErrSchema, what)
	}
	return nil
}

// validate enforces claim rules.
func (c Claim) validate(i int) error {
	if !reClaimType.MatchString(c.Type) {
		return fmt.Errorf("%w: claim %d type %q", ErrSchema, i, c.Type)
	}
	if err := checkTime(fmt.Sprintf("claim %d at", i), c.At); err != nil {
		return err
	}
	trimmed := bytes.TrimSpace(c.Payload)
	if len(trimmed) == 0 || trimmed[0] != '{' || !json.Valid(trimmed) {
		return fmt.Errorf("%w: claim %d payload is not a JSON object", ErrSchema, i)
	}
	for j, e := range c.Evidence {
		if e.Role == "" {
			return fmt.Errorf("%w: claim %d evidence %d role is empty", ErrSchema, i, j)
		}
		if !reDigest.MatchString(e.Digest) {
			return fmt.Errorf("%w: claim %d evidence %d digest", ErrSchema, i, j)
		}
	}
	if c.Verdict != nil {
		if c.Verdict.Policy == "" || c.Verdict.Decision == "" {
			return fmt.Errorf("%w: claim %d verdict is incomplete", ErrSchema, i)
		}
	}
	if c.Chain != nil {
		return c.Chain.validate(fmt.Sprintf("claim %d chain", i))
	}
	return nil
}

// validate enforces anchor rules.
func (a Anchor) validate(i int) error {
	if !anchorTypes[a.Type] {
		return fmt.Errorf("%w: anchor %d type %q", ErrSchema, i, a.Type)
	}
	if a.Seq < 1 {
		return fmt.Errorf("%w: anchor %d seq %d", ErrSchema, i, a.Seq)
	}
	if !reLink.MatchString(a.Link) {
		return fmt.Errorf("%w: anchor %d link", ErrSchema, i)
	}
	if a.Ref == "" {
		return fmt.Errorf("%w: anchor %d ref is empty", ErrSchema, i)
	}
	if a.Proof != "" {
		if _, err := base64.StdEncoding.DecodeString(a.Proof); err != nil {
			return fmt.Errorf("%w: anchor %d proof is not base64: %w", ErrSchema, i, err)
		}
	}
	return checkTime(fmt.Sprintf("anchor %d at", i), a.At)
}

// validate enforces signature rules.
func (s Signature) validate(i int) error {
	if !reDigest.MatchString(s.KeyID) {
		return fmt.Errorf("%w: signature %d key_id", ErrSchema, i)
	}
	if s.Alg != "ed25519" {
		return fmt.Errorf("%w: signature %d alg %q, want ed25519", ErrSchema, i, s.Alg)
	}
	sig, err := base64.StdEncoding.DecodeString(s.Sig)
	if err != nil {
		return fmt.Errorf("%w: signature %d sig is not base64: %w", ErrSchema, i, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature %d sig is %d bytes, want %d", ErrSchema, i, len(sig),
			ed25519.SignatureSize)
	}
	return nil
}

// checkTime requires an RFC 3339 timestamp.
func checkTime(what, s string) error {
	if _, err := time.Parse(time.RFC3339, s); err != nil {
		return fmt.Errorf("%w: %s: %w", ErrSchema, what, err)
	}
	return nil
}

// CanonicalUnsigned returns the RFC 8785 canonical form of raw with signatures set to the
// empty array. Signatures are computed and verified over exactly these bytes.
func CanonicalUnsigned(raw []byte) ([]byte, error) {
	v, err := jcs.Parse(raw)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: bundle is not a JSON object", ErrParse)
	}
	m["signatures"] = []any{}
	return jcs.Serialize(m)
}

// KeyID returns the sha256: fingerprint of a raw ed25519 public key.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(sum[:])
}
