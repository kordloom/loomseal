// Package seal builds and signs LoomSeal bundles. Producers import it to emit the format;
// the verifier does not depend on it, so verification never requires this code.
package seal

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/kordloom/loomseal/internal/bundle"
	"github.com/kordloom/loomseal/internal/chain"
	"github.com/kordloom/loomseal/jcs"
)

// KeyID returns the sha256: fingerprint of a raw ed25519 public key, the value that goes
// in producer.key_id and on the operator's trust page.
func KeyID(pub ed25519.PublicKey) string {
	return bundle.KeyID(pub)
}

// SignBundle signs an unsigned or previously signed bundle document with signer and returns
// the canonical signed bundle. Any existing signatures are replaced. The producer fields
// must already carry the matching public key; SignBundle does not edit them.
//
// The signer must hold an ed25519 key, which is the only algorithm format 1.0 fixes, but it may
// live anywhere crypto.Signer reaches: an in-memory ed25519.PrivateKey works unchanged, and a
// KMS- or HSM-backed signer works without the key ever leaving its module.
func SignBundle(raw []byte, signer crypto.Signer) ([]byte, error) {
	v, err := jcs.Parse(raw)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: bundle is not a JSON object", ErrBundle)
	}
	// Sign over the canonical unsigned form, which drops signatures and holder-controlled
	// disclosures, then re-attach the signature to the full tree so the output still carries any
	// disclosures the producer emitted. A holder may later withhold them without breaking this.
	canonical, err := bundle.CanonicalUnsigned(raw)
	if err != nil {
		return nil, err
	}
	pub, ok := signer.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: signer has no ed25519 public key", ErrBundle)
	}
	sig, err := signer.Sign(rand.Reader, canonical, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("%w: sign: %w", ErrBundle, err)
	}
	m["signatures"] = []any{map[string]any{
		"key_id": bundle.KeyID(pub),
		"alg":    "ed25519",
		"sig":    base64.StdEncoding.EncodeToString(sig),
	}}
	return jcs.Serialize(m)
}

// Present wraps a bundle in a presentation bound to a verifier and a challenge, signed by the holder
// key. The bundle is embedded exactly as given, so a holder that has reduced a claim's disclosures to
// a chosen subset presents only those. The holder signature binds the audience, the presented
// bundle's digest, the time, and the nonce, so the presentation cannot be replayed to another
// verifier or with a stale challenge. createdAt is RFC 3339 UTC.
func Present(bundleRaw []byte, holder crypto.Signer, audience, nonce, createdAt string) ([]byte, error) {
	canonical, err := jcs.Canonicalize(bundleRaw)
	if err != nil {
		return nil, err
	}
	preimage, err := bundle.PresentationSigningInput(audience, nonce, createdAt, canonical)
	if err != nil {
		return nil, err
	}
	pub, ok := holder.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: holder signer has no ed25519 public key", ErrBundle)
	}
	sig, err := holder.Sign(rand.Reader, preimage, crypto.Hash(0))
	if err != nil {
		return nil, fmt.Errorf("%w: holder sign: %w", ErrBundle, err)
	}
	m := map[string]any{
		"loomseal_presentation": "0.1",
		"created_at":            createdAt,
		"audience":              audience,
		"nonce":                 nonce,
		"holder": map[string]any{
			"key_id":     bundle.KeyID(pub),
			"public_key": base64.StdEncoding.EncodeToString(pub),
			"alg":        "ed25519",
		},
		"bundle": json.RawMessage(bundleRaw),
		"sig":    base64.StdEncoding.EncodeToString(sig),
	}
	return json.Marshal(m)
}

// LinkV1 computes a loomseal-chain-v1 link. The claim value must not carry a chain member;
// pass the claim as a Go value tree or any JSON-serializable map. With a key the link is
// an HMAC-SHA256 only the key holder can extend; with a nil key it is a plain SHA-256
// anyone can recompute.
func LinkV1(key []byte, installID string, seq int64, prev string, claim any) (string, error) {
	return chain.LinkV1(key, installID, seq, prev, claim)
}

// ClaimContent returns the members of a claim a link or leaf commits to: the one committed-content
// rule both hashing profiles share. Producers and mirror verifiers use it so their commitments can
// never drift from the reference by reimplementing the strip list.
func ClaimContent(claim map[string]any) map[string]any {
	return chain.ClaimContent(claim)
}
