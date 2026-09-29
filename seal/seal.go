// Package seal builds and signs LoomSeal bundles. Producers import it to emit the format;
// the verifier does not depend on it, so verification never requires this code.
package seal

import (
	"crypto/ed25519"
	"encoding/base64"
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

// SignBundle signs an unsigned or previously signed bundle document with priv and returns
// the canonical signed bundle. Any existing signatures are replaced. The producer fields
// must already carry the matching public key; SignBundle does not edit them.
func SignBundle(raw []byte, priv ed25519.PrivateKey) ([]byte, error) {
	v, err := jcs.Parse(raw)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: bundle is not a JSON object", ErrBundle)
	}
	m["signatures"] = []any{}
	canonical, err := jcs.Serialize(m)
	if err != nil {
		return nil, err
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: private key has no ed25519 public key", ErrBundle)
	}
	sig := ed25519.Sign(priv, canonical)
	m["signatures"] = []any{map[string]any{
		"key_id": bundle.KeyID(pub),
		"alg":    "ed25519",
		"sig":    base64.StdEncoding.EncodeToString(sig),
	}}
	return jcs.Serialize(m)
}

// LinkV1 computes a loomseal-chain-v1 link. The claim value must not carry a chain member;
// pass the claim as a Go value tree or any JSON-serializable map. With a key the link is
// an HMAC-SHA256 only the key holder can extend; with a nil key it is a plain SHA-256
// anyone can recompute.
func LinkV1(key []byte, installID string, seq int64, prev string, claim any) (string, error) {
	return chain.LinkV1(key, installID, seq, prev, claim)
}
