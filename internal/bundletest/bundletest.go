// Package bundletest builds signed LoomSeal bundles for tests. It exists so integration
// tests construct real documents through the same seal primitives a producer uses, rather
// than each test hand-rolling its own bundle and drifting from the format. Every knob is a
// plain field, so a new edge case is a new field value rather than a new builder.
//
// Keys are deterministic from a single seed byte, so two builders with different seeds
// model two different parties and a test can name "the producer's key" and "a stranger's
// key" without ceremony.
package bundletest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/kordloom/loomseal/jcs"
	"github.com/kordloom/loomseal/seal"
)

// At is the fixed claim and bundle time every built document carries. Fixed rather than
// now, because a test document should be byte-stable across runs.
const At = "2026-09-19T12:00:00Z"

// Key returns the deterministic ed25519 key pair derived from one seed byte.
func Key(seed byte) (ed25519.PrivateKey, ed25519.PublicKey) {
	s := make([]byte, ed25519.SeedSize)
	for i := range s {
		s[i] = seed
	}
	priv := ed25519.NewKeyFromSeed(s)
	return priv, priv.Public().(ed25519.PublicKey)
}

// KeyID returns the sha256: fingerprint of the key derived from one seed byte.
func KeyID(seed byte) string {
	_, pub := Key(seed)
	return seal.KeyID(pub)
}

// Claim is one claim a Builder will chain and sign.
type Claim struct {
	// Type is the namespaced claim type, defaulted to test.claim/1 when empty.
	Type string
	// Payload is the claim body, defaulted to a small fixed object when nil.
	Payload map[string]any
	// Evidence entries are attached verbatim, so a test controls digests and locations.
	Evidence []map[string]any
	// AttestSeeds counter-signs the claim once per seed byte under the role attestor.
	AttestSeeds []byte
	// Fields are selectively disclosable values. Their digests are committed as the
	// payload's _sd set, inside what the link covers, and each field marked Reveal travels
	// as a disclosure outside it.
	Fields []Field
}

// Field is one selectively disclosable value on a claim.
type Field struct {
	// Name is the field name.
	Name string
	// Value is the field's JSON value.
	Value any
	// Reveal includes the disclosure in the bundle; false commits the digest and withholds
	// the value, which is the redaction case.
	Reveal bool
}

// Salt returns the deterministic salt a builder uses for a named field. Deterministic so a
// test can independently recompute a genuine digest, or construct a lying one.
func Salt(name string) string { return "salt-" + name }

// FieldDigest returns the hex digest the _sd set commits for one field, SHA-256 over the
// RFC 8785 canonical [salt, name, value] array.
func FieldDigest(name string, value any) string {
	ser, err := jcs.Serialize([]any{Salt(name), name, value})
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(ser)
	return hex.EncodeToString(sum[:])
}

// Builder assembles one loomseal-chain-v1 bundle. The zero value plus Build yields a
// minimal valid single-claim bundle.
type Builder struct {
	// Seed selects the producer key, defaulted to 0x42.
	Seed byte
	// Install is the producing install id, defaulted to in_test.
	Install string
	// Product is the producer's product name, defaulted to bundletest.
	Product string
	// BundleID is the bundle identifier, defaulted to lsb_bundletest_0001.
	BundleID string
	// Claims are chained in order. Empty means one default claim.
	Claims []Claim
	// Mutate, when set, edits the document tree after chaining and before signing, so a
	// test builds a validly signed bundle whose content is a lie.
	Mutate func(doc map[string]any)
}

// Build chains, signs, and serializes the bundle.
func (b Builder) Build() ([]byte, error) {
	if b.Seed == 0 {
		b.Seed = 0x42
	}
	if b.Install == "" {
		b.Install = "in_test"
	}
	if b.Product == "" {
		b.Product = "bundletest"
	}
	if b.BundleID == "" {
		b.BundleID = "lsb_bundletest_0001"
	}
	if len(b.Claims) == 0 {
		b.Claims = []Claim{{}}
	}
	priv, pub := Key(b.Seed)

	claims := make([]any, 0, len(b.Claims))
	prev := ""
	var head string
	for i, c := range b.Claims {
		if c.Type == "" {
			c.Type = "test.claim/1"
		}
		if c.Payload == nil {
			c.Payload = map[string]any{"n": int64(i + 1)}
		}
		if len(c.Fields) > 0 {
			sd := make([]any, 0, len(c.Fields))
			for _, fd := range c.Fields {
				sd = append(sd, FieldDigest(fd.Name, fd.Value))
			}
			c.Payload["_sd"] = sd
		}
		claim := map[string]any{"type": c.Type, "at": At, "payload": c.Payload}
		for _, fd := range c.Fields {
			if !fd.Reveal {
				continue
			}
			claim["disclosures"] = append(asSlice(claim["disclosures"]),
				map[string]any{"salt": Salt(fd.Name), "name": fd.Name, "value": fd.Value})
		}
		if len(c.Evidence) > 0 {
			ev := make([]any, 0, len(c.Evidence))
			for _, e := range c.Evidence {
				ev = append(ev, e)
			}
			claim["evidence"] = ev
		}
		link, err := seal.LinkV1(nil, b.Install, int64(i+1), prev, seal.ClaimContent(claim))
		if err != nil {
			return nil, fmt.Errorf("claim %d link: %w", i, err)
		}
		claim["chain"] = map[string]any{"seq": int64(i + 1), "prev": prev, "link": link}
		for _, s := range c.AttestSeeds {
			claim["attestations"] = append(asSlice(claim["attestations"]),
				attestation(s, link, "attestor"))
		}
		claims = append(claims, claim)
		prev, head = link, link
	}

	doc := map[string]any{
		"loomseal": "0.1", "bundle_id": b.BundleID, "created_at": At,
		"producer": map[string]any{
			"product": b.Product, "product_version": "0.0.1", "install_id": b.Install,
			"public_key": base64.StdEncoding.EncodeToString(pub), "key_id": seal.KeyID(pub),
		},
		"subject": map[string]any{"type": "run", "id": "bundletest"},
		"chain": map[string]any{
			"profile": "loomseal-chain-v1", "keyed": false,
			"params": map[string]any{"install_id": b.Install},
			"head":   map[string]any{"seq": int64(len(b.Claims)), "link": head},
		},
		"claims": claims,
	}
	if b.Mutate != nil {
		b.Mutate(doc)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return seal.SignBundle(raw, priv)
}

// WriteTo builds the bundle and writes it into dir, returning the file path.
func (b Builder) WriteTo(dir string) (string, error) {
	raw, err := b.Build()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "bundle.loomseal.json")
	return path, os.WriteFile(path, raw, 0o600)
}

// Evidence writes content into dir under name and returns the evidence entry referencing
// it, digest computed over the bytes actually written.
func Evidence(dir, name string, content []byte) (map[string]any, error) {
	if err := os.WriteFile(filepath.Join(dir, name), content, 0o600); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(content)
	return map[string]any{
		"role": "artifact", "digest": "sha256:" + hex.EncodeToString(sum[:]),
		"present": true, "location": name,
	}, nil
}

// Present wraps a built bundle in a holder presentation bound to an audience and nonce.
func Present(bundleRaw []byte, holderSeed byte, audience, nonce string) ([]byte, error) {
	priv, _ := Key(holderSeed)
	return seal.Present(bundleRaw, priv, audience, nonce, At)
}

// attestation counter-signs one link under a role with the key of the given seed.
func attestation(seed byte, link, role string) map[string]any {
	priv, pub := Key(seed)
	obj := map[string]any{"loomseal": "attestation/1", "link": link, "role": role}
	pre, err := jcs.Serialize(obj)
	if err != nil {
		panic(err)
	}
	return map[string]any{
		"alg": "ed25519", "key_id": seal.KeyID(pub),
		"public_key": base64.StdEncoding.EncodeToString(pub),
		"role":       role,
		"sig":        base64.StdEncoding.EncodeToString(ed25519.Sign(priv, pre)),
	}
}

// asSlice returns v as a []any, treating nil as empty.
func asSlice(v any) []any {
	if v == nil {
		return nil
	}
	return v.([]any)
}
