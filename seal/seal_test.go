package seal_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/kordloom/loomseal/internal/verify"
	"github.com/kordloom/loomseal/seal"
)

// testKey returns a deterministic signing key, so a failure is reproducible rather than a new
// random one each run.
func testKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	return ed25519.NewKeyFromSeed(seed)
}

// minimalBundle returns an unsigned bundle carrying the given producer key.
func minimalBundle(t *testing.T, pub ed25519.PublicKey) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"loomseal":   "0.1",
		"bundle_id":  "lsb_sealtest",
		"created_at": "2026-07-27T15:00:00Z",
		"producer": map[string]any{
			"product": "SealTest", "product_version": "v1", "install_id": "in_test",
			"public_key": encodeKey(pub), "key_id": seal.KeyID(pub),
		},
		"subject":    map[string]any{"type": "fleet", "id": "test"},
		"claims":     []any{map[string]any{"type": "switchtender.audit/1", "at": "2026-07-27T15:00:00Z", "payload": map[string]any{"actor": "root"}}},
		"signatures": []any{},
	})
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	return raw
}

// encodeKey returns the standard base64 of a public key, the encoding a bundle carries.
func encodeKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}

// TestSignBundleProducesAVerifiableBundle pins that what this package signs is what the verifier
// accepts. The producer and the verifier are separate packages on purpose, so this is the one test
// that proves they still agree.
func TestSignBundleProducesAVerifiableBundle(t *testing.T) {
	t.Parallel()
	priv := testKey(t)
	pub := priv.Public().(ed25519.PublicKey)
	signed, err := seal.SignBundle(minimalBundle(t, pub), priv)
	if err != nil {
		t.Fatalf("SignBundle() error = %v", err)
	}
	report := verify.Run(signed, verify.Options{})
	if !report.OK {
		t.Fatalf("a freshly signed bundle does not verify: %v", report.Problems)
	}
	if !report.SignatureOK {
		t.Error("signature did not verify against the key that signed it")
	}
}

// TestSignBundleReplacesAnExistingSignature pins that re-signing produces one signature rather than
// appending, so a bundle cannot accumulate stale signatures nobody checks.
func TestSignBundleReplacesAnExistingSignature(t *testing.T) {
	t.Parallel()
	priv := testKey(t)
	pub := priv.Public().(ed25519.PublicKey)
	once, err := seal.SignBundle(minimalBundle(t, pub), priv)
	if err != nil {
		t.Fatalf("SignBundle() error = %v", err)
	}
	twice, err := seal.SignBundle(once, priv)
	if err != nil {
		t.Fatalf("SignBundle() second pass error = %v", err)
	}
	var doc struct {
		Signatures []any `json:"signatures"`
	}
	if err := json.Unmarshal(twice, &doc); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if len(doc.Signatures) != 1 {
		t.Errorf("re-signing produced %d signatures, want 1", len(doc.Signatures))
	}
	if !verify.Run(twice, verify.Options{}).OK {
		t.Error("a re-signed bundle does not verify")
	}
}

// TestSignBundleRejectsNonBundles pins that input which is not a bundle-shaped object is refused,
// rather than signed into something that looks official and means nothing.
func TestSignBundleRejectsNonBundles(t *testing.T) {
	t.Parallel()
	priv := testKey(t)
	for _, bad := range []string{`[1,2,3]`, `"a string"`, `42`, `not json at all`, ``} {
		if _, err := seal.SignBundle([]byte(bad), priv); err == nil {
			t.Errorf("SignBundle(%q) signed something that is not a bundle", bad)
		} else if bad == `[1,2,3]` && !errors.Is(err, seal.ErrBundle) {
			t.Errorf("SignBundle(array) error = %v, want ErrBundle", err)
		}
	}
}

// TestKeyIDIsStableAndFingerprintShaped pins the value an operator publishes on a trust page. A key
// id that changed between calls, or between the producer and the verifier, would make pinning
// impossible.
func TestKeyIDIsStableAndFingerprintShaped(t *testing.T) {
	t.Parallel()
	pub := testKey(t).Public().(ed25519.PublicKey)
	first, second := seal.KeyID(pub), seal.KeyID(pub)
	if first != second {
		t.Errorf("KeyID is not stable: %q then %q", first, second)
	}
	if !strings.HasPrefix(first, "sha256:") || len(first) != len("sha256:")+64 {
		t.Errorf("KeyID = %q, want sha256: followed by 64 hex characters", first)
	}
	other := make(ed25519.PublicKey, len(pub))
	copy(other, pub)
	other[0] ^= 0xff
	if seal.KeyID(other) == first {
		t.Error("two different keys share a key id, so pinning one would accept the other")
	}
}

// TestLinkV1KeyedAndUnkeyed pins that a keyed link differs from an unkeyed one over the same claim.
// The unkeyed form is recomputable by anyone; the keyed form is only extendable by the key holder,
// and a scheme where they collided would give away that distinction.
func TestLinkV1KeyedAndUnkeyed(t *testing.T) {
	t.Parallel()
	claim := map[string]any{"type": "switchtender.audit/1", "payload": map[string]any{"actor": "root"}}
	plain, err := seal.LinkV1(nil, "in_test", 1, "", claim)
	if err != nil {
		t.Fatalf("LinkV1() error = %v", err)
	}
	keyed, err := seal.LinkV1([]byte("secret"), "in_test", 1, "", claim)
	if err != nil {
		t.Fatalf("LinkV1(keyed) error = %v", err)
	}
	if plain == keyed {
		t.Error("a keyed link equals the unkeyed one, so the key adds nothing")
	}
	if again, _ := seal.LinkV1(nil, "in_test", 1, "", claim); again != plain {
		t.Error("an unkeyed link is not reproducible, so no third party can recompute it")
	}
	// The install id is part of the link, so two installs cannot produce the same one.
	if other, _ := seal.LinkV1(nil, "in_other", 1, "", claim); other == plain {
		t.Error("two installs produce the same link for the same claim")
	}
}
