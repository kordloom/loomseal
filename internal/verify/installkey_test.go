package verify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/kordloom/loomseal/jcs"
	"github.com/kordloom/loomseal/seal"
)

// TestAnInstallMintedFromAnotherKeyNeedsAnExplicitPairing pins the rule that a switchtender-audit-v1
// install id minted from one key and presented by another verifies only when the caller pinned the
// key and named the install.
//
// Another install's whole history, re-signed under a fresh key with its install id kept, recomputes
// every link and carries every third-party anchor intact, so it reached VERIFIED with nothing to tell
// it from the genuine bundle. A legitimate key rotation is byte-identical to that lift, which is why
// neither the bundle nor a pin alone can settle it and the caller has to state the pairing.
func TestAnInstallMintedFromAnotherKeyNeedsAnExplicitPairing(t *testing.T) {
	t.Parallel()
	const signer, other byte = 0x31, 0x32
	signerPub := installTestKey(signer)
	otherPub := installTestKey(other)
	pin := seal.KeyID(signerPub)

	tests := []struct {
		Profile     string
		Install     string
		Pin         string
		Accept      string
		WantOK      bool
		WantBinding string
		WantProblem string
	}{{ // Test 0: An install id minted from the signing key verifies unpinned.
		Profile: "switchtender-audit-v1", Install: currentID(signerPub),
		WantOK: true, WantBinding: "minted from the producer key",
	}, { // Test 1: The legacy form minted from the signing key verifies unpinned.
		Profile: "switchtender-audit-v1", Install: legacyID(signerPub),
		WantOK: true, WantBinding: "minted from the producer key",
	}, { // Test 2: An install id minted from another key is refused unpinned.
		Profile: "switchtender-audit-v1", Install: currentID(otherPub),
		WantOK: false, WantProblem: "was minted from a different key",
	}, { // Test 3: A pin alone does not pair the key with the install.
		Profile: "switchtender-audit-v1", Install: currentID(otherPub), Pin: pin,
		WantOK: false, WantProblem: "was minted from a different key",
	}, { // Test 4: A pin and the named install accept the rotation.
		Profile: "switchtender-audit-v1", Install: currentID(otherPub), Pin: pin,
		Accept: currentID(otherPub), WantOK: true, WantBinding: "rotation accepted",
	}, { // Test 5: Accepting a different install than the bundle names is refused.
		Profile: "switchtender-audit-v1", Install: currentID(otherPub), Pin: pin,
		Accept: currentID(signerPub), WantOK: false, WantProblem: "but this bundle names",
	}, { // Test 6: The legacy form minted from another key is refused unpinned.
		Profile: "switchtender-audit-v1", Install: legacyID(otherPub),
		WantOK: false, WantProblem: "was minted from a different key",
	}, { // Test 7: An install id in no key-minted form establishes nothing and changes nothing.
		Profile: "switchtender-audit-v1", Install: "in_vectors",
		WantOK: true, WantBinding: "",
	}, { // Test 8: Accepting an install without a pin is refused.
		Profile: "switchtender-audit-v1", Install: currentID(otherPub),
		Accept: currentID(otherPub), WantOK: false, WantProblem: "needs the producer key pinned",
	}, { // Test 9: The rule belongs to the switchtender profile and leaves other chains alone.
		Profile: "loomseal-chain-v1", Install: currentID(otherPub),
		WantOK: true, WantBinding: "",
	}}

	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			raw := installBundleForTest(t, test.Profile, signer, test.Install)
			r := Run(raw, Options{Fingerprint: test.Pin, AcceptInstall: test.Accept})
			if r.OK != test.WantOK {
				t.Errorf("OK = %v, want %v (problems: %v)", r.OK, test.WantOK, r.Problems)
			}
			if r.InstallBinding != test.WantBinding {
				t.Errorf("InstallBinding = %q, want %q", r.InstallBinding, test.WantBinding)
			}
			if test.WantProblem != "" && !hasProblemText(r, test.WantProblem) {
				t.Errorf("problems %v do not mention %q", r.Problems, test.WantProblem)
			}
			if !r.SignatureOK {
				t.Errorf("the signature verifies in every case here, problems: %v", r.Problems)
			}
		})
	}
}

// installTestKey returns the public key for a seed of one repeated byte.
func installTestKey(seedByte byte) ed25519.PublicKey {
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seedByte}, ed25519.SeedSize))
	return priv.Public().(ed25519.PublicKey)
}

// currentID computes the switchtender install id minted from a key, independently of the verifier.
func currentID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "in_" + hex.EncodeToString(sum[:])[:32]
}

// legacyID computes the legacy switchtender install id, the key's first six bytes.
func legacyID(pub ed25519.PublicKey) string { return "in_" + hex.EncodeToString(pub)[:12] }

// hasProblemText reports whether any problem contains substr.
func hasProblemText(r *Report, substr string) bool {
	for _, p := range r.Problems {
		if strings.Contains(p, substr) {
			return true
		}
	}
	return false
}

// installBundleForTest builds a one-claim bundle under profile whose producer and claim name install,
// signed by the key for seedByte. The switchtender profile folds the install id into the link, and
// loomseal-chain-v1 binds it through its params, so each is a well-formed chain of its profile.
func installBundleForTest(t *testing.T, profile string, seedByte byte, install string) []byte {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seedByte}, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	const at = "2026-09-30T12:00:00Z"
	claim := map[string]any{
		"type": "switchtender.audit/1", "at": at,
		"payload": map[string]any{"actor": "release-token", "method": "POST", "path": "/api/runs"},
	}
	chainDoc := map[string]any{"profile": profile, "keyed": false}
	var link string
	switch profile {
	case "switchtender-audit-v1":
		claim["payload"].(map[string]any)["install_id"] = install
		b, err := jcs.Serialize(map[string]any{"seq": int64(1), "at": at, "actor": "release-token",
			"method": "POST", "path": "/api/runs", "prev": "", "install_id": install})
		if err != nil {
			t.Fatalf("link: %v", err)
		}
		sum := sha256.Sum256(b)
		link = hex.EncodeToString(sum[:])
	default:
		var err error
		if link, err = seal.LinkV1(nil, install, 1, "", seal.ClaimContent(claim)); err != nil {
			t.Fatalf("link: %v", err)
		}
		chainDoc["params"] = map[string]any{"install_id": install}
	}
	claim["chain"] = map[string]any{"seq": int64(1), "prev": "", "link": link}
	chainDoc["head"] = map[string]any{"seq": int64(1), "link": link}
	doc := map[string]any{
		"loomseal": "0.1", "bundle_id": "lsb_install_key", "created_at": at,
		"producer": map[string]any{
			"product": "switchtender", "product_version": "1.101.0", "install_id": install,
			"public_key": base64.StdEncoding.EncodeToString(pub), "key_id": seal.KeyID(pub),
		},
		"subject": map[string]any{"type": "fleet", "id": "demo-yard"},
		"chain":   chainDoc,
		"claims":  []any{claim},
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signed, err := seal.SignBundle(body, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}
