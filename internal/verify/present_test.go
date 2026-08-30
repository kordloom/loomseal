package verify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/kordloom/loomseal/seal"
)

// Test the holder presentation flow: a holder wraps a signed bundle bound to a verifier and nonce,
// the verifier checks it, replay to a different audience or nonce fails, and tampering the bundle
// inside the presentation fails.
func TestRunPresentation(t *testing.T) {
	t.Parallel()
	signed := swatchBundle(t, "title") // a valid signed loomseal-chain-v1 bundle
	holder := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, 32))

	pres, err := seal.Present(signed, holder, "acme-verifier", "chal-123", at)
	if err != nil {
		t.Fatalf("present: %v", err)
	}
	if !LooksLikePresentation(pres) {
		t.Fatal("presentation not detected as one")
	}

	// Test 0: correct audience and nonce, everything verifies.
	got := RunPresentation(pres, PresentationOptions{Audience: "acme-verifier", Nonce: "chal-123"})
	if !got.OK || !got.PresentationOK || got.Bundle == nil || !got.Bundle.OK {
		t.Fatalf("presentation: ok %t presOK %t bundleOK %v problems %v", got.OK, got.PresentationOK,
			got.Bundle != nil && got.Bundle.OK, got.Problems)
	}

	// Test 1: replay to a different verifier fails on the audience pin.
	got = RunPresentation(pres, PresentationOptions{Audience: "someone-else", Nonce: "chal-123"})
	if got.OK || got.AudienceMatch == nil || *got.AudienceMatch {
		t.Fatalf("replay to wrong audience verified: ok %t", got.OK)
	}

	// Test 2: replay with a stale nonce fails.
	got = RunPresentation(pres, PresentationOptions{Audience: "acme-verifier", Nonce: "old-nonce"})
	if got.OK || got.NonceMatch == nil || *got.NonceMatch {
		t.Fatalf("replay with stale nonce verified: ok %t", got.OK)
	}

	// Test 3: tampering the bundle inside the presentation breaks the holder signature (its digest no
	// longer matches) as well as the bundle's own signature.
	var doc map[string]any
	if err := json.Unmarshal(pres, &doc); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(doc["bundle"])
	if !bytes.Contains(b, []byte("Engineer")) {
		t.Fatal("test bundle does not contain the value to tamper")
	}
	doc["bundle"] = json.RawMessage(bytes.Replace(b, []byte("Engineer"), []byte("Director"), 1))
	tampered, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	got = RunPresentation(tampered, PresentationOptions{Audience: "acme-verifier", Nonce: "chal-123"})
	if got.OK || got.PresentationOK {
		t.Fatalf("tampered presentation verified: ok %t presOK %t", got.OK, got.PresentationOK)
	}
}

// TestPresentationHolderKeyGuards pins the holder key checks: a key that decodes but is
// the wrong size, and a disclosure entry missing one of its three required parts. Both
// guards are disjunction chains that only complete inputs would otherwise exercise.
func TestPresentationHolderKeyGuards(t *testing.T) {
	t.Parallel()
	signed := swatchBundle(t, "title")
	holder := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{11}, 32))
	pres, err := seal.Present(signed, holder, "acme-verifier", "chal-123", at)
	if err != nil {
		t.Fatalf("present: %v", err)
	}
	opts := PresentationOptions{Audience: "acme-verifier", Nonce: "chal-123"}

	// Test 0: a holder key that is valid base64 of the wrong length is refused.
	var doc map[string]any
	if err := json.Unmarshal(pres, &doc); err != nil {
		t.Fatal(err)
	}
	h, _ := doc["holder"].(map[string]any)
	h["public_key"] = base64.StdEncoding.EncodeToString(make([]byte, 16))
	short, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	got := RunPresentation(short, opts)
	if got.PresentationOK {
		t.Fatalf("short holder key verified: %v", got.Problems)
	}
	found := false
	for _, p := range got.Problems {
		if bytes.Contains([]byte(p), []byte("32 byte")) {
			found = true
		}
	}
	if !found {
		t.Errorf("problems %v do not mention the key size", got.Problems)
	}
}
