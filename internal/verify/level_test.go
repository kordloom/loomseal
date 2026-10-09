package verify

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/kordloom/loomseal/seal"
)

// TestLevelFollowsTheVerdict pins that the level names what the verdict established. A bundle
// whose signature held and whose chain or pin then failed achieved nothing, and a report that words
// it "signed, chained (full)" beside ok false tells a consumer keying on the level the opposite of
// what the verdict says, and disagrees with the reference verifier on the same bytes.
func TestLevelFollowsTheVerdict(t *testing.T) {
	t.Parallel()
	pub, ok := testKey().Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("public key type")
	}
	keyID := seal.KeyID(pub)
	tests := []struct {
		Pin       string
		Mutate    func(m map[string]any)
		WantOK    bool
		WantLevel string
	}{{ // Test 0: Nothing wrong, so the level is the wording the bundle earned.
		WantOK:    true,
		WantLevel: "signed, chained (full), anchored by reference",
	}, { // Test 1: A matching pin changes nothing about the level.
		Pin: keyID, WantOK: true,
		WantLevel: "signed, chained (full), anchored by reference",
	}, { // Test 2: The signature holds and the pin does not, so no level was achieved.
		Pin:    "sha256:" + strings.Repeat("0", 62) + "ff",
		WantOK: false, WantLevel: "not verified",
	}, { // Test 3: The signature holds and the chain does not, so no level was achieved.
		Mutate: func(m map[string]any) {
			claim, _ := m["claims"].([]any)[1].(map[string]any)
			claim["chain"].(map[string]any)["link"] = strings.Repeat("ab", 32)
		},
		WantOK: false, WantLevel: "not verified",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := Run(signedBundle(t, test.Mutate), Options{Fingerprint: test.Pin})
			if !got.SignatureOK {
				t.Fatalf("the signature must hold in every case here: %v", got.Problems)
			}
			if got.OK != test.WantOK {
				t.Fatalf("ok %t, want %t; problems %v", got.OK, test.WantOK, got.Problems)
			}
			if got.Level != test.WantLevel {
				t.Errorf("level %q, want %q", got.Level, test.WantLevel)
			}
		})
	}
}

// TestDisclosedStatesOnlyOnAVerifiedBundle pins that the disclosed members and their unchecked
// count are reported only when the bundle verified. The states qualify a verified verdict, and
// listing them on a failed bundle would make this verifier, which runs every check, and the
// reference, which stops at the first failure, describe the same failing bytes two ways.
func TestDisclosedStatesOnlyOnAVerifiedBundle(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors",
		"switchtender-record-correction.loomseal.json"))
	if err != nil {
		t.Fatalf("read vector: %v", err)
	}
	passing := Run(raw, Options{})
	if !passing.OK || len(passing.Disclosed) == 0 {
		t.Fatalf("setup: want a verified bundle with disclosed members, got ok %t with %d",
			passing.OK, len(passing.Disclosed))
	}
	failing := Run(raw, Options{Fingerprint: "sha256:" + strings.Repeat("0", 62) + "ff"})
	if failing.OK || !failing.SignatureOK {
		t.Fatalf("setup: want a bundle failing past its signature, got ok %t signature %t",
			failing.OK, failing.SignatureOK)
	}
	if diff := cmp.Diff([]DisclosedMember(nil), failing.Disclosed, cmpopts.EquateEmpty()); diff != "" {
		t.Errorf("a failed bundle lists disclosed members (-want +got):\n%s", diff)
	}
	if failing.DisclosedUnchecked != 0 {
		t.Errorf("a failed bundle counts %d unchecked records, want 0", failing.DisclosedUnchecked)
	}
}

// TestCheckFingerprint pins the one form a pin may take. An empty pin is the case that matters
// most: it is what a shell sends for an unset variable, and read as no pin it would verify a bundle
// from any key with the exit code of a matched one.
func TestCheckFingerprint(t *testing.T) {
	t.Parallel()
	hex64 := strings.Repeat("ab", 32)
	tests := []struct {
		In   string
		Want error
	}{{ // Test 0: The one accepted form.
		In: "sha256:" + hex64, Want: nil,
	}, { // Test 1: Empty names no key.
		In: "", Want: ErrFingerprint,
	}, { // Test 2: An uppercase prefix is not the form a key id takes.
		In: "SHA256:" + hex64, Want: ErrFingerprint,
	}, { // Test 3: Bare hex without the prefix.
		In: hex64, Want: ErrFingerprint,
	}, { // Test 4: The prefix alone.
		In: "sha256:", Want: ErrFingerprint,
	}, { // Test 5: Uppercase hex, which a key id never carries.
		In: "sha256:" + strings.ToUpper(hex64), Want: ErrFingerprint,
	}, { // Test 6: One digit short.
		In: "sha256:" + hex64[:63], Want: ErrFingerprint,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			if got := CheckFingerprint(test.In); !errors.Is(got, test.Want) {
				t.Errorf("CheckFingerprint(%q) = %v, want %v", test.In, got, test.Want)
			}
		})
	}
}
