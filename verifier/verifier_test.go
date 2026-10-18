package verifier_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/kordloom/loomseal/verifier"
)

// vectorKey is the fingerprint of the key every conformance vector is signed with.
const vectorKey = "sha256:65b60673d6ed884bf01c2c222d82ada0740f29ac3355d6a925c81f17f47a27b8"

// TestRun holds the exported verifier to the conformance vectors it fronts.
func TestRun(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Vector      string
		Fingerprint string
		WantOK      bool
		WantPinned  bool
		WantLevel   string
	}{{ // Test 0: A full Coble proof verifies unpinned.
		Vector: "coble-proof-full", WantOK: true, WantLevel: "signed, chained (tree of 5)",
	}, { // Test 1: A disclosed Coble proof verifies pinned to its producer.
		Vector: "coble-proof-disclosed", Fingerprint: vectorKey, WantOK: true, WantPinned: true,
		WantLevel: "signed, chained (tree of 5)",
	}, { // Test 2: A rewritten comparison fails.
		Vector: "coble-proof-status-altered", WantLevel: "not verified",
	}, { // Test 3: A pin naming another key fails.
		Vector: "coble-proof-full", Fingerprint: "sha256:" + fmt.Sprintf("%064x", 0), WantPinned: true,
		WantLevel: "not verified",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			raw, err := os.ReadFile(filepath.Join("..", "testdata", "vectors", test.Vector+".loomseal.json"))
			if err != nil {
				t.Fatal(err)
			}
			r := verifier.Run(raw, verifier.Options{Fingerprint: test.Fingerprint})
			got := struct {
				OK     bool
				Pinned bool
				Level  string
			}{r.OK, r.ProducerPinned, r.Level}
			want := struct {
				OK     bool
				Pinned bool
				Level  string
			}{test.WantOK, test.WantPinned, test.WantLevel}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s\nproblems: %v", diff, r.Problems)
			}
			if !r.OK && len(r.Problems) == 0 {
				t.Error("failed report lists no problem")
			}
		})
	}
}

// TestCheckFingerprint holds the pin check to the one form a fingerprint takes.
func TestCheckFingerprint(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Want error
		Pin  string
	}{{ // Test 0: A well-formed pin passes.
		Pin: vectorKey, Want: nil,
	}, { // Test 1: An empty pin is refused.
		Pin: "", Want: verifier.ErrFingerprint,
	}, { // Test 2: Upper case hex is refused.
		Pin:  "sha256:65B60673D6ED884BF01C2C222D82ADA0740F29AC3355D6A925C81F17F47A27B8",
		Want: verifier.ErrFingerprint,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			if err := verifier.CheckFingerprint(test.Pin); !errors.Is(err, test.Want) {
				t.Errorf("got %v, want %v", err, test.Want)
			}
		})
	}
}
