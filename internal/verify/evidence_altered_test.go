package verify

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kordloom/loomseal/internal/bundle"
)

// TestAlteredEvidenceFailsVerification pins the difference between an artifact nobody supplied
// and an artifact that is sitting at its declared location with different bytes.
//
// The format allows a holder to disclose less than the whole evidence set, so an absent artifact
// is not a failure. An artifact present at the location the bundle names, whose bytes no longer
// hash to the sealed digest, is the tampering case the seal exists to catch. Both once landed in
// the same counter and neither recorded a problem, so a bundle whose underlying data had been
// edited still reached the VERIFIED verdict and exited zero. Anything gating on that verdict, a
// reader skimming for the word or a CI job checking the status, would have passed it.
func TestAlteredEvidenceFailsVerification(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name           string
		WriteBytes     []byte
		WriteAt        string
		WantVerified   int
		WantMissing    int
		WantMismatched int
		WantProblem    bool
	}{{ // Test 0: The artifact matches the sealed digest.
		Name:       "matching artifact verifies",
		WriteBytes: []byte("sealed content"), WriteAt: "run.jsonl",
		WantVerified: 1, WantMissing: 0, WantMismatched: 0, WantProblem: false,
	}, { // Test 1: Nothing supplied, which selective disclosure permits.
		Name:       "absent artifact is missing, not a problem",
		WriteBytes: nil, WriteAt: "",
		WantVerified: 0, WantMissing: 1, WantMismatched: 0, WantProblem: false,
	}, { // Test 2: Present at its declared location, bytes changed.
		Name:       "altered artifact is a problem",
		WriteBytes: []byte("edited content"), WriteAt: "run.jsonl",
		WantVerified: 0, WantMissing: 0, WantMismatched: 1, WantProblem: true,
	}}

	for testNum, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			if test.WriteAt != "" {
				if err := os.WriteFile(filepath.Join(dir, test.WriteAt), test.WriteBytes, 0o600); err != nil {
					t.Fatalf("test %d: write artifact: %v", testNum, err)
				}
			}
			sealed, err := hashBytesForTest([]byte("sealed content"))
			if err != nil {
				t.Fatalf("test %d: digest: %v", testNum, err)
			}
			b := &bundle.Bundle{Claims: []bundle.Claim{{
				Evidence: []bundle.Evidence{{
					Role: "raw-run", Digest: sealed, Present: true, Location: "run.jsonl",
				}},
			}}}
			r := &Report{}
			r.checkEvidence(b, dir)

			if r.EvidenceVerified != test.WantVerified {
				t.Errorf("test %d: verified = %d, want %d", testNum, r.EvidenceVerified, test.WantVerified)
			}
			if r.EvidenceMissing != test.WantMissing {
				t.Errorf("test %d: missing = %d, want %d", testNum, r.EvidenceMissing, test.WantMissing)
			}
			if r.EvidenceMismatched != test.WantMismatched {
				t.Errorf("test %d: mismatched = %d, want %d", testNum, r.EvidenceMismatched, test.WantMismatched)
			}
			if got := len(r.Problems) > 0; got != test.WantProblem {
				t.Errorf("test %d: problem recorded = %v, want %v (problems: %v)",
					testNum, got, test.WantProblem, r.Problems)
			}
		})
	}
}

// TestAlteredEvidenceCountsArtifactsNotReferences pins that one altered file shared by several
// claims reports as one artifact. The line says "artifact(s)", so counting references would
// overstate how much of the evidence set moved.
func TestAlteredEvidenceCountsArtifactsNotReferences(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "run.jsonl"), []byte("edited"), 0o600); err != nil {
		t.Fatalf("write artifact: %v", err)
	}
	sealed, err := hashBytesForTest([]byte("sealed content"))
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	ev := []bundle.Evidence{{Role: "raw-run", Digest: sealed, Present: true, Location: "run.jsonl"}}
	b := &bundle.Bundle{Claims: []bundle.Claim{{Evidence: ev}, {Evidence: ev}, {Evidence: ev}}}

	r := &Report{}
	r.checkEvidence(b, dir)

	if r.EvidenceMismatched != 1 {
		t.Errorf("mismatched = %d, want 1 for one file behind three claims", r.EvidenceMismatched)
	}
	if len(r.Problems) != 1 {
		t.Errorf("problems = %d, want 1; a reader should see the file once: %v", len(r.Problems), r.Problems)
	}
}

// TestEvidenceLocationCannotEscapeDirectory pins that a location is treated as attacker-controlled.
// It travels inside the bundle, so a bundle naming ../../etc/passwd must not send the verifier
// outside the directory it was pointed at.
func TestEvidenceLocationCannotEscapeDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	for _, loc := range []string{"../escape", "/etc/passwd", "a/../../escape"} {
		if withinDir(dir, loc) {
			t.Errorf("location %q was accepted as inside %q", loc, dir)
		}
	}
	for _, loc := range []string{"run.jsonl", "sub/run.jsonl", "./run.jsonl"} {
		if !withinDir(dir, loc) {
			t.Errorf("location %q was rejected but sits inside %q", loc, dir)
		}
	}
}

// hashBytesForTest returns the sha256: digest of b using the same helper the verifier uses on
// files, so a test digest and a real one are produced the same way.
func hashBytesForTest(b []byte) (string, error) {
	dir, err := os.MkdirTemp("", "loomseal-digest")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(dir)
	p := filepath.Join(dir, "artifact")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return "", err
	}
	return hashFile(p)
}
