package verify

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kordloom/loomseal/internal/bundletest"
)

// pythonVerdict runs the reference verifier over a bundle and an evidence directory and returns
// whether it reported the bundle verified. It skips the test when the interpreter or its dependency
// cannot run, so a skip is never mistaken for agreement.
func pythonVerdict(t *testing.T, bundlePath, evidenceDir string) bool {
	t.Helper()
	script := filepath.Join("..", "..", "reference", "loomverify.py")
	out, err := exec.Command("python3", script, bundlePath, evidenceDir).CombinedOutput()
	if err != nil && len(out) == 0 {
		t.Skipf("python reference verifier not runnable: %v", err)
	}
	var r map[string]any
	if jerr := json.Unmarshal(out, &r); jerr != nil {
		t.Skipf("python reference verifier did not return JSON (missing dependency?): %s",
			strings.TrimSpace(string(out)))
	}
	ok, _ := r["ok"].(bool)
	return ok
}

// writeBundle builds a signed loomseal-chain-v1 bundle with one evidence artifact, writes it and
// the artifact into dir, and returns the bundle path.
func writeBundle(t *testing.T, dir, content string) string {
	t.Helper()
	ev, err := bundletest.Evidence(dir, "artifact.txt", []byte(content))
	if err != nil {
		t.Fatal(err)
	}
	claims := []bundletest.Claim{{Evidence: []map[string]any{ev}}}
	raw, err := bundletest.Builder{Claims: claims}.Build()
	if err != nil {
		t.Fatal(err)
	}
	bp := filepath.Join(dir, "bundle.loomseal.json")
	if err := os.WriteFile(bp, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return bp
}

// TestEvidenceParityAltered is the guarantee: an artifact present at its declared location whose
// bytes do not match the sealed digest fails the bundle, in both the Go verifier and the Python
// reference. It is the fix for the defect where the reference counted an altered artifact as merely
// missing and still reported VERIFIED.
func TestEvidenceParityAltered(t *testing.T) {
	dir := t.TempDir()
	bp := writeBundle(t, dir, "the real approval, as sealed")
	raw, _ := os.ReadFile(bp)
	// Alter the artifact in place at the location the bundle names.
	if err := os.WriteFile(filepath.Join(dir, "artifact.txt"), []byte("tampered"), 0o600); err != nil {
		t.Fatal(err)
	}
	goOK := Run(raw, Options{EvidenceDir: dir}).OK
	if goOK {
		t.Errorf("go verifier accepted an altered artifact")
	}
	if pythonVerdict(t, bp, dir) {
		t.Errorf("python reference accepted an altered artifact; the two verifiers disagree")
	}
}

// TestEvidenceParityIntact is the negative control for TestEvidenceParityAltered: the same bundle
// with the artifact left intact verifies in both, so the altered check is catching tampering rather
// than failing every bundle that carries evidence.
func TestEvidenceParityIntact(t *testing.T) {
	dir := t.TempDir()
	bp := writeBundle(t, dir, "the real approval, as sealed")
	raw, _ := os.ReadFile(bp)
	goR := Run(raw, Options{EvidenceDir: dir})
	if !goR.OK || goR.EvidenceVerified != 1 {
		t.Errorf("go verifier did not accept the intact artifact: ok=%v verified=%d problems=%v",
			goR.OK, goR.EvidenceVerified, goR.Problems)
	}
	if !pythonVerdict(t, bp, dir) {
		t.Errorf("python reference rejected the intact artifact; the two verifiers disagree")
	}
}

// TestEvidenceParityTraversal is the within-dir guard: a location that escapes the evidence
// directory is never followed, so a file sitting outside it is not read as the artifact. The digest
// goes unmatched and the artifact counts as missing, which is not a failure, in both verifiers.
func TestEvidenceParityTraversal(t *testing.T) {
	parent := t.TempDir()
	dir := filepath.Join(parent, "evidence")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	// A file outside the evidence directory, which a traversal location would reach if followed.
	outside := filepath.Join(parent, "outside.txt")
	if err := os.WriteFile(outside, []byte("outside bytes"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Build a bundle whose single evidence entry names a location climbing out of the directory. The
	// sealed digest is some value no file in the directory matches.
	raw, err := bundletest.Builder{Claims: []bundletest.Claim{{Evidence: []map[string]any{{
		"role":     "artifact",
		"digest":   "sha256:" + strings.Repeat("ab", 32),
		"present":  true,
		"location": "../outside.txt",
	}}}}}.Build()
	if err != nil {
		t.Fatal(err)
	}
	bp := filepath.Join(dir, "bundle.loomseal.json")
	if err := os.WriteFile(bp, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	goR := Run(raw, Options{EvidenceDir: dir})
	if !goR.OK || goR.EvidenceMismatched != 0 || goR.EvidenceMissing != 1 {
		t.Errorf("go verifier followed a traversal location: ok=%v mismatched=%d missing=%d problems=%v",
			goR.OK, goR.EvidenceMismatched, goR.EvidenceMissing, goR.Problems)
	}
	if !pythonVerdict(t, bp, dir) {
		t.Errorf("python reference followed a traversal location or otherwise disagreed")
	}
}
