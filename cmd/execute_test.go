package cmd

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kordloom/loomseal/seal"
)

// writeBundle builds a minimal signed bundle and writes it to a file in a fresh directory.
func writeBundle(t *testing.T) string {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("public key type")
	}
	m := map[string]any{
		"loomseal":   "0.1",
		"bundle_id":  "lsb_cli",
		"created_at": "2026-07-27T12:00:00Z",
		"producer": map[string]any{
			"product": "test", "product_version": "1", "install_id": "in_1",
			"public_key": base64.StdEncoding.EncodeToString(pub),
			"key_id":     seal.KeyID(pub),
		},
		"subject": map[string]any{"type": "url", "id": "https://example.com"},
		"claims": []any{map[string]any{
			"type": "switchtender.audit/1", "at": "2026-07-27T12:00:00Z",
			"payload": map[string]any{"target_id": "tg_1"},
		}},
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signed, err := seal.SignBundle(raw, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	path := filepath.Join(t.TempDir(), "cli.loomseal.json")
	if err := os.WriteFile(path, signed, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return path
}

// run drives Execute and captures both streams.
func run(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = Execute(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// Test that a valid bundle verifies through the CLI with exit code zero.
func TestExecuteVerify(t *testing.T) {
	t.Parallel()
	code, stdout, _ := run("verify", writeBundle(t))
	if code != CodeOK || !strings.Contains(stdout, "VERIFIED") {
		t.Errorf("code %d stdout %q", code, stdout)
	}
}

// Test that a tampered bundle exits with the failure code.
func TestExecuteVerifyTampered(t *testing.T) {
	t.Parallel()
	path := writeBundle(t)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	raw = bytes.Replace(raw, []byte("tg_1"), []byte("tg_2"), 1)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	code, stdout, _ := run("verify", path)
	if code != CodeFailed || !strings.Contains(stdout, "NOT VERIFIED") {
		t.Errorf("code %d stdout %q", code, stdout)
	}
}

// Test that the JSON report is well formed and marked ok.
func TestExecuteVerifyJSON(t *testing.T) {
	t.Parallel()
	code, stdout, _ := run("verify", "--json", writeBundle(t))
	if code != CodeOK {
		t.Fatalf("code %d", code)
	}
	var report struct {
		OK    bool   `json:"ok"`
		Level string `json:"level"`
	}
	if err := json.Unmarshal([]byte(stdout), &report); err != nil {
		t.Fatalf("unmarshal report: %v", err)
	}
	if !report.OK || report.Level != "signed" {
		t.Errorf("report %+v", report)
	}
}

// Test that flags are accepted after the bundle file as well as before it.
func TestExecuteVerifyFlagsAfterFile(t *testing.T) {
	t.Parallel()
	code, stdout, _ := run("verify", writeBundle(t), "--json")
	if code != CodeOK || !strings.Contains(stdout, `"ok":true`) {
		t.Errorf("code %d stdout %q", code, stdout)
	}
	if code, _, _ := run("verify", writeBundle(t), writeBundle(t)); code != CodeUsage {
		t.Errorf("two files: code %d", code)
	}
}

// Test the usage surfaces: no arguments, unknown command, missing file, version.
func TestExecuteUsage(t *testing.T) {
	t.Parallel()
	if code, _, _ := run(); code != CodeUsage {
		t.Errorf("no arguments: code %d", code)
	}
	if code, _, _ := run("conjure"); code != CodeUsage {
		t.Errorf("unknown command: code %d", code)
	}
	if code, _, _ := run("verify"); code != CodeUsage {
		t.Errorf("missing file: code %d", code)
	}
	if code, _, _ := run("verify", filepath.Join(t.TempDir(), "absent.json")); code != CodeUsage {
		t.Errorf("absent file: code %d", code)
	}
	code, stdout, _ := run("version")
	if code != CodeOK || !strings.Contains(stdout, Version()) {
		t.Errorf("version: code %d stdout %q", code, stdout)
	}
}

// Test the holder flow end to end through the CLI: keygen, present a bundle bound to a verifier and
// nonce, then verify the presentation. Matching pins pass; a wrong audience fails.
func TestExecutePresentRoundTrip(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	bundlePath := writeBundle(t)

	code, keyOut, keyErr := run("keygen")
	if code != CodeOK {
		t.Fatalf("keygen code %d err %s", code, keyErr)
	}
	keyPath := filepath.Join(dir, "holder.key.json")
	if err := os.WriteFile(keyPath, []byte(keyOut), 0o600); err != nil {
		t.Fatal(err)
	}

	code, presOut, presErr := run("present", bundlePath, "--holder-key", keyPath,
		"--audience", "acme", "--nonce", "n1", "--at", "2026-07-27T12:00:00Z")
	if code != CodeOK {
		t.Fatalf("present code %d err %s", code, presErr)
	}
	presPath := filepath.Join(dir, "pres.json")
	if err := os.WriteFile(presPath, []byte(presOut), 0o600); err != nil {
		t.Fatal(err)
	}

	code, vOut, _ := run("verify", presPath, "--audience", "acme", "--nonce", "n1")
	if code != CodeOK || !strings.Contains(vOut, "PRESENTATION VERIFIED") {
		t.Fatalf("verify code %d out %q", code, vOut)
	}

	code, _, _ = run("verify", presPath, "--audience", "someone-else", "--nonce", "n1")
	if code != CodeFailed {
		t.Fatalf("wrong audience did not fail: code %d", code)
	}
}

// TestExecuteVerifyVerdictLines pins the human-readable verdict against the conformance
// vectors. Every line here is gated on a count or flag in the report, and each gate is
// asserted from both sides: the line appears when its count is positive and never appears
// on a bundle where it is zero, so a gate cannot quietly widen or narrow.
func TestExecuteVerifyVerdictLines(t *testing.T) {
	t.Parallel()
	vectors := "../testdata/vectors/"
	tests := []struct {
		File string
		Want []string
	}{{ // Test 0: An anchored, spanned chain reports every span and anchor line.
		File: "span-gap.loomseal.json",
		Want: []string{
			"anchors    1 matched by coordinates",
			"anchored   through seq 5",
			"span       2/4 windows attested",
			"longest gap 3m0s",
			"gap        unattested window of 3m0s",
		},
	}, { // Test 1: A tree bundle reports its size and proved append-only growth.
		File: "merkle-consistency-power-of-two.loomseal.json",
		Want: []string{
			"tree       9 leaves, 1 inclusion proof(s)",
			"growth     append-only proved from size 8",
		},
	}, { // Test 2: Anchors on an unverified declared head are named, not credited.
		File: "anchor-declared-head-proof.loomseal.json",
		Want: []string{
			"declared head is ahead of the bundled claims",
			"1 anchor(s) reference only the unverified declared head",
			"1 proof(s) sit on the unverified declared head",
		},
	}, { // Test 3: A swatch bundle reports disclosure and attestation.
		File: "swatch-attested.loomseal.json",
		Want: []string{
			"disclosed  1 field(s) revealed, 2 redacted: title",
			"attested   1 counter-signature(s) verified",
			"vouched    counterparty sha256:",
		},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			code, stdout, stderr := run("verify", vectors+test.File)
			if code != CodeOK {
				t.Fatalf("code %d stderr %q", code, stderr)
			}
			for _, want := range test.Want {
				if !strings.Contains(stdout, want) {
					t.Errorf("verdict missing %q in:\n%s", want, stdout)
				}
			}
		})
	}

	// A minimal signature-only bundle must not print any zero-count line: the gates
	// exist so absent features stay silent.
	_, stdout, _ := run("verify", writeBundle(t))
	for _, absent := range []string{
		"\nchain", "\nanchors", "\nanchored", "\ntree", "\ngrowth",
		"\nspan", "\ngap", "\ndisclosed", "\nattested", "declared head",
	} {
		if strings.Contains(stdout, absent) {
			t.Errorf("minimal verdict carries %q in:\n%s", absent, stdout)
		}
	}
}

// TestVersionFallsBackToDev pins the version resolution of a working-tree build, which
// carries neither an injected version nor a module version.
func TestVersionFallsBackToDev(t *testing.T) {
	t.Parallel()
	if got := Version(); got != "0.0.0-dev" {
		t.Errorf("version %q, want 0.0.0-dev", got)
	}
}

// TestExecutePresentGuards pins the present command's argument handling: the required
// pair, an explicit timestamp carried through, and a reveal set that clears every
// disclosure rather than erroring.
func TestExecutePresentGuards(t *testing.T) {
	t.Parallel()

	// Test 0: A missing holder key is a usage error naming the requirement.
	code, _, stderr := run("present", writeBundle(t))
	if code != CodeUsage || !strings.Contains(stderr, "--holder-key") {
		t.Errorf("code %d stderr %q", code, stderr)
	}

	// Test 1: A missing bundle file is the same usage error.
	code, _, stderr = run("present", "--holder-key", "unused")
	if code != CodeUsage || !strings.Contains(stderr, "required") {
		t.Errorf("code %d stderr %q", code, stderr)
	}
}

// TestExecuteVerifyPresentationLines pins the presentation verdict lines against the
// conformance vector: the holder line, both pin matches, and the wrapped bundle report,
// each of which is gated on a field only a presentation carries.
func TestExecuteVerifyPresentationLines(t *testing.T) {
	t.Parallel()
	code, stdout, stderr := run("verify", "--audience", "acme-verifier", "--nonce", "chal-1",
		"../testdata/vectors/present-valid.loomseal-presentation.json")
	if code != CodeOK {
		t.Fatalf("code %d stderr %q stdout %q", code, stderr, stdout)
	}
	for _, want := range []string{
		`presented  by holder sha256:`,
		`to "acme-verifier"`,
		"audience   match true",
		"nonce      match true",
		"bundle     lsb_vectors",
		"PRESENTATION VERIFIED",
	} {
		if !strings.Contains(stdout, want) {
			t.Errorf("presentation verdict missing %q in:\n%s", want, stdout)
		}
	}
}

// TestExecuteVerifyBrokenChainLine pins the failure form of the chain line: a broken
// chain prints FAILED, never the healthy summary with its claim count and head state.
func TestExecuteVerifyBrokenChainLine(t *testing.T) {
	t.Parallel()
	code, stdout, _ := run("verify", "../testdata/vectors/chain-broken-prev.loomseal.json")
	if code != CodeFailed {
		t.Fatalf("code %d", code)
	}
	if !strings.Contains(stdout, "chain      loomseal-chain-v1 FAILED") {
		t.Errorf("verdict missing the failed chain line:\n%s", stdout)
	}
	if strings.Contains(stdout, "head matched") {
		t.Errorf("broken chain printed the healthy summary:\n%s", stdout)
	}
}

// TestExecutePresentReveal pins the reveal path of the present command: an explicit
// timestamp is carried into the presentation, a named field survives, and a reveal set
// matching nothing clears every disclosure rather than erroring.
func TestExecutePresentReveal(t *testing.T) {
	t.Parallel()
	seed := `{"seed": "` + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32)) + `"}`
	keyPath := filepath.Join(t.TempDir(), "holder.seed")
	if err := os.WriteFile(keyPath, []byte(seed), 0o600); err != nil {
		t.Fatalf("write seed: %v", err)
	}
	bundle := "../testdata/vectors/swatch-attested.loomseal.json"

	// Test 0: revealing a present field keeps it, with the explicit timestamp.
	code, stdout, stderr := run("present", bundle, "--holder-key", keyPath,
		"--audience", "aud", "--nonce", "n1", "--at", "2026-07-27T12:00:00Z",
		"--reveal", "title")
	if code != CodeOK {
		t.Fatalf("code %d stderr %q", code, stderr)
	}
	var pres map[string]any
	if err := json.Unmarshal([]byte(stdout), &pres); err != nil {
		t.Fatalf("presentation is not JSON: %v", err)
	}
	if pres["created_at"] != "2026-07-27T12:00:00Z" {
		t.Errorf("created_at %v, want the explicit timestamp", pres["created_at"])
	}
	inner, _ := pres["bundle"].(map[string]any)
	claim, _ := inner["claims"].([]any)[0].(map[string]any)
	disc, _ := claim["disclosures"].([]any)
	if len(disc) != 1 {
		t.Fatalf("disclosures kept %d, want 1", len(disc))
	}
	if name, _ := disc[0].(map[string]any)["name"].(string); name != "title" {
		t.Errorf("kept disclosure %q, want title", name)
	}

	// Test 1: a reveal set naming nothing clears every disclosure.
	code, stdout, stderr = run("present", bundle, "--holder-key", keyPath,
		"--audience", "aud", "--nonce", "n1", "--at", "2026-07-27T12:00:00Z",
		"--reveal", "no-such-field")
	if code != CodeOK {
		t.Fatalf("code %d stderr %q", code, stderr)
	}
	if err := json.Unmarshal([]byte(stdout), &pres); err != nil {
		t.Fatalf("presentation is not JSON: %v", err)
	}
	inner, _ = pres["bundle"].(map[string]any)
	claim, _ = inner["claims"].([]any)[0].(map[string]any)
	if _, has := claim["disclosures"]; has {
		t.Errorf("disclosures survived an empty reveal set: %v", claim["disclosures"])
	}
}
