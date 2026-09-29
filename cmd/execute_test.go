package cmd

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
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
			"type": "dormouse.check/1", "at": "2026-07-27T12:00:00Z",
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
	if code != CodeOK || !strings.Contains(stdout, Version) {
		t.Errorf("version: code %d stdout %q", code, stdout)
	}
}
