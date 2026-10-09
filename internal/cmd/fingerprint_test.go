package cmd

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"

	"github.com/kordloom/loomseal/seal"
)

// writeBundleKeyID returns the fingerprint of the key writeBundle signs with.
func writeBundleKeyID(t *testing.T) string {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{9}, 32))
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("public key type")
	}
	return seal.KeyID(pub)
}

// TestExecuteVerifyFingerprintForm pins that a pin the caller passed is held to the one form a key
// fingerprint takes, before anything is verified. An explicit empty pin, which is what
// --fingerprint "$PIN" sends when the variable is unset, read as no pin at all would print VERIFIED
// with exit code 0, the same outcome as a matched pin, and automation keying on the exit code would
// accept a bundle from any key.
func TestExecuteVerifyFingerprintForm(t *testing.T) {
	t.Parallel()
	hex64 := strings.Repeat("0", 64)
	keyID := writeBundleKeyID(t)
	tests := []struct {
		Before     []string
		After      []string
		WantCode   int
		WantStdout string
		WantStderr string
	}{{ // Test 0: An explicit empty pin is a usage error, not an unpinned run.
		Before:   []string{"--fingerprint", ""},
		WantCode: CodeUsage, WantStderr: "--fingerprint: fingerprint is not sha256:",
	}, { // Test 1: The same pin written with an equals sign.
		Before:   []string{"--fingerprint="},
		WantCode: CodeUsage, WantStderr: "--fingerprint: fingerprint is not sha256:",
	}, { // Test 2: The flag placed after the file is still a pin.
		After:    []string{"--fingerprint", ""},
		WantCode: CodeUsage, WantStderr: "--fingerprint: fingerprint is not sha256:",
	}, { // Test 3: An empty pin with --json emits no report at all.
		Before:   []string{"--json", "--fingerprint", ""},
		WantCode: CodeUsage, WantStderr: "--fingerprint: fingerprint is not sha256:",
	}, { // Test 4: The prefix alone names no key.
		Before:   []string{"--fingerprint", "sha256:"},
		WantCode: CodeUsage, WantStderr: `"sha256:"`,
	}, { // Test 5: An uppercase prefix is not the form a key id takes.
		Before:   []string{"--fingerprint", "SHA256:" + hex64},
		WantCode: CodeUsage, WantStderr: "fingerprint is not sha256:",
	}, { // Test 6: Bare hex without the prefix.
		Before:   []string{"--fingerprint", hex64},
		WantCode: CodeUsage, WantStderr: "fingerprint is not sha256:",
	}, { // Test 7: A well-formed pin that names another key fails the bundle.
		Before:   []string{"--fingerprint", "sha256:" + hex64},
		WantCode: CodeFailed, WantStdout: "NOT VERIFIED",
	}, { // Test 8: A well-formed matching pin verifies and reports the match.
		Before:   []string{"--fingerprint", keyID},
		WantCode: CodeOK, WantStdout: "pin        match true",
	}, { // Test 9: No flag at all is the unpinned run, and the report says so.
		WantCode: CodeOK, WantStdout: "pin        NONE",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			args := append([]string{"verify"}, test.Before...)
			args = append(args, writeBundle(t))
			args = append(args, test.After...)
			code, stdout, stderr := run(args...)
			if code != test.WantCode {
				t.Errorf("code %d, want %d; stdout %q stderr %q", code, test.WantCode, stdout, stderr)
			}
			if !strings.Contains(stdout, test.WantStdout) {
				t.Errorf("stdout missing %q:\n%s", test.WantStdout, stdout)
			}
			if !strings.Contains(stderr, test.WantStderr) {
				t.Errorf("stderr missing %q:\n%s", test.WantStderr, stderr)
			}
			if code == CodeUsage && stdout != "" {
				t.Errorf("a usage error printed a report:\n%s", stdout)
			}
		})
	}
}

// TestExecuteVerifyUnpinnedFinalWord pins the final word of an unpinned pass. The command line and
// the browser page render the same report, and the page's renderer is held to the same word in its
// own self-test, so a reader comparing the two surfaces sees one verdict for one file. The
// qualification an unpinned run carries is the pin NONE line above the word, not a different word.
func TestExecuteVerifyUnpinnedFinalWord(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Pin         string
		WantPinNone bool
	}{{ // Test 0: Unpinned, so the word is qualified by the notice and nothing else.
		WantPinNone: true,
	}, { // Test 1: Pinned, so the same word stands alone.
		Pin: writeBundleKeyID(t), WantPinNone: false,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			args := []string{"verify", writeBundle(t)}
			if test.Pin != "" {
				args = append(args, "--fingerprint", test.Pin)
			}
			code, stdout, _ := run(args...)
			if code != CodeOK {
				t.Fatalf("code %d:\n%s", code, stdout)
			}
			lines := strings.Split(strings.TrimRight(stdout, "\n"), "\n")
			if last := lines[len(lines)-1]; last != "VERIFIED   signed" {
				t.Errorf("final line %q, want %q", last, "VERIFIED   signed")
			}
			notice := "pin        NONE, so this says the bundle was signed, not who signed it"
			if got := strings.Contains(stdout, notice); got != test.WantPinNone {
				t.Errorf("pin NONE present %t, want %t:\n%s", got, test.WantPinNone, stdout)
			}
		})
	}
}

// TestExecuteVerifyExpectationForm pins that an expected audience or nonce the caller passed empty
// is a usage error, as an empty pin is. --nonce "$NONCE" with the variable unset read as no nonce
// would print PRESENTATION VERIFIED with exit code 0, the outcome of a checked run, and the replay
// defense would be off without the exit code saying so.
func TestExecuteVerifyExpectationForm(t *testing.T) {
	t.Parallel()
	presentation := "../../testdata/vectors/present-valid.loomseal-presentation.json"
	tests := []struct {
		Before     []string
		After      []string
		File       string
		WantCode   int
		WantStdout string
		WantStderr string
	}{{ // Test 0: An explicit empty nonce is a usage error, not an unchecked run.
		Before: []string{"--audience", "acme-verifier", "--nonce", ""}, File: presentation,
		WantCode: CodeUsage, WantStderr: "--nonce: expected value is empty",
	}, { // Test 1: An explicit empty audience is refused the same way.
		Before: []string{"--audience", "", "--nonce", "chal-1"}, File: presentation,
		WantCode: CodeUsage, WantStderr: "--audience: expected value is empty",
	}, { // Test 2: Both empty, the shape of two unset variables.
		Before: []string{"--nonce", "", "--audience", ""}, File: presentation,
		WantCode: CodeUsage, WantStderr: "expected value is empty",
	}, { // Test 3: The equals form.
		Before: []string{"--nonce="}, File: presentation,
		WantCode: CodeUsage, WantStderr: "--nonce: expected value is empty",
	}, { // Test 4: The flag placed after the file is still an expectation.
		After: []string{"--nonce", ""}, File: presentation,
		WantCode: CodeUsage, WantStderr: "--nonce: expected value is empty",
	}, { // Test 5: With --json no report is emitted.
		Before: []string{"--json", "--audience", ""}, File: presentation,
		WantCode: CodeUsage, WantStderr: "--audience: expected value is empty",
	}, { // Test 6: Refused before the file is read, so a bundle gets the same answer.
		Before:   []string{"--nonce", ""},
		WantCode: CodeUsage, WantStderr: "--nonce: expected value is empty",
	}, { // Test 7: Matching expectations verify and report both matches.
		Before: []string{"--audience", "acme-verifier", "--nonce", "chal-1"}, File: presentation,
		WantCode: CodeOK, WantStdout: "nonce      match true",
	}, { // Test 8: A stale nonce fails the presentation.
		Before: []string{"--audience", "acme-verifier", "--nonce", "old-nonce"}, File: presentation,
		WantCode: CodeFailed, WantStdout: "nonce      match false",
	}, { // Test 9: No flags is the unchecked run, and the report says the nonce was not checked.
		File:     presentation,
		WantCode: CodeOK, WantStdout: "NOT CHECKED",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			file := test.File
			if file == "" {
				file = writeBundle(t)
			}
			args := append([]string{"verify"}, test.Before...)
			args = append(args, file)
			args = append(args, test.After...)
			code, stdout, stderr := run(args...)
			if code != test.WantCode {
				t.Errorf("code %d, want %d; stdout %q stderr %q", code, test.WantCode, stdout, stderr)
			}
			if !strings.Contains(stdout, test.WantStdout) {
				t.Errorf("stdout missing %q:\n%s", test.WantStdout, stdout)
			}
			if !strings.Contains(stderr, test.WantStderr) {
				t.Errorf("stderr missing %q:\n%s", test.WantStderr, stderr)
			}
			if code == CodeUsage && stdout != "" {
				t.Errorf("a usage error printed a report:\n%s", stdout)
			}
		})
	}
}
