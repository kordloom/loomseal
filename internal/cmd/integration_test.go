package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kordloom/loomseal/internal/bundletest"
)

// TestVerifyEndToEnd runs whole verifications through Execute, the same entry point main
// dispatches to, and asserts on the exit code and the rendered words together.
//
// The September audit found five defects and every one lived between what the verifier
// checked and what it said, so a suite that asserts only on verdicts re-opens the gap all
// five came through. Each case here pins the sentence a reader acts on, and the absence of
// a sentence that would argue against the verdict beside it. Extending the suite is one
// more table row: build a bundle with bundletest, name the flags, and say what the output
// must and must not contain.
func TestVerifyEndToEnd(t *testing.T) {
	t.Parallel()

	producerPin := bundletest.KeyID(0x42)
	attestorPin := bundletest.KeyID(0x77)

	tests := []struct {
		Name string
		// Builder shapes the bundle under test.
		Builder bundletest.Builder
		// Present, when set, wraps the bundle in a holder presentation for this audience
		// and nonce before it is written.
		PresentAudience string
		PresentNonce    string
		// Corrupt, when set, edits the serialized file after signing, modeling a holder
		// who tampers rather than a producer who lies.
		Corrupt func([]byte) []byte
		// EvidenceContent, when set, is written beside the bundle under evidence.bin and
		// the bundle's single claim references it. EvidenceOnDisk is what actually lands
		// in the file, so a mismatch models an altered artifact.
		EvidenceContent string
		EvidenceOnDisk  string
		// Flags are appended to the verify invocation.
		Flags []string
		// WantExit is the exact exit code.
		WantExit int
		// WantOut are substrings the output must contain.
		WantOut []string
		// WantAbsent are substrings the output must not contain.
		WantAbsent []string
	}{{ // Test 0: A clean unpinned pass says the signer went unchecked.
		Name:     "unpinned pass discloses the unchecked signer",
		WantExit: 0,
		WantOut:  []string{"VERIFIED", "pin        NONE"},
	}, { // Test 1: A correct pin upgrades the same bundle to an identified pass.
		Name:       "pinned pass reports the match and drops the notice",
		Flags:      []string{"--fingerprint", producerPin},
		WantExit:   0,
		WantOut:    []string{"VERIFIED", "pin        match true"},
		WantAbsent: []string{"pin        NONE"},
	}, { // Test 2: A wrong pin is a failure, not a note.
		Name:     "mismatched pin fails",
		Flags:    []string{"--fingerprint", "sha256:" + strings.Repeat("ab", 32)},
		WantExit: 1,
		WantOut:  []string{"NOT VERIFIED", "does not match pinned fingerprint"},
	}, { // Test 3: Payload tampering after signing breaks the signature, and no passing-state
		// notice softens the failure.
		Name: "tampered payload fails without reassurance",
		Corrupt: func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"n":1`), []byte(`"n":9`), 1)
		},
		WantExit:   1,
		WantOut:    []string{"NOT VERIFIED"},
		WantAbsent: []string{"pin        NONE"},
	}, { // Test 4: An altered artifact at its declared location is ALTERED, not missing.
		Name:            "altered evidence fails on its own line",
		EvidenceContent: "sealed bytes",
		EvidenceOnDisk:  "edited bytes",
		WantExit:        1,
		WantOut:         []string{"ALTERED", "NOT VERIFIED"},
		WantAbsent:      []string{"1 missing"},
	}, { // Test 5: Matching evidence verifies and counts.
		Name:            "matching evidence verifies",
		EvidenceContent: "sealed bytes",
		EvidenceOnDisk:  "sealed bytes",
		WantExit:        0,
		WantOut:         []string{"evidence   1 verified, 0 missing", "VERIFIED"},
	}, { // Test 6: A counter-signed bundle without --attestor says the signer went unchecked.
		Name: "unpinned attestation discloses itself",
		Builder: bundletest.Builder{Claims: []bundletest.Claim{
			{AttestSeeds: []byte{0x77}},
		}},
		WantExit: 0,
		WantOut:  []string{"NOT CHECKED against expected signers", "VERIFIED"},
	}, { // Test 7: Naming the expected attestor accepts it and drops the notice.
		Name: "expected attestor vouches",
		Builder: bundletest.Builder{Claims: []bundletest.Claim{
			{AttestSeeds: []byte{0x77}},
		}},
		Flags:      []string{"--attestor", attestorPin},
		WantExit:   0,
		WantOut:    []string{"vouched", "VERIFIED"},
		WantAbsent: []string{"NOT CHECKED against expected signers"},
	}, { // Test 8: A counter-signature from anyone else fails once expectations are named.
		Name: "unexpected attestor fails",
		Builder: bundletest.Builder{Claims: []bundletest.Claim{
			{AttestSeeds: []byte{0x33}},
		}},
		Flags:    []string{"--attestor", attestorPin},
		WantExit: 1,
		WantOut:  []string{"not among the expected attestors", "NOT VERIFIED"},
	}, { // Test 9: An unchallenged presentation names the replay risk and shows the nonce.
		Name:            "unchallenged presentation discloses itself",
		PresentAudience: "acme", PresentNonce: "chal-1",
		WantExit: 0,
		WantOut: []string{"PRESENTATION VERIFIED", `nonce      "chal-1", NOT CHECKED`,
			"audience   NOT CHECKED"},
	}, { // Test 10: Demanding the right audience and nonce reports both matches.
		Name:            "challenged presentation matches",
		PresentAudience: "acme", PresentNonce: "chal-1",
		Flags:      []string{"--audience", "acme", "--nonce", "chal-1"},
		WantExit:   0,
		WantOut:    []string{"audience   match true", "nonce      match true"},
		WantAbsent: []string{"NOT CHECKED"},
	}, { // Test 11: A replayed nonce fails.
		Name:            "wrong nonce fails the presentation",
		PresentAudience: "acme", PresentNonce: "chal-1",
		Flags:    []string{"--audience", "acme", "--nonce", "chal-2"},
		WantExit: 1,
		WantOut:  []string{"PRESENTATION NOT VERIFIED"},
	}, { // Test 12: An unknown format version is refused as unsupported, not judged.
		Name: "unknown version fails closed",
		Corrupt: func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"loomseal":"0.1"`), []byte(`"loomseal":"9.9"`), 1)
		},
		WantExit:   3,
		WantOut:    []string{"UNSUPPORTED"},
		WantAbsent: []string{"signature  FAILED"},
	}, { // Test 13: A duplicate key injected after signing is rejected by the canonicalizer.
		Name: "duplicate key injection fails",
		Corrupt: func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"bundle_id":`),
				[]byte(`"bundle_id":"lsb_lie","bundle_id":`), 1)
		},
		WantExit: 1,
		WantOut:  []string{"duplicate object key", "NOT VERIFIED"},
	}, { // Test 14: Garbage is a failed verification, not a crash.
		Name:     "garbage input fails cleanly",
		Corrupt:  func([]byte) []byte { return []byte("not json at all") },
		WantExit: 1,
		WantOut:  []string{"NOT VERIFIED"},
	}}

	for testNum, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			b := test.Builder
			if test.EvidenceContent != "" {
				ev, err := bundletest.Evidence(dir, "evidence.bin", []byte(test.EvidenceOnDisk))
				if err != nil {
					t.Fatalf("test %d: evidence: %v", testNum, err)
				}
				// The entry's digest must commit to the sealed content, whatever the disk holds.
				ev["digest"] = digestOf(test.EvidenceContent)
				b.Claims = []bundletest.Claim{{Evidence: []map[string]any{ev}}}
			}
			raw, err := b.Build()
			if err != nil {
				t.Fatalf("test %d: build: %v", testNum, err)
			}
			if test.PresentAudience != "" {
				if raw, err = bundletest.Present(raw, 0x11, test.PresentAudience, test.PresentNonce); err != nil {
					t.Fatalf("test %d: present: %v", testNum, err)
				}
			}
			if test.Corrupt != nil {
				raw = test.Corrupt(raw)
			}
			path := filepath.Join(dir, "bundle.loomseal.json")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatalf("test %d: write: %v", testNum, err)
			}

			args := append([]string{"verify", path, "--evidence", dir}, test.Flags...)
			var stdout, stderr bytes.Buffer
			code := Execute(args, &stdout, &stderr)
			out := stdout.String() + stderr.String()

			if code != test.WantExit {
				t.Errorf("test %d: exit = %d, want %d\n%s", testNum, code, test.WantExit, out)
			}
			for _, want := range test.WantOut {
				if !strings.Contains(out, want) {
					t.Errorf("test %d: output lacks %q\n%s", testNum, want, out)
				}
			}
			for _, absent := range test.WantAbsent {
				if strings.Contains(out, absent) {
					t.Errorf("test %d: output must not contain %q\n%s", testNum, absent, out)
				}
			}
		})
	}
}

// TestVerifyJSONContract pins the machine-facing fields a pipeline gates on, through the
// same entry point a pipeline calls. The wasm build marshals the identical report, so this
// is also the contract the browser page renders from.
func TestVerifyJSONContract(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path, err := bundletest.Builder{}.WriteTo(dir)
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := Execute([]string{"verify", path, "--json"}, &stdout, &stderr); code != 0 {
		t.Fatalf("exit = %d: %s", code, stderr.String())
	}
	var report map[string]any
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatalf("report is not JSON: %v", err)
	}
	// Fields a consumer is entitled to find. producer_pinned in particular must be present
	// even when false, since its absence is what let an unpinned pass read as an identified
	// one.
	for _, field := range []string{"ok", "level", "signature_ok", "producer_pinned",
		"chain_ok", "claims_checked"} {
		if _, ok := report[field]; !ok {
			t.Errorf("report lacks %q: %s", field, stdout.String())
		}
	}
	if report["ok"] != true || report["producer_pinned"] != false {
		t.Errorf("unpinned pass: ok=%v producer_pinned=%v", report["ok"], report["producer_pinned"])
	}
}

// TestVerifyUsageErrors pins the usage exit code for the ways a caller holds it wrong.
func TestVerifyUsageErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name string
		Args []string
	}{{ // Test 0: No file at all.
		Name: "no file", Args: []string{"verify"},
	}, { // Test 1: A file that does not exist.
		Name: "missing file", Args: []string{"verify", "/nonexistent/nope.json"},
	}, { // Test 2: Two files.
		Name: "two files", Args: []string{"verify", "a.json", "b.json"},
	}}
	for testNum, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if code := Execute(test.Args, &stdout, &stderr); code != CodeUsage {
				t.Errorf("test %d: exit = %d, want %d", testNum, code, CodeUsage)
			}
		})
	}
}

// digestOf returns the sha256: digest of a string, for evidence entries whose sealed
// content deliberately differs from the file on disk.
func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}
