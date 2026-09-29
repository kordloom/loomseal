package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kordloom/loomseal/internal/bundletest"
)

// TestSelectiveDisclosureEndToEnd attacks selective disclosure with generated bundles, the
// last surface the September audit named as vector-exercised rather than builder-attacked.
//
// The trust model under attack: the producer commits field digests inside the signed link,
// the holder chooses what to reveal, and the verifier must accept exactly the revelations
// that hash to a commitment and nothing else. Every case below is a lie a holder could
// tell with that freedom, plus the honest cases that must keep working, asserted through
// the real CLI on both the verdict and the rendered words.
func TestSelectiveDisclosureEndToEnd(t *testing.T) {
	t.Parallel()

	// two committed fields, one revealed, is the base shape most cases start from.
	base := func() bundletest.Builder {
		return bundletest.Builder{Claims: []bundletest.Claim{{
			Payload: map[string]any{"kind": "measurement"},
			Fields: []bundletest.Field{
				{Name: "score", Value: "65.5", Reveal: true},
				{Name: "customer", Value: "acme", Reveal: false},
			},
		}}}
	}

	tests := []struct {
		Name       string
		Builder    func() bundletest.Builder
		Corrupt    func([]byte) []byte
		WantExit   int
		WantOut    []string
		WantAbsent []string
	}{{ // Test 0: The honest case: one field revealed, one withheld, both counted.
		Name:     "reveal one withhold one",
		Builder:  base,
		WantExit: 0,
		WantOut:  []string{"disclosed  1 field(s) revealed, 1 redacted: score", "VERIFIED"},
	}, { // Test 1: Withholding everything is the holder's right and says so.
		Name: "withhold all",
		Builder: func() bundletest.Builder {
			b := base()
			b.Claims[0].Fields[0].Reveal = false
			return b
		},
		WantExit: 0,
		WantOut:  []string{"disclosed  0 field(s) revealed, 2 redacted", "VERIFIED"},
	}, { // Test 2: A revealed value the producer never committed must fail, not pass as extra.
		Name:    "forged value",
		Builder: base,
		Corrupt: func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"value":"65.5"`), []byte(`"value":"99.9"`), 1)
		},
		WantExit: 1,
		WantOut:  []string{"matches no committed digest", "NOT VERIFIED"},
	}, { // Test 3: The right value under the wrong salt is equally foreign.
		Name:    "forged salt",
		Builder: base,
		Corrupt: func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"salt":"salt-score"`), []byte(`"salt":"salt-wrong"`), 1)
		},
		WantExit: 1,
		WantOut:  []string{"matches no committed digest", "NOT VERIFIED"},
	}, { // Test 4: Renaming a disclosure changes the committed triple and must fail, or a
		// holder could relabel a committed value as a different field.
		Name:    "renamed field",
		Builder: base,
		Corrupt: func(raw []byte) []byte {
			return bytes.Replace(raw, []byte(`"name":"score"`), []byte(`"name":"rating"`), 1)
		},
		WantExit: 1,
		WantOut:  []string{"matches no committed digest", "NOT VERIFIED"},
	}, { // Test 5: The same disclosure presented twice must not count twice.
		Name:    "repeated disclosure",
		Builder: base,
		Corrupt: func(raw []byte) []byte {
			// json.Marshal orders members alphabetically, so the serialized triple is
			// name, salt, value.
			d := []byte(`{"name":"score","salt":"salt-score","value":"65.5"}`)
			return bytes.Replace(raw, append([]byte(`"disclosures":[`), d...),
				append(append([]byte(`"disclosures":[`), d...), append([]byte(","), d...)...), 1)
		},
		WantExit: 1,
		WantOut:  []string{"repeats the same field digest", "NOT VERIFIED"},
	}, { // Test 6: Editing a committed digest after signing breaks the link the _sd rides in,
		// so a holder cannot quietly swap which withheld value was promised.
		Name:    "tampered commitment",
		Builder: base,
		Corrupt: func(raw []byte) []byte {
			old := bundletest.FieldDigest("customer", "acme")
			return bytes.Replace(raw, []byte(old), []byte(strings.Repeat("ab", 32)), 1)
		},
		WantExit:   1,
		WantOut:    []string{"NOT VERIFIED"},
		WantAbsent: []string{"disclosed "},
	}, { // Test 7: A disclosure moved onto a claim that never committed it must fail there.
		Name: "disclosure swapped between claims",
		Builder: func() bundletest.Builder {
			return bundletest.Builder{Claims: []bundletest.Claim{
				{Payload: map[string]any{"kind": "a"}, Fields: []bundletest.Field{
					{Name: "score", Value: "65.5", Reveal: false}}},
				{Payload: map[string]any{"kind": "b"}, Fields: []bundletest.Field{
					{Name: "other", Value: "x", Reveal: false}}},
			}, Mutate: func(doc map[string]any) {
				// The genuine triple for claim 0's committed field, presented by claim 1.
				claims := doc["claims"].([]any)
				claims[1].(map[string]any)["disclosures"] = []any{map[string]any{
					"salt": bundletest.Salt("score"), "name": "score", "value": "65.5"}}
			}}
		},
		WantExit: 1,
		WantOut:  []string{"claim 1 disclosure", "matches no committed digest", "NOT VERIFIED"},
	}, { // Test 8: A duplicate digest inside _sd is a malformed commitment, not two fields.
		Name: "duplicate committed digest",
		Builder: func() bundletest.Builder {
			b := base()
			d := bundletest.FieldDigest("score", "65.5")
			b.Mutate = func(doc map[string]any) {
				claim := doc["claims"].([]any)[0].(map[string]any)
				claim["payload"].(map[string]any)["_sd"] = []any{d, d}
			}
			return b
		},
		WantExit: 1,
		WantOut:  []string{"duplicate digest", "NOT VERIFIED"},
	}, { // Test 9: An _sd entry that is not a digest is refused.
		Name: "malformed commitment entry",
		Builder: func() bundletest.Builder {
			b := base()
			b.Mutate = func(doc map[string]any) {
				claim := doc["claims"].([]any)[0].(map[string]any)
				claim["payload"].(map[string]any)["_sd"] = []any{"not-a-digest"}
			}
			return b
		},
		WantExit: 1,
		WantOut:  []string{"not a 64 hex digest", "NOT VERIFIED"},
	}, { // Test 10: An incomplete disclosure is refused rather than skipped.
		Name: "incomplete disclosure",
		Builder: func() bundletest.Builder {
			b := base()
			b.Mutate = func(doc map[string]any) {
				claim := doc["claims"].([]any)[0].(map[string]any)
				claim["disclosures"] = []any{map[string]any{"name": "score"}}
			}
			return b
		},
		WantExit: 1,
		WantOut:  []string{"incomplete", "NOT VERIFIED"},
	}}

	for testNum, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			raw, err := test.Builder().Build()
			if err != nil {
				t.Fatalf("test %d: build: %v", testNum, err)
			}
			if test.Corrupt != nil {
				mutated := test.Corrupt(raw)
				if bytes.Equal(mutated, raw) {
					t.Fatalf("test %d: corruption did not change the document", testNum)
				}
				raw = mutated
			}
			path := filepath.Join(t.TempDir(), "bundle.loomseal.json")
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatalf("test %d: write: %v", testNum, err)
			}
			var stdout, stderr bytes.Buffer
			code := Execute([]string{"verify", path}, &stdout, &stderr)
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
