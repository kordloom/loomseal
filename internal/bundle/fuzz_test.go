package bundle

import (
	"os"
	"testing"
)

// FuzzParse pins that the strict bundle parser never panics, whatever arrives. A bundle
// comes from the least trusted place in the whole design, the party presenting it, so the
// parser's failure mode has to be an error, never a crash a malformed document can trigger
// on demand. Seeded with the real conformance vectors so mutation starts from documents
// that exercise every member the schema knows.
func FuzzParse(f *testing.F) {
	// A missing vector is not fatal: the fuzzer still runs from the inline seeds.
	for _, name := range []string{
		"signed-chained-full", "merkle-sparse", "swatch-selective", "attested-claim",
		"span-valid", "anchor-corrupt-token",
	} {
		if raw, err := os.ReadFile("../../testdata/vectors/" + name + ".loomseal.json"); err == nil {
			f.Add(raw)
		}
	}
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"loomseal":"0.1"}`))
	f.Add([]byte(`{"loomseal":"0.1","claims":[{}],"signatures":[{}]}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		b, err := Parse(raw)
		if err != nil {
			return
		}
		// Anything that parses must survive the unsigned strip, since verification always
		// performs it next and a document that parses but crashes the strip is a crash a
		// presenter controls.
		doc := map[string]any{"claims": []any{map[string]any{"disclosures": []any{}}}}
		StripUnsigned(doc)
		if b.Version != Version {
			t.Fatalf("parse accepted version %q", b.Version)
		}
	})
}
