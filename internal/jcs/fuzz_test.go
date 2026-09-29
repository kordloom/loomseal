package jcs

import (
	"bytes"
	"testing"
)

// FuzzCanonicalize drives the canonicalizer with arbitrary input and holds it to the property
// every signature depends on: canonicalizing is idempotent. A signature is computed over the
// canonical bytes, so an input that canonicalizes two different ways is an input where a
// verifier and a signer can disagree about what was signed. Panics are failures too, because a
// verifier that crashes on a hostile bundle is a verifier that cannot render a verdict.
func FuzzCanonicalize(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`{"b":1,"a":2}`))
	f.Add([]byte(`{"a":{"nested":[1,2,{"z":null}]}}`))
	f.Add([]byte(`{"k":"😀"}`))
	f.Add([]byte(`{"n":9007199254740991}`))
	f.Add([]byte(`[true,false,null,""]`))
	f.Add([]byte(`{"dup":1,"dup":2}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		once, err := Canonicalize(raw)
		if err != nil {
			return
		}
		twice, err := Canonicalize(once)
		if err != nil {
			t.Fatalf("canonical output failed to canonicalize: %v\ninput %q\nonce %q", err, raw, once)
		}
		if !bytes.Equal(once, twice) {
			t.Fatalf("canonicalize is not idempotent:\ninput %q\nonce  %q\ntwice %q", raw, once, twice)
		}
	})
}
