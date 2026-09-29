package jcs

import (
	"bytes"
	"testing"
)

// FuzzCanonicalize pins the property everything downstream rests on: canonicalization is a
// fixed point. Whatever bytes arrive, either they are rejected or they canonicalize to a
// form that canonicalizes to itself, byte for byte. Two documents sharing a canonical form
// share a signature, so a canonical form that drifted under re-canonicalization would let
// one signature cover two documents, which is the exact failure the surrogate and
// duplicate-key rejections exist to prevent.
//
// Runs as a unit test over the seed corpus in CI; go test -fuzz=FuzzCanonicalize ./jcs
// explores from there.
func FuzzCanonicalize(f *testing.F) {
	seeds := []string{
		`{}`, `[]`, `null`, `true`, `0`, `-0`, `9007199254740992`,
		`{"b":1,"a":2}`, `{"a":{"b":[1,2,{"c":null}]}}`,
		`"A"`, `"😀"`, `"line\nbreak\ttab"`,
		`{"€":"literal","€":"escaped"}`,
		`{"loomseal":"0.1","claims":[{"type":"t.c/1","at":"2026-01-01T00:00:00Z"}]}`,
		`{"a":1,"a":2}`, `"\ud800"`, `"\udc00"`, `1.5`, `1e3`, `01`, `{`, `"\u12`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		c1, err := Canonicalize(raw)
		if err != nil {
			return
		}
		c2, err := Canonicalize(c1)
		if err != nil {
			t.Fatalf("canonical form rejected by its own canonicalizer: %v\ninput: %q\ncanonical: %q",
				err, raw, c1)
		}
		if !bytes.Equal(c1, c2) {
			t.Fatalf("canonicalization is not a fixed point\ninput: %q\nfirst: %q\nsecond: %q",
				raw, c1, c2)
		}
	})
}
