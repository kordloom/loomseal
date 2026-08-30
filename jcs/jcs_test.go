package jcs

import (
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestCanonicalize(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In         string
		WantResult string
		Want       error
	}{{ // Test 0: Null passes through.
		In: `null`, WantResult: `null`,
	}, { // Test 1: Booleans.
		In: `true`, WantResult: `true`,
	}, { // Test 2: Plain integer.
		In: `10`, WantResult: `10`,
	}, { // Test 3: Negative zero collapses to zero.
		In: `-0`, WantResult: `0`,
	}, { // Test 4: Largest safe integer is allowed.
		In: `9007199254740992`, WantResult: `9007199254740992`,
	}, { // Test 5: Smallest safe integer is allowed.
		In: `-9007199254740992`, WantResult: `-9007199254740992`,
	}, { // Test 6: Beyond 2^53 is rejected.
		In: `9007199254740993`, Want: ErrNumber,
	}, { // Test 7: Fractions are rejected.
		In: `1.5`, Want: ErrNumber,
	}, { // Test 8: Exponent literals are rejected.
		In: `1e3`, Want: ErrNumber,
	}, { // Test 9: Oversized literals are rejected.
		In: `18446744073709551616`, Want: ErrNumber,
	}, { // Test 10: An escaped quote re-serializes the same way.
		In: `"A\""`, WantResult: `"A\""`,
	}, { // Test 11: Named control escapes round-trip as shorthands.
		In: `"\b\t\n\f\r"`, WantResult: `"\b\t\n\f\r"`,
	}, { // Test 12: Other control characters use lowercase hex.
		In: `"\u001F"`, WantResult: `"\u001f"`,
	}, { // Test 13: Non-ASCII stays literal UTF-8.
		In: `"€"`, WantResult: `"€"`,
	}, { // Test 14: An escaped slash becomes a plain slash.
		In: `"\/"`, WantResult: `"/"`,
	}, { // Test 15: Keys sort by UTF-16 code units, digits and controls included.
		In: `{"10":1,"1":2,"\r":3}`, WantResult: `{"\r":3,"1":2,"10":1}`,
	}, { // Test 16: A surrogate-pair key sorts before U+FFFD by its first UTF-16 unit.
		In: `{"�":1,"😀":2}`, WantResult: `{"😀":2,"�":1}`,
	}, { // Test 17: Duplicate keys are rejected.
		In: `{"a":1,"a":2}`, Want: ErrParse,
	}, { // Test 18: Trailing data is rejected.
		In: `{} {}`, Want: ErrParse,
	}, { // Test 19: Whitespace is stripped and nesting holds.
		In: ` { "b" : [ 1 , { "a" : null } ] , "a" : [ ] } `, WantResult: `{"a":[],"b":[1,{"a":null}]}`,
	}, { // Test 20: Empty input is rejected.
		In: ``, Want: ErrParse,
	}, { // Test 21: Truncated input is rejected.
		In: `{`, Want: ErrParse,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got, err := Canonicalize([]byte(test.In))
			if !errors.Is(err, test.Want) {
				t.Fatalf("error mismatch: got %v, want %v", err, test.Want)
			}
			if test.Want != nil {
				return
			}
			if diff := cmp.Diff(test.WantResult, string(got)); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestValidateStrings(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In         string
		WantResult string
		Want       error
	}{{ // Test 0: A literal astral character passes and stays literal UTF-8.
		In: `"😀"`, WantResult: `"😀"`,
	}, { // Test 1: A well-formed surrogate pair escape decodes to its code point.
		In: `"\uD83D\uDE00"`, WantResult: `"😀"`,
	}, { // Test 2: A lone high surrogate escape is rejected.
		In: `"\uD800"`, Want: ErrString,
	}, { // Test 3: A lone low surrogate escape is rejected.
		In: `"\uDFFF"`, Want: ErrString,
	}, { // Test 4: A high surrogate followed by a non-low escape is rejected.
		In: `"\uD800\u0041"`, Want: ErrString,
	}, { // Test 5: A high surrogate followed by a literal is rejected.
		In: `"\uD800A"`, Want: ErrString,
	}, { // Test 6: A truncated escape is rejected.
		In: `"\uD80"`, Want: ErrString,
	}, { // Test 7: Raw invalid UTF-8 is rejected.
		In: "\"demo\xed\xa0\x80yard\"", Want: ErrString,
	}, { // Test 8: An escaped backslash leaves the following uXXXX as literal text.
		In: `"\\uD800"`, WantResult: `"\\uD800"`,
	}, { // Test 9: A plain BMP escape passes and re-serializes as literal UTF-8.
		In: `"A"`, WantResult: `"A"`,
	}, { // Test 10: The replacement character escape is valid and stays literal.
		In: `"\uFFFD"`, WantResult: `"�"`,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got, err := Canonicalize([]byte(test.In))
			if !errors.Is(err, test.Want) {
				t.Fatalf("error mismatch: got %v, want %v", err, test.Want)
			}
			if test.Want != nil {
				return
			}
			if diff := cmp.Diff(test.WantResult, string(got)); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSerializeGoValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In         any
		WantResult string
		Want       error
	}{{ // Test 0: Go ints serialize as integers.
		In: map[string]any{"n": 7}, WantResult: `{"n":7}`,
	}, { // Test 1: Integral float64 is accepted.
		In: map[string]any{"n": float64(3)}, WantResult: `{"n":3}`,
	}, { // Test 2: Fractional float64 is rejected.
		In: map[string]any{"n": 3.5}, Want: ErrNumber,
	}, { // Test 3: Unsupported types are rejected.
		In: map[string]any{"n": complex(1, 1)}, Want: ErrType,
	}, { // Test 4: int64 beyond the bound is rejected.
		In: int64(1) << 54, Want: ErrNumber,
	}, { // Test 5: A string value that is not valid UTF-8 is rejected, not emitted as U+FFFD.
		In: map[string]any{"s": string([]byte{0xff, 0xfe})}, Want: ErrString,
	}, { // Test 6: An object key that is not valid UTF-8 is rejected.
		In: map[string]any{string([]byte{0xff}): "x"}, Want: ErrString,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got, err := Serialize(test.In)
			if !errors.Is(err, test.Want) {
				t.Fatalf("error mismatch: got %v, want %v", err, test.Want)
			}
			if test.Want != nil {
				return
			}
			if diff := cmp.Diff(test.WantResult, string(got)); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestValidateStringsEscapeEdges pins the escape-decoding corners the main table leaves
// open: lowercase hex digits, the exact boundaries of the low surrogate range, and an
// escape truncated at the end of input. Every escape in the main table is uppercase, so
// without these the lowercase decode path never runs under test at all.
func TestValidateStringsEscapeEdges(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In         string
		WantResult string
		Want       error
	}{{ // Test 0: A lowercase surrogate pair decodes to its code point.
		In: `"\ud83d\ude00"`, WantResult: `"😀"`,
	}, { // Test 1: A lowercase lone low surrogate is rejected.
		In: `"\udfff"`, Want: ErrString,
	}, { // Test 2: The lowest legal pair decodes to U+10000.
		In: `"\uD800\uDC00"`, WantResult: `"𐀀"`,
	}, { // Test 3: The highest legal pair decodes to U+10FFFF.
		In: `"\uDBFF\uDFFF"`, WantResult: `"􏿿"`,
	}, { // Test 4: A high surrogate paired one below the low range is rejected.
		In: `"\uD800\uDBFF"`, Want: ErrString,
	}, { // Test 5: Mixed-case hex digits decode like either case alone.
		In: `"\uD83d\udE00"`, WantResult: `"😀"`,
	}, { // Test 6: A backslash as the final byte is a dangling escape, not a scan past the end.
		In: `"\`, Want: ErrString,
	}, { // Test 7: A lowercase BMP escape decodes to its literal character.
		In: `"\u00e9"`, WantResult: `"é"`,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got, err := Canonicalize([]byte(test.In))
			if !errors.Is(err, test.Want) {
				t.Fatalf("error mismatch: got %v, want %v", err, test.Want)
			}
			if test.Want != nil {
				return
			}
			if diff := cmp.Diff(test.WantResult, string(got)); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestCanonicalizeHexBoundaries pins the hex-digit ranges of escape decoding at their
// exact edges, and the UTF-16 key ordering RFC 8785 requires. The digit ranges are three
// two-sided comparisons a passing suite of mid-range digits leaves entirely unpinned.
func TestCanonicalizeHexBoundaries(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In         string
		WantResult string
		Want       error
	}{{ // Test 0: The a and f digit boundaries decode.
		In: `"\u00af"`, WantResult: `"¯"`,
	}, { // Test 1: The A and F digit boundaries decode.
		In: `"\u00AF"`, WantResult: `"¯"`,
	}, { // Test 2: The 0 and 9 digit boundaries decode.
		In: `"\u0909"`, WantResult: `"उ"`,
	}, { // Test 3: A digit just past f is rejected.
		In: `"\u00g0"`, Want: ErrString,
	}, { // Test 4: Keys sort by UTF-16 code units, as RFC 8785 requires: the astral
		// key's high surrogate D834 sorts before the BMP key FB33, so the astral
		// key stays first even though its code point is lower.
		In:         `{"𝌆":1,"דּ":2}`,
		WantResult: `{"𝌆":1,"דּ":2}`,
	}, { // Test 5: A strict prefix sorts first, and keys agreeing on their first
		// unit are ordered by the unit after it.
		In:         `{"ab":3,"aa":2,"a":1}`,
		WantResult: `{"a":1,"aa":2,"ab":3}`,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got, err := Canonicalize([]byte(test.In))
			if !errors.Is(err, test.Want) {
				t.Fatalf("error mismatch: got %v, want %v", err, test.Want)
			}
			if test.Want != nil {
				return
			}
			if diff := cmp.Diff(test.WantResult, string(got)); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestUTF16LessContract pins the comparator directly. Sorting can luck into the right
// order under an inconsistent comparator, so the ordering test alone cannot hold these:
// equal prefixes must defer to the next unit, and a string never sorts before itself.
func TestUTF16LessContract(t *testing.T) {
	t.Parallel()
	tests := []struct {
		A, B string
		Want bool
	}{{ // Test 0: Equal first units defer to the second.
		A: "ab", B: "aa", Want: false,
	}, { // Test 1: The mirror image orders the other way.
		A: "aa", B: "ab", Want: true,
	}, { // Test 2: A string does not sort before itself.
		A: "aa", B: "aa", Want: false,
	}, { // Test 3: A strict prefix sorts first.
		A: "a", B: "ab", Want: true,
	}, { // Test 4: The longer string never sorts before its own prefix.
		A: "ab", B: "a", Want: false,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			if got := utf16Less(test.A, test.B); got != test.Want {
				t.Errorf("utf16Less(%q, %q) = %t, want %t", test.A, test.B, got, test.Want)
			}
		})
	}
}
