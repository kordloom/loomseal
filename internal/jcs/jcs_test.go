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
