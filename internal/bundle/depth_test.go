package bundle

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// TestCheckDepth holds documents to MaxDepth, counting arrays and objects alike and ignoring
// brackets inside strings.
func TestCheckDepth(t *testing.T) {
	t.Parallel()
	arrays := func(n int) string { return strings.Repeat("[", n) + strings.Repeat("]", n) }
	objects := func(n int) string {
		return strings.Repeat(`{"a":`, n-1) + "{}" + strings.Repeat("}", n-1)
	}
	tests := []struct {
		Want error
		In   string
	}{{ // Test 0: A flat object is within the bound.
		In: `{"a":1}`,
	}, { // Test 1: Arrays nested exactly to the bound are accepted.
		In: arrays(MaxDepth),
	}, { // Test 2: Arrays nested one level past the bound are refused.
		In: arrays(MaxDepth + 1), Want: ErrParse,
	}, { // Test 3: Objects count as levels exactly as arrays do.
		In: objects(MaxDepth + 1), Want: ErrParse,
	}, { // Test 4: Brackets inside a string are text and do not count.
		In: `{"a":"` + strings.Repeat("[", MaxDepth+1) + `"}`,
	}, { // Test 5: An escaped quote does not end the string, so the brackets after it are text.
		In: `{"a":"\"` + strings.Repeat("[", MaxDepth+1) + `"}`,
	}, { // Test 6: An escaped backslash ends its escape, so the closing quote ends the string.
		In: `["\\",` + arrays(MaxDepth) + `]`, Want: ErrParse,
	}, { // Test 7: Depth is the deepest point, not the count of containers in sequence.
		In: "[" + strings.Repeat(arrays(MaxDepth-1)+",", 3) + "0]",
	}, { // Test 8: Empty input is within the bound.
		In: "",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			if err := CheckDepth([]byte(test.In), MaxDepth); !errors.Is(err, test.Want) {
				t.Errorf("error mismatch: got %v, want %v", err, test.Want)
			}
		})
	}
}

// TestParseRefusesDepth holds Parse to MaxDepth before it decodes, counting the bundle itself as
// the first level.
func TestParseRefusesDepth(t *testing.T) {
	t.Parallel()
	// envelope is the nesting above the payload member: the bundle, claims, the claim, and payload.
	const envelope = 4
	tests := []struct {
		Want  error
		Depth int
	}{{ // Test 0: A bundle nested exactly to the bound parses.
		Depth: MaxDepth,
	}, { // Test 1: A bundle nested one level past the bound is refused.
		Depth: MaxDepth + 1, Want: ErrParse,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			m := base()
			claimOf(m)["payload"] = map[string]any{"deep": "PLACEHOLDER"}
			n := test.Depth - envelope
			deep := strings.Repeat("[", n) + strings.Repeat("]", n)
			raw := strings.Replace(string(mustJSON(t, m)), `"PLACEHOLDER"`, deep, 1)
			if _, err := Parse([]byte(raw)); !errors.Is(err, test.Want) {
				t.Errorf("error mismatch: got %v, want %v", err, test.Want)
			}
		})
	}
}
