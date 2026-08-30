package verify

import (
	"fmt"
	"strings"
	"testing"
)

// TestIsHex64 pins the digest alphabet at its exact edges. The set is lowercase hex only,
// so an uppercase digest is refused rather than silently accepted into the _sd set.
func TestIsHex64(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In   string
		Want bool
	}{{ // Test 0: The low digit boundary is legal.
		In: strings.Repeat("0", 64), Want: true,
	}, { // Test 1: The high digit boundary is legal.
		In: strings.Repeat("9", 64), Want: true,
	}, { // Test 2: The low letter boundary is legal.
		In: strings.Repeat("a", 64), Want: true,
	}, { // Test 3: The high letter boundary is legal.
		In: strings.Repeat("f", 64), Want: true,
	}, { // Test 4: The letter past f is refused.
		In: strings.Repeat("g", 64),
	}, { // Test 5: Uppercase hex is refused, since the format fixes the case.
		In: strings.Repeat("A", 64),
	}, { // Test 6: The character between digits and letters is refused.
		In: strings.Repeat(":", 64),
	}, { // Test 7: A 63 character digest is refused.
		In: strings.Repeat("a", 63),
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			if got := isHex64(test.In); got != test.Want {
				t.Errorf("isHex64 = %t, want %t", got, test.Want)
			}
		})
	}
}
