package verify

import (
	"fmt"
	"testing"
)

// TestPrintable pins that a member name or detail, which the producer writes, reaches a report line
// quoted whenever it carries a character that does not print.
func TestPrintable(t *testing.T) {
	t.Parallel()
	tests := []struct {
		In         string
		WantResult string
	}{{ // Test 0: A plain name prints as it is.
		In: "decision_body", WantResult: "decision_body",
	}, { // Test 1: A non-ASCII letter prints as it is.
		In: "deci\u017fion_body", WantResult: "deci\u017fion_body",
	}, { // Test 2: An escape sequence is quoted, so it cannot recolor or move the terminal.
		In: "note\x1b[2J", WantResult: `"note\x1b[2J"`,
	}, { // Test 3: A newline is quoted, so it cannot forge a line of the report.
		In: "x\nVERIFIED", WantResult: `"x\nVERIFIED"`,
	}, { // Test 4: A bidi override is quoted, so it cannot reorder the line around it.
		In: "a\u202eb", WantResult: `"a\u202eb"`,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			if got := Printable(test.In); got != test.WantResult {
				t.Errorf("Printable(%q) = %q, want %q", test.In, got, test.WantResult)
			}
		})
	}
}
