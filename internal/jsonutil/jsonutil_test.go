package jsonutil_test

import (
	"strings"
	"testing"

	"github.com/kordloom/loomseal/internal/jsonutil"
)

// TestMarshal pins the two output shapes the CLI offers: compact by default, indented on request.
func TestMarshal(t *testing.T) {
	t.Parallel()
	value := map[string]any{"ok": true, "level": "signed"}
	compact, err := jsonutil.Marshal(value, false)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if strings.Contains(string(compact), "\n") {
		t.Errorf("compact output carries a newline: %s", compact)
	}
	pretty, err := jsonutil.Marshal(value, true)
	if err != nil {
		t.Fatalf("Marshal(pretty) error = %v", err)
	}
	if !strings.Contains(string(pretty), "\n  ") {
		t.Errorf("pretty output is not indented: %s", pretty)
	}
	// Both forms have to describe the same value, or the flag changes meaning rather than layout.
	if strings.ReplaceAll(strings.ReplaceAll(string(pretty), "\n", ""), " ", "") != string(compact) {
		t.Errorf("pretty and compact disagree:\n  %s\n  %s", pretty, compact)
	}
}

// TestMarshalReportsUnencodableValues pins that a value JSON cannot represent returns an error
// rather than partial output.
func TestMarshalReportsUnencodableValues(t *testing.T) {
	t.Parallel()
	if _, err := jsonutil.Marshal(make(chan int), false); err == nil {
		t.Error("an unencodable value marshalled without an error")
	}
}
