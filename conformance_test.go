package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kordloom/loomseal/internal/verify"
)

// vectorsDir holds the conformance vectors and their manifest.
const vectorsDir = "testdata/vectors"

// conformanceManifest is the manifest shape the vector generator writes.
type conformanceManifest struct {
	// Description says what the file is.
	Description string `json:"description"`
	// Vectors are the individual conformance cases.
	Vectors []conformanceVector `json:"vectors"`
}

// conformanceVector is one declared expectation about a bundle.
type conformanceVector struct {
	// Name identifies the case.
	Name string `json:"name"`
	// File is the bundle file name within the vectors directory.
	File string `json:"file"`
	// MustVerify is whether a conformant verifier must report the bundle verified.
	MustVerify bool `json:"must_verify"`
	// Level is the expected conformance wording when MustVerify is true.
	Level string `json:"level"`
	// FailingCheck names the step that must fail when MustVerify is false.
	FailingCheck string `json:"failing_check"`
	// Why explains the case.
	Why string `json:"why"`
}

// TestConformanceVectors drives the verifier from the manifest so the shipped verifier and the
// published vectors can never disagree. Each vector asserts the overall verdict, the conformance
// level for cases that verify, and the failing check for cases that must not.
func TestConformanceVectors(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join(vectorsDir, "manifest.json"))
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	var man conformanceManifest
	if err := json.Unmarshal(raw, &man); err != nil {
		t.Fatalf("parse manifest: %v", err)
	}
	if len(man.Vectors) == 0 {
		t.Fatal("manifest declares no vectors")
	}
	for _, v := range man.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			doc, err := os.ReadFile(filepath.Join(vectorsDir, v.File))
			if err != nil {
				t.Fatalf("read vector: %v", err)
			}
			report := verify.Run(doc, verify.Options{})
			if report.OK != v.MustVerify {
				t.Fatalf("verified %t, want %t; problems %v", report.OK, v.MustVerify,
					report.Problems)
			}
			if v.MustVerify {
				if v.Level != "" && report.Level != v.Level {
					t.Errorf("level %q, want %q", report.Level, v.Level)
				}
				return
			}
			assertFailingCheck(t, v.FailingCheck, report)
		})
	}
}

// assertFailingCheck confirms the failure fell on the check the manifest names.
func assertFailingCheck(t *testing.T, check string, r *verify.Report) {
	t.Helper()
	switch check {
	case "parse":
		// Malformed input, a bad version, or an uncanonicalizable document fails before or at
		// the signature step, so no producer signature verifies.
		if r.SignatureOK {
			t.Errorf("parse case verified its signature: %v", r.Problems)
		}
	case "signature":
		if r.SignatureOK {
			t.Errorf("signature case verified its signature: %v", r.Problems)
		}
	case "chain":
		if !r.ChainPresent || r.ChainOK {
			t.Errorf("chain case did not fail the chain: present %t ok %t", r.ChainPresent,
				r.ChainOK)
		}
	case "anchor":
		if !r.SignatureOK || !r.ChainOK {
			t.Errorf("anchor case failed earlier than the anchor step: %v", r.Problems)
		}
		if r.AnchorsMatched != 0 || !hasProblem(r, "anchor") {
			t.Errorf("anchor case did not fail on an anchor: matched %d problems %v",
				r.AnchorsMatched, r.Problems)
		}
	case "span":
		if !r.SignatureOK || !r.ChainOK {
			t.Errorf("span case failed earlier than the span step: %v", r.Problems)
		}
		if !r.SpanPresent || r.SpanOK || !hasProblem(r, "span") {
			t.Errorf("span case did not fail on a span check: present %t ok %t problems %v",
				r.SpanPresent, r.SpanOK, r.Problems)
		}
	default:
		t.Fatalf("manifest names an unknown failing_check %q", check)
	}
}

// hasProblem reports whether any recorded problem mentions substr.
func hasProblem(r *verify.Report, substr string) bool {
	for _, p := range r.Problems {
		if strings.Contains(p, substr) {
			return true
		}
	}
	return false
}
