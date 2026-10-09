package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

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
	// Level is the expected conformance wording: the level achieved when MustVerify is true, and
	// otherwise "not verified" or "unsupported".
	Level string `json:"level"`
	// FailingCheck names the step that must fail when MustVerify is false.
	FailingCheck string `json:"failing_check"`
	// Why explains the case.
	Why string `json:"why"`
	// Evidence is whether the vectors directory is the evidence directory for the case.
	Evidence bool `json:"evidence"`
	// UnknownSubjectType is the subject type a verifier must report as outside its vocabulary when
	// MustVerify is true. Empty means none may be reported.
	UnknownSubjectType string `json:"unknown_subject_type"`
	// Unchecked lists the disclosed members, as "claim N member", a verifier must report unchecked.
	Unchecked []string `json:"unchecked"`
	// Redacted lists the disclosed members a verifier must report redacted.
	Redacted []string `json:"redacted"`
	// Legacy lists the record bodies a verifier must report verified under the legacy unkeyed
	// digest form.
	Legacy []string `json:"legacy"`
	// SpanCoverage is the coverage line a verifier must report, empty when the bundle carries no
	// span claims.
	SpanCoverage string `json:"span_coverage"`
	// SpanLongestGap is the longest gap a verifier must report, empty when there is none.
	SpanLongestGap string `json:"span_longest_gap"`
	// SpanGaps lists, in order, the gap lines a verifier must report.
	SpanGaps []string `json:"span_gaps"`
}

// TestConformanceVectors drives the verifier from the manifest so the shipped verifier and the
// published vectors can never disagree. Each vector asserts the overall verdict, the conformance
// level, the states of the disclosed members, and the failing check for cases that must not verify.
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
			var opts verify.Options
			if v.Evidence {
				opts.EvidenceDir = vectorsDir
			}
			report := verify.Run(doc, opts)
			if report.OK != v.MustVerify {
				t.Fatalf("verified %t, want %t; problems %v", report.OK, v.MustVerify,
					report.Problems)
			}
			// The level is pinned on every vector. A bundle that fails achieved no level, so its
			// report must not name the step it reached before failing.
			if v.Level != "" && report.Level != v.Level {
				t.Errorf("level %q, want %q", report.Level, v.Level)
			}
			// A verified bundle is only as good as what it leaves unchecked, so the states of its
			// disclosed members are part of the verdict a vector pins, and a bundle that does not
			// verify lists none.
			unchecked, redacted := disclosedStates(report)
			if diff := cmp.Diff(v.Unchecked, unchecked, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("unchecked members (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(v.Redacted, redacted, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("redacted members (-want +got):\n%s", diff)
			}
			// A bundle that does not verify lists no disclosed member in any state, checked ones
			// included, and counts none unchecked.
			if !v.MustVerify && (len(report.Disclosed) != 0 || report.DisclosedUnchecked != 0) {
				t.Errorf("a failed bundle lists %d disclosed members and %d unchecked records",
					len(report.Disclosed), report.DisclosedUnchecked)
			}
			if v.MustVerify {
				if diff := cmp.Diff(v.Legacy, report.LegacyRecords, cmpopts.EquateEmpty()); diff != "" {
					t.Errorf("legacy records (-want +got):\n%s", diff)
				}
				if report.UnknownSubjectType != v.UnknownSubjectType {
					t.Errorf("unknown subject type %q, want %q", report.UnknownSubjectType,
						v.UnknownSubjectType)
				}
				// A gap is measured one way, so the coverage line, the longest gap, and each gap's
				// wording are part of the verdict a spanned vector pins.
				if diff := cmp.Diff(v.SpanCoverage, report.SpanCoverage); diff != "" {
					t.Errorf("span coverage (-want +got):\n%s", diff)
				}
				if diff := cmp.Diff(v.SpanLongestGap, report.SpanLongestGap); diff != "" {
					t.Errorf("span longest gap (-want +got):\n%s", diff)
				}
				gaps := cmp.Diff(v.SpanGaps, report.SpanGaps, cmpopts.EquateEmpty())
				if gaps != "" {
					t.Errorf("span gaps (-want +got):\n%s", gaps)
				}
				return
			}
			assertFailingCheck(t, v.FailingCheck, report)
		})
	}
}

// presentationManifest is the presentation conformance document.
type presentationManifest struct {
	Vectors []presentationVector `json:"vectors"`
}

// presentationVector is one presentation conformance case.
type presentationVector struct {
	Name           string  `json:"name"`
	File           string  `json:"file"`
	ExpectAudience *string `json:"expect_audience"`
	ExpectNonce    *string `json:"expect_nonce"`
	MustVerify     bool    `json:"must_verify"`
	Why            string  `json:"why"`
}

// TestPresentationConformance drives the presentation verifier from its manifest, so the shipped
// verifier and the published presentation vectors can never disagree, including on the audience and
// nonce pins the manifest declares.
func TestPresentationConformance(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(filepath.Join(vectorsDir, "presentations.json"))
	if err != nil {
		t.Fatalf("read presentation manifest: %v", err)
	}
	var man presentationManifest
	if err := json.Unmarshal(raw, &man); err != nil {
		t.Fatalf("parse presentation manifest: %v", err)
	}
	if len(man.Vectors) == 0 {
		t.Fatal("manifest declares no presentation vectors")
	}
	for _, v := range man.Vectors {
		t.Run(v.Name, func(t *testing.T) {
			t.Parallel()
			doc, err := os.ReadFile(filepath.Join(vectorsDir, v.File))
			if err != nil {
				t.Fatalf("read presentation: %v", err)
			}
			// PresentationOptions holds no difference between an expectation supplied empty and
			// none, so a case that supplies one is held to the check the command line applies to
			// a flag the caller gave, and must be refused there before anything is verified.
			var opts verify.PresentationOptions
			err = errors.Join(applyExpectation(v.ExpectAudience, &opts.Audience),
				applyExpectation(v.ExpectNonce, &opts.Nonce))
			if err != nil {
				if v.MustVerify || !errors.Is(err, verify.ErrExpectation) {
					t.Fatalf("expectation refused with %v, want verified %t", err, v.MustVerify)
				}
				return
			}
			rep := verify.RunPresentation(doc, opts)
			if rep.OK != v.MustVerify {
				t.Fatalf("verified %t, want %t; problems %v", rep.OK, v.MustVerify, rep.Problems)
			}
		})
	}
}

// applyExpectation sets dst to a supplied expectation once it passes the check the command line
// applies to a flag the caller gave. A nil expectation is none and leaves dst empty.
func applyExpectation(supplied, dst *string) error {
	if supplied == nil {
		return nil
	}
	if err := verify.CheckExpectation(*supplied); err != nil {
		return err
	}
	*dst = *supplied
	return nil
}

// assertFailingCheck confirms the failure fell on the check the manifest names.
func assertFailingCheck(t *testing.T, check string, r *verify.Report) {
	t.Helper()
	switch check {
	case "parse":
		// Malformed input or an uncanonicalizable document fails before or at the signature step,
		// so no producer signature verifies. It is not verified, which is a different verdict from
		// unsupported, so a malformed value read as an unknown profile or algorithm fails here.
		if r.SignatureOK {
			t.Errorf("parse case verified its signature: %v", r.Problems)
		}
		if r.Unsupported {
			t.Errorf("parse case was judged unsupported: %v", r.Problems)
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
		// An anchor failure is any recorded anchor problem: matching nothing and matching but
		// carrying a garbage proof are both anchor failures, and only the first has matched == 0.
		if !hasProblem(r, "anchor") {
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
	case "disclosure":
		if !r.SignatureOK {
			t.Errorf("disclosure case failed before the signature: %v", r.Problems)
		}
		if !r.DisclosuresPresent || !hasProblem(r, "disclosure") {
			t.Errorf("disclosure case did not fail on a disclosure: present %t problems %v",
				r.DisclosuresPresent, r.Problems)
		}
	case "attestation":
		if !r.SignatureOK {
			t.Errorf("attestation case failed before the signature: %v", r.Problems)
		}
		if (!r.AttestationsPresent && !r.HeadAttestationsPresent) || !hasProblem(r, "attestation") {
			t.Errorf("attestation case did not fail on an attestation: claim %t head %t problems %v",
				r.AttestationsPresent, r.HeadAttestationsPresent, r.Problems)
		}
	case "record":
		if !r.SignatureOK || !r.ChainOK {
			t.Errorf("record case failed earlier than the record check: %v", r.Problems)
		}
		if !hasProblem(r, "record:") {
			t.Errorf("record case did not fail on a disclosed record: %v", r.Problems)
		}
	case "install":
		if !r.SignatureOK || !r.ChainOK {
			t.Errorf("install case failed earlier than the install check: %v", r.Problems)
		}
		if !hasProblem(r, "install") {
			t.Errorf("install case did not fail on the install check: %v", r.Problems)
		}
	case "evidence":
		if !r.SignatureOK || !r.ChainOK {
			t.Errorf("evidence case failed earlier than the evidence check: %v", r.Problems)
		}
		if r.EvidenceMismatched == 0 || !hasProblem(r, "evidence ") {
			t.Errorf("evidence case did not fail on an altered artifact: mismatched %d problems %v",
				r.EvidenceMismatched, r.Problems)
		}
	case "unsupported":
		if !r.Unsupported {
			t.Errorf("unsupported case did not set the unsupported verdict: %v", r.Problems)
		}
		if r.SignatureOK {
			t.Errorf("unsupported case judged the signature: %v", r.Problems)
		}
	default:
		t.Fatalf("manifest names an unknown failing_check %q", check)
	}
}

// disclosedStates lists a report's unchecked and redacted disclosed members as "claim N member".
func disclosedStates(r *verify.Report) (unchecked, redacted []string) {
	for _, m := range r.Disclosed {
		entry := fmt.Sprintf("claim %d %s", m.Claim, m.Member)
		switch m.State {
		case "unchecked":
			unchecked = append(unchecked, entry)
		case "redacted":
			redacted = append(redacted, entry)
		}
	}
	return unchecked, redacted
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
