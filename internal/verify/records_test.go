package verify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/kordloom/loomseal/jcs"
	"github.com/kordloom/loomseal/seal"
)

// recordCounts is what a report says about the records a bundle discloses, under the report's own
// JSON names so a second implementation can compare its report with them directly.
type recordCounts struct {
	// Decisions is DecisionRecords.
	Decisions int `json:"decision_records"`
	// Corrections is CorrectionRecords.
	Corrections int `json:"correction_records"`
	// Verified is ReasonsVerified.
	Verified int `json:"reasons_verified"`
	// Redacted is ReasonsRedacted.
	Redacted []string `json:"reasons_redacted"`
	// Withheld is ReasonsWithheld.
	Withheld int `json:"reasons_withheld"`
	// SpecsMatched is SpecsMatched.
	SpecsMatched int `json:"specs_matched"`
	// SpecsUnchecked is SpecsUnchecked.
	SpecsUnchecked int `json:"specs_unchecked"`
	// OutcomesVerified is OutcomesVerified.
	OutcomesVerified int `json:"outcomes_verified"`
	// Outcomes is OutcomesUnchecked.
	Outcomes int `json:"outcomes_unchecked"`
	// Legacy is LegacyRecords.
	Legacy []string `json:"legacy_records"`
	// Unchecked lists the disclosed members reported unchecked, as "claim N member".
	Unchecked []string `json:"unchecked"`
	// UncheckedRecords is DisclosedUnchecked.
	UncheckedRecords int `json:"disclosed_unchecked"`
}

// recordOutcomeOlder is what the honest case's outcome claim leaves unchecked: an outcome under an
// older digest form, with its nonce, on claim i.
func recordOutcomeOlder(i int, more ...string) []string {
	return append([]string{fmt.Sprintf("claim %d outcome_body", i),
		fmt.Sprintf("claim %d outcome_nonce", i)}, more...)
}

// recordCase is one record receipt a test edits before it is linked and signed: the payloads of the
// creating request, the decision, an optional correction, and the outcome, in chain order.
type recordCase struct {
	// Payloads are the claim payloads in chain order.
	Payloads []map[string]any
}

// decision returns the decision claim's payload.
func (c *recordCase) decision() map[string]any { return c.Payloads[1] }

// correction returns the correction claim's payload, which only a case built with one carries.
func (c *recordCase) correction() map[string]any { return c.Payloads[2] }

// outcome returns the outcome claim's payload, always the last.
func (c *recordCase) outcome() map[string]any { return c.Payloads[len(c.Payloads)-1] }

// TestRecordsHoldWhatTheirEntriesCommitted pins the record check on every path it takes: a body
// that reproduces its entry's content digest in the keyed and the unkeyed form, a reason that opens
// the commitment its body carries, a redacted reason that cannot be opened by design and is never a
// failure, a withheld one, a correction, and the disclosed spec held against the decision. Every
// edit is made before the bundle is linked and signed, so the signature and every link hold and the
// record check is the only one that can object, which is the receipt a producer re-signs.
func TestRecordsHoldWhatTheirEntriesCommitted(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Correction  bool
		Edit        func(c *recordCase)
		WantOK      bool
		WantProblem string
		WantCounts  recordCounts
	}{{ // Test 0: An honest receipt verifies, its reason opened and its spec matched.
		WantOK: true,
		WantCounts: recordCounts{Decisions: 1, Verified: 1, SpecsMatched: 1, Outcomes: 1,
			Unchecked: recordOutcomeOlder(2), UncheckedRecords: 1},
	}, { // Test 1: A redacted reason is reported by its category and never fails.
		Edit: func(c *recordCase) {
			delete(c.decision(), "reason_text")
			delete(c.decision(), "reason_random")
			c.decision()["reason_redacted"] = "personal_data"
		},
		WantOK: true,
		WantCounts: recordCounts{Decisions: 1, Redacted: []string{"personal_data"},
			SpecsMatched: 1, Outcomes: 1, Unchecked: recordOutcomeOlder(2), UncheckedRecords: 1},
	}, { // Test 2: A committed reason the receipt does not disclose is withheld.
		Edit: func(c *recordCase) {
			delete(c.decision(), "reason_text")
			delete(c.decision(), "reason_random")
		},
		WantOK: true,
		WantCounts: recordCounts{Decisions: 1, Withheld: 1, SpecsMatched: 1, Outcomes: 1,
			Unchecked: recordOutcomeOlder(2), UncheckedRecords: 1},
	}, { // Test 3: A decision from before nonces verifies against its unkeyed digest, as legacy.
		Edit:   recordUnkeyed,
		WantOK: true,
		WantCounts: recordCounts{Decisions: 1, SpecsMatched: 1, Outcomes: 1,
			Legacy: []string{"claim 1 decision_body"}, Unchecked: recordOutcomeOlder(2),
			UncheckedRecords: 1},
	}, { // Test 4: A correction verifies against its own entry and its own commitment.
		Correction: true, WantOK: true,
		WantCounts: recordCounts{Decisions: 1, Corrections: 1, Verified: 2, SpecsMatched: 1,
			Outcomes: 1, Unchecked: recordOutcomeOlder(3), UncheckedRecords: 1},
	}, { // Test 5: A decision body changed after it was committed fails.
		Edit: func(c *recordCase) {
			c.decision()["decision_body"].(map[string]any)["verdict"] = "rejected"
		},
		WantProblem: "does not reproduce the content_digest its entry committed",
	}, { // Test 6: A nonce the digest did not commit fails.
		Edit: func(c *recordCase) {
			c.decision()["decision_nonce"] = hex.EncodeToString(recordTestBytes("another nonce"))
		},
		WantProblem: "has a decision_nonce the content_digest did not commit",
	}, { // Test 7: A nonce in uppercase hex is not the wire form and fails.
		Edit: func(c *recordCase) {
			n := c.decision()["decision_nonce"].(string)
			c.decision()["decision_nonce"] = string(bytes.ToUpper([]byte(n)))
		},
		WantProblem: "decision_nonce that is not 64 lowercase hex digits",
	}, { // Test 8: A keyed digest with no nonce beside it cannot be opened and fails.
		Edit:        func(c *recordCase) { delete(c.decision(), "decision_nonce") },
		WantProblem: "decision_nonce that is not 64 lowercase hex digits",
	}, { // Test 9: A nonce that is not a string fails.
		Edit:        func(c *recordCase) { c.decision()["decision_nonce"] = int64(7) },
		WantProblem: "decision_nonce that is not a string",
	}, { // Test 10: A nonce beside an unkeyed digest commits nothing and fails.
		Edit: func(c *recordCase) {
			recordUnkeyed(c)
			c.decision()["decision_nonce"] = hex.EncodeToString(recordTestBytes("nonce decision"))
		},
		WantProblem: "beside an unkeyed content_digest",
	}, { // Test 11: An unkeyed decision body changed after it was committed fails.
		Edit: func(c *recordCase) {
			recordUnkeyed(c)
			c.decision()["decision_body"].(map[string]any)["verdict"] = "rejected"
		},
		WantProblem: "does not reproduce the content_digest its entry committed",
	}, { // Test 12: A body on an entry that commits no content digest fails.
		Edit:        func(c *recordCase) { delete(c.decision(), "content_digest") },
		WantProblem: "commits no content_digest",
	}, { // Test 13: A content digest in no known form fails.
		Edit: func(c *recordCase) {
			c.decision()["content_digest"] = "md5:" + hex.EncodeToString(recordTestBytes("x")[:16])
		},
		WantProblem: "neither the sha256s: nor the sha256: form",
	}, { // Test 14: A keyed digest missing its second part fails.
		Edit: func(c *recordCase) {
			c.decision()["content_digest"] = "sha256s:" + hex.EncodeToString(recordTestBytes("x"))
		},
		WantProblem: "not sha256s: and two 64 hex digests",
	}, { // Test 15: A body that is not an object fails.
		Edit:        func(c *recordCase) { c.decision()["decision_body"] = "approved" },
		WantProblem: "decision_body is missing or not an object",
	}, { // Test 16: A nonce with no body beside it on a decision fails.
		Edit:        func(c *recordCase) { delete(c.decision(), "decision_body") },
		WantProblem: "decision_body is missing or not an object",
	}, { // Test 17: A correction body on a decision is an ordinary member, reported unchecked.
		Edit: func(c *recordCase) {
			c.decision()["correction_body"] = map[string]any{"correction_id": "aud_x"}
		},
		WantOK: true,
		WantCounts: recordCounts{Decisions: 1, Verified: 1, SpecsMatched: 1, Outcomes: 1,
			Unchecked: recordOutcomeOlder(2, "claim 1 correction_body"), UncheckedRecords: 2},
	}, { // Test 18: A reason changed after it was committed fails.
		Edit:        func(c *recordCase) { c.decision()["reason_text"] = "approved by the board" },
		WantProblem: "reason_text does not open the reason_commitment",
	}, { // Test 19: A random value that is not the one committed fails.
		Edit: func(c *recordCase) {
			c.decision()["reason_random"] = hex.EncodeToString(recordTestBytes("another random"))
		},
		WantProblem: "reason_text does not open the reason_commitment",
	}, { // Test 20: A random value that is not 64 lowercase hex digits fails.
		Edit:        func(c *recordCase) { c.decision()["reason_random"] = "ab" },
		WantProblem: "needs a reason_random of 64 lowercase hex digits",
	}, { // Test 21: A random value with no text to open fails.
		Edit:        func(c *recordCase) { delete(c.decision(), "reason_text") },
		WantProblem: "reason_random with no reason_text",
	}, { // Test 22: A redaction category beside the text it claims to have removed fails.
		Edit:        func(c *recordCase) { c.decision()["reason_redacted"] = "personal_data" },
		WantProblem: "reason_redacted must be a category alone",
	}, { // Test 23: An empty redaction category fails.
		Edit: func(c *recordCase) {
			delete(c.decision(), "reason_text")
			delete(c.decision(), "reason_random")
			c.decision()["reason_redacted"] = ""
		},
		WantProblem: "reason_redacted must be a category alone",
	}, { // Test 24: A reason beside a body that commits none fails.
		Edit: func(c *recordCase) {
			recordUnkeyed(c)
			c.decision()["reason_text"] = "approved"
		},
		WantProblem: "discloses a reason its decision_body commits none of",
	}, { // Test 25: A reason member on a claim that is no record is ordinary and unchecked.
		Edit:   func(c *recordCase) { c.Payloads[0]["reason_text"] = "approved" },
		WantOK: true,
		WantCounts: recordCounts{Decisions: 1, Verified: 1, SpecsMatched: 1, Outcomes: 1,
			Unchecked: recordOutcomeOlder(2, "claim 0 reason_text"), UncheckedRecords: 2},
	}, { // Test 26: A reason commitment that is not a digest fails even when the body matches.
		Edit: func(c *recordCase) {
			recordRebody(c.decision(), "decision", func(b map[string]any) {
				b["reason_commitment"] = "sha256:abc"
			})
		},
		WantProblem: "reason_commitment is not sha256: and 64 hex digits",
	}, { // Test 27: A commitment bound to no decision id fails.
		Edit: func(c *recordCase) {
			recordRebody(c.decision(), "decision", func(b map[string]any) {
				delete(b, "decision_id")
			})
		},
		WantProblem: "names no decision_id to bind it to",
	}, { // Test 28: A reason commitment that is not a string fails.
		Edit: func(c *recordCase) {
			recordRebody(c.decision(), "decision", func(b map[string]any) {
				b["reason_commitment"] = int64(1)
			})
		},
		WantProblem: "reason_commitment that is not a string",
	}, { // Test 29: A correction that commits no reason fails, since a correction is a reason.
		Correction: true,
		Edit: func(c *recordCase) {
			recordRebody(c.correction(), "correction", func(b map[string]any) {
				delete(b, "reason_commitment")
			})
			delete(c.correction(), "reason_text")
			delete(c.correction(), "reason_random")
		},
		WantProblem: "commits no reason, and a correction is a reason",
	}, { // Test 30: A correction's text changed after it was committed fails.
		Correction:  true,
		Edit:        func(c *recordCase) { c.correction()["reason_text"] = "a different correction" },
		WantProblem: "reason_text does not open the reason_commitment its correction_body carries",
	}, { // Test 31: A spec changed after the decision committed it fails.
		Edit:        func(c *recordCase) { c.outcome()["spec_body"] = `{"command":"rm -rf /"}` },
		WantProblem: "the disclosed spec hashes to",
	}, { // Test 32: Two outcome claims disclosing different specs fail.
		Edit: func(c *recordCase) {
			c.Payloads = append(c.Payloads, map[string]any{"actor": "system:dispatcher",
				"method": "RUN", "path": "/runs/run_records/outcome/failed",
				"spec_body": `{"command":"other"}`})
		},
		WantProblem: "two different specs",
	}, { // Test 33: A spec that is not a string cannot be hashed as disclosed and fails.
		Edit:        func(c *recordCase) { c.outcome()["spec_body"] = map[string]any{"a": "b"} },
		WantProblem: "spec_body is not a string",
	}, { // Test 34: A spec with no decision beside it is carried, not verified.
		Edit: func(c *recordCase) {
			c.Payloads = []map[string]any{c.Payloads[0], c.outcome()}
		},
		WantOK: true,
		WantCounts: recordCounts{SpecsUnchecked: 1, Outcomes: 1,
			Unchecked: recordOutcomeOlder(1, "claim 1 spec_body"), UncheckedRecords: 2},
	}, { // Test 35: A decision that commits no spec digest beside a disclosed spec fails.
		Edit: func(c *recordCase) {
			recordRebody(c.decision(), "decision", func(b map[string]any) {
				delete(b, "spec_digest")
			})
		},
		WantProblem: "a verified record committed spec (none)",
	}, { // Test 36: The members mean nothing on a claim type other than switchtender.audit/1.
		Edit: func(c *recordCase) {
			c.Payloads[0]["decision_body"] = "not checked here"
			c.Payloads[0]["claim_type"] = "acme.widget/1"
		},
		WantOK: true,
		WantCounts: recordCounts{Decisions: 1, Verified: 1, SpecsMatched: 1, Outcomes: 1,
			Unchecked: recordOutcomeOlder(2, "claim 0 decision_body"), UncheckedRecords: 2},
	}, { // Test 37: An exact-form outcome verifies and holds the spec with no decision beside it.
		Edit:       recordExactRun(recordTestOutcomeText(recordTestSpecDigest)),
		WantOK:     true,
		WantCounts: recordCounts{OutcomesVerified: 1, SpecsMatched: 1},
	}, { // Test 38: An exact-form outcome changed after it was committed fails.
		Edit: func(c *recordCase) {
			recordExactRun(recordTestOutcomeText(recordTestSpecDigest))(c)
			c.outcome()["outcome_body"] = `{"run_id":"run_records","status":"failed"}`
		},
		WantProblem: "outcome_body does not reproduce the content_digest its entry committed",
	}, { // Test 39: A nonce the exact-form digest did not commit fails.
		Edit: func(c *recordCase) {
			recordExactRun(recordTestOutcomeText(recordTestSpecDigest))(c)
			c.outcome()["outcome_nonce"] = hex.EncodeToString(recordTestBytes("another nonce"))
		},
		WantProblem: "has an outcome_nonce the content_digest did not commit",
	}, { // Test 40: An exact-form outcome that is not text cannot be checked and fails.
		Edit: func(c *recordCase) {
			recordExactRun(recordTestOutcomeText(recordTestSpecDigest))(c)
			c.outcome()["outcome_body"] = map[string]any{"status": "succeeded"}
		},
		WantProblem: "outcome_body is not a string",
	}, { // Test 41: An outcome nonce with no outcome beside it fails.
		Edit:        func(c *recordCase) { delete(c.outcome(), "outcome_body") },
		WantProblem: "outcome_nonce with no outcome_body",
	}, { // Test 42: An outcome on an entry that commits no content digest fails.
		Edit:        func(c *recordCase) { delete(c.outcome(), "content_digest") },
		WantProblem: "outcome_body is disclosed on an entry that commits no content_digest",
	}, { // Test 43: A reason member on an outcome is an ordinary member, reported unchecked.
		Edit:   func(c *recordCase) { c.outcome()["reason_redacted"] = "personal_data" },
		WantOK: true,
		WantCounts: recordCounts{Decisions: 1, Verified: 1, SpecsMatched: 1, Outcomes: 1,
			Unchecked: recordOutcomeOlder(2, "claim 2 reason_redacted"), UncheckedRecords: 2},
	}, { // Test 44: A spec the verified outcome does not name fails.
		Edit: func(c *recordCase) {
			recordExactRun(recordTestOutcomeText(recordTestSpecDigest))(c)
			c.outcome()["spec_body"] = `{"command":"rm -rf /"}`
		},
		WantProblem: "the disclosed spec hashes to",
	}, { // Test 45: An exact-form outcome naming no spec digest leaves the spec carried.
		Edit:   recordExactRun(`{"run_id":"run_records","status":"succeeded"}`),
		WantOK: true,
		WantCounts: recordCounts{OutcomesVerified: 1, SpecsUnchecked: 1,
			Unchecked: []string{"claim 1 spec_body"}, UncheckedRecords: 1},
	}, { // Test 46: An outcome nested past the bound names no spec digest anywhere.
		Edit: recordExactRun(`{"spec_digest":"` + recordTestSpecDigest + `","deep":` +
			strings.Repeat("[", 32) + strings.Repeat("]", 32) + `}`),
		WantOK: true,
		WantCounts: recordCounts{OutcomesVerified: 1, SpecsUnchecked: 1,
			Unchecked: []string{"claim 1 spec_body"}, UncheckedRecords: 1},
	}, { // Test 47: An outcome within the bound names its spec digest.
		Edit: recordExactRun(`{"spec_digest":"` + recordTestSpecDigest + `","deep":` +
			strings.Repeat("[", 31) + strings.Repeat("]", 31) + `}`),
		WantOK:     true,
		WantCounts: recordCounts{OutcomesVerified: 1, SpecsMatched: 1},
	}, { // Test 48: An outcome with a fractional number is read for no spec digest.
		Edit:   recordExactRun(`{"spec_digest":"` + recordTestSpecDigest + `","ratio":1.5}`),
		WantOK: true,
		WantCounts: recordCounts{OutcomesVerified: 1, SpecsUnchecked: 1,
			Unchecked: []string{"claim 1 spec_body"}, UncheckedRecords: 1},
	}, { // Test 49: An outcome body on a decision is an ordinary member, reported unchecked.
		Edit: func(c *recordCase) {
			c.decision()["outcome_body"] = recordTestOutcomeText(recordTestSpecDigest)
		},
		WantOK: true,
		WantCounts: recordCounts{Decisions: 1, Verified: 1, SpecsMatched: 1, Outcomes: 1,
			Unchecked: recordOutcomeOlder(2, "claim 1 outcome_body"), UncheckedRecords: 2},
	}, { // Test 50: An exact-form digest missing its second part fails.
		Edit: func(c *recordCase) {
			recordExactRun(recordTestOutcomeText(recordTestSpecDigest))(c)
			c.outcome()["content_digest"] = "sha256e:" + hex.EncodeToString(recordTestBytes("x"))
		},
		WantProblem: "not sha256e: and two 64 hex digests",
	}, { // Test 51: Record members of any shape on a claim that is no record verify as unchecked.
		Edit: func(c *recordCase) {
			c.Payloads[0]["decision_body"] = "approved by the board"
			c.Payloads[0]["decision_nonce"] = int64(7)
			c.Payloads[0]["spec_body"] = `{"command":"other"}`
		},
		WantOK: true,
		WantCounts: recordCounts{Decisions: 1, Verified: 1, SpecsMatched: 1, Outcomes: 1,
			Unchecked: append([]string{"claim 0 decision_body", "claim 0 decision_nonce",
				"claim 0 spec_body"}, recordOutcomeOlder(2)...),
			UncheckedRecords: 3},
	}, { // Test 52: A REASON entry recording a redaction is no correction, whatever it carries.
		Edit: func(c *recordCase) {
			c.Payloads = append(c.Payloads, map[string]any{"actor": "ops-admin", "method": "REASON",
				"path":            "/runs/run_records/decisions/aud_decision/reason_redacted/personal_data",
				"correction_body": "not a correction"})
		},
		WantOK: true,
		WantCounts: recordCounts{Decisions: 1, Verified: 1, SpecsMatched: 1, Outcomes: 1,
			Unchecked: recordOutcomeOlder(2, "claim 3 correction_body"), UncheckedRecords: 2},
	}, { // Test 53: A lone nonce on a claim that is no record counts as an unchecked record.
		Edit:   func(c *recordCase) { c.Payloads[0]["outcome_nonce"] = "ab" },
		WantOK: true,
		WantCounts: recordCounts{Decisions: 1, Verified: 1, SpecsMatched: 1, Outcomes: 1,
			Unchecked: recordOutcomeOlder(2, "claim 0 outcome_nonce"), UncheckedRecords: 2},
	}, { // Test 54: A case variant of a member a record reads fails beside the member.
		Edit: func(c *recordCase) {
			c.decision()["Decision_body"] = map[string]any{"verdict": "rejected"}
		},
		WantProblem: `carries "Decision_body", which differs from decision_body only in case`,
	}, { // Test 55: A case variant folded through a non-ASCII letter fails the same way.
		Edit:        func(c *recordCase) { c.decision()["reaſon_text"] = "approved by the board" },
		WantProblem: "which differs from reason_text only in case",
	}, { // Test 56: A case variant fails on its own, with no exact member beside it.
		Edit: func(c *recordCase) {
			c.outcome()["Spec_body"] = c.outcome()["spec_body"]
			delete(c.outcome(), "spec_body")
		},
		WantProblem: "which differs from spec_body only in case",
	}, { // Test 57: A case variant on a claim that is no record is an ordinary member.
		Edit:   func(c *recordCase) { c.Payloads[0]["Reason_text"] = "approved" },
		WantOK: true,
		WantCounts: recordCounts{Decisions: 1, Verified: 1, SpecsMatched: 1, Outcomes: 1,
			Unchecked: recordOutcomeOlder(2, "claim 0 Reason_text"), UncheckedRecords: 2},
	}, { // Test 58: An unkeyed decision after an entry under the keyed form fails.
		Edit: func(c *recordCase) {
			recordUnkeyed(c)
			c.Payloads[0]["content_digest"] = "sha256s:" + hex.EncodeToString(recordTestBytes("k")) +
				":" + hex.EncodeToString(recordTestBytes("m"))
		},
		WantProblem: "sits on an unkeyed content_digest after claim 0 began the keyed form",
	}, { // Test 59: An unkeyed outcome after an entry under the keyed form fails.
		Edit: func(c *recordCase) {
			c.outcome()["content_digest"] = "sha256:" + hex.EncodeToString(recordTestBytes("u"))
		},
		WantProblem: "outcome_body sits on an unkeyed content_digest after claim 1 began",
	}, { // Test 60: Unkeyed entries with nothing keyed before them are legacy and verify.
		Edit: func(c *recordCase) {
			recordUnkeyed(c)
			c.outcome()["content_digest"] = "sha256:" + hex.EncodeToString(recordTestBytes("u"))
		},
		WantOK: true,
		WantCounts: recordCounts{Decisions: 1, SpecsMatched: 1, Outcomes: 1,
			Legacy: []string{"claim 1 decision_body"}, Unchecked: recordOutcomeOlder(2),
			UncheckedRecords: 1},
	}}

	cross := os.Getenv("LOOMSEAL_CROSS_DIR")
	var manifest []recordCrossCase
	for testNum, test := range tests {
		raw := recordTestBundle(t, test.Correction, test.Edit)
		if cross != "" {
			name := fmt.Sprintf("record-%02d.loomseal.json", testNum)
			if err := os.WriteFile(filepath.Join(cross, name), raw, 0o600); err != nil {
				t.Fatalf("write %s: %v", name, err)
			}
			manifest = append(manifest, recordCrossCase{File: name, WantOK: test.WantOK,
				WantProblem: test.WantProblem, WantCounts: test.WantCounts})
		}
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			r := Run(raw, Options{})
			if !r.SignatureOK || !r.ChainOK {
				t.Fatalf("the edit broke the signature or the chain, so the record check went "+
					"untested: %v", r.Problems)
			}
			if r.OK != test.WantOK {
				t.Fatalf("OK = %v, want %v (problems: %v)", r.OK, test.WantOK, r.Problems)
			}
			if test.WantProblem != "" && !hasProblemText(r, "record: ") {
				t.Errorf("problems %v name no record check", r.Problems)
			}
			if test.WantProblem != "" && !hasProblemText(r, test.WantProblem) {
				t.Errorf("problems %v do not mention %q", r.Problems, test.WantProblem)
			}
			if !test.WantOK {
				return
			}
			got := recordCounts{Decisions: r.DecisionRecords, Corrections: r.CorrectionRecords,
				Verified: r.ReasonsVerified, Redacted: r.ReasonsRedacted, Withheld: r.ReasonsWithheld,
				SpecsMatched: r.SpecsMatched, SpecsUnchecked: r.SpecsUnchecked,
				OutcomesVerified: r.OutcomesVerified, Outcomes: r.OutcomesUnchecked,
				Legacy: r.LegacyRecords, UncheckedRecords: r.DisclosedUnchecked}
			for _, m := range r.Disclosed {
				if m.State == stateUnchecked {
					got.Unchecked = append(got.Unchecked, fmt.Sprintf("claim %d %s", m.Claim, m.Member))
				}
			}
			if diff := cmp.Diff(test.WantCounts, got, cmpopts.EquateEmpty(),
				cmpopts.SortSlices(func(a, b string) bool { return a < b })); diff != "" {
				t.Errorf("record counts mismatch (-want +got):\n%s", diff)
			}
		})
	}
	if cross != "" {
		out, err := json.MarshalIndent(manifest, "", "  ")
		if err != nil {
			t.Fatalf("marshal the cross manifest: %v", err)
		}
		if err := os.WriteFile(filepath.Join(cross, "records.json"), out, 0o600); err != nil {
			t.Fatalf("write the cross manifest: %v", err)
		}
	}
}

// recordCrossCase is one emitted bundle and the verdict a second implementation must reach on it.
type recordCrossCase struct {
	// File is the bundle's file name in the cross directory.
	File string `json:"file"`
	// WantOK is whether the bundle must verify.
	WantOK bool `json:"want_ok"`
	// WantProblem is a fragment the failing record problem must contain.
	WantProblem string `json:"want_problem,omitempty"`
	// WantCounts is what the report must say about the records of a bundle that verifies.
	WantCounts recordCounts `json:"want_counts"`
}

// recordTestBundle builds an honest record receipt, applies edit to its payloads, then links and
// signs it, so whatever the edit did travels under a valid signature and valid links. A payload
// carrying claim_type has that member removed and used as its claim's type.
func recordTestBundle(t *testing.T, correction bool, edit func(c *recordCase)) []byte {
	t.Helper()
	c := recordHonestCase(correction)
	if edit != nil {
		edit(c)
	}
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	pub := priv.Public().(ed25519.PublicKey)
	const at = "2026-10-04T12:00:00Z"
	claims := make([]any, 0, len(c.Payloads))
	prev := ""
	for i, p := range c.Payloads {
		claimType := "switchtender.audit/1"
		if ct, ok := p["claim_type"].(string); ok {
			claimType = ct
			delete(p, "claim_type")
		}
		seq := int64(i + 1)
		link := recordTestLink(t, seq, at, prev, p)
		claims = append(claims, map[string]any{
			"type": claimType, "at": at, "payload": p,
			"chain": map[string]any{"seq": seq, "prev": prev, "link": link},
		})
		prev = link
	}
	doc := map[string]any{
		"loomseal": "0.1", "bundle_id": "lsb_records", "created_at": at,
		"producer": map[string]any{
			"product": "switchtender", "product_version": "1.102.0", "install_id": "in_records",
			"public_key": base64.StdEncoding.EncodeToString(pub), "key_id": seal.KeyID(pub),
		},
		"subject": map[string]any{"type": "run", "id": "run_records"},
		"chain": map[string]any{"profile": "switchtender-audit-v1", "keyed": false,
			"head": map[string]any{"seq": int64(len(claims)), "link": prev}},
		"claims": claims,
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signed, err := seal.SignBundle(body, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

// recordTestSpec is the run's spec, as text, and recordTestSpecDigest is its digest.
const recordTestSpec = `{"command":"deploy","tool":"bash"}`

// recordTestSpecDigest is sha256: and the hex SHA-256 of recordTestSpec.
var recordTestSpecDigest = func() string {
	sum := sha256.Sum256([]byte(recordTestSpec))
	return "sha256:" + hex.EncodeToString(sum[:])
}()

// recordTestOutcomeText is a canonical outcome record naming spec.
func recordTestOutcomeText(spec string) string {
	return `{"exit_code":0,"run_id":"run_records","spec_digest":"` + spec + `","status":"succeeded"}`
}

// recordExactRun returns an edit that makes the case a run with no decision whose outcome, text,
// is committed under the exact form, the way a producer commits the bytes it discloses.
func recordExactRun(text string) func(c *recordCase) {
	return func(c *recordCase) {
		nonce := recordTestBytes("nonce exact outcome")
		nonceSum := sha256.Sum256(nonce)
		mac := hmac.New(sha256.New, nonce)
		mac.Write([]byte(text))
		c.Payloads = []map[string]any{c.Payloads[0], {
			"actor": "system:dispatcher", "method": "RUN",
			"path": "/runs/run_records/outcome/succeeded", "spec_body": recordTestSpec,
			"content_digest": "sha256e:" + hex.EncodeToString(nonceSum[:]) + ":" +
				hex.EncodeToString(mac.Sum(nil)),
			"outcome_body": text, "outcome_nonce": hex.EncodeToString(nonce),
		}}
	}
}

// recordHonestCase builds the payloads of an honest receipt: a request, an approval whose body
// commits a reason and the spec, an optional correction to that reason, and an outcome that carries
// the spec and the outcome body under an older digest form, so it travels unchecked.
func recordHonestCase(correction bool) *recordCase {
	spec := recordTestSpec
	specDigest := recordTestSpecDigest
	random := hex.EncodeToString(recordTestBytes("random decision"))
	const reason = "approved after the change review & the on-call <sign-off>"
	commitment := recordTestCommitment("aud_decision", random, reason)
	decision := map[string]any{
		"actor": "ops-admin", "method": "DECISION", "path": "/runs/run_records/decision/approved",
		"decision_body": map[string]any{
			"run_id": "run_records", "verdict": "approved", "spec_digest": specDigest,
			"decision_id": "aud_decision", "reason_commitment": commitment,
		},
		"decision_nonce": hex.EncodeToString(recordTestBytes("nonce decision")),
		"reason_text":    reason, "reason_random": random,
	}
	recordRekey(decision, "decision")
	c := &recordCase{Payloads: []map[string]any{
		{"actor": "deploy-bot", "method": "POST", "path": "/v1/runs"},
		decision,
	}}
	if correction {
		const text = "approved after the change review, with the rollback plan attached"
		cr := hex.EncodeToString(recordTestBytes("random correction"))
		p := map[string]any{
			"actor": "ops-admin", "method": "REASON",
			"path": "/runs/run_records/decisions/aud_decision/corrections/aud_correction",
			"correction_body": map[string]any{
				"run_id": "run_records", "decision_id": "aud_decision",
				"correction_id":     "aud_correction",
				"reason_commitment": recordTestCommitment("aud_correction", cr, text),
			},
			"correction_nonce": hex.EncodeToString(recordTestBytes("nonce correction")),
			"reason_text":      text, "reason_random": cr,
		}
		recordRekey(p, "correction")
		c.Payloads = append(c.Payloads, p)
	}
	c.Payloads = append(c.Payloads, map[string]any{
		"actor": "system:dispatcher", "method": "RUN", "path": "/runs/run_records/outcome/succeeded",
		"content_digest": "sha256s:" + hex.EncodeToString(recordTestBytes("a")) + ":" +
			hex.EncodeToString(recordTestBytes("b")),
		"outcome_body":  `{"run_id":"run_records","status":"succeeded"}`,
		"outcome_nonce": hex.EncodeToString(recordTestBytes("nonce outcome")),
		"spec_body":     spec,
	})
	return c
}

// recordUnkeyed turns the case's decision into one recorded before nonces and reasons: a body with
// no reason, under the unkeyed digest, with an empty nonce.
func recordUnkeyed(c *recordCase) {
	p := c.decision()
	body := p["decision_body"].(map[string]any)
	delete(body, "decision_id")
	delete(body, "reason_commitment")
	delete(p, "reason_text")
	delete(p, "reason_random")
	canonical, err := jcs.Serialize(body)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(canonical)
	p["content_digest"] = "sha256:" + hex.EncodeToString(sum[:])
	p["decision_nonce"] = ""
}

// recordRebody edits a record body and recomputes the content digest over the edited body, so the
// body matches its digest and only what the body itself says can fail.
func recordRebody(p map[string]any, kind string, edit func(body map[string]any)) {
	edit(p[kind+"_body"].(map[string]any))
	recordRekey(p, kind)
}

// recordRekey sets the payload's content digest to the keyed digest of its record body under its
// nonce, the way a producer commits a record.
func recordRekey(p map[string]any, kind string) {
	nonce, _ := hex.DecodeString(p[kind+"_nonce"].(string))
	canonical, err := jcs.Serialize(p[kind+"_body"])
	if err != nil {
		panic(err)
	}
	nonceSum := sha256.Sum256(nonce)
	mac := hmac.New(sha256.New, nonce)
	mac.Write(canonical)
	p["content_digest"] = "sha256s:" + hex.EncodeToString(nonceSum[:]) + ":" +
		hex.EncodeToString(mac.Sum(nil))
}

// recordTestCommitment computes a reason commitment independently of the verifier.
func recordTestCommitment(event, random, text string) string {
	canonical, err := jcs.Serialize(map[string]any{"event": event, "random": random, "reason": text})
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// recordTestBytes returns 32 deterministic bytes for a label.
func recordTestBytes(label string) []byte {
	sum := sha256.Sum256([]byte("records test " + label))
	return sum[:]
}

// recordTestLink computes a switchtender-audit-v1 link over a payload's bound fields.
func recordTestLink(t *testing.T, seq int64, at, prev string, p map[string]any) string {
	t.Helper()
	fields := map[string]any{"seq": seq, "at": at, "prev": prev,
		"actor": p["actor"], "method": p["method"], "path": p["path"]}
	for _, key := range []string{"actor_type", "on_behalf_of", "content_digest", "install_id"} {
		if v, _ := p[key].(string); v != "" {
			fields[key] = v
		}
	}
	b, err := jcs.Serialize(fields)
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
