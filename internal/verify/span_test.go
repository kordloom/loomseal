package verify

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/kordloom/loomseal/internal/chain"
	"github.com/kordloom/loomseal/jcs"
	"github.com/kordloom/loomseal/merkle"
	"github.com/kordloom/loomseal/seal"
)

// spanTestEntry describes one claim in a span test chain.
type spanTestEntry struct {
	// Kind is "audit" or "span".
	Kind string
	// At is the claim time.
	At string
	// Beat is the span claim's beat number.
	Beat int64
	// Count is the span claim's declared entry count.
	Count int64
	// Stream overrides the span payload stream when set.
	Stream string
	// Cadence overrides the span payload cadence when set, in seconds.
	Cadence int64
}

// spanTestBundle builds a signed loomseal-chain-v1 bundle from entries, anchoring the head when
// anchored is true.
func spanTestBundle(t *testing.T, entries []spanTestEntry, anchored bool) []byte {
	t.Helper()
	priv := testKey()
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("public key type")
	}
	claims := make([]any, len(entries))
	prev := ""
	var lastLink string
	var lastSeq int64
	for i, e := range entries {
		var c map[string]any
		if e.Kind == "span" {
			stream := e.Stream
			if stream == "" {
				stream = "chain"
			}
			cadence := e.Cadence
			if cadence == 0 {
				cadence = 60
			}
			c = map[string]any{
				"type": "loomseal.span/1", "at": e.At,
				"payload": map[string]any{
					"stream": stream, "cadence_s": cadence, "beat": e.Beat, "count": e.Count,
				},
			}
		} else {
			c = auditClaim("amy")
			c["at"] = e.At
		}
		seq := int64(i + 1)
		link, err := chain.LinkV1(nil, "in_1", seq, prev, c)
		if err != nil {
			t.Fatalf("link %d: %v", seq, err)
		}
		c["chain"] = map[string]any{"seq": seq, "prev": prev, "link": link}
		claims[i] = c
		prev, lastLink, lastSeq = link, link, seq
	}
	m := map[string]any{
		"loomseal":   "0.1",
		"bundle_id":  "lsb_span",
		"created_at": at,
		"producer": map[string]any{
			"product": "test", "product_version": "1", "install_id": "in_1",
			"public_key": base64Std(pub), "key_id": seal.KeyID(pub),
		},
		"subject": map[string]any{"type": "fleet", "id": "yard"},
		"chain": map[string]any{
			"profile": "loomseal-chain-v1", "keyed": false,
			"params": map[string]any{"install_id": "in_1"},
			"head":   map[string]any{"seq": lastSeq, "link": lastLink},
		},
		"claims": claims,
	}
	if anchored {
		m["anchors"] = []any{map[string]any{
			"type": "git", "seq": lastSeq, "link": lastLink, "at": at,
			"ref": "https://github.com/acme/anchors/commit/abc",
		}}
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signed, err := seal.SignBundle(raw, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

// spanBase returns the standard two-beat chain the span cases mutate.
func spanBase() []spanTestEntry {
	return []spanTestEntry{
		{Kind: "audit", At: "2026-07-27T12:00:10Z"},
		{Kind: "span", At: "2026-07-27T12:01:00Z", Beat: 1, Count: 1},
		{Kind: "audit", At: "2026-07-27T12:01:30Z"},
		{Kind: "span", At: "2026-07-27T12:02:00Z", Beat: 2, Count: 1},
	}
}

//nolint:funlen // Test function.
func TestSpan(t *testing.T) {
	t.Parallel()

	gapped := spanBase()
	gapped[3].At = "2026-07-27T12:04:00Z"
	falseCount := spanBase()
	falseCount[3].Count = 5
	missingBeat := spanBase()
	missingBeat[3].Beat = 3
	badFirstCount := spanBase()
	badFirstCount[1].Count = 9
	badStream := spanBase()
	badStream[3].Stream = "iam"
	jittered := spanBase()
	jittered[3].At = "2026-07-27T12:02:00.004Z"
	late := spanBase()
	late[3].At = "2026-07-27T12:02:05Z"
	halfWindow := spanBase()
	halfWindow[3].At = "2026-07-27T12:03:30Z"
	slackEdge := spanBase()
	slackEdge[3].At = "2026-07-27T12:02:01Z"
	slackPast := spanBase()
	slackPast[3].At = "2026-07-27T12:02:02Z"
	microPastEdge := spanBase()
	microPastEdge[3].At = "2026-07-27T12:02:01.000001Z"
	proportionalEdge := spanBase()
	proportionalEdge[1].Cadence, proportionalEdge[3].Cadence = 600, 600
	proportionalEdge[3].At = "2026-07-27T12:11:06Z"
	proportionalPast := spanBase()
	proportionalPast[1].Cadence, proportionalPast[3].Cadence = 600, 600
	proportionalPast[3].At = "2026-07-27T12:11:07Z"
	subMicroPastEdge := spanBase()
	subMicroPastEdge[3].At = "2026-07-27T12:02:01.0000001Z"
	halfSecondUp := spanBase()
	halfSecondUp[3].At = "2026-07-27T12:02:02.5Z"
	belowHalfSecond := spanBase()
	belowHalfSecond[3].At = "2026-07-27T12:02:02.4999995Z"
	centuries := spanBase()
	centuries[3].At = "2400-01-01T00:00:00Z"
	maxCadence := spanBase()
	maxCadence[1].Cadence, maxCadence[3].Cadence = maxCadenceS, maxCadenceS
	maxCadence[3].At = "2400-01-01T00:00:00Z"
	pastMaxCadence := spanBase()
	pastMaxCadence[1].Cadence, pastMaxCadence[3].Cadence = maxCadenceS+1, maxCadenceS+1
	hugeCadence := spanBase()
	hugeCadence[1].Cadence, hugeCadence[3].Cadence = 10_000_000_000, 10_000_000_000
	hugeCadence[3].At = "2026-07-27T12:04:00Z"

	tests := []struct {
		Entries      []spanTestEntry
		Anchored     bool
		WantOK       bool
		WantSpanOK   bool
		WantLevel    string
		WantCoverage string
		WantGaps     int
		WantGapLines []string
		WantLongest  string
		WantCarried  int
		WantProblem  string
	}{{ // Test 0: Two verifiable beats on an anchored chain earn the spanned level.
		Entries: spanBase(), Anchored: true, WantOK: true, WantSpanOK: true,
		WantLevel:    "signed, chained (full), anchored by reference, spanned",
		WantCoverage: "2/2 windows attested",
	}, { // Test 1: The same chain unanchored verifies but never reaches spanned.
		Entries: spanBase(), WantOK: true, WantSpanOK: true,
		WantLevel:    "signed, chained (full)",
		WantCoverage: "2/2 windows attested",
	}, { // Test 2: Beats further apart than the cadence report a gap and still verify.
		Entries: gapped, Anchored: true, WantOK: true, WantSpanOK: true,
		WantLevel:    "signed, chained (full), anchored by reference, spanned",
		WantCoverage: "2/4 windows attested", WantGaps: 1,
	}, { // Test 3: A count that contradicts the sequence numbers fails the bundle.
		Entries: falseCount, Anchored: true,
		WantProblem: "the chain shows",
	}, { // Test 4: A skipped beat number is a deleted window and fails.
		Entries: missingBeat, Anchored: true,
		WantProblem: "a missing beat is a deleted window",
	}, { // Test 5: A chain adopting the profile mid-life attests its prior population at beat 1.
		Entries: []spanTestEntry{
			{Kind: "audit", At: "2026-07-27T12:00:10Z"},
			{Kind: "audit", At: "2026-07-27T12:00:20Z"},
			{Kind: "span", At: "2026-07-27T12:01:00Z", Beat: 1, Count: 2},
		}, Anchored: true, WantOK: true, WantSpanOK: true,
		WantLevel:    "signed, chained (full), anchored by reference, spanned",
		WantCoverage: "1/1 windows attested",
	}, { // Test 6: A first beat past 1 leaves its count carried, never trusted, never failed.
		Entries: []spanTestEntry{
			{Kind: "audit", At: "2026-07-27T12:00:10Z"},
			{Kind: "span", At: "2026-07-27T12:01:00Z", Beat: 2, Count: 7},
		}, Anchored: true, WantOK: true, WantSpanOK: true,
		WantLevel:    "signed, chained (full), anchored by reference, spanned",
		WantCoverage: "1/1 windows attested", WantCarried: 1,
	}, { // Test 7: Beat 1 counting anything but its own position fails.
		Entries: badFirstCount, Anchored: true,
		WantProblem: "its position shows",
	}, { // Test 8: A stream this format does not define fails the claim.
		Entries: badStream, Anchored: true,
		WantProblem: "this format defines only",
	}, { // Test 9: A beat milliseconds past the cadence is a timer's scheduling, not a gap.
		Entries: jittered, Anchored: true, WantOK: true, WantSpanOK: true,
		WantLevel:    "signed, chained (full), anchored by reference, spanned",
		WantCoverage: "2/2 windows attested", WantGaps: 0,
	}, { // Test 10: A beat seconds past a one minute cadence is past the slack and is reported.
		Entries: late, Anchored: true, WantOK: true, WantSpanOK: true,
		WantLevel:    "signed, chained (full), anchored by reference, spanned",
		WantCoverage: "2/2 windows attested", WantGaps: 1,
	}, { // Test 11: A gap of two and a half cadences counts three windows, halves rounding up,
		// and is worded in whole seconds with the beat times beside it.
		Entries: halfWindow, Anchored: true, WantOK: true, WantSpanOK: true,
		WantLevel:    "signed, chained (full), anchored by reference, spanned",
		WantCoverage: "2/4 windows attested", WantGaps: 1, WantLongest: "150s",
		WantGapLines: []string{"unattested window of 150s between beat 1 " +
			"(2026-07-27T12:01:00Z) and beat 2 (2026-07-27T12:03:30Z)"},
	}, { // Test 12: A beat exactly one slack past a one minute cadence is on time.
		Entries: slackEdge, Anchored: true, WantOK: true, WantSpanOK: true,
		WantLevel:    "signed, chained (full), anchored by reference, spanned",
		WantCoverage: "2/2 windows attested", WantGaps: 0, WantGapLines: []string{},
	}, { // Test 13: A beat one second past the slack is a gap that missed no whole window.
		Entries: slackPast, Anchored: true, WantOK: true, WantSpanOK: true,
		WantLevel:    "signed, chained (full), anchored by reference, spanned",
		WantCoverage: "2/2 windows attested", WantGaps: 1, WantLongest: "62s",
		WantGapLines: []string{"unattested window of 62s between beat 1 " +
			"(2026-07-27T12:01:00Z) and beat 2 (2026-07-27T12:02:02Z)"},
	}, { // Test 14: A beat a microsecond past the slack is a gap, worded to the whole second.
		Entries: microPastEdge, Anchored: true, WantOK: true, WantSpanOK: true,
		WantLevel:    "signed, chained (full), anchored by reference, spanned",
		WantCoverage: "2/2 windows attested", WantGaps: 1, WantLongest: "61s",
		WantGapLines: []string{"unattested window of 61s between beat 1 " +
			"(2026-07-27T12:01:00Z) and beat 2 (2026-07-27T12:02:01Z)"},
	}, { // Test 15: At a ten minute cadence the slack is six seconds, so six seconds late is on
		// time.
		Entries: proportionalEdge, Anchored: true, WantOK: true, WantSpanOK: true,
		WantLevel:    "signed, chained (full), anchored by reference, spanned",
		WantCoverage: "2/2 windows attested", WantGaps: 0, WantGapLines: []string{},
	}, { // Test 16: At a ten minute cadence seven seconds late is past the slack and is a gap.
		Entries: proportionalPast, Anchored: true, WantOK: true, WantSpanOK: true,
		WantLevel:    "signed, chained (full), anchored by reference, spanned",
		WantCoverage: "2/2 windows attested", WantGaps: 1, WantLongest: "607s",
		WantGapLines: []string{"unattested window of 607s between beat 1 " +
			"(2026-07-27T12:01:00Z) and beat 2 (2026-07-27T12:11:07Z)"},
	}, { // Test 17: A beat a tenth of a microsecond past the slack is on time, because beat times
		// are read to the microsecond with finer digits dropped.
		Entries: subMicroPastEdge, Anchored: true, WantOK: true, WantSpanOK: true,
		WantLevel:    "signed, chained (full), anchored by reference, spanned",
		WantCoverage: "2/2 windows attested", WantGaps: 0, WantGapLines: []string{},
	}, { // Test 18: A gap of 62.5s rounds up to 63s while the beat time drops its fraction.
		Entries: halfSecondUp, Anchored: true, WantOK: true, WantSpanOK: true,
		WantLevel:    "signed, chained (full), anchored by reference, spanned",
		WantCoverage: "2/2 windows attested", WantGaps: 1, WantLongest: "63s",
		WantGapLines: []string{"unattested window of 63s between beat 1 " +
			"(2026-07-27T12:01:00Z) and beat 2 (2026-07-27T12:02:02Z)"},
	}, { // Test 19: A gap of 62.4999995s reads 62s, its half microsecond dropped before rounding.
		Entries: belowHalfSecond, Anchored: true, WantOK: true, WantSpanOK: true,
		WantLevel:    "signed, chained (full), anchored by reference, spanned",
		WantCoverage: "2/2 windows attested", WantGaps: 1, WantLongest: "62s",
		WantGapLines: []string{"unattested window of 62s between beat 1 " +
			"(2026-07-27T12:01:00Z) and beat 2 (2026-07-27T12:02:02Z)"},
	}, { // Test 20: Beats centuries apart are measured exactly, never clamped.
		Entries: centuries, Anchored: true, WantOK: true, WantSpanOK: true,
		WantLevel:    "signed, chained (full), anchored by reference, spanned",
		WantCoverage: "2/196405200 windows attested", WantGaps: 1, WantLongest: "11784311940s",
		WantGapLines: []string{"unattested window of 11784311940s between beat 1 " +
			"(2026-07-27T12:01:00Z) and beat 2 (2400-01-01T00:00:00Z)"},
	}, { // Test 21: The widest cadence the format allows measures a gap of centuries exactly.
		Entries: maxCadence, Anchored: true, WantOK: true, WantSpanOK: true,
		WantLevel:    "signed, chained (full), anchored by reference, spanned",
		WantCoverage: "2/374 windows attested", WantGaps: 1, WantLongest: "11784311940s",
		WantGapLines: []string{"unattested window of 11784311940s between beat 1 " +
			"(2026-07-27T12:01:00Z) and beat 2 (2400-01-01T00:00:00Z)"},
	}, { // Test 22: A cadence one second past the widest the format allows fails the claim.
		Entries: pastMaxCadence, Anchored: true,
		WantProblem: "want an integer from 1 to 31622400",
	}, { // Test 23: A cadence too wide for a nanosecond duration fails the claim, not the math.
		Entries: hugeCadence, Anchored: true,
		WantProblem: "want an integer from 1 to 31622400",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := Run(spanTestBundle(t, test.Entries, test.Anchored), Options{})
			if got.OK != test.WantOK {
				t.Errorf("ok %t, want %t; problems %v", got.OK, test.WantOK, got.Problems)
			}
			if !got.SpanPresent {
				t.Error("span claims present but not reported")
			}
			if got.SpanOK != test.WantSpanOK {
				t.Errorf("span ok %t, want %t; problems %v", got.SpanOK, test.WantSpanOK,
					got.Problems)
			}
			if test.WantLevel != "" && got.Level != test.WantLevel {
				t.Errorf("level %q, want %q", got.Level, test.WantLevel)
			}
			if test.WantCoverage != "" && got.SpanCoverage != test.WantCoverage {
				t.Errorf("coverage %q, want %q", got.SpanCoverage, test.WantCoverage)
			}
			if len(got.SpanGaps) != test.WantGaps {
				t.Errorf("gaps %d, want %d: %v", len(got.SpanGaps), test.WantGaps, got.SpanGaps)
			}
			if test.WantGapLines != nil {
				lines := cmp.Diff(test.WantGapLines, got.SpanGaps, cmpopts.EquateEmpty())
				if lines != "" {
					t.Errorf("gap lines (-want +got):\n%s", lines)
				}
				if diff := cmp.Diff(test.WantLongest, got.SpanLongestGap); diff != "" {
					t.Errorf("longest gap (-want +got):\n%s", diff)
				}
			}
			if got.SpanCountsCarried != test.WantCarried {
				t.Errorf("carried %d, want %d", got.SpanCountsCarried, test.WantCarried)
			}
			if test.WantProblem != "" && !problemContains(got, test.WantProblem) {
				t.Errorf("problems %v do not mention %q", got.Problems, test.WantProblem)
			}
		})
	}
}

// problemContains reports whether any recorded problem mentions substr.
func problemContains(r *Report, substr string) bool {
	for _, p := range r.Problems {
		if strings.Contains(p, substr) {
			return true
		}
	}
	return false
}

// TestSpanTimeMustAdvance pins the monotonic-time rule between beats. A beat whose time
// equals its predecessor's is a stalled clock, which the boundary of the gap check would
// otherwise quietly absorb.
func TestSpanTimeMustAdvance(t *testing.T) {
	t.Parallel()
	stalled := spanBase()
	stalled[3].At = stalled[1].At
	got := Run(spanTestBundle(t, stalled, true), Options{})
	if got.SpanOK {
		t.Errorf("span ok %t, want false; problems %v", got.SpanOK, got.Problems)
	}
	if !problemContains(got, "does not advance") {
		t.Errorf("problems %v do not mention the stalled clock", got.Problems)
	}
}

// TestSpanPayloadBounds pins the span payload floor values: a cadence below one second
// and a negative count are each named as problems on their own.
func TestSpanPayloadBounds(t *testing.T) {
	t.Parallel()

	// Test 0: a zero cadence is refused.
	zeroCadence := spanBase()
	zeroCadence[1].Cadence = -1
	got := Run(spanTestBundle(t, zeroCadence, true), Options{})
	if got.SpanOK || !problemContains(got, "cadence_s") {
		t.Errorf("span ok %t problems %v, want a cadence problem", got.SpanOK, got.Problems)
	}

	// Test 1: a negative count is refused.
	negCount := spanBase()
	negCount[1].Count = -2
	got = Run(spanTestBundle(t, negCount, true), Options{})
	if got.SpanOK || !problemContains(got, "count -2") {
		t.Errorf("span ok %t problems %v, want a count problem", got.SpanOK, got.Problems)
	}
}

// TestSpanBoundaryValues pins the legal floor of each span payload field and the report
// fields a clean run must leave empty: a cadence of exactly one second and a window
// counting zero entries are both valid, a single-gap run names that gap as the longest,
// and a gapless run reports no longest gap at all.
func TestSpanBoundaryValues(t *testing.T) {
	t.Parallel()

	// Test 0: cadence one and count zero are the legal floors.
	floor := []spanTestEntry{
		{Kind: "span", At: "2026-07-27T12:01:00Z", Beat: 1, Count: 0, Cadence: 1},
		{Kind: "span", At: "2026-07-27T12:01:01Z", Beat: 2, Count: 0, Cadence: 1},
	}
	got := Run(spanTestBundle(t, floor, true), Options{})
	if !got.SpanOK {
		t.Errorf("floor values refused: %v", got.Problems)
	}

	// Test 1: a gapless run reports no longest gap.
	if got.SpanLongestGap != "" {
		t.Errorf("gapless longest gap %q, want empty", got.SpanLongestGap)
	}

	// Test 2: a run with one gap names it as the longest.
	gapped := spanBase()
	gapped[3].At = "2026-07-27T12:04:00Z"
	got = Run(spanTestBundle(t, gapped, true), Options{})
	if got.SpanLongestGap != "180s" {
		t.Errorf("longest gap %q, want 180s", got.SpanLongestGap)
	}

	// Test 3: a bundle with no span claims reports no coverage line at all.
	noSpans := []spanTestEntry{{Kind: "audit", At: "2026-07-27T12:00:10Z"}}
	got = Run(spanTestBundle(t, noSpans, true), Options{})
	if got.SpanCoverage != "" || got.SpanPresent {
		t.Errorf("spanless coverage %q present %t, want empty and false", got.SpanCoverage,
			got.SpanPresent)
	}
}

// TestSpanCadenceOutOfRange pins that a cadence past the format's range is refused before any
// arithmetic runs on it, even in a bundle whose signature and canonical form already failed. A
// cadence of 2^55 seconds wraps to zero nanoseconds and one of 2^58 seconds wraps to zero
// microseconds, and measuring either would divide by zero.
func TestSpanCadenceOutOfRange(t *testing.T) {
	t.Parallel()
	gapped := spanBase()
	gapped[3].At = "2026-07-27T12:04:00Z"
	signed := string(spanTestBundle(t, gapped, true))
	tests := []struct {
		Cadence     string
		WantProblem string
	}{{ // Test 0: A cadence whose nanosecond product wraps to zero is refused.
		Cadence: "36028797018963968", WantProblem: "want an integer from 1 to 31622400",
	}, { // Test 1: The largest int64 cadence is refused.
		Cadence: "9223372036854775807", WantProblem: "want an integer from 1 to 31622400",
	}, { // Test 2: A cadence past int64 is refused.
		Cadence: "18446744073709551616", WantProblem: "want an integer from 1 to 31622400",
	}, { // Test 3: A cadence whose microsecond product wraps to zero is refused.
		Cadence: "288230376151711744", WantProblem: "want an integer from 1 to 31622400",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			defer func() {
				if p := recover(); p != nil {
					t.Fatalf("verify panicked on cadence %s: %v", test.Cadence, p)
				}
			}()
			doc := strings.Replace(signed, `"cadence_s":60`, `"cadence_s":`+test.Cadence, 1)
			if doc == signed {
				t.Fatal("bundle carries no cadence to replace")
			}
			got := Run([]byte(doc), Options{})
			if got.OK || got.SpanOK {
				t.Errorf("ok %t span ok %t, want both false", got.OK, got.SpanOK)
			}
			if !problemContains(got, test.WantProblem) {
				t.Errorf("problems %v do not mention %q", got.Problems, test.WantProblem)
			}
		})
	}
}

// TestSpanMeasure pins the integer helpers the gap measurement uses at their rounding edges.
func TestSpanMeasure(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Micros     int64
		Cadence    int64
		WantWhole  string
		WantMissed int64
		WantTime   string
	}{{ // Test 0: Half a second rounds the duration up and the beat time down.
		Micros: 62_500_000, Cadence: 60_000_000, WantWhole: "63s", WantMissed: 0,
		WantTime: "1970-01-01T00:01:02Z",
	}, { // Test 1: A microsecond under half a second rounds the duration down.
		Micros: 62_499_999, Cadence: 60_000_000, WantWhole: "62s", WantMissed: 0,
		WantTime: "1970-01-01T00:01:02Z",
	}, { // Test 2: Two and a half cadences count three windows, so two were missed.
		Micros: 150_000_000, Cadence: 60_000_000, WantWhole: "150s", WantMissed: 2,
		WantTime: "1970-01-01T00:02:30Z",
	}, { // Test 3: A beat before the epoch drops its fraction toward the earlier second.
		Micros: -500_000, Cadence: 1_000_000, WantWhole: "0s", WantMissed: 0,
		WantTime: "1969-12-31T23:59:59Z",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			if diff := cmp.Diff(test.WantWhole, wholeSeconds(test.Micros)); diff != "" {
				t.Errorf("whole seconds mismatch (-want +got):\n%s", diff)
			}
			missed := missedWindows(test.Micros, test.Cadence)
			if diff := cmp.Diff(test.WantMissed, missed); diff != "" {
				t.Errorf("missed windows mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantTime, beatTime(test.Micros)); diff != "" {
				t.Errorf("beat time mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// merkleSpanBundle builds a signed loomseal-merkle-v1 bundle whose one leaf is a span claim. The
// leaf and the root are honest, so nothing but the span rule itself can refuse the bundle.
func merkleSpanBundle(t *testing.T) []byte {
	t.Helper()
	priv := testKey()
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		t.Fatal("public key type")
	}
	claim := map[string]any{
		"type": "loomseal.span/1", "at": at,
		"payload": map[string]any{"stream": "chain", "cadence_s": 60, "beat": 1, "count": 0},
	}
	content, err := jcs.Serialize(claim)
	if err != nil {
		t.Fatalf("canonicalize claim: %v", err)
	}
	leaf, err := jcs.Serialize(map[string]any{
		"domain": "loomseal-merkle-v1", "install_id": "in_1", "claim": digestOf(content),
	})
	if err != nil {
		t.Fatalf("canonicalize leaf: %v", err)
	}
	root := hex.EncodeToString(merkle.Root([][]byte{leaf}))
	claim["chain"] = map[string]any{
		"seq": 1, "prev": "", "link": hex.EncodeToString(merkle.LeafHash(leaf)),
	}
	claim["inclusion"] = map[string]any{"path": []any{}}
	m := map[string]any{
		"loomseal":   "0.1",
		"bundle_id":  "lsb_tree_span",
		"created_at": at,
		"producer": map[string]any{
			"product": "test", "product_version": "1", "install_id": "in_1",
			"public_key": base64Std(pub), "key_id": seal.KeyID(pub),
		},
		"subject": map[string]any{"type": "fleet", "id": "yard"},
		"chain": map[string]any{
			"profile": "loomseal-merkle-v1", "keyed": false,
			"params": map[string]any{"install_id": "in_1"},
			"head":   map[string]any{"seq": 1, "link": root},
		},
		"claims": []any{claim},
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signed, err := seal.SignBundle(raw, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed
}

// TestSpanInTreeBundle pins the refusal of a span claim under the tree profile and the report it
// leaves: the span is present and not ok, so a manifest naming the span check can hold every
// verifier to the same failing step.
func TestSpanInTreeBundle(t *testing.T) {
	t.Parallel()
	got := Run(merkleSpanBundle(t), Options{})
	if got.OK {
		t.Error("a span claim in a tree bundle verified")
	}
	if !got.SignatureOK || !got.ChainOK {
		t.Errorf("signature ok %t chain ok %t, want both true so the span rule alone refuses it",
			got.SignatureOK, got.ChainOK)
	}
	if !got.SpanPresent {
		t.Error("span claim present but not reported")
	}
	if got.SpanOK {
		t.Error("span reported ok under the tree profile")
	}
	want := "is a span claim, which the loomseal-merkle-v1 profile does not carry"
	if !problemContains(got, want) {
		t.Errorf("problems %v do not name the tree profile rule", got.Problems)
	}
}
