package verify

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/kordloom/loomseal/internal/chain"
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
			c = map[string]any{
				"type": "loomseal.span/1", "at": e.At,
				"payload": map[string]any{
					"stream": stream, "cadence_s": 60, "beat": e.Beat, "count": e.Count,
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

	tests := []struct {
		Entries      []spanTestEntry
		Anchored     bool
		WantOK       bool
		WantSpanOK   bool
		WantLevel    string
		WantCoverage string
		WantGaps     int
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
