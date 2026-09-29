package verify

import (
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/kordloom/loomseal/internal/bundle"
)

// spanType is the spec-owned population attestation claim type.
const spanType = "loomseal.span/1"

// spanPayload is the loomseal.span/1 claim body the registry fixes.
type spanPayload struct {
	// Stream names the counted population; "chain" is the only stream this format defines.
	Stream string `json:"stream"`
	// CadenceS is the declared beat interval in whole seconds.
	CadenceS int64 `json:"cadence_s"`
	// Beat is the 1-based attestation counter, incremented by exactly 1 per span claim.
	Beat int64 `json:"beat"`
	// Count is the number of entries appended since the previous beat.
	Count int64 `json:"count"`
}

// spanClaim is one parsed span claim with the coordinates the checks run on.
type spanClaim struct {
	// payload is the decoded claim body.
	payload spanPayload
	// seq is the claim's position in the chain.
	seq int64
	// at is the beat time.
	at time.Time
}

// checkSpan verifies loomseal.span/1 population attestations. A false count or a missing beat
// number is a contradiction and fails the bundle. Beats further apart than the declared cadence
// are gaps, reported with their bounds and never hidden, because coverage is a measurement and
// not a badge. Whether a chain that simply stops beating did so honestly is not answerable from
// a file; that detection belongs to a published feed where a missing beat is visible.
func (r *Report) checkSpan(b *bundle.Bundle) {
	before := len(r.Problems)
	var spans []spanClaim
	for i, c := range b.Claims {
		if c.Type != spanType {
			continue
		}
		r.SpanPresent = true
		s, ok := r.parseSpanClaim(i, c)
		if ok {
			spans = append(spans, s)
		}
	}
	if !r.SpanPresent {
		return
	}
	if b.Chain == nil {
		r.problem("span claims present without a chain declaration")
	}
	r.SpanBeats = len(spans)
	r.checkSpanFirst(spans)
	r.checkSpanPairs(spans)
	r.SpanOK = len(r.Problems) == before
}

// parseSpanClaim decodes and validates one span claim, recording problems on the report.
func (r *Report) parseSpanClaim(i int, c bundle.Claim) (spanClaim, bool) {
	if c.Chain == nil {
		r.problem("span claim %d has no chain coordinates", i)
		return spanClaim{}, false
	}
	var p spanPayload
	if err := json.Unmarshal(c.Payload, &p); err != nil {
		r.problem("span claim %d payload: %v", i, err)
		return spanClaim{}, false
	}
	switch {
	case p.Stream != "chain":
		r.problem("span claim %d stream %q: this format defines only %q", i, p.Stream, "chain")
		return spanClaim{}, false
	case p.CadenceS < 1:
		r.problem("span claim %d cadence_s %d, want at least 1", i, p.CadenceS)
		return spanClaim{}, false
	case p.Beat < 1:
		r.problem("span claim %d beat %d, want at least 1", i, p.Beat)
		return spanClaim{}, false
	case p.Count < 0:
		r.problem("span claim %d count %d, want at least 0", i, p.Count)
		return spanClaim{}, false
	}
	at, err := time.Parse(time.RFC3339, c.At)
	if err != nil {
		r.problem("span claim %d at: %v", i, err)
		return spanClaim{}, false
	}
	return spanClaim{payload: p, seq: c.Chain.Seq, at: at}, true
}

// checkSpanFirst verifies the bundle's first span claim. Beat 1 commits to every entry before
// it, so its count is arithmetic even when the bundle opens mid-chain. A later first beat left
// its predecessor outside the window, so its count is carried, never trusted.
func (r *Report) checkSpanFirst(spans []spanClaim) {
	if len(spans) == 0 {
		return
	}
	first := spans[0]
	if first.payload.Beat != 1 {
		r.SpanCountsCarried++
		return
	}
	if want := first.seq - 1; first.payload.Count != want {
		r.problem("span beat 1 counts %d entries before it, its position shows %d",
			first.payload.Count, want)
		return
	}
	r.SpanCountsVerified++
}

// checkSpanPairs verifies every consecutive span claim pair: beat contiguity, the count against
// the sequence difference, and beat times against the declared cadence. It accumulates the gap
// report and the coverage wording.
func (r *Report) checkSpanPairs(spans []spanClaim) {
	var missed int64
	var longest time.Duration
	for i := 1; i < len(spans); i++ {
		prev, cur := spans[i-1], spans[i]
		if cur.payload.Beat != prev.payload.Beat+1 {
			r.problem("span beat %d follows beat %d: a missing beat is a deleted window",
				cur.payload.Beat, prev.payload.Beat)
			continue
		}
		if want := cur.seq - prev.seq - 1; cur.payload.Count != want {
			r.problem("span beat %d counts %d entries since beat %d, the chain shows %d",
				cur.payload.Beat, cur.payload.Count, prev.payload.Beat, want)
		} else {
			r.SpanCountsVerified++
		}
		delta := cur.at.Sub(prev.at)
		if delta <= 0 {
			r.problem("span beat %d time does not advance past beat %d",
				cur.payload.Beat, prev.payload.Beat)
			continue
		}
		cadence := time.Duration(prev.payload.CadenceS) * time.Second
		if delta <= cadence {
			continue
		}
		r.SpanGaps = append(r.SpanGaps,
			fmt.Sprintf("unattested window of %s between beat %d (%s) and beat %d (%s)",
				delta.Round(time.Second), prev.payload.Beat, prev.at.Format(time.RFC3339),
				cur.payload.Beat, cur.at.Format(time.RFC3339)))
		if delta > longest {
			longest = delta
		}
		if m := int64(math.Round(delta.Seconds()/cadence.Seconds())) - 1; m > 0 {
			missed += m
		}
	}
	if longest > 0 {
		r.SpanLongestGap = longest.Round(time.Second).String()
	}
	if len(spans) > 0 {
		r.SpanCoverage = fmt.Sprintf("%d/%d windows attested", len(spans),
			int64(len(spans))+missed)
	}
}
