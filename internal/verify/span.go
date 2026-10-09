package verify

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/kordloom/loomseal/internal/bundle"
	"github.com/kordloom/loomseal/jcs"
)

// spanType is the spec-owned population attestation claim type.
const spanType = "loomseal.span/1"

// maxCadenceS is the widest cadence a span claim may declare, the seconds in a 366-day year. A
// heartbeat slower than that attests nothing a reader can use, and the bound keeps every quantity
// the gap measurement forms inside a signed 64-bit count of microseconds, so no verifier wraps.
const maxCadenceS = 366 * 24 * 60 * 60

// microsPerSecond is the number of microseconds in a second. A gap is measured in microseconds.
const microsPerSecond = int64(time.Second / time.Microsecond)

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
	// at is the beat time in whole microseconds since the Unix epoch, finer digits dropped.
	at int64
}

// checkSpan verifies loomseal.span/1 population attestations. A false count or a missing beat
// number is a contradiction and fails the bundle. Beats further apart than the declared cadence
// are gaps, reported with their bounds and never hidden, because coverage is a measurement and
// not a badge. Whether a chain that simply stops beating did so honestly is not answerable from
// a file; that detection belongs to a published feed where a missing beat is visible.
func (r *Report) checkSpan(b *bundle.Bundle, st memberStates) {
	before := len(r.Problems)
	// LoomSpan is defined over the linear profiles. Its beats carry a non-empty chain.prev and its
	// coverage requires contiguous beats, and the tree profile forbids both by design: a tree has no
	// per-entry predecessor, and selective disclosure is the point of it. A span claim in a tree
	// bundle is therefore refused rather than checked, because attempting a check the profile cannot
	// satisfy would report a coverage answer that means nothing.
	treeProfile := b.Chain != nil && b.Chain.Profile == bundle.ProfileMerkle
	// A switchtender-audit-v1 link commits a claim's path and not the span members beside it, so
	// under that profile the members are bound through the path the producer wrote them into.
	pathBound := b.Chain != nil && b.Chain.Profile == bundle.ProfileSwitchTender
	var spans []spanClaim
	for i, c := range b.Claims {
		if c.Type != spanType {
			continue
		}
		r.SpanPresent = true
		if treeProfile {
			r.problem("claim %d is a span claim, which the %s profile does not carry", i,
				bundle.ProfileMerkle)
			return
		}
		s, ok := r.parseSpanClaim(i, c)
		if ok && pathBound {
			ok = r.checkSpanPath(i, c, st)
		}
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
//
// Every counted value is read from the exact canonical member of the parsed payload, never from a
// case-insensitive struct decode. A span payload is not covered by a switchtender-audit-v1 link, so
// folding beat or count onto a struct field from a case variant no reader sees would let the Go
// span check pass over a population the record does not state, while the Python verifier, reading
// the exact member, disagreed. Reading the exact member keeps the two verifiers on the same
// numbers.
func (r *Report) parseSpanClaim(i int, c bundle.Claim) (spanClaim, bool) {
	if c.Chain == nil {
		r.problem("span claim %d has no chain coordinates", i)
		return spanClaim{}, false
	}
	tree, err := jcs.Parse(c.Payload)
	if err != nil {
		r.problem("span claim %d payload: %v", i, err)
		return spanClaim{}, false
	}
	payload, ok := tree.(map[string]any)
	if !ok {
		r.problem("span claim %d payload is not an object", i)
		return spanClaim{}, false
	}
	var p spanPayload
	if s, ok := payload["stream"].(string); ok {
		p.Stream = s
	}
	cadence, cadenceOK := intMember(payload, "cadence_s")
	beat, beatOK := intMember(payload, "beat")
	count, countOK := intMember(payload, "count")
	p.CadenceS, p.Beat, p.Count = cadence, beat, count
	switch {
	case p.Stream != "chain":
		r.problem("span claim %d stream %q: this format defines only %q", i, p.Stream, "chain")
		return spanClaim{}, false
	case !cadenceOK || p.CadenceS < 1 || p.CadenceS > maxCadenceS:
		r.problem("span claim %d cadence_s %v, want an integer from 1 to %d", i,
			payload["cadence_s"], maxCadenceS)
		return spanClaim{}, false
	case !beatOK || p.Beat < 1:
		r.problem("span claim %d beat %v, want an integer of at least 1", i, payload["beat"])
		return spanClaim{}, false
	case !countOK || p.Count < 0:
		r.problem("span claim %d count %v, want an integer of at least 0", i, payload["count"])
		return spanClaim{}, false
	}
	at, err := bundle.ParseTime(c.At)
	if err != nil {
		r.problem("span claim %d at: %v", i, err)
		return spanClaim{}, false
	}
	// Beat times are measured in whole microseconds, with finer digits dropped toward the earlier
	// instant, so a verifier whose time type stops at microseconds measures the same interval as
	// this one. A four-digit year keeps the count far inside an int64.
	return spanClaim{payload: p, seq: c.Chain.Seq, at: at.UnixMicro()}, true
}

// checkSpanPath binds a span claim's members to the path a switchtender-audit-v1 link commits:
// /span/<beat>?count=<count>&cadence_s=<cadence_s>. Without it the members ride beside the link,
// and a producer re-signing its own bundle could widen the cadence to hide a gap or renumber the
// beats, with every link still recomputing.
//
// The members are read from the parsed payload by their exact names. A name that differs from one
// of them only in case is refused: a reader folding case onto the member would see a beat or a
// cadence the path never committed.
func (r *Report) checkSpanPath(i int, c bundle.Claim, st memberStates) bool {
	tree, err := jcs.Parse(c.Payload)
	payload, ok := tree.(map[string]any)
	if err != nil || !ok {
		r.problem("span claim %d payload is not an object", i)
		return false
	}
	members := make([]string, 0, len(declared.Types[spanType]))
	for name := range declared.Types[spanType] {
		members = append(members, name)
	}
	sort.Strings(members)
	if variant, member, found := caseVariant(payload, members); found {
		r.problem("span claim %d carries %q, which differs from %s only in case, so a reader that "+
			"folds case would take one for the other", i, variant, member)
		return false
	}
	path, _ := payload["path"].(string)
	stream, _ := payload["stream"].(string)
	beat, beatOK := intMember(payload, "beat")
	count, countOK := intMember(payload, "count")
	cadence, cadenceOK := intMember(payload, "cadence_s")
	want := fmt.Sprintf("/span/%d?count=%d&cadence_s=%d", beat, count, cadence)
	if stream != "chain" || !beatOK || !countOK || !cadenceOK || path != want {
		r.problem("span claim %d members do not match the span path its link commits: path %q, "+
			"members read %q", i, path, want)
		return false
	}
	for _, m := range members {
		st.settleDeclared(i, spanType, m)
	}
	return true
}

// intMember reads a payload member as an integer, reporting whether it was present and a whole
// number. A member written with a fraction or an exponent is not an integer and reads as absent, so
// a span count cannot slip through as a float the way a struct decode into an int64 would reject
// but a case-folded sibling would not.
func intMember(payload map[string]any, key string) (int64, bool) {
	num, ok := payload[key].(json.Number)
	if !ok {
		return 0, false
	}
	v, err := num.Int64()
	if err != nil {
		return 0, false
	}
	return v, true
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

// scheduleSlack is how far past its cadence a beat may land and still count as on time: a hundredth
// of the cadence and never under a second, as the format states, both in microseconds. A beat is
// written when a timer fires, and a timer fires a few milliseconds late as a matter of course, so a
// window a hair wider than the cadence is scheduling rather than an unattested stretch. Reporting
// those would list most ticks of a healthy chain as gaps, dozens a day, and bury a real gap among
// them, and the slack stays far inside the whole missed beat a genuine gap adds.
func scheduleSlack(cadence int64) int64 {
	return max(cadence/100, microsPerSecond)
}

// wholeSeconds words an interval given in microseconds as whole seconds, rounded to the nearest
// with halves up, which is the one form every verifier prints for a gap.
func wholeSeconds(micros int64) string {
	return fmt.Sprintf("%ds", (micros+microsPerSecond/2)/microsPerSecond)
}

// missedWindows is how many whole windows a gap swallowed: the gap in cadences, rounded to the
// nearest with halves up, less the window the arriving beat attests. Both arguments are in
// microseconds and the cadence is at least a second. The arithmetic is integer so that every
// verifier lands on the same count.
func missedWindows(delta, cadence int64) int64 {
	return max((delta+cadence/2)/cadence-1, 0)
}

// beatTime words a beat time given in microseconds as RFC 3339 UTC to the whole second, with the
// fraction dropped rather than rounded, the form a gap names its bounds in.
func beatTime(micros int64) string {
	return time.UnixMicro(micros).UTC().Format(time.RFC3339)
}

// checkSpanPairs verifies every consecutive span claim pair: beat contiguity, the count against
// the sequence difference, and beat times against the cadence the earlier beat declares. It
// accumulates the gap report and the coverage wording, measured as the format states so that every
// verifier reports the same gap.
func (r *Report) checkSpanPairs(spans []spanClaim) {
	var missed, longest int64
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
		delta := cur.at - prev.at
		if delta <= 0 {
			r.problem("span beat %d time does not advance past beat %d",
				cur.payload.Beat, prev.payload.Beat)
			continue
		}
		cadence := prev.payload.CadenceS * microsPerSecond
		if delta <= cadence+scheduleSlack(cadence) {
			continue
		}
		r.SpanGaps = append(r.SpanGaps,
			fmt.Sprintf("unattested window of %s between beat %d (%s) and beat %d (%s)",
				wholeSeconds(delta), prev.payload.Beat, beatTime(prev.at), cur.payload.Beat,
				beatTime(cur.at)))
		longest = max(longest, delta)
		missed += missedWindows(delta, cadence)
	}
	if longest > 0 {
		r.SpanLongestGap = wholeSeconds(longest)
	}
	if len(spans) > 0 {
		r.SpanCoverage = fmt.Sprintf("%d/%d windows attested", len(spans),
			int64(len(spans))+missed)
	}
}
