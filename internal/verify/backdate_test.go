package verify

import (
	"testing"
	"time"
)

// TestAnchorClockSkewIsBounded pins that the allowance for an authority's clock is small enough to
// be an allowance rather than a hole.
//
// An attestation earlier than the entry it covers is a contradiction: the token commits to a link,
// and that link is the hash of a claim carrying its own time, so an authority cannot honestly have
// signed it first. A producer running their own timestamp authority could otherwise sign any hash
// with any date and still reach the strongest verdict the format issues. Both clocks are real and
// neither is authoritative, so a few minutes is allowed and a backdated month is not.
func TestAnchorClockSkewIsBounded(t *testing.T) {
	t.Parallel()
	if anchorClockSkew <= 0 {
		t.Fatal("no allowance at all, so ordinary clock drift reads as forgery")
	}
	if anchorClockSkew > time.Hour {
		t.Errorf("skew allowance is %v, wide enough to hide a deliberately backdated attestation",
			anchorClockSkew)
	}
}
