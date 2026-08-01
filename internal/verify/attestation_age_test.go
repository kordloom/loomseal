package verify

import (
	"testing"
	"time"

	"github.com/kordloom/loomseal/internal/bundle"
)

// TestAttestationAgeSurvivesATruncatedTail checks that the number stays present when a bundle has
// been cut back to an old anchor.
//
// The claim-to-claim span goes quiet in exactly that case: remove the entries above an anchor and
// delete the anchors that covered them, and the bundle carries no unanchored claims at all. It then
// reads cleaner than the honest bundle it replaced, because a relying party trained to look at the
// unanchored window sees zero exposure. The age of the newest attestation does not go quiet.
func TestAttestationAgeSurvivesATruncatedTail(t *testing.T) {
	t.Parallel()
	assembled := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	b := &bundle.Bundle{CreatedAt: assembled.Format(time.RFC3339)}

	tests := []struct {
		Name    string
		Newest  time.Time
		WantSet bool
	}{{ // Test 0: Anchored minutes ago, which is what a scheduled anchor looks like.
		Name: "fresh", Newest: assembled.Add(-9 * time.Minute), WantSet: true,
	}, { // Test 1: Cut back to an anchor from months earlier.
		Name: "stale", Newest: assembled.AddDate(0, -6, 0), WantSet: true,
	}, { // Test 2: No proof verified, so there is nothing to age.
		Name: "no attestation", Newest: time.Time{}, WantSet: false,
	}}
	for testNum, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			r := &Report{}
			r.measureAttestationAge(b, test.Newest)
			if test.WantSet && r.AttestationAge == "" {
				t.Errorf("test %d: no age reported, so a bundle cut back to an old anchor reads "+
					"the same as one anchored minutes ago", testNum)
			}
			if !test.WantSet && r.AttestationAge != "" {
				t.Errorf("test %d: age = %q with no verified attestation", testNum, r.AttestationAge)
			}
		})
	}

	// The stale case must be visibly large, not rounded away.
	r := &Report{}
	r.measureAttestationAge(b, assembled.AddDate(0, -6, 0))
	if len(r.AttestationAge) < 4 {
		t.Errorf("a six month gap rendered as %q, which does not read as a gap", r.AttestationAge)
	}
}
