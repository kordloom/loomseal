package chain_test

import (
	"os"
	"testing"
)

// TestEmitCrossVerifyFixtures writes real signed tree bundles to disk so a second implementation in
// another language can be run against the exact bytes this one produces.
func TestEmitCrossVerifyFixtures(t *testing.T) {
	dir := os.Getenv("LOOMSEAL_CROSS_DIR")
	if dir == "" {
		t.Skip("set LOOMSEAL_CROSS_DIR to emit cross-verification fixtures")
	}
	priv := testKey(t)
	log := newTreeLog("in_test", 6)

	if err := os.WriteFile(dir+"/sparse.loomseal.json",
		log.bundleFor(t, priv, []int{1, 4}, 0), 0o644); err != nil {
		t.Fatalf("write sparse: %v", err)
	}
	if err := os.WriteFile(dir+"/consistency.loomseal.json",
		log.bundleFor(t, priv, []int{0, 5}, 4), 0o644); err != nil {
		t.Fatalf("write consistency: %v", err)
	}
	if err := os.WriteFile(dir+"/single.loomseal.json",
		newTreeLog("in_test", 1).bundleFor(t, priv, []int{0}, 0), 0o644); err != nil {
		t.Fatalf("write single: %v", err)
	}
	// A log of nine, disclosing one leaf from the right edge, where the fold shape is least regular.
	if err := os.WriteFile(dir+"/nine.loomseal.json",
		newTreeLog("in_test", 9).bundleFor(t, priv, []int{6}, 5), 0o644); err != nil {
		t.Fatalf("write nine: %v", err)
	}
}
