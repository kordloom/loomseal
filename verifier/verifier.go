// Package verifier verifies LoomSeal bundles from Go. It is the same verifier the loomseal command
// and the browser page run, exported so a product can check its own bundles without shelling out.
// Producers build with package seal and verify with this one, and neither carries a copy of the
// other's rules.
package verifier

import "github.com/kordloom/loomseal/internal/verify"

// Options carries the caller's verification inputs: an evidence directory, a producer key pin, an
// accepted install for a rotated key, and the acceptable counter-signers.
type Options = verify.Options

// Report is the outcome of one verification run. OK is the verdict and Problems lists every check
// that failed.
type Report = verify.Report

// DisclosedMember is one payload member a switchtender-audit-v1 link does not commit, and what it
// was held against.
type DisclosedMember = verify.DisclosedMember

// ErrFingerprint is returned for a producer key pin in any form but sha256: and 64 lowercase hex.
var ErrFingerprint = verify.ErrFingerprint

// Run verifies raw under opts and always returns a report. A bundle that cannot be parsed is a
// failed verification, not an error.
func Run(raw []byte, opts Options) *Report {
	return verify.Run(raw, opts)
}

// CheckFingerprint refuses a producer key pin that is not sha256: and 64 lowercase hex digits,
// including an empty one, so a caller never mistakes a malformed pin for no pin.
func CheckFingerprint(pin string) error {
	return verify.CheckFingerprint(pin)
}
