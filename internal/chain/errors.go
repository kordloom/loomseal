package chain

import "errors"

// ErrBroken marks a chain whose order, continuity, or links do not verify.
var ErrBroken = errors.New("chain broken")

// ErrProfile marks a chain declaration the verifier cannot process.
var ErrProfile = errors.New("chain profile")

// ErrClaim marks a claim missing what its chain profile needs.
var ErrClaim = errors.New("chain claim")
