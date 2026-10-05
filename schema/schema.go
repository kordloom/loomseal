// Package schema carries the format's machine-readable declarations, embedded so a verifier built
// from this repository reads exactly the files the repository publishes, and the reference
// verifier, which reads the same files from disk, cannot fall out of step with it.
package schema

import _ "embed"

// ClaimMembers is claim-members.json: every payload member of every claim type the format
// registers, and what a verifier holds each one against.
//
//go:embed claim-members.json
var ClaimMembers []byte
