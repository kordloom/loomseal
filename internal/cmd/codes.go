package cmd

// Process exit codes. A failed verification is a distinct outcome from a broken invocation,
// so scripts can tell "the bundle is bad" from "the command was bad."
const (
	// CodeOK means the bundle verified.
	CodeOK = 0
	// CodeFailed means verification ran and the bundle did not verify.
	CodeFailed = 1
	// CodeUsage means the invocation or input could not be processed at all.
	CodeUsage = 2
	// CodeUnsupported means the bundle declares a version, profile, or algorithm this verifier
	// does not implement. Fail-closed like CodeFailed, but a script can tell "upgrade the
	// verifier" from "distrust the bundle."
	CodeUnsupported = 3
)
