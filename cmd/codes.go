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
)
