// Package cmd is the command layer of the loomseal verifier: argument dispatch, flags, and
// exit codes. All verification logic lives in the internal packages.
package cmd

import (
	"fmt"
	"io"
)

// usage is the top-level help text.
const usage = `loomseal verifies LoomSeal proof bundles offline.

Usage:
  loomseal verify <bundle.loomseal.json> [flags]
  loomseal version

Verify flags:
  --evidence <dir>       Directory of evidence artifacts to check against the bundle digests.
  --fingerprint <id>     Require the producer key to match this sha256:<hex> fingerprint.
  --json                 Emit the verification report as JSON on stdout.
  --pretty               Indent the JSON report.

Exit codes: 0 verified, 1 verification failed, 2 usage or read error.`

// Execute runs the CLI with the given arguments and streams and returns the process exit
// code. It exists apart from main so tests can drive the full command surface.
func Execute(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, usage)
		return CodeUsage
	}
	switch args[0] {
	case "verify":
		return runVerify(args[1:], stdout, stderr)
	case "version":
		fmt.Fprintln(stdout, Version())
		return CodeOK
	case "help", "-h", "--help":
		fmt.Fprintln(stdout, usage)
		return CodeOK
	default:
		fmt.Fprintf(stderr, "loomseal: unknown command %q\n\n%s\n", args[0], usage)
		return CodeUsage
	}
}
