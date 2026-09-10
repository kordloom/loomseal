// Package cmd is the command layer of the loomseal verifier: argument dispatch, flags, and
// exit codes. All verification logic lives in the internal packages.
package cmd

import (
	"fmt"
	"io"
)

// usage is the top-level help text.
const usage = `loomseal verifies LoomSeal proof bundles and helps a holder present them, offline.

Usage:
  loomseal verify <bundle.loomseal.json> [flags]
  loomseal verify <presentation.json> [--audience <id>] [--nonce <id>]
  loomseal verify - [flags]                 read the bundle from stdin
  loomseal keygen                           print a new holder key as JSON
  loomseal present <bundle> --holder-key <file> [flags]
  loomseal version

Verify flags:
  --evidence <dir>       Directory of evidence artifacts to check against the bundle digests.
  --fingerprint <id>     Require the producer key to match this sha256:<hex> fingerprint.
  --attestor <id>        Require every counter-signature to be signed by one of these
                         sha256:<hex> fingerprints. Repeatable. Without it a verified
                         counter-signature proves a key signed the claim, not whose.
  --audience <id>        For a presentation, the verifier it must be addressed to.
  --nonce <id>           For a presentation, the challenge it must echo.
  --json                 Emit the verification report as JSON on stdout.
  --pretty               Indent the JSON report.

Present flags:
  --holder-key <file>    Holder key file, as printed by keygen (required).
  --audience <id>        The verifier this presentation is for.
  --nonce <id>           The challenge the verifier issued.
  --reveal <names>       Comma-separated field names to disclose; others are withheld.
  --at <rfc3339>         Assembly time; defaults to now.

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
	case "keygen":
		return runKeygen(args[1:], stdout, stderr)
	case "present":
		return runPresent(args[1:], stdout, stderr)
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
