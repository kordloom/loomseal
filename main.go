// Command loomseal verifies LoomSeal proof bundles offline. A bundle is a portable JSON
// document of hash-chained claims, evidence digests, external anchors, and a producer
// signature; the verifier checks all of it without contacting anyone.
package main

import (
	"os"

	"github.com/kordloom/loomseal/cmd"
)

// main dispatches to the command layer and exits with its code.
func main() {
	os.Exit(cmd.Execute(os.Args[1:], os.Stdout, os.Stderr))
}
