//go:build js && wasm

// Command wasm exposes the LoomSeal verifier to a browser page.
//
// It is the same verifier the command line runs, compiled for WebAssembly, so a relying party
// with no Go toolchain and no command line still checks a bundle with the code the format
// specifies rather than a reimplementation written for the web. Nothing here reaches the
// network: the page is static, the bundle never leaves the machine that opened it, and a
// verdict is reached from the file alone.
package main

import (
	"encoding/json"
	"syscall/js"

	"github.com/kordloom/loomseal/internal/verify"
)

// main registers the verify entry point and blocks, because a WebAssembly module that returns
// from main takes its exported functions with it.
func main() {
	js.Global().Set("loomsealVerify", js.FuncOf(verifyBundle))
	select {}
}

// verifyBundle verifies one bundle and returns the report as a JSON string.
//
// The first argument is a Uint8Array holding the file exactly as it was read. Bytes are copied
// rather than taken as a string because a signature covers the canonical form of the document,
// and any re-encoding on the way in could change the verdict. The optional second argument is a
// sha256: fingerprint to pin the producer key against.
func verifyBundle(_ js.Value, args []js.Value) any {
	if len(args) == 0 || args[0].IsUndefined() || args[0].IsNull() {
		return errorReport("no bundle supplied")
	}
	raw := make([]byte, args[0].Get("length").Int())
	js.CopyBytesToGo(raw, args[0])

	var opts verify.Options
	if len(args) > 1 && args[1].Type() == js.TypeString {
		opts.Fingerprint = args[1].String()
	}

	// Evidence artifacts live on the relying party's disk, which the page cannot read. Digests
	// are reported as referenced rather than verified, and the report says so plainly.
	out, err := json.Marshal(verify.Run(raw, opts))
	if err != nil {
		return errorReport("report could not be encoded: " + err.Error())
	}
	return string(out)
}

// errorReport returns a verdict-shaped JSON string for a failure that happened before the
// verifier ran, so the page renders every outcome the same way.
func errorReport(problem string) string {
	out, err := json.Marshal(verify.Report{
		OK:       false,
		Level:    "not verified",
		Problems: []string{problem},
	})
	if err != nil {
		return `{"ok":false,"level":"not verified","problems":["report could not be encoded"]}`
	}
	return string(out)
}
