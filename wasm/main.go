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

// main registers the verify entry points and blocks, because a WebAssembly module that returns
// from main takes its exported functions with it.
func main() {
	js.Global().Set("loomsealVerify", js.FuncOf(verifyBundle))
	js.Global().Set("loomsealVerifyPresentation", js.FuncOf(verifyPresentation))
	js.Global().Set("loomsealLooksLikePresentation", js.FuncOf(looksLikePresentation))
	select {}
}

// looksLikePresentation reports whether a file is a holder presentation rather than a bundle, by
// the same test the command line applies before choosing which to verify. The argument is a
// Uint8Array of the file. The page needs the answer before verifying, because a presentation is
// checked against an audience and a nonce that a bundle has no use for.
func looksLikePresentation(_ js.Value, args []js.Value) any {
	if len(args) == 0 || args[0].IsUndefined() || args[0].IsNull() {
		return false
	}
	raw := make([]byte, args[0].Get("length").Int())
	js.CopyBytesToGo(raw, args[0])
	return verify.LooksLikePresentation(raw)
}

// verifyPresentation verifies one holder presentation and returns the report as a JSON string. The
// first argument is a Uint8Array of the file; the optional second and third are the audience and
// nonce the verifier requires, and the optional fourth is a sha256: fingerprint to pin the embedded
// bundle's producer key against, exactly as the command line pins it for a presentation. An
// argument that is a string is an expectation the caller meant to apply, so an empty audience or
// nonce is refused as --audience "" and --nonce "" are, and a caller with none passes undefined.
func verifyPresentation(_ js.Value, args []js.Value) any {
	if len(args) == 0 || args[0].IsUndefined() || args[0].IsNull() {
		return presentationErrorReport("no presentation supplied")
	}
	raw := make([]byte, args[0].Get("length").Int())
	js.CopyBytesToGo(raw, args[0])

	var opts verify.PresentationOptions
	if len(args) > 1 && args[1].Type() == js.TypeString {
		if err := verify.CheckExpectation(args[1].String()); err != nil {
			return presentationErrorReport("audience: " + err.Error())
		}
		opts.Audience = args[1].String()
	}
	if len(args) > 2 && args[2].Type() == js.TypeString {
		if err := verify.CheckExpectation(args[2].String()); err != nil {
			return presentationErrorReport("nonce: " + err.Error())
		}
		opts.Nonce = args[2].String()
	}
	if len(args) > 3 && args[3].Type() == js.TypeString {
		if err := verify.CheckFingerprint(args[3].String()); err != nil {
			return presentationErrorReport(err.Error())
		}
		opts.Bundle.Fingerprint = args[3].String()
	}
	out, err := json.Marshal(verify.RunPresentation(raw, opts))
	if err != nil {
		return presentationErrorReport("report could not be encoded: " + err.Error())
	}
	return string(out)
}

// verifyBundle verifies one bundle and returns the report as a JSON string.
//
// The first argument is a Uint8Array holding the file exactly as it was read. Bytes are copied
// rather than taken as a string because a signature covers the canonical form of the document,
// and any re-encoding on the way in could change the verdict. The optional second argument is a
// sha256: fingerprint to pin the producer key against, and the optional third an install id to
// accept for that key after a rotation. A second argument that is a string is a pin the caller
// meant to apply, so an empty or malformed one is refused rather than read as no pin.
func verifyBundle(_ js.Value, args []js.Value) any {
	if len(args) == 0 || args[0].IsUndefined() || args[0].IsNull() {
		return errorReport("no bundle supplied")
	}
	raw := make([]byte, args[0].Get("length").Int())
	js.CopyBytesToGo(raw, args[0])

	var opts verify.Options
	if len(args) > 1 && args[1].Type() == js.TypeString {
		if err := verify.CheckFingerprint(args[1].String()); err != nil {
			return errorReport(err.Error())
		}
		opts.Fingerprint = args[1].String()
	}
	// A third argument pairs the pinned key with an install id, accepting a key rotation. It means
	// nothing without the pin, and the verifier refuses it alone.
	if len(args) > 2 && args[2].Type() == js.TypeString {
		opts.AcceptInstall = args[2].String()
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

// presentationErrorReport returns a presentation-shaped JSON string for a failure that happened
// before the verifier ran. It carries presentation_ok, so the page names the presentation in its
// verdict rather than reading the refusal as a bundle's.
func presentationErrorReport(problem string) string {
	out, err := json.Marshal(verify.PresentationReport{
		OK:             false,
		PresentationOK: false,
		Problems:       []string{problem},
	})
	if err != nil {
		return `{"ok":false,"presentation_ok":false,"problems":["report could not be encoded"]}`
	}
	return string(out)
}
