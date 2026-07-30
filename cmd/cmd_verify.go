package cmd

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/kordloom/loomseal/internal/jsonutil"
	"github.com/kordloom/loomseal/internal/verify"
)

// runVerify implements loomseal verify: read one bundle file, run the verification
// procedure, and render the report.
func runVerify(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("loomseal verify", flag.ContinueOnError)
	fs.SetOutput(stderr)
	evidence := fs.String("evidence", "", "directory of evidence artifacts to check")
	fingerprint := fs.String("fingerprint", "", "required producer key fingerprint, sha256:<hex>")
	jsonOut := fs.Bool("json", false, "emit the report as JSON on stdout")
	pretty := fs.Bool("pretty", false, "indent the JSON report")
	// The flag package stops at the first positional argument, so keep parsing past the
	// bundle file until every flag is consumed, wherever the caller put it.
	file := ""
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return CodeUsage
		}
		if fs.NArg() == 0 {
			break
		}
		if file != "" {
			fmt.Fprintln(stderr, "loomseal verify: exactly one bundle file is required")
			return CodeUsage
		}
		file = fs.Arg(0)
		rest = fs.Args()[1:]
	}
	if file == "" {
		fmt.Fprintln(stderr, "loomseal verify: exactly one bundle file is required")
		return CodeUsage
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintf(stderr, "loomseal verify: %v\n", err)
		return CodeUsage
	}
	report := verify.Run(raw, verify.Options{EvidenceDir: *evidence, Fingerprint: *fingerprint})
	if *jsonOut {
		out, err := jsonutil.Marshal(report, *pretty)
		if err != nil {
			fmt.Fprintf(stderr, "loomseal verify: encode report: %v\n", err)
			return CodeUsage
		}
		fmt.Fprintln(stdout, string(out))
	} else {
		renderReport(stdout, report)
	}
	if report.OK {
		return CodeOK
	}
	return CodeFailed
}

// renderReport writes the human-readable report.
func renderReport(w io.Writer, r *verify.Report) {
	if r.BundleID != "" {
		fmt.Fprintf(w, "bundle     %s from %s\n", r.BundleID, r.Producer)
		fmt.Fprintf(w, "subject    %s\n", r.Subject)
	}
	if r.SignatureOK {
		fmt.Fprintf(w, "signature  ok, key %s\n", r.KeyID)
	} else {
		fmt.Fprintln(w, "signature  FAILED")
	}
	if r.FingerprintMatch != nil {
		fmt.Fprintf(w, "pin        match %t\n", *r.FingerprintMatch)
	}
	switch {
	case r.ChainPresent && r.ChainOK:
		fmt.Fprintf(w, "chain      %s, %s, %d claims, head matched %t\n", r.ChainProfile,
			r.ChainMode, r.ClaimsChecked, r.HeadMatched)
	case r.ChainPresent:
		fmt.Fprintf(w, "chain      %s FAILED\n", r.ChainProfile)
	}
	if r.ChainPresent && r.ChainOK && !r.HeadMatched {
		fmt.Fprintln(w, "note       declared head is ahead of the bundled claims; its link is not verified here")
	}
	if r.AnchorsMatched > 0 || r.AnchorProofsCarried > 0 {
		fmt.Fprintf(w, "anchors    %d matched by coordinates, %d proofs carried, not validated in this version\n",
			r.AnchorsMatched, r.AnchorProofsCarried)
	}
	if r.AnchorsToDeclaredHead > 0 {
		fmt.Fprintf(w, "note       %d anchor(s) reference only the unverified declared head, not a claim in this bundle\n",
			r.AnchorsToDeclaredHead)
	}
	fmt.Fprintf(w, "evidence   %d verified, %d missing, %d referenced only\n",
		r.EvidenceVerified, r.EvidenceMissing, r.EvidenceReferenced)
	for _, t := range r.UnknownClaimTypes {
		fmt.Fprintf(w, "note       unknown claim type %s, not checked against a registry entry\n", t)
	}
	for _, p := range r.Problems {
		fmt.Fprintf(w, "problem    %s\n", p)
	}
	if r.OK {
		fmt.Fprintf(w, "VERIFIED   %s\n", r.Level)
	} else {
		fmt.Fprintln(w, "NOT VERIFIED")
	}
}
