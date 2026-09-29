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
		fmt.Fprintf(w, "anchors    %d matched by coordinates, %d proof(s) carried, %d verified\n",
			r.AnchorsMatched, r.AnchorProofsCarried, r.AnchorProofsVerified)
	}
	// A verified proof names the moment the link provably existed and who attested to it. Whether
	// that authority is worth trusting is the reader's call, so it is printed rather than judged.
	for _, a := range r.AnchorAttestations {
		fmt.Fprintf(w, "attested   %s\n", a)
	}
	if r.AnchorsToDeclaredHead > 0 {
		fmt.Fprintf(w, "note       %d anchor(s) reference only the unverified declared head, not a claim in this bundle\n",
			r.AnchorsToDeclaredHead)
	}
	// An anchor pins history only up to the position it names. What it leaves uncovered is the
	// part a compromised producer key could still rewrite, so the reader is told the size of it
	// rather than left to work it out from the claim list.
	if r.AnchoredThroughSeq > 0 {
		line := fmt.Sprintf("anchored   through seq %d", r.AnchoredThroughSeq)
		if r.UnanchoredClaims > 0 {
			line += fmt.Sprintf(", %d claim(s) after it", r.UnanchoredClaims)
			if r.UnanchoredWindow != "" {
				line += fmt.Sprintf(" spanning %s", r.UnanchoredWindow)
			}
		}
		fmt.Fprintln(w, line)
		// Printed even when nothing follows the anchor, because that is the case worth catching.
		// Cutting the entries above an anchor and deleting the anchors that covered them leaves a
		// bundle with no unanchored claims at all, reading cleaner than the honest one it replaced.
		// This line still shows the gap, and a trail anchored on a schedule keeps it small.
		if r.AttestationAge != "" {
			fmt.Fprintf(w, "attested   %s before this bundle was assembled\n", r.AttestationAge)
		}
	}
	// An anchor this verifier did not open is a claim, not a proof. The level says "by reference",
	// which is accurate, but a reader skims the word "anchored" and stops. Saying plainly that
	// nothing was checked is the difference between a relying party going and looking and one
	// believing an anchor pointing at a commit that does not exist.
	if unchecked := r.AnchorsMatched - r.AnchorProofsVerified; unchecked > 0 {
		fmt.Fprintf(w, "note       %d anchor(s) name a location this verifier did not fetch; "+
			"confirm them yourself before relying on them\n", unchecked)
	}
	// The coverage line is the population claim: how many windows the producer attested against
	// how many the cadence says there should have been. A gap is printed, never summarized away.
	if r.SpanPresent {
		if r.SpanOK {
			line := fmt.Sprintf("span       %s, %d count(s) recomputed", r.SpanCoverage,
				r.SpanCountsVerified)
			if r.SpanCountsCarried > 0 {
				line += fmt.Sprintf(", %d carried", r.SpanCountsCarried)
			}
			if r.SpanLongestGap != "" {
				line += fmt.Sprintf(", longest gap %s", r.SpanLongestGap)
			}
			fmt.Fprintln(w, line)
		} else {
			fmt.Fprintln(w, "span       FAILED")
		}
		for _, g := range r.SpanGaps {
			fmt.Fprintf(w, "gap        %s\n", g)
		}
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
