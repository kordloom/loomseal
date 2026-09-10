package cmd

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

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
	// Repeatable, because a bundle can legitimately carry counter-signatures from several
	// parties and a relying party usually knows all of them by fingerprint.
	var attestors stringList
	fs.Var(&attestors, "attestor", "acceptable counter-signer fingerprint, sha256:<hex>, repeatable")
	audience := fs.String("audience", "", "for a presentation, the verifier it must be addressed to")
	nonce := fs.String("nonce", "", "for a presentation, the challenge it must echo")
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
	var raw []byte
	var err error
	if file == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(file)
	}
	if err != nil {
		fmt.Fprintf(stderr, "loomseal verify: %v\n", err)
		return CodeUsage
	}
	bundleOpts := verify.Options{EvidenceDir: *evidence, Fingerprint: *fingerprint,
		Attestors: attestors}
	// One command accepts either a bundle or a holder presentation that wraps one, told apart by the
	// presentation version member.
	if verify.LooksLikePresentation(raw) {
		pr := verify.RunPresentation(raw, verify.PresentationOptions{
			Audience: *audience, Nonce: *nonce, Bundle: bundleOpts,
		})
		if *jsonOut {
			out, err := jsonutil.Marshal(pr, *pretty)
			if err != nil {
				fmt.Fprintf(stderr, "loomseal verify: encode report: %v\n", err)
				return CodeUsage
			}
			fmt.Fprintln(stdout, string(out))
		} else {
			renderPresentation(stdout, pr)
		}
		if pr.OK {
			return CodeOK
		}
		return CodeFailed
	}
	report := verify.Run(raw, bundleOpts)
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
	if report.Unsupported {
		return CodeUnsupported
	}
	return CodeFailed
}

// renderPresentation writes the human-readable report for a holder presentation, then the embedded
// bundle's own report beneath it.
func renderPresentation(w io.Writer, r *verify.PresentationReport) {
	if r.PresentationOK {
		fmt.Fprintf(w, "presented  by holder %s to %q\n", r.HolderKeyID, r.Audience)
	} else {
		fmt.Fprintln(w, "presented  FAILED")
	}
	if r.AudienceMatch != nil {
		fmt.Fprintf(w, "audience   match %t\n", *r.AudienceMatch)
	}
	if r.NonceMatch != nil {
		fmt.Fprintf(w, "nonce      match %t\n", *r.NonceMatch)
	}
	// The nonce is the whole replay defense, and it was never printed, so a verifier who did
	// not pass --nonce had no way to notice they were holding last quarter's presentation.
	// Show what the presentation carries and say plainly that nothing compared it, the same
	// way the evidence and pin lines announce a check that did not happen.
	if r.OK && (r.AudienceMatch == nil || r.NonceMatch == nil) {
		if r.NonceMatch == nil {
			fmt.Fprintf(w, "nonce      %q, NOT CHECKED, so a presentation made for an older\n",
				r.Nonce)
			fmt.Fprintln(w, "           challenge replays freely: pass --nonce with the one you issued")
		}
		if r.AudienceMatch == nil {
			fmt.Fprintln(w, "audience   NOT CHECKED: pass --audience with the identifier you expect")
		}
	}
	for _, p := range r.Problems {
		fmt.Fprintf(w, "problem    %s\n", p)
	}
	if r.Bundle != nil {
		fmt.Fprintln(w, "---")
		renderReport(w, r.Bundle)
	}
	if r.OK {
		fmt.Fprintln(w, "PRESENTATION VERIFIED")
	} else {
		fmt.Fprintln(w, "PRESENTATION NOT VERIFIED")
	}
}

// renderReport writes the human-readable report.
func renderReport(w io.Writer, r *verify.Report) {
	// An unsupported bundle was never judged, so no interior line may imply it was: printing
	// "signature FAILED" above an unsupported verdict is exactly the confusion the verdict
	// exists to prevent.
	if r.Unsupported {
		for _, p := range r.Problems {
			fmt.Fprintf(w, "problem    %s\n", p)
		}
		fmt.Fprintln(w, "UNSUPPORTED  this verifier does not implement what the bundle declares; not judged")
		return
	}
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
	// Any key signs its own bundle, so a valid signature says a bundle was signed, never by
	// whom. Without a pin the reader sees "signature ok" and a key id they have nothing to
	// compare against, which reads as confirmation rather than as the open question it is.
	// The evidence line already says when it checked nothing; this one has to as well.
	// Gated on the whole verdict, not just the signature. A bundle that fails for any other
	// reason has already answered the question this notice raises, and printed above a
	// failure the words "the bundle was signed" read as partial reassurance rather than as
	// the open question they are. A disclosure written for one outcome must not appear in
	// another where it argues the opposite way.
	if r.OK && !r.ProducerPinned {
		fmt.Fprintln(w, "pin        NONE, so this says the bundle was signed, not who signed it")
		fmt.Fprintln(w, "           pass --fingerprint sha256:<hex> from the producer's trust page")
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
	// A tree proves something a linear chain cannot, and the chain line above does not say it. The
	// disclosed claims were folded to the root the signature covers, so the reader is told how large
	// the log they belong to is and how many of its entries this bundle proved membership for.
	if r.TreeSize > 0 {
		fmt.Fprintf(w, "tree       %d leaves, %d inclusion proof(s) folded to the signed root\n",
			r.TreeSize, r.InclusionProofs)
		// Append-only growth is a separate question from whether this bundle is intact, so it gets
		// its own line either way. Silence would read as proved to anyone skimming.
		if r.ConsistencyOK {
			fmt.Fprintf(w, "growth     append-only proved from size %d, so nothing the earlier "+
				"root covered was changed or dropped\n", r.ConsistencyFrom)
		} else {
			fmt.Fprintln(w, "note       no consistency proof, so this bundle does not prove the "+
				"log only ever appended")
		}
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
	// A proof on a declared head that leads the claims is not opened, because the link it attests ties
	// to nothing this verifier confirmed. Saying so keeps a reader from reading "proof" as "verified".
	if r.AnchorProofsOnDeclaredHead > 0 {
		fmt.Fprintf(w, "note       %d proof(s) sit on the unverified declared head and were not checked; "+
			"they earn no anchored level\n", r.AnchorProofsOnDeclaredHead)
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
	// Selective disclosure: how many redactable fields were shown against how many were committed. The
	// link covers the committed set, so the count holds whether or not the holder revealed a field.
	if r.DisclosuresPresent {
		line := fmt.Sprintf("disclosed  %d field(s) revealed, %d redacted", r.FieldsRevealed,
			r.FieldsRedacted)
		if len(r.RevealedFields) > 0 {
			line += ": " + strings.Join(r.RevealedFields, ", ")
		}
		fmt.Fprintln(w, line)
	}
	// Counter-signatures by parties other than the producer, reported with who vouched so the reader
	// decides whether to trust them. This is what turns a self-asserted claim into a two-party one.
	if r.AttestationsPresent {
		fmt.Fprintf(w, "attested   %d counter-signature(s) verified\n", r.AttestationsVerified)
		for _, a := range r.Attestors {
			fmt.Fprintf(w, "vouched    %s\n", a)
		}
		// An attestation sits outside the producer signature so a counterparty can add one
		// after the fact. That also means any holder can attach one, signed by a key minted
		// for the purpose, under any role they like, and it verifies. "Vouched" then reads as
		// third-party endorsement when nothing established the third party.
		if r.OK && !r.AttestorsPinned {
			fmt.Fprintln(w, "           NOT CHECKED against expected signers: a counter-signature")
			fmt.Fprintln(w, "           proves a key signed this, not whose key it was. Anyone")
			fmt.Fprintln(w, "           holding the bundle can add one. Pass --attestor sha256:<hex>")
		}
	}
	fmt.Fprintf(w, "evidence   %d verified, %d missing, %d referenced only\n",
		r.EvidenceVerified, r.EvidenceMissing, r.EvidenceReferenced)
	// An altered artifact is the case a reader most needs to see, so it gets its own line
	// rather than a share of a count that also holds artifacts nobody supplied.
	if r.EvidenceMismatched > 0 {
		fmt.Fprintf(w, "ALTERED    %d artifact(s) present but not matching the sealed digest\n",
			r.EvidenceMismatched)
	}
	for _, t := range r.UnknownClaimTypes {
		fmt.Fprintf(w, "note       unknown claim type %s, not checked against a registry entry\n", t)
	}
	for _, a := range r.HeadAttestors {
		fmt.Fprintf(w, "head att.  %s vouches for the chain head\n", a)
	}
	if r.UnknownSubjectType != "" {
		fmt.Fprintf(w, "note       subject type %s is outside this verifier's vocabulary\n", r.UnknownSubjectType)
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

// stringList collects a repeatable string flag in the order it was given.
type stringList []string

// String renders the collected values for flag package output.
func (s *stringList) String() string { return strings.Join(*s, ",") }

// Set appends one occurrence of the flag.
func (s *stringList) Set(v string) error {
	*s = append(*s, v)
	return nil
}
