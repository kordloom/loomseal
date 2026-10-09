// Shared renderer and dispatcher for the browser verify page.
//
// The verdict and every qualifying line are produced here, line for line with the command line's
// renderReport and renderPresentation, so the page a relying party runs in a tab does not quietly
// drop the notices the command line prints. A notice the command line shows and the page hides, such
// as the unpinned "pin NONE" line, reads to a browser user as a bare VERIFIED with none of the
// context that says what the verdict is worth. reportLines and presentationLines are pure so they
// can be held to that parity in a test with no DOM, and verifyBytes is the one path a dropped file
// takes to the compiled verifier, so the module's self-test drives the page's own routing rather
// than the entry points behind it.
(function (global) {
  "use strict";

  // esc escapes the five HTML-significant characters, so a value carried in the bundle cannot
  // inject markup into the report.
  function esc(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }

  // pad left-aligns a label into the eleven-column gutter the command line uses.
  function pad(s) {
    return (s + "           ").slice(0, 11);
  }

  // unset reports whether a pin comparison was never made.
  function unset(v) {
    return v === undefined || v === null;
  }

  // verifyBytes runs the compiled verifier over a file's bytes the way loomseal verify does: a holder
  // presentation goes to the presentation entry point with the audience and nonce the relying party
  // expects, and anything else to the bundle entry point. A producer pin applies to either. The
  // bundle entry point refuses a presentation at parse, over its audience member, so a page that
  // skipped this test would refuse a presentation the command line and the reference accept. A
  // blank audience or nonce field is no expectation, so it is passed as undefined: the entry point
  // refuses an empty string the way the command line refuses --nonce "".
  function verifyBytes(bytes, opts) {
    opts = opts || {};
    var raw;
    if (global.loomsealLooksLikePresentation(bytes)) {
      raw = global.loomsealVerifyPresentation(bytes, opts.audience || undefined,
        opts.nonce || undefined, opts.pin || undefined);
    } else {
      raw = opts.pin ? global.loomsealVerify(bytes, opts.pin) : global.loomsealVerify(bytes);
    }
    return JSON.parse(raw);
  }

  // isPresentation reports whether a report came from the presentation entry point, which always
  // carries presentation_ok, a member a bundle report never has.
  function isPresentation(report) {
    return Object.prototype.hasOwnProperty.call(report, "presentation_ok");
  }

  // verdict returns the command line's final line for a bundle report. The level is named only on
  // a verified bundle: a failed one achieved none, and an unsupported one was never judged, so
  // neither carries a level beside its word. The plain word is kept for a bundle with nothing
  // disclosed beside its commitments left unchecked; anything else says how much was not checked.
  function verdict(report) {
    if (report.unsupported) {
      return "UNSUPPORTED  this verifier does not implement what the bundle declares; not judged";
    }
    if (report.ok !== true) return "NOT VERIFIED";
    var unchecked = report.disclosed_unchecked || 0;
    if (unchecked > 0) {
      return "VERIFIED, " + unchecked + " disclosed record(s) unchecked   " + (report.level || "");
    }
    return "VERIFIED   " + (report.level || "");
  }

  // presentationLines returns a presentation report's own rows in the command line's order and
  // wording: who presented to whom, each pin that was compared, each pin that was not, and the
  // problems. The wrapped bundle's rows follow separately.
  function presentationLines(report) {
    var rows = [];
    function row(label, text) { rows.push([label, String(text)]); }

    if (report.presentation_ok) {
      row("presented", "by holder " + (report.holder_key_id || "") + " to " +
        JSON.stringify(report.audience || ""));
    } else {
      row("presented", "FAILED");
    }
    if (!unset(report.audience_match)) row("audience", "match " + report.audience_match);
    if (!unset(report.nonce_match)) row("nonce", "match " + report.nonce_match);
    // The nonce is the whole replay defense, so a pin that was not compared is said to be
    // unchecked, as the command line says it, rather than left to be inferred from a missing row.
    if (report.ok && (unset(report.audience_match) || unset(report.nonce_match))) {
      if (unset(report.nonce_match)) {
        row("nonce", JSON.stringify(report.nonce || "") +
          ", NOT CHECKED, so a presentation made for an older");
        row("", "challenge replays freely: pass --nonce with the one you issued");
      }
      if (unset(report.audience_match)) {
        row("audience", "NOT CHECKED: pass --audience with the identifier you expect");
      }
    }
    (report.problems || []).forEach(function (p) { row("problem", p); });
    return rows;
  }

  // reportLines returns the report as [label, text] rows in the command line's order and wording.
  // An unsupported bundle was never judged, so it returns only its problems and nothing that could
  // read as a judgment.
  function reportLines(report) {
    var rows = [];
    function row(label, text) { rows.push([label, String(text)]); }

    if (report.unsupported) {
      (report.problems || []).forEach(function (p) { row("problem", p); });
      return rows;
    }
    if (report.bundle_id) {
      row("bundle", report.bundle_id + " from " + (report.producer || ""));
      row("subject", report.subject || "");
    }
    if (report.signature_ok) {
      row("signature", "ok, key " + (report.key_id || ""));
    } else {
      row("signature", "FAILED");
    }
    if (report.fingerprint_match !== undefined && report.fingerprint_match !== null) {
      row("pin", "match " + report.fingerprint_match);
    }
    if (report.install_binding === "minted from the producer key") {
      row("install", "minted from the producer key");
    } else if (report.install_binding === "rotation accepted") {
      row("install", "minted from another key, rotation accepted for the pinned key");
    }
    // Any key signs its own bundle, so a valid signature says a bundle was signed, never by whom.
    // Gated on the whole verdict, like the command line, so it never argues against a failure.
    if (report.ok && !report.producer_pinned) {
      row("pin", "NONE, so this says the bundle was signed, not who signed it");
      row("", "pass --fingerprint sha256:<hex> from the producer's trust page");
    }
    if (report.chain_present && report.chain_ok) {
      row("chain", (report.chain_profile || "") + ", " + (report.chain_mode || "") + ", " +
        (report.claims_checked || 0) + " claims, head matched " + !!report.head_matched);
    } else if (report.chain_present) {
      row("chain", (report.chain_profile || "") + " FAILED");
    }
    if (report.chain_present && report.chain_ok && !report.head_matched) {
      row("note", "declared head is ahead of the bundled claims; its link is not verified here");
    }
    if (report.tree_size) {
      row("tree", report.tree_size + " leaves, " + (report.inclusion_proofs || 0) +
        " inclusion proof(s) folded to the signed root");
      if (report.consistency_ok) {
        row("growth", "append-only proved from size " + report.consistency_from +
          ", so nothing the earlier root covered was changed or dropped");
      } else {
        row("note", "no consistency proof, so this bundle does not prove the log only ever appended");
      }
    }
    if (report.anchors_matched || report.anchor_proofs_carried) {
      row("anchors", (report.anchors_matched || 0) + " matched by coordinates, " +
        (report.anchor_proofs_carried || 0) + " proof(s) carried, " +
        (report.anchor_proofs_verified || 0) + " verified");
    }
    (report.anchor_attestations || []).forEach(function (a) { row("attested", a); });
    if (report.anchors_to_declared_head) {
      row("note", report.anchors_to_declared_head +
        " anchor(s) reference only the unverified declared head, not a claim in this bundle");
    }
    if (report.anchor_proofs_on_declared_head) {
      row("note", report.anchor_proofs_on_declared_head +
        " proof(s) sit on the unverified declared head and were not checked; they earn no anchored level");
    }
    var unopened = (report.anchor_proofs_carried || 0) - (report.anchor_proofs_verified || 0) -
      (report.anchor_proofs_on_declared_head || 0);
    if (unopened > 0) {
      row("note", unopened +
        " carried proof(s) are of a type this verifier cannot open offline, so they were counted and not checked");
    }
    if (report.anchored_through_seq) {
      var line = "through seq " + report.anchored_through_seq;
      if (report.unanchored_claims) {
        line += ", " + report.unanchored_claims + " claim(s) after it";
        if (report.unanchored_window) line += " spanning " + report.unanchored_window;
      }
      row("anchored", line);
      if (report.attestation_age) {
        row("attested", report.attestation_age + " before this bundle was assembled");
      }
    }
    var unchecked = (report.anchors_matched || 0) - (report.anchor_proofs_verified || 0);
    if (unchecked > 0) {
      row("note", unchecked +
        " anchor(s) name a location this verifier did not fetch; confirm them yourself before relying on them");
    }
    if (report.span_present) {
      if (report.span_ok) {
        var span = (report.span_coverage || "") + ", " + (report.span_counts_verified || 0) +
          " count(s) recomputed";
        if (report.span_counts_carried) span += ", " + report.span_counts_carried + " carried";
        if (report.span_longest_gap) span += ", longest gap " + report.span_longest_gap;
        row("span", span);
      } else {
        row("span", "FAILED");
      }
      (report.span_gaps || []).forEach(function (g) { row("gap", g); });
    }
    if (report.ok && report.disclosures_present) {
      var d = (report.fields_revealed || 0) + " field(s) revealed, " +
        (report.fields_redacted || 0) + " redacted";
      if ((report.revealed_fields || []).length) d += ": " + report.revealed_fields.join(", ");
      row("disclosed", d);
    }
    // A disclosed SwitchTender record, held against the digest its entry committed, and the reason
    // it carries. Gated on the whole verdict, like the command line, so a positive count never sits
    // under a failure. A body under the legacy unkeyed form is named, since its digest confirms a
    // guess.
    var records = (report.decision_records || 0) + (report.correction_records || 0) +
      (report.outcomes_verified || 0);
    if (report.ok && records > 0) {
      row("records", (report.decision_records || 0) + " decision(s), " +
        (report.correction_records || 0) + " correction(s), " + (report.outcomes_verified || 0) +
        " outcome(s) reproduce the digests their entries committed");
      var reasons = reasonsLine(report);
      if (reasons) row("reasons", reasons);
      (report.legacy_records || []).forEach(function (l) {
        row("legacy", l + " is committed under the unkeyed digest form from before nonces, which " +
          "anyone who can guess it can confirm");
      });
    }
    // Every member a switchtender-audit-v1 link does not commit, in one of three states, counted as
    // the command line counts them: a member and the one it travels with are one record. The
    // command line names the unchecked ones after its verdict; the page's verdict is its banner, so
    // they follow the redacted ones here.
    var members = report.disclosed || [];
    if (report.ok && members.length) {
      var counts = { checked: 0, unchecked: 0, redacted: 0 };
      var byMember = {};
      members.forEach(function (m) {
        if (m.with) return;
        counts[m.state] = (counts[m.state] || 0) + 1;
        if (m.state === "checked") byMember[m.member] = (byMember[m.member] || 0) + 1;
      });
      row("disclosed", counts.checked + " checked, " + counts.unchecked + " unchecked, " +
        counts.redacted + " redacted");
      var names = Object.keys(byMember).sort();
      if (names.length) {
        row("checked", names.map(function (n) { return n + " " + byMember[n]; }).join(", "));
      }
      ["redacted", "unchecked"].forEach(function (state) {
        members.forEach(function (m) {
          if (m.state === state && !m.with) {
            row(state, "claim " + m.claim + " " + m.member + ": " + m.detail);
          }
        });
      });
    }
    if (report.attestations_present) {
      row("attested", (report.attestations_verified || 0) + " counter-signature(s) verified");
      (report.attestors || []).forEach(function (a) { row("vouched", a); });
      if (report.ok && !report.attestors_pinned) {
        row("", "NOT CHECKED against expected signers: a counter-signature");
        row("", "proves a key signed this, not whose key it was. Anyone");
        row("", "holding the bundle can add one. Pass --attestor sha256:<hex>");
      }
    }
    row("evidence", (report.evidence_verified || 0) + " verified, " +
      (report.evidence_missing || 0) + " missing, " + (report.evidence_referenced || 0) +
      " referenced only");
    if (report.evidence_mismatched) {
      row("ALTERED", report.evidence_mismatched +
        " artifact(s) present but not matching the sealed digest");
    }
    (report.unknown_claim_types || []).forEach(function (t) {
      row("note", "unknown claim type " + t + ", not checked against a registry entry");
    });
    (report.head_attestors || []).forEach(function (a) {
      row("head att.", a + " vouches for the chain head");
    });
    if (report.unknown_subject_type) {
      row("note", "subject type " + report.unknown_subject_type + " is outside this verifier's vocabulary");
    }
    (report.problems || []).forEach(function (p) { row("problem", p); });
    return rows;
  }

  // reasonsLine words what the disclosed reasons came to, as the command line does: how many opened
  // their commitment, how many the holder withheld under a category it claims and nothing commits,
  // and how many were committed but not disclosed. It is empty when no record commits a reason.
  function reasonsLine(report) {
    var parts = [];
    var opened = report.reasons_verified || 0;
    if (opened === 1) {
      parts.push("1 opened its commitment");
    } else if (opened > 1) {
      parts.push(opened + " opened their commitments");
    }
    var redacted = report.reasons_redacted || [];
    if (redacted.length) {
      var noun = redacted.length > 1 ? "categories" : "category";
      parts.push(redacted.length + " withheld by the holder, " + noun +
        " claimed and not committed: " + redacted.join(", "));
    }
    if (report.reasons_withheld) {
      parts.push(report.reasons_withheld + " committed and not disclosed");
    }
    return parts.join(", ");
  }

  // padRow renders one [label, text] row into the command line's gutter, escaped for HTML.
  function padRow(r) {
    return esc(pad(r[0])) + esc(r[1]);
  }

  // renderInto writes the verdict banner and the report rows into an element. A bundle's banner is
  // the command line's final line. A presentation's banner is the presentation verdict, and its
  // rows are the presentation's own lines, a separator, the wrapped bundle's lines, and the
  // bundle's own verdict line, in the order the command line prints them.
  function renderInto(el, report, name, subEl) {
    var ok = report.ok === true;
    var banner;
    var lines;
    if (isPresentation(report)) {
      banner = ok ? "PRESENTATION VERIFIED" : "PRESENTATION NOT VERIFIED";
      lines = presentationLines(report).map(padRow);
      if (report.bundle) {
        lines.push("---");
        lines = lines.concat(reportLines(report.bundle).map(padRow), [esc(verdict(report.bundle))]);
      }
    } else {
      banner = verdict(report);
      lines = reportLines(report).map(padRow);
    }
    var html = '<div class="verdict ' + (ok ? "ok" : "no") + '">' + esc(banner) + "</div>";
    html += "<pre><code>" + lines.join("\n") + "</code></pre>";
    html += '<details><summary>Full report</summary><pre><code>' +
      esc(JSON.stringify(report, null, 2)) + "</code></pre></details>";
    el.innerHTML = html;
    if (subEl && name) subEl.textContent = "Checked " + name;
  }

  global.LoomSeal = {
    esc: esc, pad: pad, verdict: verdict, verifyBytes: verifyBytes,
    reportLines: reportLines, presentationLines: presentationLines, renderInto: renderInto,
  };
})(typeof window !== "undefined" ? window : globalThis);
