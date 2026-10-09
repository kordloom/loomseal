// Shared renderer for the browser verify page.
//
// The verdict and every qualifying line are produced here, line for line with the command line's
// renderReport, so the page a relying party runs in a tab does not quietly drop the notices the
// command line prints. A notice the command line shows and the page hides, such as the unpinned
// "pin NONE" line, reads to a browser user as a bare VERIFIED with none of the context that says
// what the verdict is worth. reportLines is pure so it can be held to that parity in a test with no
// DOM.
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

  // renderInto writes the verdict banner and the report rows into an element. The plain word is
  // kept for a bundle with nothing disclosed beside its commitments left unchecked. Anything else
  // says how much was not checked, and the rows name it.
  function renderInto(el, report, name, subEl) {
    var ok = report.ok === true;
    var unchecked = report.disclosed_unchecked || 0;
    var verdict = report.unsupported ? "UNSUPPORTED" : !ok ? "NOT VERIFIED" :
      unchecked > 0 ? "VERIFIED, " + unchecked + " disclosed record(s) unchecked" : "VERIFIED";
    var klass = report.unsupported ? "no" : (ok ? "ok" : "no");
    var html = '<div class="verdict ' + klass + '">' + verdict + "   " +
      esc(report.level || "") + "</div>";
    var body = reportLines(report).map(function (r) {
      return esc(pad(r[0])) + esc(r[1]);
    }).join("\n");
    html += "<pre><code>" + body + "</code></pre>";
    html += '<details><summary>Full report</summary><pre><code>' +
      esc(JSON.stringify(report, null, 2)) + "</code></pre></details>";
    el.innerHTML = html;
    if (subEl && name) subEl.textContent = "Checked " + name;
  }

  global.LoomSeal = { esc: esc, pad: pad, reportLines: reportLines, renderInto: renderInto };
})(typeof window !== "undefined" ? window : globalThis);
