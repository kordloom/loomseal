// DOM-level self-test for the browser verify page's renderer.
//
// The page claims to render the same lines the command line prints. This holds the shared renderer
// to that: for each qualifying notice, it renders a report that must carry the notice and one that
// must not, into a minimal element, and reads the resulting innerHTML. A missing notice fails the
// test, which is what the page quietly did before render.js existed.
//
// Usage: node site/render_selftest.mjs

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const src = fs.readFileSync(path.join(here, "public", "verify", "render.js"), "utf8");
// render.js attaches LoomSeal to globalThis when no window is present, which is the Node case.
(0, eval)(src);
const { renderInto } = globalThis.LoomSeal;

// renderToHTML runs the shared renderer into a one-field element shim and returns the innerHTML.
function renderToHTML(report) {
  const el = { innerHTML: "" };
  renderInto(el, report, "bundle.json", { textContent: "" });
  return el.innerHTML;
}

// base is a minimal verified report. Each case layers the fields that should raise a notice.
function base(extra) {
  return Object.assign({
    ok: true, level: "signed, chained (full)", bundle_id: "lsb", producer: "p 1",
    subject: "run r", key_id: "sha256:aa", signature_ok: true, producer_pinned: true,
    chain_present: true, chain_ok: true, chain_mode: "full", head_matched: true, claims_checked: 1,
    evidence_verified: 0, evidence_missing: 0, evidence_referenced: 0,
  }, extra || {});
}

let bad = 0;
function check(name, present, html, needle) {
  const has = html.includes(needle);
  if (has !== present) {
    bad++;
    console.log(`!! ${name}: ${present ? "missing" : "unexpected"} ${JSON.stringify(needle)}`);
  }
}

// pin NONE: shown for a verified unpinned bundle, hidden once the key is pinned.
check("pin NONE present", true, renderToHTML(base({ producer_pinned: false })),
  "pin        NONE, so this says the bundle was signed");
check("pin NONE absent when pinned", false, renderToHTML(base({ producer_pinned: true })),
  "pin        NONE");

// ALTERED: an artifact present but not matching the sealed digest.
check("ALTERED present", true,
  renderToHTML(base({ ok: false, evidence_mismatched: 1,
    problems: ["evidence snapshot at a.html does not match its sealed digest sha256:bb"] })),
  "ALTERED    1 artifact(s) present but not matching the sealed digest");
check("ALTERED absent when clean", false, renderToHTML(base({})),
  "ALTERED");

// declared head note: the head leads the bundled claims.
check("declared head note present", true, renderToHTML(base({ head_matched: false })),
  "note       declared head is ahead of the bundled claims");
check("declared head note absent when matched", false, renderToHTML(base({ head_matched: true })),
  "declared head is ahead");

// unknown claim type note.
check("unknown claim type present", true,
  renderToHTML(base({ unknown_claim_types: ["acme.thing/1"] })),
  "note       unknown claim type acme.thing/1, not checked against a registry entry");
check("unknown claim type absent", false, renderToHTML(base({})),
  "unknown claim type");

// install binding line.
check("install binding present", true,
  renderToHTML(base({ install_binding: "minted from the producer key" })),
  "install    minted from the producer key");
check("install binding absent", false, renderToHTML(base({})),
  "install    minted");

// attestors NOT CHECKED: a counter-signature is present and no expected signer was named.
check("attestors NOT CHECKED present", true,
  renderToHTML(base({ attestations_present: true, attestations_verified: 1,
    attestors: ["auditor sha256:cc"], attestors_pinned: false })),
  "NOT CHECKED against expected signers");
check("attestors NOT CHECKED absent when pinned", false,
  renderToHTML(base({ attestations_present: true, attestations_verified: 1,
    attestors: ["auditor sha256:cc"], attestors_pinned: true })),
  "NOT CHECKED against expected signers");

// Disclosed members: an unchecked one qualifies the verdict and is named, and a verdict with none
// stays plain.
const unchecked = base({ disclosed_unchecked: 1, disclosed: [{ claim: 1, member: "outcome_body",
  state: "unchecked", detail: "the entry committed it under an older digest form" }] });
check("unchecked qualifier present", true, renderToHTML(unchecked),
  "VERIFIED, 1 disclosed record(s) unchecked");
check("unchecked member named", true, renderToHTML(unchecked),
  "unchecked  claim 1 outcome_body: the entry committed it under an older digest form");
check("unchecked qualifier absent", false, renderToHTML(base({})), "disclosed record(s) unchecked");

// Records: the counts and a body under the legacy unkeyed form, named because its digest confirms a
// guess.
const legacy = base({ decision_records: 1, reasons_verified: 1,
  legacy_records: ["claim 1 decision_body"] });
check("records line present", true, renderToHTML(legacy),
  "records    1 decision(s), 0 correction(s), 0 outcome(s) reproduce the digests");
check("legacy present", true, renderToHTML(legacy),
  "legacy     claim 1 decision_body is committed under the unkeyed digest form");
check("legacy absent", false, renderToHTML(base({ decision_records: 1 })), "legacy ");

// Withheld reasons: a reason the holder marked redacted is worded as its claim, which nothing
// commits, and never as a redaction that took place.
const withheld = base({ decision_records: 1, correction_records: 1,
  reasons_redacted: ["trade_secret", "personal_data"] });
check("withheld reasons present", true, renderToHTML(withheld),
  "reasons    2 withheld by the holder, categories claimed and not committed: trade_secret, " +
  "personal_data");
check("withheld reason singular", true,
  renderToHTML(base({ decision_records: 1, reasons_redacted: ["trade_secret"] })),
  "reasons    1 withheld by the holder, category claimed and not committed: trade_secret");
check("withheld reasons never vouched", false, renderToHTML(withheld), "unopenable by design");

if (bad === 0) {
  console.log("ALL NOTICES RENDERED  pin NONE, ALTERED, declared head, unknown claim type, install, " +
    "attestors, unchecked members, records, legacy, withheld reasons");
  process.exit(0);
}
console.log(`${bad} NOTICE MISMATCH`);
process.exit(1);
