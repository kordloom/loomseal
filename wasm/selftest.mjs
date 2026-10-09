// Self-test for the browser verifier.
//
// The page at /verify is the only verifier most relying parties will ever run, so the compiled
// module is held to the same conformance vectors as the command line. A verdict that differs
// between the two is the format disagreeing with itself, which is the failure this catches.
//
// Every file travels the path a dropped file takes on the page, through the dispatcher in
// render.js, rather than straight into the module's entry points. A page that routed a holder
// presentation to the bundle entry point would refuse it at parse while both entry points stayed
// correct, and only a self-test of the page's own routing sees that.
//
// Usage: node wasm/selftest.mjs <dir-with-loomseal.wasm-and-wasm_exec.js>

import fs from "node:fs";
import path from "node:path";

const dir = process.argv[2] || "site/public/verify";
const root = process.cwd();

globalThis.fs = fs;
globalThis.path = path;
globalThis.performance = performance;

await import(path.resolve(dir, "wasm_exec.js"));

const go = new globalThis.Go();
const wasm = fs.readFileSync(path.join(dir, "loomseal.wasm"));
const { instance } = await WebAssembly.instantiate(wasm, go.importObject);
go.run(instance);
await new Promise((r) => setTimeout(r, 200));

// render.js attaches LoomSeal to globalThis when no window is present, which is the Node case.
(0, eval)(fs.readFileSync(path.join(root, "site/public/verify/render.js"), "utf8"));
const { verifyBytes, reportLines } = globalThis.LoomSeal;

// unopenedNote is the page's note naming carried proofs of a type the verifier cannot open, after
// its count, in the command line's words.
const unopenedNote = "carried proof(s) are of a type this verifier cannot open offline, " +
  "so they were counted and not checked";

// declaredHeadNote is the page's note naming proofs on anchors that match only the unverified
// declared head, after its count, in the command line's words.
const declaredHeadNote = "proof(s) sit on the unverified declared head and were not checked; " +
  "they earn no anchored level";

// countNotes pairs each proof count a vector can pin with the note the page names it in.
const countNotes = [
  ["anchor_proofs_unopened", unopenedNote],
  ["anchor_proofs_on_declared_head", declaredHeadNote],
];

// readBytes reads a file exactly as the page does, as raw bytes rather than text, so nothing is
// re-encoded on the way in.
function readBytes(file) {
  return new Uint8Array(fs.readFileSync(path.join(root, file)));
}

// verifyFile runs a file through the page's dispatcher under an optional producer pin.
function verifyFile(file, pin) {
  return verifyBytes(readBytes(file), { pin });
}

const manifest = JSON.parse(
  fs.readFileSync(path.join(root, "testdata/vectors/manifest.json"), "utf8"),
);

let bad = 0;
let checked = 0;
for (const v of manifest.vectors) {
  // The page never reads evidence off disk, so a case checked against an evidence directory has no
  // browser counterpart. The command line and the reference verifier are held to it.
  if (v.evidence) continue;
  checked++;
  const r = verifyFile(path.join("testdata/vectors", v.file));
  const problems = [];
  if (r.ok !== v.must_verify) {
    problems.push(`ok=${r.ok} expect=${v.must_verify}`);
  }
  // A malformed document is not verified, which is a different verdict from unsupported.
  if (!v.must_verify && v.failing_check === "parse" && r.unsupported) {
    problems.push("parse case judged unsupported");
  }
  // The level is pinned on every vector: the wording achieved when the bundle verifies, and "not
  // verified" or "unsupported" when it does not. The browser cannot read evidence off disk, so a
  // vector whose level names verified evidence would land one step lower here; none does.
  if (v.level && r.level !== v.level) {
    problems.push(`level got[${r.level}] want[${v.level}]`);
  }
  // What a verified bundle leaves unchecked is part of its verdict, here as on the command line,
  // and a bundle that does not verify lists nothing.
  for (const state of ["unchecked", "redacted"]) {
    const got = (r.disclosed || [])
      .filter((d) => d.state === state)
      .map((d) => `claim ${d.claim} ${d.member}`)
      .join(",");
    const want = (v[state] || []).join(",");
    if (got !== want) problems.push(`${state} got[${got}] want[${want}]`);
  }
  // A bundle that does not verify lists no disclosed member in any state, checked ones included,
  // and counts none unchecked.
  if (!v.must_verify && ((r.disclosed || []).length || r.disclosed_unchecked)) {
    problems.push(`failed bundle lists ${(r.disclosed || []).length} disclosed members`);
  }
  if (r.ok && v.must_verify) {
    const legacy = (r.legacy_records || []).join(",");
    const wantLegacy = (v.legacy || []).join(",");
    if (legacy !== wantLegacy) problems.push(`legacy got[${legacy}] want[${wantLegacy}]`);
    // A subject type outside the vocabulary is reported by name, and one inside it is not.
    const unknown = r.unknown_subject_type || "";
    const wantUnknown = v.unknown_subject_type || "";
    if (unknown !== wantUnknown) {
      problems.push(`unknown_subject_type got[${unknown}] want[${wantUnknown}]`);
    }
    // A gap is measured one way, so the coverage line, the longest gap, and each gap's wording
    // are part of the verdict a spanned vector pins, here as on the command line.
    for (const key of ["span_coverage", "span_longest_gap"]) {
      const got = r[key] || "";
      const want = v[key] || "";
      if (got !== want) problems.push(`${key} got[${got}] want[${want}]`);
    }
    const gaps = (r.span_gaps || []).join("|");
    const wantGaps = (v.span_gaps || []).join("|");
    if (gaps !== wantGaps) problems.push(`span_gaps got[${gaps}] want[${wantGaps}]`);
    // The signer is named by one rule, so each verified token's time and signer line is part of
    // the verdict a vector pins, here as on the command line.
    const attested = (r.anchor_attestations || []).join("|");
    const wantAttested = (v.anchor_attestations || []).join("|");
    if (attested !== wantAttested) {
      problems.push(`anchor_attestations got[${attested}] want[${wantAttested}]`);
    }
  }
  // A proof is counted as one the verifier cannot open by its type alone, so a token it opened is
  // never counted there, whether it held or failed, and a proof on an anchor matching only the
  // unverified declared head is counted on that head whatever its type. Each count is held on
  // every vector that pins it, and at zero on a vector that must verify and pins none, here as on
  // the command line. The page names each count in a note, so the note it renders is held to the
  // same number.
  for (const [key, note] of countNotes) {
    if (!Object.prototype.hasOwnProperty.call(v, key) && !v.must_verify) {
      continue;
    }
    const want = v[key] || 0;
    const got = r[key] || 0;
    if (got !== want) {
      problems.push(`${key} got[${got}] want[${want}]`);
    }
    const notes = reportLines(r)
      .filter((row) => row[0] === "note" && row[1].includes(note))
      .map((row) => row[1]);
    const wantNotes = want ? [`${want} ${note}`] : [];
    if (notes.join("|") !== wantNotes.join("|")) {
      problems.push(`${key} note got[${notes.join("|")}] want[${wantNotes.join("|")}]`);
    }
  }
  if (problems.length) {
    bad++;
    console.log(`!! ${v.name.padEnd(30)} ${problems.join("  ")}`);
  }
}

// A pinned fingerprint that does not match must fail even though the bundle is otherwise good.
const example = "examples/audit.loomseal.json";
const pinned = verifyFile(example, "sha256:" + "00".repeat(32));
if (pinned.ok) {
  bad++;
  console.log("!! mismatched key pin verified");
}

// A pin in any form but sha256: and 64 lowercase hex digits names no key, so it is refused rather
// than compared, and an explicit empty pin handed to the entry point is a pin, not the unpinned run.
// The refusal names the form, so a mismatch against a malformed pin cannot pass for it.
function refusesPin(name, r) {
  const refused = (r.problems || []).some((p) => p.includes("fingerprint is not sha256:"));
  if (r.ok || !refused) {
    bad++;
    console.log(`!! ${name} was not refused as a malformed pin: ${JSON.stringify(r.problems)}`);
  }
}
refusesPin("uppercase pin", verifyFile(example, "SHA256:" + "00".repeat(32)));
refusesPin("bare hex pin", verifyFile(example, "00".repeat(32)));
refusesPin("explicit empty pin", JSON.parse(loomsealVerify(readBytes(example), "")));

// presentationCheckError returns why a presentation report does not fail first at the check the
// manifest names, or "" if it does, in the order FORMAT.md's "Presentations" section gives: the
// presentation is read, the embedded bundle is verified, then the holder signature, the audience,
// and the nonce. Each problem is named by its check, as the command line and the reference name it.
function presentationCheckError(check, r) {
  const first = (r.problems || [])[0] || "";
  const read = !r.bundle && !r.presentation_ok;
  const bundleOK = !!(r.bundle && r.bundle.ok);
  switch (check) {
    case "parse":
      return read && !r.unsupported && first.startsWith("parse: ") ? "" :
        "parse case was not refused as it was read";
    case "unsupported":
      return read && r.unsupported && first.startsWith("unsupported") ? "" :
        "unsupported case was not judged unsupported as it was read";
    case "bundle":
      return !r.unsupported && r.bundle && !r.bundle.ok ? "" :
        "bundle case did not fail the embedded bundle";
    case "presentation":
      return bundleOK && !r.presentation_ok && first.startsWith("presentation: ") ? "" :
        "presentation case did not fail first on the holder";
    case "audience":
      return bundleOK && r.presentation_ok && r.audience_match === false ? "" :
        "audience case did not fail first on the audience";
    case "nonce":
      return bundleOK && r.presentation_ok && r.audience_match !== false &&
        r.nonce_match === false ? "" : "nonce case did not fail first on the nonce";
    default:
      return `manifest names an unknown presentation failing_check ${check}`;
  }
}

// The page verifies holder presentations through the same dispatcher, held to the presentation
// vectors as the command line is, including the audience and nonce pins each vector declares and
// the check each one fails first. The manifest pins which entry point the dispatcher sends each
// document to: a presentation report must come from the presentation entry point, or a vector that
// must not verify would pass for the wrong reason, and a document that is no JSON object carrying
// a string presentation version is read as a bundle and refused at parse, as the command line and
// the reference refuse it. The presentation entry point refuses that document at parse too.
const pres = JSON.parse(
  fs.readFileSync(path.join(root, "testdata/vectors/presentations.json"), "utf8"),
);
for (const v of pres.vectors) {
  const bytes = readBytes(path.join("testdata/vectors", v.file));
  // A vector that carries an expectation as an empty string goes straight to the module's entry
  // point, which can tell it from an absent one and must refuse it by name. The page passes a blank
  // field as no expectation, so its dispatcher is not such an entry point.
  const empty = ["audience", "nonce"].find((m) => v["expect_" + m] === "");
  if (empty) {
    const r = JSON.parse(loomsealVerifyPresentation(bytes, v.expect_audience, v.expect_nonce));
    refusesExpectation(v.name, empty, r);
    if (v.failing_check !== "expectation") {
      bad++;
      console.log(`!! ${v.name.padEnd(30)} refused as an empty expectation, ` +
        `want ${v.failing_check}`);
    }
    continue;
  }
  const r = verifyBytes(bytes, {
    audience: v.expect_audience || "", nonce: v.expect_nonce || "",
  });
  const problems = [];
  const routed = !Object.prototype.hasOwnProperty.call(r, "presentation_ok");
  let report = r;
  if (routed !== !!v.routes_as_bundle) {
    problems.push(`routed to the bundle entry point ${routed}`);
  } else if (routed) {
    if (r.ok || r.unsupported || r.signature_ok || r.level !== "not verified" ||
      !((r.problems || [])[0] || "").startsWith("parse: ")) {
      problems.push(`read as a bundle and not refused at parse: ${JSON.stringify(r.problems)}`);
    }
    report = JSON.parse(loomsealVerifyPresentation(bytes, v.expect_audience, v.expect_nonce));
  }
  if (report.ok !== v.must_verify) {
    problems.push(`ok=${report.ok} expect=${v.must_verify}`);
  } else if (!v.must_verify) {
    const why = presentationCheckError(v.failing_check, report);
    if (why) problems.push(`${why}: ${JSON.stringify(report.problems)}`);
  }
  if (problems.length) {
    bad++;
    console.log(`!! ${v.name.padEnd(30)} ${problems.join("  ")}`);
  }
}
const validPresentation = readBytes("testdata/vectors/present-valid.loomseal-presentation.json");
const emptyPresentationPin = JSON.parse(loomsealVerifyPresentation(
  validPresentation, undefined, undefined, ""));
refusesPin("explicit empty presentation pin", emptyPresentationPin);
if (!Object.prototype.hasOwnProperty.call(emptyPresentationPin, "presentation_ok")) {
  bad++;
  console.log("!! a refused presentation pin came back as a bundle report");
}

// An expected audience or nonce handed to the entry point as an empty string is an expectation that
// compares against nothing, refused as the command line refuses --nonce "" and in the words the
// reference verifier uses, before anything is verified. The refusal is a presentation report, so
// the page names the presentation in its verdict.
function refusesExpectation(name, member, r) {
  const want = `${member}: expected value is empty and compares against nothing`;
  const refused = JSON.stringify(r.problems) === JSON.stringify([want]);
  const shaped = Object.prototype.hasOwnProperty.call(r, "presentation_ok");
  if (r.ok || !refused || !shaped) {
    bad++;
    console.log(`!! ${name} was not refused as an empty expectation: ${JSON.stringify(r)}`);
  }
}

// A name the producer wrote reaches the page in the command line's form: quoted by the compiled
// verifier's own rule when a character in it does not print, so a control or bidi character can
// neither act on the reader nor reorder the line, and unchanged otherwise.
const named = globalThis.LoomSeal.reportLines({
  ok: true, level: "signed", signature_ok: true, producer_pinned: true, disclosed_unchecked: 1,
  disclosed: [
    { claim: 1, member: "decision_body", state: "checked", detail: "" },
    { claim: 1, member: "x\u001b[2J", state: "checked", detail: "" },
    { claim: 2, member: "y\u202ez", state: "unchecked", detail: "not declared\nVERIFIED" },
  ],
}).map((row) => row[0] + "|" + row[1]);
for (const want of [
  'checked|decision_body 1, "x\\x1b[2J" 1',
  'unchecked|claim 2 "y\\u202ez": "not declared\\nVERIFIED"',
]) {
  if (!named.includes(want)) {
    bad++;
    console.log(`!! name not shown in the command line's form: ${JSON.stringify(want)}`);
  }
}

console.log(
  bad === 0
    ? `ALL MATCH  ${checked} vectors + ${pres.vectors.length} presentations + key pin`
    : `${bad} MISMATCH`,
);
process.exit(bad ? 1 : 0);
