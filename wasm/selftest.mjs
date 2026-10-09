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
const { verifyBytes } = globalThis.LoomSeal;

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

// The page verifies holder presentations through the same dispatcher, held to the presentation
// vectors as the command line is, including the audience and nonce pins each vector declares.
// Every report must come from the presentation entry point, or a vector that must not verify
// would pass for the wrong reason.
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
    continue;
  }
  const r = verifyBytes(bytes, {
    audience: v.expect_audience || "", nonce: v.expect_nonce || "",
  });
  const problems = [];
  if (!Object.prototype.hasOwnProperty.call(r, "presentation_ok")) {
    problems.push("routed to the bundle entry point");
  }
  if (r.ok !== v.must_verify) {
    problems.push(`ok=${r.ok} expect=${v.must_verify}`);
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

console.log(
  bad === 0
    ? `ALL MATCH  ${checked} vectors + ${pres.vectors.length} presentations + key pin`
    : `${bad} MISMATCH`,
);
process.exit(bad ? 1 : 0);
