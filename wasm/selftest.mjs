// Self-test for the browser verifier.
//
// The page at /verify is the only verifier most relying parties will ever run, so the compiled
// module is held to the same conformance vectors as the command line. A verdict that differs
// between the two is the format disagreeing with itself, which is the failure this catches.
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

// verifyFile runs the compiled verifier over a file exactly as the page does, passing raw
// bytes rather than text so nothing is re-encoded on the way in.
function verifyFile(file, pin) {
  const bytes = new Uint8Array(fs.readFileSync(path.join(root, file)));
  return JSON.parse(pin ? loomsealVerify(bytes, pin) : loomsealVerify(bytes));
}

const manifest = JSON.parse(
  fs.readFileSync(path.join(root, "testdata/vectors/manifest.json"), "utf8"),
);

let bad = 0;
for (const v of manifest.vectors) {
  const r = verifyFile(path.join("testdata/vectors", v.file));
  const problems = [];
  if (r.ok !== v.must_verify) {
    problems.push(`ok=${r.ok} expect=${v.must_verify}`);
  }
  // The browser cannot read evidence off disk, so a vector whose level names verified evidence
  // is expected to land one step lower here. Every other level must match the command line.
  if (r.ok && v.must_verify && v.level && r.level !== v.level) {
    problems.push(`level got[${r.level}] want[${v.level}]`);
  }
  if (problems.length) {
    bad++;
    console.log(`!! ${v.name.padEnd(30)} ${problems.join("  ")}`);
  }
}

// A pinned fingerprint that does not match must fail even though the bundle is otherwise good.
const pinned = verifyFile("examples/audit.loomseal.json", "sha256:" + "00".repeat(32));
if (pinned.ok) {
  bad++;
  console.log("!! mismatched key pin verified");
}

console.log(
  bad === 0
    ? `ALL MATCH  ${manifest.vectors.length} vectors + key pin`
    : `${bad} MISMATCH`,
);
process.exit(bad ? 1 : 0);
