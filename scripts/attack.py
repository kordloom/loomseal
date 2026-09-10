"""Adversarial mutation harness: every mutation below is a lie a bundle could tell.

A verifier worth trusting rejects each one, so a mutation that still verifies is a finding.
Complements testdata/vectors, which are static files asserting fixed verdicts: this generates
mutations from whatever bundle it is handed, so it travels to a producer's own bundle shapes.

Usage: python3 attack.py [bundle.json] [evidence-dir]

Mutations that do not fit a bundle's shape report SKIPPED rather than failing, so this
runs against any claim payload and any chain profile.

Every mutation below is a lie a bundle could tell. A verifier that is worth trusting
must reject each one, so a mutation that still verifies is a finding, not a curiosity.
"""

import copy
import json
import subprocess
import sys

BASE = json.load(open(sys.argv[1] if len(sys.argv) > 1 else "base.json"))
EVIDENCE = sys.argv[2] if len(sys.argv) > 2 else "."
import os
LOOMSEAL = os.environ.get("LOOMSEAL", "loomseal")


def verify(doc, name):
    """Write doc to a scratch file and return the verifier's exit code and verdict line."""
    path = "mut.json"
    json.dump(doc, open(path, "w"))
    p = subprocess.run([LOOMSEAL, "verify", path, "--evidence", EVIDENCE],
                       capture_output=True, text=True)
    verdict = ""
    for line in p.stdout.split("\n"):
        if line.startswith(("VERIFIED", "NOT VERIFIED", "UNSUPPORTED")):
            verdict = line.strip()
    return p.returncode, verdict


def mutate(name, fn):
    """Apply fn to a copy of the bundle and report whether the lie was caught."""
    d = copy.deepcopy(BASE)
    try:
        fn(d)
    except Exception as e:  # a mutation that cannot be built is not a test
        print("  %-46s SKIPPED (%s)" % (name, e))
        return None
    code, verdict = verify(d, name)
    caught = code != 0
    print("  %-46s %-8s exit %d  %s" % (name, "CAUGHT" if caught else "*** PASSED ***",
                                        code, verdict))
    return caught


print("=== claim content ===")
results = []
results.append(mutate("flip a payload number (cobra 65.5 -> 99.9)",
    lambda d: d["claims"][0]["payload"].__setitem__("score_pct", "99.9")))
results.append(mutate("flip killed/survived counts",
    lambda d: d["claims"][0]["payload"].__setitem__("survived", 1)))
results.append(mutate("change the survivor line number",
    lambda d: d["claims"][2]["payload"].__setitem__("line", 999)))
results.append(mutate("change coverage execution count 78 -> 780",
    lambda d: d["claims"][2]["payload"].__setitem__("coverage_execution_count", 780)))
results.append(mutate("change a claim timestamp",
    lambda d: d["claims"][0].__setitem__("at", "2020-01-01T00:00:00Z")))
results.append(mutate("change a claim type",
    lambda d: d["claims"][0].__setitem__("type", "assay.something-else/1")))

print("\n=== chain structure ===")
results.append(mutate("delete the retraction claim",
    lambda d: d["claims"].pop(3)))
results.append(mutate("delete a middle claim",
    lambda d: d["claims"].pop(1)))
results.append(mutate("reorder two claims",
    lambda d: d["claims"].__setitem__(slice(0, 2), [d["claims"][1], d["claims"][0]])))
results.append(mutate("duplicate a claim",
    lambda d: d["claims"].append(copy.deepcopy(d["claims"][0]))))
results.append(mutate("rewrite a chain link",
    lambda d: d["claims"][1]["chain"].__setitem__("link", "a" * 64)))
results.append(mutate("rewrite prev to skip a claim",
    lambda d: d["claims"][2]["chain"].__setitem__("prev", d["claims"][0]["chain"]["link"])))
results.append(mutate("renumber a seq",
    lambda d: d["claims"][2]["chain"].__setitem__("seq", 99)))
results.append(mutate("point head at a different link",
    lambda d: d["chain"]["head"].__setitem__("link", "b" * 64)))
results.append(mutate("claim a longer chain than is bundled",
    lambda d: d["chain"]["head"].__setitem__("seq", 400)))

print("\n=== identity and signature ===")
results.append(mutate("truncate the signature",
    lambda d: d["signatures"][0].__setitem__("sig", d["signatures"][0]["sig"][:-8])))
results.append(mutate("flip a byte in the signature",
    lambda d: d["signatures"][0].__setitem__(
        "sig", ("A" if d["signatures"][0]["sig"][0] != "A" else "B") + d["signatures"][0]["sig"][1:])))
results.append(mutate("remove all signatures",
    lambda d: d.__setitem__("signatures", [])))
results.append(mutate("swap in a different public key",
    lambda d: d["producer"].__setitem__("public_key", "sAeJG/EJP4Mv9dGFAToZcQL+JZwp8aXT1s6GVK+GluB=")))
results.append(mutate("rewrite the key_id to disagree with the key",
    lambda d: d["producer"].__setitem__("key_id", "sha256:" + "0" * 64)))
results.append(mutate("change the producing product",
    lambda d: d["producer"].__setitem__("product", "not-assay")))
results.append(mutate("change install_id the chain is keyed on",
    lambda d: d["chain"]["params"].__setitem__("install_id", "in_somebody_else")))

print("\n=== envelope ===")
results.append(mutate("change bundle_id",
    lambda d: d.__setitem__("bundle_id", "lsb_someone_elses_bundle")))
results.append(mutate("backdate created_at",
    lambda d: d.__setitem__("created_at", "2019-01-01T00:00:00Z")))
results.append(mutate("change the subject",
    lambda d: d["subject"].__setitem__("id", "somebody-elses-measurements")))
results.append(mutate("declare an unknown format version",
    lambda d: d.__setitem__("loomseal", "99.0")))
results.append(mutate("declare an unknown chain profile",
    lambda d: d["chain"].__setitem__("profile", "loomseal-chain-v99")))

print("\n=== evidence binding ===")
results.append(mutate("point a claim at a different digest",
    lambda d: d["claims"][0]["evidence"][0].__setitem__("digest", "sha256:" + "c" * 64)))
results.append(mutate("drop an evidence reference entirely",
    lambda d: d["claims"][2].__setitem__("evidence", [])))
results.append(mutate("relocate evidence outside the directory",
    lambda d: d["claims"][0]["evidence"][0].__setitem__("location", "../../../etc/passwd")))

real = [r for r in results if r is not None]
missed = [i for i, r in enumerate(real) if not r]
print("\n%d mutations, %d caught, %d passed verification" %
      (len(real), sum(real), len(missed)))
sys.exit(1 if missed else 0)
