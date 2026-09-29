#!/usr/bin/env python3
"""Cross-verify the Go implementation's tree bundles with this reference verifier.

Two implementations that only agree with themselves can be wrong the same way. This runs the Python
verifier against bundles the Go verifier produced, and against tampered copies of them, so both
directions are checked: every honest bundle is accepted and every forgery is refused.

Emit the fixtures first, from the loomseal repository root:

    LOOMSEAL_CROSS_DIR=/tmp/crossverify go test ./internal/chain/ -run TestEmitCrossVerifyFixtures
    python3 reference/cross_verify_merkle.py /tmp/crossverify
"""
import glob
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import loomverify  # noqa: E402


def check_accepts(directory):
    """Verify every emitted bundle, returning whether all of them verified."""
    ok = True
    for path in sorted(glob.glob(os.path.join(directory, "*.loomseal.json"))):
        raw = open(path, "rb").read()
        report = loomverify.verify(raw)
        name = os.path.basename(path)
        facts = []
        if report.get("tree_size"):
            facts.append("tree=%s" % report["tree_size"])
        if report.get("inclusion_proofs"):
            facts.append("proofs=%s" % report["inclusion_proofs"])
        if report.get("consistency_ok"):
            facts.append("append-only from %s" % report["consistency_from"])
        print("  accept %-28s ok=%s  %s" % (name, report.get("ok"), " ".join(facts)))
        ok = ok and bool(report.get("ok"))
    return ok


def check_refuses(directory):
    """Tamper with a bundle six ways and require the chain check to refuse each one."""
    path = os.path.join(directory, "sparse.loomseal.json")
    raw = open(path, "rb").read()

    def altered(mutate):
        doc = json.loads(raw)
        mutate(doc)
        return doc

    cases = {
        "claim content altered":
            altered(lambda d: d["claims"][0]["payload"].__setitem__("path", "/v1/evil")),
        "audit path flipped":
            altered(lambda d: d["claims"][0]["inclusion"]["path"].__setitem__(0, "ab" * 32)),
        "leaf index moved":
            altered(lambda d: d["claims"][0]["chain"].__setitem__("seq", 3)),
        "seq past tree size":
            altered(lambda d: d["claims"][0]["chain"].__setitem__("seq", 99)),
        "install id not the signer's":
            altered(lambda d: d["chain"]["params"].__setitem__("install_id", "in_other")),
        "claim carries a prev":
            altered(lambda d: d["claims"][0]["chain"].__setitem__("prev", "cd" * 32)),
    }

    ok = True
    for name, doc in cases.items():
        report = {"chain_present": False, "unknown_types": []}
        try:
            loomverify._check_chain(doc, report)
            print("  refuse %-28s ACCEPTED, which is a failure" % name)
            ok = False
        except Exception as err:  # noqa: BLE001 - any refusal is the expected outcome
            print("  refuse %-28s %s" % (name, err))
    return ok


def main():
    directory = sys.argv[1] if len(sys.argv) > 1 else "/tmp/crossverify"
    if not glob.glob(os.path.join(directory, "*.loomseal.json")):
        print("no bundles in %s; emit them with the go test named in this file's docstring"
              % directory)
        return 1
    print("cross-verifying %s" % directory)
    accepts = check_accepts(directory)
    refuses = check_refuses(directory)
    print()
    print("accepts every honest bundle:", accepts)
    print("refuses every forgery      :", refuses)
    return 0 if accepts and refuses else 1


if __name__ == "__main__":
    raise SystemExit(main())
