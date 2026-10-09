#!/usr/bin/env python3
"""Cross-verify the Go implementation's record cases with this reference verifier.

The conformance vectors pin the record check on its main paths. The Go unit test drives it down
every path it has, each a receipt re-signed after an edit so only the record check can object, and
it writes those receipts and the verdict each must reach. This runs the Python verifier over the
same bytes, so the two implementations are shown to agree on every edge, not only on the vectors.

Emit the cases first, from the loomseal repository root:

    LOOMSEAL_CROSS_DIR=/tmp/crossrecords go test ./internal/verify/ \\
        -run TestRecordsHoldWhatTheirEntriesCommitted
    python3 reference/cross_verify_records.py /tmp/crossrecords
"""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import loomverify  # noqa: E402


# _LISTS are the counts that are lists, compared without regard to order.
_LISTS = {"reasons_redacted", "legacy_records", "unchecked"}


def main():
    directory = sys.argv[1] if len(sys.argv) > 1 else "/tmp/crossrecords"
    manifest = os.path.join(directory, "records.json")
    if not os.path.exists(manifest):
        print("no records.json in %s; emit it with the go test named in this file's docstring"
              % directory)
        return 1
    cases = json.load(open(manifest))
    bad = 0
    for case in cases:
        report = loomverify.verify(open(os.path.join(directory, case["file"]), "rb").read())
        why = ""
        if report["ok"] != case["want_ok"]:
            why = "ok=%s, want %s: %s" % (report["ok"], case["want_ok"], report["problems"])
        elif not case["want_ok"]:
            want = case.get("want_problem", "")
            if not any(p.startswith("record:") and want in p for p in report["problems"]):
                why = "no record problem mentions %r: %s" % (want, report["problems"])
            # A failed bundle achieved no level and lists no disclosed state, in this verifier and
            # in the Go one, so the two reports agree on every field a consumer might key on.
            if report["level"] != "not verified":
                why += "level=%r, want 'not verified' " % report["level"]
            if report["disclosed"] or report["disclosed_unchecked"]:
                why += "disclosed=%d unchecked=%d on a failed bundle, want none " % (
                    len(report["disclosed"]), report["disclosed_unchecked"])
        else:
            got = dict(report)
            got["unchecked"] = ["claim %d %s" % (d["claim"], d["member"])
                                for d in report["disclosed"] if d["state"] == "unchecked"]
            for key, value in case["want_counts"].items():
                have = got.get(key)
                if key in _LISTS:
                    have, value = sorted(have or []), sorted(value or [])
                elif not value:
                    value = 0
                if have != value:
                    why += "%s=%r, want %r " % (key, have, value)
        status = "!! " if why else "OK "
        bad += 1 if why else 0
        print("%s%-26s ok=%s %s" % (status, case["file"], report["ok"], why))
    print()
    print("ALL AGREE" if bad == 0 else "%d DISAGREE" % bad)
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
