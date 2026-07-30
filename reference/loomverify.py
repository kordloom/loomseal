#!/usr/bin/env python3
"""A second, independent LoomSeal v0.1 verifier, implemented from FORMAT.md and the JSON schema.

It exists to keep the format honest: the Go verifier and this one must agree on every conformance
vector, so any drift between the spec and an implementation shows up in CI. It performs the whole
offline procedure with no network access.

Usage:
  python3 loomverify.py <bundle.json> [evidence_dir]   verify one bundle
  python3 loomverify.py --vectors <dir>                 run a vector manifest
"""

import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_SAFE = 2 ** 53
V1 = "loomseal-chain-v1"
DORMOUSE = "dormouse-audit-chain-v2"
SWITCHTENDER = "switchtender-audit-v1"

KNOWN_TYPES = {"dormouse.check/1", "dormouse.change/1", "dormouse.coverage/1",
               "switchtender.audit/1", "switchtender.run/1"}


class VError(Exception):
    """A verification failure carrying the name of the check that failed."""

    def __init__(self, check, msg):
        super().__init__(msg)
        self.check = check
        self.msg = msg


# ---------- RFC 8785 canonicalization ----------

def _reject_bad_strings(text):
    """Reject lone surrogate escapes inside string literals. Raw invalid UTF-8 is already caught
    by the bytes.decode('utf-8') that runs before this."""
    i, n, in_str = 0, len(text), False
    while i < n:
        c = text[i]
        if not in_str:
            if c == '"':
                in_str = True
            i += 1
            continue
        if c == '"':
            in_str = False
            i += 1
        elif c == '\\':
            if i + 1 >= n:
                raise VError("parse", "dangling escape")
            if text[i + 1] != 'u':
                i += 2
                continue
            hi = int(text[i + 2:i + 6], 16)
            if 0xD800 <= hi <= 0xDBFF:
                if text[i + 6:i + 8] != '\\u':
                    raise VError("parse", "high surrogate without low surrogate")
                lo = int(text[i + 8:i + 12], 16)
                if not 0xDC00 <= lo <= 0xDFFF:
                    raise VError("parse", "high surrogate not followed by low surrogate")
                i += 12
            elif 0xDC00 <= hi <= 0xDFFF:
                raise VError("parse", "lone low surrogate escape")
            else:
                i += 6
        else:
            i += 1


def _no_dup_keys(pairs):
    """Reject duplicate object keys, which have no canonical form."""
    seen = {}
    for k, v in pairs:
        if k in seen:
            raise VError("parse", f"duplicate object key {k!r}")
        seen[k] = v
    return seen


def parse_strict(raw_bytes):
    """Parse bundle bytes with the strictness canonicalization needs: valid UTF-8, no lone
    surrogates, no duplicate keys, integer number literals only."""
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise VError("parse", "input is not valid UTF-8")
    _reject_bad_strings(text)

    def parse_float(_):
        raise VError("parse", "non-integer number literal")

    try:
        return json.loads(text, object_pairs_hook=_no_dup_keys, parse_float=parse_float)
    except VError:
        raise
    except json.JSONDecodeError as e:
        raise VError("parse", f"invalid JSON: {e}")


def canon(value):
    """Return the RFC 8785 canonical bytes of a parsed value."""
    return _ser(value).encode("utf-8")


def _ser(v):
    if v is None:
        return "null"
    if v is True:
        return "true"
    if v is False:
        return "false"
    if isinstance(v, int):
        if abs(v) > MAX_SAFE:
            raise VError("parse", f"integer {v} exceeds 2^53")
        return str(v)
    if isinstance(v, float):
        raise VError("parse", "non-integer number")
    if isinstance(v, str):
        return _ser_str(v)
    if isinstance(v, list):
        return "[" + ",".join(_ser(e) for e in v) + "]"
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join(_ser_str(k) + ":" + _ser(val) for k, val in items) + "}"
    raise VError("parse", f"unserializable type {type(v)}")


def _ser_str(s):
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch == '"':
            out.append('\\"')
        elif ch == '\\':
            out.append('\\\\')
        elif o == 0x08:
            out.append('\\b')
        elif o == 0x0C:
            out.append('\\f')
        elif o == 0x0A:
            out.append('\\n')
        elif o == 0x0D:
            out.append('\\r')
        elif o == 0x09:
            out.append('\\t')
        elif o < 0x20:
            out.append('\\u%04x' % o)
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


# ---------- verification ----------

def verify(raw_bytes, evidence_dir=None):
    """Verify one bundle and return a report dict. Failure is a report, never an exception."""
    report = {"ok": False, "level": "not verified", "problems": [],
              "signature_ok": False, "chain_present": False, "chain_ok": False,
              "chain_mode": "", "head_matched": False, "anchors_matched": 0,
              "anchors_to_declared_head": 0, "unknown_types": []}
    try:
        b = parse_strict(raw_bytes)
        _schema_check(b)
        _check_signature(raw_bytes, b, report)
        _check_chain(b, report)
        _check_anchors(b, report)
        _check_evidence(b, evidence_dir, report)
    except VError as e:
        report["problems"].append(f"{e.check}: {e.msg}")
        report["level"] = "not verified"
        return report
    report["ok"] = len(report["problems"]) == 0
    report["level"] = _level(report)
    return report


def _schema_check(b):
    if not isinstance(b, dict):
        raise VError("parse", "bundle is not an object")
    if b.get("loomseal") != "0.1":
        raise VError("parse", f"loomseal version {b.get('loomseal')!r}, want 0.1")
    for req in ("bundle_id", "created_at", "producer", "subject", "claims", "signatures"):
        if req not in b:
            raise VError("parse", f"missing required member {req}")
    if not isinstance(b["claims"], list) or not b["claims"]:
        raise VError("parse", "claims must be a non-empty array")
    if not isinstance(b["signatures"], list) or not b["signatures"]:
        raise VError("parse", "signatures must be a non-empty array")


def _key_id(pub_bytes):
    return "sha256:" + hashlib.sha256(pub_bytes).hexdigest()


def _check_signature(raw_bytes, b, report):
    parsed = parse_strict(raw_bytes)
    parsed["signatures"] = []
    canonical = canon(parsed)
    prod = b["producer"]
    try:
        pub_bytes = base64.b64decode(prod["public_key"], validate=True)
    except Exception:
        raise VError("signature", "producer public_key is not base64")
    if len(pub_bytes) != 32:
        raise VError("signature", "producer public_key is not 32 bytes")
    if _key_id(pub_bytes) != prod.get("key_id"):
        raise VError("signature", "producer key_id does not match the public key")
    pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
    for sig in b["signatures"]:
        if sig.get("key_id") != prod["key_id"]:
            continue
        try:
            pub.verify(base64.b64decode(sig["sig"], validate=True), canonical)
            report["signature_ok"] = True
            return
        except (InvalidSignature, Exception):
            continue
    raise VError("signature", "no producer signature verifies over the canonical bundle")


def _check_chain(b, report):
    if "chain" not in b:
        return
    report["chain_present"] = True
    chain = b["chain"]
    claims = b["claims"]
    for i, c in enumerate(claims):
        if "chain" not in c:
            raise VError("chain", f"claim {i} has no chain coordinates")
    for i, c in enumerate(claims):
        co = c["chain"]
        if i == 0:
            if co["seq"] == 1 and co.get("prev", "") != "":
                raise VError("chain", "genesis claim has a prev link")
            continue
        prev = claims[i - 1]["chain"]
        if co["seq"] != prev["seq"] + 1:
            raise VError("chain", f"claim {i} sequence is not contiguous")
        if co.get("prev", "") != prev["link"]:
            raise VError("chain", f"claim {i} prev does not match the prior link")
    head = chain["head"]
    last = claims[-1]["chain"]
    if head["seq"] < last["seq"]:
        raise VError("chain", "head sequence is behind the newest claim")
    if head["seq"] == last["seq"]:
        if head["link"] != last["link"]:
            raise VError("chain", "head link does not match the newest claim")
        report["head_matched"] = True
    if chain.get("keyed"):
        report["chain_mode"] = "structural"
    else:
        _recompute_links(b)
        report["chain_mode"] = "full"
    report["chain_ok"] = True
    for c in claims:
        if c["type"] not in KNOWN_TYPES and c["type"] not in report["unknown_types"]:
            report["unknown_types"].append(c["type"])


def _recompute_links(b):
    profile = b["chain"]["profile"]
    if profile == V1:
        _links_v1(b)
    elif profile == DORMOUSE:
        _links_dormouse(b)
    elif profile == SWITCHTENDER:
        _links_switchtender(b)
    else:
        raise VError("chain", f"unknown profile {profile}")


def _links_v1(b):
    install = (b["chain"].get("params") or {}).get("install_id")
    if not install:
        raise VError("chain", "loomseal-chain-v1 requires params.install_id")
    for i, c in enumerate(b["claims"]):
        bare = {k: v for k, v in c.items() if k != "chain"}
        claim_digest = "sha256:" + hashlib.sha256(canon(bare)).hexdigest()
        link_input = canon({"domain": V1, "install_id": install,
                             "seq": c["chain"]["seq"], "prev": c["chain"].get("prev", ""),
                             "claim": claim_digest})
        if hashlib.sha256(link_input).hexdigest() != c["chain"]["link"]:
            raise VError("chain", f"claim {i} link does not recompute")


def _links_dormouse(b):
    install = (b["chain"].get("params") or {}).get("install_id")
    if not install:
        raise VError("chain", "dormouse profile requires params.install_id")
    for i, c in enumerate(b["claims"]):
        p = c["payload"]
        snapshot = ""
        for e in c.get("evidence", []):
            if e.get("role") == "snapshot":
                snapshot = e["digest"].split("sha256:")[-1]
                break
        fields = [DORMOUSE, install, c["chain"].get("prev", ""), p.get("target_id", ""),
                  p.get("outcome", ""), str(p.get("status", "")), snapshot, p.get("error", ""),
                  str(p.get("elapsed_ns", "")), str(_unix_nanos(c["at"]))]
        blob = "".join(f"{len(f.encode('utf-8'))}:{f}" for f in fields).encode("utf-8")
        if hashlib.sha256(blob).hexdigest() != c["chain"]["link"]:
            raise VError("chain", f"claim {i} link does not recompute (dormouse)")


def _links_switchtender(b):
    for i, c in enumerate(b["claims"]):
        p = c["payload"]
        arr = canon([str(c["chain"]["seq"]), _rfc3339_utc(c["at"]), p.get("actor", ""),
                     p.get("method", ""), p.get("path", ""), c["chain"].get("prev", "")])
        if hashlib.sha256(arr).hexdigest() != c["chain"]["link"]:
            raise VError("chain", f"claim {i} link does not recompute (switchtender)")


def _unix_nanos(ts):
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)
    return int(dt.timestamp() * 1_000_000_000)


def _rfc3339_utc(ts):
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)
    if dt.microsecond:
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f").rstrip("0") + "Z"
    return dt.strftime("%Y-%m-%dT%H:%M:%S") + "Z"


def _check_anchors(b, report):
    anchors = b.get("anchors") or []
    if not anchors:
        return
    if "chain" not in b:
        raise VError("anchor", "anchors present without a chain")
    verified = {}
    for c in b["claims"]:
        if "chain" in c:
            verified[c["chain"]["seq"]] = c["chain"]["link"]
    head = b["chain"]["head"]
    if report["head_matched"]:
        verified[head["seq"]] = head["link"]
    for i, a in enumerate(anchors):
        if verified.get(a["seq"]) == a["link"]:
            report["anchors_matched"] += 1
        elif not report["head_matched"] and a["seq"] == head["seq"] and a["link"] == head["link"]:
            report["anchors_to_declared_head"] += 1
        else:
            raise VError("anchor", f"anchor {i} matches no verified claim or the declared head")


def _check_evidence(b, evidence_dir, report):
    supplied = set()
    if evidence_dir:
        for root, _, files in os.walk(evidence_dir):
            for fn in files:
                with open(os.path.join(root, fn), "rb") as fh:
                    supplied.add("sha256:" + hashlib.sha256(fh.read()).hexdigest())
    verified = missing = referenced = 0
    for c in b["claims"]:
        for e in c.get("evidence", []):
            if not evidence_dir:
                referenced += 1
            elif e["digest"] in supplied:
                verified += 1
            else:
                missing += 1
    report["evidence"] = {"verified": verified, "missing": missing, "referenced": referenced}


def _level(report):
    if not report["signature_ok"]:
        return "not verified"
    level = "signed"
    if report["chain_present"] and report["chain_ok"]:
        level += f", chained ({report['chain_mode']})"
    if report["anchors_matched"] > 0:
        level += ", anchored by reference"
    return level


# ---------- CLI ----------

def run_vectors(dirpath):
    """Run every vector in a manifest and report agreement with its declared expectations."""
    man = json.load(open(os.path.join(dirpath, "manifest.json")))
    bad = 0
    for v in man["vectors"]:
        raw = open(os.path.join(dirpath, v["file"]), "rb").read()
        r = verify(raw)
        ok = r["ok"]
        status = "OK " if ok == v["must_verify"] else "!! "
        detail = ""
        if ok and v["must_verify"] and v.get("level") and r["level"] != v["level"]:
            status, detail = "!! ", f"  level got[{r['level']}] want[{v['level']}]"
        if status == "!! ":
            bad += 1
        print(f"{status}{v['name']:<28} ok={ok} expect={v['must_verify']}{detail}")
    print(f"\n{'ALL MATCH' if bad == 0 else str(bad) + ' MISMATCH'}")
    return 1 if bad else 0


def main(argv):
    if len(argv) >= 3 and argv[1] == "--vectors":
        return run_vectors(argv[2])
    if len(argv) < 2:
        print("usage: loomverify.py <bundle.json> [evidence_dir] | --vectors <dir>")
        return 2
    report = verify(open(argv[1], "rb").read(), argv[2] if len(argv) > 2 else None)
    print(json.dumps(report, indent=2))
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
