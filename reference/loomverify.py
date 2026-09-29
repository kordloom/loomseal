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

import base64

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding
from cryptography.hazmat.primitives.serialization import pkcs7
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_SAFE = 2 ** 53
V1 = "loomseal-chain-v1"
SWITCHTENDER = "switchtender-audit-v1"

KNOWN_TYPES = {"switchtender.audit/1", "switchtender.run/1"}


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


# ---------- RFC 3161 timestamp proofs ----------

OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SHA256 = "2.16.840.1.101.3.4.2.1"

# A signer names the digest it used over the signed attributes. Assuming SHA-256 works until an
# authority signs with anything else, and then it silently compares two unrelated hashes.
DIGEST_OIDS = {
    "2.16.840.1.101.3.4.2.1": "sha256",
    "2.16.840.1.101.3.4.2.2": "sha384",
    "2.16.840.1.101.3.4.2.3": "sha512",
}


def _der(buf, i=0):
    """Read one DER element at i, returning (tag, header_len, content, end)."""
    tag = buf[i]
    n = buf[i + 1]
    j = i + 2
    if n & 0x80:
        count = n & 0x7F
        n = int.from_bytes(buf[j:j + count], "big")
        j += count
    return tag, j, buf[j:j + n], j + n


def _children(content):
    """Yield every DER element inside a constructed value."""
    i = 0
    while i < len(content):
        tag, hdr, body, end = _der(content, i)
        yield tag, body, content[i:end]
        i = end


def _oid(body):
    """Decode a DER OBJECT IDENTIFIER into dotted form."""
    first = body[0]
    parts = [str(first // 40), str(first % 40)]
    value = 0
    for byte in body[1:]:
        value = (value << 7) | (byte & 0x7F)
        if not byte & 0x80:
            parts.append(str(value))
            value = 0
    return ".".join(parts)


def _find(content, want_tag):
    """Return the first child with the given tag, or None."""
    for tag, body, full in _children(content):
        if tag == want_tag:
            return body, full
    return None, None


def _verify_timestamp(token, link, index):
    """Check that an RFC 3161 token attests to link and is signed by the certificate it carries.

    A timestamp token is the one anchor type that proves itself: it is signed by an authority over
    the link and carries its own certificates, so it is checked offline with nothing but the bundle.
    Whether the authority is worth trusting is the relying party's call, made by reading the signer
    this returns, so no root list is baked in here.
    """
    try:
        _, _, ci, _ = _der(token)
        oid_body, _ = _find(ci, 0x06)
        if _oid(oid_body) != OID_SIGNED_DATA:
            raise VError("anchor", f"anchor {index} proof is not CMS SignedData")
        explicit, _ = _find(ci, 0xA0)
        _, _, sd, _ = _der(explicit)

        encap = eci = None
        certs_der = None
        signer_infos = None
        for tag, body, full in _children(sd):
            if tag == 0x30 and encap is None:
                inner_oid, _ = _find(body, 0x06)
                if inner_oid is not None and _oid(inner_oid) == OID_TST_INFO:
                    encap = body
            elif tag == 0xA0 and certs_der is None:
                certs_der = full
            elif tag == 0x31:
                signer_infos = body
        if encap is None:
            raise VError("anchor", f"anchor {index} proof carries no TSTInfo")

        wrapper, _ = _find(encap, 0xA0)
        _, _, tst_der, _ = _der(wrapper)
        _, _, tst, _ = _der(tst_der)
    except VError:
        raise
    except Exception as exc:
        raise VError("anchor", f"anchor {index} proof is malformed: {exc}") from exc

    # The binding: this token is about this link and no other value.
    imprint = None
    for tag, body, _full in _children(tst):
        if tag == 0x30:
            algo, _ = _find(body, 0x30)
            digest, _ = _find(body, 0x04)
            if algo is not None and digest is not None:
                alg_oid, _ = _find(algo, 0x06)
                if alg_oid is not None and _oid(alg_oid) == OID_SHA256:
                    imprint = digest
                    break
    if imprint is None:
        raise VError("anchor", f"anchor {index} proof has no SHA-256 message imprint")
    if imprint != hashlib.sha256(bytes.fromhex(link)).digest():
        raise VError("anchor", f"anchor {index} proof attests to a different link")

    gen_time = None
    for tag, body, _full in _children(tst):
        if tag == 0x18:
            gen_time = body.decode("ascii").rstrip("Z")
            break

    if certs_der is None or signer_infos is None:
        raise VError("anchor", f"anchor {index} proof carries no certificate or signer")
    certs = pkcs7.load_der_pkcs7_certificates(token)
    signer_cert = None
    for cert in certs:
        try:
            eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            if x509.oid.ExtendedKeyUsageOID.TIME_STAMPING in eku:
                signer_cert = cert
                break
        except x509.ExtensionNotFound:
            continue
    if signer_cert is None:
        raise VError("anchor", f"anchor {index} proof has no timestamping certificate")

    _, _, si, _ = _der(signer_infos)
    signed_attrs = signature = digest_name = None
    pending_algo = None
    for tag, body, full in _children(si):
        if tag == 0x30 and signed_attrs is None:
            algo_oid, _ = _find(body, 0x06)
            if algo_oid is not None:
                pending_algo = DIGEST_OIDS.get(_oid(algo_oid), pending_algo)
        elif tag == 0xA0 and signed_attrs is None:
            signed_attrs = full
            digest_name = pending_algo
        elif tag == 0x04:
            signature = body
    if signed_attrs is None or signature is None:
        raise VError("anchor", f"anchor {index} proof signer is incomplete")
    if digest_name is None:
        raise VError("anchor", f"anchor {index} proof uses an unsupported digest")

    # The signed attributes must commit to the payload, or the signature covers nothing that
    # matters, and the signature is over them re-tagged as a SET rather than the implicit [0].
    _, _, attrs_body, _ = _der(signed_attrs)
    bound = False
    for tag, body, _full in _children(attrs_body):
        attr_oid, _ = _find(body, 0x06)
        if attr_oid is None or _oid(attr_oid) != OID_MESSAGE_DIGEST:
            continue
        values, _ = _find(body, 0x31)
        want, _ = _find(values, 0x04)
        if want != hashlib.new(digest_name, tst_der).digest():
            raise VError("anchor", f"anchor {index} proof commits to a different payload")
        bound = True
    if not bound:
        raise VError("anchor", f"anchor {index} proof does not commit to its payload")

    signed = b"\x31" + signed_attrs[1:]
    try:
        _verify_cert_signature(signer_cert, signature, signed, digest_name)
    except Exception as exc:
        raise VError("anchor", f"anchor {index} proof signature does not verify: {exc}") from exc

    when = gen_time or "unknown time"
    if len(when) >= 14:
        when = (f"{when[0:4]}-{when[4:6]}-{when[6:8]}T{when[8:10]}:"
                f"{when[10:12]}:{when[12:14]}Z")
    return when, signer_cert.subject.rfc4514_string()


def _verify_cert_signature(cert, signature, signed, digest_name):
    """Verify signature over signed using the certificate's public key and the signer's own digest.

    The digest comes from the signer info, never from the certificate. A certificate records how it
    was itself signed, which has nothing to do with how this token was signed, and using it would
    check the signature against the wrong hash.
    """
    key = cert.public_key()
    algo = {"sha256": hashes.SHA256(), "sha384": hashes.SHA384(),
            "sha512": hashes.SHA512()}[digest_name]
    if isinstance(key, ec.EllipticCurvePublicKey):
        key.verify(signature, signed, ec.ECDSA(algo))
    elif isinstance(key, ed25519.Ed25519PublicKey):
        key.verify(signature, signed)
    else:
        key.verify(signature, signed, padding.PKCS1v15(), algo)


# ---------- verification ----------

def verify(raw_bytes, evidence_dir=None):
    """Verify one bundle and return a report dict. Failure is a report, never an exception."""
    report = {"ok": False, "level": "not verified", "problems": [],
              "signature_ok": False, "chain_present": False, "chain_ok": False,
              "chain_mode": "", "head_matched": False, "anchors_matched": 0,
              "anchor_proofs_carried": 0, "anchor_proofs_verified": 0,
              "anchor_proofs_validated": False, "anchor_attestations": [],
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
        # alg sits outside the signed bytes, so an attacker rewrites it for free. It is read
        # only to reject a bundle that declares something this format does not fix, never to
        # choose which algorithm to verify with.
        if sig.get("alg") != "ed25519":
            raise VError("signature", f"signature alg {sig.get('alg')!r}, want ed25519")
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


def _links_switchtender(b):
    for i, c in enumerate(b["claims"]):
        p = c["payload"]
        _check_rfc3339(c["at"], i)
        arr = canon([str(c["chain"]["seq"]), c["at"], p.get("actor", ""),
                     p.get("method", ""), p.get("path", ""), c["chain"].get("prev", "")])
        if hashlib.sha256(arr).hexdigest() != c["chain"]["link"]:
            raise VError("chain", f"claim {i} link does not recompute (switchtender)")


def _unix_nanos(ts):
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)
    return int(dt.timestamp() * 1_000_000_000)


def _check_rfc3339(ts, i):
    """Reject a claim time that is not RFC 3339 UTC. The time is hashed verbatim, so this only has
    to establish that it is well formed, never to reformat it.

    Normalizing it here is what this function used to do, and it was wrong. datetime carries
    microseconds, so a nanosecond timestamp lost its last three digits and the link recomputed to a
    different value. The Go verifier, whose time type carries nanoseconds, verified the same bundle
    happily. Two conformant verifiers disagreed on valid input, and the failure surfaced as "link
    does not recompute", which reads as tampering. Hashing the stored bytes ends that, and removes
    the requirement that a verifier own a nanosecond-capable time type at all."""
    if not isinstance(ts, str) or not ts.endswith("Z"):
        raise VError("claim", f"claim {i} at must be RFC 3339 UTC ending in Z")
    body = ts[:-1]
    frac = ""
    if "." in body:
        body, frac = body.split(".", 1)
        if not frac or not frac.isdigit():
            raise VError("claim", f"claim {i} at has a malformed fractional second")
    try:
        datetime.strptime(body, "%Y-%m-%dT%H:%M:%S")
    except ValueError as exc:
        raise VError("claim", f"claim {i} at is not RFC 3339: {exc}") from exc


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
        if not a.get("proof"):
            continue
        report["anchor_proofs_carried"] += 1
        # A carried proof used to be counted and never opened, so a bundle holding a real signed
        # timestamp was reported at the same strength as one holding a URL. The format has always
        # said an rfc3161 proof is checkable offline; this is where that becomes true.
        if a["type"] != "rfc3161":
            continue
        try:
            token = base64.b64decode(a["proof"], validate=True)
        except Exception as exc:
            raise VError("anchor", f"anchor {i} proof is not base64: {exc}") from exc
        when, signer = _verify_timestamp(token, a["link"], i)
        report["anchor_proofs_verified"] += 1
        report["anchor_attestations"].append(f"{when} by {signer}")
    # True only when every proof the bundle carries was opened and held.
    report["anchor_proofs_validated"] = (
        report["anchor_proofs_carried"] > 0
        and report["anchor_proofs_verified"] == report["anchor_proofs_carried"])


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
    if report["anchor_proofs_verified"] > 0:
        # A proof checked here needed no network and no trust in the producer, which is a stronger
        # statement than a reference a relying party still has to go and confirm.
        level += ", anchored (proof verified)"
    elif report["anchors_matched"] > 0:
        level += ", anchored by reference"
    return level


# ---------- CLI ----------

def failing_check_error(check, r):
    """Return why report r does not fail at the stage the manifest names, or None if it does.

    Agreeing that a bundle is bad is not agreement. Two verifiers that reject the same file for
    different reasons disagree about the format, so the stage is checked as strictly here as it
    is in the Go conformance test.
    """
    if check in ("parse", "signature"):
        if r["signature_ok"]:
            return f"{check} case verified its signature"
    elif check == "chain":
        if not r["chain_present"] or r["chain_ok"]:
            return (f"chain case did not fail the chain: present {r['chain_present']} "
                    f"ok {r['chain_ok']}")
    elif check == "anchor":
        if not r["signature_ok"] or not r["chain_ok"]:
            return "anchor case failed earlier than the anchor step"
        if r["anchors_matched"] != 0 or not any("anchor" in p for p in r["problems"]):
            return f"anchor case did not fail on an anchor: matched {r['anchors_matched']}"
    else:
        return f"manifest names an unknown failing_check {check!r}"
    return None


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
        if status == "OK " and not v["must_verify"] and v.get("failing_check"):
            why = failing_check_error(v["failing_check"], r)
            if why:
                status, detail = "!! ", f"  {why}"
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
