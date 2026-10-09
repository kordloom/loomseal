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
import hmac
import json
import json.scanner
import re
import os
import sys
import threading
from datetime import datetime, timedelta, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

MAX_SAFE = 2 ** 53

# MAX_DEPTH is how deeply a document may nest, counting each array or object as one level and the
# outermost as the first. FORMAT.md fixes it at the bound every shipped verifier holds, so a deeper
# document is refused at parse by all of them rather than exhausting one verifier's stack where
# another reaches a verdict.
MAX_DEPTH = 3200

V1 = "loomseal-chain-v1"
SWITCHTENDER = "switchtender-audit-v1"
MERKLE = "loomseal-merkle-v1"

# DECLARATION is schema/claim-members.json, the declaration of every payload member of every claim
# type and what a verifier holds it against. The Go verifier embeds the same file, so the two cannot
# disagree about which members are bound, checked, redacted, or unchecked.
with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "schema",
                       "claim-members.json"), encoding="utf-8") as _fh:
    DECLARATION = json.load(_fh)

# KNOWN_TYPES are the registered claim types, the ones the declaration declares. The Go verifier's
# own test holds its registry to the same file, so the two report the same types as unknown. A list
# kept here by hand had fallen behind it and called whodar.knowledge-risk/1 unknown.
KNOWN_TYPES = set(DECLARATION["types"])

# KNOWN_SUBJECTS is the subject vocabulary FORMAT.md states. A type outside it is reported and never
# fails a bundle. The conformance vectors carry one bundle per known type, so a type missing from
# this set or the Go verifier's fails a vector rather than drifting apart unseen.
KNOWN_SUBJECTS = {"url", "fleet", "repo", "agent", "host", "run", "org"}

# EMPTY_EXPECTATION is the refusal for an expected audience or nonce supplied as an empty string,
# worded as the Go verify.ErrExpectation the command line and the browser module report.
EMPTY_EXPECTATION = "expected value is empty and compares against nothing"


class VError(Exception):
    """A verification failure carrying the name of the check that failed."""

    def __init__(self, check, msg):
        super().__init__(msg)
        self.check = check
        self.msg = msg


# ---------- RFC 8785 canonicalization ----------

def _hex4(text, i):
    """Read the four hex digits of a \\u escape starting at i, or reject the escape."""
    digits = text[i:i + 4]
    if len(digits) != 4 or any(ch not in "0123456789abcdefABCDEF" for ch in digits):
        raise VError("parse", f"invalid escape sequence \\u{digits}")
    return int(digits, 16)


def _scan_text(text):
    """Walk the document once before it is decoded: reject a \\u escape that is not four hex
    digits or that spells a lone surrogate, and reject nesting past MAX_DEPTH. Raw invalid UTF-8
    is already caught by the bytes.decode('utf-8') that runs before this. The walk is a loop,
    never a recursion, so a document built to exhaust a stack is refused before any decoder reads
    it."""
    i, n, in_str, depth = 0, len(text), False, 0
    while i < n:
        c = text[i]
        if not in_str:
            if c == '"':
                in_str = True
            elif c in "[{":
                depth += 1
                if depth > MAX_DEPTH:
                    raise VError("parse", f"nesting exceeds {MAX_DEPTH} levels")
            elif c in "]}":
                depth -= 1
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
            hi = _hex4(text, i + 2)
            if 0xD800 <= hi <= 0xDBFF:
                if text[i + 6:i + 8] != '\\u':
                    raise VError("parse", "high surrogate without low surrogate")
                lo = _hex4(text, i + 8)
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


# _RE_INT is a JSON integer literal in ASCII digits. Seventeen digits or more exceed 2^53, and the
# literal is refused before int() converts it, since converting a long enough literal raises.
_RE_INT = re.compile(r"-?(?:0|[1-9][0-9]{0,15})")


def _parse_int(literal):
    """Convert an integer literal, refusing one too long to be at most 2^53."""
    if not _RE_INT.fullmatch(literal):
        raise VError("parse",
                     f"integer literal {literal[:20]!r} is not a plain integer within 2^53")
    return int(literal)


def _parse_float(_):
    """Refuse a number literal with a fraction or an exponent."""
    raise VError("parse", "non-integer number literal")


def parse_strict(raw_bytes):
    """Parse bundle bytes with the strictness canonicalization needs: valid UTF-8, no lone
    surrogates, no duplicate keys, integer number literals only, nesting within MAX_DEPTH.

    The document is decoded by the standard library's pure Python scanner rather than its C one.
    On Python 3.12 and 3.13 the C scanner's nesting is capped by a C recursion limit fixed when
    the interpreter was built, which sys.setrecursionlimit does not raise, so whether a deep
    document parsed would depend on the interpreter rather than on the format. The Python scanner
    nests on frames that the recursion limit and the thread verify runs on are sized for."""
    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise VError("parse", "input is not valid UTF-8")
    _scan_text(text)
    decoder = json.JSONDecoder(object_pairs_hook=_no_dup_keys, parse_float=_parse_float,
                               parse_int=_parse_int)
    decoder.scan_once = json.scanner.py_make_scanner(decoder)
    try:
        return decoder.decode(text)
    except VError:
        raise
    except json.JSONDecodeError as e:
        raise VError("parse", f"invalid JSON: {e}")


def canon(value):
    """Return the RFC 8785 canonical bytes of a parsed value."""
    return _ser(value).encode("utf-8")


def _ser(v):
    """Serialize one value in RFC 8785 form. The containers recurse through list comprehensions
    rather than generators: a generator is driven from C by str.join, and each level of that
    re-entry costs C stack, which a document nested MAX_DEPTH levels deep would exhaust."""
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
        return "[" + ",".join([_ser(e) for e in v]) + "]"
    if isinstance(v, dict):
        items = sorted(v.items(), key=lambda kv: kv[0].encode("utf-16-be"))
        return "{" + ",".join([_ser_str(k) + ":" + _ser(val) for k, val in items]) + "}"
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
#
# A token is read as DER, by position, exactly as the Go rfc3161 package reads it: the reader
# below mirrors its der.go, and the certificate, key, and signature rules mirror its cert.go and
# rfc3161.go. No general ASN.1, X.509, or PKCS #7 parser decides anything here, because each of
# those accepts or refuses encodings by its own rules, and a verdict must not depend on which one a
# verifier happened to use. RSA signatures are checked here by RFC 8017 arithmetic for the same
# reason: OpenSSL refuses a modulus past 16384 bits, and the bound belongs to the format.


def _oid_content(dotted):
    """Encode a dotted OBJECT IDENTIFIER as its DER content octets."""
    parts = [int(p) for p in dotted.split(".")]
    out = bytearray()
    for v in [parts[0] * 40 + parts[1]] + parts[2:]:
        chunk = [v & 0x7F]
        v >>= 7
        while v:
            chunk.append(0x80 | (v & 0x7F))
            v >>= 7
        out += bytes(reversed(chunk))
    return bytes(out)


OID_SIGNED_DATA = _oid_content("1.2.840.113549.1.7.2")
OID_TST_INFO = _oid_content("1.2.840.113549.1.9.16.1.4")
OID_MESSAGE_DIGEST = _oid_content("1.2.840.113549.1.9.4")
OID_SHA256 = _oid_content("2.16.840.1.101.3.4.2.1")
OID_RSA_ENCRYPTION = _oid_content("1.2.840.113549.1.1.1")
OID_EC_PUBLIC_KEY = _oid_content("1.2.840.10045.2.1")
OID_ED25519 = _oid_content("1.3.101.112")
OID_EXT_KEY_USAGE = _oid_content("2.5.29.37")
OID_SUBJECT_KEY_ID = _oid_content("2.5.29.14")
OID_KP_TIME_STAMPING = _oid_content("1.3.6.1.5.5.7.3.8")

# A signer names the digest it used over the signed attributes. Assuming SHA-256 works until an
# authority signs with anything else, and then it silently compares two unrelated hashes.
DIGEST_OIDS = {
    _oid_content("2.16.840.1.101.3.4.2.1"): "sha256",
    _oid_content("2.16.840.1.101.3.4.2.2"): "sha384",
    _oid_content("2.16.840.1.101.3.4.2.3"): "sha512",
}

# SIGNATURE_SCHEMES maps a signature algorithm identifier to its check: the key type, the hash
# over the signed attributes (None for Ed25519, which signs them directly), and whether RSA padding
# is PSS. RSASSA-PSS is read as SHA-256 throughout and its parameters are not read, as in Go.
SIGNATURE_SCHEMES = {
    _oid_content("1.2.840.113549.1.1.11"): ("rsa", "sha256", False),
    _oid_content("1.2.840.113549.1.1.12"): ("rsa", "sha384", False),
    _oid_content("1.2.840.113549.1.1.13"): ("rsa", "sha512", False),
    _oid_content("1.2.840.113549.1.1.10"): ("rsa", "sha256", True),
    _oid_content("1.2.840.10045.4.3.2"): ("ecdsa", "sha256", False),
    _oid_content("1.2.840.10045.4.3.3"): ("ecdsa", "sha384", False),
    _oid_content("1.2.840.10045.4.3.4"): ("ecdsa", "sha512", False),
    _oid_content("1.3.101.112"): ("ed25519", None, False),
}

# EC_CURVES maps a named curve OBJECT IDENTIFIER to the curve and its field size in octets.
EC_CURVES = {
    _oid_content("1.3.132.0.33"): (ec.SECP224R1, 28),
    _oid_content("1.2.840.10045.3.1.7"): (ec.SECP256R1, 32),
    _oid_content("1.3.132.0.34"): (ec.SECP384R1, 48),
    _oid_content("1.3.132.0.35"): (ec.SECP521R1, 66),
}

# Identifier octets of the elements a token is read through. Each is the whole one-octet
# identifier, so comparing it checks the class, the constructed bit, and the number at once.
T_BOOLEAN, T_INTEGER, T_BIT_STRING, T_OCTET_STRING = 0x01, 0x02, 0x03, 0x04
T_NULL, T_OID = 0x05, 0x06
T_UTC_TIME, T_GENERALIZED_TIME, T_SEQUENCE, T_SET = 0x17, 0x18, 0x30, 0x31
T_EXPLICIT0, T_EXPLICIT1, T_EXPLICIT3 = 0xA0, 0xA1, 0xA3
T_IMPLICIT0, T_IMPLICIT1, T_IMPLICIT2 = 0x80, 0x81, 0x82


class _TokenError(Exception):
    """A token that does not hold up, carrying what failed."""


def _header(data, pos, end, what):
    """Read the identifier and length octets of the element at data[pos:end] and return its
    identifier octet and the offsets where its content starts and the element ends. The element
    must have a one-octet identifier, a definite length in its shortest form, and lie wholly before
    end. Mirrors the Go reader's next."""
    if end - pos < 2:
        raise _TokenError(f"{what}: missing or truncated")
    tag = data[pos]
    if tag & 0x1F == 0x1F:
        raise _TokenError(f"{what}: identifier uses the high tag number form")
    n, hdr = data[pos + 1], 2
    if n & 0x80:
        count = n & 0x7F
        if count == 0:
            raise _TokenError(f"{what}: indefinite length")
        if count > 4:
            raise _TokenError(f"{what}: length of {count} octets")
        if end - pos < 2 + count:
            raise _TokenError(f"{what}: truncated length")
        if data[pos + 2] == 0:
            raise _TokenError(f"{what}: length with a leading zero octet")
        n = int.from_bytes(data[pos + 2:pos + 2 + count], "big")
        if n < 0x80:
            raise _TokenError(f"{what}: long form length below 128")
        hdr += count
    if n > end - pos - hdr:
        raise _TokenError(f"{what}: length runs past its container")
    return tag, pos + hdr, pos + hdr + n


class _DER:
    """One DER element read from a buffer: its identifier octet, and where its whole encoding and
    its content lie. The content and the whole encoding are copied out only when asked for, so
    reading an element costs nothing in proportion to its size."""

    __slots__ = ("tag", "_data", "_start", "_content_start", "_end")

    def __init__(self, tag, data, start, content_start, end):
        self.tag = tag
        self._data = data
        self._start = start
        self._content_start = content_start
        self._end = end

    @property
    def content(self):
        """The element's content octets."""
        return self._data[self._content_start:self._end]

    @property
    def full(self):
        """The element's whole encoding, identifier and length octets included."""
        return self._data[self._start:self._end]


class _Reader:
    """Read consecutive DER elements from the content of a constructed element, in order. Every
    element it returns has a one-octet identifier, a definite length in its shortest form, and lies
    wholly inside what is being read. It keeps an offset into the octets rather than copying what
    is left after each element, so reading n elements takes time in proportion to n. Mirrors the Go
    reader."""

    def __init__(self, data):
        self.data = bytes(data)
        self.pos = 0

    def empty(self):
        """Report whether everything has been read."""
        return self.pos == len(self.data)

    def left(self):
        """Count the octets not read yet."""
        return len(self.data) - self.pos

    def next(self, what):
        """Read the next element, whatever its identifier."""
        tag, content_start, end = _header(self.data, self.pos, len(self.data), what)
        e = _DER(tag, self.data, self.pos, content_start, end)
        self.pos = end
        return e

    def read(self, tag, what):
        """Read the next element and require its identifier octet to be tag."""
        e = self.next(what)
        if e.tag != tag:
            raise _TokenError(f"{what}: identifier 0x{e.tag:02x}, want 0x{tag:02x}")
        return e

    def optional(self, tag, what):
        """Read the next element when there is one and its identifier octet is tag."""
        if self.empty() or self.data[self.pos] != tag:
            return None
        return self.read(tag, what)


def _only(content, tag, what):
    """Read the one element content holds: an explicit tag, an OCTET STRING, or a BIT STRING that
    wraps an encoding holds exactly one element of the identifier it requires and nothing after."""
    r = _Reader(content)
    e = r.read(tag, what)
    if not r.empty():
        raise _TokenError(f"{what}: followed by {r.left()} more octets")
    return e


def _well_formed(data, what):
    """Check that data is a run of whole DER elements and that every constructed element within
    it, however deep, holds only whole DER elements in turn. Applied to the whole token and to the
    TSTInfo, so a token is DER throughout. It walks offsets into data with an explicit stack, so it
    copies nothing and nesting depth costs no call stack. Mirrors the Go wellFormed."""
    stack = [(0, len(data))]
    while stack:
        pos, end = stack.pop()
        while pos < end:
            tag, content_start, pos = _header(data, pos, end, what)
            if tag & 0x20:
                stack.append((content_start, pos))


def _der_integer(e, what):
    """Check an INTEGER's content: at least one octet, in the shortest two's complement form."""
    c = e.content
    if not c:
        raise _TokenError(f"{what}: empty INTEGER")
    if len(c) > 1 and ((c[0] == 0x00 and not c[1] & 0x80) or (c[0] == 0xFF and c[1] & 0x80)):
        raise _TokenError(f"{what}: INTEGER not in its shortest form")


def _der_version(e, what):
    """Check a structure's version INTEGER, which must also fit a signed 64-bit integer."""
    _der_integer(e, what)
    if len(e.content) > 8:
        raise _TokenError(f"{what}: INTEGER exceeds 64 bits")


# MAX_SUBIDENTIFIER is the largest subidentifier an OBJECT IDENTIFIER a verifier reads may hold,
# 2^31-1, the bound Go's encoding/asn1 holds one to. Without a bound, one subidentifier can be as
# long as the token, and writing it out in decimal either takes time that grows with the square of
# its length or, here, fails outright: Python refuses to convert an integer of more than 4300
# digits to a string.
MAX_SUBIDENTIFIER = 2**31 - 1


def _der_oid(e, what):
    """Check an OBJECT IDENTIFIER's content: at least one octet, no subidentifier that starts with
    the padding octet 0x80 or exceeds 2^31-1, and a last octet that ends its subidentifier.
    Mirrors the Go derOID."""
    c = e.content
    if not c:
        raise _TokenError(f"{what}: empty OBJECT IDENTIFIER")
    v = 0
    start = True
    for b in c:
        if start and b == 0x80:
            raise _TokenError(f"{what}: OBJECT IDENTIFIER subidentifier not in its shortest form")
        v = (v << 7) | (b & 0x7F)
        if v > MAX_SUBIDENTIFIER:
            raise _TokenError(f"{what}: OBJECT IDENTIFIER subidentifier exceeds 2^31-1")
        start = not b & 0x80
        if start:
            v = 0
    if not start:
        raise _TokenError(f"{what}: OBJECT IDENTIFIER ends inside a subidentifier")


def _oid_string(content):
    """Write the content of an OBJECT IDENTIFIER that _der_oid accepted in dotted form. Every
    subidentifier of such a content fits 31 bits."""
    arcs, v, first = [], 0, True
    for b in content:
        v = (v << 7) | (b & 0x7F)
        if b & 0x80:
            continue
        if first:
            arcs += (["0", str(v)] if v < 40 else ["1", str(v - 40)] if v < 80
                     else ["2", str(v - 80)])
            first = False
        else:
            arcs.append(str(v))
        v = 0
    return ".".join(arcs)


def _read_algorithm(r, what):
    """Read an AlgorithmIdentifier SEQUENCE and return its OBJECT IDENTIFIER's content. Parameters
    that follow the identifier are not read."""
    alg = r.read(T_SEQUENCE, what)
    oid = _Reader(alg.content).read(T_OID, what)
    _der_oid(oid, what)
    return oid.content


def _read_token(raw):
    """Read a token by position: a ContentInfo whose [0] holds a SignedData, whose encapsulated
    content holds the DER TSTInfo, and whose one SignerInfo signs it. Nothing may follow the
    ContentInfo, and the token is DER throughout. In each SEQUENCE nothing is interpreted after the
    last member used. Mirrors the Go readToken and readSignedData."""
    _well_formed(raw, "token")
    top = _Reader(raw)
    ci = top.read(T_SEQUENCE, "ContentInfo")
    if not top.empty():
        raise _TokenError(f"{top.left()} octets follow the ContentInfo")
    r = _Reader(ci.content)
    content_type = r.read(T_OID, "contentType")
    _der_oid(content_type, "contentType")
    if content_type.content != OID_SIGNED_DATA:
        raise _TokenError(f"outer content is {_oid_string(content_type.content)}, want SignedData")
    sd = _only(r.read(T_EXPLICIT0, "ContentInfo content").content, T_SEQUENCE, "SignedData")

    r = _Reader(sd.content)
    _der_version(r.read(T_INTEGER, "SignedData version"), "SignedData version")
    r.read(T_SET, "digestAlgorithms")
    er = _Reader(r.read(T_SEQUENCE, "encapContentInfo").content)
    e_type = er.read(T_OID, "eContentType")
    _der_oid(e_type, "eContentType")
    if e_type.content != OID_TST_INFO:
        raise _TokenError(f"payload is {_oid_string(e_type.content)}, want TSTInfo")
    e_content = _only(er.read(T_EXPLICIT0, "eContent").content, T_OCTET_STRING,
                      "eContent").content
    certs = r.optional(T_EXPLICIT0, "certificates")
    r.optional(T_EXPLICIT1, "crls")
    signer = _read_signer_infos(r.read(T_SET, "signerInfos"))
    tst = _only(e_content, T_SEQUENCE, "TSTInfo")
    _well_formed(tst.content, "TSTInfo")
    info = _read_tst_info(tst)
    return {"e_content": e_content, "info": info, "certs": certs, "signer": signer}


def _read_signer_infos(infos):
    """Read every element of the signerInfos SET as a SignerInfo and return the one there must be.
    Zero signers is malformed and more than one is ambiguous."""
    r = _Reader(infos.content)
    found = []
    while not r.empty():
        found.append(_read_signer_info(r.read(T_SEQUENCE, "SignerInfo")))
    if len(found) != 1:
        raise _TokenError(f"token carries {len(found)} signers, want exactly one")
    return found[0]


def _read_signer_info(e):
    """Read one SignerInfo's members by position."""
    r = _Reader(e.content)
    _der_version(r.read(T_INTEGER, "SignerInfo version"), "SignerInfo version")
    sid = r.next("sid")
    if sid.tag == T_SEQUENCE:
        ir = _Reader(sid.content)
        ir.read(T_SEQUENCE, "sid issuer")
        _der_integer(ir.read(T_INTEGER, "sid serialNumber"), "sid serialNumber")
    elif sid.tag != T_IMPLICIT0:
        raise _TokenError("the token's signer identifier is neither an issuer and serial number "
                          "nor a subject key identifier")
    si = {"sid": sid}
    si["digest"] = _read_algorithm(r, "digestAlgorithm")
    si["signed_attrs"] = r.read(T_EXPLICIT0, "signedAttrs")
    si["signature_algorithm"] = _read_algorithm(r, "signatureAlgorithm")
    si["signature"] = r.read(T_OCTET_STRING, "signature").content
    return si


def _read_tst_info(e):
    """Read a TSTInfo by position, as RFC 3161 lays it out: version, policy, messageImprint,
    serialNumber, and genTime. A member in the wrong slot fails, and nothing after genTime is
    read."""
    r = _Reader(e.content)
    _der_version(r.read(T_INTEGER, "TSTInfo version"), "TSTInfo version")
    policy = r.read(T_OID, "TSTInfo policy")
    _der_oid(policy, "TSTInfo policy")
    ir = _Reader(r.read(T_SEQUENCE, "messageImprint").content)
    imprint_alg = _read_algorithm(ir, "messageImprint hashAlgorithm")
    imprint = ir.read(T_OCTET_STRING, "messageImprint hashedMessage").content
    _der_integer(r.read(T_INTEGER, "TSTInfo serialNumber"), "TSTInfo serialNumber")
    return {"imprint_alg": imprint_alg, "imprint": imprint, "gen_time": r.next("genTime")}


def _read_certificates(content):
    """Read every element of the certificates field as a certificate. Mirrors the Go
    readCertificates."""
    r = _Reader(content)
    certs = []
    while not r.empty():
        certs.append(_read_certificate(r.read(T_SEQUENCE, "certificate")))
    return certs


def _read_certificate(e):
    """Read a certificate's tbsCertificate by position through its extensions. The certificate's
    own signature is not read. Mirrors the Go readCertificate."""
    tbs = _Reader(e.content).read(T_SEQUENCE, "tbsCertificate")
    r = _Reader(tbs.content)
    c = {"version": None, "ski": None, "eku": []}
    wrapped = r.optional(T_EXPLICIT0, "certificate version")
    if wrapped is not None:
        v = _only(wrapped.content, T_INTEGER, "certificate version")
        _der_version(v, "certificate version")
        c["version"] = v.content
    serial = r.read(T_INTEGER, "certificate serialNumber")
    _der_integer(serial, "certificate serialNumber")
    c["serial"] = serial.content
    r.read(T_SEQUENCE, "certificate signature")
    c["issuer"] = r.read(T_SEQUENCE, "certificate issuer").full
    c["validity"] = r.read(T_SEQUENCE, "certificate validity")
    c["subject"] = r.read(T_SEQUENCE, "certificate subject").full
    c["spki"] = r.read(T_SEQUENCE, "certificate subjectPublicKeyInfo")
    r.optional(T_IMPLICIT1, "certificate issuerUniqueID")
    r.optional(T_IMPLICIT2, "certificate subjectUniqueID")
    wrapped = r.optional(T_EXPLICIT3, "certificate extensions")
    if wrapped is not None:
        _read_extensions(c, wrapped)
    return c


def _read_extensions(c, wrapped):
    """Read the [3] extensions: exactly one SEQUENCE of Extension, each an extnID, an optional
    critical BOOLEAN that DER only ever writes as TRUE, 0xFF, and an extnValue OCTET STRING, with
    no extnID twice. Mirrors the Go readExtensions."""
    r = _Reader(_only(wrapped.content, T_SEQUENCE, "certificate extensions").content)
    seen = set()
    while not r.empty():
        er = _Reader(r.read(T_SEQUENCE, "extension").content)
        ext_id = er.read(T_OID, "extnID")
        _der_oid(ext_id, "extnID")
        critical = er.optional(T_BOOLEAN, "extension critical")
        if critical is not None and critical.content != b"\xff":
            raise _TokenError(f"extension {_oid_string(ext_id.content)} critical flag is not the "
                              "DER TRUE octet")
        value = er.read(T_OCTET_STRING, "extnValue")
        if ext_id.content in seen:
            raise _TokenError(f"certificate carries extension {_oid_string(ext_id.content)} twice")
        seen.add(ext_id.content)
        if ext_id.content == OID_SUBJECT_KEY_ID:
            c["ski"] = _only(value.content, T_OCTET_STRING, "subject key identifier").content
        elif ext_id.content == OID_EXT_KEY_USAGE:
            kr = _Reader(_only(value.content, T_SEQUENCE, "extended key usage").content)
            c["eku"] = []
            while not kr.empty():
                p = kr.read(T_OID, "extended key usage purpose")
                _der_oid(p, "extended key usage purpose")
                c["eku"].append(p.content)


def _signer_certificate(certs, sid):
    """Return the first carried certificate the signer identifier names, by subject key
    identifier or by issuer and serial number, which must be a version 3 certificate marked for
    timestamping. A named certificate the token does not carry is a refusal, never an invitation to
    pick another. Mirrors the Go signerCertificate."""
    match = None
    if sid.tag == T_IMPLICIT0:
        match = next((c for c in certs if c["ski"] is not None and c["ski"] == sid.content), None)
    else:
        r = _Reader(sid.content)
        issuer = r.read(T_SEQUENCE, "sid issuer").full
        serial = r.read(T_INTEGER, "sid serialNumber").content
        match = next((c for c in certs if c["serial"] == serial and c["issuer"] == issuer), None)
    if match is None:
        raise _TokenError("the token names a signer certificate it does not carry")
    if match["version"] != b"\x02":
        raise _TokenError("the certificate the token names is not version 3")
    if OID_KP_TIME_STAMPING not in match["eku"]:
        raise _TokenError("the certificate the token names is not marked for timestamping")
    return match


# Patterns of the two certificate time forms DER and RFC 5280 allow: whole seconds, then Z.
_RE_UTC_TIME = re.compile(rb"([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z")
_RE_CERT_GENERALIZED = re.compile(rb"([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})"
                                  rb"([0-9]{2})Z")


def _parse_cert_time(e):
    """Read a certificate validity time to microseconds since the epoch: a UTCTime YYMMDDhhmmssZ,
    whose two-digit year is 19YY from 50 to 99 and 20YY below 50, or a GeneralizedTime
    YYYYMMDDhhmmssZ, with the field ranges a bundle time has. Mirrors the Go parseCertTime."""
    if e.tag == T_UTC_TIME:
        m = _RE_UTC_TIME.fullmatch(e.content)
        year = None if m is None else ("19" if m[1][0:1] >= b"5" else "20") + m[1].decode()
    elif e.tag == T_GENERALIZED_TIME:
        m = _RE_CERT_GENERALIZED.fullmatch(e.content)
        year = None if m is None else m[1].decode()
    else:
        raise _TokenError("certificate validity time is neither a UTCTime nor a GeneralizedTime")
    if m is None:
        raise _TokenError(f"certificate validity time {e.content!r} is not in its DER form")
    mo, d, h, mi, s = (g.decode() for g in m.groups()[1:])
    try:
        return _parse_time(f"{year}-{mo}-{d}T{h}:{mi}:{s}Z")
    except ValueError as exc:
        raise _TokenError(f"certificate validity time {e.content!r}: {exc}") from exc


def _validity_window(c):
    """Read the signer certificate's notBefore and notAfter. Anything after notAfter is not
    read."""
    r = _Reader(c["validity"].content)
    not_before = _parse_cert_time(r.next("notBefore"))
    not_after = _parse_cert_time(r.next("notAfter"))
    return not_before, not_after


# MAX_RSA_BITS is the longest RSA modulus a verifier reads. Go's crypto/rsa sets no upper bound,
# but OpenSSL refuses to verify with a modulus past 16384 bits, so every verifier holds keys to
# this bound instead.
MAX_RSA_BITS = 16384


class _RSAKey:
    """An RSA public key as its two numbers, checked here rather than by a library, so that no
    library's own bounds on a key decide a verdict."""

    __slots__ = ("n", "e")

    def __init__(self, n, e):
        self.n = n
        self.e = e


def _parse_public_key(spki):
    """Read the signer's subjectPublicKeyInfo into a key: an Ed25519 key of 32 octets with no
    parameters, an ECDSA key on P-224, P-256, P-384, or P-521 as an uncompressed point, or an RSA
    key with NULL parameters as exactly one SEQUENCE holding only a modulus and an exponent, with a
    positive odd modulus of 1024 to 16384 bits and an odd exponent from 3 to 2^31-1. Any other key
    is refused. Mirrors the Go parsePublicKey."""
    r = _Reader(spki.content)
    alg = r.read(T_SEQUENCE, "public key algorithm")
    bits = r.read(T_BIT_STRING, "subjectPublicKey").content
    if not bits or bits[0] != 0:
        raise _TokenError("subjectPublicKey has unused bits")
    key = bits[1:]
    ar = _Reader(alg.content)
    alg_id = ar.read(T_OID, "public key algorithm")
    _der_oid(alg_id, "public key algorithm")
    if alg_id.content == OID_ED25519:
        if not ar.empty():
            raise _TokenError("Ed25519 key carries parameters")
        if len(key) != 32:
            raise _TokenError(f"Ed25519 key is {len(key)} octets")
        return Ed25519PublicKey.from_public_bytes(key)
    if alg_id.content == OID_EC_PUBLIC_KEY:
        named = ar.read(T_OID, "elliptic curve")
        _der_oid(named, "elliptic curve")
        if named.content not in EC_CURVES:
            raise _TokenError(f"unsupported elliptic curve {_oid_string(named.content)}")
        curve, size = EC_CURVES[named.content]
        if len(key) != 1 + 2 * size or key[0] != 0x04:
            raise _TokenError("elliptic curve key is not an uncompressed point")
        try:
            return ec.EllipticCurvePublicKey.from_encoded_point(curve(), key)
        except ValueError as exc:
            raise _TokenError(f"elliptic curve key: {exc}") from exc
    if alg_id.content == OID_RSA_ENCRYPTION:
        if ar.read(T_NULL, "RSA key parameters").content:
            raise _TokenError("RSA key parameters are not NULL")
        kr = _Reader(_only(key, T_SEQUENCE, "RSA public key").content)
        n = kr.read(T_INTEGER, "RSA modulus")
        _der_integer(n, "RSA modulus")
        e = kr.read(T_INTEGER, "RSA public exponent")
        _der_integer(e, "RSA public exponent")
        if not kr.empty():
            raise _TokenError("RSA public key holds more than a modulus and an exponent")
        modulus = int.from_bytes(n.content, "big", signed=True)
        exponent = int.from_bytes(e.content, "big", signed=True)
        if (modulus <= 0 or modulus % 2 == 0 or modulus.bit_length() < 1024
                or modulus.bit_length() > MAX_RSA_BITS):
            raise _TokenError("RSA modulus is not a positive odd number of 1024 to 16384 bits")
        if exponent % 2 == 0 or exponent < 3 or exponent > 2**31 - 1:
            raise _TokenError("RSA public exponent is not odd and from 3 to 2^31-1")
        return _RSAKey(modulus, exponent)
    raise _TokenError(f"unsupported public key algorithm {_oid_string(alg_id.content)}")


def _commits_to(attrs, digest):
    """Read every signed attribute, each a SEQUENCE of a type and a SET of values, and report
    whether a messageDigest attribute is present. Every messageDigest attribute must hold exactly
    one OCTET STRING equal to digest. Mirrors the Go commitsTo."""
    r = _Reader(attrs.content)
    bound = False
    while not r.empty():
        ar = _Reader(r.read(T_SEQUENCE, "signed attribute").content)
        typ = ar.read(T_OID, "signed attribute type")
        _der_oid(typ, "signed attribute type")
        values = ar.read(T_SET, "signed attribute values")
        if typ.content != OID_MESSAGE_DIGEST:
            continue
        value = _only(values.content, T_OCTET_STRING, "message digest attribute")
        if value.content != digest:
            raise _TokenError("the signed attributes commit to a different payload")
        bound = True
    return bound


def _ecdsa_signature_ok(signature, curve_order):
    """Check an ECDSA signature's own encoding as Go's ecdsa.VerifyASN1 reads it: exactly one
    SEQUENCE of two non-negative INTEGERs in their shortest form and nothing else, each from 1 to
    the curve order less one."""
    try:
        sr = _Reader(_only(signature, T_SEQUENCE, "ECDSA signature").content)
        values = []
        for _ in range(2):
            v = sr.read(T_INTEGER, "ECDSA signature value")
            _der_integer(v, "ECDSA signature value")
            if v.content[0] & 0x80:
                return False
            values.append(int.from_bytes(v.content, "big"))
        if not sr.empty():
            return False
    except _TokenError:
        return False
    return all(0 < v < curve_order for v in values)


# EC_ORDERS holds each supported curve's group order, keyed by the curve's name.
EC_ORDERS = {
    "secp224r1": 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D,
    "secp256r1": 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551,
    "secp384r1": int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                     "C7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", 16),
    "secp521r1": int("1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"
                     "A51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", 16),
}


# _DIGEST_INFO maps a hash name to the DER DigestInfo prefix PKCS #1 v1.5 writes before the
# digest, the one encoding Go's crypto/rsa compares a recovered signature against.
_DIGEST_INFO = {
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
    "sha384": bytes.fromhex("3041300d060960864801650304020205000430"),
    "sha512": bytes.fromhex("3051300d060960864801650304020305000440"),
}


def _rsa_verify(key, hname, pss, signed, signature):
    """Check an RSA signature over signed by RFC 8017, as Go's crypto/rsa checks it, with the
    arithmetic done here so that no library's own limit on the modulus applies. The signature is
    exactly as long as the modulus and below it. The recovered encoding is the PKCS #1 v1.5 one,
    compared octet for octet, or a PSS encoding with MGF1 over the same hash and a salt as long as
    the hash."""
    k = (key.n.bit_length() + 7) // 8
    if len(signature) != k:
        raise ValueError("RSA signature length differs from the modulus length")
    s = int.from_bytes(signature, "big")
    if s >= key.n:
        raise ValueError("RSA signature is not below the modulus")
    em = pow(s, key.e, key.n).to_bytes(k, "big")
    digest = hashlib.new(hname, signed).digest()
    if pss:
        _pss_verify(em, key.n.bit_length() - 1, digest, hname)
        return
    info = _DIGEST_INFO[hname] + digest
    if k < len(info) + 11:
        raise ValueError("RSA modulus is too short for the digest")
    if em != b"\x00\x01" + b"\xff" * (k - len(info) - 3) + b"\x00" + info:
        raise ValueError("RSA PKCS #1 v1.5 verification failure")


def _mgf1(seed, length, hname):
    """Expand seed to length octets with MGF1 over the named hash, as RFC 8017 defines it."""
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.new(hname, seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def _pss_verify(em, em_bits, digest, hname):
    """Check a recovered PSS encoding em of em_bits bits against digest, with a salt as long as
    the hash, step by step as RFC 8017 EMSA-PSS-VERIFY and Go's crypto/rsa do. Octets em carries in
    front of the encoding's own length must be zero."""
    h_len = len(digest)
    em_len = (em_bits + 7) // 8
    while len(em) > em_len:
        if em[0] != 0:
            raise ValueError("RSA PSS verification failure")
        em = em[1:]
    if em_len < 2 * h_len + 2 or em[-1] != 0xBC:
        raise ValueError("RSA PSS verification failure")
    masked, h = em[:em_len - h_len - 1], em[em_len - h_len - 1:em_len - 1]
    top = 0xFF >> (8 * em_len - em_bits)
    if masked[0] & ~top & 0xFF:
        raise ValueError("RSA PSS verification failure")
    db = bytearray(a ^ b for a, b in zip(masked, _mgf1(h, len(masked), hname)))
    db[0] &= top
    ps_len = em_len - 2 * h_len - 2
    if any(db[:ps_len]) or db[ps_len] != 0x01:
        raise ValueError("RSA PSS verification failure")
    salt = bytes(db[len(db) - h_len:])
    if hashlib.new(hname, bytes(8) + digest + salt).digest() != h:
        raise ValueError("RSA PSS verification failure")


def _check_token_signature(scheme, key, signed, signature):
    """Check signature over signed with key under scheme, a (key type, hash, pss) triple. The key
    must be the type the scheme names. Mirrors the Go checkSignature."""
    kind, hname, pss = scheme
    if isinstance(key, _RSAKey):
        if kind != "rsa":
            raise ValueError("the signature algorithm does not match the RSA signer key")
        _rsa_verify(key, hname, pss, signed, signature)
    elif isinstance(key, ec.EllipticCurvePublicKey):
        if kind != "ecdsa":
            raise ValueError("the signature algorithm does not match the ECDSA signer key")
        if not _ecdsa_signature_ok(signature, EC_ORDERS[key.curve.name]):
            raise ValueError("ECDSA verification failure")
        key.verify(signature, signed, ec.ECDSA(_HASHES[hname]()))
    elif isinstance(key, ed25519.Ed25519PublicKey):
        if kind != "ed25519":
            raise ValueError("the signature algorithm does not match the Ed25519 signer key")
        key.verify(signature, signed)
    else:
        raise ValueError("unsupported signer key")


# _HASHES maps a digest name to the hash a signature check applies.
_HASHES = {"sha256": hashes.SHA256, "sha384": hashes.SHA384, "sha512": hashes.SHA512}


# RDN_SHORT_NAMES maps the nine attribute types RFC 4514 names, as DER content octets, to the
# short name a signer's subject writes them with. Every other type is written in dotted form.
RDN_SHORT_NAMES = {
    _oid_content("2.5.4.3"): "CN",
    _oid_content("2.5.4.7"): "L",
    _oid_content("2.5.4.8"): "ST",
    _oid_content("2.5.4.10"): "O",
    _oid_content("2.5.4.11"): "OU",
    _oid_content("2.5.4.6"): "C",
    _oid_content("2.5.4.9"): "STREET",
    _oid_content("0.9.2342.19200300.100.1.25"): "DC",
    _oid_content("0.9.2342.19200300.100.1.1"): "UID",
}

# Identifier octets of the string types a subject attribute's value is written out from.
T_UTF8_STRING, T_PRINTABLE_STRING, T_IA5_STRING = 0x0C, 0x13, 0x16


def _subject_name(c):
    """Name the signer for a report from the subject Name alone, never from a parse of the whole
    certificate, by the one rule FORMAT.md states: the RFC 4514 string of a subject that is a
    sequence of relative distinguished names, and otherwise # and the hexadecimal of the subject's
    whole encoding. It only names the signer and never decides a verdict, so it refuses nothing.
    Mirrors the Go subjectName."""
    name = _rfc4514_name(c["subject"])
    return name if name is not None else "#" + c["subject"].hex()


def _rfc4514_name(subject):
    """Write a Name in the RFC 4514 form: its relative distinguished names from the last to the
    first, separated by commas, and the attributes of each in the order they are encoded,
    separated by plus signs. Return None unless the Name is one SEQUENCE of one or more SETs, each
    holding one or more attribute SEQUENCEs of an OBJECT IDENTIFIER that _der_oid accepts and
    exactly one value. Mirrors the Go rfc4514Name."""
    try:
        r = _Reader(_only(subject, T_SEQUENCE, "subject").content)
        rdns = []
        while not r.empty():
            sr = _Reader(r.read(T_SET, "relative distinguished name").content)
            attrs = []
            while not sr.empty():
                ar = _Reader(sr.read(T_SEQUENCE, "attribute").content)
                typ = ar.read(T_OID, "attribute type")
                _der_oid(typ, "attribute type")
                value = ar.next("attribute value")
                if not ar.empty():
                    return None
                attrs.append(_attribute_string(typ.content, value))
            if not attrs:
                return None
            rdns.append("+".join(attrs))
    except _TokenError:
        return None
    if not rdns:
        return None
    return ",".join(reversed(rdns))


def _attribute_string(typ, value):
    """Write one attribute as its type, an equals sign, and its value. A type RFC 4514 names is
    written by that name, and its value as escaped text when the value is a string _string_value
    reads. Any other value, and every value of a type written in dotted form, is # and the
    hexadecimal of the value's whole encoding. Mirrors the Go attributeString."""
    short = RDN_SHORT_NAMES.get(typ)
    if short is None:
        return f"{_oid_string(typ)}=#{value.full.hex()}"
    text = _string_value(value)
    if text is not None:
        return f"{short}={_escape_rdn_value(text)}"
    return f"{short}=#{value.full.hex()}"


def _string_value(v):
    """Return the text of a primitive UTF8String holding valid UTF-8, or of a primitive
    PrintableString or IA5String holding only ASCII, and None for any other value. Mirrors the Go
    stringValue."""
    if v.tag == T_UTF8_STRING:
        try:
            return v.content.decode("utf-8")
        except UnicodeDecodeError:
            return None
    if v.tag in (T_PRINTABLE_STRING, T_IA5_STRING):
        return v.content.decode("ascii") if v.content.isascii() else None
    return None


def _escape_rdn_value(text):
    """Escape an attribute's text as RFC 4514 requires: a backslash before each of the characters
    " + , ; < > and backslash, before a # or a space that starts the text, and before a space that
    ends it. Every character below U+0020 or from U+007F to U+009F is written as a backslash and
    two lower case hexadecimal digits for each octet of its UTF-8 encoding. Mirrors the Go
    escapeRDNValue."""
    out = []
    last = len(text) - 1
    for i, ch in enumerate(text):
        if ch in '"+,;<>\\' or (ch == "#" and i == 0) or (ch == " " and i in (0, last)):
            out.append("\\" + ch)
        elif ch < "\x20" or "\x7f" <= ch <= "\x9f":
            out.append("".join(f"\\{o:02x}" for o in ch.encode("utf-8")))
        else:
            out.append(ch)
    return "".join(out)


def _verify_timestamp(token, link, index):
    """Check that an RFC 3161 token attests to link and is signed by the certificate it carries.

    A timestamp token is the one anchor type that proves itself: it is signed by an authority over
    the link and carries its own certificates, so it is checked offline with nothing but the bundle.
    Whether the authority is worth trusting is the relying party's call, made by reading the signer
    this returns, so no root list is baked in here. The steps and their order mirror the Go
    rfc3161.Verify.
    """
    try:
        tok = _read_token(token)
        info = tok["info"]
        # The binding: this token is about this link and no other value.
        if info["imprint_alg"] != OID_SHA256:
            raise _TokenError(f"imprint uses {_oid_string(info['imprint_alg'])}, want SHA-256")
        if not isinstance(link, str) or not re.fullmatch(r"(?:[0-9a-fA-F]{2})*", link):
            raise _TokenError("cannot be checked against a link that is not hex")
        if info["imprint"] != hashlib.sha256(bytes.fromhex(link)).digest():
            raise _TokenError("attests to a different link")
        if tok["certs"] is None:
            raise _TokenError("carries no certificate to check its signature against")
        signer = tok["signer"]
        cert = _signer_certificate(_read_certificates(tok["certs"].content), signer["sid"])
        key = _parse_public_key(cert["spki"])

        digest_name = DIGEST_OIDS.get(signer["digest"])
        if digest_name is None:
            raise _TokenError(f"unsupported digest {_oid_string(signer['digest'])}")
        # The signed attributes must commit to the payload, or the signature covers nothing that
        # matters, and the signature is over them re-tagged as a SET rather than the implicit [0].
        signed_attrs = signer["signed_attrs"]
        signed = bytes([T_SET]) + signed_attrs.full[1:]
        if not _commits_to(signed_attrs, hashlib.new(digest_name, tok["e_content"]).digest()):
            raise _TokenError("signed attributes do not commit to the payload")
        scheme = SIGNATURE_SCHEMES.get(signer["signature_algorithm"])
        if scheme is None and signer["signature_algorithm"] == OID_RSA_ENCRYPTION:
            scheme = ("rsa", digest_name, False)
        if scheme is None and signer["signature_algorithm"] == OID_EC_PUBLIC_KEY:
            scheme = ("ecdsa", digest_name, False)
        if scheme is None:
            raise _TokenError("unsupported signature algorithm "
                              f"{_oid_string(signer['signature_algorithm'])}")
        try:
            _check_token_signature(scheme, key, signed, signer["signature"])
        except (InvalidSignature, ValueError) as exc:
            raise _TokenError(f"signature does not verify: {exc}") from exc

        # An authority's certificate has to be valid when it signs, so a signing time outside the
        # signer certificate's own window is not evidence, whatever the signature says. This needs
        # no root store: it is a self-consistency check between two values the token already
        # carries. Both sides are whole microseconds since the epoch, as Go compares them.
        not_before, not_after = _validity_window(cert)
        gen_time = info["gen_time"]
        if gen_time.tag != T_GENERALIZED_TIME:
            raise _TokenError("genTime is not a GeneralizedTime")
        try:
            signed_at = _parse_gen_time(gen_time.content)
        except ValueError as exc:
            raise _TokenError(f"genTime: {exc}") from exc
        if signed_at < not_before or signed_at > not_after:
            raise _TokenError("signing time is outside the certificate validity window")
    except _TokenError as exc:
        raise VError("anchor", f"anchor {index} proof {exc}") from exc
    return signed_at, _subject_name(cert)


# ---------- verification ----------

# _MINTED_FORM is the shape of a switchtender install id minted from a key: in_ and 32 hex digits of
# the key's SHA-256, or the legacy in_ and 12 hex digits, the key's first six bytes.
_MINTED_FORM = re.compile(r"in_(?:[0-9a-f]{32}|[0-9a-f]{12})")


def _check_install_key(b, report):
    """Refuse a switchtender-audit-v1 install id minted from a key other than the one that signed.

    A different key presenting a minted id is a key rotation or another install's history re-signed,
    and the bundle alone cannot tell them apart. Accepting a rotation takes a pinned key paired with
    the install, and this verifier takes no pin, so here the case is always refused.
    """
    chain = b.get("chain")
    if not report["signature_ok"] or not chain or chain.get("profile") != SWITCHTENDER:
        return
    install = b["producer"].get("install_id", "")
    if not _MINTED_FORM.fullmatch(install):
        return
    pub = _b64(b["producer"]["public_key"])
    if install in ("in_" + hashlib.sha256(pub).hexdigest()[:32], "in_" + pub[:6].hex()):
        report["install_binding"] = "minted from the producer key"
        return
    raise VError("install", f"{install} was minted from a different key than the one that signed this "
                            "bundle, so it is either a key rotation or another install's history "
                            "re-signed; pin the install's current key and accept the install to verify it")


# _DEEP_STACK and _RECURSION_LIMIT size the thread verification runs on. A document nested
# MAX_DEPTH levels costs the scanner three Python frames per level and the serializer up to two,
# and on interpreters before 3.11 each of those frames also costs C stack, so the thread reserves
# several times what either needs.
_DEEP_STACK = 64 * 1024 * 1024
_RECURSION_LIMIT = 50_000

# _deep marks the thread verification runs on, so a nested call runs inline on it.
_deep = threading.local()


def _on_deep_stack(fn, *args):
    """Run fn on a thread whose stack and recursion limit hold a document nested MAX_DEPTH
    levels, returning its result or raising what it raised. A call already on that thread runs
    inline, and a platform that refuses a stack or a thread that large runs fn on the caller's
    thread."""
    if getattr(_deep, "active", False):
        return fn(*args)
    try:
        old_size = threading.stack_size(_DEEP_STACK)
    except (ValueError, RuntimeError):
        return fn(*args)
    outcome = {}

    def run():
        _deep.active = True
        old_limit = sys.getrecursionlimit()
        sys.setrecursionlimit(max(old_limit, _RECURSION_LIMIT))
        try:
            outcome["value"] = fn(*args)
        except BaseException as exc:
            outcome["error"] = exc
        finally:
            sys.setrecursionlimit(old_limit)

    worker = threading.Thread(target=run, name="loomverify")
    try:
        worker.start()
    except RuntimeError:
        return fn(*args)
    finally:
        threading.stack_size(old_size)
    worker.join()
    if "error" in outcome:
        raise outcome["error"]
    return outcome["value"]


def verify(raw_bytes, evidence_dir=None):
    """Verify one bundle and return a report dict. Failure is a report, never an exception."""
    return _on_deep_stack(_verify, raw_bytes, evidence_dir)


def _verify(raw_bytes, evidence_dir):
    """Run every check over one bundle and build its report. Every failure, including a fault in
    this verifier itself, lands in the report as a problem with the verdict not verified, because
    a caller parses the report and cannot parse a traceback."""
    report = {"ok": False, "level": "not verified", "unsupported": False, "problems": [],
              "signature_ok": False, "chain_present": False, "chain_ok": False,
              "chain_mode": "", "head_matched": False, "anchors_matched": 0,
              "anchor_proofs_carried": 0, "anchor_proofs_verified": 0,
              "anchor_proofs_validated": False, "anchor_attestations": [],
              "anchors_to_declared_head": 0, "unknown_types": [], "unknown_subject_type": "",
              "span_present": False, "span_ok": False, "span_beats": 0,
              "span_counts_verified": 0, "span_counts_carried": 0,
              "span_gaps": [], "span_longest_gap": "", "span_coverage": "",
              "disclosures_present": False, "fields_revealed": 0, "fields_redacted": 0,
              "revealed_fields": [], "attestations_present": False, "attestations_verified": 0,
              "head_attestations_verified": 0, "head_attestors": [],
              "attestors": [], "install_binding": "", "records_present": False,
              "decision_records": 0, "correction_records": 0, "reasons_verified": 0,
              "reasons_redacted": [], "reasons_withheld": 0, "specs_matched": 0,
              "specs_unchecked": 0, "outcomes_verified": 0, "outcomes_unchecked": 0,
              "legacy_records": [], "disclosed": [], "disclosed_unchecked": 0, "_states": {}}
    try:
        b = parse_strict(raw_bytes)
        _schema_check(b)
        _check_signature(raw_bytes, b, report)
        if b["subject"].get("type") not in KNOWN_SUBJECTS:
            report["unknown_subject_type"] = b["subject"].get("type")
        _check_chain(b, report)
        _check_install_key(b, report)
        _check_disclosures(b, report)
        _check_records(b, report)
        _check_attestations(b, report)
        _check_head_attestations(b, report)
        _check_anchors(b, report)
        _check_span(b, report)
        _check_evidence(b, evidence_dir, report)
        # The disclosed states belong to a verified verdict, so they are listed only when every
        # check passed, including an evidence check that records its problem without raising. The
        # Go verifier lists them under the same condition, which is what keeps the two reports the
        # same on a failing bundle.
        if not report["problems"]:
            _classify_disclosed(b, report)
    except VError as e:
        report.pop("_states", None)
        report["problems"].append(f"{e.check}: {e.msg}")
        if e.check == "unsupported":
            report["unsupported"] = True
            report["level"] = "unsupported"
        else:
            report["level"] = "not verified"
        return report
    except Exception as exc:
        report.pop("_states", None)
        report["problems"].append(f"verifier: {type(exc).__name__}: {exc}")
        report["level"] = "not verified"
        return report
    report.pop("_states", None)
    report["ok"] = len(report["problems"]) == 0
    # A bundle that failed any check achieved no level, whatever the earlier checks held.
    report["level"] = _level(report) if report["ok"] else "not verified"
    return report


# ---------- Schema ----------

# _ANY marks a member the schema leaves as any JSON value: a claim payload, which the claim's own
# checks read, and a disclosure value, which is the revealed field itself.
_ANY = object()

# _SCHEMA mirrors schema/loomseal-bundle.schema.json object for object: the members each object may
# carry and the JSON type each holds. A type is a Python type, the name of another object in this
# table, a one-element list naming the type of an array's elements, a one-element tuple naming the
# type of an open object's values, or _ANY. The Go verifier takes the member names from its exact
# member pass and the types from its struct decoder; this verifier is exactly as strict, because a
# member the producer signature does not cover would otherwise ride inside a green verdict, and a
# value of another type would be read as something the Go verifier never reads.
_SCHEMA = {
    "bundle": {"loomseal": str, "bundle_id": str, "created_at": str, "producer": "producer",
               "subject": "subject", "chain": "chain", "claims": ["claim"],
               "anchors": ["anchor"], "attestations": ["attestation"],
               "signatures": ["signature"]},
    "producer": {"product": str, "product_version": str, "install_id": str, "public_key": str,
                 "key_id": str},
    "subject": {"type": str, "id": str},
    "chain": {"profile": str, "keyed": bool, "params": (str,), "head": "coords",
              "consistency": "consistency"},
    "consistency": {"from_size": int, "from_root": str, "path": [str]},
    "coords": {"seq": int, "prev": str, "link": str},
    "claim": {"type": str, "at": str, "payload": _ANY, "evidence": ["evidence"],
              "verdict": "verdict", "chain": "coords", "inclusion": "inclusion",
              "disclosures": ["disclosure"], "attestations": ["attestation"]},
    "inclusion": {"path": [str]},
    "attestation": {"key_id": str, "public_key": str, "alg": str, "role": str, "sig": str,
                    "at": str},
    "disclosure": {"salt": str, "name": str, "value": _ANY},
    "evidence": {"role": str, "digest": str, "media_type": str, "present": bool, "location": str},
    "verdict": {"policy": str, "policy_digest": str, "inputs_digest": str, "decision": str,
                "detail": str},
    "anchor": {"type": str, "seq": int, "link": str, "at": str, "ref": str, "proof": str},
    "signature": {"key_id": str, "alg": str, "sig": str},
}

# _ELEMENTS names one element of each array member for a problem line.
_ELEMENTS = {"claims": "claim", "anchors": "anchor", "attestations": "attestation",
             "signatures": "signature", "evidence": "evidence", "disclosures": "disclosure",
             "path": "path"}

# _TYPE_NAMES words each JSON type for a problem line.
_TYPE_NAMES = {str: "a string", int: "an integer", bool: "a boolean"}

# The value patterns the schema fixes, matched whole. Digits are ASCII only.
_RE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_RE_LINK = re.compile(r"[0-9a-f]{64}")
_RE_CLAIM_TYPE = re.compile(r"[a-z][a-z0-9_-]*\.[a-z][a-z0-9_-]*/[0-9]+")
_RE_SUBJECT_TYPE = re.compile(r"[a-z][a-z0-9_-]{0,63}")

# _RE_TIME is the one time form this format allows: a four digit year, a two digit month, day, hour,
# minute, and second, an upper case T between the date and the time, an optional fraction of one or
# more digits after a period, and an upper case Z. Every digit is ASCII. Mirrors the Go reTime.
_RE_TIME = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})"
                      r"(?:\.([0-9]+))?Z")

# _ANCHOR_TYPES is the anchor vocabulary the format defines. Unlike a subject type, an anchor type
# outside it is refused at parse, because the type says what proof the anchor carries.
_ANCHOR_TYPES = {"rfc3161", "git", "https", "rekor"}


def _is_int(v):
    """Report whether v is a JSON integer, which excludes the booleans Python counts as ints."""
    return isinstance(v, int) and not isinstance(v, bool)


def _child(where, name):
    """Name a member of the object named where for a problem line."""
    return f"{where} {name}" if where else name


def _check_object(obj, kind, where):
    """Require obj to be an object carrying only the members _SCHEMA allows for kind, each of the
    JSON type the schema gives it."""
    if not isinstance(obj, dict):
        raise VError("parse", f"{where or 'bundle'} is not an object")
    members = _SCHEMA[kind]
    extra = sorted(set(obj) - set(members))
    if extra:
        raise VError("parse", f"{where or 'bundle'}: unknown member {extra[0]!r}")
    for name in sorted(obj):
        _check_value(obj[name], members[name], where, name)


def _check_value(v, spec, where, name):
    """Require member name of the object named where to hold the JSON type spec gives it. Null is
    refused everywhere but a member the schema leaves as any JSON: no member the schema defines
    takes null, and a reader that took null for a zero value would read a null prev as the empty
    predecessor and a null keyed as false."""
    if spec is _ANY:
        return
    label = _child(where, name)
    if v is None:
        raise VError("parse", f"{label} is null")
    if isinstance(spec, str):
        _check_object(v, spec, label)
    elif isinstance(spec, list):
        if not isinstance(v, list):
            raise VError("parse", f"{label} is not an array")
        element = _ELEMENTS[name]
        if name == "attestations" and not where:
            element = "head attestation"
        for i, e in enumerate(v):
            _check_value(e, spec[0], where, f"{element} {i}")
    elif isinstance(spec, tuple):
        if not isinstance(v, dict):
            raise VError("parse", f"{label} is not an object")
        for k in sorted(v):
            _check_value(v[k], spec[0], label, f"member {k!r}")
    elif not (_is_int(v) if spec is int else isinstance(v, spec)):
        raise VError("parse", f"{label} is not {_TYPE_NAMES[spec]}")


# _RE_BASE64 is the base64 standard encoding, padded, with no line breaks or other bytes.
_RE_BASE64 = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


def _b64(s):
    """Decode a base64 standard encoding string, refusing any byte outside the alphabet and its
    padding, as the Go verifier does. Python's own decoder skips excess padding on some versions,
    so the form is matched first, and every base64 value is decoded here."""
    if not isinstance(s, str) or not _RE_BASE64.fullmatch(s):
        raise ValueError("not base64 standard encoding")
    return base64.b64decode(s, validate=True)


def _parse_time(s):
    """Parse a time in the one form this format allows, the RFC 3339 date-time production narrowed
    to UTC, to whole microseconds since the Unix epoch, with digits past the microsecond dropped:
    the shape in _RE_TIME, a year from 0001 to 9999, a month from 01 to 12, a day within its month,
    an hour below 24, and a minute and a second below 60, so a leap second is refused. Any other
    string raises ValueError. Every time a bundle or a presentation carries is read here and by
    nothing else, under every profile. Mirrors the Go ParseTime."""
    m = _RE_TIME.fullmatch(s) if isinstance(s, str) else None
    if m is None:
        raise ValueError(f"{s!r} is not a UTC time of the form YYYY-MM-DDTHH:MM:SS[.fraction]Z")
    if m[1] == "0000":
        raise ValueError(f"{s!r} is in year 0000, and the first year allowed is 0001")
    at = datetime(int(m[1]), int(m[2]), int(m[3]), int(m[4]), int(m[5]), int(m[6]),
                  tzinfo=timezone.utc)
    fraction = int((m[7] or "")[:6].ljust(6, "0"))
    return _micros(at) + fraction


# _RE_GEN_TIME is the one genTime form RFC 3161 allows: the year, month, day, hour, minute, and
# second as fourteen ASCII digits, an optional fraction after a period with no trailing zero, and an
# upper case Z.
_RE_GEN_TIME = re.compile(rb"([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})"
                          rb"(\.[0-9]*[1-9])?Z")


def _parse_gen_time(raw):
    """Read a timestamp token's genTime, the raw bytes of its GeneralizedTime, in the one form RFC
    3161 gives it, to whole microseconds since the Unix epoch with finer digits dropped. The fields
    are range checked by _parse_time, so a genTime holds the ranges a bundle time does. A missing
    genTime, a numeric offset, a trailing zero in the fraction, and any other form raise
    ValueError. Mirrors the Go parseGenTime."""
    m = _RE_GEN_TIME.fullmatch(raw) if isinstance(raw, bytes) else None
    if m is None:
        raise ValueError(f"{raw!r} is not of the form YYYYMMDDhhmmss[.fraction]Z")
    y, mo, d, h, mi, sec, frac = (g.decode("ascii") if g else "" for g in m.groups())
    return _parse_time(f"{y}-{mo}-{d}T{h}:{mi}:{sec}{frac}Z")


def _micros(at):
    """Count an aware datetime as whole microseconds since the Unix epoch."""
    return (at - _EPOCH) // timedelta(microseconds=1)


def _is_time(s):
    """Report whether s is a time in the one form _parse_time reads."""
    try:
        _parse_time(s)
    except ValueError:
        return False
    return True


def _check_time(what, s):
    """Require a time in the one form _parse_time reads, refusing the bundle at parse when s is not
    one."""
    try:
        _parse_time(s)
    except ValueError as exc:
        raise VError("parse", f"{what}: {exc}") from exc


def _attestation_times(b):
    """Require the at of every claim attestation and head attestation that carries one to be a time
    in the one form _parse_time reads, an empty one included, refusing the bundle at parse. The Go
    verifier judges this on its parsed tree, where an attestation that carries at always carries a
    time, because its struct decoder reads an empty at as an absent one."""
    for i, c in enumerate(b.get("claims", [])):
        for j, a in enumerate(c.get("attestations", [])):
            if "at" in a:
                _check_time(f"claim {i} attestation {j} at", a["at"])
    for j, a in enumerate(b.get("attestations", [])):
        if "at" in a:
            _check_time(f"head attestation {j} at", a["at"])


def _schema_check(b):
    """Validate a parsed bundle against the schema: the version, then every member's name and JSON
    type, then each value's rule. The value rules run in the order the Go verifier's validate holds
    them, and a missing member reads as that verifier's zero value, so a document with more than
    one fault reaches the same failing check in both."""
    if not isinstance(b, dict):
        raise VError("parse", "bundle is not an object")
    version = b.get("loomseal")
    if "loomseal" in b and not isinstance(version, str):
        raise VError("parse", "bundle loomseal is not a string")
    if version != "0.1":
        raise VError("unsupported", f"loomseal version {version!r}, this verifier implements 0.1")
    _check_object(b, "bundle", "")
    _attestation_times(b)
    if not b.get("bundle_id"):
        raise VError("parse", "bundle_id is empty")
    _check_time("created_at", b.get("created_at", ""))
    _producer_values(b.get("producer", {}))
    subject = b.get("subject", {})
    if not _RE_SUBJECT_TYPE.fullmatch(subject.get("type", "")):
        raise VError("parse", f"subject type {subject.get('type', '')!r} does not match the type "
                              "pattern")
    if not subject.get("id"):
        raise VError("parse", "subject id is empty")
    chain = b.get("chain")
    if chain is not None:
        _chain_values(chain)
    claims = b.get("claims", [])
    if not claims:
        raise VError("parse", "bundle has no claims")
    for i, c in enumerate(claims):
        _claim_values(c, i)
    # A proof beside a claim tells a reader some verifier checked it, so a proof no profile would
    # check is refused rather than ignored, as are coordinates in a bundle that declares no chain,
    # whose claims are unproved by construction.
    tree = chain is not None and chain.get("profile") == MERKLE
    for i, c in enumerate(claims):
        if "inclusion" in c and not tree:
            raise VError("parse",
                         f"claim {i} carries an inclusion proof, which belongs to {MERKLE}")
        if chain is None and "chain" in c:
            raise VError("parse", f"claim {i} carries chain coordinates but the bundle declares no "
                                  "chain")
    for i, a in enumerate(b.get("anchors", [])):
        _anchor_values(a, i)
    signatures = b.get("signatures", [])
    if not signatures:
        raise VError("parse", "bundle has no signatures")
    for i, s in enumerate(signatures):
        _signature_values(s, i)


def _producer_values(p):
    """Require the producer block's fields, its key as 32 bytes of base64, and its fingerprint as
    a digest."""
    if not p.get("product") or not p.get("product_version") or not p.get("install_id"):
        raise VError("parse", "producer fields are incomplete")
    try:
        key = _b64(p.get("public_key", ""))
    except ValueError as exc:
        raise VError("parse", f"producer public_key is not base64: {exc}") from exc
    if len(key) != 32:
        raise VError("parse", f"producer public_key is {len(key)} bytes, want 32")
    if not _RE_DIGEST.fullmatch(p.get("key_id", "")):
        raise VError("parse", f"producer key_id {p.get('key_id', '')!r} is not a sha256 digest")


def _chain_values(chain):
    """Require a known profile, a well-formed head, and a consistency proof only under the tree
    profile. An unsupported profile surfaces here, before the signature is touched, so both
    verifiers reach the same verdict on the same bytes whatever else is wrong."""
    profile = chain.get("profile", "")
    if profile not in (SWITCHTENDER, V1, MERKLE):
        raise VError("unsupported",
                     f"chain profile {profile!r} is not one this verifier implements")
    _coords_values(chain.get("head", {}), "chain head")
    cons = chain.get("consistency")
    if cons is None:
        return
    if profile != MERKLE:
        raise VError("parse", f"a consistency proof belongs to {MERKLE}, not {profile}")
    if cons.get("from_size", 0) < 1:
        raise VError("parse", f"consistency from_size {cons.get('from_size', 0)}, want at least 1")
    if not _RE_LINK.fullmatch(cons.get("from_root", "")):
        raise VError("parse", "consistency from_root is not 64 hex characters")
    _hashes_values(cons.get("path", []), "consistency path")


def _hashes_values(path, where):
    """Require every element of a proof path to be a bare 64 hex hash."""
    for j, h in enumerate(path):
        if not _RE_LINK.fullmatch(h):
            raise VError("parse", f"{where} {j} is not 64 hex characters")


def _coords_values(co, where):
    """Require chain coordinates: a seq of at least one, a link of 64 hex characters, and a prev
    that is absent, empty, or 64 hex characters."""
    if co.get("seq", 0) < 1:
        raise VError("parse", f"{where} seq {co.get('seq', 0)}, want at least 1")
    if not _RE_LINK.fullmatch(co.get("link", "")):
        raise VError("parse", f"{where} link is not 64 hex characters")
    prev = co.get("prev", "")
    if prev != "" and not _RE_LINK.fullmatch(prev):
        raise VError("parse", f"{where} prev is not empty or 64 hex characters")


def _claim_values(c, i):
    """Require a claim's values: a registry-shaped type, an RFC 3339 at, an object payload,
    evidence with a role and a digest, a complete verdict, hashes in an inclusion path, and
    well-formed coordinates."""
    where = f"claim {i}"
    if not _RE_CLAIM_TYPE.fullmatch(c.get("type", "")):
        raise VError("parse", f"{where} type {c.get('type', '')!r}")
    _check_time(f"{where} at", c.get("at", ""))
    if not isinstance(c.get("payload"), dict):
        raise VError("parse", f"{where} payload is not a JSON object")
    for j, e in enumerate(c.get("evidence", [])):
        if not e.get("role"):
            raise VError("parse", f"{where} evidence {j} role is empty")
        if not _RE_DIGEST.fullmatch(e.get("digest", "")):
            raise VError("parse", f"{where} evidence {j} digest")
    verdict = c.get("verdict")
    if verdict is not None and (not verdict.get("policy") or not verdict.get("decision")):
        raise VError("parse", f"{where} verdict is incomplete")
    if "inclusion" in c:
        _hashes_values(c["inclusion"].get("path", []), f"{where} inclusion path")
    if "chain" in c:
        _coords_values(c["chain"], f"{where} chain")


def _anchor_values(a, i):
    """Require an anchor's type to be one the format defines, its coordinates well-formed, its
    ref non-empty, its proof base64 when carried, and its time RFC 3339."""
    where = f"anchor {i}"
    if a.get("type") not in _ANCHOR_TYPES:
        raise VError("parse", f"{where} type {a.get('type', '')!r}")
    if a.get("seq", 0) < 1:
        raise VError("parse", f"{where} seq {a.get('seq', 0)}")
    if not _RE_LINK.fullmatch(a.get("link", "")):
        raise VError("parse", f"{where} link")
    if not a.get("ref"):
        raise VError("parse", f"{where} ref is empty")
    if a.get("proof"):
        try:
            _b64(a["proof"])
        except ValueError as exc:
            raise VError("parse", f"{where} proof is not base64: {exc}") from exc
    _check_time(f"{where} at", a.get("at", ""))


def _signature_values(s, i):
    """Require a signature entry's key_id to be a digest, its alg to be the one this format fixes,
    and its sig to be 64 bytes of base64. An unsupported alg surfaces here, before the signature
    is touched, as an unsupported verdict rather than a failed one."""
    where = f"signature {i}"
    if not _RE_DIGEST.fullmatch(s.get("key_id", "")):
        raise VError("parse", f"{where} key_id")
    if s.get("alg") != "ed25519":
        raise VError("unsupported", f"{where} alg {s.get('alg', '')!r}, this verifier implements "
                                    "ed25519")
    try:
        sig = _b64(s.get("sig", ""))
    except ValueError as exc:
        raise VError("parse", f"{where} sig is not base64: {exc}") from exc
    if len(sig) != 64:
        raise VError("parse", f"{where} sig is {len(sig)} bytes, want 64")


def _key_id(pub_bytes):
    return "sha256:" + hashlib.sha256(pub_bytes).hexdigest()


def _check_signature(raw_bytes, b, report):
    parsed = parse_strict(raw_bytes)
    # Strip the members a producer signature does not cover: the signatures array and every claim's
    # holder-controlled disclosures. The signature commits to the _sd digest set, not to the
    # disclosures, so a holder withholds a field without breaking it.
    parsed["signatures"] = []
    parsed.pop("attestations", None)
    for claim in parsed.get("claims", []):
        if isinstance(claim, dict):
            claim.pop("disclosures", None)
            claim.pop("attestations", None)
    canonical = canon(parsed)
    prod = b["producer"]
    # The key decoded and measured 32 bytes at parse; only the fingerprint is judged here.
    pub_bytes = _b64(prod["public_key"])
    if _key_id(pub_bytes) != prod.get("key_id"):
        raise VError("signature", "producer key_id does not match the public key")
    pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
    # Every entry is checked before any is verified: the producer entry verifying first must
    # not return past a foreign rider sitting behind it in the array.
    for i, sig in enumerate(b["signatures"]):
        if sig.get("key_id") != prod["key_id"]:
            raise VError("signature",
                         f"signature {i} names a key the producer block does not hold")
    for sig in b["signatures"]:
        # alg sits outside the signed bytes, so an attacker rewrites it for free. It is read
        # only to reject a bundle that declares something this format does not fix, never to
        # choose which algorithm to verify with.
        if sig.get("alg") != "ed25519":
            raise VError("unsupported", f"signature alg {sig.get('alg')!r}, this verifier implements ed25519")
        try:
            pub.verify(_b64(sig["sig"]), canonical)
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
    # Recorded so the level wording can distinguish a tree from a linear chain, the same way the Go
    # verifier keys its wording on the profile rather than the mode.
    report["chain_profile"] = chain["profile"]
    # The tree profile is checked before the linear rules below, which it legitimately violates: a
    # tree has no per-entry predecessor, its head is a root rather than the newest claim's link, and
    # disclosing a non-contiguous subset of leaves is the whole point of the profile.
    if chain["profile"] == MERKLE:
        _check_merkle(b, report)
        for c in claims:
            if c["type"] not in KNOWN_TYPES and c["type"] not in report["unknown_types"]:
                report["unknown_types"].append(c["type"])
        return
    for i, c in enumerate(claims):
        if "chain" not in c:
            raise VError("chain", f"claim {i} has no chain coordinates")
    for i, c in enumerate(claims):
        co = c["chain"]
        if i == 0:
            if co["seq"] == 1 and co.get("prev", "") != "":
                raise VError("chain", "genesis claim has a prev link")
            # A window opening past sequence one links to the entry before it and must carry that
            # prev; an empty prev there recomputes as genesis and lets a bundle present itself as
            # unrooted at an arbitrary point.
            if co["seq"] > 1 and co.get("prev", "") == "":
                raise VError("chain", f"claim 0 opens a window at seq {co['seq']} but carries no prev")
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
        # Only loomseal-chain-v1 defines a keyed form. A switchtender-audit-v1 chain declared keyed
        # would skip the link recompute, so a payload altered after signing would still pass.
        if chain["profile"] == SWITCHTENDER:
            raise VError("chain", f"{SWITCHTENDER} is an unkeyed profile")
        report["chain_mode"] = "structural"
    else:
        _recompute_links(b)
        report["chain_mode"] = "full"
    report["chain_ok"] = True
    for c in claims:
        if c["type"] not in KNOWN_TYPES and c["type"] not in report["unknown_types"]:
            report["unknown_types"].append(c["type"])


def _leaf_hash(data):
    return hashlib.sha256(b"\x00" + data).digest()


def _node_hash(left, right):
    return hashlib.sha256(b"\x01" + left + right).digest()


def _claim_content(claim):
    """The one committed-content rule both hashing profiles share: position (chain), proof
    (inclusion), holder and third-party members (disclosures, attestations), and evidence
    packaging (present, location) stay out of every link and leaf."""
    content = {k: v for k, v in claim.items()
               if k not in ("chain", "inclusion", "disclosures", "attestations")}
    if isinstance(content.get("evidence"), list):
        content["evidence"] = [
            {k: v for k, v in e.items() if k not in ("present", "location")}
            if isinstance(e, dict) else e
            for e in content["evidence"]
        ]
    return content


def _merkle_leaf_data(claim, install):
    """Leaf bytes for one claim: the canonical object of the domain, the install, and the claim
    digest. The digest covers the claim's content with the members describing its position, its
    proof, and how this bundle packages its evidence removed, so the same log entry disclosed in two
    bundles yields one leaf."""
    content = _claim_content(claim)
    digest = "sha256:" + hashlib.sha256(canon(content)).hexdigest()
    return canon({"domain": MERKLE, "install_id": install, "claim": digest})


def _verify_inclusion(leaf, index, size, path, root):
    """Fold an audit path to the root. The index and size choose the shape of the fold; a relying
    party holds one entry and its path, never the log, so the tree is never rebuilt."""
    if index < 0 or size < 1 or index >= size:
        return False
    fn, sn = index, size - 1
    computed = _leaf_hash(leaf)
    for p in path:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            computed = _node_hash(p, computed)
            while fn and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            computed = _node_hash(computed, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and computed == root


def _verify_consistency(from_size, head_size, from_root, head_root, path):
    """Recompute both the old root and the new one from a consistency proof. Recomputing only one of
    them would say nothing about the relationship between them."""
    if from_size < 1 or from_size > head_size:
        return False
    if from_size == head_size:
        return not path and from_root == head_root
    fn, sn = from_size - 1, head_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    if fn != 0:
        if not path:
            return False
        old = new = path[0]
        rest = path[1:]
    else:
        # The prefix ends on a complete subtree, so the verifier already holds its root and the
        # proof does not carry it. This seeding case is where implementations most often split.
        old = new = from_root
        rest = path
    for p in rest:
        if sn == 0:
            return False
        if (fn & 1) or fn == sn:
            old = _node_hash(p, old)
            new = _node_hash(p, new)
            while fn and not (fn & 1):
                fn >>= 1
                sn >>= 1
        else:
            new = _node_hash(new, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and old == from_root and new == head_root


def _unhex(value, what):
    try:
        raw = bytes.fromhex(value)
    except (ValueError, TypeError):
        raise VError("chain", f"{what} is not hex")
    if len(raw) != 32:
        raise VError("chain", f"{what} is not a 32 byte hash")
    return raw


def _check_merkle(b, report):
    """Verify a bundle under loomseal-merkle-v1, per FORMAT.md."""
    chain = b["chain"]
    if chain.get("keyed"):
        raise VError("chain", f"{MERKLE} is an unkeyed profile")
    install = (chain.get("params") or {}).get("install_id")
    if not install:
        raise VError("chain", f"{MERKLE} requires params.install_id")
    # The install id is hashed into every leaf, so it must be the signer's own or the binding proves
    # nothing: a copier reusing another install's leaves, root, and timestamp token would otherwise
    # emit a bundle that is internally consistent while asserting a history its key never had.
    if install != b["producer"].get("install_id"):
        raise VError("chain", "chain params.install_id is not the producer's install")
    head = chain["head"]
    if head.get("prev", "") != "":
        raise VError("chain", "a tree head has no previous link")
    size = head["seq"]
    root = _unhex(head["link"], "head link")

    seen = set()
    prev_seq = 0
    for i, c in enumerate(b["claims"]):
        if "chain" not in c:
            raise VError("chain", f"claim {i} has no chain coordinates")
        if "inclusion" not in c:
            raise VError("chain", f"claim {i} carries no inclusion proof")
        co = c["chain"]
        if co.get("prev", "") != "":
            raise VError("chain", f"claim {i} has a previous link, which a tree has no place for")
        if co["seq"] > size:
            raise VError("chain", f"claim {i} seq is past the tree size")
        if co["seq"] in seen:
            raise VError("chain", f"claim {i} repeats a sequence")
        seen.add(co["seq"])
        if co["seq"] <= prev_seq:
            raise VError("chain", f"claim {i} sequence does not ascend")
        prev_seq = co["seq"]

        leaf = _merkle_leaf_data(c, install)
        if _leaf_hash(leaf).hex() != co["link"]:
            raise VError("chain", f"claim {i} leaf hash does not recompute")
        path = [_unhex(h, f"claim {i} inclusion path") for h in c["inclusion"]["path"]]
        # The index and size come from the claim's own seq and the signed head, never from a value
        # carried beside the proof, because folding binds a leaf to a root and not to a size.
        if not _verify_inclusion(leaf, co["seq"] - 1, size, path, root):
            raise VError("chain", f"claim {i} does not prove membership of the tree the head names")

    cons = chain.get("consistency")
    if cons is not None:
        if cons["from_size"] > size:
            raise VError("chain", "consistency from_size is past the tree size")
        proof = [_unhex(h, "consistency path") for h in cons["path"]]
        if not _verify_consistency(cons["from_size"], size,
                                   _unhex(cons["from_root"], "consistency from_root"), root, proof):
            raise VError("chain", "the log does not prove it grew from the root it names by "
                                  "appending only")
        report["consistency_from"] = cons["from_size"]
        report["consistency_ok"] = True

    report["chain_mode"] = "full"
    report["chain_ok"] = True
    report["tree_size"] = size
    report["inclusion_proofs"] = len(b["claims"])
    # Every disclosed leaf folded to the head root, so the head is confirmed by the bundle itself
    # rather than merely declared, which a linear window cannot do when its head leads the claims.
    report["head_matched"] = True


def _recompute_links(b):
    profile = b["chain"]["profile"]
    if profile == V1:
        _links_v1(b)
    elif profile == SWITCHTENDER:
        _links_switchtender(b)
    else:
        raise VError("unsupported",
                     f"chain profile {profile!r} is not one this verifier implements")


def _links_v1(b):
    install = (b["chain"].get("params") or {}).get("install_id")
    if not install:
        raise VError("chain", "loomseal-chain-v1 requires params.install_id")
    # The id has to be the signer's, not merely present. An id a bundle states but nothing ties to
    # the producer is one a copier can restate, so a link bound to it is bound to nothing they cannot
    # also claim. FORMAT.md requires this and the Go verifier enforced it; this reference verifier did
    # not, so the two disagreed on a foreign-install linear bundle until now.
    if install != b["producer"].get("install_id"):
        raise VError("chain", f"{V1} params.install_id does not match producer.install_id")
    for i, c in enumerate(b["claims"]):
        # The one committed-content rule, shared with the merkle leaf: position, proof, holder
        # and third-party members, and evidence packaging all stay out of the commitment.
        bare = _claim_content(c)
        claim_digest = "sha256:" + hashlib.sha256(canon(bare)).hexdigest()
        link_input = canon({"domain": V1, "install_id": install,
                             "seq": c["chain"]["seq"], "prev": c["chain"].get("prev", ""),
                             "claim": claim_digest})
        if hashlib.sha256(link_input).hexdigest() != c["chain"]["link"]:
            raise VError("chain", f"claim {i} link does not recompute")


def _links_switchtender(b):
    # chain.params.install_id is informational in this profile: the per-claim install_id is what
    # binds. A param that disagrees with the producer is refused rather than silently ignored, so a
    # third-party producer cannot set it and assume it binds. A param equal to the producer restates
    # it and is allowed.
    pid = (b["chain"].get("params") or {}).get("install_id")
    if pid and pid != b["producer"].get("install_id"):
        raise VError("chain", f"{SWITCHTENDER} chain.params.install_id is informational and must "
                              "equal producer.install_id; the per-claim install_id is what binds")
    for i, c in enumerate(b["claims"]):
        p = c["payload"]
        # The time was read at parse, under every profile, and is hashed verbatim below, never
        # reformatted: a time type that stops at microseconds would drop a nanosecond digit and
        # recompute a different link from the one the producer signed.
        # install_id binds the entry to the producer. When an entry carries it, it must be the
        # signer's own, and it is folded into the link like the other optional fields. A link that
        # commits to the install cannot be lifted into another install's bundle while keeping a
        # genuine anchor: rewriting the producer forces rewriting the link, which breaks any
        # third-party timestamp taken over the original. An entry that omits it is a pre-binding
        # entry, hashed exactly as before, so a chain can adopt the field without invalidating the
        # links it already published.
        install = p.get("install_id")
        if isinstance(install, str) and install and install != b["producer"].get("install_id"):
            raise VError("chain", f"claim {i} install_id does not match producer.install_id")
        claim = {"seq": c["chain"]["seq"], "at": c["at"], "prev": c["chain"].get("prev", ""),
                 "actor": p.get("actor", ""), "method": p.get("method", ""),
                 "path": p.get("path", "")}
        # Fields added after the first release are hashed only when the entry carries them, exactly
        # as the producer omits them, so an entry recorded before they existed recomputes unchanged.
        for key in ("actor_type", "on_behalf_of", "content_digest", "install_id"):
            value = p.get(key)
            if isinstance(value, str) and value:
                claim[key] = value
        if hashlib.sha256(canon(claim)).hexdigest() != c["chain"]["link"]:
            raise VError("chain", f"claim {i} link does not recompute (switchtender)")


# ANCHOR_SKEW_S is how far an authority's clock may sit behind the producer's before an attestation
# reads as predating the entry it covers. Both clocks are real and neither is authoritative, so a
# small allowance keeps honest installs from being called liars. It matches the Go verifier.
ANCHOR_SKEW_S = 300


def _time_or_none(ts):
    """Read a time in the one form _parse_time reads to microseconds since the epoch, or None when
    ts is not one."""
    try:
        return _parse_time(ts)
    except ValueError:
        return None


def _is_hex64(s):
    """Report whether s is exactly 64 lowercase hex characters, the shape of a sha256 digest."""
    return len(s) == 64 and all(c in "0123456789abcdef" for c in s)


def _check_disclosures(b, report):
    """Verify LoomSwatch field-level selective disclosure. A claim commits redactable fields as an
    _sd array of digests in its payload and reveals a subset through claim.disclosures, each a
    [salt, name, value] triple. The _sd set is covered by the link or leaf while disclosures travel
    outside both, so revealing or withholding a field never changes what the producer signed. A
    disclosure must hash to a digest in the set, or it is a foreign or tampered value."""
    chain = b.get("chain")
    swatch = chain is not None and chain.get("profile") in (V1, MERKLE)
    for i, c in enumerate(b["claims"]):
        payload = c.get("payload")
        sd = payload.get("_sd") if isinstance(payload, dict) else None
        disc = c.get("disclosures")
        if sd is None and not disc:
            continue
        report["disclosures_present"] = True
        if not swatch:
            raise VError("disclosure", f"claim {i} carries selective disclosure, which belongs to "
                                       f"{V1} or {MERKLE}")
        if sd is not None and not isinstance(sd, list):
            raise VError("disclosure", f"claim {i} disclosure set _sd is not an array")
        seen_sd = set()
        for d in (sd or []):
            if not isinstance(d, str) or not _is_hex64(d):
                raise VError("disclosure", f"claim {i} disclosure set _sd holds a value that is not "
                                           "a 64 hex digest")
            if d in seen_sd:
                raise VError("disclosure", f"claim {i} disclosure set _sd holds a duplicate digest")
            seen_sd.add(d)
        seen = set()
        names = []
        for j, d in enumerate(disc or []):
            if not isinstance(d, dict):
                raise VError("disclosure", f"claim {i} disclosure {j} is not an object")
            salt, name, has_value = d.get("salt"), d.get("name"), "value" in d
            if not isinstance(salt, str) or not salt or not isinstance(name, str) or not name \
                    or not has_value:
                raise VError("disclosure", f"claim {i} disclosure {j} is incomplete")
            digest = hashlib.sha256(canon([salt, name, d["value"]])).hexdigest()
            if digest not in seen_sd:
                raise VError("disclosure", f"claim {i} disclosure of field {name!r} matches no "
                                           "committed digest")
            if digest in seen:
                raise VError("disclosure", f"claim {i} disclosure repeats the same field digest")
            seen.add(digest)
            names.append(name)
        report["fields_revealed"] += len(names)
        report["fields_redacted"] += len(seen_sd) - len(names)
        report["revealed_fields"].extend(sorted(names))


# _RECORD_KINDS are the records a switchtender.audit/1 claim discloses as a JSON object, by the kind
# name schema/claim-members.json gives them: (body member, nonce member, event member, needs a
# reason). A correction is nothing but a reason, so a correction body committing none is
# malformed. The outcome is the third kind, carried as text and checked by _check_outcome.
_RECORD_KINDS = {
    "decision": ("decision_body", "decision_nonce", "decision_id", False),
    "correction": ("correction_body", "correction_nonce", "correction_id", True),
}

# _KEYED_PREFIX opens the digest form that commits a record's canonical bytes under a nonce.
_KEYED_PREFIX = "sha256s:"

# _EXACT_PREFIX opens the digest form that commits a disclosed text exactly as carried.
_EXACT_PREFIX = "sha256e:"

# _REASON_MEMBERS disclose a record's reason: the text and the random value that open its
# commitment, or the holder's marker that it withheld both, with the category it claims.
_REASON_MEMBERS = ("reason_text", "reason_random", "reason_redacted")

# _FOLD maps the characters Go's encoding/json folds onto a lowercase ASCII letter, beside the ASCII
# capitals: the Kelvin sign onto k and the long s onto s. Every member name the format declares is
# lowercase ASCII letters, digits, and underscores, and no other character folds onto one of those,
# so this is exactly the folding a Go reader applies to them. The Go test suite enumerates every
# character to hold that.
_FOLD = {"\u212a": "k", "\u017f": "s"}


def _folds_onto(name, member):
    """Report whether name differs from member, a declared name, only in case."""
    if name == member or len(name) != len(member):
        return False
    folded = "".join(_FOLD.get(ch, ch.lower() if "A" <= ch <= "Z" else ch) for ch in name)
    return folded == member


def _quote(name):
    """Quote a member name for a problem line the way the Go verifier does."""
    return json.dumps(name, ensure_ascii=False)


def _case_variant(payload, members):
    """Find a payload member whose name differs from one of members only in case, returning the
    pair, or None. Mirrors the Go caseVariant."""
    for name in sorted(payload):
        for member in members:
            if _folds_onto(name, member):
                return name, member
    return None


def _path_matches(pattern, path):
    """Report whether path fits pattern segment by segment, a {name} segment matching any
    non-empty segment. An empty pattern matches every path."""
    if not pattern:
        return True
    want, got = pattern.split("/"), path.split("/")
    if len(want) != len(got):
        return False
    for w, g in zip(want, got):
        if w.startswith("{") and w.endswith("}"):
            if not g:
                return False
        elif w != g:
            return False
    return True


def _path_segment(pattern, path, name):
    """Return the segment of path that the {name} segment of pattern matches, or "" when path does
    not fit pattern or pattern has no such segment. Mirrors the Go pathSegment."""
    if not _path_matches(pattern, path):
        return ""
    got = path.split("/")
    for i, w in enumerate(pattern.split("/")):
        if w == "{" + name + "}" and i < len(got):
            return got[i]
    return ""


def _outcome_run(payload):
    """Return the run an outcome claim belongs to: the {run} segment of the path its link
    commits."""
    path = payload.get("path")
    pattern = DECLARATION["records"]["kinds"]["outcome"].get("path", "")
    return _path_segment(pattern, path if isinstance(path, str) else "", "run")


def _decision_run(payload):
    """Return the run a decision claim belongs to: the run_id its verified body names, or "" when
    the body names none as a string."""
    body = payload.get("decision_body")
    run = body.get("run_id") if isinstance(body, dict) else None
    return run if isinstance(run, str) else ""


def _record_kind_of(payload):
    """Name the kind of record a switchtender.audit/1 payload is, by its committed method and path
    read by their exact names, or return "" for a claim that is no record."""
    method, path = payload.get("method"), payload.get("path")
    method = method if isinstance(method, str) else ""
    path = path if isinstance(path, str) else ""
    for name, kind in DECLARATION["records"]["kinds"].items():
        if method == kind["method"] and _path_matches(kind.get("path", ""), path):
            return name
    return ""


def _record_members(kind):
    """List the switchtender.audit/1 members a record of kind is read for, in name order."""
    members = DECLARATION["types"]["switchtender.audit/1"]
    return sorted(n for n, d in members.items() if kind in d.get("records", []))


def _first_keyed(b):
    """Return the index of the first switchtender.audit/1 claim whose content_digest is in the keyed
    or the exact form, or -1. No entry after it predates the keyed form."""
    for i, c in enumerate(b["claims"]):
        payload = c.get("payload")
        if c.get("type") != "switchtender.audit/1" or not isinstance(payload, dict):
            continue
        digest = payload.get("content_digest")
        if isinstance(digest, str) and digest.startswith((_KEYED_PREFIX, _EXACT_PREFIX)):
            return i
    return -1


def _settle_elsewhere(report, i, payload, kind):
    """Report every record member a claim carries outside its own record as unchecked: it is an
    ordinary member there, which nothing commits."""
    members = DECLARATION["types"]["switchtender.audit/1"]
    for name in payload:
        records = members.get(name, {}).get("records", [])
        if records and kind not in records:
            _settle(report, i, name, "unchecked", DECLARATION["records"]["elsewhere"])


def _settle(report, claim, member, state, detail):
    """Record what a check established about one member of one claim."""
    report["_states"][(claim, member)] = (state, detail)


def _settle_declared(report, claim, claim_type, member):
    """Record a member as its declaration states it, against the commitment it names."""
    decl = DECLARATION["types"][claim_type][member]
    _settle(report, claim, member, decl["state"], decl.get("by", ""))


def _classify_disclosed(b, report):
    """List every member a switchtender-audit-v1 link does not commit, in the state the checks left
    it: checked, redacted, or unchecked. A member no check confirmed is unchecked, with the reason
    its declaration gives, or because nothing declares it. A member counts with the one it travels
    with only when that one is on the same claim. Mirrors the Go classifyDisclosed."""
    chain = b.get("chain")
    if not chain or chain.get("profile") != SWITCHTENDER:
        return
    profile = DECLARATION[SWITCHTENDER]
    bound, refused = set(profile["bound"]), profile.get("refused", {})
    for i, c in enumerate(b["claims"]):
        payload = c.get("payload")
        if not isinstance(payload, dict):
            continue
        for name in sorted(n for n in payload if n not in bound and n not in refused):
            decl = DECLARATION["types"].get(c.get("type"), {}).get(name)
            settled = report["_states"].get((i, name))
            if settled:
                state, detail = settled
            elif decl and decl["state"] == "unchecked":
                state, detail = "unchecked", decl["reason"]
            elif decl:
                state, detail = "unchecked", "its check did not pass"
            else:
                state = "unchecked"
                detail = (f"not declared for {c.get('type')}, and a {SWITCHTENDER} link does not "
                          "commit it")
            entry = {"claim": i, "member": name, "state": state, "detail": detail}
            with_member = (decl or {}).get("with", "")
            if with_member not in payload:
                with_member = ""
            if with_member:
                entry["with"] = with_member
            report["disclosed"].append(entry)
            if state == "unchecked" and not with_member:
                report["disclosed_unchecked"] += 1


def _check_records(b, report):
    """Verify the records switchtender.audit/1 claims disclose beside the fields their links commit.

    The link commits the entry's content_digest and the digest commits the record's body, so a body
    that does not reproduce the digest is not the record the chain holds. A decision or correction
    body commits a reason, which disclosed text must open. A reason the holder marked redacted is
    not opened and is reported as withheld, with the category the holder claims, rather than
    failed. A verified decision and a verified outcome of one run must name the same spec digest,
    and a disclosed spec is held against every digest a verified record names. A claim is a record
    by its committed method and path, and only its own record's members are read on it: the same
    names elsewhere are ordinary members, reported unchecked. Mirrors the Go checkRecords."""
    keyed_at = _first_keyed(b)
    specs, committed = [], []
    for i, c in enumerate(b["claims"]):
        payload = c.get("payload")
        if c.get("type") != "switchtender.audit/1" or not isinstance(payload, dict):
            continue
        kind = _record_kind_of(payload)
        _settle_elsewhere(report, i, payload, kind)
        if not kind:
            continue
        variant = _case_variant(payload, _record_members(kind))
        if variant:
            raise VError("record", f"claim {i} carries {_quote(variant[0])}, which differs from "
                                   f"{variant[1]} only in case, so a reader that folds case would "
                                   "take one for the other")
        if kind == "outcome":
            if "spec_body" in payload:
                text = payload["spec_body"]
                if not isinstance(text, str):
                    raise VError("record", f"claim {i} spec_body is not a string, so its bytes "
                                           "cannot be hashed")
                specs.append((i, "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()))
            spec = _check_outcome(i, payload, keyed_at, report)
            run = _outcome_run(payload)
        else:
            spec = _check_record_claim(i, kind, payload, keyed_at, report)
            run = _decision_run(payload)
        if spec is not None:
            committed.append((i, kind, run, spec))
    _check_specs(specs, committed, report)


def _check_record_claim(i, kind, payload, keyed_at, report):
    """Check the decision or correction a record claim discloses, if any, and return the spec digest
    a verified decision body commits, or None."""
    body_member, nonce_member, event_member, needs_reason = _RECORD_KINDS[kind]
    if not any(m in payload for m in (body_member, nonce_member) + _REASON_MEMBERS):
        return None
    report["records_present"] = True
    body = payload.get(body_member)
    if not isinstance(body, dict):
        raise VError("record", f"claim {i} {body_member} is missing or not an object")
    legacy, why = _record_digest_problem(i, payload, nonce_member, body, keyed_at)
    if why:
        raise VError("record", f"claim {i} {body_member} {why}")
    report["decision_records" if kind == "decision" else "correction_records"] += 1
    if legacy:
        report["legacy_records"].append(f"claim {i} {body_member}")
    for member in (body_member, nonce_member):
        if member != body_member and member not in payload:
            continue
        if legacy:
            _settle(report, i, member, "checked", DECLARATION["records"]["legacy"])
        else:
            _settle_declared(report, i, "switchtender.audit/1", member)
    _check_reason(i, payload, body_member, event_member, needs_reason, body, report)
    if kind != "decision":
        return None
    spec = body.get("spec_digest")
    return spec if isinstance(spec, str) else ""


def _record_digest_problem(i, payload, nonce_member, body, keyed_at):
    """Say why a record body does not reproduce the content_digest its entry committed, returning
    (legacy, why) with why None when it does. The keyed form is sha256s:, the SHA-256 of the nonce
    and the HMAC-SHA256 of the body's canonical bytes keyed by the nonce. The legacy unkeyed form is
    sha256:, the SHA-256 of the canonical bytes, which an entry recorded before nonces carries with
    an empty nonce, and which only an entry before the bundle's first keyed one may carry."""
    digest = payload.get("content_digest")
    if not isinstance(digest, str) or not digest:
        return False, "is disclosed on an entry that commits no content_digest"
    nonce = payload.get(nonce_member, "")
    if not isinstance(nonce, str):
        return False, f"has a {nonce_member} that is not a string"
    canonical = canon(body)
    if digest.startswith(_KEYED_PREFIX):
        parts = digest[len(_KEYED_PREFIX):].split(":")
        if len(parts) != 2 or not _is_hex64(parts[0]) or not _is_hex64(parts[1]):
            return False, "sits on a content_digest that is not sha256s: and two 64 hex digests"
        if not _is_hex64(nonce):
            return False, f"has a {nonce_member} that is not 64 lowercase hex digits"
        key = bytes.fromhex(nonce)
        if hashlib.sha256(key).hexdigest() != parts[0]:
            return False, f"has a {nonce_member} the content_digest did not commit"
        if hmac.new(key, canonical, hashlib.sha256).hexdigest() != parts[1]:
            return False, "does not reproduce the content_digest its entry committed"
        return False, None
    if digest.startswith("sha256:") and _is_hex64(digest[len("sha256:"):]):
        if 0 <= keyed_at < i:
            return False, (f"sits on an unkeyed content_digest after claim {keyed_at} began the "
                           "keyed form, and only an entry from before the keyed form may carry one")
        if nonce:
            return False, (f"carries a {nonce_member} beside an unkeyed content_digest, which "
                           "commits none")
        if hashlib.sha256(canonical).hexdigest() != digest[len("sha256:"):]:
            return False, "does not reproduce the content_digest its entry committed"
        return True, None
    return False, "sits on a content_digest in neither the sha256s: nor the sha256: form"


def _check_reason(i, payload, body_member, event_member, needs_reason, body, report):
    """Check the reason a verified record body commits against what the claim discloses. Text and
    its random value must open the commitment. A redaction marker in their place is the holder's
    statement that it withheld both, with a category nothing commits, so the commitment stays
    unopened and the category is reported as claimed, never as established. A commitment with
    nothing disclosed is withheld."""
    has_text, has_random = "reason_text" in payload, "reason_random" in payload
    has_redacted = "reason_redacted" in payload
    commitment = body.get("reason_commitment", "")
    if not isinstance(commitment, str):
        raise VError("record", f"claim {i} {body_member} carries a reason_commitment that is not a "
                               "string")
    if not commitment:
        if needs_reason:
            raise VError("record", f"claim {i} {body_member} commits no reason, and a correction "
                                   "is a reason")
        if has_text or has_random or has_redacted:
            raise VError("record", f"claim {i} discloses a reason its {body_member} commits "
                                   "none of")
        return
    if not commitment.startswith("sha256:") or not _is_hex64(commitment[len("sha256:"):]):
        raise VError("record", f"claim {i} {body_member} reason_commitment is not sha256: and 64 "
                               "hex digits")
    event = body.get(event_member)
    if not isinstance(event, str) or not event:
        raise VError("record", f"claim {i} {body_member} commits a reason but names no "
                               f"{event_member} to bind it to")
    if has_redacted:
        category = payload["reason_redacted"]
        if not isinstance(category, str) or not category or has_text or has_random:
            raise VError("record", f"claim {i} reason_redacted must be a category alone, with no "
                                   "text or random value beside it")
        report["reasons_redacted"].append(category)
        by = DECLARATION["types"]["switchtender.audit/1"]["reason_redacted"]["by"]
        _settle(report, i, "reason_redacted", "redacted", f"{category}, {by}")
    elif has_text:
        text, random = payload["reason_text"], payload.get("reason_random")
        if not isinstance(text, str) or not isinstance(random, str) or not _is_hex64(random):
            raise VError("record", f"claim {i} reason_text needs a reason_random of 64 lowercase "
                                   "hex digits")
        opened = "sha256:" + hashlib.sha256(
            canon({"event": event, "random": random, "reason": text})).hexdigest()
        if opened != commitment:
            raise VError("record", f"claim {i} reason_text does not open the reason_commitment its "
                                   f"{body_member} carries")
        report["reasons_verified"] += 1
        _settle_declared(report, i, "switchtender.audit/1", "reason_text")
        _settle_declared(report, i, "switchtender.audit/1", "reason_random")
    elif has_random:
        raise VError("record", f"claim {i} discloses a reason_random with no reason_text to open")
    else:
        report["reasons_withheld"] += 1


def _check_outcome(i, payload, keyed_at, report):
    """Check the outcome record an outcome claim discloses, if any, and return the spec digest it
    names, or None.

    An outcome under the exact form is checked over the text's bytes as carried, since the producer
    redacted the record before it fixed those bytes. An outcome under an older form was committed
    over the producer's own redaction, which a verifier cannot rebuild, so it is counted as carried
    and unchecked. The unkeyed form is held to the rule a record body is. Mirrors the Go
    checkOutcome."""
    has_nonce = "outcome_nonce" in payload
    if "outcome_body" not in payload:
        if has_nonce:
            raise VError("record", f"claim {i} carries an outcome_nonce with no outcome_body")
        return None
    report["records_present"] = True
    digest = payload.get("content_digest")
    if not isinstance(digest, str) or not digest:
        raise VError("record", f"claim {i} outcome_body is disclosed on an entry that commits no "
                               "content_digest")
    if not digest.startswith(_EXACT_PREFIX):
        if digest.startswith("sha256:") and 0 <= keyed_at < i:
            raise VError("record", f"claim {i} outcome_body sits on an unkeyed content_digest "
                                   f"after claim {keyed_at} began the keyed form, and only an "
                                   "entry from before the keyed form may carry one")
        report["outcomes_unchecked"] += 1
        why = DECLARATION["types"]["switchtender.audit/1"]["outcome_body"]["unchecked"]
        _settle(report, i, "outcome_body", "unchecked", why)
        if has_nonce:
            _settle(report, i, "outcome_nonce", "unchecked", why)
        return None
    text = payload["outcome_body"]
    if not isinstance(text, str):
        raise VError("record", f"claim {i} outcome_body is not a string, so its bytes cannot be "
                               "checked")
    nonce = payload.get("outcome_nonce")
    parts = digest[len(_EXACT_PREFIX):].split(":")
    why = None
    if len(parts) != 2 or not _is_hex64(parts[0]) or not _is_hex64(parts[1]):
        why = "sits on a content_digest that is not sha256e: and two 64 hex digests"
    elif not isinstance(nonce, str) or not _is_hex64(nonce):
        why = "has an outcome_nonce that is not 64 lowercase hex digits"
    elif hashlib.sha256(bytes.fromhex(nonce)).hexdigest() != parts[0]:
        why = "has an outcome_nonce the content_digest did not commit"
    elif hmac.new(bytes.fromhex(nonce), text.encode("utf-8"),
                  hashlib.sha256).hexdigest() != parts[1]:
        why = "does not reproduce the content_digest its entry committed"
    if why:
        raise VError("record", f"claim {i} outcome_body {why}")
    report["outcomes_verified"] += 1
    _settle_declared(report, i, "switchtender.audit/1", "outcome_body")
    _settle_declared(report, i, "switchtender.audit/1", "outcome_nonce")
    return _outcome_spec(text)


# _MAX_OUTCOME_DEPTH is how deeply a verified outcome record may nest and still be read for the spec
# digest it names, the bound the Go verifier holds, so the two read the same records.
_MAX_OUTCOME_DEPTH = 32


def _within_depth(v, limit):
    """Report whether v nests no deeper than limit, each array and object counting as one level."""
    if isinstance(v, (dict, list)):
        if limit == 0:
            return False
        members = v.values() if isinstance(v, dict) else v
        return all(_within_depth(e, limit - 1) for e in members)
    return True


def _outcome_spec(text):
    """Read the spec digest a verified outcome record names: the spec_digest member of the JSON
    object the text holds, read under the bundle's own rules, unique keys, valid strings, and
    integers within 2^53, and within the depth bound, so every implementation reads the same value.
    A record that is not such an object, or names none, commits no spec digest."""
    try:
        tree = parse_strict(text.encode("utf-8"))
        if not _within_depth(tree, _MAX_OUTCOME_DEPTH):
            return None
        canon(tree)
    except (VError, RecursionError, ValueError):
        return None
    spec = tree.get("spec_digest") if isinstance(tree, dict) else None
    return spec if isinstance(spec, str) else None


def _check_specs(specs, committed, report):
    """Hold the spec digests verified records committed, as (claim, kind, run, digest) tuples,
    against one another, then every disclosed spec against them. A bundle may hold the records of
    several runs, so a decision is held only against the outcomes of its own run, whether or not
    the spec is disclosed. A spec with nothing verified beside it to commit its digest is counted
    as unchecked rather than read as matched. Mirrors the Go checkSpecs."""
    _run_specs_agree(committed)
    if not specs:
        return
    if any(s[1] != specs[0][1] for s in specs[1:]):
        raise VError("record", "the bundle discloses two different specs, and one run has one spec")
    if not committed:
        report["specs_unchecked"] = len(specs)
        why = DECLARATION["types"]["switchtender.audit/1"]["spec_body"]["unchecked"]
        for claim, _ in specs:
            _settle(report, claim, "spec_body", "unchecked", why)
        return
    for _, _, _, c in committed:
        if c != specs[0][1]:
            raise VError("record", f"a verified record committed spec {c or '(none)'} but the "
                                   f"disclosed spec hashes to {specs[0][1]}")
    report["specs_matched"] = len(specs)
    for claim, _ in specs:
        _settle_declared(report, claim, "switchtender.audit/1", "spec_body")


def _run_specs_agree(committed):
    """Fail at the first pair, in claim order, of a verified decision and a verified outcome of one
    run that name different spec digests. A record that names no run or no digest commits nothing
    to compare. Two decisions, or two outcomes, are not held against each other here. Mirrors the
    Go runSpecsAgree."""
    seen = {}
    for claim, kind, run, digest in committed:
        if not run or not digest:
            continue
        by_kind = seen.setdefault(run, {"decision": [], "outcome": []})
        other = by_kind["decision" if kind == "outcome" else "outcome"]
        if by_kind[kind] and other:
            other = other[:1]
        for e_claim, e_digest in other:
            if e_digest != digest:
                raise VError("record", f"claim {e_claim} committed spec {e_digest} and claim "
                                       f"{claim} committed spec {digest} for run {_quote(run)}, "
                                       "and a run's decision and outcome name one spec")
        by_kind[kind].append((claim, digest))


def _check_attestations(b, report):
    """Verify counter-signatures a party other than the producer added to a claim. Each attestation
    signs the RFC 8785 canonical object of the claim's link and the signer's role, binding one claim
    and what the signer says they are. Attestations are excluded from the link, the leaf, and the
    producer signature, so a counterparty attests without the producer re-signing. See the Go
    verifier for the rationale."""
    for i, c in enumerate(b["claims"]):
        atts = c.get("attestations")
        if not atts:
            continue
        report["attestations_present"] = True
        chain = c.get("chain")
        if not chain or not chain.get("link"):
            raise VError("attestation",
                         f"claim {i} carries an attestation but has no chain link to vouch for")
        for j, a in enumerate(atts):
            if a.get("alg") != "ed25519":
                raise VError("attestation",
                             f"claim {i} attestation {j} alg {a.get('alg')!r}, want ed25519")
            try:
                pub = _b64(a.get("public_key", ""))
            except Exception:
                raise VError("attestation", f"claim {i} attestation {j} public_key is not base64")
            if len(pub) != 32:
                raise VError("attestation",
                             f"claim {i} attestation {j} public_key is not a 32 byte ed25519 key")
            if _key_id(pub) != a.get("key_id"):
                raise VError("attestation",
                             f"claim {i} attestation {j} key_id does not match its public key")
            role = a.get("role")
            if not role:
                raise VError("attestation", f"claim {i} attestation {j} role is empty")
            try:
                sig = _b64(a.get("sig", ""))
            except Exception:
                raise VError("attestation", f"claim {i} attestation {j} sig is not base64")
            obj = {"loomseal": "attestation/1", "link": chain["link"], "role": role}
            # Parse refused an at that is not a time, so a carried at is one.
            if "at" in a:
                obj["at"] = a["at"]
            preimage = canon(obj)
            try:
                Ed25519PublicKey.from_public_bytes(pub).verify(sig, preimage)
            except Exception:
                raise VError("attestation", f"claim {i} attestation {j} by {a.get('key_id')} does "
                                            "not verify over the claim link")
            report["attestations_verified"] += 1
            report["attestors"].append(f"{role} {a.get('key_id')}")



def _check_head_attestations(b, report):
    atts = b.get("attestations") or []
    if not atts:
        return
    chain = b.get("chain")
    if not isinstance(chain, dict) or not isinstance(chain.get("head"), dict):
        raise VError("attestation", "bundle carries head attestations but no chain head to vouch for")
    head = chain["head"]
    for j, a in enumerate(atts):
        if a.get("alg") != "ed25519":
            raise VError("attestation", f"head attestation {j} alg {a.get('alg')!r}, want ed25519")
        try:
            pub = _b64(a.get("public_key", ""))
        except Exception:
            raise VError("attestation", f"head attestation {j} public_key is not base64")
        if len(pub) != 32:
            raise VError("attestation", f"head attestation {j} public_key is not 32 bytes")
        if _key_id(pub) != a.get("key_id"):
            raise VError("attestation", f"head attestation {j} key_id does not match its public key")
        role = a.get("role")
        if not role:
            raise VError("attestation", f"head attestation {j} role is empty")
        try:
            sig = _b64(a.get("sig", ""))
        except Exception:
            raise VError("attestation", f"head attestation {j} sig is not base64")
        obj = {"loomseal": "head-attestation/1", "link": head["link"], "seq": head["seq"],
               "role": role}
        # Parse refused an at that is not a time, so a carried at is one.
        at = a.get("at")
        if at is not None:
            obj["at"] = at
        preimage = canon(obj)
        try:
            Ed25519PublicKey.from_public_bytes(pub).verify(sig, preimage)
        except Exception:
            raise VError("attestation", f"head attestation {j} by {a.get('key_id')} does not "
                                        "verify over the chain head")
        report["head_attestations_verified"] += 1
        entry = f"{role} {a.get('key_id')}"
        if at:
            entry += f" at {at}"
        report["head_attestors"].append(entry)


def _check_anchors(b, report):
    anchors = b.get("anchors") or []
    if not anchors:
        return
    if "chain" not in b:
        raise VError("anchor", "anchors present without a chain")
    verified = {}
    # claim_at records when each anchored position says it happened, so an attestation can be held
    # against it: a timestamp authority signs a hash it is handed, and that hash cannot exist before
    # the entry it covers.
    claim_at = {}
    for c in b["claims"]:
        if "chain" in c:
            verified[c["chain"]["seq"]] = c["chain"]["link"]
            at = _time_or_none(c.get("at"))
            if at is not None:
                claim_at[c["chain"]["seq"]] = at
    head = b["chain"]["head"]
    if report["head_matched"]:
        verified[head["seq"]] = head["link"]
    # A root a verified consistency proof starts from is a coordinate this verifier recomputed, so
    # an anchor over it matches: the anchor fixed the root at a time the producer did not control,
    # and the proof shows the log there is now grew from exactly it. The Go verifier always did
    # this, and this one refused such an anchor as matching nothing until a producer's receipts
    # showed the two disagreeing on the same bytes.
    cons = b["chain"].get("consistency")
    if cons and report.get("consistency_ok"):
        verified[cons["from_size"]] = cons["from_root"]
    for i, a in enumerate(anchors):
        matched = False
        if verified.get(a["seq"]) == a["link"]:
            report["anchors_matched"] += 1
            matched = True
        elif not report["head_matched"] and a["seq"] == head["seq"] and a["link"] == head["link"]:
            report["anchors_to_declared_head"] += 1
            if a.get("proof"):
                report["anchor_proofs_on_declared_head"] = (
                    report.get("anchor_proofs_on_declared_head", 0) + 1)
        else:
            raise VError("anchor", f"anchor {i} matches no verified claim or the declared head")
        # A proof is only opened when its anchor matched a coordinate this verifier confirmed. A proof
        # over a declared head that leads the claims attests a link tied to nothing in the bundle, so
        # verifying it would let it reach "anchored (proof verified)", the strongest word the format
        # issues. It is reported separately and never counted.
        if not matched or not a.get("proof"):
            continue
        report["anchor_proofs_carried"] += 1
        # A carried proof used to be counted and never opened, so a bundle holding a real signed
        # timestamp was reported at the same strength as one holding a URL. The format has always
        # said an rfc3161 proof is checkable offline; this is where that becomes true.
        if a["type"] != "rfc3161":
            continue
        try:
            token = _b64(a["proof"])
        except Exception as exc:
            raise VError("anchor", f"anchor {i} proof is not base64: {exc}") from exc
        signed_at, signer = _verify_timestamp(token, a["link"], i)
        when = _beat_time(signed_at)
        # An attestation earlier than the entry it covers is a contradiction, not evidence: the token
        # commits to a link that is the hash of a claim carrying its own time, so an authority cannot
        # honestly have signed it first. Without this a producer running its own authority could sign
        # any hash with any date and still reach the strongest verdict the format issues. Both times
        # are whole microseconds, as the format compares them.
        skew = ANCHOR_SKEW_S * 1_000_000
        if a["seq"] in claim_at and signed_at < claim_at[a["seq"]] - skew:
            raise VError("anchor", f"anchor {i} attests {when} over entry {a['seq']}, before the "
                                   "entry it covers: a timestamp cannot precede the entry")
        report["anchor_proofs_verified"] += 1
        report["anchor_attestations"].append(f"{when} by {signer}")
    # True only when every proof the bundle carries was opened and held.
    report["anchor_proofs_validated"] = (
        report["anchor_proofs_carried"] > 0
        and report["anchor_proofs_verified"] == report["anchor_proofs_carried"])


# _EPOCH is the origin beat times are measured from. Measuring in whole microseconds from it, with
# integer arithmetic throughout, keeps every interval, threshold, and window count exactly what the
# Go verifier computes in its int64 microsecond counts.
_EPOCH = datetime(1970, 1, 1, tzinfo=timezone.utc)

# SPAN_MAX_CADENCE_S is the widest cadence a span claim may declare, the seconds in a 366-day year.
# Python integers do not wrap, but the bound is the format's, and a verifier with 64-bit integers
# needs it to keep every quantity the gap measurement forms in range, so this one refuses the same
# claims.
SPAN_MAX_CADENCE_S = 366 * 24 * 60 * 60


def _at_micros(ts, i):
    """Read a beat time to whole microseconds since the epoch for cadence measurement, with digits
    beyond the microsecond dropped, as the format measures beat times. The value is measured, never
    hashed."""
    try:
        return _parse_time(ts)
    except ValueError as exc:
        raise VError("span", f"span claim {i} at: {exc}") from exc


def _beat_time(micros):
    """Word a time in microseconds since the epoch as RFC 3339 UTC to the whole second, with the
    fraction dropped rather than rounded, the form a gap names its bounds in and a verified token
    names its signing time in."""
    at = _EPOCH + timedelta(seconds=micros // 1_000_000)
    return at.isoformat().replace("+00:00", "Z")


def _whole_seconds(micros):
    """Word a measured interval as whole seconds, rounded to the nearest with halves up, the one
    form every verifier prints for a gap."""
    return f"{(micros + 500_000) // 1_000_000}s"


def _check_span(b, report):
    """Verify loomseal.span/1 population attestations. A false count or a missing beat number is
    a contradiction and fails the bundle. Beats further apart than the declared cadence are gaps,
    reported with their bounds and never hidden: coverage is a measurement, not a badge."""
    spans = []
    chain = b.get("chain")
    # LoomSpan is defined over the linear profiles. Its beats carry a non-empty chain.prev and its
    # coverage requires contiguous beats, and the tree profile forbids both by design, so a span
    # claim in a tree bundle is refused rather than checked: a coverage answer the profile cannot
    # satisfy would mean nothing. The Go verifier refuses it the same way.
    tree = isinstance(chain, dict) and chain.get("profile") == MERKLE
    for i, c in enumerate(b["claims"]):
        if c.get("type") != "loomseal.span/1":
            continue
        report["span_present"] = True
        if tree:
            raise VError("span", f"claim {i} is a span claim, which the {MERKLE} profile does "
                                 "not carry")
        if "chain" not in b:
            raise VError("span", "span claims present without a chain declaration")
        if "chain" not in c:
            raise VError("span", f"span claim {i} has no chain coordinates")
        p = c["payload"]
        if p.get("stream") != "chain":
            raise VError("span", f"span claim {i} stream {p.get('stream')!r}: this format "
                                 "defines only 'chain'")
        cadence, beat, count = p.get("cadence_s"), p.get("beat"), p.get("count")
        if not _is_int(cadence) or not 1 <= cadence <= SPAN_MAX_CADENCE_S:
            raise VError("span", f"span claim {i} cadence_s {cadence!r}, want an integer from 1 "
                                 f"to {SPAN_MAX_CADENCE_S}")
        if not _is_int(beat) or beat < 1:
            raise VError("span", f"span claim {i} beat {beat!r}, want at least 1")
        if not _is_int(count) or count < 0:
            raise VError("span", f"span claim {i} count {count!r}, want at least 0")
        # A switchtender-audit-v1 link commits the path and not the span members beside it, so
        # under that profile the members are bound through the path they were written into.
        if b["chain"].get("profile") == SWITCHTENDER:
            variant = _case_variant(p, sorted(DECLARATION["types"]["loomseal.span/1"]))
            if variant:
                raise VError("span", f"span claim {i} carries {_quote(variant[0])}, which "
                                     f"differs from {variant[1]} only in case, so a reader that "
                                     "folds case would take one for the other")
            want = f"/span/{beat}?count={count}&cadence_s={cadence}"
            if p.get("path") != want:
                raise VError("span", f"span claim {i} members do not match the span path its link "
                                     f"commits: path {p.get('path')!r}, members read {want!r}")
            for member in ("stream", "beat", "count", "cadence_s"):
                _settle_declared(report, i, "loomseal.span/1", member)
        spans.append((p, c["chain"]["seq"], _at_micros(c["at"], i)))
    if not report["span_present"]:
        return
    report["span_beats"] = len(spans)

    # Beat 1 commits to every entry before it, so its count is arithmetic even when the bundle
    # opens mid-chain. A later first beat left its predecessor outside the window, so its count
    # is carried, never trusted.
    first_p, first_seq, _ = spans[0]
    if first_p["beat"] == 1:
        want = first_seq - 1
        if first_p["count"] != want:
            raise VError("span", f"span beat 1 counts {first_p['count']} entries before it, "
                                 f"its position shows {want}")
        report["span_counts_verified"] += 1
    else:
        report["span_counts_carried"] += 1

    missed = 0
    longest = 0
    for i in range(1, len(spans)):
        (pp, pseq, pat), (cp, cseq, cat) = spans[i - 1], spans[i]
        if cp["beat"] != pp["beat"] + 1:
            raise VError("span", f"span beat {cp['beat']} follows beat {pp['beat']}: a missing "
                                 "beat is a deleted window")
        want = cseq - pseq - 1
        if cp["count"] != want:
            raise VError("span", f"span beat {cp['beat']} counts {cp['count']} entries since "
                                 f"beat {pp['beat']}, the chain shows {want}")
        report["span_counts_verified"] += 1
        delta = cat - pat
        if delta <= 0:
            raise VError("span", f"span beat {cp['beat']} time does not advance past beat "
                                 f"{pp['beat']}")
        # The interval is measured against the cadence the earlier beat declares. A timer fires a
        # little late as a matter of course, so the format allows a scheduling slack of a hundredth
        # of the cadence and never under a second before an interval is a gap. This matches the Go
        # verifier's scheduleSlack.
        cadence = pp["cadence_s"] * 1_000_000
        if delta <= cadence + max(cadence // 100, 1_000_000):
            continue
        report["span_gaps"].append(
            f"unattested window of {_whole_seconds(delta)} between beat {pp['beat']} "
            f"({_beat_time(pat)}) and beat {cp['beat']} ({_beat_time(cat)})")
        longest = max(longest, delta)
        # A gap swallows the whole windows that fit in it, the interval in cadences rounded to the
        # nearest with halves up, less the window the arriving beat attests. Integer arithmetic,
        # because Python's round() takes halves to the even neighbor and the Go verifier does not.
        missed += max(0, (delta + cadence // 2) // cadence - 1)
    if longest:
        report["span_longest_gap"] = _whole_seconds(longest)
    report["span_coverage"] = f"{len(spans)}/{len(spans) + missed} windows attested"
    report["span_ok"] = True


def _within_dir(base, rel):
    """Report whether rel stays inside base once resolved lexically. A location is carried in the
    bundle, so it is attacker-controlled and must not reach outside the directory the verifier was
    pointed at. This matches the Go verifier's withinDir: an absolute path is refused, and the join
    is cleaned without resolving symlinks."""
    if os.path.isabs(rel):
        return False
    base_abs = os.path.abspath(base)
    full = os.path.abspath(os.path.join(base, rel))
    return full == base_abs or full.startswith(base_abs + os.sep)


def _check_evidence(b, evidence_dir, report):
    """Hash every supplied artifact and compare the bundle's digests against them. An artifact that
    was never supplied is a holder disclosing less than the whole set, which is allowed and counts as
    missing. An artifact sitting at its declared location whose bytes no longer hash to the sealed
    digest is a different thing entirely: it fails the bundle on its own ALTERED line. Counting both
    as missing let an altered artifact pass with a clean verdict, which is the defect the Go verifier
    fixed and this one now matches."""
    supplied = set()
    if evidence_dir:
        for root, _, files in os.walk(evidence_dir):
            for fn in files:
                path = os.path.join(root, fn)
                # Only regular files are hashed, so a symlink is never followed into the set,
                # matching the Go verifier, which hashes only regular directory entries.
                if os.path.islink(path) or not os.path.isfile(path):
                    continue
                with open(path, "rb") as fh:
                    supplied.add("sha256:" + hashlib.sha256(fh.read()).hexdigest())
    verified = missing = referenced = mismatched = 0
    seen_mismatch = set()
    for c in b["claims"]:
        for e in c.get("evidence", []):
            if not evidence_dir:
                referenced += 1
                continue
            if e["digest"] in supplied:
                verified += 1
                continue
            # location travels inside the bundle and is attacker-controlled, so it is followed only
            # when it stays within the evidence directory. A location that escapes, or names no
            # file, leaves the artifact counted as missing, which is not a failure.
            loc = e.get("location") or ""
            if loc and _within_dir(evidence_dir, loc) \
                    and os.path.exists(os.path.join(evidence_dir, loc)):
                # Several claims may rest on one artifact, so an altered artifact is reported once
                # rather than once per reference, matching the Go verifier's file count.
                if loc not in seen_mismatch:
                    seen_mismatch.add(loc)
                    mismatched += 1
                    report["problems"].append(
                        f"evidence {e.get('role', '')} at {loc} does not match its sealed digest "
                        f"{e['digest']}")
                continue
            missing += 1
    report["evidence"] = {"verified": verified, "missing": missing, "referenced": referenced,
                          "mismatched": mismatched}


def _level(report):
    if not report["signature_ok"]:
        return "not verified"
    level = "signed"
    if report["chain_present"] and report["chain_ok"]:
        # A tree recomputes everything, so "full" would tell a reader nothing; what it established is
        # membership in a log of a stated size, plus append-only growth when a consistency proof folded.
        # A linear chain is worded by the mode it reached. This mirrors the Go verifier's chainWording.
        if report.get("chain_profile") == MERKLE:
            wording = f"tree of {report.get('tree_size', 0)}"
            if report.get("consistency_ok"):
                wording += f", append-only from {report.get('consistency_from')}"
        else:
            wording = report["chain_mode"]
        level += f", chained ({wording})"
    # Anchored wording is reserved to a chain whose links were recomputed and bound to their claim
    # content, the full mode. A keyed chain is verified structurally only, so the producer chose
    # which link sits beside each claim and the verifier never tied the anchored link to the
    # content; granting it the anchored level would let a real token be laundered onto an invented
    # keyed entry or an unkeyed anchored chain be re-presented as keyed to alter a payload. The
    # merkle profile reports full mode, so it keeps anchoring. This mirrors the Go verifier.
    fully_chained = (report["chain_present"] and report["chain_ok"]
                     and report.get("chain_mode") == "full")
    anchored = fully_chained and (report["anchor_proofs_verified"] > 0
                                  or report["anchors_matched"] > 0)
    if fully_chained and report["anchor_proofs_verified"] > 0:
        # A proof checked here needed no network and no trust in the producer, which is a stronger
        # statement than a reference a relying party still has to go and confirm.
        level += ", anchored (proof verified)"
    elif fully_chained and report["anchors_matched"] > 0:
        level += ", anchored by reference"
    # Spanned sits above anchored: a population commitment is only worth the anchoring under it.
    if anchored and report["span_present"] and report["span_ok"]:
        level += ", spanned"
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
        # A malformed document is not verified, which is a different verdict from unsupported.
        if check == "parse" and r["unsupported"]:
            return f"parse case was judged unsupported: {r['problems']}"
    elif check == "chain":
        if not r["chain_present"] or r["chain_ok"]:
            return (f"chain case did not fail the chain: present {r['chain_present']} "
                    f"ok {r['chain_ok']}")
    elif check == "anchor":
        if not r["signature_ok"] or not r["chain_ok"]:
            return "anchor case failed earlier than the anchor step"
        if not any("anchor" in p for p in r["problems"]):
            return f"anchor case did not fail on an anchor: matched {r['anchors_matched']}"
    elif check == "span":
        if not r["signature_ok"] or not r["chain_ok"]:
            return "span case failed earlier than the span step"
        if not r["span_present"] or r["span_ok"] or not any("span" in p for p in r["problems"]):
            return f"span case did not fail on a span check: {r['problems']}"
    elif check == "disclosure":
        if not r["signature_ok"]:
            return "disclosure case failed before the signature"
        if not r["disclosures_present"] or not any("disclosure" in p for p in r["problems"]):
            return f"disclosure case did not fail on a disclosure: {r['problems']}"
    elif check == "attestation":
        if not r["signature_ok"]:
            return "attestation case failed before the signature"
        present = r["attestations_present"] or bool(r.get("head_attestations_verified") is not None
                                                    and (r.get("head_attestors") or
                                                         any("head attestation" in p for p in r["problems"])))
        if not present or not any("attestation" in p for p in r["problems"]):
            return f"attestation case did not fail on an attestation: {r['problems']}"
    elif check == "evidence":
        if not r["signature_ok"] or not r["chain_ok"]:
            return "evidence case failed earlier than the evidence check"
        mismatched = (r.get("evidence") or {}).get("mismatched", 0)
        if not mismatched or not any(p.startswith("evidence ") for p in r["problems"]):
            return f"evidence case did not fail on an altered artifact: {r['problems']}"
    elif check == "record":
        if not r["signature_ok"] or not r["chain_ok"]:
            return "record case failed earlier than the record check"
        if not any(p.startswith("record:") for p in r["problems"]):
            return f"record case did not fail on a disclosed record: {r['problems']}"
    elif check == "install":
        if not r["signature_ok"] or not r["chain_ok"]:
            return "install case failed earlier than the install check"
        if not any(p.startswith("install") for p in r["problems"]):
            return f"install case did not fail on the install check: {r['problems']}"
    elif check == "unsupported":
        if not r.get("unsupported"):
            return f"unsupported case did not set the unsupported verdict: {r['problems']}"
        if r["signature_ok"]:
            return "unsupported case judged the signature"
    else:
        return f"manifest names an unknown failing_check {check!r}"
    return None


def _faulted(r):
    """Report whether report r records a fault in this verifier rather than a verdict on the input.
    Refusing a vector because the verifier broke is not agreement with a verifier that refused it
    for a reason."""
    return any(p.startswith("verifier:") for p in r["problems"])


def run_vectors(dirpath):
    """Run every vector in a manifest and report agreement with its declared expectations."""
    man = json.load(open(os.path.join(dirpath, "manifest.json")))
    bad = 0
    for v in man["vectors"]:
        raw = open(os.path.join(dirpath, v["file"]), "rb").read()
        # A case that names evidence is checked with the vectors directory as its evidence directory.
        r = verify(raw, dirpath if v.get("evidence") else None)
        ok = r["ok"]
        status = "OK " if ok == v["must_verify"] else "!! "
        detail = ""
        # The level is pinned for every vector: the wording achieved when the bundle verifies, and
        # "not verified" or "unsupported" when it does not, so a failing report never names a level
        # it reached partway.
        if v.get("level") and r["level"] != v["level"]:
            status, detail = "!! ", f"  level got[{r['level']}] want[{v['level']}]"
        # The states of the disclosed members are part of the verdict a vector pins, and a bundle
        # that does not verify lists none.
        for state, want in (("unchecked", v.get("unchecked") or []),
                            ("redacted", v.get("redacted") or [])):
            got = [f"claim {d['claim']} {d['member']}" for d in r["disclosed"]
                   if d["state"] == state]
            if got != want:
                status, detail = "!! ", f"  {state} got{got} want{want}"
        # A bundle that does not verify lists no disclosed member in any state, checked ones
        # included, and counts none unchecked.
        if not v["must_verify"] and (r["disclosed"] or r["disclosed_unchecked"]):
            status = "!! "
            detail = (f"  failed bundle lists {len(r['disclosed'])} disclosed members and "
                      f"{r['disclosed_unchecked']} unchecked records")
        if status == "OK " and ok and v["must_verify"]:
            if r["legacy_records"] != (v.get("legacy") or []):
                status = "!! "
                detail = f"  legacy got{r['legacy_records']} want{v.get('legacy') or []}"
            # A subject type outside the vocabulary is reported by name, and one inside it is not.
            unknown = r.get("unknown_subject_type") or ""
            if unknown != (v.get("unknown_subject_type") or ""):
                status = "!! "
                detail = (f"  unknown_subject_type got[{unknown}] "
                          f"want[{v.get('unknown_subject_type') or ''}]")
            # A gap is measured one way, so the coverage line, the longest gap, and each gap's
            # wording are part of the verdict a spanned vector pins.
            for key, empty in (("span_coverage", ""), ("span_longest_gap", ""),
                               ("span_gaps", [])):
                want = v.get(key) or empty
                if r[key] != want:
                    status = "!! "
                    detail += f"  {key} got {r[key]!r} want {want!r}"
            # The signer is named by one rule, so each verified token's time and signer line is
            # part of the verdict a vector pins.
            want = v.get("anchor_attestations") or []
            if r["anchor_attestations"] != want:
                status = "!! "
                detail += f"  anchor_attestations got {r['anchor_attestations']!r} want {want!r}"
        if status == "OK " and not v["must_verify"] and v.get("failing_check"):
            why = failing_check_error(v["failing_check"], r)
            if why:
                status, detail = "!! ", f"  {why}"
        if _faulted(r):
            status, detail = "!! ", f"  verifier fault: {r['problems']}"
        if status == "!! ":
            bad += 1
        print(f"{status}{v['name']:<28} ok={ok} expect={v['must_verify']}{detail}")
    print(f"\n{'ALL MATCH' if bad == 0 else str(bad) + ' MISMATCH'}")
    return 1 if bad else 0


def _is_presentation(raw_bytes):
    """Report whether raw is a holder presentation rather than a bundle, by the presence of the
    presentation version member under its exact name. Mirrors the Go LooksLikePresentation. It
    reads the document on the stack verify runs on, so a deeply nested presentation is still
    recognized as one."""
    return _on_deep_stack(_looks_like_presentation, raw_bytes)


def _looks_like_presentation(raw_bytes):
    """Report whether raw parses to an object carrying a presentation version member."""
    try:
        d = parse_strict(raw_bytes)
    except (VError, RecursionError, ValueError):
        return False
    version = d.get("loomseal_presentation") if isinstance(d, dict) else None
    return isinstance(version, str) and version != ""


# _PRESENTATION_MEMBERS and _HOLDER_MEMBERS are the members a presentation and its holder carry,
# matched by exact name, as the Go verifier matches them. A member outside them, a case variant of a
# known one included, is refused, so no reader can be shown one value while a verifier read another.
_PRESENTATION_MEMBERS = {"audience", "bundle", "created_at", "holder", "loomseal_presentation",
                         "nonce", "sig"}
_HOLDER_MEMBERS = {"alg", "key_id", "public_key"}


def _presentation_problem(p):
    """Say why a parsed presentation's members are not the exact set, or the strings, the format
    defines, or return None. Mirrors the Go parsePresentation."""
    if not isinstance(p, dict):
        return "a presentation is a JSON object"
    extra = sorted(set(p) - _PRESENTATION_MEMBERS)
    if extra:
        return f"presentation carries an unknown member {json.dumps(extra[0], ensure_ascii=False)}"
    holder = p.get("holder", {})
    if not isinstance(holder, dict):
        return "presentation holder is not an object"
    extra = sorted(set(holder) - _HOLDER_MEMBERS)
    if extra:
        return ("presentation holder carries an unknown member "
                f"{json.dumps(extra[0], ensure_ascii=False)}")
    for obj, names in ((p, ("loomseal_presentation", "created_at", "audience", "nonce", "sig")),
                       (holder, ("key_id", "public_key", "alg"))):
        for name in names:
            if name in obj and not isinstance(obj[name], str):
                return f"presentation member {name} is not a string"
    return None


def verify_presentation(raw_bytes, audience=None, nonce=None, evidence_dir=None):
    """Verify a holder presentation: the embedded bundle, the holder signature over the presented
    bundle bound to the audience and nonce, and the optional audience and nonce pins. Mirrors the Go
    RunPresentation.

    None means no expectation. An audience or nonce passed as "" is an expectation that compares
    against nothing, so it is refused before anything is verified, in the wording the browser
    module uses, rather than read as none and the replay defense skipped under a checked verdict."""
    return _on_deep_stack(_verify_presentation, raw_bytes, audience, nonce, evidence_dir)


def _verify_presentation(raw_bytes, audience, nonce, evidence_dir):
    """Run the presentation checks and build the report, on the stack verify runs on. A fault in
    this verifier itself lands in the report as a problem, never as a traceback."""
    report = {"ok": False, "presentation_ok": False, "problems": [], "bundle": None}
    for member, expected in (("audience", audience), ("nonce", nonce)):
        if expected == "":
            report["problems"].append(f"{member}: {EMPTY_EXPECTATION}")
            return report
    try:
        return _presentation_checks(raw_bytes, audience, nonce, evidence_dir, report)
    except Exception as exc:
        report["ok"] = False
        report["problems"].append(f"verifier: {type(exc).__name__}: {exc}")
        return report


def _presentation_checks(raw_bytes, audience, nonce, evidence_dir, report):
    """Fill report with the presentation checks and return it."""
    try:
        p = parse_strict(raw_bytes)
    except VError as e:
        report["problems"].append(f"parse: {e.msg}")
        return report
    why = _presentation_problem(p)
    if why:
        report["problems"].append(f"parse: {why}")
        return report
    if p.get("loomseal_presentation") != "0.1":
        report["problems"].append("parse: not a loomseal presentation 0.1")
        return report
    report["audience"], report["nonce"] = p.get("audience"), p.get("nonce")
    report["created_at"] = p.get("created_at")
    bundle_obj = p.get("bundle")
    try:
        bundle_bytes = canon(bundle_obj)
    except VError as e:
        report["problems"].append(f"parse: {e.msg}")
        return report
    report["bundle"] = verify(bundle_bytes, evidence_dir)
    try:
        _check_presentation_sig(p, bundle_obj, report)
    except VError as e:
        report["problems"].append(f"{e.check}: {e.msg}")
    if audience is not None:
        m = p.get("audience") == audience
        report["audience_match"] = m
        if not m:
            report["problems"].append("presentation audience does not match the expected")
    if nonce is not None:
        m = p.get("nonce") == nonce
        report["nonce_match"] = m
        if not m:
            report["problems"].append("presentation nonce does not match the expected challenge")
    report["ok"] = (not report["problems"] and report["presentation_ok"]
                    and report["bundle"] is not None and report["bundle"]["ok"])
    return report


def _check_presentation_sig(p, bundle_obj, report):
    """Verify the holder key self-description and the signature over the canonical binding of audience,
    presented-bundle digest, time, and nonce."""
    holder = p.get("holder") or {}
    if holder.get("alg") != "ed25519":
        raise VError("presentation", "holder alg is not ed25519")
    try:
        pub = _b64(holder.get("public_key", ""))
    except Exception:
        raise VError("presentation", "holder public_key is not base64")
    if len(pub) != 32:
        raise VError("presentation", "holder public_key is not a 32 byte ed25519 key")
    if _key_id(pub) != holder.get("key_id"):
        raise VError("presentation", "holder key_id does not match the embedded public key")
    if not _is_time(p.get("created_at")):
        raise VError("presentation", "presentation created_at is not a UTC time of the form "
                                     "YYYY-MM-DDTHH:MM:SS[.fraction]Z")
    bundle_sha = hashlib.sha256(canon(bundle_obj)).hexdigest()
    preimage = canon({"loomseal": "presentation/1",
                      "audience": p.get("audience", ""), "bundle_sha256": bundle_sha,
                      "created_at": p.get("created_at", ""), "nonce": p.get("nonce", "")})
    try:
        sig = _b64(p.get("sig", ""))
    except Exception:
        raise VError("presentation", "holder signature is not base64")
    try:
        Ed25519PublicKey.from_public_bytes(pub).verify(sig, preimage)
    except Exception:
        raise VError("presentation", "holder signature does not verify over the presented bundle")
    report["presentation_ok"] = True
    report["holder_key_id"] = _key_id(pub)


def run_presentations(dirpath):
    """Run every presentation vector in a manifest and report agreement with its expectations."""
    man = json.load(open(os.path.join(dirpath, "presentations.json")))
    bad = 0
    for v in man["vectors"]:
        raw = open(os.path.join(dirpath, v["file"]), "rb").read()
        # An absent member is no expectation and an empty one is an expectation supplied empty, so
        # the two are passed as None and "" and never folded together.
        r = verify_presentation(raw, v.get("expect_audience"), v.get("expect_nonce"))
        ok = r["ok"]
        status = "OK " if ok == v["must_verify"] else "!! "
        detail = ""
        if _faulted(r) or (r["bundle"] is not None and _faulted(r["bundle"])):
            status, detail = "!! ", "  verifier fault"
        # An expectation supplied empty is refused by name before anything is verified, so a case
        # that carries one fails for that reason and no other.
        for member in ("audience", "nonce"):
            if v.get("expect_" + member) == "":
                if r["problems"] != [f"{member}: {EMPTY_EXPECTATION}"]:
                    status = "!! "
                    detail = f"  empty {member} was not refused: {r['problems']}"
                break
        if status == "!! ":
            bad += 1
        print(f"{status}{v['name']:<28} ok={ok} expect={v['must_verify']}{detail}")
    print(f"\n{'ALL MATCH' if bad == 0 else str(bad) + ' MISMATCH'}")
    return 1 if bad else 0


def main(argv):
    if len(argv) >= 3 and argv[1] == "--vectors":
        return run_vectors(argv[2])
    if len(argv) >= 3 and argv[1] == "--presentations":
        return run_presentations(argv[2])
    if len(argv) >= 2 and _is_presentation(open(argv[1], "rb").read()):
        raw = open(argv[1], "rb").read()
        report = verify_presentation(raw, evidence_dir=argv[2] if len(argv) > 2 else None)
        print(json.dumps(report, indent=2))
        return 0 if report["ok"] else 1
    if len(argv) < 2:
        print("usage: loomverify.py <bundle.json> [evidence_dir] | --vectors <dir>")
        return 2
    report = verify(open(argv[1], "rb").read(), argv[2] if len(argv) > 2 else None)
    print(json.dumps(report, indent=2))
    if report["ok"]:
        return 0
    return 3 if report.get("unsupported") else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
