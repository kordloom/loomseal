# LoomSeal: The KordLoom Attestation Format

Status: v0.1 draft, 2026-07-27. This file is the canonical LoomSeal specification. The
machine-readable schema is schema/loomseal-bundle.schema.json. The name is the claim: a seal
does not prevent tampering, it reveals it, and that is exactly what verification checks.

LoomSeal is one portable document shape for proof. A LoomSeal bundle carries claims about what a system
did, the evidence digests behind those claims, the hash-chain coordinates that fix each claim in
an append-only history, the external anchors that fix that history in time, and a signature from
the producer. A third party verifies a bundle offline with an open verifier, without trusting
KordLoom and without contacting KordLoom.

KordLoom products speak it, one verifier checks it:

- SwitchTender proves what you run.
- Dormouse proves what you watch.
- Future products register new claim types and inherit the same verifier.

This spec generalizes what Dormouse and SwitchTender already do in shipped code. It invents no
new cryptography. Dormouse chains checks with a keyed HMAC-SHA256 and content-addresses every
snapshot. SwitchTender chains audit entries with SHA-256 and already exports the chain signed
with ed25519 for offline verification. LoomSeal is the shared envelope around those primitives.

## Design rules

1. Offline verification. A bundle plus the open verifier is sufficient. No server calls, no
   account, no KordLoom involvement.
2. One file. A bundle is a single JSON document. Evidence artifacts may travel beside it or stay
   home; the bundle carries their digests either way.
3. Boring cryptography only. SHA-256, HMAC-SHA256, ed25519. Nothing exotic, no blockchain, no
   consensus, no tokens.
4. Deterministic. Same bundle, same verifier, same verdict, forever.
5. Honest claims. The format documents exactly what verification proves and what it cannot
   prove. Tamper-evident, not tamper-proof. See "What a bundle proves."
6. Shipped reality wins. Where this spec and released product behavior diverge, the product is
   the reference for its own chain profile and the spec updates.

## The bundle

A bundle is a JSON object with these members:

| Member       | Required | Purpose                                              |
|--------------|----------|------------------------------------------------------|
| `loomseal`       | yes      | Format version, `"0.1"`                              |
| `bundle_id`  | yes      | Producer-assigned identifier for this bundle         |
| `created_at` | yes      | RFC 3339 UTC time the bundle was assembled           |
| `producer`   | yes      | Who emitted it: product, version, install, key       |
| `subject`    | yes      | What the claims are about                            |
| `chain`      | no       | Chain profile, parameters, and head (level 2 and up) |
| `claims`     | yes      | The claims, each with payload, evidence, chain coords|
| `anchors`    | no       | External anchor records (level 3)                    |
| `signatures` | yes      | At least one producer signature over the bundle      |

Example, a Dormouse bundle at level 3 (digests are illustrative):

```json
{
  "loomseal": "0.1",
  "bundle_id": "lsb_9c41d0a2b7e3",
  "created_at": "2026-07-27T15:04:05Z",
  "producer": {
    "product": "dormouse",
    "product_version": "0.4.0",
    "install_id": "in_7f3a9b2c",
    "public_key": "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=",
    "key_id": "sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
  },
  "subject": {
    "type": "url",
    "id": "https://vendor.example.com/legal/subprocessors"
  },
  "chain": {
    "profile": "dormouse-audit-chain-v2",
    "keyed": true,
    "params": { "install_id": "in_7f3a9b2c" },
    "head": {
      "seq": 18211,
      "link": "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9"
    }
  },
  "claims": [
    {
      "type": "dormouse.check/1",
      "at": "2026-07-27T14:00:11Z",
      "payload": {
        "target_id": "tg_4b1e",
        "url": "https://vendor.example.com/legal/subprocessors",
        "outcome": "changed",
        "status": 200,
        "elapsed_ns": 412000000,
        "error": ""
      },
      "evidence": [
        {
          "role": "snapshot",
          "digest": "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "media_type": "text/html",
          "present": false
        }
      ],
      "verdict": {
        "policy": "vendor-subprocessors/3",
        "policy_digest": "sha256:7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730",
        "decision": "notify",
        "detail": "entity added: Example Analytics GmbH"
      },
      "chain": {
        "seq": 18209,
        "prev": "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456",
        "link": "6b23c0d5f35d1b11f9b683f0b0a617355deb11277d91ae091d399c655b87940d"
      }
    }
  ],
  "anchors": [
    {
      "type": "git",
      "seq": 18000,
      "link": "1f2d3c4b5a69788766554433221100ffeeddccbbaa99887766554433221100ff",
      "at": "2026-07-26T00:00:00Z",
      "ref": "https://github.com/acme/dormouse-anchors/commit/8f14e45fceea167a"
    }
  ],
  "signatures": [
    {
      "key_id": "sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
      "alg": "ed25519",
      "sig": "yA8leGOa8kM8y7yQ2P1cCcieJfNDpDbIcrXYRlpn0P5cAOSYyzOxs2Yr1JhBpVL8..."
    }
  ]
}
```

## Canonical form and digests

The canonical form of a bundle is the RFC 8785 (JSON Canonicalization Scheme) serialization of
the bundle object. Object keys are ordered by their UTF-16 code units, which RFC 8785 requires
and which differs from code point order above the basic multilingual plane. Strings must be
valid UTF-8, and every `\u` escape must denote a valid Unicode scalar value. A lone surrogate,
whether written as a `\uD800`-through-`\uDFFF` escape or as raw bytes, is rejected at parse and
never coerced to the replacement character; coercion would let two different documents share one
canonical form and one signature. Digest strings are `sha256:` followed by 64 lowercase hex
characters. Times are RFC 3339 in UTC; fractional seconds are allowed where a chain profile
requires them. Numbers in a bundle are written as plain integer literals with absolute value at
most 2^53; fractions, exponents, and larger magnitudes are invalid, because RFC 8785 serializes
numbers as IEEE doubles and those forms do not round-trip.

## Producer and signatures

`producer.public_key` is the producer's raw 32-byte ed25519 public key, base64 standard
encoding. `producer.key_id` is `sha256:` over those raw key bytes. The signing key is generated
at product initialization and never leaves the install; the public key and its `key_id`
fingerprint belong on the operator's trust page so relying parties can pin them out of band.

A signature is computed over the canonical form of the bundle with `signatures` set to the empty
array. `sig` is the base64 ed25519 signature. A bundle carries at least one signature whose
`key_id` matches `producer.key_id`. Verifiers compare `key_id` against a pinned fingerprint when
the caller provides one.

SwitchTender's existing signed audit export uses hex-encoded keys; its LoomSeal emitter re-encodes
the same key as base64. Same key, same trust, one envelope.

Signature entries carry an `alg` field so the format can adopt new algorithms without a new
envelope. The chains and evidence digests rest on SHA-256 and HMAC-SHA256, which known quantum
algorithms do not meaningfully weaken. The ed25519 signature is the component a large future
quantum computer would break; a later format version adds a NIST-standardized post-quantum
signature algorithm beside it. External anchoring already bounds that risk: a signature forged
years from now cannot rewrite history whose heads were anchored outside the producer's control
before such forgery was possible.

## Chain profiles

A chain fixes claims in an append-only order. Products already have chains with different
constructions, so LoomSeal names each construction as a profile and the verifier implements the
profiles. A bundle declares one profile in `chain.profile`. Claims carry `chain.seq`,
`chain.prev`, and `chain.link`. Claims in a bundle are sorted by ascending `seq` and must be
contiguous; discontinuous history means separate bundles.

### dormouse-audit-chain-v2

The shipped Dormouse construction. Each check's link is HMAC-SHA256 (keyed) or SHA-256 (unkeyed)
over a length-prefixed field list: the domain string `dormouse-audit-chain-v2`, the install
identifier, the previous link, then the check's target id, outcome, status, snapshot hash,
error, elapsed nanoseconds, and checked-at Unix nanoseconds. Each field is serialized as
`length:value`, so field boundaries are unambiguous. The genesis previous link is the empty
string. Sequence numbers are the 1-based trail position, matching the product's position-based
head anchoring.

The keyed form is by design not recomputable by third parties: the chain key is the secret that
prevents forgery by parties who can write the database. Relying parties verify keyed chains
structurally (each claim's `prev` equals the prior claim's `link`) and against anchors. The
operator, holding the key, verifies fully with `dormouse verify`.

### switchtender-audit-v1

The shipped SwitchTender construction. Each audit entry's link is SHA-256 over the JSON array of
its sequence (decimal string), time (RFC 3339 with nanoseconds, UTC), actor, method, path, and
previous link. Sequence starts at 1; the genesis previous link is the empty string. This profile
is unkeyed: any verifier recomputes every link from the claim payloads alone. Recomputation
formats the parsed time back to RFC 3339 nanosecond form in UTC, which round-trips the stored
form exactly.

### loomseal-chain-v1

The generic profile for future producers, Burler included. The claim digest is `sha256:` over
the canonical form of the claim object with its `chain` member removed. The link is HMAC-SHA256
(keyed) or SHA-256 (unkeyed) over the canonical form of:

```json
{ "domain": "loomseal-chain-v1", "install_id": "...", "seq": 1, "prev": "", "claim": "sha256:..." }
```

Keyed chains state `"keyed": true` in the bundle's `chain` member.

## Anchors

An anchor fixes a chain link in time, in a place the producer cannot rewrite alone. An anchor
record carries the anchored `seq` and `link`, the anchor time, a `ref` locating the anchor, and
optionally an embedded `proof`.

| Type      | Ref                                    | Offline proof                        |
|-----------|----------------------------------------|--------------------------------------|
| `rfc3161` | Timestamp authority name or URL        | Yes, the embedded token over the link|
| `git`     | Commit URL in a repository not ours    | By reference, relying party fetches  |
| `https`   | Published head URL with retrieval date | By reference                         |
| `rekor`   | Transparency log entry                 | Planned, not in v0.1                 |

The verifier checks that each anchor's `seq` and `link` match a claim in the bundle or the
declared head. Verifier v0.1 reports embedded `rfc3161` tokens as carried without validating
them; token validation lands in v0.2, and until then the report says anchored by reference and
the relying party confirms the ref out of band. Anchoring cadence bounds the
window in which a compromised producer key could rewrite unanchored history; anchor often.

## Conformance levels

| Level | Name     | Meaning                                                            |
|-------|----------|--------------------------------------------------------------------|
| 1     | Signed   | Valid producer signature over the canonical bundle                 |
| 2     | Chained  | Claims linked in a declared profile, continuity verifies           |
| 3     | Anchored | At least one verified anchor binds the chain outside the producer  |

Level 2 verification is full for unkeyed profiles (every link recomputed) and structural for
keyed profiles (continuity of `prev` to `link`, with full verification reserved to the key
holder). The verifier's report names which form it performed. Marketing language maps one to
one: signed, chained, anchored. No other adjectives.

## Verification

The verifier performs these steps in order and fails closed:

1. Parse the document, require `loomseal` version `0.1`, validate against the schema.
2. Reconstruct the canonical form with `signatures` emptied and verify at least one signature
   against `producer.public_key`. If the caller pinned a fingerprint, require `key_id` match.
3. If `chain` is present: require claims sorted, contiguous, and profile known. Recompute every
   link for unkeyed profiles; check continuity for keyed profiles.
4. For each anchor: match its coordinates to the bundle, verify embedded proofs, report the
   anchor set with times and refs.
5. For each evidence artifact supplied to the verifier: recompute its digest and compare.
   Evidence not supplied is reported as referenced, not checked, never as verified.
6. Report the conformance level achieved and an overall verdict. Any failed check fails the
   bundle.

Who can verify what:

| Role          | Holds                       | Can verify                                     |
|---------------|-----------------------------|------------------------------------------------|
| Operator      | Database, chain key         | Everything, via the product's own verify       |
| Relying party | Bundle, verifier, no secrets| Signature, digests, unkeyed links, continuity, |
|               |                             | anchors                                        |
| Public        | Published heads only        | Head existence and consistency over time       |

## Claim types

Claim types are namespaced `product.kind/major`. The payload of each type is owned by the
emitting product and documented there; this registry fixes the names and required minimums.

| Type                   | Emitted by   | Status   | Payload minimum                       |
|------------------------|--------------|----------|---------------------------------------|
| `dormouse.check/1`     | Dormouse     | v0.1     | target_id, url, outcome, status       |
| `dormouse.change/1`    | Dormouse     | draft    | target_id, url, from and to snapshots |
| `dormouse.coverage/1`  | Dormouse     | draft    | target_id, window, expected, performed|
| `switchtender.audit/1` | SwitchTender | v0.1     | actor, method, path                   |
| `switchtender.run/1`   | SwitchTender | draft    | run id, kind, hosts, approver         |

New types enter by change to this registry. Product namespaces belong to their products. A
breaking payload change bumps the major suffix; verifiers ignore types they do not know and say
so in the report.

A claim may carry a `verdict`: the deterministic policy judgment recorded at detection time,
with the policy name, the policy definition digest, and the decision. In v0.1 the verifier
attests the verdict fields and digests; recomputing verdicts from policy plus inputs is future
work and out of scope here.

## What a bundle proves, and what it does not

A verified level 3 bundle proves: the producer holding the signing key assembled these claims;
the claims sit in an append-only order that has not been reordered or rewritten since the
anchored moments; the evidence digests match any artifacts presented; the anchored history
predates the anchor times.

It does not prove: that the producer observed the world honestly at capture time (a chain fixes
the record, not the honesty of the recorder); that a keyed chain is internally valid without the
key (that verification belongs to the key holder); anything about entries created and rewritten
between anchors by an attacker holding both the database and the chain key (cadence bounds this
window). State these limits plainly everywhere the format is described. The credibility of the
whole house rests on never claiming more than the verifier checks.

## Media type and file names

Media type `application/vnd.kordloom.loomseal+json`. File name `<subject>-<date>.loomseal.json`. A
bundle with sidecar evidence travels as a directory or archive; the bundle stays one file.

## Compatibility

A bundle may be wrapped in a DSSE envelope with payload type
`application/vnd.kordloom.loomseal+json` for tooling that expects DSSE. Mapping claims onto in-toto
attestation predicates is possible later and deliberately not part of v0.1.

