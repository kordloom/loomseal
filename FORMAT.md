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
- Future products register new claim types and inherit the same verifier.

This spec generalizes constructions KordLoom already ships. It invents no new cryptography.
SwitchTender chains audit entries with SHA-256 and already exports the chain signed with
ed25519 for offline verification. LoomSeal is the shared envelope around those primitives.

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

Example, a bundle at level 3 on the generic profile (digests are illustrative):

```json
{
  "loomseal": "0.1",
  "bundle_id": "lsb_9c41d0a2b7e3",
  "created_at": "2026-07-27T15:04:05Z",
  "producer": {
    "product": "switchtender",
    "product_version": "1.33.0",
    "install_id": "in_7f3a9b2c",
    "public_key": "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=",
    "key_id": "sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
  },
  "subject": {
    "type": "host",
    "id": "web-07.fleet.example.com"
  },
  "chain": {
    "profile": "loomseal-chain-v1",
    "keyed": true,
    "params": { "install_id": "in_7f3a9b2c" },
    "head": {
      "seq": 18211,
      "link": "fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9"
    }
  },
  "claims": [
    {
      "type": "switchtender.audit/1",
      "at": "2026-07-27T14:00:11Z",
      "payload": {
        "actor": "u_4b1e",
        "method": "POST",
        "path": "/api/jobs/deploy-web",
        "outcome": "applied",
        "elapsed_ns": 412000000,
        "error": ""
      },
      "evidence": [
        {
          "role": "transcript",
          "digest": "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
          "media_type": "application/json",
          "present": false
        }
      ],
      "verdict": {
        "policy": "fleet-change-control/3",
        "policy_digest": "sha256:7d865e959b2466918c9863afca942d0fb89d7c9ac0c99bafc3749504ded97730",
        "decision": "notify",
        "detail": "changed hosts: 4 of 210"
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
      "ref": "https://github.com/acme/audit-anchors/commit/8f14e45fceea167a"
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
and which differs from code point order above the basic multilingual plane. Object keys must be
unique within an object; a repeated key has no canonical form and the bundle is rejected. Strings
must be valid UTF-8, and every `\u` escape must denote a valid Unicode scalar value. A lone surrogate,
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
array. That replacement happens on the parsed document, which is then re-canonicalized; it is not
a textual edit, and a document whose `signatures` member is absent is not a bundle. `sig` is the
base64 ed25519 signature. A bundle carries at least one signature whose `key_id` matches
`producer.key_id`. Verifiers compare `key_id` against a pinned fingerprint when the caller
provides one.

Emptying `signatures` before signing puts the whole array, including each entry's `alg` and
`key_id`, outside the signed bytes. Everything else, including `chain.profile` and every anchor,
is inside them. So `alg` is a label, never a dispatch key: a verifier MUST NOT choose an
algorithm by reading it. Format 0.1 fixes ed25519 for signatures and SHA-256 for links and
digests, and a verifier rejects any signature entry that declares otherwise rather than
following it. Selecting an algorithm from an attacker-controlled field is how signature formats
get downgraded, and the field an attacker can rewrite for free is exactly the wrong place to
look.

SwitchTender's existing signed audit export uses hex-encoded keys; its LoomSeal emitter re-encodes
the same key as base64. Same key, same trust, one envelope.

A later format version can adopt new algorithms, but it names them somewhere the signature
covers, such as a new chain profile or a version bump, rather than by widening what `alg` is
allowed to say. The chains and evidence digests rest on SHA-256 and HMAC-SHA256, which known quantum
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

`chain.head` records the newest coordinates the producer attests for the whole chain, which may
lead the claims a bundle carries: a bundle is a window into a longer history. When the head
sequence equals the newest bundled claim, the verifier confirms the head link against that claim
and reports the head as matched. When the head leads the claims, its link cannot be recomputed
from the bundle and stays unverified; the report says so and does not treat that head as proof of
anything beyond the window.

### switchtender-audit-v1

The shipped SwitchTender construction. Each audit entry's link is SHA-256 over the compact JSON
array, no insignificant whitespace, of six strings: its sequence as a decimal string, the time,
actor, method, path, and previous link. Sequence starts at 1; the genesis previous link is the
empty string. This profile is unkeyed: any verifier recomputes every link from the claim payloads
alone.

The time is the claim's `at` **exactly as it appears in the bundle**. A verifier hashes those bytes
and must not parse the value and re-serialize it. A producer writes `at` in UTC, RFC 3339, ending in
`Z`, with trailing zeros in the fractional part trimmed and the fractional part and its dot omitted
entirely when the fraction is zero, so an `at` of `2026-07-27T15:00:00Z` is stored and hashed as
`2026-07-27T15:00:00Z`. A verifier still rejects an `at` that is not well-formed RFC 3339 UTC; it
simply never rewrites a well-formed one.

Hashing the stored bytes is normative, not an optimization, and earlier wording that described the
time as carrying nanosecond precision invited the opposite reading. A verifier that parsed the value
into its language's time type and formatted it back was performing an identity only if that type
could hold every digit written. Go's `time.Time` can. Python's `datetime` carries microseconds and
JavaScript's `Date` carries milliseconds, so a nanosecond timestamp lost digits and recomputed a
different link. The two reference verifiers shipped in this repository disagreed about the same
valid bundle, and the failure surfaced as a broken chain, which reads as tampering when nothing has
been tampered with. Hashing the stored bytes removes that class of failure and lets this profile be
implemented in a language with no nanosecond-capable clock.

### loomseal-chain-v1

The generic profile for new producers. The claim digest is `sha256:` over
the canonical form of the claim object with its `chain` member removed. The link is HMAC-SHA256
(keyed) or SHA-256 (unkeyed) over the canonical form of:

```json
{ "domain": "loomseal-chain-v1", "install_id": "...", "seq": 1, "prev": "", "claim": "sha256:..." }
```

Keyed chains state `"keyed": true` in the bundle's `chain` member.

The keyed form is by design not recomputable by third parties: the chain key is the secret that
prevents forgery by a party who can write the underlying store. Relying parties verify keyed
chains structurally, checking that each claim's `prev` equals the prior claim's `link`, and
against anchors. The operator, holding the key, verifies fully.

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

The verifier checks that each anchor's `seq` and `link` match a coordinate it verified: a claim
in the bundle, or the head when the head tied to the newest claim. An anchor that matches only a
declared head beyond the bundled claims is reported, but because that head link is unverified the
anchor binds nothing the verifier confirmed and does not by itself earn the anchored level. An
anchor that matches no verified coordinate fails the bundle. An anchor type the verifier cannot
validate offline, such as `git`, `https`, or `rekor`, is matched by coordinates only and reports
as anchored by reference, leaving the relying party to confirm the ref out of band. Anchoring
cadence bounds the window in which a compromised producer key could rewrite unanchored history;
anchor often.

A verifier checks an `rfc3161` proof rather than only carrying it. It confirms the token's message
imprint is the SHA-256 of the anchored link, that the token's signed attributes commit to the
payload, and that the signature verifies against the timestamping certificate the token carries. A
bundle whose proof holds is reported at a higher level than one anchored only by reference, because
the reader needed no network and no trust in the producer to check it.

A verifier does not decide whether an authority is worth trusting, and does not carry a root list.
It reports the signer, and the relying party decides. Baking a root set into a verifier would make a
bundle's strength depend on which build read it, which is the opposite of what an offline proof is
for.

## Population attestation: LoomSpan

A chain proves its entries were not edited. It does not prove entries were written. A producer
that quietly declines to record an event emits a chain that is intact, fully verified, and
misleading, and every signed-log design shares this hole. Auditors have a name for the gap:
establishing that information produced by the entity is complete, not merely accurate.
Completeness cannot be proven absolutely, because that would be a claim about events that left
no trace. What a producer can do is commit, on a fixed cadence, to the exact population so far,
which converts silent omission into an affirmative lie: a signed statement that was false when
it was made.

This is the LoomSpan profile. Status: shipped in format 0.1; span claims are ordinary claims,
so no envelope change was needed. A verifier without span support ignores the claim type and
says so, which the registry rule already guarantees.

A span claim is an ordinary claim on the chain it attests, type `loomseal.span/1`, the first
type in the spec-owned `loomseal` namespace. The population it counts is records: entries of
this chain. Counting live resources or deployed components is a different job, deliberately not
this one.

```json
{
  "type": "loomseal.span/1",
  "at": "2026-08-02T10:01:00Z",
  "payload": { "stream": "chain", "cadence_s": 60, "beat": 1441, "count": 17 },
  "chain": { "seq": 18227, "prev": "...", "link": "..." }
}
```

The claim's `at` is the beat time. `cadence_s` is the interval, in whole seconds, the producer
commits to. `beat` starts at 1 and increases by exactly 1 per span claim on the chain. `count`
is the number of entries appended since the previous span claim. For beat 1, `count` covers
every entry that precedes it, so a chain adopting the profile mid-life attests its entire
prior population once, at adoption.

Because a span claim sits in the chain it attests, its own `chain.prev` is the head it commits
to, and `count` is redundant with the sequence numbers: the entries between two span claims
number exactly the difference of their `seq` values minus one. The verifier recomputes that
difference, and a mismatch fails the bundle. The redundancy is the point. At every beat the
producer signs a number it cannot later shrink without contradicting either the links, which
the chain checks catch, or its own counts, which this profile catches.

Two failure shapes are deliberately distinct. A missing beat number is a deleted window, and it
fails the bundle. Beat times further apart than the declared cadence are a gap: the collector
went quiet, nothing was provably deleted, and the verifier reports the gap with its bounds and
duration instead of failing. Coverage is always reported as measurement, never as a badge.
"Attested every 60s, longest unattested window 74s" is worth more than a completeness stamp,
and it is the only phrasing that survives a skeptical reader.

One limit carries the architecture. A chain that stops emitting beats and stops anchoring
simply ends, and a bundle cannot distinguish ending from having nothing more to say. Silence is
only detectable where an outside party expects the next beat and can see it missing. Publish
beat heads on the declared cadence through the `git` or `https` anchor types, to a feed where a
missing entry is visible to anyone. The feed, not the bundle, is where going dark becomes loud.

Five conformance vectors cover the profile: a valid spanned bundle, a false count, a missing
beat, a gap reported rather than failed, and a mid-life adoption. All three shipped verifiers,
Go, Python, and the browser build, agree on every one.

## Conformance levels

| Level | Name     | Meaning                                                            |
|-------|----------|--------------------------------------------------------------------|
| 1     | Signed   | Valid producer signature over the canonical bundle                 |
| 2     | Chained  | Claims linked in a declared profile, continuity verifies           |
| 3     | Anchored | At least one verified anchor binds the chain outside the producer  |
| 4     | Spanned  | Anchored, plus span claims present and every span check verifies   |

Level 2 verification is full for unkeyed profiles (every link recomputed) and structural for
keyed profiles (continuity of `prev` to `link`, with full verification reserved to the key
holder). The verifier's report names which form it performed. Marketing language maps one to
one: signed, chained, anchored, spanned. No other adjectives.

## Verification

The verifier performs these steps in order and fails closed:

1. Parse the document, require `loomseal` version `0.1`, validate against the schema.
2. Reconstruct the canonical form with `signatures` emptied and verify at least one signature
   against `producer.public_key`. If the caller pinned a fingerprint, require `key_id` match.
3. If `chain` is present: require claims sorted, contiguous, and profile known. Recompute every
   link for unkeyed profiles; check continuity for keyed profiles.
4. For each anchor: match its coordinates to the bundle, verify embedded proofs, report the
   anchor set with times and refs.
5. If span claims are present: require beat contiguity, recompute every count from the
   sequence numbers, compare beat times against the declared cadence, and report coverage:
   beats present, gaps with bounds, longest gap. A false count or a missing beat fails the
   bundle; a gap is reported, never hidden.
6. For each evidence artifact supplied to the verifier: recompute its digest and compare.
   Evidence not supplied is reported as referenced, not checked, never as verified.
7. Report the conformance level achieved and an overall verdict. Any failed check fails the
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
| `switchtender.audit/1` | SwitchTender | v0.1     | actor, method, path                   |
| `switchtender.run/1`   | SwitchTender | draft    | run id, kind, hosts, approver         |
| `loomseal.span/1`      | Any producer | v0.1     | stream, cadence_s, beat, count        |

New types enter by change to this registry. Product namespaces belong to their products. The
`loomseal` namespace is owned by this specification: its types are defined here, and any
producer may emit them. A
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

A verified level 4 bundle adds: at every beat the producer committed to the exact entry
population so far, so an entry removed after its beat contradicts either the links or the
counts, and a deleted beat is itself visible. It still does not prove an event was recorded in
the first place; a beat bounds when an omission had to begin, not whether one happened. And it
says nothing about silence after the newest anchored beat, which only the published feed can
show.

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

