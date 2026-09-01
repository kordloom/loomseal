# LoomSeal: The KordLoom Attestation Format

Status: canonical specification, 2026-08-31, release candidate for LoomSeal 1.0. The
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
6. Shipped vectors win. Where this spec and a released verifier diverge, the divergence is a
   bug, and fixing it never changes the verdict of any bundle a conforming producer could have
   emitted. Behavior that cannot be reconciled under that rule is new behavior, and new behavior
   takes a new profile name or a new wire version.

## Compatibility

This section is the contract a 1.0 verifier and a 1.0 producer hold each other to. It governs
every release from 1.0 onward.

**What 1.0 freezes.** The bundle schema, the canonical form (JCS with the integer-only number
profile), the signature preimages, the three chain profiles as specified here, the anchor and
attestation constructions, and every conformance vector shipped at the tag. A shipped vector is
never invalidated: a change that would flip any existing vector's verdict is not a revision of
this format, it is a different format under a different version string.

**The wire version.** The `loomseal` member reads `0.1` and stays `0.1` for the life of format
1.0. It is an identifier, not a semver: the 1.x releases of this specification and the libraries
evolve around an unchanging wire format. Incompatible evolution, a new canonicalization, a new
signature algorithm, a widened number profile, takes a different version string, and a 1.0
verifier refuses it as unsupported rather than judging it.

**Strict parsing is the design.** A bundle member, claim member, or signature member this
specification does not define is rejected at parse by a conforming verifier, exactly as the
schema's `additionalProperties: false` states, and a conforming producer under version `0.1`
never emits one. Rejecting the unknown is what makes a verified verdict mean something: nothing
unsigned and nothing unspecified can ride inside a bundle a verifier has accepted.

**Unsupported is not forged.** A verifier that meets an unknown `loomseal` version, an unknown
`chain.profile`, or a signature `alg` it does not implement reports the bundle as unsupported
and exits nonzero without judging the signature. Unsupported is fail-closed and never becomes a green
verdict, but it is a verdict distinct from verification failure, because "this verifier is too
old for this bundle" and "this bundle did not verify" must never share a message.

**How each surface grows.**

- Claim types are an open namespace. A type a verifier does not recognize is reported, never
  failed. Product types enter through the registry in this document.
- Claim payloads are open objects. New members ride under the digests that commit them.
- Subject types and anchor types are informational vocabularies: a verifier reports an unknown
  value and continues.
- Chain profiles are closed per name. A profile's bound field set is complete as specified, and
  a new bound field takes a new profile name. The canonical-object link makes the successor
  cheap: entries lacking the new field hash identically under both.
- Signature algorithms and the canonical form are fixed for format 1.0. A change takes a new
  wire version.

**One experimental surface.** The presentation document ("Presentations", below) is outside
this contract until it stabilizes in a later 1.x release. Everything else in this specification
is inside it.

**Verdict stability.** A 1.x release never changes the verdict of a bundle a conforming
producer could have emitted: what verifies stays verified, byte for byte, forever. Tightening
only ever applies to inputs no conforming producer produces, and each such tightening ships
with a must-not-verify vector pinning it.

## The bundle

A bundle is a JSON object with these members:

| Member       | Required | Purpose                                              |
|--------------|----------|------------------------------------------------------|
| `loomseal`       | yes      | Format version, `"0.1"`                              |
| `bundle_id`  | yes      | Producer-assigned identifier for this bundle         |
| `created_at` | yes      | RFC 3339 UTC time the bundle was assembled           |
| `producer`   | yes      | Who emitted it: product, version, install, key       |
| `subject`    | yes      | What the claims are about: a lowercase `type` token  |
|              |          | and an `id`. Types are vocabulary, not structure: a  |
|              |          | verifier reports one it does not know and continues  |
| `chain`      | no       | Chain profile, parameters, and head (level 2 and up) |
| `claims`     | yes      | The claims, each with payload, evidence, chain coords|
| `anchors`    | no       | External anchor records (level 3)                    |
| `attestations`| no      | Head-level counter-signatures over the chain head    |
| `signatures` | yes      | At least one producer signature over the bundle      |

Example, the shape of a bundle on the generic profile. Digests, keys, and the signature are
illustrative placeholders, so this exact document does not verify; the conformance vectors are
the documents that do:

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
      "seq": 18209,
      "link": "6b23c0d5f35d1b11f9b683f0b0a617355deb11277d91ae091d399c655b87940d"
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
      "seq": 18209,
      "link": "6b23c0d5f35d1b11f9b683f0b0a617355deb11277d91ae091d399c655b87940d",
      "at": "2026-07-27T15:00:00Z",
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
the bundle object, encoded as UTF-8 with no byte order mark and no trailing newline. Those bytes are
what a signature covers and what every digest in this format is taken over, so they are stated here
rather than left to a serializer's defaults. Object keys are ordered by their UTF-16 code units, which RFC 8785 requires
and which differs from code point order above the basic multilingual plane. Object keys must be
unique within an object; a repeated key has no canonical form and the bundle is rejected. Strings
must be valid UTF-8, and every `\u` escape must denote a valid Unicode scalar value. A lone surrogate,
whether written as a `\uD800`-through-`\uDFFF` escape or as raw bytes, is rejected at parse and
never coerced to the replacement character; coercion would let two different documents share one
canonical form and one signature. Digest strings are `sha256:` followed by 64 lowercase hex
characters, and a bare link or proof hash is 64 lowercase hex characters with no prefix. Hex is
lowercase on the wire and a verifier rejects uppercase rather than folding case, because two spellings
of one hash would give a bundle two canonical forms. Times are RFC 3339 in UTC; fractional seconds are allowed where a chain profile
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
base64 ed25519 signature, verified per RFC 8032 with the rules that implementations differ on stated
explicitly: a signature whose `S` component is not canonically reduced is rejected, a public key or `R`
component of small order is rejected, and cofactorless verification is used. Left unpinned, one shipped
verifier accepts a signature another rejects on the same bundle, which is the one outcome a
deterministic format cannot tolerate. Every entry in `signatures` names `producer.key_id`, and at least one of them
verifies; an entry naming any other key fails the bundle, because the array sits outside the
signed bytes and a foreign entry is a rider nothing vouches for. Counter-signatures travel as
attestations, which are defined and domain-bound, never as extra signature entries. A verifier recomputes `producer.key_id` from `producer.public_key` and rejects a
bundle whose declared fingerprint does not match the key it carries; the fingerprint is a convenience
for readers, never an input to a decision. Verifiers compare that recomputed fingerprint, not the
declared one, against a pinned value when the caller provides one. Pinning against a value the bundle
itself supplies would let any producer claim any identity.

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

**Install identity and key rotation.** `producer.install_id` is a stable installation
identifier. A producer may mint it from its first public key, and the switchtender profile
historically derives it that way, but the id names the install, not the key: it survives key
changes and is never re-derived after rotation. Rotation itself is out of format 1.0's scope; a
producer that rotates either starts a new install identity or records the succession as a claim,
and the type `loomseal.rotation/1` is reserved in the registry for that statement. A relying
party's trust is pin-based: it pins the key it has verified for an install, and a new key
claiming an existing install id is a rotation event to accept explicitly, never silently.

## Chain profiles

**What a link or leaf commits to.** Every hashing profile shares one committed-content rule: a
claim's `chain` and `inclusion` members describe position and proof, `disclosures` and
`attestations` are holder- and third-party-controlled and travel outside the commitment, and an
evidence entry's `present` and `location` are packaging, whether and where the artifact travels
beside this particular copy. All of these are excluded from every link and leaf, so the same log
entry disclosed in two bundles that package their evidence differently commits identically, and
repackaging never breaks a chain. The exclusion list is fixed for format 1.0; the reference
libraries export it as one function (`seal.ClaimContent`) so a mirror implementation cannot
drift from it by rewriting the strip by hand. The bundle-level strip a producer signature
covers is exported the same way, as `seal.BundleContent`, for the same reason: a mirror that
rewrote that list by hand fell behind it and began refusing bundles the reference accepted.

A chain fixes claims in an append-only order. Products already have chains with different
constructions, so LoomSeal names each construction as a profile and the verifier implements the
profiles. A bundle declares one profile in `chain.profile`.

Profiles come in two shapes. A **linear** profile hashes each claim onto its predecessor, so a link
depends on the whole prefix before it; `switchtender-audit-v1` and `loomseal-chain-v1` are linear.
A **tree** profile hashes claims into a Merkle tree, so an entry is proved against a root without
its neighbors; `loomseal-merkle-v1` is the tree profile. The two paragraphs below state the linear
rules. The tree profile deliberately does not follow them, and its own section is normative wherever
they differ; a verifier selects its behavior from `chain.profile`, which the signature covers, and
never from any other field.

In a linear profile claims carry `chain.seq`, `chain.prev`, and `chain.link`. Claims in a bundle are
sorted by ascending `seq` and must be contiguous; discontinuous history means separate bundles. The
first claim carries an empty `prev` only when it is genesis, at `seq` 1. A window that opens past
`seq` 1 is a slice of a longer chain, so its first claim links to the entry immediately before the
window and must carry that non-empty `prev`; a first claim above `seq` 1 with an empty `prev` is
rejected, because it recomputes as though it were genesis and would let a bundle present itself as
unrooted at an arbitrary point.

`chain.head` records the newest coordinates the producer attests for the whole chain, which may
lead the claims a bundle carries: a bundle is a window into a longer history. When the head
sequence equals the newest bundled claim, the verifier confirms the head link against that claim
and reports the head as matched. When the head leads the claims, its link cannot be recomputed
from the bundle and stays unverified; the report says so and does not treat that head as proof of
anything beyond the window.

### switchtender-audit-v1

The shipped SwitchTender construction. Each audit entry's link is SHA-256 over the RFC 8785 canonical
JSON **object** of the claim's fields: `seq` (a JSON number, starting at 1), `at` (the time, exactly
as it appears in the bundle), `actor`, `method`, `path`, and `prev` (the previous link, the empty
string at genesis). Sequence starts at 1. This profile is unkeyed: any verifier recomputes every link
from the claim payloads alone.

The object carries four further fields when, and only when, the entry has them, each a non-empty
string in the claim payload: `actor_type` (how the actor authenticated), `on_behalf_of` (the account
whose authority the actor used), `content_digest` (`sha256:` and the hex digest of the canonical,
redacted change payload), and `install_id` (the producing installation's identifier). An empty field
is omitted from the object rather than written as an empty string, so an entry recorded before a
field existed and one that simply does not use it hash identically. These four are the profile's
complete bound field set: a verifier hashes exactly the defined fields an entry carries and no
others, and a member this profile does not define is no part of the link. A future bound field
takes a new profile name, as the design rules require, and the canonical-object link is what makes
that successor cheap: an entry without the new field hashes identically under the old profile and
the new one, so a chain adopts the successor mid-life without invalidating a single link it has
already published.

`install_id` binds an entry to its producer, and when an entry carries it a verifier **requires it to
equal `producer.install_id`**. The reason is the one the tree and generic profiles state: a link that
commits to nothing about the install is one a copier can lift. A published receipt whose links named
no install could be taken whole, re-signed under another installation's producer block and key, and
would still recompute, so a relying party pinning that installation's fingerprint would read one
install's history as another's, a real third-party timestamp riding along intact because the token
commits only to the link. Folding the install into the link closes that for every entry that carries
it: rewriting the producer block forces the payload id to be rewritten to match, which changes the
link, which breaks any third-party anchor taken over the original. The binding is per entry, not per
chain, so a chain adopts it mid-life without invalidating a single link it has already published:
entries recorded before the field existed hash exactly as they always did, and stay exactly as
liftable as they always were. A producer should carry `install_id` on every new entry, and a relying
party should treat only entries that carry it as bound to the producing install.

The per-entry `install_id` is the only value that binds in this profile. `chain.params.install_id`,
which the tree and generic profiles use, is **informational** here and is not consulted when
recomputing a link. A producer may carry it to mirror the producer block, but because it binds
nothing on its own, a verifier refuses a bundle whose `chain.params.install_id` disagrees with
`producer.install_id`, so a third-party producer cannot set the param and assume it binds. A param
equal to the producer restates it and is accepted.

An earlier revision of this construction hashed six values as a positional array. Nothing consumed
that form outside this repository, so the profile was redefined in place rather than versioned; a
future addition, once the format has outside adopters, would take a new profile name instead.

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

`install_id` is `chain.params.install_id`, which this profile requires and which must equal
`producer.install_id`, for the reason the tree profile states: an install id that is merely present
rather than tied to the signer binds a link to nothing a copier cannot also copy.

Keyed chains state `"keyed": true` in the bundle's `chain` member.

The keyed form is by design not recomputable by third parties: the chain key is the secret that
prevents forgery by a party who can write the underlying store. Relying parties verify keyed
chains structurally, checking that each claim's `prev` equals the prior claim's `link`, and
against anchors. The operator, holding the key, verifies fully.

### loomseal-merkle-v1

The tree profile. Claims are the leaves of an RFC 6962 Merkle tree, the construction Certificate
Transparency uses. It exists for two things a linear chain cannot do: prove one entry belongs to the
log without disclosing any other entry, and prove that the log only ever appended.

This profile is unkeyed. `chain.keyed` must be `false`, and a bundle declaring it `true` is rejected.

**Hashing.** All hashes are SHA-256 and are written as 64 lowercase hex characters with no `sha256:`
prefix, matching `chain.link`.

- Leaf hash: `SHA-256(0x00 || leaf_data)`.
- Interior node hash: `SHA-256(0x01 || left || right)`, where `left` and `right` are the 32 raw bytes
  of the child hashes, in that order.
- Root of an empty tree: `SHA-256` of no input, that is
  `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.

The one-byte prefixes are normative. Without them the same bytes can be read as a leaf or as a node,
and an attacker presents an interior node's two child hashes as a single leaf's content to prove
membership of an entry the log never held.

**Leaf data.** The claim digest of a claim is `sha256:` and the hex SHA-256 of the RFC 8785 canonical
form of that claim's JSON object with its `chain` and `inclusion` members removed, and with the
`present` and `location` members removed from every entry of `evidence`. The removals are structural,
done on the parsed member tree before canonicalizing, never by editing text.

Each removal has a reason. `chain` carries the leaf's position and `inclusion` carries its proof, and a
leaf commits to content, not to where it sits or how it is proved. `evidence[].present` says whether
an artifact travels with this particular bundle and `evidence[].location` says where it sits relative
to it, both facts about packaging rather than about the entry: the same log entry disclosed once with
its transcript attached and once without, or laid out two ways, would otherwise hash differently, so
one disclosure could never fold to the anchored root. Every other member of an evidence entry,
including the digest itself, stays in the leaf.

Canonicalizing is not the same as reformatting a value, and this format requires the first while
forbidding the second. RFC 8785 fixes how the *structure* is written: key order, string escaping,
number form. It never rewrites the *content* of a string. So a time, a digest, or any other string is
carried into the canonical form exactly as the bundle spells it, which is what the note on time in
`switchtender-audit-v1` requires, and a verifier that parsed such a string into a native type and
formatted it back would have broken that rule regardless of canonicalization.

The leaf data is then the canonical form of

```json
{ "domain": "loomseal-merkle-v1", "install_id": "...", "claim": "sha256:..." }
```

where `install_id` is `chain.params.install_id` and `claim` is the claim digest above. This profile
requires `chain.params.install_id`, and **requires it to equal `producer.install_id`**; a verifier
rejects a bundle where the two differ.

The equality is what makes the binding real, and it is easy to get wrong by stating only that the
member exists. Hashing an install id into every leaf stops nothing on its own, because a copier takes
that member along with everything else it copies. What the equality forces is a contradiction the
copier cannot resolve: to reuse another install's leaves, root, and timestamp token, the bundle must
carry that install's id, and it must then also carry that install's `producer.install_id` while being
signed by a key that is not that install's. A relying party pinning the producer's fingerprint out of
band sees the mismatch immediately, and a relying party that pins nothing at least sees a bundle whose
producer claims to be an install it cannot sign for, rather than one that is internally consistent.
Without the equality the copied bundle is internally consistent at every step and asserts a history
its signer never had. `loomseal-chain-v1` binds `install_id` into every link for the same reason, and
takes it from the same place.

A leaf hash is not the claim digest, and it is not a `loomseal-chain-v1` link. It is
`SHA-256(0x00 || leaf_data)` over the object above. The claim digest is an input to it. They are
different values by construction and must not be substituted for one another.

**The tree is the whole log, not the bundle.** `D[n]` is the log's entries in order, every one of
them, and `n` is the log's size. A bundle discloses a subset of those leaves, so a verifier generally
cannot rebuild the tree and must not try: the root is established by the signature and confirmed by
folding each disclosed leaf's audit path. A bundle that happens to carry every leaf is not a special
case and is verified the same way.

**Tree shape.** Write `MTH(D[n])` for the tree hash of `n` leaves. `MTH` of no leaves is the empty
root above. `MTH(D[1])` is the leaf hash of the single leaf. For `n > 1`, let `k` be the largest power
of two strictly less than `n`, and

```
MTH(D[n]) = SHA-256(0x01 || MTH(D[0:k]) || MTH(D[k:n]))
```

`k` is not `n / 2`. The two definitions agree at every power of two and differ at every other size, so
an implementation that splits at `n / 2` yields correct roots for 1, 2, 4, and 8 leaves and wrong ones
for 3, 5, 6, 7, and 9. A test suite built only on power-of-two sizes does not detect this.

**Coordinates.** `chain.head.seq` is the tree size, the number of leaves in the log, and
`chain.head.link` is the root at that size. Each claim's `chain.seq` is its leaf index plus one, so a
leaf index is `seq - 1` and the first leaf has `seq` 1. Each claim's `chain.link` is that claim's leaf
hash. Each claim's `chain.prev` must be empty, whether written as an empty string or omitted, and
`chain.head` must likewise carry no non-empty `prev`. A tree has no per-entry predecessor, so a
non-empty `prev` implies a linear chain that is not being verified and a verifier rejects it.

Empty and absent are deliberately the same here, rather than one being required. The schema does not
require `prev`, and a serializer that omits empty members, which this format's own producers use,
cannot write the member at all; a rule demanding it be present would make conformant tooling emit
non-conformant bundles. Where a distinction between absent and empty carries meaning this format says
so, and here it carries none: both spell the same absence of a predecessor. A tree has no per-entry
predecessor, so a non-empty `prev` implies a linear chain that is not being verified and a verifier
rejects it; an absent `prev` on a claim is likewise rejected rather than read as empty, because a
verifier must never guess which of two spellings a producer meant.

Claims are sorted by ascending `chain.seq`, must not repeat a `seq`, and **need not be contiguous**.
Disclosing an arbitrary subset is the purpose of this profile. Every `chain.seq` must lie in the range
1 through `chain.head.seq` inclusive.

`chain.head.seq` must be at least 1. The empty root is defined above because the tree hash is defined
for every size and a consistency proof's arithmetic reaches it, but a bundle carries at least one
claim and every claim's `seq` must fall within the tree, so no valid bundle in this profile heads an
empty log.

The `inclusion` and `chain.consistency` members belong to this profile alone. A bundle carrying either
under a linear profile is rejected rather than ignored, because a reader who sees a proof beside a
claim is entitled to assume some verifier checked it. Equally, a bundle that declares no `chain` at all
must carry no `chain` coordinates and no `inclusion` on any claim: unchained claims are unproved by
construction, and proof-shaped members beside them would suggest otherwise.

**Inclusion proofs.** Every claim in this profile carries an `inclusion` member:

```json
"inclusion": { "path": ["<64 hex>", "..."] }
```

`path` is the audit path for that leaf: the sibling hashes from the leaf's level upward, lowest
first. It is required on every claim and may be an empty array, which is the correct and only value
for a log of exactly one leaf. The leaf index and the tree size are not repeated inside `inclusion`;
they are `chain.seq - 1` and `chain.head.seq`, and a verifier uses those.

The audit path is defined exactly, so that no implementation has to infer it. `PATH(m, D[n])` is the
path for leaf index `m` of a log of `n` leaves. `PATH(0, D[1])` is empty. For `n > 1`, with `k` the
largest power of two strictly less than `n`:

```
PATH(m, D[n]) = PATH(m, D[0:k]) : MTH(D[k:n])        when m <  k
PATH(m, D[n]) = PATH(m-k, D[k:n]) : MTH(D[0:k])      when m >= k
```

where `:` appends. The path is therefore ordered lowest sibling first, and its length is the depth of
that leaf, which for a tree that is not a perfect power of two is not the same for every leaf.

A verifier recomputes the claim's leaf hash from its leaf data, confirms it equals `chain.link`, and
then confirms that folding the leaf hash with the path reproduces `chain.head.link`, combining at each
level in the order the definition above fixes: the path element is the right input when the leaf's
subtree is the left half at that split, and the left input when it is the right half. An
implementation may compute this with the equivalent iterative walk over the leaf index and the
rightmost index rather than recursively; the two agree by construction, and this specification fixes
the result, not the method. The path must be exactly the length that definition produces: a path with
a level too few or too many does not verify.

An inclusion proof binds the leaf, its index, and the path to the root. It does not independently
authenticate the tree size: for some positions two sizes fold identically, so a declared size that is
wrong can still reach the correct root. This is not a weakness, because the root is the signed value,
but it fixes an obligation on the verifier: **take both the root and the tree size from
`chain.head`, which the signature covers, and never from any value supplied beside the proof.**

**Consistency proofs.** A bundle may carry one consistency proof on `chain`:

```json
"consistency": {
  "from_size": 12,
  "from_root": "<64 hex>",
  "path": ["<64 hex>", "..."]
}
```

It asserts that the log of `from_size` leaves whose root was `from_root` is a prefix of the log this
bundle heads, and that the log reached its current state by appending only. The rules are exact:

- `from_size` must be at least 1. A prefix of zero entries is rejected. RFC 6962 leaves the case
  undefined, and every log trivially extends the empty log, so accepting it would answer "prove you
  only appended" with a proof that establishes nothing. A relying party with no earlier root has
  nothing to compare and must not be handed something that looks like evidence.
- `from_size` must be less than or equal to `chain.head.seq`.
- When `from_size` equals `chain.head.seq`, `path` must be empty and `from_root` must equal
  `chain.head.link`. Nothing was appended, so there is nothing to fold.
- Otherwise `path` must be non-empty.

The proof itself is defined exactly. `PROOF(m, D[n])` for `0 < m < n` is `SUBPROOF(m, D[n], true)`,
where the flag records whether the prefix is exactly the subtree under consideration, in which case
the verifier already holds its root and it is not sent:

```
SUBPROOF(m, D[m], true)  = {}
SUBPROOF(m, D[m], false) = { MTH(D[m]) }
SUBPROOF(m, D[n], flag)  = SUBPROOF(m, D[0:k], flag) : MTH(D[k:n])        when m <= k and m < n
SUBPROOF(m, D[n], flag)  = SUBPROOF(m-k, D[k:n], false) : MTH(D[0:k])     when m >  k and m < n
```

with `k` the largest power of two strictly less than `n`, `:` appending, and the third and fourth
rules applying only when `m < n`.

A verifier cannot run a generation function, so the check is stated in the verifier's own terms. Let
`fn = from_size - 1` and `sn = head_size - 1`. While `fn` is odd, shift both `fn` and `sn` right by
one; this walks up to the boundary of the largest complete subtree the prefix ends on. If `fn` is now
zero the prefix is exactly that subtree and the verifier already holds its root, so seed both the old
and the new accumulator with `from_root` and consume no proof element; otherwise seed both with the
first proof element. This seeding case is where implementations most often split, because for a
`from_size` that is a power of two the old root is never sent and a verifier that expects it rejects
valid bundles.

Then, for each remaining proof element `p`: if `fn` is odd or `fn` equals `sn`, set the old accumulator
to `node(p, old)` and the new accumulator to `node(p, new)`, then shift both `fn` and `sn` right while
`fn` is even and non-zero; otherwise set only the new accumulator to `node(new, p)`. Shift `fn` and
`sn` right by one and continue. The proof verifies when every element has been consumed, `sn` is zero,
the old accumulator equals `from_root`, and the new accumulator equals `chain.head.link`. Recomputing
only one of the two roots is not a consistency check, and leftover proof elements or a non-zero `sn`
mean the proof does not describe these two sizes. A log that
edited or dropped anything it had already published cannot produce a proof that recomputes its old
root, however well formed the new log is on its own.

This is the difference between inferring truncation and proving its absence. A linear chain plus an
anchor detects a lost tail only indirectly: the chain no longer reaches an anchor it should. A
consistency proof states the append-only property directly, and it composes with anchoring. When an
anchor fixes a root at a moment outside the producer's control and a later bundle proves consistency
from that same root, the anchored history is provably a prefix of the current log. A producer that
quietly removed an entry recorded before the anchor cannot produce both.

**What a verifier reports.** The claims checked, the tree size, whether every inclusion proof folded
to the head root, and, when a consistency proof is present, the size it proved from and whether it
held. A bundle in this profile whose inclusion proofs all verify has a confirmed head: unlike a
linear window, whose head beyond the newest claim cannot be recomputed, a tree's root is confirmed by
any single inclusion proof that folds to it.

## Selective disclosure: LoomSwatch

A record a subject carries between parties often needs to reveal some fields and withhold others while
staying verifiable as a whole. LoomSwatch commits a claim's redactable fields as digests and lets the
holder reveal any subset, so a stranger checks the revealed fields and the sealed whole without the
producer or the platform in the loop. It applies to `loomseal-chain-v1` and `loomseal-merkle-v1`, the
profiles whose link or leaf commits the whole claim; `switchtender-audit-v1`, whose link hashes a
fixed field list, does not carry it, and a claim disclosing under that profile or under no chain is
refused.

**The `_sd` set.** A claim's payload carries an `_sd` member, an array of digests, one per redactable
field. Each digest is `sha256` in lowercase hex over the RFC 8785 canonical array `[salt, name, value]`:
a per-field salt of at least 128 bits of entropy, the field name, and the field value. The digests are
sorted and unique. Because `_sd` lives in the payload, it is committed by the link and the leaf exactly
like any other payload content, so it is fixed at signing time and cannot be added to or altered after.

**Disclosures.** A claim may carry a `disclosures` member, an array of `[salt, name, value]` triples,
one for each field the holder chooses to reveal. To reveal a field the holder includes its disclosure;
the verifier recomputes the digest and requires it to be present in `_sd`, then reads the value. A
withheld field appears only as its digest in `_sd`, with the salt and value absent, so it cannot be
brute-forced. A disclosure whose digest is not in `_sd` is a foreign or tampered value and fails the
bundle.

**Disclosures are not signed.** The `disclosures` member is removed, along with the signatures array,
before the canonical form a producer signature covers is computed, and it is likewise excluded from
the link and the leaf. Only the `_sd` set is committed. This is what makes disclosure holder
controlled: a holder attaches or withholds a disclosure, or hands one verifier fewer fields than
another, without touching the signature, the link, or the leaf. A producer emits a fully disclosed
bundle; a holder redacts by dropping disclosures; both verify.

**Honest limits.** Withholding the salt is what protects a redacted field, so a salt is never reused
across fields or records. The count of redactable fields is visible from the length of `_sd`. The
value of a revealed field is proved to be the one committed; it is not proved to be true, which is the
job of a counterparty signature, not of disclosure. Selective disclosure hides field values, not the
fact that a holder presented a record, and correlation across presentations remains the holder's
concern.

## Counterparty attestation

A complete, unaltered record of claims a producer made about itself is still only the producer's word.
Counterparty attestation lets a party other than the producer counter-sign a claim, so a self-asserted
record becomes one a second party vouches for. This is the difference between "I logged that this
happened" and "the other side agrees it happened," and it is what raises the cost of a fabricated but
internally consistent history.

A claim may carry an `attestations` array. Each attestation is `key_id`, `public_key` (raw ed25519,
base64), `alg` (`ed25519`), `role` (what the signer is to the claim, such as `counterparty` or
`auditor`), an optional `at` (RFC 3339 UTC, when the signer counter-signed), and `sig`. The
signature is over the RFC 8785 canonical object `{ "loomseal": "attestation/1", "link": <the
claim's chain.link>, "role": <role> }`, with `"at"` included exactly when the attestation carries
it. The `loomseal` member is a domain tag: it keeps this signature meaningless anywhere else a
link-and-role shaped object might be signed. The binding covers one specific claim, the role the
signer claims, and, when carried, the time they signed, which cannot be altered afterward without
breaking the counter-signature. A
verifier confirms `key_id` is the digest of `public_key`, then checks the signature; it reports each
verified attestation as its role and key fingerprint and leaves whether that signer is worth trusting
to the relying party, exactly as it does for the producer key and for anchor authorities.

Attestations are added after the producer signs and are removed, along with disclosures and the
signatures array, before the canonical form the producer signature covers is computed. They are
likewise excluded from the link and the leaf. A counterparty therefore attests a claim without the
producer re-signing anything, and without touching the link a later attestation or an inclusion proof
depends on. Because the signature binds the link, an attestation cannot be moved to a different claim,
and because it binds the role, the role cannot be changed after the fact.

A bundle may also carry a top-level `attestations` array: head-level counter-signatures over
the chain head rather than over one claim. The object shape is the same; the signature is over
`{ "loomseal": "head-attestation/1", "link": <chain.head.link>, "seq": <chain.head.seq>,
"role": <role> }`, with `"at"` included exactly when carried. The distinct domain tag means a
head attestation can never be replayed as a claim attestation or against a different head. This
is the artifact a witness mints when it counter-signs a published head, and the custody record a
re-anchoring service signs when it takes responsibility for a chain's continuity: both attach to
an already-signed bundle, because head-level attestations are stripped from the producer
preimage exactly as claim attestations are.

An attestation vouches only for the claim's existence and integrity as the signer saw it. It does not
make the claim true, and the format takes no position on which roles or signers a relying party should
accept. As with anchors, a verifier reports what it checked and lets the reader decide.

## Anchors

**Anchor verdicts are stable.** A 1.x release never changes the anchor verdict of an
already-emitted bundle: a token that opened and verified keeps opening and verifying, byte for
byte. Tightening only ever applies to tokens no conforming authority issues, and each such
tightening ships with a must-not-verify vector. A carried proof that does not open as a
timestamp token fails the anchor check outright, because garbage must never grade the same as
carrying no proof at all.

**Signer resolution.** A timestamp token carries exactly one SignerInfo; zero is malformed and
more than one is ambiguous, and both fail. The signer certificate is the one the SignerInfo's
signer identifier names, by issuer and serial number or by subject key identifier; certificate
order inside the token carries no meaning. A token whose named signer certificate is absent
fails rather than falling back to any other certificate the token happens to carry. The named
certificate must itself carry the timestamping extended key usage: a certificate its issuer never
authorized to timestamp cannot attest to a time, whatever its signature verifies against. A token
naming a certificate that lacks that usage fails, and so does one naming a certificate it does not
carry, even when some other certificate inside it would have been a valid signer.

**Self-attestation.** An anchor or attestation signed by the producer's own key verifies
mechanically like any other, and a verifier reports the signer's fingerprint exactly so a
relying party can see that it is the producer vouching for itself. The format takes no position
beyond making the self-reference visible: a producer's own countersignature adds no independence,
and whether it counts for anything is the relying party's call, never the verifier's.

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
anchor that matches no verified coordinate fails the bundle.

In `loomseal-merkle-v1` anchor resolution is total: every anchor lands in exactly one of three
outcomes, decided in this order.

1. Its `seq` and `link` equal `chain.head.seq` and `chain.head.link`. It anchors the root, and because
   every inclusion proof folds to that root the coordinate is verified.
2. The bundle carries a consistency proof and its `seq` and `link` equal `consistency.from_size` and
   `consistency.from_root`, and that proof verified. It anchors a root the log has now proved it still
   contains. This is the strongest statement the format makes about truncation: the anchor fixes a root
   at a time the producer did not control, and the consistency proof shows the current log grew from
   exactly that root.
3. Its `seq` equals some disclosed claim's `chain.seq` and its `link` equals that claim's `chain.link`.
   It anchors one leaf hash. That fixes when a single entry existed and nothing about the log's shape,
   so it is reported as matched but does not by itself earn the anchored level.

An anchor matching none of the three fails the bundle, as in every profile. Matching a coordinate is
necessary for the anchored level and never sufficient: that level additionally requires an anchor whose
offline proof the verifier checked, under the rule above. A producer anchoring this profile anchors
roots; the leaf case is defined so a verifier has an answer, not because it is useful. An anchor type the verifier cannot
validate offline, such as `git`, `https`, or `rekor`, is matched by coordinates only and reports
as anchored by reference, leaving the relying party to confirm the ref out of band. Anchoring
cadence bounds the window in which a compromised producer key could rewrite unanchored history;
anchor often.

A verifier checks an `rfc3161` proof rather than only carrying it. It confirms the token's message
imprint is the SHA-256 of the anchored link's 32 raw bytes, decoded from its hex, not of the hex text,
that the token's signed attributes commit to the payload, and that the signature verifies against the
timestamping certificate the token carries. It also holds the token's `genTime` against two other
facts the token already carries. First, `genTime` must fall within the signer certificate's own
validity window: an authority's certificate has to be valid when it signs, so a token signed outside
its certificate's life is not evidence whatever the signature says, and this is checkable with no root
store because both values travel in the token. Second, `genTime` must not precede the entry the anchor
covers, allowing a five-minute clock skew: the token commits to a link that is the hash of a claim
carrying its own time, so an authority cannot honestly have signed it before that claim existed.
Without this a producer running its own authority could sign any hash with any date and still reach the
strongest verdict the format issues. The producer-written anchor `at` is a label for the reader and is
not the value the verdict rests on; `genTime` is the fact, because it is the one time value the
producer does not control.

An `rfc3161` anchor carrying no `proof` is reported as anchored by reference, exactly like a `git` or
`https` anchor, and does not earn the anchored level. Its type declares that an offline proof exists,
and matching coordinates alone would let a producer claim the strongest anchor form by naming it.

A bundle whose proof holds is reported at a higher level than one anchored only by reference, because
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

LoomSpan is defined over the linear profiles. Its beats are chain entries carrying a non-empty
`chain.prev`, and its coverage check requires contiguous beats, both of which `loomseal-merkle-v1`
forbids by design: a tree has no per-entry predecessor, and selective disclosure is the profile's
purpose. A bundle on the tree profile therefore carries no span claims and does not reach level 4, and
a verifier that finds a span claim in a tree bundle rejects it rather than attempting a check the
profile cannot satisfy. Population attestation over a tree is a later addition, and it belongs in the
tree's own terms, as a signed sequence of roots and sizes rather than a sequence of links; it is
deliberately not specified here rather than half specified.

## Conformance levels

| Level | Name     | Meaning                                                            |
|-------|----------|--------------------------------------------------------------------|
| 1     | Signed   | Valid producer signature over the canonical bundle                 |
| 2     | Chained  | Claims fixed in a declared profile: linear continuity, or a tree   |
|       |          | whose inclusion proofs fold to the signed root                     |
| 3     | Anchored | At least one anchor with a verified offline proof binds the chain  |
|       |          | outside the producer                                               |
| 4     | Spanned  | Anchored, plus span claims present and every span check verifies   |

Level 2 verification is full for unkeyed profiles (every link recomputed) and structural for
keyed profiles (continuity of `prev` to `link`, with full verification reserved to the key
holder). In the tree profile it is full: every leaf is recomputed and every inclusion proof folded.
The verifier's report names which form it performed. A consistency proof does not introduce a level;
it is an additional property the report states, because it answers a different question from the
levels, which is whether the log grew by appending rather than whether this bundle is intact. Marketing language maps one to
one: signed, chained, anchored, spanned. No other adjectives.

## Verification

The verifier performs these steps in order and fails closed:

1. Parse the document, require `loomseal` version `0.1`, validate against the schema.
2. Require every `signatures` entry to name `producer.key_id`, reconstruct the canonical form
   with `signatures` emptied, and verify at least one entry against `producer.public_key`. If
   the caller pinned a fingerprint, require `key_id` match.
3. If `chain` is present: require the profile known and the claims sorted by `seq`. For a linear
   profile require the claims contiguous, then recompute every link for an unkeyed profile or check
   continuity for a keyed one. For the tree profile require `keyed` false, `params.install_id`
   present, every `seq` within 1 through `chain.head.seq` and none repeated, every `prev` empty or
   absent, and an `inclusion` member on every claim; then recompute each claim's leaf hash, confirm it
   equals that claim's `link`, fold each inclusion proof and require it reproduce `chain.head.link`,
   and, when a consistency proof is present, recompute both its roots. Contiguity is not required in
   the tree profile; a sparse window is its purpose. Reject `inclusion` or `chain.consistency` under
   any other profile.
   If `chain` is absent: reject any claim carrying `chain` coordinates or an `inclusion` member, since
   unchained claims are unproved by construction and proof-shaped members beside them would suggest
   otherwise.
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
| `switchtender.run/1`   | SwitchTender | reserved | not emitted yet, not in any verifier's |
|                        |              |          | known set until something emits it    |
| `loomseal.span/1`      | Any producer | v0.1     | stream, cadence_s, beat, count        |
| `loomseal.rotation/1`  | reserved     |          | key succession statement, unspecified |
| `loomseal.agentrun/1`  | Any producer | v0.1     | session, tool, args, outcome          |
| `whodar.knowledge-risk/1` | Whodar    | v0.1     | finding, topics_scored, critical      |

`switchtender.run/1` is reserved and nothing emits it. A run's record travels today as
`switchtender.audit/1` claims: the request that created it, any approval or rejection, and an outcome
entry whose method is `RUN` and whose `content_digest` commits to what the run did, which a holder of
the outcome body can check. The name is held so that a later, richer run claim cannot be defined by
somebody else, and this row says so rather than describing a payload no bundle carries. A verifier
that meets the type today reports it as unknown, which is the correct outcome for a type with no
producer.

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
the claims sit in an order fixed by the declared profile that has not been reordered or rewritten
since the anchored moments, which for a linear profile is the chain itself and for a tree profile is
membership in the anchored root, with append-only growth proved only when a consistency proof is
present and anchored; the evidence digests match any artifacts presented; the anchored history
predates the anchor times.

A verified level 4 bundle adds: at every beat the producer committed to the exact entry
population so far, so an entry removed after its beat contradicts either the links or the
counts, and a deleted beat is itself visible. It still does not prove an event was recorded in
the first place; a beat bounds when an omission had to begin, not whether one happened. And it
says nothing about silence after the newest anchored beat, which only the published feed can
show.

A bundle on `loomseal-merkle-v1` proves two further things, and they are the reason the profile
exists. First, each disclosed claim belongs to the log whose root the producer signed, so a receipt
about one subject can be handed to an outsider while the other entries stay undisclosed: the audit
path is a list of hashes, not content. Second, when the bundle carries a consistency proof from a root
that was anchored earlier, the log is proved to have grown from that root by appending only, so an
entry recorded before the anchor cannot have been edited or dropped since. That is a stronger
statement than the linear profile can make, where a lost tail is inferred from an anchor the chain no
longer reaches rather than refuted outright.

State the limits of the non-disclosure plainly, because it is easy to oversell. An audit path hides
content, not existence: it discloses the log's size through `chain.head.seq`, the disclosed entry's
position, and the fact that particular sibling subtrees exist. Leaves are not salted, so a reader who
can guess an entry's exact bytes can confirm the guess by hashing it, which matters when a claim's
payload is drawn from a small or predictable set. Where that is a real exposure the producer's answer
is the payload, not the tree: commit to a `content_digest` and keep the body out of the claim, exactly
as `switchtender-audit-v1` already does. A consistency proof whose `from_root` was never anchored or
published proves only that the producer is self-consistent, since it chose both roots, and a verifier
reports such a proof as unwitnessed rather than as evidence of append-only history.

It does not prove the log is complete. A tree fixes what it contains, and a producer that never wrote
an entry has a perfectly consistent log without it. Nor does an inclusion proof say anything about the
tree size on its own, which is why the size is read from the signed head.

It does not prove: that the producer observed the world honestly at capture time (a chain fixes
the record, not the honesty of the recorder); that a keyed chain is internally valid without the
key (that verification belongs to the key holder); anything about entries created and rewritten
between anchors by an attacker holding both the database and the chain key (cadence bounds this
window). State these limits plainly everywhere the format is described. The credibility of the
whole house rests on never claiming more than the verifier checks.

## Presentations

**Status: experimental.** The presentation document is the one surface outside the 1.0 freeze:
it is newer than everything else here, has no integrator mileage yet, and stabilizes in a later
1.x release with its own vectors and its own compatibility note. Until then this section may
change, and a verifier should treat presentation verdicts as provisional in a way bundle
verdicts never are. Bundles inside presentations are ordinary bundles and keep every 1.0
guarantee.

A bundle is evidence anyone can check. A presentation is how the subject of that evidence carries it
to a particular verifier and shows only what they choose, bound so it cannot be replayed elsewhere. A
presentation is a separate document that wraps one bundle.

A presentation has `loomseal_presentation` (version `0.1`), `created_at` (RFC 3339 UTC), `audience`
(who it is being shown to), `nonce` (a challenge the verifier issued), a `holder` block (`key_id`,
`public_key`, `alg`), the `bundle` it presents, and a `sig`. The holder signature is over the RFC 8785
canonical object `{ "audience", "bundle_sha256", "created_at", "nonce" }`, where `bundle_sha256` is the
sha256 of the presented bundle's canonical form. It binds four things at once: the exact bundle shown,
the verifier it is shown to, the challenge that verifier issued, and the time. A presentation therefore
cannot be replayed to a different verifier, answered with a stale challenge, or altered without
breaking the holder signature.

The holder key is a key the subject controls. Binding that key to a real-world identity is a
trust-establishment concern the format leaves to the relying party, exactly as it does for a producer
key or an anchor authority. Before presenting, a holder reduces each claim's `disclosures` to the
subset it wants to reveal; because disclosures sit outside the producer signature, the link, and the
leaf, the reduced bundle still verifies, and the presentation commits to exactly the reduced form.

A verifier checks the embedded bundle on its own terms, then the holder signature over the presented
bundle, and finally that the `audience` and `nonce` match what it expected. It reports the holder
fingerprint and both matches, and leaves whether the holder is who they claim to the relying party.

## Media type and file names

Media type `application/vnd.kordloom.loomseal+json`. File name `<subject>-<date>.loomseal.json`. A
bundle with sidecar evidence travels as a directory or archive; the bundle stays one file. A
presentation uses `application/vnd.kordloom.loomseal-presentation+json` and
`<subject>-<date>.loomseal-presentation.json`.

## Interoperability

A bundle may be wrapped in a DSSE envelope with payload type
`application/vnd.kordloom.loomseal+json` for tooling that expects DSSE. Mapping claims onto in-toto
attestation predicates is possible later and deliberately not part of v0.1.

### Producer library notes

These describe the reference Go library, not the format itself. The format is unchanged.

- Since v0.11.0 the canonical serializer refuses input that is not valid UTF-8 rather than emitting
  the replacement character. This was always the correct behavior, since coercing invalid bytes to
  U+FFFD lets two different inputs share one canonical form and one hash. A producer that fed raw,
  possibly invalid, bytes into the serializer now receives an error where earlier it received output,
  so the failure surfaces as "this input was never valid" rather than "hashing stopped working."

