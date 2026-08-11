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
| `subject`    | yes      | What the claims are about: a `type` from the schema's|
|              |          | enum and an `id`                                     |
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
deterministic format cannot tolerate. A bundle carries at least one signature whose `key_id` matches
`producer.key_id`. A verifier recomputes `producer.key_id` from `producer.public_key` and rejects a
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

## Chain profiles

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
sorted by ascending `seq` and must be contiguous; discontinuous history means separate bundles.

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

The object carries three further fields when, and only when, the entry has them, each a non-empty
string: `actor_type` (how the actor authenticated), `on_behalf_of` (the account whose authority the
actor used), and `content_digest` (`sha256:` and the hex digest of the canonical, redacted change
payload). An empty field is omitted from the object rather than written as an empty string, so an
entry recorded before a field existed and one that simply does not use it hash identically. Because
the link commits to a canonical object rather than a fixed positional array, a field added later is
committed without changing how any earlier entry hashes, which is what lets this profile carry new
evidence without a new profile version. A verifier hashes exactly the fields present and no others.

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
`present` member removed from every entry of `evidence`. The removals are structural, done on the
parsed member tree before canonicalizing, never by editing text.

Each removal has a reason. `chain` carries the leaf's position and `inclusion` carries its proof, and a
leaf commits to content, not to where it sits or how it is proved. `evidence[].present` says whether
an artifact travels with this particular bundle, which is a fact about packaging rather than about the
entry: the same log entry disclosed once with its transcript attached and once without would otherwise
hash two different ways, so one of the two could never fold to the anchored root. Every other member of
an evidence entry, including the digest itself, stays in the leaf.

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
that the token's signed attributes commit to the payload, that the signature verifies against the
timestamping certificate the token carries, and that the token's `genTime` equals the anchor's declared
`at` to within one minute. That last check is what makes the anchor time mean anything: `at` is written
by the producer, so without comparing it to the time the authority actually signed, a producer
backdates an anchor by writing whatever `at` it likes beside a genuine token. Where the two disagree
the token's `genTime` is the fact and the bundle is rejected, because a producer that misreports the
one value it does not control has misreported its evidence.

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
2. Reconstruct the canonical form with `signatures` emptied and verify at least one signature
   against `producer.public_key`. If the caller pinned a fingerprint, require `key_id` match.
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

## Media type and file names

Media type `application/vnd.kordloom.loomseal+json`. File name `<subject>-<date>.loomseal.json`. A
bundle with sidecar evidence travels as a directory or archive; the bundle stays one file.

## Compatibility

A bundle may be wrapped in a DSSE envelope with payload type
`application/vnd.kordloom.loomseal+json` for tooling that expects DSSE. Mapping claims onto in-toto
attestation predicates is possible later and deliberately not part of v0.1.

