# RFC 6962 Merkle known-answer tests

An independent Python reference for RFC 6962 Merkle trees, plus machine-readable vectors that a
second implementation can consume to prove the two agree.

This code was written from the RFC text alone. It deliberately does not share structure, helpers,
or test data with the Go implementation it is meant to check. If both produce the same hashes for
the same inputs, that agreement means something. If either had been derived from the other, it
would not.

## Files

`rfc6962.py` holds the implementation and the self-checks. `kat.json` holds the emitted vectors.

## Leaf and node domain separation

Every hash in the tree is prefixed with a one byte tag:

    leaf hash     SHA-256(0x00 || entry)
    node hash     SHA-256(0x01 || left_child_hash || right_child_hash)
    empty tree    SHA-256("")

The prefixes are not decoration. Without them the tree is open to a second-preimage attack that
lets an attacker prove inclusion of entries that were never logged.

Suppose leaf and node hashing were both plain SHA-256 of their input. An internal node covering
leaves `d0` and `d1` hashes the 64 byte string `H(d0) || H(d1)`. An attacker submits a single new
entry whose bytes are exactly those 64 bytes. That entry's leaf hash is `SHA-256(H(d0) || H(d1))`,
which is bit for bit the internal node's hash. The attacker now holds one leaf that is
indistinguishable from an interior node, so any audit path that passes through that node can be
reinterpreted as a path through the forged leaf, and vice versa. A log could show two different
tree structures with the same root, which destroys the property the root is supposed to carry.

The 0x00 and 0x01 prefixes make the two preimage spaces disjoint. A leaf preimage always starts
with 0x00 and a node preimage always starts with 0x01, so no leaf can ever collide with a node
regardless of what bytes the submitter chooses. The empty tree hashes the empty string, which is
neither, so it cannot be confused with either.

`check_domain_separation` in `rfc6962.py` builds that exact forged payload and asserts the leaf
hash and node hash of the same 64 bytes differ.

## The exact definition of k

For a tree of `n > 1` entries, RFC 6962 section 2.1 splits at `k`, where:

> k is the largest power of two smaller than n

Read that literally. `k` is a power of two, and `k < n <= 2k`. It is **not** `n / 2`, and it is not
the smallest power of two greater than or equal to `n / 2`.

    n      k      split         n/2 split (WRONG)
    2      1      1 | 1         1 | 1
    3      2      2 | 1         1 | 2
    4      2      2 | 2         2 | 2
    5      4      4 | 1         2 | 3
    6      4      4 | 2         3 | 3
    7      4      4 | 3         3 | 4
    8      4      4 | 4         4 | 4
    9      8      8 | 1         4 | 5

The left subtree is always a perfect binary tree. The right subtree holds whatever is left over.
This is what makes an append-only log cheap to extend: adding entries never reshapes the left
subtree, it only ever grows the right edge.

The two splits agree only when `k` happens to equal `n / 2`, which is `n` in 1, 2, 4, 8 and other
powers of two. Getting this wrong produces a tree that looks correct for `n = 1, 2, 4, 8` and
silently diverges everywhere else, which is why the classic bug survives a weak test suite.
`check_split_is_not_half` asserts the two constructions differ at exactly `n` in 3, 5, 6, 7, 9 for
the sizes covered here. If a second implementation matches on 1, 2, 4, 8 but not on 3 or 5, it is
splitting at `n / 2`.

As a second guard, `mth_streaming` rebuilds the same tree by pushing leaves onto a stack and
merging neighbors only when their subtree sizes match. That is a different algorithm from the
recursive split and it agrees with `mth` for every size from 0 to 64.

## Verification

`verify_inclusion` and `verify_consistency` are the functions a relying party runs. They use the
iterative walks from RFC 9162 sections 2.1.3.2 and 2.1.4.2, driven only by the proof, the index,
and the tree sizes. Neither rebuilds the tree, because a real verifier holds a proof and a root,
not the log.

That split matters for the cross-check. The proofs are generated recursively straight from the
RFC 6962 definitions of PATH, PROOF, and SUBPROOF, then verified by a different iterative
algorithm. Agreement between the two is evidence beyond self-consistency.

Note the step in consistency verification where `first_root` is prepended to the proof when
`first_size` is an exact power of two. RFC 6962 omits that node from the proof, because a
power-of-two prefix is a whole perfect subtree whose hash the verifier already has. Skipping the
prepend makes every power-of-two case fail.

## Regenerating the vectors

    python3 rfc6962.py            # run the self-checks only
    python3 rfc6962.py --emit     # run the self-checks, then write kat.json

The emit path re-verifies every vector through the verifiers after building the document, so
`kat.json` is never written from an unchecked build. No arguments, no dependencies, standard
library only.

Leaf data is deterministic. Leaf `i` is the ASCII bytes of `leaf-<i>`, so `leaf-0`, `leaf-1`, and
so on, with no trailing newline and no length prefix.

## Vector file shape

`kat.json` holds `leaf_data_scheme`, `empty_root`, `roots` keyed by tree size 0 through 9,
`inclusion` with one entry per tree size 1 through 9 and per leaf index, and `consistency` with one
entry per pair `1 <= first_size < second_size <= 9`. All hashes are lowercase hex with no
`sha256:` prefix. Audit paths and consistency proofs are ordered as the RFC produces them, closest
to the leaf first and closest to the root last.

## Judgment calls

These are the points where the RFC leaves room and two implementations can diverge quietly. Each
one is a place to compare notes rather than assume.

**Zero first size in a consistency proof.** RFC 6962 defines PROOF(m, D[n]) for `0 < m`. At `m = 0`
the SUBPROOF recursion has no base case, since it terminates on `m == n` and the left spine bottoms
out at size 1. This implementation refuses `first_size == 0` and returns false. An implementation
that treats the empty tree as trivially consistent with everything and returns true is also
defensible. The vectors do not cover it, so the two would never notice the disagreement through
`kat.json` alone.

**Equal sizes in a consistency proof.** For `first_size == second_size` this implementation
requires an empty proof and equal roots. RFC 6962 gives SUBPROOF(m, D[m], true) = {}, so an empty
proof is right, but the RFC does not say what a verifier should do with a non-empty one. This
implementation rejects a non-empty proof rather than ignoring the extra elements.

**Proof element length.** The RFC does not tell a verifier to check that each proof element is 32
bytes. This implementation rejects anything else up front. An implementation that concatenates
without checking will still fail on a wrong length, but only by accident of the hash not matching.

**Tree size is not authenticated by an inclusion proof.** This one is worth stating plainly,
because it looks like a bug and is not. An inclusion proof commits to the shape of the walk from
leaf to root, not to the exact tree size. Different tree sizes that produce the same walk shape for
a given index accept the same proof. For the sizes covered here there are 64 such pairs, for
example a proof for leaf 0 of a 5 entry tree also verifies against a claimed size of 6, 7, or 8,
and a proof for leaf 4 of a 7 entry tree also verifies against a claimed size of 8.

This is not exploitable on its own. Accepting the lie still requires the caller to supply the root
of the honest tree, and a size 8 tree with the root of a size 7 tree cannot exist without a SHA-256
collision across the domain separators. It does mean the size and the root must be bound together
by the log's signature over the tree head. A verifier that takes a tree size from an unsigned field
and an inclusion proof from elsewhere is trusting the size, not verifying it.

`check_inclusion_adversarial` records these cases rather than asserting they fail, and asserts
instead that at least one size lie is caught for every tree and index, plus a named case that must
be caught. An implementation that claims to reject every wrong tree size is either checking the
proof length separately or has a stricter rule that should be compared against this one.

## What the self-checks cover

Running the file asserts all of the following, and exits non-zero on any failure.

The empty tree hash equals SHA-256 of empty input. A single leaf hashes with the 0x00 prefix and
not bare. The leaf hash of empty data matches the published SHA-256 of a single zero byte, which
anchors leaf hashing against an outside constant rather than against this file.

Every audit path for every leaf index in every tree of size 1 through 9 verifies against the tree
root, which is 45 proofs.

Tampering is rejected in every form tried: one flipped byte in each path element in turn, a wrong
leaf index, a substituted leaf value, and a short path.

Every consistency proof for every pair `1 <= m < n <= 9` verifies, which is 36 proofs.

The append-only property holds. For every pair, and for every earlier leaf that the old root
already covered, the log rewrites that leaf's bytes and offers an honest proof for the rewritten
tree. Verification against the previously published old root fails in all 120 cases. This is the
case that matters most, because it is the one an evidence bundle depends on.
