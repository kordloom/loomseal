#!/usr/bin/env python3
"""Independent reference implementation of RFC 6962 Merkle trees.

Written from the RFC 6962 text (Certificate Transparency, section 2.1) and the
verification algorithms restated in RFC 9162 (CT v2, sections 2.1.3.2 and
2.1.4.2). This file exists to cross-check a separate implementation, so it
deliberately mirrors the specification wording rather than any other codebase.

Run with no arguments to execute the self-checks. Run with --emit to execute
the self-checks and write kat.json next to this file.
"""

import argparse
import hashlib
import json
import os
import sys

# LEAF_PREFIX is the domain separator RFC 6962 places before leaf data.
LEAF_PREFIX = b"\x00"

# NODE_PREFIX is the domain separator RFC 6962 places before internal nodes.
NODE_PREFIX = b"\x01"

# HASH_SIZE is the SHA-256 output length in bytes.
HASH_SIZE = 32

# MAX_TREE_SIZE is the largest tree the known-answer vectors cover.
MAX_TREE_SIZE = 9


def sha256(data):
    """sha256 returns the SHA-256 digest of data as raw bytes."""
    return hashlib.sha256(data).digest()


def empty_root():
    """empty_root returns MTH({}), the SHA-256 hash of the empty string."""
    return sha256(b"")


def leaf_hash(data):
    """leaf_hash returns MTH({data}), which is SHA-256(0x00 || data)."""
    return sha256(LEAF_PREFIX + data)


def node_hash(left, right):
    """node_hash returns SHA-256(0x01 || left || right) for two child hashes."""
    return sha256(NODE_PREFIX + left + right)


def split_point(n):
    """split_point returns k, the largest power of two strictly less than n.

    RFC 6962 defines the split this way and not as n/2. For n = 5 the split is
    4 and 1, never 2 and 3. Requires n > 1.
    """
    if n <= 1:
        raise ValueError("split_point requires n > 1, got %d" % n)
    k = 1 << ((n - 1).bit_length() - 1)
    # The RFC states k < n <= 2k. Assert it so a bad bit twiddle cannot hide.
    assert k < n <= 2 * k, "bad split for n=%d: k=%d" % (n, k)
    assert k & (k - 1) == 0, "k=%d is not a power of two" % k
    return k


def mth(entries):
    """mth returns the Merkle Tree Hash of an ordered list of leaf byte strings.

    MTH({}) is SHA-256 of the empty string, MTH({d0}) is SHA-256(0x00 || d0),
    and for n > 1 the tree splits at the largest power of two below n.
    """
    n = len(entries)
    if n == 0:
        return empty_root()
    if n == 1:
        return leaf_hash(entries[0])
    k = split_point(n)
    return node_hash(mth(entries[:k]), mth(entries[k:]))


def path(m, entries):
    """path returns PATH(m, D[n]), the audit path for leaf m, per section 2.1.1.

    The returned list runs from the sibling closest to the leaf outward to the
    sibling closest to the root.
    """
    n = len(entries)
    if not 0 <= m < n:
        raise IndexError("leaf index %d out of range for tree size %d" % (m, n))
    if n == 1:
        return []
    k = split_point(n)
    if m < k:
        return path(m, entries[:k]) + [mth(entries[k:])]
    return path(m - k, entries[k:]) + [mth(entries[:k])]


def proof(m, entries):
    """proof returns PROOF(m, D[n]), the consistency proof, per section 2.1.2.

    It proves that the tree of the first m entries is a prefix of the tree of
    all n entries. Requires 0 < m <= n.
    """
    n = len(entries)
    if not 0 < m <= n:
        raise ValueError("consistency proof requires 0 < m <= n, got m=%d n=%d" % (m, n))
    return subproof(m, entries, True)


def subproof(m, entries, b):
    """subproof implements SUBPROOF(m, D[n], b) exactly as RFC 6962 defines it.

    The flag b records whether MTH(D[0:m]) is already known to the verifier,
    which is true only while the recursion stays on the left spine.
    """
    n = len(entries)
    if m == n:
        if b:
            return []
        return [mth(entries)]
    k = split_point(n)
    if m <= k:
        return subproof(m, entries[:k], b) + [mth(entries[k:])]
    return subproof(m - k, entries[k:], False) + [mth(entries[:k])]


def verify_inclusion(leaf_data, leaf_index, tree_size, audit_path, expected_root):
    """verify_inclusion checks an audit path the way a relying party would.

    It walks the path iteratively from the leaf to the root using only the
    proof, the index, and the tree size. It never rebuilds the tree.
    """
    if tree_size <= 0 or leaf_index < 0 or leaf_index >= tree_size:
        return False
    if len(expected_root) != HASH_SIZE:
        return False
    for sibling in audit_path:
        if len(sibling) != HASH_SIZE:
            return False

    fn = leaf_index
    sn = tree_size - 1
    r = leaf_hash(leaf_data)
    for sibling in audit_path:
        if sn == 0:
            # The path is longer than the tree can justify.
            return False
        if (fn & 1) == 1 or fn == sn:
            r = node_hash(sibling, r)
            if (fn & 1) == 0:
                while (fn & 1) == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, sibling)
        fn >>= 1
        sn >>= 1

    return sn == 0 and r == expected_root


def verify_consistency(first_size, first_root, second_size, second_root, consistency_path):
    """verify_consistency checks a consistency proof the way a verifier would.

    It recomputes both the old root and the new root from the proof alone, so a
    log that rewrote an earlier entry cannot satisfy it.
    """
    if first_size < 0 or second_size < 0 or first_size > second_size:
        return False
    if len(first_root) != HASH_SIZE or len(second_root) != HASH_SIZE:
        return False
    for node in consistency_path:
        if len(node) != HASH_SIZE:
            return False
    if first_size == 0:
        # RFC 6962 leaves PROOF(0, D[n]) undefined. Refuse rather than accept an
        # unproven claim. See README for this judgment call.
        return False
    if first_size == second_size:
        return len(consistency_path) == 0 and first_root == second_root

    nodes = list(consistency_path)
    if first_size & (first_size - 1) == 0:
        # A power-of-two prefix is a whole subtree, so RFC 6962 omits its hash
        # from the proof. Put it back before running the walk.
        nodes = [first_root] + nodes
    if not nodes:
        return False

    fn = first_size - 1
    sn = second_size - 1
    while (fn & 1) == 1:
        fn >>= 1
        sn >>= 1

    fr = nodes[0]
    sr = nodes[0]
    for node in nodes[1:]:
        if sn == 0:
            return False
        if (fn & 1) == 1 or fn == sn:
            fr = node_hash(node, fr)
            sr = node_hash(node, sr)
            if (fn & 1) == 0:
                while (fn & 1) == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, node)
        fn >>= 1
        sn >>= 1

    return sn == 0 and fr == first_root and sr == second_root


def leaves(n):
    """leaves returns the deterministic leaf data for a tree of n entries."""
    return [("leaf-%d" % i).encode("ascii") for i in range(n)]


def flip_byte(digest, position=0):
    """flip_byte returns digest with one bit flipped in the byte at position."""
    raw = bytearray(digest)
    raw[position] ^= 0x01
    return bytes(raw)


def check_empty_and_split():
    """check_empty_and_split verifies the empty root and the definition of k."""
    want = hashlib.sha256(b"").hexdigest()
    assert empty_root().hex() == want, "empty root mismatch"
    assert mth([]).hex() == want, "MTH({}) must equal SHA-256 of empty input"
    assert want == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    # k is the largest power of two strictly less than n, never n/2.
    for n, want_k in [(2, 1), (3, 2), (4, 2), (5, 4), (6, 4), (7, 4), (8, 4), (9, 8), (16, 8)]:
        got = split_point(n)
        assert got == want_k, "split_point(%d) = %d, want %d" % (n, got, want_k)

    # A single leaf must hash with the leaf prefix, not bare.
    assert mth([b"leaf-0"]) == sha256(b"\x00leaf-0")
    assert mth([b"leaf-0"]) != sha256(b"leaf-0")
    return want


def mth_streaming(entries):
    """mth_streaming builds the same tree by appending leaves onto a stack.

    This is a different algorithm from the recursive split, so agreeing with mth
    is real evidence that the split rule is right rather than self-consistent.
    Each stack element is a perfect subtree, and two neighbors merge only when
    their sizes match, which reproduces the largest-power-of-two split.
    """
    if not entries:
        return empty_root()
    stack = []
    for data in entries:
        stack.append((leaf_hash(data), 1))
        while len(stack) >= 2 and stack[-1][1] == stack[-2][1]:
            right_hash, right_size = stack.pop()
            left_hash, left_size = stack.pop()
            stack.append((node_hash(left_hash, right_hash), left_size + right_size))
    # Fold the leftover perfect subtrees from the right edge inward.
    root, _ = stack[-1]
    for left_hash, _ in reversed(stack[:-1]):
        root = node_hash(left_hash, root)
    return root


def check_streaming_matches():
    """check_streaming_matches compares the recursive and streaming builds."""
    for n in range(0, 65):
        data = leaves(n)
        assert mth(data) == mth_streaming(data), "tree builds disagree at n=%d" % n
    return 64


def mth_half_split(entries):
    """mth_half_split is the classic wrong tree, splitting at n/2 instead of at k.

    It exists only so the self-checks can prove the two differ. Never use it.
    """
    n = len(entries)
    if n == 0:
        return empty_root()
    if n == 1:
        return leaf_hash(entries[0])
    k = n // 2
    return node_hash(mth_half_split(entries[:k]), mth_half_split(entries[k:]))


def check_split_is_not_half():
    """check_split_is_not_half proves the RFC split differs from an n/2 split."""
    differ = []
    for n in range(1, MAX_TREE_SIZE + 1):
        data = leaves(n)
        if mth(data) != mth_half_split(data):
            differ.append(n)
    # The two agree only where k happens to equal n/2, which is n = 1, 2, 4, 8.
    # The first divergence is n = 3, where the RFC splits 2 and 1 while n/2
    # splits 1 and 2. At n = 5 the RFC splits 4 and 1 while n/2 splits 2 and 3.
    assert differ == [3, 5, 6, 7, 9], "unexpected divergence set %r" % differ
    assert split_point(3) == 2 and 3 // 2 == 1
    assert split_point(5) == 4 and 5 // 2 == 2
    return differ


def check_domain_separation():
    """check_domain_separation proves a leaf cannot impersonate an internal node.

    Without the 0x00 and 0x01 prefixes an attacker could submit a leaf whose
    bytes are the concatenation of two child hashes and claim the resulting node
    hash proves inclusion of leaves that were never logged.
    """
    forged = mth(leaves(2))
    # A leaf carrying the exact bytes of an internal node's children.
    payload = leaf_hash(b"leaf-0") + leaf_hash(b"leaf-1")
    assert leaf_hash(payload) != forged, "leaf and node hashes collide"
    assert leaf_hash(payload) == sha256(LEAF_PREFIX + payload)
    assert forged == sha256(NODE_PREFIX + payload)
    # The prefixes are the only difference, so they carry the whole separation.
    assert LEAF_PREFIX != NODE_PREFIX

    # SHA-256 of a single zero byte is a widely published constant, so it anchors
    # leaf hashing against an outside source rather than against this file.
    assert leaf_hash(b"").hex() == (
        "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d"
    )


def check_inclusion():
    """check_inclusion verifies every audit path for tree sizes 1 through 9."""
    count = 0
    for n in range(1, MAX_TREE_SIZE + 1):
        data = leaves(n)
        root = mth(data)
        for m in range(n):
            p = path(m, data)
            assert verify_inclusion(data[m], m, n, p, root), "inclusion failed n=%d m=%d" % (n, m)
            count += 1
    return count


def check_inclusion_adversarial():
    """check_inclusion_adversarial verifies that tampered inclusion proofs fail.

    Wrong tree sizes are handled separately. A proof does not commit to the tree
    size directly, only to the shape of the walk, so some size lies are outside
    what an inclusion proof alone can detect. See the README.
    """
    corrupted = 0
    wrong_index = 0
    wrong_size_rejected = 0
    wrong_leaf = 0
    size_collisions = []

    for n in range(1, MAX_TREE_SIZE + 1):
        data = leaves(n)
        root = mth(data)
        for m in range(n):
            p = path(m, data)

            # Flip one byte in each path element in turn.
            for i in range(len(p)):
                bad = list(p)
                bad[i] = flip_byte(bad[i], i % HASH_SIZE)
                assert not verify_inclusion(data[m], m, n, bad, root), (
                    "corrupted path accepted n=%d m=%d i=%d" % (n, m, i)
                )
                corrupted += 1

            # Claim a different leaf index in the same tree.
            for other in range(n):
                if other == m:
                    continue
                assert not verify_inclusion(data[m], other, n, p, root), (
                    "wrong index accepted n=%d m=%d other=%d" % (n, m, other)
                )
                wrong_index += 1

            # Claim a different tree size against the same root.
            rejected_here = 0
            for other_n in range(1, MAX_TREE_SIZE + 2):
                if other_n == n or m >= other_n:
                    continue
                if verify_inclusion(data[m], m, other_n, p, root):
                    size_collisions.append((n, m, other_n))
                else:
                    rejected_here += 1
                    wrong_size_rejected += 1
            if n > 1:
                assert rejected_here > 0, "no tree size lie detected for n=%d m=%d" % (n, m)

            # Claim a different leaf value at the same position.
            assert not verify_inclusion(b"tampered", m, n, p, root), (
                "tampered leaf accepted n=%d m=%d" % (n, m)
            )
            wrong_leaf += 1

    # The task asks for one concrete tree size lie that must be caught. Leaf 3 of
    # a 4 leaf tree has a right edge path that a size 8 claim cannot satisfy.
    data = leaves(4)
    assert verify_inclusion(data[3], 3, 4, path(3, data), mth(data))
    assert not verify_inclusion(data[3], 3, 8, path(3, data), mth(data))
    assert not verify_inclusion(data[3], 3, 5, path(3, data), mth(data))

    return corrupted, wrong_index, wrong_size_rejected, wrong_leaf, size_collisions


def check_consistency():
    """check_consistency verifies every consistency proof for 1 <= m < n <= 9."""
    count = 0
    for n in range(2, MAX_TREE_SIZE + 1):
        data = leaves(n)
        second_root = mth(data)
        for m in range(1, n):
            first_root = mth(data[:m])
            pr = proof(m, data)
            assert verify_consistency(m, first_root, n, second_root, pr), (
                "consistency failed m=%d n=%d" % (m, n)
            )
            count += 1
    return count


def check_consistency_adversarial():
    """check_consistency_adversarial verifies that a rewritten log is rejected.

    The log changes the bytes of a leaf that already existed when the old root
    was published, then offers an honest proof for the rewritten tree. The old
    root is unchanged, because the auditor recorded it earlier.
    """
    rewrites = 0
    corrupted = 0
    truncated = 0
    swapped = 0

    for n in range(2, MAX_TREE_SIZE + 1):
        data = leaves(n)
        second_root = mth(data)
        for m in range(1, n):
            old_root = mth(data[:m])
            pr = proof(m, data)

            # Rewrite one earlier leaf, the leaves the old root already covered.
            for victim in range(m):
                rewritten = list(data)
                rewritten[victim] = b"rewritten-" + rewritten[victim]
                bad_root = mth(rewritten)
                bad_proof = proof(m, rewritten)
                assert not verify_consistency(m, old_root, n, bad_root, bad_proof), (
                    "rewritten log accepted m=%d n=%d victim=%d" % (m, n, victim)
                )
                rewrites += 1

            # Flip one byte in each proof element in turn.
            for i in range(len(pr)):
                bad = list(pr)
                bad[i] = flip_byte(bad[i], i % HASH_SIZE)
                assert not verify_consistency(m, old_root, n, second_root, bad), (
                    "corrupted consistency proof accepted m=%d n=%d i=%d" % (m, n, i)
                )
                corrupted += 1

            # Drop the last element of the proof.
            if pr:
                assert not verify_consistency(m, old_root, n, second_root, pr[:-1]), (
                    "truncated consistency proof accepted m=%d n=%d" % (m, n)
                )
                truncated += 1

            # Claim the trees in the wrong order.
            assert not verify_consistency(n, second_root, m, old_root, pr), (
                "reversed sizes accepted m=%d n=%d" % (m, n)
            )
            swapped += 1

    return rewrites, corrupted, truncated, swapped


def check_edge_cases():
    """check_edge_cases verifies the boundary behavior of both verifiers."""
    data = leaves(4)
    root = mth(data)

    # An empty tree admits no inclusion proof.
    assert not verify_inclusion(data[0], 0, 0, [], root)
    # An index at or past the tree size is rejected.
    assert not verify_inclusion(data[0], 4, 4, path(0, data), root)
    assert not verify_inclusion(data[0], -1, 4, path(0, data), root)
    # A short path leaves the walk unfinished.
    assert not verify_inclusion(data[0], 0, 4, [], root)
    # A path element of the wrong length is rejected outright.
    assert not verify_inclusion(data[0], 0, 4, [b"\x00" * 31, b"\x00" * 32], root)

    # A single leaf tree has an empty path and the leaf hash as its root.
    assert path(0, leaves(1)) == []
    assert verify_inclusion(b"leaf-0", 0, 1, [], mth(leaves(1)))

    # Equal sizes need an empty proof and matching roots.
    assert verify_consistency(4, root, 4, root, [])
    assert not verify_consistency(4, root, 4, root, [root])
    assert not verify_consistency(4, root, 4, mth(leaves(5)), [])
    # A first size larger than the second is rejected.
    assert not verify_consistency(5, mth(leaves(5)), 4, root, [])
    # A zero first size is refused, see the README.
    assert not verify_consistency(0, empty_root(), 4, root, [])
    # A proof that is empty when it must not be is rejected.
    assert not verify_consistency(2, mth(leaves(2)), 4, root, [])

    # PROOF requires 0 < m <= n.
    for bad_m in (0, 5):
        try:
            proof(bad_m, data)
        except ValueError:
            pass
        else:
            raise AssertionError("proof(%d, D[4]) should have raised" % bad_m)

    # PATH rejects an out of range index.
    for bad_m in (-1, 4):
        try:
            path(bad_m, data)
        except IndexError:
            pass
        else:
            raise AssertionError("path(%d, D[4]) should have raised" % bad_m)


def build_vectors():
    """build_vectors returns the known-answer vector document as a dict."""
    roots = {}
    for n in range(0, MAX_TREE_SIZE + 1):
        roots[str(n)] = mth(leaves(n)).hex()

    inclusion = []
    for n in range(1, MAX_TREE_SIZE + 1):
        data = leaves(n)
        root = mth(data).hex()
        for m in range(n):
            inclusion.append({
                "tree_size": n,
                "leaf_index": m,
                "path": [h.hex() for h in path(m, data)],
                "root": root,
            })

    consistency = []
    for n in range(2, MAX_TREE_SIZE + 1):
        data = leaves(n)
        second_root = mth(data).hex()
        for m in range(1, n):
            consistency.append({
                "first_size": m,
                "second_size": n,
                "proof": [h.hex() for h in proof(m, data)],
                "first_root": mth(data[:m]).hex(),
                "second_root": second_root,
            })

    return {
        "leaf_data_scheme": "ascii 'leaf-<i>'",
        "empty_root": empty_root().hex(),
        "roots": roots,
        "inclusion": inclusion,
        "consistency": consistency,
    }


def verify_vectors(doc):
    """verify_vectors re-checks an emitted document through the verifiers."""
    assert doc["empty_root"] == doc["roots"]["0"]
    for entry in doc["inclusion"]:
        n = entry["tree_size"]
        m = entry["leaf_index"]
        audit = [bytes.fromhex(h) for h in entry["path"]]
        root = bytes.fromhex(entry["root"])
        assert root.hex() == doc["roots"][str(n)]
        assert verify_inclusion(leaves(n)[m], m, n, audit, root)
    for entry in doc["consistency"]:
        m = entry["first_size"]
        n = entry["second_size"]
        pr = [bytes.fromhex(h) for h in entry["proof"]]
        first_root = bytes.fromhex(entry["first_root"])
        second_root = bytes.fromhex(entry["second_root"])
        assert first_root.hex() == doc["roots"][str(m)]
        assert second_root.hex() == doc["roots"][str(n)]
        assert verify_consistency(m, first_root, n, second_root, pr)


def main():
    """main runs the self-checks and optionally writes the vector file."""
    parser = argparse.ArgumentParser(description="RFC 6962 reference implementation")
    parser.add_argument("--emit", action="store_true", help="Write kat.json next to this file.")
    args = parser.parse_args()

    empty_hex = check_empty_and_split()
    divergence = check_split_is_not_half()
    streaming_max = check_streaming_matches()
    check_domain_separation()
    inclusion_count = check_inclusion()
    corrupted, wrong_index, wrong_size, wrong_leaf, collisions = check_inclusion_adversarial()
    consistency_count = check_consistency()
    rewrites, bad_proofs, truncated, swapped = check_consistency_adversarial()
    check_edge_cases()

    doc = build_vectors()
    verify_vectors(doc)

    print("MTH({})            = %s" % empty_hex)
    print("MTH(D[1])          = %s" % doc["roots"]["1"])
    print("MTH(D[8])          = %s" % doc["roots"]["8"])
    print("MTH(D[9])          = %s" % doc["roots"]["9"])
    print("n/2 split differs at tree sizes %r" % divergence)
    print("recursive build matches streaming build for n = 0..%d" % streaming_max)
    print("inclusion vectors  = %d (verified)" % inclusion_count)
    print("consistency vectors= %d (verified)" % consistency_count)
    print("rejected: corrupted path=%d wrong index=%d wrong size=%d wrong leaf=%d"
          % (corrupted, wrong_index, wrong_size, wrong_leaf))
    print("rejected: rewritten log=%d bad proof=%d truncated=%d reversed=%d"
          % (rewrites, bad_proofs, truncated, swapped))
    print("tree size lies not detectable from the proof alone = %d" % len(collisions))
    for n, m, other_n in collisions:
        print("  n=%d m=%d also verifies as tree_size=%d" % (n, m, other_n))

    if args.emit:
        out = os.path.join(os.path.dirname(os.path.abspath(__file__)), "kat.json")
        with open(out, "w") as handle:
            json.dump(doc, handle, indent=2)
            handle.write("\n")
        print("wrote %s" % out)

    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
