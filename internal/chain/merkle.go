package chain

import (
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/kordloom/loomseal/internal/bundle"
	"github.com/kordloom/loomseal/internal/merkle"
	"github.com/kordloom/loomseal/jcs"
)

// verifyMerkle checks a bundle under loomseal-merkle-v1: every disclosed claim's leaf hash is
// recomputed from its content, folded through its audit path, and required to reproduce the root the
// signed head names, and any consistency proof is folded to recompute both roots.
//
// It is reached before the linear coordinate and continuity rules, which a tree legitimately
// violates: a tree has no per-entry predecessor, and disclosing an arbitrary subset of leaves is the
// profile's purpose, so contiguity is not required here.
func verifyMerkle(raw []byte, b *bundle.Bundle) (Result, error) {
	var res Result
	if b.Chain.Keyed {
		return res, fmt.Errorf("%w: %s is an unkeyed profile", ErrProfile, bundle.ProfileMerkle)
	}
	installID := b.Chain.Params["install_id"]
	if installID == "" {
		return res, fmt.Errorf("%w: %s requires params.install_id", ErrProfile, bundle.ProfileMerkle)
	}
	// The install id is hashed into every leaf, so it must be the signer's own or the binding proves
	// nothing: a copier that reused another install's leaves, root, and timestamp token would
	// otherwise emit a bundle that is internally consistent at every step while asserting a history
	// its key never had.
	if installID != b.Producer.InstallID {
		return res, fmt.Errorf("%w: chain params.install_id %q is not the producer's install %q",
			ErrClaim, installID, b.Producer.InstallID)
	}
	if b.Chain.Head.Prev != "" {
		return res, fmt.Errorf("%w: a tree head has no previous link", ErrClaim)
	}
	size := b.Chain.Head.Seq
	root, err := hex.DecodeString(b.Chain.Head.Link)
	if err != nil {
		return res, fmt.Errorf("%w: head link is not hex", ErrClaim)
	}

	claims, err := rawClaims(raw, len(b.Claims))
	if err != nil {
		return res, err
	}

	seen := make(map[int64]bool, len(b.Claims))
	var prevSeq int64
	for i := range b.Claims {
		c := &b.Claims[i]
		if c.Chain == nil {
			return res, fmt.Errorf("%w: claim %d has no chain coordinates", ErrClaim, i)
		}
		if c.Inclusion == nil {
			return res, fmt.Errorf("%w: claim %d carries no inclusion proof", ErrClaim, i)
		}
		if c.Chain.Prev != "" {
			return res, fmt.Errorf("%w: claim %d has a previous link, which a tree has no place for",
				ErrClaim, i)
		}
		if c.Chain.Seq > size {
			return res, fmt.Errorf("%w: claim %d seq %d is past the tree size %d", ErrClaim, i,
				c.Chain.Seq, size)
		}
		if seen[c.Chain.Seq] {
			return res, fmt.Errorf("%w: claim %d repeats seq %d", ErrBroken, i, c.Chain.Seq)
		}
		seen[c.Chain.Seq] = true
		if c.Chain.Seq <= prevSeq {
			return res, fmt.Errorf("%w: claim %d seq %d does not ascend", ErrBroken, i, c.Chain.Seq)
		}
		prevSeq = c.Chain.Seq

		leaf, err := leafData(claims[i], installID)
		if err != nil {
			return res, fmt.Errorf("%w: claim %d: %w", ErrClaim, i, err)
		}
		if got := hex.EncodeToString(merkle.LeafHash(leaf)); got != c.Chain.Link {
			return res, fmt.Errorf("%w: claim %d leaf hash does not recompute", ErrBroken, i)
		}
		path, err := decodeHashes(c.Inclusion.Path)
		if err != nil {
			return res, fmt.Errorf("%w: claim %d inclusion path: %w", ErrClaim, i, err)
		}
		// The index and the size come from the claim's own seq and the signed head, never from a
		// value carried beside the proof, because folding binds a leaf to a root and not to a size.
		if !merkle.VerifyInclusion(leaf, c.Chain.Seq-1, size, path, root) {
			return res, fmt.Errorf("%w: claim %d does not prove membership of the tree the head names",
				ErrBroken, i)
		}
		res.InclusionProofs++
	}

	if err := verifyConsistency(b, root, size); err != nil {
		return res, err
	}
	// Recorded only once the fold above returned, so a reported proof is one that held.
	if c := b.Chain.Consistency; c != nil {
		res.ConsistencyFrom = c.FromSize
		res.ConsistencyOK = true
	}
	res.Mode = ModeFull
	res.Claims = len(b.Claims)
	res.TreeSize = size
	// Every disclosed leaf folded to the head root, so the head is confirmed by the bundle itself
	// rather than merely declared, which a linear window cannot do when its head leads the claims.
	res.HeadMatched = true
	return res, nil
}

// verifyConsistency folds a bundle's consistency proof, when it carries one, and requires it to
// recompute both the earlier root it names and the head root. Recomputing only one of them would
// prove nothing about the relationship between them.
func verifyConsistency(b *bundle.Bundle, root []byte, size int64) error {
	c := b.Chain.Consistency
	if c == nil {
		return nil
	}
	if c.FromSize > size {
		return fmt.Errorf("%w: consistency from_size %d is past the tree size %d", ErrClaim,
			c.FromSize, size)
	}
	from, err := hex.DecodeString(c.FromRoot)
	if err != nil {
		return fmt.Errorf("%w: consistency from_root is not hex", ErrClaim)
	}
	path, err := decodeHashes(c.Path)
	if err != nil {
		return fmt.Errorf("%w: consistency path: %w", ErrClaim, err)
	}
	if !merkle.VerifyConsistency(c.FromSize, size, from, root, path) {
		return fmt.Errorf("%w: the log does not prove it grew from the root it names by appending "+
			"only, so an entry it had already published may have been changed or dropped", ErrBroken)
	}
	return nil
}

// leafData builds one claim's leaf bytes: the canonical form of the domain, the install, and the
// claim digest. The digest covers the claim's own content with the members that describe its
// position, its proof, and how this bundle happens to package its evidence removed, so the same log
// entry disclosed in two bundles yields one leaf.
func leafData(claim map[string]any, installID string) ([]byte, error) {
	content := make(map[string]any, len(claim))
	for k, v := range claim {
		if k == "chain" || k == "inclusion" {
			continue
		}
		content[k] = v
	}
	if ev, ok := content["evidence"].([]any); ok {
		stripped := make([]any, 0, len(ev))
		for _, e := range ev {
			obj, ok := e.(map[string]any)
			if !ok {
				return nil, fmt.Errorf("%w: evidence entry is not an object", ErrClaim)
			}
			cp := make(map[string]any, len(obj))
			for k, v := range obj {
				if k == "present" {
					continue
				}
				cp[k] = v
			}
			stripped = append(stripped, cp)
		}
		content["evidence"] = stripped
	}
	canonical, err := jcs.Serialize(content)
	if err != nil {
		return nil, err
	}
	digest := merkle.Sum256Hex(canonical)
	return jcs.Serialize(map[string]any{
		"domain":     bundle.ProfileMerkle,
		"install_id": installID,
		"claim":      "sha256:" + digest,
	})
}

// rawClaims returns the bundle's claims as parsed objects, so a leaf is built from the members the
// document carries rather than from a re-encoding of the decoded structs.
func rawClaims(raw []byte, want int) ([]map[string]any, error) {
	tree, err := jcs.Parse(raw)
	if err != nil {
		return nil, err
	}
	root, ok := tree.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: bundle is not a JSON object", ErrClaim)
	}
	list, ok := root["claims"].([]any)
	if !ok || len(list) != want {
		return nil, fmt.Errorf("%w: claims are not an array of objects", ErrClaim)
	}
	out := make([]map[string]any, 0, want)
	for i, c := range list {
		obj, ok := c.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%w: claim %d is not an object", ErrClaim, i)
		}
		out = append(out, obj)
	}
	return out, nil
}

// decodeHashes turns a proof's hex hashes into raw bytes, rejecting anything that is not a hash.
func decodeHashes(in []string) ([][]byte, error) {
	out := make([][]byte, 0, len(in))
	for i, h := range in {
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != merkle.HashSize {
			return nil, fmt.Errorf("%w: element %d is not a 32 byte hash", ErrClaim, i)
		}
		out = append(out, b)
	}
	return out, nil
}

// compile-time proof that a claim's payload stays raw JSON, which leafData relies on by working from
// the parsed document rather than the decoded struct.
var _ = json.RawMessage(nil)
