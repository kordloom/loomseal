package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"

	"github.com/kordloom/loomseal/internal/bundle"
	"github.com/kordloom/loomseal/jcs"
)

// checkDisclosures verifies LoomSwatch field-level selective disclosure. A claim commits redactable
// fields as an _sd array of digests inside its payload, and reveals any subset through
// claim.disclosures, each a [salt, name, value] triple. The _sd set is part of the payload, so it is
// covered by the link or the leaf, while disclosures travel outside both. Revealing or withholding a
// field therefore never changes what the producer signed. A disclosure must hash to a digest in the
// set, or it is a foreign or tampered value and the bundle fails.
//
// It works from the raw parsed document, not the decoded structs, so a value's canonical bytes are the
// ones the producer committed rather than a re-encoding of a decoded number.
func (r *Report) checkDisclosures(raw []byte, b *bundle.Bundle) {
	tree, err := jcs.Parse(raw)
	if err != nil {
		return
	}
	root, ok := tree.(map[string]any)
	if !ok {
		return
	}
	rawClaims, ok := root["claims"].([]any)
	if !ok {
		return
	}
	// Selective disclosure commits its _sd set through the link, which only the generic and tree
	// profiles cover for the whole claim. A switchtender-audit-v1 link hashes a fixed field list and
	// would not cover _sd, and a bundle with no chain commits nothing, so a claim disclosing under
	// either is refused rather than checked into a false sense of binding.
	swatchProfile := b.Chain != nil &&
		(b.Chain.Profile == bundle.ProfileV1 || b.Chain.Profile == bundle.ProfileMerkle)

	for i, rc := range rawClaims {
		obj, ok := rc.(map[string]any)
		if !ok {
			continue
		}
		var sd []any
		if payload, ok := obj["payload"].(map[string]any); ok {
			sd, _ = payload["_sd"].([]any)
		}
		disc, _ := obj["disclosures"].([]any)
		if sd == nil && len(disc) == 0 {
			continue
		}
		r.DisclosuresPresent = true
		if !swatchProfile {
			r.problem("claim %d carries selective disclosure, which belongs to %s or %s", i,
				bundle.ProfileV1, bundle.ProfileMerkle)
			continue
		}

		set := make(map[string]bool, len(sd))
		badSet := false
		for _, e := range sd {
			d, ok := e.(string)
			if !ok || !isHex64(d) {
				r.problem("claim %d disclosure set _sd holds a value that is not a 64 hex digest", i)
				badSet = true
				continue
			}
			if set[d] {
				r.problem("claim %d disclosure set _sd holds a duplicate digest", i)
				badSet = true
			}
			set[d] = true
		}

		seen := make(map[string]bool, len(disc))
		var names []string
		for j, e := range disc {
			dobj, ok := e.(map[string]any)
			if !ok {
				r.problem("claim %d disclosure %d is not an object", i, j)
				continue
			}
			salt, _ := dobj["salt"].(string)
			name, _ := dobj["name"].(string)
			value, hasValue := dobj["value"]
			if salt == "" || name == "" || !hasValue {
				r.problem("claim %d disclosure %d is incomplete", i, j)
				continue
			}
			ser, serr := jcs.Serialize([]any{salt, name, value})
			if serr != nil {
				r.problem("claim %d disclosure %q: %v", i, name, serr)
				continue
			}
			sum := sha256.Sum256(ser)
			dg := hex.EncodeToString(sum[:])
			if !set[dg] {
				r.problem("claim %d disclosure of field %q matches no committed digest", i, name)
				continue
			}
			if seen[dg] {
				r.problem("claim %d disclosure repeats the same field digest", i)
				continue
			}
			seen[dg] = true
			names = append(names, name)
		}
		if badSet {
			continue
		}
		r.FieldsRevealed += len(names)
		r.FieldsRedacted += len(set) - len(names)
		sort.Strings(names)
		r.RevealedFields = append(r.RevealedFields, names...)
	}
}

// isHex64 reports whether s is exactly 64 lowercase hex characters, the shape of a sha256 digest.
func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}
