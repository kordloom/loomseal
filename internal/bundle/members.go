package bundle

import (
	"fmt"
	"sort"

	"github.com/kordloom/loomseal/jcs"
)

// The exact member set each object in a bundle may carry, mirroring the schema's
// additionalProperties: false and the Python reference verifier's own table object for object. A
// member outside its set, including a case variant of a known member, is refused rather than
// folded. Two surfaces are deliberately open and not listed here: a claim payload, whose members
// belong to the emitting product, and chain.params, a free-form parameter bag. A disclosure value
// is any JSON and is not an object to check.
var (
	rootMembers = memberSet("anchors", "attestations", "bundle_id", "chain", "claims", "created_at",
		"loomseal", "producer", "signatures", "subject")
	producerMembers    = memberSet("install_id", "key_id", "product", "product_version", "public_key")
	subjectMembers     = memberSet("id", "type")
	chainMembers       = memberSet("consistency", "head", "keyed", "params", "profile")
	consistencyMembers = memberSet("from_root", "from_size", "path")
	coordsMembers      = memberSet("link", "prev", "seq")
	claimMembers       = memberSet("at", "attestations", "chain", "disclosures", "evidence",
		"inclusion", "payload", "type", "verdict")
	inclusionMembers   = memberSet("path")
	attestationMembers = memberSet("alg", "at", "key_id", "public_key", "role", "sig")
	disclosureMembers  = memberSet("name", "salt", "value")
	evidenceMembers    = memberSet("digest", "location", "media_type", "present", "role")
	verdictMembers     = memberSet("decision", "detail", "inputs_digest", "policy", "policy_digest")
	anchorMembers      = memberSet("at", "link", "proof", "ref", "seq", "type")
	signatureMembers   = memberSet("alg", "key_id", "sig")
)

// memberSet builds a set from member names.
func memberSet(names ...string) map[string]bool {
	m := make(map[string]bool, len(names))
	for _, n := range names {
		m[n] = true
	}
	return m
}

// checkExactMembers parses raw as the canonical tree and refuses any object member outside the
// exact set allowed at its position. It runs over the same parsed tree the signature and the link
// recomputation read, so a member a verdict reads is one this has already approved by its exact
// name.
func checkExactMembers(raw []byte) error {
	v, err := jcs.Parse(raw)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrParse, err)
	}
	root, ok := v.(map[string]any)
	if !ok {
		return fmt.Errorf("%w: bundle is not a JSON object", ErrParse)
	}
	if err := exactMembers(root, rootMembers, "bundle"); err != nil {
		return err
	}
	if err := exactChild(root, "producer", producerMembers, "producer"); err != nil {
		return err
	}
	if err := exactChild(root, "subject", subjectMembers, "subject"); err != nil {
		return err
	}
	if chain, ok := root["chain"].(map[string]any); ok {
		if err := exactMembers(chain, chainMembers, "chain"); err != nil {
			return err
		}
		if err := stringParams(chain); err != nil {
			return err
		}
		if err := exactChild(chain, "consistency", consistencyMembers, "chain.consistency"); err != nil {
			return err
		}
		// The head carries chain coordinates that drive the head match and anchor resolution, so its
		// members are checked exactly like a claim's. The Python verifier checks it the same way.
		if err := exactChild(chain, "head", coordsMembers, "chain.head"); err != nil {
			return err
		}
	}
	if err := exactClaims(root); err != nil {
		return err
	}
	if err := exactArray(root, "signatures", signatureMembers, "signature"); err != nil {
		return err
	}
	if err := exactArray(root, "anchors", anchorMembers, "anchor"); err != nil {
		return err
	}
	// Head-level attestations sit at the top of the document and are verified and reported, so their
	// members are checked exactly as claim attestations are.
	return exactArray(root, "attestations", attestationMembers, "head attestation")
}

// exactClaims checks every claim object and the sub-objects a claim carries.
func exactClaims(root map[string]any) error {
	if err := nullElements(root, "claims", "claim"); err != nil {
		return err
	}
	claims, ok := root["claims"].([]any)
	if !ok {
		return nil
	}
	for i, c := range claims {
		obj, ok := c.(map[string]any)
		if !ok {
			continue
		}
		where := fmt.Sprintf("claim %d", i)
		if err := exactMembers(obj, claimMembers, where); err != nil {
			return err
		}
		if err := exactChild(obj, "chain", coordsMembers, where+" chain"); err != nil {
			return err
		}
		if err := exactChild(obj, "inclusion", inclusionMembers, where+" inclusion"); err != nil {
			return err
		}
		if err := exactChild(obj, "verdict", verdictMembers, where+" verdict"); err != nil {
			return err
		}
		if err := exactArray(obj, "attestations", attestationMembers, where+" attestation"); err != nil {
			return err
		}
		if err := exactArray(obj, "disclosures", disclosureMembers, where+" disclosure"); err != nil {
			return err
		}
		if err := exactArray(obj, "evidence", evidenceMembers, where+" evidence"); err != nil {
			return err
		}
	}
	return nil
}

// stringParams refuses a chain.params value that is not a string. The bag is open by name, but the
// schema types every value as a string, and the struct decoder reads a null there as the empty
// string, which would let a null install_id read as an absent one.
func stringParams(chain map[string]any) error {
	params, ok := chain["params"].(map[string]any)
	if !ok {
		return nil
	}
	var bad []string
	for k, v := range params {
		if _, ok := v.(string); !ok {
			bad = append(bad, k)
		}
	}
	if len(bad) == 0 {
		return nil
	}
	sort.Strings(bad)
	return fmt.Errorf("%w: chain params member %q is not a string", ErrSchema, bad[0])
}

// exactChild checks an optional child object against its member set and, when the child is a proof
// carrying a path, refuses a null element in that path.
func exactChild(parent map[string]any, key string, allowed map[string]bool, where string) error {
	child, ok := parent[key].(map[string]any)
	if !ok {
		return nil
	}
	if err := exactMembers(child, allowed, where); err != nil {
		return err
	}
	return nullElements(child, "path", where+" path")
}

// exactArray checks every object in an optional array member against its member set and refuses
// a null element.
func exactArray(parent map[string]any, key string, allowed map[string]bool, where string) error {
	if err := nullElements(parent, key, where); err != nil {
		return err
	}
	arr, ok := parent[key].([]any)
	if !ok {
		return nil
	}
	for j, e := range arr {
		obj, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if err := exactMembers(obj, allowed, fmt.Sprintf("%s %d", where, j)); err != nil {
			return err
		}
	}
	return nil
}

// exactMembers refuses the first object member outside the allowed set, naming it, and then the
// first allowed member whose value is null. The lowest name is reported so the message is stable
// across runs regardless of map iteration order.
//
// No member the schema defines takes null: each is a string, a number, a boolean, an object, or an
// array. The struct decoder reads null as the zero value, so without this a null prev would read
// as the empty string and recompute as genesis, and a null keyed would read as false. The one
// exception is a disclosure's value, which the schema leaves as any JSON because it is the
// revealed field itself.
func exactMembers(obj map[string]any, allowed map[string]bool, where string) error {
	var extra, nulls []string
	for k, v := range obj {
		switch {
		case !allowed[k]:
			extra = append(extra, k)
		case v == nil && k != "value":
			nulls = append(nulls, k)
		}
	}
	if len(extra) > 0 {
		sort.Strings(extra)
		return fmt.Errorf("%w: %s carries an unknown member %q", ErrSchema, where, extra[0])
	}
	if len(nulls) > 0 {
		sort.Strings(nulls)
		return fmt.Errorf("%w: %s member %q is null", ErrSchema, where, nulls[0])
	}
	return nil
}

// nullElements refuses a null element in an optional array member. No array the schema defines
// holds null, and the struct decoder would read one as a zero-value entry.
func nullElements(parent map[string]any, key, where string) error {
	arr, ok := parent[key].([]any)
	if !ok {
		return nil
	}
	for j, e := range arr {
		if e == nil {
			return fmt.Errorf("%w: %s %d is null", ErrSchema, where, j)
		}
	}
	return nil
}
