// Package chain verifies that a bundle's claims sit in an intact append-only chain under
// the declared profile. Unkeyed profiles recompute every link; keyed profiles verify
// continuity only, because the link key is the producer's forgery secret and never travels.
package chain

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/kordloom/loomseal/internal/bundle"
	"github.com/kordloom/loomseal/jcs"
)

// Mode names for a chain verification.
const (
	// ModeFull means every link was recomputed from claim content.
	ModeFull = "full"
	// ModeStructural means only continuity of prev to link could be checked without the key.
	ModeStructural = "structural"
)

// Result describes how the chain verified.
type Result struct {
	// Mode is ModeFull or ModeStructural.
	Mode string
	// Claims is how many chained claims were checked.
	Claims int
	// HeadMatched reports whether the declared head coincided with the newest claim and
	// matched it. A head beyond the bundled claims cannot be tied to them and stays false.
	HeadMatched bool
	// TreeSize is how many leaves the signed head names, which in the tree profile is the size of
	// the whole log rather than of the disclosed window. It stays zero under a linear profile.
	TreeSize int64
	// InclusionProofs is how many audit paths were folded and reproduced the head root. It stays
	// zero under a linear profile, which has no per-claim proofs.
	InclusionProofs int
	// ConsistencyFrom is the earlier log size a verified consistency proof grew from. It stays zero
	// when the bundle carried no such proof.
	ConsistencyFrom int64
	// ConsistencyOK reports whether that proof recomputed both roots, so the log is proved to have
	// grown from the earlier one by appending only.
	ConsistencyOK bool
}

// Verify checks the bundle's chain: coordinates on every claim, contiguous ascending
// sequence, continuity, the genesis rule, head consistency, and link recomputation where
// the profile permits. The raw document is needed for profiles that digest claim bytes.
func Verify(raw []byte, b *bundle.Bundle) (Result, error) {
	var res Result
	if b.Chain == nil {
		return res, fmt.Errorf("%w: bundle declares no chain", ErrClaim)
	}
	// The tree profile is checked before the linear rules below, which it legitimately violates: a
	// tree has no per-entry predecessor for continuity to follow, its head is a root rather than the
	// newest claim's link, and disclosing a non-contiguous subset of leaves is the whole point.
	if b.Chain.Profile == bundle.ProfileMerkle {
		return verifyMerkle(raw, b)
	}
	for i := range b.Claims {
		if b.Claims[i].Chain == nil {
			return res, fmt.Errorf("%w: claim %d has no chain coordinates", ErrClaim, i)
		}
	}
	if err := checkContinuity(b.Claims); err != nil {
		return res, err
	}
	head := b.Chain.Head
	last := b.Claims[len(b.Claims)-1].Chain
	switch {
	case head.Seq < last.Seq:
		return res, fmt.Errorf("%w: head seq %d is behind newest claim seq %d", ErrBroken,
			head.Seq, last.Seq)
	case head.Seq == last.Seq:
		if head.Link != last.Link {
			return res, fmt.Errorf("%w: head link does not match newest claim", ErrBroken)
		}
		res.HeadMatched = true
	}
	mode, err := checkLinks(raw, b)
	if err != nil {
		return res, err
	}
	res.Mode = mode
	res.Claims = len(b.Claims)
	return res, nil
}

// checkContinuity requires contiguous ascending sequence numbers, prev-to-link continuity,
// and the genesis rule for a segment that starts at sequence one.
func checkContinuity(claims []bundle.Claim) error {
	for i := range claims {
		c := claims[i].Chain
		if i == 0 {
			if c.Seq == 1 && c.Prev != "" {
				return fmt.Errorf("%w: claim 0 is genesis but has a prev link", ErrBroken)
			}
			// A window that opens past sequence one is a slice of a longer chain, so its first claim
			// links to the entry before the window and must carry that prev. Without this rule a
			// window opening at any position with an empty prev recomputes as though it were genesis,
			// which lets a bundle present itself as unrooted at an arbitrary point.
			if c.Seq > 1 && c.Prev == "" {
				return fmt.Errorf("%w: claim 0 opens a window at seq %d but carries no prev link",
					ErrBroken, c.Seq)
			}
			continue
		}
		prev := claims[i-1].Chain
		if c.Seq != prev.Seq+1 {
			return fmt.Errorf("%w: claim %d seq %d does not follow %d", ErrBroken, i, c.Seq,
				prev.Seq)
		}
		if c.Prev != prev.Link {
			return fmt.Errorf("%w: claim %d prev does not match claim %d link", ErrBroken, i,
				i-1)
		}
	}
	return nil
}

// checkLinks recomputes links under the declared profile where possible and returns the
// verification mode achieved.
func checkLinks(raw []byte, b *bundle.Bundle) (string, error) {
	switch b.Chain.Profile {
	case bundle.ProfileSwitchTender:
		if b.Chain.Keyed {
			return "", fmt.Errorf("%w: %s is an unkeyed profile", ErrProfile,
				bundle.ProfileSwitchTender)
		}
		return ModeFull, checkSwitchTender(b)
	case bundle.ProfileV1:
		if b.Chain.Keyed {
			return ModeStructural, nil
		}
		return ModeFull, checkV1(raw, b)
	default:
		return "", fmt.Errorf("%w: %q", ErrProfile, b.Chain.Profile)
	}
}

// switchTenderPayload is the payload minimum of a switchtender.audit claim.
type switchTenderPayload struct {
	// Actor is who performed the recorded mutation.
	Actor string `json:"actor"`
	// Method is the HTTP method of the mutation.
	Method string `json:"method"`
	// Path is the request path of the mutation.
	Path string `json:"path"`
	// ActorType is how the actor authenticated, empty on an entry recorded before the field existed.
	ActorType string `json:"actor_type"`
	// OnBehalfOf is the account whose authority the actor used, empty when it acted as itself.
	OnBehalfOf string `json:"on_behalf_of"`
	// ContentDigest covers the canonical change payload, empty when the request carried no body.
	ContentDigest string `json:"content_digest"`
	// InstallID is the producing installation, empty on an entry recorded before the field existed.
	InstallID string `json:"install_id"`
}

// checkSwitchTender recomputes the shipped SwitchTender construction: SHA-256 over the canonical
// JSON object of the claim's sequence, time, actor, method, path, and previous link, plus the actor
// type, delegated account, content digest, and install id when the entry carries them.
func checkSwitchTender(b *bundle.Bundle) error {
	// chain.params.install_id is informational in this profile: the per-claim install_id is what
	// binds. A third-party producer might set the param and assume it binds something, so a param
	// that disagrees with the producer is refused rather than silently ignored. Because a bound
	// claim's install_id must equal the producer, this also keeps the param from disagreeing with the
	// claims. A param equal to the producer is allowed and simply restates it.
	if pid := b.Chain.Params["install_id"]; pid != "" && pid != b.Producer.InstallID {
		return fmt.Errorf("%w: %s chain.params.install_id %q is informational and must equal "+
			"producer.install_id %q; the per-claim install_id is what binds", ErrProfile,
			bundle.ProfileSwitchTender, pid, b.Producer.InstallID)
	}
	for i := range b.Claims {
		claim := &b.Claims[i]
		var p switchTenderPayload
		if err := json.Unmarshal(claim.Payload, &p); err != nil {
			return fmt.Errorf("%w: claim %d payload: %w", ErrClaim, i, err)
		}
		// install_id binds the entry to the producer. When an entry carries it, it must be the
		// signer's own, and it is folded into the link like the other optional fields. A link that
		// commits to the install cannot be lifted into another install's bundle while keeping a
		// genuine anchor: rewriting the producer forces rewriting the link, which breaks any
		// third-party timestamp taken over the original. An entry that omits it is a pre-binding
		// entry, hashed exactly as before, so a chain can adopt the field without invalidating the
		// links it already published.
		if p.InstallID != "" && p.InstallID != b.Producer.InstallID {
			return fmt.Errorf("%w: claim %d install_id %q does not match producer.install_id %q",
				ErrProfile, i, p.InstallID, b.Producer.InstallID)
		}
		// The time is validated but hashed verbatim, exactly as it appears in the bundle.
		//
		// Parsing and reformatting it was meant to be an identity, and for this implementation it
		// was, because Go's time carries nanoseconds. It is not an identity everywhere: Python's
		// datetime carries microseconds, so the reference verifier silently dropped the last three
		// digits of a nanosecond timestamp and recomputed a different link. The same bundle verified
		// here and failed there, reported as "link does not recompute", which reads as tampering
		// when nothing has been tampered with. A format whose two verifiers disagree on valid input
		// is worse than one that is merely strict.
		//
		// Hashing the stored bytes removes the disagreement and the whole class of it. It also drops
		// the requirement that a verifier own a nanosecond-capable time type, which JavaScript and
		// Python do not, and it is what this profile always meant: the spec says the serialization
		// round-trips the stored form exactly.
		if _, err := time.Parse(time.RFC3339, claim.At); err != nil {
			return fmt.Errorf("%w: claim %d at: %w", ErrClaim, i, err)
		}
		// Held as a map because the link commits to the canonical JSON object of the entry's
		// defined fields, empty ones omitted, not to a fixed list in a fixed order. An entry from
		// before an optional field existed therefore hashes identically to one that does not use
		// it. The field set itself is closed per profile: a new bound field takes a successor
		// profile name, which this construction makes cheap, since entries lacking the field hash
		// the same under both. The previous construction hashed six values positionally, which
		// made even the successor path a breaking change for every implementation.
		fields := map[string]any{
			"seq":    claim.Chain.Seq,
			"at":     claim.At,
			"actor":  p.Actor,
			"method": p.Method,
			"path":   p.Path,
			"prev":   claim.Chain.Prev,
		}
		// A field added later is hashed only when the entry carries it, exactly as the producer omits
		// it, so an entry recorded before it existed recomputes unchanged.
		for key, value := range map[string]string{
			"actor_type":     p.ActorType,
			"on_behalf_of":   p.OnBehalfOf,
			"content_digest": p.ContentDigest,
			"install_id":     p.InstallID,
		} {
			if value != "" {
				fields[key] = value
			}
		}
		payload, err := jcs.Serialize(fields)
		if err != nil {
			return fmt.Errorf("%w: claim %d: %w", ErrClaim, i, err)
		}
		sum := sha256.Sum256(payload)
		if hex.EncodeToString(sum[:]) != claim.Chain.Link {
			return fmt.Errorf("%w: claim %d link does not recompute", ErrBroken, i)
		}
	}
	return nil
}

// checkV1 recomputes the generic construction for unkeyed chains: SHA-256 over the
// canonical link input, whose claim digest covers the canonical claim without its chain
// member.
func checkV1(raw []byte, b *bundle.Bundle) error {
	installID := b.Chain.Params["install_id"]
	if installID == "" {
		return fmt.Errorf("%w: %s requires params.install_id", ErrProfile, bundle.ProfileV1)
	}
	// The id has to be the signer's, not merely present. An id a bundle states but nothing ties to
	// the producer is something a copier can restate, so a link bound to it is bound to nothing they
	// cannot also claim. The tree profile has always required this; the linear one described it and
	// did not check it.
	if installID != b.Producer.InstallID {
		return fmt.Errorf("%w: %s params.install_id %q does not match producer.install_id %q",
			ErrProfile, bundle.ProfileV1, installID, b.Producer.InstallID)
	}
	tree, err := jcs.Parse(raw)
	if err != nil {
		return err
	}
	root, ok := tree.(map[string]any)
	if !ok {
		return fmt.Errorf("%w: bundle is not a JSON object", ErrClaim)
	}
	rawClaims, ok := root["claims"].([]any)
	if !ok || len(rawClaims) != len(b.Claims) {
		return fmt.Errorf("%w: claims are not an array of objects", ErrClaim)
	}
	for i := range b.Claims {
		claim := &b.Claims[i]
		obj, ok := rawClaims[i].(map[string]any)
		if !ok {
			return fmt.Errorf("%w: claim %d is not an object", ErrClaim, i)
		}
		// The one committed-content rule: see ClaimContent. Evidence packaging (present, location)
		// is excluded here exactly as it is from a merkle leaf, so repackaging a bundle's evidence
		// never breaks a link.
		link, err := LinkV1(nil, installID, claim.Chain.Seq, claim.Chain.Prev, ClaimContent(obj))
		if err != nil {
			return fmt.Errorf("%w: claim %d: %w", ErrClaim, i, err)
		}
		if link != claim.Chain.Link {
			return fmt.Errorf("%w: claim %d link does not recompute", ErrBroken, i)
		}
	}
	return nil
}

// ClaimContent returns the members of a claim that a link or leaf commits to. This is the one
// committed-content rule both hashing profiles share: chain and inclusion describe position and
// proof, disclosures and attestations are holder- and third-party-controlled and travel outside
// the commitment, and an evidence entry's present and location are packaging details, whether and
// where the artifact travels beside this copy of the bundle. All are excluded, so the same log
// entry disclosed in two bundles that package their evidence differently commits identically.
// Redactable fields stay committed through the payload's _sd digest set either way.
func ClaimContent(claim map[string]any) map[string]any {
	content := make(map[string]any, len(claim))
	for k, v := range claim {
		if k == "chain" || k == "inclusion" || k == "disclosures" || k == "attestations" {
			continue
		}
		content[k] = v
	}
	ev, ok := content["evidence"].([]any)
	if !ok {
		return content
	}
	stripped := make([]any, 0, len(ev))
	for _, e := range ev {
		obj, ok := e.(map[string]any)
		if !ok {
			stripped = append(stripped, e)
			continue
		}
		cp := make(map[string]any, len(obj))
		for k, v := range obj {
			if k == "present" || k == "location" {
				continue
			}
			cp[k] = v
		}
		stripped = append(stripped, cp)
	}
	content["evidence"] = stripped
	return content
}

// LinkV1 computes a loomseal-chain-v1 link for a claim value tree that carries no chain
// member. With a key the link is an HMAC only the key holder can extend; without one it is
// a plain SHA-256 anyone can recompute.
func LinkV1(key []byte, installID string, seq int64, prev string, claim any) (string, error) {
	claimCanon, err := jcs.Serialize(claim)
	if err != nil {
		return "", err
	}
	claimSum := sha256.Sum256(claimCanon)
	input, err := jcs.Serialize(map[string]any{
		"domain":     bundle.ProfileV1,
		"install_id": installID,
		"seq":        seq,
		"prev":       prev,
		"claim":      "sha256:" + hex.EncodeToString(claimSum[:]),
	})
	if err != nil {
		return "", err
	}
	if len(key) == 0 {
		sum := sha256.Sum256(input)
		return hex.EncodeToString(sum[:]), nil
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(input)
	return hex.EncodeToString(mac.Sum(nil)), nil
}
