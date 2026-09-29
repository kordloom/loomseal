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
	"strconv"
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
}

// Verify checks the bundle's chain: coordinates on every claim, contiguous ascending
// sequence, continuity, the genesis rule, head consistency, and link recomputation where
// the profile permits. The raw document is needed for profiles that digest claim bytes.
func Verify(raw []byte, b *bundle.Bundle) (Result, error) {
	var res Result
	if b.Chain == nil {
		return res, fmt.Errorf("%w: bundle declares no chain", ErrClaim)
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
}

// checkSwitchTender recomputes the shipped SwitchTender construction: SHA-256 over the
// JSON array of sequence, RFC 3339 nanosecond UTC time, actor, method, path, and the
// previous link.
func checkSwitchTender(b *bundle.Bundle) error {
	for i := range b.Claims {
		claim := &b.Claims[i]
		var p switchTenderPayload
		if err := json.Unmarshal(claim.Payload, &p); err != nil {
			return fmt.Errorf("%w: claim %d payload: %w", ErrClaim, i, err)
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
		// Held as []any because the JCS encoder works over parsed JSON values, which is what makes
		// it the same encoder a verifier applies to a whole document.
		fields := []any{
			strconv.FormatInt(claim.Chain.Seq, 10), claim.At,
			p.Actor, p.Method, p.Path, claim.Chain.Prev,
		}
		// Serialized with this module's own JCS encoder rather than encoding/json.
		//
		// encoding/json escapes &, <, >, U+2028, and U+2029 for embedding in HTML. RFC 8785 emits
		// them raw, which is what the producer and the Python reference both do. A single recorded
		// path containing an ampersand therefore recomputed to a different link here than at the
		// two other implementations, and this verifier called an honest chain broken. The entry is
		// append-only, so every future bundle covering it failed the same way, and the only escape
		// was to truncate the trail past it. This module already had the correct encoder; this call
		// site simply did not use it.
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
		delete(obj, "chain")
		link, err := LinkV1(nil, installID, claim.Chain.Seq, claim.Chain.Prev, obj)
		if err != nil {
			return fmt.Errorf("%w: claim %d: %w", ErrClaim, i, err)
		}
		if link != claim.Chain.Link {
			return fmt.Errorf("%w: claim %d link does not recompute", ErrBroken, i)
		}
	}
	return nil
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
