package verify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"

	"github.com/kordloom/loomseal/jcs"
)

// switchTenderClaimType is the claim type whose payloads carry SwitchTender's disclosed records.
const switchTenderClaimType = "switchtender.audit/1"

// recordKind describes one record a switchtender.audit/1 claim can disclose beside the fields its
// link commits: the payload member holding the body, the member holding the nonce its digest is
// keyed under, and the body member naming the event a reason commitment is bound to.
type recordKind struct {
	// Name is the kind's name in schema/claim-members.json, which says what claims are this kind.
	Name string
	// Body is the payload member holding the record body, a JSON object.
	Body string
	// Nonce is the payload member holding the hex nonce the entry's content_digest is keyed under.
	Nonce string
	// Event is the body member naming the event the record's reason commitment is bound to.
	Event string
	// NeedsReason reports whether the record is nothing but a reason, so a body committing none is
	// malformed rather than merely silent.
	NeedsReason bool
}

// recordKinds are the records a switchtender.audit/1 claim discloses as a JSON object: an approval
// decision and a correction appended to a decision's reason. A run's outcome is the third kind of
// record, carried as text and checked by checkOutcome.
var recordKinds = map[string]recordKind{
	"decision": {Name: "decision", Body: "decision_body", Nonce: "decision_nonce",
		Event: "decision_id"},
	"correction": {Name: "correction", Body: "correction_body", Nonce: "correction_nonce",
		Event: "correction_id", NeedsReason: true},
}

// Digest forms a record's entry commits it under, beside the legacy unkeyed sha256: form.
const (
	// keyedDigestPrefix opens the form that commits a record's canonical bytes: the hex SHA-256 of
	// the nonce and the hex HMAC-SHA256 of the bytes keyed by the nonce.
	keyedDigestPrefix = "sha256s:"
	// exactDigestPrefix opens the form that commits a disclosed text exactly as carried: the hex
	// SHA-256 of the nonce and the hex HMAC-SHA256 of the text's UTF-8 bytes keyed by the nonce.
	exactDigestPrefix = "sha256e:"
)

// reasonMembers are the payload members that disclose a record's reason: the text and the random
// value that open its commitment, or the category of the privacy redaction that removed both.
var reasonMembers = []string{"reason_text", "reason_random", "reason_redacted"}

// checkRecords verifies the records switchtender.audit/1 claims disclose beside the fields their
// links commit. The link commits the entry's content_digest, and the digest commits the record's
// body, so a body that does not reproduce the digest is not the record the chain holds. A decision
// or correction body then commits a reason, which a disclosed text must open. A redacted reason
// cannot be opened, by design, and is reported as redacted rather than failed. A disclosed spec is
// held against the spec digest every verified decision and outcome committed.
//
// A claim is a record by the method and path its link commits, and only its own record's members
// are read on it. The same names on any other claim are ordinary members, reported unchecked, so a
// bundle that used one as a plain field before records existed verifies exactly as it did.
//
// It reads the claims from the parsed document by their exact member names, so a body is
// canonicalized from the values the producer signed rather than from a decoded struct, and no name
// is folded onto another.
func (r *Report) checkRecords(claims []map[string]any, st memberStates) {
	keyedAt := firstKeyed(claims)
	var specs []disclosedSpecAt
	var committed []string
	for i, obj := range claims {
		if t, _ := obj["type"].(string); t != switchTenderClaimType {
			continue
		}
		payload, ok := obj["payload"].(map[string]any)
		if !ok {
			continue
		}
		kind := recordKindOf(payload)
		settleElsewhere(i, payload, kind, st)
		if kind == "" {
			continue
		}
		if variant, member, found := caseVariant(payload, recordMembers(kind)); found {
			r.problem("record: claim %d carries %q, which differs from %s only in case, so a reader "+
				"that folds case would take one for the other", i, variant, member)
			continue
		}
		if kind == "outcome" {
			if spec, ok := r.disclosedSpec(i, payload); ok {
				specs = append(specs, disclosedSpecAt{claim: i, digest: spec})
			}
			if digest, ok := r.checkOutcome(i, payload, keyedAt, st); ok {
				committed = append(committed, digest)
			}
			continue
		}
		k := recordKinds[kind]
		if digest, ok := r.checkRecordClaim(i, &k, payload, keyedAt, st); ok {
			committed = append(committed, digest)
		}
	}
	r.checkSpecs(specs, committed, st)
}

// firstKeyed returns the index of the first switchtender.audit/1 claim whose content_digest is in
// the keyed or the exact form, or -1 when none is. A producer that keys its digests keys every
// entry from then on, so no entry after that claim predates the keyed form.
func firstKeyed(claims []map[string]any) int {
	for i, obj := range claims {
		if t, _ := obj["type"].(string); t != switchTenderClaimType {
			continue
		}
		payload, _ := obj["payload"].(map[string]any)
		digest, _ := payload["content_digest"].(string)
		if strings.HasPrefix(digest, keyedDigestPrefix) ||
			strings.HasPrefix(digest, exactDigestPrefix) {
			return i
		}
	}
	return -1
}

// settleElsewhere reports every record member a claim carries outside its own record as unchecked.
// A record member is read only on a claim of a kind that carries it, so on any other claim it is an
// ordinary member that nothing commits.
func settleElsewhere(i int, payload map[string]any, kind string, st memberStates) {
	for name := range payload {
		decl, ok := declared.Types[switchTenderClaimType][name]
		if !ok || len(decl.Records) == 0 || slices.Contains(decl.Records, kind) {
			continue
		}
		st.settle(i, name, stateUnchecked, declared.Records.Elsewhere)
	}
}

// disclosedSpecAt is one disclosed spec's digest and the claim it rides on.
type disclosedSpecAt struct {
	// claim is the index of the claim carrying the spec.
	claim int
	// digest is sha256: and the hex SHA-256 of the spec text.
	digest string
}

// disclosedSpec returns the digest of the spec an outcome claim discloses, the SHA-256 of the
// spec_body text's UTF-8 bytes exactly as carried. The text is the canonical form the producer
// digested, so it is hashed as given and never parsed and serialized again.
func (r *Report) disclosedSpec(i int, payload map[string]any) (string, bool) {
	value, ok := payload["spec_body"]
	if !ok {
		return "", false
	}
	text, ok := value.(string)
	if !ok {
		r.problem("record: claim %d spec_body is not a string, so its bytes cannot be hashed", i)
		return "", false
	}
	sum := sha256.Sum256([]byte(text))
	return "sha256:" + hex.EncodeToString(sum[:]), true
}

// checkRecordClaim checks the decision or correction a record claim discloses, if any, and returns
// the spec digest a verified decision body commits, so the disclosed spec can be held against it.
func (r *Report) checkRecordClaim(i int, kind *recordKind, payload map[string]any, keyedAt int,
	st memberStates) (string, bool) {
	disclosed := false
	for _, m := range append([]string{kind.Body, kind.Nonce}, reasonMembers...) {
		if _, ok := payload[m]; ok {
			disclosed = true
		}
	}
	if !disclosed {
		return "", false
	}
	r.RecordsPresent = true
	body, ok := payload[kind.Body].(map[string]any)
	if !ok {
		r.problem("record: claim %d %s is missing or not an object", i, kind.Body)
		return "", false
	}
	legacy, why := recordDigestProblem(i, payload, kind, body, keyedAt)
	if why != "" {
		r.problem("record: claim %d %s %s", i, kind.Body, why)
		return "", false
	}
	if kind.Name == "decision" {
		r.DecisionRecords++
	} else {
		r.CorrectionRecords++
	}
	settle := func(member string) {
		if legacy {
			st.settle(i, member, stateChecked, declared.Records.Legacy)
			return
		}
		st.settleDeclared(i, switchTenderClaimType, member)
	}
	if legacy {
		r.LegacyRecords = append(r.LegacyRecords, fmt.Sprintf("claim %d %s", i, kind.Body))
	}
	settle(kind.Body)
	if _, ok := payload[kind.Nonce]; ok {
		settle(kind.Nonce)
	}
	r.checkReason(i, payload, kind, body, st)
	if kind.Name != "decision" {
		return "", false
	}
	spec, _ := body["spec_digest"].(string)
	return spec, true
}

// recordDigestProblem says why a record body does not reproduce the content_digest its entry
// committed, or returns empty when it does, and reports whether it did so under the legacy form.
// The digest is either the keyed form, sha256s:, the SHA-256 of the nonce and the HMAC-SHA256 of
// the body's canonical bytes keyed by the nonce, or the legacy unkeyed form, sha256:, the SHA-256
// of the canonical bytes, which an entry recorded before nonces carries with an empty nonce.
// Anyone who can guess a body confirms it against an unkeyed digest, so the form is accepted only
// on an entry that comes before the bundle's first keyed one, and is reported as legacy.
func recordDigestProblem(i int, payload map[string]any, kind *recordKind, body map[string]any,
	keyedAt int) (legacy bool, why string) {
	digest, _ := payload["content_digest"].(string)
	if digest == "" {
		return false, "is disclosed on an entry that commits no content_digest"
	}
	nonceValue, hasNonce := payload[kind.Nonce]
	nonce, isString := nonceValue.(string)
	if hasNonce && !isString {
		return false, "has a " + kind.Nonce + " that is not a string"
	}
	canonical, err := jcs.Serialize(body)
	if err != nil {
		return false, "cannot be canonicalized: " + err.Error()
	}
	if rest, keyed := strings.CutPrefix(digest, keyedDigestPrefix); keyed {
		nonceHash, mac, ok := strings.Cut(rest, ":")
		if !ok || !isHex64(nonceHash) || !isHex64(mac) {
			return false, "sits on a content_digest that is not sha256s: and two 64 hex digests"
		}
		if !isHex64(nonce) {
			return false, "has a " + kind.Nonce + " that is not 64 lowercase hex digits"
		}
		key, _ := hex.DecodeString(nonce)
		sum := sha256.Sum256(key)
		if hex.EncodeToString(sum[:]) != nonceHash {
			return false, "has a " + kind.Nonce + " the content_digest did not commit"
		}
		h := hmac.New(sha256.New, key)
		h.Write(canonical)
		if hex.EncodeToString(h.Sum(nil)) != mac {
			return false, "does not reproduce the content_digest its entry committed"
		}
		return false, ""
	}
	if rest, unkeyed := strings.CutPrefix(digest, "sha256:"); unkeyed && isHex64(rest) {
		if keyedAt >= 0 && keyedAt < i {
			return false, fmt.Sprintf("sits on an unkeyed content_digest after claim %d began the "+
				"keyed form, and only an entry from before the keyed form may carry one", keyedAt)
		}
		if nonce != "" {
			return false, "carries a " + kind.Nonce + " beside an unkeyed content_digest, which " +
				"commits none"
		}
		sum := sha256.Sum256(canonical)
		if hex.EncodeToString(sum[:]) != rest {
			return false, "does not reproduce the content_digest its entry committed"
		}
		return true, ""
	}
	return false, "sits on a content_digest in neither the sha256s: nor the sha256: form"
}

// checkReason checks the reason a verified record body commits against what the claim discloses.
// Text and its random value must open the commitment. A redaction category stands in for both
// once a privacy redaction removed them, and the commitment stays, so the reason is reported as
// redacted and cannot be opened by design. A commitment with nothing disclosed is withheld.
func (r *Report) checkReason(i int, payload map[string]any, kind *recordKind, body map[string]any,
	st memberStates) {
	text, hasText := payload["reason_text"]
	random, hasRandom := payload["reason_random"]
	category, hasRedacted := payload["reason_redacted"]
	commitValue, hasCommit := body["reason_commitment"]
	commitment, isString := commitValue.(string)
	if hasCommit && !isString {
		r.problem("record: claim %d %s carries a reason_commitment that is not a string", i, kind.Body)
		return
	}
	if commitment == "" {
		if kind.NeedsReason {
			r.problem("record: claim %d %s commits no reason, and a correction is a reason", i,
				kind.Body)
			return
		}
		if hasText || hasRandom || hasRedacted {
			r.problem("record: claim %d discloses a reason its %s commits none of", i, kind.Body)
		}
		return
	}
	if rest, ok := strings.CutPrefix(commitment, "sha256:"); !ok || !isHex64(rest) {
		r.problem("record: claim %d %s reason_commitment is not sha256: and 64 hex digits", i,
			kind.Body)
		return
	}
	event, _ := body[kind.Event].(string)
	if event == "" {
		r.problem("record: claim %d %s commits a reason but names no %s to bind it to", i,
			kind.Body, kind.Event)
		return
	}
	switch {
	case hasRedacted:
		name, ok := category.(string)
		if !ok || name == "" || hasText || hasRandom {
			r.problem("record: claim %d reason_redacted must be a category alone, with no text or "+
				"random value beside it", i)
			return
		}
		r.ReasonsRedacted = append(r.ReasonsRedacted, name)
		st.settle(i, "reason_redacted", stateRedacted,
			name+", "+declared.Types[switchTenderClaimType]["reason_redacted"].By)
	case hasText:
		t, textOK := text.(string)
		rv, randomOK := random.(string)
		if !textOK || !randomOK || !isHex64(rv) {
			r.problem("record: claim %d reason_text needs a reason_random of 64 lowercase hex digits",
				i)
			return
		}
		if !reasonOpens(commitment, event, rv, t) {
			r.problem("record: claim %d reason_text does not open the reason_commitment its %s "+
				"carries", i, kind.Body)
			return
		}
		r.ReasonsVerified++
		st.settleDeclared(i, switchTenderClaimType, "reason_text")
		st.settleDeclared(i, switchTenderClaimType, "reason_random")
	case hasRandom:
		r.problem("record: claim %d discloses a reason_random with no reason_text to open", i)
	default:
		r.ReasonsWithheld++
	}
}

// reasonOpens reports whether text under random opens commitment for the event: the commitment is
// sha256: and the hex SHA-256 of the canonical object {"event", "random", "reason"}.
func reasonOpens(commitment, event, random, text string) bool {
	canonical, err := jcs.Serialize(map[string]any{"event": event, "random": random, "reason": text})
	if err != nil {
		return false
	}
	sum := sha256.Sum256(canonical)
	return "sha256:"+hex.EncodeToString(sum[:]) == commitment
}

// checkOutcome checks the outcome record an outcome claim discloses, if any, and returns the spec
// digest it names.
//
// An outcome committed under the exact form is checked over the text's bytes as carried: the
// producer redacted and canonicalized the record before it fixed those bytes, so nothing here
// depends on the producer's redaction rules. An outcome under an older form was committed over the
// producer's own redaction of the record, which this verifier cannot rebuild, so it is counted as
// carried and unchecked, never as verified. The unkeyed form is held to the rule a record body is:
// only an entry from before the keyed form may carry it.
func (r *Report) checkOutcome(i int, payload map[string]any, keyedAt int,
	st memberStates) (string, bool) {
	value, hasBody := payload["outcome_body"]
	_, hasNonce := payload["outcome_nonce"]
	if !hasBody {
		if hasNonce {
			r.problem("record: claim %d carries an outcome_nonce with no outcome_body", i)
		}
		return "", false
	}
	r.RecordsPresent = true
	digest, _ := payload["content_digest"].(string)
	if digest == "" {
		r.problem("record: claim %d outcome_body is disclosed on an entry that commits no "+
			"content_digest", i)
		return "", false
	}
	if !strings.HasPrefix(digest, exactDigestPrefix) {
		if strings.HasPrefix(digest, "sha256:") && keyedAt >= 0 && keyedAt < i {
			r.problem("record: claim %d outcome_body sits on an unkeyed content_digest after claim "+
				"%d began the keyed form, and only an entry from before the keyed form may carry one",
				i, keyedAt)
			return "", false
		}
		r.OutcomesUnchecked++
		why := declared.Types[switchTenderClaimType]["outcome_body"].Unchecked
		st.settle(i, "outcome_body", stateUnchecked, why)
		if hasNonce {
			st.settle(i, "outcome_nonce", stateUnchecked, why)
		}
		return "", false
	}
	text, ok := value.(string)
	if !ok {
		r.problem("record: claim %d outcome_body is not a string, so its bytes cannot be checked", i)
		return "", false
	}
	nonce, _ := payload["outcome_nonce"].(string)
	if why := exactDigestProblem(digest, nonce, []byte(text)); why != "" {
		r.problem("record: claim %d outcome_body %s", i, why)
		return "", false
	}
	r.OutcomesVerified++
	st.settleDeclared(i, switchTenderClaimType, "outcome_body")
	st.settleDeclared(i, switchTenderClaimType, "outcome_nonce")
	return outcomeSpec(text)
}

// exactDigestProblem says why text does not reproduce an exact-form digest under nonce, or returns
// empty when it does.
func exactDigestProblem(digest, nonce string, text []byte) string {
	nonceHash, mac, ok := strings.Cut(strings.TrimPrefix(digest, exactDigestPrefix), ":")
	if !ok || !isHex64(nonceHash) || !isHex64(mac) {
		return "sits on a content_digest that is not sha256e: and two 64 hex digests"
	}
	if !isHex64(nonce) {
		return "has an outcome_nonce that is not 64 lowercase hex digits"
	}
	key, _ := hex.DecodeString(nonce)
	sum := sha256.Sum256(key)
	if hex.EncodeToString(sum[:]) != nonceHash {
		return "has an outcome_nonce the content_digest did not commit"
	}
	h := hmac.New(sha256.New, key)
	h.Write(text)
	if hex.EncodeToString(h.Sum(nil)) != mac {
		return "does not reproduce the content_digest its entry committed"
	}
	return ""
}

// maxOutcomeDepth is how deeply a verified outcome record may nest and still be read for the spec
// digest it names. A record is a handful of levels deep. The bound is what keeps every
// implementation reading the same records: a parser built on recursion runs out of stack long
// before one built on a loop does, and a deeper record names nothing here, everywhere.
const maxOutcomeDepth = 32

// outcomeSpec reads the spec digest a verified outcome record names: the spec_digest member of the
// JSON object the text holds. The text is read under the bundle's own rules, unique keys, valid
// strings, and integers within 2^53, and within maxOutcomeDepth, so every implementation reads the
// same value. A record that is not such an object, or names none, commits no spec digest to
// compare, which is not a failure: the record itself was checked.
func outcomeSpec(text string) (string, bool) {
	tree, err := jcs.Parse([]byte(text))
	if err != nil || !withinDepth(tree, maxOutcomeDepth) {
		return "", false
	}
	if _, err := jcs.Serialize(tree); err != nil {
		return "", false
	}
	obj, ok := tree.(map[string]any)
	if !ok {
		return "", false
	}
	spec, ok := obj["spec_digest"].(string)
	return spec, ok
}

// withinDepth reports whether v nests no deeper than limit, counting each array and object as one
// level and a scalar as none.
func withinDepth(v any, limit int) bool {
	switch t := v.(type) {
	case map[string]any:
		if limit == 0 {
			return false
		}
		for _, e := range t {
			if !withinDepth(e, limit-1) {
				return false
			}
		}
	case []any:
		if limit == 0 {
			return false
		}
		for _, e := range t {
			if !withinDepth(e, limit-1) {
				return false
			}
		}
	}
	return true
}

// checkSpecs holds every disclosed spec against the spec digest each verified decision body and
// each verified outcome record committed. A bundle discloses a spec only as one run's receipt, so
// it holds one spec, and every decision and outcome in it concerns that spec. A spec with nothing
// verified beside it to commit its digest has no commitment this verifier can reach, so it is
// counted as unchecked rather than read as matched.
func (r *Report) checkSpecs(specs []disclosedSpecAt, committed []string, st memberStates) {
	if len(specs) == 0 {
		return
	}
	for _, s := range specs[1:] {
		if s.digest != specs[0].digest {
			r.problem("record: the bundle discloses two different specs, and one run has one spec")
			return
		}
	}
	if len(committed) == 0 {
		r.SpecsUnchecked = len(specs)
		why := declared.Types[switchTenderClaimType]["spec_body"].Unchecked
		for _, s := range specs {
			st.settle(s.claim, "spec_body", stateUnchecked, why)
		}
		return
	}
	for _, c := range committed {
		if c != specs[0].digest {
			r.problem("record: a verified record committed spec %s but the disclosed spec hashes "+
				"to %s", orNone(c), specs[0].digest)
			return
		}
	}
	r.SpecsMatched = len(specs)
	for _, s := range specs {
		st.settleDeclared(s.claim, switchTenderClaimType, "spec_body")
	}
}

// orNone returns a committed spec digest for a problem line, naming an empty one plainly.
func orNone(digest string) string {
	if digest == "" {
		return "(none)"
	}
	return digest
}
