package verify

import (
	"encoding/json"
	"slices"
	"sort"
	"strings"

	"github.com/kordloom/loomseal/internal/bundle"
	"github.com/kordloom/loomseal/jcs"
	"github.com/kordloom/loomseal/schema"
)

// Member states a disclosed member is reported in.
const (
	// stateChecked is a member held against a commitment that held.
	stateChecked = "checked"
	// stateUnchecked is a member nothing this verifier reaches commits.
	stateUnchecked = "unchecked"
	// stateRedacted is a member that is the holder's statement that it withheld what the member
	// stood for, with a category nothing commits.
	stateRedacted = "redacted"
)

// memberDecl is how claim-members.json declares one payload member.
type memberDecl struct {
	// State is checked, unchecked, or redacted.
	State string `json:"state"`
	// By names the commitment a checked or redacted member is held against.
	By string `json:"by"`
	// Reason says why an unchecked member is unchecked.
	Reason string `json:"reason"`
	// Unchecked says when a member declared checked is unchecked instead.
	Unchecked string `json:"unchecked"`
	// With names the member this one travels with, so the pair counts as one record.
	With string `json:"with"`
	// Records names the record kinds whose claims carry and check the member. A member that names
	// any is read only on a claim of one of them, and is an ordinary member everywhere else.
	Records []string `json:"records"`
}

// recordDecl is how claim-members.json identifies one kind of record: by the method and path a
// switchtender-audit-v1 link commits.
type recordDecl struct {
	// Method is the committed method a claim of this kind carries.
	Method string `json:"method"`
	// Path is the committed path's pattern, compared segment by segment, where a {name} segment
	// matches any non-empty segment. Empty matches every path.
	Path string `json:"path"`
}

// declaration is claim-members.json.
type declaration struct {
	// Records says which switchtender.audit/1 claims are records, and what a verifier reports for a
	// record member it does not read.
	Records struct {
		// Kinds identifies each kind of record by name.
		Kinds map[string]recordDecl `json:"kinds"`
		// Elsewhere is why a record member on a claim that is not its record is unchecked.
		Elsewhere string `json:"elsewhere"`
		// Legacy is what a record body checked against the legacy unkeyed digest form is held
		// against.
		Legacy string `json:"legacy"`
	} `json:"records"`
	// SwitchTender is what switchtender-audit-v1 binds and refuses.
	SwitchTender struct {
		// Bound are the members its link commits.
		Bound []string `json:"bound"`
		// Refused are the members it refuses, with why.
		Refused map[string]string `json:"refused"`
	} `json:"switchtender-audit-v1"`
	// Types declares each registered claim type's members.
	Types map[string]map[string]memberDecl `json:"types"`
}

// declared is the member declaration every verifier in this repository reads. The file is embedded,
// so one that does not parse is a build that should never have shipped, and it stops at once.
var declared = func() declaration {
	var d declaration
	if err := json.Unmarshal(schema.ClaimMembers, &d); err != nil {
		panic("verify: schema/claim-members.json does not parse: " + err.Error())
	}
	return d
}()

// DisclosedMember is one payload member a switchtender-audit-v1 link does not commit, and what it
// was held against.
type DisclosedMember struct {
	// Claim is the claim's index in the bundle.
	Claim int `json:"claim"`
	// Member is the payload member's name.
	Member string `json:"member"`
	// State is checked, unchecked, or redacted.
	State string `json:"state"`
	// Detail names the commitment it was checked against, the category the holder claims for what
	// it withheld, or why it is unchecked.
	Detail string `json:"detail"`
	// With names the member this one travels with, so a reader counts the pair as one record. Empty
	// for a member that is a record of its own.
	With string `json:"with,omitempty"`
}

// memberKey names one member of one claim.
type memberKey struct {
	// claim is the claim's index.
	claim int
	// member is the payload member's name.
	member string
}

// memberState is what a check established about one member.
type memberState struct {
	// state is checked, unchecked, or redacted.
	state string
	// detail is what it was held against, or why not.
	detail string
}

// memberStates holds what each check established about the members it covered, for one run. It is
// kept beside the report rather than in it, so a report stays a value a caller can compare.
type memberStates map[memberKey]memberState

// settle records what a check established about one member of one claim.
func (st memberStates) settle(claim int, member, state, detail string) {
	st[memberKey{claim: claim, member: member}] = memberState{state: state, detail: detail}
}

// settleDeclared records a member as its declaration states it: checked or redacted against the
// commitment the declaration names.
func (st memberStates) settleDeclared(claim int, claimType, member string) {
	decl := declared.Types[claimType][member]
	st.settle(claim, member, decl.State, decl.By)
}

// recordKindOf names the kind of record a switchtender.audit/1 payload is, by the method and path
// its link commits, read by their exact names. It returns empty for a claim that is no record.
func recordKindOf(payload map[string]any) string {
	method, _ := payload["method"].(string)
	path, _ := payload["path"].(string)
	for name, kind := range declared.Records.Kinds {
		if method == kind.Method && pathMatches(kind.Path, path) {
			return name
		}
	}
	return ""
}

// pathMatches reports whether path fits pattern segment by segment, a {name} segment matching any
// non-empty segment and every other segment matching only itself. An empty pattern matches every
// path.
func pathMatches(pattern, path string) bool {
	if pattern == "" {
		return true
	}
	want, got := strings.Split(pattern, "/"), strings.Split(path, "/")
	if len(want) != len(got) {
		return false
	}
	for i, w := range want {
		if strings.HasPrefix(w, "{") && strings.HasSuffix(w, "}") {
			if got[i] == "" {
				return false
			}
			continue
		}
		if w != got[i] {
			return false
		}
	}
	return true
}

// pathSegment returns the segment of path that the {name} segment of pattern matches, or empty
// when path does not fit pattern or pattern has no such segment.
func pathSegment(pattern, path, name string) string {
	if !pathMatches(pattern, path) {
		return ""
	}
	got := strings.Split(path, "/")
	for i, w := range strings.Split(pattern, "/") {
		if w == "{"+name+"}" && i < len(got) {
			return got[i]
		}
	}
	return ""
}

// recordMembers lists, in name order, the switchtender.audit/1 members a record of kind is read
// for.
func recordMembers(kind string) []string {
	var out []string
	for name, decl := range declared.Types[switchTenderClaimType] {
		if slices.Contains(decl.Records, kind) {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// caseVariant finds a payload member whose name differs from one of members only in case, and
// returns it with the member it folds to. Case is folded the way encoding/json folds a member onto
// a struct field, so a reader decoding with it would take the variant for the member a check read
// by its exact name. The format compares names exactly, so a claim carrying one is refused rather
// than read either way.
func caseVariant(payload map[string]any, members []string) (variant, member string, ok bool) {
	names := make([]string, 0, len(payload))
	for name := range payload {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, m := range members {
			if name != m && strings.EqualFold(name, m) {
				return name, m, true
			}
		}
	}
	return "", "", false
}

// claimTrees parses raw and returns its claims by their exact member names, an entry that is not
// an object left nil. It returns nil when raw does not parse, which the signature check has
// already reported.
func claimTrees(raw []byte) []map[string]any {
	tree, err := jcs.Parse(raw)
	if err != nil {
		return nil
	}
	root, ok := tree.(map[string]any)
	if !ok {
		return nil
	}
	rawClaims, _ := root["claims"].([]any)
	out := make([]map[string]any, len(rawClaims))
	for i, c := range rawClaims {
		out[i], _ = c.(map[string]any)
	}
	return out
}

// classifyDisclosed lists every member a switchtender-audit-v1 link does not commit, in the state
// the checks left it: checked, redacted, or unchecked. A member no check confirmed is unchecked,
// with the reason its declaration gives, or because nothing declares it. Under a profile that
// commits the whole claim nothing is disclosed beside the link, and with no chain nothing is
// committed beyond the signature, which the conformance level already says. Names are read from
// the parsed claims exactly, so a name that differs from a declared one only in case is reported as
// the undeclared member it is.
func (r *Report) classifyDisclosed(b *bundle.Bundle, claims []map[string]any, st memberStates) {
	if b.Chain == nil || b.Chain.Profile != bundle.ProfileSwitchTender {
		return
	}
	bound := map[string]bool{}
	for _, m := range declared.SwitchTender.Bound {
		bound[m] = true
	}
	for i, c := range claims {
		claimType, _ := c["type"].(string)
		payload, ok := c["payload"].(map[string]any)
		if !ok {
			continue
		}
		names := make([]string, 0, len(payload))
		for name := range payload {
			if !bound[name] && declared.SwitchTender.Refused[name] == "" {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		for _, name := range names {
			decl, isDeclared := declared.Types[claimType][name]
			// A member counts with the one it travels with only when that one is on the same claim.
			// Alone, it is a record of its own, or a stray nonce could ride unchecked and uncounted.
			with := decl.With
			if _, present := payload[with]; !present {
				with = ""
			}
			m := DisclosedMember{Claim: i, Member: name, With: with}
			got, settled := st[memberKey{claim: i, member: name}]
			switch {
			case settled:
				m.State, m.Detail = got.state, got.detail
			case isDeclared && decl.State == stateUnchecked:
				m.State, m.Detail = stateUnchecked, decl.Reason
			case isDeclared:
				m.State, m.Detail = stateUnchecked, "its check did not pass"
			default:
				m.State = stateUnchecked
				m.Detail = "not declared for " + claimType + ", and a " + bundle.ProfileSwitchTender +
					" link does not commit it"
			}
			r.Disclosed = append(r.Disclosed, m)
			if m.State == stateUnchecked && m.With == "" {
				r.DisclosedUnchecked++
			}
		}
	}
}
