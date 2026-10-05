package verify

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"unicode"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	"github.com/kordloom/loomseal/internal/bundle"
)

// TestNoMemberGoesSilent is the invariant behind schema/claim-members.json: every payload member of
// every claim type a verifier knows is either held against a commitment or declared unchecked with
// its reason, and every such member is pinned by a vector in which the producer alters it and
// re-signs, and by vectors in which the producer plants a name that differs from it only in case.
//
// A member a switchtender-audit-v1 link does not commit used to ride inside a verified bundle with
// nothing checking it, so a producer re-signing its own receipt could rewrite it. The declaration
// says, member by member, what each one is held against. This test fails the build when a claim
// type is added without a declaration, when a declared member says neither what checks it nor why
// nothing does, when a verifying vector carries a member nothing declares and nothing expects
// reported unchecked, or when a declared member has no tamper vector, no case vector, or, for a
// name with a letter a non-ASCII character folds onto, no fold vector. Those vectors are what prove
// the verifiers do what the declaration says, and that no reader folding case can be shown one
// value while a verifier checked another.
func TestNoMemberGoesSilent(t *testing.T) {
	t.Parallel()
	var types []string
	for claimType := range declared.Types {
		types = append(types, claimType)
	}
	var known []string
	for claimType := range knownClaimTypes {
		known = append(known, claimType)
	}
	sort.Strings(types)
	sort.Strings(known)
	if diff := cmp.Diff(known, types); diff != "" {
		t.Errorf("declared claim types differ from the registry (-registry +declared):\n%s", diff)
	}

	for claimType, members := range declared.Types {
		for name, d := range members {
			where := claimType + " " + name
			switch d.State {
			case stateChecked, stateRedacted:
				if d.By == "" {
					t.Errorf("%s is %s but names nothing it is held against", where, d.State)
				}
			case stateUnchecked:
				if d.Reason == "" {
					t.Errorf("%s is unchecked with no reason given", where)
				}
				if d.Unchecked != "" {
					t.Errorf("%s is unchecked, so a condition under which it is unchecked means "+
						"nothing", where)
				}
			default:
				t.Errorf("%s has state %q, want checked, unchecked, or redacted", where, d.State)
			}
			if d.With != "" {
				partner, ok := members[d.With]
				if !ok || partner.With != "" || partner.State != d.State {
					t.Errorf("%s travels with %q, which is not a record of its own in the same state",
						where, d.With)
				}
			}
			if slices.Contains(declared.SwitchTender.Bound, name) {
				t.Errorf("%s is declared beside the link, but %s binds it", where,
					bundle.ProfileSwitchTender)
			}
			if !memberName.MatchString(name) {
				t.Errorf("%s is not lowercase ASCII letters, digits, and underscores, which the case "+
					"folding rule every verifier applies is defined over", where)
			}
			for _, kind := range d.Records {
				if _, ok := declared.Records.Kinds[kind]; !ok || claimType != switchTenderClaimType {
					t.Errorf("%s is read on %q, which is not a record kind of %s", where, kind,
						switchTenderClaimType)
				}
			}
		}
	}
	checkRecordKinds(t)

	man := readVectorManifest(t)
	names := map[string]bool{}
	for _, v := range man {
		names[v.Name] = true
	}
	for claimType, members := range declared.Types {
		slug := strings.NewReplacer(".", "-", "/", "-").Replace(claimType)
		for name, d := range members {
			want := []string{"tamper-" + slug + "-" + name, "tamper-" + slug + "-" + name + "-case"}
			if d.Unchecked != "" || (d.With != "" && members[d.With].Unchecked != "") {
				want = append(want, want[0]+"-older")
			}
			if strings.ContainsAny(name, "sk") {
				want = append(want, want[0]+"-fold")
			}
			for _, vector := range want {
				if !names[vector] {
					t.Errorf("%s %s has no tamper vector %s; regenerate the vectors", claimType, name,
						vector)
				}
			}
		}
	}

	for _, v := range man {
		// A vector that must not verify vouches for nothing it carries, so nothing in it is silent.
		if !v.MustVerify {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", v.File))
		if err != nil {
			t.Fatalf("read %s: %v", v.File, err)
		}
		for _, undeclared := range undeclaredMembers(raw, v.Unchecked) {
			t.Errorf("vector %s carries %s, which nothing declares and the vector does not expect "+
				"to be reported unchecked", v.Name, undeclared)
		}
	}
}

// manifestVector is the part of a conformance manifest entry this test reads.
type manifestVector struct {
	// Name identifies the case.
	Name string `json:"name"`
	// File is the bundle file within the vectors directory.
	File string `json:"file"`
	// MustVerify is whether the bundle must verify.
	MustVerify bool `json:"must_verify"`
	// Unchecked are the disclosed members the case expects reported unchecked.
	Unchecked []string `json:"unchecked"`
}

// memberName is the shape of every declared member name: the case folding rule the format states
// is exact for names of this shape in every language a verifier is written in.
var memberName = regexp.MustCompile(`^[a-z0-9_]+$`)

// checkRecordKinds holds the declaration's record kinds to the record check: the kinds are told
// apart by their committed method alone, so a claim is at most one of them, and each kind reads
// exactly the members the check reads for it, so the case variants a claim is refused for are the
// names the check would otherwise have read.
func checkRecordKinds(t *testing.T) {
	t.Helper()
	methods := map[string]string{}
	for name, kind := range declared.Records.Kinds {
		if other, ok := methods[kind.Method]; ok {
			t.Errorf("record kinds %s and %s share method %s", name, other, kind.Method)
		}
		methods[kind.Method] = name
	}
	if declared.Records.Elsewhere == "" || declared.Records.Legacy == "" {
		t.Error("the declaration gives no reason for a record member off its record, or for a " +
			"legacy record")
	}
	want := map[string][]string{"outcome": {"outcome_body", "outcome_nonce", "spec_body"}}
	for name, kind := range recordKinds {
		want[name] = append([]string{kind.Body, kind.Nonce}, reasonMembers...)
	}
	for name := range declared.Records.Kinds {
		got := recordMembers(name)
		sort.Strings(want[name])
		if diff := cmp.Diff(want[name], got); diff != "" {
			t.Errorf("record kind %s reads members the check does not (-check +declared):\n%s",
				name, diff)
		}
	}
}

// TestCaseFoldingIsTheFormatRule pins the folding a verifier refuses a case variant by. Go folds a
// name onto a struct field character by character, two characters folding together exactly when
// they share an orbit of unicode.SimpleFold, as strings.EqualFold does. The format states the same
// fold in a form any language implements: ASCII capitals onto their lowercase letters, the Kelvin
// sign onto k, and the long s onto s. Each character a declared name may hold has its whole orbit
// checked against that rule, so a fold the rule misses fails here rather than as a disagreement
// between verifiers.
func TestCaseFoldingIsTheFormatRule(t *testing.T) {
	t.Parallel()
	const targets = "abcdefghijklmnopqrstuvwxyz0123456789_"
	stated := map[rune][]rune{'k': {'K', '\u212a'}, 's': {'S', '\u017f'}}
	for _, c := range targets {
		var orbit []rune
		for r := unicode.SimpleFold(c); r != c; r = unicode.SimpleFold(r) {
			if !strings.EqualFold(string(r), string(c)) {
				t.Errorf("U+%04X shares an orbit with %q and does not fold onto it", r, c)
			}
			orbit = append(orbit, r)
		}
		want, ok := stated[c]
		if !ok && c >= 'a' && c <= 'z' {
			want = []rune{unicode.ToUpper(c)}
		}
		slices.Sort(orbit)
		slices.Sort(want)
		if diff := cmp.Diff(want, orbit, cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("characters folding onto %q (-format rule +Go):\n%s", c, diff)
		}
	}
	tests := []struct {
		Name       string
		WantMember string
		WantOK     bool
	}{{ // Test 0: A capital is a variant.
		Name: "Decision_body", WantMember: "decision_body", WantOK: true,
	}, { // Test 1: The long s is a variant.
		Name: "rea\u017fon_text", WantMember: "reason_text", WantOK: true,
	}, { // Test 2: The name itself is not a variant of itself.
		Name: "decision_body",
	}, { // Test 3: A ligature that only full case folding expands is not a variant.
		Name: "\ufb01nding",
	}}
	members := []string{"decision_body", "finding", "reason_text"}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			_, member, ok := caseVariant(map[string]any{test.Name: true}, members)
			if ok != test.WantOK || member != test.WantMember {
				t.Errorf("caseVariant(%q) = %q, %t, want %q, %t", test.Name, member, ok,
					test.WantMember, test.WantOK)
			}
		})
	}
}

// readVectorManifest reads the conformance manifest.
func readVectorManifest(t *testing.T) []manifestVector {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "vectors", "manifest.json"))
	if err != nil {
		t.Fatalf("read the manifest: %v", err)
	}
	var man struct {
		// Vectors are the cases.
		Vectors []manifestVector `json:"vectors"`
	}
	if err := json.Unmarshal(raw, &man); err != nil {
		t.Fatalf("parse the manifest: %v", err)
	}
	return man.Vectors
}

// undeclaredMembers lists, as "claim N member", every member a switchtender-audit-v1 claim of raw
// carries that the profile does not bind, refuse, or declare for the claim's type, and that
// expected does not name as reported unchecked.
func undeclaredMembers(raw []byte, expected []string) []string {
	var doc struct {
		// Chain is the bundle's chain declaration.
		Chain *struct {
			// Profile is the declared profile.
			Profile string `json:"profile"`
		} `json:"chain"`
		// Claims are the bundle's claims.
		Claims []struct {
			// Type is the claim type.
			Type string `json:"type"`
			// Payload is the claim payload.
			Payload map[string]json.RawMessage `json:"payload"`
		} `json:"claims"`
	}
	if json.Unmarshal(raw, &doc) != nil || doc.Chain == nil ||
		doc.Chain.Profile != bundle.ProfileSwitchTender {
		return nil
	}
	var out []string
	for i, c := range doc.Claims {
		for name := range c.Payload {
			entry := fmt.Sprintf("claim %d %s", i, name)
			_, isDeclared := declared.Types[c.Type][name]
			switch {
			case slices.Contains(declared.SwitchTender.Bound, name),
				declared.SwitchTender.Refused[name] != "",
				isDeclared, slices.Contains(expected, entry):
				continue
			}
			out = append(out, entry)
		}
	}
	sort.Strings(out)
	return out
}
