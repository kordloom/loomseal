package chain

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/kordloom/loomseal/internal/bundle"
	"github.com/kordloom/loomseal/jcs"
)

// at is the fixed claim time used throughout the chain tests.
const at = "2026-07-27T12:00:00Z"

// stLink recomputes the SwitchTender v2 construction for building fixtures: SHA-256 over the
// canonical JSON object of the claim's fields, so a fixture link matches what the verifier computes.
func stLink(t *testing.T, seq int64, actor, method, path, prev string) string {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		t.Fatalf("parse time: %v", err)
	}
	payload, err := jcs.Serialize(map[string]any{
		"seq": seq, "at": parsed.UTC().Format(time.RFC3339Nano),
		"actor": actor, "method": method, "path": path, "prev": prev,
	})
	if err != nil {
		t.Fatalf("serialize fields: %v", err)
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// wrap assembles a parseable bundle around chained claims and returns the raw document
// and the parsed bundle.
func wrap(t *testing.T, profile string, keyed bool, params map[string]any,
	claims []any, head map[string]any) ([]byte, *bundle.Bundle) {
	t.Helper()
	keyID := "sha256:" + strings.Repeat("ab", 32)
	m := map[string]any{
		"loomseal":   "0.1",
		"bundle_id":  "lsb_test",
		"created_at": at,
		"producer": map[string]any{
			"product":         "test",
			"product_version": "1",
			"install_id":      "in_1",
			"public_key":      base64.StdEncoding.EncodeToString(make([]byte, 32)),
			"key_id":          keyID,
		},
		"subject": map[string]any{"type": "url", "id": "https://example.com"},
		"chain": map[string]any{
			"profile": profile, "keyed": keyed, "params": params, "head": head,
		},
		"claims": claims,
		"signatures": []any{map[string]any{
			"key_id": keyID, "alg": "ed25519",
			"sig": base64.StdEncoding.EncodeToString(make([]byte, 64)),
		}},
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("marshal bundle: %v", err)
	}
	b, err := bundle.Parse(raw)
	if err != nil {
		t.Fatalf("parse bundle: %v", err)
	}
	return raw, b
}

// stClaim builds one switchtender.audit claim with chain coordinates.
func stClaim(seq int64, actor, prev, link string) any {
	return map[string]any{
		"type": "switchtender.audit/1", "at": at,
		"payload": map[string]any{"actor": actor, "method": "POST", "path": "/api/runs"},
		"chain":   map[string]any{"seq": seq, "prev": prev, "link": link},
	}
}

func TestVerifySwitchTender(t *testing.T) {
	t.Parallel()
	link1 := stLink(t, 1, "amy", "POST", "/api/runs", "")
	link2 := stLink(t, 2, "bo", "POST", "/api/runs", link1)

	tests := []struct {
		Claims     []any
		Head       map[string]any
		Keyed      bool
		WantResult Result
		Want       error
	}{{ // Test 0: An intact two-entry chain verifies fully with a tied head.
		Claims:     []any{stClaim(1, "amy", "", link1), stClaim(2, "bo", link1, link2)},
		Head:       map[string]any{"seq": 2, "link": link2},
		WantResult: Result{Mode: ModeFull, Claims: 2, HeadMatched: true},
	}, { // Test 1: A head beyond the bundled claims stays untied but verifies.
		Claims:     []any{stClaim(1, "amy", "", link1)},
		Head:       map[string]any{"seq": 9, "link": strings.Repeat("cd", 32)},
		WantResult: Result{Mode: ModeFull, Claims: 1},
	}, { // Test 2: A tampered actor breaks link recomputation.
		Claims: []any{stClaim(1, "mallory", "", link1)},
		Head:   map[string]any{"seq": 1, "link": link1},
		Want:   ErrBroken,
	}, { // Test 3: A non-contiguous sequence breaks the chain.
		Claims: []any{stClaim(1, "amy", "", link1), stClaim(3, "bo", link1, link2)},
		Head:   map[string]any{"seq": 3, "link": link2},
		Want:   ErrBroken,
	}, { // Test 4: A genesis entry with a prev link breaks the chain.
		Claims: []any{stClaim(1, "amy", strings.Repeat("ef", 32), link1)},
		Head:   map[string]any{"seq": 1, "link": link1},
		Want:   ErrBroken,
	}, { // Test 5: A head behind the newest claim breaks the chain.
		Claims: []any{stClaim(1, "amy", "", link1), stClaim(2, "bo", link1, link2)},
		Head:   map[string]any{"seq": 1, "link": link1},
		Want:   ErrBroken,
	}, { // Test 6: A head link that contradicts the newest claim breaks the chain.
		Claims: []any{stClaim(1, "amy", "", link1)},
		Head:   map[string]any{"seq": 1, "link": strings.Repeat("ef", 32)},
		Want:   ErrBroken,
	}, { // Test 7: Continuity failure between entries breaks the chain.
		Claims: []any{stClaim(1, "amy", "", link1), stClaim(2, "bo", strings.Repeat("ef", 32), link2)},
		Head:   map[string]any{"seq": 2, "link": link2},
		Want:   ErrBroken,
	}, { // Test 8: Declaring the unkeyed profile as keyed is a profile error.
		Claims: []any{stClaim(1, "amy", "", link1)},
		Head:   map[string]any{"seq": 1, "link": link1},
		Keyed:  true,
		Want:   ErrProfile,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			raw, b := wrap(t, bundle.ProfileSwitchTender, test.Keyed, nil, test.Claims, test.Head)
			got, err := Verify(raw, b)
			if !errors.Is(err, test.Want) {
				t.Fatalf("error mismatch: got %v, want %v", err, test.Want)
			}
			if test.Want != nil {
				return
			}
			if diff := cmp.Diff(test.WantResult, got); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestVerifyV1(t *testing.T) {
	t.Parallel()
	// v1Claim builds one claim without chain coordinates for link computation.
	v1Claim := func(actor string) map[string]any {
		return map[string]any{
			"type": "switchtender.audit/1", "at": at,
			"payload": map[string]any{"actor": actor, "method": "POST", "path": "/api/runs"},
		}
	}
	c1 := v1Claim("amy")
	link1, err := LinkV1(nil, "in_1", 1, "", c1)
	if err != nil {
		t.Fatalf("link 1: %v", err)
	}
	c1["chain"] = map[string]any{"seq": 1, "prev": "", "link": link1}
	c2 := v1Claim("bo")
	link2, err := LinkV1(nil, "in_1", 2, link1, c2)
	if err != nil {
		t.Fatalf("link 2: %v", err)
	}
	c2["chain"] = map[string]any{"seq": 2, "prev": link1, "link": link2}
	head := map[string]any{"seq": 2, "link": link2}
	params := map[string]any{"install_id": "in_1"}

	// Test 0: An intact unkeyed generic chain recomputes fully.
	raw, b := wrap(t, bundle.ProfileV1, false, params, []any{c1, c2}, head)
	got, err := Verify(raw, b)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	want := Result{Mode: ModeFull, Claims: 2, HeadMatched: true}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}

	// Test 1: Tampering with a payload after linking breaks recomputation.
	tampered := v1Claim("mallory")
	tampered["chain"] = map[string]any{"seq": 1, "prev": "", "link": link1}
	raw, b = wrap(t, bundle.ProfileV1, false, params, []any{tampered}, map[string]any{
		"seq": 1, "link": link1,
	})
	if _, err := Verify(raw, b); !errors.Is(err, ErrBroken) {
		t.Errorf("error mismatch: got %v, want %v", err, ErrBroken)
	}

	// Test 2: A keyed generic chain verifies structurally, and a keyed link differs from
	// the unkeyed one so the key actually participates.
	keyedLink, err := LinkV1([]byte("secret"), "in_1", 1, "", v1Claim("amy"))
	if err != nil {
		t.Fatalf("keyed link: %v", err)
	}
	if keyedLink == link1 {
		t.Error("keyed link equals unkeyed link, the key is not participating")
	}

	// Test 3: A claim without chain coordinates is a claim error.
	bare := v1Claim("amy")
	raw, b = wrap(t, bundle.ProfileV1, false, params, []any{bare}, head)
	if _, err := Verify(raw, b); !errors.Is(err, ErrClaim) {
		t.Errorf("error mismatch: got %v, want %v", err, ErrClaim)
	}
}

// Known-answer links for the switchtender-audit-v1 construction.
//
// These are hardcoded on purpose. Every other link in this file is produced by stLink, which
// reimplements the construction, so a change made in both the verifier and that helper passes
// unnoticed. That is not a hypothetical: the profile moved from a positional six-field array to a
// canonical object and no test objected, which left every published verifier rejecting bundles the
// producer considered valid.
//
// The values below were computed from the specification by a separate implementation, not by this
// package, so they pin the bytes on the wire rather than agreeing with whatever the code does today.
// A change to the construction must fail here and be a deliberate, versioned decision.
const (
	// katLinkBase covers the six fields every entry carries.
	katLinkBase = "4e03f42f52842aa7f4f086d13a210a6856f6a0abadea183e257d3c7554e2211c"
	// katLinkExtended adds the optional actor type, delegated account, and content digest.
	katLinkExtended = "b89efb20412f0b328d59bd2266ed09469e42218ebdc8b4a62dfc4b5dcd680efd"
	// katLinkEscapes covers a path holding the characters RFC 8785 emits raw and encoding/json
	// escapes: an ampersand, angle brackets, and U+2028. Verifiers have disagreed here before.
	katLinkEscapes = "156f98eff9b037a9ea05028c6778889a2424d19136f647ec284353794a6735bc"
	// katAt is the claim time the known answers were computed over.
	katAt = "2026-07-27T15:00:00Z"
)

// TestSwitchTenderLinkKnownAnswers pins the wire format of a switchtender-audit-v1 link.
//
// It builds claims whose links are the constants above and requires the verifier to accept them. If
// the construction drifts in any way, by field name, ordering, encoding, or the treatment of an
// absent optional field, these stop recomputing and the test fails.
func TestSwitchTenderLinkKnownAnswers(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name    string
		Payload map[string]any
		Link    string
	}{{ // Test 0: The base construction over the six fields every entry carries.
		Name:    "base",
		Payload: map[string]any{"actor": "release-token", "method": "POST", "path": "/api/runs"},
		Link:    katLinkBase,
	}, { // Test 1: The optional fields are hashed when the entry carries them.
		Name: "extended",
		Payload: map[string]any{
			"actor": "release-token", "method": "POST", "path": "/api/runs",
			"actor_type": "token", "on_behalf_of": "ops@example.com",
			"content_digest": "sha256:deadbeef",
		},
		Link: katLinkExtended,
	}, { // Test 2: Characters RFC 8785 emits raw must not be escaped before hashing.
		Name: "json escapes",
		Payload: map[string]any{
			"actor": "release-token", "method": "POST",
			"path": "/api/runs/prod&staging<x> y",
		},
		Link: katLinkEscapes,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d %s", testNum, test.Name), func(t *testing.T) {
			t.Parallel()
			claim := map[string]any{
				"type": "switchtender.audit/1", "at": katAt, "payload": test.Payload,
				"chain": map[string]any{"seq": 1, "prev": "", "link": test.Link},
			}
			raw, b := wrap(t, bundle.ProfileSwitchTender, false, nil,
				[]any{claim}, map[string]any{"seq": 1, "link": test.Link})
			if _, err := Verify(raw, b); err != nil {
				t.Fatalf("the published link construction changed: a claim whose link is the "+
					"specified %s no longer recomputes: %v", test.Name, err)
			}
		})
	}
}

// TestSwitchTenderRejectsPositionalLink guards the revision that broke every published verifier.
//
// The profile once hashed six values as a positional array. A bundle built that way must now be
// refused rather than quietly accepted, or the two constructions would both be valid and a verifier
// could be shown whichever one suited.
func TestSwitchTenderRejectsPositionalLink(t *testing.T) {
	t.Parallel()
	fields := []any{"1", katAt, "release-token", "POST", "/api/runs", ""}
	payload, err := jcs.Serialize(fields)
	if err != nil {
		t.Fatalf("serialize positional fields: %v", err)
	}
	sum := sha256.Sum256(payload)
	positional := hex.EncodeToString(sum[:])
	if positional == katLinkBase {
		t.Fatal("the positional and object constructions collide, so this guard proves nothing")
	}

	claim := map[string]any{
		"type": "switchtender.audit/1", "at": katAt,
		"payload": map[string]any{"actor": "release-token", "method": "POST", "path": "/api/runs"},
		"chain":   map[string]any{"seq": 1, "prev": "", "link": positional},
	}
	raw, b := wrap(t, bundle.ProfileSwitchTender, false, nil,
		[]any{claim}, map[string]any{"seq": 1, "link": positional})
	if _, err := Verify(raw, b); !errors.Is(err, ErrBroken) {
		t.Errorf("a positional-form link verified as %v, want ErrBroken", err)
	}
}
