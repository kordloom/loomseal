package chain

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"

	"github.com/kordloom/loomseal/internal/bundle"
)

// at is the fixed claim time used throughout the chain tests.
const at = "2026-07-27T12:00:00Z"

// stLink recomputes the SwitchTender construction for building fixtures.
func stLink(t *testing.T, seq int64, actor, method, path, prev string) string {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339Nano, at)
	if err != nil {
		t.Fatalf("parse time: %v", err)
	}
	payload, err := json.Marshal([]string{
		strconv.FormatInt(seq, 10), parsed.UTC().Format(time.RFC3339Nano), actor, method,
		path, prev,
	})
	if err != nil {
		t.Fatalf("marshal fields: %v", err)
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
