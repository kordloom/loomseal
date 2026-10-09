package bundle

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

// base returns a minimal valid unchained bundle as a value tree.
func base() map[string]any {
	keyID := "sha256:" + strings.Repeat("ab", 32)
	return map[string]any{
		"loomseal":   "0.1",
		"bundle_id":  "lsb_test",
		"created_at": "2026-07-27T12:00:00Z",
		"producer": map[string]any{
			"product":         "switchtender",
			"product_version": "0.4.0",
			"install_id":      "in_1",
			"public_key":      base64.StdEncoding.EncodeToString(make([]byte, 32)),
			"key_id":          keyID,
		},
		"subject": map[string]any{"type": "url", "id": "https://example.com"},
		"claims": []any{map[string]any{
			"type":    "switchtender.audit/1",
			"at":      "2026-07-27T12:00:00Z",
			"payload": map[string]any{"target_id": "tg_1"},
		}},
		"signatures": []any{map[string]any{
			"key_id": keyID,
			"alg":    "ed25519",
			"sig":    base64.StdEncoding.EncodeToString(make([]byte, 64)),
		}},
	}
}

// mustJSON marshals a value tree or fails the test.
func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

// producerOf returns the producer submap for mutation.
func producerOf(m map[string]any) map[string]any {
	p, _ := m["producer"].(map[string]any)
	return p
}

// claimOf returns the first claim submap for mutation.
func claimOf(m map[string]any) map[string]any {
	c, _ := m["claims"].([]any)
	first, _ := c[0].(map[string]any)
	return first
}

// testAttestation returns an attestation object carrying at, whose key and signature are well
// formed and verify nothing, which parse does not check.
func testAttestation(at string) map[string]any {
	return map[string]any{
		"key_id": "sha256:" + strings.Repeat("ab", 32), "alg": "ed25519", "role": "approver",
		"public_key": base64.StdEncoding.EncodeToString(make([]byte, 32)),
		"sig":        base64.StdEncoding.EncodeToString(make([]byte, 64)), "at": at,
	}
}

func TestParse(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Mutate  func(m map[string]any)
		Want    error
		WantMsg string
	}{{ // Test 0: The base bundle is valid.
		Mutate: func(m map[string]any) {},
	}, { // Test 1: Unknown top-level fields are rejected.
		Mutate: func(m map[string]any) { m["extra"] = 1 }, Want: ErrParse,
	}, { // Test 2: A wrong format version is rejected.
		Mutate: func(m map[string]any) { m["loomseal"] = "0.2" }, Want: ErrUnsupported,
	}, { // Test 3: An empty bundle_id is rejected.
		Mutate: func(m map[string]any) { m["bundle_id"] = "" }, Want: ErrSchema,
	}, { // Test 4: A malformed created_at is rejected.
		Mutate: func(m map[string]any) { m["created_at"] = "yesterday" }, Want: ErrSchema,
	}, { // Test 5: A wrong-size public key is rejected.
		Mutate: func(m map[string]any) {
			producerOf(m)["public_key"] = base64.StdEncoding.EncodeToString(make([]byte, 16))
		}, Want: ErrSchema,
	}, { // Test 6: A malformed producer key_id is rejected.
		Mutate: func(m map[string]any) { producerOf(m)["key_id"] = "abc" }, Want: ErrSchema,
	}, { // Test 7: A subject type outside the token pattern is rejected; an unknown token is
		// vocabulary and passes, which the subject-unknown-type vector pins from the other side.
		Mutate: func(m map[string]any) {
			m["subject"] = map[string]any{"type": "Not A Token!", "id": "x"}
		}, Want: ErrSchema,
	}, { // Test 8: A bundle without claims is rejected.
		Mutate: func(m map[string]any) { m["claims"] = []any{} }, Want: ErrSchema,
	}, { // Test 9: A malformed claim type is rejected.
		Mutate: func(m map[string]any) { claimOf(m)["type"] = "SwitchTender.Audit" }, Want: ErrSchema,
	}, { // Test 10: A non-object payload is rejected.
		Mutate: func(m map[string]any) { claimOf(m)["payload"] = []any{1} }, Want: ErrSchema,
	}, { // Test 11: A malformed evidence digest is rejected.
		Mutate: func(m map[string]any) {
			claimOf(m)["evidence"] = []any{map[string]any{"role": "snapshot", "digest": "sha256:short"}}
		}, Want: ErrSchema,
	}, { // Test 12: An unknown chain profile is rejected.
		Mutate: func(m map[string]any) {
			m["chain"] = map[string]any{
				"profile": "mystery-v9", "keyed": false,
				"head": map[string]any{"seq": 1, "link": strings.Repeat("ab", 32)},
			}
		}, Want: ErrUnsupported,
	}, { // Test 13: A chain head with a bad link is rejected.
		Mutate: func(m map[string]any) {
			m["chain"] = map[string]any{
				"profile": ProfileV1, "keyed": false,
				"head": map[string]any{"seq": 1, "link": "nope"},
			}
		}, Want: ErrSchema,
	}, { // Test 14: Claim chain coordinates below one are rejected.
		Mutate: func(m map[string]any) {
			claimOf(m)["chain"] = map[string]any{"seq": 0, "link": strings.Repeat("ab", 32)}
		}, Want: ErrSchema,
	}, { // Test 15: An unknown anchor type is rejected.
		Mutate: func(m map[string]any) {
			m["anchors"] = []any{map[string]any{
				"type": "carrier-pigeon", "seq": 1, "link": strings.Repeat("ab", 32),
				"at": "2026-07-27T12:00:00Z", "ref": "x",
			}}
		}, Want: ErrSchema,
	}, { // Test 16: A bundle without signatures is rejected.
		Mutate: func(m map[string]any) { m["signatures"] = []any{} }, Want: ErrSchema,
	}, { // Test 17: A wrong signature algorithm is rejected.
		Mutate: func(m map[string]any) {
			s, _ := m["signatures"].([]any)
			first, _ := s[0].(map[string]any)
			first["alg"] = "rsa"
		}, Want: ErrUnsupported,
	}, { // Test 18: A wrong-size signature is rejected.
		Mutate: func(m map[string]any) {
			s, _ := m["signatures"].([]any)
			first, _ := s[0].(map[string]any)
			first["sig"] = base64.StdEncoding.EncodeToString(make([]byte, 63))
		}, Want: ErrSchema,
	}, { // Test 19: An incomplete verdict is rejected.
		Mutate: func(m map[string]any) {
			claimOf(m)["verdict"] = map[string]any{"policy": "p/1"}
		}, Want: ErrSchema,
	}, { // Test 20: A genesis claim with an empty prev parses, the control for the null case.
		Mutate: func(m map[string]any) { chainWithPrev(m, "") },
	}, { // Test 21: A null prev is rejected rather than read as the empty string.
		Mutate: func(m map[string]any) { chainWithPrev(m, nil) }, Want: ErrSchema,
	}, { // Test 22: A null keyed flag is rejected rather than read as false.
		Mutate: func(m map[string]any) {
			chainWithPrev(m, "")
			m["chain"].(map[string]any)["keyed"] = nil
		}, Want: ErrSchema,
	}, { // Test 23: A public key carrying a line break inside its base64 is rejected.
		Mutate: func(m map[string]any) {
			key := base64.StdEncoding.EncodeToString(make([]byte, 32))
			producerOf(m)["public_key"] = key[:10] + "\n" + key[10:]
		}, Want: ErrSchema,
	}, { // Test 24: A signature carrying a line break inside its base64 is rejected.
		Mutate: func(m map[string]any) {
			s, _ := m["signatures"].([]any)
			first, _ := s[0].(map[string]any)
			sig := base64.StdEncoding.EncodeToString(make([]byte, 64))
			first["sig"] = sig[:20] + "\r\n" + sig[20:]
		}, Want: ErrSchema,
	}, { // Test 25: A null disclosure value is the one null the schema allows, since the value is
		// the revealed field itself.
		Mutate: func(m map[string]any) {
			claimOf(m)["disclosures"] = []any{
				map[string]any{"salt": "s", "name": "n", "value": nil},
			}
		},
	}, { // Test 26: A null chain param is rejected rather than read as the empty string.
		Mutate: func(m map[string]any) {
			chainWithPrev(m, "")
			m["chain"].(map[string]any)["params"] = map[string]any{"install_id": nil}
		}, Want: ErrSchema,
	}, { // Test 27: A string chain param parses, the control for the null case.
		Mutate: func(m map[string]any) {
			chainWithPrev(m, "")
			m["chain"].(map[string]any)["params"] = map[string]any{"install_id": "in_1"}
		},
	}, { // Test 28: A null claim attestation entry is rejected rather than read as an empty one.
		Mutate: func(m map[string]any) { claimOf(m)["attestations"] = []any{nil} },
		Want:   ErrSchema,
	}, { // Test 29: A null head attestation entry is rejected rather than read as an empty one.
		Mutate: func(m map[string]any) { m["attestations"] = []any{nil} },
		Want:   ErrSchema,
	}, { // Test 30: A null disclosure entry is rejected rather than read as an empty one.
		Mutate: func(m map[string]any) { claimOf(m)["disclosures"] = []any{nil} },
		Want:   ErrSchema,
	}, { // Test 31: A null claim is rejected as null rather than read as an empty claim, which
		// would fail later for its empty fields.
		Mutate:  func(m map[string]any) { m["claims"] = []any{claimOf(m), nil} },
		Want:    ErrSchema,
		WantMsg: "claim 1 is null",
	}, { // Test 32: A created_at with a one-digit hour is not RFC 3339 and is rejected.
		Mutate: func(m map[string]any) { m["created_at"] = "2026-07-27T1:00:00Z" },
		Want:   ErrSchema,
	}, { // Test 33: A claim time carrying a numeric offset is rejected, since every time ends in Z.
		Mutate:  func(m map[string]any) { claimOf(m)["at"] = "2026-07-27T15:00:00+00:00" },
		Want:    ErrSchema,
		WantMsg: "claim 0 at",
	}, { // Test 34: A claim attestation carrying a time in the one form parses.
		Mutate: func(m map[string]any) {
			claimOf(m)["attestations"] = []any{testAttestation("2026-08-30T12:00:00Z")}
		},
	}, { // Test 35: A claim attestation carrying an empty at is rejected rather than read as one
		// that carries no time.
		Mutate: func(m map[string]any) {
			claimOf(m)["attestations"] = []any{testAttestation("")}
		},
		Want:    ErrSchema,
		WantMsg: "claim 0 attestation 0 at",
	}, { // Test 36: A claim attestation whose at carries a numeric offset is rejected.
		Mutate: func(m map[string]any) {
			claimOf(m)["attestations"] = []any{testAttestation("2026-08-30T12:00:00+00:00")}
		},
		Want:    ErrSchema,
		WantMsg: "claim 0 attestation 0 at",
	}, { // Test 37: A head attestation carrying an empty at is rejected.
		Mutate:  func(m map[string]any) { m["attestations"] = []any{testAttestation("")} },
		Want:    ErrSchema,
		WantMsg: "head attestation 0 at",
	}, { // Test 38: An attestation that carries no at parses, since the member is optional.
		Mutate: func(m map[string]any) {
			att := testAttestation("")
			delete(att, "at")
			claimOf(m)["attestations"] = []any{att}
		},
	}, { // Test 39: A bundle with no version declares none and is refused at parse.
		Mutate:  func(m map[string]any) { delete(m, "loomseal") },
		Want:    ErrParse,
		WantMsg: "carries no loomseal member",
	}, { // Test 40: A version that is not a string declares none and is refused at parse.
		Mutate:  func(m map[string]any) { m["loomseal"] = 1 },
		Want:    ErrParse,
		WantMsg: "loomseal is not a string",
	}, { // Test 41: Another version is unsupported beside a member the schema does not define.
		Mutate: func(m map[string]any) {
			m["loomseal"] = "0.2"
			m["extra"] = 1
		},
		Want: ErrUnsupported,
	}, { // Test 42: Another version is unsupported beside a number outside the profile.
		Mutate: func(m map[string]any) {
			m["loomseal"] = "0.2"
			claimOf(m)["payload"].(map[string]any)["r"] = 1.5
		},
		Want: ErrUnsupported,
	}, { // Test 43: Version 0.1 refuses a number outside the profile at parse.
		Mutate:  func(m map[string]any) { claimOf(m)["payload"].(map[string]any)["r"] = 1.5 },
		Want:    ErrParse,
		WantMsg: "non-integer literal",
	}, { // Test 44: The number profile is held before the value rule that finds a chain profile
		// unknown, so the number is what refuses the bundle.
		Mutate: func(m map[string]any) {
			m["chain"] = map[string]any{
				"profile": "mystery-v9", "keyed": false,
				"head": map[string]any{"seq": 1, "link": strings.Repeat("ab", 32)},
			}
			claimOf(m)["payload"].(map[string]any)["r"] = 1.5
		},
		Want: ErrParse,
	}, { // Test 45: Member names are held before the value rule that finds a chain profile
		// unknown, so the unknown member is what refuses the bundle.
		Mutate: func(m map[string]any) {
			m["chain"] = map[string]any{
				"profile": "mystery-v9", "keyed": false,
				"head": map[string]any{"seq": 1, "link": strings.Repeat("ab", 32)},
			}
			claimOf(m)["extra"] = "x"
		},
		Want: ErrParse,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			m := base()
			test.Mutate(m)
			_, err := Parse(mustJSON(t, m))
			if !errors.Is(err, test.Want) {
				t.Errorf("error mismatch: got %v, want %v", err, test.Want)
			}
			if test.WantMsg != "" && (err == nil || !strings.Contains(err.Error(), test.WantMsg)) {
				t.Errorf("error message mismatch: got %v, want it to contain %q", err, test.WantMsg)
			}
		})
	}
}

// TestParseTime holds ParseTime to the one time form the format allows, the RFC 3339 date-time
// production narrowed to UTC with years from 0001 to 9999, refusing the looser forms time.Parse
// accepts under the RFC3339 layout and the forms general date parsers read. A time that parses
// is read to the whole microsecond, with finer digits dropped toward the earlier instant.
func TestParseTime(t *testing.T) {
	t.Parallel()
	tests := []struct {
		WantMicro int64
		WantOK    bool
		In        string
	}{{ // Test 0: A UTC time parses.
		In: "2026-07-27T15:00:00Z", WantOK: true, WantMicro: 1785164400000000,
	}, { // Test 1: A fraction after a period parses at any length, read to the microsecond.
		In: "2026-07-27T15:00:00.123456789123Z", WantOK: true, WantMicro: 1785164400123456,
	}, { // Test 2: The first instant of year 0001 parses.
		In: "0001-01-01T00:00:00Z", WantOK: true, WantMicro: -62135596800000000,
	}, { // Test 3: The last instant of year 9999 parses, its nanosecond digits dropped.
		In: "9999-12-31T23:59:59.999999999Z", WantOK: true, WantMicro: 253402300799999999,
	}, { // Test 4: February 29 parses in a leap year.
		In: "2024-02-29T00:00:00Z", WantOK: true, WantMicro: 1709164800000000,
	}, { // Test 5: A numeric offset is refused.
		In: "2026-07-27T15:00:00-05:30",
	}, { // Test 6: A zero numeric offset is refused.
		In: "2026-07-27T15:00:00+00:00",
	}, { // Test 7: Year 0000 is refused.
		In: "0000-02-29T00:00:00Z",
	}, { // Test 8: A one-digit hour is refused.
		In: "2026-07-27T1:00:00Z",
	}, { // Test 9: A comma before the fraction is refused.
		In: "2026-07-27T15:00:00,5Z",
	}, { // Test 10: A lower case separator is refused.
		In: "2026-07-27t15:00:00Z",
	}, { // Test 11: A lower case zone letter is refused.
		In: "2026-07-27T15:00:00z",
	}, { // Test 12: A space between the date and the time is refused.
		In: "2026-07-27 15:00:00Z",
	}, { // Test 13: A leap second is refused.
		In: "2016-12-31T23:59:60Z",
	}, { // Test 14: An hour of 24 is refused.
		In: "2026-07-27T24:00:00Z",
	}, { // Test 15: February 29 is refused in a common year.
		In: "1900-02-29T00:00:00Z",
	}, { // Test 16: A month of 13 is refused.
		In: "2026-13-01T00:00:00Z",
	}, { // Test 17: A time with no zone is refused.
		In: "2026-07-27T15:00:00",
	}, { // Test 18: Trailing text is refused.
		In: "2026-07-27T15:00:00Z\n",
	}, { // Test 19: A digit outside ASCII is refused.
		In: "2026-07-27T15:00:0\uff10Z",
	}, { // Test 20: A period with no fraction digits is refused.
		In: "2026-07-27T15:00:00.Z",
	}, { // Test 21: An empty string is refused.
		In: "",
	}, { // Test 22: Half a microsecond is dropped, not rounded up.
		In: "2026-07-27T15:00:00.0000005Z", WantOK: true, WantMicro: 1785164400000000,
	}, { // Test 23: A sub-microsecond fraction before the epoch drops toward the earlier instant.
		In: "1969-12-31T23:59:59.9999999Z", WantOK: true, WantMicro: -1,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got, err := ParseTime(test.In)
			if ok := err == nil; ok != test.WantOK {
				t.Errorf("ok mismatch for %q: got %v, want %v (%v)", test.In, ok, test.WantOK, err)
			}
			if !test.WantOK {
				return
			}
			if diff := cmp.Diff(time.UnixMicro(test.WantMicro).UTC(), got); diff != "" {
				t.Errorf("time mismatch for %q (-want +got):\n%s", test.In, diff)
			}
		})
	}
}

// chainWithPrev declares an unkeyed loomseal-chain-v1 chain on m and gives its one claim genesis
// coordinates carrying prev, so a test can spell the empty predecessor two ways.
func chainWithPrev(m map[string]any, prev any) {
	link := strings.Repeat("ab", 32)
	m["chain"] = map[string]any{
		"profile": ProfileV1, "keyed": false,
		"head": map[string]any{"seq": 1, "link": link},
	}
	claimOf(m)["chain"] = map[string]any{"seq": 1, "prev": prev, "link": link}
}

// Test that trailing data after the bundle document is rejected.
func TestParseTrailingData(t *testing.T) {
	t.Parallel()
	raw := append(mustJSON(t, base()), []byte(" {}")...)
	if _, err := Parse(raw); !errors.Is(err, ErrParse) {
		t.Errorf("error mismatch: got %v, want %v", err, ErrParse)
	}
}

// Test that CanonicalUnsigned empties signatures and is independent of member order.
func TestCanonicalUnsigned(t *testing.T) {
	t.Parallel()
	a := []byte(`{"b":1,"a":2,"signatures":[{"key_id":"x"}]}`)
	c := []byte(`{"signatures":[],"a":2,"b":1}`)
	gotA, err := CanonicalUnsigned(a)
	if err != nil {
		t.Fatalf("canonicalize a: %v", err)
	}
	gotC, err := CanonicalUnsigned(c)
	if err != nil {
		t.Fatalf("canonicalize c: %v", err)
	}
	if diff := cmp.Diff(string(gotC), string(gotA)); diff != "" {
		t.Errorf("mismatch (-want +got):\n%s", diff)
	}
	if want := `{"a":2,"b":1,"signatures":[]}`; string(gotA) != want {
		t.Errorf("canonical form mismatch: got %s, want %s", gotA, want)
	}
}

// TestAnchorValidate pins every rule an anchor record has to satisfy.
//
// An anchor is the part of a bundle that says the chain existed at a point in time. A malformed one
// that parsed anyway would let a producer attach something that looks like external corroboration
// and is not, which is worse than carrying no anchor at all.
func TestAnchorValidate(t *testing.T) {
	t.Parallel()
	good := Anchor{
		Type: "rfc3161", Seq: 1, Link: strings.Repeat("ab", 32),
		At: "2026-07-27T15:00:00Z", Ref: "https://freetsa.org/tsr",
	}
	if err := good.validate(0); err != nil {
		t.Fatalf("a well-formed anchor was rejected: %v", err)
	}
	withProof := good
	withProof.Proof = base64.StdEncoding.EncodeToString([]byte("token bytes"))
	if err := withProof.validate(0); err != nil {
		t.Errorf("an anchor carrying a valid proof was rejected: %v", err)
	}

	tests := []struct {
		Name   string
		Mutate func(a *Anchor)
	}{
		{Name: "unknown type", Mutate: func(a *Anchor) { a.Type = "carrier-pigeon" }},
		{Name: "empty type", Mutate: func(a *Anchor) { a.Type = "" }},
		{Name: "sequence below one", Mutate: func(a *Anchor) { a.Seq = 0 }},
		{Name: "negative sequence", Mutate: func(a *Anchor) { a.Seq = -5 }},
		{Name: "link is not a hash", Mutate: func(a *Anchor) { a.Link = "nope" }},
		{Name: "empty link", Mutate: func(a *Anchor) { a.Link = "" }},
		{Name: "no reference to check", Mutate: func(a *Anchor) { a.Ref = "" }},
		{Name: "proof is not base64", Mutate: func(a *Anchor) { a.Proof = "!!! not base64 !!!" }},
		{Name: "proof carries a line break", Mutate: func(a *Anchor) { a.Proof = "dG9r\nZW4=" }},
		{Name: "time is not RFC 3339", Mutate: func(a *Anchor) { a.At = "last Tuesday" }},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			bad := good
			test.Mutate(&bad)
			if err := bad.validate(3); err == nil {
				t.Error("an invalid anchor validated")
			} else if !errors.Is(err, ErrSchema) {
				t.Errorf("error = %v, want ErrSchema so the caller can tell a schema fault apart", err)
			}
		})
	}
}

// TestKeyIDShape pins the producer fingerprint an operator publishes and a relying party pins.
func TestKeyIDShape(t *testing.T) {
	t.Parallel()
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for i := range pub {
		pub[i] = byte(i)
	}
	id := KeyID(pub)
	if !strings.HasPrefix(id, "sha256:") || len(id) != len("sha256:")+64 {
		t.Errorf("KeyID = %q, want sha256: followed by 64 hex characters", id)
	}
	if KeyID(pub) != id {
		t.Error("KeyID is not stable, so a published fingerprint would stop matching")
	}
	other := make(ed25519.PublicKey, len(pub))
	copy(other, pub)
	other[31] ^= 0xff
	if KeyID(other) == id {
		t.Error("two different keys share a fingerprint, so pinning one accepts the other")
	}
}

// TestParseFieldGuards pins validation rules whose guards are disjunction chains, which a
// suite that only ever feeds complete documents leaves free to weaken one clause at a time.
func TestParseFieldGuards(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Mutate func(m map[string]any)
		Want   error
	}{{ // Test 0: An empty producer product is rejected on its own.
		Mutate: func(m map[string]any) { producerOf(m)["product"] = "" }, Want: ErrSchema,
	}, { // Test 1: An empty producer product_version is rejected on its own.
		Mutate: func(m map[string]any) { producerOf(m)["product_version"] = "" }, Want: ErrSchema,
	}, { // Test 2: An empty producer install_id is rejected on its own.
		Mutate: func(m map[string]any) { producerOf(m)["install_id"] = "" }, Want: ErrSchema,
	}, { // Test 3: A verdict missing only its decision is rejected.
		Mutate: func(m map[string]any) {
			claimOf(m)["verdict"] = map[string]any{"policy": "p1", "decision": ""}
		}, Want: ErrSchema,
	}, { // Test 4: A verdict missing only its policy is rejected.
		Mutate: func(m map[string]any) {
			claimOf(m)["verdict"] = map[string]any{"policy": "", "decision": "allow"}
		}, Want: ErrSchema,
	}, { // Test 5: A consistency prefix of zero entries is refused, since every log
		// extends the empty log and such a proof establishes nothing.
		Mutate: func(m map[string]any) {
			m["chain"] = merkleChain(0)
		}, Want: ErrSchema,
	}, { // Test 6: A consistency prefix of exactly one entry is legal.
		Mutate: func(m map[string]any) {
			m["chain"] = merkleChain(1)
		},
	}, { // Test 7: A complete verdict is accepted.
		Mutate: func(m map[string]any) {
			claimOf(m)["verdict"] = map[string]any{"policy": "p1", "decision": "allow"}
		},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			m := base()
			test.Mutate(m)
			_, err := Parse(mustJSON(t, m))
			if !errors.Is(err, test.Want) {
				t.Errorf("error mismatch: got %v, want %v", err, test.Want)
			}
		})
	}
}

// merkleChain builds a tree-profile chain declaration whose consistency proof claims a
// prefix of fromSize entries, for exercising the consistency guards.
func merkleChain(fromSize int64) map[string]any {
	link := strings.Repeat("ab", 32)
	return map[string]any{
		"profile": ProfileMerkle, "keyed": false,
		"head": map[string]any{"seq": 2, "link": link},
		"consistency": map[string]any{
			"from_size": fromSize, "from_root": link, "path": []any{link},
		},
	}
}
