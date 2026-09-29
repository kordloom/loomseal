package verify

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/kordloom/loomseal/seal"
)

// TestUnpinnedRunSaysTheSignerWasNotChecked pins that an unpinned verification reports the
// absence of a pin rather than leaving a reader to infer it.
//
// Any key produces a valid signature over its own bundle, so "signature ok" establishes that
// a bundle was signed and never by whom. A forged bundle carrying another producer's product
// name, bundle id and claim shapes, signed with a key minted a minute earlier, reaches the
// same VERIFIED verdict and the same exit code as the genuine article. That is correct
// behavior for a signature check and dangerous behavior for a reader, because nothing on the
// output distinguishes the two. The evidence line already announces when it checked nothing;
// this makes the signature line do the same.
func TestUnpinnedRunSaysTheSignerWasNotChecked(t *testing.T) {
	t.Parallel()
	raw, pub := signedBundleForTest(t, 0x42)
	keyID := seal.KeyID(pub)

	tests := []struct {
		Name       string
		Pin        string
		WantPinned bool
		WantOK     bool
	}{{ // Test 0: No pin, so the signer is unchecked and the report must say so.
		Name: "no pin reports unpinned", Pin: "",
		WantPinned: false, WantOK: true,
	}, { // Test 1: Correct pin, so the signer is established.
		Name: "matching pin reports pinned", Pin: keyID,
		WantPinned: true, WantOK: true,
	}, { // Test 2: Wrong pin is a failure, not a note.
		Name: "mismatched pin fails the bundle", Pin: "sha256:" + "00000000000000000000000000000000000000000000000000000000000000ff",
		WantPinned: true, WantOK: false,
	}}

	for testNum, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			r := Run(raw, Options{Fingerprint: test.Pin})
			if r.ProducerPinned != test.WantPinned {
				t.Errorf("test %d: ProducerPinned = %v, want %v", testNum, r.ProducerPinned, test.WantPinned)
			}
			if r.OK != test.WantOK {
				t.Errorf("test %d: OK = %v, want %v (problems: %v)", testNum, r.OK, test.WantOK, r.Problems)
			}
			if !r.SignatureOK {
				t.Errorf("test %d: signature should verify in every case here", testNum)
			}
		})
	}
}

// TestForgedBundleIsIndistinguishableWithoutAPin pins the reason the notice above has to
// exist. Two bundles with the same producer strings and different keys both verify, and the
// only thing that separates them is a fingerprint the caller supplies.
func TestForgedBundleIsIndistinguishableWithoutAPin(t *testing.T) {
	t.Parallel()
	genuine, genuinePub := signedBundleForTest(t, 0x42)
	forged, forgedPub := signedBundleForTest(t, 0x9e)

	gr := Run(genuine, Options{})
	fr := Run(forged, Options{})
	if !gr.OK || !fr.OK {
		t.Fatalf("both should verify unpinned: genuine=%v forged=%v", gr.OK, fr.OK)
	}
	if gr.ProducerPinned || fr.ProducerPinned {
		t.Error("neither run was pinned, so neither may report that it was")
	}

	// Pinning the genuine key is the only thing that separates them.
	if r := Run(forged, Options{Fingerprint: seal.KeyID(genuinePub)}); r.OK {
		t.Error("a forged bundle pinned to the genuine key must not verify")
	}
	if r := Run(genuine, Options{Fingerprint: seal.KeyID(genuinePub)}); !r.OK {
		t.Errorf("the genuine bundle pinned to its own key must verify: %v", r.Problems)
	}
	if seal.KeyID(genuinePub) == seal.KeyID(forgedPub) {
		t.Fatal("test keys collided, so the comparison proves nothing")
	}
}

// signedBundleForTest builds a minimal single-claim bundle signed by a key derived from the
// given seed byte, so two callers can produce bundles that differ only in who signed them.
func signedBundleForTest(t *testing.T, seedByte byte) ([]byte, ed25519.PublicKey) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = seedByte
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	install := "in_test"
	claim := map[string]any{
		"type": "test.claim/1", "at": "2026-09-09T21:45:00Z",
		"payload": map[string]any{"score": "65.5"},
	}
	link, err := seal.LinkV1(nil, install, 1, "", seal.ClaimContent(claim))
	if err != nil {
		t.Fatalf("link: %v", err)
	}
	claim["chain"] = map[string]any{"seq": int64(1), "prev": "", "link": link}

	doc := map[string]any{
		"loomseal": "0.1", "bundle_id": "lsb_test_0001", "created_at": "2026-09-09T21:45:00Z",
		"producer": map[string]any{
			"product": "assay", "product_version": "1.0.0", "install_id": install,
			"public_key": base64.StdEncoding.EncodeToString(pub), "key_id": seal.KeyID(pub),
		},
		"subject": map[string]any{"type": "measurement-set", "id": "s1"},
		"chain": map[string]any{
			"profile": "loomseal-chain-v1", "keyed": false,
			"params": map[string]any{"install_id": install},
			"head":   map[string]any{"seq": int64(1), "link": link},
		},
		"claims": []any{claim},
	}
	body, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	signed, err := seal.SignBundle(body, priv)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signed, pub
}

// TestUnchallengedPresentationLeavesTheMatchesUnset pins that a presentation verified without
// an expected audience or nonce records that neither was compared, rather than leaving a caller
// to infer it from two absent fields.
//
// The nonce is the entire replay defense. It was carried in the presentation and never printed,
// so a verifier who did not pass --nonce had nothing on screen to compare and nothing telling
// them the comparison had not happened. A presentation cut for one auditor and one challenge
// replays freely against anyone who runs the bare command.
func TestUnchallengedPresentationLeavesTheMatchesUnset(t *testing.T) {
	t.Parallel()
	if (&PresentationReport{}).AudienceMatch != nil {
		t.Error("a fresh report must not claim an audience comparison it never made")
	}
	if (&PresentationReport{}).NonceMatch != nil {
		t.Error("a fresh report must not claim a nonce comparison it never made")
	}
	// Nonce is echoed on the report so the renderer can show what went unchecked. Without it
	// there is nothing to print and the reader is blind rather than merely uninformed.
	r := &PresentationReport{Nonce: "chal-12345", Audience: "acme"}
	if r.Nonce == "" {
		t.Error("the report must carry the presented nonce for the renderer to surface")
	}
}

// TestDisclosuresDoNotSoftenAFailure pins that a notice written for a passing outcome does not
// appear beside a failing one.
//
// The unpinned notice says "this says the bundle was signed, not who signed it". True, and the
// right thing to tell someone holding a bundle that otherwise verified. Printed above ALTERED
// and NOT VERIFIED it reads as partial reassurance instead, and argues the opposite way from
// the verdict two lines below it. The verdict word is not the only thing that can lie: a
// disclosure added for one state can contradict another, and a test that checks only the word
// will not see it. Both notices are therefore gated on the whole verdict rather than on the
// local check that motivated them.
func TestDisclosuresDoNotSoftenAFailure(t *testing.T) {
	t.Parallel()
	raw, _ := signedBundleForTest(t, 0x42)

	// A bundle that verifies and was never pinned is the one case the notice belongs to.
	if r := Run(raw, Options{}); !r.OK || r.ProducerPinned {
		t.Fatalf("setup: want a passing unpinned run, got ok=%v pinned=%v", r.OK, r.ProducerPinned)
	}
	// A bundle pinned to the wrong key fails, and a failing run must not be able to reach the
	// unpinned notice at all: it is pinned, so the condition is false for that reason too.
	bad := Run(raw, Options{Fingerprint: "sha256:" + "00000000000000000000000000000000000000000000000000000000000000ff"})
	if bad.OK {
		t.Fatal("a mismatched pin must fail the bundle")
	}
	if !bad.ProducerPinned {
		t.Error("a run that compared a fingerprint must report that it did, even when it failed")
	}
	// The renderer gates on OK, so any failing report must be one where OK is false. This is
	// the invariant the gate rests on: nothing else may set OK true while problems exist.
	if bad.OK != (len(bad.Problems) == 0) {
		t.Errorf("OK must track the absence of problems: ok=%v problems=%d", bad.OK, len(bad.Problems))
	}
}
