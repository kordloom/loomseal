package rfc3161

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"os"
	"strings"
	"testing"
)

// tokenLink is the chain link the stored token attests to. The token was issued by a public
// timestamp authority over exactly this value, so the fixture and the constant move together.
const tokenLink = "77c95e0459eef7970de647dfd263004d23b2c9a44b7feb10a24940bd695a05d3"

// loadToken reads the stored timestamp token.
func loadToken(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/freetsa-token.der")
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	return raw
}

// TestVerifyRealToken pins that a genuine timestamp token verifies against the link it attests to,
// and reports what it attests.
//
// The fixture is a real token from a public authority rather than one this package minted, because
// a token this package both produced and checked would only prove the code agrees with itself.
func TestVerifyRealToken(t *testing.T) {
	t.Parallel()
	res, err := Verify(loadToken(t), tokenLink)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if res.Time.IsZero() {
		t.Error("verified token reports no time, so it fixes nothing in time")
	}
	if !strings.Contains(res.Signer, "freetsa.org") {
		t.Errorf("signer = %q, want the authority that issued the fixture", res.Signer)
	}
	if res.Policy == "" || res.SerialNumber == "" {
		t.Errorf("policy = %q serial = %q, want both reported so a reader can look the token up",
			res.Policy, res.SerialNumber)
	}
}

// TestVerifyRejectsAWrongLink pins that a token does not verify against a link it does not attest
// to. A token that verified against any link would let a producer move a real timestamp onto a
// chain the authority never saw, which is the whole attack an anchor exists to stop.
func TestVerifyRejectsAWrongLink(t *testing.T) {
	t.Parallel()
	other := "00" + tokenLink[2:]
	if _, err := Verify(loadToken(t), other); !errors.Is(err, ErrImprint) {
		t.Errorf("Verify() against a different link error = %v, want ErrImprint", err)
	}
}

// TestVerifyRejectsDamagedTokens pins that a token altered anywhere fails, rather than failing only
// when the alteration lands somewhere the parser happens to read.
func TestVerifyRejectsDamagedTokens(t *testing.T) {
	t.Parallel()
	good := loadToken(t)
	tests := []struct {
		Name string
		At   int
	}{
		{Name: "first byte", At: 0},
		{Name: "one quarter in", At: len(good) / 4},
		{Name: "middle", At: len(good) / 2},
		{Name: "last byte", At: len(good) - 1},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			bad := make([]byte, len(good))
			copy(bad, good)
			bad[test.At] ^= 0xff
			if _, err := Verify(bad, tokenLink); err == nil {
				t.Errorf("a token damaged at byte %d verified, so tampering there goes unnoticed",
					test.At)
			}
		})
	}
}

// TestVerifyRejectsMalformedInput pins that garbage is refused with a parse error rather than
// panicking, since a verifier reads bundles from strangers.
func TestVerifyRejectsMalformedInput(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name  string
		Token []byte
		Link  string
	}{
		{Name: "empty", Token: nil, Link: tokenLink},
		{Name: "not asn1", Token: []byte("this is not a timestamp token"), Link: tokenLink},
		{Name: "truncated", Token: loadToken(t)[:40], Link: tokenLink},
		{Name: "link not hex", Token: loadToken(t), Link: "zzzz"},
		{Name: "link odd length", Token: loadToken(t), Link: "abc"},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			if _, err := Verify(test.Token, test.Link); err == nil {
				t.Error("malformed input verified")
			}
		})
	}
}

// TestSignatureAlgorithmMapping pins how a signer's declared algorithm resolves to the check that
// verifies it.
//
// A wrong mapping here is the quiet kind of bug: verification still runs, still returns success,
// and has checked the signature against the wrong hash. The freetsa fixture signs with
// ECDSA-SHA512, which is exactly the case a SHA-256 assumption gets away with until it does not.
func TestSignatureAlgorithmMapping(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Name    string
		OID     asn1.ObjectIdentifier
		Digest  crypto.Hash
		Want    x509.SignatureAlgorithm
		WantErr bool
	}{
		{Name: "ecdsa sha512, what the fixture uses",
			OID: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}, Digest: crypto.SHA512,
			Want: x509.ECDSAWithSHA512},
		{Name: "ecdsa sha256",
			OID: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}, Digest: crypto.SHA256,
			Want: x509.ECDSAWithSHA256},
		{Name: "rsa sha256",
			OID: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, Digest: crypto.SHA256,
			Want: x509.SHA256WithRSA},
		{Name: "ed25519",
			OID: asn1.ObjectIdentifier{1, 3, 101, 112}, Digest: crypto.SHA512,
			Want: x509.PureEd25519},
		// An authority may name only the key algorithm and leave the digest to the signer info.
		{Name: "bare rsa resolves through the digest",
			OID: oidRSAEncryption, Digest: crypto.SHA384, Want: x509.SHA384WithRSA},
		{Name: "bare ec resolves through the digest",
			OID: oidECPublicKey, Digest: crypto.SHA256, Want: x509.ECDSAWithSHA256},
		{Name: "unknown algorithm is refused rather than guessed",
			OID: asn1.ObjectIdentifier{1, 2, 3, 4}, Digest: crypto.SHA256, WantErr: true},
	}
	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			t.Parallel()
			got, err := signatureAlgorithm(test.OID, test.Digest)
			if test.WantErr {
				if err == nil {
					t.Error("an unknown algorithm resolved, so a signature would be checked with a " +
						"scheme the signer never named")
				}
				return
			}
			if err != nil {
				t.Fatalf("signatureAlgorithm() error = %v", err)
			}
			if got != test.Want {
				t.Errorf("algorithm = %v, want %v", got, test.Want)
			}
		})
	}
}

// TestHashForRejectsUnsupportedDigests pins that an unknown digest is refused rather than defaulted,
// since defaulting would hash the payload with something the signer did not use.
func TestHashForRejectsUnsupportedDigests(t *testing.T) {
	t.Parallel()
	for _, oid := range []asn1.ObjectIdentifier{oidSHA256, oidSHA384, oidSHA512} {
		if _, err := hashFor(oid); err != nil {
			t.Errorf("hashFor(%v) error = %v, want a hash", oid, err)
		}
	}
	// SHA-1, which no conforming authority should be using for this.
	if _, err := hashFor(asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}); err == nil {
		t.Error("an unsupported digest resolved")
	}
}

// TestDecodeHex pins the link decoder, since a link that decodes wrong produces an imprint that
// matches nothing and the failure would look like tampering.
func TestDecodeHex(t *testing.T) {
	t.Parallel()
	got, err := decodeHex("00ffAb")
	if err != nil {
		t.Fatalf("decodeHex() error = %v", err)
	}
	if len(got) != 3 || got[0] != 0x00 || got[1] != 0xff || got[2] != 0xab {
		t.Errorf("decodeHex() = %x, want 00ffab", got)
	}
	for _, bad := range []string{"abc", "zz", "0g"} {
		if _, err := decodeHex(bad); err == nil {
			t.Errorf("decodeHex(%q) accepted invalid hex", bad)
		}
	}
}
