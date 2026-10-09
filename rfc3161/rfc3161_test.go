package rfc3161

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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
	if res.Policy == "" || res.SerialNumber == nil || res.SerialNumber.Sign() <= 0 {
		t.Errorf("policy = %q serial = %v, want both reported so a reader can look the token up",
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

// TestVerifyRejectsDamagedTokens pins that a token altered in anything its check reads or its
// signature covers fails: its framing, its TSTInfo, the signer's public key, its signed attributes,
// and its signature. A length anywhere fails too, because a token is DER throughout. A character
// inside a carried certificate the check never interprets, here in the subject of the authority's
// root, does not change the verdict, because no reading of the token depends on it and no signature
// the check verifies covers it.
func TestVerifyRejectsDamagedTokens(t *testing.T) {
	t.Parallel()
	good := loadToken(t)
	tests := []struct {
		WantVerified bool
		At           int
	}{{ // Test 0: The ContentInfo identifier.
		At: 0,
	}, { // Test 1: A byte of the TSTInfo, which the signed attributes commit to.
		At: 100,
	}, { // Test 2: A byte of the signer certificate's public key.
		At: 1000,
	}, { // Test 3: A byte of the messageDigest attribute.
		At: 4460,
	}, { // Test 4: The last byte of the signature.
		At: len(good) - 1,
	}, { // Test 5: A length inside the root certificate's subject.
		At: 2317,
	}, { // Test 6: A character of the root certificate's subject, which is never interpreted.
		At: 2400, WantVerified: true,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			bad := make([]byte, len(good))
			copy(bad, good)
			bad[test.At] ^= 0xff
			_, err := Verify(bad, tokenLink)
			if diff := cmp.Diff(test.WantVerified, err == nil); diff != "" {
				t.Errorf("verified mismatch at byte %d (-want +got):\n%s\nerror %v", test.At,
					diff, err)
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

// TestSignatureScheme pins how a signer's declared algorithm resolves to the check that verifies
// it.
//
// A wrong mapping here is the quiet kind of bug: verification still runs, still returns success,
// and has checked the signature against the wrong hash. The freetsa fixture signs with
// ECDSA-SHA512, which is exactly the case a SHA-256 assumption gets away with until it does not.
func TestSignatureScheme(t *testing.T) {
	t.Parallel()
	tests := []struct {
		WantScheme scheme
		Want       error
		OID        asn1.ObjectIdentifier
		Digest     crypto.Hash
	}{{ // Test 0: ECDSA with SHA-512, what the fixture uses.
		OID: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}, Digest: crypto.SHA512,
		WantScheme: scheme{key: keyECDSA, hash: crypto.SHA512},
	}, { // Test 1: ECDSA with SHA-256.
		OID: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}, Digest: crypto.SHA256,
		WantScheme: scheme{key: keyECDSA, hash: crypto.SHA256},
	}, { // Test 2: RSA with SHA-256.
		OID: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}, Digest: crypto.SHA256,
		WantScheme: scheme{key: keyRSA, hash: crypto.SHA256},
	}, { // Test 3: Ed25519 signs the attributes themselves, whatever the digest.
		OID: asn1.ObjectIdentifier{1, 3, 101, 112}, Digest: crypto.SHA512,
		WantScheme: scheme{key: keyEd25519},
	}, { // Test 4: A bare RSA key algorithm resolves through the signer's digest.
		OID: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}, Digest: crypto.SHA384,
		WantScheme: scheme{key: keyRSA, hash: crypto.SHA384},
	}, { // Test 5: A bare EC key algorithm resolves through the signer's digest.
		OID: asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}, Digest: crypto.SHA256,
		WantScheme: scheme{key: keyECDSA, hash: crypto.SHA256},
	}, { // Test 6: RSASSA-PSS is SHA-256 whatever the signer's digest.
		OID: asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}, Digest: crypto.SHA512,
		WantScheme: scheme{key: keyRSA, hash: crypto.SHA256, pss: true},
	}, { // Test 7: An unknown algorithm is refused rather than guessed.
		OID: asn1.ObjectIdentifier{1, 2, 3, 4}, Digest: crypto.SHA256, Want: ErrParse,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got, err := signatureScheme(oidContent(test.OID), test.Digest)
			if !errors.Is(err, test.Want) {
				t.Fatalf("error mismatch: got %v, want %v", err, test.Want)
			}
			if diff := cmp.Diff(test.WantScheme, got, cmp.AllowUnexported(scheme{})); diff != "" {
				t.Errorf("scheme mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestHashForRejectsUnsupportedDigests pins that an unknown digest is refused rather than defaulted,
// since defaulting would hash the payload with something the signer did not use.
func TestHashForRejectsUnsupportedDigests(t *testing.T) {
	t.Parallel()
	for _, oid := range [][]byte{oidSHA256, oidSHA384, oidSHA512} {
		if _, err := hashFor(oid); err != nil {
			t.Errorf("hashFor(%x) error = %v, want a hash", oid, err)
		}
	}
	// SHA-1, which no conforming authority should be using for this.
	if _, err := hashFor(oidContent(asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26})); err == nil {
		t.Error("an unsupported digest resolved")
	}
}

// tsaCert generates a self-signed timestamping certificate with the given serial and
// common name, so certificate selection can be tested without a real authority.
func tsaCert(t *testing.T, serial int64, cn string) (*x509.Certificate, []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageTimeStamping},
		// A real authority's certificate carries one, and it is the other form a signer identifier
		// may name a certificate by, so the fixtures have to have it for that path to be reachable.
		SubjectKeyId: []byte{byte(serial >> 8), byte(serial), 0xAA, 0xBB},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return c, der
}

// readCerts reads concatenated certificates through the verifier's own certificate reader.
func readCerts(t *testing.T, ders ...[]byte) []*certificate {
	t.Helper()
	certs, err := readCertificates(bytes.Join(ders, nil))
	if err != nil {
		t.Fatalf("readCertificates() error = %v", err)
	}
	return certs
}

// issuerSerialSID encodes an IssuerAndSerialNumber signer identifier naming c.
func issuerSerialSID(t *testing.T, c *x509.Certificate) element {
	t.Helper()
	der, err := asn1.Marshal(struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}{asn1.RawValue{FullBytes: c.RawIssuer}, c.SerialNumber})
	if err != nil {
		t.Fatalf("marshal signer id: %v", err)
	}
	r := reader{rest: der}
	sid, err := readSignerID(&r)
	if err != nil {
		t.Fatalf("readSignerID() error = %v", err)
	}
	return sid
}

// TestSignerCertificateNamesBothFields pins signer resolution as a conjunction of serial
// and issuer. A decoy from the same issuer under a different serial, listed first, must
// not be selected: matching on either field alone would report, and check the signature
// against, a certificate the token never claimed signed it.
func TestSignerCertificateNamesBothFields(t *testing.T) {
	t.Parallel()
	// Both certificates carry the same issuer name; only the serial separates them.
	_, decoyDER := tsaCert(t, 1000, "Acme TSA")
	signer, signerDER := tsaCert(t, 2000, "Acme TSA")

	got, err := signerCertificate(readCerts(t, decoyDER, signerDER), issuerSerialSID(t, signer))
	if err != nil {
		t.Fatalf("signer certificate: %v", err)
	}
	if derBigInt(got.serial).Cmp(signer.SerialNumber) != 0 {
		t.Errorf("selected serial %v, want %v", derBigInt(got.serial), signer.SerialNumber)
	}
}

// TestSignerCertificateRefusesToFallBack pins the rule the format states: a token whose named signer
// certificate is absent fails, rather than being graded against another certificate it carries.
//
// This verifier used to fall back to the first certificate marked for timestamping. That made the
// outcome depend on the order certificates appear in, which the format says carries no meaning, and
// it meant a token could be reported as validly signed by a certificate its own signer identifier
// never named. The token here carries a perfectly good timestamping certificate; it is simply not
// the one the token points at, and that has to be a refusal.
func TestSignerCertificateRefusesToFallBack(t *testing.T) {
	t.Parallel()
	_, carriedDER := tsaCert(t, 1000, "Acme TSA")
	absent, _ := tsaCert(t, 9999, "Acme TSA")

	got, err := signerCertificate(readCerts(t, carriedDER), issuerSerialSID(t, absent))
	if err == nil {
		t.Fatalf("a token resolved to serial %v, which its signer identifier never named",
			derBigInt(got.serial))
	}
	if !errors.Is(err, ErrParse) {
		t.Errorf("error = %v, want it to wrap ErrParse", err)
	}
}

// TestSignerCertificateResolvesASubjectKeyIdentifier covers the other signer identifier form.
//
// A CMS signer identifier is a choice of an issuer and serial number or a subject key identifier
// tagged [0]. Reading only the first form meant a conforming token using the second was
// unresolvable, and the previous fallback hid that by quietly picking a certificate by position.
func TestSignerCertificateResolvesASubjectKeyIdentifier(t *testing.T) {
	t.Parallel()
	_, decoyDER := tsaCert(t, 1000, "Acme TSA")
	signer, signerDER := tsaCert(t, 2000, "Other TSA")

	sid := element{tag: tagImplicit0, content: signer.SubjectKeyId}
	got, err := signerCertificate(readCerts(t, decoyDER, signerDER), sid)
	if err != nil {
		t.Fatalf("signer certificate: %v", err)
	}
	if derBigInt(got.serial).Cmp(signer.SerialNumber) != 0 {
		t.Errorf("selected serial %v, want %v", derBigInt(got.serial), signer.SerialNumber)
	}
}

// TestReaderNext holds every element a token is read through to DER's identifier and length
// rules, so no verifier reads a BER form another refuses.
func TestReaderNext(t *testing.T) {
	t.Parallel()
	long := bytes.Repeat([]byte{0xAB}, 200)
	tests := []struct {
		WantContent []byte
		WantRest    []byte
		Want        error
		In          []byte
	}{{ // Test 0: A short form length reads.
		In: []byte{0x04, 0x02, 0xAA, 0xBB, 0x05}, WantContent: []byte{0xAA, 0xBB},
		WantRest: []byte{0x05},
	}, { // Test 1: A long form length of 128 or more reads.
		In: append([]byte{0x04, 0x81, 0xC8}, long...), WantContent: long, WantRest: []byte{},
	}, { // Test 2: A long form length below 128 is refused.
		In: []byte{0x04, 0x81, 0x02, 0xAA, 0xBB}, Want: ErrParse,
	}, { // Test 3: A long form length with a leading zero octet is refused.
		In: append([]byte{0x04, 0x82, 0x00, 0xC8}, long...), Want: ErrParse,
	}, { // Test 4: An indefinite length is refused.
		In: []byte{0x30, 0x80, 0x05, 0x00, 0x00, 0x00}, Want: ErrParse,
	}, { // Test 5: A length that runs past its container is refused.
		In: []byte{0x04, 0x03, 0xAA, 0xBB}, Want: ErrParse,
	}, { // Test 6: A length of five octets is refused.
		In: []byte{0x04, 0x85, 0x01, 0x00, 0x00, 0x00, 0x00}, Want: ErrParse,
	}, { // Test 7: The high tag number form is refused, even for a tag it could name minimally.
		In: []byte{0x1F, 0x02, 0x01, 0x01}, Want: ErrParse,
	}, { // Test 8: A truncated length is refused.
		In: []byte{0x04, 0x82, 0x01}, Want: ErrParse,
	}, { // Test 9: An identifier with no length is refused.
		In: []byte{0x04}, Want: ErrParse,
	}, { // Test 10: An empty element reads.
		In: []byte{0x05, 0x00}, WantContent: []byte{}, WantRest: []byte{},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			r := reader{rest: test.In}
			got, err := r.next("element")
			if !errors.Is(err, test.Want) {
				t.Fatalf("error mismatch: got %v, want %v", err, test.Want)
			}
			if test.Want != nil {
				return
			}
			if diff := cmp.Diff(test.WantContent, got.content, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("content mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantRest, r.rest, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("rest mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestOnly pins that a wrapper holds exactly one element of the identifier it requires.
func TestOnly(t *testing.T) {
	t.Parallel()
	tests := []struct {
		Want error
		In   []byte
		Tag  byte
	}{{ // Test 0: One element of the right identifier reads.
		In: []byte{0x30, 0x00}, Tag: tagSequence,
	}, { // Test 1: A second element after it is refused.
		In: []byte{0x30, 0x00, 0x05, 0x00}, Tag: tagSequence, Want: ErrParse,
	}, { // Test 2: A stray octet after it is refused.
		In: []byte{0x30, 0x00, 0x00}, Tag: tagSequence, Want: ErrParse,
	}, { // Test 3: Another identifier is refused.
		In: []byte{0x31, 0x00}, Tag: tagSequence, Want: ErrParse,
	}, { // Test 4: Nothing at all is refused.
		In: nil, Tag: tagSequence, Want: ErrParse,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			if _, err := only(test.In, test.Tag, "wrapper"); !errors.Is(err, test.Want) {
				t.Errorf("error mismatch: got %v, want %v", err, test.Want)
			}
		})
	}
}

// TestDERInteger pins INTEGER content to at least one octet in its shortest form, versions to 64
// bits, and a TSTInfo serial number to 21 octets, the length of a positive 160-bit value, refused
// past it in the words the Python reference writes.
func TestDERInteger(t *testing.T) {
	t.Parallel()
	tests := []struct {
		WantSerialText string
		WantVersion    error
		WantSerial     error
		Want           error
		In             []byte
	}{{ // Test 0: One octet reads.
		In: []byte{0x01},
	}, { // Test 1: A leading zero before a high bit reads.
		In: []byte{0x00, 0x80},
	}, { // Test 2: An empty INTEGER is refused.
		In: []byte{}, Want: ErrParse, WantVersion: ErrParse, WantSerial: ErrParse,
	}, { // Test 3: A redundant leading zero is refused.
		In: []byte{0x00, 0x01}, Want: ErrParse, WantVersion: ErrParse, WantSerial: ErrParse,
	}, { // Test 4: A redundant leading 0xFF is refused.
		In: []byte{0xFF, 0x80}, Want: ErrParse, WantVersion: ErrParse, WantSerial: ErrParse,
	}, { // Test 5: Nine octets are an INTEGER and a serial but not a version.
		In: []byte{0x01, 0, 0, 0, 0, 0, 0, 0, 0}, WantVersion: ErrParse,
	}, { // Test 6: Eight octets are a version.
		In: []byte{0x7F, 0, 0, 0, 0, 0, 0, 0},
	}, { // Test 7: 2^160-1 in 21 octets is a serial.
		In: append([]byte{0x00}, bytes.Repeat([]byte{0xFF}, 20)...), WantVersion: ErrParse,
	}, { // Test 8: A negative serial of 21 octets is a serial.
		In: append([]byte{0x80}, make([]byte, 20)...), WantVersion: ErrParse,
	}, { // Test 9: 2^168-1 in 22 octets is an INTEGER but not a serial.
		In: append([]byte{0x00}, bytes.Repeat([]byte{0xFF}, 21)...), WantVersion: ErrParse,
		WantSerial:     ErrParse,
		WantSerialText: "TSTInfo serialNumber: INTEGER longer than 21 octets",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			e := element{tag: tagInteger, content: test.In}
			if err := derInteger(e, "integer"); !errors.Is(err, test.Want) {
				t.Errorf("derInteger error mismatch: got %v, want %v", err, test.Want)
			}
			if err := derVersion(e, "version"); !errors.Is(err, test.WantVersion) {
				t.Errorf("derVersion error mismatch: got %v, want %v", err, test.WantVersion)
			}
			err := derSerial(e, "TSTInfo serialNumber")
			if !errors.Is(err, test.WantSerial) {
				t.Errorf("derSerial error mismatch: got %v, want %v", err, test.WantSerial)
			}
			if test.WantSerialText != "" && (err == nil ||
				!strings.HasSuffix(err.Error(), test.WantSerialText)) {
				t.Errorf("derSerial error = %v, want it to end %q", err, test.WantSerialText)
			}
		})
	}
}

// TestDEROID pins OBJECT IDENTIFIER content to DER and its dotted form to X.690's first arc rule.
func TestDEROID(t *testing.T) {
	t.Parallel()
	tests := []struct {
		WantDotted string
		Want       error
		In         []byte
	}{{ // Test 0: SHA-256 reads.
		In: oidSHA256, WantDotted: "2.16.840.1.101.3.4.2.1",
	}, { // Test 1: A first subidentifier of 120 is arc 2.40, never 3.0.
		In: []byte{0x78}, WantDotted: "2.40",
	}, { // Test 2: A multi-octet first subidentifier reads.
		In: []byte{0x88, 0x37, 0x01}, WantDotted: "2.999.1",
	}, { // Test 3: A subidentifier of 2^31-1 reads.
		In: []byte{0x2A, 0x87, 0xFF, 0xFF, 0xFF, 0x7F}, WantDotted: "1.2.2147483647",
	}, { // Test 4: An empty OBJECT IDENTIFIER is refused.
		In: []byte{}, Want: ErrParse,
	}, { // Test 5: A subidentifier padded with 0x80 is refused.
		In: []byte{0x2A, 0x80, 0x01}, Want: ErrParse,
	}, { // Test 6: A first subidentifier padded with 0x80 is refused.
		In: []byte{0x80, 0x2A}, Want: ErrParse,
	}, { // Test 7: Content that ends inside a subidentifier is refused.
		In: []byte{0x2A, 0x86}, Want: ErrParse,
	}, { // Test 8: A subidentifier of 2^31 is refused.
		In: []byte{0x2A, 0x88, 0x80, 0x80, 0x80, 0x00}, Want: ErrParse,
	}, { // Test 9: A subidentifier wider than 64 bits is refused.
		In:   []byte{0x2A, 0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00},
		Want: ErrParse,
	}, { // Test 10: A first subidentifier of 2^31-1 reads as arc 2 and the rest.
		In: []byte{0x87, 0xFF, 0xFF, 0xFF, 0x7F}, WantDotted: "2.2147483567",
	}, { // Test 11: A first subidentifier of 2^31 is refused.
		In: []byte{0x88, 0x80, 0x80, 0x80, 0x00}, Want: ErrParse,
	}, { // Test 12: A subidentifier of 3,000 octets is refused before it is written out.
		In:   append(append([]byte{0x2A}, bytes.Repeat([]byte{0xFF}, 2999)...), 0x7F),
		Want: ErrParse,
	}, { // Test 13: An OBJECT IDENTIFIER of many short subidentifiers reads.
		In:         append([]byte{0x2A}, bytes.Repeat([]byte{0x01}, 4)...),
		WantDotted: "1.2.1.1.1.1",
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			err := derOID(element{tag: tagOID, content: test.In}, "oid")
			if !errors.Is(err, test.Want) {
				t.Fatalf("error mismatch: got %v, want %v", err, test.Want)
			}
			if test.Want != nil {
				return
			}
			if diff := cmp.Diff(test.WantDotted, oidString(test.In)); diff != "" {
				t.Errorf("dotted mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestParseCertTime pins certificate validity times to their DER forms: seconds and Z, nothing
// else, with RFC 5280's two-digit year rule.
func TestParseCertTime(t *testing.T) {
	t.Parallel()
	tests := []struct {
		WantTime time.Time
		Want     error
		In       element
	}{{ // Test 0: A UTCTime reads.
		In:       element{tag: tagUTCTime, content: []byte("260727150100Z")},
		WantTime: time.Date(2026, 7, 27, 15, 1, 0, 0, time.UTC),
	}, { // Test 1: A two-digit year of 50 is 1950.
		In:       element{tag: tagUTCTime, content: []byte("500101000000Z")},
		WantTime: time.Date(1950, 1, 1, 0, 0, 0, 0, time.UTC),
	}, { // Test 2: A two-digit year of 49 is 2049.
		In:       element{tag: tagUTCTime, content: []byte("491231235959Z")},
		WantTime: time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC),
	}, { // Test 3: A GeneralizedTime reads.
		In:       element{tag: tagGeneralizedTime, content: []byte("20500101000000Z")},
		WantTime: time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC),
	}, { // Test 4: A UTCTime without seconds is refused.
		In: element{tag: tagUTCTime, content: []byte("2607271501Z")}, Want: ErrParse,
	}, { // Test 5: A UTCTime with an offset is refused.
		In: element{tag: tagUTCTime, content: []byte("260727160100+0100")}, Want: ErrParse,
	}, { // Test 6: A GeneralizedTime with a fraction is refused.
		In: element{tag: tagGeneralizedTime, content: []byte("20260101000000.5Z")}, Want: ErrParse,
	}, { // Test 7: Year 0000 is refused.
		In: element{tag: tagGeneralizedTime, content: []byte("00000101000000Z")}, Want: ErrParse,
	}, { // Test 8: A leap second is refused.
		In: element{tag: tagUTCTime, content: []byte("261231235960Z")}, Want: ErrParse,
	}, { // Test 9: Another time type is refused.
		In: element{tag: tagOctetString, content: []byte("260727150100Z")}, Want: ErrParse,
	}, { // Test 10: A lower case zone letter is refused.
		In: element{tag: tagUTCTime, content: []byte("260727150100z")}, Want: ErrParse,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got, err := parseCertTime(test.In)
			if !errors.Is(err, test.Want) {
				t.Fatalf("error mismatch: got %v, want %v", err, test.Want)
			}
			if diff := cmp.Diff(test.WantTime, got); diff != "" {
				t.Errorf("time mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// derTLV encodes one DER element with a definite shortest form length.
func derTLV(tag byte, content ...[]byte) []byte {
	c := bytes.Join(content, nil)
	switch {
	case len(c) < 0x80:
		return append([]byte{tag, byte(len(c))}, c...)
	case len(c) < 0x100:
		return append([]byte{tag, 0x81, byte(len(c))}, c...)
	}
	return append([]byte{tag, 0x82, byte(len(c) >> 8), byte(len(c))}, c...)
}

// TestSubjectName pins the one rule a signer is named by, read from the subject Name alone: RFC
// 4514 text when the Name is a sequence of relative distinguished names, with the nine short names
// and the escapes FORMAT.md states, and otherwise # and the hexadecimal of the whole encoding.
//
//nolint:funlen // One row per clause of the rule.
func TestSubjectName(t *testing.T) {
	t.Parallel()
	oid := func(arcs ...int) []byte { return derTLV(tagOID, []byte(oidKey(arcs...))) }
	attr := func(typ []byte, value []byte) []byte { return derTLV(tagSequence, typ, value) }
	rdn := func(attrs ...[]byte) []byte { return derTLV(tagSet, attrs...) }
	name := func(rdns ...[]byte) []byte { return derTLV(tagSequence, rdns...) }
	utf8s := func(text string) []byte { return derTLV(tagUTF8String, []byte(text)) }
	cn := func(value []byte) []byte { return name(rdn(attr(oid(2, 5, 4, 3), value))) }
	tests := []struct {
		WantName string
		In       []byte
	}{{ // Test 0: One common name.
		In: cn(utf8s("TSA")), WantName: "CN=TSA",
	}, { // Test 1: RDNs run last to first, and a multi-valued RDN keeps its encoded order.
		In: name(rdn(attr(oid(2, 5, 4, 6), derTLV(tagPrintableString, []byte("DE")))),
			rdn(attr(oid(2, 5, 4, 10), utf8s("Acme")), attr(oid(2, 5, 4, 11), utf8s("TSA")))),
		WantName: "O=Acme+OU=TSA,C=DE",
	}, { // Test 2: A type with no short name is dotted, and its value is hexadecimal.
		In: name(rdn(attr(oid(1, 2, 840, 113549, 1, 9, 1),
			derTLV(tagIA5String, []byte("a@b"))))),
		WantName: "1.2.840.113549.1.9.1=#1603614062",
	}, { // Test 3: DC and UID are short names.
		In: name(rdn(attr(oid(0, 9, 2342, 19200300, 100, 1, 25), derTLV(tagIA5String,
			[]byte("org")))), rdn(attr(oid(0, 9, 2342, 19200300, 100, 1, 1), utf8s("u1")))),
		WantName: "UID=u1,DC=org",
	}, { // Test 4: Special characters and a leading # are escaped.
		In: cn(utf8s(`#a,b+c;d<e>f"g\h`)), WantName: `CN=\#a\,b\+c\;d\<e\>f\"g\\h`,
	}, { // Test 5: A # or = after the start is not escaped.
		In: cn(utf8s("a#b=c")), WantName: "CN=a#b=c",
	}, { // Test 6: A leading and a trailing space are escaped, and an inner one is not.
		In: cn(utf8s(" a b ")), WantName: `CN=\ a b\ `,
	}, { // Test 7: A value of one space is escaped once.
		In: cn(utf8s(" ")), WantName: `CN=\ `,
	}, { // Test 8: Control characters, DEL and C1 controls are written as hexadecimal octets.
		In: cn(utf8s("a\nb\x7fc\u0085")), WantName: `CN=a\0ab\7fc\c2\85`,
	}, { // Test 9: Other non-ASCII text is written as it is.
		In: cn(utf8s("W\u00fcrzburg")), WantName: "CN=W\u00fcrzburg",
	}, { // Test 10: A UTF8String that is not UTF-8 is hexadecimal.
		In: cn(derTLV(tagUTF8String, []byte{0xff})), WantName: "CN=#0c01ff",
	}, { // Test 11: A PrintableString that is not ASCII is hexadecimal.
		In: cn(derTLV(tagPrintableString, []byte{0xe9})), WantName: "CN=#1301e9",
	}, { // Test 12: A BMPString is hexadecimal.
		In: cn(derTLV(0x1e, []byte{0x00, 0x41})), WantName: "CN=#1e020041",
	}, { // Test 13: A constructed UTF8String is hexadecimal.
		In: cn(derTLV(0x2c, utf8s("A"))), WantName: "CN=#2c030c0141",
	}, { // Test 14: An empty Name is named by its encoding.
		In: name(), WantName: "#3000",
	}, { // Test 15: An empty RDN makes the Name hexadecimal.
		In: name(rdn()), WantName: "#30023100",
	}, { // Test 16: An attribute with two values makes the Name hexadecimal.
		In:       name(rdn(derTLV(tagSequence, oid(2, 5, 4, 3), utf8s("A"), utf8s("B")))),
		WantName: "#300f310d300b06035504030c01410c0142",
	}, { // Test 17: An RDN written as a SEQUENCE makes the Name hexadecimal.
		In:       name(derTLV(tagSequence, attr(oid(2, 5, 4, 3), utf8s("A")))),
		WantName: "#300c300a300806035504030c0141",
	}, { // Test 18: An attribute type that pads a subidentifier makes the Name hexadecimal.
		In:       name(rdn(attr(derTLV(tagOID, []byte{0x55, 0x04, 0x80, 0x03}), utf8s("A")))),
		WantName: "#300d310b30090604550480030c0141",
	}, { // Test 19: An attribute type past 2^31-1 makes the Name hexadecimal.
		In: name(rdn(attr(derTLV(tagOID, []byte{0x55, 0x04, 0x88, 0x80, 0x80, 0x80, 0x00}),
			utf8s("A")))),
		WantName: "#3010310e300c0607550488808080000c0141",
	}, { // Test 20: Each bidirectional embedding and override is hexadecimal, and U+202F is not.
		In:       cn(utf8s("a\u202ab\u202bc\u202cd\u202de\u202ef\u202fg")),
		WantName: `CN=a\e2\80\aab\e2\80\abc\e2\80\acd\e2\80\ade\e2\80\aef` + "\u202f" + "g",
	}, { // Test 21: Each bidirectional isolate is hexadecimal, and U+2065 and U+206A are not.
		In:       cn(utf8s("\u2065a\u2066b\u2067c\u2068d\u2069e\u206a")),
		WantName: "CN=\u2065" + `a\e2\81\a6b\e2\81\a7c\e2\81\a8d\e2\81\a9e` + "\u206a",
	}, { // Test 22: Each bidirectional mark is hexadecimal, and its neighbors are not.
		In:       cn(utf8s("\u200da\u200eb\u200fc\u2010d\u061be\u061cf\u061d")),
		WantName: "CN=\u200d" + `a\e2\80\8eb\e2\80\8fc` + "\u2010d\u061b" + `e\d8\9cf` + "\u061d",
	}, { // Test 23: The line and paragraph separators are hexadecimal, and U+2027 is not.
		In:       cn(utf8s("a\u2027b\u2028c\u2029d")),
		WantName: "CN=a\u2027" + `b\e2\80\a8c\e2\80\a9d`,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got := (&certificate{subject: test.In}).subjectName()
			if diff := cmp.Diff(test.WantName, got); diff != "" {
				t.Errorf("name mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestReadExtensions pins the extension list rules: a critical flag is the DER TRUE octet, no
// extnID appears twice, and the extended key usage and subject key identifier values each hold
// exactly one element.
func TestReadExtensions(t *testing.T) {
	t.Parallel()
	eku := derTLV(tagOID, oidExtKeyUsage)
	ski := derTLV(tagOID, oidSubjectKeyID)
	tsp := derTLV(tagOctetString, derTLV(tagSequence, derTLV(tagOID, oidKPTimeStamping)))
	tests := []struct {
		WantEKU [][]byte
		WantSKI []byte
		Want    error
		Exts    [][]byte
	}{{ // Test 0: A critical extended key usage with the timestamping purpose reads.
		Exts:    [][]byte{derTLV(tagSequence, eku, derTLV(tagBoolean, []byte{0xFF}), tsp)},
		WantEKU: [][]byte{oidKPTimeStamping},
	}, { // Test 1: A critical flag of 0x01 is refused.
		Exts: [][]byte{derTLV(tagSequence, eku, derTLV(tagBoolean, []byte{0x01}), tsp)},
		Want: ErrParse,
	}, { // Test 2: A critical flag written out as FALSE is refused, since DER omits a default.
		Exts: [][]byte{derTLV(tagSequence, eku, derTLV(tagBoolean, []byte{0x00}), tsp)},
		Want: ErrParse,
	}, { // Test 3: An extension that appears twice is refused.
		Exts: [][]byte{derTLV(tagSequence, eku, tsp), derTLV(tagSequence, eku, tsp)},
		Want: ErrParse,
	}, { // Test 4: A subject key identifier reads.
		Exts: [][]byte{derTLV(tagSequence, ski,
			derTLV(tagOctetString, derTLV(tagOctetString, []byte{1, 2})))},
		WantSKI: []byte{1, 2},
	}, { // Test 5: A subject key identifier followed by another element is refused.
		Exts: [][]byte{derTLV(tagSequence, ski, derTLV(tagOctetString,
			derTLV(tagOctetString, []byte{1, 2}), derTLV(tagNull)))},
		Want: ErrParse,
	}, { // Test 6: An extended key usage holding something other than an OID is refused.
		Exts: [][]byte{derTLV(tagSequence, eku,
			derTLV(tagOctetString, derTLV(tagSequence, derTLV(tagNull))))},
		Want: ErrParse,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			c := &certificate{}
			wrapped := element{tag: tagExplicit3,
				content: derTLV(tagSequence, bytes.Join(test.Exts, nil))}
			err := c.readExtensions(wrapped)
			if !errors.Is(err, test.Want) {
				t.Fatalf("error mismatch: got %v, want %v", err, test.Want)
			}
			if test.Want != nil {
				return
			}
			if diff := cmp.Diff(test.WantEKU, c.extKeyUsage, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("key purposes mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(test.WantSKI, c.subjectKeyID, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("subject key identifier mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestParsePublicKey pins the three key forms a signer may hold and the bounds each is held to.
func TestParsePublicKey(t *testing.T) {
	t.Parallel()
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	point, err := ecKey.PublicKey.Bytes()
	if err != nil {
		t.Fatalf("point: %v", err)
	}
	compressed := elliptic.MarshalCompressed(elliptic.P256(), ecKey.X, ecKey.Y)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	edAlg := derTLV(tagSequence, derTLV(tagOID, oidEd25519))
	ecAlg := derTLV(tagSequence, derTLV(tagOID, oidECPublicKey), derTLV(tagOID, oidCurveP256))
	rsaAlg := derTLV(tagSequence, derTLV(tagOID, oidRSAEncryption), derTLV(tagNull))
	bits := func(b []byte) []byte { return derTLV(tagBitString, append([]byte{0}, b...)) }
	rsaBits := func(n, e *big.Int) []byte {
		in := func(v *big.Int) []byte {
			b, err := asn1.Marshal(v)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			return b
		}
		return bits(derTLV(tagSequence, in(n), in(e)))
	}
	odd := func(bits uint) *big.Int {
		v := new(big.Int).Lsh(big.NewInt(1), bits-1)
		return v.Add(v, big.NewInt(1))
	}
	rsaInts := func(ints ...*big.Int) []byte {
		var out [][]byte
		for _, v := range ints {
			b, err := asn1.Marshal(v)
			if err != nil {
				t.Fatalf("marshal: %v", err)
			}
			out = append(out, b)
		}
		return bytes.Join(out, nil)
	}
	e := big.NewInt(65537)
	tests := []struct {
		Want error
		SPKI []byte
	}{{ // Test 0: An Ed25519 key reads.
		SPKI: derTLV(tagSequence, edAlg, bits(make([]byte, 32))),
	}, { // Test 1: An Ed25519 key with parameters is refused.
		SPKI: derTLV(tagSequence, derTLV(tagSequence, derTLV(tagOID, oidEd25519), derTLV(tagNull)),
			bits(make([]byte, 32))),
		Want: ErrParse,
	}, { // Test 2: An Ed25519 key of 31 octets is refused.
		SPKI: derTLV(tagSequence, edAlg, bits(make([]byte, 31))), Want: ErrParse,
	}, { // Test 3: A key BIT STRING with unused bits is refused.
		SPKI: derTLV(tagSequence, edAlg, derTLV(tagBitString, append([]byte{1},
			make([]byte, 32)...))),
		Want: ErrParse,
	}, { // Test 4: An uncompressed P-256 point reads.
		SPKI: derTLV(tagSequence, ecAlg, bits(point)),
	}, { // Test 5: A compressed point is refused.
		SPKI: derTLV(tagSequence, ecAlg, bits(compressed)), Want: ErrParse,
	}, { // Test 6: A curve outside P-224, P-256, P-384, and P-521 is refused.
		SPKI: derTLV(tagSequence, derTLV(tagSequence, derTLV(tagOID, oidECPublicKey),
			derTLV(tagOID, oidContent(asn1.ObjectIdentifier{1, 3, 132, 0, 10}))), bits(point)),
		Want: ErrParse,
	}, { // Test 7: A 2048-bit RSA key reads.
		SPKI: derTLV(tagSequence, rsaAlg, rsaBits(rsaKey.N, big.NewInt(65537))),
	}, { // Test 8: An RSA key without NULL parameters is refused.
		SPKI: derTLV(tagSequence, derTLV(tagSequence, derTLV(tagOID, oidRSAEncryption)),
			rsaBits(rsaKey.N, big.NewInt(65537))),
		Want: ErrParse,
	}, { // Test 9: An RSA modulus below 1024 bits is refused.
		SPKI: derTLV(tagSequence, rsaAlg, rsaBits(odd(1023), e)), Want: ErrParse,
	}, { // Test 10: An even RSA exponent is refused.
		SPKI: derTLV(tagSequence, rsaAlg, rsaBits(rsaKey.N, big.NewInt(65536))), Want: ErrParse,
	}, { // Test 11: An RSA exponent above 2^31-1 is refused.
		SPKI: derTLV(tagSequence, rsaAlg, rsaBits(rsaKey.N, big.NewInt(1<<31+1))),
		Want: ErrParse,
	}, { // Test 12: An even RSA modulus is refused.
		SPKI: derTLV(tagSequence, rsaAlg, rsaBits(new(big.Int).Add(rsaKey.N, big.NewInt(1)),
			big.NewInt(65537))),
		Want: ErrParse,
	}, { // Test 13: An RSA key followed by another element in its BIT STRING is refused.
		SPKI: derTLV(tagSequence, rsaAlg, derTLV(tagBitString, append([]byte{0},
			append(derTLV(tagSequence, derTLV(tagInteger, []byte{1})), 0x05, 0x00)...))),
		Want: ErrParse,
	}, { // Test 14: Another key algorithm is refused.
		SPKI: derTLV(tagSequence, derTLV(tagSequence,
			derTLV(tagOID, oidContent(asn1.ObjectIdentifier{1, 3, 101, 113}))),
			bits(make([]byte, 57))),
		Want: ErrParse,
	}, { // Test 15: An RSA modulus of 16384 bits, the longest read, reads.
		SPKI: derTLV(tagSequence, rsaAlg, rsaBits(odd(16384), e)),
	}, { // Test 16: An RSA modulus of 16385 bits is refused.
		SPKI: derTLV(tagSequence, rsaAlg, rsaBits(odd(16385), e)), Want: ErrParse,
	}, { // Test 17: An RSA key SEQUENCE with a third INTEGER after the exponent is refused.
		SPKI: derTLV(tagSequence, rsaAlg, bits(derTLV(tagSequence,
			rsaInts(rsaKey.N, e, big.NewInt(5))))),
		Want: ErrParse,
	}, { // Test 18: An RSA key SEQUENCE with octets that are not DER after the exponent is refused.
		SPKI: derTLV(tagSequence, rsaAlg, bits(derTLV(tagSequence, rsaInts(rsaKey.N, e),
			[]byte{0xff, 0xff, 0xff}))),
		Want: ErrParse,
	}, { // Test 19: An Ed25519 key of 33 octets is refused.
		SPKI: derTLV(tagSequence, edAlg, bits(make([]byte, 33))), Want: ErrParse,
	}, { // Test 20: An RSA exponent of 2^32-5 is refused.
		SPKI: derTLV(tagSequence, rsaAlg, rsaBits(rsaKey.N, big.NewInt(1<<32-5))),
		Want: ErrParse,
	}, { // Test 21: An RSA exponent of 1 is refused.
		SPKI: derTLV(tagSequence, rsaAlg, rsaBits(rsaKey.N, big.NewInt(1))), Want: ErrParse,
	}, { // Test 22: An even RSA exponent of 4 is refused.
		SPKI: derTLV(tagSequence, rsaAlg, rsaBits(rsaKey.N, big.NewInt(4))), Want: ErrParse,
	}, { // Test 23: RSA key parameters that are a NULL holding an octet are refused.
		SPKI: derTLV(tagSequence, derTLV(tagSequence, derTLV(tagOID, oidRSAEncryption),
			derTLV(tagNull, []byte{0})), rsaBits(rsaKey.N, e)),
		Want: ErrParse,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			r := reader{rest: test.SPKI}
			spki, err := r.read(tagSequence, "spki")
			if err != nil {
				t.Fatalf("read spki: %v", err)
			}
			if _, err := parsePublicKey(spki); !errors.Is(err, test.Want) {
				t.Errorf("error mismatch: got %v, want %v", err, test.Want)
			}
		})
	}
}

// TestCheckSignatureRefusesAMismatchedKey pins that a signature algorithm naming one key type is
// never checked under the signer key's own type.
func TestCheckSignatureRefusesAMismatchedKey(t *testing.T) {
	t.Parallel()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
	msg := []byte("signed attributes")
	sig := ed25519.Sign(priv, msg)
	tests := []struct {
		Want   bool
		Scheme scheme
	}{{ // Test 0: Ed25519 under its own scheme verifies.
		Scheme: scheme{key: keyEd25519}, Want: true,
	}, { // Test 1: Ed25519 under an ECDSA scheme is refused.
		Scheme: scheme{key: keyECDSA, hash: crypto.SHA256},
	}, { // Test 2: Ed25519 under an RSA scheme is refused.
		Scheme: scheme{key: keyRSA, hash: crypto.SHA256},
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			err := checkSignature(test.Scheme, pub, msg, sig)
			if diff := cmp.Diff(test.Want, err == nil); diff != "" {
				t.Errorf("verified mismatch (-want +got):\n%s\nerror %v", diff, err)
			}
		})
	}
}

// TestParseGenTime holds parseGenTime to the one genTime form RFC 3161 allows and to whole
// microseconds, with finer digits dropped rather than rounded, so a verdict that compares the
// signing time never turns on a digit a microsecond verifier cannot hold.
func TestParseGenTime(t *testing.T) {
	t.Parallel()
	tests := []struct {
		WantMicro int64
		Want      error
		In        element
	}{{ // Test 0: A whole-second time parses.
		In: genTime("20260727150100Z"), WantMicro: 1785164460000000,
	}, { // Test 1: A fraction is read to the microsecond.
		In: genTime("20260727150100.5Z"), WantMicro: 1785164460500000,
	}, { // Test 2: Digits past the microsecond are dropped, not rounded up.
		In: genTime("20260727150100.0000009Z"), WantMicro: 1785164460000000,
	}, { // Test 3: A numeric offset is refused.
		In: genTime("20260727150100+0000"), Want: ErrParse,
	}, { // Test 4: A trailing zero in the fraction is refused.
		In: genTime("20260727150100.50Z"), Want: ErrParse,
	}, { // Test 5: A period with no fraction digits is refused.
		In: genTime("20260727150100.Z"), Want: ErrParse,
	}, { // Test 6: A time with no zone is refused.
		In: genTime("20260727150100"), Want: ErrParse,
	}, { // Test 7: A lower case zone letter is refused.
		In: genTime("20260727150100z"), Want: ErrParse,
	}, { // Test 8: Year 0000 is refused.
		In: genTime("00000727150100Z"), Want: ErrParse,
	}, { // Test 9: A leap second is refused.
		In: genTime("20161231235960Z"), Want: ErrParse,
	}, { // Test 10: A day outside its month is refused.
		In: genTime("20260230150100Z"), Want: ErrParse,
	}, { // Test 11: Minutes without seconds are refused.
		In: genTime("202607271501Z"), Want: ErrParse,
	}, { // Test 12: A valid genTime text under the UTCTime tag is refused.
		In: element{tag: tagUTCTime, content: []byte("20260727150100Z")}, Want: ErrParse,
	}, { // Test 13: A nonzero numeric offset, which a generic decoder reads, is refused.
		In: genTime("20260727160100+0100"), Want: ErrParse,
	}, { // Test 14: A valid genTime text under a context-specific tag is refused.
		In: element{tag: 0x98, content: []byte("20260727150100Z")}, Want: ErrParse,
	}, { // Test 15: A valid genTime text in a constructed GeneralizedTime is refused.
		In: element{tag: 0x38, content: []byte("20260727150100Z")}, Want: ErrParse,
	}}
	for testNum, test := range tests {
		t.Run(fmt.Sprintf("test %d", testNum), func(t *testing.T) {
			t.Parallel()
			got, err := parseGenTime(test.In)
			if !errors.Is(err, test.Want) {
				t.Fatalf("error mismatch: got %v, want %v", err, test.Want)
			}
			if test.Want != nil {
				return
			}
			if diff := cmp.Diff(time.UnixMicro(test.WantMicro).UTC(), got); diff != "" {
				t.Errorf("time mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// genTime wraps text as a GeneralizedTime element.
func genTime(text string) element {
	return element{tag: tagGeneralizedTime, content: []byte(text)}
}
