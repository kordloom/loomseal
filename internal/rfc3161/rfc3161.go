// Package rfc3161 verifies the timestamp tokens an anchor may carry as an embedded proof.
//
// An anchor fixes a chain link in time somewhere the producer cannot rewrite alone. Most anchor
// types are checked by going and fetching what they point at, which needs a network and a place that
// still exists. An RFC 3161 token is different: it is signed by a timestamp authority over the link
// itself and carries its own certificates, so a relying party checks it offline, years later, with
// nothing but the bundle.
//
// The format has always said so. Nothing verified it, so a bundle carrying a real signed timestamp
// was reported at the same strength as one carrying a URL.
package rfc3161

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// Errors returned when a token does not hold up.
var (
	// ErrParse means the token is not a well-formed timestamp token.
	ErrParse = errors.New("timestamp token is malformed")
	// ErrImprint means the token attests to a different value than the anchor claims.
	ErrImprint = errors.New("timestamp token does not attest to this link")
	// ErrSignature means the token's signature does not verify against its own signer certificate.
	ErrSignature = errors.New("timestamp token signature does not verify")
)

// OIDs used inside a timestamp token.
var (
	oidSignedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidTSTInfo       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4}
	oidMessageDigest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSHA256        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512        = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidRSAEncryption = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidECPublicKey   = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidEd25519       = asn1.ObjectIdentifier{1, 3, 101, 112}
)

// signatureOIDs maps a signature algorithm identifier to the x509 algorithm that checks it. An
// authority names its own scheme, and the set below is what the standards actually put in a token:
// RSA and ECDSA across the SHA-2 family, plus Ed25519.
var signatureOIDs = map[string]x509.SignatureAlgorithm{
	"1.2.840.113549.1.1.11": x509.SHA256WithRSA,
	"1.2.840.113549.1.1.12": x509.SHA384WithRSA,
	"1.2.840.113549.1.1.13": x509.SHA512WithRSA,
	"1.2.840.113549.1.1.10": x509.SHA256WithRSAPSS,
	"1.2.840.10045.4.3.2":   x509.ECDSAWithSHA256,
	"1.2.840.10045.4.3.3":   x509.ECDSAWithSHA384,
	"1.2.840.10045.4.3.4":   x509.ECDSAWithSHA512,
	"1.3.101.112":           x509.PureEd25519,
}

// Result is what a verified token attests.
type Result struct {
	// Time is the instant the authority signed, which is the moment the link provably existed.
	Time time.Time
	// Signer is the subject of the certificate that signed the token, so a relying party can decide
	// whether it trusts that authority.
	Signer string
	// Policy is the authority's stated timestamping policy.
	Policy string
	// SerialNumber identifies the token at the authority.
	SerialNumber string
}

// contentInfo is the outer CMS wrapper.
type contentInfo struct {
	// ContentType names what the content is; a token is SignedData.
	ContentType asn1.ObjectIdentifier
	// Content is the SignedData, explicitly tagged.
	Content asn1.RawValue `asn1:"explicit,optional,tag:0"`
}

// signedData is the CMS SignedData a timestamp token carries.
type signedData struct {
	// Version is the structure version.
	Version int
	// DigestAlgorithms lists the digests used, unread here.
	DigestAlgorithms asn1.RawValue `asn1:"set"`
	// EncapContentInfo holds the TSTInfo being signed.
	EncapContentInfo encapContentInfo
	// Certificates carries the signer's certificate chain.
	Certificates asn1.RawValue `asn1:"optional,tag:0"`
	// CRLs is unread.
	CRLs asn1.RawValue `asn1:"optional,tag:1"`
	// SignerInfos holds one signer, the authority.
	SignerInfos []signerInfo `asn1:"set"`
}

// encapContentInfo wraps the signed payload.
type encapContentInfo struct {
	// EContentType names the payload; a token's is TSTInfo.
	EContentType asn1.ObjectIdentifier
	// EContent is the DER-encoded TSTInfo, wrapped in an OCTET STRING.
	EContent []byte `asn1:"explicit,optional,tag:0"`
}

// signerInfo describes one signature over the payload.
type signerInfo struct {
	// Version is the structure version.
	Version int
	// SID identifies the signing certificate, by issuer and serial or by key id.
	SID asn1.RawValue
	// DigestAlgorithm is the hash used over the signed attributes.
	DigestAlgorithm algorithmIdentifier
	// SignedAttrs are the attributes actually signed, including the payload's digest.
	SignedAttrs asn1.RawValue `asn1:"optional,tag:0"`
	// SignatureAlgorithm is the signature scheme.
	SignatureAlgorithm algorithmIdentifier
	// Signature is the signature itself.
	Signature []byte
	// UnsignedAttrs is unread.
	UnsignedAttrs asn1.RawValue `asn1:"optional,tag:1"`
}

// algorithmIdentifier names an algorithm and its parameters.
type algorithmIdentifier struct {
	// Algorithm is the OID.
	Algorithm asn1.ObjectIdentifier
	// Parameters are optional and unread.
	Parameters asn1.RawValue `asn1:"optional"`
}

// attribute is one signed attribute.
type attribute struct {
	// Type names the attribute.
	Type asn1.ObjectIdentifier
	// Values holds its values.
	Values asn1.RawValue `asn1:"set"`
}

// messageImprint is the hash the authority timestamped.
type messageImprint struct {
	// Algorithm is the hash function.
	Algorithm algorithmIdentifier
	// Digest is the hash of the value being timestamped.
	Digest []byte
}

// tstInfo is the payload a timestamp token signs.
type tstInfo struct {
	// Version is the structure version.
	Version int
	// Policy is the authority's timestamping policy.
	Policy asn1.ObjectIdentifier
	// MessageImprint is the hash that was timestamped.
	MessageImprint messageImprint
	// SerialNumber identifies the token at the authority.
	SerialNumber *big.Int
	// GenTime is when the authority says it signed.
	GenTime time.Time `asn1:"generalized"`
	// Accuracy, Ordering, Nonce, TSA and Extensions follow and are unread.
	Rest asn1.RawValue `asn1:"optional,any"`
}

// Verify checks that token attests to link, and that it is signed by the certificate it carries.
//
// It deliberately does not decide whether the authority is trustworthy. That is the relying party's
// call, and it is made by looking at the signer this returns. Baking a root list into a verifier
// would mean a bundle's strength depended on which build of the verifier read it, which is the
// opposite of what an offline proof is for.
func Verify(token []byte, link string) (*Result, error) {
	raw, err := decodeHex(link)
	if err != nil {
		return nil, fmt.Errorf("%w: link is not hex: %w", ErrImprint, err)
	}
	sum := sha256.Sum256(raw)

	var ci contentInfo
	if _, err := asn1.Unmarshal(token, &ci); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParse, err)
	}
	if !ci.ContentType.Equal(oidSignedData) {
		return nil, fmt.Errorf("%w: outer content is %v, want SignedData", ErrParse, ci.ContentType)
	}
	var sd signedData
	if _, err := asn1.Unmarshal(ci.Content.Bytes, &sd); err != nil {
		return nil, fmt.Errorf("%w: signed data: %w", ErrParse, err)
	}
	if !sd.EncapContentInfo.EContentType.Equal(oidTSTInfo) {
		return nil, fmt.Errorf("%w: payload is %v, want TSTInfo", ErrParse,
			sd.EncapContentInfo.EContentType)
	}
	if len(sd.SignerInfos) == 0 {
		return nil, fmt.Errorf("%w: token carries no signer", ErrParse)
	}

	var info tstInfo
	if _, err := asn1.Unmarshal(sd.EncapContentInfo.EContent, &info); err != nil {
		return nil, fmt.Errorf("%w: TSTInfo: %w", ErrParse, err)
	}
	// The binding: this token is about this link and no other value.
	if !info.MessageImprint.Algorithm.Algorithm.Equal(oidSHA256) {
		return nil, fmt.Errorf("%w: imprint uses %v, want SHA-256", ErrImprint,
			info.MessageImprint.Algorithm.Algorithm)
	}
	if !equalBytes(info.MessageImprint.Digest, sum[:]) {
		return nil, ErrImprint
	}

	signer, err := signerCertificate(sd)
	if err != nil {
		return nil, err
	}
	if err := verifySignature(sd.SignerInfos[0], sd.EncapContentInfo.EContent, signer); err != nil {
		return nil, err
	}
	return &Result{
		Time:         info.GenTime.UTC(),
		Signer:       signer.Subject.String(),
		Policy:       info.Policy.String(),
		SerialNumber: info.SerialNumber.String(),
	}, nil
}

// signerCertificate returns the certificate that signed the token. A token carries its chain so a
// relying party needs nothing else, and the leaf is the one bearing the timestamping usage.
func signerCertificate(sd signedData) (*x509.Certificate, error) {
	if len(sd.Certificates.Bytes) == 0 {
		return nil, fmt.Errorf("%w: token carries no certificate to check its signature against",
			ErrParse)
	}
	certs, err := x509.ParseCertificates(sd.Certificates.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: certificates: %w", ErrParse, err)
	}
	for _, c := range certs {
		for _, eku := range c.ExtKeyUsage {
			if eku == x509.ExtKeyUsageTimeStamping {
				return c, nil
			}
		}
	}
	return nil, fmt.Errorf("%w: no certificate in the token is marked for timestamping", ErrParse)
}

// verifySignature checks the signer's signature over the signed attributes, and that those
// attributes commit to the payload.
//
// A token signs its attributes, not the payload directly, so checking the signature alone would
// leave the payload unbound. The messageDigest attribute is the link between them, and both have to
// hold for the token to mean anything.
func verifySignature(si signerInfo, payload []byte, cert *x509.Certificate) error {
	if len(si.SignedAttrs.Bytes) == 0 {
		return fmt.Errorf("%w: signer carries no signed attributes", ErrParse)
	}
	var attrs []attribute
	if _, err := asn1.UnmarshalWithParams(reTagAsSet(si.SignedAttrs), &attrs, "set"); err != nil {
		return fmt.Errorf("%w: signed attributes: %w", ErrParse, err)
	}
	hashFn, err := hashFor(si.DigestAlgorithm.Algorithm)
	if err != nil {
		return err
	}
	want := hashFn.New()
	want.Write(payload)
	payloadDigest := want.Sum(nil)

	var bound bool
	for _, a := range attrs {
		if !a.Type.Equal(oidMessageDigest) {
			continue
		}
		var digest []byte
		if _, err := asn1.Unmarshal(a.Values.Bytes, &digest); err != nil {
			return fmt.Errorf("%w: message digest attribute: %w", ErrParse, err)
		}
		if !equalBytes(digest, payloadDigest) {
			return fmt.Errorf("%w: the signed attributes commit to a different payload", ErrSignature)
		}
		bound = true
	}
	if !bound {
		return fmt.Errorf("%w: signed attributes do not commit to the payload", ErrSignature)
	}

	// The signature is over the attributes re-encoded as a SET, not as the implicit [0] they appear
	// in on the wire. Getting this wrong is the classic way to verify nothing at all.
	algo, err := signatureAlgorithm(si.SignatureAlgorithm.Algorithm, hashFn)
	if err != nil {
		return err
	}
	if err := cert.CheckSignature(algo, reTagAsSet(si.SignedAttrs), si.Signature); err != nil {
		return fmt.Errorf("%w: %w", ErrSignature, err)
	}
	return nil
}

// reTagAsSet rewrites the implicit [0] tag the signed attributes carry on the wire back to the
// universal SET tag the signature was computed over.
func reTagAsSet(v asn1.RawValue) []byte {
	out := make([]byte, len(v.FullBytes))
	copy(out, v.FullBytes)
	if len(out) > 0 {
		out[0] = 0x31
	}
	return out
}

// hashFor maps a digest OID to its hash.
func hashFor(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidSHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidSHA384):
		return crypto.SHA384, nil
	case oid.Equal(oidSHA512):
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("%w: unsupported digest %v", ErrParse, oid)
	}
}

// signatureAlgorithm resolves the algorithm that checks a signer's signature.
//
// An authority usually names the full scheme, such as ecdsa-with-SHA512. Some name only the key
// algorithm and leave the digest to the signer info, so that case is resolved by pairing the key
// algorithm with the digest the signer declared.
func signatureAlgorithm(oid asn1.ObjectIdentifier, h crypto.Hash) (x509.SignatureAlgorithm, error) {
	if algo, ok := signatureOIDs[oid.String()]; ok {
		return algo, nil
	}
	switch {
	case oid.Equal(oidRSAEncryption):
		switch h {
		case crypto.SHA256:
			return x509.SHA256WithRSA, nil
		case crypto.SHA384:
			return x509.SHA384WithRSA, nil
		case crypto.SHA512:
			return x509.SHA512WithRSA, nil
		}
	case oid.Equal(oidECPublicKey):
		switch h {
		case crypto.SHA256:
			return x509.ECDSAWithSHA256, nil
		case crypto.SHA384:
			return x509.ECDSAWithSHA384, nil
		case crypto.SHA512:
			return x509.ECDSAWithSHA512, nil
		}
	case oid.Equal(oidEd25519):
		return x509.PureEd25519, nil
	}
	return 0, fmt.Errorf("%w: unsupported signature algorithm %v", ErrParse, oid)
}

// equalBytes reports whether two byte slices match.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// decodeHex decodes a lowercase hex string.
func decodeHex(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, fmt.Errorf("odd length")
	}
	out := make([]byte, len(s)/2)
	for i := range out {
		hi, err := hexNibble(s[i*2])
		if err != nil {
			return nil, err
		}
		lo, err := hexNibble(s[i*2+1])
		if err != nil {
			return nil, err
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

// hexNibble decodes one hex character.
func hexNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	default:
		return 0, fmt.Errorf("invalid hex character %q", c)
	}
}
