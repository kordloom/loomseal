// Package rfc3161 reads and checks RFC 3161 timestamp tokens.
//
// It is public because a producer needs it. LoomSeal's own CLI only verifies bundles, so anything
// that writes anchors, including SwitchTender, lives outside this module and could not reach this
// code while it sat under internal. The result was a second, independent implementation of the same
// ASN.1 in the producer, which drifted: it hardcoded SHA-256 for the payload digest and rejected
// every token from an authority that answers in SHA-512, while this package accepted them. Two
// parsers that must agree, with no way to test that they do, is the shape of that bug.
//
// Verify deliberately does not decide whether an authority is trustworthy. That is the relying
// party's call, made by looking at the signer this returns.
//
// A token is read as DER, by position, through the reader in der.go, and the signer certificate
// through the rules in cert.go, rather than through encoding/asn1 and crypto/x509. Both of those
// accept encodings DER forbids, in ways that depend on the Go release, and the Python reference
// verifier must read every token exactly as this package does.

package rfc3161

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"regexp"
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
	// ErrValidity means the token's signing time lies outside its signer certificate's validity window.
	ErrValidity = errors.New("timestamp token signing time is outside the certificate validity window")
)

// OIDs a token is read against, as DER content octets.
var (
	oidSignedData    = oidContent(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2})
	oidTSTInfo       = oidContent(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 4})
	oidMessageDigest = oidContent(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4})
	oidSHA256        = oidContent(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1})
	oidSHA384        = oidContent(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2})
	oidSHA512        = oidContent(asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3})
	oidRSAEncryption = oidContent(asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1})
	oidECPublicKey   = oidContent(asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1})
	oidEd25519       = oidContent(asn1.ObjectIdentifier{1, 3, 101, 112})
)

// keyKind names the public key type a signature scheme needs.
type keyKind int

// The key types a token's signer may hold.
const (
	keyRSA keyKind = iota + 1
	keyECDSA
	keyEd25519
)

// scheme is how a signer's signature is checked: the key type it needs, the hash applied to the
// signed attributes, and for RSA whether the padding is PSS.
type scheme struct {
	// key is the public key type the scheme needs.
	key keyKind
	// hash is applied to the signed attributes before an RSA or ECDSA check, and is zero for
	// Ed25519, which signs the attributes themselves.
	hash crypto.Hash
	// pss marks RSASSA-PSS, checked with MGF1 over the same hash and a salt as long as the hash.
	pss bool
}

// signatureSchemes maps a signature algorithm identifier, as its DER content octets, to the check
// that verifies it. An authority names its own scheme, and the set below is what the standards
// actually put in a token: RSA and ECDSA across the SHA-2 family, plus Ed25519. RSASSA-PSS is
// read as SHA-256 throughout, and its parameters are not read.
var signatureSchemes = map[string]scheme{
	oidKey(1, 2, 840, 113549, 1, 1, 11): {key: keyRSA, hash: crypto.SHA256},
	oidKey(1, 2, 840, 113549, 1, 1, 12): {key: keyRSA, hash: crypto.SHA384},
	oidKey(1, 2, 840, 113549, 1, 1, 13): {key: keyRSA, hash: crypto.SHA512},
	oidKey(1, 2, 840, 113549, 1, 1, 10): {key: keyRSA, hash: crypto.SHA256, pss: true},
	oidKey(1, 2, 840, 10045, 4, 3, 2):   {key: keyECDSA, hash: crypto.SHA256},
	oidKey(1, 2, 840, 10045, 4, 3, 3):   {key: keyECDSA, hash: crypto.SHA384},
	oidKey(1, 2, 840, 10045, 4, 3, 4):   {key: keyECDSA, hash: crypto.SHA512},
	oidKey(1, 3, 101, 112):              {key: keyEd25519},
}

// Result is what a verified token attests.
type Result struct {
	// Time is the instant the authority signed, which is the moment the link provably existed, in
	// UTC and to the whole microsecond.
	Time time.Time
	// Signer is the subject of the certificate that signed the token, so a relying party can decide
	// whether it trusts that authority.
	Signer string
	// Policy is the authority's stated timestamping policy.
	Policy string
	// SerialNumber identifies the token at the authority. It is the value as read, never written
	// out in decimal here, and it has at most 21 octets, the bound maxSerialOctets states.
	SerialNumber *big.Int
}

// token is what a verifier reads from a timestamp token before checking it.
type token struct {
	// eContent is the content of the OCTET STRING that holds the DER TSTInfo, the bytes the
	// signed attributes commit to.
	eContent []byte
	// info is what is read from the TSTInfo.
	info tstInfo
	// certificates is the content of the SignedData certificates field.
	certificates []byte
	// hasCertificates reports whether the SignedData carries the certificates field.
	hasCertificates bool
	// signer is what is read from the one SignerInfo.
	signer signerInfo
}

// tstInfo is what a verifier reads from a TSTInfo: its first five members, by position.
type tstInfo struct {
	// policy is the content of the authority's policy OBJECT IDENTIFIER.
	policy []byte
	// imprintAlgorithm is the content of the message imprint's hash algorithm OBJECT IDENTIFIER.
	imprintAlgorithm []byte
	// imprint is the hashed message the authority timestamped.
	imprint []byte
	// serial is the content of the serialNumber INTEGER.
	serial []byte
	// genTime is the genTime element, read by parseGenTime.
	genTime element
}

// signerInfo is what a verifier reads from a SignerInfo.
type signerInfo struct {
	// sid is the signer identifier element, an IssuerAndSerialNumber SEQUENCE or a [0]
	// subjectKeyIdentifier.
	sid element
	// digestAlgorithm is the content of the digest algorithm OBJECT IDENTIFIER.
	digestAlgorithm []byte
	// signedAttrs is the [0] signed attributes element, whose encoding the signature covers once
	// its identifier is rewritten as a SET.
	signedAttrs element
	// signatureAlgorithm is the content of the signature algorithm OBJECT IDENTIFIER.
	signatureAlgorithm []byte
	// signature is the signature octets.
	signature []byte
}

// Verify checks that token attests to link, and that it is signed by the certificate it carries.
//
// It deliberately does not decide whether the authority is trustworthy. That is the relying party's
// call, and it is made by looking at the signer this returns. Baking a root list into a verifier
// would mean a bundle's strength depended on which build of the verifier read it, which is the
// opposite of what an offline proof is for.
func Verify(raw []byte, link string) (*Result, error) {
	linkBytes, err := hex.DecodeString(link)
	if err != nil {
		return nil, fmt.Errorf("%w: link is not hex: %w", ErrImprint, err)
	}
	sum := sha256.Sum256(linkBytes)

	tok, err := readToken(raw)
	if err != nil {
		return nil, err
	}
	// The binding: this token is about this link and no other value.
	if !bytes.Equal(tok.info.imprintAlgorithm, oidSHA256) {
		return nil, fmt.Errorf("%w: imprint uses %s, want SHA-256", ErrImprint,
			oidString(tok.info.imprintAlgorithm))
	}
	if !bytes.Equal(tok.info.imprint, sum[:]) {
		return nil, ErrImprint
	}

	if !tok.hasCertificates {
		return nil, fmt.Errorf("%w: token carries no certificate to check its signature against",
			ErrParse)
	}
	certs, err := readCertificates(tok.certificates)
	if err != nil {
		return nil, err
	}
	signer, err := signerCertificate(certs, tok.signer.sid)
	if err != nil {
		return nil, err
	}
	pub, err := parsePublicKey(signer.spki)
	if err != nil {
		return nil, err
	}
	if err := verifySignature(tok.signer, tok.eContent, pub); err != nil {
		return nil, err
	}
	// An authority's certificate has to be valid when it signs, so a token whose signing time falls
	// outside its own signer certificate's window is not evidence of anything, whatever the signature
	// says. This needs no root store: it is a self-consistency check between two values the token
	// already carries. Without it a token signed years outside its certificate's life still reaches
	// the strongest verdict the format issues.
	notBefore, notAfter, err := signer.validityWindow()
	if err != nil {
		return nil, err
	}
	genTime, err := parseGenTime(tok.info.genTime)
	if err != nil {
		return nil, err
	}
	if genTime.Before(notBefore) || genTime.After(notAfter) {
		return nil, fmt.Errorf("%w: signed at %s, certificate valid %s to %s", ErrValidity,
			genTime.Format(time.RFC3339), notBefore.Format(time.RFC3339),
			notAfter.Format(time.RFC3339))
	}
	return &Result{
		Time:         genTime,
		Signer:       signer.subjectName(),
		Policy:       oidString(tok.info.policy),
		SerialNumber: derBigInt(tok.info.serial),
	}, nil
}

// readToken reads a token by position: a ContentInfo whose [0] holds a SignedData, whose
// encapsulated content holds the DER TSTInfo, and whose one SignerInfo signs it. The token is DER
// throughout and nothing may follow the ContentInfo. In each SEQUENCE nothing is interpreted after
// the last member a verifier uses.
func readToken(raw []byte) (*token, error) {
	if err := wellFormed(raw, "token"); err != nil {
		return nil, err
	}
	top := reader{rest: raw}
	ci, err := top.read(tagSequence, "ContentInfo")
	if err != nil {
		return nil, err
	}
	if !top.empty() {
		return nil, fmt.Errorf("%w: %d octets follow the ContentInfo", ErrParse, len(top.rest))
	}
	r := reader{rest: ci.content}
	contentType, err := r.read(tagOID, "contentType")
	if err != nil {
		return nil, err
	}
	if err := derOID(contentType, "contentType"); err != nil {
		return nil, err
	}
	if !bytes.Equal(contentType.content, oidSignedData) {
		return nil, fmt.Errorf("%w: outer content is %s, want SignedData", ErrParse,
			oidString(contentType.content))
	}
	wrapped, err := r.read(tagExplicit0, "ContentInfo content")
	if err != nil {
		return nil, err
	}
	sd, err := only(wrapped.content, tagSequence, "SignedData")
	if err != nil {
		return nil, err
	}
	return readSignedData(sd)
}

// readSignedData reads a SignedData's members by position and the TSTInfo it encapsulates.
func readSignedData(sd element) (*token, error) {
	tok := &token{}
	r := reader{rest: sd.content}
	version, err := r.read(tagInteger, "SignedData version")
	if err != nil {
		return nil, err
	}
	if err := derVersion(version, "SignedData version"); err != nil {
		return nil, err
	}
	if _, err := r.read(tagSet, "digestAlgorithms"); err != nil {
		return nil, err
	}
	encap, err := r.read(tagSequence, "encapContentInfo")
	if err != nil {
		return nil, err
	}
	if tok.eContent, err = readEncapsulated(encap); err != nil {
		return nil, err
	}
	certs, ok, err := r.optional(tagExplicit0, "certificates")
	if err != nil {
		return nil, err
	}
	tok.certificates, tok.hasCertificates = certs.content, ok
	if _, _, err := r.optional(tagExplicit1, "crls"); err != nil {
		return nil, err
	}
	infos, err := r.read(tagSet, "signerInfos")
	if err != nil {
		return nil, err
	}
	if tok.signer, err = readSignerInfos(infos); err != nil {
		return nil, err
	}
	info, err := only(tok.eContent, tagSequence, "TSTInfo")
	if err != nil {
		return nil, err
	}
	if err := wellFormed(info.content, "TSTInfo"); err != nil {
		return nil, err
	}
	if tok.info, err = readTSTInfo(info); err != nil {
		return nil, err
	}
	return tok, nil
}

// readEncapsulated reads an encapContentInfo, which must name TSTInfo and hold it in an OCTET
// STRING under an explicit [0], and returns that OCTET STRING's content.
func readEncapsulated(encap element) ([]byte, error) {
	r := reader{rest: encap.content}
	eType, err := r.read(tagOID, "eContentType")
	if err != nil {
		return nil, err
	}
	if err := derOID(eType, "eContentType"); err != nil {
		return nil, err
	}
	if !bytes.Equal(eType.content, oidTSTInfo) {
		return nil, fmt.Errorf("%w: payload is %s, want TSTInfo", ErrParse,
			oidString(eType.content))
	}
	wrapped, err := r.read(tagExplicit0, "eContent")
	if err != nil {
		return nil, err
	}
	octets, err := only(wrapped.content, tagOctetString, "eContent")
	if err != nil {
		return nil, err
	}
	return octets.content, nil
}

// readSignerInfos reads every element of the signerInfos SET as a SignerInfo and returns the one
// there must be. A timestamp token has exactly one signer, the authority. Zero is malformed, and
// more than one is ambiguous: verifying only the first would let an unverified second signer ride
// along.
func readSignerInfos(infos element) (signerInfo, error) {
	r := reader{rest: infos.content}
	var all []signerInfo
	for !r.empty() {
		e, err := r.read(tagSequence, "SignerInfo")
		if err != nil {
			return signerInfo{}, err
		}
		si, err := readSignerInfo(e)
		if err != nil {
			return signerInfo{}, err
		}
		all = append(all, si)
	}
	if len(all) != 1 {
		return signerInfo{}, fmt.Errorf("%w: token carries %d signers, want exactly one", ErrParse,
			len(all))
	}
	return all[0], nil
}

// readSignerInfo reads one SignerInfo's members by position.
func readSignerInfo(e element) (signerInfo, error) {
	var si signerInfo
	r := reader{rest: e.content}
	version, err := r.read(tagInteger, "SignerInfo version")
	if err != nil {
		return si, err
	}
	if err := derVersion(version, "SignerInfo version"); err != nil {
		return si, err
	}
	if si.sid, err = readSignerID(&r); err != nil {
		return si, err
	}
	if si.digestAlgorithm, err = readAlgorithm(&r, "digestAlgorithm"); err != nil {
		return si, err
	}
	if si.signedAttrs, err = r.read(tagExplicit0, "signedAttrs"); err != nil {
		return si, err
	}
	if si.signatureAlgorithm, err = readAlgorithm(&r, "signatureAlgorithm"); err != nil {
		return si, err
	}
	signature, err := r.read(tagOctetString, "signature")
	if err != nil {
		return si, err
	}
	si.signature = signature.content
	return si, nil
}

// readSignerID reads a signer identifier: a [0] subjectKeyIdentifier, primitive as an implicitly
// tagged OCTET STRING is, or an IssuerAndSerialNumber SEQUENCE of an issuer Name SEQUENCE and a
// serialNumber INTEGER.
func readSignerID(r *reader) (element, error) {
	sid, err := r.next("sid")
	if err != nil {
		return element{}, err
	}
	switch sid.tag {
	case tagImplicit0:
		return sid, nil
	case tagSequence:
		ir := reader{rest: sid.content}
		if _, err := ir.read(tagSequence, "sid issuer"); err != nil {
			return element{}, err
		}
		serial, err := ir.read(tagInteger, "sid serialNumber")
		if err != nil {
			return element{}, err
		}
		if err := derInteger(serial, "sid serialNumber"); err != nil {
			return element{}, err
		}
		return sid, nil
	default:
		return element{}, fmt.Errorf("%w: the token's signer identifier is neither an issuer and "+
			"serial number nor a subject key identifier", ErrParse)
	}
}

// readAlgorithm reads an AlgorithmIdentifier SEQUENCE and returns its OBJECT IDENTIFIER's content.
// Parameters that follow the identifier are not read.
func readAlgorithm(r *reader, what string) ([]byte, error) {
	alg, err := r.read(tagSequence, what)
	if err != nil {
		return nil, err
	}
	ar := reader{rest: alg.content}
	id, err := ar.read(tagOID, what)
	if err != nil {
		return nil, err
	}
	if err := derOID(id, what); err != nil {
		return nil, err
	}
	return id.content, nil
}

// readTSTInfo reads a TSTInfo by position, as RFC 3161 lays it out: version, policy,
// messageImprint, serialNumber, and genTime. A member in the wrong slot fails, and nothing after
// genTime is read.
func readTSTInfo(e element) (tstInfo, error) {
	var info tstInfo
	r := reader{rest: e.content}
	version, err := r.read(tagInteger, "TSTInfo version")
	if err != nil {
		return info, err
	}
	if err := derVersion(version, "TSTInfo version"); err != nil {
		return info, err
	}
	policy, err := r.read(tagOID, "TSTInfo policy")
	if err != nil {
		return info, err
	}
	if err := derOID(policy, "TSTInfo policy"); err != nil {
		return info, err
	}
	info.policy = policy.content
	imprint, err := r.read(tagSequence, "messageImprint")
	if err != nil {
		return info, err
	}
	ir := reader{rest: imprint.content}
	if info.imprintAlgorithm, err = readAlgorithm(&ir, "messageImprint hashAlgorithm"); err != nil {
		return info, err
	}
	hashed, err := ir.read(tagOctetString, "messageImprint hashedMessage")
	if err != nil {
		return info, err
	}
	info.imprint = hashed.content
	serial, err := r.read(tagInteger, "TSTInfo serialNumber")
	if err != nil {
		return info, err
	}
	if err := derSerial(serial, "TSTInfo serialNumber"); err != nil {
		return info, err
	}
	info.serial = serial.content
	if info.genTime, err = r.next("genTime"); err != nil {
		return info, err
	}
	return info, nil
}

// reGenTime is the one genTime form RFC 3161 allows: the year, month, day, hour, minute, and
// second as fourteen ASCII digits, an optional fraction after a period with no trailing zero, and
// an upper case Z.
var reGenTime = regexp.MustCompile(
	`^([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})(\.[0-9]*[1-9])?Z$`)

// parseGenTime reads a token's genTime in the one form RFC 3161 gives it, with the field ranges a
// bundle time has: a year from 0001 to 9999, a day within its month, an hour below 24, and a minute
// and a second below 60. The result is UTC and whole microseconds, with finer digits dropped toward
// the earlier instant rather than rounded, so the comparisons a verifier makes against it are the
// ones a verifier whose time type stops at microseconds makes. A generic GeneralizedTime reader
// also accepts a numeric offset, which RFC 3161 forbids.
func parseGenTime(e element) (time.Time, error) {
	if e.tag != tagGeneralizedTime {
		return time.Time{}, fmt.Errorf("%w: genTime is not a GeneralizedTime", ErrParse)
	}
	m := reGenTime.FindSubmatch(e.content)
	if m == nil {
		return time.Time{}, fmt.Errorf(
			"%w: genTime %q is not of the form YYYYMMDDhhmmss[.fraction]Z", ErrParse, e.content)
	}
	t, err := timeFromFields(m[1], m[2], m[3], m[4], m[5], m[6], m[7])
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: genTime %q: %w", ErrParse, e.content, err)
	}
	return t.Truncate(time.Microsecond), nil
}

// timeFromFields builds a UTC time from matched digit fields and an optional fraction, refusing
// year 0000 and any field out of its range, such as a second of 60 or a day past its month.
func timeFromFields(year, month, day, hour, minute, second, fraction []byte) (time.Time, error) {
	if string(year) == "0000" {
		return time.Time{}, errors.New("year 0000")
	}
	return time.Parse(time.RFC3339, fmt.Sprintf("%s-%s-%sT%s:%s:%s%sZ", year, month, day, hour,
		minute, second, fraction))
}

// verifySignature checks the signer's signature over the signed attributes, and that those
// attributes commit to the payload.
//
// A token signs its attributes, not the payload directly, so checking the signature alone would
// leave the payload unbound. The messageDigest attribute is the link between them, and both have to
// hold for the token to mean anything.
func verifySignature(si signerInfo, payload []byte, pub crypto.PublicKey) error {
	hashFn, err := hashFor(si.digestAlgorithm)
	if err != nil {
		return err
	}
	want := hashFn.New()
	want.Write(payload)
	payloadDigest := want.Sum(nil)

	// The signature is over the attributes re-encoded as a SET, not as the implicit [0] they appear
	// in on the wire. Getting this wrong is the classic way to verify nothing at all.
	signed := append([]byte{tagSet}, si.signedAttrs.full[1:]...)
	bound, err := commitsTo(si.signedAttrs, payloadDigest)
	if err != nil {
		return err
	}
	if !bound {
		return fmt.Errorf("%w: signed attributes do not commit to the payload", ErrSignature)
	}
	sch, err := signatureScheme(si.signatureAlgorithm, hashFn)
	if err != nil {
		return err
	}
	if err := checkSignature(sch, pub, signed, si.signature); err != nil {
		return fmt.Errorf("%w: %w", ErrSignature, err)
	}
	return nil
}

// commitsTo reads every signed attribute, each a SEQUENCE of a type and a SET of values, and
// reports whether a messageDigest attribute is present. Every messageDigest attribute must hold
// exactly one OCTET STRING equal to digest.
func commitsTo(attrs element, digest []byte) (bool, error) {
	r := reader{rest: attrs.content}
	var bound bool
	for !r.empty() {
		attr, err := r.read(tagSequence, "signed attribute")
		if err != nil {
			return false, err
		}
		ar := reader{rest: attr.content}
		typ, err := ar.read(tagOID, "signed attribute type")
		if err != nil {
			return false, err
		}
		if err := derOID(typ, "signed attribute type"); err != nil {
			return false, err
		}
		values, err := ar.read(tagSet, "signed attribute values")
		if err != nil {
			return false, err
		}
		if !bytes.Equal(typ.content, oidMessageDigest) {
			continue
		}
		value, err := only(values.content, tagOctetString, "message digest attribute")
		if err != nil {
			return false, err
		}
		if !bytes.Equal(value.content, digest) {
			return false, fmt.Errorf("%w: the signed attributes commit to a different payload",
				ErrSignature)
		}
		bound = true
	}
	return bound, nil
}

// hashFor maps a digest algorithm identifier's content to its hash.
func hashFor(oid []byte) (crypto.Hash, error) {
	switch {
	case bytes.Equal(oid, oidSHA256):
		return crypto.SHA256, nil
	case bytes.Equal(oid, oidSHA384):
		return crypto.SHA384, nil
	case bytes.Equal(oid, oidSHA512):
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("%w: unsupported digest %s", ErrParse, oidString(oid))
	}
}

// signatureScheme resolves the check for a signer's signature algorithm identifier.
//
// An authority usually names the full scheme, such as ecdsa-with-SHA512. Some name only the key
// algorithm and leave the digest to the signer info, so that case is resolved by pairing the key
// algorithm with the digest the signer declared.
func signatureScheme(oid []byte, h crypto.Hash) (scheme, error) {
	if s, ok := signatureSchemes[string(oid)]; ok {
		return s, nil
	}
	switch {
	case bytes.Equal(oid, oidRSAEncryption):
		return scheme{key: keyRSA, hash: h}, nil
	case bytes.Equal(oid, oidECPublicKey):
		return scheme{key: keyECDSA, hash: h}, nil
	}
	return scheme{}, fmt.Errorf("%w: unsupported signature algorithm %s", ErrParse,
		oidString(oid))
}

// checkSignature checks signature over signed with pub under sch. The key must be the type the
// scheme names: an algorithm identifier that disagrees with the certificate's key fails rather than
// being checked under the key's own scheme.
func checkSignature(sch scheme, pub crypto.PublicKey, signed, signature []byte) error {
	var digest []byte
	if sch.hash != 0 {
		h := sch.hash.New()
		h.Write(signed)
		digest = h.Sum(nil)
	}
	switch k := pub.(type) {
	case *rsa.PublicKey:
		if sch.key != keyRSA {
			return errors.New("the signature algorithm does not match the RSA signer key")
		}
		if len(signature) != (k.N.BitLen()+7)/8 {
			return errors.New("RSA signature length differs from the modulus length")
		}
		if sch.pss {
			return rsa.VerifyPSS(k, sch.hash, digest, signature,
				&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
		return rsa.VerifyPKCS1v15(k, sch.hash, digest, signature)
	case *ecdsa.PublicKey:
		if sch.key != keyECDSA {
			return errors.New("the signature algorithm does not match the ECDSA signer key")
		}
		if !ecdsa.VerifyASN1(k, digest, signature) {
			return errors.New("ECDSA verification failure")
		}
		return nil
	case ed25519.PublicKey:
		if sch.key != keyEd25519 {
			return errors.New("the signature algorithm does not match the Ed25519 signer key")
		}
		if !ed25519.Verify(k, signed, signature) {
			return errors.New("Ed25519 verification failure")
		}
		return nil
	}
	return errors.New("unsupported signer key")
}
