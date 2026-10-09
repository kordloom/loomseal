package rfc3161

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// OIDs a certificate is read against, as DER content octets.
var (
	oidExtKeyUsage    = oidContent(asn1.ObjectIdentifier{2, 5, 29, 37})
	oidSubjectKeyID   = oidContent(asn1.ObjectIdentifier{2, 5, 29, 14})
	oidKPTimeStamping = oidContent(asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 8})
	oidCurveP224      = oidContent(asn1.ObjectIdentifier{1, 3, 132, 0, 33})
	oidCurveP256      = oidContent(asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7})
	oidCurveP384      = oidContent(asn1.ObjectIdentifier{1, 3, 132, 0, 34})
	oidCurveP521      = oidContent(asn1.ObjectIdentifier{1, 3, 132, 0, 35})
)

// certificate is what a verifier reads from one carried X.509 certificate. Every carried
// certificate is read this far, so a token's certificates are all DER whichever one signed it.
type certificate struct {
	// version is the content of the explicit [0] version INTEGER, nil when the member is absent.
	version []byte
	// serial is the content of the serialNumber INTEGER.
	serial []byte
	// issuer is the issuer Name's whole encoding, compared octet for octet with a signer
	// identifier's issuer.
	issuer []byte
	// validity is the validity SEQUENCE, read only for the signer certificate.
	validity element
	// subject is the subject Name's whole encoding, used only to name the signer in a result.
	subject []byte
	// spki is the subjectPublicKeyInfo SEQUENCE, read only for the signer certificate.
	spki element
	// subjectKeyID is the subject key identifier, nil when the certificate carries none.
	subjectKeyID []byte
	// extKeyUsage lists the content of each extended key usage OBJECT IDENTIFIER.
	extKeyUsage [][]byte
}

// readCertificates reads every element of the certificates field as a certificate. The field is a
// SET of certificates, so every element must be one.
func readCertificates(content []byte) ([]*certificate, error) {
	r := reader{rest: content}
	var certs []*certificate
	for !r.empty() {
		e, err := r.read(tagSequence, "certificate")
		if err != nil {
			return nil, err
		}
		c, err := readCertificate(e)
		if err != nil {
			return nil, err
		}
		certs = append(certs, c)
	}
	return certs, nil
}

// readCertificate reads a certificate's tbsCertificate by position through its extensions. The
// certificate's own signature is not read: whether its issuer is trusted is the relying party's
// call, made from the signer a result names.
func readCertificate(e element) (*certificate, error) {
	cr := reader{rest: e.content}
	tbs, err := cr.read(tagSequence, "tbsCertificate")
	if err != nil {
		return nil, err
	}
	c := &certificate{}
	r := reader{rest: tbs.content}
	if wrapped, ok, err := r.optional(tagExplicit0, "certificate version"); err != nil {
		return nil, err
	} else if ok {
		v, err := only(wrapped.content, tagInteger, "certificate version")
		if err != nil {
			return nil, err
		}
		if err := derVersion(v, "certificate version"); err != nil {
			return nil, err
		}
		c.version = v.content
	}
	serial, err := r.read(tagInteger, "certificate serialNumber")
	if err != nil {
		return nil, err
	}
	if err := derInteger(serial, "certificate serialNumber"); err != nil {
		return nil, err
	}
	c.serial = serial.content
	if _, err := r.read(tagSequence, "certificate signature"); err != nil {
		return nil, err
	}
	issuer, err := r.read(tagSequence, "certificate issuer")
	if err != nil {
		return nil, err
	}
	c.issuer = issuer.full
	if c.validity, err = r.read(tagSequence, "certificate validity"); err != nil {
		return nil, err
	}
	subject, err := r.read(tagSequence, "certificate subject")
	if err != nil {
		return nil, err
	}
	c.subject = subject.full
	if c.spki, err = r.read(tagSequence, "certificate subjectPublicKeyInfo"); err != nil {
		return nil, err
	}
	if _, _, err := r.optional(tagImplicit1, "certificate issuerUniqueID"); err != nil {
		return nil, err
	}
	if _, _, err := r.optional(tagImplicit2, "certificate subjectUniqueID"); err != nil {
		return nil, err
	}
	wrapped, ok, err := r.optional(tagExplicit3, "certificate extensions")
	if err != nil {
		return nil, err
	}
	if ok {
		if err := c.readExtensions(wrapped); err != nil {
			return nil, err
		}
	}
	return c, nil
}

// readExtensions reads the [3] extensions: exactly one SEQUENCE of Extension, each a SEQUENCE of
// an extnID, an optional critical BOOLEAN, and an extnValue OCTET STRING, with no extnID twice.
// DER never encodes a BOOLEAN's default, so a critical member is present only to say TRUE, as the
// one octet 0xFF.
func (c *certificate) readExtensions(wrapped element) error {
	list, err := only(wrapped.content, tagSequence, "certificate extensions")
	if err != nil {
		return err
	}
	r := reader{rest: list.content}
	seen := map[string]bool{}
	for !r.empty() {
		ext, err := r.read(tagSequence, "extension")
		if err != nil {
			return err
		}
		er := reader{rest: ext.content}
		id, err := er.read(tagOID, "extnID")
		if err != nil {
			return err
		}
		if err := derOID(id, "extnID"); err != nil {
			return err
		}
		if critical, ok, err := er.optional(tagBoolean, "extension critical"); err != nil {
			return err
		} else if ok && !bytes.Equal(critical.content, []byte{0xff}) {
			return fmt.Errorf("%w: extension %s critical flag is not the DER TRUE octet",
				ErrParse, oidString(id.content))
		}
		value, err := er.read(tagOctetString, "extnValue")
		if err != nil {
			return err
		}
		if seen[string(id.content)] {
			return fmt.Errorf("%w: certificate carries extension %s twice", ErrParse,
				oidString(id.content))
		}
		seen[string(id.content)] = true
		switch {
		case bytes.Equal(id.content, oidSubjectKeyID):
			ski, err := only(value.content, tagOctetString, "subject key identifier")
			if err != nil {
				return err
			}
			c.subjectKeyID = ski.content
		case bytes.Equal(id.content, oidExtKeyUsage):
			if c.extKeyUsage, err = readKeyPurposes(value.content); err != nil {
				return err
			}
		}
	}
	return nil
}

// readKeyPurposes reads an extended key usage value: exactly one SEQUENCE whose every element is
// an OBJECT IDENTIFIER.
func readKeyPurposes(value []byte) ([][]byte, error) {
	list, err := only(value, tagSequence, "extended key usage")
	if err != nil {
		return nil, err
	}
	r := reader{rest: list.content}
	purposes := [][]byte{}
	for !r.empty() {
		p, err := r.read(tagOID, "extended key usage purpose")
		if err != nil {
			return nil, err
		}
		if err := derOID(p, "extended key usage purpose"); err != nil {
			return nil, err
		}
		purposes = append(purposes, p.content)
	}
	return purposes, nil
}

// signerCertificate returns the carried certificate the signer identifier names, rather than
// whichever carried certificate happens to have the timestamping usage. Naming the signer matters
// when a token carries more than one certificate, such as an authority mid key rollover: picking
// the first timestamping certificate would report, and check the signature against, a certificate
// the token never claimed signed it.
//
// The named certificate has to be the one that verifies. Falling back to another certificate the
// token happens to carry would make the outcome depend on the order they appear in, which the
// format states carries no meaning, and would let a token be graded against a certificate its
// signer identifier never named. The signer must be a version 3 certificate marked for
// timestamping.
func signerCertificate(certs []*certificate, sid element) (*certificate, error) {
	match := certificateNamedBy(certs, sid)
	if match == nil {
		return nil, fmt.Errorf("%w: the token names a signer certificate it does not carry", ErrParse)
	}
	if !bytes.Equal(match.version, []byte{2}) {
		return nil, fmt.Errorf("%w: the certificate the token names is not version 3", ErrParse)
	}
	for _, p := range match.extKeyUsage {
		if bytes.Equal(p, oidKPTimeStamping) {
			return match, nil
		}
	}
	return nil, fmt.Errorf("%w: the certificate the token names is not marked for timestamping",
		ErrParse)
}

// certificateNamedBy returns the first carried certificate a signer identifier names, or nil when
// the token carries no such certificate.
//
// A signer identifier is a choice: an issuer and serial number, or a subject key identifier tagged
// [0]. Both forms are read, because an authority may use either and a verifier that understands
// only one would report a conforming token as unresolvable. A serial number is compared by its DER
// content, which is one encoding per value.
func certificateNamedBy(certs []*certificate, sid element) *certificate {
	if sid.tag == tagImplicit0 {
		for _, c := range certs {
			if c.subjectKeyID != nil && bytes.Equal(c.subjectKeyID, sid.content) {
				return c
			}
		}
		return nil
	}
	r := reader{rest: sid.content}
	issuer, _ := r.read(tagSequence, "sid issuer")
	serial, _ := r.read(tagInteger, "sid serialNumber")
	for _, c := range certs {
		if bytes.Equal(c.serial, serial.content) && bytes.Equal(c.issuer, issuer.full) {
			return c
		}
	}
	return nil
}

// validityWindow reads the signer certificate's validity: notBefore and notAfter, each a UTCTime
// or a GeneralizedTime in its DER form. Anything after notAfter is not read.
func (c *certificate) validityWindow() (time.Time, time.Time, error) {
	r := reader{rest: c.validity.content}
	nb, err := r.next("notBefore")
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	notBefore, err := parseCertTime(nb)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	na, err := r.next("notAfter")
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	notAfter, err := parseCertTime(na)
	if err != nil {
		return time.Time{}, time.Time{}, err
	}
	return notBefore, notAfter, nil
}

// Patterns of the two certificate time forms DER and RFC 5280 allow: whole seconds, then Z.
var (
	reUTCTime = regexp.MustCompile(
		`^([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z$`)
	reCertGeneralized = regexp.MustCompile(
		`^([0-9]{4})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})([0-9]{2})Z$`)
)

// parseCertTime reads a certificate validity time: a UTCTime YYMMDDhhmmssZ, whose two-digit year
// is 19YY from 50 to 99 and 20YY below 50, or a GeneralizedTime YYYYMMDDhhmmssZ. Both carry
// seconds and the zone Z and nothing else, with the field ranges a bundle time has.
func parseCertTime(e element) (time.Time, error) {
	var year []byte
	var m [][]byte
	switch e.tag {
	case tagUTCTime:
		m = reUTCTime.FindSubmatch(e.content)
		if m != nil {
			year = []byte("20" + string(m[1]))
			if m[1][0] >= '5' {
				year = []byte("19" + string(m[1]))
			}
		}
	case tagGeneralizedTime:
		m = reCertGeneralized.FindSubmatch(e.content)
		if m != nil {
			year = m[1]
		}
	default:
		return time.Time{}, fmt.Errorf("%w: certificate validity time is neither a UTCTime nor a "+
			"GeneralizedTime", ErrParse)
	}
	if m == nil {
		return time.Time{}, fmt.Errorf("%w: certificate validity time %q is not in its DER form",
			ErrParse, e.content)
	}
	t, err := timeFromFields(year, m[2], m[3], m[4], m[5], m[6], nil)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: certificate validity time %q: %w", ErrParse, e.content,
			err)
	}
	return t, nil
}

// parsePublicKey reads the signer certificate's subjectPublicKeyInfo: an AlgorithmIdentifier
// SEQUENCE and a BIT STRING with no unused bits. Three key types are read, each in one form: an
// Ed25519 key of 32 octets with no parameters; an ECDSA key on P-224, P-256, P-384, or P-521, named
// by a curve OBJECT IDENTIFIER and written as an uncompressed point on that curve; and an RSA key
// with NULL parameters, written as exactly one SEQUENCE of a modulus and an exponent and nothing
// else. Any other key is refused.
func parsePublicKey(spki element) (crypto.PublicKey, error) {
	r := reader{rest: spki.content}
	alg, err := r.read(tagSequence, "public key algorithm")
	if err != nil {
		return nil, err
	}
	bits, err := r.read(tagBitString, "subjectPublicKey")
	if err != nil {
		return nil, err
	}
	if len(bits.content) == 0 || bits.content[0] != 0 {
		return nil, fmt.Errorf("%w: subjectPublicKey has unused bits", ErrParse)
	}
	key := bits.content[1:]
	ar := reader{rest: alg.content}
	id, err := ar.read(tagOID, "public key algorithm")
	if err != nil {
		return nil, err
	}
	if err := derOID(id, "public key algorithm"); err != nil {
		return nil, err
	}
	switch {
	case bytes.Equal(id.content, oidEd25519):
		if !ar.empty() {
			return nil, fmt.Errorf("%w: Ed25519 key carries parameters", ErrParse)
		}
		if len(key) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: Ed25519 key is %d octets", ErrParse, len(key))
		}
		return ed25519.PublicKey(key), nil
	case bytes.Equal(id.content, oidECPublicKey):
		return parseECKey(&ar, key)
	case bytes.Equal(id.content, oidRSAEncryption):
		return parseRSAKey(&ar, key)
	}
	return nil, fmt.Errorf("%w: unsupported public key algorithm %s", ErrParse,
		oidString(id.content))
}

// parseECKey reads an ECDSA key: a named curve parameter and an uncompressed point on that curve.
func parseECKey(ar *reader, key []byte) (crypto.PublicKey, error) {
	named, err := ar.read(tagOID, "elliptic curve")
	if err != nil {
		return nil, err
	}
	if err := derOID(named, "elliptic curve"); err != nil {
		return nil, err
	}
	var curve elliptic.Curve
	switch {
	case bytes.Equal(named.content, oidCurveP224):
		curve = elliptic.P224()
	case bytes.Equal(named.content, oidCurveP256):
		curve = elliptic.P256()
	case bytes.Equal(named.content, oidCurveP384):
		curve = elliptic.P384()
	case bytes.Equal(named.content, oidCurveP521):
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("%w: unsupported elliptic curve %s", ErrParse,
			oidString(named.content))
	}
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, key)
	if err != nil {
		return nil, fmt.Errorf("%w: elliptic curve key: %w", ErrParse, err)
	}
	return pub, nil
}

// maxRSABits is the longest RSA modulus a verifier reads. Go's crypto/rsa sets no upper bound,
// but OpenSSL refuses to verify with a modulus past 16384 bits, so a verifier built on it would
// refuse a token another verifier accepts. Every verifier holds keys to this bound instead.
const maxRSABits = 16384

// parseRSAKey reads an RSA key: NULL parameters, then exactly one SEQUENCE holding only a modulus
// and a public exponent. The modulus must be positive, odd, and from 1024 to 16384 bits, and the
// exponent odd and from 3 to 2^31-1. The lower bounds and the exponent's upper bound are the ones
// Go's crypto/rsa holds a key to before it verifies anything.
func parseRSAKey(ar *reader, key []byte) (crypto.PublicKey, error) {
	params, err := ar.read(tagNull, "RSA key parameters")
	if err != nil {
		return nil, err
	}
	if len(params.content) != 0 {
		return nil, fmt.Errorf("%w: RSA key parameters are not NULL", ErrParse)
	}
	seq, err := only(key, tagSequence, "RSA public key")
	if err != nil {
		return nil, err
	}
	kr := reader{rest: seq.content}
	n, err := kr.read(tagInteger, "RSA modulus")
	if err != nil {
		return nil, err
	}
	if err := derInteger(n, "RSA modulus"); err != nil {
		return nil, err
	}
	e, err := kr.read(tagInteger, "RSA public exponent")
	if err != nil {
		return nil, err
	}
	if err := derInteger(e, "RSA public exponent"); err != nil {
		return nil, err
	}
	if !kr.empty() {
		return nil, fmt.Errorf("%w: RSA public key holds more than a modulus and an exponent",
			ErrParse)
	}
	modulus, exponent := derBigInt(n.content), derBigInt(e.content)
	if modulus.Sign() <= 0 || modulus.Bit(0) == 0 || modulus.BitLen() < 1024 ||
		modulus.BitLen() > maxRSABits {
		return nil, fmt.Errorf("%w: RSA modulus is not a positive odd number of 1024 to 16384 "+
			"bits", ErrParse)
	}
	if exponent.Bit(0) == 0 || exponent.Cmp(big.NewInt(3)) < 0 ||
		exponent.Cmp(big.NewInt(1<<31-1)) > 0 {
		return nil, fmt.Errorf("%w: RSA public exponent is not odd and from 3 to 2^31-1", ErrParse)
	}
	return &rsa.PublicKey{N: modulus, E: int(exponent.Int64())}, nil
}

// rdnShortNames maps the nine attribute types RFC 4514 names, as DER content octets, to the
// short name a signer's subject writes them with. Every other type is written in dotted form.
var rdnShortNames = map[string]string{
	oidKey(2, 5, 4, 3):                       "CN",
	oidKey(2, 5, 4, 7):                       "L",
	oidKey(2, 5, 4, 8):                       "ST",
	oidKey(2, 5, 4, 10):                      "O",
	oidKey(2, 5, 4, 11):                      "OU",
	oidKey(2, 5, 4, 6):                       "C",
	oidKey(2, 5, 4, 9):                       "STREET",
	oidKey(0, 9, 2342, 19200300, 100, 1, 25): "DC",
	oidKey(0, 9, 2342, 19200300, 100, 1, 1):  "UID",
}

// Identifier octets of the string types a subject attribute's value is written out from.
const (
	tagUTF8String      byte = 0x0c
	tagPrintableString byte = 0x13
	tagIA5String       byte = 0x16
)

// subjectName names the signer for a result from the subject Name alone, never from a parse of
// the whole certificate, by the one rule FORMAT.md states: the RFC 4514 string of a subject that
// is a sequence of relative distinguished names, and otherwise # and the hexadecimal of the
// subject's whole encoding. It only names the signer and never decides a verdict, so it refuses
// nothing, and every verifier writes the same name for the same subject.
func (c *certificate) subjectName() string {
	if name, ok := rfc4514Name(c.subject); ok {
		return name
	}
	return "#" + hex.EncodeToString(c.subject)
}

// rfc4514Name writes a Name in the RFC 4514 form: its relative distinguished names from the last
// to the first, separated by commas, and the attributes of each in the order they are encoded,
// separated by plus signs. It reports false unless the Name is one SEQUENCE of one or more SETs,
// each holding one or more attribute SEQUENCEs of an OBJECT IDENTIFIER that derOID accepts and
// exactly one value.
func rfc4514Name(subject []byte) (string, bool) {
	name, err := only(subject, tagSequence, "subject")
	if err != nil {
		return "", false
	}
	var rdns []string
	r := reader{rest: name.content}
	for !r.empty() {
		set, err := r.read(tagSet, "relative distinguished name")
		if err != nil {
			return "", false
		}
		var attrs []string
		sr := reader{rest: set.content}
		for !sr.empty() {
			attr, err := sr.read(tagSequence, "attribute")
			if err != nil {
				return "", false
			}
			ar := reader{rest: attr.content}
			typ, err := ar.read(tagOID, "attribute type")
			if err != nil || derOID(typ, "attribute type") != nil {
				return "", false
			}
			value, err := ar.next("attribute value")
			if err != nil || !ar.empty() {
				return "", false
			}
			attrs = append(attrs, attributeString(typ.content, value))
		}
		if len(attrs) == 0 {
			return "", false
		}
		rdns = append(rdns, strings.Join(attrs, "+"))
	}
	if len(rdns) == 0 {
		return "", false
	}
	slices.Reverse(rdns)
	return strings.Join(rdns, ","), true
}

// attributeString writes one attribute as its type, an equals sign, and its value. A type RFC
// 4514 names is written by that name, and its value as escaped text when the value is a string
// stringValue reads. Any other value, and every value of a type written in dotted form, is # and
// the hexadecimal of the value's whole encoding, as RFC 4514 writes a value it has no string for.
func attributeString(typ []byte, value element) string {
	short, named := rdnShortNames[string(typ)]
	if !named {
		return oidString(typ) + "=#" + hex.EncodeToString(value.full)
	}
	if text, ok := stringValue(value); ok {
		return short + "=" + escapeRDNValue(text)
	}
	return short + "=#" + hex.EncodeToString(value.full)
}

// stringValue returns the text of a primitive UTF8String holding valid UTF-8, or of a primitive
// PrintableString or IA5String holding only ASCII, and reports false for any other value.
func stringValue(v element) (string, bool) {
	switch v.tag {
	case tagUTF8String:
		return string(v.content), utf8.Valid(v.content)
	case tagPrintableString, tagIA5String:
		for _, b := range v.content {
			if b >= 0x80 {
				return "", false
			}
		}
		return string(v.content), true
	}
	return "", false
}

// escapeRDNValue escapes an attribute's text as RFC 4514 requires: a backslash before each of
// the characters " + , ; < > and backslash, before a # or a space that starts the text, and before
// a space that ends it. Every character below U+0020 or from U+007F to U+009F is written as a
// backslash and two lower case hexadecimal digits for each octet of its UTF-8 encoding, so a name
// cannot act on the terminal that prints it.
func escapeRDNValue(text string) string {
	var b strings.Builder
	for i, r := range text {
		switch {
		case strings.ContainsRune(`"+,;<>\`, r), r == '#' && i == 0,
			r == ' ' && (i == 0 || i+1 == len(text)):
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r >= 0x7f && r <= 0x9f:
			for _, o := range []byte(string(r)) {
				fmt.Fprintf(&b, "\\%02x", o)
			}
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
