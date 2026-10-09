package rfc3161

import (
	"encoding/asn1"
	"fmt"
	"math/big"
	"strconv"
	"strings"
)

// Identifier octets of the elements a token is read through. Each is the whole one-octet
// identifier, class and constructed bit included, so comparing one octet checks all three.
const (
	tagBoolean         byte = 0x01
	tagInteger         byte = 0x02
	tagBitString       byte = 0x03
	tagOctetString     byte = 0x04
	tagNull            byte = 0x05
	tagOID             byte = 0x06
	tagUTCTime         byte = 0x17
	tagGeneralizedTime byte = 0x18
	tagSequence        byte = 0x30
	tagSet             byte = 0x31
	tagExplicit0       byte = 0xA0
	tagExplicit1       byte = 0xA1
	tagExplicit3       byte = 0xA3
	tagImplicit0       byte = 0x80
	tagImplicit1       byte = 0x81
	tagImplicit2       byte = 0x82
)

// element is one DER element a verifier has read.
type element struct {
	// tag is the element's one identifier octet.
	tag byte
	// content is the element's content octets.
	content []byte
	// full is the element's whole encoding, identifier and length octets included.
	full []byte
}

// reader reads consecutive DER elements from the content of a constructed element, in order.
//
// Every element it returns has a one-octet identifier, a definite length in its shortest form,
// and lies wholly inside what is being read. Those are the rules of DER that every element obeys
// whatever it holds, and the reader enforces them so that no caller can read an element without
// them. A verifier that accepted a BER form here would accept a token another verifier refuses.
type reader struct {
	// rest is what has not been read yet.
	rest []byte
}

// empty reports whether everything has been read.
func (r *reader) empty() bool {
	return len(r.rest) == 0
}

// next reads the next element, whatever its identifier.
func (r *reader) next(what string) (element, error) {
	in := r.rest
	if len(in) < 2 {
		return element{}, fmt.Errorf("%w: %s: missing or truncated", ErrParse, what)
	}
	tag := in[0]
	if tag&0x1f == 0x1f {
		return element{}, fmt.Errorf("%w: %s: identifier uses the high tag number form", ErrParse,
			what)
	}
	n, hdr := int(in[1]), 2
	if n&0x80 != 0 {
		count := n & 0x7f
		switch {
		case count == 0:
			return element{}, fmt.Errorf("%w: %s: indefinite length", ErrParse, what)
		case count > 4:
			return element{}, fmt.Errorf("%w: %s: length of %d octets", ErrParse, what, count)
		case len(in) < 2+count:
			return element{}, fmt.Errorf("%w: %s: truncated length", ErrParse, what)
		case in[2] == 0:
			return element{}, fmt.Errorf("%w: %s: length with a leading zero octet", ErrParse,
				what)
		}
		n = 0
		for _, b := range in[2 : 2+count] {
			n = n<<8 | int(b)
		}
		if n < 0x80 {
			return element{}, fmt.Errorf("%w: %s: long form length below 128", ErrParse, what)
		}
		hdr += count
	}
	if n > len(in)-hdr {
		return element{}, fmt.Errorf("%w: %s: length runs past its container", ErrParse, what)
	}
	r.rest = in[hdr+n:]
	return element{tag: tag, content: in[hdr : hdr+n], full: in[:hdr+n]}, nil
}

// read reads the next element and requires its identifier octet to be tag.
func (r *reader) read(tag byte, what string) (element, error) {
	e, err := r.next(what)
	if err != nil {
		return element{}, err
	}
	if e.tag != tag {
		return element{}, fmt.Errorf("%w: %s: identifier 0x%02x, want 0x%02x", ErrParse, what,
			e.tag, tag)
	}
	return e, nil
}

// optional reads the next element when there is one and its identifier octet is tag.
func (r *reader) optional(tag byte, what string) (element, bool, error) {
	if r.empty() || r.rest[0] != tag {
		return element{}, false, nil
	}
	e, err := r.read(tag, what)
	return e, err == nil, err
}

// only reads the one element content holds: an explicit tag, an OCTET STRING, or a BIT STRING
// that wraps an encoding holds exactly one element of the identifier it requires and nothing
// after it.
func only(content []byte, tag byte, what string) (element, error) {
	r := reader{rest: content}
	e, err := r.read(tag, what)
	if err != nil {
		return element{}, err
	}
	if !r.empty() {
		return element{}, fmt.Errorf("%w: %s: followed by %d more octets", ErrParse, what,
			len(r.rest))
	}
	return e, nil
}

// wellFormed checks that data is a run of whole DER elements and that every constructed element
// within it, however deep, holds only whole DER elements in turn. It is applied to the whole token
// and to the TSTInfo, so a token is DER throughout, including the members a verifier never
// interprets. It walks with an explicit stack, so nesting depth costs no call stack.
func wellFormed(data []byte, what string) error {
	stack := [][]byte{data}
	for len(stack) > 0 {
		r := reader{rest: stack[len(stack)-1]}
		stack = stack[:len(stack)-1]
		for !r.empty() {
			e, err := r.next(what)
			if err != nil {
				return err
			}
			if e.tag&0x20 != 0 {
				stack = append(stack, e.content)
			}
		}
	}
	return nil
}

// derInteger checks an INTEGER's content: at least one octet, and the shortest two's complement
// form, so the first nine bits are never all zero or all one.
func derInteger(e element, what string) error {
	c := e.content
	if len(c) == 0 {
		return fmt.Errorf("%w: %s: empty INTEGER", ErrParse, what)
	}
	if len(c) > 1 && (c[0] == 0x00 && c[1]&0x80 == 0 || c[0] == 0xff && c[1]&0x80 != 0) {
		return fmt.Errorf("%w: %s: INTEGER not in its shortest form", ErrParse, what)
	}
	return nil
}

// derVersion checks a structure's version INTEGER, which must also fit a signed 64-bit integer.
func derVersion(e element, what string) error {
	if err := derInteger(e, what); err != nil {
		return err
	}
	if len(e.content) > 8 {
		return fmt.Errorf("%w: %s: INTEGER exceeds 64 bits", ErrParse, what)
	}
	return nil
}

// maxSerialOctets is the most content octets a TSTInfo serial number may have. RFC 3161 has a
// verifier accept a serial of up to 160 bits and sets no larger bound, and DER writes a positive
// 160-bit value in 21 octets, a zero octet ahead of its 20 so the top bit does not read as the
// sign. Without a bound a serial can be as long as the token, and writing one out in decimal takes
// time that grows faster than its length.
const maxSerialOctets = 21

// derSerial checks a TSTInfo serial number: a DER INTEGER of at most maxSerialOctets octets.
func derSerial(e element, what string) error {
	if err := derInteger(e, what); err != nil {
		return err
	}
	if len(e.content) > maxSerialOctets {
		return fmt.Errorf("%w: %s: INTEGER longer than %d octets", ErrParse, what, maxSerialOctets)
	}
	return nil
}

// derBigInt reads an INTEGER's checked content as a signed value.
func derBigInt(content []byte) *big.Int {
	v := new(big.Int).SetBytes(content)
	if len(content) > 0 && content[0]&0x80 != 0 {
		v.Sub(v, new(big.Int).Lsh(big.NewInt(1), uint(8*len(content))))
	}
	return v
}

// maxSubidentifier is the largest subidentifier an OBJECT IDENTIFIER a verifier reads may hold,
// 2^31-1, the bound Go's encoding/asn1 holds one to. Without a bound, one subidentifier can be
// as long as the token, and a verifier that writes it out in decimal either takes time
// that grows with the square of its length or, in Python, refuses to convert it at all.
const maxSubidentifier = 1<<31 - 1

// derOID checks an OBJECT IDENTIFIER's content: at least one octet, no subidentifier that
// starts with the padding octet 0x80 or exceeds 2^31-1, and a last octet that ends its
// subidentifier.
func derOID(e element, what string) error {
	c := e.content
	if len(c) == 0 {
		return fmt.Errorf("%w: %s: empty OBJECT IDENTIFIER", ErrParse, what)
	}
	var v uint64
	start := true
	for _, b := range c {
		if start && b == 0x80 {
			return fmt.Errorf("%w: %s: OBJECT IDENTIFIER subidentifier not in its shortest form",
				ErrParse, what)
		}
		v = v<<7 | uint64(b&0x7f)
		if v > maxSubidentifier {
			return fmt.Errorf("%w: %s: OBJECT IDENTIFIER subidentifier exceeds 2^31-1", ErrParse,
				what)
		}
		start = b&0x80 == 0
		if start {
			v = 0
		}
	}
	if !start {
		return fmt.Errorf("%w: %s: OBJECT IDENTIFIER ends inside a subidentifier", ErrParse, what)
	}
	return nil
}

// oidString writes the content of an OBJECT IDENTIFIER that derOID accepted in dotted form. Every
// subidentifier of such a content fits 31 bits, so each is written in time proportional to its
// length.
func oidString(content []byte) string {
	var arcs []string
	var v uint64
	first := true
	for _, b := range content {
		v = v<<7 | uint64(b&0x7f)
		if b&0x80 != 0 {
			continue
		}
		if first {
			switch {
			case v < 40:
				arcs = append(arcs, "0", strconv.FormatUint(v, 10))
			case v < 80:
				arcs = append(arcs, "1", strconv.FormatUint(v-40, 10))
			default:
				arcs = append(arcs, "2", strconv.FormatUint(v-80, 10))
			}
			first = false
		} else {
			arcs = append(arcs, strconv.FormatUint(v, 10))
		}
		v = 0
	}
	return strings.Join(arcs, ".")
}

// oidContent is the DER content of oid, the form an OBJECT IDENTIFIER read from a token is
// compared against.
func oidContent(oid asn1.ObjectIdentifier) []byte {
	der, err := asn1.Marshal(oid)
	if err != nil {
		panic(err)
	}
	return der[2:]
}

// oidKey is the DER content of the OBJECT IDENTIFIER with the given arcs as a string, the form a
// map keyed by identifier is looked up with.
func oidKey(arcs ...int) string {
	return string(oidContent(asn1.ObjectIdentifier(arcs)))
}
