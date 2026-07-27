// Package jcs implements RFC 8785 JSON canonicalization restricted to the LoomSeal number
// profile: numbers are integers with absolute value at most 2^53. Identical input always
// serializes to identical bytes, which is what signatures and digests are computed over.
package jcs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

// maxSafeInt is the largest integer magnitude an IEEE double represents exactly, 2^53.
const maxSafeInt = int64(1) << 53

// Canonicalize parses exactly one JSON value from raw and re-serializes it canonically.
func Canonicalize(raw []byte) ([]byte, error) {
	v, err := Parse(raw)
	if err != nil {
		return nil, err
	}
	return Serialize(v)
}

// Parse returns the value tree of raw as nil, bool, json.Number, string, []any, and
// map[string]any. It rejects duplicate object keys and trailing data.
func Parse(raw []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing data after value", ErrParse)
	}
	return v, nil
}

// Serialize writes a value tree canonically: object keys sorted by UTF-16 code units,
// minimal string escaping, integers in plain decimal.
func Serialize(v any) ([]byte, error) {
	var b bytes.Buffer
	if err := writeValue(&b, v); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// parseValue reads one value from the decoder.
func parseValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParse, err)
	}
	delim, ok := tok.(json.Delim)
	if !ok {
		return tok, nil
	}
	switch delim {
	case '{':
		return parseObject(dec)
	case '[':
		return parseArray(dec)
	default:
		return nil, fmt.Errorf("%w: unexpected %q", ErrParse, delim.String())
	}
}

// parseObject reads members until the closing brace, rejecting duplicate keys.
func parseObject(dec *json.Decoder) (map[string]any, error) {
	m := make(map[string]any)
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrParse, err)
		}
		key, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("%w: object key is not a string", ErrParse)
		}
		if _, dup := m[key]; dup {
			return nil, fmt.Errorf("%w: duplicate object key %q", ErrParse, key)
		}
		val, err := parseValue(dec)
		if err != nil {
			return nil, err
		}
		m[key] = val
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParse, err)
	}
	return m, nil
}

// parseArray reads elements until the closing bracket.
func parseArray(dec *json.Decoder) ([]any, error) {
	s := []any{}
	for dec.More() {
		val, err := parseValue(dec)
		if err != nil {
			return nil, err
		}
		s = append(s, val)
	}
	if _, err := dec.Token(); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrParse, err)
	}
	return s, nil
}

// writeValue serializes one value of the tree.
func writeValue(b *bytes.Buffer, v any) error {
	switch t := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		b.WriteString(strconv.FormatBool(t))
	case string:
		writeString(b, t)
	case json.Number:
		return writeNumber(b, t)
	case int:
		return writeInt(b, int64(t))
	case int64:
		return writeInt(b, t)
	case float64:
		if t != float64(int64(t)) {
			return fmt.Errorf("%w: non-integer number %v", ErrNumber, t)
		}
		return writeInt(b, int64(t))
	case []any:
		b.WriteByte('[')
		for i, e := range t {
			if i > 0 {
				b.WriteByte(',')
			}
			if err := writeValue(b, e); err != nil {
				return err
			}
		}
		b.WriteByte(']')
	case map[string]any:
		return writeObject(b, t)
	default:
		return fmt.Errorf("%w: unsupported type %T", ErrType, v)
	}
	return nil
}

// writeObject serializes members with keys ordered by their UTF-16 code units.
func writeObject(b *bytes.Buffer, m map[string]any) error {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		writeString(b, k)
		b.WriteByte(':')
		if err := writeValue(b, m[k]); err != nil {
			return err
		}
	}
	b.WriteByte('}')
	return nil
}

// writeInt serializes an integer, enforcing the 2^53 magnitude bound.
func writeInt(b *bytes.Buffer, n int64) error {
	if n > maxSafeInt || n < -maxSafeInt {
		return fmt.Errorf("%w: integer %d exceeds 2^53", ErrNumber, n)
	}
	b.WriteString(strconv.FormatInt(n, 10))
	return nil
}

// writeNumber serializes a parsed number literal. Only plain integer literals within the
// profile bound are accepted; fractions and exponents are invalid in a bundle.
func writeNumber(b *bytes.Buffer, n json.Number) error {
	s := string(n)
	if strings.ContainsAny(s, ".eE") {
		return fmt.Errorf("%w: non-integer literal %q", ErrNumber, s)
	}
	v, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: integer literal %q does not fit 64 bits", ErrNumber, s)
	}
	return writeInt(b, v)
}

// writeString serializes a string with RFC 8785 minimal escaping: shorthand escapes where
// they exist, \u00xx with lowercase hex for other control characters, everything else as
// literal UTF-8.
func writeString(b *bytes.Buffer, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		default:
			if r < 0x20 {
				fmt.Fprintf(b, `\u%04x`, r)
			} else {
				b.WriteRune(r)
			}
		}
	}
	b.WriteByte('"')
}

// utf16Less orders strings by their UTF-16 code units, which differs from rune order for
// characters above the basic multilingual plane and is what RFC 8785 requires.
func utf16Less(a, c string) bool {
	ua := utf16.Encode([]rune(a))
	uc := utf16.Encode([]rune(c))
	for i := 0; i < len(ua) && i < len(uc); i++ {
		if ua[i] != uc[i] {
			return ua[i] < uc[i]
		}
	}
	return len(ua) < len(uc)
}
