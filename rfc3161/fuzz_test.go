package rfc3161

import (
	"encoding/base64"
	"os"
	"strings"
	"testing"
)

// FuzzVerify pins that the timestamp token parser never panics on adversarial DER. The
// token travels inside a bundle from the presenting party, so its parser sees attacker
// bytes by design, and the September audit named this parser as read rather than fuzzed.
// This closes that. Seeded with the genuine token vector so mutation starts from a
// structure that reaches every branch of the ASN.1 walk.
func FuzzVerify(f *testing.F) {
	if b64, err := os.ReadFile("../testdata/vectors/rfc3161-token.b64"); err == nil {
		if token, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b64))); err == nil {
			f.Add(token, "0000000000000000000000000000000000000000000000000000000000000000")
		}
	}
	f.Add([]byte{0x30, 0x03, 0x02, 0x01, 0x01}, "00")
	f.Add([]byte{}, "")
	f.Fuzz(func(t *testing.T, token []byte, link string) {
		// Only the absence of a panic is asserted. A fuzzer-built token that verifies would
		// be a forged timestamp, but rejecting forgeries is the signature check's job and it
		// is pinned elsewhere; this test's one claim is that parsing hostile bytes is safe.
		_, _ = Verify(token, link)
	})
}
