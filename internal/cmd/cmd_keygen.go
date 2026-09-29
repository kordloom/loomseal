package cmd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"io"

	"github.com/kordloom/loomseal/internal/jsonutil"
	"github.com/kordloom/loomseal/seal"
)

// runKeygen prints a new ed25519 holder key as JSON: the secret seed, the public key, and the key id.
// The seed is what a holder feeds to `present`; it is secret and belongs in a private file.
func runKeygen(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("loomseal keygen", flag.ContinueOnError)
	fs.SetOutput(stderr)
	pretty := fs.Bool("pretty", false, "indent the JSON")
	if err := fs.Parse(args); err != nil {
		return CodeUsage
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		fmt.Fprintf(stderr, "loomseal keygen: %v\n", err)
		return CodeUsage
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub, _ := priv.Public().(ed25519.PublicKey)
	key := map[string]any{
		"seed":       base64.StdEncoding.EncodeToString(seed),
		"public_key": base64.StdEncoding.EncodeToString(pub),
		"key_id":     seal.KeyID(pub),
		"note":       "the seed is secret; keep this file private",
	}
	out, err := jsonutil.Marshal(key, *pretty)
	if err != nil {
		fmt.Fprintf(stderr, "loomseal keygen: %v\n", err)
		return CodeUsage
	}
	fmt.Fprintln(stdout, string(out))
	return CodeOK
}
