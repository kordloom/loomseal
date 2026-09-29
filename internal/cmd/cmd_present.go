package cmd

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/kordloom/loomseal/seal"
)

// runPresent wraps a bundle in a holder presentation bound to a verifier and challenge, revealing
// only the chosen fields. The bundle it reads is a producer-signed bundle; the holder reduces each
// claim's disclosures to the requested subset and signs the presentation with the holder key.
func runPresent(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("loomseal present", flag.ContinueOnError)
	fs.SetOutput(stderr)
	holderKey := fs.String("holder-key", "", "holder key file printed by keygen")
	audience := fs.String("audience", "", "the verifier this presentation is for")
	nonce := fs.String("nonce", "", "the challenge the verifier issued")
	reveal := fs.String("reveal", "", "comma-separated field names to disclose; others are withheld")
	atFlag := fs.String("at", "", "assembly time in RFC 3339, defaults to now")

	file := ""
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return CodeUsage
		}
		if fs.NArg() == 0 {
			break
		}
		if file != "" {
			fmt.Fprintln(stderr, "loomseal present: exactly one bundle file is required")
			return CodeUsage
		}
		file = fs.Arg(0)
		rest = fs.Args()[1:]
	}
	revealSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "reveal" {
			revealSet = true
		}
	})
	if file == "" || *holderKey == "" {
		fmt.Fprintln(stderr, "loomseal present: a bundle file and --holder-key are required")
		return CodeUsage
	}

	bundleRaw, err := readInput(file)
	if err != nil {
		fmt.Fprintf(stderr, "loomseal present: %v\n", err)
		return CodeUsage
	}
	priv, err := loadHolderSeed(*holderKey)
	if err != nil {
		fmt.Fprintf(stderr, "loomseal present: %v\n", err)
		return CodeUsage
	}
	// When --reveal is given, keep only those fields; omitting it presents the bundle's disclosures
	// as they are.
	if revealSet {
		keep := map[string]bool{}
		for _, name := range strings.Split(*reveal, ",") {
			if name = strings.TrimSpace(name); name != "" {
				keep[name] = true
			}
		}
		bundleRaw, err = reduceDisclosures(bundleRaw, keep)
		if err != nil {
			fmt.Fprintf(stderr, "loomseal present: %v\n", err)
			return CodeUsage
		}
	}
	at := *atFlag
	if at == "" {
		at = time.Now().UTC().Format(time.RFC3339)
	}
	pres, err := seal.Present(bundleRaw, priv, *audience, *nonce, at)
	if err != nil {
		fmt.Fprintf(stderr, "loomseal present: %v\n", err)
		return CodeUsage
	}
	fmt.Fprintln(stdout, string(pres))
	return CodeOK
}

// readInput reads a file, or stdin when the name is "-".
func readInput(file string) ([]byte, error) {
	if file == "-" {
		return io.ReadAll(os.Stdin)
	}
	return os.ReadFile(file)
}

// loadHolderSeed reads a keygen key file and returns the holder private key.
func loadHolderSeed(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var k struct {
		Seed string `json:"seed"`
	}
	if err := json.Unmarshal(raw, &k); err != nil {
		return nil, fmt.Errorf("holder key file: %w", err)
	}
	seed, err := base64.StdEncoding.DecodeString(k.Seed)
	if err != nil {
		return nil, fmt.Errorf("holder seed is not base64: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("holder seed is %d bytes, want %d", len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// reduceDisclosures keeps only the named disclosures on each claim, so a holder reveals a chosen
// subset. Claims and other members are untouched; a claim left with no disclosures drops the member.
func reduceDisclosures(bundleRaw []byte, keep map[string]bool) ([]byte, error) {
	var m map[string]any
	if err := json.Unmarshal(bundleRaw, &m); err != nil {
		return nil, fmt.Errorf("bundle: %w", err)
	}
	claims, ok := m["claims"].([]any)
	if !ok {
		return bundleRaw, nil
	}
	for _, c := range claims {
		claim, ok := c.(map[string]any)
		if !ok {
			continue
		}
		disc, ok := claim["disclosures"].([]any)
		if !ok {
			continue
		}
		var kept []any
		for _, d := range disc {
			dm, ok := d.(map[string]any)
			if !ok {
				continue
			}
			if name, _ := dm["name"].(string); keep[name] {
				kept = append(kept, d)
			}
		}
		if len(kept) == 0 {
			delete(claim, "disclosures")
		} else {
			claim["disclosures"] = kept
		}
	}
	return json.Marshal(m)
}
