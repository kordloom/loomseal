//go:build ignore

// Command generate rebuilds examples/audit.loomseal.json from a fixed key and fixed content, so
// the checked-in example always links and signs under the current format rules. Run from the
// repository root with `go run examples/generate.go`. The example drifted once: a committed-content
// rule change relinked the world while the example kept its old links, and CI caught the exact
// verdict flip a hand-built artifact invites.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/kordloom/loomseal/seal"
)

func main() {
	// A documented throwaway key: thirty-one bytes of 0x42 and one of 0x24.
	seedBytes := make([]byte, ed25519.SeedSize)
	for i := range seedBytes {
		seedBytes[i] = 0x42
	}
	seedBytes[ed25519.SeedSize-1] = 0x24
	priv := ed25519.NewKeyFromSeed(seedBytes)
	pub := priv.Public().(ed25519.PublicKey)

	snap, err := os.ReadFile("examples/evidence/snapshot.html")
	if err != nil {
		panic(err)
	}
	snapDigest := sha256.Sum256(snap)

	install := "in_demo"
	claim1 := map[string]any{
		"type": "switchtender.audit/1",
		"at":   "2026-07-27T15:00:00Z",
		"payload": map[string]any{
			"actor": "release-token", "method": "POST", "path": "/api/runs",
		},
		"evidence": []any{map[string]any{
			"role": "snapshot", "media_type": "text/html",
			"digest":   "sha256:" + hex.EncodeToString(snapDigest[:]),
			"present":  true,
			"location": "evidence/snapshot.html",
		}},
	}
	claim2 := map[string]any{
		"type": "switchtender.audit/1",
		"at":   "2026-07-27T15:00:00Z",
		"payload": map[string]any{
			"actor": "release-token", "method": "POST", "path": "/api/runs/1/approve",
		},
	}

	link1, err := seal.LinkV1(nil, install, 1, "", seal.ClaimContent(claim1))
	if err != nil {
		panic(err)
	}
	claim1["chain"] = map[string]any{"seq": int64(1), "prev": "", "link": link1}
	link2, err := seal.LinkV1(nil, install, 2, link1, seal.ClaimContent(claim2))
	if err != nil {
		panic(err)
	}
	claim2["chain"] = map[string]any{"seq": int64(2), "prev": link1, "link": link2}

	doc := map[string]any{
		"loomseal":   "0.1",
		"bundle_id":  "lsb_example_0001",
		"created_at": "2026-07-27T15:04:05Z",
		"producer": map[string]any{
			"product": "switchtender", "product_version": "1.34.0",
			"install_id": install,
			"public_key": base64.StdEncoding.EncodeToString(pub),
			"key_id":     seal.KeyID(pub),
		},
		"subject": map[string]any{"type": "run", "id": "run_example"},
		"chain": map[string]any{
			"profile": "loomseal-chain-v1", "keyed": false,
			"params": map[string]any{"install_id": install},
			"head":   map[string]any{"seq": int64(2), "link": link2},
		},
		"claims": []any{claim1, claim2},
		"anchors": []any{map[string]any{
			"type": "git", "seq": int64(2), "link": link2,
			"at":  "2026-07-27T15:00:00Z",
			"ref": "https://github.com/kordloom/loomseal/commit/example",
		}},
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		panic(err)
	}
	signed, err := seal.SignBundle(raw, priv)
	if err != nil {
		panic(err)
	}
	var pretty any
	if err := json.Unmarshal(signed, &pretty); err != nil {
		panic(err)
	}
	out, err := json.MarshalIndent(pretty, "", "  ")
	if err != nil {
		panic(err)
	}
	if err := os.WriteFile("examples/audit.loomseal.json", append(out, '\n'), 0o600); err != nil {
		panic(err)
	}
	fmt.Println("wrote examples/audit.loomseal.json")
}
