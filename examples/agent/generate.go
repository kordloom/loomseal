//go:build ignore

// Command generate writes the LoomWitness demo bundle: a sealed record of one AI agent session,
// where every tool call the agent made is a claim in an append-only chain and loomseal.span/1
// beats attest that no call was dropped between them. Run it from the repository root with
// `go run examples/agent/generate.go`. The output is deterministic, so the checked-in bundle
// changes only when this generator does.
//
// The bundle is a demonstration of the format, not a recording of a production system. The
// session below is synthetic. What is real is the cryptography: the links recompute, the
// signature verifies, and the anchor is a commit in this repository that nobody can rewrite.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/kordloom/loomseal/seal"
)

const (
	// out is where the demo bundle is written, relative to the repository root.
	out = "examples/agent/agent-window.loomseal.json"
	// installID is the producing installation, the LoomWitness gateway instance.
	installID = "in_witness_demo"
	// boundary names the attested execution boundary the gateway sits on.
	boundary = "mcp://demo-agent-tools"
	// cadence is the declared span beat interval in whole seconds.
	cadence = 60
	// profile is the chain profile the bundle uses.
	profile = "loomseal-chain-v1"
	// agentType is the claim type for one witnessed tool call.
	agentType = "loomseal.agentrun/1"
	// spanType is the spec-owned population attestation claim type.
	spanType = "loomseal.span/1"
	// anchorRef is the commit that publishes this chain's head outside the producer's reach.
	// It is filled in by the second run, after the head is committed. See README.md.
	anchorRef = "https://github.com/kordloom/loomseal/commits/main/examples/agent/HEAD"
)

// start is the session's first beat time. Later times are offsets from it.
var start = time.Date(2026, 8, 4, 17, 0, 0, 0, time.UTC)

// call is one tool invocation the gateway witnessed at the boundary.
type call struct {
	// Offset is seconds after start.
	Offset int
	// Tool is the tool name as it crossed the boundary.
	Tool string
	// Args is the invocation's arguments. A deployment may carry digests instead.
	Args map[string]any
	// Result summarizes what the tool returned.
	Result string
	// Outcome is ok or error.
	Outcome string
}

// session is the synthetic agent run the demo bundle records: a support agent that looks up a
// customer, reads an order, refunds it, and writes a note. The refund is the reason anyone
// would ever ask what this agent did.
var session = []call{
	{5, "get_customer", map[string]any{"email": "r.okonkwo@example.com"}, "1 record", "ok"},
	{9, "lookup_order", map[string]any{"order_id": "ord_88213"}, "1 record, status shipped", "ok"},
	{14, "get_policy", map[string]any{"name": "refund_window_days"}, "30", "ok"},
	{21, "issue_refund", map[string]any{"order_id": "ord_88213", "amount_cents": 4995, "reason": "damaged_in_transit"}, "refund rf_20194 accepted", "ok"},
	{26, "send_email", map[string]any{"template": "refund_confirmation", "order_id": "ord_88213"}, "queued", "ok"},
	{31, "write_note", map[string]any{"order_id": "ord_88213", "note": "Refunded per policy. Photo evidence on file."}, "note_5512", "ok"},
}

// beats places span attestations after the given call counts, each declaring how many chain
// entries were appended since the previous beat.
var beats = []struct {
	// After is the number of tool calls emitted before this beat.
	After int
	// Offset is seconds after start.
	Offset int
}{
	{3, 60},
	{6, 120},
}

func main() {
	// A dedicated demo key. The seed is fixed so the bundle is reproducible, which also means
	// this key signs demonstrations and nothing else.
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(0x40 + i)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	claims := buildClaims()
	m := map[string]any{
		"loomseal":   "0.1",
		"bundle_id":  "lsb_witness_demo_0001",
		"created_at": iso(start.Add(130 * time.Second)),
		"producer": map[string]any{
			"product":         "loomwitness-demo",
			"product_version": "0.1.0",
			"install_id":      installID,
			"public_key":      base64.StdEncoding.EncodeToString(pub),
			"key_id":          seal.KeyID(pub),
		},
		// The subject is the attested boundary itself, which is what the claims are about and
		// what the coverage statement is scoped to. The schema's subject enum has no agent
		// member; a shipping LoomWitness would propose one.
		"subject":    map[string]any{"type": "url", "id": boundary},
		"claims":     claims,
		"signatures": []any{},
	}
	relink(m)
	addAnchor(m)

	raw, err := json.Marshal(m)
	if err != nil {
		fail(err)
	}
	signed, err := seal.SignBundle(raw, priv)
	if err != nil {
		fail(err)
	}
	if err := os.WriteFile(out, signed, 0o644); err != nil {
		fail(err)
	}

	head := m["chain"].(map[string]any)["head"].(map[string]any)
	if err := os.WriteFile("examples/agent/HEAD", []byte(head["link"].(string)+"\n"), 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("wrote %s\nhead %s seq %d\nkey  %s\n", out, head["link"], head["seq"], seal.KeyID(pub))
}

// buildClaims interleaves the witnessed tool calls with the span beats that attest to their
// count, in the order they were appended to the chain.
func buildClaims() []any {
	var claims []any
	emitted := 0
	beatIdx := 0
	prevBeatEntries := 0
	for i, c := range session {
		claims = append(claims, map[string]any{
			"type": agentType,
			"at":   iso(start.Add(time.Duration(c.Offset) * time.Second)),
			"payload": map[string]any{
				"boundary":      boundary,
				"session":       "sess_7f31c8",
				"model":         "claude-opus-4-8",
				"tool":          c.Tool,
				"args":          c.Args,
				"result_digest": digest(c.Result),
				"outcome":       c.Outcome,
			},
		})
		emitted++
		// A beat counts the chain entries appended since the previous beat, not counting itself.
		if beatIdx < len(beats) && i+1 == beats[beatIdx].After {
			total := len(claims) - prevBeatEntries
			claims = append(claims, map[string]any{
				"type": spanType,
				"at":   iso(start.Add(time.Duration(beats[beatIdx].Offset) * time.Second)),
				"payload": map[string]any{
					"stream":    "chain",
					"cadence_s": cadence,
					"beat":      beatIdx + 1,
					"count":     total,
				},
			})
			prevBeatEntries = len(claims)
			beatIdx++
		}
	}
	return claims
}

// relink computes every chain link from the claim contents and sets the head.
func relink(m map[string]any) {
	claims := m["claims"].([]any)
	prev := ""
	var lastLink string
	var lastSeq int64
	for i, c := range claims {
		claim := c.(map[string]any)
		seq := int64(i + 1)
		link, err := seal.LinkV1(nil, installID, seq, prev, stripChain(claim))
		if err != nil {
			fail(err)
		}
		claim["chain"] = map[string]any{"seq": seq, "prev": prev, "link": link}
		prev = link
		lastLink = link
		lastSeq = seq
	}
	m["chain"] = map[string]any{
		"profile": profile,
		"keyed":   false,
		"params":  map[string]any{"install_id": installID},
		"head":    map[string]any{"seq": lastSeq, "link": lastLink},
	}
}

// addAnchor fixes the chain head to a commit in a public repository, which is what makes the
// history impossible to backfill. The link and seq must match an entry in the chain.
func addAnchor(m map[string]any) {
	head := m["chain"].(map[string]any)["head"].(map[string]any)
	m["anchors"] = []any{map[string]any{
		"type": "git",
		"ref":  anchorRef,
		"at":   iso(start.Add(180 * time.Second)),
		"seq":  head["seq"],
		"link": head["link"],
	}}
}

// stripChain returns the claim without its chain member, the value a link is computed over.
func stripChain(claim map[string]any) map[string]any {
	c := make(map[string]any, len(claim))
	for k, v := range claim {
		if k == "chain" {
			continue
		}
		c[k] = v
	}
	return c
}

// digest returns the sha256: digest of a string, the form the format uses for evidence.
func digest(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// iso formats a time the way the format stores claim times.
func iso(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

// fail prints an error and exits non-zero.
func fail(err error) {
	fmt.Fprintln(os.Stderr, "generate:", err)
	os.Exit(1)
}
