# Agent boundary demo

`agent-window.loomseal.json` is a sealed record of one AI agent session. Every tool call the
agent made at a declared boundary is a claim in an append-only chain, and two
`loomseal.span/1` beats attest how many entries were appended between them.

Verify it with either implementation:

```
loomseal verify agent-window.loomseal.json
python3 reference/loomverify.py agent-window.loomseal.json
```

Both report `signed, chained (full), anchored by reference, spanned`.

Regenerate it with:

```
go run examples/agent/generate.go
```

## What is real and what is not

The session is synthetic. No production system produced these tool calls, and the timestamps
describe a demonstration rather than a recorded hour.

The cryptography is real. The links recompute from the claim contents, the signature verifies
against the producer key, the span counts are checked rather than asserted, and the Go and
Python verifiers agree on the result independently. `HEAD` carries the chain head and is
committed to this repository, which is what the bundle's anchor references.

## Format support

The two gaps building this surfaced are now closed.

The subject enum in `schema/loomseal-bundle.schema.json` carries an `agent` member, so this bundle
names the attested execution boundary with type `agent` rather than borrowing `url`. Both verifiers
accept it.

`loomseal.agentrun/1` is in both verifiers' claim-type registry, so the bundle verifies with no
unknown-type note. The type is a registered part of the format, not a sketch, and a prospect
verifying this bundle gets a completely clean result.
