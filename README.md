<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/loomseal-banner-dark.png">
    <img src="assets/loomseal-banner.png" alt="LoomSeal woven LS mark" width="820">
  </picture>
</p>

# LoomSeal

**The KordLoom proof format, and the free verifier anyone can run.**

KordLoom products record what they did in keyed, append-only hash chains. LoomSeal is how that
proof travels: one JSON bundle carrying claims, evidence digests, chain coordinates, external
anchors, and an ed25519 producer signature. The `loomseal` verifier checks a bundle offline,
without an account, without a server, and without trusting KordLoom.

- SwitchTender proves what you run and exports LoomSeal.
- Dormouse proves what you watch and exports LoomSeal.
- Anyone on earth verifies the file for free.

One binary. One file. Provable.

## Install

    go install github.com/kordloom/loomseal@latest

Or build from source:

    go build -o loomseal .

The binary has no dependencies outside the Go standard library, so every line that touches a
verification decision is in this repository.

## Verify a bundle

    loomseal verify evidence.loomseal.json

Typical output:

    bundle     lsb_9c41d0a2b7e3 from dormouse 0.4.0
    subject    url https://vendor.example.com/legal/subprocessors
    signature  ok, key sha256:2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae
    chain      dormouse-audit-chain-v2, structural, 3 claims, head matched true
    anchors    1 matched by coordinates, 1 proofs carried, not validated in this version
    evidence   1 verified, 0 missing, 0 referenced only
    VERIFIED   signed, chained (structural), anchored by reference

Flags: `--evidence <dir>` checks artifact digests against files you were given,
`--fingerprint sha256:<hex>` pins the producer key to the fingerprint published on the
operator's trust page, `--json` emits the report for machines, `--pretty` indents it. Exit
codes: 0 verified, 1 verification failed, 2 usage or read error.

## What verification proves

Anyone can generate a convincing screenshot now. A log can be edited, a dashboard can lie, and
a compliance PDF can be written five minutes before the meeting. When every artifact is cheap
to fabricate, the only evidence worth sending is evidence a stranger can check without
trusting the sender. That is what a bundle is.

Run `loomseal verify` on one file and, seconds later, offline, with no account and no trust in
KordLoom or the operator who sent it, you know three things:

- The producer holding the signing key assembled these exact claims. Flip one byte anywhere in
  the bundle and the signature fails, loudly, with the break named.
- The claims sit in an append-only chain that has not been reordered, rewritten, or trimmed
  since its heads were anchored outside the producer's reach. Anchored history cannot be
  manufactured after the fact, at any price, by anyone. Whoever has been recording, wins.
- Every artifact you were handed matches its recorded digest exactly: the page as it stood,
  the run as it happened, the approval as it was given.

Send that file to an auditor, a security reviewer, a customer, a regulator, or another
machine. None of them has to believe a word you say. That is the point.

And because proof that overclaims is just marketing, the verifier states its boundary plainly:
it cannot prove the recorder observed the world honestly at capture time. A chain fixes the
record, not the character of the recorder. Keyed chains verify structurally here and fully for
the key holder, and anchor proofs are carried but not yet validated by this version, so
confirm anchor refs out of band. The full discipline is in [FORMAT.md](FORMAT.md), which is
the specification, and the conformance wording is exactly three words: signed, chained,
anchored. No other adjectives, on purpose.

## Emit the format

Producers use the [seal](seal) package to sign bundles and compute generic chain links:

    import "github.com/kordloom/loomseal/seal"

    signed, err := seal.SignBundle(raw, privateKey)

The format document is [FORMAT.md](FORMAT.md); the schema is
[schema/loomseal-bundle.schema.json](schema/loomseal-bundle.schema.json). New claim types enter
through the registry in the spec.

## License

Apache-2.0. The format, the schema, and this verifier are open so the proof can be checked by
people who have no reason to trust the producer. KordLoom's products are licensed separately.
