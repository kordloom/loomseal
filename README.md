<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/loomseal-banner-dark.png">
    <img src="assets/loomseal-banner.png" alt="LoomSeal woven LS mark" width="820">
  </picture>
</p>

# LoomSeal

**Proof, not promises.**

An open format for evidence somebody else can check.

You already have a record of what your software did. The trouble is that the person who needs to
believe it, an auditor, a customer, a security reviewer, a regulator, cannot, because you own the
system that record lives in. Your log is worth exactly as much as their trust in you.

LoomSeal turns that record into one JSON file: the claims, the digests of the evidence behind
them, their position in an append-only hash chain, the anchors that fix that chain in time, and
an ed25519 signature from the machine that produced it. You send the file. They run a verifier
and get a yes or a no in seconds, offline. You are not in the loop, which is the point.

## Free, and structurally so

This is not a trial, an open-core tease, or a format with a paid tier waiting behind it.

- **Apache-2.0.** Adopt it, fork it, re-implement it, ship it in a competing product. No
  negotiation, no license call, no per-seat price, no permission.
- **Nothing to charge for.** LoomSeal is a file format and a checker. There is no server to rent
  and no seat to meter, which is why it is free permanently rather than free for now.
- **Verification never phones home.** No account, no server, no network, no telemetry. The
  verifier works on a machine that has never heard of KordLoom and never will.
- **Auditable end to end.** The binary has no dependencies outside the Go standard library, so
  every line that touches a verification decision is in this repository and readable in an
  afternoon. A tool that checks evidence should not itself have to be taken on faith.
- **Two independent implementations already.** The Go verifier here and a separate Python one in
  `reference/`, cross-checked in CI against the same conformance vectors. A format with one
  implementation is a product. A format with two is a standard.

One binary. One file. Provable.

## Install

    go install github.com/kordloom/loomseal@latest

Or build from source:

    go build -o loomseal .

The binary has no dependencies outside the Go standard library, so every line that touches a
verification decision is in this repository.

## Verify a bundle

    loomseal verify examples/audit.loomseal.json --evidence examples/evidence

The output, reproducible from this repository right now:

    bundle     lsb_example_0001 from loomseal-demo 0.1.0
    subject    fleet demo-yard
    signature  ok, key sha256:f8840a25992b58b823321187e1c44d36ee1a748023034a46d26ea93419edaf07
    chain      loomseal-chain-v1, full, 2 claims, head matched true
    anchors    1 matched by coordinates, 0 proofs carried, not validated in this version
    evidence   1 verified, 0 missing, 0 referenced only
    VERIFIED   signed, chained (full), anchored by reference

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

KordLoom uses this on its own products for a reason that is a little uncomfortable.
SwitchTender's promise is that it proves every change. Without a bundle, that promise is a
sentence on a website, and you would simply have to believe us that the audit trail behind it
is honest. Building on `do not take our word for it` and then asking you to take our word for
it is not a position we can defend, so SwitchTender's audit export is being rebuilt as a
LoomSeal bundle.

And because proof that overclaims is just marketing, the verifier states its boundary plainly:
it cannot prove the recorder observed the world honestly at capture time. A chain fixes the
record, not the character of the recorder. Keyed chains verify structurally here and fully for
the key holder, and anchor proofs are carried but not yet validated by this version, so
confirm anchor refs out of band. The full discipline is in [FORMAT.md](FORMAT.md), which is
the specification, and the conformance wording is exactly three words: signed, chained,
anchored. No other adjectives, on purpose.

Why it exists, what it is worth, the cryptography, quantum computers, and what happens if
KordLoom disappears: [docs/FAQ.md](docs/FAQ.md).

## Emit the format

Producers use the [seal](seal) package to sign bundles and compute generic chain links:

    import "github.com/kordloom/loomseal/seal"

    signed, err := seal.SignBundle(raw, privateKey)

The format document is [FORMAT.md](FORMAT.md); the schema is
[schema/loomseal-bundle.schema.json](schema/loomseal-bundle.schema.json). New claim types enter
through the registry in the spec.

## Status

Format v0.1 draft. The format, the schema, the verifier, and the seal package are complete,
tested, and exercised by the example bundle in this repository. No product emits LoomSeal from a
live system yet, so the example bundle and the seal package are the reference producers.

## License

Apache-2.0. The format, the schema, and this verifier are open so the proof can be checked by
people who have no reason to trust the producer. KordLoom's products are licensed separately.
