# LoomSeal FAQ

Short answers to the questions that matter. The specification is [FORMAT.md](../FORMAT.md);
nothing here overrides it.

## Why does LoomSeal exist?

Because generating convincing artifacts became free. Screenshots, logs, dashboards, and
compliance documents can all be produced or edited in seconds, which means none of them are
evidence anymore. When anything can be fabricated, the scarce and valuable thing is a claim a
stranger can check. LoomSeal is the format for such claims: one file that carries what
happened, the digests of the evidence behind it, its position in an append-only chain, the
external anchors that fix that chain in time, and a signature. The verifier checks all of it
offline, with no account and no trust in the producer or in KordLoom.

## What is the value if I operate a system?

You stop asking people to believe you. When an auditor, a security reviewer, a customer, or a
regulator asks how you know your controls ran, you send a file they can verify in seconds
instead of a deck they have to take on faith. And because chained history cannot be created
retroactively, every quiet month you record is evidence a competitor who starts later can
never manufacture. The record compounds.

## What is the value if I am the one reviewing?

You verify instead of trusting. No vendor portal, no screenshots, no phone calls to confirm a
PDF. One command, offline, and the math either holds or it does not. If the bundle was
altered, verification fails loudly and names the break.

## Why should I trust the verifier?

You should not have to, which is the design. The verifier is small, Apache-2.0, and built on
the Go standard library alone, so every line that touches a verification decision is in this
repository and readable in an afternoon. If you would rather not run our binary, build it from
source, or implement your own verifier from FORMAT.md and the schema; the format belongs to
anyone who implements it.

## Why is the format open if KordLoom is a business?

A sealed format cannot be a standard, and proof that only its vendor can check is not proof.
KordLoom's products are the business; the proof language they speak is public on purpose. The
license tiers are deliberate: the products carry their own licenses, while the format, schema,
and verifier are Apache-2.0 so adopting them requires no negotiation and carries an express
patent grant. The LoomSeal name and mark are trademarks, not part of the code license.

## What cryptography does it use, and why so plain?

SHA-256 for content digests, HMAC-SHA256 for keyed chains, ed25519 for signatures. Boring on
purpose: every primitive is decades-tested, standardized, and available in every mainstream
language. There is no blockchain, no token, no consensus, and no network dependency. The
security model is a private ledger with a maker's mark, not a coin.

## How is it kept secure?

The chain key is the secret that prevents forgery, it is generated on the producing install,
and it never travels: not in bundles, not to KordLoom, not anywhere. Signing keys likewise
stay on the install; only the public key travels, and relying parties can pin its fingerprint
from the operator's trust page. Verification is offline by design, so there is no service to
compromise between the evidence and the person checking it.

## What about quantum computers?

The chains and digests rest on SHA-256, which known quantum algorithms do not meaningfully
weaken, so the part of LoomSeal that carries history is built on the quantum-resilient half of
cryptography. The ed25519 signature is the component a large future quantum computer would
break, and the format is ready for that: signatures carry an algorithm field, so a
NIST-standardized post-quantum signature can be added beside ed25519 without a new envelope.
Anchoring already bounds the damage, because a signature forged years from now cannot rewrite
history whose heads were published outside the producer's control before such forgery was
possible. A quantum computer does not un-publish a hash.

## What does verification prove, exactly?

Three things: the producer holding the signing key assembled these exact claims; the claims
sit in an append-only order that has not been reordered, rewritten, or trimmed since its heads
were anchored; and any artifacts supplied match their recorded digests. The conformance
wording is exactly three words: signed, chained, anchored.

## What does it deliberately not prove?

That the producer observed the world honestly at capture time. A chain fixes the record, not
the character of the recorder. A dishonest producer can record fiction; what it cannot do is
rewrite that fiction later without breaking the chain, or backdate a history it never kept.
Keyed chains verify structurally for third parties and fully for the key holder, and in the
current verifier anchor proofs are carried but not validated, so relying parties confirm
anchor references out of band. Stating this boundary plainly is a feature: proof that
overclaims is just marketing.

## Why not a blockchain?

Because the property needed is tamper evidence, not distributed consensus. An append-only
keyed chain plus anchors published where the producer cannot rewrite them, a timestamp
authority, a public repository, a transparency log, delivers that property without gas fees,
without volatility, and without asking an auditor to believe in a coin. Anchoring borrows
exactly one idea from that world, publishing a commitment where you cannot take it back, and
leaves the rest.

## What happens if KordLoom disappears?

Nothing happens to your proof. Bundles verify offline forever, the spec and schema and
verifier are Apache-2.0 and forkable, and no verification step ever contacts KordLoom. Records
you anchored stay anchored, because the anchors live outside KordLoom too. A proof format you
could lose in a vendor's shutdown would not be worth adopting, so LoomSeal is built to outlive
its author.

## How do I emit bundles from my own software?

Import the [seal](../seal) package to sign bundles and compute generic chain links, follow the
bundle shape in [FORMAT.md](../FORMAT.md) and the schema, and register new claim types through
the registry in the spec. Producers own their payloads; the envelope, chain profiles, and
verification procedure stay common so one verifier checks everyone.
