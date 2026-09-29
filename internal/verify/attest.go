package verify

import (
	"crypto/ed25519"
	"encoding/base64"
	"time"

	"github.com/kordloom/loomseal/internal/bundle"
	"github.com/kordloom/loomseal/jcs"
)

// checkAttestations verifies counter-signatures a party other than the producer added to a claim. An
// attestation signs the RFC 8785 canonical object of the claim's link and the signer's role, so it
// binds one specific claim and what the signer says they are. It turns a self-asserted claim into one
// a second party vouches for, which is what makes a complete, unaltered record also credible rather
// than merely intact.
//
// Attestations are added after the producer signs and are excluded from the link, the leaf, and the
// producer signature, so a counterparty attests without the producer re-signing and a verifier reports
// the counter-signatures as a measurement, never as something the producer asserted.
// checkHeadAttestations verifies counter-signatures over the chain head itself: a witness or
// custodian vouching that it saw this head, attached after the producer signed. The preimage binds
// the head's link, its seq, and the role under its own domain tag, so a head attestation can never
// be replayed as a claim attestation or against a different head, and re-anchoring custody has a
// place to live on an already-signed bundle.
func (r *Report) checkHeadAttestations(b *bundle.Bundle) {
	if len(b.Attestations) == 0 {
		return
	}
	r.HeadAttestationsPresent = true
	if b.Chain == nil {
		r.problem("bundle carries head attestations but no chain head to vouch for")
		return
	}
	for j := range b.Attestations {
		a := b.Attestations[j]
		if a.Alg != "ed25519" {
			r.problem("head attestation %d alg %q, want ed25519", j, a.Alg)
			continue
		}
		pub, err := base64.StdEncoding.DecodeString(a.PublicKey)
		if err != nil || len(pub) != ed25519.PublicKeySize {
			r.problem("head attestation %d public_key is not a 32 byte ed25519 key", j)
			continue
		}
		if bundle.KeyID(pub) != a.KeyID {
			r.problem("head attestation %d key_id does not match its public key", j)
			continue
		}
		if a.Role == "" {
			r.problem("head attestation %d role is empty", j)
			continue
		}
		sig, err := base64.StdEncoding.DecodeString(a.Sig)
		if err != nil {
			r.problem("head attestation %d sig is not base64", j)
			continue
		}
		obj := map[string]any{"loomseal": "head-attestation/1", "link": b.Chain.Head.Link,
			"seq": b.Chain.Head.Seq, "role": a.Role}
		if a.At != "" {
			if _, err := time.Parse(time.RFC3339, a.At); err != nil {
				r.problem("head attestation %d at: %v", j, err)
				continue
			}
			obj["at"] = a.At
		}
		preimage, err := jcs.Serialize(obj)
		if err != nil {
			r.problem("head attestation %d: %v", j, err)
			continue
		}
		if !ed25519.Verify(pub, preimage, sig) {
			r.problem("head attestation %d by %s does not verify over the chain head", j, a.KeyID)
			continue
		}
		r.HeadAttestationsVerified++
		entry := a.Role + " " + a.KeyID
		if a.At != "" {
			entry += " at " + a.At
		}
		r.HeadAttestors = append(r.HeadAttestors, entry)
	}
}

func (r *Report) checkAttestations(b *bundle.Bundle) {
	for i := range b.Claims {
		c := &b.Claims[i]
		if len(c.Attestations) == 0 {
			continue
		}
		r.AttestationsPresent = true
		if c.Chain == nil {
			r.problem("claim %d carries an attestation but has no chain link to vouch for", i)
			continue
		}
		for j := range c.Attestations {
			a := c.Attestations[j]
			if a.Alg != "ed25519" {
				r.problem("claim %d attestation %d alg %q, want ed25519", i, j, a.Alg)
				continue
			}
			pub, err := base64.StdEncoding.DecodeString(a.PublicKey)
			if err != nil || len(pub) != ed25519.PublicKeySize {
				r.problem("claim %d attestation %d public_key is not a 32 byte ed25519 key", i, j)
				continue
			}
			if bundle.KeyID(pub) != a.KeyID {
				r.problem("claim %d attestation %d key_id does not match its public key", i, j)
				continue
			}
			if a.Role == "" {
				r.problem("claim %d attestation %d role is empty", i, j)
				continue
			}
			sig, err := base64.StdEncoding.DecodeString(a.Sig)
			if err != nil {
				r.problem("claim %d attestation %d sig is not base64", i, j)
				continue
			}
			// The domain tag keeps this signature meaningless anywhere else a {link, role}
			// shaped object might be signed. When the attestation carries at, the time sits
			// inside the signed bytes, so a sign-off time cannot be edited after the fact.
			obj := map[string]any{"loomseal": "attestation/1", "link": c.Chain.Link, "role": a.Role}
			if a.At != "" {
				if _, err := time.Parse(time.RFC3339, a.At); err != nil {
					r.problem("claim %d attestation %d at: %v", i, j, err)
					continue
				}
				obj["at"] = a.At
			}
			preimage, err := jcs.Serialize(obj)
			if err != nil {
				r.problem("claim %d attestation %d: %v", i, j, err)
				continue
			}
			if !ed25519.Verify(pub, preimage, sig) {
				r.problem("claim %d attestation %d by %s does not verify over the claim link", i, j,
					a.KeyID)
				continue
			}
			r.AttestationsVerified++
			entry := a.Role + " " + a.KeyID
			if a.At != "" {
				entry += " at " + a.At
			}
			r.Attestors = append(r.Attestors, entry)
		}
	}
}
