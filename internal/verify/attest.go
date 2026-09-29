package verify

import (
	"crypto/ed25519"
	"encoding/base64"

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
			preimage, err := jcs.Serialize(map[string]any{"link": c.Chain.Link, "role": a.Role})
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
			r.Attestors = append(r.Attestors, a.Role+" "+a.KeyID)
		}
	}
}
