# Discovery target list

Companies whose AI agents take consequential actions. For asking one question:
*"When an enterprise customer's security review asks how you prove what your agent did
in their environment, what happens today?"*

Compiled 2026-08-04. Product claims quoted from company sites. Founder names and funding
are the weakest column; verify on LinkedIn before sending. Not for publishing.

## Contact first

| Company | What the agent does | Contact | Why they feel it |
|---|---|---|---|
| Lorikeet | Rent payments, 40-step refund flows through customer Stripe and internal APIs | Steve Hind (ex-Stripe), Jamie Hall — both public LinkedIn | Moves real money, no SOC 2 shown, fintech and healthtech customers |
| Sedai | Autopilot makes unattended production changes, no human approval | Suresh Mathew CEO, Benji Thomas CTO (both ex-PayPal) | Capital One and Experian in production. Public answer is an assertion, not evidence |
| NeuBird | Executes rollbacks, restarts, scaling with "full audit trail" | Goutham Rao CEO, Vinod Jayaraman CTO — LinkedIn on their about page | Commonwealth Bank. Already markets audit trail, so they were asked |
| Tennr | Submits prior authorizations, auto-updates charts and orders | Trey Holterman CEO, Tyler Johnson CTO, Ashley Ferguson VP Legal/Compliance | HIPAA audits ask which agent changed the order |
| Gradient Labs | Freezes cards, files chargebacks | Dimitri Masin CEO (Monzo #20), Neal Lathia CTO | FCA-regulated fintechs, already cites EU AI Act |
| Cleric | AI SRE, "read-only by default, write access when you're ready" | Shahram Anver CEO, Willem Pienaar CTO (created Feast, publicly active) | That read-to-write transition IS the moment the review bites |
| Maven AGI | Multi-step actions across Zendesk/Salesforce | Jonathan Corbin, Sami Shalabi, Eugene Mann — all public X handles | Best reachability on the list. ISO 42001 + HIPAA + PCI |

## Also strong

| Company | What the agent does | Contact |
|---|---|---|
| ZeroPath | Merges AI security patches into customer repos | Raphael Karger CTO. Regulated fintech customers, no SOC 2 yet |
| Prophet Security | Autonomous threat containment | Kamal Shah CEO, Vibhav Sreekanti CTO. Citi + Amex Ventures |
| Radiant Security | One-click remediation into customer stack | Shahar Ben-Hador CEO, Barry Shteiman CTO (LinkedIn) |
| Parcha | KYB/AML decisions at regulated fintechs | AJ Asver CEO, Miguel Rios CTO (LinkedIn, ex-Brex) |
| Komodor | Autonomous K8s resolution, ships audit trail + SIEM | Ben Ofiri CEO, Itiel Shwartz CTO. $90M raised |
| Factory AI | Droids ship 7 deploys/week, air-gapped tier | Blackstone, Adyen, J.P. Morgan. Founders unverified |
| OpenHands | Issue to PR in isolated container, per-action audit logs | Source-available, active Slack/GitHub |
| Augment Code | Ticket-to-PR loop | ISO 42001 + SOC 2 Type II. Contact unverified |
| Traversal | DISPUTED whether it writes or only analyzes. Confirm first | Anish Agarwal, Raj Agrawal + others |
| Firefly | Agent remediation, markets "audit-ready evidence for DORA" | Contact unverified |
| Exaforce | Access revocation, isolation. HITRUST + HIPAA | No team page |
| Kubiya | Runs shell and Terraform in customer infra | Contact unverified |

## Validation interviews, not sales targets

These already built exactly this. Ask what it cost, what buyers still push back on,
and whether it actually closed deals. Faster answer than ten cold prospects.

- **Basis** (security@ofbasis.com) — "Every agent action is logged and auditable." ISO 42001
- **Bretton** (was Greenlite) — "Every decision logged with reasoning, evidence, model version." AML for banks
- **Nym Health** — routes coded encounters to billing with zero human intervention, markets audit trails
- **CodaMetrix** (hello@codametrix.com) — autonomous medical coding into claims

## Skip

- **Codegen** — acquired by ClickUp
- **Thoughtful.ai** — absorbed into SmarterDx, domain redirects
- **Parity** — domain refused connection, may be dead
- **Cognition, Cast AI** — too large, founders will not answer
- **Rootly, Dropzone** — human sign-off gating weakens the pain. Contrast interviews only
- **Qodo** — review only, no autonomous write. Competitor data point
- **Simbian, Pylon** — action claims unsubstantiated, verify first

## Unverified claims from the research

Treat as leads to check, not facts to repeat: COSO generative AI guidance (Feb 2026),
EU AI Act Article 12 full application (Aug 2026), "88% of agent pilots never reach
production", Gravitee agent-security survey figures, the PocketOS database deletion
incident. Every one needs a primary source before it goes in a pitch.
