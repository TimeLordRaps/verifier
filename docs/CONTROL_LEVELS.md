# Privacy, consent and governance control levels

Verifier Standard (VSTD) is a language and reference implementation for bounded
computational claims. Generative simulation specification (SIM) and closed-loop
agent simulation specification (BOT) objects remain subject to their own evidence
and replay requirements.

This local development candidate follows the maintainer's 2026-09-27 clarification:
`[OBJECT]-6.m` denotes privacy, `[OBJECT]-7.m` consent, and `[OBJECT]-8.m`
governance. `[OBJECT]` is a named object, 6 through 8 are positive meta-tier
numbers, and `m` indexes an internal grounding certificate within that tier.
These dimensionless coordinates are not assurance scores or wire-schema identifiers.

## Separate questions, combined admission

| Control | Question | Current implementation scope |
|---|---|---|
| 6: privacy/disclosure | What exact information may this operation emit to this recipient for this purpose? | Existing emission helper, independently scoped to configured bounds and supported adapters. |
| 7: consent | Does current authenticated consent cover this artifact, operation, actor, recipient and purpose? | Candidate consent evaluator; configured authority, expiry and revocation checks. |
| 8: governance | Does the current policy admit this particular action under its decision and accountability rules? | Candidate governance evaluator; configured authority, quorum, policy revision and supplied status snapshot. |

The existing computational catalogue gives tiers 1–5 corroboration meanings;
accountability objects require their distinct authority and responsibility mappings.
Controls 6–8 do not add computational evidence, repair a failed computation, or erase
a historical verdict. Consent
cannot expand a privacy bound; governance cannot supply absent consent. All
applicable controls must be satisfied independently for a composed admission.

The existing normative catalogue has level-6 rows with no registered certification
mechanism. An emission-helper result does not discharge every one of those rows.
The new consent/governance packages are candidate mechanisms for bounded operation
checks. They do not silently extend existing numbered-profile certificate schemas,
alter their depths, or announce fully mechanized level-7/8 certification.

## Authority and time

Authority configuration must arrive through the operator's trusted control surface,
separately from submitted requests. A signature authenticates against that configured
authority; it does not prove legal entitlement, comprehension, voluntariness or the
truth of a computational claim. Shared-secret authentication makes verifiers capable
of issuing authenticators too; it is not public-key independent attestation.

Evaluation time comes from the trusted caller in integer seconds since the Unix
epoch in Coordinated Universal Time (UTC). Request timestamps cannot select an old
revocation state. A previously valid receipt can be replayed as historical evidence
without authorizing a new action. Status snapshots must satisfy the evaluator's
explicit age limit, but offline checking cannot discover a newer state that its
trusted source withholds.

The composed privacy timestamp accepts `YYYY-MM-DDTHH:MM:SS`, optionally followed
by an all-zero decimal fraction, and a `Z` or `+HH:MM`/`-HH:MM` offset. It must
identify exactly the same integer second as the trusted evaluation time. Nonzero
fractions and fractional offsets are rejected before parsing; no rounded timestamp
can supply an exact context match.

Denial, altered authentication or mismatched scope cannot become a permission.
Unavailable authority, freshness or enforcement evidence remains `UNKNOWN`. A
decision record cannot prove that an external service enforced it, atomically
consumed an invocation, handled an appeal, or followed an applicable law.

## Integration and qualification

The guides [privacy](PRIVACY_LEVEL6_REVIEW.md), [consent](CONSENT_LEVEL7.md) and
[governance](GOVERNANCE_LEVEL8.md) specify each implementation's exact inputs,
mechanisms, falsifiers and exclusions. Coordinate registration, host enforcement,
key provisioning and operational deployment are separate gates. Existing wire
identifiers remain unchanged.

`verifier.controlled_emission.evaluate_controlled_emission` composes the three
helpers with native domain-certificate replay. It binds the entire canonical
certificate, including its certificate digest, to the action's hexadecimal artifact
digest. Only `admission == "PASS"` returns an unchanged certificate; other results
return no emitted certificate. It performs no external action or atomic invocation
consumption. Its audit receipt requires a separate disclosure review before sharing.
The exercised integration is in `tests/test_controlled_emission.py`.

The intended beneficiary is an operator who needs reproducible decisions before
an agent publishes or uses an artifact. Effective field-wide self-regulation is
a research and deployment objective. These checks alone do not establish it.
