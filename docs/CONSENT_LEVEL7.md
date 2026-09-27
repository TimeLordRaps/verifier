# Proposed consent meta-tier: bounded executable admission

Verifier Standard (VSTD) meta-tier 7 is the maintainer-requested consent tier.
Its coordinate form is `[OBJECT]-7.m`: `[OBJECT]` names an object and `m` indexes
an internal grounding certificate within this positive-numbered tier. Both numbers
are dimensionless. The existing catalogue has no registered tier-7 certificates. This document
proposes concrete obligations for that intent. The helper implementation is
executable; it does not itself register domain certificate obligations, establish
full tier conformance, or prove that artificial intelligence (AI) can self-regulate.

The existing holding and consequence boundary (`OWNER`) already includes a
`consent` limb in `src/verifier/domains/owner.py`. Its declared instrument and
lifecycle do not authenticate an issuer. The privacy adapter already recognizes
`consent_governed` as a transmission-principle label. A label is not consent
evidence. The new `verifier.consent` package supplies the missing bounded
admission mechanism without changing those existing serialized meanings.

## Proposed obligations and implemented mechanism

| Coordinate | Bounded proposition | Mechanism |
|---|---|---|
| 7.1 | The request matches the artifact, action, actor, observer and purpose granted. | Exact object name and artifact digest; explicit scope membership; no wildcard inference. |
| 7.2 | A configured consent holder authenticated the grant. | Independently supplied artifact authority, actor/key binding, and keyed authentication. |
| 7.3 | Grant validity and revocation evidence cover trusted evaluation time. | Current action time equality, half-open grant interval, authenticated status snapshot, maximum age and rollback floor. |
| 7.4 | Delegation never widens parent scope or validity. | Ordered parent-digest chain, delegate identity, explicit delegation flag, ancestor revocation, bounded chain length. |
| 7.5 | Retained admission can be recomputed from bound inputs. | Deterministic receipt; exact full-field comparison after evaluation with independently supplied policy and clock. |
| 7.6 | Consent does not strengthen a computational verdict. | The input computational verdict is retained unchanged and never used to decide consent. |

These proposed `7.1`–`7.6` rows are candidate obligations, not registered
`[OBJECT]-7.m` certificates or claims that a domain certificate reaches tier 7.
Per-coordinate registration, prerequisites and whole-repository checks
are separate integration gates. A helper `PASS` means only the configured
mechanism admitted the exact request under its supplied authority assumptions.

## Interface and units

`ConsentContext(object_name, artifact_digest, operation, actor_id, observer_id,
purpose, timestamp)` names one exact request. `artifact_digest` is a lowercase
64-character Secure Hash Algorithm 256-bit (SHA-256) hexadecimal digest of the
application-selected artifact bytes. Names and digests are dimensionless.
`timestamp`, `evaluation_time`, `not_before`, `not_after`, `as_of`, and
`next_update` are nonnegative integer Coordinated Universal Time (UTC) Unix
seconds, bounded by `2**53 - 1`. The upper bound preserves integer representation
in common JavaScript Object Notation (JSON) consumers. The bound is an encoding
limit, not a scheduling horizon recommendation. Freshness durations are seconds;
chain lengths and collection limits are dimensionless.

`evaluate_consent(context, grants, policy=..., revocation=...,
evaluation_time=..., computational_verdict="UNKNOWN")` returns a
`ConsentEvaluation` with `verdict` and `receipt`. `grants` is an ordered tuple of
authenticated grant envelopes from root to final delegate. The trusted caller
supplies `evaluation_time`; an absent time is `UNKNOWN`, and an action time that
differs from it is `REJECTED`. There is no automatic ambient-clock fallback and
no accepted clock skew. All grant intervals are half-open: start is inclusive,
end is exclusive. The caller must obtain an appropriate trusted clock.

`ConsentPolicy` contains the required `grantor_id`, exact `artifact_bindings`,
immutable configured `ConsentKey` records, root-key and revocation-key roles,
maximum status age, minimum admitted status time and maximum chain length.
`artifact_bindings` cannot be supplied by a request as authority. An empty set
is `UNKNOWN`; an artifact outside the configured set is `REJECTED`.

The checker captures plain built-in context and policy fields, configured key
roots, grant envelopes and revocation evidence before authentication. The same
captured values drive scope, freshness, revocation and receipt fields. Mutation
of the caller's original context or policy during authentication cannot expand
the admitted action or authority. Custom string, bytes, tuple, list and object
subclasses are outside this plain-value admission boundary; their overridden
length, membership, iteration or equality methods do not grant scope or satisfy
key-length requirements. A malformed capture is `REJECTED`, with unavailable
context, policy or evidence digests represented as `null` rather than hashing
uncaptured caller data.

Each envelope binds `key_id`, `payload`, `payload_digest` and `authenticator`.
`authenticate_consent` computes a hash-based message authentication code (HMAC)
using SHA-256 over a domain-separated, sorted-key compact JSON body. A digest
alone is not authentication. The evaluator recomputes both digest and
authenticator using its external key configuration, and checks the configured
key's actor against `issuer_id`. Unknown keys are `UNKNOWN`; known-key forgery,
payload mutation, unexpected fields or an unauthorized authority role are
`REJECTED`. Runtime keys must contain at least 32 exact bytes. Length alone does not
establish randomness; secure provisioning is the operator's responsibility.

The revocation snapshot is separately authenticated by an authorized status key.
It binds the policy identifier, issue time, next-update time and revoked grant
identifiers. A known revoked ancestor rejects the chain even if the snapshot is
stale. A future snapshot or stale absence of revocation cannot admit an action.
The maximum age and `minimum_revocation_as_of` are trusted policy values, not
grant-selected thresholds. The latter allows an operator to prevent rollback
behind its last admitted registry checkpoint.

`recheck_consent` recomputes the complete receipt with the supplied context,
evidence, policy, time and unchanged computational verdict. Its Boolean result
means equality, including for an `UNKNOWN` or `REJECTED` receipt; callers must
also inspect admission. It bounds and copies the carried receipt before
serialization. It never treats a request-supplied `PASS` as authority.

## Authority and limitations

This is a shared-secret authority mechanism: every holder of an authentication
key can create statements for that configured key. It is not a publicly
verifiable signature, independent human consent, an assessment of comprehension,
legal capacity, voluntariness, ownership or jurisdiction. The operator must
establish the consent holder's authority over each configured artifact and the
integrity, completeness and timeliness of its revocation registry. Missing these
external facts cannot be repaired by hashing, a privacy bound or an `OWNER` label.

Removing a key makes statements under it `UNKNOWN`; replacing its secret rejects
old authenticators. Rotating keys or changing policy invalidates exact receipt
replay unless the historical policy is deliberately retained. Secret bytes are
never serialized in receipts. Policy descriptors retain key fingerprints, which
identify configuration changes but do not establish authority. Protecting
configuration, choosing high-entropy keys, deleting obsolete keys, advancing the
rollback floor and persisting registry state remain host responsibilities.

Admission is bounded by the accepted snapshot and its configured freshness
window; this offline function does not know of unobserved revocations or denied
grants omitted from the supplied chain. A denying grant rejects when present;
hosts must encode effective global denials in their authoritative registry or
policy. Multiple required consent holders must each be evaluated separately and
combined by the host's explicit policy. Consent for one holder is not consent
for every affected person.

The receipt covers the seven context fields. Extra governance fields such as
jurisdiction and invocation identity require their own binding. No single-use
redemption, cross-process lock, durable replay prevention, receipt signature,
network registry synchronization or application enforcement is implemented here.
Repeated checks are deliberately deterministic; they do not consume a grant.
`enforcement` remains `NOT_ESTABLISHED`. A historical replay with a deliberately
supplied historical clock proves only that historical evaluation, never current
permission. The supplied computational verdict remains caller input, not a
computation independently rerun by consent evaluation.

All runtime imports use the standard library. Candidate evidence capture is
limited to depth 64, 50,000 traversed values, one mebibyte of encoded text,
10,000 entries per candidate collection and at most 4,096 bits per integer.
The trusted policy capture admits at most 50,000 combined key, role and
artifact-binding entries and one mebibyte of descriptor source text before
cloning. Its public descriptor remains under the one-mebibyte canonical limit.
Configured secret-root bytes are runtime inputs outside that public text budget;
operators must bound their storage and key-processing cost. Canonical
serialization remains limited to one mebibyte. Text and object keys are limited
to 512 characters, name lists to 128 entries and delegation to at most 16
grants. These are representation limits, not physical time or assurance scores.
Inputs are already parsed Python values: this is not a general untrusted JSON
parser, in-process code sandbox or network denial-of-service defense.

## Reproduction

Run `python -u -m pytest tests/test_consent_level7.py -vv -s --durations=10
--timeout=60` with the documented test dependencies installed. Tests generate
ephemeral test-only secrets at runtime, authenticate bounded inline grants and
exercise exact binding, expiry, clock substitution, key rotation, digest and
authenticator forgery, missing and stale authority, revocation, ancestor
withdrawal, forbidden delegation widening, deterministic replay and unchanged
computational verdicts. No private keys or deployment configuration are stored.
