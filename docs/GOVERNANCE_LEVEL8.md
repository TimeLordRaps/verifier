# Governance admission at proposed level 8

Verifier Standard (VSTD) uses governance here for an exact action admission
predicate. The proposed `[OBJECT]-8.m` internal grounding certificates concern who may decide under which
current policy. They neither govern the repository's maintainers nor demonstrate
effective self-regulation of the artificial intelligence field. This standalone
runtime candidate is not, by itself, a registered domain certification mechanism.

The implementation is [`verifier.governance`](../src/verifier/governance/__init__.py).
Its `GovernanceContext` binds object name, artifact digest, operation, actor,
observer, purpose, timestamp, jurisdiction, and invocation identifier. Jurisdiction
is an exact configured scope string; matching it establishes no legal conclusion.
Timestamps are nonnegative integer Unix seconds in Coordinated Universal Time
(UTC). The trusted executor independently supplies `evaluation_time`, which must
equal the requested action's timestamp. Candidate evidence cannot choose the
freshness clock.

## Independently supplied authority

`GovernancePolicy` is trusted operator configuration, not candidate evidence. It
specifies a positive revision, admitted object names, operations and jurisdictions,
distinct decision-maker identifiers and keys, achievable quorum, veto holders,
effective interval, status root, maximum snapshot age, and optional appeal route.
No arbitrary role label supplies authority. Keys must be provisioned independently
and kept outside receipts. An updated policy's public-term digest invalidates
decisions and status evidence for the prior policy. The executor must actually
load the current policy; this offline function cannot discover policy updates.

The supported mechanism uses hash-based message authentication code (HMAC) with
Secure Hash Algorithm 256-bit (SHA-256). Every secret holder can create evidence
under that secret, including the verifier. This is a shared-secret trust boundary,
not asymmetric nonrepudiation, independent human identity, consent, or proof that
distinct people participated. Distinct principals may not share key bytes or key
identifiers; the separately configured status root is also distinct. A minimum
key length is enforced, but entropy and key custody require external provisioning.

## Retained evidence and decisions

Decision records use `verifier-governance-decision-1` and contain `decision_id`,
`policy_digest`, complete `binding`, `actor_id`, `key_id`, `decision`, `issued_at`,
and `expires_at`, plus `signature`. Decisions are `APPROVE`, `DENY`, or `VETO`;
only configured veto holders may veto. Any authenticated denial rejects admission.
Two records by one actor, duplicate decision identifiers, unknown decision makers,
wrong keys, altered signatures, binding mismatches, stale policy, and expired
decisions reject. The complete canonical binding distinguishes integer timestamps
from numerically equal floating-point values.

Status records use `verifier-governance-status-1` and contain `policy_digest`,
`key_id`, `observed_at`, `expires_at`, `revoked_decisions`, `revoked_actors`, and
`consumed_invocations`, plus `signature`. They must authenticate under the separate
status root. Freshness is evaluated against the independent clock and maximum
age. Revoked decision makers, revoked decisions, and already consumed invocation
identifiers reject. An unavailable, future, expired, or stale status snapshot
leaves current admission `UNKNOWN`; a detectable forgery remains `REJECTED`.

To sign either record, exclude only `signature`, serialize the remaining record
as canonical JavaScript Object Notation (JSON) with sorted keys, compact separators,
American Standard Code for Information Interchange (ASCII) escapes, and forbidden
nonfinite numbers; authenticate those encoded bytes.
The signed schema discriminator binds the record kind. Unknown fields reject.
Intervals include their start and exclude their end. Decision inventories are
bounded at 256 records; each status inventory at 10,000 identifiers.

`evaluate_governance` recomputes `PASS`, `REJECTED`, or `UNKNOWN`; a passing
receipt establishes only this bounded admission predicate. `recheck_governance`
reruns supplied context, original evidence, independent policy and clock, then
compares complete canonical receipt bytes. Equality also reproduces a rejection or
unknown result; a true recheck is not automatically permission. Evidence digests
bind retained bytes but supply no authority or archival availability themselves.

## Composition and limits

The receipt preserves the caller's computational verdict without upgrading it and
sets `privacy` and `consent` to `NOT_EVALUATED`. Governance admission cannot waive
either requirement. `enforcement` remains `UNKNOWN`: no action is executed, no
atomic invocation redemption occurs, and repeated evaluations against an unchanged
snapshot are intentionally reproducible. The caller must handle durable consumption
and races before relying on single-use authority. The appeal route is descriptive
provenance; filing, hearing, remedy, enforcement, policy legitimacy, legal authority,
human comprehension, external identity and field-wide outcomes are not established.

The focused adversarial suite is [`test_governance_level8.py`](../tests/test_governance_level8.py).
It constructs signatures independently with fresh ephemeral keys. It covers exact
binding, quorum, outsider and duplicate-key rejection, denial, veto, policy updates,
revocation, known replay, expiry, stale status, receipt alteration, missing clocks,
and numeric aliasing. Full-repository integration remains a separate gate.
