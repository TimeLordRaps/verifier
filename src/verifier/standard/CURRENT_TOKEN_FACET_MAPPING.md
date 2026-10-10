# Current capability-token partial facet mapping

Status: locally admitted experimental engineering contract. JavaScript Object
Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
This mapping projects retained capability-token declarations. It establishes no
complete application facet inventory, host authority, whole-tier conformance,
financial balance/supply semantics or formal Safety tier.

## Exact scope and origins

The semantic version is verifier-current-object-obligations-1. Each selected
TOKEN namespace record must declare scope retained-capability-token-records
and clock_unit microsecond. The token inventory commitment is the namespace
field payload/artifact/tokens_digest. Epoch indices, active epoch counts and
invocation quotas are dimensionless. The clock identifier is an opaque label;
declaring its unit establishes no physical meaning, clock calibration or actual
passage of time. Other units or scopes remain UNKNOWN.

The following partial projections retain the source-defined legacy clauses in
DOMAIN_OBLIGATIONS.md and ZIZK_TOKENS.md; historical coordinates are citations,
not admissions of historical certificates as current certificates.

| Partial semantic projection | Retained token fields | Source coordinate |
| --- | --- | --- |
| token-kind | kind, token_id | TOKEN-1.1 |
| birth-seed | birth_epoch, commitment | TOKEN-1.3 |
| aging-head-interval | birth_token_id, epoch_start, epoch_end, accumulator_digest, accumulated_epochs, revocation_status | TOKEN-1.4 |
| lease-scope-quota | permitted_scopes, max_invocations | TOKEN-1.5 |
| issuance-declaration | issuing_key_id, issued_at | TOKEN-1.6 |
| validity-window | not_before, not_after | TOKEN-1.10 |
| replay-identifier | replay_id | TOKEN-1.11 |
| caveat-set | caveats | TOKEN-1.13 |
| parent-grant-relation | parent_grant_id | TOKEN-4.3 |
| soulbound-delegate | soulbound, delegate_key_id | TOKEN-3.4 |

These are projections from inputs/tokens retained in the native evidence, anchored
to its namespace commitment. Merely retaining a digest establishes none of its
contents. Native replay must independently verify the committed arrays.
Genesis openings, issuer signatures, controlling-key existence, actual survival,
global issuance uniqueness, physical clock truth and actual discharge remain
unestablished. Declared unbounded expiry is reported; it is no finite-expiry proof.
The native conditional soulbound predicate establishes no unconditional mandatory
soulbound construction. Parent-grant links are retained documentary relations,
not namespace operands or certificate prerequisite edges.

## Authored native obligations

| Source property | Current predicate | Required artifact fields | Bound interaction |
| --- | --- | --- | --- |
| selected_capability_token_tenure | TOKEN-2.1 | tokens_digest, epochs_digest, clock | token commitment and ordered epoch commitment |
| selected_capability_token_windows | TOKEN-3.1 | tokens_digest, clock, clock_skew | token commitment and declared skew |
| selected_capability_token_parent_grants | TOKEN-4.1 | tokens_digest, clock, root_scopes | token commitment and retained root scope set |

The obligations implement CURRENT_TOKEN_CHECKS.md. Every derivation requires the
exact scope/unit, all listed field anchors and an origin containing tokens_digest.
Missing anchors, unrelated origins, unsupported scopes or units remain UNKNOWN.
The original five structural semantic facets remain companion obligations.
Repeated partial semantic origins and interactions deduplicate by exact object
and native proposition; they do not multiply certificate requirements.

Each current token checker freshly replays exact namespace composition and token
inventory inline. These real prerequisites require no separate certificate edge.
Tenure separately replays the committed ordered epoch sequence; windows and
delegation use the actual selected token fields, not independent substitute arrays.
PASS means those finite retained predicates reproduced. It cannot discharge
unrelated partial facets, complete holding closure, real authority or enforcement.

The sidecar rule set pins the mapping, checker, retained-selection helper, native
token/statics/common/evidence sources and normative specifications. A changed
source or rule requires independent policy reselection. Authored-rule admission
is separate from application mapping authority and production-profile approval.
The finite namespace-field census is not a semantic application denominator.
Full facet and interaction applicability remain UNKNOWN; no exemption is inferred.
