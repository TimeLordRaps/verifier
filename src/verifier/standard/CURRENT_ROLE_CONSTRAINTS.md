# Current finite ROLE constraints certificate

Verifier Standard (VSTD) current `ROLE-3.1` selects one static proposition under
`verifier-current-object-obligations-1`. It checks a complete retained finite
typed collection against an independently selected matrix commitment. It does
not reinterpret a historical coordinate or complete ROLE's statics tier.

`role_constraints_request` binds the exact ROLE identifier and record digest,
complete collection digest, matrix digest, retained evidence byte reference,
installed policy digest, proposition and finite limits. Select these externally;
never derive an accepted selection from an untrusted carried certificate.
Trust-root strings are selected labels, not authenticated authority evidence.
The mechanism digest binds its source, certificate/evidence/namespace/receipt
infrastructure, retained selection, shared typed relation expansion, and the
installed namespace, identity and this specification's exact bytes.

Evidence is canonical JavaScript Object Notation (JSON), with exactly
`schema_version`, `objects` and `inputs`. Its version is
`verifier-current-role-constraints-evidence-1`; `objects` retains each complete
namespace record, and `inputs` contains exactly `matrix`. The matrix version is
`verifier-current-role-constraints-matrix-1` and has exactly these fields:

- `collective_id`: the selected retained COLLECTIVE identifier.
- `roles`: rows with `role_id`, sorted unique `allowed_permissions` and
  `allowed_scopes`, and integer `min_occupants` and `max_occupants`.
- `actors`: rows with `actor_id` and sorted unique `allowed_roles`.
- `occupancies`: rows with `identity_id`, `actor_id`, `role_id` and `scope`.
- `exclusive_role_sets`: sorted unique arrays of at least two selected role
  identifiers. Each inner array is sorted and unique.

Rows are sorted by their identifier and have no duplicate identifiers. The
matrix inventories must equal every retained ROLE, ACTOR and IDENTITY,
respectively. The selected COLLECTIVE's typed role graph must expand to exactly
the matrix roles. Namespace composition is freshly checked against the external
complete collection commitment, including all types, roots and references.
Unrelated retained kinds remain part of that commitment; their payload truth
does not follow from structural replay.

Each ROLE payload must retain `permissions` and `admitted_scopes` as sorted
unique arrays; each must be a subset of its selected bound. Other payload fields
remain uninterpreted. Each IDENTITY must expand to exactly one ACTOR and ROLE,
retain a scope, and equal its complete selected occupancy row. Its role must be
allowed for that ACTOR and its scope admitted by that ROLE. Duplicate actor-role
occupancies fail; occupancy counts are distinct ACTOR identifiers. Every count
must lie within its selected inclusive interval. Bounds satisfy
`0 <= min_occupants <= max_occupants <= 4096`.

For every mutually exclusive role set, distinct roles must have disjoint ACTOR
occupants and disjoint declared responsible HUMAN identifiers. Multiple ACTOR
identifiers referring to one responsible HUMAN therefore cannot evade the
selected separation constraint. This is declared accountability separation;
it does not establish actor independence or authenticate any human.

The certificate version is `verifier-current-role-constraints-certificate-1`.
Replay rehashes retained bytes, reruns the native predicates and reconstructs
the entire certificate; a rehashed carried PASS is insufficient. PASS establishes
only these finite declared constraints. Missing bytes, missing ROLE permission
or scope declarations, missing IDENTITY scope, unsupported evidence/matrix
versions and exhausted bounds yield UNKNOWN. Contradictory commitments, bad
types, malformed present declarations, inventory omissions, substituted cells,
excess permissions or scopes, false counts and shared occupants or responsible
humans under a selected exclusion yield FAIL. Invalid carried certificate
structure or a result that does not reproduce causes replay refusal.

Default ceilings are 256 objects, 4096 items per input container, 100000 charged
input/predicate visits, 100000 separate composition operations, 100000 popped
typed relation references, and four mebibytes each of evidence, aggregate payload
and reference bytes. JSON nesting is bounded at 64 before recursive parsing.
Certificate bytes are separately bounded at eight mebibytes. All selected limits
are positive integers no larger than their ceilings. Relation expansion shares
one counter across the collective, actor roots and identity operands. Visits and
references are dimensionless checker counts, not machine instructions or a time
guarantee. Byte commitments use Secure Hash Algorithm 256-bit (SHA-256).

Even at PASS, real-world authority, actual occupancy or liveness, permission
issuance, human authenticity and enforcement remain NOT_ESTABLISHED. Finite
inventory completeness does not establish out-of-collection completeness,
permission meaning, legal or ethical adequacy, full ROLE statics-tier or object
profile conformance, or privacy, consent, governance or security admission.
All other required `.m` objectives remain separately unestablished.

Retained-reader capacity availability is a distinct boundary. Decoder recursion,
overflow and explicitly unavailable checking capacity raise `RoleConstraintsUnavailable`,
an `OSError` subtype, and current public routes preserve UNKNOWN. This capacity
category does not establish replay or refute the selected predicate. Demonstrated
selection substitutions, malformed semantic bytes and exact-reconstruction
contradictions remain `RoleConstraintsError` refusals; ordinary `ValueError` is never
downgraded to unavailability. Evaluator capacity exhaustion remains UNKNOWN.
An already observed FAIL is retained; no uninspected later predicate is certified.
Source/mechanism changes require freshly selected policies and certificates;
previous exact bytes and their genuine verdicts are not rewritten.
