# Current finite selected ROLE lifecycle certificate

Verifier Standard (VSTD) current `ROLE-2.1`, under
`verifier-current-object-obligations-1`, selects a finite protocol interpretation
of one ROLE class's retained `lifecycle_state`, `permissions` and `admitted_scopes`
payload fields. Namespace composition does not assign activation, suspension or
deprovisioning semantics to those fields. Their meaning here comes solely from
the externally selected explicit transition protocol. This versioned proposition
does not migrate the historical ROLE-2 rows in `DOMAIN_OBLIGATIONS.md`, determine
all required current `.m` objectives or establish whole dynamics-tier conformance.

Each externally selected endpoint independently binds the exact same ROLE
identifier, its endpoint record digest and complete typed collection digest,
plus the exact child request, policy and certificate digests. Each retained
`ROLE-3.1` child is freshly rechecked under that independently selected request
and policy. Its kind, subject, scope, semantic version, coordinate and collection
must match the endpoint, and its computed status must be PASS. A carried PASS
without retained bytes or a newly hashed substituted child cannot supply this
prerequisite. The final endpoint's object and collection equal the parent request's
selected current object and collection. Endpoint commitments and policies are
selected externally, never accepted from an untrusted parent certificate.

Evidence version `verifier-current-role-lifecycle-evidence-1` has exactly
`schema_version`, `protocol`, `endpoints` and `events`. Each endpoint has exactly
`child_request`, `child_policy` and a canonical base64 `child_certificate` holding
the exact immutable child certificate bytes. The protocol has exactly
`schema_version`, `states` and `transitions`. Its version is
`verifier-current-role-lifecycle-protocol-1`. States are sorted unique bounded
nonblank strings; transitions are sorted by the unique `(from_state,to_state)`
pair and have exactly these fields:

- `from_state`, `to_state`: states in the selected vocabulary.
- `add_permissions`, `remove_permissions`, `add_scopes`, `remove_scopes`:
  sorted unique bounded arrays of values allowed to be added or removed.
- `allow_taking`, `allow_leaving`: plain booleans permitting nonempty occupancy
  additions or removals at this transition.

For every adjacent endpoint pair, native replay requires an explicit selected
state transition, computes each exact permission/scope set difference, and
checks it against that transition's permitted addition/removal sets. All remaining
ROLE payload fields stay canonically equal; endpoint statics independently check
the full selected role inventory, permissions, scopes and occupancy matrices.
No implicit restriction follows from the spelling of a state, and an omitted
transition is forbidden under the selected finite protocol.

Each ordered event has exactly `position`, `taking` and `leaving`. Position is
the plain positive integer index of the destination endpoint, starting at one.
Taking/leaving arrays are sorted unique ACTOR identifiers. They must equal the
exact differences of the selected role's endpoint occupancy sets. Applying each
ordered removal/addition to the initial retained occupancy must reproduce its
destination endpoint. These events describe finite endpoint changes, not complete
historical occurrences, physical time, temporary activity within an interval,
delegation, decisions in flight, acting personally, or complete paired hand-over
semantics. Unretained intermediate changes are not established by equal endpoints.

The parent request binds the complete ordered endpoint selection, protocol,
evidence, policy, proposition and limits. Replay rehashes every retained byte,
reruns endpoint statics and native lifecycle predicates, and reconstructs the
entire parent certificate. Rehashing a carried result cannot upgrade its verdict.
Missing retained components, omitted selected endpoints/events, missing lifecycle
declarations, UNKNOWN endpoint prerequisites, unsupported versions and exhausted
bounds yield UNKNOWN. Malformed present inputs, substituted selections, invalid
children, extra endpoints/events, false event positions/deltas, illegal selected
transitions, forbidden permission/scope changes and changed remaining ROLE facets
yield FAIL. An invalid carried parent or nonreproducing result causes replay refusal.

Missing independent support does not mask a detected contradiction. Present child
request, policy and certificate commitments are checked independently before an
absent companion is recorded. Every available selected child is examined even
when another endpoint, protocol or event is missing. Replayed endpoint fields
support local predicates when their inputs exist: missing state blocks its legal
state-pair rule but does not hide a fixed-facet or occupancy-event contradiction.
Available adjacent states and permission/scope sets remain checkable when events
are missing. No unselected state rule or missing endpoint is invented. A detected
FAIL takes precedence over accumulated missing support; absent support without a
computed refutation remains UNKNOWN. Parent operation-budget exhaustion stops
checking with UNKNOWN, and unavailable child replay remains bounded by its own
selected limits and the aggregate child reserve.

Default ceilings are 16 endpoints, 4096 items per input container, 100000 parent
input/predicate visits, two mebibytes per child certificate, eight mebibytes of
evidence and sixteen mebibytes of parent certificate bytes. The aggregate child
operation reserve is 4800000: before each child replay, its externally selected
input/predicate, composition and relation ceilings are added to one reserve,
which cannot exceed the selected parent limit. These are independent child
checker ceilings, not measured machine instructions or time. Every selected
limit is a positive plain integer no larger than its ceiling. Shared child
JavaScript Object Notation (JSON) nesting is checked before recursive parsing. Mechanism
hashing binds the native parent and shared infrastructure plus the endpoint's
computed mechanism digest, including actual installed shared specification bytes.
Digest commitments use Secure Hash Algorithm 256-bit (SHA-256).

Even at PASS, authority, actual execution, historical occurrence, enforcement,
actual occupancy, whole-tier and object-profile conformance remain
NOT_ESTABLISHED. Physical liveness, human authenticity, actor independence,
out-of-collection completeness and all other required current `.m` obligations
remain separate. Trust-root strings are selected labels, not proof of authority.

Retained-reader capacity availability is a distinct boundary. Decoder recursion,
overflow and explicitly unavailable checking capacity raise `RoleLifecycleUnavailable`,
an `OSError` subtype, and current public routes preserve UNKNOWN. This capacity
category does not establish replay or refute the selected predicate. Demonstrated
selection substitutions, malformed semantic bytes and exact-reconstruction
contradictions remain `RoleLifecycleError` refusals; ordinary `ValueError` is never
downgraded to unavailability. Evaluator capacity exhaustion remains UNKNOWN.
An already observed FAIL is retained; no uninspected later predicate is certified.
Source/mechanism changes require freshly selected policies and certificates;
previous exact bytes and their genuine verdicts are not rewritten.

A native static child's typed unavailable checking capacity is accumulated as
missing endpoint support. Other available exact endpoints remain checked; a later
genuinely rechecked FAIL or independent present contradiction still refutes the
selected lifecycle. Unknown endpoint states cannot supply a transition PASS.
Semantic child reconstruction refusal remains a refutation, not unavailability.
