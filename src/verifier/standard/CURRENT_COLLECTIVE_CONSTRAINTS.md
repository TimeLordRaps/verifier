# Current COLLECTIVE static constraints

Verifier Standard (VSTD), JavaScript Object Notation (JSON), Secure Hash Algorithm
256-bit (SHA-256), Unicode Transformation Format, 8-bit (UTF-8).

`COLLECTIVE-3.1`, selected under `verifier-current-object-obligations-1`, checks one
finite retained declaration. It does not reinterpret the legacy COLLECTIVE quorum
check, establish a collective vote or complete a statics tier.

The external policy selects sorted distinct `{role_id, role_digest}` records,
one exact charter byte digest and one integer quorum. The request independently
binds the subject, full typed collection, evidence bytes, policy, proposition and
finite limits. COLLECTIVE membership follows the namespace's `roles: ROLE`
contract. Its complete declared `roles` operand, expanded through explicitly
typed ROLE graphs to distinct ROLE leaves, must equal the external selection;
each selected ROLE must occur with its exact kind and digest in that collection.
Nested graph paths do not create additional quorum seats. Every visited reference
consumes the predicate-operation budget; composition independently checks graph
typing, complete retained references and acyclicity before membership expansion.
This completeness concerns that operand and finite selection. It cannot discover
omitted real members or determine that the selection is an exhaustive charter.

The subject payload carries `static_constraints` with exactly `schema_version`,
`charter_digest`, `membership_digest` and `quorum`. The constraint version is
`verifier-current-collective-static-constraints-1`. Membership binds the canonical
selected record list. Quorum must match the external selection and lie between one
and the selected ROLE count, inclusive. A feasible count is a static invariant;
it does not authenticate independent occupants or show that they voted.

Evidence version `verifier-current-collective-constraints-evidence-1` carries the
complete `objects` list and `inputs`. The latter retains `membership`, `quorum`
and `charter: {sha256, base64}`. The charter's retained bytes must reproduce the
selected digest and decode to nonblank UTF-8 text. No charter language, legal
meaning, sufficiency, or authority is interpreted. A hash without retained bytes
cannot discharge the charter check.

Changed selected records, wrong kinds, duplicate members, different operand
membership, commitment mismatch, infeasible quorum, malformed evidence, and
empty or invalid charter text produce `FAIL`. Absent required retained inputs,
unsupported subject constraint semantics and exhausted finite bounds produce
`UNKNOWN`. Present contradictions are checked before reporting an absent retained
charter. Byte/operation exhaustion can prevent further inspection and remains
`UNKNOWN`. A malformed external selection or substituted certificate is refused.

The selected ceilings are 256 objects, 100000 input/predicate operations, 100000
composition operations, 4096 items per structure, 4 mebibytes each of evidence,
composition references and payloads, 64 JSON nesting delimiters, and 65536 charter
bytes. Input traversal, role/member iteration and decoded charter bytes consume
the operation budget. The certificate ceiling is 8 mebibytes. Counts are
dimensionless. Smaller positive external limits are binding, including at exact
boundaries. Nesting is scanned before recursive parsing. Resource exhaustion is
uncertainty, never a passing replay.

The native module supplies policy/request constructors, certificate generation
and `recheck_collective_constraints_certificate`. Recheck imports the exact
retained evidence and reproduces the entire envelope. The mechanism digest binds
the native module, core canonicalization/evidence/namespace/JSON readers, bounded
domain primitives, this specification and the imported namespace specification.
Changing any dependency invalidates the selected installed policy.

Every result preserves object-profile conformance, whole-tier conformance, actual
execution, authority, real membership completeness, ROLE occupancy, charter
authority and an actual quorum decision as `NOT_ESTABLISHED`. The separate
governance signature/quorum mechanism has its own proposition and evidence;
this static check grants none of its admissions. Applicable `.m` obligations and
complete object/tier certification require a separately selected obligation set
and passing evidence for every requirement.

Retained-reader capacity availability is a distinct boundary. Decoder recursion,
overflow and explicitly unavailable checking capacity raise `CollectiveConstraintsUnavailable`,
an `OSError` subtype, and current public routes preserve UNKNOWN. This capacity
category does not establish replay or refute the selected predicate. Demonstrated
selection substitutions, malformed semantic bytes and exact-reconstruction
contradictions remain `CollectiveConstraintsError` refusals; ordinary `ValueError` is never
downgraded to unavailability. Evaluator capacity exhaustion remains UNKNOWN.
An already observed FAIL is retained; no uninspected later predicate is certified.
Source/mechanism changes require freshly selected policies and certificates;
previous exact bytes and their genuine verdicts are not rewritten.
