# Current ACTOR decision-record retention

Status: experimental, versioned, bounded objective. Verifier Standard (VSTD)
names the claim; the Python mechanism is a reference implementation. JavaScript
Object Notation (JSON) bytes are canonicalized and committed with Secure Hash
Algorithm 256-bit (SHA-256). Positions, decision counts and operation counts
are dimensionless; byte ceilings count encoded bytes.

`verifier-current-object-obligations-1` / `ACTOR-3.3` grounds one bounded,
strict subset of this row of `DOMAIN_OBLIGATIONS.md`, quoted verbatim:

> Past decisions remain the actor's own after revocation, rotation or dissolution. Ending an actor's capacity to decide never ends its record of having decided.

The row depends on `ACTOR-3.1` and `ACTOR-3.2`. Neither is emitted here.

## Selection

The external request independently selects an exact ACTOR identifier and
namespace-record digest, the complete typed-collection digest, the digests of a
retained earlier decision record, a declared event window and a retained later
decision record, an evidence byte reference, a policy digest and finite
checking limits. The evidence bundle has exact fields `schema_version`,
`objects` and `inputs`; `inputs` is absent or `null` (UNKNOWN), or an object
with exact keys `earlier`, `events` and `later`. A missing key is UNKNOWN. Each
retained input is rehashed and must equal its selected digest.

An object's kind is read from its typed namespace record, never from its
identifier.

## Check

Each decision record is `{"head_position", "decisions"}`. Each decision has a
unique `decision_id`, a `position` (strictly increasing, at most the head), an
`actor` resolving to a typed ACTOR record and a `content_digest` commitment.
The later head is not before the earlier head.

The window holds `delegation`, `revocation`, `rotation` and `dissolution`
events, each after the earlier head and at most the later head, in strictly
increasing position, each actor resolving to a typed ACTOR record. A window
holding a membership or succession event is outside this row and is UNKNOWN.
The row's premise must hold: the window has at least one revocation, rotation or
dissolution, and the selected ACTOR has at least one earlier decision;
otherwise the result is UNKNOWN.

Then every earlier decision, of every actor, must occur in the later record
with the same identifier, position, accountable actor and content commitment. A
dropped decision, a re-dated decision, accountability moved to another actor,
or a rewritten content commitment each refutes.

## Verdicts

`PASS` establishes only that, across this finite declared window, the later
retained record keeps every earlier retained decision as the same actor's own.
It does not establish that any decision happened or that either record is
complete; decisions added to the later record, including backdated insertions,
are outside this certificate. Absent inputs, an unmet premise, an out-of-scope
event, or an exhausted operation, item, decision, event or byte limit yields
`UNKNOWN`. A malformed or substituted policy, request or certificate is
rejected before any computational verdict.

The result carries `decision_record_retention`, `PASS` only on a pass.
Personhood, real-world completeness, record authenticity, authority, consent,
the whole ACTOR statics tier and `object_profile_conformance` are always
`NOT_ESTABLISHED`.

The external policy binds the installed implementation and this specification
by a mechanism digest, selected trust-root labels and a certificate byte
ceiling. Offline recheck needs the independently selected request and policy,
re-executes the installed mechanism and compares complete certificate bytes.
