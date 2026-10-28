# Current ACTOR closure result

Status: experimental, versioned, bounded objective. Verifier Standard (VSTD)
names the claim; the Python mechanism is a reference implementation. JavaScript
Object Notation (JSON) bytes are canonicalized and committed with Secure Hash
Algorithm 256-bit (SHA-256). Positions, decision counts and operation counts
are dimensionless; byte ceilings count encoded bytes.

`verifier-current-object-obligations-1` / `ACTOR-4.6` grounds one bounded,
strict subset of this row of `DOMAIN_OBLIGATIONS.md`, quoted verbatim:

> The inventory, the attributions and their independence are reported together; a closure missing any of the three is incomplete rather than passing.

The row depends on `ACTOR-4.3`, `ACTOR-4.4` and `ACTOR-4.5`, which depend on
`ACTOR-4.1` and `ACTOR-4.2`. Those rows are checked only as the finite
component predicates below; none of them is emitted.

## Selection

The external request independently selects an exact ACTOR identifier and
namespace-record digest, the complete typed-collection digest, the digests of a
retained inventory, attributions and independence component, an evidence byte
reference, a policy digest and finite checking limits. The evidence bundle has
exact fields `schema_version`, `objects` and `inputs`; `inputs` is absent or
`null` (UNKNOWN), or an object whose keys are drawn from `inventory`,
`attributions` and `independence`. A key that is absent or `null` marks that
component `ABSENT`. Each present component is rehashed and must equal its
selected digest.

An object's kind is read from its typed namespace record, never from its
identifier.

## Components

Each component is evaluated and reported in
`observations.closure.components` with status `PASS`, `FAIL`, `UNKNOWN` or
`ABSENT`.

- **inventory** (from `ACTOR-4.1`): `{"interval", "decision_classes",
  "decisions"}`; decisions have unique identifiers, a stated position and a
  class, and their positions are exactly the declared interval, one each.
- **attributions** (from `ACTOR-4.2` to `ACTOR-4.4`): each names a decision, an
  actor resolving to a typed ACTOR record and a sorted list of cited records; no
  decision is attributed twice; with the inventory present, every attributed
  decision is inventoried and every decision in the declared classes is
  attributed. Without the inventory, coverage is `UNKNOWN`.
- **independence** (from `ACTOR-4.5`): `{"records"}`, each with a unique
  identifier and a nonempty sorted list of controllers resolving to typed ACTOR
  records. An attribution citing only records whose sole controller is its
  actor refutes; one citing nothing, an unretained record, or a mix of such a
  record and another, is `UNKNOWN`. Without attributions it is `UNKNOWN`.

## Verdicts

Any `FAIL` component makes the closure `FAIL`, even beside a missing one. Else
any `ABSENT` or `UNKNOWN` component makes it `UNKNOWN`: a closure missing any of
the three is incomplete rather than passing. Only three present, passing
components give `PASS`. An exhausted operation, item, decision, record or byte
limit yields `UNKNOWN`. A malformed or substituted policy, request or
certificate is rejected before any computational verdict.

`PASS` does not establish that the inventory is every decision the actor took,
that any decision happened, that a cited record's declared controllers are its
real ones, or joint accountability through a collective. The result carries
`closure_result`, `PASS` only on a pass. Personhood, real-world completeness,
record authenticity, authority, consent, the whole ACTOR closure tier and
`object_profile_conformance` are always `NOT_ESTABLISHED`.

The external policy binds the installed implementation and this specification
by a mechanism digest, selected trust-root labels and a certificate byte
ceiling. Offline recheck needs the independently selected request and policy,
re-executes the installed mechanism and compares complete certificate bytes.
