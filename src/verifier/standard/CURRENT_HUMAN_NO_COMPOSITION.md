# Current HUMAN-3.6: no declared arrangement yields a human

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) specifies the claim; this Python mechanism is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes, and Secure
Hash Algorithm 256-bit (SHA-256) names commitments. Route depth counts declared
arrangement hops and is dimensionless. Counts and checking budgets are
dimensionless.

## Selected row

The pair `verifier-current-object-obligations-1` / `HUMAN-3.6` selects a
bounded, strict subset of this `DOMAIN_OBLIGATIONS.md` requirement, quoted
verbatim:

> HUMAN-3.6 No composition yields a human: "No arrangement of models, agents, bots, simulations or collectives produces a human, at any strength, by any route. This is the one statics row no composition can reach."

It also selects a bounded subset of its prerequisite row:

> HUMAN-3.1 Singularity: "A human is singular and non-copyable and cannot be manufactured on demand. This is what makes Sybil resistance mean anything, and no declaration or adaptation changes it."

## Proposition

The request selects one exact `HUMAN` namespace record, a complete finite typed
collection and the SHA-256 commitment of one retained array of DECLARED
arrangement records. Every kind is read from the typed namespace record, never
from an identifier or label: a `BOT` whose identifier begins `human:` is a
`BOT`, and a `HUMAN` whose identifier begins `bot:` is a `HUMAN`.

The collection must pass namespace composition. `HUMAN` has no composition
contract there, so a record typed `HUMAN` that carries operands, such as a
collective of roles typed as a human, is `FAIL` before any arrangement is read.

Each arrangement record has exactly `arrangement_id`, `arranged`, `output`,
`declared_output_kind` and `strength`. Identifiers are sorted and unique;
`arranged` is a nonempty sorted unique array of collection identifiers; `output`
is a collection identifier outside `arranged`; `declared_output_kind` is a
namespace kind; `strength` is a nonempty label.

The row's "models, agents, bots, simulations or collectives" are the typed kinds
`MODEL`, `AGENT`, `BOT`, `SIM` and `COLLECTIVE`. Each such record is reached at
route depth 0. A record whose namespace operands include a reached record is
reached at that operand's depth, so an `ACTOR` representing a `BOT` is reached.
An arrangement whose least reached constituent has depth d reaches its output
at depth d + 1. This least depth over every route is the reading of "by any
route".

The certificate is `FAIL` when:

1. an arrangement with a reached constituent outputs a typed `HUMAN` record or
   declares `HUMAN` as its output kind; the reason names the least route depth;
2. any other arrangement outputs a typed `HUMAN` record or declares `HUMAN`.
   This is the selected reading of HUMAN-3.1 "cannot be manufactured on demand",
   and the reason cites `HUMAN-3.1`;
3. an arrangement's declared output kind differs from its typed output record.

`strength` is retained and never consulted. This is the reading of "at any
strength": a weak, partial or statistical arrangement is refuted exactly as a
full one.

## Verdicts

`PASS` means no selected declared arrangement yields a typed `HUMAN` record;
`no_composition_yields_human` is then `PASS`. An empty arrangement array is a
vacuous `PASS` over the selected collection. `FAIL` names one counterexample.
Absent arrangement records, absent evidence, or an exhausted operation, item
or byte ceiling is `UNKNOWN`. A malformed request or policy raises
`HumanNoCompositionError` before replay (`REJECTED`).

## Exclusions

These certificates decide properties of declared records only. They never
establish that anyone is a person, that a declared arrangement ran, or that
no undeclared derivation exists. HUMAN-3.1 singularity, non-copyability and
Sybil resistance beyond the declared arrangements stay `NOT_ESTABLISHED`
(`human_singularity`). Personhood, liveness, biometric accuracy, presentation
and injection attack resistance, uniqueness, death as a fact, authority,
consent and privacy are always `NOT_ESTABLISHED`. The whole HUMAN statics tier
and object-profile conformance remain `NOT_ESTABLISHED`.

## Invalidation

The certificate retains the exact evidence bytes, request and replay result.
Public release of retained contents requires separate disclosure authority.
Changed checker source, this specification, `NAMESPACE_OBJECTS.md`, retained
bytes or policy invalidates the pinned mechanism. A digest or trust-root label
is not proof that any arrangement occurred.
