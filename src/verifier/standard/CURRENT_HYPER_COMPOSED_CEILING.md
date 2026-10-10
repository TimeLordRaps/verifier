# Current HYPER-3.1: composed ceiling from selected operand tier prefixes

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) specifies the claim; this Python mechanism is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes, and Secure
Hash Algorithm 256-bit (SHA-256) names commitments. Byte limits are bytes.
Meta-tiers, depths, counts and checking budgets are dimensionless integers.

## Row

The pair `verifier-current-object-obligations-1` / `HYPER-3.1` decides a
bounded strict subset of this row of `DOMAIN_OBLIGATIONS.md` (line 622):

> | HYPER-3.1 | Composed ceiling | The weakest operand bound is the composed ceiling, whatever the composed object declares. | none | statics:ceiling |

`META_TIERS.md` lines 394-396 give the same rule in prose.

## Proposition

The checker takes one exact HYPER record in an exact retained typed
collection. Every selected child certificate must be bound to one distinct
direct operand record, sit on that operand's own kind ladder, and replay `PASS`
through the registered current-object route. Each direct operand's bound is
the largest `k` such that selected children at meta-tiers 1 through `k` all
replay `PASS`; the bound is zero when tier 1 is not selected. The composed
ceiling is the minimum of those bounds, whatever the HYPER payload declares.
The payload's `declared_depth` must be a nonnegative integer that is not above
that ceiling.

## Grounding

- **Legacy check.** The legacy statics check (`domains/statics.py` line 95
  and lines 495-507) recomputes the ceiling as the minimum over operand
  depths. It refuses a `declared_depth` above it ("the composition claims a
  depth no operand established").
- **Operand depths come from replay.** The legacy check takes caller-supplied
  operand depths. This objective instead derives each operand's depth by
  replaying the selected child certificates.
- **Depth is an uninterrupted prefix.** It follows the definitions in
  `LADDER.md` line 70 ("count upward only while every required coordinate
  remains established") and `META_TIERS.md` line 1000 (the "largest
  uninterrupted established prefix, or zero").
- **No skipping gaps.** A tier selected after a gap is not counted.

The legacy `HYPER-3.1` (`statics:ceiling`) is a different semantic version.
It is not relabelled.

## Mechanism

The request, the retained evidence and the binding checks are those of
`CURRENT_HYPER_UNKNOWN_ABSORPTION.md`, with these differences:

- Selections are unique and sorted by target, then meta-tier. One target may
  have one selection per tier.
- A selection whose coordinate names a kind other than the operand's own
  kind is `FAIL`.

The order of decisions is:

1. Every binding check finishes before any replay.
2. A selected child that replays `UNKNOWN` or is unavailable makes the result
   `UNKNOWN`.
3. Otherwise a selected child that replays `FAIL`, or that does not replay,
   makes it `FAIL`.
4. The ceiling is then the minimum over the direct operands' prefixes.
5. A missing `declared_depth` is `UNKNOWN`, as with the legacy `need`.
6. A non-integer, Boolean, float or negative declaration is `FAIL`, and so is
   a declaration above the ceiling.

The observations always report the computed ceiling. A declaration can never
raise or lower it.

## Exclusions

`PASS` counts only selected children. It is not an object profile depth over
every required coordinate of an operand's tiers, and it is not a closure of
any tier. The result keeps all of the following `NOT_ESTABLISHED`:

- substrate recurrence, decider exteriority, manufacture impossibility and
  level independence (`HYPER-3.2` to `HYPER-3.5`);
- the whole HYPER statics tier;
- object profile depth and object-profile conformance;
- authority, privacy, consent, governance and security.

Strength order and absorption beyond the selected children (`HYPER-2`) are
not decided.

## Invalidation

Any change to the following invalidates the pinned mechanism:

- the selected HYPER record or its declaration;
- the collection, child selections or retained child bytes;
- the policy or limits;
- this module or `hyper_unknown_absorption.py`;
- `current_object_routes.py`;
- `NAMESPACE_OBJECTS.md`, `DOMAIN_OBLIGATIONS.md`, `LADDER.md`, `META_TIERS.md`,
  `CURRENT_HYPER_UNKNOWN_ABSORPTION.md` or this specification.
