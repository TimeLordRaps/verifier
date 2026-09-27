# Experimental global-cycle assessment

Verifier Standard (VSTD) global-cycle assessment is a direct-module version 0.1
experiment. It composes separately replayed relation-boundary evidence and
separately source-grounded relation semantics into one exact finite graph. It
keeps three meanings distinct: support/dependency cycles, simultaneous
constraint loops with no chosen causal direction, and explicit clock-relative
temporal relations.

Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit
(SHA-256); identifier (ID). Graph sizes, relation counts, offsets measured in
declared ticks, and IDs are dimensionless. A temporal relation may instead use
nanoseconds, a duration unit equal to one billionth of a second.

## 1. Exact relation inputs

`verifier-global-cycle-assessment-1` contains one to 512 relation entries, sorted
by relation ID. Each entry binds a distinct relation-boundary receipt, its
declaration, a separate semantic-source object, and the source-grounding
declaration and receipt for that semantic source.

Every material bundle also supplies the exact relation artifacts and exact
grounding evidence needed to reproduce both lower-order receipts. Digests bind
roles but do not interpret them. The declaration, relation, semantic source,
grounding declaration, grounding receipt, and grounding certificate must remain
distinct to prevent circular or aliased support.

The semantic source is a canonical wrapper containing exactly
`cycle_relation_semantics`. Its body binds the exact relation declaration and
receipt, source and target proposition IDs plus artifact digests, and exactly
one interpretation:

- `support`: source-to-target `DEPENDENCY`;
- `constraint`: simultaneous `SAME` or `INVERTED` parity; or
- `temporal`: clock ID, signed offset, and `tick` or `nanosecond` unit.

The source-grounding proposition must be `JSON_POINTER_EQUALS` at path
`cycle_relation_semantics` with the exact body as its expected value. Therefore
callers cannot relabel relation kind, endpoint, polarity, clock, unit, or offset
without changing and regrounding the semantic source.

## 2. Assessment facets

The receipt `verifier-global-cycle-assessment-receipt-1` retains its declaration
digest, local checker-source coordinate, exact limits, per-relation replay
results, semantics, residual obligations, and three independent facets:

- support dependencies report directed cycle groups or `ACYCLIC`;
- simultaneous constraints solve the finite parity system and report
  `CONSISTENT` or `CONFLICTED`;
- temporal relations solve clock-relative difference constraints, enumerate
  declared negative-offset backward-time relation IDs, and report
  `CONSISTENT`, `CONFLICTED`, or unit-invalid state.

`assessment_state` is `ASSESSED`, `CONFLICTED`, `UNKNOWN`, or `INVALID`, and
`assessment_complete` is true only after all selected relation and semantic
evidence replays and all three facets finish. A support cycle is a structural
feature, not automatically a conflict. A negative relative offset is a declared
backward-time relation, not evidence of physical retrocausation. A simultaneous
constraint loop has no inferred causal direction.

Missing evidence or exhausted work bounds remains `UNKNOWN`; malformed,
substituted, circular, or contradictory role binding is `INVALID`; a solved
constraint contradiction is `CONFLICTED`. Recheck recomputes the exact complete
receipt and requires byte equality.

Public JSON Schema validation is structural only. It cannot replay lower-order
receipts, establish grounded interpretation, solve the graph, or establish that
the graph models every relevant relation.

## 3. Claim boundary

The assessment covers only the exact finite relations and proposition identities
in its declaration. It does not establish physical causation, truth of a
constraint model, source completeness, open-world acyclicity, safety, authority,
runtime execution, or a numbered VSTD profile. No inert global-cycle profile is
published: the receipt binds its exact declaration, lower-order profiles,
checker-source coordinate, and runtime limits instead.

