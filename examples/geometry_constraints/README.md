# Explicit geometry constraints

Verifier Standard (VSTD); Boolean satisfiability problem (SAT); unsatisfiable
(UNSAT); conjunctive normal form (CNF); reverse unit propagation (RUP).
Boolean values here are dimensionless, two-valued configuration choices.

This experimental follow-on connects exact VSTD-2 geometry coordinates to explicit
Boolean clauses and the existing bounded proof-producing solver and proof checker.
It is unreleased 2.0.0 source, not a new receipt format or a general
translation from domain knowledge to logic. No optional dependency is required.

From a source checkout with `src` on `PYTHONPATH`, run:

```text
python -u -B -S examples/geometry_constraints/demo.py
```

The fictional menu has compact-layout and icon choices. Its two coordinate
judgments stay `INDETERMINATE` in every case:

| Explicit interpretation | Expected result | What it establishes |
|---|---|---|
| Select compact layout; compact requires icons | `SAT` | A directly checked assignment satisfies these clauses. |
| Also disable icons | `UNSAT` | The existing `VSTD4-RUP-1` checker accepts a refutation of these clauses. |
| Select compact or icons, with zero decision depth | `UNKNOWN` | The bounded search did not establish either outcome. |

No clause is inferred from a judgment, label, dependency edge, missing evidence,
or similarly named coordinate. A positive literal means the caller-declared
proposition holds within this interpretation; negation is explicit. Clauses are
disjunctions joined by conjunction. An empty clause is false; an empty clause
set is true. The declarations themselves are assumptions, not verified premises.

## Consumer-controlled checking

Import `SignedProposition`, `GeometryClause`, `GeometryConstraintBounds`,
`prepare_geometry_constraints`, `solve_geometry_constraints`, and
`recheck_geometry_constraints` directly from
`verifier.interoperability.geometry_constraints`. They are experimental direct
imports, not supported facade exports.

Preparation accepts canonical geometry bytes, explicit `SharedPropositionIdentity`
bindings, and named clauses. The problem digest binds the exact geometry snapshots,
coordinate-to-proposition mapping, and clauses, not just their numeric encoding.
The consumer selects the expected problem digest before checking an outcome.
Taking the expected digest from an untrusted outcome would lose that boundary.

Rechecking reconstructs the encoding and checks a model or the existing proof
without calling the solver. A valid proof of unrelated clauses is insufficient;
even a binding change leaving the numeric formula unchanged changes the problem
identity. Geometry changes require fresh preparation and checking. Resource
limits remain consumer-selected; malformed input or rejected evidence is not
silently relabeled `UNKNOWN` or accepted.
An `UNKNOWN` result has no witness. Rechecking that record preserves uncertainty;
it does not prove a producer actually ran or exhausted its historical budget.

Admission is limited to four geometries totaling 262,144 bytes, 32 propositions,
128 clauses and 1,024 literals. Search defaults to decision depth 10 and 256 proof
steps; additional conservative work estimates can stop search or checking earlier.
These are calculation bounds, not a wall-clock deadline or process sandbox.

This is solver/proof/checker composition inside one implementation, not independent
operator evidence. Neither consistency nor contradiction validates the meaning of
the declarations, proves native adapter compatibility, closes a verification
surface hole, establishes physical safety, or authorizes execution. Existing
structural conflict diagnostics and graph temporal/equation analysis are unchanged.

Targeted regression checks:

```text
python -u -m pytest tests/test_geometry_constraints.py tests/test_geometry_constraints_example.py -vv -s --durations=10 --timeout=60
```
