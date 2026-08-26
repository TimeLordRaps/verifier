# Verifier Standard (VSTD)-Graph-4 — Refutable Transformation Closure

> **Acronym:** unsatisfiable (UNSAT).

> Reader aid: [concept glossary and primary precedents](https://github.com/TimeLordRaps/verifier/blob/main/docs/CONCEPTS_AND_PRECEDENTS.md).

**Layer:** 4 of 5 on the graph axis (see `LADDER.md`)
**Status:** implemented candidate computation; rating-evidence binding not implemented
**License:** Apache-2.0

VSTD-Graph-4 closes non-compositional refutability. A collection reaches this
layer only when every member and reachable ancestor is at object layer 4 or
higher, statuses are admissible, and every transformation hyperedge carries
layer-4 evidence including a valid `RefutabilityClosure`.

Two VSTD-4 nodes connected by an unevidenced edge do not make a VSTD-Graph-4
collection. A challenge to the collection output must localize to a member,
ancestor, transformation, or the composition itself.

The UNSAT certificate at the next level is the computed explanation of the candidate
ceiling over caller-supplied ratings. It does not establish Graph-4 conformance or
validate the claimed `RefutabilityClosure` records.
