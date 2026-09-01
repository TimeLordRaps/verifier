# Verifier Standard (VSTD)-Graph-4 — Refutable Transformation Closure

> **Acronym:** unsatisfiable (UNSAT).

> Reader aid: [concept glossary and primary precedents](https://github.com/TimeLordRaps/verifier/blob/main/docs/CONCEPTS_AND_PRECEDENTS.md).

**Numbered profile:** VSTD-Graph-4; required closure coordinate: Refutable Transformation Closure (see `LADDER.md`)
**Status:** project specification with implemented candidate and evidence-bound reference paths
**License:** Apache-2.0

VSTD-Graph-4 closes non-compositional refutability. A collection satisfies this candidate
profile only when every member and reachable ancestor is rated at object profile 4 or
higher, statuses are admissible, and every transformation hyperedge carries
profile-4 ratings including a valid `RefutabilityClosure`.

Two VSTD-4 nodes connected by an unevidenced edge do not make a VSTD-Graph-4
collection. A challenge to the collection output must localize to a member,
ancestor, transformation, or the composition itself.

The unsatisfiable (UNSAT) certificate at the next profile is the computed explanation of the candidate
ceiling over caller-supplied ratings. It does not establish Graph-4 conformance or
validate the claimed `RefutabilityClosure` records.
The evidence-bound path reruns every exact rating mechanism and embeds the proposition
bindings and evidence bytes for offline replay. Those bindings commit to the exact Graph,
deduplicated members, collection identifier, and claim binding. A Graph-4 edge rating mechanism must
actually check the applicable `RefutabilityClosure`; naming one is insufficient.
