# VSTD-Graph-3 — Accountable Provenance Closure

> Reader aid: [concept glossary and primary precedents](https://github.com/TimeLordRaps/verifier/blob/main/docs/CONCEPTS_AND_PRECEDENTS.md).

**Layer:** 3 of 5 on the graph axis (see `LADDER.md`)
**Status:** implemented computed profile
**License:** Apache-2.0

VSTD-Graph-3 closes unaccountable substrate across a collection. A collection
reaches this layer only when every member and reachable ancestor is at object
layer 3 or higher, every reachable status is admissible, and every transformation
hyperedge carries layer-3 edge evidence.

The provenance closure condition is normative: rating only the selected members
is insufficient. The weakest reachable ancestor or transformation caps the
collection.

VSTD-Graph-3 cannot establish that an outside party could refute the composed
collection. That blind spot is closed by VSTD-Graph-4.
