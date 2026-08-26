# Verifier Standard (VSTD)-Graph-2 — Bounded Collection Surface

> Reader aid: [concept glossary and primary precedents](https://github.com/TimeLordRaps/verifier/blob/main/docs/CONCEPTS_AND_PRECEDENTS.md).

**Layer:** 2 of 5 on the graph axis (see `LADDER.md`)
**Status:** implemented candidate computation; rating-evidence binding not implemented
**License:** Apache-2.0

VSTD-Graph-2 closes collection-level scope leakage. A collection reaches this
layer only when every member and provenance ancestor is at object layer 2 or
higher, every reachable status is admissible, and every transformation hyperedge
carries layer-2 edge evidence.

`verifier.data.graph_level` computes a candidate from caller-supplied ratings and marks
conformance `NOT_ESTABLISHED`. The `FAIL` certificate for Graph layer 2 names the member,
ancestor, status, or edge obligation that prevents admission under those inputs. It does
not validate the ratings themselves.

VSTD-Graph-2 does not establish that the evidence sources behind the collection
are accountable. That is the blind spot closed by VSTD-Graph-3.
