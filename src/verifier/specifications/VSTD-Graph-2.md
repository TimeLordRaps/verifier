# Verifier Standard (VSTD)-Graph-2 — Bounded Collection Surface

> Reader aid: [concept glossary and primary precedents](https://github.com/TimeLordRaps/verifier/blob/main/docs/CONCEPTS_AND_PRECEDENTS.md).

**Numbered profile:** VSTD-Graph-2; required closure coordinate: Bounded Collection Surface (see `LADDER.md`)
**Status:** project specification with implemented candidate and evidence-bound reference paths
**License:** Apache-2.0

VSTD-Graph-2 closes collection-scope leakage. A collection satisfies this candidate
profile only when every member and provenance ancestor is rated at object profile 2 or
higher, every reachable status is admissible, and every transformation hyperedge
carries profile-2 edge ratings.

`verifier.data.graph_level.graph_level` computes a candidate from caller-supplied ratings and marks
conformance `NOT_ESTABLISHED`. `establish_graph_level` instead reruns exact member,
ancestor, and edge rating propositions from embedded evidence through registered
mechanisms; only that path may report `MECHANISM_EVALUATED` and `ESTABLISHED`. The
rating propositions bind one digest over the exact historical Graph, deduplicated member
set, collection identifier, and Graph claim binding. A neighboring collection, topology,
or claim therefore contributes rating zero. Profile zero is never established. The
`FAIL` certificate for Graph profile 2 names the member,
ancestor, status, or edge obligation that prevents admission under those inputs. It does
not validate the ratings themselves.

VSTD-Graph-2 does not establish that the evidence sources behind the collection
are accountable. That is the blind spot closed by VSTD-Graph-3.
