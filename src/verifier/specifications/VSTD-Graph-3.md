# Verifier Standard (VSTD)-Graph-3 — Accountable Provenance Closure

> Reader aid: [concept glossary and primary precedents](https://github.com/TimeLordRaps/verifier/blob/main/docs/CONCEPTS_AND_PRECEDENTS.md).

**Numbered profile:** VSTD-Graph-3; required closure coordinate: Accountable Provenance Closure (see `LADDER.md`)
**Status:** project specification with implemented candidate and evidence-bound reference paths
**License:** Apache-2.0

VSTD-Graph-3 closes unaccountable substrate across a collection. A collection
satisfies this candidate profile only when every member and reachable ancestor is rated at
object profile 3 or higher, every reachable status is admissible, and every transformation
hyperedge carries profile-3 edge ratings.

The provenance closure condition is normative: rating only the selected members
is insufficient. The weakest reachable ancestor or transformation caps the
collection.

The compatibility computation consumes caller-supplied ratings and therefore reports a
candidate with conformance `NOT_ESTABLISHED`. `establish_graph_level` reruns a registered
mechanism over the exact evidence bytes for every member, ancestor, and transformation
rating; missing, failed, uncertain, neighboring, or out-of-closure bindings contribute
zero and prevent conformance. Every proposition also binds the exact Graph bytes,
deduplicated member set, collection identifier, and claim binding.

VSTD-Graph-3 cannot establish that an outside party could refute the composed
collection. That blind spot is closed by VSTD-Graph-4.
