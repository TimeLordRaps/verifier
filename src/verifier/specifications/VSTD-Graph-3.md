# Verifier Standard (VSTD)-Graph-3 — Accountable Provenance Closure

> Reader aid: [concept glossary and primary precedents](https://github.com/TimeLordRaps/verifier/blob/main/docs/CONCEPTS_AND_PRECEDENTS.md).

**Numbered profile:** VSTD-Graph-3; required closure coordinate: Accountable Provenance Closure (see `LADDER.md`)
**Status:** implemented candidate computation; rating-evidence binding not implemented
**License:** Apache-2.0

VSTD-Graph-3 closes unaccountable substrate across a collection. A collection
satisfies this candidate profile only when every member and reachable ancestor is rated at
object profile 3 or higher, every reachable status is admissible, and every transformation
hyperedge carries profile-3 edge ratings.

The provenance closure condition is normative: rating only the selected members
is insufficient. The weakest reachable ancestor or transformation caps the
collection.

The reference computation consumes caller-supplied ratings and therefore reports a
candidate with conformance `NOT_ESTABLISHED`. Its certificate does not establish that a
VSTD-3 mechanism produced any supplied rating.

VSTD-Graph-3 cannot establish that an outside party could refute the composed
collection. That blind spot is closed by VSTD-Graph-4.
