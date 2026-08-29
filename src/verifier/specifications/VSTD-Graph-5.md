# Verifier Standard (VSTD)-Graph-5 — Corroborated Verification Network

> Reader aid: [concept glossary and primary precedents](https://github.com/TimeLordRaps/verifier/blob/main/docs/CONCEPTS_AND_PRECEDENTS.md).

**Numbered profile:** VSTD-Graph-5; required closure coordinate: Corroborated Verification Network (see `LADDER.md`)
**Status:** project specification with implemented candidate and evidence-bound reference paths
**License:** Apache-2.0

VSTD-Graph-5 is the collection profile for independently corroborated members,
ancestors, and transformations. The candidate-profile computation requires
object and edge ratings of at least 5, provenance closure, and admissible status
throughout.

The compatibility implementation computes this profile over externally supplied
profile-5 ratings and reports `NOT_ESTABLISHED`. The evidence-bound path can establish
it only when registered mechanisms rerun exact VSTD-5 member/ancestor ratings and
profile-5 transformation ratings from embedded evidence. Every rating is bound to the
exact Graph bytes, deduplicated member set, collection identifier, and claim binding. A result based on
self-declared ratings is not VSTD-Graph-5
conformance.

Conflicting witness records are retained as conflict records and make the relevant
subject inadmissible to a clean candidate Graph profile. They are never averaged into
a passing collection.
