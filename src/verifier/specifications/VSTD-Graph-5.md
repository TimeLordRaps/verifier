# Verifier Standard (VSTD)-Graph-5 — Corroborated Verification Network

> Reader aid: [concept glossary and primary precedents](https://github.com/TimeLordRaps/verifier/blob/main/docs/CONCEPTS_AND_PRECEDENTS.md).

**Numbered profile:** VSTD-Graph-5; required closure coordinate: Corroborated Verification Network (see `LADDER.md`)
**Status:** DRAFT profile; computation is implemented, witness protocol is not
**License:** Apache-2.0

VSTD-Graph-5 is the collection profile for independently corroborated members,
ancestors, and transformations. The candidate-profile computation requires
object and edge ratings of at least 5, provenance closure, and admissible status
throughout.

Because VSTD-5 is draft, the reference implementation can compute this profile
only over externally supplied profile-5 ratings; it does not manufacture or verify
their independence. A result based on self-declared ratings is not VSTD-Graph-5
conformance.

Conflicting witness records are retained as conflict records and make the relevant
subject inadmissible to a clean candidate Graph profile. They are never averaged into
a passing collection.
