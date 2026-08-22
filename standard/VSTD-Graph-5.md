# VSTD-Graph-5 — Corroborated Verification Network

**Layer:** 5 of 5 on the graph axis (see `LADDER.md`)
**Status:** DRAFT profile; computation is implemented, witness protocol is not
**License:** Apache-2.0

VSTD-Graph-5 is the collection profile for independently corroborated members,
ancestors, and transformations. The computed graph-level mechanism requires
object and edge ratings of at least 5, provenance closure, and admissible status
throughout.

Because VSTD-5 is draft, the reference implementation can compute this profile
only over externally supplied level-5 ratings; it does not manufacture or verify
their independence. A result based on self-declared ratings is not VSTD-Graph-5
conformance.

Conflicting witness records degrade the relevant object status and therefore the
computed collection level. They are never averaged into a passing collection.
