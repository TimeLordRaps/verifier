# Artifact-first reference surfaces

> **Acronyms:** reduced instruction set computer (RISC); Verifier Standard (VSTD);
> zero-identity/zero-knowledge (ZIZK).

VSTD's governing ZIZK artifact-first architecture is normative in
[`standard/LADDER.md` section 1.1](../../standard/LADDER.md#11-artifact-first-support-and-diagnostic-orientation).
It gives actor identity and reputation no assurance weight, treats actor and artifact as
contextual roles, carries bounded Artifact support forward, and carries diagnostic Rust
backward without scalar cancellation or inherited guilt.

This directory contains bounded reference mechanisms under that architecture. A
mechanism may be optional without making the architecture optional.

## Bounded identity-disclosure evaluator

[`zero_identity/`](zero_identity/) is a standard-library reference evaluator that
preserves the identity, authorization, provenance, `UNKNOWN`, and `CONFLICTED`
boundaries exposed by a disclosure record. It earns no identity-derived trust, carries
no wire identifier, and establishes no VSTD conformance result.

## RISC Zero hidden-witness mechanism

[`risc0/`](risc0/) contains the pinned Rust prover/verifier, its claim boundary and
threat model, and the exact tracked public artifacts from one real composite scalable
transparent argument of knowledge proof. The private witness is excluded. Start with
[`risc0/README.md`](risc0/README.md) to verify the recorded receipt offline.

The proof establishes only execution of its fixed hidden-witness predicate under the
named image identifier and proof-system assumptions. It does not establish external
truth, identity, authorization, independence, complete VSTD trichotomy semantics, or a
general VSTD conformance result.
