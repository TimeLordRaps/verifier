# Claim boundary

> **Acronyms:** identifier (ID); JavaScript Object Notation (JSON); reduced instruction set computer (RISC);
> Verifier Standard (VSTD); zero-identity/zero-knowledge (ZIZK);
> zero-knowledge virtual machine (zkVM).

## Permitted claim after the recorded real-proof run

This bounded reference mechanism demonstrates that RISC Zero zkVM 3.0.6 can produce a real,
locally verified zero-knowledge receipt for one fixed bounded predicate, while keeping
the mechanism's private witness out of the serialized public artifact package.

The concrete verified statement is:

> The program identified by the expected image ID halted successfully and authenticated
> a journal stating that its private encoded input satisfied the fixed mechanism
> predicate and was bound to the journal's subject, policy, challenge, threshold, and
> salted evidence commitment.

The repository's governed offline command additionally builds the tracked guest with
the locked toolchain and refuses the receipt unless that build's image ID equals the
recorded image ID. Proof verification alone binds an image identifier; this separate
comparison is what connects the tracked source-facing build to that identifier.

The zero-knowledge basis is the selected protocol and implementation, not merely the
absence of witness text from JSON. The artifact scan is an additional serialization
check, not a proof of zero knowledge.

## Prohibited claims

The reference mechanism does not prove:

- that the hidden evidence is true, complete, authentic, fresh, or lawfully obtained;
- that its producer is authorized, unique, independent, honest, or non-revoked;
- that the private `Supported` tag was assigned correctly;
- that the subject or policy digest resolves to trustworthy external content;
- freshness beyond possession of the journal's challenge;
- prevention of replay for the same challenge;
- host confidentiality, constant-time behavior, or side-channel resistance;
- security of every RISC Zero component or transitive dependency;
- independent implementation or external adoption;
- VSTD conformance for this mechanism; or
- that VSTD should require zero knowledge for full-disclosure receipts.

An `Unknown` or `Conflicted` mechanism input is rejected by this particular predicate.
That rejection does not turn uncertainty into falsity, and it never upgrades either
state into a clean result. Other VSTD mechanisms must continue to preserve `UNKNOWN` and
`CONFLICTED` when those are the evidence-supported outcomes.

## Architecture consequence

This mechanism implements one bounded proof-carrying privacy path under VSTD's governing
ZIZK artifact-first architecture. Specifically, it places a cryptographic zero-knowledge
enclosure around the architectural rule that no unevidenced proposition is presumed. The
proof binds one exact program, predicate, public commitment set, output, parameter set,
and verifier while withholding its witness; prover identity and reputation add no TRUST,
VSTD's formal name for mechanism-earned artifact support.
It neither creates the architecture nor makes its specific proof system mandatory. No
serialized receipt identifier, schema, canonical digest, lifecycle token, console alias, or
existing receipt interpretation changes.
