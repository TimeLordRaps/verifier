# Claim boundary

> **Acronyms:** identifier (ID); JavaScript Object Notation (JSON); reduced instruction set computer (RISC);
> Verifier Standard (VSTD); zero-knowledge virtual machine (zkVM).

## Permitted claim after the recorded real-proof run

This optional experiment demonstrates that RISC Zero zkVM 3.0.6 can produce a real,
locally verified zero-knowledge receipt for one fixed bounded predicate, while keeping
the experiment's private witness out of the serialized public artifact package.

The concrete verified statement is:

> The program identified by the expected image ID halted successfully and authenticated
> a journal stating that its private encoded input satisfied the fixed experiment
> predicate and was bound to the journal's subject, policy, challenge, threshold, and
> salted evidence commitment.

The zero-knowledge basis is the selected protocol and implementation, not merely the
absence of witness text from JSON. The artifact scan is an additional serialization
check, not a proof of zero knowledge.

## Prohibited claims

The experiment does not prove:

- that the hidden evidence is true, complete, authentic, fresh, or lawfully obtained;
- that its producer is authorized, unique, independent, honest, or non-revoked;
- that the private `Supported` tag was assigned correctly;
- that the subject or policy digest resolves to trustworthy external content;
- freshness beyond possession of the journal's challenge;
- prevention of replay for the same challenge;
- host confidentiality, constant-time behavior, or side-channel resistance;
- security of every RISC Zero component or transitive dependency;
- independent implementation or external adoption;
- VSTD conformance for this experiment; or
- that VSTD should require zero knowledge for full-disclosure receipts.

An `Unknown` or `Conflicted` experiment input is rejected by this particular predicate.
That rejection does not turn uncertainty into falsity, and it never upgrades either
state into a clean result. Other VSTD mechanisms must continue to preserve `UNKNOWN` and
`CONFLICTED` when those are the evidence-supported outcomes.

## Architecture consequence

The strongest architecture justified by this experiment is an optional, proof-system-
identified privacy profile adjacent to disclosure-neutral VSTD core behavior. No frozen
wire identifier, schema, canonical digest, lifecycle token, console alias, or existing
receipt interpretation changes.
