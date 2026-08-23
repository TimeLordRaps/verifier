# Threat model

**Scope:** the optional zero-knowledge experiment only.

## Protected secret

The intended secret is the private witness supplied to the pinned guest: evidence
bytes, a 32-byte salt, a measurement, and an experiment-local candidate state. The
receipt intentionally reveals the public journal. Subject, policy, challenge,
threshold, predicate result, and salted evidence commitment are not secrets.

## Trust roots

Acceptance depends on all of the following:

1. the expected RISC Zero image ID obtained from the reviewed guest ELF;
2. RISC Zero zkVM 3.0.6 verification code and its proof-system parameters;
3. the pinned Rust sources and `Cargo.lock`;
4. SHA-256 collision and preimage resistance for the public digests;
5. correct public-statement comparison after receipt verification; and
6. a verifier obtaining the expected image ID independently rather than trusting an
   unbound metadata field supplied by the prover.

The composite STARK uses transparent public setup. Its non-interactive security relies
on the proof system's Fiat-Shamir construction and its documented hash assumptions.
This repository does not independently prove the cryptographic reduction.

## Attacks tested

| Attack | Required result |
|---|---|
| private measurement below threshold | proof attempt rejected |
| private `Unknown` candidate state | proof attempt rejected |
| private `Conflicted` candidate state | proof attempt rejected |
| mutated public threshold | wrapper verification rejected |
| different subject or challenge | statement transplantation rejected |
| wrong image ID | receipt verification rejected |
| corrupted receipt bytes | decoding or verification rejected |
| authenticated journal mutation | receipt verification rejected |
| private byte strings copied to public files | serialization scan rejected |

## Residual risks

### Host compromise and operational leakage

The proof system hides guest inputs from a receipt verifier. It does not protect the
witness from the prover's operating system, shell history, swap, crash dumps, malware,
debuggers, or a modified host binary. The manual workflow writes a temporary private
JSON file and requires the operator to protect and remove it.

### Side channels

The experiment does not claim constant-time host behavior, traffic-analysis resistance,
or protection from proof-time, memory-use, file-size, power, or hardware side channels.
The evidence length is hidden by the proof but could be correlated with prover-side
observations.

### Low-entropy evidence

The public commitment includes a private random 32-byte salt to impede offline guessing.
Weak or reused salts, disclosure of the salt, or host compromise can make low-entropy
evidence guessable. The proof does not certify salt quality.

### Replay and freshness

The public challenge is authenticated by the journal, so a proof cannot be transplanted
to a different challenge without rejection. The same valid proof can still be replayed
for the same challenge. Challenge issuance, uniqueness, expiry, clock trust, and replay
storage are outside this experiment and must remain explicit assumptions or UNKNOWN.

### Parser and denial of service

Receipt and envelope reads have size limits. MessagePack is used because RISC Zero's
receipt documentation recommends a serde format with depth limits for untrusted input.
The experiment does not establish a complete resource-exhaustion bound for all malformed
receipts.

### Supply chain

Version pins and a committed lock file constrain dependencies but do not independently
audit every transitive crate, compiler binary, installer, or build host. Reproducing an
image ID on another trusted build host is useful evidence, not supplied here as an
independent implementation.

### Semantic overreach

A prover selects the private bytes and candidate tag. The proof does not show that those
bytes are truthful, complete, authorized, fresh, legally valid, independently sourced,
or causally connected to the real world. It proves only execution of the fixed predicate
over the committed input.
