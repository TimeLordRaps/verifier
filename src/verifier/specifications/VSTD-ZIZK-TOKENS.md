# Verifier Standard (VSTD) zero-identity/zero-knowledge (ZIZK) token specification

> **Acronyms:** command-line interface (CLI); JavaScript Object Notation (JSON); Request for Comments (RFC); Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD); zero-identity/zero-knowledge (ZIZK).

**Status:** normative specification for zero-identity cryptographic token mechanics
**Date:** 2026-09-17

This specification standardizes the portable, bounded, refutable record format for
actor identity tokens under the zero-identity/zero-knowledge (ZIZK) trust architecture.
In Verifier Standard (VSTD), identity is strictly an adjacent proposition. A computational
verification verdict across the numbered VSTD profiles (VSTD-1 through VSTD-5) depends
solely on inspected artifact bytes, environment bounds, formal specifications, and checking
mechanisms. Actor identity never upgrades, repairs, shortcuts, or validates computational
verification truth.

## 1. Purpose and The Bet

When autonomous software agents propose, execute, and publish verification receipts,
traditional civil identity (Know-Your-Customer or jurisdiction-bound identification)
is inapplicable, intrusive, or easily forged by synthetic personas. Conversely, unanchored
pseudonymity permits costless Sybil replication and unconstrained credential leakage.

VSTD resolves this tension by treating identity as an **adjacent proposition** verified
through bounded cryptographic tokens:

1. **Birth Token (`VSTD-BIRTH-TOKEN-1`)**: Anchors identity creation epoch without leaking civil identity or activity telemetry.
2. **Aging Token (`VSTD-AGING-TOKEN-1`)**: Cryptographically proves continuous, unrevoked tenure across discrete epochs without leaking transaction history.
3. **Lifetime Token (`VSTD-LIFETIME-TOKEN-1`)**: Grants ephemeral, soulbound capability leases for runner delegation with zero blast radius to genesis keys.
4. **Actor Binding (`VSTD-ACTOR-BINDING-1`)**: Records mutual dual-signed edges between an actor and a publisher or operator.

## 2. Prime Invariant: Actor Identity Is Strictly Adjacent

> **Prime Invariant:** An actor identity NEVER upgrades a computational verdict.

A receipt verdict (`VERIFIED`, `FALSIFIED`, `UNKNOWN`, `REJECTED`) is an immutable mathematical
function of the inspected artifact, trace, bounds, and checker kernel. Holding a valid birth
token, an extensive aging tenure, or an authorized lifetime lease confers zero evidentiary
weight upon an unverified claim.

Specifically, verifiers conforming to VSTD MUST NOT:
- Convert an `UNKNOWN` or `CONFLICTED` verdict into `VERIFIED` on the basis of actor standing.
- Soften a falsified proof into an indeterminate result because an actor is reputable.
- Skip verification steps or bypass timeout bounds for privileged keys.
- Allow an actor key to notarize a receipt without holding the separate publisher signing key.

## 3. The Three-Token Zero-Knowledge Lifecycle

### 3.1 Birth Token (`VSTD-BIRTH-TOKEN-1`)

A Birth Token records the genesis commitment of an actor identity.

- **Wire Identifier:** `schema_version = "VSTD-BIRTH-TOKEN-1"`
- **Genesis Commitment:** Commitment C equals SHA-256 over genesis secret key, birth epoch, and salt.
- **Semantics:** Establishes that the controlling key existed at or before birth epoch. It establishes no civil identity, no real-world reputation, and no authorization over any target artifact.

### 3.2 Aging Token (`VSTD-AGING-TOKEN-1`)

An Aging Token proves continuous, unrevoked tenure across N discrete verification epochs.

- **Wire Identifier:** `schema_version = "VSTD-AGING-TOKEN-1"`
- **Tenure Accumulator:** Accumulator A_t equals SHA-256 over A_{t-1}, epoch t, and status.
- **Semantics:** Proves an identity has survived across epochs without revocation. It leaks no activity logs, no receipt history, and no transaction telemetry.

### 3.3 Lifetime Token (`VSTD-LIFETIME-TOKEN-1`)

A Lifetime Token is an ephemeral, soulbound capability lease delegated to a runner worker or subagent.

- **Wire Identifier:** `schema_version = "VSTD-LIFETIME-TOKEN-1"`
- **Bounding Invariant:** The lease is restricted to explicitly listed `permitted_scopes`, cannot be re-delegated (`soulbound = true`), and becomes invalid after expiry.
- **Semantics:** Allows temporary automated execution with strictly bounded blast radius. If compromised, the runner key cannot rotate the actor genesis key or act outside its permitted scopes.

### 3.4 Actor Binding (`VSTD-ACTOR-BINDING-1`)

An Actor Binding records an attribution or control relationship between two distinct identities.

- **Wire Identifier:** `schema_version = "VSTD-ACTOR-BINDING-1"`
- **Mutual Signature:** Requires signatures from both parties over an immutable normative proposition literal.
- **Semantics:** Establishes only that both keys signed the exact stated proposition at this hub at this time. It establishes no real-world identity, no mutual endorsement of claims, and no transfer of verification truth.

## 4. The 16 Prohibited Inferences

Conforming evaluators MUST enforce the following 16 prohibited inferences without exception:

1. Absent civil identity implies anonymity or unlinkability.
2. A pseudonym implies a distinct actor.
3. A shared pseudonym implies a single actor.
4. Two distinct pseudonyms imply two independent actors.
5. A verified signature implies authorization.
6. A grant implies that the authority is currently active.
7. Absent revocation evidence implies active authority.
8. Absent uniqueness evidence implies Sybil resistance.
9. Hashing, redaction, encryption, omission, or pseudonymity alone implies zero identity.
10. Disclosure minimization preserves the original claim boundary.
11. Missing evidence implies safety.
12. A signer is the author of the claim.
13. A relayed, delegated, or aggregated claim is first-party authorship.
14. An absent authorship role means degree zero.
15. A recorded ancestry chain establishes that authority survived every hop.
16. Actor standing, tenure, or token validity implies verification correctness.

## 5. Conformance and Offline Evaluation

Zero-identity tokens MUST evaluate offline without external network or hub dependencies.
When required coordinates are missing, evaluation MUST fail closed to `UNKNOWN`. When evidence
contradicts a property, evaluation MUST yield `REFUTED` (overall verdict `REJECTED`).
