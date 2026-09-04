# Non-critical interoperability compositions

> **Acronyms:** reverse unit propagation (RUP); Boolean satisfiability problem (SAT);
> Secure Hash Algorithm 256-bit (SHA-256); Supply Chain Integrity, Transparency, and Trust (SCITT);
> Verifier Standard (VSTD).

These examples execute bounded combinations of verifier-like components while retaining
each native result and the exact artifact digest at every transition. They are teaching
surfaces, not evidence that composition automatically creates safety, independence,
correctness, or authority to act.

## 1. Proof-producing solver to proof checker

[`refutation_chain.py`](refutation_chain.py) uses a four-clause Boolean satisfiability
problem (SAT) that is unsatisfiable (UNSAT), meaning it has no satisfying assignment. The bounded solver and proof producer are
fused in `ProofProducingDPLL`; its reverse unit propagation (RUP) proof is then checked by
the separate `RefutationChecker` algorithm:

```text
conjunctive-normal-form formula
  -> proof-producing solver: UNSAT + exact proof bytes
  -> proof checker: ACCEPTED or REJECTED
```

Run it after installing this checkout:

```bash
python examples/interoperability_compositions/refutation_chain.py
```

The report binds the formula and proof with Secure Hash Algorithm 256-bit (SHA-256)
digests plus the exact registry digest and component entry points. The checker reconstructs
its input from the canonical transition bytes and rejects any artifact, implementation,
or catalog-coordinate mismatch before checking. Canonical but malformed formula structures
produce a typed rejection rather than an uncaught checker exception. Solver/prover fusion is explicit. The checker runs in the same
Python process and package, so matching results do not establish actor, implementation, or
runtime independence. A changed formula, forged proof, changed transition, or exhausted
proof bound cannot retain `PASS`.

## 2. VSTD result beside SCITT registration evidence

The existing [SCITT example](../scitt_interop/) executes the other non-critical
composition. Supply Chain Integrity, Transparency, and Trust (SCITT) signature and
registration evidence is verified under ephemeral test keys, then composed beside an
exact Verifier Standard (VSTD) result. Neither side replaces or upgrades the other's
native semantics; registration does not establish payload truth or VSTD conformance.

These two examples cover different relationship geometries: producer/prover to checker,
and adjacent verifier results joined under a fail-closed composition rule. They do not
constitute external interoperability or critical-domain readiness.
