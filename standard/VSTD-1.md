# VSTD-1 — Claim Mechanics

**Layer:** 1 of 5 on the object axis (see `LADDER.md`)
**Receipt wire format:** `schema_version = "VSTD-0.1"` — frozen; see `WIRE_IDENTIFIERS.md`
**Status:** Project Specification with Implemented Reference Subset
**Maintainer:** TimeLordRaps
**Date:** 2026-08-21

---

## 1. Purpose & Thesis

VSTD specifies infrastructure for consequential computational claims to carry
independently checkable evidence. Conformance is defined by this document, not by
the identity of its maintainer.

Modern AI systems, scientific simulators, and autonomous code generators routinely
produce complex assertions without an attached, machine-checkable audit trail showing
what evidence is offered for those claims. **VSTD-1** is a project
specification for representing claims, capturing runtime provenance, structuring
machine-readable verification receipts, defining reproducibility levels, and
separating trusted computing bases from untrusted outputs. It is not a consensus or
accredited standard.

---

## 2. Scope & Boundaries

### 2.1 What VSTD-1 Covers
- **Software Artifacts**: Deterministic test execution, static invariant validation, schema conformance.
- **Formal & Logic Artifacts**: Bounded propositional entailment, derivation graphs,
  acyclicity checks, and grounding invariants. The current reference subset implements
  a minimal propositional DPLL path; it does not implement general SMT verification.
- **AI & Autonomous Agents**: Bounded input/output constraints, zero-trust admission policies, and execution traces.
- **Scientific Simulation**: Invariant checking, exactness bounds, and deterministic reproduction traces.

### 2.2 What a VSTD Verification Claim Does NOT Imply
1. **Universal Truth**: Verification is strictly relative to the declared formal system, input formula, and explicit scope.
2. **Unbounded Safety**: A verified component does not guarantee overall system safety if surrounding orchestration or unmodeled environmental dynamics fail.
3. **Semantic Infallibility of Unchecked Layers**: Non-extracted, unverified natural language outside the formal translation grammar is not certified.

---

## 3. Epistemic Ontology & Claim Statuses

Claims conforming to this specification must carry one of the following explicit status
labels. Producers and validators MUST downgrade or challenge a claim when applicable
evidence is missing or falsified. A historical receipt is immutable: correction is an
additive record rather than an in-place rewrite.

| Status | Definition |
| :--- | :--- |
| `DEMONSTRATED` | The claim is backed by executable tests or formal proofs that pass in an independently reproducible environment. |
| `BENCHMARKED` | Quantitative performance or accuracy metrics have been empirically measured against a defined reference baseline. |
| `SUPPORTED` | Theoretical derivation or empirical evidence is established, but automated end-to-end continuous verification is partial. |
| `IMPLEMENTED_UNVALIDATED` | Code or logic exists on disk, but automated independent verification has not yet run or passed. |
| `INDETERMINATE` | Evidence is ambiguous, supporting leaves are unspecified, or solver execution timed out. |
| `UNSUPPORTED` | No valid empirical or formal evidence is attached to the proposition. |
| `FALSIFIED` | An executable check, counterexample, or independent audit refuted the claim. |
| `HYPOTHESIS` | A stated conjecture intended for experimental falsification. |
| `LONG_RANGE_OBJECTIVE` | A strategic or architectural aspiration requiring substantial future R&D. |

---

## 4. Claim Representation Schema

A canonical claim record contains:
- `id`: Unique identifier (e.g., `VFY-000001`).
- `title`: Short human-readable summary.
- `statement`: Precise, bounded technical claim.
- `status`: Verification status from the ontology above.
- `scope`: Bounded operational domain.
- `limitations`: Explicit list of assumptions, bounds, and exclusions.
- `falsification_condition`: Explicit condition under which the claim is considered refuted.
- `last_verified`: ISO-8601 UTC timestamp of the most recent passing verification.

---

## 5. Independent Verification & Trusted Computing Base (TCB)

To prevent self-referential confirmation bias (systems verifying their own uninspected
outputs), VSTD-1 defines an **Independent Verification Layer** as a conformance
requirement for claims labeled independent:

```text
Target System (Producer)
       ↓ (Generates derivation / CNF / artifacts)
Independent VSTD-Conformant Auditor
       ↓ (Runs independent DPLL solver + DAG grounding checker in isolated TCB)
Structured VFY Receipt
```

### Trusted Computing Base Invariant
An auditor described as independent must:
1. Share zero solver state or runtime logic with the producer.
2. Rely exclusively on a minimal, inspectable codebase (e.g. Python standard library).
3. Explicitly declare its TCB components in every generated receipt.

Running the bundled reference implementation does not by itself establish
organizational, implementation, or runtime independence. A receipt MUST state the
actual separation achieved. If producer and auditor share relevant logic or state, the
result is still inspectable but MUST NOT be labeled independent on that seam.

---

## 6. Reproducibility Taxonomy

VSTD-1 defines a five-tier reproducibility taxonomy:

1. `BITWISE_IDENTICAL`: Byte-for-byte exact match across all generated files, logs, and artifacts.
2. `CONTENT_IDENTICAL`: Canonical JSON representation of stable verification payload matches exactly, ignoring volatile execution fields (timestamps, elapsed wall-clock ms, hostnames).
3. `EVIDENCE_EQUIVALENT`: All checks, proofs, SAT assignments, and invariant bounds evaluate to the same truth values and proof certificates, though internal trace order or solver step counts may differ.
4. `RESULT_EQUIVALENT`: High-level verification verdict (`VERIFIED`/`FALSIFIED`) and primary metrics agree within declared tolerance bounds.
5. `SEMANTIC_REPRODUCTION`: The underlying formal proposition is sustained under an independent translation or alternate solver.

---

## 7. Canonical Receipt Specification & Hashing

A VSTD-1 receipt separates **stable verification content** from **volatile execution metadata**.
Its historical wire identifier remains frozen:

```
receipt.json
├── schema_version: "VSTD-0.1"
├── receipt_id: "VFY-XXXXXX"
├── canonical_digest: SHA256(canonical_json(stable_payload))
├── claim: {...}
├── evidence: {...}
├── target_result: {...}
├── independent_audit: {...}
├── provenance: {...}
├── reproducibility: {...}
└── execution_metadata: (volatile: timestamps, elapsed_ms, logs)
```

### Canonicalization Algorithm
1. Extract stable fields (`schema_version`, `receipt_id`, `claim`, `evidence`, `target_result`, `independent_audit`, `provenance_stable`, `reproducibility`).
2. Serialize the VSTD-1 JSON subset with alphabetically sorted object keys, compact
   separators `","` and `":"`, UTF-8 encoding, and no non-finite numbers. This
   project-specific canonicalization is deterministic for the supported value subset;
   VSTD-1 does not claim full RFC 8785 conformance.
3. Compute `SHA-256` digest over the serialized bytes.
4. The digest remains invariant across directory moves, path changes, and reformatting of human-readable reports.

---

## 8. Challenge & Correction Model

1. Any party may submit a counterexample, failing test, or ungrounded leaf finding.
2. A validator or reproducer returns failure when the bound content or declared rerun
   does not match. It does not silently mutate a historical receipt.
3. The maintainer or integrating system must publish an additive `FALSIFIED`,
   `INDETERMINATE`, or challenged record, preserving the affected receipt's provenance.

---

## 9. Implementation Roadmap & Extensibility

- **Currently Implemented Reference Subset**: Minimal propositional DPLL entailment,
  derivation-graph acyclicity and grounding checks, Git/runtime provenance capture,
  stable-payload digest validation, generic command receipts, and bounded
  reproducibility comparison.
- **VSTD-2 — Verification Surface**: verification geometry, residual-driven deconstruction, horizons, valences, and bounded self-closure. VSTD-2 does not reinterpret existing receipts whose wire identifier is `VSTD-0.1`.
- **Unassigned Future Work**: Additional proof mechanisms, execution-environment binding, and cross-institutional proof-carrying software gates require separate scoped proposals and evidence. No future version number is reserved here.
