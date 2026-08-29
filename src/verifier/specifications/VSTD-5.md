# Verifier Standard (VSTD)-5 — Witness Corroboration

> Reader aid: [concept glossary and primary precedents](https://github.com/TimeLordRaps/verifier/blob/main/docs/CONCEPTS_AND_PRECEDENTS.md).

**Numbered profile:** VSTD-5 on the object axis; required closure coordinate: Witness Corroboration (see `LADDER.md`)
**Status:** DRAFT — not implemented
**Editor:** TimeLordRaps
**License:** Apache-2.0
**Date:** 2026-08-22

VSTD-5 binds a fully refutable claim to witnesses that do not share the
declarant's trust root. It is the first numbered profile that cannot be established by a
declarant acting alone.

This document is a draft interface, not an implementation or a claim that any
independent witness exists.

---

## 1. Entry gate

Every VSTD-5 procedure MUST reject a claim unless VSTD-1/2/3 preconditions and all
VSTD-4 rung propositions have been evidence-bound and checked, establishing normative
VSTD-4 conformance at normative depth 14:

```
vstd4_depth(claim) == 14
```

The gate is not satisfied by a structural candidate over caller-supplied references.
The current reference candidate reports `conformance_status = NOT_ESTABLISHED`, and
`require_vstd5_entry` rejects it even at candidate depth 14. A witness cannot
corroborate a claim whose refutability does not compose.

---

## 2. Required record families

A future conforming receipt will contain:

* `WitnessIdentity` — the witness and the method used to bind the record to it;
* `IndependenceAssertion` — shared control, vendor, jurisdiction, funding,
  infrastructure, and trust-root relationships;
* `CorroborationRecord` — what the witness independently checked, the VSTD-4
  certificate checked, observable results, time, and bounds;
* `CorroborationClass` — procurement, power/thermal envelope, network egress,
  vendor telemetry, financial attestation, or physical inspection; and
* `DisagreementRecord` — conflicting observations and their effect on the claim.

Independence fields MUST be evidence-bearing. A declarant's statement that a
witness is independent is not independence evidence.

---

## 3. Independence

At minimum, an independence assertion MUST name whether declarant and witness
share:

1. ownership or operational control;
2. a verdict-producing codebase;
3. a verifier trust root;
4. an evidence source or telemetry provider;
5. infrastructure capable of changing the observed result;
6. financial dependence material to the corroboration; and
7. a jurisdiction or contractual relationship material to compulsion.

`UNKNOWN` in any required independence dimension MUST cap the independence claim.

> Claim independence MUST NOT exceed the independence of its weakest binding
> witness.

Independence is not manufacturable from self-report at any cryptographic
strength.

---

## 4. Corroboration and disagreement

A corroboration record MUST bind the exact VSTD-4 commitment `C`, certificate
digest, checker descriptor, observable evidence, result, and observation time.
Checking a neighbouring claim or a different commitment is not corroboration.

Witnesses are not votes. Conflicting witnesses MUST degrade the claim and create
an additive `DisagreementRecord`; their conclusions MUST NOT be averaged into an
apparently clean result.

---

## 5. Draft boundary

The schema `receipts/schema/vstd5_receipt.json` records the intended shape for
review. No reference witness transport, identity scheme, independence scoring
algorithm, or second-party implementation is shipped in release v1.0.0.

The document remains `DRAFT` until VSTD-4 operating experience supplies evidence
for the final protocol. A draft schema MUST NOT be presented as VSTD-5
conformance.
