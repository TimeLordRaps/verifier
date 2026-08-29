# Verifier Standard (VSTD)-5 — Witness Corroboration

> Reader aid: [concept glossary and primary precedents](https://github.com/TimeLordRaps/verifier/blob/main/docs/CONCEPTS_AND_PRECEDENTS.md).

**Numbered profile:** VSTD-5 on the object axis; required closure coordinate: Witness Corroboration (see `LADDER.md`)
**Status:** project specification with implemented evidence-bound reference mechanism
**Editor:** TimeLordRaps
**License:** Apache-2.0
**Date:** 2026-08-29

VSTD-5 binds a fully refutable claim to an actually checked witness relation. It is
the first numbered object profile that a declarant acting alone cannot satisfy.
Witness identity names a coordinate; it never supplies computational trust.

---

## 1. Entry gate

Every VSTD-5 procedure MUST reject a claim unless VSTD-1, VSTD-2, and VSTD-3
preconditions and all VSTD-4 rung propositions were evidence-bound and checked,
establishing VSTD-4 conformance at depth 14.

The compatibility `vstd4_depth` candidate never satisfies this gate. The reference
`establish_vstd4` path may satisfy it only after rerunning every exact evidence
binding and checking its depth certificate. `require_vstd5_entry` distinguishes the
two result types and fails closed.

---

## 2. Required records

The reference receipt contains:

* `WitnessIdentity` — witness coordinate plus content-addressed identity evidence;
* an ordered `independence_assertions` array — every supplied
  `IndependenceAssertion`, including duplicates, orphan references, and missing
  cardinality as an empty or incomplete array, so negative assessment inputs are not
  collapsed during serialization;
* `CorroborationRecord` — exact VSTD-4 commitment, certificate, checker descriptor,
  observations, result, time, class, and executable verification binding;
* derived disagreements — conflicting checked records retained without voting or
  averaging; and
* embedded evidence bytes — enough to rehash and rerun the registered mechanisms
  offline.

Schema validity establishes only shape. `recheck_vstd5_receipt` imports and hashes
the embedded bytes, checks the admitted VSTD-4 result digest, reruns every registered
mechanism, and compares the complete derived result. Every receipt emitted by
`build_vstd5_receipt`, including `UNKNOWN` / `NOT_ESTABLISHED` error receipts, MUST
preserve the exact error-producing input and recheck identically.

---

## 3. Independence

For every declarant/witness pair, the procedure checks whether they share:

1. ownership or operational control;
2. verdict-producing code;
3. a verifier trust root;
4. an evidence source or telemetry provider;
5. infrastructure capable of changing the observed result;
6. financial dependence material to the corroboration; and
7. jurisdictional or contractual dependence material to compulsion.

Every `SEPARATE` state MUST carry a `BoundProposition` for the exact negative
relationship, the admitted claim commitment, evidence references, mechanism
identifier and digest, trust roots, and bounds. `SHARED`, `UNKNOWN`, missing,
failed, or unevaluable dimensions prevent an `INDEPENDENT` result.

Repeated evidence, duplicate identifiers, identity keys, signatures, reputation,
and field names MUST NOT manufacture independence. The same identity evidence used
under multiple witness identifiers is rejected.

---

## 4. Corroboration and disagreement

A corroboration mechanism MUST bind and check the exact:

* claim commitment;
* VSTD-4 certificate digest;
* checker descriptor digest;
* witness coordinate;
* observation time;
* observation evidence bytes; and
* `CORROBORATED`, `REFUTED`, or `UNKNOWN` result.

A record's certificate digest MUST equal the admitted evidence-bound VSTD-4 witness,
not merely a caller-selected digest repeated in both fields. Every identified witness
MUST contribute a corroboration record; dangling identities do not create plurality.

A mechanism-earned negative result remains negative. Conflicting checked records
produce `CONFLICTED`; witnesses are not votes, and majority count never cleans the
conflict. A positive corroboration with any unresolved independence seam is reported as
overall `UNKNOWN`, not as independently corroborated. Reusing the same evidence set under
another corroboration identifier is rejected rather than counted twice.

---

## 5. Reference algorithm

`verifier.core.witness.assess_witness_corroboration` performs, in order:

1. evidence-bound VSTD-4 entry validation;
2. identity-evidence availability and duplicate detection;
3. exact seven-dimension independence evaluation;
4. exact corroboration binding and mechanism execution;
5. duplicate-evidence refusal;
6. disagreement derivation; and
7. bounded result emission with all errors and limitations retained.

`build_vstd5_receipt` serializes witness identities and independence assertions as
separate ordered arrays so duplicate and orphan assertions survive round trip.
`recheck_vstd5_receipt` reruns them. Neither function turns an identity coordinate
into trust or establishes a fact outside the propositions checked by its registered
mechanisms.

---

## 6. Current limits

The repository ships the meta-verification mechanism and adversarial fixtures. It
does not ship or claim a real independent third-party witness, external
interoperability deployment, accreditation, or a universal way to infer real-world
separation. A deployment must supply mechanisms that actually check its evidence;
registering a mechanism names the trust boundary but does not make that mechanism
correct.
