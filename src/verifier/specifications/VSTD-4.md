# VSTD-4 — Refutability

**Layer:** 4 of 5 on the object axis (see `LADDER.md`)
**Certificate format:** `VSTD4-GDC-1`
**Status:** implemented project specification
**Editor:** TimeLordRaps
**License:** Apache-2.0
**Date:** 2026-08-22

VSTD-4 defines **adversarially portable checkability**. A verdict reaches this
layer only when its exact meaning, evidence, failure conditions, and checking
procedure can leave the declarant and survive hostile independent inspection.

VSTD-4 establishes that independent checking is possible. It does not establish
that an independent party exists or has checked anything; that is VSTD-5.

> **No verdict without a portable certificate.**
> **No portable certificate without an explicit falsifier.**

---

## 1. Conformance and lower-layer preconditions

VSTD-4 conformance is incremental. A claim MUST conform to VSTD-1, VSTD-2, and
VSTD-3 before it can conform to VSTD-4. A VSTD-4 certificate over an
unaccountable substrate does not repair the missing VSTD-3 evidence.

The normative depth is computed:

```
vstd4_depth(claim) = max { k : CNF_4k(claim) is satisfiable }
```

An implementation MUST NOT accept a declarant-supplied depth as authoritative.
For a depth below 14, the `FAIL` certificate for rung `k+1` is the normative
explanation of the ceiling. Entry to any VSTD-5 procedure requires:

```
vstd4_depth(claim) == 14
```

The reference implementation is `verifier.core.depth`.

---

## 2. The fourteen-rung ladder

Each rung depends on the evidence named below and on every lower-layer
precondition. Rung 4.14 depends on the complete ladder.

| Rung | Requirement | Direct dependencies |
|---|---|---|
| 4.1 | Decision certification | — |
| 4.2 | Semantic binding | 4.1 |
| 4.3 | Anti-equivocation | 4.2 |
| 4.4 | Portable verification | 4.3 |
| 4.5 | Bounded verification | 4.4 |
| 4.6 | Re-derivability | 4.4 |
| 4.7 | Minimal trusted checker | 4.5 |
| 4.8 | Availability | 4.6 |
| 4.9 | Disclosure-safe checkability | 4.8 |
| 4.10 | Explicit refutation surface | 4.2 |
| 4.11 | Prior commitment | 4.10 |
| 4.12 | Challenge handling | 4.10 and 4.1 |
| 4.13 | Monotonic degradation | 4.12 and 4.8 |
| 4.14 | Compositionality | all preceding rungs |

### 2.1 Decision certification

Every `PASS`, `FAIL`, and `UNKNOWN` MUST carry a `DecisionCertificate`.

* `PASS` carries a model or enumerable witness that can be evaluated.
* `FAIL` carries an enumerable counterexample or a checkable clausal proof.
* `UNKNOWN` carries an `IndeterminacyCertificate` showing the exact deterministic
  point at which the declared bound was exhausted.

An `UNKNOWN` certificate MUST NOT claim that no proof exists. It certifies only
bounded exhaustion. Supported reason codes are:

* `PROOF_BOUND_EXCEEDED`
* `DEPTH_BOUND_EXCEEDED`
* `DEPENDENCY_UNAVAILABLE`
* `DISCLOSURE_UNSATISFIABLE`
* `ARTIFACT_UNRETRIEVABLE`
* `VERIFIER_UNAVAILABLE`

### 2.2 Semantic binding

The certificate MUST prove the exact declared claim coordinate. The grounding
block MUST map every variable to a content-addressed fact and every clause to an
instance of a named encoding rule. A valid proof over a formula grounded to the
wrong artifact is non-conforming.

### 2.3 Anti-equivocation

Every certificate MUST carry the commitment:

```
C = H(claim || coordinate || policy_root || evidence_root || verifier
      || resource_bounds || prior_commitment)
```

Canonical serialization MUST use sorted object keys, integer-valued numeric
fields, no floating-point values, UTF-8, and no insignificant whitespace. A
checker MUST reject a certificate whose binding does not match the independently
supplied `ClaimBinding`.

### 2.4 Portable verification

Checking MUST NOT require post-verdict cooperation from the declarant. Every
verdict-critical input MUST accompany the certificate or be obtainable through
a content-addressed reference governed by a declared retention policy.

### 2.5 Bounded verification

The header MUST declare variable, clause, literal, proof-step, and width counts.
The binding declares verification cost as `literal_count + step_count`, memory
as the maximum simultaneously retained clause count, and certificate size in
canonical bytes. A zero certificate-size field preserves a legacy producer's
explicitly undeclared size ceiling; it does not establish bounded size. A checker MUST
refuse over-budget work from the header before inspecting the proof body. The
result is `UNKNOWN/PROOF_BOUND_EXCEEDED`, with zero proof steps checked.

The checker enforces the declared bound against itself. A declarant's cost claim
is therefore a falsifiable prediction rather than self-report.

### 2.6 Re-derivability

No undeclared hidden state, unpinned dependency, local path, wall-clock read, or
ambient entropy may be verdict-material. Randomness, if used, MUST be committed
and replayable under the declared randomness policy.

### 2.7 Minimal trusted checker

A `VerifierDescriptor` MUST identify:

```yaml
specification_hash: sha256:...
implementation_hash: sha256:...
parser_hash: sha256:...
certificate_format: VSTD4-GDC-1
format_fragment: UP,WIDTH-K,RES
dependencies: []
deterministic: true
```

Hashes MUST be computed from the referenced bytes, never copied from literal
claims about the implementation. The certificate semantics MUST be sufficiently
specified to permit a checker sharing no verdict-producing code with the
declarant. The reference kernel is `verifier.core.kernel`; it imports no solver
or policy producer.

### 2.8 Availability

Verdict-critical artifacts use the ordered availability lattice:

```
IDENTIFIED < AVAILABLE < PORTABLE < SELF_CONTAINED
```

A digest alone establishes only `IDENTIFIED`. VSTD-4 requires at least
`AVAILABLE`, and the claim's bundle is capped by its weakest verdict-critical
artifact. A declared level that its retrieval and retention evidence cannot
support MUST be rejected.

A locator and retention declaration alone are not retrieval evidence. `AVAILABLE`
requires a successful retrieval observation bound to the artifact identifier, declared
locator, observed bytes, observation time, and observer. The observed bytes MUST match
the content address. `PORTABLE` additionally requires anonymous access and a declared
retrieval procedure. A retrieval observation is scoped to its named trust root; it does
not by itself establish independent retrieval.

### 2.9 Disclosure-safe checkability

Confidential evidence MUST still expose a declared verification interface. The
interface MUST state what is committed, which predicate is checked, what a
checker receives, and which conclusion does not follow. Confidentiality does
not permit an evidence-free verdict.

### 2.10 Explicit refutation surface

Free prose alone is insufficient. A `RefutationSurface` MUST contain a bound
claim coordinate, machine-readable `admissible_refutations`, the evidence that
would overturn each predicate, and `excluded_claims`.

`PHYSICAL_WORLD_COMPLETENESS` MUST remain explicitly excluded unless a future
claim supplies a finite enumerated world. A receipt digest proves integrity of
recorded bytes, not completeness of the physical world.

### 2.11 Prior commitment

A `PrecommitmentEnvelope` MUST bind every verdict-material degree of freedom
before evidence produced by that degree of freedom is observed:

* claim and claim coordinate;
* evaluation policy;
* admissible evidence classes and evidence-selection rule;
* verifier and checker identity;
* resource budget and stopping condition;
* randomness policy; and
* disclosure policy.

A declarant MUST NOT select a verdict-material degree of freedom after observing
the evidence it controls.

### 2.12 Challenge handling

A challenge names the target claim and certificate, the challenged predicate,
the challenge type, counterevidence, and its certificate. Admission returns
`ACCEPTED`, `REJECTED`, or `UNRESOLVED`.

Claim status is a function over append-only challenge and adjudication records;
it is never a mutable field inside commitment `C`:

```
VALID -> CHALLENGED -> REVOKED
                  \-> VALID       (challenge disproven)
```

A valid challenge mechanism that cannot change claim status is non-conforming.
Synthetic challenges test structural challengeability at VSTD-4. Actual
independent action belongs to VSTD-5.

### 2.13 Monotonic degradation

Loss of certificate validity, artifact accessibility, dependency validity, or
commitment integrity MUST NOT leave the associated verdict unchanged at its
former strength. Removing rung evidence MUST NOT increase `vstd4_depth`.

### 2.14 Compositionality

A `RefutabilityClosure` MUST bind input certificates, the transformation
certificate, the output claim, and a total output-refutation mapping. A challenge
to an output must localize to an input, the transformation, or the composition.

Output depth MUST NOT exceed the weakest required input or transformation depth.
This closure is both the handoff to VSTD-Graph edge evidence and the entry gate to
VSTD-5.

---

## 3. VSTD4-GDC-1 decision certificate

The canonical structure is:

```
DecisionCertificate
├── header       binding C, verdict, tier, width and declared counts
├── formula      normalized clauses
├── grounding    variable-to-fact and clause-to-rule evidence
├── decision     model, propagation proof, resolution proof, or transcript
└── hints        untrusted and strippable
```

The JSON serialization is defined by
`receipts/schema/vstd4_certificate.json`. Canonical bytes MUST round-trip without
change, and the certificate digest MUST enter the anti-equivocation binding when
the certificate is embedded in a higher-order receipt.

### 3.1 Grounding

The checker MUST perform grounding before decision checking. It verifies:

1. every variable has exactly one retrievable fact;
2. every clause has exactly one grounding record;
3. the named rule exists;
4. the clause is the normalized instance of that rule; and
5. each role's variable is grounded to the subject named by the clause.

This block detects a correct proof of the wrong formula. Claim-agnostic SAT proof
formats do not provide this check.

### 3.2 Cost tiers

| Tier | Admits | Checking bound |
|---|---|---|
| `UP` | Horn/unit-propagation proofs | linear in total literals |
| `WIDTH-K` | resolution with clause width at most `k` | polynomial for fixed `k` |
| `RES` | general resolution | declared; exponential worst case |
| `SAT-PRESERVING` | RAT-class inprocessing | declared; exponential worst case |

The tightest admissible tier is mandatory. A Horn formula MUST use `UP`; tier
inflation is a conformance failure. The reference kernel implements `UP`,
`WIDTH-K`, and `RES`. It declares `SAT-PRESERVING` outside its implemented
fragment and returns `UNKNOWN`, never a guessed verdict.

### 3.3 Decision forms

* A `PASS` model assigns every variable and satisfies every clause.
* A `FAIL` over an enumerable universal uses the grounded conflict witness.
* Other `FAIL` decisions use a proof admitted by the declared tier.
* `UNKNOWN` uses a replayable deterministic transcript.

Hints are untrusted accelerators. Corrupting or removing a hint may leave the
verdict unchanged or yield `UNKNOWN`; it MUST NOT change which proposition is
accepted.

---

## 4. Normative invariants

> A verdict MUST NOT be recorded at a strength exceeding the strength of the
> certificate an independent party could check without the declarant's
> cooperation.

> Loss of certificate validity, accessibility, dependency validity, or
> commitment integrity MUST NOT leave the associated verdict unchanged at its
> former strength.

---

## 5. Prohibited challenge theater

A claim is not VSTD-4 merely because:

* source code or logs are public;
* someone could theoretically rerun it;
* a hash exists;
* the declarant says reproduction is possible;
* the same implementation reruns itself;
* a challenge endpoint exists but cannot change verdict state;
* the certificate proves a weaker neighbouring proposition;
* checking requires undisclosed information; or
* checking requires unbounded computation.

Labels do not substitute for mechanisms, grounding, portable artifacts, or
bounded checking.

---

## 6. Reference implementation boundary

The reference producer and data structures are in:

* `src/verifier/core/certificate.py`
* `src/verifier/core/grounding.py`
* `src/verifier/core/depth.py`
* `src/verifier/core/refutation.py`
* `src/verifier/layer4/`

The trusted checker is `src/verifier/core/kernel.py`. Producer modules are not
part of its trusted import boundary.

No external implementation, interoperability profile, or third-party attack has
yet been demonstrated for `VSTD4-GDC-1`. This implementation status MUST remain
visible in claims about the format.
