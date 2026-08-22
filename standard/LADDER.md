# The VSTD Ladder — what the numbers mean

**Status:** project specification (normative for numbering and composition)
**Editor:** Tyler Roost
**License:** Apache-2.0

VSTD specification numbers are **layers of verification depth**, not revisions of a single
document. VSTD-3 does not supersede VSTD-1 any more than a floor supersedes its
foundation.

---

## 1. The governing idea

Each layer names a distinct verification question and a distinct failure class. The
ordering is a composition rule, not logical entailment between layers.

**Evidence for one layer never supplies evidence for another layer.** In particular,
layer-4 evidence does not supply, imply, upgrade, or repair layer 3, 2, or 1. A reported
depth of `N` is only shorthand for `N` separately checked results, one for each layer
from 1 through `N`.

Reflection and metalanguage are useful design analogies for asking what a given
verification surface leaves unexamined. VSTD does not claim that Tarski's
undefinability theorem proves this ladder, that adjacent layers form formal
metalanguages, or that a lower-layer implementation is logically incapable of
describing another layer's failure. The normative requirement is narrower: an
implementation MUST NOT treat success on one question as evidence for a different
question.

---

## 2. The object ladder

VSTD proper governs the verification of **one object**. Call this verification
*mechanics*.

| Layer | Name | Closes | Does not establish |
|---|---|---|---|
| **1** | Claim mechanics | A malformed or tampered statement | Whether the claim applies where it is being applied |
| **2** | Verification surface | A verdict leaking beyond the coordinate actually verified | Whether the evidence behind it is real |
| **3** | Substrate accountability | A lying or unaccountable evidence source | Whether anyone but the declarant could re-derive it |
| **4** | Refutability | A claim unfalsifiable in principle by any outside party | Whether the parties who could check are independent |
| **5** | Witness corroboration | Pseudo-independence — witnesses sharing the declarant's trust root | — |

### 2.1 The self-discernability boundary

**Layers 1 through 4 are self-discernable.** A declarant can establish them alone, with
no second party in existence.

**Layer 5 is not.** It requires another party to exist, to act, and to be independent.

That transition between 4 and 5 is the most important boundary in the ladder. Layer 4
asks *could a stranger check this?* Layer 5 asks *did one, and were they actually a
stranger?* The first is a property of the claim. The second is a property of the world.

An implementation MUST NOT report a layer-5 property on the basis of layer-4 evidence.
Preparing to be checked is not being checked.

---

## 3. The Graph axis

VSTD-Graph governs the verification of a **collection** of objects. Call this
verification *dynamics*.

The two axes are parallel but coupled: a collection's dynamics are constrained by its
members' mechanics, and by the provenance edges between them.

| Layer | Name | Collection-level closure |
|---|---|---|
| **Graph-1** | Recorded lineage | members and transformations are represented |
| **Graph-2** | Bounded collection surface | scope does not leak across the collection |
| **Graph-3** | Accountable provenance closure | every reachable substrate is accountable |
| **Graph-4** | Refutable transformation closure | challenges compose across hyperedges |
| **Graph-5** | Corroborated verification network | member and edge witnesses are independently corroborated |

A collection `C` holds at Graph layer `N` only if all four conditions hold:

1. **Membership floor** — every member is at object layer ≥ N.
2. **Provenance closure** — every ancestor reachable from any member is at layer ≥ N.
3. **Status admissibility** — no ancestor is `REVOKED`, `CHALLENGED`, `STALE`, or
   `UNKNOWN`.
4. **Edge evidence** — the transformation hyperedges themselves carry layer-N evidence.

Condition 2 is what a plain minimum over members misses. Condition 4 is what makes this
dynamics rather than aggregation: **a graph is only as verified as its edges**, and an
unevidenced edge between two layer-5 artifacts does not yield a layer-5 collection.

The level is **computed, never declared**:

```
graph_level(C) = max { N : CNF_N(C) is satisfiable }
```

The reference implementation searches 5→1. At a result below 5, the grounded
`FAIL` certificate for `N+1` is the explanation of the ceiling. A level without
that certificate is a declaration and is non-conforming.

---

## 4. Why satisfiability is the spine

The decision procedure is not incidental to the design. Three consequences follow, and
the third is the load-bearing one.

### 4.1 Some receipt fields are checkable certificates

VSTD does not classify every receipt as an NP certificate. Specific bounded formats,
including `VSTD4-GDC-1`, define a finite decision problem, a certificate language, and
an independent checker. Complexity claims apply only to such a defined formal problem.
Other receipt fields may be signed declarations, hashes, measurements, or references
whose meaning depends on explicitly named trust roots.

The useful engineering asymmetry is concrete rather than universal: when a result can
carry a smaller independently checkable artifact instead of requiring the original
computation, VSTD preserves that artifact and its verification bounds.

### 4.2 Bounded admission uses CNF

The reference admission procedures encode finite, bounded policy questions as CNF.
CNF is not identical to 3-SAT. A finite CNF satisfiability instance can be transformed
in polynomial time into an equisatisfiable 3-CNF instance, using auxiliary variables
where required. VSTD does not need that transformation for every checker and does not
infer a physical-world claim from the complexity of the encoded formula.

### 4.3 Global completeness is outside the observation boundary

`PHYSICAL_WORLD_COMPLETENESS: UNSUPPORTED` in VSTD-3 §16 means exactly that ordinary
VSTD evidence does not enumerate every physical execution that could exist. That is an
observational and claim-coordinate limit. It is not presented as a consequence of
Tarski's theorem, as a generic co-NP classification, or as a proof that a future,
explicitly finite observation system is impossible.

A future claim may cover a finite enumerated world if its observation boundary and
completeness mechanism are declared and checked. It still MUST NOT be widened into a
claim about unobserved physical activity.

This is why the ladder tops out at corroboration rather than proof of global absence. Layer 5
does not detect hidden work. It makes the *independence status* of declared work legible,
and leaves the undeclared remainder named and quantified rather than silent.

---

## 5. Certificates for refusals

This section applies to the finite propositional decision procedures used by the
reference layer-4 implementation.

A satisfiable result already carries its certificate: the model. Anyone can evaluate it
against the clause set without a solver.

An unsatisfiable result, by default, carries nothing but the solver's word.

For a fail-closed standard, **refusals are the most consequential output**. A standard
whose passes are checkable and whose refusals are not has its assurance backwards.
Layer 4 therefore requires a refutation certificate — a clausal proof, verifiable by
reverse unit propagation, checkable without re-solving.

Resolution proofs have exponential lower bounds for some formula families. A
conforming implementation therefore MUST declare a bound and MUST answer `UNKNOWN`
when the implemented search or proof check exceeds that bound. **Fail-closed under
resource exhaustion is a conformance requirement, not an implementation shortcut.**
An `UNKNOWN` is never a pass and never an unsatisfiability claim.

Reference implementation: `verifiable.core.refutation`.

### 5.1 The internal VSTD-4 ladder

VSTD-4 contains fourteen ordered rungs, from decision certification through
semantic binding, anti-equivocation, bounded portable checking, availability,
precommitment, challenge handling, degradation, and compositionality. Its depth
is computed:

```
vstd4_depth(claim) = max { k : CNF_4k(claim) is satisfiable }
```

The certificate for rung `k+1` explains a partial depth. Only depth 14 admits a
claim to any VSTD-5 procedure. See `VSTD-4.md` for the normative rung graph and
`VSTD4-GDC-1` format.

---

## 6. Composition — layers do not supply or substitute

Layer results may be composed into a depth report. They do not replace, entail, or
supply one another.

- Layer 4 without layer 3 certifies a claim whose evidence source is unaccountable.
- Layer 5 without layer 4 solicits witnesses for a claim no witness could check.
- Layer 2 without layer 1 scopes a statement whose integrity is unestablished.

An implementation reporting aggregate depth *N* MUST present separately checkable
evidence for every layer from 1 through *N*. Conformance may also be reported for an
individual layer without claiming aggregate depth. Conformance profiles are declared
per layer, following VSTD-3 §7.

"Higher is more protected" is true only in the sense that more classes of failure are
closed. It never means the lower layers became unnecessary.

---

## 7. Numbering

- **Specification layers are integers**: VSTD-1 … VSTD-5, VSTD-Graph-1 … VSTD-Graph-5.
- **Repository releases use semantic versioning** and are independent of layer numbers.

A release version never implies a layer, and a layer never implies a release. See
`WIRE_IDENTIFIERS.md` for frozen wire identifiers and the historical public filenames.
