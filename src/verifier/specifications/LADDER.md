# The Verifier Standard (VSTD) Ladder — what the numbers mean

> **Acronyms:** conjunctive normal form (CNF); Certificate Transparency (CT);
> deletion resolution asymmetric tautology (DRAT); grounded decision certificate (GDC);
> JavaScript Object Notation (JSON); National Institute of Standards and Technology (NIST);
> nondeterministic polynomial time (NP); proof-carrying code (PCC);
> World Wide Web Consortium provenance vocabulary (PROV); PROV data model (PROV-DM); Protect the Software (PS);
> Request for Comments (RFC); reverse unit propagation (RUP); Boolean satisfiability problem (SAT);
> Supply-chain Levels for Software Artifacts (SLSA); satisfiability modulo theories (SMT);
> SMT library standard (SMT-LIB); Secure Software Development Framework (SSDF); The Update Framework (TUF);
> unsatisfiable (UNSAT); World Wide Web Consortium (W3C).

**Status:** project specification (normative for numbering and composition)
**Editor:** TimeLordRaps
**License:** Apache-2.0

**Normative language:** The uppercase key words in this series are interpreted as
described by [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119) and
[RFC 8174](https://www.rfc-editor.org/rfc/rfc8174) only when they appear in all capitals;
lowercase uses are ordinary prose.

**Reader context:** [`Concept guide and intellectual precedents`](https://github.com/TimeLordRaps/verifier/blob/main/docs/CONCEPTS_AND_PRECEDENTS.md)

VSTD specification numbers are **layers of verification depth**, not revisions of a single
document. VSTD-3 does not supersede VSTD-1 any more than a floor supersedes its
foundation.

---

## 1. The governing idea

Each layer names a distinct verification question and a distinct failure class. The
ordering is a composition rule, not logical entailment between layers.

The nearest familiar security analogy is
[defense in depth](https://en.wikipedia.org/wiki/Defense_in_depth_%28computing%29 "Wikipedia orientation; primary references are mapped below"),
but the analogy is limited: VSTD layers are separately evidenced questions, not
interchangeable controls whose mere quantity establishes assurance. Decomposing assurance
into named components also has precedent in the Common Criteria, while VSTD deliberately
uses different layers, evidence rules, and conformance semantics.

**Evidence for one layer never supplies evidence for another layer.** In particular,
layer-4 evidence does not supply, imply, upgrade, or repair layer 3, 2, or 1. A reported
depth of `N` is only shorthand for `N` separately checked results, one for each layer
from 1 through `N`.

Reflection and [metalanguage](https://en.wikipedia.org/wiki/Metalogic "Wikipedia orientation; not a proof of the VSTD ladder")
are useful design analogies for asking what a given
verification surface leaves unexamined. VSTD does not claim that Tarski's
[undefinability theorem](https://en.wikipedia.org/wiki/Tarski%27s_undefinability_theorem "Wikipedia orientation; the theorem does not derive this ladder")
proves this ladder, that adjacent layers form formal
metalanguages, or that a lower-layer implementation is logically incapable of
describing another layer's failure. The normative requirement is narrower: an
implementation MUST NOT treat success on one question as evidence for a different
question.

### 1.1 Artifact-first causal provenance orientation

VSTD evaluates artifact-bound claims, evidence, predicates, mechanisms, and declared
trust roots. Standing alone, an actor's identity, popularity, repetition, or reputation
MUST NOT strengthen an artifact-bound result. A named mechanism MAY establish an exact
attribution, authorization, or separation proposition by checking the required identity
evidence; that result does not promote an unrelated computational claim. **Actor** and
**artifact** are contextual roles rather than permanent entity classes: a coding agent
may be an artifact when it is created, versioned, or evaluated and an actor when it
creates or transforms another artifact.

The same bound development graph carries two typed causal-provenance propagation
directions:

```text
development: ancestor artifact --bounded positive support--> descendant claim or artifact
diagnosis:   descendant Rust   --memetic causal backtrace--> recorded ancestor states
```

**Memetic propagation** is the transmission of claim and evidence state through recorded
developmental provenance. The genetic or viral language names this inheritance mechanic:
positive Artifact support propagates forward into descendant claim space, while Rust
propagates backward toward ancestor states as a provenance backtrace. It does not claim
biological transmission or make identity and reputation sources of assurance.

**Artifact trust** is positive support already established for an exact artifact-bound
obligation. It moves parent-to-child only across a declared creation or dependency edge
whose relevant transformation obligations pass. Applicable support composes by
intersection and is capped by the weakest required parent or edge; it is never added,
averaged, voted, or converted into actor standing. Every child MUST still discharge its
new predicates, transformations, boundaries, and evidence obligations.

**Rust** is a typed diagnostic trace created by an observed descendant deviation from a
declared expectation. It moves child-to-parent only through recorded admissible creation,
input, or transformation paths. Distinct comparable backtraces may concentrate on a
shared ancestor and prioritize it for diagnostic examination. Transferred Rust establishes
ancestral reachability, not direct observation or causal responsibility; localization
requires additional intervention, ablation, reproduction by a distinct actor, or equivalent
declared evidence.

The word *causal* is required here for recorded developmental and provenance causality:
the graph states which artifacts and transformations produced later claim architecture.
Propagation across those causal-provenance edges does not by itself establish
intervention-level physical causality, causal localization, responsibility, or guilt.

Forward support and backward Rust MUST remain separate. They do not cancel, form one
scalar score, or flow in the opposite direction as inherited truth or guilt. `UNKNOWN`
and `CONFLICTED` support or lineage MUST remain visible and MUST NOT become a clean
signal. This section fixes the semantic orientation and prohibited inferences; an event
format, transfer algebra, concentration-independence rule, and localization protocol each
require their own specification and evidence. Until those exist, Artifact trust and Rust
are causal-provenance propagation constraints, not computable conformance results; no
current VSTD runtime emits or validates either transfer.

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

VSTD-1 records the claim-mechanics status of actor independence but cannot infer it from
two runs or matching artifacts. VSTD-5 requires the corroborating witness procedure that
uses such separately evidenced actor participation; recording a field is not witnessing.

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
members' mechanics, and by the
[provenance](https://en.wikipedia.org/wiki/Data_provenance "Wikipedia orientation; see W3C PROV-DM and supply-chain references below")
edges between them. The implemented N-ary representation is a
[hypergraph](https://en.wikipedia.org/wiki/Hypergraph "Wikipedia orientation; not a claim of complete real-world lineage").

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
3. **Status admissibility** — no ancestor is `REVOKED`, `CHALLENGED`, `STALE`,
   `UNKNOWN`, or subject to an unresolved `CONFLICTED` record.
4. **Edge evidence** — the transformation hyperedges themselves carry layer-N evidence.

Condition 2 is what a plain minimum over members misses. Condition 4 is what makes this
dynamics rather than aggregation: **a graph is only as verified as its edges**, and an
unevidenced edge between two layer-5 artifacts does not yield a layer-5 collection.

The level is **computed from validated object and edge ratings, never declared**:

```
graph_level(C) = max { N : CNF_N(C) is satisfiable }
```

The reference implementation searches 5→1 and certifies its Boolean encoding. Its
current rating inputs are caller-supplied, so it reports a **candidate level** with
`conformance_status = NOT_ESTABLISHED`; the certificate proves the computation over
those inputs, not the validity of the ratings. At a result below 5, the grounded `FAIL`
certificate for `N+1` explains that candidate ceiling. Graph conformance additionally
requires evidence-bound ratings under the applicable object and edge profiles.

---

## 4. Why satisfiability is the spine

The decision procedure is not incidental to the design. Three consequences follow, and
the third is the load-bearing one.

### 4.1 Some receipt fields are checkable certificates

VSTD does not classify every receipt as an NP certificate. Specific bounded formats,
including `VSTD4-GDC-1`, define a finite decision problem, a certificate language, and
a checker implemented separately from the producer path. Complexity claims apply only
to such a defined formal problem; checker separation alone does not establish distinct
actors.
Other receipt fields may be signed declarations, hashes, measurements, or references
whose meaning depends on explicitly named trust roots.

The useful engineering asymmetry is concrete rather than universal: when a result can
carry a smaller consumer-checkable artifact instead of requiring the original
computation, VSTD preserves that artifact and its verification bounds.

### 4.2 Bounded admission uses CNF

The reference admission procedures encode finite, bounded policy questions as
[conjunctive normal form](https://en.wikipedia.org/wiki/Conjunctive_normal_form "Wikipedia orientation; the implemented format is finite CNF")
(CNF) for the
[Boolean satisfiability problem](https://en.wikipedia.org/wiki/Boolean_satisfiability_problem "Wikipedia orientation; SAT success establishes only the encoded formula").
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
[reverse unit propagation](https://en.wikipedia.org/wiki/Unit_propagation "Wikipedia orientation; VSTD implements a bounded RUP checker"),
checkable without re-solving. This follows the same producer-certificate/consumer-checker
engineering asymmetry as
[proof-carrying code](https://en.wikipedia.org/wiki/Proof-carrying_code "Wikipedia orientation; VSTD does not inherit PCC's safety theorem"),
while using a narrower certificate language.

Resolution proofs have exponential lower bounds for some formula families. A
conforming implementation therefore MUST declare a bound and MUST answer `UNKNOWN`
when the implemented search or proof check exceeds that bound. **Fail-closed under
resource exhaustion is a conformance requirement, not an implementation shortcut.**
An `UNKNOWN` is never a pass and never an unsatisfiability claim.

Reference implementation: `verifier.core.refutation`.

### 5.1 The internal VSTD-4 ladder

VSTD-4 contains fourteen ordered rungs, from decision certification through
semantic binding, anti-equivocation, bounded portable checking, availability,
precommitment, challenge handling, degradation, and compositionality. Its depth
is computed:

```
vstd4_depth(claim) = max { k : CNF_4k(claim) is satisfiable }
```

The certificate for rung `k+1` explains a partial normative depth. Only established
VSTD-4 conformance at depth 14 admits a claim to any VSTD-5 procedure. The current
reference `vstd4_depth` function instead computes a structural candidate from
caller-supplied rung references, labels conformance `NOT_ESTABLISHED`, and never admits
VSTD-5. See `VSTD-4.md` for the normative rung graph and `VSTD4-GDC-1` format.

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
- **Repository releases use [semantic versioning](https://semver.org/)** and are independent
  of layer numbers.

A release version never implies a layer, and a layer never implies a release. See
`WIRE_IDENTIFIERS.md` for frozen wire identifiers and the historical public filenames.

---

## 8. Intellectual lineage and adjacent precedents

The ladder is VSTD project architecture; no cited work proves that these five layers are
necessary, sufficient, complete, or uniquely ordered. The references below show that its
individual design pressures have established precedents in security engineering,
provenance, reproducible systems, and proof checking. The
[`concept guide`](https://github.com/TimeLordRaps/verifier/blob/main/docs/CONCEPTS_AND_PRECEDENTS.md) provides definitions, additional
sources, and explicit non-equivalences.

| VSTD pressure | Adjacent precedent | What the precedent contributes—and does not |
|---|---|---|
| Separate failure surfaces and fail-closed defaults | Saltzer and Schroeder, [*The Protection of Information in Computer Systems*](https://web.mit.edu/Saltzer/www/publications/pubs.html) | Classic principles include fail-safe defaults, complete mediation, separation of privilege, and least common mechanism. They motivate separation; they do not derive VSTD's layer count. |
| Named assurance components | Common Criteria, [Part 3: Security assurance components](https://www.commoncriteriaportal.org/files/ccfiles/CC2022PART3R1.pdf) | Demonstrates established componentized assurance and assurance packages. VSTD is not a Common Criteria evaluation or an Evaluation Assurance Level. |
| Stable cryptographic representations | [RFC 8785: JSON Canonicalization Scheme](https://www.rfc-editor.org/rfc/rfc8785.html) | Shows why JSON used as cryptographic input needs invariant representation. VSTD formats retain their own declared canonicalization rules. |
| Recorded entities, activities, and agents | W3C [PROV-DM](https://www.w3.org/TR/prov-dm/) | Supplies an interoperable provenance model adjacent to the Graph axis. VSTD-Graph is not a PROV implementation and does not infer complete history. |
| Software materials, builders, steps, and products | [in-toto specification v1.0](https://in-toto.io/docs/specs/) and [SLSA v1.2](https://slsa.dev/spec/v1.2/) | Establish supply-chain provenance and attestation precedents. VSTD may bind their evidence but cannot manufacture their authorization or assurance level. |
| Preserved release and provenance evidence | NIST [Special Publication (SP) 800-218 SSDF 1.1](https://doi.org/10.6028/NIST.SP.800-218) | Protect the Software practices PS.3.1 and PS.3.2 call for preserving releases and provenance and enabling integrity verification. They do not certify a VSTD receipt. |
| Independent recreation | Reproducible Builds, [formal definition](https://reproducible-builds.org/docs/definition/) | Grounds the special case where another party recreates specified artifacts from declared inputs and instructions. Reproducibility does not establish every semantic claim. |
| Producer-supplied portable certificates | Necula, [*Proof-Carrying Code*](https://doi.org/10.1145/263699.263712) | Establishes the pattern of an untrusted producer supplying a proof checked under a declared policy. VSTD uses the pattern beyond code safety without inheriting PCC's theorem. |
| Consumer-checked UNSAT results | Wetzler, Heule, and Hunt, [*DRAT-trim*](https://www.cs.cmu.edu/~mheule/publications/drat-trim.pdf) | Establishes practical checking of clausal unsatisfiability proofs rather than trusting solver output. VSTD's implemented RUP format is narrower than DRAT. |
| A first-class refusal to fabricate a Boolean answer | [SMT-LIB Standard 2.7](https://smt-lib.org/papers/smt-lib-reference-v2.7-r2025-04-09.pdf) | Its response grammar includes `sat`, `unsat`, and `unknown`. VSTD independently defines a richer status system with the same fail-closed pressure. |
| Append-only public evidence and detectable equivocation | [RFC 9162: Certificate Transparency Version 2.0](https://www.rfc-editor.org/rfc/rfc9162.html) | Merkle proofs make log inclusion and consistency auditable while preserving explicit split-view limitations. VSTD additive receipts are analogous, not a CT implementation. |
| Freshness, rollback, freeze, and compromise recovery | [The Update Framework specification](https://theupdateframework.github.io/specification/latest/) | Demonstrates that authentic old data is not automatically current data. VSTD does not implement TUF, but likewise keeps freshness and revocation distinct from byte identity. |
