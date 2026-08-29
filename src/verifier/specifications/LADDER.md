# The Verifier Standard (VSTD) verification complex — what the numbers mean

> **Acronyms:** application programming interface (API); conjunctive normal form (CNF); Certificate Transparency (CT);
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

VSTD records separate answers to separate verification questions about an identified
claim, its evidence, the mechanism that checked it, and the bounds of that check. It does
not collapse those answers into one universal “verified” label or confidence score. The
questions, their evidence-bearing relations, and cumulative profiles over them form the
VSTD **verification complex**.

### Read this first: the number is a checklist position, not a strength score

A numbered profile is a cumulative checklist on one axis. `VSTD-3`, for example, means
that the required questions for `VSTD-1`, `VSTD-2`, and `VSTD-3` are each established by
their own applicable evidence. It does **not** mean “assurance strength 3,” software
version 3, or evidence that is three times stronger than `VSTD-1`.

Here, **established** means that a named mechanism checked the exact required proposition
against bound evidence under declared limits. A field, document, or actor merely saying
that the proposition passed does not establish it.

Consider one verification object with these separately recorded results:

| Object-axis question | Current result |
|---|---|
| `VSTD-1` Claim Mechanics | established |
| `VSTD-2` Verification Surface | `UNKNOWN` |
| `VSTD-3` Substrate Accountability | established |

Its **object profile depth is 1**. The cumulative checklist cannot skip the missing
`VSTD-2` result. The `VSTD-3` coordinate evidence remains recorded and useful, but it does
not fill the `VSTD-2` gap or make profile 3 satisfied.

The Graph axis applies a different cumulative checklist to a collection of artifacts and
their recorded relations. `VSTD-3` and `VSTD-Graph-3` therefore ask different questions;
the shared number does not make them equivalent.

In one sentence: a **closure coordinate** is one verification question, a **numbered
profile** is a cumulative checklist of those questions on one axis, and **profile depth**
is the largest uninterrupted prefix of that checklist that is established.

### Terminology contract

The rest of the Standard uses the following terms precisely:

| Term | Plain meaning | Important boundary |
|---|---|---|
| **Closure coordinate** | One named verification question and its failure class, such as Claim Mechanics or Refutability. | Closure is scoped to that question. VSTD-2 surface closure, Graph provenance closure, refutability closure, and artifact-seal structural closure are different results. |
| **Numbered profile** | A cumulative checklist selected by `VSTD-N` or `VSTD-Graph-N`. Profile `N` requires its named coordinate and every earlier coordinate on the same axis. | A profile number is not a software revision, spatial layer, confidence score, or substitute for the underlying results. |
| **Profile axis** | One ordered family of cumulative checklists. VSTD has an object axis and a Graph axis. | Equal numbers on different axes do not identify equivalent or interchangeable results. |
| **Object profile depth** | For one verification object, start at `VSTD-1` and count upward only while every required coordinate remains established. The last uninterrupted number is its depth. | Depth is a compact summary of separately established results, not a new verdict, evidence-strength rating, or permission to ignore a later established coordinate after an earlier gap. |
| **Candidate Graph profile** | The greatest Graph checklist position satisfied by the current caller-supplied ratings. | The current calculation is `NOT_ESTABLISHED` because those ratings are not evidence-bound. It is not a verified Graph profile. |
| **Evidence-bound Graph profile** | The greatest Graph checklist position obtained after rerunning exact member, ancestor, and edge rating mechanisms from content-addressed evidence. | It is established only under the named mechanisms, trust roots, evidence, bounds, lifecycle view, and conflict state. |
| **VSTD-4 rung** | One of the fourteen ordered refutability obligations `4.1` through `4.14`. | “Rung” names only this internal sequence, never a top-level VSTD profile. |
| **Verification order** | One adjacent meta-verification order in the VSTD-2 geometry model. | The compatibility names `VerificationLayer` and `verification_layers` do not denote numbered VSTD profiles. |
| **Level** | A retained word in an explicitly named external taxonomy or compatibility identifier, including `ReproducibilityLevel`, `AvailabilityLevel`, `graph_level`, and serialized Graph `level` fields. | In Graph compatibility identifiers, the value is the candidate Graph profile number; “level” is not the governing name for a VSTD profile. |
| **Layer** | An implementation, protocol, or physical stack whose parts are ordered by containment. | It does not name `VSTD-N` or `VSTD-Graph-N`; historical paths such as `verifier.layer4` remain compatibility identifiers only. |
| **Tier** | A declared checker-cost class in `VSTD4-GDC-1`. | It is not a VSTD profile, evidence-strength rating, or actor rating. |

“Profile” must also be qualified when confusion is possible: **numbered profile**, **receipt
profile**, **application profile**, or **geometry profile**. Likewise, “depth” must be
qualified as object profile depth, VSTD-4 normative or candidate depth, or lineage
topological depth. The retained `LADDER.md` filename is a stable document path, not the
governing topology; this document defines a verification complex.
Current public serialized identifiers, fields, class names, functions, and module paths
retain their exact compatibility spelling; adjacent prose supplies the precise meaning.
Profiles are therefore **requirement-set coordinates**, not spatial layers. A profile is
satisfied only when a named mechanism has bound evidence for every required fact; Boolean
SAT over caller-supplied assertions establishes only a candidate formula result.

---

## 1. The governing idea

Each closure coordinate names a distinct verification question and failure class. Profile
ordering is a composition rule, not logical entailment between coordinates.

The nearest familiar security analogy is
[defense in depth](https://en.wikipedia.org/wiki/Defense_in_depth_%28computing%29 "Wikipedia orientation; primary references are mapped below"),
but the analogy is limited: VSTD closure coordinates are separately evidenced questions, not
interchangeable controls whose mere quantity establishes assurance. Decomposing assurance
into named components also has precedent in the Common Criteria, while VSTD deliberately
uses different coordinates, evidence rules, and conformance semantics.

**Evidence for one closure coordinate never supplies evidence for another.** In particular,
Refutability evidence does not supply, imply, upgrade, or repair Substrate Accountability,
Verification Surface, or Claim Mechanics evidence. A reported object profile depth of `N`
is only shorthand for the separately checked results required by profiles 1 through `N`.

Reflection and [metalanguage](https://en.wikipedia.org/wiki/Metalogic "Wikipedia orientation; not a proof of the VSTD verification complex")
are useful design analogies for asking what a given
verification surface leaves unexamined. VSTD does not claim that Tarski's
[undefinability theorem](https://en.wikipedia.org/wiki/Tarski%27s_undefinability_theorem "Wikipedia orientation; the theorem does not derive this verification complex")
proves these profile coordinates, that adjacent profiles form formal
metalanguages, or that an earlier-profile implementation is logically incapable of
describing another coordinate's failure. The normative requirement is narrower: an
implementation MUST NOT treat success on one question as evidence for a different
question.

### 1.1 Artifact-first causal provenance orientation

VSTD evaluates bounded propositions about computational processes represented by
identified software, executions, evidence, and resulting artifacts. It does not evaluate
whether an actor is good, bad, reputable, or worthy of trust. Standing alone, an actor's
identity, popularity, repetition, or reputation MUST NOT strengthen an artifact-bound
result. A named mechanism MAY establish an exact attribution, authorization, or separation
proposition by checking the required identity evidence; that result remains an adjacent
proposition and MUST NOT promote an unrelated computational claim.

**Zero identity** means zero identity-derived verdict weight, not anonymity or absence of
identifiers. **Zero knowledge** means zero unevidenced knowledge is presumed: without a
mechanism-earned result for the exact proposition, its state remains `UNKNOWN`. This
architectural zero-knowledge rule MAY be enclosed by cryptographic zero knowledge when a
witness must remain confidential. That enclosure MUST bind the exact software or program
coordinate, predicate, public commitments, output, proof parameters, and verification
mechanism while revealing no more witness information than its declared proof statement.
Cryptographic zero knowledge MUST be claimed only when a named proof system establishes
that property under explicit assumptions; a digest or undisclosed input alone is not such
a proof. The resulting support is bearer- and artifact-bound, never prover-identity-bound.
**Actor** and **artifact** remain contextual roles, not permanent entity classes: software
can be an artifact when created, versioned, or evaluated and an actor when it executes a
transformation.

The capitalized terms **TRUST**, **RUST**, and **ROT** are formal VSTD semantic names, not
acronyms, numbered-profile receipt verdicts, actor ratings, scalar scores, or references to
the Rust programming language. They serialize as typed event kinds only in the non-receipt
`VSTD-GRAPH-ASSURANCE-1` mechanism log. The same bound development graph and its time-indexed lifecycle carry three
distinct relations:

```text
development: ancestor artifact --TRUST through a checked transformation--> descendant
lifecycle:   recorded TRUST    --ROT under typed current-state evidence--> reassessment
diagnosis:   descendant deviation --RUST memetic causal backtrace--> ancestor candidates
```

**Memetic propagation** is the transmission of claim and evidence state through recorded
developmental provenance. The genetic or viral language names this inheritance mechanic:
TRUST moves forward into descendant claim space; RUST moves backward toward recorded
ancestor states; ROT changes the current admissibility of previously recorded support. It
does not claim biological transmission or make identity and reputation sources of
assurance.

**TRUST** is positive support earned when a named mechanism checks an exact
artifact-bound process obligation under declared evidence, specification, bounds, and
trust roots. It moves parent-to-child only across a declared creation or dependency edge
whose relevant transformation obligations pass. Applicable support composes by
intersection and is capped by the weakest required parent or edge; it is never added,
averaged, voted, or converted into actor standing. Every child MUST still discharge its
new predicates, transformations, boundaries, and evidence obligations. A declared trust
root is an explicit dependency and stopping boundary, not actor TRUST.

The reference event mechanism realizes that rule edge by edge. Each TRUST event binds the
historical Graph digest, one exact transformation, its complete input artifact set, one
output artifact, and the exact prerequisite TRUST event for every derived input. A
descendant event is current only while every recursively required event, input, output,
and transformation remains admissible and free of an admissibility-blocking conflict. A
status-conflict resolution projects its selected state into the current view: `VALID` or
`COMPLETED` may restore the affected route, while `REVOKED`, `FAILED`, or another
inadmissible state cannot. Resolving an arbitrary predicate selects a retained value but
does not establish its admissibility effect, so the route remains blocked. The current
reference runtime implements no general non-status admissibility-effect mechanism.
Alternate or duplicate paths remain distinct recorded routes; their count supplies no
added strength or witness independence.

**ROT** is typed, time-indexed degradation of the current admissibility of recorded TRUST.
It requires exact lifecycle or dependency evidence, such as expiry under a declared
freshness bound, `STALE`, `CHALLENGED`, `REVOKED`, `SUPERSEDED`, or an invalidated required
coordinate. Wall-clock passage, age, or popularity alone MUST NOT create ROT. ROT MUST NOT
rewrite an immutable historical receipt or imply that its historical result was false. It
may require reassessment of dependent descendants, but any resulting status change still
requires its named policy or mechanism.

**RUST** is the inverse-TRUST diagnostic mechanic: a typed trace created by an observed
descendant deviation from a declared expectation. It moves child-to-parent only through
historically recorded contributing creation, input, or transformation paths. Current
revocation, challenge, staleness, or conflict can remove a route from current TRUST without
erasing it from historical diagnostic ancestry. The inverse is directional and diagnostic,
not arithmetic: TRUST and RUST never cancel. Distinct comparable backtraces may concentrate
on a shared ancestor and prioritize it for falsification or diagnostic examination.
Transferred RUST establishes ancestral reachability, not current admissibility, direct
observation, falsehood, or causal responsibility; localization requires additional
intervention, ablation, independently bound execution evidence, or an equivalent declared
mechanism.

Reference causal localization MUST select one exact passing RUST event, bind that event's
digest and the exact descendant-deviation proposition digest, confirm the selected artifact
is among that event's recorded ancestors, and preserve those coordinates through replay.

**BLAME** and **GUILT** are bounded artifact-relative diagnostic results, not opposite
directions on the Graph. BLAME requires a named mechanism to establish that an exact
artifact bears responsibility for or materially contributed to an exact localized
deviation. GUILT is the stronger combined proposition: the same localized responsibility
plus an exact obligation that the artifact violated. Thus GUILT contains a responsibility
component, while BLAME alone establishes no obligation or violation. Neither term concerns
actor morality, character, identity, or reputation. Exoneration, obligation satisfaction,
or not-guilty conclusions require their own exact propositions and mechanisms; absent such
evidence the result remains `UNKNOWN`. BLAME and GUILT bind the causal-localization event
digest; that event transitively binds the selected RUST event and exact deviation, so neither
result can float across two deviations on the same descendant.

The word *causal* is required here for recorded developmental and provenance causality:
the graph states which artifacts and transformations produced later claim architecture.
Propagation across those causal-provenance edges does not by itself establish
intervention-level physical causality, causal localization, responsibility, or guilt.

TRUST, ROT, and RUST MUST remain separate. They do not cancel, form one scalar score, or
flow in the opposite direction as inherited truth, decay, or guilt. `UNKNOWN` and
`CONFLICTED` support or lineage MUST remain visible and MUST NOT become a clean signal.
`VSTD-GRAPH-ASSURANCE-1` now serializes an additive, hash-chained reference event log with
the complete historical Graph, exact proposition bindings, and embedded evidence bytes.
`AssuranceLedger` implements mechanism-earned forward TRUST edge by edge, typed ROT,
challenge-ledger status projection, reverse RUST reachability, unique-descendant structural
concentration, additive conflict declaration and resolution, explicit causal localization,
and bounded artifact-relative diagnostic attribution. Duplicate paths and repeated records
remain set-valued and earn no strength. `recheck_assurance_log` reconstructs the historical Graph, rehashes the embedded
evidence, reruns every exact mechanism, reproduces the event hash chain, and compares the
derived current view. A deployment still supplies the proposition-specific mechanisms: the
event format and dispatcher do not create a universal support-transfer algebra or infer
causality from topology.

Artifact freezing and sealing are bounded mechanisms under this orientation, specified
separately in [`ARTIFACT_CONTROL.md`](ARTIFACT_CONTROL.md). A verified freeze preserves
and recomputes exact bytes; a verified seal earns structural closure for those bytes. It
does not earn semantic correctness, prevent ROT, localize RUST, create actor TRUST, or
supply any numbered profile. A sealed realm or temporal descriptor remains a bound input
until its own mapping, continuity, or transition verifier checks the exact proposition.

---

## 2. The object profile axis

VSTD proper governs the verification of **one object**. Call this verification
*mechanics*.

| Numbered profile | Required closure coordinate | Closes | Does not establish |
|---|---|---|---|
| **1** | Claim mechanics | A malformed or tampered statement | Whether the claim applies where it is being applied |
| **2** | Verification surface | A verdict leaking beyond the coordinate actually verified | Whether the evidence behind it is real |
| **3** | Substrate accountability | A lying or unaccountable evidence source | Whether anyone but the declarant could re-derive it |
| **4** | Refutability | A claim unfalsifiable in principle by any outside party | Whether the parties who could check are independent |
| **5** | Witness corroboration | Pseudo-independence — witnesses sharing the declarant's trust root | — |

### 2.1 The single-declarant boundary

**A single declarant can in principle produce the evidence required by profiles 1 through
4.** No second party is required merely to create those bounded inputs and mechanisms.

**Profile 5 is not.** It requires another party to exist, to act, and to be independent.

VSTD-1 records the claim-mechanics status of actor independence but cannot infer it from
two runs or matching artifacts. VSTD-5 requires the corroborating witness procedure that
uses such separately evidenced actor participation; recording a field is not witnessing.

That transition between profiles 4 and 5 is the most important object-axis boundary.
Refutability asks *is a bounded outside check possible?* Witness Corroboration asks *was
one performed, and are the required separation seams evidence-bound?* The first is a
property of the claim surface. The second requires additional evidence about an execution.

An implementation MUST NOT report a profile-5 property on the basis of Refutability evidence.
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

| Numbered profile | Required closure coordinate | Collection proposition |
|---|---|---|
| **Graph-1** | Recorded lineage | members and transformations are represented |
| **Graph-2** | Bounded collection surface | scope does not leak across the collection |
| **Graph-3** | Accountable provenance closure | every reachable substrate is accountable |
| **Graph-4** | Refutable transformation closure | challenges compose across hyperedges |
| **Graph-5** | Corroborated verification network | member and edge witnesses are independently corroborated |

A collection `C` satisfies candidate Graph profile `N` only if all four conditions hold:

1. **Membership floor** — every member rating is at object profile ≥ N.
2. **Provenance closure** — every ancestor reachable from any member is rated at object
   profile ≥ N.
3. **Status admissibility** — no ancestor is `REVOKED`, `CHALLENGED`, `STALE`,
   `UNKNOWN`, or subject to an unresolved `CONFLICTED` record.
4. **Edge evidence** — the transformation hyperedges themselves carry profile-N ratings.

Condition 2 is what a plain minimum over members misses. Condition 4 is what makes this
dynamics rather than aggregation: **a graph is only as verified as its edges**, and an
unevidenced edge between two profile-5 artifacts does not yield a Graph-5 collection.

The candidate Graph profile number is **computed from object and edge ratings, never
declared**:

```
candidate_graph_profile(C) = max { N : CNF_N(C) is satisfiable }
```

The compatibility API `graph_level` implements that function and the frozen Graph receipt
stores its number in a `level` field. The reference implementation searches 5→1 and
certifies its Boolean encoding. Its current rating inputs are caller-supplied, so it reports
a **candidate Graph profile** with
`conformance_status = NOT_ESTABLISHED`; the certificate proves the computation over
those inputs, not the validity of the ratings. At a result below 5, the grounded `FAIL`
certificate for profile `N+1` explains that candidate ceiling. Graph conformance additionally
requires evidence-bound ratings under the applicable object and edge profiles.
`establish_graph_level` supplies that path: it rehashes embedded evidence, reruns the exact
registered rating mechanism for every member, ancestor, and reached edge, then recomputes
and kernel-checks the Graph certificate. Each rating proposition binds a digest over the
historical Graph bytes, deduplicated member set, collection identifier, and claim binding;
neighboring collection or topology evidence therefore contributes zero. Missing,
non-integer, or non-passing bindings also contribute zero and prevent conformance. Profile
zero never receives `ESTABLISHED`. The record builder recomputes before serialization, and
the rechecker preserves offline replay.

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

This is why the object profile axis tops out at corroboration rather than proof of global absence. Profile 5
does not detect hidden work. It makes the *independence status* of declared work legible,
and leaves the undeclared remainder named and quantified rather than silent.

---

## 5. Certificates for refusals

This section applies to the finite propositional decision procedures used by the
reference Refutability implementation.

A satisfiable result already carries its certificate: the model. Anyone can evaluate it
against the clause set without a solver.

An unsatisfiable result, by default, carries nothing but the solver's word.

For a fail-closed standard, **refusals are the most consequential output**. A standard
whose passes are checkable and whose refusals are not has its assurance backwards.
The Refutability coordinate therefore requires a refutation certificate — a clausal proof, verifiable by
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

### 5.1 The internal VSTD-4 rung sequence

VSTD-4 contains fourteen ordered rungs, from decision certification through
semantic binding, anti-equivocation, bounded portable checking, availability,
precommitment, challenge handling, degradation, and compositionality. Its normative depth
is computed:

```
vstd4_depth(claim) = max { k : CNF_4k(claim) is satisfiable }
```

The certificate for rung `k+1` explains a partial VSTD-4 normative depth. Only established
VSTD-4 conformance at normative depth 14 admits a claim to any VSTD-5 procedure. The current
reference `vstd4_depth` function instead computes a structural candidate from
caller-supplied rung references, labels conformance `NOT_ESTABLISHED`, and never admits
VSTD-5. `establish_vstd4` reruns exact VSTD-1/2/3 and rung bindings and may report
`EVIDENCE_BOUND` / `ESTABLISHED` only when every mechanism and the independent kernel pass.
See `VSTD-4.md` for the normative rung graph and `VSTD4-GDC-1` format.

---

## 6. Composition — closure coordinates do not supply or substitute

Closure-coordinate results may be composed into an object profile-depth report. They do
not replace, entail, or supply one another.

- Refutability without Substrate Accountability certifies a claim whose evidence source is unaccountable.
- Witness Corroboration without Refutability solicits witnesses for a claim no witness could check.
- Verification Surface without Claim Mechanics scopes a statement whose integrity is unestablished.

An implementation reporting object profile depth *N* MUST present separately checkable
evidence for every required coordinate in profiles 1 through *N*. Conformance may also be
reported for one coordinate without claiming cumulative profile depth. Incremental
Substrate Accountability profiles are declared in VSTD-3 §7.

"Higher is more protected" is true only in the sense that more classes of failure are
closed. It never means the prerequisite coordinates became unnecessary.

---

## 7. Numbering

- **Numbered profiles use integers**: VSTD-1 … VSTD-5, VSTD-Graph-1 … VSTD-Graph-5.
- **Repository releases use [semantic versioning](https://semver.org/)** and are independent
  of profile numbers.

A release version never implies a numbered profile, and a numbered profile never implies a
release. See
`WIRE_IDENTIFIERS.md` for serialized receipt identifiers and historical public filenames.

---

## 8. Intellectual lineage and adjacent precedents

The verification complex is VSTD project architecture; no cited work proves that these five
coordinates on either axis are
necessary, sufficient, complete, or uniquely ordered. The references below show that its
individual design pressures have established precedents in security engineering,
provenance, reproducible systems, and proof checking. The
[`concept guide`](https://github.com/TimeLordRaps/verifier/blob/main/docs/CONCEPTS_AND_PRECEDENTS.md) provides definitions, additional
sources, and explicit non-equivalences.

| VSTD pressure | Adjacent precedent | What the precedent contributes—and does not |
|---|---|---|
| Separate failure surfaces and fail-closed defaults | Saltzer and Schroeder, [*The Protection of Information in Computer Systems*](https://web.mit.edu/Saltzer/www/publications/pubs.html) | Classic principles include fail-safe defaults, complete mediation, separation of privilege, and least common mechanism. They motivate separation; they do not derive VSTD's coordinate count. |
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
