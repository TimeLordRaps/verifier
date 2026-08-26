# Verifier Standard (VSTD)-2 — Verification Surface

> **Acronyms:** abstract syntax tree (AST); continuous delivery or deployment (CD); continuous integration (CI);
> intermediate representation (IR); trusted computing base (TCB).

> Reader aid: [concept glossary and primary precedents](https://github.com/TimeLordRaps/verifier/blob/main/docs/CONCEPTS_AND_PRECEDENTS.md).

**Layer:** 2 of 5 on the object axis (see `LADDER.md`)
**Receipt wire format:** `schema_version = "VSTD-0.2"` — frozen; see `WIRE_IDENTIFIERS.md`
**Status:** Additive experimental standard with an implemented vertical slice
**Maintainer:** TimeLordRaps
**Date:** 2026-08-20

---

## 1. Relationship to earlier standards

VSTD-2 adds a verification-geometry ontology to VSTD-1. It does not replace or
reinterpret historical receipts whose wire identifiers are `VSTD-0.1` or
`VSTD-DATA-0.1`. A document conforms to this
extension only when it declares `schema_version = "VSTD-0.2"`; older validators may
continue to process their existing receipt kinds unchanged.

VSTD-1 answers how a bounded claim carries evidence, provenance, a checker judgment,
an explicitly evidenced independence basis, and reproducibility information. VSTD-Graph-1 answers how artifacts and
transformations compose into a provenance hypergraph. VSTD-2 answers a different
question: **what geometry was selected for verification, what did reconstruction
expose that the geometry missed, and has the sufficiency of the declared closure
itself been verified?**

The normative typed slice is implemented by:

- `verifier.core.geometry`;
- `receipts/schema/vstd2_receipt.json`; and
- `tests/test_verification_geometry.py`.

---

## 2. Epistemic law

VSTD MUST NOT claim more than the declared verification surface and actual evidence
establish.

Assumptions MUST NOT manufacture closure. Unknownness, unsupported structure,
missing evidence, unresolved translation, an unverified mechanism, and an unverified
root are information. They MUST remain explicit states, residuals, valences, or
horizons.

A declared trust root is a boundary, not evidence that the root is true. When a
derivation stops at such a boundary, the geometry MUST record a `TRUST_ROOT` horizon
and MUST NOT claim self-closure.

---

## 3. Verification geometry

### 3.1 Subject and locus

A **subject** is the overall entity under consideration. A subject may itself become
an addressable entity inside a larger subject.

A **locus** is a scale-independent, addressable place or entity to which verification
can attach. A locus may recursively contain other loci. Repositories, functions, AST
nodes, instructions, dataset rows, models, processes, interfaces, and dependency
relations are all possible loci.

`LOCUS` answers **where or what**.

### 3.2 Facet

A **facet** is a dimension of assurance applicable to a locus, such as functional or
semantic correctness, termination, determinism, integrity, provenance,
reproducibility, translation fidelity, performance, or security.

`FACET` answers **in what respect**.

A facet is not a constituent part of a subject. New facets remain expressible through
stable identifiers rather than a permanently closed enumeration.

### 3.3 Region, grain, and stratum

A **region** is a meaningful collection of loci considered together, whether or not
they are syntactically contiguous. The implemented slice represents a region through
a named surface selection; a separate region object is deferred until distinct region
semantics are demonstrated.

**Grain** is the resolution at which a subject is decomposed: repository, module,
function, statement, instruction, row, checkpoint, or another declared resolution.

**Stratum** is the representation layer: requirement, source, AST, IR, assembly,
execution, output, or verification.

Grain and stratum are orthogonal. Two loci may have function grain while one belongs
to source stratum and another to execution stratum.

### 3.4 Seam

A **seam** is an interface, transition, dependency, or translation boundary between
loci. A seam records its source locus, target locus, and relation. A seam can be made
a locus when assurance must attach to the seam itself.

### 3.5 Coordinate and surface

A **coordinate** is a locus-facet pair:

`coordinate = locus x facet`

A verification claim attaches to a coordinate or an explicitly represented relation
among coordinates.

A **verification surface** is the declared set of coordinates and relevant seams for
which verification status is claimed. For subject `S`, loci `L`, and facets `F`:

`surface(S) = (C_selected, E_selected)`

where `C_selected` is a finite subset of `L x F` and `E_selected` is the finite set of
relevant seams. Coordinates not selected by the surface do not inherit its verdict.

### 3.6 Horizon

A **horizon** is a localized point at which the current verification derivation cannot
proceed because evidence, representation, mechanism, grain, ontology, or a root ends.
A horizon proves nothing beyond itself. It records the limit without converting the
limit into an assumption.

---

## 4. Decomposition, reconstruction, and deconstruction

**Decomposition** resolves or partitions a subject into loci at a declared grain. It
asks: *what parts can be exposed?*

**Reconstruction** generates, reproduces, simulates, or predicts a subject or its
relevant behavior from the represented geometry. It asks: *is this representation
sufficient to regenerate what mattered?*

**Deconstruction** is the iterative inference of a reconstructible verification
geometry. It combines decomposition, reverse engineering, reconstruction pressure,
residual analysis, and ontology refinement:

```text
SUBJECT --deconstruct--> GEOMETRY
   ^                       |
   |                       |
   +----reconstruct--------+
```

Deconstruction may recurse over the subject by exposing finer loci. It may also
recurse over the ontology when a residual cannot be expressed by the current
verification language. Neither recursion licenses invented structure.

Zero residual is not itself a valid objective. A residual eliminated by enlarging an
unverified TCB, deleting unsupported semantics, overfitting a reconstruction, or
adding an assumption remains epistemically unresolved. Every material residual MUST
instead be resolved, localized, represented, or terminated at a horizon.

---

## 5. Residuals and novelty

### 5.1 Residual taxonomy

A **residual** is an evidenced difference between observation and the current
verification geometry or reconstruction.

- `STRUCTURAL`: observed structure absent from the locus/dependency geometry.
- `BEHAVIORAL`: observed behavior differs from reconstructed or predicted behavior.
- `SEMANTIC`: source meaning differs from meaning established by its formalization.
- `ONTOLOGICAL`: the current verification ontology cannot adequately classify the
  observed phenomenon.

A residual has a disposition:

- `OPEN`: discovered but not yet adequately localized;
- `LOCALIZED`: bound to a locus, coordinate, or seam but not discharged;
- `RESOLVED`: discharged by represented evidence and refinement; or
- `HORIZON`: localized at an explicit boundary beyond which derivation cannot proceed.

An assumption is not a residual disposition.

### 5.2 Novelty

**Novelty** is residual structure that cannot be discharged using the currently
declared geometry or mechanism vocabulary. A novelty claim MUST cite its grounding
residual and classify the insufficiency as grain, locus, facet, seam, stratum,
mechanism, or ontological novelty. Surprise alone is not novelty.

---

## 6. Closure, valence, and self-closure

### 6.1 Ordinary bounded closure

Ordinary closure asks whether all obligations selected by the declared surface have
been discharged. The implemented vertical slice permits **bounded closure up to an
explicit horizon** when:

1. every selected coordinate has a `VERIFIED` judgment backed by evidence and an
   identified mechanism; and
2. every material residual is `RESOLVED` or explicitly terminated at a `HORIZON`.

This form of closure is never evidence about what lies beyond a horizon.

### 6.2 Verification valence

**Verification valence** is an open relational or evidentiary capacity licensed by
the existing geometry. A valence identifies its source, the relation or evidence slot
that the geometry implies, and whether that slot is `OPEN`, `DISCHARGED`, or terminated
at a `HORIZON`.

Valence describes the shape of an unresolved obligation. It does not invent the
entity or evidence that would satisfy it.

### 6.3 Self-closure

**Self-closure is closure that recursively verifies the sufficiency of its own
declared closure conditions and exposes remaining verification valence rather than
assuming it away.**

Self-closure requires:

1. structurally valid verification geometry;
2. ordinary bounded closure;
3. every material residual `RESOLVED`, not merely stopped at a horizon;
4. every verification valence `DISCHARGED` by evidence;
5. every material verification mechanism post-verified by identified evidence;
6. no unresolved evidence, mechanism, ontology, grain, representation, or trust-root
   horizon; and
7. a finite, contiguous sequence of adjacent verification orders.

If any condition fails, the geometry MUST refuse self-closure and enumerate the
blockers.

### 6.4 Higher verification orders

Higher-order verification is represented as a finite sequence:

- `V0`: verification of the primary subject;
- `V1`: verification of V0's geometry, evidence, mechanisms, and selected surface;
- `V2`: verification of V1's sufficiency criteria; and so on only when evidenced.

Each order greater than zero MUST verify exactly the preceding order. Skipped layers
violate the adjacent-layer invariant. A finite document never claims that simply
adding one more self-description would close the sequence; inability to justify the
next order is a horizon or open valence.

---

## 7. Lifecycle vocabulary

- `PRE_VERIFIED`: the coordinate or surface exists before an applicable verification
  has had the opportunity to establish a result. It is not a passing status.
- `VERIFIED`: a bounded coordinate passed an applicable mechanism with bound evidence,
  declared limitations, freshness, and non-expansion.
- `POST_VERIFIED`: a passing result is bound to a frozen, content-identified snapshot
  of the subject, evidence, mechanism state, and relevant environment.
- `GEOMETRY_INSPECTABLE`: the declared situation has an inspectable geometry that
  represents covered, unsupported, indeterminate, and horizon-bounded coordinates
  honestly. This vocabulary is prose-only: it is not a wire value, and it is not a
  member of the `CoordinateStatus` enumeration serialized in a VSTD-2 receipt.
- `COMPLETELY_VERIFIED`: the declared closed surface satisfies self-closure. It never
  means universal truth, unbounded safety, or permanent validity.

Systems SHOULD minimize pre-verified surface area and dwell time. Post-verified
snapshots are useful compositional checkpoints, but continuous verification is
preferred: material changes invalidate dependent judgments and create new
pre-verified coordinates until checks pass again.

---

## 8. Verifying processes and the common verification language

A **verifying process** has an attached self-verification pipeline that observes its
operation, translates relevant facts into the common verification geometry, applies
mechanisms, and emits evidence about both the process and the pipeline.

Self-observation is not self-certification. A pipeline that does not represent its own
mechanisms, dependencies, translation limits, and horizons is only
verification-instrumented.

The common **verification language** is the typed graph of subjects, loci, facets,
coordinates, seams, surfaces, judgments, mechanisms, residuals, horizons, valences,
and adjacent verification layers. It is not an intermediate programming language for
every CI/CD system. Native workflows translate observable verification events through
thin adapters into this graph:

```text
native process -> adjacent adapter -> verification geometry -> verifier
```

The adapter and verifier become loci in the next adjacent verification layer. This
keeps verification orders adjacent and finite instead of recursing into infinite
workflow abstraction.

The language is self-describing only in the bounded sense that its schema, adapter,
validator, and closure criteria can themselves become subjects. Their description is
not evidence of their correctness.

---

## 9. Reprogramming compatibility

VSTD-2 reserves no universal transformation engine. It remains compatible with the
following future pattern:

```text
SUBJECT S0
  -> deconstruct to GEOMETRY G0
  -> transform selected verified coordinates into G1
  -> reconstruct SUBJECT S1
  -> verify the transformation and resulting behavior
```

**Reprogramming** is a verified transformation of selected coordinates in a
deconstructed representation followed by reconstruction into a modified subject.
Any future implementation MUST receipt the selection, transformation, reconstruction,
residuals, and resulting verification without silently transferring S0 judgments to
S1.

---

## 10. Conformance and present limits

A VSTD-2 geometry document conforms to the implemented vertical slice when:

1. it validates against `vstd2_receipt.json`;
2. `validate_geometry` returns no errors;
3. every `VERIFIED` judgment cites evidence and a known mechanism;
4. references and containment are internally consistent;
5. reconstruction residuals are typed and localized;
6. verification orders obey the adjacent-layer invariant; and
7. closure is reported by `assess_closure` without suppressing its blockers.

The current slice does not infer loci automatically, prove ontology completeness,
translate arbitrary CI/CD workflow languages, or certify its own Python runtime. Those
are explicit present limits, not assumed capabilities.
