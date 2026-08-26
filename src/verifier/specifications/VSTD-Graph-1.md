# Verifier Standard (VSTD)-Graph-1 — Recorded Lineage

> **Acronyms:** conjunctive normal form (CNF); Davis-Putnam-Logemann-Loveland (DPLL); operating system (OS);
> Boolean satisfiability problem (SAT); Secure Hash Algorithm 256-bit (SHA-256); satisfiability modulo theories (SMT);
> Software Package Data Exchange (SPDX); uniform resource identifier (URI).

> Reader aid: [concept glossary and primary precedents](https://github.com/TimeLordRaps/verifier/blob/main/docs/CONCEPTS_AND_PRECEDENTS.md).

**Layer:** 1 of 5 on the graph axis (see `LADDER.md`)
**Receipt wire format:** `schema_version = "VSTD-DATA-0.1"` — frozen; see `WIRE_IDENTIFIERS.md`
**Status:** Project Specification with Implemented Reference Subset
**Maintainer:** TimeLordRaps
**Date:** 2026-08-21

---

## 1. Purpose & Core Thesis

> **Dataset and training provenance is the foundational substrate of computational verifiability: data sits directly upstream of training runs, checkpoints, fine-tuned adapters, evaluations, model behavior, downstream software products, licensing, and attribution.**

`VSTD-Graph-1` establishes a content-addressed **Hypergraph Specification** for
capturing recorded and evidenced lineage of datasets, neural weights, and computational
outputs within a declared observation boundary. It does not infer unobserved history or
prove that the recorded graph is complete in the real world. Transformations are
first-class **N-ary Hyperedges**, which represent many-to-many merges, sharding, and
multi-input processing without flattening those relationships into ambiguous binary
links.

This document is the first rung of the Graph axis. `VSTD-Graph-2.md` through
`VSTD-Graph-5.md` apply progressively stronger object and transformation-edge
requirements to the same closed collection. `LADDER.md` defines the computed
level and its ceiling certificate; `verifier.data.graph_level.graph_level`
implements that computation.

---

## 2. The Provenance Hypergraph Abstraction

A Dataset Provenance Hypergraph is a 6-tuple:
$$\mathcal{H} = (\mathcal{A}, \mathcal{T}, \mathcal{C}, \mathcal{R}, \mathcal{P}, \mathcal{X})$$

### 2.1 Artifact Nodes ($\mathcal{A}$)
Represents any discrete, inspectable data object or model state:
- `artifact_id`: Unique identifier (e.g. `art:sha256:...`).
- `artifact_type`: `RAW_SOURCE_FILE`, `CORPUS`, `SHARD`, `DATASET_SPLIT`, `TOKENIZED_CORPUS`, `CHECKPOINT`, `ADAPTER`, `MODEL`, `EVALUATION_REPORT`, `SUBMISSION_ARTIFACT`.
- **Content-Addressable Cryptographic Digests**:
  - `content_digest`: a declared `SHA-256` over raw payload bytes. It becomes a verified
    byte-identity statement only when a named mechanism actually hashes accessible bytes
    and binds the observation as evidence.
  - `metadata_digest`: a declared `SHA-256` over explicitly normalized metadata.
  - `provenance_digest`: a declared `SHA-256` over an explicitly canonicalized ancestor
    subgraph.
- `byte_size`, `record_count`, `mime_type`, `storage_uris`.
- `status`: `VALID`, `CHALLENGED`, `STALE`, `SUPERSEDED`, `REVOKED`, `UNKNOWN`.

### 2.2 Transformation Hyperedges ($\mathcal{T}$)
Represents a declared N-ary transformation relationship consuming inputs and producing
outputs. The edge records ancestry; it does not by itself establish causal influence:
- `transformation_id`: Unique process identifier.
- `transformation_type`: `COLLECTION`, `EXTRACTION`, `FILTERING`, `DEDUPLICATION`, `NORMALIZATION`, `AUGMENTATION`, `SYNTHETIC_GENERATION`, `TOKENIZATION`, `TRAINING`, `FINE_TUNING`, `DISTILLATION`, `QUANTIZATION`, `EVALUATION`.
- `inputs`: List of input artifact references with role bindings (e.g. `TRAINING_SPLIT`, `BASE_WEIGHTS`, `CONFIG`).
- `outputs`: List of produced artifact references with role bindings (e.g. `CHECKPOINT_WEIGHTS`, `METRICS_LOG`).
- `software_provenance`: Git repository, commit SHA, branch, clean/dirty state, script path, execution command.
- `parameters`: Exact hyperparameter dictionary, filter criteria, or random seeds.
- `execution_environment`: Python runtime, host OS, hardware acceleration class, timestamp.

### 2.3 Contributor Nodes ($\mathcal{C}$)
- `contributor_id`, `name`, `contributor_type` (`INDIVIDUAL`, `ORGANIZATION`, `MODEL_GENERATOR`, `AUTOMATED_SYSTEM`), `uri`.

### 2.4 Rights & Licensing Nodes ($\mathcal{R}$)
- `rights_id`, `license_spdx` (e.g. `CC-BY-NC-4.0`, `MIT`, `Apache-2.0`), `commercial_allowed`, `attribution_required`.

### 2.5 Policy & Formal Constraints ($\mathcal{P}$)
- Machine-checkable Boolean admission rules. The current reference subset evaluates
  bounded CNF with its minimal DPLL implementation; general SMT is not implemented.

### 2.6 Conflict Records ($\mathcal{X}$)
- `conflict_id`, `subject_id`, and `predicate` identify the disputed coordinate.
- `competing_values` retains at least two incompatible values.
- `evidence_refs` retains at least two evidence records rather than selecting a winner.

A conflict record does not mutate the frozen artifact-status vocabulary. It makes the
subject inadmissible to a clean computed Graph level. The current reference implementation
has no conflict-resolution transition; later resolution must be additive and must retain the
competing evidence.

---

## 3. Provenance Completeness Dimensions

`VSTD-Graph-1` rejects treating a monolithic score as proof. The reference subset
reports six descriptive dimensions plus a disclosed weighted summary:

$$\mathbf{C} = \langle C_{\text{src}}, C_{\text{trans}}, C_{\text{integ}}, C_{\text{lic}}, C_{\text{contrib}}, C_{\text{lineage}} \rangle$$

1. **Source-declaration coverage ($C_{\text{src}}$)**: Share of root artifacts with a
   non-empty storage URI or `source_repository` declaration $[0.0, 1.0]$.
2. **Transformation-declaration coverage ($C_{\text{trans}}$)**: Share of hyperedges
   with a recorded commit identifier or script path $[0.0, 1.0]$.
3. **Content-digest declaration coverage ($C_{\text{integ}}$)**: Share of artifacts with
   a syntactically valid 64-hex-character digest $[0.0, 1.0]$. This metric does not by
   itself show that the referenced physical bytes were rehashed.
4. **License-metadata coverage ($C_{\text{lic}}$)**: Share of root artifacts linked to
   an explicit rights record $[0.0, 1.0]$. It is not a legal-validity score.
5. **Contributor Coverage ($C_{\text{contrib}}$)**: Share of artifacts attributed to identified agents $[0.0, 1.0]$.
6. **Downstream Lineage Depth ($C_{\text{lineage}}$)**: Integer topological depth from
   root sources to reachable outputs.

The current weighted summary is
`0.25*C_src + 0.25*C_trans + 0.25*C_integ + 0.15*C_lic + 0.10*C_contrib`.
It is a coverage summary, not a probability, trust score, or verification verdict.

---

## 4. Epistemic Incompleteness & Fail-Closed Law

* **The `UNKNOWN` Principle**: If an artifact's status is omitted, or its upstream
  origin or transformation is not evidenced, the applicable state remains `UNKNOWN` or
  the applicable coverage dimension remains incomplete. It never silently becomes
  observed real-world truth.
* **The `CONFLICTED` Principle**: Incompatible retained evidence remains an explicit
  conflict record. It is neither averaged nor collapsed into `UNKNOWN`, `VALID`, or a
  scalar confidence value.
* **Fail-Closed Policy Admission**: A policy passes only the Boolean condition it
  actually encodes. For example, "no ancestor is marked `REVOKED`" does not establish
  that every ancestor is `VALID`; a clean-ancestor policy must explicitly require
  `VALID` and reject `UNKNOWN`, `CHALLENGED`, `STALE`, and `SUPERSEDED`.

---

## 5. Challenge & Revocation Blast Radius

When an upstream source $S$ is marked `REVOKED` (e.g. due to copyright claim, data poisoning, or corruption):
1. The hypergraph query engine computes the forward reachability closure:
   $$\text{BlastRadius}(S) = \{ a \in \mathcal{A} \mid S \rightsquigarrow a \}$$
2. An integrating lifecycle controller can use that returned set to create additive
   `CHALLENGED` or `REVOKED` records. The reference query does not silently mutate
   historical artifact nodes.

---

## 6. Threat Model & Explicit Non-Guarantees

### What the implemented reference subset can establish
- **Receipt integrity**: Detects changes to stable fields bound by the receipt's
  canonical digest.
- **Recorded graph structure**: Checks references, acyclicity, reachability, and the
  declared coverage metrics of the stored hypergraph.
- **Declared lineage queries**: Computes ancestors, descendants, and forward blast
  radius over recorded edges.
- **Bounded policy evaluation**: Evaluates the recorded CNF condition over its declared
  graph-to-variable mapping. This does not prove that the mapping captured every
  real-world fact.
- **Byte identity when separately observed**: A named adapter that rehashes accessible
  bytes can establish whether those bytes match a recorded digest at that observation
  time. Receipt validation alone does not access unbundled upstream files.

### What `VSTD-Graph-1` Does NOT Guarantee
- **Real-World Ground Truth**: A hash proves byte identity; it does not prove the data is empirically accurate.
- **Legal Copyright Validity**: A declared SPDX license string records claimed provenance; it is not a judicial copyright ruling.
- **Authenticity of declarations**: A digest binds bytes or fields; it does not prove
  that a claimed origin, contributor, execution, or license declaration is authentic.
- **Complete real-world lineage**: Missing instrumentation, hidden inputs, pre-observation
  contamination, and out-of-band transformations remain outside the graph unless
  independently evidenced.
- **Automatic physical-file checking**: A stored VSTD-Graph receipt validates its own
  stable content. It flags a physical-file mismatch only when an adapter supplies and
  rehashes that file.
- **Translation completeness**: SAT success establishes the encoded formula, not the
  completeness or correctness of the translation from policy prose or the external
  world into that formula.
