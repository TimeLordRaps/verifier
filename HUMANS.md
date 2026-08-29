# Human operating guide for Verifier Standard (VSTD)

**Role:** practical reasoning guide for human maintainers and reviewers. Normative meaning
remains in [`standard/`](standard/); this file defines no receipt, status, or serialized receipt format.

## Three repository controls

| Surface | Use it for | Do not use it for |
|---|---|---|
| [`AGENTS.md`](AGENTS.md) | Rules for automated and coding-agent work | Human interpretation or normative semantics |
| `HUMANS.md` | The questions a human asks before relying on a result | A second specification |
| [`TIME.md`](TIME.md) | The live annunciator for contradictions in this repository's authoritative state | Runtime evidence conflicts, roadmaps, or ordinary limitations |

## Traverse a claim with the five As

The five As are a human traversal over existing VSTD records, not a new ontology or an
assurance score.

1. **ASSURE — establish the input state.** Identify the evidence or previously assessed
   claim. Preserve its provenance, evidence basis, bounds, trust roots, limitations,
   freshness, current state, conflicts, and unknowns.
2. **ATTRIBUTE — name the supported proposition.** State the exact subject and predicate,
   the mapping, extraction, or transformation that connects the evidence to them, its scope
   and bounds, and any information loss. A reference without a checked mapping is not
   attributed support.
3. **ASSIGN — locate the evidenced execution.** Record only the coordinates established for
   the computation, execution instance, software/runtime, machine/substrate, and optional
   actor or operator. Partial assignment is valid. Assignment does not imply trust,
   authorization, independence, or responsibility.
4. **ASSESS — run the named mechanism.** Ask which bounded proposition this verifier,
   specification, profile, trust-root set, and resource bound actually checks. The result
   earns no predicate outside that mechanism.
5. **ASSURE — preserve the output as new evidence.** Record the assessed claim with lineage
   to every input, mechanism, bound, limitation, conflict, and unknown. A later assessment
   may consume it, but propagation alone cannot strengthen it or rewrite its ancestors.

> Storage location, field name, repetition, graph multiplicity, actor reputation, and
> propagation add no semantic strength. Every increase in assurance names the mechanism
> that earned it.

## Read artifact state as TRUST, ROT, and RUST

These capitalized terms are formal semantic names, not acronyms, actor ratings, scalar
scores, serialized receipt values, or references to the Rust programming language.

| Term | Human reading |
|---|---|
| **TRUST** | A named mechanism earned bounded forward support for an exact artifact-bound process claim. It says nothing about whether an actor is good, bad, reputable, or trustworthy. |
| **ROT** | Typed lifecycle or dependency evidence degraded the support's current admissibility. Reassess affected dependents, but preserve the immutable historical receipt and its original result. |
| **RUST** | An observed descendant deviation can be traced backward through recorded contributing ancestry. The trace identifies candidates for examination; it does not prove ancestor falsehood, guilt, responsibility, or causal localization. |

The reference `AssuranceLedger` records these as additive Graph events. Treat structural
RUST concentration as a triage count of unique deviating descendants, never causal
strength. A bounded artifact-relative `BLAME` or `GUILT` result exists only after separate
localization and attribution mechanisms pass; it never evaluates an actor's character.
For reliance, replay the portable log with `recheck_assurance_log`: a stored event word or
hash chain without successful evidence rehash and mechanism execution is not current
assurance. When upstream status changes, inspect `current_trust_events` and the deduplicated
`impacted_descendants` reassessment surface rather than deleting historical results.

Zero identity means identity contributes no verdict weight by itself. Zero knowledge means
no unevidenced proposition is presumed: absent a mechanism-earned result, keep `UNKNOWN`.
When a witness must remain confidential, a cryptographic zero-knowledge proof can enclose
that architectural rule by binding the exact program, predicate, commitments, output,
parameters, and verifier. Check the proof system rather than the prover's identity. A digest
or undisclosed input alone is not a zero-knowledge proof. Identity, authorization,
attribution, or actor separation may still be checked as their own bounded propositions;
they never become TRUST in the validity of the represented computational process.

## Read freeze, seal, and thaw separately

- A **freeze** means the current preserved bytes, paths, manifest, and read-only tripwire
  recomputed. It does not mean an external archive retained them or privileged mutation
  is impossible.
- A **seal** means the finite signature-and-identifier closure verified. It is not
  encryption and does not establish correctness, ownership, authorization, trusted time,
  or actor trust. Use an expected artifact/key coordinate to detect complete substitution.
- A **thaw** creates a mutable descendant. `THAWED_CLEAN` records present equality to the
  parent identity; `THAWED_DIRTY` records divergence. Neither state changes the parent.

A time capsule adds a realm-specific temporal proposition and evidence. A structural seal
alone does not establish continuous custody between endpoints, a realm's physical laws,
cross-realm mappings, or the truth of generated text.

## What a human may conclude

These terms describe different evidence states; none substitutes for another.

| Evidence state | Safe conclusion |
|---|---|
| **Recorded** | The identified statement or bytes are present at the named coordinate. Their presence does not establish truth or validation. |
| **Checked** | The named mechanism ran its declared checks. Read its result and limits; execution alone is not a pass. |
| **Bound** | The named digest, commitment, or coordinate ties the result to the declared subject inside its scope. Binding does not establish the subject's external truth. |
| **Reproduced** | A declared rerun or comparison met the recorded equivalence rule. It does not by itself establish correctness, provenance completeness, or independent actors. |
| **Independently corroborated** | Distinct actors and every independence seam required by the applicable profile are evidence-bound and checked. Matching runs, processes, machines, or self-declared references are insufficient. The version 1.2.0 bundled runtime has no actor/execution evidence-binding adapter and cannot derive `EVIDENCED`. |

Status words are profile-scoped. Use their controlling specification; the safe minimum
reading is:

| Result | Safe conclusion |
|---|---|
| `PASS` | The named mechanism established its bounded proposition under the recorded preconditions. |
| `FAIL` | The mechanism established the specified violation, counterexample, or failed condition. Do not dilute an evidenced failure into uncertainty. |
| `UNKNOWN` | Available evidence, implemented fragment, or declared resources did not decide the proposition. This proves neither truth nor falsehood. |
| `CONFLICTED` | Incompatible evidence is retained without collapse into a clean state. This is an evidence/runtime condition, not a TIME repository contradiction. |
| `UNSUPPORTED` | The named mechanism lacks the capability or observation surface required for the proposition. This is not a `FAIL` and not a promise of future support. |

First-hand and second-hand identify **provenance, not strength**. A first-hand
self-observation can be weak; a second-hand certificate can be strongly bound to a narrow
proposition. Judge the mechanism and binding, not the label, actor identity, or reputation.

VSTD allows a human to select trust roots, compare bounded evidence, and make a separate
risk or action decision. It does not make that judgment for the human. Record any judgment
as a distinct decision with its own basis; do not rewrite a verifier result to match it.

## Read and escalate

When surfaces appear to disagree, use the complete authority order in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): normative numbered-profile document, serialized receipt identifier/profile,
published schema, typed runtime and validator, conformance tests, then generated references
and examples. A lower surface cannot silently redefine a higher one.

Escalate to [`TIME.md`](TIME.md) when current authoritative repository surfaces remain
incompatible—for example normative text versus schema, schema versus runtime, runtime versus
conformance tests, a public claim beyond implementation, incompatible frozen semantics, or a
five-As transition that gains assurance without a mechanism. Preserve both sides and exact
coordinates; resolve only from evidence.

Do **not** escalate a receipt's `CONFLICTED` evidence, an honest `UNKNOWN`, a roadmap item,
or speculative research to TIME. Development branches may keep precise open contradictions.
For publication, the tag-triggered workflow checks the exact tagged `TIME.md` and fails
unless it contains exactly one `Status: CLEAR` line; maintainer judgment cannot override
that release invariant.
