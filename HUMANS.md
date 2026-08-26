# Human operating guide for Verifier Standard (VSTD)

**Role:** practical reasoning guide for human maintainers and reviewers. Normative meaning
remains in [`standard/`](standard/); this file defines no receipt, status, or wire format.

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
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): normative layer document, frozen wire/profile,
published schema, typed runtime and validator, conformance tests, then generated references
and examples. A lower surface cannot silently redefine a higher one.

Escalate to [`TIME.md`](TIME.md) when current authoritative repository surfaces remain
incompatible—for example normative text versus schema, schema versus runtime, runtime versus
conformance tests, a public claim beyond implementation, incompatible frozen semantics, or a
five-As transition that gains assurance without a mechanism. Preserve both sides and exact
coordinates; resolve only from evidence.

Do **not** escalate a receipt's `CONFLICTED` evidence, an honest `UNKNOWN`, a roadmap item,
or speculative research to TIME. Before release, the maintainer should confirm
`TIME.md` says `Status: CLEAR`. This is a human check in version 1.2.0, not a continuous
integration gate; development branches may keep precise open contradictions.
