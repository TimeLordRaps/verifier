# Experimental artifact-first mechanisms

> **Acronyms:** reduced instruction set computer (RISC); Verifier Standard (VSTD);
> zero-identity/zero-knowledge (ZIZK).

This directory does **not** make VSTD's ZIZK artifact-first architecture experimental.
That governing orientation is normative in
[`standard/LADDER.md` section 1.1](../../standard/LADDER.md#11-artifact-first-causal-provenance-orientation).

TRUST is mechanism-earned forward artifact support; ROT is typed, time-indexed
degradation of current admissibility; and RUST is the inverse-TRUST diagnostic backtrace
toward recorded ancestors. These are formal semantic names, not acronyms, actor ratings,
receipt verdicts, scalar scores, or references to the Rust programming language. They
serialize as typed events in `VSTD-GRAPH-ASSURANCE-1`, not self-authenticating status words.

## Implemented bounded mechanisms

- Assurance event serialization and replay: `recheck_assurance_log` reconstructs the
  historical Graph, rehashes embedded evidence, and rechecks the bound propositions for
  the recorded events.
- Edge-local TRUST transfer: `record_trust` binds an exact transformation and prerequisite
  events; degraded or conflicted routes are excluded from current support without deleting
  history. This is not a universal support algebra.
- ROT derivation and propagation through challenge projection produce additive current-state
  overlays.
  Descendant discovery alone does not establish a descendant verdict.
- RUST concentration and localization use reverse reachability, deduplication, and diagnostic
  attribution in bounded reference mechanisms. Structural reachability alone does not establish
  causality, blame, guilt, or responsibility.

The [architecture ownership matrix](../../docs/ARCHITECTURE.md#governing-zizk-architecture-and-mechanism-ownership)
states the exact mechanism boundaries. Their implementation does not establish independent
deployment, external interoperability, or domain-general correctness.

## Remaining experimental work

Open work includes domain-specific transfer, current-admissibility and localization
mechanisms; independent deployment, reimplementation and replay; the complete
domain-independent TRUST-transfer algebra; complete hidden-witness trichotomy derivation; and
specific optional proof backends while they remain unfinished. Preserve the manifest's
`UNKNOWN` horizons; universal anonymity remains `OUT_OF_SCOPE`, not a promised feature.

The bounded identity-disclosure evaluator and tracked RISC Zero proof-carrying reference
mechanism are under
[`examples/zizk_artifact_first/`](../../examples/zizk_artifact_first/). The
[`experiment.json`](experiment.json) manifest records the mechanism studies and their
remaining horizons without assigning experimental status to the governing architecture.
