# Experimental artifact-first mechanisms

> **Acronyms:** reduced instruction set computer (RISC); Verifier Standard (VSTD);
> zero-identity/zero-knowledge (ZIZK).

This directory does **not** make VSTD's ZIZK artifact-first architecture experimental.
That governing orientation is normative in
[`standard/LADDER.md` section 1.1](../../standard/LADDER.md#11-artifact-first-causal-orientation).

Only the following unfinished mechanisms are experimental here:

- event serialization;
- bounded support-transfer algebra;
- Rust concentration and localization;
- complete hidden-witness trichotomy derivation; and
- specific optional proof backends while they remain unfinished.

The bounded identity-disclosure evaluator and tracked RISC Zero proof-carrying reference
mechanism are under
[`examples/zizk_artifact_first/`](../../examples/zizk_artifact_first/). The
[`experiment.json`](experiment.json) manifest records the mechanism studies and their
remaining horizons without assigning experimental status to the governing architecture.
