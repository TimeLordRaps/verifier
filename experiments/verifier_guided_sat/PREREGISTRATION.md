# Preregistration

> **Acronyms:** Boolean satisfiability problem (SAT); unsatisfiable (UNSAT);
> Verifier Standard (VSTD).

This protocol was frozen before any live held-out evaluation. Live held-out evaluation has not begun.

## Question

Can one unchanged LM, generic harness, and pinned generic SAT backend use existing verifier objects to generate empirically easier accepted residual SAT routes in two held-out domains without domain-specific SAT-engine changes or complete domain encodings in Arm C?

## Domains and instances

- Development: stable matching, 20 instances, generator size 6.
- Held out: graph isomorphism, 20 instances, generator size 8.
- Held out: integer factorization, 20 instances, generator size 1 (bounded 8-bit-factor generator setting).
- Seeds and exact values are frozen in `instances/manifest.json`.

Exactly one LM request is allowed per arm and instance. No retry is part of the frozen primary evaluation. Failed or malformed routes remain failed routes and `UNKNOWN` domain outcomes.

## Frozen elements

- route language and strict compiler;
- generic system, Arm B, and Arm C prompts;
- external verifier-object contracts;
- CaDiCaL 3.0.0 configuration through `python-sat==1.9.dev15`;
- harness search policy and one-request limit;
- timing/accounting procedure;
- 10% aggregate end-to-end improvement threshold;
- correctness and failure classification rules.

Hashes are in `freeze-manifest.json`. After freeze, a held-out domain may add only its predeclared verifier adapter, manifest instance, and witness decoder. Those adapters are already present and frozen. No generic code or prompt may change after a live held-out run starts.

## Timing-noise rule

Five Arm A repetitions were taken on each of the 20 development instances. The noise statistic is the median per-instance relative median absolute deviation of total accounted time. The meaningful aggregate threshold is:

```text
max(10%, 3 * measured relative-MAD statistic)
```

The measured statistic was below the 10% floor, so the frozen threshold is 10%. Exact measurements are in `development-noise.json`. This is timing instrumentation calibration, not evidence about an LM route.

## Primary criterion

Primary success requires all of:

1. zero accepted outcomes that fail exact native-verifier reexecution;
2. correct preservation of `UNKNOWN` and route-local `UNSAT`;
3. the same frozen harness/solver on both held-out domains;
4. no domain-specific SAT-engine change;
5. lower pinned-solver work on accepted Arm C routes than Arm A where a complete baseline exists;
6. more than 10% aggregate end-to-end improvement without lower accepted completion;
7. independently valid record bindings and reproduced native verdicts;
8. claims bounded to recorded instances, verifiers, LM disclosure boundary, and environment.

For criterion 5, solver work is compared separately on each held-out domain over all
20 matched accepted non-generate-and-check Arm C residuals. The aggregate vector is
the sum of decisions, conflicts, propagations, and SAT elapsed nanoseconds. Arm C is
lower only when every component is no greater than Arm A and at least one component
is strictly lower. Missing telemetry or fewer than 20 matched accepted residuals
cannot satisfy this criterion.

For criterion 6, aggregate end-to-end improvement is
`1 - sum(Arm C total ns) / sum(Arm A total ns)` over the 40 matched held-out
instances. It must be strictly greater than 10%, and Arm C must accept all 20
instances in each held-out domain. Each total includes all preregistered timing
components.

Wrong candidates are worst-case regardless of speed. Solver-only gains do not satisfy the criterion.

## Negative classifications

The predefined classifications are `PRIMARY_SPEED_HYPOTHESIS_NOT_SUPPORTED`, `SOLVER_EASIER_END_TO_END_SLOWER`, `GENERALIZATION_NOT_ESTABLISHED`, `VERIFIER_GUIDED_SEARCH_ONLY`, `DIRECT_SAT_COMPARISON_UNAVAILABLE`, and `VSTD_OPERATIONAL_ADVANTAGE_NOT_ESTABLISHED`. A runtime hard blocker is recorded separately and is not relabeled as an experimental negative result.

Only one tuning round would be allowed after a negative development pilot. No tuning round or live pilot occurred because the selected real-LM runtime was blocked first.

Classification precedence is: a real LM request failure is the hard blocker
`BLOCKED_NO_REAL_LM_RUNTIME`; otherwise complete primary success; then
`VERIFIER_GUIDED_SEARCH_ONLY` when Arm B succeeds but no accepted residual route
exists; then `GENERALIZATION_NOT_ESTABLISHED` for incomplete held-out Arm C
completion; then `SOLVER_EASIER_END_TO_END_SLOWER` for a solver-work improvement
without end-to-end success; otherwise `PRIMARY_SPEED_HYPOTHESIS_NOT_SUPPORTED`.
The direct-comparison and VSTD-operational-value classifications remain reportable
when their stated preconditions apply, but neither is mechanically inferred for this
three-domain design because complete Arm A encodings and independent VSTD
reverification are present.
