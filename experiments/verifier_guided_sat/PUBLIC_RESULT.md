# Public result

> **Acronyms:** graphics processing unit (GPU); Boolean satisfiability problem (SAT);
> Secure Hash Algorithm 256-bit (SHA-256); unsatisfiable (UNSAT); Verifier Standard (VSTD).

## Identity

- Base SHA: `598c545be3833d6d81bb7e252ca5837f3bb2a449`
- Branch: `codex/verifier-guided-sat`
- Status: `BLOCKED_NO_REAL_LM_RUNTIME`
- Blocker category: **technical / packaging, current-state**

## Exact status

The public experiment infrastructure is implemented and tested. All 60 canonical Arm A routes produced real CaDiCaL SAT witnesses, decoded candidates accepted by the exact vendored native verifier, and VSTD-bound records that passed independent rehashing, formula recompilation, SAT-status reexecution, graph validation, and native-verdict reexecution.

Arms B and C were **not run**. The first pinned real-LM runtime stopped at its released GGUF plugin and native source-build toolchain boundary. The second pinned runtime reached its GGUF model loader after explicit tokenizer and adjacent configuration. Loading from the Windows-mounted filesystem exceeded the available 32 GiB WSL host-memory envelope before the server became ready. One bounded temporary-swap correction caused an unclean WSL restart. A final attempt used a checksum-confirmed byte-identical artifact on native WSL storage, removing the Windows-filesystem mapping variable, but WSL again restarted uncleanly during model load. WSL was recovered; all temporary model, runtime, cache, and swap files were removed; and no listener or inference process remained. No endpoint or real completion was produced. No mock, replay, deterministic fixture, or tiny substitute model was used as LM evidence.

A final runtime check on 2026-08-24 again found no LM listener. Unrelated
workloads occupied 23,750 MiB of the 24,564 MiB GPU allocation, leaving 389 MiB
free; those workloads were not interrupted. This resource observation is an
additional current-state constraint, not evidence about LM quality.

## Hypotheses

| Question | Result |
|---|---|
| Can the generic compiler and pinned solver produce real decoded candidates across all three verifier domains? | Supported as baseline/infrastructure evidence |
| Can records bind and independently reverify the route artifacts and native outcomes? | Supported for the 60 Arm A records |
| Can an unchanged LM/harness generate useful residual routes across held-out domains? | Not tested; blocked |
| Are Arm C residual formulas easier than Arm A? | Not measured |
| Is Arm C faster end to end? | Not measured |
| Does the result establish domain-general SAT acceleration? | No |

This is a hard infrastructure blocker, not one of the preregistered experimental failure classifications. Primary success and Failures A-F remain unresolved.

## Selected tools

- CaDiCaL 3.0.0 through `python-sat==1.9.dev15`
- AlgoTune verifier objects at commit `dff9914c10800c7a031c9e8c3d4d1c8cd1b38906`
- `matching==1.4.3`, NetworkX 3.5, and SymPy 1.14.0 predeclared reserves
- Generic environment-configured OpenAI-compatible LM interface
- Both selected runtime attempts and exact dependency pins recorded in `selected-tools.lock`

## Public reproducibility boundary

The public repo contains the instances, exact verifier source bytes, constraints, prompts, compiler, solver configuration, baseline records, tests, validators, and hashes. The private model identity, model artifact, local endpoint, credential state, launcher details, and full hardware identity are excluded. Consequently, even a future live run with the identity withheld would be local implementation evidence rather than a fully reproducible model benchmark.

## Verifier domains

- Development: stable matching, 20 bounded instances.
- Held out: graph isomorphism, 20 bounded instances.
- Held out: integer factorization, 20 bounded semiprime instances.

Each domain uses the exact AlgoTune primary and one predeclared reserve described
in `VERIFIER_OBJECT_CONTRACT.md`. No reserve replaced a primary.

## Counts and measured results

| Metric | Arm A baseline | Arms B/C |
|---|---:|---:|
| Instances | 60 | 0 measured |
| Native-verifier accepted | 60 | Not measured |
| False acceptances | 0 | Not measured |
| Native-verifier reexecution disagreements | 0 | Not measured |
| Final UNKNOWN | 0 | Not measured |
| Route-local UNSAT | 0 | Not measured |
| Independently invalid records | 0 | Not measured |

The baseline timing and solver telemetry remain machine-local observations in `results/baseline.json.gz`. They are not a performance comparison. No solver-hardness delta, end-to-end delta, crossover point, or VSTD operational advantage is reported.

The recorded clean baseline window was
`2026-08-24T13:11:12.508515Z` through `2026-08-24T13:11:14.931960Z`.
Its median per-instance SAT time was 1,745,850 ns and median bound total-system
probe time was 16,832,850 ns. The total includes verifier/contract/prompt
preparation, LM time where applicable, harness, SAT, native verification, VSTD
creation, and full producer-plus-independent-consumer reverification. Final
record construction and post-probe QA are deliberately outside the recursive
timing probe and are not represented as measured comparison time. These values
characterize only this baseline rerun.

## Engineering surface and VSTD overhead

Generic and domain-specific physical-line counts are recorded separately in
`engineering-surface.json`: 2,437 generic lines and 394 domain-adapter lines
under its declared rule. Human engineering time was not instrumented
prospectively and remains `UNKNOWN`; line count is not used as a time substitute.

VSTD creation-probe and reverification timing are present per baseline trial.
Median creation-probe time was 2,529,100 ns; median producer-aware plus separate
consumer reverification time was 9,329,200 ns; median per-trial combined VSTD
accounting was 11,911,400 ns. These
values demonstrate that overhead is accounted for, but without Arms B/C they do
not demonstrate operational advantage.

## Freeze hashes

The prompt, compiler, harness, verifier contract, solver configuration, timing rule, success threshold, adapters, and instance hashes are recorded in `freeze-manifest.json`. No live held-out evaluation began after the freeze.

| Frozen surface | SHA-256 |
|---|---|
| Complete freeze manifest payload | `685db0205e191462f7830379f94733c94c48847c56ad30e6c1c66602db3883c5` |
| Solver configuration | `50c07335ed45f08f93c942a278cf2f19cb7c59891f40bd760e5fa759af796e10` |
| Stable-matching verifier contract | `75cc5ce5df220bcbcff3221656a833844dc615a50e2afd1e3759dfac6585de5b` |
| Graph-isomorphism verifier contract | `501c8c9e6d7c8be6055cf7c46844e504f04d1c8a0de9c679b21f074ce1447ee9` |
| Integer-factorization verifier contract | `a39bf7e115629a674e192430d30359a85217afec5b9c1ad4ab85de026f11fe66` |

The current `freeze_digest` is `sha256:685db0205e191462f7830379f94733c94c48847c56ad30e6c1c66602db3883c5`; individual frozen file hashes remain in the machine-readable manifest.

### Freeze lineage

The freeze was renewed once, before any held-out evaluation, so the digest above is the second freeze of this experiment.
The first freeze, dated 2026-08-24, has `freeze_digest` `sha256:ad3cf35cbcb6f785a5b9ee0b9090036c7e58ebe040f7b74cb58ab216c62df74b`.
Thirteen of the thirty frozen files were then conformed to the public-reader acronym and namespace gates, which this experiment's base commit predates.
Eleven Python files gained only a leading comment block and are syntax-tree identical.
`vstd_binding.py` differs in three string constants.
The Markdown files gained acronym blockquotes, and `metrics.schema.json` gained an annotation-only `description`.
No pin of the verifier contracts, solver configuration, timing rule, or success threshold changed.
`freeze-lineage.json` records each digest, and the previous and current hash of every changed frozen file.
A test fails if that record stops accounting for every frozen file.

This document formerly cited `sha256:bfea7838f05e8a06b0cb6545e10d251aedc09c8f71c80567e1489f7bef8f3ea2`.
No preserved freeze manifest reproduces that digest, and the committed blocked result already failed the result validator against the manifest of record, so its origin is `UNKNOWN`.
The blocked result now cites the current digest and a test runs the result validator against it.

## Exact justified claims

1. The pinned external verifier objects execute on the 60 public bounded instances.
2. The unchanged generic compiler and CaDiCaL backend produce real SAT witnesses for the three complete Arm A encodings.
3. Those decoded baseline candidates pass the exact native predicates and their verdicts reexecute consistently in the tested environment.
4. The non-normative VSTD binding detects tested artifact mutations and preserves route-local `UNSAT` as `UNKNOWN` about the domain.
5. The real-LM evaluation is currently blocked at the pinned packaging and WSL runtime boundaries; native WSL storage did not resolve the model-load failure.

## Exact prohibited claims

- verifier-guided SAT is faster, easier, or cross-domain generalizable;
- the LM reduced work or found a residual route;
- baseline SAT results predict Arm C behavior;
- route-local `UNSAT` or failed routes prove global nonexistence;
- verifier acceptance proves the verifier is sound;
- VSTD validation proves semantic truth, identity, independence, or authorization;
- the measurements are a reproducible public model benchmark;
- the system provides universal SAT acceleration, zero knowledge, anonymity, or confidentiality.

## Unresolved assumptions

- availability of a compatible real-LM runtime that fits the host-memory envelope without changing the frozen experiment logic;
- stability of timing under a future live endpoint load;
- utility of the closed route language to a real LM;
- equivalence of verifier predicates to any external domain specification;
- whether independent UNSAT proof extraction can be added without changing the selected solver binding.

## Validation

These counts were recorded when the experiment was authored; they are not re-measurements.
The reconciliation re-validation is stated in the final subsection.

- Experiment suite: 44 passed.
- Repository suite: 243 passed, 4 skipped.
- Clean public Arm A rerun: 60 records generated; 60 independently validated.
- Presentation gate: passed.
- Compilation of `src`, `scripts`, and the complete experiment: passed.
- Complete staged-diff whitespace check: passed.
- Public text and decompressed-result scan: passed.

Skipped repository tests retain their repository-defined optional-environment
meaning; no failing test was waived. The live LM hypothesis remains blocked rather
than represented by a skipped or fake empirical test.

### Reconciliation re-validation

On 2026-10-03 the experiment was carried into the reconciled repository tree and re-run against the repository's current public sources.

- Experiment suite: 47 passed, none skipped: the 44 authored tests plus three tests that bind the committed blocked result, this document, and the freeze lineage to the freeze manifest.
- Every pin of the freeze manifest is reproduced from the files on disk, and the committed blocked result passes the result validator.
- The 60-record Arm A results and the instance data are byte-identical to the authored files, and the clean Arm A rerun was not repeated.
- No live LM evaluation ran: `live_trial_count` remains 0 and the status remains `BLOCKED_NO_REAL_LM_RUNTIME`.
- The experiment environment has no per-test timeout plugin, so the run used an overall deadline and a fault-handler timeout instead of per-test isolation.
