# Tool and verifier research record

> **Acronyms:** application programming interface (API); Boolean satisfiability problem (SAT);
> unsatisfiable (UNSAT).

**Status:** non-normative experiment record
**Checked:** 2026-08-24

## Generic SAT engine

Exactly one SAT engine was selected: [CaDiCaL](https://github.com/arminbiere/cadical)
3.0.0 through `python-sat==1.9.dev15`, using the PySAT solver name
`cadical300`. CaDiCaL 3.0.1 exists upstream, but the experiment pins the exact
engine exposed by the selected binding rather than silently relabeling it as the
newer release.

The official [PySAT solver API](https://pysathq.github.io/docs/html/api/solvers.html)
documents the unified solver interface, `Cadical300`, model extraction, limited
solving, timing, and accumulated statistics. The experiment directly confirms a
SAT model plus decisions, conflicts, and propagations through that interface.
The selected binding did not expose a nonempty independently checkable UNSAT
proof in the tested configuration. An `UNSAT` observation is therefore recorded
without a certificate and remains local to the submitted route.

Selection reasons:

- real machine-readable `SAT`, `UNSAT`, and bounded `UNKNOWN` results;
- real witness extraction;
- decisions, conflicts, propagations, and elapsed time;
- one unchanged backend on every domain;
- MIT-licensed upstream and binding;
- installable in the isolated experiment environment.

Invocation is `pysat.solvers.Solver(name="cadical300",
bootstrap_with=clauses, use_timer=True)`. Clause order and variable allocation are
deterministic in the experiment compiler. Wall time and search telemetry remain
environment-sensitive observations.

## External verifier objects

The source suite is [AlgoTune](https://github.com/oripress/AlgoTune), an externally
maintained NeurIPS 2025 benchmark distributed under the MIT License. Three exact
task files are vendored from commit
`dff9914c10800c7a031c9e8c3d4d1c8cd1b38906`; their byte hashes and the license
hash are pinned in `selected-tools.lock`.

| Role | Domain | Primary invocation | Input / witness | Verification and diagnostics |
|---|---|---|---|---|
| Development | Stable matching | `StableMatchingTask.is_solution(problem, solution)` | Two complete preference tables / matching permutation | Format, permutation, and blocking-pair predicate; captured logging may identify a failure |
| Held out | Graph isomorphism | `GraphIsomorphism.is_solution(problem, solution)` | Two finite graphs / node permutation | Bijection, degree, and edge predicate; captured logging may identify a failure |
| Held out | Integer factorization | `IntegerFactorization.is_solution(problem, solution)` | Decimal composite / two integer factors | Exact product, nontriviality, and primality predicate; captured logging may identify a failure |

The exact experiment-local contracts record source digests, schemas, cost
boundaries, trust roots, canonicalization, and accepted/rejected/error/UNKNOWN
semantics. Acceptance establishes only the implemented predicate for the bound
candidate and instance.

The tested platform is Python 3.12 on 64-bit Windows. The exact upstream task
bytes import NumPy and SymPy as pinned by `requirements-experiment.txt`; the graph
and matching reserves add NetworkX and `matching`. The wrappers change neither
the upstream source bytes nor their `is_solution` predicates.

Exactly one reserve was declared before evaluation for each domain:
`matching==1.4.3`, NetworkX 3.5, and SymPy 1.14.0. Reserves corroborate tests and
may replace a primary only for a pre-evaluation incompatibility. They are not
silently combined into a stronger domain claim.

## Real-LM boundary research

The public harness uses only a generic local OpenAI-compatible chat-completion
interface. Runtime selection attempts and their exact public package versions are
recorded in `selected-tools.lock`. Private model, artifact, endpoint, credential,
and launcher coordinates are excluded. Neither tested runtime produced a real
completion, so the public result remains a current-state technical/packaging
blocker rather than LM-performance evidence.

No mock, replay, deterministic fixture, or substitute model contributes to the
empirical result. Unit fixtures exercise parsing and failure semantics only.
