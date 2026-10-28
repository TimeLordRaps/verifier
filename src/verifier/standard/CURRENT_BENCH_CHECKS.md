# Current retained benchmark checks

Benchmark specification graph (BENCH); dataset integrity and lineage (DATA);
Verifier Standard (VSTD); JavaScript Object
Notation (JSON); conjunctive normal form (CNF); Boolean satisfiability problem (SAT);
unsatisfiable (UNSAT). These experimental native propositions use semantic version
`verifier-current-object-obligations-1`. Time is milliseconds, memory is bytes,
and scores, weights, tolerances and operation counts are dimensionless.

An independently selected request binds the exact BENCH subject, finite collection,
retained evidence, native check, proposition, installed mechanism, policy and limits.
Every namespace record must reconstruct exactly and pass typed finite composition.
The BENCH payload is its native problem/threshold artifact. This mechanism supports
one `verifier` operand whose VERIFIER payload is exactly `mechanism_id` and
`mechanism_digest` for this installed contract, and one `data` operand whose DATA
payload is exactly `problems` with the selected problem list. Both records are bound
by the selected collection. Other admitted operand multiplicities remain UNKNOWN.
This identity binding does not certify the verifier's general correctness or the
dataset's external provenance; the selected built-in oracle actually runs below.

| Current coordinate | Native check | Exact proposition |
|---|---|---|
| BENCH-1.2 | problems | Bind a nonempty finite problem set to exactly one retained candidate answer per problem and positive weights. |
| BENCH-1.4 | oracles | Execute each named built-in oracle and compare the exact weighted solved fraction against the selected minimum score. |
| BENCH-3.6 | budgets | Compare every retained timing and memory observation against the exact positive problem ceilings. |
| BENCH-4.4 | coverage | Recompute the complete weighted result using native oracles, require the selected minimum and compare the reported score within the fixed reporting tolerance. |

Each problem has exactly `id`, `kind`, `specification`, `weight`, `timeout_ms` and
`memory_bytes`. Each retained run has exactly `id`, `problem_digest`, `answer`,
`execution_ms` and `peak_memory_bytes`. Extra runs, duplicate identities and
substituted specifications are refuted; missing runs remain UNKNOWN. Evidence
contains `schema_version`, `objects` and `inputs`; inputs admit only `runs` and
`score`. Missing support remains UNKNOWN and unsupported extra fields are refuted.

Oracles support canonical exact-answer equality, complete CNF-SAT assignments,
bounded exhaustive CNF-UNSAT checking, and linear-system residual checking.
They consume candidate answers, never a supplied solved flag. Unsupported oracle
kinds remain UNKNOWN. CNF enumeration charges every tested assignment and stops
with UNKNOWN when the selected operation budget is exhausted.

Finite plain integers and floating-point numbers have magnitude at most 1e100;
booleans and nonfinite values are rejected. Exact rational arithmetic preserves
the parsed integer or binary floating-point value for linear residuals, weights
and score-threshold decisions. The selected nonnegative linear tolerance is not
weakened. Resource ceilings compare original validated values: equality passes,
any excess fails. The retained score reporting tolerance remains the exact parsed
value of `1e-12`. It applies only to reported-score agreement, never to admission
against the selected minimum. The result preserves the approximate `score` field
and adds `score_exact` with numerator and denominator so rounding cannot disguise
an imperfect score. Positive weights and a nonempty inventory make the denominator
positive. No wall-clock or memory observations are independently collected here.

These four registrations explicitly map native operations named under the same
legacy coordinate spellings in `DOMAIN_OBLIGATIONS.md`. New current requests and
certificates are required. No historical verdict, neighboring numbered objective,
prerequisite or complete tier is transferred by spelling.

`bench_checks_request`, `bench_checks_policy`, `build_bench_checks_certificate`
and `recheck_bench_checks_certificate` in `verifier.domains.contracts.bench_checks`
select, construct and replay certificates. Their distinct identifiers are
`verifier-current-bench-checks-*-1`. Public replay uses `vstd current-object check`
with exact objective, semantic version, represented kind BENCH, external request
and policy. Replay reconstructs the whole canonical certificate and native result.
Partial redaction cannot retain canonical certificate status.

Bounds admit at most 256 objects, 100,000 native operations, 100,000 separately
charged composition operations, 4,096 items per container, four mebibytes each of
evidence, payload and references, and eight mebibytes of certificate bytes. Every
retained structure is charged before evaluation. Namespace records retain their
one-mebibyte per-object payload bound. Rational operands remain bounded by finite
numeric admission and container/operation limits; no external code is loaded.

Unsupported selectors are refused before artifact or evidence access. Missing
support and exhausted bounds yield UNKNOWN; contradictory retained evidence yields
FAIL. Malformed selection, changed dependencies and forged certificates are rejected.
Trust-root labels do not authenticate observers. Live execution, external oracle
correctness, sampling validity, generalization, complete coverage, authority,
public checkability and polished issuance remain unestablished.
Independent positive and negative cases are in `tests/test_current_bench_checks.py`.
