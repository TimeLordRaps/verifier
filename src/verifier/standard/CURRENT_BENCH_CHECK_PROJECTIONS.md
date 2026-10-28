# Current BENCH-check projection boundary

Status: bounded source-only integration; semantic completeness `UNKNOWN` and
release admissible `false`.

Secure Hash Algorithm 256-bit (SHA-256) identifies every digest below.

This successor adds four fixed BENCH mappings: BENCH-1.2 problems, BENCH-1.4
oracles, BENCH-3.6 budgets, and BENCH-4.4 coverage. Each is a one-way
`ROUTE_TO_UNION` proposition-text narrowing with no reverse mapping,
equivalence, digest alias, or universal schema.

The native source is `src/verifier/domains/contracts/bench_checks.py`, SHA-256
`3826e27fba32889349b989be5e6362bcc5a04ddce8aa897e1243b31bc13a4e5a`.
The acceptance mechanism is
`verifier.domains.contracts.bench_checks.recheck_bench_checks_certificate`.

BENCH-2.1 remains excluded because it belongs to the separate bench-attempts
mechanism. This projection neither maps it nor gives duplicate credit. The
four mappings reduce the structural denominator from 93 to 89, with zero
evidence, authority, package, installed-mechanism, test, profile,
completeness, and release credit.
