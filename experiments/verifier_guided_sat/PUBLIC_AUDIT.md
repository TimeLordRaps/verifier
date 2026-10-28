# Public-boundary and compatibility audit

> **Acronyms:** application programming interface (API); conjunctive normal form (CNF);
> unsatisfiable (UNSAT); Verifier Standard (VSTD).

**Base:** `598c545be3833d6d81bb7e252ca5837f3bb2a449`
**Branch:** `codex/verifier-guided-sat`
**Scope:** `experiments/verifier_guided_sat/` only

## Repository boundary

The exact worktree is the isolated lowercase public-repository worktree and its
remote is `https://github.com/TimeLordRaps/verifier.git`. `origin/main` matched the
required base before work began. No file outside the experiment directory is part
of this change.

Comparison with the base confirms no change to:

- receipt schemas or schema `$id` values;
- `standard/WIRE_IDENTIFIERS.md` or its packaged copy;
- console aliases;
- lifecycle tokens;
- existing checker or conformance behavior;
- `pyproject.toml` or required runtime dependencies.

All third-party requirements are isolated in `requirements-experiment.txt`. The
vendored upstream verifier files and license are hash-pinned.

## Public-data scan

The experiment audit scans normal text and decompressed `*.json.gz` results for:

- absolute private Windows, home, or mounted-host paths;
- local endpoint coordinates;
- email addresses;
- assigned credentials, tokens, passwords, or secrets;
- private-key material.

A separate complete-diff review checks private model and deployment identifiers,
launcher details, commercial strategy material, unsupported adoption/security/generalization
claims, global-UNSAT language, and any promotion of `UNKNOWN`. Generic environment
variable names and generic interface descriptions are intentional public API, not
deployment coordinates.

## Semantic review

- Native verifier acceptance is the only path to a bounded accepted candidate.
- Route-local `UNSAT`, solver `UNKNOWN`, request failure, malformed output,
  compilation failure, native rejection/error, and resource exhaustion never
  become a domain `PASS`.
- A real-LM runtime failure stops the live runner without retry or substitution.
- Unit fixtures are explicitly test-only and are not included as empirical LM
  evidence.
- The separate consumer validator does not import the producer canonicalizer,
  route compiler, VSTD binding, or SAT-backend wrapper; it rehashes, replays the
  bound CNF, decodes the candidate, and reexecutes the native verifier.
- The public result makes no speed, easier-SAT, cross-domain-generalization,
  global-UNSAT, identity, independence, authorization, zero-knowledge, anonymity,
  confidentiality, or external-adoption claim.

## Freeze lineage

`freeze-lineage.json` accounts for the freeze digest of record and for every
digest this experiment's documents have cited.

- The first freeze (2026-08-24) is reproduced byte for byte by the pins that
  were carried into the reconciled tree before any edit.
- The current freeze (2026-10-03) differs in thirteen of thirty frozen files:
  acronym and namespace conformance only. Eleven Python files are syntax-tree
  identical, `vstd_binding.py` differs in three string constants, and no
  verifier-contract, solver-configuration, timing, or threshold pin changed.
- No held-out live evaluation had started at either freeze, so the preregistered
  rule that forbids changes after a live held-out run starts was not engaged.
- One digest cited by the authored result documents is reproduced by no
  preserved freeze manifest; its origin is `UNKNOWN`. The result validator
  rejected the committed blocked result against the manifest of record before
  this repair, and a test now runs that validator on the committed result.

## Validation evidence

The final validation run and exact counts are reported in `PUBLIC_RESULT.md` and
the signed-commit report. `artifact-manifest.json` binds every distributable file
under this experiment except itself.
