# Verifier-guided Boolean satisfiability problem (SAT) experiment

> **Acronyms:** JavaScript Object Notation (JSON); unsatisfiable (UNSAT);
> Verifier Standard (VSTD).

This non-normative experiment asks whether one unchanged language-model harness and one generic SAT backend can use existing verifier objects to propose useful residual witness routes in a development domain and two held-out domains.

**Current status: live LM evaluation is blocked.** The public infrastructure, three external primary verifier objects, three predeclared reserves, complete Arm A encodings, real CaDiCaL SAT witnesses, VSTD-bound route records, 60 public instances, and independent record validation run. Neither pinned runtime attempt produced a real LM completion: one stopped at its released GGUF plugin/toolchain boundary, and the other reached its model loader but caused an unclean WSL restart both under a bounded memory correction and with a byte-identical artifact staged on native WSL storage. Arms B and C were therefore not measured, and no speed or cross-domain-generalization claim is made. See [PUBLIC_RESULT.md](PUBLIC_RESULT.md).

## Dataflow

```text
domain instance
  -> verifier-object contract
  -> LM proposal (complete candidate or bounded route)
  -> strict generic finite-domain compiler
  -> unchanged CaDiCaL backend
  -> decoded candidate
  -> exact vendored native verifier
  -> non-normative VSTD binding and provenance hypergraph route history
```

The native verifier is authoritative for candidate acceptance. `UNSAT` applies only to the submitted route. A failed, malformed, timed-out, or exhausted route ends as `UNKNOWN` about the domain instance.

## Public setup

From the repository root, using Python 3.12:

```powershell
python -m venv experiments/verifier_guided_sat/.venv
experiments/verifier_guided_sat/.venv/Scripts/python -m pip install -r experiments/verifier_guided_sat/requirements-experiment.txt
$env:PYTHONPATH = "src;experiments/verifier_guided_sat"
experiments/verifier_guided_sat/.venv/Scripts/python -m pytest -q experiments/verifier_guided_sat/tests
```

Materialize and rehash the 60 public instances:

```powershell
experiments/verifier_guided_sat/.venv/Scripts/python -m verifier_guided_sat.benchmark --mode materialize
```

Re-measure development timing noise and freeze every component that can affect
held-out classification before any live run:

```powershell
experiments/verifier_guided_sat/.venv/Scripts/python -m verifier_guided_sat.benchmark --mode noise
experiments/verifier_guided_sat/.venv/Scripts/python -m verifier_guided_sat.benchmark --mode freeze
```

Run Arm A only and independently validate all generated records:

```powershell
experiments/verifier_guided_sat/.venv/Scripts/python -m verifier_guided_sat.benchmark --mode baseline
experiments/verifier_guided_sat/.venv/Scripts/python -m verifier_guided_sat.benchmark --mode validate --output experiments/verifier_guided_sat/results/baseline.json.gz
```

The gzip result is deterministic JSON compression (`mtime=0`), but timing values vary by machine and load.

## Live LM boundary

The harness accepts a real local OpenAI-compatible chat-completion backend through environment variables:

- `VGSAT_LM_BASE_URL`
- `VGSAT_LM_MODEL`
- `VGSAT_LM_API_KEY` (optional when the local server requires none)
- `VGSAT_LM_TIMEOUT_SECONDS` (optional; default 180)

The public record deliberately withholds private model identity, endpoint, credentials, and launcher details. Exact runtime and dependency versions, failure boundaries, and cleanup state are recorded without naming the private artifact. A run that withholds model identity is local implementation evidence, not a fully reproducible model benchmark. Unit tests do not contact an LM and are not LM-performance evidence.

With a separately configured real endpoint, run and validate the frozen live
benchmark as follows. A request-level runtime failure is bound into a fail-closed
record and stops the run without a retry or substitute:

```powershell
experiments/verifier_guided_sat/.venv/Scripts/python -m verifier_guided_sat.benchmark --mode live
experiments/verifier_guided_sat/.venv/Scripts/python -m verifier_guided_sat.benchmark --mode validate --output experiments/verifier_guided_sat/results/live.json.gz
```

The preregistered classifier compares the live records with the public Arm A
records. It does not accept a hand-written success label. Exact solver-work,
end-to-end, and failure-classification rules are in
[PREREGISTRATION.md](PREREGISTRATION.md).

## Selected tools

- [CaDiCaL](https://github.com/arminbiere/cadical) 3.0.0 through `python-sat==1.9.dev15`
- [AlgoTune](https://github.com/oripress/AlgoTune) verifier objects at commit `dff9914c10800c7a031c9e8c3d4d1c8cd1b38906`
- Reserve libraries pinned in [selected-tools.lock](selected-tools.lock)

Selection evidence and official source links are in [RESEARCH.md](RESEARCH.md).
The compatibility and leak review is in [PUBLIC_AUDIT.md](PUBLIC_AUDIT.md).

The selected PySAT binding produces SAT models and telemetry. It did not expose a nonempty independently checkable proof through the tested CaDiCaL binding, so the experiment records `unsat_certificate_available=false` and prohibits global-UNSAT claims.

## Layout

- `verifier_guided_sat/`: harness, compiler, solver, LM boundary, VSTD binding, benchmark, producer-aware validation, and a separately implemented consumer validator
- `vendor/algotune/`: exact MIT-licensed verifier source bytes
- `instances/manifest.json`: 20 deterministic instances per domain
- `prompts/`: generic prompts shared across development and held-out domains
- `tests/`: positive, negative, mutation, and fail-closed tests
- `results/`: baseline-only records and a machine-readable live blocker
- `freeze-manifest.json`: hashes frozen before any held-out live evaluation

No experiment package is imported by `verifier-standard`, and no runtime dependency was added to the distribution.
