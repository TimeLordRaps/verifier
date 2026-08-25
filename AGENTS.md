# AGENTS.md

Working rules for automated contributors to VSTD. Read this before editing anything.

## 1. What this repository is

VSTD is a **verification domain language** plus its **reference implementation** for
portable, bounded, refutable evidence about computational claims. It standardizes claim
boundaries and portable result semantics across domain verifiers without replacing their
native work. The distribution is `verifier-standard`, the import package is `verifier`,
and `vstd` is the canonical command.

Two independent axes: `VSTD-1..5` (object mechanics) and `VSTD-Graph-1..5` (collection
dynamics). Layers 1-4 are implemented; **layer 5 is DRAFT**. An aggregate depth of `N`
holds only when distinct evidence passes every layer from 1 through `N`. A higher-layer
result never supplies, implies, upgrades, or repairs a lower-layer one.

This is founder-maintained alpha project work. It is **not** an accredited, consensus,
IETF, ISO, or W3C standard, and it has no demonstrated external adoption. Do not write
text implying otherwise. Orientation: [`README.md`](README.md),
[`standard/LADDER.md`](standard/LADDER.md),
[`docs/CLAIMS_AND_LIMITS.md`](docs/CLAIMS_AND_LIMITS.md), [`GOVERNANCE.md`](GOVERNANCE.md).

## 2. Prime directive

> Changes that strengthen a claim without stronger evidence are non-conforming.

This inverts the usual agent instinct. An uncertain or negative result here is often the
**correct** result, and "fixing" it is the defect. Specifically, never:

- turn `UNKNOWN` or `CONFLICTED` into a clean or passing result;
- infer, backfill, or synthesize missing provenance;
- treat self-observation as independent verification;
- widen a verdict beyond its declared coordinates, bounds, and trust roots;
- soften a detected forgery into "I do not know" — a `REJECTED` is a positive result.

When a check cannot be discharged, the conforming output is the uncertain verdict with a
reason, not a pass. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## 3. Environment and commands

```bash
python -m pip install ".[test]"
python -m pytest -q
python scripts/check_presentation.py
python scripts/build_reference.py --check
python -m compileall -q src scripts
PYTHONPATH=src python scripts/build_experiment_index.py --check
```

Stdlib-purity smoke, mirroring the `stdlib-smoke` CI job:

```bash
PYTHONPATH=src python -S -c "import verifier; from verifier.core.run import load_manifest; print(verifier.__version__)"
```

Local release-integrity pair, mirroring the `release-integrity` job:

```bash
python scripts/release_artifacts.py source --ref HEAD --release ci --output-dir /tmp/vstd-release
python scripts/release_artifacts.py verify /tmp/vstd-release/verifier-standard-ci.manifest.json
```

**No linter, formatter, or typechecker is configured.** There is no ruff, black, mypy,
flake8, pre-commit, Makefile, or tox. Do not run one, and do not add one unprompted; the
only `[tool.*]` sections in `pyproject.toml` are setuptools package-data and pytest.

**Shadowed-install trap.** If another checkout of this package is installed in the active
interpreter, `import verifier` silently resolves to it and the suite fails with
confusing `ModuleNotFoundError` or missing-file errors that are not repository bugs.
Check before believing a failure:

```bash
python -c "import verifier; print(verifier.__file__, verifier.__version__)"
```

If that path is not inside this repository, prefix commands with `PYTHONPATH=src`.

## 4. Layout

- `standard/` — normative layer documents plus the frozen `WIRE_IDENTIFIERS.md`.
- `src/verifier/core/` — receipt, checker, certificate, grounding, kernel, run.
- `src/verifier/constraints/`, `hardware/`, `layer4/`, `data/` — layer surfaces.
- `src/verifier/runtime/` — `public_cli.py` (every CLI entry point) and `demo.py`.
- `src/verifier/specifications/` — byte-identical copies of normative spec files.
- `receipts/schema/` — JSON Schemas. `examples/` — runnable specimens.
- `experiments/` — non-normative profile manifests with explicit horizons.
- `src/verifier/experimental_workflow/` — optional workflow/profile interchange; it
  records allocation but never grants a VSTD verdict from repository state.
- `scripts/` — `check_presentation.py`, `release_artifacts.py`, `build_pages.py`,
  `build_reference.py`, and `build_experiment_index.py`.
- `tests/` — flat `tests/test_*.py`, no `conftest.py`.

## 5. Invariants that must not be refactored away

**Kernel isolation (rung 4.7).** `src/verifier/core/kernel.py` deliberately duplicates
unit propagation from `core/refutation.py`. A producer and a checker agreeing because they
share a function is not agreement. `tests/test_gdc_certificate.py` enforces both halves:
`kernel.py`, `certificate.py`, and `grounding.py` may not import anything whose module tail
is `checker`, `refutation`, `policy`, `run`, `receipt`, or `builder`; and `kernel.py` must
stay under 400 executable statements so an auditor can re-implement it from the
specification alone. Do not deduplicate it, and do not grow it.

**Zero required runtime dependencies.** `dependencies = []` is enforced by the `python -S`
smoke job. Anything new belongs in an optional extra in `pyproject.toml`, imported lazily
behind that extra. A new third-party import on the base path breaks the build.

**Lazy exports.** `_LAZY_EXPORTS` plus module `__getattr__` in `src/verifier/__init__.py`
keeps import cost near zero. Do not convert these into eager imports.

**Console scripts.** `vstd`, `verifier`, and `verifiable` all map to
`verifier.runtime.public_cli:main`. `vstd` is canonical because an unqualified `verifier`
on Windows commonly resolves to Windows Driver Verifier. `verifiable` is a **permanent**
alias: published receipts bind it in falsification instructions, so removing it would
render already-published refutation steps unrunnable.

**Frozen wire identifiers.** `VSTD-0.1`, `VSTD-0.2`, `VSTD-3.0`, and `VSTD-DATA-0.1` are
frozen; readers dispatch on them, not on filenames. Released artifacts are immutable and
corrections are additive only. See
[`standard/WIRE_IDENTIFIERS.md`](standard/WIRE_IDENTIFIERS.md).

**Packaged specification bytes.** Editing `LADDER.md`, `VSTD-3.md`, `VSTD-4.md`, or
`WIRE_IDENTIFIERS.md` under `standard/` requires copying the exact bytes into
`src/verifier/specifications/`. `tests/test_packaged_specifications.py` compares them
byte-for-byte.

**Schema `$id` is a live route.** Every `receipts/schema/*.json` must carry
`"$id": "https://timelordraps.github.io/verifier/schemas/<filename>"`. `scripts/build_pages.py`
refuses to assemble the site otherwise, and `tests/test_presentation_surface.py` checks that
each schema deploys byte-identical under that route. Renaming a schema file means updating
its `$id` in the same change.

**LF line endings.** `.gitattributes` forces `eol=lf`, and the release verifier refuses
CRLF/LF equivalence as byte identity. This matters when working on Windows.

## 6. The presentation gate reads what you write

`scripts/check_presentation.py` runs in CI and inside `python -m pytest -q` by way of
`tests/test_presentation_surface.py`. It scans every text file in the repository —
**including this one** — and fails closed on:

- a markdown or HTML link whose local target does not exist;
- a version disagreement across `pyproject.toml`, `src/verifier/__init__.py`,
  `CITATION.cff`, `.zenodo.json`, and a dated `## X.Y.Z - YYYY-MM-DD` heading in
  `CHANGELOG.md` — bump all five together or the gate fails;
- a missing required boundary phrase in `README.md`, `ROADMAP.md`, or
  `standard/WIRE_IDENTIFIERS.md` (alpha status, non-substitution of layers, canonical CLI
  disclosure, explicit non-goals). Do not reword those sentences casually;
- a local Windows or home-directory path leaked into committed content;
- a change to the overview asset dimensions or its accessibility role.
- a stale generated CLI/API reference or experiment index.

The `conformance-gate` job requires `base`, `stdlib-smoke`, `release-integrity`,
`installed-wheel-smoke`, and `presentation` to all succeed.

## 7. Conventions

Every substantive module opens with `from __future__ import annotations`; the only files
without it are empty package `__init__.py` markers. Annotate all parameters and return
types. Records are frozen dataclasses by default; verdicts and tiers are enums. Module
docstrings are normative — they state which ladder rung the code discharges, so update the
docstring whenever behavior changes.

`requires-python = ">=3.10"`, and CI runs the suite on 3.10 through 3.13. Everything under
`scripts/` must run on 3.10 too: the presentation gate uses a bounded parser instead of
Python 3.11's `tomllib` for exactly this reason. Do not use 3.11+ standard-library APIs
anywhere in this repository.

## 8. Tests

pytest only, using `tmp_path` and `capsys`; manifests and specimens are built inline. A
normative change needs a test that **fails before and passes after**. Never weaken an
assertion to make a suite green.

## 9. Change process

Work lands via pull request into `main`. `.github/PULL_REQUEST_TEMPLATE.md` requires a
Coordinate (layer, release, seam), a falsification condition, and compatibility plus
frozen-wire impact. Commit subjects are short and imperative. Do not run release or tag
workflows; [`RELEASING.md`](RELEASING.md) is a maintainer procedure.

`.github/workflows/pages.yml` publishes the `scripts/build_pages.py` output to GitHub Pages
on every push to `main`. Documentation and schema edits become public the moment they merge,
so treat `docs/` and `receipts/schema/` as published surfaces rather than drafts.

## 10. Safety

`vstd run` executes an arbitrary command from a manifest and **does not sandbox it**. Use
`vstd plan MANIFEST --json` for side-effect-free inspection. `vstd demo` is side-effect
free.

Never commit an HMAC key or any test key material. The `hardware/` HMAC emulator and local
anchor keys are explicitly test-only and are not production roots of trust. Keep private
project names, proprietary model identifiers, home-directory paths, credentials, and
personal email addresses out of committed content — this is a release gate, not a
preference. Report vulnerabilities through [`SECURITY.md`](SECURITY.md), never a public
issue.
