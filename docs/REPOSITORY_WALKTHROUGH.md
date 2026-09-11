# Repository walkthrough

The Verifier Standard (VSTD) repository contains a verification-domain language,
its Python reference implementation, worked examples, and tests. This guide
shows how to move between those surfaces without treating them as equivalent.

## Set up a development checkout

```bash
git clone https://github.com/TimeLordRaps/verifier.git
cd verifier
python -m venv .venv
```

Activate the environment using the [installation guide](INSTALLATION.md), then
install the checkout and its declared test dependencies:

```bash
python -m pip install -e ".[test]"
git rev-parse HEAD
vstd demo
```

Record the full commit when reporting behavior. A dirty checkout also needs its
patch or exact changed files; a commit alone does not identify uncommitted work.
The current repository may contain additions beyond the latest package release.

## Find the owner of a change

| Surface | Location | What to use it for |
|---|---|---|
| Normative profile meaning | `standard/` | Requirements, vocabulary, claim boundaries |
| Installed specifications | `src/verifier/specifications/` | Byte-identical packaged copies of applicable standard files |
| Runtime | `src/verifier/` | Implemented mechanisms and public exports |
| command-line interface (CLI) | `src/verifier/runtime/public_cli.py` | Arguments and dispatch from `vstd` |
| Examples | `examples/` | Bounded demonstrations and input artifacts |
| Tests | `tests/` | Executable assertions about named behavior |
| Explanation | `docs/` | Guides, architecture, and policies |
| Research records | `experiments/` | Non-normative experiments and unresolved horizons |

The [architecture map](ARCHITECTURE.md) names the runtime, schema, and test owners
for each profile. Normative meaning is controlled by `standard/`; generated pages
are a presentation of that source.

## Trace one command

Start with `vstd plan` from [your first receipt](FIRST_RECEIPT.md):

1. Read its parser and dispatch in `src/verifier/runtime/public_cli.py`.
2. Follow the plan construction in `src/verifier/core/run_planning.py`.
3. Compare the manifest with `examples/generic_run/manifest.json`.
4. Read the generic-run assertions in `tests/test_generic_run.py`.
5. Consult `standard/VSTD-1.md` before changing the receipt meaning.

For Python application programming interface (API) work, start with
`src/verifier/__init__.py` and the [API stability policy](API_STABILITY.md).
An importable internal helper is not automatically a supported public API.

## Run a bounded check

For a change to the generic-run path, begin with its relevant test file:

```bash
python -m pytest tests/test_generic_run.py -vv -s --durations=10 --timeout=60
```

Then run the checks appropriate to the affected surface. Presentation changes
should include the generated-reference and documentation checks:

```bash
python scripts/build_reference.py --check
python scripts/check_presentation.py
python scripts/check_acronyms.py
python scripts/check_terminology.py
```

A passing test establishes its named assertion under that environment. It does
not promote the implementation to a standard, independently verified result, or
universal compatibility claim.

## Build the documentation portal

The portal adds navigation, local search, and reader tools to the existing source
renderer. It also builds a separate released reference from tag `v1.3.0`.
The build requires that tag locally, Python, and Git; it needs no frontend package
manager or third-party search account.

```bash
git fetch origin tag v1.3.0
python scripts/build_docs_portal.py --output build/documentation-portal
python -m http.server 8933 --bind 127.0.0.1 --directory build/documentation-portal
```

Use an empty output directory. The build refuses to merge with existing files.
`portal-coordinate.json` records release and repository coordinates;
`build-manifest.json` records file digests. Generated artifacts belong under
`build/`, not among maintained documentation sources.

The existing GitHub Pages build and schema identifiers remain unchanged.
The documentation domain is a separate hosting target. See
[documentation hosting](DOCUMENTATION_HOSTING.md) for its cutover procedure.

## Prepare a contribution

Follow the [contribution guidelines](../CONTRIBUTING.md). Describe the exact
affected proposition, source coordinate, change, validation, and remaining
unknowns. Use the designated [security reporting route](../SECURITY.md) for
sensitive findings. A useful counterexample is one another maintainer can rerun.
