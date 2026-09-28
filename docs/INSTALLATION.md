# Install Verifier

Verifier implements the Verifier Standard (VSTD), a verification-domain language for
portable, bounded, refutable evidence about computational claims.

## Install the v2.0.0 candidate source

Use Python 3.10 or newer in a fresh virtual environment. The base runtime has no
required third-party dependencies. Use the v2.0.0 source revision identified in
the GitHub Pages `documentation-coordinate.json` or the portal preview's
`portal-coordinate.json`. Version 2.0.0 is not yet a
published Python Package Index (PyPI) release. From that source checkout:

```bash
python -m venv .venv
```

Activate the environment on Windows PowerShell:

```powershell
.venv\Scripts\Activate.ps1
```

Or on macOS and Linux:

```bash
source .venv/bin/activate
```

Install and inspect the version:

```bash
python -m pip install .
python -c "import verifier; print(verifier.__version__)"
vstd --help
```

The version command should print `2.0.0` for this candidate source. The distribution name is
`verifier-standard`; the Python import is `verifier`; the cross-platform command
is `vstd`. On Windows, the name `verifier` can resolve to Windows Driver Verifier,
so use `vstd` for this package.

## Check the defensive demo

```bash
vstd demo
```

The demo exercises four expected defensive outcomes, including rejection and
preservation of `UNKNOWN`. Its `[DEMO OK]` result means those expectations matched
for these specimens. It is not an assurance claim about your own application.

Continue with [your first receipt](FIRST_RECEIPT.md) to capture a small computation.

## Use Python directly

The application programming interface (API) is exposed through the top-level
`verifier` package. For example, canonical digesting produces the same digest for
these two mappings, whose key order differs:

```python
from verifier import compute_canonical_digest

left = {"claim": "example", "value": 3}
right = {"value": 3, "claim": "example"}
assert compute_canonical_digest(left) == compute_canonical_digest(right)
```

This checks canonical digest agreement for these payloads. It does not establish
the truth of a claim, authenticate its producer, or create a complete receipt.
See the [API stability policy](API_STABILITY.md) before depending on an export.

## Choose a documentation coordinate

The root documentation and generated reference describe the v2.0.0 candidate
source. They are tied to the repository revision in the site's build metadata.
Read the [candidate scope and migration guide](V2_CANDIDATE.md) and
[open contradictions](../TIME.md) before relying on candidate behavior.

The separately built portal preview has a version selector and a tagged archive
for the published `1.5.0` package. If you need that release, install
`verifier-standard==1.5.0` from PyPI and use its tagged
[GitHub release](https://github.com/TimeLordRaps/verifier/releases/tag/v1.5.0)
and corresponding reference. The GitHub Pages build does not include the portal
archive.
Do not mix examples or API coverage across these coordinates.

To work on repository changes, follow the
[repository walkthrough](REPOSITORY_WALKTHROUGH.md). Avoid mixing an editable
checkout and a released package in the same environment when comparing behavior.

## Troubleshoot the environment

If `vstd` is unavailable, confirm the virtual environment is active and inspect
the package in that same interpreter:

```bash
python -m pip show verifier-standard
python -c "import sys, verifier; print(sys.executable); print(verifier.__file__)"
```

An unexpected import path can indicate another installed package or a local file
named `verifier.py`. Resolve that shadowing before interpreting a command result.
