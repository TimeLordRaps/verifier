# Install Verifier

Verifier implements the Verifier Standard (VSTD), a verification-domain language for
portable, bounded, refutable evidence about computational claims.

## Install the released package

Use Python 3.10 or newer in a fresh virtual environment. The base runtime has no
required third-party dependencies. These instructions pin release **1.3.0** from
the Python Package Index (PyPI).

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
python -m pip install verifier-standard==1.3.0
python -c "import verifier; print(verifier.__version__)"
vstd --help
```

The version command should print `1.3.0`. The distribution name is
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

The documentation portal provides a released `1.3.0` reference generated from the
corresponding Git tag and a separate current repository reference. Repository
source can include commands that the released distribution does not yet contain.
Use the version selector or the **Package reference · 1.3.0** navigation group when
working with the package above.

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
