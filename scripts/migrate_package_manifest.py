"""Compatibility command for Verifier's installed manifest-migration engine.

The production implementation is packaged under ``verifier.runtime`` so the
installed ``vstd polish`` command never executes a repository-provided script.
This wrapper exports one statically discoverable command entry point; tests and
library callers import the installed module directly.
"""

from __future__ import annotations

from verifier.runtime.package_manifest_migration import main


if __name__ == "__main__":
    raise SystemExit(main())
