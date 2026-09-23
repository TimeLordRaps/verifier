"""Allow ``python -m verifier`` to reach the same command-line interface.

The console entry points are ``vstd`` and ``verifier``. Both require the
package to have been installed. ``python -m verifier`` works from a source
checkout with ``PYTHONPATH=src`` and is the first thing many people try, so it
dispatches to exactly the same ``main``.
"""
from __future__ import annotations

from verifier.runtime.public_cli import main

if __name__ == "__main__":
    raise SystemExit(main())
