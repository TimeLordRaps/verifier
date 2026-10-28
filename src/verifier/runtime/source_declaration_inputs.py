"""Declaration inputs of one Python source file.

Namespace derivation reads a small, fixed set of facts from each Python file:
definitions, lexical role hints, ``__vstd_kinds__`` markers, exports, imports as
written, and whether construction is dynamic.  The digest here covers exactly that
set, so a reviewed answer bound to a file stays valid while the digest is equal,
even if the whole-file syntax tree changed.  Locations are removed, so moving code
does not count as changing it.

Boundary, stated so a caller cannot over-read it: this is a per-file fingerprint.
It does not cover what another file's change does to this one (for example an
imported name disappearing); a caller that skips work on an equal digest must also
account for the fingerprints of the files this one imports.  It is also not a claim
that the file is correct or that its obligations are met; polish still checks the
current bytes against every obligation.
"""

from __future__ import annotations

import ast
import re
from typing import Any

from verifier.runtime import namespace_discovery, namespace_exports
from verifier.runtime.tier_zero_profile import value_digest

UNAVAILABLE = "PYTHON_DECLARATION_INPUTS_UNAVAILABLE"
SCHEMA = "verifier-python-declaration-inputs-1"

_LOCATION_KEYS = frozenset({
    "line", "lineno", "end_line", "end_lineno", "col", "col_offset", "span", "location",
})


def _without_locations(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _without_locations(item) for key, item in value.items()
                if key not in _LOCATION_KEYS}
    if isinstance(value, (list, tuple)):
        return [_without_locations(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted((_without_locations(item) for item in value), key=repr)
    return value


def _imports_as_written(tree: ast.Module) -> list[list[Any]]:
    """Every import in every scope, order-insensitive, without resolving targets."""
    rows: list[list[Any]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            rows.extend(["import", alias.name, alias.asname] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            rows.extend(["from", node.level, node.module, alias.name, alias.asname]
                        for alias in node.names)
    return sorted(rows, key=repr)


def python_declaration_inputs(path: str, raw: bytes) -> dict[str, Any]:
    """Return the location-free facts namespace derivation reads from this file.

    Raises ``ValueError(UNAVAILABLE)`` when the source cannot be parsed within the
    discovery bounds; an unavailable fingerprint must never compare as unchanged.
    """
    try:
        tree = ast.parse(raw, filename=path)
        surfaces = namespace_discovery._python_surfaces(path, raw, tree)
        summary = namespace_exports.summarize(path, tree, surfaces)
        # No source-import permissions are granted here: the flag may only be
        # more conservative than the whole-package discovery, never less.
        dynamic = namespace_exports.has_dynamic_construction(
            tree, closed_lazy=summary["closed_lazy"], permitted_source_imports=None)
    except (SyntaxError, UnicodeError, RecursionError, ValueError) as exc:
        raise ValueError(UNAVAILABLE) from exc
    return {
        "schema_version": SCHEMA,
        "path": path,
        "surfaces": [
            {**_without_locations(row),
             # A duplicate-definition suffix carries a line number; keep that it
             # is a duplicate, not where it sits.
             "surface_id": re.sub(r"@\d+$", "@<line>", row["surface_id"])}
            for row in surfaces
        ],
        "exports": _without_locations(summary),
        "imports": _imports_as_written(tree),
        "dynamic_construction": dynamic,
    }


def python_declaration_inputs_digest(path: str, raw: bytes) -> str:
    return value_digest(python_declaration_inputs(path, raw))
