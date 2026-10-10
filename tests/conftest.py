"""Shared pytest fixtures for the Verifier test suite."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
import importlib.util
from pathlib import Path
import sys
from typing import Any

import pytest

# Registries that tests change through ``monkeypatch.delitem``. pytest undoes a
# deletion by assigning the key back, which restores the entry but appends it,
# so every later test, and any comparison with a freshly imported interpreter
# such as an installed wheel, would see a different iteration order.
_ORDERED_REGISTRIES = (
    ("verifier.domains.contracts.current_object_routes", "_ROUTES"),
    ("verifier.domains.inventory", "MECHANIZED_12_POINT_BINDINGS"),
)

_BOUNDARY_SCANNER = Path(__file__).resolve().parents[1] / "scripts" / "check_presentation.py"
_scanner: Any = None


@pytest.fixture(autouse=True)
def _restore_registry_iteration_order() -> Iterator[None]:
    """Put a registry back in its original order when only the order changed."""
    snapshots = []
    for module_name, attribute in _ORDERED_REGISTRIES:
        registry = getattr(sys.modules.get(module_name), attribute, None)
        if isinstance(registry, dict):
            snapshots.append((registry, list(registry.items())))
    yield
    for registry, items in snapshots:
        # Contents that differ are a leaked mutation, not an ordering artifact:
        # leave those visible instead of repairing them here.
        if list(registry.items()) != items and dict(registry) == dict(items):
            registry.clear()
            registry.update(items)


def _boundary_labels(text: str) -> list[str]:
    """Labels the release boundary scanner gives ``text``, loaded once from the scanner's own file."""
    global _scanner
    if _scanner is None:
        spec = importlib.util.spec_from_file_location("_verifier_boundary_scanner", _BOUNDARY_SCANNER)
        if spec is None or spec.loader is None:
            raise RuntimeError("the release boundary scanner cannot be loaded")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _scanner = module
    return _scanner.public_boundary_violations(text)


def public_id_violations(names: Iterable[str]) -> dict[str, list[str]]:
    """The test names the release boundary scanner would reject in a test report, with their labels."""
    flagged = {}
    for name in names:
        labels = _boundary_labels(name)
        if labels:
            flagged[name] = labels
    return flagged


@pytest.hookimpl(trylast=True)
def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Stop before running a test whose generated id the public boundary scan rejects in the test report.

    ``scripts/check_release_boundary.py`` rejects such a report, but only after the whole suite has run.
    A parameter that looks like a credential, an address or a workstation path needs an explicit ``id``.
    The message names the test function and the label, never the id, so the matched text is not repeated.
    """
    flagged = public_id_violations(item.name for item in items)
    if not flagged:
        return
    parts = sorted({
        f"{item.path.name}::{getattr(item, 'originalname', None) or item.name.split('[', 1)[0]}"
        f" ({', '.join(flagged[item.name])})"
        for item in items if item.name in flagged
    })
    raise pytest.UsageError(
        "generated test ids match public-boundary patterns; give the parameter an explicit id: "
        + "; ".join(parts[:20])
    )
