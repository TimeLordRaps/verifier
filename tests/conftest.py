"""Shared pytest fixtures for the Verifier test suite."""

from __future__ import annotations

from collections.abc import Iterable, Iterator
import hashlib
from pathlib import Path
import shutil

import pytest

from scripts import check_presentation as presentation_scanner
from verifier.domains import inventory
from verifier.domains.contracts import current_object_routes

REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
# Building a wheel in place makes setuptools rewrite ``src/*.egg-info`` and ``build/``.
# objects.vstd pins the tracked egg-info bytes, so one in-place build makes the next
# ``vstd polish`` refuse that owner as drifted.  Wheel tests build from ``wheel_source``.
_GENERATED_METADATA = REPOSITORY_ROOT / "src" / "verifier_standard.egg-info"
_WHEEL_BUILD_INPUTS = ("pyproject.toml", "README.md", "LICENSE", "NOTICE", "MANIFEST.in")


def _generated_metadata_digests() -> dict[str, str]:
    if not _GENERATED_METADATA.is_dir():
        return {}
    return {path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(_GENERATED_METADATA.iterdir()) if path.is_file()}


@pytest.fixture(scope="session", autouse=True)
def _generated_metadata_unchanged() -> Iterator[None]:
    """Fail the session when a test rewrote the tracked generated package metadata."""
    before = _generated_metadata_digests()
    yield
    after = _generated_metadata_digests()
    changed = sorted(name for name in before.keys() | after.keys() if before.get(name) != after.get(name))
    assert not changed, (
        "src/verifier_standard.egg-info changed during this test session (" + ", ".join(changed)
        + "): a test built a distribution from the live checkout; build from the wheel_source fixture.")


@pytest.fixture
def wheel_source(tmp_path: Path) -> Path:
    """Copy exactly what setuptools reads to build this project's wheel, so a build writes only here."""
    source = tmp_path / "wheel-source"
    source.mkdir()
    for name in _WHEEL_BUILD_INPUTS:
        shutil.copy2(REPOSITORY_ROOT / name, source / name)
    # MANIFEST.in names sdist-only scripts; copying them keeps egg_info's file list complete.
    for line in (REPOSITORY_ROOT / "MANIFEST.in").read_text(encoding="utf-8").splitlines():
        command, _, relative = line.partition(" ")
        if command == "include" and (REPOSITORY_ROOT / relative).is_file():
            (source / relative).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(REPOSITORY_ROOT / relative, source / relative)
    shutil.copytree(REPOSITORY_ROOT / "src", source / "src",
                    ignore=shutil.ignore_patterns("*.egg-info", "__pycache__", "*.pyc"))
    return source

# Registries that tests change through ``monkeypatch.delitem``. pytest undoes a
# deletion by assigning the key back, which restores the entry but appends it,
# so every later test, and any comparison with a freshly imported interpreter
# such as an installed wheel, would see a different iteration order.
@pytest.fixture(autouse=True)
def _restore_registry_iteration_order() -> Iterator[None]:
    """Put a registry back in its original order when only the order changed."""
    snapshots = []
    for registry in (
        current_object_routes._ROUTES,
        inventory.MECHANIZED_12_POINT_BINDINGS,
    ):
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
    """Labels the release boundary scanner gives ``text``."""
    return presentation_scanner.public_boundary_violations(text)


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
