"""Source-selected normative resources must survive distribution verification.

Verifier Standard (VSTD); source distribution (sdist); JavaScript Object Notation
(JSON); ZIP archive format (ZIP); Unicode Transformation Format, 8-bit (UTF-8).
Synthetic archives exercise the real distribution checker, without building,
installing, launching child processes or asserting hosted artifact damage.
Counts are dimensionless. Byte lengths are exact encoded quantities.
"""
from __future__ import annotations

import inspect
import io
from pathlib import Path
import tarfile
import zipfile

import pytest
import verifier
from scripts import release_artifacts


ROOT = Path(verifier.__file__).resolve().parents[2]
REQUIRED = "standard/POLISH_REQUIREMENTS.md"


def source_members():
    members = {"__init__.py": b'__version__ = "2.0.0"\n'}
    for name in ("polish.py", "polish_capacity.py", "polish_requirements.py"):
        members["runtime/" + name] = (ROOT / "src" / "verifier" / "runtime" / name).read_bytes()
    for source in (ROOT / "src" / "verifier" / "standard").glob("*.md"):
        members["standard/" + source.name] = source.read_bytes()
    for name in release_artifacts.PACKAGED_SCHEMA_NAMES:
        members["schemas/" + name] = b"{}\n"  # Existing gate validates schema inventory, not content.
    assert REQUIRED in members
    return members


def archives(tmp_path, *, surface=None, mutation=None):
    members = source_members()
    # Freeze external source selection before changing either archive.
    selected_source = {"src/verifier/" + name: payload for name, payload in members.items()}
    wheel_members, sdist_members = list(members.items()), list(members.items())
    chosen = wheel_members if surface == "wheel" else sdist_members
    if mutation == "missing":
        chosen[:] = [(name, payload) for name, payload in chosen if name != REQUIRED]
    elif mutation == "changed":
        chosen[:] = [(name, bytes([payload[0] ^ 1]) + payload[1:] if name == REQUIRED else payload)
                     for name, payload in chosen]
    elif mutation == "extra":
        chosen.append(("standard/UNSELECTED_EXTRA.md", b"Unselected normative claim.\n"))
    elif mutation == "duplicate":
        chosen.append((REQUIRED, members[REQUIRED]))
    metadata = b"Metadata-Version: 2.4\nName: verifier-standard\nVersion: 2.0.0\n\n"
    entries = "[console_scripts]\n" + "".join(
        name + " = " + target + "\n" for name, target in release_artifacts.CONSOLE_SCRIPTS.items())
    wheel = tmp_path / "verifier_standard-2.0.0-py3-none-any.whl"
    sdist = tmp_path / "verifier_standard-2.0.0.tar.gz"
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("verifier_standard-2.0.0.dist-info/METADATA", metadata)
        archive.writestr("verifier_standard-2.0.0.dist-info/entry_points.txt", entries.encode("utf-8"))
        seen = set()
        for name, payload in wheel_members:
            if name in seen:
                with pytest.warns(UserWarning, match="Duplicate name"):
                    archive.writestr("verifier/" + name, payload)
            else:
                archive.writestr("verifier/" + name, payload)
            seen.add(name)
    root = "verifier_standard-2.0.0/"
    with tarfile.open(sdist, "w:gz") as archive:
        for name, payload in [(root + "PKG-INFO", metadata)] + [
                (root + "src/verifier/" + name, data) for name, data in sdist_members]:
            entry = tarfile.TarInfo(name)
            entry.size = len(payload)
            archive.addfile(entry, io.BytesIO(payload))
    return wheel, sdist, selected_source


def verify(wheel, sdist, selected_source):
    # Baseline compatibility only: the unchanged helper lacks this independent
    # selector. Exercise its actual acceptance behavior instead of making RED a
    # missing-keyword TypeError. The post-repair path passes the frozen source.
    kwargs = ({"source_files": selected_source}
        if "source_files" in inspect.signature(release_artifacts._verify_python_distributions).parameters else {})
    return release_artifacts._verify_python_distributions(wheel, sdist, "2.0.0", **kwargs)


def test_distribution_specification_positive_control(tmp_path):
    verify(*archives(tmp_path))


@pytest.mark.parametrize("surface", ["wheel", "sdist"])
@pytest.mark.parametrize("mutation", ["missing", "changed", "extra", "duplicate"])
def test_distribution_specifications_are_exactly_source_bound(tmp_path, surface, mutation):
    wheel, sdist, selected_source = archives(tmp_path, surface=surface, mutation=mutation)
    expected_reason = "duplicate" if mutation == "duplicate" else "UNSELECTED_EXTRA" if mutation == "extra" else "POLISH_REQUIREMENTS"
    with pytest.raises(release_artifacts.ReleaseError, match=expected_reason):
        verify(wheel, sdist, selected_source)
