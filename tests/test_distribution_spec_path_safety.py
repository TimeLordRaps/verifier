"""Archive aliases must not replace independently selected specification bytes.

Verifier Standard (VSTD); source distribution (sdist); ZIP archive format (ZIP).
Portable tests exercise the real distribution checker and its existing positive
archive fixture. The Windows-only extraction observations read each archive member
with the standard library and write it into an independently checked owned
destination, so the case-insensitive file system is the only installer-like
behaviour under test. They do not install a wheel, launch a child process, use
an installer's private helpers, or establish a hosted exploit.
Byte sizes are exact encoded quantities; counts have no physical unit.
"""
from __future__ import annotations

import copy
import io
import os
import posixpath
import re
import stat
import tarfile
import zipfile

import pytest
import test_distribution_source_spec_binding as _fixture

from scripts import release_artifacts


# Reuse the already accepted positive-control producer, not a second checker.
archives = _fixture.archives
REQUIRED = _fixture.REQUIRED


def _verify(wheel, sdist, selected_source):
    # Require the independent selector. A signature shim cannot mask its loss.
    release_artifacts._verify_python_distributions(
        wheel, sdist, "2.0.0", source_files=selected_source)


def _changed(payload):
    assert payload
    return bytes([payload[0] ^ 1]) + payload[1:]


def _rewrite_wheel(path, *, append=None, replace=None, mode=None):
    with zipfile.ZipFile(path) as bundle:
        original = [(copy.copy(info), bundle.read(info)) for info in bundle.infolist()]
    with zipfile.ZipFile(path, "w") as bundle:
        for info, payload in original:
            if info.filename == "verifier/" + REQUIRED:
                if replace is not None:
                    payload = replace(payload)
                if mode is not None:
                    info.create_system = 3
                    info.external_attr = mode << 16
            bundle.writestr(info, payload)
            if info.filename == "verifier/" + REQUIRED and mode == 0:
                # writestr supplies permission bits for zero attributes. The
                # central-directory record must retain literal zero for this
                # distinct historical-compatible control.
                info.external_attr = 0
        if append is not None:
            bundle.writestr(*append)


def _rewrite_sdist(path, *, append=None, replace=None, member_type=None):
    with tarfile.open(path, "r:gz") as bundle:
        original = []
        for member in bundle.getmembers():
            handle = bundle.extractfile(member) if member.isfile() else None
            original.append((copy.copy(member), handle.read() if handle is not None else None))
    with tarfile.open(path, "w:gz") as bundle:
        for member, payload in original:
            if member.name.endswith("/src/verifier/" + REQUIRED):
                if replace is not None:
                    payload = replace(payload)
                    member.size = len(payload)
                if member_type is not None:
                    member.type = member_type
                    member.size = 0
                    member.linkname = "unused-contained-target"
                    payload = None
            bundle.addfile(member, io.BytesIO(payload) if payload is not None else None)
        if append is not None:
            name, payload = append
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            bundle.addfile(member, io.BytesIO(payload))


def _alias_name(surface, variant):
    package = {
        "directory-case": "verifier/Standard/POLISH_REQUIREMENTS.md",
        "extension-case": "verifier/standard/POLISH_REQUIREMENTS.MD",
        "package-case": "Verifier/standard/POLISH_REQUIREMENTS.md",
        "parent-segment": "verifier/x/../standard/POLISH_REQUIREMENTS.md",
        "dot-segment": "verifier/./standard/POLISH_REQUIREMENTS.md",
        "double-separator": "verifier//standard/POLISH_REQUIREMENTS.md",
        "windows-separator": "verifier\\standard\\POLISH_REQUIREMENTS.md",
    }[variant]
    return package if surface == "wheel" else "verifier_standard-2.0.0/src/" + package


def _mutated_alias_archives(tmp_path, surface, variant):
    wheel, sdist, selected = archives(tmp_path)
    changed = _changed(selected["src/verifier/" + REQUIRED])
    appended = (_alias_name(surface, variant), changed)
    if surface == "wheel":
        if variant == "windows-separator" and os.sep == "\\":
            # CPython ZipInfo normalizes the constructor's backslashes before
            # serialization on Windows. This producer writes an exact duplicate,
            # which the existing duplicate guard must continue to reject.
            with pytest.warns(UserWarning, match=r"^Duplicate name: 'verifier/standard/POLISH_REQUIREMENTS\.md'$"):
                _rewrite_wheel(wheel, append=appended)
        else:
            _rewrite_wheel(wheel, append=appended)
    else:
        _rewrite_sdist(sdist, append=appended)
    return wheel, sdist, selected, changed


def test_exact_archives_remain_a_positive_control(tmp_path):
    _verify(*archives(tmp_path))


@pytest.mark.parametrize("surface", ["wheel", "sdist"])
@pytest.mark.parametrize("variant", [
    "directory-case", "extension-case", "package-case", "parent-segment",
    "dot-segment", "double-separator", "windows-separator",
])
def test_selected_specification_path_aliases_are_rejected(tmp_path, surface, variant):
    wheel, sdist, selected, _ = _mutated_alias_archives(tmp_path, surface, variant)
    expected_reason = "noncanonical packaged specification member alias"
    if surface == "wheel" and variant == "windows-separator":
        with zipfile.ZipFile(wheel) as bundle:
            infos = bundle.infolist()
        canonical = "verifier/" + REQUIRED
        if os.sep == "\\":
            # Inspect the serialized archive, independently of the checker:
            # both original central-directory names are already canonical.
            assert [info.filename for info in infos].count(canonical) == 2
            assert [info.orig_filename for info in infos].count(canonical) == 2
            assert _alias_name(surface, variant) not in [info.orig_filename for info in infos]
            expected_reason = "^wheel contains duplicate packaged specification members$"
        else:
            assert [info.filename for info in infos].count(canonical) == 1
            assert _alias_name(surface, variant) in [info.orig_filename for info in infos]
    with pytest.raises(release_artifacts.ReleaseError, match=expected_reason):
        _verify(wheel, sdist, selected)


@pytest.mark.parametrize("scheme", ["purelib", "platlib"])
def test_wheel_install_scheme_aliases_are_rejected(tmp_path, scheme):
    wheel, sdist, selected = archives(tmp_path)
    alias = f"verifier_standard-2.0.0.data/{scheme}/verifier/" + REQUIRED
    _rewrite_wheel(wheel, append=(alias, _changed(selected["src/verifier/" + REQUIRED])))
    with pytest.raises(release_artifacts.ReleaseError, match="noncanonical packaged specification member alias"):
        _verify(wheel, sdist, selected)


@pytest.mark.parametrize("mode", [stat.S_IFLNK | 0o777, stat.S_IFDIR | 0o755, stat.S_IFIFO | 0o600])
def test_wheel_selected_specifications_require_regular_members(tmp_path, mode):
    wheel, sdist, selected = archives(tmp_path)
    _rewrite_wheel(wheel, mode=mode)
    with pytest.raises(release_artifacts.ReleaseError, match="wheel specification is not a regular file"):
        _verify(wheel, sdist, selected)


@pytest.mark.parametrize("mode", [0, 0o600, stat.S_IFREG | 0o644])
def test_wheel_implicit_and_explicit_regular_modes_are_compatible(tmp_path, mode):
    wheel, sdist, selected = archives(tmp_path)
    _rewrite_wheel(wheel, mode=mode)
    _verify(wheel, sdist, selected)


@pytest.mark.parametrize("member_type", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE])
def test_sdist_nonregular_selected_specifications_remain_rejected(tmp_path, member_type):
    wheel, sdist, selected = archives(tmp_path)
    _rewrite_sdist(sdist, member_type=member_type)
    with pytest.raises(release_artifacts.ReleaseError, match="sdist specification is not a regular file"):
        _verify(wheel, sdist, selected)


@pytest.mark.parametrize("surface", ["wheel", "sdist"])
@pytest.mark.parametrize("mutation", ["truncate", "extend"])
def test_selected_specification_sizes_are_checked_before_content(tmp_path, surface, mutation):
    wheel, sdist, selected = archives(tmp_path)
    change = (lambda data: data[:-1]) if mutation == "truncate" else (lambda data: data + b"\x00")
    if surface == "wheel":
        _rewrite_wheel(wheel, replace=change)
    else:
        _rewrite_sdist(sdist, replace=change)
    qualifier = "packaged specification" if surface == "wheel" else "specification"
    member = ("verifier/" if surface == "wheel" else "verifier_standard-2.0.0/src/verifier/") + REQUIRED
    expected_reason = re.escape(
        f"{surface} {qualifier} byte size differs from selected source: {member}")
    with pytest.raises(release_artifacts.ReleaseError, match="^" + expected_reason + "$"):
        _verify(wheel, sdist, selected)


@pytest.mark.skipif(os.name != "nt", reason="OS_CAPABILITY_GUARD: Windows case-insensitive extraction observation")
@pytest.mark.parametrize("surface", ["wheel", "sdist"])
@pytest.mark.parametrize("variant", ["directory-case", "extension-case"])
def test_actual_case_alias_overwrites_are_contained(tmp_path, surface, variant):
    wheel, sdist, selected, changed = _mutated_alias_archives(tmp_path, surface, variant)
    destination = (tmp_path / "owned-extraction").resolve()
    destination.mkdir()
    # Independent containment gate covers EVERY member before extraction; no
    # submitted path or link can reach outside this owned test directory.
    if surface == "wheel":
        with zipfile.ZipFile(wheel) as bundle:
            members = [(info.filename, bundle.read(info)) for info in bundle.infolist() if not info.is_dir()]
            assert len(members) == len(bundle.infolist())
        for name, _ in members:
            target = (destination / posixpath.normpath(name.replace("\\", "/"))).resolve()
            assert target.is_relative_to(destination)
        target = destination / "verifier" / REQUIRED
    else:
        with tarfile.open(sdist, "r:gz") as bundle:
            members = []
            for member in bundle.getmembers():
                assert member.isfile()
                # The source-distribution directory is the single leading path segment.
                name = member.name.split("/", 1)[1]
                handle = bundle.extractfile(member)
                assert handle is not None
                members.append((name, handle.read()))
        for name, _ in members:
            target = (destination / posixpath.normpath(name)).resolve()
            assert target.is_relative_to(destination)
        target = destination / "src" / "verifier" / REQUIRED
    # Plain writes in archive order reproduce an installer's extraction: a later case-alias member
    # replaces the earlier canonical bytes only on a case-insensitive file system.
    for name, payload in members:
        path = (destination / posixpath.normpath(name.replace("\\", "/"))).resolve()
        assert path.is_relative_to(destination)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(payload)
    assert target.read_bytes() == changed
    assert changed != selected["src/verifier/" + REQUIRED]
