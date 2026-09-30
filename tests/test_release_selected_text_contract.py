"""Archive text selection must inspect portable and prohibited payloads alike.

This native fixture binds both release scripts to the current repository.
"""
from __future__ import annotations

import importlib.util
from io import BytesIO
from pathlib import Path
import sys
import tarfile
import zipfile

import pytest

RELEASE_ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def release(monkeypatch):
    def load(name, filename):
        spec = importlib.util.spec_from_file_location(name, RELEASE_ROOT / 'scripts' / filename)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        assert Path(module.__file__).resolve() == RELEASE_ROOT / "scripts" / filename
        return module
    monkeypatch.setitem(sys.modules, 'check_presentation', load('acceptance_presentation', 'check_presentation.py'))
    return load('acceptance_release', 'check_release_boundary.py')


def _marker():
    return 'E:' + '/synthetic-private-acceptance/record'


def _archive(path, member, payload):
    if path.name.endswith('.tar.gz'):
        with tarfile.open(path, 'w:gz') as archive:
            info = tarfile.TarInfo(member)
            info.size = len(payload)
            archive.addfile(info, BytesIO(payload))
    else:
        with zipfile.ZipFile(path, 'w', zipfile.ZIP_DEFLATED) as archive:
            archive.writestr(member, payload)


@pytest.mark.parametrize('suffix', ['.zip', '.whl'])
@pytest.mark.parametrize('member', ['package/client.js', 'package/client.' + 'ts'.upper(), 'LICENSE', 'Dockerfile'])
@pytest.mark.parametrize('prohibited', [False, True])
def test_release_selected_text_requires_real_inspection(release, tmp_path, suffix, member, prohibited):
    artifact = tmp_path / ('actual' + suffix)
    value = _marker() if prohibited else 'docs/guide.md'
    _archive(artifact, member, ('source = "' + value + '";').encode())
    errors = []
    assert release.check_artifact(artifact, errors) == 1, 'A supported text member must actually be inspected'
    assert bool(errors) is prohibited
    assert all(value not in error for error in errors)
    assert release.main([str(artifact)]) == int(prohibited)


@pytest.mark.parametrize('prohibited', [False, True])
def test_release_existing_markdown_control(release, tmp_path, prohibited):
    artifact = tmp_path / 'ordinary.zip'
    _archive(artifact, 'guide.md', (_marker() if prohibited else 'docs/guide.md').encode())
    errors = []
    assert release.check_artifact(artifact, errors) == 1
    assert bool(errors) is prohibited
