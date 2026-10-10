"""Public scan boundaries retain coverage without visiting ignored build trees."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path

import pytest
import verifier

ROOT = Path(verifier.__file__).resolve().parents[2]


def scanner(name: str, root: Path):
    spec = importlib.util.spec_from_file_location('scan_boundary_' + name, ROOT / 'scripts' / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.ROOT = root
    if name == 'check_acronyms':
        module.GLOSSARY = root / 'docs' / 'ACRONYMS.md'
    return module, module._public_files if name == 'check_presentation' else module.public_reader_files


@pytest.mark.parametrize('name', ['check_presentation', 'check_acronyms'])
@pytest.mark.parametrize('ignored', ['build', 'dist', '.git', '.venv', '.pytest_cache', '__pycache__'])
def test_public_scan_never_descends_into_ignored_subtree(name, ignored, tmp_path, monkeypatch):
    hidden = tmp_path / 'nested' / ignored
    hidden.mkdir(parents=True)
    (hidden / 'omitted.md').write_text('Excluded generated material.', encoding='utf-8')
    visible = tmp_path / 'nested' / 'kept.md'
    visible.write_text('Required public material.', encoding='utf-8')
    module, scan = scanner(name, tmp_path)
    original = os.scandir

    def refuse_ignored_visit(path):
        if Path(path) == hidden:
            raise AssertionError('ignored subtree was traversed')
        return original(path)

    monkeypatch.setattr(os, 'scandir', refuse_ignored_visit)
    assert scan() == [visible]


@pytest.mark.parametrize('name', ['check_presentation', 'check_acronyms'])
def test_public_scan_preserves_declared_file_selection(name, tmp_path):
    paths = ['README.md', 'docs/visible.md', 'tests/test_visible.py', '.zenodo.json',
             'receipts/schema/sample.json', '.github/ISSUE_TEMPLATE/report.yml',
             'fixtures/ordinary.json', 'scripts/tool.rs', 'opaque.bin', 'docs/ACRONYMS.md',
             'nested/build/excluded.md', 'dist/excluded.py']
    for relative in paths:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('Retained fixture.', encoding='utf-8')
    module, scan = scanner(name, tmp_path)
    expected = ['README.md', 'docs/visible.md', 'tests/test_visible.py', '.zenodo.json',
                'receipts/schema/sample.json', '.github/ISSUE_TEMPLATE/report.yml']
    expected += ['fixtures/ordinary.json', 'docs/ACRONYMS.md'] if name == 'check_presentation' else ['scripts/tool.rs']
    assert scan() == sorted(tmp_path / relative for relative in expected)
