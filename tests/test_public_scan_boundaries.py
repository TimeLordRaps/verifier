"""Public scan boundaries retain coverage without visiting ignored build trees."""
from __future__ import annotations

import os
from pathlib import Path

import pytest
import verifier
from scripts import check_acronyms
from scripts import check_presentation

ROOT = Path(verifier.__file__).resolve().parents[2]


def scanner(name: str, root: Path, monkeypatch: pytest.MonkeyPatch):
    modules = {
        'check_presentation': check_presentation,
        'check_acronyms': check_acronyms,
    }
    module = modules[name]
    monkeypatch.setattr(module, 'ROOT', root)
    if name == 'check_acronyms':
        monkeypatch.setattr(module, 'GLOSSARY', root / 'docs' / 'ACRONYMS.md')
    return module, module._public_files if name == 'check_presentation' else module.public_reader_files


@pytest.mark.parametrize('name', ['check_presentation', 'check_acronyms'])
@pytest.mark.parametrize('ignored', ['build', 'dist', '.git', '.venv', '.pytest_cache', '__pycache__'])
def test_public_scan_never_descends_into_ignored_subtree(name, ignored, tmp_path, monkeypatch):
    hidden = tmp_path / 'nested' / ignored
    hidden.mkdir(parents=True)
    (hidden / 'omitted.md').write_text('Excluded generated material.', encoding='utf-8')
    visible = tmp_path / 'nested' / 'kept.md'
    visible.write_text('Required public material.', encoding='utf-8')
    module, scan = scanner(name, tmp_path, monkeypatch)
    original = os.scandir

    def refuse_ignored_visit(path):
        if Path(path) == hidden:
            raise AssertionError('ignored subtree was traversed')
        return original(path)

    monkeypatch.setattr(os, 'scandir', refuse_ignored_visit)
    assert scan() == [visible]


@pytest.mark.parametrize('name', ['check_presentation', 'check_acronyms'])
def test_public_scan_preserves_declared_file_selection(name, tmp_path, monkeypatch):
    paths = ['README.md', 'docs/visible.md', 'tests/test_visible.py', '.zenodo.json',
             'receipts/schema/sample.json', '.github/ISSUE_TEMPLATE/report.yml',
             'fixtures/ordinary.json', 'scripts/tool.rs', 'opaque.bin', 'docs/ACRONYMS.md',
             'nested/build/excluded.md', 'dist/excluded.py']
    for relative in paths:
        path = tmp_path / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('Retained fixture.', encoding='utf-8')
    module, scan = scanner(name, tmp_path, monkeypatch)
    expected = ['README.md', 'docs/visible.md', 'tests/test_visible.py', '.zenodo.json',
                'receipts/schema/sample.json', '.github/ISSUE_TEMPLATE/report.yml']
    expected += ['fixtures/ordinary.json', 'docs/ACRONYMS.md'] if name == 'check_presentation' else ['scripts/tool.rs']
    assert scan() == sorted(tmp_path / relative for relative in expected)
