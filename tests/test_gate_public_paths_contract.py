"""Public command-line interface (CLI) and bounded scanner regression contracts.

JavaScript Object Notation (JSON) diagnostics remain portable; trusted local
application programming interface (API) diagnostics retain exact findings.
"""
from __future__ import annotations

from io import BytesIO
import json
from pathlib import Path
import tarfile
import zipfile

import pytest

from verifier.runtime import gate, public_cli

main = public_cli.main

ROOT = Path(__file__).resolve().parents[1]
# Bind native imports to this checkout rather than an installed shadow package.
assert Path(gate.__file__).resolve() == ROOT / "src/verifier/runtime/gate.py"
assert Path(public_cli.__file__).resolve() == ROOT / "src/verifier/runtime/public_cli.py"


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


def _record_reads(monkeypatch):
    reads = []
    counters = []
    original = gate._read_scan_stream
    def observe(stream, used):
        class ReadObserver:
            def read(self, size=-1):
                assert size >= 0, 'Every underlying read must have an explicit bound'
                data = stream.read(size)
                reads.append(len(data))
                return data
        counters.append(used)
        return original(ReadObserver(), used)
    monkeypatch.setattr(gate, '_read_scan_stream', observe)
    return reads, counters


@pytest.mark.parametrize('json_output', [False, True])
@pytest.mark.parametrize('directory', [False, True])
def test_public_paths_diagnostics_keep_safe_relative_location_without_echo(tmp_path, capsys, json_output, directory):
    nested = tmp_path / 'nested'
    nested.mkdir()
    path = nested / 'client.js'
    path.write_text(_marker(), encoding='utf-8')
    target = tmp_path if directory else path
    expected_locator = 'nested/client.js' if directory else 'client.js'
    args = ['gate', 'paths', str(target)] + (['--json'] if json_output else [])
    assert main(args) == 1
    output = capsys.readouterr().out
    assert _marker() not in output, 'Public diagnostics must not echo matched source bytes'
    assert str(tmp_path) not in output and tmp_path.as_posix() not in output
    assert 'FAIL' in output and expected_locator in output.replace('\\', '/')
    if json_output:
        record = json.loads(output)
        assert record['status'] == 'FAIL' and record['scanned_files'] == 1
        assert record['violations'][0]['file'] == expected_locator
        assert record['violations'][0]['line'] == 1
        assert record['violations'][0]['label'] == 'Windows drive path'


def test_trusted_paths_api_retains_exact_diagnostics(tmp_path):
    path = tmp_path / 'client.js'
    path.write_text(_marker(), encoding='utf-8')
    count, findings = gate.run_paths_gate(path)
    assert count == 1 and len(findings) == 1
    assert findings[0]['match'] == _marker() and findings[0]['file'] == str(path)


@pytest.mark.parametrize('json_output', [False, True])
def test_paths_cli_redacts_locator_matching_existing_secret_detector(tmp_path, capsys, json_output):
    # This is the existing detector's shape, not a new private-filename policy.
    secret_filename = 'sk-' + 'A' * 32 + '.js'
    assert any(pattern.search(secret_filename) for _label, pattern in gate.SECRET_PATTERNS)
    (tmp_path / secret_filename).write_text(_marker(), encoding='utf-8')
    args = ['gate', 'paths', str(tmp_path)] + (['--json'] if json_output else [])
    assert main(args) == 1
    output = capsys.readouterr().out
    assert secret_filename not in output, 'Relativizing a secret-shaped filename does not redact it'
    assert _marker() not in output and str(tmp_path) not in output
    assert 'FAIL' in output and 'Windows drive path' in output
    if json_output:
        record = json.loads(output)
        assert record['status'] == 'FAIL' and record['scanned_files'] == 1
        finding = record['violations'][0]
        assert finding['line'] == 1 and finding['label'] == 'Windows drive path'
        assert isinstance(finding['file'], str) and 'redacted' in finding['file'].lower()


@pytest.mark.parametrize('json_output', [False, True])
def test_existing_boundary_cli_redaction_contract_is_preserved(tmp_path, capsys, json_output):
    secret_filename = 'sk-' + 'A' * 32 + '.js'
    (tmp_path / secret_filename).write_text('synthetic forbidden marker', encoding='utf-8')
    args = ['gate', 'boundary', str(tmp_path), '--forbidden', 'forbidden marker']
    if json_output:
        args.append('--json')
    assert main(args) == 1
    output = capsys.readouterr().out
    assert secret_filename not in output and str(tmp_path) not in output
    assert 'FAIL' in output and 'forbidden_term_leak' in output


def test_clean_paths_cli_control_stays_a_real_inspected_pass(tmp_path, capsys):
    (tmp_path / 'client.js').write_text('docs/guide.md', encoding='utf-8')
    assert main(['gate', 'paths', str(tmp_path), '--json']) == 0
    record = json.loads(capsys.readouterr().out)
    assert record == {'status': 'PASS', 'scanned_files': 1, 'violations': []}


def test_rejected_stream_bytes_consume_total_budget(monkeypatch):
    monkeypatch.setattr(gate, 'MAX_SCAN_FILE_BYTES', 8)
    monkeypatch.setattr(gate, 'MAX_SCAN_TOTAL_BYTES', 16)
    used = [0, 0]
    reads = []
    for _ in range(3):
        stream = BytesIO(b'x' * 12)
        with pytest.raises(ValueError):
            gate._read_scan_stream(stream, used)
        reads.append(stream.tell())
    assert sum(reads) <= 17, 'Only one sentinel byte may exceed the aggregate budget'
    assert used[0] == sum(reads), 'Rejected bytes must remain charged to the aggregate counter'


@pytest.mark.parametrize('scanner', ['paths', 'boundary'])
@pytest.mark.parametrize('oversized', [False, True])
def test_directory_callers_enforce_actual_total_bytes(tmp_path, monkeypatch, scanner, oversized):
    monkeypatch.setattr(gate, 'MAX_SCAN_FILE_BYTES', 8)
    monkeypatch.setattr(gate, 'MAX_SCAN_TOTAL_BYTES', 16)
    for index in range(3):
        (tmp_path / f'{index}.js').write_bytes(b'x' * (12 if oversized else 4))
    reads, counters = _record_reads(monkeypatch)
    count, findings = (gate.run_paths_gate if scanner == 'paths' else gate.run_boundary_gate)(tmp_path)
    assert sum(reads) <= 17
    assert counters and counters[-1][0] == sum(reads)
    if oversized:
        assert count == 0 and findings
    else:
        assert count == 3 and findings == [] and sum(reads) == 12


@pytest.mark.parametrize('suffix', ['.zip', '.whl', '.tar.gz'])
@pytest.mark.parametrize('overflow', [False, True])
def test_archive_callers_charge_rejected_tail_reads(tmp_path, monkeypatch, suffix, overflow):
    monkeypatch.setattr(gate, 'MAX_SCAN_FILE_BYTES', 8)
    monkeypatch.setattr(gate, 'MAX_SCAN_TOTAL_BYTES', 256)
    for index in range(34 if overflow else 4):
        path = tmp_path / (f'{index:03d}' + suffix)
        _archive(path, 'client.js', b'ordinary')
        assert path.stat().st_size <= 256, 'Compressed archive must fit admission for this probe'
    reads, counters = _record_reads(monkeypatch)
    count, findings = gate.run_boundary_gate(tmp_path)
    assert sum(reads) <= 257, 'Archive rejections must not reset or bypass the aggregate allowance'
    assert counters and counters[-1][0] == sum(reads)
    if overflow:
        assert count == 32 and findings
    else:
        assert count == 4 and findings == [] and sum(reads) == 32

