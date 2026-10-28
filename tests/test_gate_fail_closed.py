"""Refutable failure boundaries for the Verifier Standard (VSTD) automation gates.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
"""
from __future__ import annotations

import json
import io
from pathlib import Path
import stat
import tarfile
from types import SimpleNamespace
import zipfile

import pytest

from verifier.core.certificate import canonical_digest
from verifier.runtime import gate
from verifier.runtime.public_cli import main


@pytest.mark.parametrize("scanner", [gate.run_paths_gate, gate.run_ast_gate, gate.run_boundary_gate])
def test_missing_and_empty_scope_cannot_pass(scanner, tmp_path: Path) -> None:
    for target in (tmp_path / "missing", tmp_path):
        count, violations = scanner(target)
        assert count == 0
        assert violations, "No inspected input cannot establish a clean scan"


@pytest.mark.parametrize("scanner", [gate.run_paths_gate, gate.run_ast_gate, gate.run_boundary_gate])
def test_unreadable_selected_file_cannot_pass(scanner, tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "selected.py"
    target.write_text("answer = 42\n", encoding="utf-8")
    original = Path.open

    def denied(path, *args, **kwargs):
        if path == target:
            raise PermissionError("selected input denied")
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "open", denied)
    assert scanner(target)[1]


def test_corrupt_archive_cannot_pass(tmp_path: Path) -> None:
    archive = tmp_path / "broken.zip"
    archive.write_bytes(b"not a zip archive")
    assert gate.run_boundary_gate(archive)[1]


def test_invalid_utf8_selected_text_cannot_pass(tmp_path: Path) -> None:
    target = tmp_path / "broken.py"
    target.write_bytes(b"x = 1\n\xff")
    assert gate.run_boundary_gate(target)[1]


def test_oversized_archive_member_is_not_read_without_bound(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(gate, "MAX_SCAN_FILE_BYTES", 64, raising=False)
    archive = tmp_path / "oversized.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as stream:
        stream.writestr("payload.txt", "x" * 65)
    assert gate.run_boundary_gate(archive)[1]


def test_missing_forbidden_terms_file_fails_closed(tmp_path: Path, capsys) -> None:
    target = tmp_path / "public.txt"
    target.write_text("public", encoding="utf-8")
    result = main(["gate", "boundary", str(target), "--forbidden-file", str(tmp_path / "missing"), "--json"])
    assert result != 0
    assert json.loads(capsys.readouterr().out)["status"] != "PASS"


def test_key_selected_verification_rejects_unsigned_downgrade() -> None:
    unsigned = gate.create_ci_attestation_receipt(workflow="test", run_id="1")
    assert gate.verify_ci_attestation_receipt(unsigned, key="checker-selected-key")[0] is False


@pytest.mark.parametrize("signature", ["\u00e9", [], None, "abcd", "G" * 64])
def test_malformed_authentication_signature_rejects_without_crashing(signature) -> None:
    receipt = gate.create_ci_attestation_receipt(workflow="test", run_id="1", key="test-key")
    receipt["signature"] = signature
    assert gate.verify_ci_attestation_receipt(receipt, key="test-key")[0] is False


def test_rehashed_outer_pass_cannot_override_inner_failure() -> None:
    receipt = gate.create_ci_attestation_receipt(workflow="test", run_id="1", status="FAIL")
    receipt["status"] = "PASS"
    receipt["receipt_digest"] = "sha256:" + canonical_digest({k: v for k, v in receipt.items() if k != "receipt_digest"})
    assert gate.verify_ci_attestation_receipt(receipt)[0] is False


def test_unsigned_record_reports_integrity_not_authenticated_execution(tmp_path: Path, capsys) -> None:
    receipt = gate.create_ci_attestation_receipt(workflow="test", run_id="1")
    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(receipt), encoding="utf-8")
    assert main(["gate", "attest", "--verify", str(path), "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["authenticated"] is False
    assert result["execution_verified"] is False


def test_unknown_attestation_fields_are_rejected_even_if_rehashed() -> None:
    receipt = gate.create_ci_attestation_receipt(workflow="test", run_id="1")
    receipt["authority"] = "release-approved"
    receipt["receipt_digest"] = "sha256:" + canonical_digest({k: v for k, v in receipt.items() if k != "receipt_digest"})
    assert gate.verify_ci_attestation_receipt(receipt)[0] is False


@pytest.mark.parametrize("archive", [False, True])
def test_environment_dotfile_is_inside_boundary_scope(tmp_path: Path, archive: bool) -> None:
    marker = "synthetic_forbidden_marker"
    if archive:
        target = tmp_path / "bundle.zip"
        with zipfile.ZipFile(target, "w") as stream:
            stream.writestr(".env", marker)
            stream.writestr("readme.txt", "ordinary")
    else:
        target = tmp_path
        (target / ".env").write_text(marker, encoding="utf-8")
        (target / "readme.txt").write_text("ordinary", encoding="utf-8")
    assert any(v["kind"] == "forbidden_term_leak" for v in gate.run_boundary_gate(target, forbidden_terms=[marker])[1])


def test_directory_special_file_is_rejected_before_open(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "special.py"
    target.write_text("pass", encoding="utf-8")
    original = Path.lstat

    def special(path, *args, **kwargs):
        if path == target:
            return SimpleNamespace(st_mode=stat.S_IFIFO, st_file_attributes=0)
        return original(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", special)
    assert gate.run_ast_gate(tmp_path)[1]


def test_every_adapter_count_in_description_is_checked() -> None:
    from verifier.domains.catalog import CHECKS
    body = f"Coordinate: local\n{len(CHECKS)} domain adapters. Later: {len(CHECKS)+1} domain adapters."
    report, findings = gate.run_pr_gate(body)
    assert report["status"] == "FAIL" and findings


def test_description_commit_must_resolve_to_actual_repository(tmp_path: Path) -> None:
    report, findings = gate.run_pr_gate("Coordinate: repo=fixture\n" + "a" * 40,
                                       commit="a" * 40, repo_root=tmp_path)
    assert report["status"] == "FAIL" and findings


def test_tar_does_not_decompress_unselected_members_beyond_scan_budget(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(gate, "MAX_SCAN_FILE_BYTES", 64)
    path = tmp_path / "bounded.tar.gz"
    with tarfile.open(path, "w:gz") as archive:
        for name, data in (("large.bin", b"x" * 65), ("ordinary.txt", b"ordinary")):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    assert gate.run_boundary_gate(path)[1]
