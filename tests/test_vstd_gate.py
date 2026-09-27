"""Terminology: abstract syntax tree (AST); command-line interface (CLI);
continuous integration (CI); JavaScript Object Notation (JSON);
pull request (PR); uniform resource identifier (URI); Verifier Standard (VSTD).

Comprehensive adversarial test suite for vstd gate command-line interface (CLI) suite.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
import tarfile
import zipfile
import pytest

from verifier.runtime.gate import (
    run_paths_gate,
    run_ast_gate,
    run_boundary_gate,
    run_pr_gate,
    create_ci_attestation_receipt,
    verify_ci_attestation_receipt,
)
from verifier.runtime.public_cli import main


# ---------------------------------------------------------------------------
# PR Gate Tests
# ---------------------------------------------------------------------------

def test_pr_gate_empty_fails() -> None:
    report, findings = run_pr_gate("")
    assert report["status"] == "FAIL"
    assert any("empty" in f.lower() for f in findings)


def test_pr_gate_missing_coordinate_fails() -> None:
    report, findings = run_pr_gate("This PR does some work but mentions no coordinate.")
    assert report["status"] == "FAIL"
    assert any("coordinate" in f.lower() for f in findings)


def test_pr_gate_incorrect_adapter_count_fails() -> None:
    pr_text = "Coordinate: repo=test branch=main\nThis adds thirteen grounded domain adapters."
    report, findings = run_pr_gate(pr_text)
    assert report["status"] == "FAIL"
    assert any("states thirteen domain adapters" in f for f in findings)


def test_pr_gate_valid_passes() -> None:
    pr_text = (
        "## Coordinate\n"
        "Coordinate: repo=verifier branch=codex/v2-candidate\n\n"
        "This release includes twelve grounded domain adapters."
    )
    report, findings = run_pr_gate(pr_text)
    assert report["status"] == "PASS"
    assert findings == []


def test_pr_gate_cli_invocation(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    pr_file = tmp_path / "pr.md"
    pr_file.write_text(
        "Coordinate: repo=verifier branch=main\nValid PR description.\n",
        encoding="utf-8",
    )
    exit_code = main(["gate", "pr", "--file", str(pr_file), "--json"])
    assert exit_code == 0
    captured = capsys.readouterr()
    data = json.loads(captured.out)
    assert data["report"]["status"] == "PASS"


# ---------------------------------------------------------------------------
# Paths Gate Tests
# ---------------------------------------------------------------------------

def test_paths_gate_clean_passes(tmp_path: Path) -> None:
    f = tmp_path / "clean.txt"
    f.write_text("relative/path/to/resource.json\n", encoding="utf-8")
    count, violations = run_paths_gate(tmp_path)
    assert count == 1
    assert violations == []


@pytest.mark.parametrize("path_str,label_substr", [
    ("C:" + "\\Us" + "ers\\alice\\repo\\file.py", "Windows drive path"),
    ("D:" + "/workspace/sub/dir/test.txt", "Windows drive path"),
    ("\\\\server\\share\\project\\data", "UNC share path"),
    ("/ho" + "me/developer/code/main.py", "POSIX user home"),
    ("/Us" + "ers/bob/Documents/spec.md", "POSIX user home"),
    ("file:///" + "C:" + "/Us" + "ers/alice/data.json", "Absolute file URI"),
    ("file:///ho" + "me/bob/data.json", "Absolute file URI"),
], ids=("windows-home", "windows-workspace", "unc-share", "posix-home",
        "macos-home", "windows-file-uri", "posix-file-uri"))
def test_paths_gate_detects_forbidden_absolute_paths(
    tmp_path: Path, path_str: str, label_substr: str
) -> None:
    bad_file = tmp_path / "leak.txt"
    bad_file.write_text(f"Found path at: {path_str}\n", encoding="utf-8")
    count, violations = run_paths_gate(tmp_path)
    assert count == 1
    assert len(violations) >= 1
    assert any(label_substr in v["label"] for v in violations)


def test_paths_gate_cli_detects_violation_and_fails_closed(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    bad_file = tmp_path / "leaked_config.yaml"
    bad_file.write_text("workspace: " + "E:" + "\\projects\\internal\\tool\n", encoding="utf-8")
    exit_code = main(["gate", "paths", str(tmp_path), "--json"])
    assert exit_code == 1
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "FAIL"
    assert len(payload["violations"]) == 1


def test_paths_gate_exclude_flag_works(tmp_path: Path) -> None:
    # An exclusion narrows a nonempty scope; excluding everything is not a clean scan.
    (tmp_path / "clean.txt").write_text("portable relative input", encoding="utf-8")
    sub = tmp_path / "vendor"
    sub.mkdir()
    bad_file = sub / "vendor_file.txt"
    bad_file.write_text("C:" + "\\Windows\\system32\n", encoding="utf-8")
    # without exclude: fails
    count, violations = run_paths_gate(tmp_path)
    assert len(violations) == 1
    # with exclude: passes
    count, violations = run_paths_gate(tmp_path, additional_excludes=["*/vendor/*"])
    assert len(violations) == 0


def test_paths_gate_detects_multiple_violations_per_line(tmp_path: Path) -> None:
    f = tmp_path / "multi_leak.txt"
    f.write_text(
        "First: " + "C:" + "\\Us" + "ers\\alice\\file.py and second: /ho" + "me/bob/project/code.py\n",
        encoding="utf-8",
    )
    count, violations = run_paths_gate(tmp_path)
    assert count == 1
    assert len(violations) == 2
    labels = {v["label"] for v in violations}
    assert "Windows drive path" in labels
    assert "POSIX user home" in labels


def test_paths_gate_detects_non_windows_file_uri(tmp_path: Path) -> None:
    f = tmp_path / "uri_leak.txt"
    f.write_text("See: file://localhost/etc/shadow\n", encoding="utf-8")
    count, violations = run_paths_gate(tmp_path)
    assert count == 1
    assert len(violations) == 1
    assert "Absolute file URI" in violations[0]["label"]



# ---------------------------------------------------------------------------
# AST Gate Tests
# ---------------------------------------------------------------------------

def test_ast_gate_clean_python_passes(tmp_path: Path) -> None:
    clean_py = tmp_path / "clean.py"
    clean_py.write_text(
        "def compute(n: int) -> int:\n"
        "    total = 0\n"
        "    for i in range(100):\n"
        "        total += i\n"
        "    while total > 0:\n"
        "        total -= 1\n"
        "    return total\n",
        encoding="utf-8",
    )
    count, violations = run_ast_gate(tmp_path)
    assert count == 1
    assert violations == []


def test_ast_gate_unbounded_while_true_without_break_fails(tmp_path: Path) -> None:
    bad_py = tmp_path / "infinite.py"
    bad_py.write_text(
        "def loop_forever():\n"
        "    while True:\n"
        "        print('busy')\n",
        encoding="utf-8",
    )
    count, violations = run_ast_gate(tmp_path)
    assert len(violations) == 1
    assert violations[0]["kind"] == "unbounded_infinite_loop"


def test_ast_gate_while_true_with_break_passes(tmp_path: Path) -> None:
    ok_py = tmp_path / "bounded_loop.py"
    ok_py.write_text(
        "def loop_with_break():\n"
        "    while True:\n"
        "        break\n",
        encoding="utf-8",
    )
    count, violations = run_ast_gate(tmp_path)
    assert len(violations) == 0


def test_ast_gate_loop_bound_exceeded_fails(tmp_path: Path) -> None:
    big_loop_py = tmp_path / "big_loop.py"
    big_loop_py.write_text(
        "def process():\n"
        "    for i in range(5000000):\n"
        "        pass\n",
        encoding="utf-8",
    )
    count, violations = run_ast_gate(tmp_path, max_iterations=100000)
    assert len(violations) == 1
    assert violations[0]["kind"] == "loop_bound_exceeded"


def test_ast_gate_memory_accumulation_cap_fails(tmp_path: Path) -> None:
    oom_py = tmp_path / "oom.py"
    oom_py.write_text(
        "def allocate():\n"
        "    huge = [0] * 20000000\n"
        "    return huge\n",
        encoding="utf-8",
    )
    count, violations = run_ast_gate(tmp_path)
    assert len(violations) == 1
    assert violations[0]["kind"] == "memory_accumulation_cap_exceeded"


def test_ast_gate_cli_invocation(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad_py = tmp_path / "bad.py"
    bad_py.write_text("while 1:\n    x = 1\n", encoding="utf-8")
    exit_code = main(["gate", "ast", str(tmp_path), "--json"])
    assert exit_code == 1
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "FAIL"


def test_ast_gate_scalar_multiplication_clean_passes(tmp_path: Path) -> None:
    scalar_py = tmp_path / "scalar.py"
    scalar_py.write_text(
        "def compute_nanos(seconds: int) -> int:\n"
        "    multiplier = 1000000000\n"
        "    res = 1 * 20000000\n"
        "    return seconds * multiplier\n",
        encoding="utf-8",
    )
    count, violations = run_ast_gate(tmp_path)
    assert len(violations) == 0


def test_ast_gate_listcomp_memory_accumulation_fails(tmp_path: Path) -> None:
    comp_py = tmp_path / "comp.py"
    comp_py.write_text(
        "def make_large_list():\n"
        "    return [i for i in range(20000000)]\n",
        encoding="utf-8",
    )
    count, violations = run_ast_gate(tmp_path)
    assert len(violations) == 1
    assert violations[0]["kind"] == "memory_accumulation_cap_exceeded"



# ---------------------------------------------------------------------------
# Boundary Gate Tests
# ---------------------------------------------------------------------------

def test_boundary_gate_clean_passes(tmp_path: Path) -> None:
    f = tmp_path / "public.txt"
    f.write_text("Public open source artifact.\n", encoding="utf-8")
    count, violations = run_boundary_gate(tmp_path, forbidden_terms=["ConfidentialWorkspace"])
    assert violations == []


def test_boundary_gate_detects_parameterized_forbidden_term(tmp_path: Path) -> None:
    f = tmp_path / "leak.txt"
    f.write_text("Reference to ConfidentialProjectName here.\n", encoding="utf-8")
    count, violations = run_boundary_gate(
        tmp_path, forbidden_terms=["ConfidentialProjectName"]
    )
    assert len(violations) == 1
    assert violations[0]["kind"] == "forbidden_term_leak"


def test_boundary_gate_detects_secret_leak(tmp_path: Path) -> None:
    f = tmp_path / "key.pem"
    f.write_text("-----BEGIN " + "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n", encoding="utf-8")
    count, violations = run_boundary_gate(tmp_path)
    assert len(violations) == 1
    assert violations[0]["kind"] == "secret_leak"
    assert "private key block" in violations[0]["label"]


def test_boundary_gate_scans_zip_archive(tmp_path: Path) -> None:
    zip_path = tmp_path / "dist.zip"
    with zipfile.ZipFile(zip_path, "w") as zf:
        zf.writestr("module/leak.py", "secret_org_token = 'secret_org_token_xyz'\n")
    count, violations = run_boundary_gate(zip_path, forbidden_terms=["secret_org_token_xyz"])
    assert len(violations) == 1


def test_boundary_gate_scans_nested_archive_in_directory(tmp_path: Path) -> None:
    pkg_dir = tmp_path / "packages"
    pkg_dir.mkdir()
    whl_path = pkg_dir / "my_pkg-0.1.0-py3-none-any.whl"
    with zipfile.ZipFile(whl_path, "w") as zf:
        zf.writestr("my_pkg/secret.py", "INTERNAL_API_KEY = 'super_secret_internal_key_abc'\n")
    count, violations = run_boundary_gate(tmp_path, forbidden_terms=["super_secret_internal_key_abc"])
    assert len(violations) == 1
    assert violations[0]["kind"] == "forbidden_term_leak"
    assert "my_pkg-0.1.0-py3-none-any.whl:my_pkg/secret.py" in violations[0]["location"]




def test_boundary_gate_cli_with_forbidden_flag(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    f = tmp_path / "notes.md"
    f.write_text("Private proprietary asset.\n", encoding="utf-8")
    exit_code = main(["gate", "boundary", str(tmp_path), "--forbidden", "Private proprietary", "--json"])
    assert exit_code == 1
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["status"] == "FAIL"


@pytest.mark.parametrize("json_output", [False, True])
def test_boundary_cli_does_not_log_a_secret_shaped_filename(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], json_output: bool
) -> None:
    secret = "sk-" + "A" * 32
    (tmp_path / (secret + ".py")).write_text("visible forbidden marker\n", encoding="utf-8")
    args = ["gate", "boundary", str(tmp_path), "--forbidden", "forbidden marker"]
    if json_output:
        args.append("--json")
    assert main(args) == 1
    output = capsys.readouterr().out
    assert secret not in output
    assert "FAIL" in output


# ---------------------------------------------------------------------------
# Attest Gate Tests
# ---------------------------------------------------------------------------

def test_attest_gate_creates_valid_receipt() -> None:
    receipt = create_ci_attestation_receipt(
        workflow="repository-check",
        run_id="998877",
        run_number="42",
        job="conformance-gate",
        actor="octocat",
        commit_sha="abcdef1234567890abcdef1234567890abcdef12",
        ref="refs/heads/main",
        event_name="pull_request",
        status="PASS",
    )
    assert receipt["schema_version"] == "verifier-ci-attestation-1"
    assert receipt["receipt_id"] == "ci:998877:conformance-gate"
    assert receipt["status"] == "PASS"
    assert receipt["signer_kind"] == "CANONICAL-SHA256"
    assert receipt["attestation_digest"].startswith("sha256:")
    assert receipt["receipt_digest"].startswith("sha256:")


def test_attest_gate_hmac_signing() -> None:
    receipt = create_ci_attestation_receipt(
        workflow="nightly",
        run_id="12345",
        status="PASS",
        key="secret-signing-key",
    )
    assert receipt["signer_kind"] == "HMAC-SHA256"
    assert len(receipt["signature"]) == 64


def test_attest_gate_cli_writes_output_file(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out_file = tmp_path / "ci_attestation.receipt.json"
    exit_code = main([
        "gate", "attest",
        "--workflow", "test-ci",
        "--run-id", "123",
        "--job", "smoke",
        "--output", str(out_file),
    ])
    assert exit_code == 0
    assert out_file.exists()
    data = json.loads(out_file.read_text(encoding="utf-8"))
    assert data["schema_version"] == "verifier-ci-attestation-1"
    assert data["attestation"]["job"] == "smoke"


def test_attest_gate_verify_canonical_success(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    receipt = create_ci_attestation_receipt(
        workflow="ci", run_id="100", status="PASS"
    )
    valid, reason = verify_ci_attestation_receipt(receipt)
    assert valid is True
    assert reason == "valid"

    receipt_file = tmp_path / "valid_receipt.json"
    receipt_file.write_text(json.dumps(receipt), encoding="utf-8")

    exit_code = main(["gate", "attest", "--verify", str(receipt_file), "--json"])
    assert exit_code == 0
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert payload["valid"] is True

    # Also test formatted output
    exit_code_text = main(["gate", "attest", "--verify", str(receipt_file)])
    assert exit_code_text == 0
    text_captured = capsys.readouterr()
    assert "[PASS] CI attestation receipt verified" in text_captured.out


def test_attest_gate_verify_hmac_success_and_failures(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    secret = "ci-hmac-secret-key-42"
    receipt = create_ci_attestation_receipt(
        workflow="release-ci", run_id="200", status="PASS", key=secret
    )
    receipt_file = tmp_path / "hmac_receipt.json"
    receipt_file.write_text(json.dumps(receipt), encoding="utf-8")

    # Missing key: fails
    exit_code_no_key = main(["gate", "attest", "--verify", str(receipt_file)])
    assert exit_code_no_key == 1
    err_no_key = capsys.readouterr().err
    assert "requires verification key" in err_no_key

    # Wrong key: fails
    exit_code_wrong_key = main(["gate", "attest", "--verify", str(receipt_file), "--key", "wrong-secret"])
    assert exit_code_wrong_key == 1
    err_wrong = capsys.readouterr().err
    assert "signature verification failed" in err_wrong

    # Correct key: passes
    exit_code_ok = main(["gate", "attest", "--verify", str(receipt_file), "--key", secret])
    assert exit_code_ok == 0
    out_ok = capsys.readouterr().out
    assert "[PASS] CI attestation receipt verified" in out_ok


def test_attest_gate_verify_tampered_fails(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    receipt = create_ci_attestation_receipt(
        workflow="ci", run_id="300", status="PASS"
    )
    # Tamper with the inner payload
    receipt["attestation"]["job"] = "tampered-job-name"
    tampered_file = tmp_path / "tampered.json"
    tampered_file.write_text(json.dumps(receipt), encoding="utf-8")

    exit_code = main(["gate", "attest", "--verify", str(tampered_file)])
    assert exit_code == 1
    err = capsys.readouterr().err
    assert "attestation_digest does not match" in err


def test_attest_gate_verify_missing_file_fails(
    capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(["gate", "attest", "--verify", "non_existent_receipt_file_xyz.json"])
    assert exit_code == 1
    err = capsys.readouterr().err
    assert "Receipt file not found" in err
