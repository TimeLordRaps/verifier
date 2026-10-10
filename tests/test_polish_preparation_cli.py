"""Preparation command-line interface (CLI) integration and tutorial controls.

JavaScript Object Notation (JSON); Pull Request Domain Explanation Language
(PRDEL). Passing preparation concerns selected local bytes, not correctness or
publication. Temporary Git commits are fixture artifacts only.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import shutil
import subprocess

import pytest

from verifier.runtime.public_cli import main
from verifier.runtime.polish_workflow import STAGES

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/first_verifiable_software"


def pin(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def invoke(capsys, source: Path, *arguments: str) -> tuple[int, dict]:
    code = main(["polish", "prepare", str(source), *arguments, "--json"])
    captured = capsys.readouterr()
    assert "Traceback" not in captured.out + captured.err
    return code, json.loads(captured.out)


def options(policy: str, output: Path) -> list[str]:
    path = EXAMPLE / policy
    quality = EXAMPLE / "quality-profile.json"
    return [
        "--policy",
        str(path),
        "--policy-digest",
        pin(path),
        "--quality-profile",
        str(quality),
        "--quality-profile-digest",
        pin(quality),
        "--output",
        str(output),
    ]


def git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        capture_output=True,
        text=True,
        timeout=20,
        check=True,
    ).stdout.strip()


def test_existing_report_format_reaches_downstream_and_rejects_stale_bytes(
    tmp_path, capsys
) -> None:
    from verifier.runtime.gates import run_gates

    source = tmp_path / "software"
    source.mkdir()
    (source / "demo.py").write_bytes(b"def increment(value):\n    return value + 1\n")
    code, compatible = invoke(
        capsys, source, "--report-format", "verifier-polish-preparation-1"
    )
    assert code == 0 and compatible["schema_version"] == "verifier-polish-preparation-1"
    accepted = run_gates(source, polish_report_bytes=json.dumps(compatible).encode())
    assert accepted["coverage"]["preparation_status"] == "PASS"
    assert compatible["polished"] is False
    (source / "demo.py").write_bytes(b"def increment(value):\n    return value + 2\n")
    stale = run_gates(source, polish_report_bytes=json.dumps(compatible).encode())
    assert (
        stale["coverage"]["preparation_status"] == "FAIL"
        and stale["clearance"] == "NOT_CLEAR"
    )


def test_report_formats_refuse_mixed_options_before_mutation(tmp_path, capsys) -> None:
    source = tmp_path / "software"
    source.mkdir()
    before = b"def increment(value):\r\n    return value + 1\r\n"
    (source / "demo.py").write_bytes(before)
    code, refused = invoke(
        capsys,
        source,
        "--report-format",
        "verifier-polish-preparation-1",
        "--policy",
        "untrusted.json",
        "--normalize-text",
        "--apply",
    )
    assert code == 1 and refused["reason"] == "INCOMPATIBLE_PREPARATION_OPTIONS"
    code, refused = invoke(
        capsys,
        source,
        "--report-format",
        "verifier-polish-preparation-1",
        "--dry-run",
        "--apply",
        "--normalize-text",
    )
    assert code == 1
    code, refused = invoke(
        capsys,
        source,
        *options("check-policy.json", tmp_path / "retained"),
        "--normalize-text",
        "--apply",
    )
    assert code == 1 and refused["status"] == "FAIL"
    assert (source / "demo.py").read_bytes() == before


def test_existing_report_format_normalizes_only_explicitly_selected_text(
    tmp_path, capsys
) -> None:
    source = tmp_path / "software"
    source.mkdir()
    (source / "demo.py").write_bytes(b"def increment(value):\r\n    return value + 1")
    code, planned = invoke(
        capsys,
        source,
        "--report-format",
        "verifier-polish-preparation-1",
        "--dry-run",
        "--normalize-text",
    )
    assert code == 2 and planned["status"] == "UNKNOWN" and planned["changes"]
    assert b"\r\n" in (source / "demo.py").read_bytes()
    code, applied = invoke(
        capsys,
        source,
        "--report-format",
        "verifier-polish-preparation-1",
        "--normalize-text",
        "--apply",
    )
    assert code == 0 and applied["status"] == "PASS" and applied["polished"] is False
    assert (
        source / "demo.py"
    ).read_bytes() == b"def increment(value):\n    return value + 1\n"


def test_tutorial_failure_fix_resume_apply_repeat_and_later_commit(
    tmp_path, capsys
) -> None:
    source, output = tmp_path / "software", tmp_path / "retained"
    shutil.copytree(EXAMPLE / "source", source)
    (source / "demo.py").write_bytes(
        b"# vstd-explanation: begin orphan\n" + (source / "demo.py").read_bytes()
    )
    before = (source / "demo.py").read_bytes()
    code, failed = invoke(capsys, source, *options("check-policy.json", output))
    assert code == 1 and failed["status"] == "FAIL"
    assert failed["quality"]["stages"][0]["execution_status"] == "EXECUTED"
    assert failed["quality"]["stages"][0]["status"] == "FAIL"
    assert (source / "demo.py").read_bytes() == before and not failed["bundle"]
    failure = tmp_path / "failed.json"
    failure.write_text(json.dumps(failed), encoding="utf-8")
    (source / "demo.py").write_bytes(b"def increment(value):\n    return value + 1\n")
    code, fixed = invoke(
        capsys, source, *options("check-policy.json", output), "--resume", str(failure)
    )
    assert code == 0 and fixed["status"] == "PASS"
    assert (
        fixed["resume"]["invalidated_stages"] and not fixed["resume"]["reused_stages"]
    )
    assert failure.read_text(encoding="utf-8") == json.dumps(failed)
    assert list((output / "attempts").glob("*.json"))
    git(source, "init", "--quiet")
    git(source, "config", "user.name", "Fixture")
    git(source, "config", "user.email", "fixture" + "@" + "example.invalid")
    git(source, "config", "commit.gpgsign", "false")
    git(source, "config", "core.autocrlf", "false")
    git(source, "add", ".")
    git(source, "commit", "--quiet", "-m", "retain original fixture")
    base = git(source, "rev-parse", "HEAD")
    authored = [
        "--definition",
        str(EXAMPLE / "definitions.json"),
        "--git-root",
        str(source),
        "--base",
        base,
        "--commit",
        base,
    ]
    code, staged = invoke(
        capsys, source, *options("apply-policy.json", output), *authored
    )
    assert code == 0 and staged["state"] == "PREPARED_PENDING_COMMIT"
    assert b"vstd-explanation" not in (source / "demo.py").read_bytes()
    code, applied = invoke(
        capsys, source, *options("apply-policy.json", output), *authored, "--apply"
    )
    assert code == 0 and applied["evidence_invalidated"]
    final = (source / "demo.py").read_bytes()
    assert final.count(b"# vstd-explanation: begin example.increment") == 1
    assert not applied["polished"] and not applied["promotable"]
    code, repeated = invoke(
        capsys,
        source,
        *options("apply-policy.json", output),
        "--definition",
        str(EXAMPLE / "definitions.json"),
        "--apply",
    )
    assert code == 0 and (source / "demo.py").read_bytes() == final
    bundle = Path(applied["bundle"]["path"])
    manifest_before = (bundle / "manifest.json").read_bytes()
    assert (bundle / "description.prepared.md").is_file()
    assert b"not verified" in (bundle / "description.prepared.md").read_bytes()
    git(source, "add", ".")
    git(source, "commit", "--quiet", "-m", "retain prepared fixture")
    head = git(source, "rev-parse", "HEAD")
    code, association = invoke(
        capsys, source, "--associate", str(bundle / "manifest.json"), "--commit", head
    )
    assert code == 0 and association["status"] == "PASS"
    assert (bundle / "manifest.json").read_bytes() == manifest_before
    (source / "demo.py").write_bytes(final + b"# later handwritten edit\n")
    code, recovery = invoke(
        capsys, source, "--recover", applied["apply_plan"], "--rollback"
    )
    assert code == 1 and recovery["status"] == "FAIL"
    assert (source / "demo.py").read_bytes().endswith(b"# later handwritten edit\n")


@pytest.mark.parametrize(
    "arguments", [[], ["--rollback"], ["--apply"], ["--associate", "missing.json"]]
)
def test_preparation_missing_and_conflicting_selectors_are_failures(
    tmp_path, capsys, arguments
) -> None:
    code, report = invoke(capsys, tmp_path, *arguments)
    assert code == 1 and report["status"] == "FAIL"
    assert not report["polished"] and not report["promotable"]


def test_preparation_help_and_tutorial_use_actual_stage_catalogue(capsys) -> None:
    with pytest.raises(SystemExit) as raised:
        main(["polish", "prepare", "--help"])
    assert raised.value.code == 0
    help_text = capsys.readouterr().out
    tutorial = (ROOT / "docs/tutorials/YOUR_FIRST_VERIFIABLE_SOFTWARE.md").read_text(
        encoding="utf-8"
    )
    for stage in STAGES:
        assert stage["id"] in help_text and stage["id"] in tutorial
    for route in ("catalog", "assess", "coverage", "check"):
        with pytest.raises(SystemExit) as raised:
            main(["polish", route, "--help"])
        assert raised.value.code == 0
        capsys.readouterr()


def test_source_bound_compilation_does_not_claim_runtime_clearance(
    tmp_path, capsys
) -> None:
    source = tmp_path / "repository"
    source.mkdir()
    (source / "README.md").write_text("A bounded example.\n", encoding="utf-8")
    git(source, "init", "--quiet")
    git(source, "config", "user.name", "Fixture")
    git(source, "config", "user.email", "fixture" + "@" + "example.invalid")
    git(source, "config", "commit.gpgsign", "false")
    git(source, "config", "core.autocrlf", "false")
    git(source, "add", ".")
    git(source, "commit", "--quiet", "-m", "baseline")
    base = git(source, "rev-parse", "HEAD")
    (source / "README.md").write_text("A bounded retained example.\n", encoding="utf-8")
    git(source, "add", ".")
    git(source, "commit", "--quiet", "-m", "edit")
    head = git(source, "rev-parse", "HEAD")
    policy = json.loads((EXAMPLE / "check-policy.json").read_bytes())
    policy["input_paths"] = ["README.md"]
    for row in policy["stages"]:
        row["selected"] = row["required"] = row["id"] in {
            "bind-inputs",
            "validate-definitions",
            "compile-explanations",
            "retain-bundle",
        }
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy), encoding="utf-8")
    code, report = invoke(
        capsys,
        source,
        "--policy",
        str(path),
        "--policy-digest",
        pin(path),
        "--git-root",
        str(source),
        "--base",
        base,
        "--commit",
        head,
        "--output",
        str(tmp_path / "output"),
    )
    assert code == 0 and report["verification"]["status"] == "PASS"
    assert report["verification"]["verdict_scope"] == "GATE_OBLIGATION_FULFILLMENT"
    assert not report["polished"] and not report["promotable"]
    description = Path(report["bundle"]["path"]) / "description.committed.pr.md"
    assert description.is_file()
    assert (
        main(
            [
                "gate",
                "pr",
                "--contract",
                "verifier-prdel-1",
                "--root",
                str(source),
                "--base",
                base,
                "--commit",
                head,
                "--file",
                str(description),
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["report"]["status"] == "PASS"
