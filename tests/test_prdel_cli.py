# Terminology: Verifier Standard (VSTD).
"""pull request (PR); Pull Request Domain Explanation Language (PRDEL) controls.

The command-line interface (CLI) must separate bounded validation from generation
and rendering, retain exact source bindings and refuse metadata-only clearance.
JavaScript Object Notation (JSON) inputs are data; candidate Python is not executed.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess

import pytest
import test_prdel_shards as shard_helpers

from scripts import check_pr_description as pr_description_script
from verifier.runtime import gate as _shard_budget_gate
from verifier.runtime.public_cli import main

ROOT = Path(__file__).resolve().parents[1]


def git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        capture_output=True,
        text=True,
        check=True,
        timeout=20,
    ).stdout.strip()


@pytest.fixture
def repository(tmp_path: Path) -> tuple[Path, str, str]:
    root = tmp_path / "repository"
    root.mkdir()
    git(root, "init", "--quiet")
    git(root, "config", "user.name", "Fixture")
    git(root, "config", "user.email", "fixture" + "@" + "example.invalid")
    git(root, "config", "commit.gpgsign", "false")
    (root / "README.md").write_text("A retained example.\n", encoding="utf-8")
    (root / "candidate.py").write_text(
        "raise RuntimeError('candidate source must remain data')\n", encoding="utf-8"
    )
    git(root, "add", ".")
    git(root, "commit", "--quiet", "-m", "baseline")
    base = git(root, "rev-parse", "HEAD")
    (root / "README.md").write_text("A retained bounded example.\n", encoding="utf-8")
    git(root, "add", ".")
    git(root, "commit", "--quiet", "-m", "explain example boundary")
    return root, base, git(root, "rev-parse", "HEAD")


def invoke(capsys: pytest.CaptureFixture[str], *arguments: str) -> tuple[int, dict]:
    result = main(["gate", "pr", "--contract", "verifier-prdel-1", *arguments, "--json"])
    captured = capsys.readouterr()
    assert "Traceback" not in captured.out + captured.err
    return result, json.loads(captured.out)


def options(repository: tuple[Path, str, str]) -> list[str]:
    root, base, head = repository
    return ["--root", str(root), "--base", base, "--commit", head]


def store(tmp_path: Path, document: dict, name: str = "description.json") -> Path:
    path = tmp_path / name
    path.write_text(
        json.dumps(document, indent=2) + "\n", encoding="utf-8", newline="\n"
    )
    return path


def fill(document: dict) -> dict:
    """Use only the engine's supported predicates, not arbitrary assurance prose."""
    from verifier.runtime.prdel import claim_text

    selected = copy.deepcopy(document)
    requirement = selected["requirements"]["items"][0]
    obligations = {row["id"]: row for row in selected["source_obligations"]}
    for record in selected["records"]:
        record["requirement_ids"] = [requirement["id"]]
        record["why"] = {
            "requirement_id": requirement["id"],
            "quote": requirement["text"],
        }
        obligation = obligations[record["id"]]
        record["claims"] = (
            [{"kind": "source_delta", "obligation_id": record["id"]}]
            if obligation["kind"] == "source"
            else []
        )
        record["claims"].append(
            {
                "kind": "requirement_quote",
                "requirement_id": requirement["id"],
                "quote": requirement["text"],
            }
        )
        record["summary"] = "\n".join(
            claim_text(claim, selected) for claim in record["claims"]
        )
        record["limits"] = [
            "NO_RUNTIME_CORRECTNESS",
            "NO_EXECUTION_PROVENANCE",
            "NO_REQUIREMENT_AUTHORITY",
            "NO_COMPLETE_OBJECTIVE_CLOSURE",
            "EXACT_COMMIT_SCOPE",
        ]
    return selected


def generated(repository: tuple[Path, str, str]) -> dict:
    from verifier.runtime.prdel import generate_prdel

    return generate_prdel(repository[0], repository[1], repository[2])


def test_help_exposes_existing_route_tool_modes_and_validation_codes(capsys) -> None:
    with pytest.raises(SystemExit) as result:
        main(["gate", "pr", "--help"])
    assert result.value.code == 0
    text = capsys.readouterr().out
    for flag in (
        "--generate",
        "--document",
        "--render",
        "--impact-dag",
        "--requirements-digest",
        "--evidence-digest",
    ):
        assert flag in text
    assert "UNKNOWN" in text and "do not grant clearance" in " ".join(text.split())


def test_manual_template_generation_success_is_not_validation_clearance(
    repository, capsys, tmp_path
) -> None:
    result, document = invoke(capsys, *options(repository), "--generate", "--template")
    assert result == 0 and document["schema_version"] == "verifier-prdel-1"
    assert document["binding"]["base"] == repository[1]
    assert document["binding"]["head"] == repository[2]
    assert document["source_obligations"]
    result, report = invoke(
        capsys, *options(repository), "--document", str(store(tmp_path, document))
    )
    assert result == 1 and report["status"] == "FAIL"
    assert report["report"]["findings"]


def test_automatic_source_rules_have_a_bounded_positive(
    repository, capsys, tmp_path
) -> None:
    result, document = invoke(capsys, *options(repository), "--generate")
    assert result == 0 and document["schema_version"] == "verifier-prdel-1"
    assert all(row["claims"] and row["summary"] for row in document["records"])
    result, report = invoke(
        capsys, *options(repository), "--document", str(store(tmp_path, document))
    )
    assert result == 0 and report["status"] == "PASS"
    assert report["report"]["verdict_scope"] == "GATE_OBLIGATION_FULFILLMENT"


def test_compilation_mode_retains_rules_and_authored_unknowns(
    repository, capsys, tmp_path
) -> None:
    result, envelope = invoke(
        capsys, *options(repository), "--generate", "--compilation"
    )
    assert result == 0 and envelope["schema_version"] == "verifier-prdel-compilation-1"
    assert envelope["gate_status"] == "NOT_ASSESSED"
    assert envelope["rule_results"] and envelope["rule_catalogue"]
    assert any(
        row["code"] == "AUTHOR_MOTIVATION_UNRESOLVED" and not row["required"]
        for row in envelope["residuals"]
    )
    result, report = invoke(
        capsys, *options(repository), "--document", str(store(tmp_path, envelope))
    )
    assert result == 0 and report["report"]["compilation_replay"]["status"] == "PASS"
    envelope["rule_results"][0]["rule_version"] = "unadmitted"
    result, report = invoke(
        capsys, *options(repository), "--document", str(store(tmp_path, envelope))
    )
    assert result == 1 and report["status"] == "FAIL"
    assert any(
        row["category"] == "COMPILATION_REPLAY" for row in report["report"]["findings"]
    )


@pytest.mark.parametrize(
    "arguments",
    [
        ["--template"],
        ["--compilation"],
        ["--generate", "--template", "--compilation"],
    ],
)
def test_authoring_selector_conflicts_fail_closed(
    repository, capsys, arguments
) -> None:
    result, report = invoke(capsys, *options(repository), *arguments)
    assert result == 1 and report["status"] == "FAIL"


def test_validation_wrapper_has_distinct_packaged_schema(
    repository, capsys, tmp_path
) -> None:
    from importlib.resources import files
    from jsonschema import Draft202012Validator

    path = store(tmp_path, fill(generated(repository)))
    result, wrapper = invoke(capsys, *options(repository), "--document", str(path))
    assert result == 0 and wrapper["schema_version"] == "verifier-prdel-cli-1"
    assert wrapper["report"]["schema_version"] == "verifier-prdel-report-1"
    schema = json.loads(
        files("verifier")
        .joinpath("schemas/verifier-prdel-cli-1.schema.json")
        .read_text(encoding="utf-8")
    )
    Draft202012Validator(schema).validate(wrapper)


def test_filled_bounded_source_predicates_have_a_legitimate_positive(
    repository, capsys, tmp_path
) -> None:
    document = fill(generated(repository))
    result, report = invoke(
        capsys, *options(repository), "--document", str(store(tmp_path, document))
    )
    assert result == 0 and report["status"] == "PASS"
    assert report["report"]["source_grounding_status"] == "PASS"
    assert "runtime" in report["report"]["claim_boundary"].lower()


@pytest.mark.parametrize(
    "prose",
    [
        "A short summary without source representation.",
        (
            "All 234 tier certifications are complete; model "
            "correctness and overall safety are established."
        ),
        "The current requirements use 1..8.m across every kind; all work is complete.",
    ],
)
def test_plaintext_metadata_cannot_clear_substantive_gate(
    repository, capsys, prose
) -> None:
    text = f"Coordinate: bounded fixture\nCurrent signed head: {repository[2]}\n{prose}"
    result, report = invoke(capsys, *options(repository), "--text", text)
    assert result == 1 and report["status"] == "FAIL"
    assert report["report"]["findings"]


def test_irrelevant_summary_cannot_borrow_valid_source_ids(
    repository, capsys, tmp_path
) -> None:
    document = fill(generated(repository))
    document["records"][0]["summary"] = "The unrelated weather forecast is sunny."
    result, report = invoke(
        capsys, *options(repository), "--document", str(store(tmp_path, document))
    )
    assert result == 1 and report["status"] == "FAIL"
    assert any(
        row["code"] == "SUMMARY_RENDERING_MISMATCH"
        for row in report["report"]["findings"]
    )


def test_complete_description_with_unsupported_extra_prose_remains_unknown(
    repository, capsys, tmp_path
) -> None:
    from verifier.runtime.prdel import render_prdel

    document = fill(generated(repository))
    text = (
        render_prdel(document)
        + "\nA separate interpretation still needs a supported predicate.\n"
    )
    result, wrapper = invoke(
        capsys,
        *options(repository),
        "--document",
        str(store(tmp_path, document)),
        "--text",
        text,
    )
    assert result == 2 and wrapper["status"] == "UNKNOWN"
    assert any(
        row["code"] == "UNSUPPORTED_NARRATIVE" for row in wrapper["report"]["findings"]
    )
    assert not any(row["status"] == "FAIL" for row in wrapper["report"]["findings"])


def test_required_unrun_runtime_checks_fail_and_remain_visible(
    repository, capsys, tmp_path
) -> None:
    root, base, _ = repository
    (root / "feature.py").write_text(
        "def plus_one(value):\n    return value + 1\n", encoding="utf-8"
    )
    git(root, "add", ".")
    git(root, "commit", "--quiet", "-m", "bounded function fixture")
    selected = (root, base, git(root, "rev-parse", "HEAD"))
    document = fill(generated(selected))
    for record in document["records"]:
        record["coverage"] = {
            layer: {
                "status": "NOT_RUN",
                "evidence_ids": [],
                "reason": "Required fixture check not run.",
            }
            for layer in ("unit", "integration", "regression", "preventative")
        }
    result, wrapper = invoke(
        capsys, *options(selected), "--document", str(store(tmp_path, document))
    )
    report = wrapper["report"]
    assert result == 1 and report["status"] == "FAIL"
    assert report["verdict_scope"] == "GATE_OBLIGATION_FULFILLMENT"
    assert report["proposition_truth"] == "NOT_INFERRED_FROM_MISSING_EVIDENCE"
    assert report["required_checks_not_run"] > 0
    assert report["coverage"]["layers"]["base"]["verdict"] == "PASS"
    for layer in ("unit", "integration", "regression", "preventative"):
        assert report["coverage"]["layers"][layer]["verdict"] == "FAIL"
        assert report["coverage"]["layers"][layer]["execution_status"] == "NOT_RUN"
        assert any(
            row["execution_status"] == "NOT_RUN"
            for row in report["coverage"]["layers"][layer]["obligations"]
        )


def test_complete_document_with_unavailable_source_is_unknown(
    repository, capsys, tmp_path
) -> None:
    document = fill(generated(repository))
    root = tmp_path / "unavailable-source"
    root.mkdir()
    result, wrapper = invoke(
        capsys,
        "--root",
        str(root),
        "--base",
        repository[1],
        "--commit",
        repository[2],
        "--document",
        str(store(tmp_path, document)),
    )
    assert result == 2 and wrapper["status"] == "UNKNOWN"
    assert any(
        row["code"] == "SOURCE_UNAVAILABLE" for row in wrapper["report"]["findings"]
    )
    assert not any(row["status"] == "FAIL" for row in wrapper["report"]["findings"])


def test_missing_changed_region_surfaces_actionable_residual(
    repository, capsys, tmp_path
) -> None:
    document = fill(generated(repository))
    document["records"] = []
    result, report = invoke(
        capsys, *options(repository), "--document", str(store(tmp_path, document))
    )
    assert result == 1 and report["status"] == "FAIL"
    assert any(
        row.get("obligation_id") and row.get("question")
        for row in report["report"]["findings"]
    )


def test_wrong_head_binding_is_refuted(repository, capsys, tmp_path) -> None:
    document = fill(generated(repository))
    document["binding"]["head"] = "0" * 40
    result, report = invoke(
        capsys, *options(repository), "--document", str(store(tmp_path, document))
    )
    assert result == 1 and report["status"] == "FAIL"


def test_fetched_exact_head_can_be_reviewed_without_checkout(
    repository, capsys, tmp_path
) -> None:
    document = fill(generated(repository))
    path = store(tmp_path, document)
    git(repository[0], "checkout", "--quiet", "--detach", repository[1])
    assert git(repository[0], "rev-parse", "HEAD") != repository[2]
    result, report = invoke(capsys, *options(repository), "--document", str(path))
    assert result == 0 and report["status"] == "PASS"


def test_false_current_head_metadata_cannot_hide_in_valid_document(
    repository, capsys, tmp_path
) -> None:
    from verifier.runtime.prdel import render_prdel

    document = fill(generated(repository))
    text = render_prdel(document).replace(
        f"Current head: `{repository[2]}`", f"Current head: `{repository[1]}`", 1
    )
    result, report = invoke(
        capsys,
        *options(repository),
        "--document",
        str(store(tmp_path, document)),
        "--text",
        text,
    )
    assert result == 1 and report["status"] == "FAIL"
    assert report["report"]["metadata_findings"]
    assert (
        report["report"]["source_grounding_status"]
        == report["report"]["semantic_status"]
        == "FAIL"
    )


def test_external_requirements_need_explicit_matching_bytes_and_digest(
    repository, capsys, tmp_path
) -> None:
    raw = json.dumps(
        {
            "schema_version": "verifier-prdel-requirements-1",
            "items": [
                {
                    "id": "selected-boundary",
                    ("text"): (
                        "Represent exact retained regions without "
                        "claiming complete runtime correctness."
                    ),
                }
            ],
        }
    ).encode("utf-8")
    path = tmp_path / "requirements.json"
    path.write_bytes(raw)
    selected = [
        "--requirements",
        str(path),
        "--requirements-digest",
        hashlib.sha256(raw).hexdigest(),
    ]
    result, report = invoke(
        capsys, *options(repository), "--generate", "--requirements", str(path)
    )
    assert result == 1 and report["status"] == "FAIL"
    result, document = invoke(capsys, *options(repository), "--generate", *selected)
    assert result == 0
    description = store(tmp_path, fill(document))
    result, report = invoke(
        capsys, *options(repository), "--document", str(description), *selected
    )
    assert result == 0 and report["status"] == "PASS"
    result, report = invoke(
        capsys, *options(repository), "--document", str(description)
    )
    assert result == 1 and report["status"] == "FAIL"


def test_external_evidence_is_bound_without_becoming_execution_proof(
    repository, capsys, tmp_path
) -> None:
    document = fill(generated(repository))
    description = store(tmp_path, document)
    raw = json.dumps(
        {
            "schema_version": "verifier-prdel-evidence-1",
            "binding": document["binding"],
            "evidence": [],
        }
    ).encode("utf-8")
    evidence = tmp_path / "evidence.json"
    evidence.write_bytes(raw)
    result, report = invoke(
        capsys,
        *options(repository),
        "--document",
        str(description),
        "--evidence",
        str(evidence),
    )
    assert result == 1 and report["status"] == "FAIL"
    result, report = invoke(
        capsys,
        *options(repository),
        "--document",
        str(description),
        "--evidence",
        str(evidence),
        "--evidence-digest",
        hashlib.sha256(raw).hexdigest(),
    )
    assert result == 0 and report["status"] == "PASS"
    assert "execution provenance" in report["report"]["claim_boundary"]


@pytest.mark.parametrize(
    "payload", [b"not json", b'{"schema_version":1,"schema_version":2}', b"\xff"]
)
def test_malformed_document_has_machine_readable_failure(
    repository, capsys, tmp_path, payload
) -> None:
    path = tmp_path / "invalid.json"
    path.write_bytes(payload)
    result, report = invoke(capsys, *options(repository), "--document", str(path))
    assert result == 1 and report["status"] == "FAIL"
    assert report["report"]["findings"][0]["category"] == "INVALID_INPUT"


def test_missing_file_and_bad_git_revision_do_not_traceback(
    repository, capsys, tmp_path
) -> None:
    result, report = invoke(
        capsys, *options(repository), "--file", str(tmp_path / "absent.md")
    )
    assert result == 1 and report["status"] == "FAIL"
    result, report = invoke(
        capsys, "--generate", "--root", str(repository[0]), "--base", "not-a-revision",
        "--commit", repository[2]
    )
    assert result == 2 and report["status"] == "UNKNOWN"


@pytest.mark.parametrize("flag", ["--file", "--document"])
def test_unreadable_cli_input_is_unknown_while_confirmed_missing_is_fail(
    repository, capsys, tmp_path, monkeypatch, flag
) -> None:
    path = store(tmp_path, fill(generated(repository)))
    original = Path.open

    def denied(selected, *arguments, **keywords):
        if selected == path:
            raise PermissionError("Fixture selected input is unreadable")
        return original(selected, *arguments, **keywords)

    monkeypatch.setattr(Path, "open", denied)
    result, report = invoke(capsys, *options(repository), flag, str(path))
    assert result == 2 and report["status"] == "UNKNOWN"
    assert report["report"]["findings"][0]["code"] == "UNAVAILABLE_INPUT"
    result, report = invoke(
        capsys, *options(repository), flag, str(tmp_path / "absent.json")
    )
    assert result == 1 and report["status"] == "FAIL"


@pytest.mark.parametrize("complete,expected", [(False, 1), (True, 2)])
def test_unwritable_output_preserves_established_obligation_failure(
    repository, capsys, tmp_path, monkeypatch, complete, expected
) -> None:
    document = generated(repository)
    path = store(tmp_path, fill(document) if complete else document)
    destination = tmp_path / "unwritable-report.json"
    original = Path.open

    def denied(selected, *arguments, **keywords):
        if selected == destination:
            raise PermissionError("Fixture destination is unwritable")
        return original(selected, *arguments, **keywords)

    monkeypatch.setattr(Path, "open", denied)
    result, wrapper = invoke(
        capsys,
        *options(repository),
        "--document",
        str(path),
        "--output",
        str(destination),
    )
    assert result == expected
    assert any(
        row["code"] == "UNAVAILABLE_INPUT" and row["status"] == "UNKNOWN"
        for row in wrapper["report"]["findings"]
    )
    assert wrapper["status"] == ("UNKNOWN" if complete else "FAIL")
    if not complete:
        assert any(row["status"] == "FAIL" for row in wrapper["report"]["findings"])


def test_render_and_impact_are_usable_without_claiming_clearance(
    repository, capsys, tmp_path
) -> None:
    path = store(tmp_path, generated(repository))
    for flag, marker in (("--render", "UNRESOLVED"), ("--impact-dag", "flowchart")):
        assert (
            main(["gate", "pr", *options(repository), "--document", str(path), flag])
            == 0
        )
        output = capsys.readouterr().out
        assert marker in output


def test_rendered_document_roundtrips_through_file_gate(
    repository, capsys, tmp_path
) -> None:
    path = store(tmp_path, fill(generated(repository)))
    output = tmp_path / "description.md"
    assert (
        main(
            [
                "gate",
                "pr",
                *options(repository),
                "--document",
                str(path),
                "--render",
                "--output",
                str(output),
            ]
        )
        == 0
    )
    assert capsys.readouterr().out == ""
    result, report = invoke(capsys, *options(repository), "--file", str(output))
    assert result == 0 and report["status"] == "PASS"


def test_json_render_keeps_tool_result_separate_from_clearance(
    repository, capsys, tmp_path
) -> None:
    path = store(tmp_path, generated(repository))
    result, rendered = invoke(
        capsys, *options(repository), "--document", str(path), "--render"
    )
    assert result == 0 and rendered["schema_version"] == "verifier-prdel-render-1"
    assert rendered["report"]["status"] == "FAIL"
    assert "```vstd-prdel" in rendered["rendered"]


def test_output_uses_lf_and_does_not_leak_to_stdout(
    repository, capsys, tmp_path
) -> None:
    target = tmp_path / "template.json"
    assert (
        main(
            ["gate", "pr", *options(repository), "--generate", "--output", str(target)]
        )
        == 0
    )
    assert capsys.readouterr().out == ""
    raw = target.read_bytes()
    assert b"\r\n" not in raw and json.loads(raw)["binding"]["head"] == repository[2]


def modern_script(script, arguments):
    """Select modern behavior explicitly; event coordinates come from event data."""
    return script.main(["--contract", "verifier-prdel-1", *arguments])


def unavailable_coordinates():
    """Explicit fake object identifiers for diagnostic-priority controls only.

    These are not qualification evidence. Their absent local snapshots remain
    UNKNOWN while separately readable missing/malformed inputs retain FAIL.
    """
    return ["--base", "0" * 40, "--head", "1" * 40]


def load_script():
    assert Path(pr_description_script.__file__).resolve() == (
        ROOT / "scripts/check_pr_description.py"
    )
    return pr_description_script


def test_script_uses_same_engine_for_new_document_without_old_manifest(
    repository, capsys, tmp_path, monkeypatch
) -> None:
    script = load_script()
    monkeypatch.setattr(script, "ROOT", repository[0])
    monkeypatch.setattr(script, "SOURCE", repository[0] / "src")
    path = store(tmp_path, fill(generated(repository)))
    assert (
        modern_script(script, 
            [
                "--base",
                repository[1],
                "--commit",
                repository[2],
                "--document",
                str(path),
                "--json",
            ]
        )
        == 0
    )
    report = json.loads(capsys.readouterr().out)
    assert (
        report["status"] == "PASS"
        and report["schema_version"] == "verifier-prdel-report-1"
    )


def test_script_confirmed_invalid_document_is_fail_not_unavailable(
    tmp_path, capsys
) -> None:
    script = load_script()
    path = store(tmp_path, {"schema_version": "forged"})
    assert modern_script(script, [*unavailable_coordinates(), "--document", str(path), "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["status"] == report["semantic_status"] == "FAIL"
    assert report["findings"][0]["code"] == "INVALID_INPUT"


@pytest.mark.parametrize("require_pr", [False, True])
def test_confirmed_absent_attached_pr_fails_required_description(
    capsys, monkeypatch, require_pr
) -> None:
    script = load_script()
    monkeypatch.setattr(
        script.subprocess,
        "run",
        lambda command, **kwargs: subprocess.CompletedProcess(
            command, 1, "", "no pull requests found for branch fixture"
        ),
    )
    arguments = [*unavailable_coordinates(), "--json"] + (["--require-pull-request"] if require_pr else [])
    assert modern_script(script, arguments) == 1
    report = json.loads(capsys.readouterr().out)
    assert (
        report["status"] == "FAIL"
        and report["findings"][0]["code"] == "MISSING_REQUIRED_DESCRIPTION"
    )
    assert report["proposition_truth"] == "NOT_INFERRED_FROM_MISSING_EVIDENCE"


@pytest.mark.parametrize(
    "fault",
    [
        "no default remote",
        "authentication failed",
        "network unavailable",
        "missing-tool",
    ],
)
def test_unavailable_pr_query_does_not_infer_absence(
    capsys, monkeypatch, fault
) -> None:
    script = load_script()

    def query(command, **kwargs):
        if fault == "missing-tool":
            raise FileNotFoundError("tool unavailable")
        return subprocess.CompletedProcess(command, 1, "", fault)

    monkeypatch.setattr(script.subprocess, "run", query)
    assert modern_script(script, [*unavailable_coordinates(), "--json", "--require-pull-request"]) == 2
    report = json.loads(capsys.readouterr().out)
    assert (
        report["status"] == "UNKNOWN"
        and report["findings"][0]["code"] == "UNAVAILABLE_INPUT"
    )


def test_missing_selected_body_fails_but_unreadable_body_is_unknown(
    tmp_path, capsys, monkeypatch
) -> None:
    script = load_script()
    path = tmp_path / "description.md"
    assert modern_script(script, [*unavailable_coordinates(), "--body", str(path), "--json"]) == 1
    assert (
        json.loads(capsys.readouterr().out)["findings"][0]["code"]
        == "MISSING_REQUIRED_DESCRIPTION"
    )
    path.write_text("retained text", encoding="utf-8")

    def denied(selected):
        raise PermissionError("Selected body is unreadable")

    monkeypatch.setattr(script, "_bounded_input", denied)
    assert modern_script(script, [*unavailable_coordinates(), "--body", str(path), "--json"]) == 2
    assert json.loads(capsys.readouterr().out)["status"] == "UNKNOWN"


@pytest.mark.parametrize("flag", ["--document", "--requirements", "--evidence"])
def test_confirmed_missing_selected_script_inputs_fail(tmp_path, capsys, flag) -> None:
    script = load_script()
    # Supply the required selector pair so this control reaches confirmed file
    # absence. This placeholder is not a digest of execution or available bytes.
    selected = [flag, str(tmp_path / "absent.json")]
    if flag in {"--requirements", "--evidence"}:
        selected += [flag + "-digest", "sha256:" + "0" * 64]
    assert modern_script(script, [*unavailable_coordinates(), *selected, "--json"]) == 1
    report = json.loads(capsys.readouterr().out)
    assert (
        report["status"] == "FAIL"
        and report["findings"][0]["code"] == "MISSING_REQUIRED_INPUT"
    )
    assert report["findings"][0]["execution_status"] == "NOT_RUN"
    assert report["required_checks_not_run"] == 1


def test_confirmed_missing_protected_event_file_fails(tmp_path, capsys) -> None:
    script = load_script()
    assert (
        modern_script(script, 
            [
                "--repo",
                "Owner/repository",
                "--commit",
                "a" * 40,
                "--event",
                str(tmp_path / "absent-event.json"),
                "--json",
            ]
        )
        == 1
    )
    report = json.loads(capsys.readouterr().out)
    assert (
        report["status"] == "FAIL"
        and report["findings"][0]["code"] == "MISSING_REQUIRED_INPUT"
    )


@pytest.mark.parametrize(
    "quotation",
    [
        "Historical thirteen domain adapters. Current head: " + "f" * 40,
        "Historical fenced format identifier: ```vstd-source-features",
        "Historical format identifier: ```vstd-prdel",
    ],
)
def test_retained_source_quotes_do_not_become_current_metadata_assertions(
    repository, capsys, tmp_path, monkeypatch, quotation
) -> None:
    from verifier.runtime.prdel import render_prdel

    root, base, _ = repository
    (root / "README.md").write_text(quotation + "\n", encoding="utf-8")
    git(root, "add", ".")
    git(root, "commit", "-qm", "Retained quotation")
    selected = (root, base, git(root, "rev-parse", "HEAD"))
    document = fill(generated(selected))
    path = store(tmp_path, document)
    result, wrapper = invoke(capsys, *options(selected), "--document", str(path))
    assert result == 0 and wrapper["status"] == "PASS"
    script = load_script()
    monkeypatch.setattr(script, "ROOT", root)
    monkeypatch.setattr(script, "SOURCE", root / "src")
    assert (
        modern_script(script, 
            [
                "--base",
                selected[1],
                "--commit",
                selected[2],
                "--document",
                str(path),
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["status"] == "PASS"
    event = {
        "repository": {"full_name": "Owner/repository"},
        "pull_request": {
            "base": {"sha": selected[1]},
            "head": {"sha": selected[2]},
            "body": render_prdel(document),
        },
    }
    event_path = store(tmp_path, event, "quote-event.json")
    assert (
        modern_script(script, 
            [
                "--repo",
                "Owner/repository",
                "--commit",
                selected[2],
                "--event",
                str(event_path),
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["status"] == "PASS"


def test_protected_event_parity_never_imports_candidate_python(
    repository, capsys, tmp_path, monkeypatch
) -> None:
    from verifier.runtime.prdel import render_prdel

    script = load_script()
    monkeypatch.setattr(script, "ROOT", repository[0])
    # The selected candidate.py contains a top-level exception. Successful
    # protected evaluation must parse selected candidate bytes without executing.
    document = fill(generated(repository))
    event = {
        "repository": {"full_name": "Owner/repository"},
        "pull_request": {
            "base": {"sha": repository[1]},
            "head": {"sha": repository[2]},
            "body": render_prdel(document),
        },
    }
    path = store(tmp_path, event, "event.json")
    assert (
        modern_script(script, 
            [
                "--repo",
                "Owner/repository",
                "--commit",
                repository[2],
                "--event",
                str(path),
                "--json",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["status"] == "PASS"


def test_protected_unavailable_candidate_objects_remain_unknown(
    repository, capsys, tmp_path, monkeypatch
) -> None:
    from verifier.runtime.prdel import render_prdel

    script = load_script()
    unavailable_root = tmp_path / "unavailable-source"
    unavailable_root.mkdir()
    monkeypatch.setattr(script, "ROOT", unavailable_root)
    head = repository[2]
    event = {
        "repository": {"full_name": "Owner/repository"},
        "pull_request": {
            "base": {"sha": repository[1]},
            "head": {"sha": head},
            "body": render_prdel(fill(generated(repository))),
        },
    }
    path = store(tmp_path, event, "unavailable-event.json")
    assert (
        modern_script(script, 
            [
                "--repo",
                "Owner/repository",
                "--commit",
                head,
                "--event",
                str(path),
                "--json",
            ]
        )
        == 2
    )
    report = json.loads(capsys.readouterr().out)
    assert (
        report["status"] == "UNKNOWN"
        and report["findings"][0]["category"] == "SOURCE_UNAVAILABLE"
    )


def test_protected_missing_representation_is_fail_even_if_source_unavailable(
    repository, capsys, tmp_path, monkeypatch
) -> None:
    script = load_script()
    unavailable_root = tmp_path / "unavailable-source"
    unavailable_root.mkdir()
    monkeypatch.setattr(script, "ROOT", unavailable_root)
    event = {
        "repository": {"full_name": "Owner/repository"},
        "pull_request": {
            "base": {"sha": repository[1]},
            "head": {"sha": repository[2]},
            "body": f"Current head: {repository[2]}",
        },
    }
    path = store(tmp_path, event, "known-missing-event.json")
    assert (
        modern_script(script, 
            [
                "--repo",
                "Owner/repository",
                "--commit",
                repository[2],
                "--event",
                str(path),
                "--json",
            ]
        )
        == 1
    )
    report = json.loads(capsys.readouterr().out)
    assert any(
        row["code"] == "PRDEL_REPRESENTATION_MISSING" and row["status"] == "FAIL"
        for row in report["findings"]
    )
    assert any(
        row["code"] == "SOURCE_UNAVAILABLE" and row["status"] == "UNKNOWN"
        for row in report["findings"]
    )


def test_unavailable_platform_inventory_cannot_erase_known_missing_representation(
    repository, capsys, tmp_path, monkeypatch
) -> None:
    script = load_script()
    monkeypatch.setattr(script, "ROOT", repository[0])

    def unavailable(*arguments):
        raise script.Unanswered("Platform tree is unavailable")

    monkeypatch.setattr(script, "tracked_files", unavailable)
    event = {
        "repository": {"full_name": "Owner/repository"},
        "pull_request": {
            "base": {"sha": repository[1]},
            "head": {"sha": repository[2]},
            "body": f"Current head: {repository[2]}\ntracked inventory is 2 files",
        },
    }
    path = store(tmp_path, event, "unavailable-inventory-event.json")
    assert (
        modern_script(script, 
            [
                "--repo",
                "Owner/repository",
                "--commit",
                repository[2],
                "--event",
                str(path),
                "--json",
            ]
        )
        == 1
    )
    report = json.loads(capsys.readouterr().out)
    assert any(
        row["code"] == "PRDEL_REPRESENTATION_MISSING" and row["status"] == "FAIL"
        for row in report["findings"]
    )
    assert any(
        row["code"] == "PLATFORM_INVENTORY_UNAVAILABLE" and row["status"] == "UNKNOWN"
        for row in report["findings"]
    )


@pytest.mark.parametrize("fault", ["head", "repo", "body", "malformed"])
def test_protected_confirmed_schema_or_coordinate_failures_are_refuted(
    repository, capsys, tmp_path, monkeypatch, fault
) -> None:
    script = load_script()
    monkeypatch.setattr(script, "ROOT", repository[0])
    event = {
        "repository": {"full_name": "Owner/repository"},
        "pull_request": {
            "base": {"sha": repository[1]},
            "head": {"sha": repository[2]},
            "body": "metadata only",
        },
    }
    if fault == "head":
        event["pull_request"]["head"]["sha"] = repository[1]
    elif fault == "repo":
        event["repository"]["full_name"] = "Other/repository"
    elif fault == "body":
        event["pull_request"]["body"] = []
    path = store(tmp_path, event, "invalid-event.json")
    if fault == "malformed":
        path.write_text("not JSON", encoding="utf-8")
    assert (
        modern_script(script, 
            [
                "--repo",
                "Owner/repository",
                "--commit",
                repository[2],
                "--event",
                str(path),
                "--json",
            ]
        )
        == 1
    )
    report = json.loads(capsys.readouterr().out)
    assert (
        report["status"] == "FAIL"
        and report["findings"][0]["category"] == "INVALID_EVENT"
    )


def test_cli_preventative_comparison_recomputes_pinned_graphs_and_never_sends(
    repository, capsys, tmp_path
) -> None:
    from verifier.runtime.prdel import generate_prdel

    document = fill(generated(repository))
    current = store(tmp_path, document)
    git(repository[0], "checkout", "--quiet", "--detach", repository[1])
    (repository[0] / "README.md").write_text(
        "Another retained bounded example.\n", encoding="utf-8"
    )
    git(repository[0], "add", ".")
    git(repository[0], "commit", "--quiet", "-m", "other explanation change")
    other_head = git(repository[0], "rev-parse", "HEAD")
    other = generate_prdel(repository[0], repository[1], other_head)
    comparison = store(tmp_path, other, "comparison.json")
    result, report = invoke(
        capsys,
        *options(repository),
        "--document",
        str(current),
        "--compare-document",
        str(comparison),
    )
    assert result == 2 and report["status"] == "UNKNOWN"
    preventative = report["preventative"]
    assert preventative["delivery"] == "NOT_SENT"
    assert preventative["source_binding"] == document["binding"]
    assert preventative["compared_bindings"] == [other["binding"]]
    assert preventative["notices"]
    assert all(
        row["source_binding"] == document["binding"]
        and row["target_binding"] == other["binding"]
        and row["delivery"] == "NOT_SENT"
        and row["status"] == "UNKNOWN"
        for row in preventative["notices"]
    )
    forged = copy.deepcopy(other)
    forged["impact_graph"]["nodes"] = []
    comparison = store(tmp_path, forged, "forged-comparison.json")
    result, report = invoke(
        capsys,
        *options(repository),
        "--document",
        str(current),
        "--compare-document",
        str(comparison),
    )
    assert result == 1 and report["status"] == "FAIL"
    assert any(
        row["code"] == "STALE_OR_SUBSTITUTED_COMPARISON"
        for row in report["preventative"]["findings"]
    )


def test_ordinary_metadata_argv_remains_bounded_and_does_not_clear_prdel(
    repository, capsys
) -> None:
    body = "Coordinate: VSTD.20\n"
    assert main(["gate", "pr", "--text", body, "--json"]) == 0
    legacy = json.loads(capsys.readouterr().out)
    assert "schema_version" not in legacy
    assert "Coordinate presence" in legacy["report"]["claim_boundary"]
    assert "substantive claims" in legacy["report"]["claim_boundary"]
    result, modern = invoke(capsys, *options(repository), "--text", body)
    assert result == 1 and modern["status"] == "FAIL"
    assert any(row["code"] == "PRDEL_REPRESENTATION_MISSING"
               for row in modern["report"]["findings"])


@pytest.mark.parametrize("missing", ["base", "head", "both"])
def test_modern_contract_missing_explicit_coordinates_cannot_fall_back(
    repository, capsys, monkeypatch, missing
) -> None:
    from verifier.runtime import gate

    def forbidden_metadata(*arguments, **keywords):
        raise AssertionError("Modern mode must never call metadata fallback")

    monkeypatch.setattr(gate, "run_pr_gate", forbidden_metadata)
    selected = ["--root", str(repository[0])]
    if missing not in {"base", "both"}:
        selected += ["--base", repository[1]]
    if missing not in {"head", "both"}:
        selected += ["--commit", repository[2]]
    result, report = invoke(capsys, *selected, "--text", "Coordinate: VSTD.20")
    assert result == 1 and report["status"] == "FAIL"


@pytest.mark.parametrize("selector", ["--generate", "--document", "--compilation"])
def test_modern_selector_without_contract_never_falls_back(
    capsys, monkeypatch, selector
) -> None:
    from verifier.runtime import gate

    def forbidden_metadata(*arguments, **keywords):
        raise AssertionError("Modern selector must never call metadata fallback")

    monkeypatch.setattr(gate, "run_pr_gate", forbidden_metadata)
    selected = [selector]
    if selector == "--document":
        selected.append("absent.json")
    elif selector == "--compilation":
        selected.append("--generate")
    assert main(["gate", "pr", *selected, "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "FAIL"


def test_explicit_local_revision_selectors_bind_exact_commits(repository, capsys) -> None:
    result, compilation = invoke(
        capsys, "--root", str(repository[0]), "--base", "HEAD~1", "--head", "HEAD",
        "--generate", "--compilation",
    )
    assert result == 0
    assert compilation["binding"]["base"] == repository[1]
    assert compilation["binding"]["head"] == repository[2]


def test_modern_script_missing_coordinates_does_not_call_legacy(
    capsys, monkeypatch
) -> None:
    script = load_script()

    def forbidden_legacy(*arguments, **keywords):
        raise AssertionError("Modern script must never call legacy fallback")

    monkeypatch.setattr(script, "_main_working_tree", forbidden_legacy)
    assert modern_script(script, ["--json"]) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "FAIL"


@pytest.mark.parametrize("selector", ["--document", "--requirements-digest", "--evidence-digest", "--base"])
def test_empty_modern_selector_cannot_fall_back_to_metadata(
    capsys, monkeypatch, selector
) -> None:
    from verifier.runtime import gate

    def forbidden_metadata(*arguments, **keywords):
        raise AssertionError("An empty modern value must never call metadata fallback")

    monkeypatch.setattr(gate, "run_pr_gate", forbidden_metadata)
    assert main(["gate", "pr", selector, "", "--text", "Coordinate: VSTD.20", "--json"]) == 1
    assert json.loads(capsys.readouterr().out)["status"] == "FAIL"


def _shard_cli_arguments(tmp_path, *, executable=False):
    rendered, manifest, shards, base, head, selection = shard_helpers._gate_render(
        tmp_path, executable=executable
    )
    manifest_path = tmp_path / 'selected-manifest.json'
    manifest_path.write_bytes(manifest)
    residual_path = tmp_path / 'selected-residuals.json'
    residual_path.write_text(json.dumps(selection['expected_required_residuals']), encoding='utf-8')
    args = ['--root', str(tmp_path), '--base', base, '--head', head,
            '--manifest', str(manifest_path), '--manifest-digest', selection['expected_manifest_digest'],
            '--source-digest', selection['expected_source_digest'], '--compilation-residuals', str(residual_path),
            '--packet-budget-bytes', str(selection['packet_budget_bytes'])]
    for index, (raw, digest) in enumerate(zip(shards, selection['expected_shard_digests'])):
        shard_path = tmp_path / f'selected-shard-{index}.json'
        shard_path.write_bytes(raw)
        args += ['--shard', str(shard_path), '--shard-digest', digest]
    return args, rendered


def _shard_cli_invoke(capsys, *args):
    exit_code = main(['gate', 'pr', *args, '--json'])
    out = capsys.readouterr()
    assert 'Traceback' not in out.out + out.err
    return exit_code, json.loads(out.out)


def test_cli_new_contract_renders_and_validates_selected_packet(tmp_path, capsys):
    args, expected = _shard_cli_arguments(tmp_path)
    result, rendered = _shard_cli_invoke(capsys, '--contract', 'verifier-prdel-shard-description-1', *args, '--render')
    assert result == 0 and rendered['operation'] == 'render'
    from jsonschema import Draft202012Validator
    schema = json.loads((ROOT / 'src/verifier/schemas/verifier-prdel-shard-description-1.schema.json').read_text(encoding='utf-8'))
    Draft202012Validator(schema).validate(rendered)
    assert rendered['body'] == expected['body']
    assert rendered['report']['status'] == 'PASS'
    body_path = tmp_path / 'selected-body.md'
    body_path.write_text(rendered['body'], encoding='utf-8', newline='\n')
    result, checked = _shard_cli_invoke(capsys, '--contract', 'verifier-prdel-shard-description-1', *args, '--file', str(body_path))
    assert result == 0 and checked['operation'] == 'validate'
    assert checked['status'] == checked['report']['status'] == 'PASS'


def test_cli_render_success_does_not_change_required_failures(tmp_path, capsys):
    args, _ = _shard_cli_arguments(tmp_path, executable=True)
    result, rendered = _shard_cli_invoke(capsys, '--contract', 'verifier-prdel-shard-description-1', *args, '--render')
    assert result == 0 and rendered['report']['status'] == 'FAIL'
    result, checked = _shard_cli_invoke(capsys, '--contract', 'verifier-prdel-shard-description-1', *args, '--text', rendered['body'])
    assert result == 1 and checked['report']['logical_report']['required_checks_not_run'] > 0


@pytest.mark.parametrize('selector', ['absent-contract', 'v1-contract', 'missing-shard-digest'])
def test_shard_selectors_never_fall_back_or_lose_external_pins(tmp_path, capsys, selector):
    args, expected = _shard_cli_arguments(tmp_path)
    contract = [] if selector == 'absent-contract' else ['--contract', 'verifier-prdel-1' if selector == 'v1-contract' else 'verifier-prdel-shard-description-1']
    if selector == 'missing-shard-digest':
        index = args.index('--shard-digest')
        del args[index:index+2]
    result, value = _shard_cli_invoke(capsys, *contract, *args, '--text', expected['body'])
    assert result == 1 and value['status'] == 'FAIL'


def _shard_budget_selectors(tmp_path, budget):
    manifest = tmp_path / "manifest.json"
    shard = tmp_path / "shard.json"
    residuals = tmp_path / "residuals.json"
    manifest.write_bytes(b"{}")
    shard.write_bytes(b"{}{}")
    residuals.write_bytes(b"[]")
    return ["gate", "pr", "--contract", "verifier-prdel-shard-description-1",
        "--root", str(tmp_path), "--base", "a" * 40, "--head", "b" * 40,
        "--manifest", str(manifest), "--manifest-digest", "c" * 64,
        "--shard", str(shard), "--shard-digest", "d" * 64,
        "--source-digest", "e" * 64, "--compilation-residuals", str(residuals),
        "--packet-budget-bytes", str(budget), "--render", "--json"], manifest, shard


def test_manifest_read_allocation_obeys_selected_packet_budget(tmp_path, monkeypatch, capsys):
    args, manifest, _ = _shard_budget_selectors(tmp_path, 1)
    monkeypatch.setattr(_shard_budget_gate, "_resolve_prdel_coordinates", lambda args: None)
    original = _shard_budget_gate._prdel_file
    calls = []
    def allocated(path, *, byte_limit=_shard_budget_gate.MAX_PRDEL_INPUT_BYTES):
        calls.append((path, byte_limit))
        if path == str(manifest):
            assert byte_limit <= 1, "Manifest allocation exceeded the caller's aggregate packet budget before decoding"
        return original(path, byte_limit=byte_limit)
    monkeypatch.setattr(_shard_budget_gate, "_prdel_file", allocated)
    assert main(args) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "UNKNOWN" and result["body"] is None
    assert calls == [(str(manifest), 1)]


def test_shard_read_allocation_obeys_remaining_packet_budget(tmp_path, monkeypatch, capsys):
    args, manifest, shard = _shard_budget_selectors(tmp_path, 4)
    monkeypatch.setattr(_shard_budget_gate, "_resolve_prdel_coordinates", lambda args: None)
    original = _shard_budget_gate._prdel_file
    calls = []
    def allocated(path, *, byte_limit=_shard_budget_gate.MAX_PRDEL_INPUT_BYTES):
        calls.append((path, byte_limit))
        if path == str(shard):
            assert byte_limit <= 2
        return original(path, byte_limit=byte_limit)
    monkeypatch.setattr(_shard_budget_gate, "_prdel_file", allocated)
    assert main(args) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "UNKNOWN" and result["body"] is None
    assert [row[0] for row in calls] == [str(manifest), str(shard)]
