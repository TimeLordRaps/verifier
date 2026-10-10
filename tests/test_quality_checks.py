"""Selected formatting checks and counterexamples; no behavioral assurance.

JavaScript Object Notation (JSON) supplies explicitly selected policy and receipts.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import sys
import time

import pytest

from verifier.runtime import quality_checks as quality


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def encode(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True).encode()


def profile(tmp_path: Path, *, backend: str | None = None) -> dict:
    (tmp_path / "demo.py").write_bytes(b"def increment(x):\n    return x + 1\n")
    stages = [
        {
            "id": name,
            "selected": name == "comment-format",
            "required": name == "comment-format",
            "backend": (
                "builtin-managed-python-comments-1"
                if name == "comment-format"
                else None
            ),
            "tool": None,
            "config": None,
        }
        for name in quality.STAGES
    ]
    value = {
        "schema_version": quality.PROFILE,
        "sources": ["demo.py"],
        "stages": stages,
        "timeout_seconds": 2,
        "max_output_bytes": 4096,
    }
    if backend:
        stage = stages[1 if backend == "ruff" else 2]
        config = {"schema_version": "verifier-quality-tool-config-1", "line_length": 88}
        if backend == "ruff":
            config["select"] = ["E", "F"]
        raw = encode(config)
        (tmp_path / "quality.json").write_bytes(raw)
        stage.update(
            selected=True,
            required=True,
            backend=backend,
            tool={
                "version": "1.2.3",
                "interpreter_digest": "sha256:" + "1" * 64,
                "distribution_digest": "sha256:" + "2" * 64,
            },
            config={"path": "quality.json", "digest": digest(raw)},
        )
    return value


def run(tmp_path: Path, value: dict, definitions: dict | None = None) -> dict:
    raw = encode(value)
    return quality.run_quality_profile(tmp_path, raw, digest(raw), definitions)


def definition(identifier: str = "increment.intent", path: str = "demo.py") -> dict:
    return {
        "schema_version": "verifier-explanation-definitions-1",
        "definitions": [
            {
                "id": identifier,
                "target": {"path": path, "symbol": "increment"},
                "intent": "Expose an increment operation",
                "requirement_ids": [],
                "invariants": [],
                "limits": [],
            }
        ],
    }


def managed(identifier: str = "increment.intent") -> bytes:
    return (
        "# handwritten lead comment\n"
        f"# vstd-explanation: begin {identifier}\n"
        "# Authored intent (not verified): expose an increment operation\n"
        f"# vstd-explanation: end {identifier}\n"
        "def increment(x):\n    return x + 1\n"
    ).encode()


def admitted_tool(backend: str, _root: Path) -> dict:
    return {
        "backend": backend,
        "version": "1.2.3",
        "interpreter": sys.executable,
        "interpreter_digest": "sha256:" + "1" * 64,
        "distribution_digest": "sha256:" + "2" * 64,
        "distribution_files": 3,
        "invocation": "isolated Python module, check-only",
    }


def command_result(
    *_args: object, code: int = 0, status: str = "PASS", **_kwargs: object
) -> dict:
    return {
        "exit_code": code,
        "status": status,
        "cleanup": "OWNED_TREE_TERMINATED",
        "stdout": "[]",
        "stderr": "private secret diagnostic",
    }


def test_absent_profile_has_no_selected_obligations(tmp_path: Path) -> None:
    result = quality.run_quality_profile(tmp_path, None, None)
    assert result["status"] == "PASS"
    assert all(
        row["status"] == row["execution_status"] == "NOT_SELECTED"
        for row in result["stages"]
    )
    assert result["source_digest"] is None


def test_missing_selected_profile_fails_without_running(tmp_path: Path) -> None:
    result = quality.run_quality_profile(tmp_path, None, "sha256:" + "0" * 64)
    assert result["status"] == "FAIL"
    assert result["findings"][0]["execution_status"] == "NOT_RUN"


def test_builtin_positive_binds_current_bytes_and_preserves_source(
    tmp_path: Path,
) -> None:
    value = profile(tmp_path)
    raw = managed()
    (tmp_path / "demo.py").write_bytes(raw)
    result = run(tmp_path, value, definition())
    assert result["status"] == "PASS"
    assert result["inputs_unchanged"] is True
    assert result["sources"] == [
        {"path": "demo.py", "size_bytes": len(raw), "digest": digest(raw)}
    ]
    assert result["stages"][0]["execution_status"] == "EXECUTED"
    assert result["stages"][1]["status"] == "NOT_SELECTED"
    assert (tmp_path / "demo.py").read_bytes() == raw
    assert run(tmp_path, value, definition()) == result


@pytest.mark.parametrize(
    "text",
    [
        "# vstd-explanation: begin x\n# authored\n",
        "# vstd-explanation: end x\n",
        "# vstd-explanation: begin x\n# authored\n# vstd-explanation: end y\n",
        (
            "# vstd-explanation: begin x\n# vstd-explanation: begin "
            "y\n# authored\n# vstd-explanation: end y\n"
        ),
        "# vstd-explanation: begin x\nprint('injected')\n# vstd-explanation: end x\n",
        "print(1) # vstd-explanation: begin x\n# authored\n# vstd-explanation: end x\n",
        (
            "# vstd-explanation: begin invalid id\n# authored\n# "
            "vstd-explanation: end invalid id\n"
        ),
        "# vstd-explanation: begin x\n# vstd-explanation: end x\n",
        "# vstd-explanation: begin x\n# authored\n# vstd-explanation: end x\n" * 2,
    ],
)
def test_managed_comment_counterexamples_fail(tmp_path: Path, text: str) -> None:
    value = profile(tmp_path)
    (tmp_path / "demo.py").write_bytes(text.encode())
    result = run(tmp_path, value)
    assert result["status"] == "FAIL"
    assert result["stages"][0]["execution_status"] == "EXECUTED"
    assert result["stages"][0]["findings"]


def test_marker_text_in_strings_and_handwritten_comments_is_not_managed(
    tmp_path: Path,
) -> None:
    value = profile(tmp_path)
    (tmp_path / "demo.py").write_text(
        'text = "# vstd-explanation: begin x"\n# handwritten prose\n', encoding="utf-8"
    )
    assert run(tmp_path, value)["status"] == "PASS"


@pytest.mark.parametrize(
    "mutation", ["unknown", "wrongpath", "duplicate", "invaliddefinition"]
)
def test_definition_binding_is_checked(tmp_path: Path, mutation: str) -> None:
    value = profile(tmp_path)
    (tmp_path / "demo.py").write_bytes(managed())
    selected = definition()
    if mutation == "unknown":
        selected["definitions"][0]["id"] = "other"
    elif mutation == "wrongpath":
        selected["definitions"][0]["target"]["path"] = "other.py"
    elif mutation == "duplicate":
        selected["definitions"].append(copy.deepcopy(selected["definitions"][0]))
    else:
        selected["unexpected"] = True
    assert run(tmp_path, value, selected)["status"] == "FAIL"


@pytest.mark.parametrize(
    "path",
    [
        "../escape.py",
        "/escape.py",
        "bad\\path.py",
        "x/./demo.py",
        "x//demo.py",
        "NUL.py",
        "x:stream",
        "demo.py ",
        "x*.py",
        "\n.py",
    ],
)
def test_nonportable_source_paths_fail(tmp_path: Path, path: str) -> None:
    value = profile(tmp_path)
    value["sources"] = [path]
    result = run(tmp_path, value)
    assert result["status"] == "FAIL"
    assert all(row["execution_status"] != "EXECUTED" for row in result["stages"])


@pytest.mark.parametrize(
    "mutation",
    [
        "required-unselected",
        "arbitrary-command",
        "env",
        "tool",
        "duplicate-stage",
        "missing-stage",
        "nan",
        "source-case-alias",
    ],
)
def test_policy_contract_does_not_admit_candidate_authority(
    tmp_path: Path, mutation: str
) -> None:
    value = profile(tmp_path)
    if mutation == "required-unselected":
        value["stages"][1]["required"] = True
    elif mutation == "arbitrary-command":
        value["stages"][0]["argv"] = ["publish"]
    elif mutation == "env":
        value["environment"] = {"PYTHONPATH": "."}
    elif mutation == "tool":
        value["stages"][0]["backend"] = "candidate-hook"
    elif mutation == "duplicate-stage":
        value["stages"][1] = copy.deepcopy(value["stages"][0])
    elif mutation == "missing-stage":
        value["stages"].pop()
    elif mutation == "nan":
        value["timeout_seconds"] = float("nan")
    else:
        value["sources"].append("Demo.py")
    assert run(tmp_path, value)["status"] == "FAIL"


def test_profile_digest_tampering_fails(tmp_path: Path) -> None:
    value = profile(tmp_path)
    raw = encode(value)
    value["stages"][0]["required"] = False
    assert (
        quality.run_quality_profile(tmp_path, encode(value), digest(raw))["status"]
        == "FAIL"
    )


def test_missing_selected_source_fails_not_run(tmp_path: Path) -> None:
    value = profile(tmp_path)
    (tmp_path / "demo.py").unlink()
    result = run(tmp_path, value)
    assert result["status"] == result["stages"][0]["status"] == "FAIL"
    assert result["stages"][0]["execution_status"] == "NOT_RUN"


def test_observation_unavailable_is_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = profile(tmp_path)
    monkeypatch.setattr(
        quality,
        "_read",
        lambda _path: (_ for _ in ()).throw(
            quality._Unavailable("observation unavailable")
        ),
    )
    result = run(tmp_path, value)
    assert result["status"] == "UNKNOWN"
    assert result["stages"][0]["execution_status"] == "NOT_RUN"


def test_unsupported_comment_language_is_unknown(tmp_path: Path) -> None:
    value = profile(tmp_path)
    (tmp_path / "other.js").write_text("const x = 1;", encoding="utf-8")
    value["sources"] = ["other.js"]
    result = run(tmp_path, value)
    assert result["status"] == result["stages"][0]["status"] == "UNKNOWN"


def test_source_change_during_builtin_check_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = profile(tmp_path)
    original = quality._comments

    def changing(contents: dict, definitions: dict | None) -> list:
        findings = original(contents, definitions)
        (tmp_path / "demo.py").write_text("x = 3\n", encoding="utf-8")
        return findings

    monkeypatch.setattr(quality, "_comments", changing)
    result = run(tmp_path, value)
    assert result["status"] == "FAIL"
    assert result["inputs_unchanged"] is False


@pytest.mark.parametrize("backend", ["ruff", "black"])
def test_admitted_adapters_build_check_only_argv_and_keep_diagnostics_private(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, backend: str
) -> None:
    value = profile(tmp_path, backend=backend)
    monkeypatch.setattr(quality, "_tool_identity", admitted_tool)
    seen: list[list[str]] = []

    def command(argv: list[str], *_args: object, **kwargs: object) -> dict:
        seen.append(argv)
        assert "RUFF_OUTPUT_FILE" not in kwargs["env"]
        result = command_result()
        if backend == "black":
            result["stderr"] += "\n1 file would be left unchanged.\n"
        return result

    monkeypatch.setattr(quality, "_command", command)
    result = run(tmp_path, value)
    assert result["status"] == "PASS"
    assert seen[0][:5] == [sys.executable, "-I", "-B", "-m", backend]
    assert "--no-cache" in seen[0] and seen[0][-1] == str(
        (tmp_path / "demo.py").resolve()
    )
    assert ("--no-fix" if backend == "ruff" else "--check") in seen[0]
    assert ("--isolated" if backend == "ruff" else "--config") in seen[0]
    assert "private secret diagnostic" not in json.dumps(result)
    assert "private diagnostic" not in json.dumps(result)
    row = result["stages"][1 if backend == "ruff" else 2]
    assert row["execution_status"] == "EXECUTED"
    diagnostic = b"private secret diagnostic" + (
        b"\n1 file would be left unchanged.\n" if backend == "black" else b""
    )
    assert row["observation"]["stderr_digest"] == digest(diagnostic)


@pytest.mark.parametrize(
    "status,code,expected",
    [
        ("PASS", 0, "PASS"),
        ("FAIL", 1, "FAIL"),
        ("FAIL", 2, "UNKNOWN"),
        ("TIMEOUT", None, "UNKNOWN"),
        ("OUTPUT_LIMIT", 1, "UNKNOWN"),
        ("ERROR", None, "UNKNOWN"),
    ],
)
def test_adapter_outcomes_preserve_bounds_and_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: str,
    code: int | None,
    expected: str,
) -> None:
    value = profile(tmp_path, backend="ruff")
    monkeypatch.setattr(quality, "_tool_identity", admitted_tool)
    result = command_result(status=status, code=code)
    if code == 1:
        result["stdout"] = json.dumps(
            [
                {
                    "code": "F821",
                    "filename": str((tmp_path / "demo.py").resolve()),
                    "location": {"row": 1, "column": 1},
                    "message": "undefined name",
                }
            ]
        )
    monkeypatch.setattr(quality, "_command", lambda *_args, **_kwargs: result)
    assert run(tmp_path, value)["status"] == expected


def test_unavailable_tool_is_unknown_not_fake_absence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = profile(tmp_path, backend="ruff")
    monkeypatch.setattr(
        quality,
        "_tool_identity",
        lambda *_args: (_ for _ in ()).throw(quality._Unavailable("not observed")),
    )
    result = run(tmp_path, value)
    assert result["status"] == "UNKNOWN"
    assert result["stages"][1]["execution_status"] == "NOT_RUN"


@pytest.mark.parametrize(
    "mutation", ["version", "interpreter_digest", "distribution_digest"]
)
def test_selected_tool_identity_mismatch_fails_not_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    value = profile(tmp_path, backend="ruff")
    value["stages"][1]["tool"][mutation] = (
        "bad" if mutation == "version" else "sha256:" + "3" * 64
    )
    monkeypatch.setattr(quality, "_tool_identity", admitted_tool)
    result = run(tmp_path, value)
    assert result["status"] == "FAIL"
    assert result["stages"][1]["execution_status"] == "NOT_RUN"


@pytest.mark.parametrize(
    "mutation", ["missing", "digest", "extra", "outside", "selector-injection"]
)
def test_configuration_contract_fails_without_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    value = profile(tmp_path, backend="ruff")
    stage = value["stages"][1]
    if mutation == "missing":
        (tmp_path / "quality.json").unlink()
    elif mutation == "digest":
        stage["config"]["digest"] = "sha256:" + "0" * 64
    elif mutation == "outside":
        stage["config"]["path"] = "../outside.json"
    else:
        configured = json.loads((tmp_path / "quality.json").read_bytes())
        if mutation == "extra":
            configured["extend"] = "../pyproject.toml"
        else:
            configured["select"] = ["F;publish"]
        raw = encode(configured)
        (tmp_path / "quality.json").write_bytes(raw)
        stage["config"]["digest"] = digest(raw)
    monkeypatch.setattr(
        quality, "_command", lambda *_args, **_kwargs: pytest.fail("must not run")
    )
    result = run(tmp_path, value)
    assert result["status"] == "FAIL"
    assert result["stages"][1]["execution_status"] == "NOT_RUN"


def test_configuration_mutation_after_run_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = profile(tmp_path, backend="ruff")
    monkeypatch.setattr(quality, "_tool_identity", admitted_tool)

    def command(*_args: object, **_kwargs: object) -> dict:
        (tmp_path / "quality.json").write_bytes(b"changed")
        return command_result()

    monkeypatch.setattr(quality, "_command", command)
    result = run(tmp_path, value)
    assert result["status"] == "FAIL" and result["inputs_unchanged"] is False


def test_distribution_change_after_run_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = profile(tmp_path, backend="ruff")
    calls = 0

    def observe(backend: str, root: Path) -> dict:
        nonlocal calls
        calls += 1
        result = admitted_tool(backend, root)
        if calls > 1:
            result["distribution_digest"] = "sha256:" + "4" * 64
        return result

    monkeypatch.setattr(quality, "_tool_identity", observe)
    monkeypatch.setattr(quality, "_command", command_result)
    assert run(tmp_path, value)["status"] == "FAIL"


def test_duplicate_json_keys_rejected_even_with_matching_digest(tmp_path: Path) -> None:
    raw = (
        b'{"schema_version":"verifier-quality-profile-1","schema_versi'
        b'on":"verifier-quality-profile-1"}'
    )
    assert quality.run_quality_profile(tmp_path, raw, digest(raw))["status"] == "FAIL"


def test_profile_schema_accepts_runtime_positive_example(tmp_path: Path) -> None:
    import jsonschema

    value = profile(tmp_path)
    schema = json.loads(
        (
            Path(quality.__file__).parents[1]
            / "schemas"
            / "verifier-quality-profile-1.schema.json"
        ).read_bytes()
    )
    jsonschema.Draft202012Validator(schema).validate(value)


def test_discovery_order_does_not_change_selected_source_binding(
    tmp_path: Path,
) -> None:
    value = profile(tmp_path)
    (tmp_path / "other.py").write_text("x = 3\n", encoding="utf-8")
    value["sources"].append("other.py")
    first = run(tmp_path, value)
    value["sources"].reverse()
    value["stages"].reverse()
    second = run(tmp_path, value)
    assert first["source_digest"] == second["source_digest"]
    assert first["stages"] == second["stages"]


def test_source_edit_changes_fresh_receipt_identity(tmp_path: Path) -> None:
    value = profile(tmp_path)
    first = run(tmp_path, value)
    (tmp_path / "demo.py").write_text("x = 4\n", encoding="utf-8")
    second = run(tmp_path, value)
    assert first["status"] == second["status"] == "PASS"
    assert first["profile_digest"] == second["profile_digest"]
    assert first["source_digest"] != second["source_digest"]


@pytest.mark.parametrize("linked", ["source", "root-parent"])
def test_linked_path_rejected_without_platform_link_privilege(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, linked: str
) -> None:
    value = profile(tmp_path)
    original = Path.is_symlink
    target = tmp_path / "demo.py" if linked == "source" else tmp_path.parent
    monkeypatch.setattr(
        Path, "is_symlink", lambda path: path == target or original(path)
    )
    result = run(tmp_path, value)
    assert result["status"] == "FAIL"
    assert result["stages"][0]["execution_status"] == "NOT_RUN"


def test_cancelled_check_is_unknown_and_later_stages_not_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = profile(tmp_path, backend="ruff")
    monkeypatch.setattr(quality, "_tool_identity", admitted_tool)
    monkeypatch.setattr(
        quality,
        "_command",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(KeyboardInterrupt()),
    )
    result = run(tmp_path, value)
    assert result["status"] == "UNKNOWN"
    assert result["stages"][1]["execution_status"] == "INTERRUPTED"
    assert result["stages"][2]["execution_status"] == "NOT_SELECTED"


def test_process_not_started_is_not_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = profile(tmp_path, backend="ruff")
    monkeypatch.setattr(quality, "_tool_identity", admitted_tool)
    result = command_result(status="ERROR", code=None)
    result["cleanup"] = "NOT_STARTED"
    monkeypatch.setattr(quality, "_command", lambda *_args, **_kwargs: result)
    observed = run(tmp_path, value)
    assert observed["status"] == "UNKNOWN"
    assert observed["stages"][1]["execution_status"] == "NOT_RUN"


def test_tool_inventory_reconstructs_distribution_bytes_and_rejects_candidate_supply(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = tmp_path / "tools"
    base.mkdir()
    (base / "ruff").mkdir()
    (base / "ruff" / "__main__.py").write_bytes(b"# retained tool implementation\n")

    class Distribution:
        metadata = {"Name": "ruff"}
        version = "1.2.3"
        files = [Path("ruff/__main__.py")]

        def locate_file(self, entry: str | Path) -> Path:
            return base / entry

    monkeypatch.setattr(
        quality.importlib.metadata, "distributions", lambda **_kwargs: [Distribution()]
    )
    selected_root = tmp_path / "candidate"
    selected_root.mkdir()
    first = quality._tool_identity("ruff", selected_root)
    assert first["version"] == "1.2.3"
    assert first["distribution_files"] == 1
    (base / "ruff" / "__main__.py").write_bytes(b"# changed tool implementation\n")
    assert (
        quality._tool_identity("ruff", selected_root)["distribution_digest"]
        != first["distribution_digest"]
    )
    with pytest.raises(quality._Invalid, match="candidate root"):
        quality._tool_identity("ruff", tmp_path)


@pytest.mark.parametrize("encoding", ["latin-1", "utf-8-sig"])
def test_python_declared_encodings_are_supported(tmp_path: Path, encoding: str) -> None:
    value = profile(tmp_path)
    text = (
        managed()
        .decode()
        .replace("expose an increment operation", "caf\u00e9 increment")
    )
    if encoding == "latin-1":
        text = "# coding: latin-1\n" + text
    (tmp_path / "demo.py").write_bytes(text.encode(encoding))
    assert run(tmp_path, value, definition())["status"] == "PASS"


def test_unresolved_tokenization_is_unknown(tmp_path: Path) -> None:
    value = profile(tmp_path)
    (tmp_path / "demo.py").write_bytes(b'x = """unterminated\n')
    assert run(tmp_path, value)["status"] == "UNKNOWN"


@pytest.mark.parametrize(
    "variant",
    [
        "invalidjson",
        "emptyfailure",
        "foreignfile",
        "wrongrule",
        "badlocation",
        "successwithfinding",
        "unknownfield",
    ],
)
def test_unrecognized_linter_protocol_is_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variant: str
) -> None:
    value = profile(tmp_path, backend="ruff")
    monkeypatch.setattr(quality, "_tool_identity", admitted_tool)
    finding = {
        "code": "F821",
        "filename": str((tmp_path / "demo.py").resolve()),
        "location": {"row": 1, "column": 1},
        "message": "undefined name",
    }
    result = command_result(code=1, status="FAIL")
    if variant == "foreignfile":
        finding["filename"] = str(tmp_path / "outside.py")
    elif variant == "wrongrule":
        finding["code"] = "W123"
    elif variant == "badlocation":
        finding["location"]["row"] = 0
    elif variant == "successwithfinding":
        result.update(code=0, exit_code=0, status="PASS")
    elif variant == "unknownfield":
        finding["run_command"] = "publish"
    result["stdout"] = (
        "not JSON"
        if variant == "invalidjson"
        else "[]" if variant == "emptyfailure" else json.dumps([finding])
    )
    monkeypatch.setattr(quality, "_command", lambda *_args, **_kwargs: result)
    assert run(tmp_path, value)["status"] == "UNKNOWN"


@pytest.mark.parametrize(
    "variant,expected",
    [
        ("changed", "FAIL"),
        ("unparsed", "UNKNOWN"),
        ("count", "UNKNOWN"),
        ("foreignfile", "UNKNOWN"),
        ("internal", "UNKNOWN"),
        ("unsupportedflags", "UNKNOWN"),
    ],
)
def test_formatter_protocol_and_internal_errors_are_distinct(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variant: str, expected: str
) -> None:
    value = profile(tmp_path, backend="black")
    monkeypatch.setattr(quality, "_tool_identity", admitted_tool)
    result = command_result(code=1, status="FAIL")
    result["stdout"] = ""
    name = str((tmp_path / "demo.py").resolve())
    result["stderr"] = f"would reformat {name}\n1 file would be reformatted.\n"
    if variant == "unparsed":
        result["stderr"] = "unexpected diagnostic"
    elif variant == "count":
        result["stderr"] = f"would reformat {name}\n2 files would be reformatted.\n"
    elif variant == "foreignfile":
        result["stderr"] = "would reformat outside.py\n1 file would be reformatted.\n"
    elif variant == "internal":
        result.update(exit_code=123, stderr="error: cannot format: INTERNAL ERROR")
    elif variant == "unsupportedflags":
        result.update(exit_code=2, stderr="unsupported flag")
    monkeypatch.setattr(quality, "_command", lambda *_args, **_kwargs: result)
    assert run(tmp_path, value)["status"] == expected


def test_actual_owned_command_receives_only_fixed_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("RUFF_OUTPUT_FILE", str(tmp_path / "unexpected-secret-output"))
    monkeypatch.setenv("BLACK_NUM_WORKERS", "1000")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    environment = quality._environment()
    code = (
        "import os,json; print(json.dumps({k:os.environ.get(k) for k "
        "in ('RUFF_OUTPUT_FILE','BLACK_NUM_WORKERS','PYTHONPATH')}))"
    )
    result = quality._command(
        [sys.executable, "-I", "-B", "-c", code],
        tmp_path,
        time.monotonic() + 3,
        4096,
        lambda _: None,
        env=environment,
    )
    assert result["status"] == "PASS"
    assert json.loads(result["stdout"]) == {
        "RUFF_OUTPUT_FILE": None,
        "BLACK_NUM_WORKERS": None,
        "PYTHONPATH": None,
    }
    assert not (tmp_path / "unexpected-secret-output").exists()


def test_comment_token_analysis_bound_is_unknown(tmp_path: Path) -> None:
    value = profile(tmp_path)
    (tmp_path / "demo.py").write_bytes(b"# unselected handwritten prose\n" * 20000)
    result = run(tmp_path, value)
    assert result["status"] == "UNKNOWN"
    assert result["stages"][0]["execution_status"] == "NOT_RUN"


def test_contradictory_producer_exit_and_status_is_unknown(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    value = profile(tmp_path, backend="ruff")
    monkeypatch.setattr(quality, "_tool_identity", admitted_tool)
    monkeypatch.setattr(
        quality,
        "_command",
        lambda *_args, **_kwargs: command_result(status="FAIL", code=0),
    )
    assert run(tmp_path, value)["status"] == "UNKNOWN"
