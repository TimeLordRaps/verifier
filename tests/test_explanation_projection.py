"""Atomic authored explanation projection and bounded Git provenance controls.

Terminology: abstract syntax tree (AST); carriage return and line feed (CRLF);
identifier (ID); JavaScript Object Notation (JSON); line feed (LF);
Secure Hash Algorithm 256-bit (SHA-256); Unicode Transformation Format, 8-bit (UTF-8).
These controls do not establish authored intent truth or execution provenance.
"""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from verifier.runtime import explanation_projection as projection


def definition(
    symbol: str | None = "calculate",
    *,
    path: str = "sample.py",
    definition_id: str = "ex.calculate",
) -> dict:
    return {
        "id": definition_id,
        "target": {"path": path, "symbol": symbol},
        "intent": "Explain the selected calculation.\nThis is authored intent.",
        "requirement_ids": ["req.finite"],
        "invariants": ["Preserve the selected input domain."],
        "limits": ["No complete runtime correctness is established."],
    }


def definitions(*rows: dict) -> dict:
    return {
        "schema_version": projection.DEFINITION_SCHEMA,
        "definitions": list(rows or [definition()]),
    }


def project(raw: bytes, selected: dict | None = None) -> dict:
    return projection.project_comments({"sample.py": raw}, selected or definitions())


def test_unselected_prose_marker_text_is_not_a_managed_python_comment() -> None:
    files = {
        "sample.py": b"def calculate(x):\n    return x + 1\n",
        "tutorial.md": b"```python\n# vstd-explanation: begin orphan\n```\n",
    }
    result = projection.project_comments(files, definitions())
    assert result["status"] == "PASS"
    assert result["files"]["tutorial.md"] == files["tutorial.md"]
    unsupported = projection.project_comments(
        files, definitions(definition(path="tutorial.md"))
    )
    assert unsupported["status"] == "UNKNOWN" and unsupported["files"] == files
    invalid = {**files, "bad.py": b"# vstd-explanation: begin orphan\n"}
    failed = projection.project_comments(invalid, definitions())
    assert failed["status"] == "FAIL" and failed["files"] == invalid


def test_long_authored_comments_wrap_without_changing_code_or_definition() -> None:
    raw = b"def calculate(x):\n    return x + 1\n"
    row = definition()
    row["intent"] = (
        "Explain this explicitly authored intent without asserting its truth. " * 4
    )
    selected = definitions(row)
    before_definition = projection.canonical_definitions(selected)
    result = project(raw, selected)
    assert result["status"] == "PASS"
    assert all(
        len(line) <= 88 for line in result["files"]["sample.py"].decode().splitlines()
    )
    assert ast.dump(ast.parse(raw)) == ast.dump(ast.parse(result["files"]["sample.py"]))
    assert projection.canonical_definitions(selected) == before_definition
    repeated = projection.project_comments(result["files"], selected)
    assert repeated["status"] == "PASS" and repeated["files"] == result["files"]


def test_strict_canonical_contract_and_schema_route() -> None:
    selected = definitions()
    raw = projection.canonical_definitions(selected)
    assert projection.load_definitions(raw) == selected
    assert (
        raw
        == json.dumps(
            selected, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode()
    )
    schema = json.loads(
        (
            Path(projection.__file__).parents[1]
            / "schemas"
            / "verifier-explanation-definitions-1.schema.json"
        ).read_text()
    )
    assert schema["$id"].endswith(
        "/schemas/verifier-explanation-definitions-1.schema.json"
    )
    assert schema["additionalProperties"] is False


@pytest.mark.parametrize(
    "raw",
    [
        b'{"schema_version":"verifier-explanation-definitions-1","schema_version":"other","definitions":[]}',
        b'{"schema_version":"verifier-explanation-definitions-1","definitions":[{"id":"a","id":"b"}]}',
        b'{"schema_version":"verifier-explanation-definitions-1","definitions":[],"extra":true}',
        b'{"schema_version":"other","definitions":[]}',
        b"[]",
        b"NaN",
        b"\xff",
        b"{",
    ],
)
def test_malformed_or_substituted_definition_contract_fails(raw: bytes) -> None:
    with pytest.raises(ValueError):
        projection.load_definitions(raw)


@pytest.mark.parametrize(
    "target",
    [
        "../sample.py",
        "/sample.py",
        "a//sample.py",
        "a/./sample.py",
        "C:sample.py",
        "a\\sample.py",
        "CON.py",
        "a./sample.py",
        "a\u2028.py",
    ],
)
def test_nonportable_definition_target_is_rejected(target: str) -> None:
    with pytest.raises(ValueError):
        projection.canonical_definitions(definitions(definition(path=target)))


def test_duplicate_id_target_and_invalid_authored_types_fail() -> None:
    for selected in (
        definitions(definition(), definition(symbol="other")),
        definitions(definition(), definition(definition_id="other")),
    ):
        with pytest.raises(ValueError):
            projection.canonical_definitions(selected)
    for field, value in (
        ("intent", 42),
        ("requirement_ids", ["unknown requirement"]),
        ("invariants", [" "]),
        ("limits", ["x", "x"]),
        ("intent", "\x00"),
    ):
        selected = definitions()
        selected["definitions"][0][field] = value
        with pytest.raises(ValueError):
            projection.canonical_definitions(selected)


def test_empty_authored_fields_are_explicit_not_inferred() -> None:
    row = definition()
    row.update(intent="", requirement_ids=[], invariants=[], limits=[])
    selected = definitions(row)
    assert (
        projection.load_definitions(projection.canonical_definitions(selected))
        == selected
    )
    result = project(b"def calculate(x):\n    return x + 1\n", selected)
    assert result["status"] == "PASS"
    assert b"(not supplied)" in result["files"]["sample.py"]
    assert result["authored_status"] == "AUTHORED_NOT_PROVED"


def test_projection_is_atomic_idempotent_and_preserves_handwritten_source() -> None:
    raw = (
        b"# Human explanation stays.\n@decorate\ndef calculate(x):\n    "
        b'"""Existing documentation."""\n    return x + 1'
    )
    original = {"sample.py": raw, "README.md": b"Unmodified narrative.\n"}
    result = projection.project_comments(original, definitions())
    assert result["status"] == "PASS" and original["sample.py"] == raw
    updated = result["files"]["sample.py"]
    assert updated.startswith(
        b"# Human explanation stays.\n# vstd-explanation: begin ex.calculate\n"
    )
    assert updated.endswith(
        (
            b'@decorate\ndef calculate(x):\n    """Existing '
            b'documentation."""\n    return x + 1'
        )
    )
    assert result["files"]["README.md"] == original["README.md"]
    assert result["source_before"] != result["source_after"]
    assert result["changes"][0]["after_sha256"] == hashlib.sha256(updated).hexdigest()
    repeated = projection.project_comments(result["files"], definitions())
    assert repeated["files"] == result["files"] and repeated["changes"] == []
    assert repeated["source_before"] == repeated["source_after"]
    assert ast.dump(ast.parse(raw)) == ast.dump(ast.parse(updated))


@pytest.mark.parametrize("newline", [b"\n", b"\r\n"])
def test_unicode_nested_targets_preserve_offsets_encoding_and_newlines(
    newline: bytes,
) -> None:
    raw = newline.join(
        [
            b"#!/usr/bin/env python",
            b"# coding: utf-8",
            "# café stays".encode(),
            "class Café:".encode(),
            b"\t@decorate",
            "\tdef calculé(self):".encode(),
            b"\t\treturn 7",
            b"",
        ]
    )
    selected = definitions(definition(symbol="Café.calculé"))
    selected["definitions"][0]["intent"] = "Préserver l’explication."
    result = project(raw, selected)
    assert result["status"] == "PASS"
    updated = result["files"]["sample.py"]
    assert updated.startswith(
        newline.join(
            [b"#!/usr/bin/env python", b"# coding: utf-8", "# café stays".encode()]
        )
    )
    assert b"\t# vstd-explanation: begin ex.calculate" + newline in updated
    assert updated.replace(newline, b"").count(b"\n") == 0
    assert project(updated, selected)["files"]["sample.py"] == updated
    assert ast.dump(ast.parse(raw)) == ast.dump(ast.parse(updated))


def test_module_projection_preserves_shebang_cookie_bom_and_docstring() -> None:
    raw = (
        b'\xef\xbb\xbf#!/usr/bin/env python\n# coding: utf-8\n"""Existing module '
        b'documentation."""\n'
    )
    result = project(raw, definitions(definition(symbol=None)))
    updated = result["files"]["sample.py"]
    assert result["status"] == "PASS"
    assert updated.startswith(
        b"\xef\xbb\xbf#!/usr/bin/env python\n# coding: utf-8\n# vstd-explanation:"
    )
    assert updated.endswith(b'"""Existing module documentation."""\n')
    assert (
        project(updated, definitions(definition(symbol=None)))["files"]["sample.py"]
        == updated
    )


def test_markers_in_strings_and_fake_declarations_are_not_managed_or_targets() -> None:
    raw = (
        b'"""# vstd-explanation: begin ex.calculate\ndef '
        b'calculate(x):\n# vstd-explanation: end ex.calculate\n"""\n'
    )
    result = project(raw)
    assert result["status"] == "FAIL" and result["files"]["sample.py"] == raw
    valid = raw + b"def calculate(x):\n    return x\n"
    assert project(valid)["status"] == "PASS"


@pytest.mark.parametrize(
    "raw",
    [
        b"# vstd-explanation: begin ex.calculate\ndef calculate(x):\n    return x\n",
        b"# vstd-explanation: end ex.calculate\ndef calculate(x):\n    return x\n",
        (
            b"# vstd-explanation: begin ex.calculate\n# "
            b"vstd-explanation: end wrong\ndef calculate(x):\n    "
            b"return x\n"
        ),
        (
            b"# vstd-explanation: begin ex.calculate\n# "
            b"vstd-explanation: begin other\n# vstd-explanation: end "
            b"other\n# vstd-explanation: end ex.calculate\ndef "
            b"calculate(x):\n    return x\n"
        ),
        (
            b"# vstd-explanation: begin ex.calculate\nx = 3\n# "
            b"vstd-explanation: end ex.calculate\ndef calculate(x):\n   "
            b" return x\n"
        ),
        (
            b"x = 3 # vstd-explanation: begin ex.calculate\ndef "
            b"calculate(x):\n    return x\n"
        ),
        (
            b"# vstd-explanation: begin unknown\n# Authored intent\n# "
            b"vstd-explanation: end unknown\ndef calculate(x):\n    "
            b"return x\n"
        ),
    ],
)
def test_malformed_managed_blocks_fail_without_partial_mutation(raw: bytes) -> None:
    result = project(raw)
    assert result["status"] == "FAIL" and result["changes"] == []
    assert result["files"]["sample.py"] == raw


def test_stale_managed_target_fails_and_authored_edits_update_only_managed_bytes() -> (
    None
):
    result = project(b"def calculate(x):\n    return x\n")
    updated = result["files"]["sample.py"]
    selected = definitions()
    selected["definitions"][0]["intent"] = "Updated authored intent."
    next_result = project(updated, selected)
    assert next_result["status"] == "PASS"
    assert b"Updated authored intent." in next_result["files"]["sample.py"]
    stale = updated.replace(
        b"def calculate", b"# Unrelated human region\ndef calculate"
    )
    rejected = project(stale)
    assert rejected["status"] == "FAIL" and rejected["files"]["sample.py"] == stale


def test_duplicate_scopes_language_and_parse_boundaries_stay_unknown() -> None:
    for raw in (
        b"def calculate(x):\n    return x\ndef calculate(x):\n    return x + 1\n",
        b"def calculate(:\n",
        b"def calculate(x):\r\n    return x\n",
    ):
        result = project(raw)
        assert result["status"] == "UNKNOWN" and result["files"]["sample.py"] == raw
    files = {"sample.js": b"function calculate(x) { return x; }"}
    result = projection.project_comments(
        files, definitions(definition(path="sample.js"))
    )
    assert result["status"] == "UNKNOWN" and result["files"] == files


def test_failure_in_another_file_rolls_back_all_staged_changes() -> None:
    files = {"sample.py": b"def calculate(x):\n    return x\n", "other.py": b"x = 1\n"}
    selected = definitions(
        definition(),
        definition(symbol="missing", path="other.py", definition_id="other"),
    )
    result = projection.project_comments(files, selected)
    assert (
        result["status"] == "FAIL"
        and result["files"] == files
        and result["changes"] == []
    )


def test_definition_order_does_not_change_comment_or_authored_rendering() -> None:
    rows = [definition(), definition(symbol=None, definition_id="ex.module")]
    selected = definitions(*rows)
    permuted = definitions(*reversed(rows))
    raw = b"def calculate(x):\n    return x\n"
    assert project(raw, selected)["files"] == project(raw, permuted)["files"]
    assert projection.render_authored_intent(
        selected
    ) == projection.render_authored_intent(permuted)
    selected["definitions"][0][
        "intent"
    ] = "```vstd-prdel\n[link](https://example.invalid)"
    rendered = projection.render_authored_intent(selected)
    assert "\\n" in rendered and "    " in rendered
    assert not any(line.startswith("```") for line in rendered.splitlines())


def test_bounds_are_explicit_and_no_input_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    selected = definitions()
    monkeypatch.setattr(projection, "MAX_DEFINITION_BYTES", 20)
    with pytest.raises(ValueError):
        projection.canonical_definitions(selected)
    monkeypatch.setattr(projection, "MAX_DEFINITION_BYTES", 1024 * 1024)
    monkeypatch.setattr(projection, "MAX_SOURCE_FILE_BYTES", 10)
    raw = b"def calculate(x):\n    return x\n"
    assert project(raw)["status"] == "UNKNOWN"
    monkeypatch.setattr(projection, "MAX_SOURCE_FILE_BYTES", 512 * 1024)
    monkeypatch.setattr(projection, "MAX_SOURCE_BYTES", 10)
    assert project(raw)["status"] == "UNKNOWN"


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


@pytest.fixture
def definition_repository(tmp_path: Path) -> tuple[Path, str, str]:
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.name", "Fixture")
    git(tmp_path, "config", "user.email", "fixture" + "@" + "example.invalid")
    git(tmp_path, "config", "commit.gpgsign", "false")
    (tmp_path / "definitions.json").write_bytes(
        projection.canonical_definitions(definitions())
    )
    git(tmp_path, "add", "definitions.json")
    git(tmp_path, "commit", "-qm", "Introduce authored definition")
    introduced = git(tmp_path, "rev-parse", "HEAD")
    selected = definitions()
    selected["definitions"][0]["intent"] = "Edited authored intent."
    (tmp_path / "definitions.json").write_bytes(
        projection.canonical_definitions(selected)
    )
    git(tmp_path, "add", "definitions.json")
    git(tmp_path, "commit", "-qm", "Edit authored definition")
    return tmp_path, introduced, git(tmp_path, "rev-parse", "HEAD")


def test_provenance_observes_exact_introduction_and_edit_without_pr_guesses(
    definition_repository: tuple[Path, str, str],
) -> None:
    root, introduced, head = definition_repository
    result = projection.resolve_definition_provenance(root, head, "definitions.json")
    assert (
        result["status"] == "PASS"
        and result["commit_status"] == "COMMITTED_BYTES_OBSERVED"
    )
    assert result["definitions"][0]["introduced_commit"] == introduced
    assert result["definitions"][0]["last_edit_commit"] == head
    assert result["workspace_sha256"] == result["committed_sha256"]
    assert (
        result["pr_associations"] == []
        and result["scope"] == "BOUNDED_PATH_OCCURRENCE_HISTORY"
    )


def test_uncommitted_or_stale_head_definitions_are_pending_not_future_attestations(
    definition_repository: tuple[Path, str, str],
) -> None:
    root, introduced, head = definition_repository
    for selected_head in (introduced, head):
        if selected_head == head:
            selected = definitions()
            selected["definitions"][0]["intent"] = "Uncommitted intent."
            (root / "definitions.json").write_bytes(
                projection.canonical_definitions(selected)
            )
        result = projection.resolve_definition_provenance(
            root, selected_head, "definitions.json"
        )
        assert (
            result["status"] == "UNKNOWN"
            and result["commit_status"] == "PENDING_COMMIT"
        )
        assert result["definitions"][0]["introduced_commit"] is None
        assert result["definitions"][0]["last_edit_commit"] is None
        assert result["pr_associations"] == []


def test_untracked_definitions_are_pending_and_known_missing_is_fail(
    definition_repository: tuple[Path, str, str],
) -> None:
    root, _, head = definition_repository
    (root / "new.json").write_bytes(projection.canonical_definitions(definitions()))
    result = projection.resolve_definition_provenance(root, head, "new.json")
    assert (
        result["commit_status"] == "PENDING_COMMIT"
        and result["committed_sha256"] is None
    )
    assert (
        projection.resolve_definition_provenance(root, head, "missing.json")["status"]
        == "FAIL"
    )
    assert (
        projection.resolve_definition_provenance(root, "HEAD", "definitions.json")[
            "status"
        ]
        == "FAIL"
    )
    assert (
        projection.resolve_definition_provenance(root, head, "../definitions.json")[
            "status"
        ]
        == "FAIL"
    )


def test_history_and_git_observation_bounds_remain_unknown(
    definition_repository: tuple[Path, str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    root, _, head = definition_repository
    monkeypatch.setattr(projection, "MAX_HISTORY_COMMITS", 1)
    assert (
        projection.resolve_definition_provenance(root, head, "definitions.json")[
            "status"
        ]
        == "UNKNOWN"
    )
    monkeypatch.setattr(projection, "MAX_HISTORY_COMMITS", 256)
    monkeypatch.setattr(projection, "MAX_GIT_BYTES", 5)
    assert (
        projection.resolve_definition_provenance(root, head, "definitions.json")[
            "status"
        ]
        == "UNKNOWN"
    )


def test_invalid_current_definitions_fail_before_unavailable_git(
    tmp_path: Path,
) -> None:
    (tmp_path / "definitions.json").write_bytes(
        b'{"schema_version":"wrong","definitions":[]}'
    )
    result = projection.resolve_definition_provenance(
        tmp_path, "0" * 40, "definitions.json"
    )
    assert result["status"] == "FAIL"


def test_projection_without_definitions_is_an_explicit_noop() -> None:
    files = {"sample.py": b"x = 1\n"}
    selected = {"schema_version": projection.DEFINITION_SCHEMA, "definitions": []}
    result = projection.project_comments(files, selected)
    assert (
        result["status"] == "PASS"
        and result["files"] == files
        and result["changes"] == []
    )
    assert result["source_before"] == result["source_after"]


def test_exception_scope_declaration_is_found_without_runtime_assumptions() -> None:
    raw = b"try:\n    risky()\nexcept Error:\n    def calculate(x):\n        return x\n"
    result = project(raw)
    assert result["status"] == "PASS"
    assert (
        b"    # vstd-explanation: begin ex.calculate\n    # Authored intent"
        in result["files"]["sample.py"]
    )
    assert ast.dump(ast.parse(raw)) == ast.dump(ast.parse(result["files"]["sample.py"]))


def test_unrepresentable_authored_encoding_and_ast_bound_are_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    raw = b"# coding: latin-1\n# caf\xe9\ndef calculate(x):\n    return x\n"
    selected = definitions()
    assert project(raw, selected)["status"] == "PASS"
    selected["definitions"][0][
        "intent"
    ] = "An emoji \U0001f642 cannot be encoded in this file."
    result = project(raw, selected)
    assert result["status"] == "UNKNOWN" and result["files"]["sample.py"] == raw
    monkeypatch.setattr(projection, "MAX_AST_NODES", 1)
    assert project(b"def calculate(x):\n    return x\n")["status"] == "UNKNOWN"


def test_duplicate_blocks_and_case_colliding_inventory_fail() -> None:
    updated = project(b"def calculate(x):\n    return x\n")["files"]["sample.py"]
    block = updated[: updated.index(b"def calculate")]
    assert project(block + updated)["status"] == "FAIL"
    inventory = {
        "sample.py": b"def calculate(x):\n    return x\n",
        "SAMPLE.py": b"x = 1\n",
    }
    assert projection.project_comments(inventory, definitions())["status"] == "FAIL"


def test_provenance_reintroduction_retains_first_path_occurrence(
    definition_repository: tuple[Path, str, str],
) -> None:
    root, introduced, _ = definition_repository
    retained = (root / "definitions.json").read_bytes()
    (root / "definitions.json").write_bytes(
        projection.canonical_definitions(
            {"schema_version": projection.DEFINITION_SCHEMA, "definitions": []}
        )
    )
    git(root, "add", "definitions.json")
    git(root, "commit", "-qm", "Remove selected occurrence")
    (root / "definitions.json").write_bytes(retained)
    git(root, "add", "definitions.json")
    git(root, "commit", "-qm", "Reintroduce selected occurrence")
    head = git(root, "rev-parse", "HEAD")
    result = projection.resolve_definition_provenance(root, head, "definitions.json")
    assert result["status"] == "PASS"
    assert result["definitions"][0]["introduced_commit"] == introduced
    assert result["definitions"][0]["last_edit_commit"] == head


def test_merged_definition_history_does_not_invent_single_introducer(
    definition_repository: tuple[Path, str, str],
) -> None:
    root, introduced, head = definition_repository
    main = git(root, "branch", "--show-current")
    git(root, "checkout", "-qb", "alternate", introduced)
    selected = definitions()
    selected["definitions"][0]["limits"] = ["Alternate authored limit."]
    (root / "definitions.json").write_bytes(projection.canonical_definitions(selected))
    git(root, "add", "definitions.json")
    git(root, "commit", "-qm", "Alternate edit")
    git(root, "checkout", "-q", main)
    assert git(root, "rev-parse", "HEAD") == head
    subprocess.run(
        ["git", "-C", str(root), "merge", "--no-commit", "--no-ff", "alternate"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )
    selected["definitions"][0]["intent"] = "Edited authored intent."
    (root / "definitions.json").write_bytes(projection.canonical_definitions(selected))
    git(root, "add", "definitions.json")
    git(root, "commit", "-qm", "Retain explicit merged definition")
    result = projection.resolve_definition_provenance(
        root, git(root, "rev-parse", "HEAD"), "definitions.json"
    )
    assert result["status"] == "UNKNOWN"
    assert result["definitions"] == []
    assert "merged" in result["findings"][0]["message"]


def test_shallow_history_and_total_observation_budget_remain_unknown(
    definition_repository: tuple[Path, str, str],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, _, head = definition_repository
    clone = tmp_path / "shallow"
    subprocess.check_call(
        ["git", "clone", "-q", "--depth=1", "--no-local", str(root), str(clone)]
    )
    result = projection.resolve_definition_provenance(clone, head, "definitions.json")
    assert (
        result["status"] == "UNKNOWN" and "shallow" in result["findings"][0]["message"]
    )
    monkeypatch.setattr(projection, "MAX_HISTORY_BYTES", 1)
    assert (
        projection.resolve_definition_provenance(root, head, "definitions.json")[
            "status"
        ]
        == "UNKNOWN"
    )
    monkeypatch.setattr(projection, "MAX_HISTORY_BYTES", 8 * 1024 * 1024)
    monkeypatch.setattr(projection, "MAX_PROVENANCE_SECONDS", 0)
    result = projection.resolve_definition_provenance(root, head, "definitions.json")
    assert (
        result["status"] == "UNKNOWN" and "duration" in result["findings"][0]["message"]
    )


def test_git_replacement_does_not_rewrite_observed_commit_history(
    definition_repository: tuple[Path, str, str],
) -> None:
    root, introduced, head = definition_repository
    git(root, "replace", introduced, head)
    result = projection.resolve_definition_provenance(root, head, "definitions.json")
    assert result["status"] == "PASS"
    assert result["definitions"][0]["introduced_commit"] == introduced


def test_known_absence_dominates_other_unresolved_projection() -> None:
    selected = definitions(
        definition(path="missing.py"),
        definition(path="other.js", definition_id="other"),
    )
    files = {"other.js": b"function calculate() {}"}
    result = projection.project_comments(files, selected)
    assert result["status"] == "FAIL" and result["files"] == files
    assert {row["status"] for row in result["findings"]} == {"FAIL", "UNKNOWN"}


def test_direct_dictionary_byte_bound_precedes_full_serialization(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    row = definition()
    row["invariants"] = [str(index).zfill(3) + "x" * 8100 for index in range(128)]
    row["limits"] = [str(index).zfill(3) + "y" * 8100 for index in range(128)]
    selected = definitions(row)

    def excessive_serialization(value: object) -> bytes:
        raise AssertionError("oversized direct dictionary must not be serialized")

    monkeypatch.setattr(projection, "_canonical", excessive_serialization)
    with pytest.raises(projection.DefinitionError, match="byte bound"):
        projection.canonical_definitions(selected)
