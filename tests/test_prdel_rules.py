"""Pull Request Domain Explanation Language (PRDEL) compilation controls.

Terminology: abstract syntax tree (AST). Facts, authored intent and selected finite
cases have
distinct support. Generation and replay do not supply execution evidence.
"""

from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess

import pytest

from verifier.runtime import prdel, prdel_rules


def git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *arguments],
        capture_output=True,
        text=True,
        check=True,
        timeout=20,
    ).stdout.strip()


def commit(
    root: Path, files: dict[str, str | bytes], message: str = "Fixture change"
) -> str:
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(
            content if isinstance(content, bytes) else content.encode("utf-8")
        )
    git(root, "add", ".")
    git(root, "commit", "--quiet", "-m", message)
    return git(root, "rev-parse", "HEAD")


@pytest.fixture
def repository(tmp_path: Path) -> tuple[Path, str, str]:
    root = tmp_path / "repository"
    root.mkdir()
    git(root, "init", "--quiet")
    git(root, "config", "user.name", "Fixture")
    git(root, "config", "user.email", "fixture" + "@" + "example.invalid")
    git(root, "config", "commit.gpgsign", "false")
    git(root, "config", "core.autocrlf", "false")
    base = commit(root, {"README.md": "Retained before.\n"}, "Baseline")
    head = commit(root, {"README.md": "Retained after.\n"})
    return root, base, head


def requirements(items: list[dict]) -> dict:
    raw = prdel.canonical(
        {"schema_version": "verifier-prdel-requirements-1", "items": items}
    )
    return {
        "requirements_bytes": raw,
        "expected_requirements_digest": prdel.digest(raw),
    }


def definitions(
    path: str,
    identifiers: list[str],
    symbol: str | None = None,
    intent: str = "An authored purpose, not checked behavior.",
) -> dict:
    return {
        "schema_version": "verifier-explanation-definitions-1",
        "definitions": [
            {
                "id": "retained-explanation",
                "target": {"path": path, "symbol": symbol},
                "intent": intent,
                "requirement_ids": identifiers,
                "invariants": [],
                "limits": [],
            }
        ],
    }


def test_default_compiles_checked_facts_without_manual_template(repository) -> None:
    result = prdel_rules.compile_prdel(*repository)
    assert result["status"] == "PASS" and result["operation_status"] == "GENERATED"
    assert result["gate_status"] == "NOT_ASSESSED"
    document = result["document"]
    assert document["evidence"] == []
    for record in document["records"]:
        assert record["limits"] == list(prdel.LIMITS)
        assert record["summary"] == "\n".join(
            prdel.claim_text(claim, document) for claim in record["claims"]
        )
    assert prdel.validate_prdel(document, *repository)["status"] == "PASS"
    assert (
        prdel.evaluate_description(prdel.render_prdel(document), *repository)["status"]
        == "PASS"
    )
    assert any(
        row["code"] == "AUTHOR_MOTIVATION_UNRESOLVED" and not row["required"]
        for row in result["residuals"]
    )


def test_empty_diff_is_explicit_and_deterministic(repository) -> None:
    root, base, _ = repository
    result = prdel_rules.compile_prdel(root, base, base)
    assert result == prdel_rules.compile_prdel(root, base, base)
    assert result["status"] == "PASS"
    assert result["document"]["records"][0]["claims"][0]["kind"] == "no_source_changes"
    assert (
        prdel.validate_prdel(result["document"], root, base, base)["status"] == "PASS"
    )


def test_every_rule_has_explicit_support_assumptions_bounds_counterexamples() -> None:
    catalogue = prdel_rules.rule_catalogue()
    assert len({item["id"] for item in catalogue}) == len(catalogue)
    for rule in catalogue:
        assert set(rule) == {
            "id",
            "version",
            "mechanism",
            "support",
            "assumptions",
            "bounds",
            "counterexamples",
        }
        assert rule["version"] == "1" and rule["support"] and rule["counterexamples"]
        assert rule["assumptions"] and all(
            value > 0 for value in rule["bounds"].values()
        )


def test_project_requirements_do_not_attach_by_convenience(repository) -> None:
    selected = requirements(
        [{"id": "retry-order", "text": "Retries must preserve ordering."}]
    )
    result = prdel_rules.compile_prdel(*repository, **selected)
    assert result["status"] == "FAIL" and result["operation_status"] == "GENERATED"
    assert result["document"]["records"][0]["requirement_ids"] == []
    assert {row["code"] for row in result["residuals"]} >= {
        "MISSING_REQUIREMENT_ASSOCIATION",
        "UNREPRESENTED_REQUIREMENT",
    }


def test_external_default_name_with_different_meaning_is_not_generic(
    repository,
) -> None:
    selected = requirements(
        [{"id": "bounded-source-description", "text": "Every execution is safe."}]
    )
    assert prdel_rules.compile_prdel(*repository, **selected)["status"] == "FAIL"


def test_authored_association_retained_without_inventing_semantic_claim(
    repository,
) -> None:
    selected = requirements(
        [{"id": "doc-change", "text": "Update the retained wording."}]
    )
    authored = definitions(
        "README.md", ["doc-change"], intent="Because the author prefers this wording."
    )
    result = prdel_rules.compile_prdel(*repository, definition=authored, **selected)
    assert result["status"] == "PASS"
    assert result["definitions"] == authored
    assert result["definition_digest"] == prdel.digest(prdel.canonical(authored))
    assert all(
        "author prefers" not in record["summary"]
        for record in result["document"]["records"]
    )
    assert (
        prdel.validate_prdel(result["document"], *repository, **selected)["status"]
        == "PASS"
    )


def test_empty_authored_intent_remains_explicitly_unresolved(repository) -> None:
    result = prdel_rules.compile_prdel(
        *repository,
        definition=definitions("README.md", ["bounded-source-description"], intent=""),
    )
    assert result["status"] == "PASS"
    assert any(
        row["code"] == "AUTHOR_MOTIVATION_UNRESOLVED" for row in result["residuals"]
    )


def test_invalid_authored_association_fails_even_when_source_unavailable(
    repository, monkeypatch
) -> None:
    def unavailable(*args, **kwargs):
        raise prdel.PrdelUnavailable("exact source observation unavailable")

    monkeypatch.setattr(prdel, "generate_prdel", unavailable)
    result = prdel_rules.compile_prdel(
        *repository, definition=definitions("README.md", ["absent-requirement"])
    )
    assert result["status"] == "FAIL" and result["document"] is None
    assert {row["code"] for row in result["residuals"]} == {
        "SOURCE_UNAVAILABLE",
        "UNKNOWN_AUTHORED_REQUIREMENT",
    }


def test_malformed_definition_fails_before_source_query(
    repository, monkeypatch
) -> None:
    monkeypatch.setattr(
        prdel,
        "generate_prdel",
        lambda *args, **kwargs: pytest.fail("source query should not run"),
    )
    assert (
        prdel_rules.compile_prdel(*repository, definition={"definitions": []})["status"]
        == "FAIL"
    )


def test_missing_base_is_unknown_and_no_document_is_fabricated(repository) -> None:
    result = prdel_rules.compile_prdel(repository[0], "f" * 40, repository[2])
    assert result["status"] == "UNKNOWN" and result["operation_status"] == "BLOCKED"
    assert result["document"] is None


def test_resolved_ast_is_generated_but_missing_execution_still_blocks(
    repository,
) -> None:
    root, _, old_head = repository
    base = commit(
        root,
        {
            ("candidate.py"): (
                "def producer(x):\n    return x + 1\n\ndef "
                "consumer(x):\n    return producer(x)\n"
            )
        },
    )
    head = commit(
        root,
        {
            ("candidate.py"): (
                "def producer(x):\n    return x + 2\n\ndef "
                "consumer(x):\n    return producer(x)\n"
            )
        },
    )
    result = prdel_rules.compile_prdel(root, base, head)
    assert any(
        claim["kind"] == "ast_relationship"
        for record in result["document"]["records"]
        for claim in record["claims"]
    )
    assert all(
        "behavioral invariant" in record["summary"]
        for record in result["document"]["records"]
        if record["claims"][0]["kind"] == "ast_relationship"
    )
    report = prdel.validate_prdel(result["document"], root, base, head)
    assert report["status"] == "FAIL" and report["required_checks_not_run"] > 0
    assert {"unit", "integration", "regression", "preventative"}.issubset(
        report["coverage"]["layers"]
    )


@pytest.mark.parametrize(
    "source",
    [
        "def candidate(x):\n    return handler(x)\n",
        "@decorate\ndef candidate(x):\n    return x\n",
        "def candidate(x):\n    if x:\n        return x\n    return 0\n",
    ],
)
def test_unsupported_semantics_and_dynamic_edges_remain_unknown(
    repository, source
) -> None:
    root, _, base = repository
    head = commit(root, {"candidate.py": source})
    selected = requirements(
        [
            {
                "id": "candidate-contract",
                "text": "Check selected cases.",
                "predicate": {
                    "kind": "finite_python_function",
                    "path": "candidate.py",
                    "symbol": "candidate",
                    "cases": [{"arguments": [2], "expected": 2}],
                },
            }
        ]
    )
    result = prdel_rules.compile_prdel(root, base, head, **selected)
    assert result["status"] == "UNKNOWN"
    assert any(
        row["code"] == "UNSUPPORTED_SELECTED_REQUIREMENT" for row in result["residuals"]
    )
    assert all(
        "matches all" not in record["summary"]
        for record in result["document"]["records"]
    )


@pytest.mark.parametrize("expected,status", [(4, "PASS"), (5, "FAIL")])
def test_independently_selected_finite_cases_pass_or_refute(
    repository, expected, status
) -> None:
    root, _, base = repository
    head = commit(root, {"candidate.py": "def double(x):\n    return x * 2\n"})
    selected = requirements(
        [
            {
                "id": "double-contract",
                "text": "Selected double cases.",
                "predicate": {
                    "kind": "finite_python_function",
                    "path": "candidate.py",
                    "symbol": "double",
                    "cases": [{"arguments": [2], "expected": expected}],
                },
            }
        ]
    )
    result = prdel_rules.compile_prdel(root, base, head, **selected)
    assert result["status"] == status
    assert all(
        record["requirement_ids"] == ["double-contract"]
        for record in result["document"]["records"]
    )
    assert any(
        row["rule_id"] == "finite-cases" and row["status"] == status
        for row in result["rule_results"]
    )


def test_selected_counterexample_cannot_be_hidden_by_missing_association(
    repository,
) -> None:
    root, _, _ = repository
    base = commit(root, {"candidate.py": "def double(x):\n    return x * 2\n"})
    head = commit(root, {"README.md": "An unrelated edit.\n"})
    selected = requirements(
        [
            {
                "id": "contrary-case",
                "text": "Selected contrary case.",
                "predicate": {
                    "kind": "finite_python_function",
                    "path": "candidate.py",
                    "symbol": "double",
                    "cases": [{"arguments": [2], "expected": 5}],
                },
            }
        ]
    )
    result = prdel_rules.compile_prdel(root, base, head, **selected)
    assert result["status"] == "FAIL"
    assert {row["code"] for row in result["residuals"]} >= {
        "CONTRADICTED_SELECTED_REQUIREMENT",
        "UNREPRESENTED_REQUIREMENT",
    }


@pytest.mark.parametrize(
    "mutation",
    ["rule-version", "rule-omission", "span", "source-hash", "summary", "extra-field"],
)
def test_replay_rejects_tampered_rule_support_and_binding(repository, mutation) -> None:
    result = prdel_rules.compile_prdel(*repository)
    altered = copy.deepcopy(result)
    if mutation == "rule-version":
        altered["rule_catalogue"][0]["version"] = "99"
    elif mutation == "rule-omission":
        altered["rule_results"].pop()
    elif mutation == "span":
        altered["document"]["source_obligations"][0]["new_range"][0] += 1
    elif mutation == "source-hash":
        altered["document"]["binding"]["source_digest"] = "f" * 64
    elif mutation == "summary":
        altered["document"]["records"][0]["summary"] = "The model is correct."
    else:
        altered["unadmitted"] = True
    assert prdel_rules.validate_compilation(altered, *repository)["status"] == "FAIL"
    assert prdel_rules.validate_compilation(result, *repository)["status"] == "PASS"


def test_replay_rejects_stale_commit_and_selected_authored_input(repository) -> None:
    authored = definitions("README.md", ["bounded-source-description"])
    result = prdel_rules.compile_prdel(*repository, definition=authored)
    changed = copy.deepcopy(authored)
    changed["definitions"][0]["intent"] = "Different authored input."
    assert (
        prdel_rules.validate_compilation(result, *repository, definition=changed)[
            "status"
        ]
        == "FAIL"
    )
    root, base, head = repository
    later = commit(root, {"README.md": "A later exact edit.\n"})
    assert (
        prdel_rules.validate_compilation(result, root, base, later)["status"] == "FAIL"
    )


@pytest.mark.parametrize(
    "mutation", ["head", "requirement", "result-version", "definition-digest"]
)
def test_known_staleness_fails_even_when_replay_source_is_unavailable(
    repository, monkeypatch, mutation
) -> None:
    result = prdel_rules.compile_prdel(
        *repository, definition=definitions("README.md", ["bounded-source-description"])
    )
    if mutation == "head":
        result["binding"]["head"] = "f" * 40
    elif mutation == "requirement":
        result["document"]["requirements"]["items"][0][
            "text"
        ] = "Unselected requirement."
    elif mutation == "result-version":
        result["rule_results"][0]["rule_version"] = "999"
    else:
        result["definition_digest"] = "f" * 64

    def unavailable(*args, **kwargs):
        raise prdel.PrdelUnavailable("source observation unavailable")

    monkeypatch.setattr(prdel, "generate_prdel", unavailable)
    assert prdel_rules.validate_compilation(result, *repository)["status"] == "FAIL"


def test_known_invalid_input_does_not_echo_private_exception_text(
    repository, monkeypatch
) -> None:
    def unavailable(*args, **kwargs):
        raise OSError("private path must not escape")

    monkeypatch.setattr(prdel, "generate_prdel", unavailable)
    result = prdel_rules.compile_prdel(*repository)
    assert result["status"] == "UNKNOWN"
    assert "private path" not in prdel.canonical(result).decode()


def test_bounds_do_not_turn_partial_compilation_into_success(
    repository, monkeypatch
) -> None:
    monkeypatch.setattr(prdel_rules, "MAX_RULE_OPERATIONS", 1)
    result = prdel_rules.compile_prdel(*repository)
    assert result["status"] == "UNKNOWN"
    assert result["counters"]["operations"] <= 1
    assert any(row["code"] == "RULE_OPERATION_BOUND" for row in result["residuals"])


def test_bound_retains_previously_observed_known_failure(
    repository, monkeypatch
) -> None:
    monkeypatch.setattr(prdel_rules, "MAX_RULE_OPERATIONS", 1)
    result = prdel_rules.compile_prdel(
        *repository, definition=definitions("README.md", ["unselected"])
    )
    assert result["status"] == "FAIL"
    assert {row["code"] for row in result["residuals"]} >= {
        "UNKNOWN_AUTHORED_REQUIREMENT",
        "RULE_OPERATION_BOUND",
    }


def test_byte_bound_returns_no_oversized_artifact(repository, monkeypatch) -> None:
    monkeypatch.setattr(prdel_rules, "MAX_COMPILED_BYTES", 32)
    result = prdel_rules.compile_prdel(*repository)
    assert result["status"] == "UNKNOWN" and result["document"] is None


@pytest.mark.parametrize(
    "content",
    [
        b"Before Unicode caf\xc3\xa9.\r\nAfter Unicode caf\xc3\xa9.\r\n",
        b"\x00binary remains data\xff",
    ],
)
def test_unicode_crlf_and_binary_source_are_data(repository, content) -> None:
    root, _, base = repository
    suffix = "README.md" if b"\x00" not in content else "payload.bin"
    head = commit(root, {suffix: content})
    result = prdel_rules.compile_prdel(root, base, head)
    assert result["status"] == ("PASS" if suffix == "README.md" else "UNKNOWN")
    row = next(
        item
        for item in result["document"]["source_obligations"]
        if item["kind"] == "source"
    )
    if suffix == "README.md":
        assert "\r\n" in row["after_text"] and "café" in row["after_text"]


def test_fake_declarations_names_and_defaults_do_not_invent_semantics(
    repository,
) -> None:
    root, _, base = repository
    head = commit(
        root,
        {"candidate.py": """# def certified(): return True
fake = "def validate(): return success"
def outer():
    def duplicate():
        return 1
    return duplicate
def secure(retries=5) -> str:
    return retries
"""},
    )
    result = prdel_rules.compile_prdel(root, base, head)
    graph = result["document"]["impact_graph"]
    assert not any(
        node["symbol"] in {"certified", "validate"} for node in graph["nodes"]
    )
    claims = [
        claim for record in result["document"]["records"] for claim in record["claims"]
    ]
    assert not any(claim["kind"] == "finite_function_contract" for claim in claims)
    assert all(
        claim["kind"] in {"source_delta", "ast_relationship", "requirement_quote"}
        for claim in claims
    )


def test_rename_and_edit_retains_both_absence_and_addition(repository) -> None:
    root, _, base = repository
    (root / "README.md").unlink()
    head = commit(root, {"GUIDE.md": "The renamed and edited text.\n"})
    result = prdel_rules.compile_prdel(root, base, head)
    source = [
        row
        for row in result["document"]["source_obligations"]
        if row["kind"] == "source"
    ]
    assert {(row["path"], row["change_kind"]) for row in source} == {
        ("README.md", "removed"),
        ("GUIDE.md", "added"),
    }
    assert result["status"] == "PASS"


def test_equivalent_requirement_order_composes_in_canonical_identifier_order(
    repository,
) -> None:
    items = [
        {"id": "z-wording", "text": "Retain changed wording."},
        {"id": "a-exact", "text": "Retain exact source facts."},
    ]
    authored = definitions("README.md", ["z-wording", "a-exact"])
    first = prdel_rules.compile_prdel(
        *repository, definition=authored, **requirements(items)
    )
    second = prdel_rules.compile_prdel(
        *repository, definition=authored, **requirements(list(reversed(items)))
    )
    assert first["document"]["records"] == second["document"]["records"]
    assert (
        first["document"]["binding"]["requirements_digest"]
        != second["document"]["binding"]["requirements_digest"]
    )
    assert first["document"]["records"][0]["requirement_ids"] == [
        "a-exact",
        "z-wording",
    ]


def test_poison_candidate_is_never_executed(repository) -> None:
    root, _, base = repository
    sentinel = root / "must-not-exist"
    head = commit(
        root,
        {
            ("candidate.py"): (
                "from pathlib import Path\nPath('must-not-exist').writ"
                "e_text('bad')\nraise RuntimeError('must remain "
                "data')\n"
            )
        },
    )
    result = prdel_rules.compile_prdel(root, base, head)
    assert result["document"] is not None
    assert not sentinel.exists()


def test_packaged_compilation_schema_resolves_closed_contracts(repository) -> None:
    from jsonschema import Draft202012Validator, ValidationError
    from referencing import Registry, Resource

    folder = Path(__file__).resolve().parents[1] / "src" / "verifier" / "schemas"
    names = (
        "verifier-prdel-1.schema.json",
        "verifier-prdel-compilation-1.schema.json",
        "verifier-explanation-definitions-1.schema.json",
    )
    schemas = [json.loads((folder / name).read_bytes()) for name in names]
    registry = Registry().with_resources(
        [(schema["$id"], Resource.from_contents(schema)) for schema in schemas]
    )
    validator = Draft202012Validator(schemas[1], registry=registry)
    for authored in (None, definitions("README.md", ["bounded-source-description"])):
        result = prdel_rules.compile_prdel(*repository, definition=authored)
        validator.validate(result)
        result["rule_results"][0]["rule_version"] = "unregistered"
        with pytest.raises(ValidationError):
            validator.validate(result)
