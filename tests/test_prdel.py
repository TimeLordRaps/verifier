"""Pull Request Domain Explanation Language (PRDEL) independent controls.

Terminology: abstract syntax tree (AST); JavaScript Object Notation (JSON);
Secure Hash Algorithm 256-bit (SHA-256). These controls distinguish supported
finite predicates from prose, source identity, and invented execution evidence.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from verifier.runtime import prdel


def git(root: Path, *args: str) -> str:
    return subprocess.check_output(["git", "-C", str(root), *args], text=True).strip()


@pytest.fixture
def repository(tmp_path: Path) -> tuple[Path, str, str]:
    git(tmp_path, "init", "-q")
    git(tmp_path, "config", "user.name", "Fixture")
    git(tmp_path, "config", "user.email", "fixture" + "@" + "example.invalid")
    git(tmp_path, "config", "commit.gpgsign", "false")
    (tmp_path / "README.md").write_text("Before exact text.\n", encoding="utf-8")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-qm", "Baseline")
    base = git(tmp_path, "rev-parse", "HEAD")
    (tmp_path / "README.md").write_text("After exact text.\n", encoding="utf-8")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-qm", "Change")
    return tmp_path, base, git(tmp_path, "rev-parse", "HEAD")


def filled(document: dict) -> dict:
    result = copy.deepcopy(document)
    requirements = result["requirements"]["items"]
    by_id = {row["id"]: row for row in result["source_obligations"]}
    for record in result["records"]:
        row = by_id[record["id"]]
        record["requirement_ids"] = [item["id"] for item in requirements]
        record["why"] = {
            "requirement_id": requirements[0]["id"],
            "quote": requirements[0]["text"],
        }
        if row["kind"] == "source":
            record["claims"] = [
                {
                    "kind": (
                        "no_source_changes" if row.get("no_change") else "source_delta"
                    ),
                    "obligation_id": row["id"],
                }
            ]
        elif row["kind"] == "contract":
            record["claims"] = [{"kind": "ast_relationship", "edge_id": row["edge_id"]}]
        else:
            continue
        record["summary"] = "\n".join(
            prdel.claim_text(claim, result) for claim in record["claims"]
        )
        record["limits"] = [
            "NO_RUNTIME_CORRECTNESS",
            "NO_COMPLETE_OBJECTIVE_CLOSURE",
            "EXACT_COMMIT_SCOPE",
        ]
    return result


def evaluate(
    document: dict, repository: tuple[Path, str, str], **kwargs: object
) -> dict:
    return prdel.validate_prdel(document, *repository, **kwargs)


def test_real_bounded_positive_and_portable_render(repository):
    document = filled(prdel.generate_prdel(*repository))
    source = document["source_obligations"][0]
    assert source["before_text"] == "Before exact text.\n"
    assert source["after_text"] == "After exact text.\n"
    assert source["after_sha256"] == hashlib.sha256(b"After exact text.\n").hexdigest()
    report = evaluate(document, repository)
    assert report["status"] == "PASS"
    assert report["source_grounding_status"] == "PASS"
    assert report["execution_provenance"] == "NOT_ESTABLISHED"
    assert set(report["coverage"]["layers"]) == {
        "base",
        "unit",
        "integration",
        "regression",
        "preventative",
    }
    rendered = prdel.render_prdel(document)
    assert "Selected rationale:" in rendered and "```vstd-prdel" in rendered
    assert prdel.evaluate_description(rendered, *repository)["status"] == "PASS"


def test_legitimate_no_change_is_an_explicit_positive(repository):
    root, base, _ = repository
    document = filled(prdel.generate_prdel(root, base, base))
    assert prdel.validate_prdel(document, root, base, base)["status"] == "PASS"
    template = prdel.generate_prdel(root, base, base)
    assert prdel.validate_prdel(template, root, base, base)["status"] == "FAIL"


def test_untouched_template_is_not_clear(repository):
    report = evaluate(prdel.generate_prdel(*repository), repository)
    assert report["status"] == "FAIL"
    assert any(row["code"] == "UNREPRESENTED_CHANGE" for row in report["findings"])
    assert report["verdict_scope"] == "GATE_OBLIGATION_FULFILLMENT"
    assert report["proposition_truth"] == "NOT_INFERRED_FROM_MISSING_EVIDENCE"
    assert report["required_checks_not_run"] > 0


def test_missing_structure_fails_even_when_source_evaluation_is_unknown(
    repository, monkeypatch
):
    template = prdel.generate_prdel(*repository)
    complete = filled(template)

    def unavailable(*args, **kwargs):
        raise prdel.PrdelUnavailable("Selected source replay is unavailable.")

    monkeypatch.setattr(prdel, "generate_prdel", unavailable)
    missing = evaluate(template, repository)
    assert missing["status"] == "FAIL"
    assert any(
        row["code"] == "SOURCE_UNAVAILABLE" and row["status"] == "UNKNOWN"
        for row in missing["findings"]
    )
    assert evaluate(complete, repository)["status"] == "UNKNOWN"


def test_late_description_source_unavailability_preserves_known_failure(
    repository, monkeypatch
):
    document = prdel.generate_prdel(*repository)
    body = prdel.render_prdel(document) + "Additional unsupported assertion.\n"

    def unavailable(*args, **kwargs):
        raise prdel.PrdelUnavailable("Selected source replay is unavailable.")

    monkeypatch.setattr(prdel, "generate_prdel", unavailable)
    monkeypatch.setattr(prdel, "_snapshot", unavailable)
    report = prdel.evaluate_description(body, *repository, document=document)
    assert report["status"] == "FAIL"
    assert any(
        row["code"] == "MISSING_REQUIRED_CLAIM" and row["status"] == "FAIL"
        for row in report["findings"]
    )
    assert any(
        row["code"] == "SOURCE_UNAVAILABLE" and row["status"] == "UNKNOWN"
        for row in report["findings"]
    )
    assert report["required_checks_not_run"] > 0


@pytest.mark.parametrize("selection", ["requirements", "evidence"])
def test_known_selected_bytes_absence_fails_before_unavailable_source(
    repository, monkeypatch, selection
):
    document = filled(prdel.generate_prdel(*repository))

    def unavailable(*args, **kwargs):
        raise prdel.PrdelUnavailable("Selected source replay is unavailable.")

    monkeypatch.setattr(prdel, "generate_prdel", unavailable)
    report = evaluate(
        document, repository, **{"expected_" + selection + "_digest": "f" * 64}
    )
    assert report["status"] == "FAIL"
    assert "selected " + selection + " bytes missing" in report["findings"][0]["reason"]


@pytest.mark.parametrize("coordinate", ["base", "head"])
def test_known_exact_binding_mismatch_survives_unavailable_source(
    repository, monkeypatch, coordinate
):
    document = filled(prdel.generate_prdel(*repository))
    document["binding"][coordinate] = "f" * 40

    def unavailable(*args, **kwargs):
        raise prdel.PrdelUnavailable("Selected source replay is unavailable.")

    monkeypatch.setattr(prdel, "generate_prdel", unavailable)
    report = evaluate(document, repository)
    assert report["status"] == "FAIL"
    assert any(
        row["code"] == "STALE_OR_SUBSTITUTED_BINDING" and row["status"] == "FAIL"
        for row in report["findings"]
    )
    assert any(
        row["code"] == "SOURCE_UNAVAILABLE" and row["status"] == "UNKNOWN"
        for row in report["findings"]
    )


def test_structurally_complete_unsupported_selected_semantics_remain_unknown(
    repository,
):
    root, _, _ = repository
    (root / "maths.py").write_text(
        "def divide(x):\n    return x // 2\n", encoding="utf-8"
    )
    git(root, "add", ".")
    git(root, "commit", "-qm", "Retained unsupported finite semantics")
    base = git(root, "rev-parse", "HEAD")
    (root / "README.md").write_text(
        "Complete selected narrative change.\n", encoding="utf-8"
    )
    git(root, "add", ".")
    git(root, "commit", "-qm", "Narrative change")
    head = git(root, "rev-parse", "HEAD")
    raw = prdel.canonical(
        {
            "schema_version": "verifier-prdel-requirements-1",
            "items": [
                {
                    "id": "selected-finite",
                    "text": "For the selected input two, divide returns one.",
                    "predicate": {
                        "kind": "finite_python_function",
                        "path": "maths.py",
                        "symbol": "divide",
                        "cases": [{"arguments": [2], "expected": 1}],
                    },
                }
            ],
        }
    )
    document = filled(prdel.generate_prdel(root, base, head, raw, prdel.digest(raw)))
    report = prdel.validate_prdel(document, root, base, head, raw, prdel.digest(raw))
    assert report["status"] == "UNKNOWN"
    assert any(
        row["code"] == "UNRESOLVED_SELECTED_REQUIREMENT" for row in report["findings"]
    )
    assert not any(row["status"] == "FAIL" for row in report["findings"])


@pytest.mark.parametrize(
    "mutation",
    [
        "irrelevant_summary",
        "missing_region",
        "invented_proof",
        "stale_head",
        "erased_graph",
        "duplicate_record",
    ],
)
def test_valid_hashes_do_not_launder_invalid_explanations(repository, mutation):
    document = filled(prdel.generate_prdel(*repository))
    if mutation == "irrelevant_summary":
        document["records"][0][
            "summary"
        ] = "Unrelated citation README.md; bananas are yellow."
    elif mutation == "missing_region":
        document["records"] = []
    elif mutation == "invented_proof":
        document["records"][0]["claims"].append({"kind": "all_234_certified"})
    elif mutation == "stale_head":
        document["binding"]["head"] = "a" * 40
    elif mutation == "erased_graph":
        document["impact_graph"]["nodes"] = []
    elif mutation == "duplicate_record":
        document["records"].append(copy.deepcopy(document["records"][0]))
    report = evaluate(document, repository)
    assert report["status"] in {"FAIL", "UNKNOWN"}
    assert report["findings"]
    assert all(
        row["code"] and row["question"] and row["reason"] for row in report["findings"]
    )


def test_equal_count_wrong_requirements_and_retirement_are_not_clear(repository):
    raw = prdel.canonical(
        {
            "schema_version": "verifier-prdel-requirements-1",
            "items": [
                {"id": f"R{i}", "text": f"Selected requirement {i}."}
                for i in range(1, 10)
            ],
        }
    )
    expected_digest = prdel.digest(raw)
    document = filled(prdel.generate_prdel(*repository, raw, expected_digest))
    assert (
        evaluate(
            document,
            repository,
            requirements_bytes=raw,
            expected_requirements_digest=expected_digest,
        )["status"]
        == "PASS"
    )
    forged = copy.deepcopy(document)
    forged["requirements"]["items"][-1]["id"] = "R10"
    assert (
        evaluate(
            forged,
            repository,
            requirements_bytes=raw,
            expected_requirements_digest=expected_digest,
        )["status"]
        == "FAIL"
    )
    document["records"][0]["requirement_ids"] = ["R1"]
    report = evaluate(
        document,
        repository,
        requirements_bytes=raw,
        expected_requirements_digest=expected_digest,
    )
    assert report["status"] == "FAIL"
    assert (
        len([r for r in report["findings"] if r["code"] == "UNREPRESENTED_REQUIREMENT"])
        == 8
    )


def test_workspace_edits_are_excluded_and_disclosed(repository):
    root, _, _ = repository
    document = filled(prdel.generate_prdel(*repository))
    (root / "README.md").write_text("Dirty contradictory bytes", encoding="utf-8")
    (root / "untracked.py").write_text(
        "raise RuntimeError('must not execute')", encoding="utf-8"
    )
    report = evaluate(document, repository)
    assert report["status"] == "PASS"
    assert report["source_scope"] == "EXACT_COMMITS_ONLY"
    assert "No workspace" in report["claim_boundary"]


def test_observed_ref_movement_during_validation_fails(repository, monkeypatch):
    document = filled(prdel.generate_prdel(*repository))
    original = prdel.generate_prdel
    calls = 0

    def moving(*args, **kwargs):
        nonlocal calls
        result = original(*args, **kwargs)
        calls += 1
        if calls == 2:
            result["binding"]["source_digest"] = "f" * 64
        return result

    monkeypatch.setattr(prdel, "generate_prdel", moving)
    report = evaluate(document, repository)
    assert report["status"] == "FAIL"
    assert any(
        row["code"] == "SOURCE_CHANGED_DURING_VALIDATION" for row in report["findings"]
    )


def test_forged_successful_test_record_is_not_execution(repository):
    document = filled(prdel.generate_prdel(*repository))
    identifier = document["records"][0]["id"]
    document["evidence"] = [
        {
            "id": "test",
            **document["binding"],
            "obligation_ids": [identifier],
            "layer": "base",
            "kind": "test_result",
            "status": "PASS",
            "command": "invented",
            "result_digest": "f" * 64,
        }
    ]
    document["records"][0]["coverage"] = {
        "base": {"status": "EXECUTED", "evidence_ids": ["test"], "reason": ""}
    }
    report = evaluate(document, repository)
    assert report["execution_provenance"] == "NOT_ESTABLISHED"
    document["evidence"][0]["head"] = "a" * 40
    report = evaluate(document, repository)
    assert report["status"] == "FAIL"
    assert any(row["code"] == "STALE_EVIDENCE" for row in report["findings"])


def test_actual_finite_predicate_positive_and_counterexample(repository):
    root, base, _ = repository
    (root / "maths.py").write_text(
        "def increment(x):\n    return x + 1\n", encoding="utf-8"
    )
    git(root, "add", ".")
    git(root, "commit", "-qm", "Finite function")
    head = git(root, "rev-parse", "HEAD")
    requirement = {
        "schema_version": "verifier-prdel-requirements-1",
        "items": [
            {
                "id": "finite",
                ("text"): (
                    "For selected integers zero and one, increment "
                    "returns one and two."
                ),
                "predicate": {
                    "kind": "finite_python_function",
                    "path": "maths.py",
                    "symbol": "increment",
                    "cases": [
                        {"arguments": [0], "expected": 1},
                        {"arguments": [1], "expected": 2},
                    ],
                },
            }
        ],
    }
    raw = prdel.canonical(requirement)
    pin = prdel.digest(raw)
    document = filled(prdel.generate_prdel(root, base, head, raw, pin))
    claim = {"kind": "finite_function_contract", "requirement_id": "finite"}
    assert "matches all 2" in prdel.claim_text(claim, document)
    document["records"][0]["claims"].append(claim)
    document["records"][0]["summary"] = "\n".join(
        prdel.claim_text(c, document) for c in document["records"][0]["claims"]
    )
    report = prdel.validate_prdel(document, root, base, head, raw, pin)
    assert any(
        r["predicate"] == "finite_function_contract" and r["status"] == "PASS"
        for r in report["predicate_results"]
    )
    assert report["status"] == "FAIL"  # Required runtime evidence was not supplied.
    assert report["coverage"]["layers"]["unit"]["verdict"] == "FAIL"
    assert report["coverage"]["layers"]["base"]["verdict"] == "PASS"
    (root / "maths.py").write_text(
        "def increment(x):\n    return x + 2\n", encoding="utf-8"
    )
    git(root, "add", ".")
    git(root, "commit", "-qm", "Contradict selected contract")
    failed = prdel.generate_prdel(root, base, git(root, "rev-parse", "HEAD"), raw, pin)
    with pytest.raises(prdel.PrdelRefuted):
        prdel.claim_text(claim, failed)


@pytest.mark.parametrize(
    "text,code",
    [
        (
            "Current notation: every object has 1..8.m obligations.",
            "CURRENT_REQUIREMENT_CONTRADICTION",
        ),
        (
            "This implements all 234 tier certifications.",
            "UNSUPPORTED_FULL_QUALIFICATION",
        ),
    ],
)
def test_known_requirement_contradictions_fail_even_without_prdel(
    repository, text, code
):
    root, base, _ = repository
    source = root / "src/verifier/core"
    source.mkdir(parents=True)
    (source / "namespace.py").write_text(
        "class MetaTier:\n    SECURITY = 9\n", encoding="utf-8"
    )
    git(root, "add", ".")
    git(root, "commit", "-qm", "Nine tiers")
    report = prdel.evaluate_description(
        "## Coordinate\n" + text, root, base, git(root, "rev-parse", "HEAD")
    )
    assert report["status"] == "FAIL"
    assert any(row["code"] == code for row in report["findings"])


def test_two_line_sha_body_fails_required_representation(repository):
    report = prdel.evaluate_description(
        "Coordinate: fixture\n" + repository[2], *repository
    )
    assert report["status"] == "FAIL"
    assert report["findings"][0]["code"] == "PRDEL_REPRESENTATION_MISSING"


def test_duplicate_json_keys_refused():
    with pytest.raises(prdel.PrdelError):
        prdel.decode(b'{"schema_version":"a","schema_version":"b"}')


@pytest.mark.parametrize(
    "text",
    [
        "All 234 tier certifications are complete; model correctness is established.",
        "Current notation is 1..8.m for every object.",
        "This irrelevant narrative is nonempty.",
    ],
)
def test_arbitrary_limits_cannot_escape_via_canonical_render(repository, text):
    document = filled(prdel.generate_prdel(*repository))
    document["records"][0]["limits"] = [text]
    report = prdel.evaluate_description(prdel.render_prdel(document), *repository)
    assert report["status"] == report["semantic_status"] == "FAIL"
    assert any(item["code"] == "INCOMPLETE_EXPLANATION" for item in report["findings"])


def test_explicit_document_cannot_hide_forged_or_multiple_embedded_documents(
    repository,
):
    document = filled(prdel.generate_prdel(*repository))
    forged = '```vstd-prdel\n{"schema_version":"forged","records":[]}\n```'
    assert (
        prdel.evaluate_description(forged, *repository, document=document)["status"]
        == "FAIL"
    )
    body = prdel.render_prdel(document)
    assert (
        prdel.evaluate_description(body + body, *repository, document=document)[
            "status"
        ]
        == "FAIL"
    )


def test_global_coverage_bound_never_disappears(repository):
    document = filled(prdel.generate_prdel(*repository))
    document["evidence"] = [
        {
            "id": "reported",
            **document["binding"],
            "obligation_ids": ["o" + str(i) for i in range(100001)],
            "layer": "base",
            "kind": "test_result",
            "status": "PASS",
            "command": "untrusted",
            "result_digest": "f" * 64,
        }
    ]
    report = evaluate(document, repository)
    assert report["status"] == report["semantic_status"] == "UNKNOWN"
    assert any(item["code"] == "BOUND_EXHAUSTED" for item in report["findings"])
    assert not report["coverage"]["bounds"]["complete"]
    assert set(report["coverage"]["layers"]) == {
        "base",
        "unit",
        "integration",
        "regression",
        "preventative",
    }


def test_invalid_base_coverage_never_keeps_aggregate_pass(repository):
    document = filled(prdel.generate_prdel(*repository))
    document["records"][0]["coverage"] = {
        "base": {"status": "INVALID", "evidence_ids": [], "reason": ""}
    }
    report = evaluate(document, repository)
    assert (
        report["status"]
        == report["semantic_status"]
        == report["source_grounding_status"]
        == "FAIL"
    )
    assert report["coverage"]["layers"]["base"]["verdict"] == "FAIL"
    assert any(
        item["verdict"] == "FAIL"
        for item in report["coverage"]["layers"]["base"]["obligations"]
    )


def test_snapshot_reads_git_blobs_without_export_transformations(repository):
    root, _, _ = repository
    (root / ".gitattributes").write_text(
        "hidden.py export-ignore\nREADME.md export-subst\n", encoding="utf-8"
    )
    (root / "hidden.py").write_text(
        "raise RuntimeError('candidate must not execute')\n", encoding="utf-8"
    )
    (root / "README.md").write_text("$Format:%H$\n", encoding="utf-8")
    git(root, "add", ".")
    git(root, "commit", "-qm", "Export attributes")
    snapshot = prdel._snapshot(root, git(root, "rev-parse", "HEAD"))
    assert snapshot["README.md"] == b"$Format:%H$\n"
    assert snapshot["hidden.py"].startswith(b"raise RuntimeError")
    assert snapshot.modes["hidden.py"] == "100644"


def test_executable_mode_only_change_is_bound_and_requires_coverage(repository):
    root, _, before = repository
    first = prdel.generate_prdel(root, before, before)
    git(root, "update-index", "--chmod=+x", "README.md")
    git(root, "commit", "-qm", "Executable mode change")
    document = filled(
        prdel.generate_prdel(root, before, git(root, "rev-parse", "HEAD"))
    )
    row = document["source_obligations"][0]
    assert row["before_mode"] == "100644" and row["after_mode"] == "100755"
    assert document["binding"]["source_digest"] != first["binding"]["source_digest"]
    report = prdel.validate_prdel(
        document, root, before, git(root, "rev-parse", "HEAD")
    )
    assert report["status"] == "FAIL"
    assert report["coverage"]["layers"]["unit"]["verdict"] == "FAIL"


def test_additional_prose_updates_semantic_status(repository):
    document = filled(prdel.generate_prdel(*repository))
    report = prdel.evaluate_description(
        prdel.render_prdel(document) + "Unrelated claim of safety.\n", *repository
    )
    assert report["status"] == report["semantic_status"] == "UNKNOWN"
    assert report["coverage"]["layers"]["base"]["verdict"] == "UNKNOWN"


@pytest.mark.parametrize(
    "quotation",
    [
        "Historical quotation: This implements all 234 tier certifications.",
        "Historical quotation: Current notation: every object has 1..8.m obligations.",
    ],
)
def test_checked_historical_source_quotes_stay_data_with_additional_prose(
    repository, quotation
):
    root, _, _ = repository
    namespace = root / "src/verifier/core"
    namespace.mkdir(parents=True)
    (namespace / "namespace.py").write_text(
        "class MetaTier:\n    SECURITY = 9\n", encoding="utf-8"
    )
    git(root, "add", ".")
    git(root, "commit", "-qm", "Retained nine-tier namespace")
    base = git(root, "rev-parse", "HEAD")
    (root / "README.md").write_text(quotation + "\n", encoding="utf-8")
    git(root, "add", ".")
    git(root, "commit", "-qm", "Retained historical quotation")
    head = git(root, "rev-parse", "HEAD")
    document = filled(prdel.generate_prdel(root, base, head))
    body = prdel.render_prdel(document)
    assert prdel.evaluate_description(body, root, base, head)["status"] == "PASS"
    report = prdel.evaluate_description(
        body + "Additional unsupported assertion.\n", root, base, head
    )
    assert report["status"] == "UNKNOWN"
    assert not any(row["status"] == "FAIL" for row in report["findings"])


def test_omitted_selected_finite_predicate_cannot_hide_refutation(repository):
    root, _, _ = repository
    (root / "maths.py").write_text(
        "def increment(x):\n    return x + 1\n", encoding="utf-8"
    )
    git(root, "add", ".")
    git(root, "commit", "-qm", "Existing finite function")
    base = git(root, "rev-parse", "HEAD")
    (root / "README.md").write_text(
        "Another exact narrative region.\n", encoding="utf-8"
    )
    git(root, "add", ".")
    git(root, "commit", "-qm", "Narrative change only")
    head = git(root, "rev-parse", "HEAD")
    requirements = {
        "schema_version": "verifier-prdel-requirements-1",
        "items": [
            {
                "id": "required-finite",
                "text": "For selected zero input, increment returns two.",
                "predicate": {
                    "kind": "finite_python_function",
                    "path": "maths.py",
                    "symbol": "increment",
                    "cases": [{"arguments": [0], "expected": 2}],
                },
            }
        ],
    }
    raw = prdel.canonical(requirements)
    pin = prdel.digest(raw)
    document = filled(prdel.generate_prdel(root, base, head, raw, pin))
    assert all(
        claim["kind"] != "finite_function_contract"
        for record in document["records"]
        for claim in record["claims"]
    )
    report = prdel.validate_prdel(document, root, base, head, raw, pin)
    assert report["status"] == "FAIL"
    assert any(
        item["code"] == "CONTRADICTED_SELECTED_REQUIREMENT"
        for item in report["findings"]
    )


def test_unreferenced_failed_receipt_remains_blocking(repository):
    document = filled(prdel.generate_prdel(*repository))
    document["evidence"] = [
        {
            "id": "retained-failure",
            **document["binding"],
            "obligation_ids": [document["records"][0]["id"]],
            "layer": "base",
            "kind": "test_result",
            "status": "FAIL",
            "command": "reported unsuccessful command",
            "result_digest": "f" * 64,
        }
    ]
    assert document["records"][0]["coverage"] == {}
    report = evaluate(document, repository)
    assert report["status"] == report["coverage"]["layers"]["base"]["verdict"] == "FAIL"


@pytest.mark.parametrize(
    "path",
    ["requirements.txt", "CMakeLists.txt", "setup.cfg", "package.json", "source.rs"],
)
def test_behavior_bearing_artifacts_have_no_documentation_waiver(repository, path):
    root, base, _ = repository
    (root / path).write_text("selected retained bytes\n", encoding="utf-8")
    git(root, "add", ".")
    git(root, "commit", "-qm", "Behavior-bearing artifact")
    head = git(root, "rev-parse", "HEAD")
    document = filled(prdel.generate_prdel(root, base, head))
    report = prdel.validate_prdel(document, root, base, head)
    assert report["status"] == "FAIL"
    assert report["coverage"]["layers"]["unit"]["verdict"] == "FAIL"


def test_packaged_structural_schema_accepts_template_but_rejects_bad_exclusion(
    repository,
):
    from importlib.resources import files
    from jsonschema import Draft202012Validator

    schema = json.loads(
        files("verifier")
        .joinpath("schemas/verifier-prdel-1.schema.json")
        .read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema)
    template = prdel.generate_prdel(*repository)
    validator.validate(template)
    document = filled(template)
    validator.validate(document)
    document["records"][0]["limits"] = ["Fabricated completion"]
    assert list(validator.iter_errors(document))


@pytest.mark.parametrize("separator", ["\n", "\r", "\u0085", "\u2028", "\u2029"])
def test_control_path_metadata_cannot_inject_canonical_prose(separator):
    path = (
        "docs/notes.md"
        + separator
        + "This implements all 234 tier certifications."
        + separator
        + "extra.md"
    )
    with pytest.raises(prdel.PrdelError):
        prdel._changes({}, {path: b"inert source\n"})


def test_requirement_quotations_render_as_inert_single_line(repository):
    quote = "Retained selected context.\n```\nHistorical quotation, not execution."
    raw = prdel.canonical(
        {
            "schema_version": "verifier-prdel-requirements-1",
            "items": [{"id": "context", "text": quote}],
        }
    )
    document = filled(prdel.generate_prdel(*repository, raw, prdel.digest(raw)))
    claim = {"kind": "requirement_quote", "requirement_id": "context", "quote": quote}
    text = prdel.claim_text(claim, document)
    assert "\n" not in text and "\\n" in text
    report = prdel.evaluate_description(
        prdel.render_prdel(document),
        *repository,
        requirements_bytes=raw,
        expected_requirements_digest=prdel.digest(raw),
    )
    assert report["status"] == "PASS"


def test_repeated_selected_source_expansion_is_refused_before_copy(
    repository, monkeypatch
):
    root, _, _ = repository
    (root / "maths.py").write_text(
        "#" + " " * 3000 + "\ndef increment(x):\n    return x + 1\n", encoding="utf-8"
    )
    git(root, "add", ".")
    git(root, "commit", "-qm", "Selected source")
    head = git(root, "rev-parse", "HEAD")
    raw = prdel.canonical(
        {
            "schema_version": "verifier-prdel-requirements-1",
            "items": [
                {
                    "id": str(index),
                    "text": "Selected finite case.",
                    "predicate": {
                        "kind": "finite_python_function",
                        "path": "maths.py",
                        "symbol": "increment",
                        "cases": [{"arguments": [0], "expected": 1}],
                    },
                }
                for index in range(4)
            ],
        }
    )
    monkeypatch.setattr(prdel, "MAX_DOCUMENT_BYTES", 12000)
    with pytest.raises(prdel.PrdelUnavailable, match="aggregate source byte bound"):
        prdel.generate_prdel(root, head, head, raw, prdel.digest(raw))


def test_generation_never_emits_an_unreadable_oversized_template(
    repository, monkeypatch
):
    monkeypatch.setattr(prdel, "MAX_DOCUMENT_BYTES", 2048)
    with pytest.raises(prdel.PrdelUnavailable, match="generated document byte bound"):
        prdel.generate_prdel(*repository)
