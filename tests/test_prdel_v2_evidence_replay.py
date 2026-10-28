"""Independent replay for source-bound PRDEL version two.

Pull Request Domain Explanation Language (PRDEL); JavaScript Object Notation
(JSON); Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD).

The replay plan selects fixed pytest node identifiers.  It cannot carry a test
outcome, arbitrary command, import target, or pytest option.  A passing replay
establishes only bounded explanation-obligation fulfillment for the selected
commits; it does not establish runtime correctness or checker independence.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from typing import Any

import pytest

from verifier.runtime import gate, prdel, prdel_evidence
from verifier.runtime.public_cli import main


def _git(root: Path, *arguments: str) -> str:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    return result.stdout.strip()


def _repository(
    tmp_path: Path, tests: bytes | None = None
) -> tuple[Path, str, str, bytes]:
    root = tmp_path / "repository"
    (root / "src/example").mkdir(parents=True)
    (root / "tests").mkdir()
    (root / "src/example/value.py").write_text(
        "VALUE = 1\n", encoding="utf-8", newline="\n"
    )
    if tests is None:
        tests = (
            "from example.value import VALUE\n\n"
            "def test_unit():\n    assert VALUE == 2\n\n"
            "def test_integration():\n    assert VALUE + 1 == 3\n\n"
            "def test_regression():\n    assert VALUE != 1\n\n"
            "def test_preventative():\n    assert isinstance(VALUE, int)\n"
        ).encode("utf-8")
    (root / "tests/test_value.py").write_bytes(tests)
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "PRDEL test")
    _git(root, "config", "user.email", "prdel" + "@" + "example.invalid")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "Add base")
    base = _git(root, "rev-parse", "HEAD")
    (root / "src/example/value.py").write_text(
        "VALUE = 2\n", encoding="utf-8", newline="\n"
    )
    _git(root, "add", "src/example/value.py")
    _git(root, "commit", "-q", "-m", "Change value")
    return root, base, _git(root, "rev-parse", "HEAD"), tests


def _json_repository(tmp_path: Path) -> tuple[Path, str, str, bytes]:
    root = tmp_path / "json-repository"
    (root / "config").mkdir(parents=True)
    (root / "tests").mkdir()
    tests = (
        b"def test_unit():\n    assert True\n"
        b"def test_integration():\n    assert True\n"
        b"def test_regression():\n    assert True\n"
        b"def test_preventative():\n    assert True\n"
    )
    (root / "tests/test_value.py").write_bytes(tests)
    (root / "config/example.json").write_text('{"value": 1}\n', encoding="utf-8")
    _git(root, "init", "-q")
    _git(root, "config", "user.name", "PRDEL test")
    _git(root, "config", "user.email", "prdel" + "@" + "example.invalid")
    _git(root, "add", ".")
    _git(root, "commit", "-q", "-m", "Add base")
    base = _git(root, "rev-parse", "HEAD")
    (root / "config/example.json").write_text('{"value": 2}\n', encoding="utf-8")
    _git(root, "add", "config/example.json")
    _git(root, "commit", "-q", "-m", "Change configuration")
    return root, base, _git(root, "rev-parse", "HEAD"), tests


def _fill(document: dict[str, Any], check_ids: dict[str, str]) -> dict[str, Any]:
    requirement = document["requirements"]["items"][0]
    obligations = {row["id"]: row for row in document["source_obligations"]}
    for record in document["records"]:
        row = obligations[record["id"]]
        record["requirement_ids"] = [requirement["id"]]
        record["why"] = {
            "requirement_id": requirement["id"],
            "quote": requirement["text"],
        }
        claims: list[dict[str, Any]] = []
        if row["kind"] == "source":
            claims.append({"kind": "source_delta", "obligation_id": row["id"]})
        elif row["kind"] == "contract":
            claims.append({"kind": "ast_relationship", "edge_id": row["edge_id"]})
        claims.append(
            {
                "kind": "requirement_quote",
                "requirement_id": requirement["id"],
                "quote": requirement["text"],
            }
        )
        record["claims"] = claims
        record["summary"] = "\n".join(
            prdel.claim_text(claim, document) for claim in claims
        )
        record["limits"] = list(prdel.LIMITS)
        record["coverage"] = {
            layer: {
                "status": "EXECUTED",
                "evidence_ids": [identifier],
                "reason": "",
            }
            for layer, identifier in check_ids.items()
        }
    return document


def _plan(
    document: dict[str, Any],
    tests: bytes,
    *,
    nodeids: dict[str, str] | None = None,
    frontier_resolutions: list[dict[str, Any]] | None = None,
    limits: dict[str, int] | None = None,
) -> tuple[dict[str, str], dict[str, Any], bytes]:
    layers = ("unit", "integration", "regression", "preventative")
    check_ids = {layer: "check:" + layer for layer in layers}
    selected_nodeids = nodeids or {
        layer: f"tests/test_value.py::test_{layer}" for layer in layers
    }
    obligation_ids = sorted(row["id"] for row in document["source_obligations"])
    value = {
        "schema_version": "verifier-prdel-replay-plan-1",
        "binding": document["binding"],
        "checks": [
            {
                "id": check_ids[layer],
                "layer": layer,
                "obligation_ids": obligation_ids,
                "runner": "pytest-nodeids-1",
                "nodeids": [selected_nodeids[layer]],
                "selected_files": [
                    {
                        "path": "tests/test_value.py",
                        "sha256": hashlib.sha256(tests).hexdigest(),
                    }
                ],
            }
            for layer in layers
        ],
        "frontier_resolutions": frontier_resolutions or [],
        "limits": limits
        or {
            "timeout_seconds": 30,
            "max_output_bytes": 1048576,
            "max_tests": 16,
            "max_files": 16,
        },
    }
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return check_ids, value, raw


def _validate(
    document: dict[str, Any], root: Path, base: str, head: str, raw: bytes
) -> dict[str, Any]:
    return prdel.validate_prdel_v2(
        document,
        root,
        base,
        head,
        replay_plan_bytes=raw,
        expected_replay_plan_digest=hashlib.sha256(raw).hexdigest(),
    )


def test_exact_plan_replay_can_fulfil_executable_prdel_obligations(
    tmp_path: Path,
) -> None:
    root, base, head, tests = _repository(tmp_path)
    document = prdel.generate_prdel_v2(root, base, head)
    assert not [
        row for row in document["source_obligations"] if row["kind"] == "frontier"
    ]
    check_ids, _value, raw = _plan(document, tests)
    _fill(document, check_ids)
    report = _validate(document, root, base, head, raw)

    assert report["status"] == "PASS"
    assert report["coverage"]["execution_authentication"] == "VERIFIER_REPLAYED"
    assert report["execution_provenance"] == "VERIFIER_REPLAYED_EXACT_HEAD"
    assert report["runtime_correctness"] == "NOT_ESTABLISHED"
    assert report["checker_independence"] == "NOT_ESTABLISHED"
    assert report["whole_estate_completeness"] == "NOT_ESTABLISHED"


def test_carried_pass_receipts_cannot_authenticate_their_own_execution(
    tmp_path: Path,
) -> None:
    root, base, head, tests = _repository(tmp_path)
    document = prdel.generate_prdel_v2(root, base, head)
    check_ids, _plan_value, _raw = _plan(document, tests)
    _fill(document, check_ids)
    obligations = sorted(row["id"] for row in document["source_obligations"])
    document["evidence"] = [
        {
            "id": identifier,
            "kind": "test_result",
            "layer": layer,
            "status": "PASS",
            "command": "claimed external run",
            "result_digest": "a" * 64,
            **document["binding"],
            "obligation_ids": obligations,
        }
        for layer, identifier in check_ids.items()
    ]

    report = prdel.validate_prdel_v2(document, root, base, head)

    assert report["status"] == "UNKNOWN"
    assert report["coverage"]["execution_authentication"] == "NOT_ESTABLISHED"
    assert {row["code"] for row in report["findings"]} >= {
        "EXECUTION_NOT_ESTABLISHED",
        "EXECUTED_VALIDATION_NOT_ESTABLISHED",
    }


@pytest.mark.parametrize("mutation", ["digest", "nodeid-option"])
def test_replay_rejects_stale_digest_and_nodeid_option_injection(
    tmp_path: Path, mutation: str
) -> None:
    root, base, head, tests = _repository(tmp_path)
    document = prdel.generate_prdel_v2(root, base, head)
    check_ids, plan, raw = _plan(document, tests)
    _fill(document, check_ids)
    expected = hashlib.sha256(raw).hexdigest()
    if mutation == "digest":
        expected = "0" * 64
    else:
        plan["checks"][0]["nodeids"] = ["-k"]
        raw = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode("utf-8")
        expected = hashlib.sha256(raw).hexdigest()

    report = prdel.validate_prdel_v2(
        document,
        root,
        base,
        head,
        replay_plan_bytes=raw,
        expected_replay_plan_digest=expected,
    )

    assert report["status"] == "FAIL"
    assert "INVALID_OR_UNAVAILABLE_INPUT" in {
        row["code"] for row in report["findings"]
    }


@pytest.mark.parametrize(
    ("tests", "nodeid"),
    [
        (
            b"def test_unit():\n    assert False\n",
            "tests/test_value.py::test_unit",
        ),
        (
            b"import pytest\n" + b"@" + b"pytest.mark.skip\ndef test_unit():\n    pass\n",
            "tests/test_value.py::test_unit",
        ),
        (
            b"import pytest\n" + b"@" + b"pytest.mark.xfail\ndef test_unit():\n    assert False\n",
            "tests/test_value.py::test_unit",
        ),
        (b"def test_other():\n    pass\n", "tests/test_value.py::test_unit"),
    ],
    ids=("failure", "skip", "xfail", "zero-selected"),
)
def test_non_green_replay_never_authenticates_pass(
    tmp_path: Path, tests: bytes, nodeid: str
) -> None:
    root, base, head, selected = _repository(tmp_path, tests)
    document = prdel.generate_prdel_v2(root, base, head)
    nodeids = {layer: nodeid for layer in prdel_evidence.LAYERS}
    check_ids, _plan_value, raw = _plan(document, selected, nodeids=nodeids)
    _fill(document, check_ids)

    report = _validate(document, root, base, head, raw)

    assert report["status"] == "FAIL"
    assert report["coverage"]["execution_authentication"] != "VERIFIER_REPLAYED"


@pytest.mark.parametrize("failure", ["timeout", "output", "tool"])
def test_replay_timeout_output_and_tool_outage_remain_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: str,
) -> None:
    tests = (
        b"import time\n"
        b"def test_unit():\n"
        + (b"    time.sleep(2)\n" if failure == "timeout" else b"    print('x' * 1000)\n")
        + b"    assert True\n"
        b"def test_integration():\n    assert True\n"
        b"def test_regression():\n    assert True\n"
        b"def test_preventative():\n    assert True\n"
    )
    root, base, head, selected = _repository(tmp_path, tests)
    document = prdel.generate_prdel_v2(root, base, head)
    limits = {
        "timeout_seconds": 1 if failure == "timeout" else 30,
        "max_output_bytes": 1 if failure == "output" else 1048576,
        "max_tests": 16,
        "max_files": 16,
    }
    _ids, plan, raw = _plan(document, selected, limits=limits)
    plan["checks"] = plan["checks"][:1]
    raw = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode("utf-8")
    before = prdel._snapshot(root, base)
    after = prdel._snapshot(root, head)
    if failure == "tool":
        monkeypatch.setattr(
            prdel_evidence.subprocess,
            "Popen",
            lambda *args, **kwargs: (_ for _ in ()).throw(OSError("unavailable")),
        )

    assessed = prdel_evidence.replay_plan(
        raw,
        hashlib.sha256(raw).hexdigest(),
        document["binding"],
        document["source_obligations"],
        before,
        after,
    )

    assert any(result.status == "UNKNOWN" for result in assessed.results)
    assert all(result.status != "PASS" for result in assessed.results[:1])


def test_replay_detects_private_source_mutation(tmp_path: Path) -> None:
    tests = (
        b"from pathlib import Path\n"
        b"def test_unit():\n"
        b"    Path('src/example/value.py').write_text('MUTATED')\n"
        b"def test_integration():\n    assert True\n"
        b"def test_regression():\n    assert True\n"
        b"def test_preventative():\n    assert True\n"
    )
    root, base, head, selected = _repository(tmp_path, tests)
    document = prdel.generate_prdel_v2(root, base, head)
    _ids, _plan_value, raw = _plan(document, selected)

    assessed = prdel_evidence.replay_plan(
        raw,
        hashlib.sha256(raw).hexdigest(),
        document["binding"],
        document["source_obligations"],
        prdel._snapshot(root, base),
        prdel._snapshot(root, head),
    )

    assert assessed.results[0].status == "FAIL"
    assert assessed.results[0].reason_code == "SOURCE_MUTATED_DURING_REPLAY"
    assert assessed.issues[0].code == "SOURCE_MUTATED_DURING_REPLAY"


@pytest.mark.parametrize(
    ("selection", "expected"),
    [("closed-json", "PASS"), ("unselected", "UNKNOWN"), ("mismatched", "FAIL")],
)
def test_frontiers_require_matching_closed_mechanical_replay(
    tmp_path: Path, selection: str, expected: str
) -> None:
    root, base, head, tests = _json_repository(tmp_path)
    document = prdel.generate_prdel_v2(root, base, head)
    frontiers = [
        row for row in document["source_obligations"] if row["kind"] == "frontier"
    ]
    assert frontiers and all(
        row["frontier_kind"] == "unsupported_language" for row in frontiers
    )
    mechanism = (
        "exact-utf8-plus-replay-1"
        if selection == "mismatched"
        else "exact-json-plus-replay-1"
    )
    resolutions = (
        []
        if selection == "unselected"
        else [
            {
                "frontier_id": row["id"],
                "mechanism_id": mechanism,
                "source_obligation_ids": sorted(row["source_obligations"]),
                "check_ids": sorted(
                    "check:" + layer for layer in prdel_evidence.LAYERS
                ),
            }
            for row in frontiers
        ]
    )
    check_ids, _value, raw = _plan(
        document, tests, frontier_resolutions=resolutions
    )
    _fill(document, check_ids)
    rows = {row["id"]: row for row in document["source_obligations"]}
    for record in document["records"]:
        if rows[record["id"]]["kind"] != "frontier":
            continue
        claim = {
            "kind": "frontier_resolution",
            "frontier_id": record["id"],
            "mechanism_id": mechanism,
        }
        record["claims"].insert(0, claim)
        record["summary"] = "\n".join(
            prdel.claim_text(item, document) for item in record["claims"]
        )

    report = _validate(document, root, base, head, raw)

    assert report["status"] == expected
    assert report["runtime_correctness"] == "NOT_ESTABLISHED"


def test_analysis_and_resource_frontiers_are_not_evidence_dischargeable() -> None:
    obligation = "source:" + "a" * 64
    frontier = {
        "id": "frontier:analysis-bound",
        "kind": "frontier",
        "frontier_kind": "analysis_bound",
        "path": "<analysis-frontier>",
        "source_obligations": [obligation],
    }
    results = tuple(
        prdel_evidence.ReplayResult(
            "check:" + layer,
            layer,
            "PASS",
            (frontier["id"], obligation),
            "python -m pytest <fixed-selected-nodeids>",
            "b" * 64,
            {
                "base": "1" * 40,
                "head": "2" * 40,
                "source_digest": "3" * 64,
                "requirements_digest": "4" * 64,
            },
            "VERIFIER_REPLAYED",
        )
        for layer in prdel_evidence.LAYERS
    )
    plan = {
        "frontier_resolutions": [
            {
                "frontier_id": frontier["id"],
                "mechanism_id": "selected-replay-1",
                "source_obligation_ids": [obligation],
                "check_ids": sorted(item.identifier for item in results),
            }
        ]
    }

    statuses, _mechanisms, issues = prdel_evidence._frontier_statuses(
        plan, [frontier], {}, {}, results
    )

    assert statuses[frontier["id"]] == "UNKNOWN"
    assert issues[0].code == "NON_DISCHARGEABLE_ANALYSIS_FRONTIER"


def test_validation_recomputes_identical_selected_graph_limits(tmp_path: Path) -> None:
    root, base, head, _tests = _repository(tmp_path)
    selected = {
        "max_nodes": 9999,
        "max_edges": 19999,
        "max_operations": 199999,
        "max_output_bytes": 8000000,
    }
    document = prdel.generate_prdel_v2(root, base, head, limits=selected)

    same = prdel.validate_prdel_v2(document, root, base, head, limits=selected)
    changed = prdel.validate_prdel_v2(
        document,
        root,
        base,
        head,
        limits={**selected, "max_operations": selected["max_operations"] - 1},
    )

    assert "STALE_OR_SUBSTITUTED_IMPACT_GRAPH" not in {
        row["code"] for row in same["findings"]
    }
    assert changed["status"] == "FAIL"
    assert "STALE_OR_SUBSTITUTED_IMPACT_GRAPH" in {
        row["code"] for row in changed["findings"]
    }


def test_cli_graph_limit_selection_is_explicit_and_capped() -> None:
    selected = argparse.Namespace(
        prdel_max_nodes=200000,
        prdel_max_edges=400000,
        prdel_max_operations=50000000,
        prdel_max_output_bytes=33554432,
    )
    assert gate._prdel_v2_graph_limits(selected) == {
        "max_nodes": 200000,
        "max_edges": 400000,
        "max_operations": 50000000,
        "max_output_bytes": 33554432,
    }
    selected.prdel_max_nodes += 1
    with pytest.raises(ValueError, match="fixed cap"):
        gate._prdel_v2_graph_limits(selected)
    selected.prdel_max_nodes = None
    with pytest.raises(ValueError, match="selected together"):
        gate._prdel_v2_graph_limits(selected)
    defaults = argparse.Namespace(
        prdel_max_nodes=None,
        prdel_max_edges=None,
        prdel_max_operations=None,
        prdel_max_output_bytes=None,
    )
    with pytest.raises(ValueError, match="selected together"):
        gate._prdel_v2_graph_limits(defaults, require_explicit=True)


def test_cli_replay_route_uses_selected_plan_and_identical_graph_limits(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    root, base, head, tests = _repository(tmp_path)
    limits = {
        "max_nodes": 10000,
        "max_edges": 20000,
        "max_operations": 200000,
        "max_output_bytes": 8388608,
    }
    document = prdel.generate_prdel_v2(root, base, head, limits=limits)
    check_ids, _value, raw = _plan(document, tests)
    _fill(document, check_ids)
    document_path = tmp_path / "document.json"
    plan_path = tmp_path / "plan.json"
    document_path.write_bytes(prdel.canonical(document))
    plan_path.write_bytes(raw)

    result = main(
        [
            "gate",
            "pr",
            "--contract",
            "verifier-prdel-2",
            "--root",
            str(root),
            "--base",
            base,
            "--commit",
            head,
            "--document",
            str(document_path),
            "--replay-plan",
            str(plan_path),
            "--replay-plan-digest",
            hashlib.sha256(raw).hexdigest(),
            "--prdel-max-nodes",
            str(limits["max_nodes"]),
            "--prdel-max-edges",
            str(limits["max_edges"]),
            "--prdel-max-operations",
            str(limits["max_operations"]),
            "--prdel-max-output-bytes",
            str(limits["max_output_bytes"]),
            "--json",
        ]
    )
    envelope = json.loads(capsys.readouterr().out)

    assert result == 0, envelope
    assert envelope["status"] == "PASS"
    assert envelope["report"]["execution_provenance"] == (
        "VERIFIER_REPLAYED_EXACT_HEAD"
    )
    assert envelope["report"]["coverage"]["execution_authentication"] == (
        "VERIFIER_REPLAYED"
    )

