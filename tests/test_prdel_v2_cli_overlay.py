"""Focused retained-fixture checks for the source-bound PRDEL v2 command-line interface (CLI) overlay."""

from __future__ import annotations

import argparse
import hashlib
import inspect
import json
import os
from pathlib import Path
import re
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from verifier.runtime import gate as base_gate
from verifier.runtime import prdel, prdel_v2_shards


BASE = "a" * 40
HEAD = "b" * 40
SOURCE_DIGEST = "c" * 64
V1_COMPATIBILITY_SELECTION = {
    "coordinate": "bc19a6c0d5f83cc55c37a2009c60eea03966ee7f",
    "functions": {
        "gate.run_prdel_gate": "555e2f870beb4b9f8836814a9f6d185376aced15055f4885536864db064c2e2d",
        "gate._handle_prdel_shard_command": "5e68158b441a450d552714713a8e755d69e3d2a1ac3b6248c2e46d9c4cce4033",
        "gate._compare_prdel_documents": "8bc09d2bcdb9c75bb08d69c5513001ab599539694420ce0fcc6a7691b7e67c91",
        "prdel.generate_prdel": "2e2b8b45e80dde1bb803b2bfd42c1f628f431e23631f937d507c7f5be96dce90",
        "prdel.validate_prdel": "21c531457c4545dd75b2db3495cea645ed9d40efad988fbed6ac39aab7a8f49a",
        "prdel.render_prdel": "9f0efff708e1ed3df384cd3317a72a916db1278492ef87102a8f29debc6f2991",
    },
}
OVERLAY_ROOT = Path(__file__).resolve().parents[1]
OVERLAY_GATE = OVERLAY_ROOT / "src/verifier/runtime/gate.py"
OVERLAY_SCHEMA = (
    OVERLAY_ROOT / "src/verifier/schemas/verifier-prdel-cli-2.schema.json"
)


gate = base_gate
CLI_SCHEMA = json.loads(OVERLAY_SCHEMA.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def retained_run() -> Path:
    selected = os.environ["PRDEL_CLI_V2_RETAINED_FIXTURE_ROOT"]
    run_id = os.environ["PRDEL_CLI_V2_RETAINED_RUN_ID"]
    assert re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}", run_id)
    root = Path(selected).resolve()
    assert root.is_dir()
    run = root / run_id
    run.mkdir(exist_ok=False)
    _exclusive_bytes(
        run / "RUN_CONTEXT.json",
        json.dumps(
            {
                "schema_version": "prdel-v2-cli-retained-fixture-1",
                "target_source_coordinate": (
                    "2312413c8610fc0e4a7f8fd147e3af4ac8c5d6e557ea77bfaadbd3261e6ecade"
                ),
                "run_id": run_id,
                "retention": "RETAIN_ALL_CREATED_ARTIFACTS",
            },
            indent=2,
            sort_keys=True,
        ).encode("utf-8")
        + b"\n",
    )
    return run


def _case_dir(run: Path, name: str) -> Path:
    selected = run / name
    selected.mkdir(exist_ok=False)
    return selected


def _exclusive_bytes(path: Path, value: bytes) -> None:
    with path.open("xb") as stream:
        stream.write(value)


def _digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _args(**updates: Any) -> argparse.Namespace:
    selected: dict[str, Any] = {
        "contract": "verifier-prdel-2",
        "root": ".",
        "base": BASE,
        "commit": HEAD,
        "requirements": None,
        "requirements_digest": None,
        "evidence": None,
        "evidence_digest": None,
        "generate": False,
        "template": False,
        "compilation": False,
        "definition": None,
        "compare_document": [],
        "render": False,
        "impact_dag": False,
        "file": None,
        "text": None,
        "document": None,
        "output": None,
        "json": True,
        "manifest": None,
        "manifest_digest": None,
        "shard": [],
        "shard_digest": [],
        "source_digest": None,
        "compilation_residuals": None,
        "packet_budget_bytes": None,
    }
    selected.update(updates)
    return argparse.Namespace(**selected)


def _logical_report(status: str, reason: str) -> dict[str, Any]:
    return {
        "schema_version": "verifier-prdel-report-2",
        "status": status,
        "source_grounding_status": status,
        "semantic_status": status,
        "verdict_scope": "GATE_OBLIGATION_FULFILLMENT",
        "proposition_truth": "NOT_INFERRED_FROM_MISSING_EVIDENCE",
        "required_checks_not_run": 1 if status == "UNKNOWN" else 0,
        "claim_boundary": "Focused source-bound CLI wiring result only.",
        "findings": [
            {
                "code": "FOCUSED_" + status,
                "category": "FOCUSED_" + status,
                "status": status,
                "reason": reason,
                "question": "Retain and inspect the focused result.",
            }
        ],
    }


def _shard_report(
    status: str,
    *,
    transport: str,
    reason: str | None = None,
) -> dict[str, Any]:
    selected = prdel_v2_shards._report(status, transport, reason)
    if transport == "PASS":
        selected["coverage_status"] = "PASS"
        selected["recomposition_status"] = "PASS"
        selected["logical_report"] = _logical_report(status, reason or status)
    return selected


def _json_result(
    args: argparse.Namespace, capsys: pytest.CaptureFixture[str]
) -> tuple[int, dict[str, Any]]:
    result = gate._handle_prdel_command(args)
    envelope = json.loads(capsys.readouterr().out)
    Draft202012Validator(CLI_SCHEMA).validate(envelope)
    return result, envelope


def _packet(case: Path) -> tuple[Path, list[Path], bytes, list[bytes]]:
    manifest_bytes = prdel.canonical(
        {"document_header": {"binding": {"source_digest": SOURCE_DIGEST}}}
    )
    shard_bytes = [b'{"index":0}\n', b'{"index":1}\n']
    manifest_path = case / "manifest.json"
    shard_paths = [case / "shard-0.json", case / "shard-1.json"]
    _exclusive_bytes(manifest_path, manifest_bytes)
    for path, raw in zip(shard_paths, shard_bytes):
        _exclusive_bytes(path, raw)
    return manifest_path, shard_paths, manifest_bytes, shard_bytes


def _packet_args(
    manifest_path: Path,
    shard_paths: list[Path],
    manifest_bytes: bytes,
    shard_bytes: list[bytes],
    **updates: Any,
) -> argparse.Namespace:
    selected = {
        "manifest": str(manifest_path),
        "manifest_digest": _digest(manifest_bytes),
        "shard": [str(path) for path in shard_paths],
        "shard_digest": [_digest(raw) for raw in shard_bytes],
        "source_digest": SOURCE_DIGEST,
        "packet_budget_bytes": 65536,
    }
    selected.update(updates)
    return _args(**selected)


def test_render_is_exact_and_carries_logical_result(
    retained_run: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    case = _case_dir(retained_run, "render")
    document = {
        "schema_version": "verifier-prdel-2",
        "binding": {
            "base": BASE,
            "head": HEAD,
            "source_digest": SOURCE_DIGEST,
            "requirements_digest": "d" * 64,
        },
        "requirements": {"schema_version": "verifier-prdel-requirements-1", "items": []},
        "source_obligations": [],
        "impact_graph": {},
        "records": [],
        "evidence": [],
    }
    document_path = case / "document.json"
    _exclusive_bytes(
        document_path,
        json.dumps(document, sort_keys=True).encode("utf-8") + b"\n",
    )
    expected = prdel.render_prdel_v2(document)
    observed: dict[str, Any] = {}

    def run_gate(body: str, **selected: Any) -> tuple[dict[str, Any], list[str]]:
        observed["body"] = body
        observed["document"] = selected["document"]
        return _logical_report("PASS", "exact render accepted"), ["exact render accepted"]

    monkeypatch.setattr(gate, "_resolve_prdel_coordinates", lambda *a, **k: None)
    monkeypatch.setattr(gate, "run_prdel_gate_v2", run_gate)
    result, envelope = _json_result(
        _args(render=True, document=str(document_path)), capsys
    )
    assert result == 0
    assert envelope["operation"] == "render"
    assert envelope["rendered"] == expected
    assert envelope["report"]["status"] == "PASS"
    assert observed == {"body": expected, "document": document}

    def fail_gate(body: str, **selected: Any) -> tuple[dict[str, Any], list[str]]:
        assert body == expected
        return _logical_report("FAIL", "logical refutation retained"), [
            "logical refutation retained"
        ]

    monkeypatch.setattr(gate, "run_prdel_gate_v2", fail_gate)
    result = gate._handle_prdel_command(
        _args(render=True, document=str(document_path), json=False)
    )
    assert result == 1
    assert capsys.readouterr().out == expected


def test_shard_cli_calls_existing_validator_and_carries_pass_and_fail(
    retained_run: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    case = _case_dir(retained_run, "shard-pass-fail")
    manifest_path, shard_paths, manifest_bytes, shard_bytes = _packet(case)
    observed: list[tuple[bytes, list[bytes], str, str]] = []
    selected_status = {"value": "PASS"}

    def validate(
        manifest: bytes,
        shards: list[bytes],
        root: Path,
        base: str,
        head: str,
        **selected: Any,
    ) -> dict[str, Any]:
        observed.append((manifest, list(shards), base, head))
        assert root == Path(".")
        assert selected["requirements_bytes"] is None
        return _shard_report(
            selected_status["value"],
            transport="PASS",
            reason="logical " + selected_status["value"].lower(),
        )

    monkeypatch.setattr(gate, "_resolve_prdel_coordinates", lambda *a, **k: None)
    monkeypatch.setattr(prdel_v2_shards, "validate_prdel_v2_shards", validate)
    args = _packet_args(
        manifest_path, shard_paths, manifest_bytes, shard_bytes
    )
    result, envelope = _json_result(args, capsys)
    assert result == 0
    assert envelope["operation"] == "validate-shards"
    assert envelope["status"] == "PASS"
    assert envelope["shard_report"]["transport_status"] == "PASS"
    assert observed[-1] == (manifest_bytes, shard_bytes, BASE, HEAD)

    selected_status["value"] = "FAIL"
    result, envelope = _json_result(args, capsys)
    assert result == 1
    assert envelope["status"] == "FAIL"
    assert envelope["report"]["status"] == "FAIL"
    assert envelope["shard_report"]["logical_report"]["status"] == "FAIL"


def test_shard_cli_refutations_and_unknowns_are_fail_closed(
    retained_run: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    case = _case_dir(retained_run, "shard-refutations")
    manifest_path, shard_paths, manifest_bytes, shard_bytes = _packet(case)
    mode = {"value": "exact"}

    def validate(
        manifest: bytes,
        shards: list[bytes],
        root: Path,
        base: str,
        head: str,
        **selected: Any,
    ) -> dict[str, Any]:
        if len(shards) < len(shard_bytes):
            return _shard_report(
                "UNKNOWN", transport="UNKNOWN", reason="selected shard omitted"
            )
        if shards != shard_bytes:
            return _shard_report(
                "FAIL", transport="FAIL", reason="ordered shard bytes differ"
            )
        if mode["value"] in {"parse", "frontier", "analysis"}:
            return _shard_report(
                "UNKNOWN",
                transport="PASS",
                reason=mode["value"] + " bound remains unresolved",
            )
        return _shard_report("PASS", transport="PASS")

    monkeypatch.setattr(gate, "_resolve_prdel_coordinates", lambda *a, **k: None)
    monkeypatch.setattr(prdel_v2_shards, "validate_prdel_v2_shards", validate)

    omitted = _packet_args(
        manifest_path, shard_paths[:1], manifest_bytes, shard_bytes[:1]
    )
    result, envelope = _json_result(omitted, capsys)
    assert (result, envelope["status"]) == (2, "UNKNOWN")

    reordered = _packet_args(
        manifest_path,
        list(reversed(shard_paths)),
        manifest_bytes,
        list(reversed(shard_bytes)),
    )
    result, envelope = _json_result(reordered, capsys)
    assert (result, envelope["status"]) == (1, "FAIL")

    substituted = _packet_args(
        manifest_path,
        shard_paths,
        manifest_bytes,
        shard_bytes,
        shard_digest=[_digest(shard_bytes[0]), "0" * 64],
    )
    result, envelope = _json_result(substituted, capsys)
    assert (result, envelope["status"]) == (1, "FAIL")

    cross_bound = _packet_args(
        manifest_path,
        shard_paths,
        manifest_bytes,
        shard_bytes,
        source_digest="e" * 64,
    )
    result, envelope = _json_result(cross_bound, capsys)
    assert (result, envelope["status"]) == (1, "FAIL")

    capacity = _packet_args(
        manifest_path,
        shard_paths,
        manifest_bytes,
        shard_bytes,
        packet_budget_bytes=len(manifest_bytes) - 1,
    )
    result, envelope = _json_result(capacity, capsys)
    assert (result, envelope["status"]) == (2, "UNKNOWN")

    unavailable = _packet_args(
        case / "selected-but-unavailable-manifest.json",
        shard_paths,
        manifest_bytes,
        shard_bytes,
    )
    result, envelope = _json_result(unavailable, capsys)
    assert (result, envelope["status"]) == (2, "UNKNOWN")

    for unresolved in ("parse", "frontier", "analysis"):
        mode["value"] = unresolved
        result, envelope = _json_result(
            _packet_args(manifest_path, shard_paths, manifest_bytes, shard_bytes),
            capsys,
        )
        assert (result, envelope["status"]) == (2, "UNKNOWN")
        assert unresolved in envelope["shard_report"]["reason"]


def test_unsupported_v2_capabilities_and_selected_v1_functions_remain_unchanged(
    retained_run: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    _case_dir(retained_run, "compatibility")
    assert re.fullmatch(
        r"[0-9a-f]{40}|[0-9a-f]{64}",
        V1_COMPATIBILITY_SELECTION["coordinate"],
    )
    selected_functions = {
        "gate.run_prdel_gate": base_gate.run_prdel_gate,
        "gate._handle_prdel_shard_command": base_gate._handle_prdel_shard_command,
        "gate._compare_prdel_documents": base_gate._compare_prdel_documents,
        "prdel.generate_prdel": prdel.generate_prdel,
        "prdel.validate_prdel": prdel.validate_prdel,
        "prdel.render_prdel": prdel.render_prdel,
    }
    observed = {
        name: _digest(inspect.getsource(function).encode("utf-8"))
        for name, function in selected_functions.items()
    }
    assert observed == V1_COMPATIBILITY_SELECTION["functions"]

    monkeypatch.setattr(gate, "_resolve_prdel_coordinates", lambda *a, **k: None)
    monkeypatch.setattr(
        gate,
        "_handle_prdel_shard_command",
        lambda args: pytest.fail("v2 fell through to the v1 shard route"),
    )
    for selected in (
        {"impact_dag": True},
        {"compare_document": ["comparison.json"]},
        {"compilation": True},
        {"definition": "rules.json"},
    ):
        result, envelope = _json_result(_args(**selected), capsys)
        assert (result, envelope["status"]) == (2, "UNKNOWN")
        assert envelope["report"]["findings"][0]["code"] == (
            "PRDEL_V2_CAPABILITY_UNAVAILABLE"
        )

    assert CLI_SCHEMA["properties"]["report"]["properties"]["schema_version"][
        "const"
    ] == "verifier-prdel-report-2"
    assert CLI_SCHEMA["properties"]["operation"]["enum"] == [
        "render",
        "validate-shards",
    ]
    assert Path(gate.__file__).resolve() == OVERLAY_GATE.resolve()
    assert Path(prdel.__file__).resolve().relative_to(OVERLAY_ROOT) == Path(
        "src/verifier/runtime/prdel.py"
    )
    assert Path(prdel_v2_shards.__file__).resolve().relative_to(OVERLAY_ROOT) == Path(
        "src/verifier/runtime/prdel_v2_shards.py"
    )
    assert OVERLAY_GATE.resolve().relative_to(OVERLAY_ROOT) == Path(
        "src/verifier/runtime/gate.py"
    )
    assert OVERLAY_SCHEMA.resolve().relative_to(OVERLAY_ROOT) == Path(
        "src/verifier/schemas/verifier-prdel-cli-2.schema.json"
    )
    assert not OVERLAY_ROOT.joinpath("Raven").exists()
    assert "Raven" not in OVERLAY_GATE.read_text(encoding="utf-8")
    assert "Raven" not in OVERLAY_SCHEMA.read_text(encoding="utf-8")
