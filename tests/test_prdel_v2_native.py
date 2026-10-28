"""Native Pull Request Domain Explanation Language (PRDEL) v2 route tests.

Version two is explicitly selected and source-bound.  Version-one bytes remain
historical behavior, and unavailable compilation or shard capabilities remain
``UNKNOWN`` rather than falling through to a version-one implementation.
"""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from verifier.runtime import gate, prdel
from verifier.runtime.public_cli import main


BASE = "a" * 40
HEAD = "b" * 40


def _select_snapshots(
    monkeypatch: pytest.MonkeyPatch,
    before: dict[str, bytes],
    after: dict[str, bytes],
) -> None:
    monkeypatch.setattr(prdel, "_revision", lambda root, selected: selected)
    monkeypatch.setattr(prdel, "_git", lambda *args, **kwargs: b"")
    monkeypatch.setattr(
        prdel,
        "_snapshot",
        lambda root, revision, **_limits: before if revision == BASE else after,
    )


def _fill(document: dict[str, Any]) -> dict[str, Any]:
    selected = copy.deepcopy(document)
    requirement = selected["requirements"]["items"][0]
    obligations = {row["id"]: row for row in selected["source_obligations"]}
    for record in selected["records"]:
        row = obligations[record["id"]]
        record["requirement_ids"] = [requirement["id"]]
        record["why"] = {
            "requirement_id": requirement["id"],
            "quote": requirement["text"],
        }
        claims: list[dict[str, Any]] = []
        if row["kind"] == "source":
            claims.append(
                {
                    "kind": (
                        "no_source_changes" if row.get("no_change") else "source_delta"
                    ),
                    "obligation_id": row["id"],
                }
            )
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
            prdel.claim_text(claim, selected) for claim in claims
        )
        record["limits"] = list(prdel.LIMITS)
    return selected


def _readme_snapshots() -> tuple[dict[str, bytes], dict[str, bytes]]:
    return (
        {"README.md": b"A retained example.\n"},
        {"README.md": b"A retained bounded example.\n"},
    )


def test_v1_fixture_remains_byte_identical(monkeypatch: pytest.MonkeyPatch) -> None:
    before, after = _readme_snapshots()
    _select_snapshots(monkeypatch, before, after)

    document = prdel.generate_prdel(Path("."), BASE, HEAD)

    assert document["schema_version"] == "verifier-prdel-1"
    assert document["impact_graph"]["schema_version"] == "verifier-prdel-impact-1"
    assert hashlib.sha256(prdel.canonical(document)).hexdigest() == (
        "3e976fd3953722b386469e47543f1e02630a74e5ea21ec82e0c588d7d3c18c8b"
    )


def test_v2_generator_resolves_interned_source_sets(monkeypatch: pytest.MonkeyPatch) -> None:
    before = {
        "producer.py": b"def produce(value):\n    return value\n",
        "consumer.py": (
            b"from producer import produce\n"
            b"def consume(value):\n"
            b"    retained = produce(value)\n"
            b"    return missing(retained)\n"
        ),
    }
    after = dict(before)
    after["producer.py"] = b"def produce(value):\n    return value + 1\n"
    _select_snapshots(monkeypatch, before, after)

    document = prdel.generate_prdel_v2(Path("."), BASE, HEAD)

    assert document["schema_version"] == "verifier-prdel-2"
    assert document["impact_graph"]["schema_version"] == "verifier-prdel-impact-2"
    assert document["impact_graph"]["source_obligation_sets"]
    assert document["impact_graph"]["counters"]["materialized_bytes"] == len(
        prdel.canonical(document["impact_graph"])
    )
    assert document["impact_graph"]["counters"]["materialized_bytes"] <= (
        document["impact_graph"]["bounds"]["max_output_bytes"]
    )
    graph_rows = document["impact_graph"]["obligations"] + document["impact_graph"]["frontier"]
    assert graph_rows and all("source_obligation_set_id" in row for row in graph_rows)
    projected = [row for row in document["source_obligations"] if row["kind"] != "source"]
    assert projected
    assert all(row["source_obligations"] for row in projected)
    assert all("source_obligation_set_id" not in row for row in projected)
    assert any(row["kind"] == "frontier" for row in projected)


def test_v2_final_graph_bound_includes_outer_binding_and_predicates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before, after = _readme_snapshots()
    _select_snapshots(monkeypatch, before, after)
    roomy = prdel.generate_prdel_v2(Path("."), BASE, HEAD)
    exact = roomy["impact_graph"]["counters"]["materialized_bytes"]

    with pytest.raises(prdel.PrdelUnavailable, match="final byte bound exceeded"):
        prdel.generate_prdel_v2(
            Path("."), BASE, HEAD, limits={"max_output_bytes": exact - 10}
        )
    graph = copy.deepcopy(roomy["impact_graph"])
    graph["bounds"]["max_output_bytes"] = 9999
    prdel._finalize_source_bound_graph_size(graph)
    exact_same_width = graph["counters"]["materialized_bytes"]
    graph["bounds"]["max_output_bytes"] = exact_same_width - 1
    with pytest.raises(prdel.PrdelUnavailable, match="final byte bound exceeded"):
        prdel._finalize_source_bound_graph_size(graph)


def test_v2_complete_bounded_document_validates(monkeypatch: pytest.MonkeyPatch) -> None:
    before, after = _readme_snapshots()
    _select_snapshots(monkeypatch, before, after)
    document = _fill(prdel.generate_prdel_v2(Path("."), BASE, HEAD))

    report = prdel.validate_prdel_v2(document, Path("."), BASE, HEAD)
    rendered = prdel.render_prdel_v2(document)
    replay = prdel.evaluate_description_v2(rendered, Path("."), BASE, HEAD)

    assert report["schema_version"] == "verifier-prdel-report-2"
    assert report["status"] == "PASS"
    assert replay["status"] == "PASS"
    assert "verifier-prdel-2" in rendered


def test_v2_no_change_retains_explicit_empty_diff_obligation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshot = {"README.md": b"unchanged\n"}
    _select_snapshots(monkeypatch, snapshot, snapshot)
    document = prdel.generate_prdel_v2(Path("."), BASE, HEAD)

    assert len(document["source_obligations"]) == 1
    assert document["source_obligations"][0]["no_change"] is True
    complete = _fill(document)
    assert complete["records"][0]["claims"][0]["kind"] == "no_source_changes"
    assert prdel.validate_prdel_v2(complete, Path("."), BASE, HEAD)["status"] == "PASS"


def test_v2_substituted_graph_fails_exact_recomputation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before, after = _readme_snapshots()
    _select_snapshots(monkeypatch, before, after)
    document = _fill(prdel.generate_prdel_v2(Path("."), BASE, HEAD))
    document["impact_graph"]["whole_estate_diagnostics"]["omitted_nodes"] += 1

    report = prdel.validate_prdel_v2(document, Path("."), BASE, HEAD)

    assert report["status"] == "FAIL"
    assert any(
        finding["code"] == "STALE_OR_SUBSTITUTED_IMPACT_GRAPH"
        for finding in report["findings"]
    )


def test_v1_and_v2_readers_reject_cross_version_documents(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before, after = _readme_snapshots()
    _select_snapshots(monkeypatch, before, after)
    v1 = _fill(prdel.generate_prdel(Path("."), BASE, HEAD))
    v2 = _fill(prdel.generate_prdel_v2(Path("."), BASE, HEAD))

    assert prdel.validate_prdel(v2, Path("."), BASE, HEAD)["status"] == "FAIL"
    assert prdel.validate_prdel_v2(v1, Path("."), BASE, HEAD)["status"] == "FAIL"


def test_v2_unknown_frontier_cannot_be_closed_by_green_prose(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = {
        "producer.py": b"def produce(value):\n    return value\n",
        "consumer.py": (
            b"from producer import produce\n"
            b"def consume(value):\n    return missing(produce(value))\n"
        ),
    }
    after = dict(before)
    after["producer.py"] = b"def produce(value):\n    return value + 1\n"
    _select_snapshots(monkeypatch, before, after)
    document = _fill(prdel.generate_prdel_v2(Path("."), BASE, HEAD))

    report = prdel.validate_prdel_v2(document, Path("."), BASE, HEAD)

    assert report["status"] != "PASS"
    assert any(
        finding["code"] == "UNRESOLVED_CONTRACT_BOUNDARY"
        and finding["status"] == "UNKNOWN"
        for finding in report["findings"]
    )


def test_v2_malformed_source_set_reference_fails_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before, after = _readme_snapshots()
    _select_snapshots(monkeypatch, before, after)

    def malformed(*args: Any, **kwargs: Any) -> dict[str, Any]:
        from verifier.runtime.prdel_graph import build_source_bound_impact_graph

        graph = build_source_bound_impact_graph(*args, **kwargs)
        graph["frontier"][0]["source_obligation_set_id"] = "source-set:missing"
        return graph

    monkeypatch.setattr(prdel, "_build_source_bound_impact_graph", malformed)

    with pytest.raises(prdel.PrdelError, match="source obligation set"):
        prdel.generate_prdel_v2(Path("."), BASE, HEAD)


def test_v2_shared_source_set_amplification_is_rejected_before_expansion() -> None:
    selected = [f"source:{index:064x}" for index in range(1000)]
    identifier = prdel._source_set_identifier(selected)
    graph = {
        "schema_version": "verifier-prdel-impact-2",
        "source_obligation_sets": [
            {"id": identifier, "source_obligations": selected}
        ],
        "nodes": [],
        "edges": [],
        "obligations": [
            {"id": f"obligation:{index}", "source_obligation_set_id": identifier}
            for index in range(3000)
        ],
        "frontier": [],
    }

    with pytest.raises(prdel.PrdelUnavailable, match="provenance expansion"):
        prdel._resolved_source_bound_rows(
            graph, [{"id": identifier} for identifier in selected]
        )


def test_v2_late_graph_augmentation_is_not_a_valid_emitted_surface(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before, after = _readme_snapshots()
    _select_snapshots(monkeypatch, before, after)
    document = _fill(prdel.generate_prdel_v2(Path("."), BASE, HEAD))
    exact_graph = copy.deepcopy(document["impact_graph"])

    prdel.render_prdel_v2(document)
    assert document["impact_graph"] == exact_graph
    document["impact_graph"]["late_augmentation"] = "unmeasured"
    assert document["impact_graph"]["counters"]["materialized_bytes"] != len(
        prdel.canonical(document["impact_graph"])
    )
    report = prdel.validate_prdel_v2(document, Path("."), BASE, HEAD)
    assert report["status"] == "FAIL"
    assert any(
        finding["code"] == "STALE_OR_SUBSTITUTED_IMPACT_GRAPH"
        for finding in report["findings"]
    )


def test_cli_explicit_v2_selector_reaches_only_v2_generator(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    sentinel = {
        "schema_version": "verifier-prdel-2",
        "binding": {},
        "requirements": {},
        "source_obligations": [],
        "impact_graph": {},
        "records": [],
        "evidence": [],
    }
    monkeypatch.setattr(gate, "_resolve_prdel_coordinates", lambda *args, **kwargs: None)
    monkeypatch.setattr(prdel, "generate_prdel_v2", lambda *args, **kwargs: sentinel)
    monkeypatch.setattr(
        prdel,
        "generate_prdel",
        lambda *args, **kwargs: pytest.fail("v2 selector fell through to v1"),
    )

    result = main(
        [
            "gate", "pr", "--contract", "verifier-prdel-2",
            "--root", ".", "--base", BASE, "--commit", HEAD,
            "--generate", "--template", "--json",
        ]
    )

    assert result == 0
    assert json.loads(capsys.readouterr().out) == sentinel


def test_cli_v2_unwritable_output_falls_back_once_and_returns_unknown(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    sentinel = {
        "schema_version": "verifier-prdel-2",
        "binding": {},
        "requirements": {},
        "source_obligations": [],
        "impact_graph": {},
        "records": [],
        "evidence": [],
    }
    destination = tmp_path / "denied.json"
    original_open = Path.open

    def denied(path: Path, *args: Any, **kwargs: Any) -> Any:
        if path == destination:
            raise OSError("denied output")
        return original_open(path, *args, **kwargs)

    monkeypatch.setattr(gate, "_resolve_prdel_coordinates", lambda *args, **kwargs: None)
    monkeypatch.setattr(prdel, "generate_prdel_v2", lambda *args, **kwargs: sentinel)
    monkeypatch.setattr(Path, "open", denied)

    result = main(
        [
            "gate", "pr", "--contract", "verifier-prdel-2",
            "--root", ".", "--base", BASE, "--commit", HEAD,
            "--generate", "--template", "--output", str(destination),
        ]
    )
    envelope = json.loads(capsys.readouterr().out)

    assert result == 2
    assert not destination.exists()
    assert envelope["schema_version"] == "verifier-prdel-cli-2"
    assert envelope["status"] == "UNKNOWN"
    assert envelope["report"]["findings"][0]["code"] == "UNAVAILABLE_INPUT"


@pytest.mark.parametrize("selector", [[], ["--compilation"], ["--definition", "rules.json"]])
def test_cli_v2_compilation_capabilities_fail_closed_unknown(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    selector: list[str],
) -> None:
    monkeypatch.setattr(gate, "_resolve_prdel_coordinates", lambda *args, **kwargs: None)

    result = main(
        [
            "gate", "pr", "--contract", "verifier-prdel-2",
            "--root", ".", "--base", BASE, "--commit", HEAD,
            "--generate", *selector, "--json",
        ]
    )
    envelope = json.loads(capsys.readouterr().out)

    assert result == 2
    assert envelope["schema_version"] == "verifier-prdel-cli-2"
    assert envelope["status"] == "UNKNOWN"
    assert envelope["report"]["schema_version"] == "verifier-prdel-report-2"
    assert envelope["report"]["findings"][0]["code"] == (
        "PRDEL_V2_CAPABILITY_UNAVAILABLE"
    )


@pytest.mark.parametrize(
    "selector",
    [
        ["--render"],
        ["--impact-dag"],
        ["--compare-document", "comparison.json"],
        ["--manifest", "manifest.json"],
        ["--shard", "shard.json"],
    ],
)
def test_cli_v2_unimplemented_tools_never_fall_through(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    selector: list[str],
) -> None:
    monkeypatch.setattr(gate, "_resolve_prdel_coordinates", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        prdel,
        "generate_prdel",
        lambda *args, **kwargs: pytest.fail("v2 tool selector fell through to v1"),
    )

    result = main(
        [
            "gate", "pr", "--contract", "verifier-prdel-2",
            "--root", ".", "--base", BASE, "--commit", HEAD,
            *selector, "--json",
        ]
    )
    envelope = json.loads(capsys.readouterr().out)

    assert result == 2
    assert envelope["schema_version"] == "verifier-prdel-cli-2"
    assert envelope["status"] == "UNKNOWN"
    assert envelope["report"]["findings"][0]["code"] == (
        "PRDEL_V2_CAPABILITY_UNAVAILABLE"
    )


def test_cli_v2_validates_exact_document_and_emits_v2_envelope(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    tmp_path: Path,
) -> None:
    before, after = _readme_snapshots()
    _select_snapshots(monkeypatch, before, after)
    monkeypatch.setattr(gate, "_resolve_prdel_coordinates", lambda *args, **kwargs: None)
    document = _fill(prdel.generate_prdel_v2(Path("."), BASE, HEAD))
    selected = tmp_path / "prdel-v2.json"
    selected.write_text(json.dumps(document), encoding="utf-8", newline="\n")

    result = main(
        [
            "gate", "pr", "--contract", "verifier-prdel-2",
            "--root", ".", "--base", BASE, "--commit", HEAD,
            "--document", str(selected), "--json",
        ]
    )
    envelope = json.loads(capsys.readouterr().out)
    schema_root = Path(prdel.__file__).resolve().parents[1] / "schemas"
    cli_schema = json.loads(
        (schema_root / "verifier-prdel-cli-2.schema.json").read_text(encoding="utf-8")
    )

    assert result == 0
    assert envelope["schema_version"] == "verifier-prdel-cli-2"
    assert envelope["report"]["schema_version"] == "verifier-prdel-report-2"
    Draft202012Validator(cli_schema).validate(envelope)


def test_v2_schemas_are_packaged_and_discriminate_nested_graph() -> None:
    root = Path(prdel.__file__).resolve().parents[1]
    document = json.loads(
        (root / "schemas/verifier-prdel-2.schema.json").read_text(encoding="utf-8")
    )
    cli = json.loads(
        (root / "schemas/verifier-prdel-cli-2.schema.json").read_text(encoding="utf-8")
    )

    assert document["properties"]["schema_version"]["const"] == "verifier-prdel-2"
    assert document["properties"]["impact_graph"]["properties"]["schema_version"]["const"] == (
        "verifier-prdel-impact-2"
    )
    assert cli["properties"]["schema_version"]["const"] == "verifier-prdel-cli-2"
    assert cli["properties"]["report"]["properties"]["schema_version"]["const"] == (
        "verifier-prdel-report-2"
    )


def test_v2_schema_accepts_generated_document_and_rejects_partial_relabel(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before, after = _readme_snapshots()
    _select_snapshots(monkeypatch, before, after)
    schema_root = Path(prdel.__file__).resolve().parents[1] / "schemas"
    schema = json.loads(
        (schema_root / "verifier-prdel-2.schema.json").read_text(encoding="utf-8")
    )
    validator = Draft202012Validator(schema)
    v2 = prdel.generate_prdel_v2(Path("."), BASE, HEAD)
    v1 = prdel.generate_prdel(Path("."), BASE, HEAD)
    partial = copy.deepcopy(v1)
    partial["schema_version"] = "verifier-prdel-2"

    Draft202012Validator.check_schema(schema)
    validator.validate(v2)
    assert not validator.is_valid(v1)
    assert not validator.is_valid(partial)
