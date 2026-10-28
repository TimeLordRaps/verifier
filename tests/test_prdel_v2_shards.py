"""Bounded transport tests for a complete source-derived PRDEL v2 document."""

from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from verifier.runtime import prdel, prdel_v2_shards


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
            prdel.claim_text(claim, selected) for claim in claims
        )
        record["limits"] = list(prdel.LIMITS)
    return selected


def _cross_partition_document(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    before = {
        "producer.py": b"def produce(value):\n    return value\n",
        "consumer.py": (
            b"from producer import produce\n"
            b"def consume(value):\n    return produce(value)\n"
        ),
    }
    after = {
        "producer.py": b"def produce(value):\n    return value + 1\n",
        "consumer.py": (
            b"from producer import produce\n"
            b"def consume(value):\n    return produce(value) * 2\n"
        ),
    }
    for index in range(18):
        name = f"notes/{index:02d}.md"
        before[name] = f"before {index}\n".encode()
        after[name] = f"after {index}\n".encode()
    _select_snapshots(monkeypatch, before, after)
    document = _fill(prdel.generate_prdel_v2(Path("."), BASE, HEAD))
    # Keep the global graph/header fixed while making the aligned record wire
    # large enough to exercise more than two transport shards.
    for record in document["records"]:
        record["summary"] += "x" * 8000
    return document


def _wire(packet: dict[str, Any]) -> tuple[bytes, list[bytes]]:
    return (
        prdel.canonical(packet["manifest"]),
        [prdel.canonical(shard) for shard in packet["shards"]],
    )


def test_v2_transport_recomposes_exact_document_and_cross_partition_edges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = _cross_partition_document(monkeypatch)
    packet = prdel_v2_shards.partition_prdel_v2_document(
        document, max_artifact_bytes=65536
    )
    manifest_bytes, shard_bytes = _wire(packet)

    reconstructed = prdel_v2_shards.reconstruct_prdel_v2_document(
        manifest_bytes, shard_bytes
    )
    report = prdel_v2_shards.validate_prdel_v2_shards(
        manifest_bytes, shard_bytes, Path("."), BASE, HEAD
    )

    assert len(shard_bytes) > 1
    assert reconstructed == document
    assert any(
        row.get("relationship") == "import"
        for row in reconstructed["impact_graph"]["edges"]
    )
    assert report["transport_status"] == "PASS"
    assert report["coverage_status"] == "PASS"
    assert report["recomposition_status"] == "PASS"
    assert report["logical_report"]["status"] == "FAIL"


def test_v2_transport_manifest_exactly_covers_every_section(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = _cross_partition_document(monkeypatch)
    packet = prdel_v2_shards.partition_prdel_v2_document(
        document, max_artifact_bytes=65536
    )
    manifest = packet["manifest"]

    assert manifest["schema_version"] == "verifier-prdel-v2-shard-manifest-1"
    assert manifest["logical_document_sha256"] == prdel.digest(
        prdel.canonical(document)
    )
    assert manifest["logical_document_bytes"] == len(prdel.canonical(document))
    assert [row["index"] for row in manifest["shards"]] == list(
        range(len(packet["shards"]))
    )
    assert manifest["document_header"]["impact_graph"] == document["impact_graph"]
    assert manifest["logical_obligation_ids"] == [
        row["id"] for row in document["source_obligations"]
    ]
    assert all(
        [row["id"] for row in shard["source_obligations"]]
        == [row["id"] for row in shard["records"]]
        for shard in packet["shards"]
    )
    assert all(len(prdel.canonical(shard)) <= 65536 for shard in packet["shards"])
    assert len(prdel.canonical(manifest)) <= 65536


@pytest.mark.parametrize("mutation", ["duplicate", "reorder"])
def test_v2_transport_refutes_nonunique_or_reordered_shard_inventory(
    monkeypatch: pytest.MonkeyPatch, mutation: str
) -> None:
    document = _cross_partition_document(monkeypatch)
    packet = prdel_v2_shards.partition_prdel_v2_document(
        document, max_artifact_bytes=65536
    )
    manifest_bytes, shard_bytes = _wire(packet)
    assert len(shard_bytes) > 2
    if mutation == "duplicate":
        selected = shard_bytes + [shard_bytes[-1]]
    else:
        selected = list(shard_bytes)
        selected[0], selected[1] = selected[1], selected[0]

    with pytest.raises(prdel.PrdelError):
        prdel_v2_shards.reconstruct_prdel_v2_document(manifest_bytes, selected)


def test_v2_transport_missing_selected_shard_remains_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = _cross_partition_document(monkeypatch)
    packet = prdel_v2_shards.partition_prdel_v2_document(
        document, max_artifact_bytes=65536
    )
    manifest_bytes, shard_bytes = _wire(packet)

    report = prdel_v2_shards.validate_prdel_v2_shards(
        manifest_bytes, shard_bytes[:-1], Path("."), BASE, HEAD
    )

    assert report["status"] == "UNKNOWN"
    assert report["transport_status"] == "UNKNOWN"


def test_v2_transport_refutes_substituted_row_even_with_valid_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = _cross_partition_document(monkeypatch)
    packet = prdel_v2_shards.partition_prdel_v2_document(
        document, max_artifact_bytes=65536
    )
    manifest_bytes, shard_bytes = _wire(packet)
    substituted = list(shard_bytes)
    shard = prdel.decode(substituted[-1])
    shard["records"][0] = copy.deepcopy(shard["records"][0])
    shard["records"][0]["summary"] += "substitution"
    substituted[-1] = prdel.canonical(shard)

    with pytest.raises(prdel.PrdelError, match="substituted shard bytes"):
        prdel_v2_shards.reconstruct_prdel_v2_document(
            manifest_bytes, substituted
        )


def test_v2_transport_refutes_manifest_row_gap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = _cross_partition_document(monkeypatch)
    packet = prdel_v2_shards.partition_prdel_v2_document(
        document, max_artifact_bytes=65536
    )
    manifest = copy.deepcopy(packet["manifest"])
    manifest["shards"][1]["start"] += 1
    manifest_bytes = prdel.canonical(manifest)
    shard_bytes = [prdel.canonical(shard) for shard in packet["shards"]]

    with pytest.raises(prdel.PrdelError):
        prdel_v2_shards.reconstruct_prdel_v2_document(
            manifest_bytes, shard_bytes
        )


def test_v2_transport_blank_template_fails_closed_without_promoting(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = {"sample.py": b"def value():\n    return missing()\n"}
    after = {"sample.py": b"def value():\n    return missing() + 1\n"}
    _select_snapshots(monkeypatch, before, after)
    document = prdel.generate_prdel_v2(Path("."), BASE, HEAD)
    packet = prdel_v2_shards.partition_prdel_v2_document(document)
    manifest_bytes, shard_bytes = _wire(packet)

    report = prdel_v2_shards.validate_prdel_v2_shards(
        manifest_bytes, shard_bytes, Path("."), BASE, HEAD
    )

    assert report["transport_status"] == "PASS"
    assert report["status"] == "FAIL"
    assert report["logical_report"]["status"] == "FAIL"
    assert report["logical_report"]["source_grounding_status"] == "FAIL"
    assert report["logical_report"]["semantic_status"] == "FAIL"
    assert report["logical_report"]["findings"] == [
        {
            "code": "UNCOMPLETED_MANUAL_TEMPLATE",
            "status": "FAIL",
            "count": len(document["records"]),
            "reason": (
                "Exact source and packet replay passed, but explanation records "
                "and required execution evidence are known unfilled."
            ),
        }
    ]


def test_v2_transport_cancellation_remains_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = {"README.md": b"before\n"}
    after = {"README.md": b"after\n"}
    _select_snapshots(monkeypatch, before, after)
    packet = prdel_v2_shards.partition_prdel_v2_document(
        prdel.generate_prdel_v2(Path("."), BASE, HEAD)
    )
    manifest_bytes, shard_bytes = _wire(packet)

    report = prdel_v2_shards.validate_prdel_v2_shards(
        manifest_bytes,
        shard_bytes,
        Path("."),
        BASE,
        HEAD,
        cancelled=True,
    )

    assert report["status"] == "UNKNOWN"
    assert report["transport_status"] == "UNKNOWN"


def test_v2_transport_enforces_exact_packet_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = _cross_partition_document(monkeypatch)
    packet = prdel_v2_shards.partition_prdel_v2_document(
        document, max_artifact_bytes=65536
    )
    exact = packet["manifest"]["aggregate_packet_bytes"]

    admitted = prdel_v2_shards.partition_prdel_v2_document(
        document, max_artifact_bytes=65536, max_packet_bytes=exact
    )
    exact = admitted["manifest"]["aggregate_packet_bytes"]
    admitted = prdel_v2_shards.partition_prdel_v2_document(
        document, max_artifact_bytes=65536, max_packet_bytes=exact
    )
    assert admitted["manifest"]["aggregate_packet_bytes"] == exact
    with pytest.raises(prdel.PrdelUnavailable, match="packet byte bound"):
        prdel_v2_shards.partition_prdel_v2_document(
            document, max_artifact_bytes=65536, max_packet_bytes=exact - 1
        )


def test_v2_reader_preflights_aggregate_bound_before_shard_hashing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    document = _cross_partition_document(monkeypatch)
    packet = prdel_v2_shards.partition_prdel_v2_document(
        document, max_artifact_bytes=65536
    )
    manifest = copy.deepcopy(packet["manifest"])
    manifest["max_packet_bytes"] = 1
    manifest_bytes = prdel.canonical(manifest)
    shard_bytes = [prdel.canonical(shard) for shard in packet["shards"]]

    monkeypatch.setattr(
        prdel,
        "digest",
        lambda raw: pytest.fail("over-budget shard was hashed before admission"),
    )
    with pytest.raises(prdel.PrdelError, match="aggregate packet byte bound"):
        prdel_v2_shards.reconstruct_prdel_v2_document(
            manifest_bytes, shard_bytes
        )


def test_v2_transport_enforces_one_row_artifact_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = {"README.md": b"before\n"}
    after = {"README.md": b"after\n"}
    _select_snapshots(monkeypatch, before, after)
    document = _fill(prdel.generate_prdel_v2(Path("."), BASE, HEAD))
    document["records"][0]["summary"] += "x" * 20000
    expected_shard = {
        "schema_version": "verifier-prdel-v2-document-shard-1",
        "binding": document["binding"],
        "index": 0,
        "start": 0,
        "source_obligations": [document["source_obligations"][0]],
        "records": [document["records"][0]],
    }
    exact = len(prdel.canonical(expected_shard))

    packet = prdel_v2_shards.partition_prdel_v2_document(
        document, max_artifact_bytes=exact
    )
    assert len(prdel.canonical(packet["shards"][0])) == exact
    with pytest.raises(prdel.PrdelUnavailable, match="one obligation/record"):
        prdel_v2_shards.partition_prdel_v2_document(
            document, max_artifact_bytes=exact - 1
        )


def test_v2_transport_rejects_v1_document(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = {"README.md": b"before\n"}
    after = {"README.md": b"after\n"}
    _select_snapshots(monkeypatch, before, after)

    with pytest.raises(prdel.PrdelError, match="verifier-prdel-2"):
        prdel_v2_shards.partition_prdel_v2_document(
            prdel.generate_prdel(Path("."), BASE, HEAD)
        )


def test_v2_transport_schemas_accept_exact_packet(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = {"README.md": b"before\n"}
    after = {"README.md": b"after\n"}
    _select_snapshots(monkeypatch, before, after)
    packet = prdel_v2_shards.partition_prdel_v2_document(
        prdel.generate_prdel_v2(Path("."), BASE, HEAD)
    )
    schema_root = Path("src/verifier/schemas")
    manifest_schema = prdel.decode(
        (schema_root / "verifier-prdel-v2-shard-manifest-1.schema.json").read_bytes()
    )
    shard_schema = prdel.decode(
        (schema_root / "verifier-prdel-v2-document-shard-1.schema.json").read_bytes()
    )

    Draft202012Validator(manifest_schema).validate(packet["manifest"])
    for shard in packet["shards"]:
        Draft202012Validator(shard_schema).validate(shard)


def test_v2_transport_refutes_dangling_global_graph_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = {
        "producer.py": b"def produce(value):\n    return value\n",
        "consumer.py": b"from producer import produce\n",
    }
    after = dict(before)
    after["producer.py"] = b"def produce(value):\n    return value + 1\n"
    _select_snapshots(monkeypatch, before, after)
    document = prdel.generate_prdel_v2(Path("."), BASE, HEAD)
    assert document["impact_graph"]["edges"]
    document["impact_graph"]["edges"][0]["source"] = "node:missing"

    with pytest.raises(prdel.PrdelError, match="dangling impact edge"):
        prdel_v2_shards.partition_prdel_v2_document(document)


def test_v2_transport_rejects_v1_manifest_identifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    before = {"README.md": b"before\n"}
    after = {"README.md": b"after\n"}
    _select_snapshots(monkeypatch, before, after)
    packet = prdel_v2_shards.partition_prdel_v2_document(
        prdel.generate_prdel_v2(Path("."), BASE, HEAD)
    )
    manifest = copy.deepcopy(packet["manifest"])
    manifest["schema_version"] = "verifier-prdel-compilation-manifest-2"

    with pytest.raises(prdel.PrdelError, match="private v2 manifest"):
        prdel_v2_shards.reconstruct_prdel_v2_document(
            prdel.canonical(manifest),
            [prdel.canonical(shard) for shard in packet["shards"]],
        )
