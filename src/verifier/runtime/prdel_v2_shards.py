"""Private bounded transport for one complete logical PRDEL v2 document.

The complete impact graph remains in the manifest.  Only aligned, contiguous
obligation/record pairs are partitioned, so shards have no independent verdict
and cannot omit cross-partition graph relationships.  Exact source replay is
still required; transport integrity alone grants no correctness or release
claim.

The impact graph records a directed acyclic graph (DAG) between components.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from verifier.runtime import prdel


MANIFEST_VERSION = "verifier-prdel-v2-shard-manifest-1"
SHARD_VERSION = "verifier-prdel-v2-document-shard-1"
REPORT_VERSION = "verifier-prdel-v2-shard-report-1"
SCOPE = "V2_MANUAL_TEMPLATE_TRANSPORT_ONLY"
GATE_STATUS = "NOT_ASSESSED"
MAX_ANALYSIS_NODES = prdel.MAX_REGIONS * 4
MAX_ANALYSIS_EDGES = prdel.MAX_REGIONS * 20
MAX_ANALYSIS_OPERATIONS = prdel.MAX_REGIONS * 2000

_DOCUMENT_FIELDS = {
    "schema_version",
    "binding",
    "requirements",
    "source_obligations",
    "impact_graph",
    "records",
    "evidence",
}
_MANIFEST_FIELDS = {
    "schema_version",
    "document_header",
    "logical_document_sha256",
    "logical_document_bytes",
    "logical_obligation_ids",
    "selected_source_ids",
    "analysis_limits",
    "shards",
    "max_artifact_bytes",
    "max_packet_bytes",
    "aggregate_packet_bytes",
    "scope",
    "gate_status",
}
_SHARD_FIELDS = {
    "schema_version",
    "binding",
    "index",
    "start",
    "source_obligations",
    "records",
}
_ENTRY_FIELDS = {"index", "start", "count", "sha256", "bytes", "obligation_ids"}


def _selected_limits(value: dict[str, Any] | None) -> dict[str, int]:
    selected = {
        "max_nodes": 10000,
        "max_edges": 20000,
        "max_operations": 200000,
        "max_output_bytes": 8 * 1024 * 1024,
    }
    if value is not None:
        if type(value) is not dict or set(value) != set(selected):
            raise prdel.PrdelError("exact private v2 analysis limits required")
        selected = dict(value)
    ceilings = {
        "max_nodes": MAX_ANALYSIS_NODES,
        "max_edges": MAX_ANALYSIS_EDGES,
        "max_operations": MAX_ANALYSIS_OPERATIONS,
        "max_output_bytes": prdel.MAX_DOCUMENT_BYTES,
    }
    for name, ceiling in ceilings.items():
        current = selected.get(name)
        if (
            type(current) is not int
            or isinstance(current, bool)
            or current < 1
            or current > ceiling
        ):
            raise prdel.PrdelError(
                f"private v2 {name} must be a positive integer no greater than {ceiling}"
            )
    return selected


def _selected_wire_bounds(
    max_artifact_bytes: int, max_packet_bytes: int
) -> tuple[int, int]:
    for name, value, ceiling in (
        ("artifact", max_artifact_bytes, prdel.MAX_DOCUMENT_BYTES),
        ("packet", max_packet_bytes, prdel.MAX_DESCRIPTION_BYTES),
    ):
        if (
            type(value) is not int
            or isinstance(value, bool)
            or value < 1
            or value > ceiling
        ):
            raise prdel.PrdelError(
                f"private v2 {name} byte bound must be within the existing ceiling"
            )
    return max_artifact_bytes, max_packet_bytes


def _graph_references(document: dict[str, Any]) -> None:
    graph = document.get("impact_graph")
    if type(graph) is not dict or graph.get("schema_version") != "verifier-prdel-impact-2":
        raise prdel.PrdelError("complete verifier-prdel-impact-2 graph required")
    if graph.get("binding") != document.get("binding"):
        raise prdel.PrdelError("impact graph binding differs from document binding")
    selected_source_ids = {
        row["id"]
        for row in document["source_obligations"]
        if type(row) is dict and row.get("kind") == "source" and type(row.get("id")) is str
    }
    raw_sets = graph.get("source_obligation_sets")
    if type(raw_sets) is not list or len(raw_sets) > prdel.MAX_REGIONS * 4:
        raise prdel.PrdelError("bounded source obligation set inventory required")
    source_sets: set[str] = set()
    for row in raw_sets:
        if type(row) is not dict or set(row) != {"id", "source_obligations"}:
            raise prdel.PrdelError("exact source obligation set fields required")
        identifier, values = row["id"], row["source_obligations"]
        if (
            type(identifier) is not str
            or identifier in source_sets
            or type(values) is not list
            or values != sorted(set(values))
            or any(type(value) is not str or value not in selected_source_ids for value in values)
            or identifier != prdel._source_set_identifier(values)
        ):
            raise prdel.PrdelError("invalid source obligation set")
        source_sets.add(identifier)

    def indexed(name: str) -> dict[str, dict[str, Any]]:
        rows = graph.get(name)
        if type(rows) is not list or len(rows) > prdel.MAX_REGIONS * 4:
            raise prdel.PrdelError(f"bounded impact {name} required")
        result: dict[str, dict[str, Any]] = {}
        for row in rows:
            if type(row) is not dict or type(row.get("id")) is not str or row["id"] in result:
                raise prdel.PrdelError(f"unique impact {name} identifiers required")
            if row.get("source_obligation_set_id") not in source_sets:
                raise prdel.PrdelError(f"impact {name} source set reference differs")
            result[row["id"]] = row
        return result

    nodes = indexed("nodes")
    edges = indexed("edges")
    obligations = indexed("obligations")
    frontier = indexed("frontier")
    for edge in edges.values():
        if edge.get("source") not in nodes or edge.get("target") not in nodes:
            raise prdel.PrdelError("dangling impact edge endpoint")
    for row in obligations.values():
        endpoints = row.get("endpoints")
        if (
            type(endpoints) is not list
            or any(value not in nodes for value in endpoints)
            or row.get("edge_id") not in edges
        ):
            raise prdel.PrdelError("dangling impact obligation reference")
    for row in frontier.values():
        consumer = row.get("consumer_id")
        if consumer is not None and consumer not in nodes:
            raise prdel.PrdelError("dangling impact frontier consumer")
    components = graph.get("components")
    if type(components) is not list or len(components) > prdel.MAX_REGIONS * 4:
        raise prdel.PrdelError("bounded impact components required")
    component_ids: set[str] = set()
    component_members: set[str] = set()
    for component in components:
        if type(component) is not dict:
            raise prdel.PrdelError("impact component object required")
        identifier, members = component.get("id"), component.get("members")
        if (
            type(identifier) is not str
            or identifier in component_ids
            or type(members) is not list
            or members != sorted(set(members))
            or any(member not in nodes or member in component_members for member in members)
        ):
            raise prdel.PrdelError("dangling or duplicate impact component member")
        component_ids.add(identifier)
        component_members.update(members)
    if component_members != set(nodes):
        raise prdel.PrdelError("impact component coverage differs from graph nodes")
    dag_edges = graph.get("dag_edges")
    if type(dag_edges) is not list or len(dag_edges) > prdel.MAX_REGIONS * 4:
        raise prdel.PrdelError("bounded impact component DAG required")
    for row in dag_edges:
        if (
            type(row) is not dict
            or row.get("source") not in component_ids
            or row.get("target") not in component_ids
            or type(row.get("edge_ids")) is not list
            or any(identifier not in edges for identifier in row["edge_ids"])
        ):
            raise prdel.PrdelError("dangling impact component DAG reference")


def _document_rows(document: dict[str, Any]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    if type(document) is not dict or set(document) != _DOCUMENT_FIELDS:
        raise prdel.PrdelError("exact logical PRDEL document fields required")
    if document.get("schema_version") != prdel.SCHEMA_V2:
        raise prdel.PrdelError("verifier-prdel-2 logical document required")
    rows, records = document.get("source_obligations"), document.get("records")
    if (
        type(rows) is not list
        or type(records) is not list
        or not rows
        or len(rows) > prdel.MAX_REGIONS * 4
        or len(records) != len(rows)
    ):
        raise prdel.PrdelError("complete bounded obligation and record lists required")
    ids: list[str] = []
    for row, record in zip(rows, records):
        if (
            type(row) is not dict
            or type(record) is not dict
            or type(row.get("id")) is not str
            or row["id"] != record.get("id")
        ):
            raise prdel.PrdelError("aligned obligation and record identifiers required")
        ids.append(row["id"])
    if len(ids) != len(set(ids)):
        raise prdel.PrdelError("duplicate logical obligation identifier")
    if type(document.get("evidence")) is not list:
        raise prdel.PrdelError("bounded evidence list required")
    _selected_limits(document["impact_graph"].get("bounds"))
    _graph_references(document)
    return rows, records


def _shard(
    binding: dict[str, Any],
    index: int,
    start: int,
    rows: list[dict[str, Any]],
    records: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": SHARD_VERSION,
        "binding": binding,
        "index": index,
        "start": start,
        "source_obligations": rows,
        "records": records,
    }


def partition_prdel_v2_document(
    document: dict[str, Any],
    *,
    max_artifact_bytes: int = prdel.MAX_DOCUMENT_BYTES,
    max_packet_bytes: int = prdel.MAX_DESCRIPTION_BYTES,
) -> dict[str, Any]:
    """Partition aligned rows while retaining one complete global graph header."""
    max_artifact_bytes, max_packet_bytes = _selected_wire_bounds(
        max_artifact_bytes, max_packet_bytes
    )
    rows, records = _document_rows(document)
    logical_raw = prdel.canonical(document)
    if len(logical_raw) > prdel.MAX_DESCRIPTION_BYTES:
        raise prdel.PrdelUnavailable("logical sharded document aggregate byte bound exhausted")
    shards: list[dict[str, Any]] = []
    current_rows: list[dict[str, Any]] = []
    current_records: list[dict[str, Any]] = []
    current_size = 0
    start = 0
    for row, record in zip(rows, records):
        row_raw, record_raw = prdel.canonical(row), prdel.canonical(record)
        if not current_rows:
            current_size = len(
                prdel.canonical(
                    _shard(document["binding"], len(shards), start, [], [])
                )
            )
        added = len(row_raw) + len(record_raw) + (2 if current_rows else 0)
        if current_size + added > max_artifact_bytes and current_rows:
            shards.append(
                _shard(
                    document["binding"],
                    len(shards),
                    start,
                    current_rows,
                    current_records,
                )
            )
            start += len(current_rows)
            current_rows, current_records = [row], [record]
            current_size = len(
                prdel.canonical(
                    _shard(document["binding"], len(shards), start, [], [])
                )
            ) + len(row_raw) + len(record_raw)
        else:
            current_rows.append(row)
            current_records.append(record)
            current_size += added
        if current_size > max_artifact_bytes:
            raise prdel.PrdelUnavailable(
                "one obligation/record pair exceeds the selected artifact byte bound"
            )
    if current_rows:
        shards.append(
            _shard(
                document["binding"],
                len(shards),
                start,
                current_rows,
                current_records,
            )
        )
    shard_raw = [prdel.canonical(shard) for shard in shards]
    entries = []
    for shard, raw in zip(shards, shard_raw):
        if len(raw) > max_artifact_bytes:
            raise prdel.PrdelUnavailable("shard artifact byte bound exhausted")
        entries.append(
            {
                "index": shard["index"],
                "start": shard["start"],
                "count": len(shard["source_obligations"]),
                "sha256": prdel.digest(raw),
                "bytes": len(raw),
                "obligation_ids": [
                    row["id"] for row in shard["source_obligations"]
                ],
            }
        )
    header = {
        key: value
        for key, value in document.items()
        if key not in {"source_obligations", "records"}
    }
    manifest = {
        "schema_version": MANIFEST_VERSION,
        "document_header": header,
        "logical_document_sha256": prdel.digest(logical_raw),
        "logical_document_bytes": len(logical_raw),
        "logical_obligation_ids": [row["id"] for row in rows],
        "selected_source_ids": [row["id"] for row in rows if row["kind"] == "source"],
        "analysis_limits": dict(document["impact_graph"]["bounds"]),
        "shards": entries,
        "max_artifact_bytes": max_artifact_bytes,
        "max_packet_bytes": max_packet_bytes,
        "aggregate_packet_bytes": 0,
        "scope": SCOPE,
        "gate_status": GATE_STATUS,
    }
    for _ in range(16):
        manifest_raw = prdel.canonical(manifest)
        total = len(manifest_raw) + sum(len(raw) for raw in shard_raw)
        if manifest["aggregate_packet_bytes"] == total:
            break
        manifest["aggregate_packet_bytes"] = total
    else:
        raise prdel.PrdelUnavailable("packet byte counter did not stabilize")
    manifest_raw = prdel.canonical(manifest)
    total = len(manifest_raw) + sum(len(raw) for raw in shard_raw)
    if manifest["aggregate_packet_bytes"] != total:
        raise prdel.PrdelUnavailable("packet byte counter is not exact")
    if len(manifest_raw) > max_artifact_bytes:
        raise prdel.PrdelUnavailable("manifest artifact byte bound exhausted")
    if total > max_packet_bytes:
        raise prdel.PrdelUnavailable("packet byte bound exhausted")
    return {"manifest": manifest, "shards": shards}


def compile_prdel_v2_shards(
    root: Path,
    base: str,
    head: str,
    requirements_bytes: bytes | None = None,
    expected_requirements_digest: str | None = None,
    *,
    limits: dict[str, Any] | None = None,
    max_artifact_bytes: int = prdel.MAX_DOCUMENT_BYTES,
    max_packet_bytes: int = prdel.MAX_DESCRIPTION_BYTES,
) -> dict[str, Any]:
    """Generate one logical v2 template and encode its private bounded transport."""
    selected_limits = _selected_limits(limits)
    document = prdel._generate_prdel_template(
        Path(root),
        base,
        head,
        requirements_bytes,
        expected_requirements_digest,
        selected_limits,
        sharded=True,
        contract=prdel.SCHEMA_V2,
        source_bound=True,
    )
    return partition_prdel_v2_document(
        document,
        max_artifact_bytes=max_artifact_bytes,
        max_packet_bytes=max_packet_bytes,
    )


def reconstruct_prdel_v2_document(
    manifest_bytes: bytes, shard_bytes: list[bytes]
) -> dict[str, Any]:
    """Reconstruct only a complete exact packet; missing selected bytes are UNKNOWN."""
    if type(manifest_bytes) is not bytes:
        raise prdel.PrdelUnavailable("selected manifest bytes missing")
    manifest = prdel.decode(manifest_bytes)
    if prdel.canonical(manifest) != manifest_bytes:
        raise prdel.PrdelError("noncanonical or substituted manifest bytes")
    if (
        type(manifest) is not dict
        or set(manifest) != _MANIFEST_FIELDS
        or manifest.get("schema_version") != MANIFEST_VERSION
        or manifest.get("scope") != SCOPE
        or manifest.get("gate_status") != GATE_STATUS
    ):
        raise prdel.PrdelError("separate closed private v2 manifest required")
    max_artifact_bytes, max_packet_bytes = _selected_wire_bounds(
        manifest["max_artifact_bytes"], manifest["max_packet_bytes"]
    )
    if len(manifest_bytes) > max_artifact_bytes:
        raise prdel.PrdelError("manifest artifact byte bound exceeded")
    entries = manifest.get("shards")
    if type(entries) is not list or not entries or len(entries) > prdel.MAX_REGIONS * 4:
        raise prdel.PrdelError("complete bounded shard inventory required")
    if type(shard_bytes) is not list or len(shard_bytes) < len(entries):
        raise prdel.PrdelUnavailable("missing selected shard bytes")
    if len(shard_bytes) > len(entries):
        raise prdel.PrdelError("extraneous selected shard bytes")
    aggregate = len(manifest_bytes)
    for raw in shard_bytes:
        if type(raw) is not bytes or len(raw) > max_artifact_bytes:
            raise prdel.PrdelError("shard artifact byte bound exceeded")
        aggregate += len(raw)
        if aggregate > max_packet_bytes:
            raise prdel.PrdelError("aggregate packet byte bound exceeded")
    header = manifest.get("document_header")
    if (
        type(header) is not dict
        or set(header) != _DOCUMENT_FIELDS - {"source_obligations", "records"}
        or header.get("schema_version") != prdel.SCHEMA_V2
    ):
        raise prdel.PrdelError("complete logical v2 document header required")
    selected_limits = _selected_limits(manifest.get("analysis_limits"))
    if header.get("impact_graph", {}).get("bounds") != selected_limits:
        raise prdel.PrdelError("selected graph limits differ from manifest")
    rows: list[dict[str, Any]] = []
    records: list[dict[str, Any]] = []
    identifiers: list[str] = []
    expected_start = 0
    for index, (entry, raw) in enumerate(zip(entries, shard_bytes)):
        if (
            type(entry) is not dict
            or set(entry) != _ENTRY_FIELDS
            or type(entry.get("index")) is not int
            or entry["index"] != index
            or type(entry.get("start")) is not int
            or entry["start"] != expected_start
            or type(entry.get("count")) is not int
            or entry["count"] < 1
            or type(raw) is not bytes
            or len(raw) > max_artifact_bytes
            or entry.get("bytes") != len(raw)
            or entry.get("sha256") != prdel.digest(raw)
        ):
            raise prdel.PrdelError("missing, reordered or substituted shard bytes")
        shard = prdel.decode(raw)
        if (
            prdel.canonical(shard) != raw
            or type(shard) is not dict
            or set(shard) != _SHARD_FIELDS
            or shard.get("schema_version") != SHARD_VERSION
            or shard.get("binding") != header.get("binding")
            or shard.get("index") != index
            or shard.get("start") != expected_start
            or type(shard.get("source_obligations")) is not list
            or type(shard.get("records")) is not list
            or len(shard["source_obligations"]) != entry["count"]
            or len(shard["records"]) != entry["count"]
        ):
            raise prdel.PrdelError("invalid private v2 shard wire")
        current = [row.get("id") for row in shard["source_obligations"]]
        if (
            current != entry.get("obligation_ids")
            or current != [record.get("id") for record in shard["records"]]
        ):
            raise prdel.PrdelError("shard obligation and record coverage differs")
        rows.extend(shard["source_obligations"])
        records.extend(shard["records"])
        identifiers.extend(current)
        expected_start += entry["count"]
        if len(identifiers) > prdel.MAX_REGIONS * 4:
            raise prdel.PrdelError("logical obligation count bound exhausted")
    if (
        len(identifiers) != len(set(identifiers))
        or identifiers != manifest.get("logical_obligation_ids")
    ):
        raise prdel.PrdelError("omitted, duplicate or reordered logical obligation")
    selected_source_ids = [row["id"] for row in rows if row.get("kind") == "source"]
    if selected_source_ids != manifest.get("selected_source_ids"):
        raise prdel.PrdelError("selected source coverage differs")
    document = {**header, "source_obligations": rows, "records": records}
    logical_raw = prdel.canonical(document)
    if (
        len(logical_raw) > prdel.MAX_DESCRIPTION_BYTES
        or manifest.get("logical_document_bytes") != len(logical_raw)
        or manifest.get("logical_document_sha256") != prdel.digest(logical_raw)
    ):
        raise prdel.PrdelError("reconstructed logical document differs")
    aggregate = len(manifest_bytes) + sum(len(raw) for raw in shard_bytes)
    if (
        aggregate != manifest.get("aggregate_packet_bytes")
        or aggregate > max_packet_bytes
    ):
        raise prdel.PrdelError("aggregate packet byte binding differs")
    _document_rows(document)
    return document


def _report(status: str, transport_status: str, reason: str | None = None) -> dict[str, Any]:
    return {
        "schema_version": REPORT_VERSION,
        "status": status,
        "transport_status": transport_status,
        "coverage_status": "UNKNOWN",
        "recomposition_status": "UNKNOWN",
        "scope": SCOPE,
        "gate_status": GATE_STATUS,
        "reason": reason,
        "logical_report": None,
    }


def validate_prdel_v2_shards(
    manifest_bytes: bytes,
    shard_bytes: list[bytes],
    root: Path,
    base: str,
    head: str,
    requirements_bytes: bytes | None = None,
    expected_requirements_digest: str | None = None,
    evidence_bytes: bytes | None = None,
    expected_evidence_digest: str | None = None,
    *,
    cancelled: bool = False,
) -> dict[str, Any]:
    """Verify transport, exact recomposition and independently selected source."""
    if cancelled:
        return _report("UNKNOWN", "UNKNOWN", "validation cancelled before replay")
    try:
        document = reconstruct_prdel_v2_document(manifest_bytes, shard_bytes)
        manifest = prdel.decode(manifest_bytes)
        expected_packet = partition_prdel_v2_document(
            document,
            max_artifact_bytes=manifest["max_artifact_bytes"],
            max_packet_bytes=manifest["max_packet_bytes"],
        )
        if (
            manifest_bytes != prdel.canonical(expected_packet["manifest"])
            or shard_bytes
            != [prdel.canonical(shard) for shard in expected_packet["shards"]]
        ):
            raise prdel.PrdelError("packet differs from deterministic exact partition")
        expected = prdel._generate_prdel_template(
            Path(root),
            base,
            head,
            requirements_bytes,
            expected_requirements_digest,
            manifest["analysis_limits"],
            sharded=True,
            contract=prdel.SCHEMA_V2,
            source_bound=True,
        )
        for key in ("binding", "requirements", "source_obligations", "impact_graph"):
            if document[key] != expected[key]:
                raise prdel.PrdelError(
                    f"{key} differs from exact independently selected source replay"
                )
        manual_template = not document["evidence"] and all(
            record
            == {
                "id": row["id"],
                "requirement_ids": [],
                "why": {"requirement_id": None, "quote": ""},
                "claims": [],
                "summary": "",
                "limits": [],
                "coverage": {},
            }
            for row, record in zip(document["source_obligations"], document["records"])
        )
        if manual_template:
            if evidence_bytes is not None or expected_evidence_digest is not None:
                raise prdel.PrdelError(
                    "selected evidence cannot be attached to an uncompleted template"
                )
            logical_report = {
                "schema_version": prdel.REPORT_SCHEMA_V2,
                # The ordinary v2 validator treats an exact blank manual
                # template as a known incomplete explanation: required
                # rationale, claims, summaries and coverage are absent.  Keep
                # that fail-closed semantic result while aggregating the
                # otherwise per-obligation findings to stay within the
                # selected transport/output bounds.
                "status": "FAIL",
                "source_grounding_status": "FAIL",
                "semantic_status": "FAIL",
                "binding": expected["binding"],
                "claim_boundary": prdel.BOUNDARY,
                "findings": [
                    {
                        "code": "UNCOMPLETED_MANUAL_TEMPLATE",
                        "status": "FAIL",
                        "count": len(document["records"]),
                        "reason": (
                            "Exact source and packet replay passed, but explanation "
                            "records and required execution evidence are known unfilled."
                        ),
                    }
                ],
            }
        else:
            logical_report = prdel._validate_sharded_prdel_v2(
                document,
                Path(root),
                base,
                head,
                requirements_bytes,
                expected_requirements_digest,
                evidence_bytes,
                expected_evidence_digest,
                manifest["analysis_limits"],
            )
        report = _report(logical_report["status"], "PASS")
        report["coverage_status"] = "PASS"
        report["recomposition_status"] = "PASS"
        report["logical_report"] = logical_report
        return report
    except (prdel.PrdelUnavailable, OSError) as exc:
        return _report("UNKNOWN", "UNKNOWN", str(exc))
    except (
        prdel.PrdelError,
        ValueError,
        TypeError,
        KeyError,
        RecursionError,
        OverflowError,
    ) as exc:
        return _report("FAIL", "FAIL", str(exc))
