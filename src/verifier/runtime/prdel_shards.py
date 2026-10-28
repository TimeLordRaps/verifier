"""Bounded Pull Request Domain Explanation Language (PRDEL) document shards.

Terminology: identifier (ID); Secure Hash Algorithm 256-bit (SHA-256);
Unicode Transformation Format, 8-bit (UTF-8). This separate wire
retains every exact selected obligation and compilation finding. Partitioning
does not establish source predicates, execution evidence or promotion clearance.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from verifier.runtime import prdel, prdel_rules

MANIFEST_VERSION = "verifier-prdel-compilation-manifest-2"
LEGACY_MANIFEST_VERSION = "verifier-prdel-compilation-manifest-1"
SHARD_VERSION = "verifier-prdel-document-shard-1"
_DOCUMENT_FIELDS = {"schema_version", "binding", "requirements", "source_obligations", "impact_graph", "records", "evidence"}


def _partition_compilation(
    compilation: dict[str, Any], manifest_version: str
) -> dict[str, Any]:
    """Partition for one selected wire version; never omit an oversized row."""
    if manifest_version not in {LEGACY_MANIFEST_VERSION, MANIFEST_VERSION}:
        raise prdel.PrdelError("Unsupported compilation manifest version.")
    document = compilation.get("document")
    if not isinstance(document, dict) or set(document) != _DOCUMENT_FIELDS:
        if compilation.get("status") == "FAIL":
            raise prdel.PrdelError("Known compilation failure; no complete retained document for sharding.")
        raise prdel.PrdelUnavailable("Complete retained document required for sharding.")
    rows, records = document["source_obligations"], document["records"]
    if len(rows) > prdel.MAX_REGIONS * 4 or len(records) != len(rows):
        raise prdel.PrdelError("Obligation/record count exceeds the existing document grammar.")
    row_ids = [row["id"] for row in rows]
    record_ids = [row["id"] for row in records]
    by_id = {row["id"]: row for row in rows}
    by_record = {row["id"]: row for row in records}
    if (len(by_id) != len(rows) or len(by_record) != len(records)
            or row_ids != record_ids):
        raise prdel.PrdelError(
            "Each selected obligation requires one record in the same exact order."
        )
    wire_ids = (
        sorted(by_id) if manifest_version == LEGACY_MANIFEST_VERSION else row_ids
    )
    operations = compilation["counters"]["operations"]
    if operations + 2 * len(rows) > prdel_rules.MAX_RULE_OPERATIONS:
        raise prdel.PrdelUnavailable("Existing explanation operation budget cannot complete sharding.")
    limit = prdel_rules.MAX_COMPILED_BYTES
    selected = sorted(identifier for identifier, row in by_id.items() if row["kind"] == "source")
    shards: list[dict[str, Any]] = []
    entries: list[dict[str, Any]] = []

    def empty() -> dict[str, Any]:
        return {"schema_version": SHARD_VERSION, "binding": document["binding"],
            "index": len(shards), "source_obligations": [], "records": []}

    current = empty()
    size = len(prdel.canonical(current))
    for identifier in wire_ids:
        row, record = by_id[identifier], by_record[identifier]
        added = len(prdel.canonical(row)) + len(prdel.canonical(record)) + (2 if current["records"] else 0)
        if size + added > limit and current["records"]:
            shards.append(current)
            current = empty()
            size = len(prdel.canonical(current))
            added = len(prdel.canonical(row)) + len(prdel.canonical(record))
        if size + added > limit:
            raise prdel.PrdelUnavailable("One selected obligation/record exceeds the unchanged artifact byte bound.")
        current["source_obligations"].append(row)
        current["records"].append(record)
        size += added
    if current["records"]:
        shards.append(current)
    for shard in shards:
        raw = prdel.canonical(shard)
        if len(raw) > limit:
            raise prdel.PrdelUnavailable("Shard byte bound exhausted.")
        entries.append({"index": shard["index"], "sha256": prdel.digest(raw), "bytes": len(raw),
            "obligation_ids": [row["id"] for row in shard["source_obligations"]]})
    manifest = {"schema_version": manifest_version,
        "document_header": {key: value for key, value in document.items() if key not in {"source_obligations", "records"}},
        "compilation_header": {key: value for key, value in compilation.items() if key != "document"},
        "selected_source_ids": selected, "obligation_ids": wire_ids, "shards": entries,
        "partition_operations": 2 * len(rows), "max_artifact_bytes": limit,
        "scope": "EXPLANATION_COMPILATION_ONLY", "gate_status": "NOT_ASSESSED"}
    if len(prdel.canonical(manifest)) > limit:
        raise prdel.PrdelUnavailable("Manifest exceeds the unchanged artifact byte bound.")
    return {"manifest": manifest, "shards": shards}


def partition_compilation(compilation: dict[str, Any]) -> dict[str, Any]:
    """Produce the order-preserving version-two wire for one bounded compilation."""
    return _partition_compilation(compilation, MANIFEST_VERSION)


def compile_prdel_shards(root: Path, base: str, head: str,
        requirements_bytes: bytes | None = None,
        expected_requirements_digest: str | None = None,
        definition: dict[str, Any] | None = None) -> dict[str, Any]:
    """Compile the same scope/rules with a separate bounded artifact representation."""
    compilation = prdel_rules._compile_prdel(root, base, head, requirements_bytes,
        expected_requirements_digest, definition, retain_document=True)
    return partition_compilation(compilation)


def reconstruct_compilation(manifest_bytes: bytes, shard_bytes: list[bytes]) -> dict[str, Any]:
    """Verify closed manifests, exact bytes and one occurrence of every selected ID."""
    manifest = prdel.decode(manifest_bytes)
    version = manifest.get("schema_version")
    fields = {"schema_version", "document_header", "compilation_header", "selected_source_ids", "obligation_ids", "shards", "partition_operations", "max_artifact_bytes", "scope", "gate_status"}
    if prdel.canonical(manifest) != manifest_bytes or set(manifest) != fields or version not in {LEGACY_MANIFEST_VERSION, MANIFEST_VERSION} or manifest["scope"] != "EXPLANATION_COMPILATION_ONLY" or manifest["gate_status"] != "NOT_ASSESSED":
        raise prdel.PrdelError("Separate closed compilation manifest required.")
    limit = prdel_rules.MAX_COMPILED_BYTES
    if manifest["max_artifact_bytes"] != limit or len(manifest_bytes) > limit or type(shard_bytes) is not list:
        raise prdel.PrdelError("Selected artifact bound differs.")
    entries = manifest["shards"]
    if type(entries) is not list or len(entries) != len(shard_bytes) or not entries or len(entries) > prdel.MAX_REGIONS * 4:
        raise prdel.PrdelError("Complete bounded shard inventory required.")
    rows, records, ids = [], [], []
    header = manifest["document_header"]
    if set(header) != _DOCUMENT_FIELDS - {"source_obligations", "records"}:
        raise prdel.PrdelError("Complete closed document header required.")
    for index, (entry, raw) in enumerate(zip(entries, shard_bytes)):
        if set(entry) != {"index", "sha256", "bytes", "obligation_ids"} or type(entry["index"]) is not int or entry["index"] != index or type(raw) is not bytes or len(raw) > limit or entry["bytes"] != len(raw) or entry["sha256"] != prdel.digest(raw):
            raise prdel.PrdelError("Missing, reordered or substituted shard bytes.")
        shard = prdel.decode(raw)
        if prdel.canonical(shard) != raw or set(shard) != {"schema_version", "binding", "index", "source_obligations", "records"} or shard["schema_version"] != SHARD_VERSION or type(shard["index"]) is not int or shard["index"] != index or shard["binding"] != header["binding"]:
            raise prdel.PrdelError("Shard wire or exact binding differs.")
        current = [row["id"] for row in shard["source_obligations"]]
        if current != entry["obligation_ids"] or current != [record["id"] for record in shard["records"]]:
            raise prdel.PrdelError("Shard obligation/record coverage differs.")
        rows.extend(shard["source_obligations"]);records.extend(shard["records"]);ids.extend(current)
        if len(ids) > prdel.MAX_REGIONS * 4:
            raise prdel.PrdelError("Existing obligation count bound exhausted.")
    if version == LEGACY_MANIFEST_VERSION:
        invalid_ids = ids != sorted(set(ids)) or ids != manifest["obligation_ids"]
    else:
        invalid_ids = len(ids) != len(set(ids)) or ids != manifest["obligation_ids"]
    if invalid_ids:
        raise prdel.PrdelError(
            "Omitted, duplicate or reordered selected obligation."
        )
    selected = sorted(row["id"] for row in rows if row["kind"] == "source")
    if selected != manifest["selected_source_ids"] or manifest["partition_operations"] != 2 * len(ids):
        raise prdel.PrdelError("Complete selected source inventory differs.")
    compilation = manifest["compilation_header"]
    if set(compilation) != prdel_rules._ENVELOPE_FIELDS - {"document"} or compilation["binding"] != header["binding"]:
        raise prdel.PrdelError("Compilation header or exact binding differs.")
    if compilation["counters"]["operations"] + manifest["partition_operations"] > prdel_rules.MAX_RULE_OPERATIONS:
        raise prdel.PrdelError("Existing explanation operation budget exhausted.")
    return {**compilation, "document": {**header, "source_obligations": rows, "records": records}}


def validate_prdel_shards(manifest_bytes: bytes, shard_bytes: list[bytes], root: Path,
        base: str, head: str, requirements_bytes: bytes | None = None,
        expected_requirements_digest: str | None = None,
        definition: dict[str, Any] | None = None) -> dict[str, Any]:
    """Independently replay the selected source; retention alone gives no validity."""
    try:
        carried = reconstruct_compilation(manifest_bytes, shard_bytes)
        compilation = prdel_rules._compile_prdel(
            root, base, head, requirements_bytes, expected_requirements_digest,
            definition, retain_document=True
        )
        manifest_version = prdel.decode(manifest_bytes).get("schema_version")
        expected = _partition_compilation(compilation, manifest_version)
        if manifest_bytes != prdel.canonical(expected["manifest"]) or shard_bytes != [prdel.canonical(shard) for shard in expected["shards"]]:
            raise prdel.PrdelError("Sharded compilation differs from exact independently selected replay.")
        return {"status": carried["status"], "residuals": carried["residuals"],
            "scope": "EXPLANATION_COMPILATION_ONLY", "gate_status": "NOT_ASSESSED"}
    except (prdel.PrdelUnavailable, OSError) as exc:
        return {"status": "UNKNOWN", "reason": str(exc), "gate_status": "NOT_ASSESSED"}
    except (prdel.PrdelError, ValueError, TypeError, KeyError, RecursionError, OverflowError) as exc:
        return {"status": "FAIL", "reason": str(exc), "gate_status": "NOT_ASSESSED"}


SHARD_GATE_SCHEMA = "verifier-prdel-shard-gate-1"
SHARD_GATE_SCOPE = "BOUNDED_SHARDED_EXACT_SOURCE_ONLY"
SHARD_HUMAN_BODY_BYTES = 32 * 1024


def _shard_gate_error(status: str, reason: str) -> dict[str, Any]:
    return {"schema_version": SHARD_GATE_SCHEMA, "status": status,
        "scope": SHARD_GATE_SCOPE, "claim_boundary": prdel.BOUNDARY,
        "execution_provenance": "NOT_ESTABLISHED", "binding": None,
        "manifest_sha256": None, "shard_sha256": [],
        "compilation_replay": {"status": "NOT_RUN"}, "logical_report": None,
        "required_compilation_residuals": [], "required_native_findings": [],
        "admission_policy": None, "required_replay_findings": [{"code": "SHARDED_INPUT_" + status,
            "status": status, "reason": reason}], "description_digest": None}


def _shard_gate_packet_admission(manifest_bytes: bytes, shard_bytes: list[bytes], packet_budget_bytes: int | None) -> None:
    """Admit the selected receiver budget before hashing or decoding artifacts."""
    if type(packet_budget_bytes) is not int or not 0 < packet_budget_bytes <= prdel.MAX_SNAPSHOT_BYTES:
        raise prdel.PrdelError("An explicit positive caller packet budget within the retained-source receiver profile is required.")
    if type(manifest_bytes) is not bytes or type(shard_bytes) is not list:
        raise prdel.PrdelError("Exact manifest bytes and ordered shard bytes required.")
    if not shard_bytes or len(shard_bytes) > prdel.MAX_REGIONS * 4:
        raise prdel.PrdelError("Complete finite shard inventory required.")
    total = len(manifest_bytes)
    artifact_limit = min(prdel_rules.MAX_COMPILED_BYTES, prdel.MAX_DOCUMENT_BYTES)
    if total > artifact_limit:
        raise prdel.PrdelError("Manifest exceeds the unchanged artifact bound.")
    for raw in shard_bytes:
        if type(raw) is not bytes or len(raw) > artifact_limit:
            raise prdel.PrdelError("Shard exceeds the unchanged artifact bound.")
        total += len(raw)
        if total > packet_budget_bytes:
            raise prdel.PrdelUnavailable("Selected aggregate shard transport budget exhausted.")


def _shard_gate_body(index: str, report: dict[str, Any], ceiling: int) -> str:
    assessment = prdel.canonical(report)
    if len(assessment) > prdel.MAX_DESCRIPTION_BYTES:
        raise prdel.PrdelUnavailable("Complete native assessment exceeds the output bound.")
    lines = [index.rstrip(), "", "## Required native gate findings", "",
        "Native gate status: " + report["status"],
        "Assessment scope: " + SHARD_GATE_SCOPE,
        "Assessment SHA-256: `" + prdel.digest(assessment) + "`", ""]
    total = sum(len(line.encode("utf-8")) + 1 for line in lines)
    if total > ceiling:
        raise prdel.PrdelUnavailable("Complete native findings exceed the description bound.")
    for label, key in (("Native", "required_native_findings"), ("Replay", "required_replay_findings")):
        for number, row in enumerate(report[key]):
            line = f"- {label} finding {number}: " + prdel.canonical(row).decode("utf-8")
            total += len(line.encode("utf-8")) + 1
            if total > ceiling:
                raise prdel.PrdelUnavailable("Complete native findings exceed the description bound.")
            lines.append(line)
    # Each row was already admitted under the existing artifact grammar. This
    # final output ceiling is separate from leaf inventory traversal accounting.
    return "\n".join(lines).rstrip() + "\n"


def render_prdel_shard_description(
    manifest_bytes: bytes, shard_bytes: list[bytes], root: Path, base: str, head: str,
    *, expected_manifest_digest: str, expected_shard_digests: list[str],
    expected_source_digest: str, requirements_digest: str,
    expected_required_residuals: list[dict[str, Any]],
    packet_budget_bytes: int | None = None,
    requirements_bytes: bytes | None = None, evidence_bytes: bytes | None = None,
    expected_evidence_digest: str | None = None, definition: dict[str, Any] | None = None,
    limits: Any = None,
) -> dict[str, Any]:
    """Generate an exact selected index plus all independently assessed residuals.

    Compilation retention and replay are separate from logical source checking.
    The returned assessment proves only its listed bounded predicates. Its body
    is not accepted by the unchanged version-one description contract.
    """
    report = None
    try:
        _shard_gate_packet_admission(manifest_bytes, shard_bytes, packet_budget_bytes)
        from verifier.runtime.prdel_shard_index import (
            IndexErrorBound, IndexLimits, parse_shard_description_linkage,
            render_shard_description_index,
        )
        selected_limits = IndexLimits(max_description_bytes=SHARD_HUMAN_BODY_BYTES) if limits is None else limits
        if type(selected_limits) is not IndexLimits or selected_limits.max_description_bytes > SHARD_HUMAN_BODY_BYTES:
            raise prdel.PrdelError("The local human-description profile is at most32KiB UTF-8; this is not a host compatibility claim.")
        selection = {"expected_manifest_digest": expected_manifest_digest,
            "expected_shard_digests": expected_shard_digests, "base": base, "head": head,
            "expected_source_digest": expected_source_digest,
            "requirements_digest": requirements_digest,
            "expected_required_residuals": expected_required_residuals,
            "limits": selected_limits}
        index = render_shard_description_index(manifest_bytes, shard_bytes, **selection)
        linkage = parse_shard_description_linkage(index, manifest_bytes, shard_bytes, **selection)
        _, selected_requirements_digest = prdel._requirements(requirements_bytes,
            requirements_digest if requirements_bytes is not None else None)
        if selected_requirements_digest != requirements_digest:
            raise prdel.PrdelError("Selected requirements digest differs.")
        carried = reconstruct_compilation(manifest_bytes, shard_bytes)
        replay = validate_prdel_shards(manifest_bytes, shard_bytes, root, base, head,
            requirements_bytes, requirements_digest if requirements_bytes is not None else None, definition)
        logical = prdel._validate_sharded_prdel(carried["document"], root, base, head,
            requirements_bytes, requirements_digest if requirements_bytes is not None else None,
            evidence_bytes, expected_evidence_digest)
        # Match the selected requirements independently; a default selection
        # cannot borrow an externally asserted requirements hash.
        statuses = [carried["status"], replay["status"], logical["status"]]
        status = "FAIL" if "FAIL" in statuses else "UNKNOWN" if "UNKNOWN" in statuses else "PASS"
        report = {"schema_version": SHARD_GATE_SCHEMA, "status": status,
            "scope": SHARD_GATE_SCOPE, "claim_boundary": prdel.BOUNDARY,
            "execution_provenance": "NOT_ESTABLISHED", "binding": linkage["binding"],
            "manifest_sha256": expected_manifest_digest, "shard_sha256": expected_shard_digests,
            "compilation_replay": replay, "logical_report": logical,
            "required_compilation_residuals": [row for row in carried["residuals"] if row["required"]],
            "required_native_findings": [row for row in logical["findings"] if row["status"] in {"FAIL", "UNKNOWN"}],
            "required_replay_findings": [], "description_digest": None,
            "admission_policy": {"schema_version": "verifier-prdel-shard-admission-profile-1",
                "max_packet_bytes": packet_budget_bytes, "max_description_bytes": selected_limits.max_description_bytes,
                "max_rows": selected_limits.max_rows, "leaf_inventory_operations": selected_limits.max_operations}}
        if replay["status"] != "PASS":
            report["required_replay_findings"].append({
                "code": "SHARDED_COMPILATION_REPLAY_" + replay["status"],
                "status": replay["status"],
                "reason": replay.get("reason", "Required compilation residuals remain unresolved; full selected artifacts retain them.")})
        body = _shard_gate_body(index, report, selected_limits.max_description_bytes)
        return {"body": body, "report": report}
    except (prdel.PrdelUnavailable, OSError) as exc:
        if report is not None:
            if report["status"] != "FAIL":
                report["status"] = "UNKNOWN"
            report["required_replay_findings"].append({"code": "SHARDED_OUTPUT_UNKNOWN", "status": "UNKNOWN",
                "reason": "Complete selected output could not be retained within its budget."})
            return {"body": None, "report": report}
        return {"body": None, "report": _shard_gate_error("UNKNOWN", str(exc))}
    except (prdel.PrdelError, ValueError, TypeError, KeyError, RecursionError, OverflowError) as exc:
        return {"body": None, "report": _shard_gate_error("FAIL", str(exc))}


def evaluate_prdel_shard_description(
    body: str, manifest_bytes: bytes, shard_bytes: list[bytes], root: Path, base: str, head: str,
    *, expected_manifest_digest: str, expected_shard_digests: list[str],
    expected_source_digest: str, requirements_digest: str,
    expected_required_residuals: list[dict[str, Any]],
    packet_budget_bytes: int | None = None,
    requirements_bytes: bytes | None = None, evidence_bytes: bytes | None = None,
    expected_evidence_digest: str | None = None, definition: dict[str, Any] | None = None,
    limits: Any = None,
) -> dict[str, Any]:
    """Recompute selected replay, predicates and the entire canonical human body."""
    try:
        from verifier.runtime.prdel_shard_index import IndexLimits, _bounded_body
        selected_limits = IndexLimits(max_description_bytes=SHARD_HUMAN_BODY_BYTES) if limits is None else limits
        if type(selected_limits) is not IndexLimits or selected_limits.max_description_bytes > SHARD_HUMAN_BODY_BYTES:
            raise prdel.PrdelError("Selected human-description budget exceeds the local profile.")
        _bounded_body(body, selected_limits)
        rendered = render_prdel_shard_description(manifest_bytes, shard_bytes, root, base, head,
            expected_manifest_digest=expected_manifest_digest, expected_shard_digests=expected_shard_digests,
            expected_source_digest=expected_source_digest, requirements_digest=requirements_digest,
            expected_required_residuals=expected_required_residuals, packet_budget_bytes=packet_budget_bytes, requirements_bytes=requirements_bytes,
            evidence_bytes=evidence_bytes, expected_evidence_digest=expected_evidence_digest,
            definition=definition, limits=limits)
        report = rendered["report"]
        if rendered["body"] is not None and body != rendered["body"]:
            marker = "\n## Required native gate findings\n"
            index_matches = (body.count(marker) == 1
                and body.split(marker, 1)[0] == rendered["body"].split(marker, 1)[0])
            unavailable = report["compilation_replay"]["status"] == "UNKNOWN"
            # An unavailable source cannot refute a previously rendered native
            # assessment. Known artifact/index mismatches still fail; unresolved
            # assessment prose remains UNKNOWN and can never clear the gate.
            mismatch_status = "UNKNOWN" if unavailable and index_matches else "FAIL"
            if mismatch_status == "FAIL":
                report["status"] = "FAIL"
            report["required_replay_findings"].append({"code": "SHARDED_DESCRIPTION_" + mismatch_status,
                "status": mismatch_status, "reason": "Complete native findings differ from the currently available assessment."})
        report["description_digest"] = prdel.digest(body.encode("utf-8"))
        return report
    except (prdel.PrdelUnavailable, OSError) as exc:
        return _shard_gate_error("UNKNOWN", str(exc))
    except (prdel.PrdelError, ValueError, TypeError, KeyError, RecursionError, OverflowError) as exc:
        return _shard_gate_error("FAIL", str(exc))
