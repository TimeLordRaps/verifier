"""Pure, bounded human index for Pull Request Domain Explanation Language (PRDEL) shards.

Terminology: identifier (ID); Secure Hash Algorithm 256-bit (SHA-256); Unicode
Transformation Format, 8-bit (UTF-8). This module checks packet linkage and
preserves every required compilation residual. It never assesses source claims,
execution evidence, gate clearance, or publication authority. Callers must run
independent source replay and logical gate validation separately.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any

from verifier.runtime import prdel, prdel_rules, prdel_shards


LINKAGE_VERSION = "verifier-prdel-shard-description-1"
_MAX_ROWS = prdel.MAX_REGIONS * 4
_MAX_OPERATIONS = 200_000
_HEX64 = re.compile(r"[0-9a-f]{64}\Z")
_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_RESIDUAL_FIELDS = {"index", "code", "status", "obligation_id", "requirement_id"}
_LINKAGE_FIELDS = {
    "schema_version", "binding", "manifest_sha256", "shard_sha256",
    "required_residuals_sha256",
}


class IndexErrorBound(ValueError):
    """Selected packet or compact description is malformed, stale, or outside bounds."""


@dataclass(frozen=True)
class IndexLimits:
    """Fixed output and declared-inventory ceilings, not a parser time limit."""

    max_description_bytes: int = prdel.MAX_DESCRIPTION_BYTES
    max_rows: int = _MAX_ROWS
    max_operations: int = _MAX_OPERATIONS

    def __post_init__(self) -> None:
        for value, ceiling in (
            (self.max_description_bytes, prdel.MAX_DESCRIPTION_BYTES),
            (self.max_rows, _MAX_ROWS),
            (self.max_operations, _MAX_OPERATIONS),
        ):
            if type(value) is not int or not 0 < value <= ceiling:
                raise IndexErrorBound("Index limits must be positive and within fixed ceilings.")


def _selected_digest(value: str) -> None:
    if type(value) is not str or _HEX64.fullmatch(value) is None:
        raise IndexErrorBound("An exact externally selected SHA-256 digest is required.")


def _required_rows(compilation: dict[str, Any], limits: IndexLimits) -> list[dict[str, Any]]:
    residuals = compilation.get("residuals")
    if type(residuals) is not list or len(residuals) > limits.max_rows:
        raise IndexErrorBound("Bounded complete compilation residuals required.")
    result = []
    for index, row in enumerate(residuals):
        if type(row) is not dict or type(row.get("required")) is not bool:
            raise IndexErrorBound("Malformed compilation residual.")
        if not row["required"]:
            continue
        if (
            type(row.get("code")) is not str or not row["code"]
            or type(row.get("status")) is not str
            or row["status"] not in {"FAIL", "UNKNOWN"}
            or any(value is not None and type(value) is not str
                   for value in (row.get("obligation_id"), row.get("requirement_id")))
        ):
            raise IndexErrorBound("Malformed required compilation residual.")
        result.append({
            "index": index,
            "code": row["code"],
            "status": row["status"],
            "obligation_id": row.get("obligation_id"),
            "requirement_id": row.get("requirement_id"),
        })
    return result


def _selected_rows(value: list[dict[str, Any]], limits: IndexLimits) -> None:
    if type(value) is not list or len(value) > limits.max_rows:
        raise IndexErrorBound("Bounded selected required residual inventory required.")
    for row in value:
        if type(row) is not dict or set(row) != _RESIDUAL_FIELDS:
            raise IndexErrorBound("Closed required residual selection required.")
        if (
            type(row["index"]) is not int or row["index"] < 0
            or type(row["code"]) is not str or not row["code"]
            or type(row["status"]) is not str or row["status"] not in {"FAIL", "UNKNOWN"}
            or any(item is not None and type(item) is not str
                   for item in (row["obligation_id"], row["requirement_id"]))
        ):
            raise IndexErrorBound("Invalid required residual selection.")


def _bounded_body(body: str, limits: IndexLimits) -> None:
    """Count UTF-8 incrementally after a constant-time character preflight."""
    if type(limits) is not IndexLimits or type(body) is not str:
        raise IndexErrorBound("Explicit finite limits and a text body are required.")
    if len(body) > limits.max_description_bytes:
        raise IndexErrorBound("Bounded UTF-8 shard description required.")
    used = 0
    try:
        for offset in range(0, len(body), 8192):
            used += len(body[offset:offset + 8192].encode("utf-8"))
            if used > limits.max_description_bytes:
                raise IndexErrorBound("Bounded UTF-8 shard description required.")
    except UnicodeError as exc:
        raise IndexErrorBound("Valid UTF-8 shard description required.") from exc


def _packet_index(
    manifest_bytes: bytes,
    shard_bytes: list[bytes],
    *,
    expected_manifest_digest: str,
    expected_shard_digests: list[str],
    base: str,
    head: str,
    expected_source_digest: str,
    requirements_digest: str,
    expected_required_residuals: list[dict[str, Any]],
    limits: IndexLimits,
) -> tuple[dict[str, Any], dict[str, Any], list[dict[str, Any]], list[tuple[str, dict[str, int]]]]:
    if type(limits) is not IndexLimits:
        raise IndexErrorBound("Explicit finite index limits required.")
    _selected_digest(expected_manifest_digest)
    _selected_digest(expected_source_digest)
    _selected_digest(requirements_digest)
    if (
        type(base) is not str or _COMMIT.fullmatch(base) is None
        or type(head) is not str or _COMMIT.fullmatch(head) is None
        or type(manifest_bytes) is not bytes
        or type(shard_bytes) is not list
        or not shard_bytes or len(shard_bytes) > limits.max_rows
        or type(expected_shard_digests) is not list
        or len(expected_shard_digests) != len(shard_bytes)
    ):
        raise IndexErrorBound("Complete selected packet and exact commits required.")
    artifact_limit = min(prdel_rules.MAX_COMPILED_BYTES, prdel.MAX_DOCUMENT_BYTES)
    if (
        len(manifest_bytes) > artifact_limit
        or any(type(raw) is not bytes or len(raw) > artifact_limit for raw in shard_bytes)
    ):
        raise IndexErrorBound("Existing per-artifact byte bound exceeded.")
    _selected_rows(expected_required_residuals, limits)
    if hashlib.sha256(manifest_bytes).hexdigest() != expected_manifest_digest:
        raise IndexErrorBound("Selected manifest digest differs.")
    for raw, selected in zip(shard_bytes, expected_shard_digests):
        _selected_digest(selected)
        if hashlib.sha256(raw).hexdigest() != selected:
            raise IndexErrorBound("Selected ordered shard digest differs.")
    try:
        manifest = prdel.decode(manifest_bytes)
        inventory = manifest.get("obligation_ids")
        source_ids = manifest.get("selected_source_ids")
        entries = manifest.get("shards")
        header = manifest.get("compilation_header")
        residuals = header.get("residuals") if type(header) is dict else None
        if (
            type(inventory) is not list or type(source_ids) is not list
            or type(entries) is not list or type(residuals) is not list
            or len(inventory) > limits.max_rows
            or len(source_ids) > limits.max_rows
            or len(entries) > limits.max_rows
            or len(residuals) > limits.max_rows
        ):
            raise IndexErrorBound("Declared inventory exceeds the selected row bound.")
        # A conservative upper bound for this leaf's list traversals. It is not
        # a wall-clock or JSON-parser operation claim; every wire stays bounded.
        if len(entries) + 2 * len(inventory) + len(residuals) > limits.max_operations:
            raise IndexErrorBound("Declared index inventory exceeds the operation bound.")
        compilation = prdel_shards.reconstruct_compilation(manifest_bytes, shard_bytes)
    except IndexErrorBound:
        raise
    except (prdel.PrdelError, ValueError, TypeError, KeyError, RecursionError, OverflowError) as exc:
        raise IndexErrorBound("Canonical bounded shard packet required.") from exc
    binding = compilation["binding"]
    if (
        type(binding) is not dict
        or set(binding) != {"base", "head", "source_digest", "requirements_digest"}
        or binding["base"] != base or binding["head"] != head
        or binding["requirements_digest"] != requirements_digest
        or binding["source_digest"] != expected_source_digest
        or type(binding["source_digest"]) is not str
        or _HEX64.fullmatch(binding["source_digest"]) is None
    ):
        raise IndexErrorBound("Exact selected source or requirements binding differs.")
    required = _required_rows(compilation, limits)
    if required != expected_required_residuals:
        raise IndexErrorBound("Required residual inventory differs or is reordered.")
    expected_status = (
        "FAIL" if any(row["status"] == "FAIL" for row in required)
        else "UNKNOWN" if required else "PASS"
    )
    if compilation.get("status") != expected_status:
        raise IndexErrorBound("Compilation status contradicts required residuals.")
    rows = compilation["document"]["source_obligations"]
    if type(rows) is not list or len(rows) > limits.max_rows:
        raise IndexErrorBound("Bounded complete obligation inventory required.")
    paths: dict[str, dict[str, int]] = {}
    for row in rows:
        if (
            type(row) is not dict or type(row.get("path")) is not str
            or type(row.get("kind")) is not str
            or row["kind"] not in {"source", "contract", "frontier"}
        ):
            raise IndexErrorBound("Malformed indexed obligation.")
        counts = paths.setdefault(row["path"], {"source": 0, "contract": 0, "frontier": 0})
        counts[row["kind"]] += 1
    if len(shard_bytes) + len(rows) + len(required) + len(paths) > limits.max_operations:
        raise IndexErrorBound("Index operation bound exhausted; no abbreviated index produced.")
    linkage = {
        "schema_version": LINKAGE_VERSION,
        "binding": binding,
        "manifest_sha256": expected_manifest_digest,
        "shard_sha256": expected_shard_digests,
        "required_residuals_sha256": hashlib.sha256(prdel.canonical(required)).hexdigest(),
    }
    return linkage, manifest, required, sorted(paths.items())


def render_shard_description_index(
    manifest_bytes: bytes,
    shard_bytes: list[bytes],
    *,
    expected_manifest_digest: str,
    expected_shard_digests: list[str],
    base: str,
    head: str,
    expected_source_digest: str,
    requirements_digest: str,
    expected_required_residuals: list[dict[str, Any]],
    limits: IndexLimits = IndexLimits(),
) -> str:
    """Render all path counts and required residuals without repeating record prose."""
    linkage, manifest, required, paths = _packet_index(
        manifest_bytes, shard_bytes,
        expected_manifest_digest=expected_manifest_digest,
        expected_shard_digests=expected_shard_digests,
        base=base, head=head, expected_source_digest=expected_source_digest,
        requirements_digest=requirements_digest,
        expected_required_residuals=expected_required_residuals, limits=limits,
    )
    compilation = manifest["compilation_header"]
    if compilation["status"] not in {"PASS", "FAIL", "UNKNOWN"}:
        raise IndexErrorBound("Malformed compilation status.")
    lines = [
        "# Source-bound sharded change index", "", "## Coordinate", "",
        f"Current head: `{head}`", f"Base: `{base}`",
        f"Source digest: `{linkage['binding']['source_digest']}`",
        f"Requirements digest: `{requirements_digest}`", "",
        prdel.BOUNDARY, "", "## Packet", "",
        f"Manifest SHA-256: `{expected_manifest_digest}`",
        f"Obligations: {len(manifest['obligation_ids'])}",
        f"Selected source regions: {len(manifest['selected_source_ids'])}",
        f"Compilation status: {compilation['status']}",
        "Gate status: NOT_ASSESSED", "",
    ]
    emitted_bytes = sum(len(line.encode("utf-8")) + 1 for line in lines)

    def append(line: str) -> None:
        nonlocal emitted_bytes
        emitted_bytes += len(line.encode("utf-8")) + 1
        if emitted_bytes > limits.max_description_bytes:
            raise IndexErrorBound("Compact description byte bound exhausted; no trimmed body produced.")
        lines.append(line)

    if emitted_bytes > limits.max_description_bytes:
        raise IndexErrorBound("Compact description byte bound exhausted; no trimmed body produced.")
    for entry in manifest["shards"]:
        append(
            f"- Shard {entry['index']}: SHA-256 `{entry['sha256']}`; "
            f"{entry['bytes']} bytes; {len(entry['obligation_ids'])} obligations."
        )
    for line in ("", "## Changed paths and retained relationships", ""):
        append(line)
    for path, counts in paths:
        append(
            f"- {json.dumps(path, ensure_ascii=True)}: "
            f"{counts['source']} source, {counts['contract']} contract, "
            f"{counts['frontier']} frontier obligations."
        )
    for line in ("", "## Required compilation residuals", ""):
        append(line)
    for row in required:
        append(
            f"- {row['index']}: {json.dumps(row['status'])} "
            f"{json.dumps(row['code'], ensure_ascii=True)}; "
            f"obligation {json.dumps(row['obligation_id'], ensure_ascii=True)}; "
            f"requirement {json.dumps(row['requirement_id'], ensure_ascii=True)}."
        )
    for line in (
        "", "The manifest and ordered shards retain full claims, source changes, "
        "frontiers, records, limits and residual reasons. This index is linkage "
        "only; independent replay and gate validation remain required.",
        "", "```vstd-prdel-shards", prdel.canonical(linkage).decode("utf-8"), "```",
    ):
        append(line)
    body = "\n".join(lines).rstrip() + "\n"
    return body


def parse_shard_description_linkage(
    body: str,
    manifest_bytes: bytes,
    shard_bytes: list[bytes],
    *,
    expected_manifest_digest: str,
    expected_shard_digests: list[str],
    base: str,
    head: str,
    expected_source_digest: str,
    requirements_digest: str,
    expected_required_residuals: list[dict[str, Any]],
    limits: IndexLimits = IndexLimits(),
) -> dict[str, Any]:
    """Require exactly the selected canonical index and one closed linkage block."""
    _bounded_body(body, limits)
    expected = render_shard_description_index(
        manifest_bytes, shard_bytes,
        expected_manifest_digest=expected_manifest_digest,
        expected_shard_digests=expected_shard_digests,
        base=base, head=head, expected_source_digest=expected_source_digest,
        requirements_digest=requirements_digest,
        expected_required_residuals=expected_required_residuals, limits=limits,
    )
    if body != expected or body.count("```vstd-prdel-shards\n") != 1:
        raise IndexErrorBound("Exactly the selected canonical sharded index is required.")
    raw = body.split("```vstd-prdel-shards\n", 1)[1].split("\n```\n", 1)[0].encode("utf-8")
    try:
        linkage = prdel.decode(raw)
    except (prdel.PrdelError, ValueError, TypeError) as exc:
        raise IndexErrorBound("Canonical closed shard linkage required.") from exc
    if set(linkage) != _LINKAGE_FIELDS or linkage["schema_version"] != LINKAGE_VERSION:
        raise IndexErrorBound("Closed shard linkage fields required.")
    return linkage
