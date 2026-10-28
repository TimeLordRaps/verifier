"""Bounded, source-neutral Pull Request Domain Explanation Language (PRDEL) shard index controls."""

from __future__ import annotations

import copy
import hashlib
import json

import pytest

from verifier.runtime import prdel, prdel_rules, prdel_shards, prdel_shard_index
from verifier.runtime.prdel_shard_index import (
    IndexErrorBound,
    IndexLimits,
    parse_shard_description_linkage,
    render_shard_description_index,
)


def _packet(monkeypatch: pytest.MonkeyPatch) -> tuple[bytes, list[bytes], dict]:
    monkeypatch.setattr(prdel_rules, "MAX_COMPILED_BYTES", 12000)
    binding = {
        "base": "a" * 40,
        "head": "b" * 40,
        "source_digest": "c" * 64,
        "requirements_digest": "d" * 64,
    }
    rows = [
        {
            "id": f"source:{index:02d}",
            "kind": "source",
            "path": f"path-{index}.py",
            "question": "Retain exact source.",
            "old_text": "a" * 900,
            "new_text": "b" * 900,
        }
        for index in range(8)
    ]
    records = [
        {
            "id": row["id"],
            "requirement_ids": [],
            "why": {"requirement_id": None, "quote": ""},
            "claims": [],
            "summary": "s" * 1800,
            "limits": [],
            "coverage": {},
        }
        for row in rows
    ]
    document = {
        "schema_version": prdel.SCHEMA,
        "binding": binding,
        "requirements": prdel.DEFAULT_REQUIREMENTS,
        "source_obligations": rows,
        "records": records,
        "evidence": [],
        "impact_graph": {"frontier": [{"path": "unknown", "status": "UNKNOWN"}]},
    }
    residuals = [
        prdel_rules._residual("UNRESOLVED_ANALYSIS_FRONTIER", "UNKNOWN", "Unknown.", obligation_id="source:00"),
        prdel_rules._residual("MISSING_REQUIRED_CLAIM", "FAIL", "Missing.", obligation_id="source:01"),
        prdel_rules._residual("AUTHOR_MOTIVATION_UNRESOLVED", "UNKNOWN", "Optional.", required=False),
    ]
    compiled = prdel_rules._envelope(document, None, [], residuals, prdel_rules._Work())
    packet = prdel_shards.partition_compilation(compiled)
    return prdel.canonical(packet["manifest"]), [prdel.canonical(shard) for shard in packet["shards"]], binding


def _selection(manifest: bytes, shards: list[bytes], binding: dict) -> dict:
    residuals = json.loads(manifest)["compilation_header"]["residuals"]
    return {
        "expected_manifest_digest": hashlib.sha256(manifest).hexdigest(),
        "expected_shard_digests": [hashlib.sha256(raw).hexdigest() for raw in shards],
        "base": binding["base"],
        "head": binding["head"],
        "expected_source_digest": binding["source_digest"],
        "requirements_digest": binding["requirements_digest"],
        "expected_required_residuals": [
            {"index": index, "code": row["code"], "status": row["status"],
             "obligation_id": row["obligation_id"], "requirement_id": row["requirement_id"]}
            for index, row in enumerate(residuals) if row["required"]
        ],
    }


def test_exact_roundtrip_retains_ordered_packet_and_every_required_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    manifest, shards, binding = _packet(monkeypatch)
    selected = _selection(manifest, shards, binding)
    assert len(shards) > 1
    body = render_shard_description_index(manifest, shards, **selected)
    linkage = parse_shard_description_linkage(body, manifest, shards, **selected)
    assert linkage["manifest_sha256"] == selected["expected_manifest_digest"]
    assert linkage["shard_sha256"] == selected["expected_shard_digests"]
    assert linkage["required_residuals_sha256"] == hashlib.sha256(prdel.canonical(selected["expected_required_residuals"])).hexdigest()
    assert "UNRESOLVED_ANALYSIS_FRONTIER" in body
    assert "MISSING_REQUIRED_CLAIM" in body
    assert "AUTHOR_MOTIVATION_UNRESOLVED" not in body
    assert "Gate status: NOT_ASSESSED" in body
    assert "Compilation status: FAIL" in body
    assert body == render_shard_description_index(manifest, shards, **selected)


@pytest.mark.parametrize("mutation", ["omission", "duplicate", "reorder", "shard_digest", "manifest_digest", "base", "head", "source", "requirements", "residual_omission", "residual_duplicate", "residual_reorder"])
def test_external_selection_and_order_are_mandatory(monkeypatch: pytest.MonkeyPatch, mutation: str) -> None:
    manifest, shards, binding = _packet(monkeypatch)
    selected = _selection(manifest, shards, binding)
    if mutation == "omission":
        shards.pop()
    elif mutation == "duplicate":
        shards.append(shards[0])
    elif mutation == "reorder":
        shards.reverse()
    elif mutation == "shard_digest":
        selected["expected_shard_digests"][0] = "e" * 64
    elif mutation == "manifest_digest":
        selected["expected_manifest_digest"] = "e" * 64
    elif mutation in {"base", "head", "source", "requirements"}:
        key = {"source": "expected_source_digest", "requirements": "requirements_digest"}.get(mutation, mutation)
        selected[key] = "e" * (40 if mutation in {"base", "head"} else 64)
    elif mutation == "residual_omission":
        selected["expected_required_residuals"].pop()
    elif mutation == "residual_duplicate":
        selected["expected_required_residuals"].append(copy.deepcopy(selected["expected_required_residuals"][0]))
    else:
        selected["expected_required_residuals"].reverse()
    with pytest.raises(IndexErrorBound):
        render_shard_description_index(manifest, shards, **selected)


@pytest.mark.parametrize("mutation", ["extra_prose", "duplicate_block", "noncanonical_block", "substituted_manifest", "missing_block"])
def test_parser_refuses_ambiguous_or_substituted_body(monkeypatch: pytest.MonkeyPatch, mutation: str) -> None:
    manifest, shards, binding = _packet(monkeypatch)
    selected = _selection(manifest, shards, binding)
    body = render_shard_description_index(manifest, shards, **selected)
    if mutation == "extra_prose":
        body += "PASS\n"
    elif mutation == "duplicate_block":
        body += body[body.index("```vstd-prdel-shards"):]
    elif mutation == "noncanonical_block":
        body = body.replace('"schema_version":', '"schema_version": ')
    elif mutation == "substituted_manifest":
        body = body.replace(selected["expected_manifest_digest"], "e" * 64)
    else:
        body = body[:body.index("```vstd-prdel-shards")]
    with pytest.raises(IndexErrorBound):
        parse_shard_description_linkage(body, manifest, shards, **selected)


def test_limits_fail_closed_without_truncation(monkeypatch: pytest.MonkeyPatch) -> None:
    manifest, shards, binding = _packet(monkeypatch)
    selected = _selection(manifest, shards, binding)
    for limits in (IndexLimits(max_description_bytes=64), IndexLimits(max_rows=1), IndexLimits(max_operations=1)):
        with pytest.raises(IndexErrorBound):
            render_shard_description_index(manifest, shards, limits=limits, **selected)
    with pytest.raises(IndexErrorBound):
        IndexLimits(max_description_bytes=prdel.MAX_DESCRIPTION_BYTES + 1)


def test_self_consistent_manifest_substitution_still_needs_external_source_pin(monkeypatch: pytest.MonkeyPatch) -> None:
    manifest, shards, binding = _packet(monkeypatch)
    selected = _selection(manifest, shards, binding)
    substituted = json.loads(manifest)
    changed = "e" * 64
    substituted["document_header"]["binding"]["source_digest"] = changed
    substituted["compilation_header"]["binding"]["source_digest"] = changed
    changed_shards = [json.loads(raw) for raw in shards]
    for shard in changed_shards:
        shard["binding"]["source_digest"] = changed
    shards = [prdel.canonical(shard) for shard in changed_shards]
    for entry, raw in zip(substituted["shards"], shards):
        entry["sha256"] = hashlib.sha256(raw).hexdigest()
        entry["bytes"] = len(raw)
    manifest = prdel.canonical(substituted)
    selected["expected_manifest_digest"] = hashlib.sha256(manifest).hexdigest()
    selected["expected_shard_digests"] = [hashlib.sha256(raw).hexdigest() for raw in shards]
    with pytest.raises(IndexErrorBound):
        render_shard_description_index(manifest, shards, **selected)


@pytest.mark.parametrize("mutation", ["noncanonical_manifest", "duplicate_key", "invalid_utf8", "manifest_bound", "shard_bound"])
def test_wire_serialization_and_existing_artifact_bounds_fail_closed(monkeypatch: pytest.MonkeyPatch, mutation: str) -> None:
    manifest, shards, binding = _packet(monkeypatch)
    selected = _selection(manifest, shards, binding)
    if mutation == "noncanonical_manifest":
        manifest = json.dumps(json.loads(manifest), indent=2).encode()
    elif mutation == "duplicate_key":
        manifest = manifest.replace(b'{"compilation_header":', b'{"compilation_header":null,"compilation_header":', 1)
    elif mutation == "invalid_utf8":
        shards[0] += b"\xff"
    elif mutation == "manifest_bound":
        monkeypatch.setattr(prdel, "MAX_DOCUMENT_BYTES", len(manifest) - 1)
    else:
        monkeypatch.setattr(prdel, "MAX_DOCUMENT_BYTES", len(shards[0]) - 1)
    if mutation in {"noncanonical_manifest", "duplicate_key"}:
        selected["expected_manifest_digest"] = hashlib.sha256(manifest).hexdigest()
    if mutation == "invalid_utf8":
        selected["expected_shard_digests"][0] = hashlib.sha256(shards[0]).hexdigest()
    with pytest.raises(IndexErrorBound):
        render_shard_description_index(manifest, shards, **selected)


def test_malformed_retained_residual_fails_closed(monkeypatch: pytest.MonkeyPatch) -> None:
    manifest, shards, binding = _packet(monkeypatch)
    selected = _selection(manifest, shards, binding)
    value = json.loads(manifest)
    value["compilation_header"]["residuals"][0]["status"] = []
    manifest = prdel.canonical(value)
    selected["expected_manifest_digest"] = hashlib.sha256(manifest).hexdigest()
    with pytest.raises(IndexErrorBound):
        render_shard_description_index(manifest, shards, **selected)


def test_required_residual_cannot_be_presented_as_compilation_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    manifest, shards, binding = _packet(monkeypatch)
    selected = _selection(manifest, shards, binding)
    value = json.loads(manifest)
    value["compilation_header"]["status"] = "PASS"
    manifest = prdel.canonical(value)
    selected["expected_manifest_digest"] = hashlib.sha256(manifest).hexdigest()
    with pytest.raises(IndexErrorBound):
        render_shard_description_index(manifest, shards, **selected)


@pytest.mark.parametrize("target", ["manifest", "shard"])
def test_artifact_size_preflight_precedes_hashing(monkeypatch: pytest.MonkeyPatch, target: str) -> None:
    manifest, shards, binding = _packet(monkeypatch)
    selected = _selection(manifest, shards, binding)
    ceiling = prdel_rules.MAX_COMPILED_BYTES
    if target == "manifest":
        manifest += b" " * (ceiling + 1 - len(manifest))
        selected["expected_manifest_digest"] = hashlib.sha256(manifest).hexdigest()
    else:
        shards[0] += b" " * (ceiling + 1 - len(shards[0]))
        selected["expected_shard_digests"][0] = hashlib.sha256(shards[0]).hexdigest()

    def forbidden_hash(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("oversized artifact was hashed before admission")

    monkeypatch.setattr(prdel_shard_index.hashlib, "sha256", forbidden_hash)
    with pytest.raises(IndexErrorBound):
        render_shard_description_index(manifest, shards, **selected)


@pytest.mark.parametrize("target", ["manifest", "shard"])
def test_lowered_decoder_ceiling_precedes_hashing(monkeypatch: pytest.MonkeyPatch, target: str) -> None:
    manifest, shards, binding = _packet(monkeypatch)
    selected = _selection(manifest, shards, binding)
    if target == "manifest":
        monkeypatch.setattr(prdel, "MAX_DOCUMENT_BYTES", len(manifest) - 1)
    else:
        decoder_limit = prdel_rules.MAX_COMPILED_BYTES - 1
        shards[0] += b" " * (decoder_limit + 1 - len(shards[0]))
        selected["expected_shard_digests"][0] = hashlib.sha256(shards[0]).hexdigest()
        monkeypatch.setattr(prdel, "MAX_DOCUMENT_BYTES", decoder_limit)

    def forbidden_hash(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("decoder-oversized artifact was hashed before admission")

    monkeypatch.setattr(prdel_shard_index.hashlib, "sha256", forbidden_hash)
    with pytest.raises(IndexErrorBound):
        render_shard_description_index(manifest, shards, **selected)


@pytest.mark.parametrize(
    "body,limits",
    [("short", None), ("\ud800", IndexLimits()), ("x" * 1000, IndexLimits(max_description_bytes=64))],
    ids=["invalid-limits", "surrogate", "oversized-text"],
)
def test_parser_rejects_invalid_limits_surrogates_and_oversized_text(body: str, limits: IndexLimits | None, monkeypatch: pytest.MonkeyPatch) -> None:
    manifest, shards, binding = _packet(monkeypatch)
    selected = _selection(manifest, shards, binding)
    with pytest.raises(IndexErrorBound):
        parse_shard_description_linkage(body, manifest, shards, limits=limits, **selected)


@pytest.mark.parametrize("limit", ["rows", "operations"])
def test_inventory_preflight_precedes_reconstruction(monkeypatch: pytest.MonkeyPatch, limit: str) -> None:
    manifest, shards, binding = _packet(monkeypatch)
    selected = _selection(manifest, shards, binding)

    def forbidden_reconstruction(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("reconstruction began before inventory admission")

    monkeypatch.setattr(prdel_shards, "reconstruct_compilation", forbidden_reconstruction)
    limits = IndexLimits(max_rows=1) if limit == "rows" else IndexLimits(max_operations=1)
    with pytest.raises(IndexErrorBound):
        render_shard_description_index(manifest, shards, limits=limits, **selected)


def test_compilation_pass_does_not_assert_gate_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    manifest, shards, binding = _packet(monkeypatch)
    value = json.loads(manifest)
    value["compilation_header"]["residuals"] = value["compilation_header"]["residuals"][2:]
    value["compilation_header"]["status"] = "PASS"
    manifest = prdel.canonical(value)
    selected = _selection(manifest, shards, binding)
    body = render_shard_description_index(manifest, shards, **selected)
    assert "Compilation status: PASS" in body
    assert "Gate status: NOT_ASSESSED" in body
    assert parse_shard_description_linkage(body, manifest, shards, **selected)["schema_version"] == prdel_shard_index.LINKAGE_VERSION
