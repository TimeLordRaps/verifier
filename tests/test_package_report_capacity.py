"""Verifier Standard (VSTD) command-line interface (CLI) report capacity.

Terminology: JavaScript Object Notation (JSON).

Terminology: gigabyte (GB).
"""
from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from verifier.runtime import core_obligation_union as binding
from verifier.runtime import core_tier_progression
from verifier.runtime import manifest_gate
from verifier.runtime import package_manifest_refresh
from verifier.runtime import package_polish as package
from verifier.runtime import package_polish_schema_validation
from verifier.runtime import self_polish_tiers as cli
from verifier.runtime import tier_zero_manifest
from verifier.runtime.package_kind_requirements import accepts_subject


def _capacity_fixture_rows() -> tuple[list[dict], list[dict]]:
    declarations = [
        ("subject-1", "GRAPH"),
        ("actor-1", "ACTOR"),
        ("actor-2", "ACTOR"),
        *[(f"object-{index}", "OBJECT") for index in range(23)],
    ]
    rows = []
    graph_objects = []
    cells = core_tier_progression.installed_core_route_inventory()[
        "family_cells"
    ]
    for object_id, kind in declarations:
        object_digest = binding.value_digest({
            "object_id": object_id,
            "kind": kind,
        })
        graph_objects.append({
            "object_id": object_id,
            "kind": kind,
            "object_digest": object_digest,
            "specializations": [],
        })
        for cell in cells:
            if cell["object_kind"] != kind or cell["tier"] > 3:
                continue
            for installed in cell["registered_route_memberships"]:
                route = {
                    **installed,
                    "object_kind": kind,
                    "tier": cell["tier"],
                }
                if not accepts_subject(route, kind):
                    continue
                identity = {
                    "object_id": object_id,
                    "object_digest": object_digest,
                    "coordinate": route["coordinate"],
                    "tier": route["tier"],
                    "proposition_digest": route["proposition_digest"],
                }
                rows.append({
                    **identity,
                    "object_kind": kind,
                    "declared_kind": kind,
                    "specializations": [],
                    "checking_mechanism": route["checking_mechanism"],
                    "scope": route["scope"],
                    "status": "UNKNOWN",
                    "checker_status": "NOT_RUN",
                    "instance_digest": binding.value_digest(identity),
                    "blockers": ["PACKAGE_INSTANCE_EVIDENCE_MISSING"],
                    "selected_package_check": None,
                })
    assert len(rows) == 101
    return rows, graph_objects


def _capacity_denominator_commitment(rows: list[dict]) -> dict:
    index = [{
        "object_id": row["object_id"],
        "object_kind": row["object_kind"],
        "coordinate": row["coordinate"],
        "tier": row["tier"],
        "instance_digest": row["instance_digest"],
    } for row in rows]
    index.sort(key=lambda item: (
        item["tier"], item["object_id"], item["coordinate"],
        item["object_kind"], item["instance_digest"],
    ))
    body = {
        "schema_version":
            "verifier-package-obligation-denominator-commitment-1",
        "status": "COMMITTED",
        "selected_instance_count": len(index),
        "selected_instance_index_digest": binding.value_digest(index),
        "conditional_refutation_count": 0,
        "conditional_refutations": [],
        "conditional_refutations_digest": binding.value_digest([]),
        "claim_boundary": "Synthetic exact denominator commitment.",
    }
    return {**body, "commitment_digest": binding.value_digest(body)}


def test_capacity_receipt_binds_projected_conditional_commitment_to_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = next(
        row for row in manifest_gate.obligation_catalog()
        if row["object_kind"] == "OBJECT"
        and row["tier"] == 1
        and row["coordinate"] == "OBJECT-1.2"
    )
    check_body = {
        "status": "PASS",
        "evidence_origin": "INSTALLED_SOURCE_VARIANT_APPLICABILITY_REVIEW",
        "object_id": "subject",
        "object_digest": "sha256:" + "1" * 64,
        "collection_digest": "sha256:" + "a" * 64,
        "applicability_established": True,
        "applicability_classification": "CONDITION_NOT_MET",
        "fulfillment_required": False,
        "native_coordinate": route["coordinate"],
        "conditional_coordinate": route["coordinate"],
        "adaptation_obligation_id": "object-conditional-variant",
        "adaptation_result_digest": "sha256:" + "4" * 64,
        "condition": route["applicability"]["condition"],
        "applicability_digest": route["applicability_digest"],
        "condition_status": "NOT_TRIGGERED",
        "reason": "The source does not select this variant.",
    }
    check = {
        **check_body,
        "result_digest": binding.value_digest(check_body),
    }
    identity = {
        "object_id": "subject",
        "object_digest": "sha256:" + "1" * 64,
        "coordinate": route["coordinate"],
        "tier": route["tier"],
        "proposition_digest": route["proposition_digest"],
    }
    row = {
        **identity,
        "object_kind": "OBJECT",
        "instance_digest": binding.value_digest(identity),
        "status": "PASS",
        "checker_status": "NOT_REQUIRED",
        "blockers": [],
        "selected_package_check": check,
    }
    conditional_refutations = package._conditional_refutation_index([row])
    compact_body = {
        "schema_version": (
            "verifier-package-obligation-denominator-commitment-2"
        ),
        "status": "COMMITTED",
        "selected_instance_count": 1,
        "selected_instance_index_digest": binding.value_digest([{
            "object_id": row["object_id"],
            "object_kind": row["object_kind"],
            "coordinate": row["coordinate"],
            "tier": row["tier"],
            "instance_digest": row["instance_digest"],
        }]),
        "conditional_refutation_count": 1,
        "conditional_refutations_digest": binding.value_digest(
            conditional_refutations
        ),
        "conditional_refutations_transport": (
            "RECONSTRUCT_FROM_PROJECTED_ROWS"
        ),
        "claim_boundary": "Projected rows retain the conditional evidence.",
    }
    report = {
        "schema_version": package.EXTENSIBLE_REPORT_SCHEMA,
        "kind_denominators": package.namespace_contracts.kind_denominators(),
        "requested_tier": 1,
        "status": "PASS",
        "blockers": [],
        "manifest": {},
        "package_graph": {"objects": []},
        "verifier_execution": {
            "obligation_denominator_commitment": {
                **compact_body,
                "commitment_digest": binding.value_digest(compact_body),
            }
        },
        "pass_instance_definitions": [],
        "obligation_instance_projection": {
            "schema_version": "verifier-pass-instance-projection-2",
        },
        "obligation_instances": [row],
        "tier_results": [],
    }
    monkeypatch.setattr(
        manifest_gate,
        "obligation_catalog",
        lambda: [route],
    )
    monkeypatch.setattr(manifest_gate, "package_findings", lambda _: [])
    monkeypatch.setattr(
        manifest_gate,
        "repository_finding",
        lambda *_, **__: {"gate_id": "capacity", "status": "UNKNOWN"},
    )
    monkeypatch.setattr(
        package, "_capacity_denominator_complete", lambda *args, **kwargs: True,
    )

    source_digest = binding.bytes_digest(binding.canonical_bytes(report))
    receipt = package._capacity_receipt(report)
    retained = receipt["package_graph_reference"][
        "obligation_denominator_commitment"
    ]

    assert retained["schema_version"] == (
        "verifier-package-obligation-denominator-commitment-3"
    )
    assert "conditional_refutations" not in retained
    assert retained["conditional_refutations_digest"] == binding.value_digest(
        conditional_refutations
    )
    assert retained["conditional_refutations_transport"] == (
        "REPLAY_FROM_DIGEST_BOUND_SOURCE_REPORT"
    )
    assert retained["source_report_digest"] == source_digest
    assert retained["commitment_digest"] == binding.value_digest({
        key: value for key, value in retained.items()
        if key != "commitment_digest"
    })


def _accept_deliberately_schema_invalid_formatter_fixture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """These fixtures mutate report shape solely to exercise wire encoding."""
    monkeypatch.setattr(
        package_polish_schema_validation,
        "validate_package_polish_report",
        lambda report: package_polish_schema_validation.PackagePolishSchemaValidation(
            schema_version=report.get("schema_version"),
            schema_supported=True,
            valid=True,
            errors=(),
        ),
    )


def test_capacity_receipt_retains_compact_self_polish_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    self_polish = {
        "schema_version": "verifier-package-self-polish-graph-1",
        "status": "UNKNOWN",
        "aggregate_verifier_id": "verifier-core-self",
        "aggregate_verifier_digest": "sha256:" + "1" * 64,
        "verified_graph_id": "vstd-package-graph",
        "verified_graph_digest": "sha256:" + "2" * 64,
        "requested_tier": 1,
        "member_verifier_count": 2,
        "member_status_counts": {"PASS": 1, "UNKNOWN": 1},
        "member_verifier_digest": "sha256:" + "3" * 64,
        "member_verifiers": [{
            "verifier_id": "unknown-member", "declared_kind": "DATA",
            "verifier_classification": "UNRESOLVED",
            "owner_resolution": "EXACT", "mechanism_count": 1,
            "mechanism_digest": "sha256:" + "a" * 64,
            "subject_object_count": 1,
            "subject_object_digest": "sha256:" + "b" * 64,
            "obligation_instance_count": 1,
            "obligation_instance_digest": "sha256:" + "c" * 64,
            "status_counts": {"UNKNOWN": 1}, "status": "UNKNOWN",
            "blockers": ["MEMBER_VERIFIER_CLASSIFICATION_NOT_ESTABLISHED"],
            "member_digest": "sha256:" + "d" * 64,
        }],
        "edge_count": 2,
        "edge_digest": "sha256:" + "4" * 64,
        "polish_system_subject_count": 1,
        "polish_system_status": "UNKNOWN",
        "polish_system_subject_digest": "sha256:" + "5" * 64,
        "polish_system_subjects": [{
            "object_id": "polish-source", "aggregate": False,
            "obligation_instance_count": 1,
            "obligation_instance_digest": "sha256:" + "e" * 64,
            "status_counts": {"UNKNOWN": 1}, "status": "UNKNOWN",
            "blockers": ["POLISH_SYSTEM_OBLIGATIONS_NOT_PASS"],
            "subject_digest": "sha256:" + "f" * 64,
        }],
        "tier_results": [{"tier": 1, "status": "UNKNOWN"}],
        "blockers": ["SELF_POLISH_MEMBER_UNKNOWN"],
        "aggregate_result_is_member_evidence": False,
        "self_application_authority": "NOT_ESTABLISHED",
        "graph_digest": "sha256:" + "6" * 64,
        "claim_boundary": "Aggregate results cannot supply member evidence.",
    }
    report = {
        "schema_version": package.EXTENSIBLE_REPORT_SCHEMA,
        "kind_denominators": package.namespace_contracts.kind_denominators(),
        "requested_tier": 1,
        "status": "UNKNOWN",
        "blockers": [],
        "manifest": {},
        "package_graph": {
            "status": "PASS", "root_id": "vstd-package-graph",
            "root_kind": "GRAPH", "manifest_digest": "sha256:" + "7" * 64,
            "collection_digest": "sha256:" + "8" * 64, "object_count": 0,
            "objects": [],
        },
        "verifier_execution": {"self_polish": self_polish},
        "obligation_instances": [],
        "tier_results": [],
    }
    monkeypatch.setattr(package, "_capacity_denominator_complete", lambda *a, **k: False)
    receipt = package._capacity_receipt(report)
    reference = receipt["package_graph_reference"]["self_polish_reference"]
    assert reference["aggregate_verifier_id"] == "verifier-core-self"
    assert reference["verified_graph_id"] == "vstd-package-graph"
    assert reference["aggregate_result_is_member_evidence"] is False
    assert reference["nonpass_member_count"] == 1
    assert reference["nonpass_members"][0]["verifier_id"] == "unknown-member"
    assert reference["nonpass_polish_system_subject_count"] == 1
    assert reference["tier_results_digest"] == binding.value_digest(
        self_polish["tier_results"]
    )


@pytest.fixture(autouse=True)
def _isolate_capacity_formatting_from_manifest_refresh(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Keep report-wire tests focused on capacity, not full remigration cost.

    Manifest refresh has its own integration suite.  Re-running the package
    migration planner before every formatter case both obscures this file's
    target and makes its runtime depend on the size of the repository graph.
    """

    digest = "sha256:" + "8" * 64
    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda *_args, **_kwargs: {
            "schema_version": package_manifest_refresh.RECEIPT_SCHEMA,
            "status": "CURRENT",
            "before_digest": digest,
            "after_digest": digest,
            "backup_digest": None,
            "source_census_digest": "sha256:" + "9" * 64,
            "migration_mechanism_digest": "sha256:" + "a" * 64,
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        },
    )


@pytest.mark.parametrize("tier", [1, 2, 3])
@pytest.mark.parametrize("status,exit_code", [("PASS", 0), ("UNKNOWN", 2), ("FAIL", 1)])
def test_compact_report_preserves_every_field_at_exact_byte_bound(
        monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
        tier: int, status: str, exit_code: int) -> None:
    # Isolate only assessment: this exercises the production command formatter,
    # not a second serializer masquerading as an installed command.
    _accept_deliberately_schema_invalid_formatter_fixture(monkeypatch)
    result = package.assess_package_polish(tier, Path("."), cancelled=True)
    result.pop("report_digest")
    result["status"] = status
    result["obligation_instances"] = [
        {"object_id": "subject", "coordinate": "POLICY-3.1", "status": "UNKNOWN", "object_kind": "POLICY",
         "blockers": ["PACKAGE_INSTANCE_EVIDENCE_MISSING"],
         "reason": "Recorded uncertainty stays unknown: é λ 🤖", "values": [False, 0, None]}]
    result = package._seal(result)
    original = deepcopy(result)
    compact = (json.dumps(
        result, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ) + "\n").encode("utf-8")
    assert len(compact) < len(cli._json_report_wire_bytes(result))
    calls = []

    def assessment(*args: object, **kwargs: object) -> dict:
        calls.append(kwargs)
        return result

    monkeypatch.setattr(package, "assess_package_polish", assessment)
    monkeypatch.setattr(package, "MAX_REPORT_BYTES", len(compact))
    assert cli.handle_self_polish_tier_argv([str(tier), "--json"]) == exit_code
    output = capsys.readouterr().out.encode("utf-8")
    assert output == compact
    assert json.loads(output) == original == result
    assert len(calls) == 1  # Never replace a complete, fitting report with fallback.


@pytest.mark.parametrize("status,exit_code", [("PASS", 0), ("UNKNOWN", 2), ("FAIL", 1)])
def test_compact_utf8_preserves_complete_report_at_exact_wire_bound(
        monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str],
        status: str, exit_code: int) -> None:
    _accept_deliberately_schema_invalid_formatter_fixture(monkeypatch)
    actual = package.assess_package_polish
    result = actual(3, Path("."), cancelled=True)
    result.pop("report_digest")
    result["status"] = status
    result["padding"] = "é λ 🤖" * 1000
    result = package._seal(result)
    compact = (json.dumps(
        result, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ) + "\n").encode("utf-8")
    assert not compact.isascii()
    assert len(compact) == len(binding.canonical_bytes(result)) + 1
    calls = []

    def assessment(tier: int, root: str, *, cancelled: bool = False) -> dict:
        calls.append(cancelled)
        return actual(tier, root, cancelled=True) if cancelled else result

    monkeypatch.setattr(package, "assess_package_polish", assessment)
    monkeypatch.setattr(package, "MAX_REPORT_BYTES", len(compact))
    assert cli.handle_self_polish_tier_argv(["3", "--json"]) == exit_code
    output = capsys.readouterr().out.encode("utf-8")
    assert calls == [False]
    assert output == compact
    assert json.loads(output) == result


def test_small_report_keeps_existing_pretty_wire_bytes(
        monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    result = package.assess_package_polish(1, Path("."), cancelled=True)
    expected = cli._json_report_wire_bytes(result)
    monkeypatch.setattr(package, "assess_package_polish", lambda *args, **kwargs: result)
    monkeypatch.setattr(package, "MAX_REPORT_BYTES", len(expected))
    assert cli.handle_self_polish_tier_argv(["1", "--json"]) == 2
    assert capsys.readouterr().out.encode("utf-8") == expected

@pytest.mark.parametrize("compact", [False, True])
def test_real_pipe_emits_exact_checked_bytes_without_platform_newlines(compact: bool) -> None:
    import subprocess
    import sys

    result = package.assess_package_polish(3, Path("."), cancelled=True)
    pretty = cli._json_report_wire_bytes(result)
    small = (json.dumps(
        result, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ) + "\n").encode("utf-8")
    expected = small if compact else pretty
    # Select the same implementation as this test process. This is a formatter
    # isolation test, not evidence of root-package conformance or CLI installation.
    code = (
        "import sys\n"
        f"sys.path.insert(0, {str(Path(package.__file__).parents[2])!r})\n"
            "from verifier.runtime import package_manifest_refresh as r, package_polish as p, self_polish_tiers as c\n"
        "digest = 'sha256:' + '8' * 64\n"
        "result = p.assess_package_polish(3, '.', cancelled=True)\n"
        "p.assess_package_polish = lambda *args, **kwargs: result\n"
            "r.ensure_current_manifest = lambda *args, **kwargs: {"
            "'schema_version': r.RECEIPT_SCHEMA, 'status': 'CURRENT', "
            "'before_digest': digest, 'after_digest': digest, "
            "'backup_digest': None, 'source_census_digest': digest, "
            "'migration_mechanism_digest': digest, "
            "'refresh_is_admission': False, 'refresh_is_polish': False}\n"
        f"p.MAX_REPORT_BYTES = {len(expected)}\n"
        "raise SystemExit(c.handle_self_polish_tier_argv(['3', '--json']))\n"
    )
    completed = subprocess.run([sys.executable, "-B", "-c", code], capture_output=True, timeout=30)
    assert completed.returncode == 2 and completed.stderr == b""
    assert completed.stdout == expected
    assert len(completed.stdout) <= len(expected)

def test_text_only_redirect_keeps_logical_report(monkeypatch: pytest.MonkeyPatch) -> None:
    from contextlib import redirect_stdout
    from io import StringIO

    result = package.assess_package_polish(3, Path("."), cancelled=True)
    monkeypatch.setattr(package, "assess_package_polish", lambda *args, **kwargs: result)
    output = StringIO()
    with redirect_stdout(output):
        assert cli.handle_self_polish_tier_argv(["3", "--json"]) == 2
    assert json.loads(output.getvalue()) == result


@pytest.mark.parametrize(
    "status,exit_code", [("PASS", 2), ("UNKNOWN", 2), ("FAIL", 1)]
)
def test_tier_zero_capacity_receipt_preserves_failure_and_source_schema(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    status: str,
    exit_code: int,
) -> None:
    from verifier.runtime import package_admission, tier_zero

    result = {
        "schema_version": package_admission.REPORT_SCHEMA,
        "status": status,
        "obligation_count": 9,
        "obligations": [],
        "blockers": ["ORIGINAL_REFUTATION"] if status == "FAIL" else [],
        "findings": [],
        "padding": "x" * 4096,
        "tier_1_plus_status": "NOT_ESTABLISHED",
        "polished": False,
        "release_authorized": False,
        "deployment_authorized": False,
    }
    monkeypatch.setattr(tier_zero, "assess_tier_zero", lambda *args, **kwargs: deepcopy(result))
    monkeypatch.setattr(tier_zero, "MAX_REPORT_BYTES", 1024)
    assert cli.handle_self_polish_tier_argv(["0", "--json"]) == exit_code
    output = json.loads(capsys.readouterr().out)
    assert output["schema_version"] == tier_zero.CAPACITY_REPORT_SCHEMA
    assert output["source_report_schema"] == package_admission.REPORT_SCHEMA
    assert output["status"] == ("FAIL" if status == "FAIL" else "UNKNOWN")
    assert output["blockers"] == ["TIER_ZERO_REPORT_CAPACITY_EXHAUSTED"]


def test_tier_zero_digest_resource_failure_reaches_capacity_receipt(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from verifier.runtime import package_admission, tier_zero

    result = {
        "schema_version": package_admission.REPORT_SCHEMA,
        "status": "UNKNOWN",
        "obligation_count": 9,
        "obligations": [],
        "blockers": [],
        "findings": [],
        "tier_1_plus_status": "NOT_ESTABLISHED",
        "polished": False,
        "release_authorized": False,
        "deployment_authorized": False,
    }
    real_digest = binding.value_digest
    calls = 0

    def fail_once(value: object) -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise MemoryError
        return real_digest(value)

    monkeypatch.setattr(tier_zero, "assess_tier_zero", lambda *args, **kwargs: deepcopy(result))
    monkeypatch.setattr(
        package_manifest_refresh,
        "ensure_current_manifest",
        lambda *_args, **_kwargs: {
            "schema_version": package_manifest_refresh.RECEIPT_SCHEMA,
            "status": "CURRENT",
            "before_digest": "sha256:" + "8" * 64,
            "after_digest": "sha256:" + "8" * 64,
            "backup_digest": None,
            "source_census_digest": "sha256:" + "9" * 64,
            "migration_mechanism_digest": "sha256:" + "a" * 64,
            "refresh_is_admission": False,
            "refresh_is_polish": False,
        },
    )
    monkeypatch.setattr(cli.core_obligation_union, "value_digest", fail_once)
    assert cli.handle_self_polish_tier_argv(["0", "--json"]) == 2
    output = json.loads(capsys.readouterr().out)
    assert output["schema_version"] == tier_zero.CAPACITY_REPORT_SCHEMA
    assert output["blockers"] == ["TIER_ZERO_REPORT_CAPACITY_EXHAUSTED"]
    assert calls == 2


@pytest.mark.parametrize("tier,expected_status", [(1, "UNKNOWN"), (99, "FAIL")])
def test_package_polish_api_returns_small_capacity_receipt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    tier: int,
    expected_status: str,
) -> None:
    # The strict capacity schema itself requires three content digests plus a
    # retained actionable finding, so 1,500 bytes is below its irreducible
    # canonical representation.  Four KiB remains a deliberately small bound
    # while exercising the real, schema-valid fallback rather than demanding
    # an invalid receipt.
    capacity_bound = 4 * 1024
    monkeypatch.setattr(package, "MAX_REPORT_BYTES", capacity_bound)
    close_accounting = package._close_incomplete_cumulative_accounting

    def oversized_source_report(report, *, tier, stage):
        close_accounting(report, tier=tier, stage=stage)
        report["capacity_test_padding"] = "x" * (capacity_bound * 2)

    monkeypatch.setattr(
        package,
        "_close_incomplete_cumulative_accounting",
        oversized_source_report,
    )
    result = package.assess_package_polish(tier, tmp_path)
    assert result["schema_version"] == package.CAPACITY_REPORT_SCHEMA
    assert result["status"] == expected_status
    assert "PACKAGE_REPORT_CAPACITY_EXHAUSTED" in result["blockers"]
    if tier == 1:
        assert "PACKAGE_MANIFEST_MISSING" in result["blockers"]
    assert len(binding.canonical_bytes(result)) <= capacity_bound


def test_tier_three_graph_repetition_content_addresses_shared_observation_once(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """20,675 bindings must not serialize one 5.89 GB repeated observation."""

    repeated_realization = {
        "class": "DIRECT",
        "explanation": "Replay the exact immutable repository observation.",
        "adaptation_necessity": None,
        "obligation_semantic_digest": "sha256:" + "7" * 64,
        "mechanism_bindings": ["x" * 285_000],
        "falsifiers": ["A changed source coordinate refutes this observation."],
    }
    full_realization_digest = binding.value_digest(repeated_realization)
    realization_bytes = len(binding.canonical_bytes(repeated_realization))
    tier_counts = {1: 6_892, 3: 20_675}
    assert realization_bytes * tier_counts[3] > 5_890_000_000

    real_canonical = binding.canonical_bytes
    calls = {1: 0, 3: 0}

    for tier, count in tier_counts.items():
        shared_check = {
            "status": "PASS",
            "reason": "The bounded checker passed.",
        }
        rows = [{
            "object_id": f"tier-{tier}-subject-{index}",
            "coordinate": f"OBJECT-{tier}.1",
            "status": "FAIL" if index == 0 else "PASS",
            "checker_status": "FAIL" if index == 0 else "PASS",
            "blockers": (
                ["PACKAGE_INSTANCE_CHECK_REFUTED"] if index == 0 else []
            ),
            "selected_package_check": shared_check,
            "repository_realization": repeated_realization,
        } for index in range(count)]
        original_ids = [row["object_id"] for row in rows]

        def counted(value):
            if value is repeated_realization:
                calls[tier] += 1
            return real_canonical(value)

        with monkeypatch.context() as selected:
            selected.setattr(binding, "canonical_bytes", counted)
            package._compact_successful_instance_checks(rows)

        assert [row["object_id"] for row in rows] == original_ids
        assert rows[0]["status"] == "FAIL"
        assert rows[0]["repository_realization"] is repeated_realization
        assert sum(row["status"] == "PASS" for row in rows) == count - 1
        reference = rows[1]["repository_realization"]
        assert set(reference) == {
            "schema_version", "explanation", "full_realization_digest",
            "full_realization_bytes", "transport", "claim_boundary",
            "class", "adaptation_necessity", "obligation_semantic_digest",
        }
        assert reference["full_realization_digest"] == full_realization_digest
        assert all(
            row["repository_realization"] == reference
            for row in rows[1:]
        )

    # Tier 3 carries three times as many bindings, but the immutable content
    # encoding count is identical. Remaining graph overhead is only bounded
    # per-instance identity/status/reference material, not repository work.
    assert calls == {1: 1, 3: 1}


def test_repeated_nonpass_payloads_keep_first_status_example_expanded(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """Repeated diagnostics are interned without hiding first FAIL/UNKNOWN."""

    shared_check = {
        "status": "FAIL",
        "reason": "The bounded checker refuted the selected proposition.",
        "diagnostic": "counterexample" * 512,
    }
    shared_realization = {
        "explanation": "Replay the selected repository process.",
        "mechanism_bindings": ["trace" * 512],
    }
    rows = [
        {
            "object_id": f"subject-{index}",
            "status": status,
            "checker_status": "FAIL" if status == "FAIL" else "UNKNOWN",
            "blockers": [
                "PACKAGE_INSTANCE_CHECK_REFUTED"
                if status == "FAIL"
                else "PACKAGE_INSTANCE_CHECK_UNAVAILABLE"
            ],
            "selected_package_check": shared_check,
            "repository_realization": shared_realization,
        }
        for index, status in enumerate(("FAIL", "FAIL", "UNKNOWN", "UNKNOWN"))
    ]
    original_ids = [row["object_id"] for row in rows]
    monkeypatch.setattr(package, "MAX_INLINE_INSTANCE_PAYLOAD_BYTES", 1)
    monkeypatch.setattr(package, "MAX_INLINE_SELECTED_CHECK_BYTES", 1)
    monkeypatch.setattr(
        package, "MAX_INLINE_REPOSITORY_REALIZATION_BYTES", 1,
    )

    package._compact_successful_instance_checks(rows)

    assert [row["object_id"] for row in rows] == original_ids
    assert rows[0]["selected_package_check"] is shared_check
    assert rows[0]["repository_realization"] is shared_realization
    assert rows[2]["selected_package_check"] is shared_check
    assert rows[2]["repository_realization"] is shared_realization
    for index in (1, 3):
        check_reference = rows[index]["selected_package_check"]
        realization_reference = rows[index]["repository_realization"]
        assert check_reference["status"] == "FAIL"
        assert check_reference["full_check_digest"] == binding.value_digest(
            shared_check
        )
        assert realization_reference["full_realization_digest"] == (
            binding.value_digest(shared_realization)
        )
    assert [row["status"] for row in rows] == [
        "FAIL", "FAIL", "UNKNOWN", "UNKNOWN",
    ]
    assert [row["blockers"] for row in rows] == [
        ["PACKAGE_INSTANCE_CHECK_REFUTED"],
        ["PACKAGE_INSTANCE_CHECK_REFUTED"],
        ["PACKAGE_INSTANCE_CHECK_UNAVAILABLE"],
        ["PACKAGE_INSTANCE_CHECK_UNAVAILABLE"],
    ]


def test_obligation_capacity_is_preflighted_before_any_instance_execution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    route = {
        "coordinate": "OBJECT-0.1-capacity-probe",
        "proposition_digest": "sha256:" + "0" * 64,
        "reason": "A finite test route needs an explicit denominator.",
    }
    monkeypatch.setattr(
        package.core_tier_progression,
        "installed_core_route_inventory",
        lambda: {
            "family_cells": [
                {
                    "object_kind": "OBJECT",
                    "tier": 1,
                    "registered_route_memberships": [route, dict(route)],
                }
            ]
        },
    )
    monkeypatch.setattr(
        package.core_tier_progression,
        "installed_core_route_declarations",
        lambda: {("OBJECT", 1, route["coordinate"]): {}},
    )
    monkeypatch.setattr(
        package.tier_zero_reasons,
        "installed_reason_ledger",
        lambda root: {"objectives": {}},
    )
    monkeypatch.setattr(package, "MAX_OBLIGATION_INSTANCES", 1)
    monkeypatch.setattr(package, "accepts_subject", lambda route, kind: True)
    executions: list[str] = []
    monkeypatch.setattr(
        package.package_execution,
        "evaluate",
        lambda *args, **kwargs: executions.append("executed"),
    )
    subject = SimpleNamespace(
        object_id="capacity-subject",
        digest="sha256:" + "0" * 64,
        kind=SimpleNamespace(value="OBJECT"),
    )
    verifier = SimpleNamespace(object_id="capacity-verifier")

    with pytest.raises(package.PackagePolishCapacity):
        package._instance_obligations(
            1,
            (subject,),
            Path("."),
            verifier,
            {"results": []},
        )
    assert executions == []


def test_capacity_receipt_keeps_only_bounded_manifest_identity() -> None:
    report = {
        "schema_version": package.EXTENSIBLE_REPORT_SCHEMA,
        "kind_denominators": package.namespace_contracts.kind_denominators(),
        "requested_tier": 3,
        "status": "FAIL",
        "manifest": {
            "path": "objects.vstd",
            "status": "SELECTED",
            "digest": "sha256:" + "1" * 64,
            "validation": {"padding": "x" * 4096},
        },
    }
    receipt = package._capacity_receipt(report)
    assert receipt["status"] == "FAIL"
    assert receipt["manifest"] == {
        "path": "objects.vstd",
        "status": "SELECTED",
        "digest": "sha256:" + "1" * 64,
    }
    assert receipt["denominator_status"] == "NOT_RETAINED"
    assert receipt["source_report_encoding_status"] == "AVAILABLE"
    assert "padding" not in json.dumps(receipt)


def test_minimal_capacity_receipt_never_substitutes_a_summary_digest() -> None:
    receipt = package._minimal_capacity_receipt({
        "schema_version": package.EXTENSIBLE_REPORT_SCHEMA,
        "kind_denominators": package.namespace_contracts.kind_denominators(),
        "requested_tier": 3,
        "status": "UNKNOWN",
        "unencodable": object(),
    })

    assert receipt["denominator_status"] == "NOT_RETAINED"
    assert receipt["source_report_encoding_status"] == "UNAVAILABLE"
    assert receipt["source_report_digest"] is None
    assert receipt["source_report_bytes"] is None
    assert receipt["kind_denominators"] == (
        package.namespace_contracts.kind_denominators()
    )


@pytest.mark.parametrize(
    ("mutation", "diagnostic"),
    (
        ("missing", "PACKAGE_KIND_DENOMINATORS_FIELDS_INVALID"),
        ("native-38", "PACKAGE_OBJECT_KIND_COUNT_INVALID"),
        ("native-bool", "PACKAGE_OBJECT_KIND_COUNT_INVALID"),
        (
            "wrong-scope",
            "PACKAGE_OBJECT_KIND_DENOMINATOR_SCOPE_INVALID",
        ),
        (
            "namespace-37",
            "PACKAGE_INSTALLED_NAMESPACE_KIND_COUNT_INVALID",
        ),
    ),
)
def test_capacity_conversion_rejects_unbound_kind_denominators(
    mutation: str, diagnostic: str,
) -> None:
    report = {
        "schema_version": package.EXTENSIBLE_REPORT_SCHEMA,
        "kind_denominators": package.namespace_contracts.kind_denominators(),
        "requested_tier": 3,
        "status": "UNKNOWN",
        "blockers": [],
    }
    if mutation == "missing":
        report.pop("kind_denominators")
    elif mutation == "native-38":
        report["kind_denominators"]["object_kind_count"] = 38
    elif mutation == "native-bool":
        report["kind_denominators"]["object_kind_count"] = True
    elif mutation == "wrong-scope":
        report["kind_denominators"]["object_kind_denominator_scope"] = (
            "INSTALLED_NAMESPACE"
        )
    else:
        report["kind_denominators"]["installed_namespace_kind_count"] = 37

    with pytest.raises(ValueError, match=diagnostic):
        package._capacity_receipt(report)


@pytest.mark.parametrize(
    "builder",
    (package._minimal_capacity_receipt, package._capacity_receipt),
)
def test_capacity_receipt_fails_closed_for_non_utf8_source_text(builder) -> None:
    receipt = builder({
        "schema_version": package.EXTENSIBLE_REPORT_SCHEMA,
        "kind_denominators": package.namespace_contracts.kind_denominators(),
        "requested_tier": 3,
        "status": "UNKNOWN",
        "blockers": [],
        "claim_boundary": "\ud800" * 1000,
    })

    assert receipt["denominator_status"] == "NOT_RETAINED"
    assert receipt["source_report_encoding_status"] == "UNAVAILABLE"
    assert receipt["source_report_digest"] is None
    assert receipt["source_report_bytes"] is None


def test_capacity_source_report_coordinate_is_independent_of_seal_presence(
        monkeypatch) -> None:
    from verifier.runtime import manifest_gate

    body = {
        "schema_version": package.EXTENSIBLE_REPORT_SCHEMA,
        "kind_denominators": package.namespace_contracts.kind_denominators(),
        "requested_tier": 3,
        "status": "UNKNOWN",
        "blockers": [],
        "findings": [],
        "manifest": None,
        "obligation_instances": [],
    }
    encoded = binding.canonical_bytes(body)
    expected_digest = binding.bytes_digest(encoded)
    monkeypatch.setattr(manifest_gate, "package_findings", lambda _report: [])

    monkeypatch.setattr(package, "MAX_REPORT_BYTES", len(encoded) - 1)
    before_seal = package._seal(deepcopy(body))
    monkeypatch.setattr(package, "MAX_REPORT_BYTES", len(encoded))
    after_seal = package._seal(deepcopy(body))

    for receipt in (before_seal, after_seal):
        assert receipt["source_report_encoding_status"] == "AVAILABLE"
        assert receipt["source_report_digest"] == expected_digest
        assert receipt["source_report_bytes"] == len(encoded)


def _actionable_capacity_report() -> tuple[dict, dict, dict]:
    """Return a private over-capacity report, its first graph route and that row."""
    rows, graph_objects = _capacity_fixture_rows()
    validation_repository = "https://example.invalid/verifier.git"
    validation_revision = "a" * 40
    validation_manifest = tier_zero_manifest.manifest_template(
        repository=validation_repository,
        revision=validation_revision,
    )
    validation = tier_zero_manifest.validate_manifest(
        validation_manifest,
        expected_repository=validation_repository,
        expected_revision=validation_revision,
    )
    graph_route = next(
        route for route in manifest_gate.obligation_catalog()
        if route["tier"] == 1 and route["object_kind"] == "GRAPH"
    )
    row = next(
        item for item in rows
        if item["object_id"] == "subject-1"
        and item["coordinate"] == graph_route["coordinate"]
    )
    route = graph_route
    source_coordinate = {
        "source_head": "1" * 40,
        "source_tree": "2" * 40,
        "source_worktree_status_digest": "sha256:" + "b" * 64,
        "source_manifest_digest": "sha256:" + "c" * 64,
    }
    source_coordinate_digest = binding.value_digest(source_coordinate)
    tier_zero_obligations = [
        {
            "coordinate": f"VSTD-T0.{index}",
            "status": "PASS",
            "assessment_reason": "Repository admission obligation passed.",
        }
        for index in range(1, 10)
    ]
    tier_execution = {}
    for tier, name, digit in (
        (0, "ADMISSION", "6"),
        (1, "FACETS", "7"),
        (2, "DYNAMICS", "8"),
        (3, "STATICS", "9"),
    ):
        execution_body = {
            "schema_version": "verifier-self-polish-tier-execution-1",
            "tier": tier,
            "tier_name": name,
            "execution_status": "EXECUTED",
            "status": "PASS",
            "reason": f"Fresh Tier {tier} execution completed.",
            "evidence_digest": "sha256:" + digit * 64,
            "blocking_prerequisite": None,
        }
        tier_execution[str(tier)] = {
            **execution_body,
            "execution_record_digest": binding.value_digest(execution_body),
        }
    native_diagnostics = {
        "schema_version": "verifier-native-diagnostic-reference-1",
        "status": "PASS",
        "report_digest": "sha256:" + "5" * 64,
        "prerequisites": {
            "0": {
                "status": "PASS",
                "report_digest": "sha256:" + "6" * 64,
                "manifest_digest": "sha256:" + "1" * 64,
                "obligation_count": 9,
                "obligation_status_counts": {"PASS": 9, "FAIL": 0, "UNKNOWN": 0},
                "obligations": tier_zero_obligations,
            },
            "1": {
                "schema_version": "verifier-self-polish-tier-assessment-7",
                "tier": 1,
                "status": "PASS",
                "report_digest": "sha256:" + "7" * 64,
                    "source_coordinate_digest": source_coordinate_digest,
                    "post_replay_full_source_recapture": "PASS",
                "obligation_count": 5123,
                "obligation_status_counts": {"PASS": 5123},
            },
            "2": {
                "schema_version": "verifier-self-polish-tier-assessment-7",
                "tier": 2,
                "status": "PASS",
                "report_digest": "sha256:" + "8" * 64,
                    "source_coordinate_digest": source_coordinate_digest,
                    "post_replay_full_source_recapture": "PASS",
                "obligation_count": 4611,
                "obligation_status_counts": {"PASS": 4611},
            },
        },
        "tier_execution": tier_execution,
    }
    tier_results = []
    for depth in range(1, 4):
        selected = [item for item in rows if item["tier"] == depth]
        tier_results.append({
            "tier": depth,
            "instance_count": len(selected),
            "status_counts": {"UNKNOWN": len(selected)},
            "status": "UNKNOWN",
            "checker_status_counts": {"NOT_RUN": len(selected)},
            "prerequisite_tiers": list(range(depth)),
        })
    report = {
        "schema_version": package.EXTENSIBLE_REPORT_SCHEMA,
        "kind_denominators": package.namespace_contracts.kind_denominators(),
        "requested_tier": 3, "status": "UNKNOWN",
        "blockers": ["PACKAGE_INSTANCE_EVIDENCE_INCOMPLETE"],
        "manifest": {
            "path": "objects.vstd",
            "status": "SELECTED",
            "digest": "sha256:" + "1" * 64,
            "validation": validation,
        },
        "source_coordinate": source_coordinate,
        "source_coordinate_digest": source_coordinate_digest,
        "mechanism_digest": "sha256:" + "4" * 64,
        "package_graph": {"status": "PASS", "root_id": "subject-1",
                          "root_kind": "GRAPH", "object_count": 26,
                          "objects": graph_objects,
                          "manifest_digest": "sha256:" + "1" * 64,
                          "collection_digest": "sha256:" + "a" * 64},
        "native_diagnostics": native_diagnostics,
        "verifier_execution": {
            "subject_id": "subject-1",
            "subject_collection_digest": "sha256:" + "a" * 64,
            "manifest_digest": "sha256:" + "1" * 64,
            "mechanism_digest": "sha256:" + "4" * 64,
            "requested_tier": 3,
            "native_diagnostic_report_digest": "sha256:" + "5" * 64,
            "obligation_denominator_commitment":
                _capacity_denominator_commitment(rows),
        },
        "tier_results": tier_results,
        "obligation_instances": rows,
    }
    return report, route, row


def test_capacity_receipt_keeps_actionable_index_without_source_authority() -> None:
    report, route, row = _actionable_capacity_report()

    receipt = package._capacity_receipt(report)

    assert receipt["schema_version"] == package.CAPACITY_REPORT_SCHEMA
    # A private synthetic report has no caller-selected source root to replay.
    # It may retain actionable rows, but cannot claim a complete denominator.
    assert receipt["denominator_status"] == "NOT_RETAINED"
    assert receipt["source_report_encoding_status"] == "AVAILABLE"
    assert receipt["native_diagnostics"] == report["native_diagnostics"]
    assert set(receipt["native_diagnostics"]["tier_execution"]) == {
        "0", "1", "2", "3",
    }
    assert len(
        receipt["native_diagnostics"]["prerequisites"]["0"]["obligations"]
    ) == 9
    assert receipt["obligation_index"]["instance_count"] == 101
    entry = next(
        item for item in receipt["obligation_index"]["entries"]
        if item["object_id"] == "subject-1"
    )
    assert entry["object_id"] == "subject-1"
    assert entry["object_kind"] == route["object_kind"]
    assert entry["coordinate"] == route["coordinate"]
    assert entry["obligation_id"] == route["obligation_id"]
    assert entry["tier"] == route["tier"]
    assert entry["status"] == "UNKNOWN"
    assert entry["checker_status"] == "NOT_RUN"
    assert entry["instance_digest"] == row["instance_digest"]
    assert entry["blockers"] == ["PACKAGE_INSTANCE_EVIDENCE_MISSING"]
    assert "No package-instance input" in entry["reason"]
    assert entry["rerun_argv"] == [
        "vstd", "gate", "--object", "subject-1", "--obligation",
        route["obligation_id"],
    ]
    assert len(entry["actions"]) == 1
    assert entry["actions"][0]["gate_id"] == "instance-evidence"
    assert entry["actions"][0]["next_action"]
    assert "PACKAGE_INSTANCE_EVIDENCE_INCOMPLETE" in receipt["blockers"]
    assert "PACKAGE_REPORT_CAPACITY_EXHAUSTED" in receipt["blockers"]
    assert receipt["omitted_finding_count"] == 0
    finding = next(
        item for item in receipt["findings"]
        if item.get("object_id") == "subject-1"
    )
    assert finding["obligation_id"] == route["obligation_id"]
    assert finding["rerun_argv"] == [
        "vstd", "gate", "--object", "subject-1", "--obligation",
        route["obligation_id"],
    ]
    assert any(
        finding["code"] == "PACKAGE_REPORT_CAPACITY_EXHAUSTED"
        for finding in receipt["findings"]
    )
    import jsonschema
    schema = json.loads((
        Path(__file__).resolve().parents[1]
        / "src/verifier/schemas/verifier-manifest-package-polish-capacity-2.schema.json"
    ).read_bytes())
    jsonschema.Draft202012Validator.check_schema(schema)
    validator = jsonschema.Draft202012Validator(schema)
    validator.validate(receipt)
    assert receipt["report_digest"] == binding.value_digest({
        key: value for key, value in receipt.items() if key != "report_digest"
    })

    finding_without_reason = deepcopy(receipt)
    selected_finding = next(
        item for item in finding_without_reason["findings"]
        if item.get("object_id") == "subject-1"
    )
    selected_finding.pop("reason")
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(finding_without_reason)
    selected_finding["reason"] = "   "
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(finding_without_reason)

    action_without_reason = deepcopy(receipt)
    selected_entry = next(
        item for item in action_without_reason["obligation_index"]["entries"]
        if item["object_id"] == "subject-1"
    )
    selected_entry["actions"][0].pop("reason")
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(action_without_reason)
    selected_entry["actions"][0]["reason"] = "   "
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(action_without_reason)


def _canonical_size(value: dict) -> int:
    return len(binding.canonical_bytes(value))


def _fit_between_full_and_grouped(monkeypatch: pytest.MonkeyPatch, report: dict) -> dict:
    """Shrink the wire cap just below the fully detailed receipt and return that receipt."""
    full = package._capacity_receipt(deepcopy(report))
    monkeypatch.setattr(package, "MAX_REPORT_BYTES", _canonical_size(full) - 512)
    return full


def test_over_cap_receipt_groups_findings_and_drops_instance_actions(
        monkeypatch: pytest.MonkeyPatch) -> None:
    """The receipt degrades to grouped next actions before it degrades to nothing."""
    report, _route, _row = _actionable_capacity_report()
    full = _fit_between_full_and_grouped(monkeypatch, report)

    receipt = package._capacity_receipt(deepcopy(report))

    assert receipt["schema_version"] == package.CAPACITY_REPORT_SCHEMA
    assert _canonical_size(receipt) <= package.MAX_REPORT_BYTES
    # Every instance identity and status stays reachable; only repeated prose is dropped.
    assert receipt["obligation_index"]["instance_count"] == 101
    assert len(receipt["obligation_index"]["entries"]) == 101
    assert [
        (item["object_id"], item["coordinate"], item["status"], item["instance_digest"])
        for item in receipt["obligation_index"]["entries"]
    ] == [
        (item["object_id"], item["coordinate"], item["status"], item["instance_digest"])
        for item in full["obligation_index"]["entries"]
    ]
    assert all(item["actions"] == [] for item in receipt["obligation_index"]["entries"])
    assert all(item["reason"] and item["rerun_argv"]
               for item in receipt["obligation_index"]["entries"]
               if item["status"] != "PASS")
    assert receipt["obligation_index"]["status_counts"] == full["obligation_index"]["status_counts"]
    # Findings are counted groups, and the number folded away is stated.
    assert len(receipt["findings"]) < len(full["findings"])
    assert receipt["finding_count"] == len(receipt["findings"])
    assert receipt["omitted_finding_count"] == len(full["findings"]) - len(receipt["findings"])
    assert sum(item.get("instance_count", 1) for item in receipt["findings"]) == len(full["findings"])
    assert "obligation_instances.actions" in receipt["omitted_sections"]
    assert "findings.instance_detail" in receipt["omitted_sections"]
    assert any(item["code"] == "PACKAGE_REPORT_CAPACITY_EXHAUSTED" for item in receipt["findings"])
    assert "PACKAGE_REPORT_CAPACITY_EXHAUSTED" in receipt["blockers"]
    assert receipt["report_digest"] == binding.value_digest({
        key: value for key, value in receipt.items() if key != "report_digest"
    })


def test_grouped_receipt_validates_against_the_published_capacity_schema(
        monkeypatch: pytest.MonkeyPatch) -> None:
    import jsonschema
    report, _route, _row = _actionable_capacity_report()
    _fit_between_full_and_grouped(monkeypatch, report)
    receipt = package._capacity_receipt(deepcopy(report))
    schema = json.loads((
        Path(__file__).resolve().parents[1]
        / "src/verifier/schemas/verifier-manifest-package-polish-capacity-2.schema.json"
    ).read_bytes())
    jsonschema.Draft202012Validator(schema).validate(receipt)
    assert any(item.get("scope") == "group" for item in receipt["findings"])


def test_grouped_receipt_never_hides_a_refutation_in_a_group(
        monkeypatch: pytest.MonkeyPatch) -> None:
    report, _route, _row = _actionable_capacity_report()
    refuted = report["obligation_instances"][0]
    refuted["status"] = "FAIL"
    refuted["checker_status"] = "FAIL"
    _fit_between_full_and_grouped(monkeypatch, report)
    receipt = package._capacity_receipt(deepcopy(report))
    statuses = [item["status"] for item in receipt["findings"]]
    assert statuses == sorted(statuses, key=lambda value: value != "FAIL")
    assert receipt["obligation_index"]["status_counts"].get("FAIL", 0) >= 1


def test_over_cap_receipt_compacts_native_records_only_when_grouping_is_not_enough(
        monkeypatch: pytest.MonkeyPatch) -> None:
    report, _route, _row = _actionable_capacity_report()
    records = [
        {"status": "UNKNOWN", "object_id": f"subject-{index}",
         "obligation_id": "VSTD-T0.2-namespace-admission",
         "gate_id": "namespace-admission", "coordinate": "VSTD-T0.2",
         "path": f"$.prerequisites.0.obligations[{index}]",
         "reason": "x" * 400,
         "rerun_argv": ["vstd", "gate", "--object", f"subject-{index}",
                        "--obligation", "VSTD-T0.2-namespace-admission"]}
        for index in range(300)
    ]
    report["native_diagnostics"]["prerequisites"]["0"]["nonpass_records"] = records
    _fit_between_full_and_grouped(monkeypatch, report)
    # Grouping alone cannot hold 300 native records in this cap.
    monkeypatch.setattr(package, "MAX_REPORT_BYTES", 120_000)

    receipt = package._capacity_receipt(deepcopy(report))

    assert receipt["schema_version"] == package.CAPACITY_REPORT_SCHEMA
    assert _canonical_size(receipt) <= package.MAX_REPORT_BYTES
    prerequisite = receipt["native_diagnostics"]["prerequisites"]["0"]
    assert "nonpass_records" not in prerequisite
    assert prerequisite["nonpass_record_count"] == 300
    assert receipt["denominator_status"] == "NOT_RETAINED"
    assert "native_diagnostics.nonpass_records" in receipt["omitted_sections"]
    assert receipt["obligation_index"]["instance_count"] == 101
    assert len(receipt["obligation_index"]["entries"]) == 101


class _WholeReportEncodingAttempted(Exception):
    """A spy refused a whole-report encoding instead of allocating its bytes."""


def _refuse_whole_report_encoding(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record and refuse whole-report canonical encoding.

    The 22,136-row shape below would expand to tens of gigabytes if it were
    materialized. Refusing the call keeps the test from allocating the payload
    while still proving that the guarded path never reached the encoder.
    """

    attempts: list[str] = []
    real_canonical_bytes = binding.canonical_bytes

    def spy(value: Any) -> bytes:
        if type(value) is dict and value.get("schema_version") in {
            package.REPORT_SCHEMA, package.EXTENSIBLE_REPORT_SCHEMA,
        }:
            attempts.append(value["schema_version"])
            raise _WholeReportEncodingAttempted(value["schema_version"])
        return real_canonical_bytes(value)

    monkeypatch.setattr(binding, "canonical_bytes", spy)
    return attempts


def _shared_payload_report(rows: int, payload: str) -> dict[str, Any]:
    """Build a shallow report whose expanded encoding is driven by one object.

    Every row refers to the same realization dictionary by identity, so the
    report looks small at the top level but canonical JSON would repeat the
    payload once per row.
    """

    shared_realization = {
        "explanation": "Shared immutable observation.",
        "mechanism_bindings": [payload],
    }
    return {
        "schema_version": package.EXTENSIBLE_REPORT_SCHEMA,
        "kind_denominators": package.namespace_contracts.kind_denominators(),
        "requested_tier": 3,
        "status": "UNKNOWN",
        "blockers": ["PACKAGE_INSTANCE_EVIDENCE_INCOMPLETE"],
        "manifest": {
            "path": "objects.vstd",
            "status": "SELECTED",
            "digest": "sha256:" + "1" * 64,
        },
        "source_coordinate_digest": None,
        "mechanism_digest": None,
        "obligation_instances": [
            {
                "object_id": f"subject-{index}",
                "object_kind": "OBJECT",
                "coordinate": "OBJECT-1.2",
                "tier": 1,
                "status": "PASS",
                "checker_status": "PASS",
                "blockers": [],
                "repository_realization": shared_realization,
            }
            for index in range(rows)
        ],
        "tier_results": [],
        "claim_boundary": "Synthetic shared-object envelope probe.",
    }


def test_seal_refuses_whole_report_encoding_for_shared_expansion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED: the first whole-report canonicalization must not happen.

    One mebibyte shared by 22,136 rows expands to about 22 GB. The guard must
    route this obviously over-envelope source straight to the capacity receipt.
    """

    report = _shared_payload_report(22_136, "x" * (1 << 20))
    attempts = _refuse_whole_report_encoding(monkeypatch)

    receipt = package._seal(report)

    assert attempts == []
    assert receipt["schema_version"] == package.CAPACITY_REPORT_SCHEMA
    assert receipt["source_report_encoding_status"] == "UNAVAILABLE"
    assert receipt["source_report_digest"] is None
    assert receipt["source_report_bytes"] is None
    assert receipt["denominator_status"] == "NOT_RETAINED"
    assert receipt["whole_package_conformance"] == "NOT_ESTABLISHED"
    assert "PACKAGE_REPORT_CAPACITY_EXHAUSTED" in receipt["blockers"]


def test_minimal_receipt_leaves_over_envelope_source_unencoded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED: a summary receipt must not canonicalize an over-budget source."""

    report = _shared_payload_report(22_136, "y" * (1 << 20))
    attempts = _refuse_whole_report_encoding(monkeypatch)

    receipt = package._minimal_capacity_receipt(report)

    assert attempts == []
    assert receipt["source_report_encoding_status"] == "UNAVAILABLE"
    assert receipt["source_report_digest"] is None
    assert receipt["source_report_bytes"] is None
    assert receipt["denominator_status"] == "NOT_RETAINED"
    assert receipt["source_instance_count"] == 22_136


def test_capacity_receipt_retains_bounded_index_without_source_encoding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RED: a bounded actionable index survives without re-encoding the source.

    Twenty-two thousand rows fit the explicit 32,768-row index bound and a
    compact per-row entry, so the complete index may be retained while the
    denominator stays NOT_RETAINED and the source identity stays UNAVAILABLE.
    """

    report = _shared_payload_report(22_136, "z" * (1 << 20))
    attempts = _refuse_whole_report_encoding(monkeypatch)

    receipt = package._capacity_receipt(report)

    assert attempts == []
    assert receipt["denominator_status"] == "NOT_RETAINED"
    assert receipt["source_report_encoding_status"] == "UNAVAILABLE"
    assert receipt["obligation_index"]["instance_count"] == 22_136
    assert len(receipt["obligation_index"]["entries"]) == 22_136
    assert receipt["report_digest"] == binding.value_digest({
        key: value for key, value in receipt.items() if key != "report_digest"
    })
    assert len(binding.canonical_bytes(receipt)) <= package.MAX_REPORT_BYTES


def test_normal_report_keeps_canonical_bytes_and_digest_binding() -> None:
    """Under-envelope reports keep exactly the ordinary sealed encoding."""

    report = _shared_payload_report(3, "ordinary")

    sealed = package._seal(report)

    assert sealed["schema_version"] == package.EXTENSIBLE_REPORT_SCHEMA
    assert sealed["obligation_instances"][0]["status"] == "PASS"
    body = {key: value for key, value in sealed.items() if key != "report_digest"}
    assert sealed["report_digest"] == binding.bytes_digest(
        binding.canonical_bytes(body)
    )


def test_capacity_obligation_index_v2_factors_passes_and_round_trips() -> None:
    entries = []
    for index in range(128):
        entries.append({
            "object_id": f"subject-{index % 8}",
            "object_kind": "OBJECT",
            "coordinate": f"OBJECT-1.{index % 4 + 1}",
            "obligation_id": f"object-obligation-{index % 4 + 1}",
            "tier": 1,
            "status": "PASS",
            "checker_status": "PASS" if index % 2 else "NOT_REQUIRED",
            "instance_digest": binding.value_digest({"instance": index}),
            "blockers": [],
            "reason": None,
            "actions": [],
            "rerun_argv": None,
        })
    body = {
        "schema_version": "verifier-package-obligation-index-1",
        "instance_count": len(entries),
        "status_counts": {"PASS": len(entries)},
        "entries": entries,
    }
    expanded = {**body, "index_digest": binding.value_digest(body)}

    compact = package._compact_capacity_obligation_index(expanded)

    assert compact is not None
    assert compact["schema_version"] == "verifier-package-obligation-index-2"
    assert package._expand_capacity_obligation_index(compact) == entries
    assert len(binding.canonical_bytes(compact)) < len(binding.canonical_bytes(expanded))
    tampered = deepcopy(compact)
    tampered["pass_entries"][0][1] = 99
    assert package._expand_capacity_obligation_index(tampered) is None

    finding = manifest_gate.repository_finding(
        "PACKAGE_REPORT_CAPACITY_EXHAUSTED", "UNKNOWN", tier=1,
    )
    candidates = list(package._capacity_body_candidates({
        "obligation_index": compact,
        "findings": [finding, deepcopy(finding)],
        "finding_count": 2,
        "omitted_finding_count": 0,
        "omitted_sections": [],
        "native_diagnostics": None,
    }))
    assert len(candidates) == 2
    grouped = candidates[1]
    assert grouped["obligation_index"]["schema_version"] == (
        "verifier-package-obligation-index-2"
    )
    grouped_index_body = {
        key: value for key, value in grouped["obligation_index"].items()
        if key != "index_digest"
    }
    assert grouped["obligation_index"]["index_digest"] == binding.value_digest(
        grouped_index_body
    )
    assert grouped["finding_count"] < 2


