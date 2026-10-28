"""Read-only dangerous-pathway security helper tests.

command-line interface (CLI); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). No test performs transport or publication.
"""
from __future__ import annotations

import argparse
import hashlib
import json

from verifier.core.certificate import canonical_bytes
from verifier.domains.contracts import dangerous_pathway_security as security
from verifier.runtime import security_cli
from verifier.runtime.security_cli import add_security_parsers, handle_security_command


def h(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def check(status: str = "PASS") -> tuple[dict, dict]:
    selected = {
        "check_id": "refutation",
        "purpose": "REFUTATION",
        "mechanism_digest": h("mechanism"),
        "request_digest": h("request"),
        "policy_digest": h("policy"),
        "confidential": False,
    }
    result = {
        "check_id": "refutation",
        "mechanism_digest": selected["mechanism_digest"],
        "request_digest": selected["request_digest"],
        "policy_digest": selected["policy_digest"],
        "certificate_digest": h("certificate"),
        "replay_digest": h("replay"),
        "status": status,
    }
    return selected, result


def selected_material(*, status: str = "PASS") -> tuple[dict, dict]:
    selected, result = check(status)
    # A separate counterexample-search check is needed for a positive refutation.
    counterexample = {**selected, "check_id": "counterexample", "purpose": "COUNTEREXAMPLE",
                      "mechanism_digest": h("counter-mechanism"),
                      "request_digest": h("counter-request"),
                      "policy_digest": h("counter-policy")}
    counter_result = {**result, "check_id": "counterexample",
                      "mechanism_digest": counterexample["mechanism_digest"],
                      "request_digest": counterexample["request_digest"],
                      "policy_digest": counterexample["policy_digest"],
                      "certificate_digest": h("counter-certificate"),
                      "replay_digest": h("counter-replay")}
    checks = sorted([selected, counterexample], key=lambda row: row["check_id"])
    results = sorted([result, counter_result], key=lambda row: row["check_id"])
    request = security.dangerous_pathway_request(
        artifact_digest=h("artifact"), derived_surface_digest=h("surface"),
        source_coordinate_digest=h("source"), dependency_inventory_digest=h("dependencies"),
        object_kind="MODEL", risk_policy_digest=h("risk-policy"),
        threat_catalog_digest=h("catalog"), threat_catalog_version="catalog-2026-10-09",
        pathway_search_scope_digest=h("pathway-search-scope"),
        operating_envelope_digest=h("envelope"),
        capability_inventory_digest=h("capabilities"), pathway_id="pathway",
        catalog_entry_digest=h("catalog-entry"), severity="HIGH",
        required_checks=checks, reviewer_policy_digest=h("reviewer-policy"),
        invalidator_policy_digest=h("invalidator-policy"))
    verdict = "REFUTED_WITHIN_ENVELOPE" if status == "PASS" else "UNKNOWN"
    observation = {
        "schema_version": security.OBSERVATION_VERSION,
        "applicability": "APPLICABLE",
        "applicability_evidence_digest": None,
        "verdict": verdict,
        "trigger_witness_digest": None,
        "check_results": results,
        "counterexample_search_digest": h("search") if status == "PASS" else None,
        "mitigation_digests": [],
        "residual_risk_digest": h("residual"),
        "residual_risk_status": "PASS",
        "review": [],
        "invalidators": [],
    }
    certificate = json.loads(security.build_dangerous_pathway_certificate(request, observation))
    return request, certificate


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser()
    add_security_parsers(root.add_subparsers(dest="command", required=True))
    return root


def review(label: str) -> dict:
    return {
        "reviewer_id_digest": h("reviewer-" + label),
        "role_digest": h("role-" + label),
        "conflict_check_digest": h("conflict-" + label),
        "mechanism_digest": h("mechanism-" + label),
        "review_digest": h("review-" + label),
        "review_status": "PASS", "conflict_status": "PASS",
    }


def assessment(certificate: dict) -> dict:
    reviewers = sorted([review("one"), review("two")],
                       key=lambda row: (row["reviewer_id_digest"], row["review_digest"]))
    polish = [
        {"tier": tier, "tier_name": name, "status": "PASS",
         "receipt_digest": h(f"polish-tier-{tier}")}
        for tier, name in security.POLISH_TIER_NAMES.items()
    ]
    r2_evidence = {
        "capability_observation": {
            "inventory_digest": certificate["capability_inventory_digest"],
            "observer_mechanism_digest": h("capability-observer"),
            "observer_certificate_digest": h("capability-certificate"),
            "observer_replay_digest": h("capability-replay"),
            "status": "PASS", "generalizable_tooling": "PRESENT", "risk_floor": "R2",
        },
        "catalog_coverage": {
            "catalog_digest": certificate["threat_catalog_digest"],
            "catalog_version": certificate["threat_catalog_version"],
            "search_scope_digest": certificate["pathway_search_scope_digest"],
            "entry_inventory_digest": security._digest_value(
                [certificate["catalog_entry_digest"]]),
            "entry_count": 1, "coverage_evidence_digest": h("catalog-coverage"),
            "status": "PASS", "scope_claim": "PINNED_CATALOG_ONLY",
        },
        "operating_envelope": {
            "envelope_digest": certificate["operating_envelope_digest"],
            "replay_digest": h("envelope-replay"), "status": "PASS",
        },
        "invalidator_coverage": {
            "policy_digest": certificate["invalidator_policy_digest"],
            "inventory_digest": security._digest_value([]),
            "coverage_evidence_digest": h("invalidator-coverage"), "status": "PASS",
        },
        "composition_coverage": {
            "component_inventory_digest": security._digest_value([]),
            "interaction_inventory_digest": security._digest_value([]),
            "coverage_evidence_digest": h("composition-coverage"), "status": "PASS",
        },
    }
    return security._aggregate_legacy_dangerous_pathway_assessment_record(
        artifact_digest=certificate["artifact_digest"],
        derived_surface_digest=certificate["derived_surface_digest"],
        source_coordinate_digest=certificate["source_coordinate_digest"],
        dependency_inventory_digest=certificate["dependency_inventory_digest"],
        object_kind=certificate["object_kind"], namespace_digest=h("namespace"),
        polish_receipt_digest=security._digest_value(polish), ordinary_polish=polish,
        risk_policy_digest=certificate["risk_policy_digest"],
        threat_catalog_digest=certificate["threat_catalog_digest"],
        threat_catalog_version=certificate["threat_catalog_version"],
        pathway_search_scope_digest=certificate["pathway_search_scope_digest"],
        operating_envelope_digest=certificate["operating_envelope_digest"],
        reviewer_policy_digest=certificate["reviewer_policy_digest"],
        invalidator_policy_digest=certificate["invalidator_policy_digest"],
        capability_inventory_digest=certificate["capability_inventory_digest"],
        pathways=[certificate], components=[], interactions=[],
        predecessor={"artifact_digest": None, "derived_surface_digest": None,
                     "assessment_digest": None, "risk_class": None},
        r2_evidence=r2_evidence,
        risk_class="R2", assurance_level="SEC3_INDEPENDENTLY_REFUTED",
        maximum_release_scope="BOUNDED_INTERFACE", review=reviewers, invalidators=[])


def test_catalog_is_local_mechanical_metadata(capsys) -> None:
    args = parser().parse_args(["security", "catalog", "--json"])
    assert handle_security_command(args) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "PASS"
    assert result["publication_authority"] == "NOT_ESTABLISHED"
    assert "security_outcome" not in result
    assert {"SIM", "MODEL", "AGENT", "HARNESS", "BOT", "DATA"} <= set(result["object_kinds"])
    assert result["design_provenance_authority"] == "DESIGN_ONLY"
    assert result["risk_basis"] == "OBSERVED_CAPABILITY_AND_GENERALIZABLE_TOOLING_NOT_OBJECT_KIND"
    assert result["commercial_priority_security_effect"] == "NONE"
    assert result["assessment_schema_version"] == security.ASSESSMENT_V2_VERSION
    assert result["legacy_assessment_schema_version"] == security.ASSESSMENT_VERSION
    assert result["legacy_assessment_security_eligibility"] == "DENY"
    assert (result["legacy_assessment_revocation_reason"]
            == "R2_PREDECESSOR_REPLAY_NOT_ESTABLISHED")
    assert result["legacy_certificate_security_eligibility"] == "DENY"
    assert (result["legacy_certificate_revocation_reason"]
            == "SELECTED_CHECK_SEMANTIC_REPLAY_NOT_ESTABLISHED")
    assert result["installed_eligibility_replayer_count"] == 0
    assert result["current_v2_security_eligibility"] == "DENY"


def test_public_cli_registers_and_dispatches_security(capsys) -> None:
    from verifier.runtime.public_cli import main

    assert main(["security", "catalog", "--json"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["schema_version"] == security.CATALOG_VERSION
    assert result["design_provenance_authority"] == "DESIGN_ONLY"
    assert result["publication_authority"] == "NOT_ESTABLISHED"


def test_pathway_check_is_legacy_unqualified_and_exits_two(tmp_path, capsys) -> None:
    request, certificate = selected_material()
    request_path, certificate_path = tmp_path / "request.json", tmp_path / "certificate.json"
    request_path.write_bytes(canonical_bytes(request))
    certificate_path.write_bytes(canonical_bytes(certificate))
    args = parser().parse_args(["security", "pathway-check", str(certificate_path),
                                "--request", str(request_path), "--json"])
    assert handle_security_command(args) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["replay_status"] == "REPRODUCED"
    assert result["status"] == "PASS"
    assert result["security_outcome"] == "NOT_ESTABLISHED"
    assert result["recorded_security_outcome"] == "ESTABLISHED"
    assert result["security_eligibility"] == "DENY"
    assert result["qualification_status"] == "LEGACY_UNQUALIFIED"
    assert (result["revocation_reason"]
            == "SELECTED_CHECK_SEMANTIC_REPLAY_NOT_ESTABLISHED")
    assert result["publication_authority"] == "NOT_ESTABLISHED"


def test_public_pathway_cli_rejects_fully_rehashed_opaque_pass_rows(
        tmp_path, capsys) -> None:
    """Caller-coherent opaque digests cannot qualify selected check semantics."""
    from verifier.runtime.public_cli import main

    request, certificate = selected_material()
    for index, result in enumerate(certificate["required_check_results"]):
        result["certificate_digest"] = h(f"attacker-certificate-{index}")
        result["replay_digest"] = h(f"attacker-replay-{index}")
        result["status"] = "PASS"
    certificate["certificate_digest"] = security._digest_without(
        certificate, "certificate_digest")

    request_path = tmp_path / "attacker-request.json"
    certificate_path = tmp_path / "attacker-certificate.json"
    request_path.write_bytes(canonical_bytes(request))
    certificate_path.write_bytes(canonical_bytes(certificate))

    assert main(["security", "pathway-check", str(certificate_path),
                 "--request", str(request_path), "--json"]) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["replay_status"] == "REPRODUCED"
    assert result["status"] == "PASS"
    assert result["security_outcome"] == "NOT_ESTABLISHED"
    assert result["recorded_security_outcome"] == "ESTABLISHED"
    assert result["security_eligibility"] == "DENY"
    assert result["qualification_status"] == "LEGACY_UNQUALIFIED"
    assert (result["revocation_reason"]
            == "SELECTED_CHECK_SEMANTIC_REPLAY_NOT_ESTABLISHED")
    assert result["publication_authority"] == "NOT_ESTABLISHED"


def test_pathway_unknown_has_stable_exit_two(tmp_path, capsys) -> None:
    request, certificate = selected_material(status="UNKNOWN")
    request_path, certificate_path = tmp_path / "request.json", tmp_path / "certificate.json"
    request_path.write_bytes(canonical_bytes(request))
    certificate_path.write_bytes(canonical_bytes(certificate))
    args = parser().parse_args(["security", "pathway-check", str(certificate_path),
                                "--request", str(request_path), "--json"])
    assert handle_security_command(args) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "UNKNOWN"
    assert result["security_outcome"] == "UNKNOWN"
    assert result["recorded_security_outcome"] == "UNKNOWN"
    assert result["security_eligibility"] == "DENY"


def test_security_decision_exit_lattice_uses_security_outcome() -> None:
    assert security_cli._exit({"status": "PASS", "security_outcome": "ESTABLISHED"}) == 0
    assert security_cli._exit({"status": "FAIL", "security_outcome": "NOT_ESTABLISHED"}) == 1
    assert security_cli._exit({"status": "PASS", "security_outcome": "FAIL"}) == 1
    assert security_cli._exit({"status": "UNKNOWN", "security_outcome": "UNKNOWN"}) == 2
    assert security_cli._exit({"status": "PASS", "security_outcome": "UNKNOWN"}) == 2
    assert security_cli._exit({"status": "PASS", "security_outcome": "NOT_ESTABLISHED"}) == 2


def test_aggregate_replay_has_stable_exit_and_no_authority(tmp_path, capsys) -> None:
    _, certificate = selected_material()
    path = tmp_path / "assessment.json"
    path.write_bytes(canonical_bytes(assessment(certificate)))
    args = parser().parse_args(["security", "aggregate", str(path), "--json"])
    assert handle_security_command(args) == 2
    result = json.loads(capsys.readouterr().out)
    assert result["risk_class"] == "R2"
    assert result["security_outcome"] == "NOT_ESTABLISHED"
    assert result["recorded_security_outcome"] == "ESTABLISHED"
    assert result["security_eligibility"] == "DENY"
    assert result["qualification_status"] == "LEGACY_UNQUALIFIED"
    assert result["revocation_reason"] == "R2_PREDECESSOR_REPLAY_NOT_ESTABLISHED"
    assert result["security_tier_status"] == "PASS"
    assert result["publication_authority"] == "NOT_ESTABLISHED"


def test_tampered_or_overbound_input_fails_closed(tmp_path, capsys) -> None:
    request, certificate = selected_material()
    certificate["security_outcome"] = "UNKNOWN"
    request_path, certificate_path = tmp_path / "request.json", tmp_path / "certificate.json"
    request_path.write_bytes(canonical_bytes(request))
    certificate_path.write_bytes(canonical_bytes(certificate))
    args = parser().parse_args(["security", "pathway-check", str(certificate_path),
                                "--request", str(request_path), "--json"])
    assert handle_security_command(args) == 1
    assert json.loads(capsys.readouterr().out)["reason"] == "SECURITY_CONTRACT_REJECTED"

    request_path.write_bytes(b" " * (security.MAX_REQUEST_BYTES + 1))
    args = parser().parse_args(["security", "pathway-check", str(certificate_path),
                                "--request", str(request_path), "--json"])
    assert handle_security_command(args) == 2
    assert json.loads(capsys.readouterr().out)["reason"] == "SECURITY_CHECKER_UNAVAILABLE"


def test_helper_help_surface_has_only_read_only_commands() -> None:
    help_text = parser().format_help()
    assert "security" in help_text
    security_parser = parser()._subparsers._group_actions[0].choices["security"]
    commands = security_parser._subparsers._group_actions[0].choices
    assert set(commands) == {"catalog", "pathway-check", "aggregate"}
    assert "publish" not in commands
