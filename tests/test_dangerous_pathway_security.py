"""Dangerous-pathway security contract and adversarial replay tests.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
Verifier Standard (VSTD). These tests establish bounded mechanics, not safety or
publication authority.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.domains.contracts import dangerous_pathway_security as security


def h(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def native_digest(schema_version: str, **payload: object) -> str:
    return security._digest_value({"schema_version": schema_version, **payload})


def selected_check(check_id: str, purpose: str, *, confidential: bool = False) -> dict:
    return {
        "check_id": check_id,
        "purpose": purpose,
        "mechanism_digest": h("mechanism-" + check_id),
        "request_digest": h("request-" + check_id),
        "policy_digest": h("policy-" + check_id),
        "confidential": confidential,
    }


def result_for(check: dict, status: str = "PASS", *,
               pathway_id: str = "selected-pathway") -> dict:
    certificate_digest = native_digest(
        "verifier-dangerous-pathway-native-check-certificate-1",
        pathway_id=pathway_id, selection=check, status=status)
    replay_digest = native_digest(
        "verifier-dangerous-pathway-native-check-replay-1",
        pathway_id=pathway_id, selection=check, status=status,
        certificate_digest=certificate_digest)
    return {
        "check_id": check["check_id"],
        "mechanism_digest": check["mechanism_digest"],
        "request_digest": check["request_digest"],
        "policy_digest": check["policy_digest"],
        "certificate_digest": certificate_digest,
        "replay_digest": replay_digest,
        "status": status,
    }


def request(*, kind: str = "SIM", checks: list[dict] | None = None,
            artifact: str | None = None, surface: str | None = None) -> dict:
    selected = checks or [
        selected_check("counterexample", "COUNTEREXAMPLE"),
        selected_check("refutation", "REFUTATION"),
    ]
    return security.dangerous_pathway_request(
        artifact_digest=artifact or h("artifact"),
        derived_surface_digest=surface or h("surface"),
        source_coordinate_digest=h("source"),
        dependency_inventory_digest=h("dependencies"),
        object_kind=kind,
        risk_policy_digest=h("risk-policy"),
        threat_catalog_digest=h("catalog"),
        threat_catalog_version="catalog-2026-10-09",
        pathway_search_scope_digest=h("pathway-search-scope"),
        operating_envelope_digest=h("envelope"),
        capability_inventory_digest=h("capabilities"),
        pathway_id="selected-pathway",
        catalog_entry_digest=h("catalog-entry"),
        severity="HIGH",
        required_checks=selected,
        reviewer_policy_digest=h("reviewer-policy"),
        invalidator_policy_digest=h("invalidator-policy"),
    )


def observation(req: dict, *, applicability: str = "APPLICABLE",
                applicability_evidence_digest: str | None = None,
                verdict: str = "REFUTED_WITHIN_ENVELOPE",
                trigger_witness_digest: str | None = None,
                statuses: dict[str, str] | None = None,
                mitigations: list[str] | None = None,
                invalidators: list[str] | None = None,
                residual_risk_status: str = "PASS") -> dict:
    statuses = statuses or {}
    return {
        "schema_version": security.OBSERVATION_VERSION,
        "applicability": applicability,
        "applicability_evidence_digest": applicability_evidence_digest,
        "verdict": verdict,
        "trigger_witness_digest": trigger_witness_digest,
        "check_results": [result_for(
            row, statuses.get(row["check_id"], "PASS"),
            pathway_id=req["pathway_id"])
                          for row in req["required_checks"]],
        "counterexample_search_digest": (
            h("counterexample-search") if verdict == "REFUTED_WITHIN_ENVELOPE" else None),
        "mitigation_digests": sorted(mitigations or []),
        "residual_risk_digest": h("residual-risk"),
        "residual_risk_status": residual_risk_status,
        "review": [],
        "invalidators": sorted(invalidators or []),
    }


def certificate(req: dict, **changes) -> dict:
    raw = security.build_dangerous_pathway_certificate(req, observation(req, **changes))
    return json.loads(raw)


def reviewer(label: str, mechanism: str) -> dict:
    reviewer_id_digest = h("reviewer-" + label)
    role_digest = h("role-" + label)
    mechanism_digest = h("review-mechanism-" + mechanism)
    conflict_check_digest = native_digest(
        "verifier-dangerous-pathway-native-conflict-check-1",
        reviewer_id_digest=reviewer_id_digest, role_digest=role_digest,
        mechanism_digest=mechanism_digest, conflict_status="PASS")
    review_digest = native_digest(
        "verifier-dangerous-pathway-native-review-1",
        reviewer_id_digest=reviewer_id_digest, role_digest=role_digest,
        mechanism_digest=mechanism_digest,
        conflict_check_digest=conflict_check_digest,
        conflict_status="PASS", review_status="PASS")
    return {
        "reviewer_id_digest": reviewer_id_digest,
        "role_digest": role_digest,
        "conflict_check_digest": conflict_check_digest,
        "mechanism_digest": mechanism_digest,
        "review_digest": review_digest,
        "review_status": "PASS",
        "conflict_status": "PASS",
    }


def reviews() -> list[dict]:
    return sorted([reviewer("one", "one"), reviewer("two", "two")],
                  key=lambda row: (row["reviewer_id_digest"], row["review_digest"]))


def synthetic_reviews() -> list[dict]:
    return sorted([
        {
            "reviewer_id_digest": h("reviewer-" + label),
            "role_digest": h("role-" + label),
            "conflict_check_digest": h("conflict-" + label),
            "mechanism_digest": h("review-mechanism-" + label),
            "review_digest": h("review-" + label),
            "review_status": "PASS", "conflict_status": "PASS",
        }
        for label in ("one", "two")
    ], key=lambda row: (row["reviewer_id_digest"], row["review_digest"]))


def ordinary_polish(status: str) -> list[dict]:
    return [
        {"tier": tier, "tier_name": name, "status": status,
         "receipt_digest": native_digest(
             "verifier-polish-tier-native-receipt-1",
             tier=tier, tier_name=name, status=status)}
        for tier, name in security.POLISH_TIER_NAMES.items()
    ]


def aggregate(pathway: dict, *, risk: str = "R2", assurance: str = "SEC3_INDEPENDENTLY_REFUTED",
              scope: str = "BOUNDED_INTERFACE", components: list[dict] | None = None,
              interactions: list[dict] | None = None, predecessor: dict | None = None,
              aggregate_reviews: list[dict] | None = None,
              invalidators: list[dict] | None = None,
              ordinary_polish_status: str | None = None,
              evidence_statuses: dict[str, str] | None = None,
              generalizable_tooling: str | None = None,
              capability_risk_floor: str | None = None,
              exported_v1_boundary: bool = False) -> dict:
    selected_components = components or []
    selected_interactions = interactions or []
    selected_invalidators = invalidators or []
    statuses = evidence_statuses or {}
    default_status = "PASS" if risk in {"R2", "R3"} else "UNKNOWN"
    polish = ordinary_polish(ordinary_polish_status or default_status)
    capability = {
        "inventory_digest": pathway["capability_inventory_digest"],
        "observer_mechanism_digest": h("capability-observer"),
        "observer_certificate_digest": h("capability-certificate"),
        "observer_replay_digest": h("capability-replay"),
        "status": statuses.get("capability", default_status),
        "generalizable_tooling": generalizable_tooling or (
            "PRESENT" if risk in {"R2", "R3"} else "UNKNOWN"),
        "risk_floor": capability_risk_floor or risk,
    }
    r2_evidence = {
        "capability_observation": capability,
        "catalog_coverage": {
            "catalog_digest": pathway["threat_catalog_digest"],
            "catalog_version": pathway["threat_catalog_version"],
            "search_scope_digest": pathway["pathway_search_scope_digest"],
            "entry_inventory_digest": security._digest_value(
                [pathway["catalog_entry_digest"]]),
            "entry_count": 1,
            "coverage_evidence_digest": h("catalog-coverage"),
            "status": statuses.get("catalog", default_status),
            "scope_claim": "PINNED_CATALOG_ONLY",
        },
        "operating_envelope": {
            "envelope_digest": pathway["operating_envelope_digest"],
            "replay_digest": h("envelope-replay"),
            "status": statuses.get("envelope", default_status),
        },
        "invalidator_coverage": {
            "policy_digest": pathway["invalidator_policy_digest"],
            "inventory_digest": security._digest_value(selected_invalidators),
            "coverage_evidence_digest": h("invalidator-coverage"),
            "status": statuses.get("invalidators", default_status),
        },
        "composition_coverage": {
            "component_inventory_digest": security._digest_value(selected_components),
            "interaction_inventory_digest": security._digest_value(selected_interactions),
            "coverage_evidence_digest": h("composition-coverage"),
            "status": statuses.get("composition", default_status),
        },
    }
    constructor = (security.aggregate_dangerous_pathway_assessment
                   if exported_v1_boundary
                   else security._aggregate_legacy_dangerous_pathway_assessment_record)
    return constructor(
        artifact_digest=pathway["artifact_digest"],
        derived_surface_digest=pathway["derived_surface_digest"],
        source_coordinate_digest=pathway["source_coordinate_digest"],
        dependency_inventory_digest=pathway["dependency_inventory_digest"],
        object_kind=pathway["object_kind"],
        namespace_digest=h("namespace"),
        polish_receipt_digest=security._digest_value(polish),
        ordinary_polish=polish,
        risk_policy_digest=pathway["risk_policy_digest"],
        threat_catalog_digest=pathway["threat_catalog_digest"],
        threat_catalog_version=pathway["threat_catalog_version"],
        pathway_search_scope_digest=pathway["pathway_search_scope_digest"],
        operating_envelope_digest=pathway["operating_envelope_digest"],
        reviewer_policy_digest=pathway["reviewer_policy_digest"],
        invalidator_policy_digest=pathway["invalidator_policy_digest"],
        capability_inventory_digest=pathway["capability_inventory_digest"],
        pathways=[pathway],
        components=selected_components,
        interactions=selected_interactions,
        predecessor=predecessor or {
            "artifact_digest": None, "derived_surface_digest": None,
            "assessment_digest": None, "risk_class": None,
        },
        r2_evidence=r2_evidence,
        risk_class=risk,
        assurance_level=assurance,
        maximum_release_scope=scope,
        review=aggregate_reviews if aggregate_reviews is not None else reviews(),
        invalidators=selected_invalidators,
    )


def v2_material(*, artifact: str | None = None, kind: str = "SIM",
                entries: list[tuple[str, str]] | None = None) -> tuple[list[dict], list[dict]]:
    selected_entries = entries or [("critical-path", "CRITICAL"), ("high-path", "HIGH")]
    manifest = sorted([
        {"pathway_id": pathway_id,
         "catalog_entry_digest": h("catalog-entry-" + pathway_id),
         "severity": severity}
        for pathway_id, severity in selected_entries
    ], key=lambda row: (row["pathway_id"], row["catalog_entry_digest"], row["severity"]))
    catalog_digest = security._digest_value(manifest)
    certificates = []
    for entry in manifest:
        if entry["severity"] not in {"HIGH", "CRITICAL"}:
            continue
        checks = [
            selected_check("counterexample", "COUNTEREXAMPLE"),
            selected_check("refutation", "REFUTATION"),
        ]
        req = security.dangerous_pathway_request(
            artifact_digest=artifact or h("v2-artifact"),
            derived_surface_digest=h("v2-surface"),
            source_coordinate_digest=h("v2-source"),
            dependency_inventory_digest=h("v2-dependencies"),
            object_kind=kind, risk_policy_digest=h("v2-risk-policy"),
            threat_catalog_digest=catalog_digest,
            threat_catalog_version="catalog-v2-2026-10-09",
            pathway_search_scope_digest=h("v2-pathway-search-scope"),
            operating_envelope_digest=h("v2-envelope"),
            capability_inventory_digest=h("v2-capabilities"),
            pathway_id=entry["pathway_id"],
            catalog_entry_digest=entry["catalog_entry_digest"],
            severity=entry["severity"], required_checks=checks,
            reviewer_policy_digest=h("v2-reviewer-policy"),
            invalidator_policy_digest=h("v2-invalidator-policy"),
        )
        certificates.append(certificate(req))
    return manifest, sorted(certificates, key=lambda row: row["pathway_id"])


def aggregate_v2(manifest: list[dict], pathways: list[dict], *,
                 risk: str = "R2_PENDING", predecessor: dict | None = None,
                 scope: str | None = None, components: list[dict] | None = None,
                 interactions: list[dict] | None = None,
                 invalidators: list[dict] | None = None,
                 synthetic_h_pass: bool = False,
                 evidence_artifact_manifest: list[dict] | None = None,
                 evidence_artifacts: dict[str, bytes] | None = None,
                 source_inventory_digest: str | None = None,
                 package_inventory_digest: str | None = None) -> dict:
    first = pathways[0]
    selected_components = components or []
    selected_interactions = interactions or []
    selected_invalidators = invalidators or []
    polish = ordinary_polish("PASS")
    if synthetic_h_pass:
        polish = [
            {"tier": tier, "tier_name": name, "status": "PASS",
             "receipt_digest": h(f"polish-tier-{tier}")}
            for tier, name in security.POLISH_TIER_NAMES.items()
        ]
    capability_subject = {
        "inventory_digest": first["capability_inventory_digest"],
        "observer_mechanism_digest": h("v2-capability-observer"),
        "status": "PASS", "generalizable_tooling": "PRESENT", "risk_floor": "R2",
    }
    capability_certificate = native_digest(
        "verifier-dangerous-pathway-native-capability-certificate-1",
        subject=capability_subject)
    capability = {
        **capability_subject,
        "observer_certificate_digest": (
            h("v2-capability-certificate")
            if synthetic_h_pass else capability_certificate),
        "observer_replay_digest": (
            h("v2-capability-replay") if synthetic_h_pass else native_digest(
                "verifier-dangerous-pathway-native-capability-replay-1",
                subject=capability_subject, certificate_digest=capability_certificate)),
    }
    catalog_subject = {
        "catalog_digest": first["threat_catalog_digest"],
        "catalog_version": first["threat_catalog_version"],
        "search_scope_digest": first["pathway_search_scope_digest"],
        "entry_inventory_digest": security._digest_value(
            [row["catalog_entry_digest"] for row in manifest]),
        "entry_count": len(manifest), "status": "PASS",
        "scope_claim": "PINNED_CATALOG_ONLY",
    }
    envelope_subject = {
        "envelope_digest": first["operating_envelope_digest"], "status": "PASS",
    }
    invalidator_subject = {
        "policy_digest": first["invalidator_policy_digest"],
        "inventory_digest": security._digest_value(selected_invalidators),
        "status": "PASS",
    }
    composition_subject = {
        "component_inventory_digest": security._digest_value(selected_components),
        "interaction_inventory_digest": security._digest_value(selected_interactions),
        "status": "PASS",
    }
    evidence = {
        "capability_observation": capability,
        "catalog_coverage": {
            **catalog_subject,
            "coverage_evidence_digest": (
                h("v2-catalog-coverage") if synthetic_h_pass else native_digest(
                    "verifier-dangerous-pathway-native-catalog-coverage-1",
                    subject=catalog_subject)),
        },
        "operating_envelope": {
            **envelope_subject,
            "replay_digest": (
                h("v2-envelope-replay") if synthetic_h_pass else native_digest(
                    "verifier-dangerous-pathway-native-envelope-replay-1",
                    subject=envelope_subject)),
        },
        "invalidator_coverage": {
            **invalidator_subject,
            "coverage_evidence_digest": (
                h("v2-invalidator-coverage") if synthetic_h_pass else native_digest(
                    "verifier-dangerous-pathway-native-invalidator-coverage-1",
                    subject=invalidator_subject)),
        },
        "composition_coverage": {
            **composition_subject,
            "coverage_evidence_digest": (
                h("v2-composition-coverage") if synthetic_h_pass else native_digest(
                    "verifier-dangerous-pathway-native-composition-coverage-1",
                    subject=composition_subject)),
        },
    }
    selected_review = ([] if risk == "R2_PENDING" else
                       (synthetic_reviews() if synthetic_h_pass else reviews()))
    return security.aggregate_dangerous_pathway_assessment_v2(
        artifact_digest=first["artifact_digest"],
        derived_surface_digest=first["derived_surface_digest"],
        source_coordinate_digest=first["source_coordinate_digest"],
        dependency_inventory_digest=first["dependency_inventory_digest"],
        source_inventory_digest=source_inventory_digest or h("v2-source-inventory"),
        package_inventory_digest=package_inventory_digest or h("v2-package-inventory"),
        object_kind=first["object_kind"], namespace_digest=h("v2-namespace"),
        polish_receipt_digest=security._digest_value(polish), ordinary_polish=polish,
        risk_policy_digest=first["risk_policy_digest"],
        threat_catalog_digest=first["threat_catalog_digest"],
        threat_catalog_version=first["threat_catalog_version"],
        pathway_search_scope_digest=first["pathway_search_scope_digest"],
        operating_envelope_digest=first["operating_envelope_digest"],
        reviewer_policy_digest=first["reviewer_policy_digest"],
        invalidator_policy_digest=first["invalidator_policy_digest"],
        capability_inventory_digest=first["capability_inventory_digest"],
        catalog_manifest=manifest, pathways=pathways,
        components=selected_components, interactions=selected_interactions,
        predecessor_assessment_bytes=(
            canonical_bytes(predecessor) if predecessor is not None else None),
        r2_evidence=evidence, risk_class=risk,
        assurance_level=("SEC2_PATHWAYS_REPLAYED" if risk == "R2_PENDING"
                         else "SEC3_INDEPENDENTLY_REFUTED"),
        maximum_release_scope=scope or "DENY",
        review=selected_review, invalidators=selected_invalidators,
        evidence_artifact_manifest=evidence_artifact_manifest or [],
        evidence_artifacts=evidence_artifacts,
    )


@pytest.mark.parametrize("kind", ["SIM", "MODEL", "AGENT", "HARNESS", "BOT", "DATA", "OBJECT"])
def test_all_relevant_object_kinds_can_enter_the_same_pathway_contract(kind: str) -> None:
    selected = request(kind=kind)
    assert selected["object_kind"] == kind
    assert security.dangerous_pathway_catalog()["publication_authority"] == "NOT_ESTABLISHED"


def test_refutation_certificate_and_r2_aggregate_replay_without_publication_authority() -> None:
    req = request()
    cert = certificate(req)
    assert cert["status"] == "PASS"
    assert cert["security_outcome"] == "ESTABLISHED"
    replay = security.recheck_dangerous_pathway_certificate(
        canonical_bytes(cert), request_bytes=canonical_bytes(req))
    assert replay["replay_status"] == "REPRODUCED"
    assert replay["status"] == "PASS"
    assert replay["security_outcome"] == "NOT_ESTABLISHED"
    assert replay["recorded_security_outcome"] == "ESTABLISHED"
    assert replay["security_eligibility"] == "DENY"
    assert replay["qualification_status"] == "LEGACY_UNQUALIFIED"
    assert (replay["revocation_reason"]
            == "SELECTED_CHECK_SEMANTIC_REPLAY_NOT_ESTABLISHED")
    assert replay["publication_authority"] == "NOT_ESTABLISHED"

    assessment = aggregate(cert)
    assert assessment["status"] == "PASS"
    assert assessment["aggregate"] == {
        "risk_class": "R2",
        "assurance_level": "SEC3_INDEPENDENTLY_REFUTED",
        "security_outcome": "ESTABLISHED",
        "maximum_release_scope": "BOUNDED_INTERFACE",
        "security_tier": 9,
        "security_tier_name": "SECURITY",
        "security_tier_status": "PASS",
        "publication_authority": "NOT_ESTABLISHED",
    }
    replayed = security.recheck_dangerous_pathway_assessment(canonical_bytes(assessment))
    assert replayed["replay_status"] == "REPRODUCED"
    assert replayed["security_outcome"] == "NOT_ESTABLISHED"
    assert replayed["recorded_security_outcome"] == "ESTABLISHED"
    assert replayed["security_eligibility"] == "DENY"
    assert replayed["qualification_status"] == "LEGACY_UNQUALIFIED"
    assert replayed["revocation_reason"] == "R2_PREDECESSOR_REPLAY_NOT_ESTABLISHED"
    assert replayed["publication_authority"] == "NOT_ESTABLISHED"


def test_exported_v1_constructor_returns_only_legacy_unqualified_deny() -> None:
    decision = aggregate(certificate(request()), exported_v1_boundary=True)
    assert decision["security_outcome"] == "NOT_ESTABLISHED"
    assert decision["recorded_security_outcome"] == "ESTABLISHED"
    assert decision["security_eligibility"] == "DENY"
    assert decision["qualification_status"] == "LEGACY_UNQUALIFIED"
    assert decision["revocation_reason"] == "R2_PREDECESSOR_REPLAY_NOT_ESTABLISHED"
    assert decision["publication_authority"] == "NOT_ESTABLISHED"


def test_proved_not_applicable_requires_selected_passing_evidence() -> None:
    applicability = selected_check("applicability", "APPLICABILITY")
    req = request(checks=[applicability])
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="proved inapplicability"):
        certificate(req, applicability="PROVED_NOT_APPLICABLE", verdict="UNKNOWN")
    cert = certificate(
        req, applicability="PROVED_NOT_APPLICABLE",
        applicability_evidence_digest=h("not-applicable-proof"), verdict="UNKNOWN")
    assert cert["status"] == "PASS"
    assert cert["security_outcome"] == "ESTABLISHED"


def test_containment_is_not_refutation_and_unknown_blocks_r2() -> None:
    containment = selected_check("containment", "CONTAINMENT")
    req = request(checks=[containment])
    cert = certificate(req, verdict="CONTAINED_NOT_REFUTED", mitigations=[h("mitigation")])
    assert cert["status"] == "PASS"
    assert cert["security_outcome"] == "UNKNOWN"
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="R2 requires independent bounded refutation"):
        aggregate(cert)
    pending = aggregate(cert, risk="R2_PENDING", assurance="SEC2_PATHWAYS_REPLAYED",
                        scope="DENY", aggregate_reviews=[])
    assert pending["aggregate"]["security_outcome"] == "UNKNOWN"


def test_present_pathway_forces_r3_deny_but_mechanical_status_passes() -> None:
    trigger = selected_check("trigger", "TRIGGER")
    req = request(checks=[trigger])
    cert = certificate(req, verdict="PRESENT",
                       trigger_witness_digest=h("trigger-witness"))
    assert cert["status"] == "PASS"
    assert cert["security_outcome"] == "FAIL"
    replay = security.recheck_dangerous_pathway_certificate(
        canonical_bytes(cert), request_bytes=canonical_bytes(req))
    assert replay["status"] == "PASS"
    assert replay["security_outcome"] == "NOT_ESTABLISHED"
    assert replay["recorded_security_outcome"] == "FAIL"
    assert replay["security_eligibility"] == "DENY"
    assessment = aggregate(cert, risk="R3", assurance="SEC2_PATHWAYS_REPLAYED",
                           scope="DENY", aggregate_reviews=[])
    assert assessment["status"] == "PASS"
    assert assessment["aggregate"]["security_outcome"] == "FAIL"
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="present pathway requires R3 denial"):
        aggregate(cert, risk="R2_PENDING", assurance="SEC2_PATHWAYS_REPLAYED",
                  scope="METADATA_ONLY", aggregate_reviews=[])


def test_sim_enters_pending_and_present_sim_is_r3_denied() -> None:
    refuted = certificate(request(kind="SIM"))
    pending = aggregate(
        refuted, risk="R2_PENDING", assurance="SEC2_PATHWAYS_REPLAYED",
        scope="DENY", aggregate_reviews=[])
    assert pending["object_kind"] == "SIM"
    assert pending["aggregate"]["risk_class"] == "R2_PENDING"
    assert pending["aggregate"]["security_outcome"] == "UNKNOWN"
    assert pending["aggregate"]["publication_authority"] == "NOT_ESTABLISHED"
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="pending risk is denied"):
        aggregate(
            refuted, risk="R2_PENDING", assurance="SEC2_PATHWAYS_REPLAYED",
            scope="BOUNDED_INTERFACE", aggregate_reviews=[])

    trigger = selected_check("trigger", "TRIGGER")
    present = certificate(
        request(kind="SIM", checks=[trigger]), verdict="PRESENT",
        trigger_witness_digest=h("sim-trigger"))
    denied = aggregate(
        present, risk="R3", assurance="SEC2_PATHWAYS_REPLAYED",
        scope="DENY", aggregate_reviews=[])
    assert denied["aggregate"]["risk_class"] == "R3"
    assert denied["aggregate"]["security_outcome"] == "FAIL"
    assert denied["aggregate"]["maximum_release_scope"] == "DENY"
    assert denied["aggregate"]["publication_authority"] == "NOT_ESTABLISHED"


def test_r2_pending_is_unconditionally_denied_not_metadata_releasable() -> None:
    cert = certificate(request(kind="MODEL"))
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="pending risk is denied"):
        aggregate(
            cert, risk="R2_PENDING", assurance="SEC2_PATHWAYS_REPLAYED",
            scope="METADATA_ONLY", aggregate_reviews=[])


@pytest.mark.parametrize("kind", ["SIM", "MODEL"])
def test_capability_and_generalizable_tooling_set_risk_floor_not_kind(kind: str) -> None:
    cert = certificate(request(kind=kind))
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="below observed capability and tooling floor"):
        aggregate(cert, risk="R2", capability_risk_floor="R3")
    denied = aggregate(
        cert, risk="R3", assurance="SEC3_INDEPENDENTLY_REFUTED", scope="DENY",
        capability_risk_floor="R3")
    assert denied["object_kind"] == kind
    assert denied["aggregate"]["maximum_release_scope"] == "DENY"


def test_generalizable_tooling_cannot_be_classified_pending() -> None:
    cert = certificate(request(kind="OBJECT"))
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="generalizable tooling requires at least R2"):
        aggregate(
            cert, risk="R2_PENDING", scope="DENY", aggregate_reviews=[],
            generalizable_tooling="PRESENT", capability_risk_floor="R2_PENDING")


@pytest.mark.parametrize(
    "missing",
    ["capability", "catalog", "envelope", "invalidators", "composition"],
)
def test_each_exact_r2_evidence_gate_is_required(missing: str) -> None:
    cert = certificate(request(kind="MODEL"))
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="R2 requires independent bounded refutation"):
        aggregate(cert, evidence_statuses={missing: "UNKNOWN"})


def test_tiers_one_through_five_are_necessary_but_do_not_replace_security_tier() -> None:
    cert = certificate(request())
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="R2 requires independent bounded refutation"):
        aggregate(cert, ordinary_polish_status="UNKNOWN")
    established = aggregate(cert)
    assert [row["tier"] for row in established["ordinary_polish"]] == [1, 2, 3, 4, 5]
    assert established["aggregate"]["security_tier"] == 9
    assert established["aggregate"]["security_tier_status"] == "PASS"


def test_residual_unknown_preserves_mechanical_pass_but_blocks_security() -> None:
    req = request()
    cert = certificate(req, residual_risk_status="UNKNOWN")
    assert cert["status"] == "PASS"
    assert cert["security_outcome"] == "UNKNOWN"
    replay = security.recheck_dangerous_pathway_certificate(
        canonical_bytes(cert), request_bytes=canonical_bytes(req))
    assert replay["replay_status"] == "REPRODUCED"
    assert replay["status"] == "PASS"
    assert replay["security_outcome"] == "UNKNOWN"
    assert replay["recorded_security_outcome"] == "UNKNOWN"
    assert replay["security_eligibility"] == "DENY"
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="R2 requires independent bounded refutation"):
        aggregate(cert)


def test_r3_is_denied_even_without_a_triggering_witness() -> None:
    cert = certificate(request())
    denied = aggregate(cert, risk="R3", scope="DENY", capability_risk_floor="R3")
    assert denied["aggregate"]["security_outcome"] == "NOT_ESTABLISHED"
    assert denied["aggregate"]["maximum_release_scope"] == "DENY"
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="R3 is never releasable"):
        aggregate(cert, risk="R3", scope="METADATA_ONLY", capability_risk_floor="R3")


def test_catalog_version_and_search_scope_are_certificate_bindings() -> None:
    req = request()
    cert = certificate(req)
    substituted = deepcopy(req)
    substituted["threat_catalog_version"] = "catalog-substituted"
    substituted["request_digest"] = security._digest_without(
        substituted, "request_digest")
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="certificate result or digest differs"):
        security.recheck_dangerous_pathway_certificate(
            canonical_bytes(cert), request_bytes=canonical_bytes(substituted))
    assert "unknown- or future-pathway absence" in cert["claim_boundary"]


def test_payment_or_customer_priority_cannot_waive_gates_or_add_authority() -> None:
    assessment = aggregate(certificate(request()))
    assessment["customer_priority_override"] = "PAID_FAST_TRACK"
    assessment["assessment_digest"] = security._digest_without(
        assessment, "assessment_digest")
    with pytest.raises(security.DangerousPathwaySecurityError, match="fields differ"):
        security.recheck_dangerous_pathway_assessment(canonical_bytes(assessment))
    catalog = security.dangerous_pathway_catalog()
    assert catalog["commercial_priority_security_effect"] == "NONE"
    assert catalog["publication_authority"] == "NOT_ESTABLISHED"


def test_r3_cannot_be_downgraded_in_place() -> None:
    cert = certificate(request())
    predecessor = {
        "artifact_digest": cert["artifact_digest"],
        "derived_surface_digest": h("old-surface"),
        "assessment_digest": h("old-assessment"),
        "risk_class": "R3",
    }
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="R3 cannot be downgraded in place"):
        aggregate(cert, predecessor=predecessor)


def test_capability_removal_requires_new_surface_digest() -> None:
    removal = selected_check("removal", "CAPABILITY_REMOVAL")
    artifact = h("same-bytes")
    req = request(checks=[removal], artifact=artifact, surface=artifact)
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="separately digested derived surface"):
        certificate(req, verdict="CAPABILITY_REMOVED")
    changed = request(checks=[removal], artifact=artifact, surface=h("derived-surface"))
    assert certificate(changed, verdict="CAPABILITY_REMOVED")["security_outcome"] == "ESTABLISHED"


def test_missing_interaction_amplification_stays_unknown() -> None:
    cert = certificate(request())
    components = [
        {"component_id": "a", "digest": h("a"), "risk_class": "R2_PENDING"},
        {"component_id": "b", "digest": h("b"), "risk_class": "R2_PENDING"},
    ]
    pending = aggregate(cert, risk="R2_PENDING", assurance="SEC2_PATHWAYS_REPLAYED",
                        scope="DENY", components=components,
                        aggregate_reviews=[])
    assert pending["status"] == "UNKNOWN"
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="R2 requires independent bounded refutation"):
        aggregate(cert, components=components)


def test_partial_pairwise_interaction_cannot_clear_higher_order_composition() -> None:
    cert = certificate(request())
    components = [
        {"component_id": name, "digest": h(name), "risk_class": "R2_PENDING"}
        for name in ("a", "b", "c")
    ]
    partial = [{
        "interaction_id": "a+b",
        "component_ids": ["a", "b"],
        "amplification_status": "PASS",
        "counterexample_search_digest": h("a+b-search"),
    }]
    pending = aggregate(
        cert, risk="R2_PENDING", assurance="SEC2_PATHWAYS_REPLAYED",
        scope="DENY", components=components, interactions=partial,
        aggregate_reviews=[])
    assert pending["status"] == "UNKNOWN"
    assert pending["aggregate"]["security_outcome"] == "UNKNOWN"
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="R2 requires independent bounded refutation"):
        aggregate(cert, components=components, interactions=partial)

    complete = [
        *partial,
        {
            "interaction_id": "a+b+c",
            "component_ids": ["a", "b", "c"],
            "amplification_status": "PASS",
            "counterexample_search_digest": h("a+b+c-search"),
        },
    ]
    established = aggregate(cert, components=components, interactions=complete)
    assert established["status"] == "PASS"
    assert established["aggregate"]["security_outcome"] == "ESTABLISHED"


def test_component_risk_floor_and_interaction_amplification_are_conserved() -> None:
    cert = certificate(request())
    r3_component = [{"component_id": "dangerous", "digest": h("dangerous"),
                     "risk_class": "R3"}]
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="composition cannot lower component risk"):
        aggregate(cert, risk="R2_PENDING", assurance="SEC2_PATHWAYS_REPLAYED",
                  scope="DENY", components=r3_component,
                  aggregate_reviews=[])

    components = [
        {"component_id": "a", "digest": h("a"), "risk_class": "R2_PENDING"},
        {"component_id": "b", "digest": h("b"), "risk_class": "R2_PENDING"},
    ]
    interactions = [{"interaction_id": "a+b", "component_ids": ["a", "b"],
                     "amplification_status": "FAIL",
                     "counterexample_search_digest": h("interaction-witness")}]
    assessment = aggregate(
        cert, risk="R3", assurance="SEC2_PATHWAYS_REPLAYED", scope="DENY",
        components=components, interactions=interactions, aggregate_reviews=[])
    assert assessment["status"] == "PASS"
    assert assessment["aggregate"]["security_outcome"] == "FAIL"


def test_confidential_digest_only_result_cannot_pass() -> None:
    confidential = selected_check("confidential", "REFUTATION", confidential=True)
    req = request(checks=[confidential])
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="confidential digest-only evidence"):
        security.build_dangerous_pathway_certificate(
            req, observation(req, verdict="UNKNOWN"))
    cert = certificate(req, verdict="UNKNOWN", statuses={"confidential": "UNKNOWN"})
    assert cert["status"] == "UNKNOWN"
    assert cert["security_outcome"] == "UNKNOWN"


def test_independent_r2_review_requires_two_reviewers_and_mechanisms() -> None:
    cert = certificate(request())
    one = reviews()[0]
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="R2 requires independent bounded refutation"):
        aggregate(cert, aggregate_reviews=[one])
    duplicate_mechanism = deepcopy(reviews())
    duplicate_mechanism[1]["mechanism_digest"] = duplicate_mechanism[0]["mechanism_digest"]
    duplicate_mechanism.sort(key=lambda row: (row["reviewer_id_digest"], row["review_digest"]))
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="R2 requires independent bounded refutation"):
        aggregate(cert, aggregate_reviews=duplicate_mechanism)


def test_active_invalidator_and_unknown_check_remain_unknown() -> None:
    req = request()
    cert = certificate(req, verdict="UNKNOWN", statuses={"refutation": "UNKNOWN"})
    assert cert["status"] == "UNKNOWN"
    pending = aggregate(
        cert, risk="R2_PENDING", assurance="SEC2_PATHWAYS_REPLAYED",
        scope="DENY", aggregate_reviews=[],
        invalidators=[{"invalidator_id": "catalog-change", "digest": h("change"),
                      "status": "ACTIVE"}],
    )
    assert pending["status"] == "UNKNOWN"


def test_tampering_and_unknown_fields_are_rejected_even_when_rehashed() -> None:
    req = request()
    cert = certificate(req)
    cert["security_outcome"] = "UNKNOWN"
    cert["certificate_digest"] = security._digest_without(cert, "certificate_digest")
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="certificate result or digest differs"):
        security.recheck_dangerous_pathway_certificate(
            canonical_bytes(cert), request_bytes=canonical_bytes(req))
    req["producer_callback"] = "run-me"
    with pytest.raises(security.DangerousPathwaySecurityError, match="fields differ"):
        security.recheck_dangerous_pathway_certificate(
            canonical_bytes(certificate(request())), request_bytes=canonical_bytes(req))


def test_duplicate_json_and_rehashed_publication_authority_are_rejected() -> None:
    req = request()
    cert = certificate(req)
    raw_request = canonical_bytes(req)
    duplicate = b'{"schema_version":"attacker-version",' + raw_request[1:]
    with pytest.raises(security.DangerousPathwaySecurityError, match="strict JSON"):
        security.recheck_dangerous_pathway_certificate(
            canonical_bytes(cert), request_bytes=duplicate)

    assessment = aggregate(cert)
    assessment["aggregate"]["publication_authority"] = "AUTHORIZED"
    assessment["assessment_digest"] = security._digest_without(
        assessment, "assessment_digest")
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="aggregate semantics differ"):
        security.recheck_dangerous_pathway_assessment(canonical_bytes(assessment))


def test_v2_exact_predecessor_cannot_promote_without_installed_replayers() -> None:
    manifest, pathways = v2_material()
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="initial assessment must be R2_PENDING"):
        aggregate_v2(manifest, pathways, risk="R2")
    pending = aggregate_v2(manifest, pathways)
    assert pending["aggregate"]["risk_class"] == "R2_PENDING"
    assert pending["aggregate"]["maximum_release_scope"] == "DENY"
    assert pending["aggregate"]["security_outcome"] == "UNKNOWN"
    assert pending["aggregate"]["security_eligibility"] == "DENY"
    assert pending["mechanism_digest"] == security.mechanism_digest()
    assert pending["source_inventory_digest"] == h("v2-source-inventory")
    assert pending["package_inventory_digest"] == h("v2-package-inventory")
    assert pending["predecessor_assessment_digest"] is None
    assert pending["predecessor_replay_digest"] is None
    assert pending["aggregate"]["catalog_authority"] == "UNKNOWN"
    assert pending["aggregate"]["assessment_time_authority"] == "UNKNOWN"
    assert pending["aggregate"]["reviewer_authority"] == "NOT_ESTABLISHED"

    denied = aggregate_v2(manifest, pathways, risk="R2", predecessor=pending)
    assert denied["aggregate"]["risk_class"] == "R2"
    assert denied["aggregate"]["security_outcome"] == "UNKNOWN"
    assert denied["aggregate"]["security_eligibility"] == "DENY"
    assert denied["aggregate"]["maximum_release_scope"] == "DENY"
    assert denied["evidence_artifact_manifest"] == []
    assert denied["predecessor_assessment"]["assessment_digest"] == pending[
        "assessment_digest"]
    assert denied["predecessor_assessment_digest"] == pending["assessment_digest"]
    assert denied["predecessor_replay_digest"].startswith("sha256:")
    replay = security.recheck_dangerous_pathway_assessment_v2(
        canonical_bytes(denied), predecessor_assessment_bytes=canonical_bytes(pending))
    assert replay["replay_status"] == "REPRODUCED"
    assert replay["assessment_scope_digest"] == denied["assessment_scope_digest"]
    assert replay["mechanism_digest"] == security.mechanism_digest()
    assert replay["source_inventory_digest"] == h("v2-source-inventory")
    assert replay["package_inventory_digest"] == h("v2-package-inventory")
    assert replay["predecessor_assessment_digest"] == pending["assessment_digest"]
    assert replay["predecessor_replay_digest"] == denied["predecessor_replay_digest"]
    assert replay["security_outcome"] == "UNKNOWN"
    assert replay["security_eligibility"] == "DENY"
    assert replay["publication_authority"] == "NOT_ESTABLISHED"
    generic_replay = security.recheck_dangerous_pathway_assessment(
        canonical_bytes(denied))
    assert generic_replay["schema_version"].endswith("replay-2")
    assert generic_replay["assessment_digest"] == denied["assessment_digest"]
    eligibility_substituted = deepcopy(denied)
    eligibility_substituted["aggregate"][
        "security_eligibility"] = "ELIGIBLE_FOR_SEPARATE_PUBLICATION_AUTHORIZATION"
    eligibility_substituted["assessment_digest"] = security._digest_without(
        eligibility_substituted, "assessment_digest")
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="security eligibility differs"):
        security.recheck_dangerous_pathway_assessment_v2(
            canonical_bytes(eligibility_substituted))

def test_v2_attacker_artifacts_and_consistent_rehash_cannot_establish_eligibility() -> None:
    manifest, pathways = v2_material()
    synthetic_pathways = deepcopy(pathways)
    for pathway in synthetic_pathways:
        for result in pathway["required_check_results"]:
            result["certificate_digest"] = h(
                "certificate-" + pathway["pathway_id"] + "-" + result["check_id"])
            result["replay_digest"] = h(
                "replay-" + pathway["pathway_id"] + "-" + result["check_id"])
        pathway["certificate_digest"] = security._digest_without(
            pathway, "certificate_digest")
    source_bytes = canonical_bytes({"inventory": ["attacker-source"], "status": "PASS"})
    package_bytes = canonical_bytes({"inventory": ["attacker-package"], "status": "PASS"})
    source_digest = "sha256:" + hashlib.sha256(source_bytes).hexdigest()
    package_digest = "sha256:" + hashlib.sha256(package_bytes).hexdigest()
    components = [
        {"component_id": "a", "digest": h("component-a"), "risk_class": "R2"},
        {"component_id": "b", "digest": h("component-b"), "risk_class": "R2"},
    ]
    interactions = [{
        "interaction_id": "a+b", "component_ids": ["a", "b"],
        "amplification_status": "PASS",
        "counterexample_search_digest": h("attacker-interaction-pass"),
    }]
    invalidators = [{
        "invalidator_id": "attacker-cleared", "digest": h("invalidator"),
        "status": "CLEARED",
    }]
    common = {
        "synthetic_h_pass": True,
        "source_inventory_digest": source_digest,
        "package_inventory_digest": package_digest,
        "components": components,
        "interactions": interactions,
        "invalidators": invalidators,
    }
    pending = aggregate_v2(manifest, synthetic_pathways, **common)
    probe = aggregate_v2(
        manifest, synthetic_pathways, risk="R2", predecessor=pending, **common)
    contributors = security._evidence_contributors(probe)
    assert {value["kind"] for value in contributors.values()} == (
        security._EVIDENCE_CONTRIBUTOR_KINDS)
    references = []
    artifacts: dict[str, bytes] = {}
    for contributor_id, expected in sorted(contributors.items()):
        if expected["kind"] == "SOURCE_INVENTORY":
            raw = source_bytes
        elif expected["kind"] == "PACKAGE_INVENTORY":
            raw = package_bytes
        else:
            raw = expected["expected_bytes"]
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        artifact_id = "urn:sha256:" + digest.removeprefix("sha256:")
        artifacts[artifact_id] = raw
        references.append({
            "schema_version": security.EVIDENCE_REFERENCE_VERSION,
            "contributor_id": contributor_id,
            "contributor_kind": expected["kind"],
            "artifact_id": artifact_id,
            "artifact_digest": digest,
            "replayer_id": expected["replayer_id"],
        })
    denied = aggregate_v2(
        manifest, synthetic_pathways, risk="R2", predecessor=pending,
        evidence_artifact_manifest=references, evidence_artifacts=artifacts,
        **common)
    assert len(denied["evidence_artifact_manifest"]) == len(contributors)
    assert denied["aggregate"]["security_outcome"] == "UNKNOWN"
    assert denied["aggregate"]["security_eligibility"] == "DENY"
    replay = security.recheck_dangerous_pathway_assessment_v2(
        canonical_bytes(denied), evidence_artifacts=artifacts)
    assert replay["security_outcome"] == "UNKNOWN"
    assert replay["security_eligibility"] == "DENY"
    unresolved = security.recheck_dangerous_pathway_assessment_v2(
        canonical_bytes(denied))
    assert unresolved["security_outcome"] == "UNKNOWN"
    assert unresolved["security_eligibility"] == "DENY"

    substituted_replayer = deepcopy(denied)
    substituted_replayer["evidence_artifact_manifest"][0][
        "replayer_id"] = "attacker.selected.replayer.1"
    substituted_replayer["assessment_digest"] = security._digest_without(
        substituted_replayer, "assessment_digest")
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="fixed replayer is unresolved"):
        security.recheck_dangerous_pathway_assessment_v2(
            canonical_bytes(substituted_replayer), evidence_artifacts=artifacts)

    forged = deepcopy(denied)
    forged["aggregate"]["security_outcome"] = "ESTABLISHED"
    forged["aggregate"][
        "security_eligibility"] = "ELIGIBLE_FOR_SEPARATE_PUBLICATION_AUTHORIZATION"
    forged["aggregate"]["security_tier_status"] = "PASS"
    forged["aggregate"]["maximum_release_scope"] = "BOUNDED_INTERFACE"
    forged["assessment_digest"] = security._digest_without(
        forged, "assessment_digest")
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="unreplayed R2 evidence is denied"):
        security.recheck_dangerous_pathway_assessment_v2(
            canonical_bytes(forged), evidence_artifacts=artifacts)


@pytest.mark.parametrize("kind", ["SIM", "VERIFIER", "HYPER", "GRAPH"])
def test_v2_current_object_kinds_enter_pending_without_policy_defaults(kind: str) -> None:
    manifest, pathways = v2_material(kind=kind)
    pending = aggregate_v2(manifest, pathways)
    assert pending["object_kind"] == kind
    assert pending["aggregate"]["risk_class"] == "R2_PENDING"
    assert pending["aggregate"]["security_eligibility"] == "DENY"
    assert pending["aggregate"]["publication_authority"] == "NOT_ESTABLISHED"


def test_v2_same_scope_transitions_are_monotone_and_r3_cannot_downgrade() -> None:
    manifest, pathways = v2_material()
    pending = aggregate_v2(manifest, pathways)
    r3 = aggregate_v2(manifest, pathways, risk="R3", predecessor=pending)
    assert r3["aggregate"]["maximum_release_scope"] == "DENY"
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="same-scope risk transition is not monotone"):
        aggregate_v2(manifest, pathways, risk="R2", predecessor=r3)


def test_v2_scope_change_restarts_pending_and_blocks_scope_substitution() -> None:
    manifest, pathways = v2_material()
    pending = aggregate_v2(manifest, pathways)
    promoted = aggregate_v2(manifest, pathways, risk="R2", predecessor=pending)
    changed_manifest, changed_pathways = v2_material(artifact=h("changed-artifact"))
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="scope change must restart at R2_PENDING"):
        aggregate_v2(changed_manifest, changed_pathways, risk="R2", predecessor=promoted)
    restarted = aggregate_v2(changed_manifest, changed_pathways, predecessor=promoted)
    assert restarted["aggregate"]["risk_class"] == "R2_PENDING"
    assert restarted["assessment_scope_digest"] != promoted["assessment_scope_digest"]


def test_v2_replays_complete_predecessor_and_rejects_tamper_or_wrong_expected_bytes() -> None:
    manifest, pathways = v2_material()
    pending = aggregate_v2(manifest, pathways)
    tampered = deepcopy(pending)
    tampered["aggregate"]["risk_class"] = "R3"
    tampered["assessment_digest"] = security._digest_without(tampered, "assessment_digest")
    with pytest.raises(security.DangerousPathwaySecurityError):
        aggregate_v2(manifest, pathways, risk="R2", predecessor=tampered)

    mechanism_substituted = deepcopy(pending)
    mechanism_substituted["mechanism_digest"] = h("substituted-mechanism")
    mechanism_substituted["assessment_scope_digest"] = security.assessment_scope_digest(
        mechanism_substituted)
    mechanism_substituted["assessment_digest"] = security._digest_without(
        mechanism_substituted, "assessment_digest")
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="mechanism differs from installed source"):
        security.recheck_dangerous_pathway_assessment_v2(
            canonical_bytes(mechanism_substituted))

    promoted = aggregate_v2(manifest, pathways, risk="R2", predecessor=pending)
    replay_digest_substituted = deepcopy(promoted)
    replay_digest_substituted["predecessor_replay_digest"] = h(
        "substituted-predecessor-replay")
    replay_digest_substituted["assessment_digest"] = security._digest_without(
        replay_digest_substituted, "assessment_digest")
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="predecessor replay digest binding differs"):
        security.recheck_dangerous_pathway_assessment_v2(
            canonical_bytes(replay_digest_substituted))

    other_manifest, other_pathways = v2_material(artifact=h("other-artifact"))
    other = aggregate_v2(other_manifest, other_pathways)
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="expected predecessor assessment differs"):
        security.recheck_dangerous_pathway_assessment_v2(
            canonical_bytes(promoted), predecessor_assessment_bytes=canonical_bytes(other))


def test_v2_exact_manifest_requires_each_high_and_critical_certificate() -> None:
    manifest, pathways = v2_material()
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="every HIGH or CRITICAL"):
        aggregate_v2(manifest, pathways[:-1])

    substituted = deepcopy(manifest)
    substituted[0]["severity"] = "LOW"
    substituted.sort(key=lambda row: (
        row["pathway_id"], row["catalog_entry_digest"], row["severity"]))
    # The exact catalog digest is also independently bound into every certificate.
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="threat catalog digest differs"):
        aggregate_v2(substituted, pathways)

    original = pathways[0]["request"]
    severity_substituted_request = security.dangerous_pathway_request(
        artifact_digest=original["artifact_digest"],
        derived_surface_digest=original["derived_surface_digest"],
        source_coordinate_digest=original["source_coordinate_digest"],
        dependency_inventory_digest=original["dependency_inventory_digest"],
        object_kind=original["object_kind"],
        risk_policy_digest=original["risk_policy_digest"],
        threat_catalog_digest=original["threat_catalog_digest"],
        threat_catalog_version=original["threat_catalog_version"],
        pathway_search_scope_digest=original["pathway_search_scope_digest"],
        operating_envelope_digest=original["operating_envelope_digest"],
        capability_inventory_digest=original["capability_inventory_digest"],
        pathway_id=original["pathway_id"],
        catalog_entry_digest=original["catalog_entry_digest"], severity="HIGH",
        required_checks=original["required_checks"],
        reviewer_policy_digest=original["reviewer_policy_digest"],
        invalidator_policy_digest=original["invalidator_policy_digest"],
        limits=original["limits"],
    )
    severity_substituted = certificate(severity_substituted_request)
    replaced = sorted([severity_substituted, *pathways[1:]],
                      key=lambda row: row["pathway_id"])
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="certificate differs from exact catalog manifest"):
        aggregate_v2(manifest, replaced)

    low_manifest, low_pathways = v2_material(
        entries=[("high-path", "HIGH"), ("low-path", "LOW")])
    pending = aggregate_v2(low_manifest, low_pathways)
    assert [row["pathway_id"] for row in pending["pathways"]] == ["high-path"]


def test_v2_predecessor_depth_and_manifest_bounds_fail_closed() -> None:
    manifest, pathways = v2_material()
    current = aggregate_v2(manifest, pathways)
    for _ in range(security.MAX_PREDECESSOR_DEPTH + 1):
        wrapped = deepcopy(current)
        wrapped["predecessor_assessment"] = current
        wrapped["assessment_digest"] = security._digest_without(
            wrapped, "assessment_digest")
        current = wrapped
    with pytest.raises(security.DangerousPathwaySecurityUnavailable,
                       match="predecessor assessment chain exceeds capacity"):
        security.recheck_dangerous_pathway_assessment_v2(canonical_bytes(current))

    oversized = [
        {"pathway_id": f"path-{index:05d}",
         "catalog_entry_digest": h(f"entry-{index}"), "severity": "LOW"}
        for index in range(security.MAX_ROWS + 1)
    ]
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="capacity|bounded nonempty inventory"):
        aggregate_v2(oversized, pathways)


def test_schemas_are_strict_meta_schema_valid_and_match_runtime_versions() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    referencing = pytest.importorskip("referencing")
    root = Path(__file__).parents[1] / "src" / "verifier" / "schemas"
    expected = {
        "verifier-dangerous-pathway-request-1.schema.json": security.REQUEST_VERSION,
        "verifier-dangerous-pathway-certificate-1.schema.json": security.CERTIFICATE_VERSION,
        "claim-garden-dangerous-pathway-assessment-1.schema.json": security.ASSESSMENT_VERSION,
        "claim-garden-dangerous-pathway-assessment-2.schema.json": security.ASSESSMENT_V2_VERSION,
    }
    schemas = {}
    registry = referencing.Registry()
    for name, version in expected.items():
        schema = json.loads((root / name).read_text(encoding="utf-8"))
        jsonschema.Draft202012Validator.check_schema(schema)
        assert schema["properties"]["schema_version"]["const"] == version
        assert schema["additionalProperties"] is False
        schemas[name] = schema
        registry = registry.with_resource(
            schema["$id"], referencing.Resource.from_contents(schema))
    req = request()
    cert = certificate(req)
    assessment = aggregate(cert)
    manifest, v2_pathways = v2_material()
    assessment_v2 = aggregate_v2(manifest, v2_pathways)
    runtime_kinds = sorted(kind.value for kind in security.ObjectKind)
    for name in (
        "verifier-dangerous-pathway-certificate-1.schema.json",
        "claim-garden-dangerous-pathway-assessment-1.schema.json",
        "claim-garden-dangerous-pathway-assessment-2.schema.json",
    ):
        assert schemas[name]["$defs"]["objectKind"]["enum"] == runtime_kinds
    for name, value in (
        ("verifier-dangerous-pathway-request-1.schema.json", req),
        ("verifier-dangerous-pathway-certificate-1.schema.json", cert),
        ("claim-garden-dangerous-pathway-assessment-1.schema.json", assessment),
        ("claim-garden-dangerous-pathway-assessment-2.schema.json", assessment_v2),
    ):
        jsonschema.Draft202012Validator(schemas[name], registry=registry).validate(value)

    invalid_kind = deepcopy(assessment_v2)
    invalid_kind["object_kind"] = "NOT_A_RUNTIME_OBJECT_KIND"
    v2_schema = schemas["claim-garden-dangerous-pathway-assessment-2.schema.json"]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(v2_schema, registry=registry).validate(invalid_kind)
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="object kind is not admitted"):
        security.recheck_dangerous_pathway_assessment_v2(canonical_bytes(invalid_kind))

    invalid_v1 = deepcopy(assessment)
    invalid_v1["object_kind"] = "NOT_A_RUNTIME_OBJECT_KIND"
    invalid_v1["assessment_digest"] = security._digest_without(
        invalid_v1, "assessment_digest")
    v1_schema = schemas["claim-garden-dangerous-pathway-assessment-1.schema.json"]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(v1_schema, registry=registry).validate(invalid_v1)
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="object kind is not admitted"):
        security.recheck_dangerous_pathway_assessment(canonical_bytes(invalid_v1))

    invalid_certificate = deepcopy(cert)
    invalid_certificate["object_kind"] = "NOT_A_RUNTIME_OBJECT_KIND"
    invalid_certificate["request"]["object_kind"] = "NOT_A_RUNTIME_OBJECT_KIND"
    invalid_certificate["request"]["request_digest"] = security._digest_without(
        invalid_certificate["request"], "request_digest")
    invalid_certificate["request_digest"] = invalid_certificate["request"][
        "request_digest"]
    invalid_certificate["certificate_digest"] = security._digest_without(
        invalid_certificate, "certificate_digest")
    certificate_schema = schemas["verifier-dangerous-pathway-certificate-1.schema.json"]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(
            certificate_schema, registry=registry).validate(invalid_certificate)
    with pytest.raises(security.DangerousPathwaySecurityError,
                       match="object kind is not admitted"):
        security.recheck_dangerous_pathway_certificate(
            canonical_bytes(invalid_certificate),
            request_bytes=canonical_bytes(invalid_certificate["request"]))


def test_source_contains_no_dynamic_dispatch_or_transport_surface() -> None:
    text = Path(security.__file__).read_text(encoding="utf-8")
    for forbidden in ("subprocess", "importlib", "urllib", "requests", "os.system", "eval(", "exec("):
        assert forbidden not in text
