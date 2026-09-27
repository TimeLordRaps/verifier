"""Refutable retained checks for HUMAN and IDENTITY accountability routes.

Verifier Standard (VSTD) checks here do not authenticate personhood or authority.
"""
from copy import deepcopy

import pytest

from verifier.domains import human, identity
from verifier.domains.common import Budget, Refuted, Unavailable, digest


def human_specimen():
    records = [{"id": "capture-1", "class": "in-person", "capture_pipeline": "desk-1",
                "witness_id": "witness-1", "record_digest": digest("retained-capture-1")}]
    events = [{"position": 0, "event": "enrollment", "at": 10,
               "evidence_id": "capture-1", "instrument": "desk-1"}]
    artifact = {"subject_ref": "pseudonym-1", "evidence_class": "in-person",
                "capture_pipeline": "desk-1", "liveness_claim": True,
                "uniqueness_claim": False, "enrollment_population": "cohort-1",
                "deduplication_mechanism": "manual-review", "unasserted_attributes":
                ["name", "nationality", "civil_identity"], "evidence_digest": digest(records),
                "events_digest": digest(events), "validity": {"start": 10, "end": 20}}
    return artifact, {"evidence_records": records, "events": events}


def identity_specimen():
    bearer = {"schema_version": "verifier-domain-certification-1",
              "evidence": {"domain": "BOT", "subject_id": "bot-1"}}
    role = {"schema_version": "verifier-domain-certification-1",
            "evidence": {"domain": "ROLE", "subject_id": "seat-1",
                         "artifact": {"role_class_id": "role:reviewer"}}}
    occupancy = {"bearer_subject_id": "bot-1", "role_subject_id": "seat-1",
                 "role_coordinate": "ROLE-1.1", "evidence_ref": digest("retained-occupancy")}
    events = [{"position": 0, "event": "enrollment", "at": 10,
               "bearer_subject_id": "bot-1"},
              {"position": 1, "event": "presentation", "at": 11,
               "bearer_subject_id": "bot-1"}]
    artifact = {"bearer_class": "BOT", "bearer_subject_id": "bot-1",
                "bearer_certificate_digest": digest(bearer), "role_subject_id": "seat-1",
                "role_class_id": "role:reviewer",
                "role_coordinate": "ROLE-1.1", "role_certificate_digest": digest(role),
                "occupancy_digest": digest(occupancy), "assurance_level": "declared",
                "inherited_scope": "simulation:sim-1", "validity": {"start": 10, "end": 20},
                "revocation_surface": "issuer-1", "disclosure": "held",
                "events_digest": digest(events), "simulation_id": "sim-1"}
    return artifact, {"bearer_certificate": bearer, "role_certificate": role,
                      "occupancy_evidence": occupancy, "events": events}


def test_human_retained_assertion_does_not_certify_personhood():
    artifact, inputs = human_specimen()
    result = human.evaluate("assertion", artifact, inputs, Budget(1000))
    assert result["personhood"] == "NOT_ESTABLISHED"
    assert result["witness_independence"] == "NOT_ESTABLISHED"
    with pytest.raises(Unavailable):
        human.evaluate("closure", artifact, inputs, Budget(1000))


@pytest.mark.parametrize("mutation", ["global", "forged-record", "self-witness", "identifier", "malformed-hash"])
def test_human_assertion_refutes_unsupported_declarations(mutation):
    artifact, inputs = human_specimen()
    if mutation == "global": artifact["enrollment_population"] = "global"
    if mutation == "forged-record": inputs["evidence_records"][0]["id"] = "other"
    if mutation == "self-witness": inputs["evidence_records"][0]["witness_id"] = artifact["subject_ref"]
    if mutation == "identifier": artifact["unasserted_attributes"].remove("name")
    if mutation == "malformed-hash": inputs["evidence_records"][0]["record_digest"] = "sha256:fake"
    if mutation in {"self-witness", "malformed-hash"}:
        artifact["evidence_digest"] = digest(inputs["evidence_records"])
    with pytest.raises(Refuted):
        human.evaluate("assertion", artifact, inputs, Budget(1000))


def test_human_lifecycle_replays_and_death_ends_assertion():
    artifact, inputs = human_specimen()
    state = human.evaluate("lifecycle", artifact, inputs, Budget(1000))
    assert state["declared_state"] == "DECLARED_ACTIVE"
    assert "current_state" not in state
    inputs["events"].append({"position": 1, "event": "death", "at": 12,
                              "evidence_id": "capture-1", "instrument": "desk-1"})
    artifact["events_digest"] = digest(inputs["events"])
    with pytest.raises(Unavailable):
        human.evaluate("lifecycle", artifact, inputs, Budget(1000))


def test_human_post_expiry_event_cannot_pass_lifecycle():
    artifact, inputs = human_specimen()
    inputs["events"].append({"position": 1, "event": "reverification", "at": 20,
                              "evidence_id": "capture-1", "instrument": "desk-1"})
    artifact["events_digest"] = digest(inputs["events"])
    with pytest.raises(Unavailable, match="validity"):
        human.evaluate("lifecycle", artifact, inputs, Budget(1000))


def test_identity_retained_occupancy_rejects_bare_agent_and_substitution():
    artifact, inputs = identity_specimen()
    result = identity.evaluate("occupancy", artifact, inputs, Budget(1000))
    assert result["bearer_authenticity"] == "NOT_ESTABLISHED"
    assert result["role_authority"] == "NOT_ESTABLISHED"
    bad = deepcopy(artifact)
    bad["bearer_class"] = "AGENT"
    with pytest.raises(Refuted):
        identity.evaluate("occupancy", bad, inputs, Budget(1000))
    inputs["occupancy_evidence"]["role_subject_id"] = "other-seat"
    artifact["occupancy_digest"] = digest(inputs["occupancy_evidence"])
    with pytest.raises(Refuted):
        identity.evaluate("occupancy", artifact, inputs, Budget(1000))
    inputs["occupancy_evidence"]["role_subject_id"] = "seat-1"
    inputs["occupancy_evidence"]["evidence_ref"] = "sha256:fake"
    artifact["occupancy_digest"] = digest(inputs["occupancy_evidence"])
    with pytest.raises(Refuted):
        identity.evaluate("occupancy", artifact, inputs, Budget(1000))


def test_identity_lifecycle_rejects_post_revocation_presentation():
    artifact, inputs = identity_specimen()
    assert identity.evaluate("lifecycle", artifact, inputs, Budget(1000))["presentations"] == 1
    inputs["events"].insert(1, {"position": 1, "event": "revocation", "at": 11,
                                "bearer_subject_id": "bot-1"})
    inputs["events"][2]["position"] = 2
    artifact["events_digest"] = digest(inputs["events"])
    with pytest.raises(Refuted):
        identity.evaluate("lifecycle", artifact, inputs, Budget(1000))


def test_identity_support_does_not_accept_unreplayed_certificates():
    artifact, inputs = identity_specimen()
    with pytest.raises(Unavailable):
        identity.evaluate("support", artifact, inputs, Budget(1000))


def test_identity_rejects_unsupported_assurance_and_role_class_substitution():
    artifact, inputs = identity_specimen()
    artifact["assurance_level"] = "independent-personhood"
    with pytest.raises(Unavailable, match="assurance"):
        identity.evaluate("occupancy", artifact, inputs, Budget(1000))
    artifact["assurance_level"] = "declared"
    artifact["role_class_id"] = "role:other"
    with pytest.raises(Refuted, match="role class"):
        identity.evaluate("occupancy", artifact, inputs, Budget(1000))


def test_human_bearer_stays_unknown_even_with_purported_checker_policy():
    artifact, inputs = identity_specimen()
    artifact["bearer_class"] = "HUMAN"
    artifact["bearer_subject_id"] = "person-1"
    artifact["inherited_scope"] = "human:person-1"
    del artifact["simulation_id"]
    inputs["bearer_certificate"]["evidence"]["domain"] = "HUMAN"
    inputs["bearer_certificate"]["evidence"]["subject_id"] = "person-1"
    inputs["occupancy_evidence"]["bearer_subject_id"] = "person-1"
    artifact["bearer_certificate_digest"] = digest(inputs["bearer_certificate"])
    artifact["occupancy_digest"] = digest(inputs["occupancy_evidence"])
    with pytest.raises(Unavailable, match="living bearer authenticity"):
        identity.evaluate("support", artifact, inputs, Budget(1000),
                          mechanism_digest="purported-checker", policy={})
