"""Current AGENT-3.1 ceiling fixity over exact retained namespace records.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Observation ceilings and counts are
dimensionless. These fixtures execute no agent, model or harness; oracles read
the bound HARNESS record directly instead of calling the mechanism.
"""
from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import agent_ceiling_fixity as contract
from verifier.domains.inventory import get_slot

SRC = Path(contract.__file__).parents[2]
SPEC = SRC / "standard" / "CURRENT_AGENT_CEILING_FIXITY.md"
ROW_PREFIX = "| AGENT-3.1 |"
CEILING = 3


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def harness_payload(ceiling: object = CEILING) -> dict:
    return {"fixture": "harness", "observation_ceiling": {
        "ceiling": ceiling, "observed": ["chat", "effects", "tool_io"]}}


def collection(*, declared: object = CEILING, harness: dict | None = None,
               decoy: dict | None = None, bound: str = "harness") -> list[NamespaceObject]:
    make = NamespaceObject.create
    names = ["arch", "data", "env", "hardware", "object", "space", "time", "verifier"]
    objects = [make(name, name.upper(), {"fixture": name}) for name in names]
    objects.append(make("harness", "HARNESS", harness_payload() if harness is None else harness))
    if decoy is not None:
        objects.append(make("decoy-harness", "HARNESS", decoy))
    objects += [
        make("event", "EVENT", {"fixture": "event"},
             {"time": ["time"], "space": ["space"], "meaning": ["object"]}),
        make("bench", "BENCH", {"fixture": "bench"}, {"verifier": ["verifier"], "data": ["data"]}),
        make("train", "TRAIN", {"fixture": "train"},
             {"data": ["data"], "events": ["event"], "bench": ["bench"], "arch": ["arch"]}),
        make("model", "MODEL", {"fixture": "model"},
             {"train": ["train"], "data": ["data"], "events": ["event"], "bench": ["bench"],
              "arch": ["arch"], "env": ["env"], "hardware": ["hardware"]}),
        make("agent", "AGENT", {"scope": "retained-agent-ceiling-fixity",
                                "declared_ceiling": declared},
             {"model": ["model"], "harness": [bound], "env": ["env"]}),
    ]
    return objects


def selected(objects: list[NamespaceObject] | None = None, *, subject: str = "agent",
             include_evidence: bool = True, trust_roots: list[str] | None = None,
             **limits: int):
    objects = collection() if objects is None else objects
    chosen = next(item for item in objects if item.object_id == subject)
    evidence = canonical_bytes({
        "schema_version": contract.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in sorted(objects, key=lambda item: item.object_id)],
    })
    policy = contract.agent_ceiling_fixity_policy(trust_roots=trust_roots or ["agent-statics-root"])
    request = contract.agent_ceiling_fixity_request(
        subject_id=chosen.object_id, object_digest=chosen.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=digest(json.loads(evidence)), policy=policy, limits=limits or None)
    return request, policy, (evidence if include_evidence else None)


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = contract.build_agent_ceiling_fixity_certificate(request, evidence, policy=policy)
    result = contract.recheck_agent_ceiling_fixity_certificate(
        certificate, expected_request=request, policy=policy)
    return certificate, result


def oracle(objects: list[NamespaceObject]) -> tuple[str, int]:
    """Independent reading: follow the AGENT's harness operand, compare integers."""
    rows = {item.object_id: item.to_dict() for item in objects}
    bound = rows["agent"]["operands"]["harness"][0]
    ceiling = rows[bound]["payload"]["observation_ceiling"]["ceiling"]
    declared = rows["agent"]["payload"]["declared_ceiling"]
    return ("PASS" if declared == ceiling else "FAIL"), ceiling


def test_inventory_selects_agent_ceiling_fixity_and_spec_quotes_row() -> None:
    slot = get_slot("AGENT", 3)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.coordinate == "AGENT-3.1" == contract.COORDINATE
    route = slot.mechanized_route
    assert route["checking_mechanism"] == (
        "verifier.domains.contracts.agent_ceiling_fixity.recheck_agent_ceiling_fixity_certificate")
    assert route["artifact_coordinate"] == "AGENT-3.1"
    assert route["exact_claim"] == contract.registration()["proposition"]
    rows = (SRC / "standard" / "DOMAIN_OBLIGATIONS.md").read_text(encoding="utf-8").splitlines()
    row = next(line for line in rows if line.startswith(ROW_PREFIX))
    spec = SPEC.read_text(encoding="utf-8")
    assert row in spec.splitlines()
    proposition = spec.split("## Proposition", 1)[1].split("\n## ", 1)[0]
    assert " ".join(proposition.split()) == contract.registration()["proposition"]


def test_bound_harness_ceiling_passes_and_rechecks_from_decoded_bytes() -> None:
    objects = collection()
    request, policy, evidence = selected(objects)
    certificate, result = replay(request, policy, evidence)
    expected, ceiling = oracle(objects)
    assert expected == "PASS"
    assert result["status"] == "PASS"
    assert result["ceiling_fixity"] == "PASS"
    observations = result["evaluation"]["observations"]
    assert observations == {"harness_id": "harness", "harness_ceiling": ceiling}
    for field in ("whole_agent_statics_tier", "object_profile_conformance", "unknowability",
                  "declaration_impotence", "harness_enforcement", "authority", "safety"):
        assert result[field] == "NOT_ESTABLISHED"
    decoded = json.loads(certificate.decode("utf-8"))
    assert canonical_bytes(decoded) == certificate
    again = contract.recheck_agent_ceiling_fixity_certificate(
        canonical_bytes(decoded), expected_request=request, policy=policy)
    assert again == result
    assert certificate == contract.build_agent_ceiling_fixity_certificate(
        request, evidence, policy=policy)


@pytest.mark.parametrize("name, objects", [
    ("agent-declares-higher-than-bound-harness", lambda: collection(declared=CEILING + 1)),
    ("agent-declares-lower-than-bound-harness", lambda: collection(declared=CEILING - 1)),
    ("unbound-harness-matches-agent-declaration",
     lambda: collection(declared=7, decoy=harness_payload(7))),
    ("agent-rebound-to-a-harness-with-a-lower-ceiling",
     lambda: collection(decoy=harness_payload(CEILING - 2), bound="decoy-harness")),
])
def test_ceiling_not_fixed_by_the_bound_harness_is_refuted(name, objects) -> None:
    selected_objects = objects()
    expected, ceiling = oracle(selected_objects)
    assert expected == "FAIL", name
    request, policy, evidence = selected(selected_objects)
    _, result = replay(request, policy, evidence)
    assert result["status"] == "FAIL", (name, result["evaluation"]["details"])
    assert result["ceiling_fixity"] == "NOT_ESTABLISHED"
    assert "harness_ceiling" not in result["evaluation"]["observations"]


def test_unbound_harness_ceiling_does_not_move_the_verdict() -> None:
    for decoy_ceiling in (0, CEILING, 99):
        objects = collection(decoy=harness_payload(decoy_ceiling))
        request, policy, evidence = selected(objects)
        _, result = replay(request, policy, evidence)
        assert result["status"] == oracle(objects)[0] == "PASS"
        assert result["evaluation"]["observations"]["harness_ceiling"] == CEILING


@pytest.mark.parametrize("case", ["budget", "absent-declaration", "harness-states-no-ceiling",
                                  "missing-evidence"])
def test_exhausted_or_absent_inputs_remain_unknown(case: str) -> None:
    if case == "budget":
        request, policy, evidence = selected(max_operations=8)
    elif case == "absent-declaration":
        request, policy, evidence = selected(collection(declared=None))
    elif case == "harness-states-no-ceiling":
        request, policy, evidence = selected(collection(harness={"fixture": "harness"}))
    else:
        request, policy, evidence = selected(include_evidence=False)
    _, result = replay(request, policy, evidence)
    assert result["status"] == "UNKNOWN"
    assert result["ceiling_fixity"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("position", [0, 0.5, -2])
def test_one_flipped_certificate_bit_is_refused(position: float) -> None:
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    index = int(len(certificate) * position) if type(position) is float else position % len(certificate)
    tampered = bytearray(certificate)
    tampered[index] ^= 0x01
    with pytest.raises(contract.AgentCeilingFixityError):
        contract.recheck_agent_ceiling_fixity_certificate(
            bytes(tampered), expected_request=request, policy=policy)


def test_substituted_subject_request_policy_or_verdict_is_refused() -> None:
    objects = collection()
    request, policy, evidence = selected(objects)
    certificate, _ = replay(request, policy, evidence)
    harness = next(item for item in objects if item.object_id == "harness")
    other = deepcopy(request)
    other["subject_id"], other["object_digest"] = "harness", harness.digest
    with pytest.raises(contract.AgentCeilingFixityError):
        contract.recheck_agent_ceiling_fixity_certificate(
            certificate, expected_request=other, policy=policy)
    other_policy = contract.agent_ceiling_fixity_policy(trust_roots=["another-root"])
    with pytest.raises(contract.AgentCeilingFixityError):
        contract.recheck_agent_ceiling_fixity_certificate(
            certificate, expected_request=request, policy=other_policy)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(contract.AgentCeilingFixityError):
        contract.recheck_agent_ceiling_fixity_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)
    wrong_kind = selected(objects, subject="harness")
    assert replay(*wrong_kind)[1]["status"] == "FAIL"
    malformed = deepcopy(request)
    malformed["coordinate"] = "AGENT-3.2"
    with pytest.raises(contract.AgentCeilingFixityError):
        contract.build_agent_ceiling_fixity_certificate(malformed, evidence, policy=policy)


def test_public_route_and_command_replay_the_selected_objective(tmp_path: Path, capsys) -> None:
    from verifier.runtime.public_cli import main
    from verifier.runtime.polish import assess_polish

    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=contract.SEMANTIC_VERSION,
        objective=contract.COORDINATE, represented_kind="AGENT",
        expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["ceiling_fixity"] == "PASS"
    for name, contents in (("request", canonical_bytes(request)),
                           ("policy", canonical_bytes(policy)), ("certificate", certificate)):
        (tmp_path / (name + ".json")).write_bytes(contents)
    code = main(["current-object", "check", str(tmp_path / "certificate.json"),
                 "--semantic-version", contract.SEMANTIC_VERSION,
                 "--objective", contract.COORDINATE, "--represented-kind", "AGENT",
                 "--request", str(tmp_path / "request.json"),
                 "--policy", str(tmp_path / "policy.json"), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"
    certificate_digest = digest(json.loads(certificate))
    bundle = {"schema_version": "verifier-polish-bundle-1",
              "objects": json.loads(evidence)["objects"],
              "certificates": {certificate_digest: certificate.decode()}}
    polish_request = {"schema_version": "verifier-polish-request-1", "root_id": "agent",
                      "collection_digest": request["collection_digest"],
                      "bundle_digest": digest(bundle),
                      "requirements": [{"object_id": "agent", "tier": tier,
                                        "applicability": "REQUIRED",
                                        "rationale": "Selected ceiling fixity only",
                                        "objectives": []} for tier in range(1, 10)]}
    polish_request["requirements"][2]["objectives"] = [{
        "semantic_version": contract.SEMANTIC_VERSION, "coordinate": contract.COORDINATE,
        "request": request, "policy": policy, "certificate_digest": certificate_digest}]
    polished = assess_polish(canonical_bytes(bundle), request_bytes=canonical_bytes(polish_request))
    assert polished["objectives"][0]["status"] == "PASS", polished["objectives"][0]
    assert polished["status"] == "UNKNOWN" and polished["polished"] is False


def test_retained_certificate_refuses_evidence_redaction() -> None:
    from verifier.privacy import (DisclosureBound, DisclosureSurface, EmissionContext,
                                  EmissionEvaluator, EmissionRefusalError, ObserverParty)

    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    retained = json.loads(certificate)
    fields = tuple(key for key in retained if key != "evidence_payloads")
    surface = DisclosureSurface("AGENT", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",)) for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"), "test-time")
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(retained, surface, bounds, context)


@pytest.mark.parametrize("relative", ["domains/contracts/agent_ceiling_fixity.py",
                                      "standard/CURRENT_AGENT_CEILING_FIXITY.md"])
def test_mechanism_sources_invalidate_polish(relative: str, monkeypatch) -> None:
    from verifier.runtime import polish

    target = Path(polish.__file__).parents[1] / relative
    before = polish.mechanism_digest()
    original = Path.read_bytes

    def changed(path):
        data = original(path)
        return data + b"\nchanged statics dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    assert polish.mechanism_digest() != before


@pytest.mark.parametrize("relative", [
    "domains/contracts/agent_ceiling_fixity.py", "domains/statics.py", "domains/common.py",
    "domains/contracts/retained_selection.py", "core/namespace.py",
    "standard/CURRENT_AGENT_CEILING_FIXITY.md", "standard/NAMESPACE_OBJECTS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative: str, monkeypatch) -> None:
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    target = SRC / relative
    original = Path.read_bytes

    def changed(path):
        data = original(path)
        return data + b"\nchanged selected dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        contract.recheck_agent_ceiling_fixity_certificate(
            certificate, expected_request=request, policy=policy)
