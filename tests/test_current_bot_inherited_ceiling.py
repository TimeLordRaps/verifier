"""Current BOT-3.1 inherited observation ceiling over exact retained records.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Observation ceilings and counts are
dimensionless. These fixtures execute no bot, agent or harness; oracles walk
the BOT -> AGENT -> HARNESS operand bindings directly.
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
from verifier.domains.contracts import bot_inherited_ceiling as contract
from verifier.domains.inventory import get_slot

SRC = Path(contract.__file__).parents[2]
SPEC = SRC / "standard" / "CURRENT_BOT_INHERITED_CEILING.md"
ROW_PREFIX = "| BOT-3.1 |"
CEILING = 3
LOW_CEILING = 1
_ABSENT = object()


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def harness_payload(ceiling: object) -> dict:
    return {"fixture": "harness", "observation_ceiling": {
        "ceiling": ceiling, "observed": ["chat", "effects", "tool_io"]}}


def agent_payload(declared: object = _ABSENT) -> dict:
    payload: dict = {"fixture": "agent"}
    if declared is not _ABSENT:
        payload["declared_ceiling"] = declared
    return payload


def collection(*, claimed: object = None, declared: object = _ABSENT,
               harness: dict | None = None, decoy: dict | None = None,
               bound_agents: tuple[str, ...] = ("agent",)) -> list[NamespaceObject]:
    make = NamespaceObject.create
    names = ["arch", "data", "env", "hardware", "object", "space", "time", "verifier"]
    objects = [make(name, name.upper(), {"fixture": name}) for name in names]
    objects += [
        make("harness", "HARNESS", harness_payload(CEILING) if harness is None else harness),
        make("harness-low", "HARNESS", harness_payload(LOW_CEILING)),
        make("event", "EVENT", {"fixture": "event"},
             {"time": ["time"], "space": ["space"], "meaning": ["object"]}),
        make("bench", "BENCH", {"fixture": "bench"}, {"verifier": ["verifier"], "data": ["data"]}),
        make("train", "TRAIN", {"fixture": "train"},
             {"data": ["data"], "events": ["event"], "bench": ["bench"], "arch": ["arch"]}),
        make("model", "MODEL", {"fixture": "model"},
             {"train": ["train"], "data": ["data"], "events": ["event"], "bench": ["bench"],
              "arch": ["arch"], "env": ["env"], "hardware": ["hardware"]}),
        make("agent", "AGENT", agent_payload(declared),
             {"model": ["model"], "harness": ["harness"], "env": ["env"]}),
        make("agent-low", "AGENT", agent_payload(),
             {"model": ["model"], "harness": ["harness-low"], "env": ["env"]}),
        make("sim", "SIM", {"fixture": "sim"},
             {"data": ["data"], "verifier": ["verifier"], "objects": ["object"], "env": ["env"]}),
        make("bot", "BOT", {"scope": "retained-bot-inherited-ceiling", "claimed_ceiling": claimed},
             {"agent": list(bound_agents), "sim": ["sim"], "env": ["env"]}),
    ]
    if decoy is not None:
        objects.append(make("decoy-harness", "HARNESS", decoy))
    return objects


def selected(objects: list[NamespaceObject] | None = None, *, subject: str = "bot",
             include_evidence: bool = True, trust_roots: list[str] | None = None,
             **limits: int):
    objects = collection() if objects is None else objects
    chosen = next(item for item in objects if item.object_id == subject)
    evidence = canonical_bytes({
        "schema_version": contract.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in sorted(objects, key=lambda item: item.object_id)],
    })
    policy = contract.bot_inherited_ceiling_policy(trust_roots=trust_roots or ["bot-statics-root"])
    request = contract.bot_inherited_ceiling_request(
        subject_id=chosen.object_id, object_digest=chosen.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=digest(json.loads(evidence)), policy=policy, limits=limits or None)
    return request, policy, (evidence if include_evidence else None)


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = contract.build_bot_inherited_ceiling_certificate(request, evidence, policy=policy)
    result = contract.recheck_bot_inherited_ceiling_certificate(
        certificate, expected_request=request, policy=policy)
    return certificate, result


def oracle(objects: list[NamespaceObject]) -> tuple[str, int, int]:
    """Independent reading: follow two operand edges, then compare every present claim."""
    rows = {item.object_id: item.to_dict() for item in objects}
    bot = rows["bot"]
    agent = rows[bot["operands"]["agent"][0]]
    harness = rows[agent["operands"]["harness"][0]]
    ceiling = harness["payload"]["observation_ceiling"]["ceiling"]
    claims = [value for value in (bot["payload"]["claimed_ceiling"],
                                  agent["payload"].get("declared_ceiling")) if value is not None]
    verdict = "PASS" if all(claim <= ceiling for claim in claims) else "FAIL"
    return verdict, ceiling, len(claims)


def test_inventory_selects_bot_inherited_ceiling_and_spec_quotes_row() -> None:
    slot = get_slot("BOT", 3)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.coordinate == "BOT-3.1" == contract.COORDINATE
    route = slot.mechanized_route
    assert route["checking_mechanism"] == (
        "verifier.domains.contracts.bot_inherited_ceiling.recheck_bot_inherited_ceiling_certificate")
    assert route["artifact_coordinate"] == "BOT-3.1"
    assert route["exact_claim"] == contract.registration()["proposition"]
    rows = (SRC / "standard" / "DOMAIN_OBLIGATIONS.md").read_text(encoding="utf-8").splitlines()
    row = next(line for line in rows if line.startswith(ROW_PREFIX))
    spec = SPEC.read_text(encoding="utf-8")
    assert row in spec.splitlines()
    proposition = spec.split("## Proposition", 1)[1].split("\n## ", 1)[0]
    assert " ".join(proposition.split()) == contract.registration()["proposition"]


@pytest.mark.parametrize("name, objects", [
    ("neither-bot-nor-agent-claims-a-ceiling", lambda: collection()),
    ("bot-claims-a-lower-ceiling", lambda: collection(claimed=LOW_CEILING)),
    ("both-claim-and-agent-claims-lower", lambda: collection(claimed=CEILING, declared=CEILING - 1)),
])
def test_inherited_ceiling_holds_whatever_is_claimed(name, objects) -> None:
    selected_objects = objects()
    expected, ceiling, claims = oracle(selected_objects)
    assert expected == "PASS", name
    request, policy, evidence = selected(selected_objects)
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS", (name, result["evaluation"]["details"])
    assert result["inherited_ceiling"] == "PASS"
    assert result["evaluation"]["observations"] == {
        "agent_id": "agent", "harness_id": "harness",
        "inherited_ceiling": ceiling, "claims_checked": claims}
    for field in ("whole_bot_statics_tier", "object_profile_conformance", "coupling_latency",
                  "disclosure_limit", "policy_impotence", "harness_enforcement",
                  "authority", "safety"):
        assert result[field] == "NOT_ESTABLISHED"
    decoded = json.loads(certificate.decode("utf-8"))
    assert contract.recheck_bot_inherited_ceiling_certificate(
        canonical_bytes(decoded), expected_request=request, policy=policy) == result
    assert certificate == contract.build_bot_inherited_ceiling_certificate(
        request, evidence, policy=policy)


@pytest.mark.parametrize("name, objects", [
    ("agent-claims-above-its-harness", lambda: collection(declared=CEILING + 2)),
    ("bot-claims-above-the-inherited-ceiling", lambda: collection(claimed=CEILING + 1)),
    ("bot-rebound-to-an-agent-whose-harness-is-lower",
     lambda: collection(claimed=CEILING, bound_agents=("agent-low",))),
    ("unbound-harness-would-admit-the-claim",
     lambda: collection(claimed=9, decoy=harness_payload(9))),
])
def test_claim_above_the_inherited_ceiling_is_refuted(name, objects) -> None:
    selected_objects = objects()
    assert oracle(selected_objects)[0] == "FAIL", name
    request, policy, evidence = selected(selected_objects)
    _, result = replay(request, policy, evidence)
    assert result["status"] == "FAIL", (name, result["evaluation"]["details"])
    assert result["inherited_ceiling"] == "NOT_ESTABLISHED"
    assert "inherited_ceiling" not in result["evaluation"]["observations"]


def test_rebinding_moves_the_reported_ceiling_and_decoys_do_not() -> None:
    low = collection(bound_agents=("agent-low",))
    request, policy, evidence = selected(low)
    _, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    assert result["evaluation"]["observations"]["inherited_ceiling"] == oracle(low)[1] == LOW_CEILING
    for decoy_ceiling in (0, 99):
        objects = collection(decoy=harness_payload(decoy_ceiling))
        request, policy, evidence = selected(objects)
        assert replay(request, policy, evidence)[1]["evaluation"]["observations"][
            "inherited_ceiling"] == CEILING


@pytest.mark.parametrize("case", ["budget", "missing-evidence", "harness-states-no-ceiling",
                                  "agent-operand-binds-two-agents"])
def test_exhausted_or_ambiguous_inputs_remain_unknown(case: str) -> None:
    if case == "budget":
        request, policy, evidence = selected(max_operations=8)
    elif case == "missing-evidence":
        request, policy, evidence = selected(include_evidence=False)
    elif case == "harness-states-no-ceiling":
        request, policy, evidence = selected(collection(harness={"fixture": "harness"}))
    else:
        request, policy, evidence = selected(collection(bound_agents=("agent", "agent-low")))
    _, result = replay(request, policy, evidence)
    assert result["status"] == "UNKNOWN", result["evaluation"]["details"]
    assert result["inherited_ceiling"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("position", [0, 0.5, -2])
def test_one_flipped_certificate_bit_is_refused(position: float) -> None:
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    index = int(len(certificate) * position) if type(position) is float else position % len(certificate)
    tampered = bytearray(certificate)
    tampered[index] ^= 0x01
    with pytest.raises(contract.BotInheritedCeilingError):
        contract.recheck_bot_inherited_ceiling_certificate(
            bytes(tampered), expected_request=request, policy=policy)


def test_substituted_subject_request_policy_or_verdict_is_refused() -> None:
    objects = collection()
    request, policy, evidence = selected(objects)
    certificate, _ = replay(request, policy, evidence)
    agent = next(item for item in objects if item.object_id == "agent")
    other = deepcopy(request)
    other["subject_id"], other["object_digest"] = "agent", agent.digest
    with pytest.raises(contract.BotInheritedCeilingError):
        contract.recheck_bot_inherited_ceiling_certificate(
            certificate, expected_request=other, policy=policy)
    other_policy = contract.bot_inherited_ceiling_policy(trust_roots=["another-root"])
    with pytest.raises(contract.BotInheritedCeilingError):
        contract.recheck_bot_inherited_ceiling_certificate(
            certificate, expected_request=request, policy=other_policy)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(contract.BotInheritedCeilingError):
        contract.recheck_bot_inherited_ceiling_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)
    assert replay(*selected(objects, subject="agent"))[1]["status"] == "FAIL"
    malformed = deepcopy(request)
    malformed["object_kind"] = "AGENT"
    with pytest.raises(contract.BotInheritedCeilingError):
        contract.build_bot_inherited_ceiling_certificate(malformed, evidence, policy=policy)


def test_public_route_and_command_replay_the_selected_objective(tmp_path: Path, capsys) -> None:
    from verifier.runtime.public_cli import main
    from verifier.runtime.polish import assess_polish

    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=contract.SEMANTIC_VERSION,
        objective=contract.COORDINATE, represented_kind="BOT",
        expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["inherited_ceiling"] == "PASS"
    for name, contents in (("request", canonical_bytes(request)),
                           ("policy", canonical_bytes(policy)), ("certificate", certificate)):
        (tmp_path / (name + ".json")).write_bytes(contents)
    code = main(["current-object", "check", str(tmp_path / "certificate.json"),
                 "--semantic-version", contract.SEMANTIC_VERSION,
                 "--objective", contract.COORDINATE, "--represented-kind", "BOT",
                 "--request", str(tmp_path / "request.json"),
                 "--policy", str(tmp_path / "policy.json"), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"
    certificate_digest = digest(json.loads(certificate))
    bundle = {"schema_version": "verifier-polish-bundle-1",
              "objects": json.loads(evidence)["objects"],
              "certificates": {certificate_digest: certificate.decode()}}
    polish_request = {"schema_version": "verifier-polish-request-1", "root_id": "bot",
                      "collection_digest": request["collection_digest"],
                      "bundle_digest": digest(bundle),
                      "requirements": [{"object_id": "bot", "tier": tier,
                                        "applicability": "REQUIRED",
                                        "rationale": "Selected inherited ceiling only",
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
    surface = DisclosureSurface("BOT", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",)) for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"), "test-time")
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(retained, surface, bounds, context)


@pytest.mark.parametrize("relative", ["domains/contracts/bot_inherited_ceiling.py",
                                      "standard/CURRENT_BOT_INHERITED_CEILING.md"])
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
    "domains/contracts/bot_inherited_ceiling.py", "domains/statics.py", "domains/common.py",
    "domains/contracts/retained_selection.py", "core/namespace.py",
    "standard/CURRENT_BOT_INHERITED_CEILING.md", "standard/NAMESPACE_OBJECTS.md",
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
        contract.recheck_bot_inherited_ceiling_certificate(
            certificate, expected_request=request, policy=policy)
