"""Independent current BOT retained coupling contract tests.

Verifier Standard (VSTD); JavaScript Object Notation (JSON). BOT is the situated
agent object name, not an acronym. These finite specimens do not execute agents.
"""
from __future__ import annotations

from copy import deepcopy
from functools import lru_cache
import importlib.util
import json
from pathlib import Path
from typing import Any

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.certification import build_domain_certificate, domain_policy, domain_request
from verifier.domains.common import digest
from verifier.domains.contracts import bot_checks as bot_checks_contract
from verifier.domains.contracts import current_object_routes as routes
from test_current_typed_facets import collection as typed_collection

SEMANTIC = "verifier-current-object-obligations-1"
CHECKS = {"binding": "BOT-1.6", "alignment": "BOT-2.1", "observation": "BOT-2.2",
          "actuation": "BOT-2.3", "containment": "BOT-4.1"}


@lru_cache(maxsize=1)
def original_bundle() -> dict:
    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("current_bot_example", root / "examples/domain_grounding.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.specimens()["BOT"]


def certify(evidence: dict, depth: int) -> dict:
    return build_domain_certificate(domain_request(evidence, target_depth=depth), evidence,
        policy=domain_policy(trust_roots=["test:historical-retained-bot"]))


def specimen() -> tuple[dict, dict]:
    bundle = deepcopy(original_bundle())
    retained = bundle["inputs"]
    agent = retained["agent_certificate"]["evidence"]
    harness = agent["inputs"]["harness_certificate"]["evidence"]
    harness["subject_id"] = "harness"
    child = certify(harness, 5)
    agent["inputs"]["harness_certificate"] = child
    agent["artifact"]["harness_subject_id"] = "harness"
    agent["artifact"]["harness_certificate_digest"] = digest(child)
    for name, subject, depth in (("agent", "agent", 5), ("sim", "sim", 4),
            ("agent_environment", "env-agent", 2), ("sim_environment", "env-sim", 2)):
        evidence = retained[name + "_certificate"]["evidence"]
        evidence["subject_id"] = subject
        child = certify(evidence, depth)
        assert child["result"]["status"] == "PASS"
        retained[name + "_certificate"] = child
        bundle["artifact"][name + "_certificate_digest"] = digest(child)
    return bundle["artifact"], retained


def collection(artifact: dict, retained: dict) -> list[NamespaceObject]:
    agent = retained["agent_certificate"]["evidence"]
    harness = agent["inputs"]["harness_certificate"]["evidence"]
    payloads = {"BOT": artifact, "AGENT": agent["artifact"], "HARNESS": harness["artifact"],
                "SIM": retained["sim_certificate"]["evidence"]["artifact"]}
    objects = []
    for item in typed_collection():
        operands = dict(item.operands)
        if item.kind.value in ("AGENT", "SIM"):
            operands["env"] = ["env-agent" if item.kind.value == "AGENT" else "env-sim"]
        objects.append(NamespaceObject.create(item.object_id, item.kind,
            payloads.get(item.kind.value, item.payload), operands))
    for name in ("agent", "sim"):
        child = retained[name + "_environment_certificate"]["evidence"]
        objects.append(NamespaceObject.create("env-" + name, "ENV", child["artifact"], {}))
    return objects


def inputs(check: str, *, artifact: dict | None = None, retained: dict | None = None,
           objects: list[NamespaceObject] | None = None, **limits: int) -> tuple[Any, dict, dict, bytes]:
    contract = bot_checks_contract
    if artifact is None:
        artifact, retained = specimen()
    artifact, retained = deepcopy(artifact), deepcopy(retained)
    objects = collection(artifact, retained) if objects is None else objects
    selected = next(item for item in objects if item.object_id == "bot")
    if retained is not None:
        records = {item.object_id: item for item in objects}
        retained.setdefault("environment", records["env"].payload)
        retained.setdefault("agent_model", records["model"].payload)
    evidence = canonical_bytes({"schema_version": "verifier-current-bot-checks-evidence-1",
        "objects": [item.to_dict() for item in sorted(objects, key=lambda item: item.object_id)], "inputs": retained})
    policy = contract.bot_checks_policy(trust_roots=["test:current-external-bot"], max_tolerance=1e-12)
    request = contract.bot_checks_request(check=check, subject_id="bot", object_digest=selected.digest,
        collection_digest=composition_digest(objects), evidence_ref=digest(json.loads(evidence)),
        policy=policy, limits=limits or None)
    return contract, request, policy, evidence


def replay(contract: Any, request: dict, policy: dict, evidence: bytes | None) -> dict:
    certificate = contract.build_bot_checks_certificate(request, evidence, policy=policy)
    return routes.replay_current_object_certificate(certificate, semantic_version=SEMANTIC,
        objective=request["coordinate"], represented_kind="BOT", expected_request=request, policy=policy)


@pytest.mark.parametrize("check", CHECKS)
def test_current_bot_positive_replay_is_deterministic_and_bounded(check: str) -> None:
    contract, request, policy, evidence = inputs(check)
    assert contract.build_bot_checks_certificate(request, evidence, policy=policy) == contract.build_bot_checks_certificate(request, evidence, policy=policy)
    result = replay(contract, request, policy, evidence)
    assert result["computational_status"] == "PASS"
    native = result["native_result"]
    assert native["authority"] == native["object_profile_conformance"] == "NOT_ESTABLISHED"
    assert native["evaluation"]["observations"]["bot"]["historical_child_policy_reproduction"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("check", CHECKS)
def test_current_bot_native_counterexamples_are_refuted(check: str) -> None:
    artifact, retained = specimen()
    if check == "binding": artifact["agent_certificate_digest"] = "sha256:" + "0" * 64
    elif check == "alignment": artifact["step_map"] = [2, 1]
    elif check == "observation": artifact["initial_observation_record"] = 1
    elif check == "actuation": artifact["step_map"] = [0, 2]
    else: artifact["separation"] = "unsupported"
    assert replay(*inputs(check, artifact=artifact, retained=retained))["computational_status"] == "FAIL"


@pytest.mark.parametrize("check", CHECKS)
@pytest.mark.parametrize("bound", ["max_operations", "max_items", "max_objects", "max_composition_operations",
                                  "max_evidence_bytes", "max_payload_bytes", "max_reference_bytes"])
def test_selected_resource_exhaustion_is_unknown(check: str, bound: str) -> None:
    assert replay(*inputs(check, **{bound: 1}))["computational_status"] == "UNKNOWN"


@pytest.mark.parametrize("check", CHECKS)
def test_missing_evidence_is_unknown(check: str) -> None:
    contract, request, policy, _ = inputs(check)
    assert replay(contract, request, policy, None)["computational_status"] == "UNKNOWN"


@pytest.mark.parametrize("field", ["subject_id", "object_digest", "collection_digest", "evidence_ref", "policy_digest"])
def test_carried_certificate_cannot_select_request(field: str) -> None:
    contract, request, policy, evidence = inputs("binding")
    certificate = contract.build_bot_checks_certificate(request, evidence, policy=policy)
    request[field] = "other" if field == "subject_id" else "sha256:" + "0" * 64
    with pytest.raises(ValueError):
        contract.recheck_bot_checks_certificate(certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("field,value", [("status", "FAIL"), ("authority", "ESTABLISHED"),
                                         ("object_profile_conformance", "ESTABLISHED")])
def test_rehashed_result_promotion_is_rejected(field: str, value: str) -> None:
    contract, request, policy, evidence = inputs("binding")
    certificate = json.loads(contract.build_bot_checks_certificate(request, evidence, policy=policy))
    certificate["result"][field] = value
    certificate["digest"] = digest({k: v for k, v in certificate.items() if k != "digest"})
    with pytest.raises(ValueError):
        contract.recheck_bot_checks_certificate(canonical_bytes(certificate), expected_request=request, policy=policy)


@pytest.mark.parametrize("record", ["agent", "sim", "harness", "env-agent", "env-sim", "env", "model"])
def test_substituted_actual_operand_payload_is_refuted(record: str) -> None:
    artifact, retained = specimen()
    retained["environment"] = {"fixture": "ENV"}
    retained["agent_model"] = {"fixture": "MODEL"}
    objects = collection(artifact, retained)
    objects = [NamespaceObject.create(item.object_id, item.kind, {**item.payload, "substituted": True}, dict(item.operands))
               if item.object_id == record else item for item in objects]
    assert replay(*inputs("binding", artifact=artifact, retained=retained, objects=objects))["computational_status"] == "FAIL"


@pytest.mark.parametrize("name", ["agent", "sim", "agent_environment", "sim_environment"])
def test_missing_native_child_stays_unknown(name: str) -> None:
    artifact, retained = specimen()
    objects = collection(artifact, retained)
    del retained[name + "_certificate"]
    assert replay(*inputs("binding", artifact=artifact, retained=retained, objects=objects))["computational_status"] == "UNKNOWN"


def test_fused_environments_do_not_establish_separation() -> None:
    artifact, retained = specimen(); artifact["separation"] = "fused"
    assert replay(*inputs("containment", artifact=artifact, retained=retained))["computational_status"] == "UNKNOWN"


def test_valid_binding_does_not_require_equal_bot_agent_and_sim_environments() -> None:
    artifact, retained = specimen()
    objects = collection(artifact, retained)
    assert len({dict(item.operands)["env"][0] for item in objects if item.kind.value in ("BOT", "AGENT", "SIM")}) == 3
    assert replay(*inputs("binding", artifact=artifact, retained=retained, objects=objects))["computational_status"] == "PASS"


@pytest.mark.parametrize("check", CHECKS)
def test_exact_shared_native_operation_limit_and_one_under(check: str) -> None:
    contract, request, policy, evidence = inputs(check)
    used = replay(contract, request, policy, evidence)["native_result"]["evaluation"]["observations"]["operations"]
    request["limits"]["max_operations"] = used
    assert replay(contract, request, policy, evidence)["computational_status"] == "PASS"
    request["limits"]["max_operations"] = used - 1
    assert replay(contract, request, policy, evidence)["computational_status"] == "UNKNOWN"


def test_canonical_bot_evidence_cannot_be_redacted() -> None:
    from verifier.privacy.engine import EmissionEvaluator, EmissionRefusalError
    from verifier.privacy.models import DisclosureSurface, DisclosureBound, EmissionContext, ObserverParty
    contract, request, policy, evidence = inputs("binding")
    value = json.loads(contract.build_bot_checks_certificate(request, evidence, policy=policy))
    surface = DisclosureSurface("BOT", tuple(k for k in value if k != "evidence_payloads"), ("evidence_payloads",))
    bounds = tuple(DisclosureBound(field, field, admitted_observers=("reader",)) for field in surface.disclosed_fields)
    context = EmissionContext(ObserverParty("reader", "reviewer", "local"), "2026-09-28T00:00:00Z")
    with pytest.raises(EmissionRefusalError, match="canonical certificate"):
        EmissionEvaluator().evaluate_emission(value, surface, bounds, context)


@pytest.mark.parametrize("relative", ["domains/contracts/bot_checks.py", "domains/bot.py", "standard/CURRENT_BOT_CHECKS.md"])
def test_current_bot_dependencies_invalidate_polish(relative: str, monkeypatch: Any) -> None:
    from verifier.runtime import polish
    original = Path.read_bytes; target = Path(polish.__file__).parents[1] / relative
    before = polish.mechanism_digest()
    def replaced(path: Path) -> bytes:
        return original(path) + (b"\n# external mutation" if path == target else b"")
    monkeypatch.setattr(Path, "read_bytes", replaced)
    assert polish.mechanism_digest() != before


@pytest.mark.parametrize("check", CHECKS)
def test_registered_inventory_binds_each_current_bot_objective(check: str) -> None:
    from verifier.domains.inventory import slot_inventory
    rows = [objective for slot in slot_inventory() for objective in slot["registered_objectives"]]
    selected = next(row for row in rows if row["coordinate"] == CHECKS[check])
    assert selected["binding"]["checking_mechanism"] == "verifier.domains.contracts.bot_checks.recheck_bot_checks_certificate"


@pytest.mark.parametrize("tolerance,expected", [(0, "UNKNOWN"), (1e-13, "UNKNOWN"), (1e-12, "PASS")])
def test_external_current_policy_controls_child_numerical_tolerance(tolerance: float, expected: str) -> None:
    contract, request, _, evidence = inputs("binding")
    policy = contract.bot_checks_policy(trust_roots=["test:current-external-bot"], max_tolerance=tolerance)
    request["policy_digest"] = digest(policy)
    assert replay(contract, request, policy, evidence)["computational_status"] == expected


@pytest.mark.parametrize("tolerance", [True, -1, 0.01, float("inf"), float("nan"), "0"])
def test_unsupported_policy_tolerance_is_refused(tolerance: Any) -> None:
    contract = bot_checks_contract
    with pytest.raises(ValueError, match="tolerance"):
        contract.bot_checks_policy(trust_roots=["test:current-external-bot"], max_tolerance=tolerance)


@pytest.mark.parametrize("check", CHECKS)
def test_public_bot_command_executes_native_replay(check: str, tmp_path: Path, capsys: Any) -> None:
    from verifier.runtime.public_cli import main
    contract, request, policy, evidence = inputs(check)
    certificate = contract.build_bot_checks_certificate(request, evidence, policy=policy)
    paths = {name: tmp_path / (name + ".json") for name in ("certificate", "request", "policy")}
    for name, data in (("certificate", certificate), ("request", canonical_bytes(request)), ("policy", canonical_bytes(policy))):
        paths[name].write_bytes(data)
    code = main(["current-object", "check", str(paths["certificate"]), "--semantic-version", SEMANTIC,
        "--objective", CHECKS[check], "--represented-kind", "BOT", "--request", str(paths["request"]),
        "--policy", str(paths["policy"]), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"


def rehash_child(child: dict) -> None:
    child["request"] = domain_request(child["evidence"], target_depth=child["request"]["target_depth"])
    child["certificate_digest"] = digest({k: v for k, v in child.items() if k != "certificate_digest"})


@pytest.mark.parametrize("name", ["agent", "sim", "agent_environment", "sim_environment"])
@pytest.mark.parametrize("mutation,expected", [("result", "FAIL"), ("mechanism", "UNKNOWN"), ("depth", "UNKNOWN")])
def test_rehashed_child_success_cannot_replace_current_native_replay(name: str, mutation: str, expected: str) -> None:
    artifact, retained = specimen(); child = retained[name + "_certificate"]
    if mutation == "result": child["result"]["scope"] = "forged broader property"
    elif mutation == "mechanism": child["mechanism_digest"] = "sha256:" + "0" * 64
    else: child["result"]["domain_depth"] = 0
    rehash_child(child); artifact[name + "_certificate_digest"] = digest(child)
    assert replay(*inputs("binding", artifact=artifact, retained=retained))["computational_status"] == expected


@pytest.mark.parametrize("name", ["agent", "sim", "agent_environment", "sim_environment"])
def test_bound_child_false_evidence_is_recomputed_despite_carried_success(name: str) -> None:
    artifact, retained = specimen(); child = retained[name + "_certificate"]
    value = child["evidence"]
    if name == "agent":
        value["inputs"]["steps"][0]["record"] = 99
        value["artifact"]["steps_digest"] = digest(value["inputs"]["steps"])
    elif name == "sim":
        value["inputs"]["states"][1]["x"] = 99.0
        value["artifact"]["trajectory_digest"] = digest(value["inputs"]["states"])
    else:
        next(iter(value["inputs"]["files"].values()))["base64"] = "ZmFsc2U="
    assert child["result"]["status"] == "PASS"
    rehash_child(child); artifact[name + "_certificate_digest"] = digest(child)
    assert replay(*inputs("binding", artifact=artifact, retained=retained))["computational_status"] == "FAIL"


@pytest.mark.parametrize("role,kind", [("agent", "AGENT"), ("sim", "SIM"), ("env", "ENV")])
def test_valid_graph_operand_is_unknown_to_direct_native_coupling(role: str, kind: str) -> None:
    artifact, retained = specimen(); objects = collection(artifact, retained)
    subject = next(item for item in objects if item.object_id == "bot")
    operands = dict(subject.operands); leaves = list(operands[role]); operands[role] = ["qualified-operand"]
    replacement = NamespaceObject.create("bot", "BOT", artifact, operands)
    objects = [replacement if item.object_id == "bot" else item for item in objects]
    objects.append(NamespaceObject.create("qualified-operand", "GRAPH", {"element_kind": kind}, {"members": leaves}))
    assert replay(*inputs("binding", artifact=artifact, retained=retained, objects=objects))["computational_status"] == "UNKNOWN"


@pytest.mark.parametrize("relative", ["domains/sim.py", "domains/agent.py", "domains/harness.py",
    "domains/certification.py", "standard/DOMAIN_GROUNDING.md", "domains/contracts/bot_checks.py"])
def test_transitive_native_source_substitution_invalidates_bot_policy(relative: str, monkeypatch: Any) -> None:
    contract, request, policy, evidence = inputs("binding")
    original = Path.read_bytes; target = Path(contract.__file__).parents[2] / relative
    def changed(path: Path) -> bytes:
        return original(path) + (b"\n# substituted source" if path == target else b"")
    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        contract.build_bot_checks_certificate(request, evidence, policy=policy)


def test_current_initial_observation_preserves_native_ceiling_unknown() -> None:
    artifact, retained = specimen(); evidence = retained["agent_certificate"]["evidence"]
    evidence["artifact"]["required_channels"] = ["world_action"]
    evidence["inputs"]["steps"] = evidence["inputs"]["steps"][1:]
    for index, step in enumerate(evidence["inputs"]["steps"]): step["index"] = index
    evidence["artifact"]["steps_digest"] = digest(evidence["inputs"]["steps"])
    child = certify(evidence, 5); assert child["result"]["status"] == "PASS"
    retained["agent_certificate"] = child; artifact["agent_certificate_digest"] = digest(child)
    assert replay(*inputs("binding", artifact=artifact, retained=retained))["computational_status"] == "PASS"
    assert replay(*inputs("observation", artifact=artifact, retained=retained))["computational_status"] == "UNKNOWN"


def test_no_attributed_transition_cannot_establish_agent_loop() -> None:
    artifact, retained = specimen()
    artifact["step_map"] = []; artifact["exogenous_transitions"] = [0, 1]
    assert replay(*inputs("alignment", artifact=artifact, retained=retained))["computational_status"] == "UNKNOWN"


def test_current_external_policy_and_actual_native_checker_are_used(monkeypatch: Any) -> None:
    from verifier.domains import bot
    contract, request, policy, evidence = inputs("observation")
    original = bot.evaluate; observations = []
    def observed(check: str, artifact: dict, retained: dict, budget: Any, **kwargs: Any) -> dict:
        observations.append((check, kwargs["policy"]["trust_roots"], kwargs["policy"]["max_tolerance"], budget.limit))
        return original(check, artifact, retained, budget, **kwargs)
    monkeypatch.setattr(bot, "evaluate", observed)
    assert replay(contract, request, policy, evidence)["computational_status"] == "PASS"
    assert observations and all(row == ("observation", policy["trust_roots"], policy["max_tolerance"], request["limits"]["max_operations"]) for row in observations)


@pytest.mark.parametrize("check", ["observation", "actuation"])
def test_duplicate_identical_invocations_do_not_change_retained_correspondence(check: str) -> None:
    artifact, retained = specimen(); agent = retained["agent_certificate"]["evidence"]
    harness = agent["inputs"]["harness_certificate"]["evidence"]
    harness["inputs"]["invocations"].append(deepcopy(harness["inputs"]["invocations"][0]))
    child = certify(harness, 5); assert child["result"]["status"] == "PASS"
    agent["inputs"]["harness_certificate"] = child
    agent["artifact"]["harness_certificate_digest"] = digest(child)
    child = certify(agent, 5); assert child["result"]["status"] == "PASS"
    retained["agent_certificate"] = child; artifact["agent_certificate_digest"] = digest(child)
    assert replay(*inputs(check, artifact=artifact, retained=retained))["computational_status"] == "PASS"
