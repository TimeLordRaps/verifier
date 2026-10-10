"""HUMAN-3.6 no declared arrangement yields a HUMAN, over a finite typed collection.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); command-line interface (CLI). Route depths and
counts are dimensionless. Kind is read from typed namespace records only, never
from an identifier or label. These tests never establish that anyone is a person.
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
from verifier.domains.contracts import human_no_composition as hnc
from verifier.domains.inventory import get_slot

ARRANGING_KINDS = {"MODEL", "AGENT", "BOT", "SIM", "COLLECTIVE"}


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _make(name: str, kind: str, operands: dict | None = None) -> NamespaceObject:
    return NamespaceObject.create(name, kind, {"label": name}, operands)


def records(extra: list[NamespaceObject] | None = None) -> list[NamespaceObject]:
    """Two HUMAN leaves, one complete BOT composition labelled `human:` and plain outputs."""
    rows = [
        NamespaceObject.create("person-a", "HUMAN", {"assertion": "declared"}),
        NamespaceObject.create("bot:person-b", "HUMAN", {"assertion": "declared"}),
        _make("env", "ENV"), _make("harness", "HARNESS"), _make("data", "DATA"),
        _make("verifier", "VERIFIER"), _make("object", "OBJECT"),
        _make("time", "TIME"), _make("space", "SPACE"), _make("arch", "ARCH"),
        _make("hardware", "HARDWARE"), _make("role", "ROLE"),
        _make("derived-data", "DATA"), _make("sim-output", "DATA"),
        _make("report", "OBJECT"), _make("relay", "OBJECT"),
        _make("event", "EVENT", {"time": ["time"], "space": ["space"], "meaning": ["object"]}),
        _make("bench", "BENCH", {"verifier": ["verifier"], "data": ["data"]}),
        _make("train", "TRAIN", {"data": ["data"], "events": ["event"],
                                 "bench": ["bench"], "arch": ["arch"]}),
        _make("model", "MODEL", {"train": ["train"], "data": ["data"], "events": ["event"],
                                 "bench": ["bench"], "arch": ["arch"], "env": ["env"],
                                 "hardware": ["hardware"]}),
        _make("agent", "AGENT", {"model": ["model"], "harness": ["harness"], "env": ["env"]}),
        _make("sim", "SIM", {"data": ["data"], "verifier": ["verifier"],
                             "objects": ["object"], "env": ["env"]}),
        _make("human:courier", "BOT", {"agent": ["agent"], "sim": ["sim"], "env": ["env"]}),
        _make("collective", "COLLECTIVE", {"roles": ["role"]}),
        _make("bot-actor", "ACTOR", {"representation": ["human:courier"],
                                     "root_human": ["person-a"]}),
    ]
    return rows + list(extra or [])


def arrangements() -> list[dict]:
    return [
        {"arrangement_id": "arr-1", "arranged": ["agent", "sim"],
         "output": "human:courier", "declared_output_kind": "BOT", "strength": "full"},
        {"arrangement_id": "arr-2", "arranged": ["data", "model"],
         "output": "derived-data", "declared_output_kind": "DATA", "strength": "partial"},
        {"arrangement_id": "arr-3", "arranged": ["collective", "derived-data"],
         "output": "report", "declared_output_kind": "OBJECT", "strength": "statistical"},
    ]


def selected(rows: list[dict] | None = None, *, objects: list[NamespaceObject] | None = None,
             subject_id: str = "person-a", limits: dict | None = None,
             include_inputs: bool = True):
    rows = arrangements() if rows is None else rows
    objects = records() if objects is None else objects
    subject = next(item for item in objects if item.object_id == subject_id)
    value = {"schema_version": hnc.EVIDENCE_VERSION,
             "objects": [item.to_dict() for item in objects]}
    if include_inputs:
        value["inputs"] = {"arrangements": rows}
    evidence = canonical_bytes(value)
    policy = hnc.human_no_composition_policy(trust_roots=["human-root"])
    request = hnc.human_no_composition_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest(objects), arrangements_digest=digest(rows),
        evidence_ref="sha256:" + hashlib.sha256(evidence).hexdigest(),
        policy=policy, limits=limits)
    return request, policy, evidence


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = hnc.build_human_no_composition_certificate(request, evidence, policy=policy)
    result = hnc.recheck_human_no_composition_certificate(
        certificate, expected_request=request, policy=policy)
    return certificate, result


def oracle(objects: list[NamespaceObject], rows: list[dict]) -> tuple[str, int | None]:
    """Independent Bellman-Ford relaxation over containment and arrangement edges.

    Returns the verdict and the least route depth at which a HUMAN is produced
    from an arranging kind, or None when no such route exists.
    """
    kinds = {item.object_id: item.kind.value for item in objects}
    infinity = len(objects) + len(rows) + 1
    depth = {name: (0 if kind in ARRANGING_KINDS else infinity) for name, kind in kinds.items()}
    for _ in range(len(objects) + len(rows) + 1):
        for item in objects:
            for _, targets in item.operands:
                for target in targets:
                    depth[item.object_id] = min(depth[item.object_id], depth[target])
        for row in rows:
            through = min(depth[name] for name in row["arranged"]) + 1
            depth[row["output"]] = min(depth[row["output"]], through)
    reached = [depth[row["output"]] for row in rows
               if kinds[row["output"]] == "HUMAN" or row["declared_output_kind"] == "HUMAN"]
    routed = []
    for row in rows:
        if kinds[row["output"]] == "HUMAN" or row["declared_output_kind"] == "HUMAN":
            through = min(depth[name] for name in row["arranged"]) + 1
            if through < infinity:
                routed.append(through)
    if routed:
        return "FAIL", min(routed)
    if reached:
        return "FAIL", None
    return "PASS", None


def test_typed_collection_with_machine_arrangements_passes_and_rechecks():
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert oracle(records(), arrangements()) == ("PASS", None)
    assert result["status"] == "PASS"
    assert result["no_composition_yields_human"] == "PASS"
    observed = result["evaluation"]["observations"]["arrangements"]
    humans = sorted(item.object_id for item in records() if item.kind.value == "HUMAN")
    assert observed["human_records"] == humans == ["bot:person-b", "person-a"]
    assert "human:courier" not in observed["human_records"]
    assert observed["arrangement_count"] == 3
    for field in ("personhood", "liveness", "biometric_accuracy",
                  "presentation_attack_resistance", "injection_attack_resistance",
                  "uniqueness_claim", "death", "authority", "consent", "privacy",
                  "human_singularity", "human_statics_tier_conformance",
                  "object_profile_conformance"):
        assert result[field] == "NOT_ESTABLISHED"
    assert json.loads(certificate)["result"] == result


def _plus(*rows: dict) -> list[dict]:
    return sorted([*arrangements(), *rows], key=lambda row: row["arrangement_id"])


MUTANTS = {
    "agent_composition_declares_human": (records(), _plus({
        "arrangement_id": "arr-4", "arranged": ["agent"], "output": "human:courier",
        "declared_output_kind": "HUMAN", "strength": "full"}), "route depth 1"),
    "human_provenance_cites_sim_output": (records(), _plus(
        {"arrangement_id": "arr-4", "arranged": ["sim"], "output": "sim-output",
         "declared_output_kind": "DATA", "strength": "full"},
        {"arrangement_id": "arr-5", "arranged": ["sim-output"], "output": "person-a",
         "declared_output_kind": "DATA", "strength": "full"}), "route depth 2"),
    "depth_three_indirect_weak_route": (records(), _plus(
        {"arrangement_id": "arr-4", "arranged": ["report"], "output": "relay",
         "declared_output_kind": "OBJECT", "strength": "negligible"},
        {"arrangement_id": "arr-5", "arranged": ["relay"], "output": "bot:person-b",
         "declared_output_kind": "OBJECT", "strength": "negligible"}), "route depth 3"),
    "actor_containing_bot_yields_human": (records(), _plus({
        "arrangement_id": "arr-4", "arranged": ["bot-actor"], "output": "person-a",
        "declared_output_kind": "HUMAN", "strength": "weak"}), "route depth 1"),
    "human_labelled_bot_manufactured_from_harness": (records(), _plus({
        "arrangement_id": "arr-4", "arranged": ["harness"], "output": "bot:person-b",
        "declared_output_kind": "OBJECT", "strength": "full"}), "HUMAN-3.1"),
}


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_each_refuting_mutant_fails_for_its_own_reason(name):
    objects, rows, reason = MUTANTS[name]
    verdict, depth = oracle(objects, rows)
    assert verdict == "FAIL"
    if reason.startswith("route depth"):
        assert reason == "route depth " + str(depth)
    request, policy, evidence = selected(rows, objects=objects)
    _, result = replay(request, policy, evidence)
    assert result["status"] == "FAIL"
    assert result["no_composition_yields_human"] == "NOT_ESTABLISHED"
    assert reason in result["evaluation"]["details"], result["evaluation"]["details"]


def test_seeded_random_arrangements_agree_with_the_independent_oracle():
    """Differential check: 120 seeded arrangement sets, module verdict and depth vs oracle."""
    import random

    generator = random.Random(20261001)
    objects = records()
    kinds = {item.object_id: item.kind.value for item in objects}
    names = sorted(kinds)
    seen = {"PASS": 0, "routed": 0, "unrouted": 0}
    for case in range(120):
        rows = []
        for index in range(generator.randint(0, 5)):
            output = generator.choice(names)
            pool = [name for name in names if name != output]
            arranged = sorted(generator.sample(pool, generator.randint(1, 3)))
            declared = "HUMAN" if generator.random() < 0.1 else kinds[output]
            rows.append({"arrangement_id": f"arr-{index}", "arranged": arranged,
                         "output": output, "declared_output_kind": declared,
                         "strength": generator.choice(["full", "weak", "negligible"])})
        verdict, depth = oracle(objects, rows)
        request, policy, evidence = selected(rows, objects=objects)
        result = replay(request, policy, evidence)[1]
        assert result["status"] == verdict, (case, rows, result["evaluation"]["details"])
        if verdict == "PASS":
            seen["PASS"] += 1
        elif depth is None:
            seen["unrouted"] += 1
            assert "HUMAN-3.1" in result["evaluation"]["details"], case
        else:
            seen["routed"] += 1
            assert "route depth " + str(depth) in result["evaluation"]["details"], case
    assert all(seen.values()), seen


def test_collective_typed_as_human_is_a_composition_counterexample():
    objects = records([NamespaceObject.create(
        "crowd", "HUMAN", {"assertion": "declared"}, {"roles": ["role"]})])
    request, policy, evidence = selected(objects=objects)
    _, result = replay(request, policy, evidence)
    assert result["status"] == "FAIL"
    assert "HUMAN operand roles differ" in result["evaluation"]["details"]


def test_label_neither_makes_nor_unmakes_a_human():
    # A BOT labelled human: may be produced; a HUMAN labelled bot: may not.
    request, policy, evidence = selected(subject_id="human:courier")
    _, result = replay(request, policy, evidence)
    assert result["status"] == "FAIL"
    assert "differs from external selection" in result["evaluation"]["details"]
    request, policy, evidence = selected(subject_id="bot:person-b")
    assert replay(request, policy, evidence)[1]["status"] == "PASS"


def test_budget_exhaustion_and_absent_arrangements_remain_unknown():
    request, policy, evidence = selected(limits={"max_operations": 8})
    assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN"
    request, policy, evidence = selected(include_inputs=False)
    assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN"
    assert replay(request, policy, None)[1]["status"] == "UNKNOWN"


@pytest.mark.parametrize("fraction", [0.1, 0.5, 0.9])
def test_one_bit_flip_in_certificate_is_refused(fraction):
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    flipped = bytearray(certificate)
    flipped[int(len(flipped) * fraction)] ^= 0x01
    with pytest.raises(hnc.HumanNoCompositionError):
        hnc.recheck_human_no_composition_certificate(
            bytes(flipped), expected_request=request, policy=policy)


def test_substituted_subject_request_policy_and_forged_verdict_are_refused():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    other_request = deepcopy(request)
    other_request["subject_id"] = "bot:person-b"
    with pytest.raises(hnc.HumanNoCompositionError):
        hnc.recheck_human_no_composition_certificate(
            certificate, expected_request=other_request, policy=policy)
    other_policy = hnc.human_no_composition_policy(trust_roots=["other-root"])
    with pytest.raises(hnc.HumanNoCompositionError):
        hnc.recheck_human_no_composition_certificate(
            certificate, expected_request=request, policy=other_policy)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(hnc.HumanNoCompositionError):
        hnc.recheck_human_no_composition_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)
    malformed = deepcopy(request)
    malformed["object_kind"] = "BOT"
    with pytest.raises(hnc.HumanNoCompositionError):
        hnc.build_human_no_composition_certificate(malformed, evidence, policy=policy)


def test_inventory_slot_names_this_recheck():
    slot = get_slot("HUMAN", 3)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.mechanized_route["artifact_coordinate"] == "HUMAN-3.6"
    assert slot.mechanized_route["checking_mechanism"] == (
        "verifier.domains.contracts.human_no_composition."
        "recheck_human_no_composition_certificate")


def test_public_route_and_command_replay_no_composition(tmp_path: Path, capsys):
    from verifier.runtime.public_cli import main

    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=hnc.SEMANTIC_VERSION,
        objective=hnc.COORDINATE, represented_kind="HUMAN",
        expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["human_singularity"] == "NOT_ESTABLISHED"
    for name, contents in (("request", canonical_bytes(request)),
                           ("policy", canonical_bytes(policy)),
                           ("certificate", certificate)):
        (tmp_path / (name + ".json")).write_bytes(contents)
    code = main(["current-object", "check", str(tmp_path / "certificate.json"),
                 "--semantic-version", hnc.SEMANTIC_VERSION,
                 "--objective", hnc.COORDINATE, "--represented-kind", "HUMAN",
                 "--request", str(tmp_path / "request.json"),
                 "--policy", str(tmp_path / "policy.json"), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"


@pytest.mark.parametrize("relative", [
    "domains/contracts/human_no_composition.py",
    "standard/CURRENT_HUMAN_NO_COMPOSITION.md",
    "standard/NAMESPACE_OBJECTS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    target = Path(hnc.__file__).parents[2] / relative
    original = Path.read_bytes

    def changed(path):
        data = original(path)
        return data + b"\nchanged selected dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        hnc.recheck_human_no_composition_certificate(
            certificate, expected_request=request, policy=policy)


def _obligation_rows() -> dict[str, str]:
    """Requirement cells of the HUMAN table rows, read from the shipped standard."""
    text = (Path(hnc.__file__).parents[2] / "standard" / "DOMAIN_OBLIGATIONS.md").read_text(encoding="utf-8")
    rows = {}
    for line in text.splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) >= 3 and cells[0].startswith("HUMAN-"):
            rows[cells[0]] = cells[2]
    return rows


def test_proposition_quotes_its_obligation_rows_verbatim():
    rows = _obligation_rows()
    spec = (Path(hnc.__file__).parents[2] / "standard" / "CURRENT_HUMAN_NO_COMPOSITION.md").read_text(encoding="utf-8")
    quoted = {hnc.COORDINATE: hnc.ROW, **hnc.PREREQUISITE_ROWS}
    for coordinate, text in quoted.items():
        assert rows[coordinate] == text, coordinate
        assert '"' + text + '"' in spec, coordinate
    assert hnc.registration()["obligation_row"] == rows[hnc.COORDINATE]
