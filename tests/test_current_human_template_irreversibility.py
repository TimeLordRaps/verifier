"""HUMAN-2.5 declared biometric template irreversibility over a retained event log.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); command-line interface (CLI). Positions are
dimensionless order indices; counts are dimensionless. These tests decide only
properties of DECLARED humanness-assertion event records. They never establish
that anyone is a person, that a template was breached, or that a breach was real.
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
from verifier.domains.contracts import human_template_irreversibility as hti
from verifier.domains.inventory import get_slot


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _make(name: str, kind: str, operands: dict | None = None) -> NamespaceObject:
    return NamespaceObject.create(name, kind, {"label": name}, operands)


def machine_records(bot_id: str) -> list[NamespaceObject]:
    """A complete typed BOT composition whose BOT carries a caller-chosen identifier."""
    env, harness, data = _make("env", "ENV"), _make("harness", "HARNESS"), _make("data", "DATA")
    verifier, thing = _make("verifier", "VERIFIER"), _make("object", "OBJECT")
    when, where = _make("time", "TIME"), _make("space", "SPACE")
    arch, hardware = _make("arch", "ARCH"), _make("hardware", "HARDWARE")
    event = _make("event", "EVENT", {"time": ["time"], "space": ["space"], "meaning": ["object"]})
    bench = _make("bench", "BENCH", {"verifier": ["verifier"], "data": ["data"]})
    train = _make("train", "TRAIN", {"data": ["data"], "events": ["event"],
                                     "bench": ["bench"], "arch": ["arch"]})
    model = _make("model", "MODEL", {"train": ["train"], "data": ["data"], "events": ["event"],
                                     "bench": ["bench"], "arch": ["arch"], "env": ["env"],
                                     "hardware": ["hardware"]})
    agent = _make("agent", "AGENT", {"model": ["model"], "harness": ["harness"], "env": ["env"]})
    sim = _make("sim", "SIM", {"data": ["data"], "verifier": ["verifier"],
                               "objects": ["object"], "env": ["env"]})
    bot = _make(bot_id, "BOT", {"agent": ["agent"], "sim": ["sim"], "env": ["env"]})
    return [env, harness, data, verifier, thing, when, where, arch, hardware,
            event, bench, train, model, agent, sim, bot]


def events() -> list[dict]:
    return [
        {"position": 1, "event": "enrollment", "template_id": "template-1",
         "evidence_class": "biometric", "instrument": "iris-capture-station-3"},
        {"position": 2, "event": "reverification", "template_id": "template-1"},
        {"position": 4, "event": "compromise", "template_id": "template-1",
         "breach": "permanent"},
        {"position": 5, "event": "revocation", "template_id": "template-1",
         "effective_position": 5},
        {"position": 7, "event": "enrollment", "template_id": "template-2",
         "evidence_class": "biometric", "instrument": "iris-capture-station-3"},
        {"position": 8, "event": "reverification", "template_id": "template-2"},
    ]


def selected(rows: list[dict] | None = None, *, subject_id: str = "person-a",
             limits: dict | None = None, include_inputs: bool = True):
    rows = events() if rows is None else rows
    person = NamespaceObject.create("person-a", "HUMAN", {"assertion": "declared"})
    objects = [person, *machine_records("human:courier")]
    subject = next(item for item in objects if item.object_id == subject_id)
    value = {"schema_version": hti.EVIDENCE_VERSION,
             "objects": [item.to_dict() for item in objects]}
    if include_inputs:
        value["inputs"] = {"events": rows}
    evidence = canonical_bytes(value)
    policy = hti.human_template_irreversibility_policy(trust_roots=["human-root"])
    request = hti.human_template_irreversibility_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest(objects), events_digest=digest(rows),
        evidence_ref="sha256:" + hashlib.sha256(evidence).hexdigest(),
        policy=policy, limits=limits)
    return request, policy, evidence


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = hti.build_human_template_irreversibility_certificate(
        request, evidence, policy=policy)
    result = hti.recheck_human_template_irreversibility_certificate(
        certificate, expected_request=request, policy=policy)
    return certificate, result


RESTORATIVE = {"rotation", "restoration", "rebinding", "remediation"}


def oracle(rows: list[dict]) -> tuple[str, set[str]]:
    """Independent set-based reading of the selected proposition."""
    positions = [row["position"] for row in rows]
    if positions != sorted(set(positions)):
        return "FAIL", set()
    breach_at: dict[str, int] = {}
    for row in rows:
        if row["event"] == "compromise":
            breach_at.setdefault(row["template_id"], row["position"])
    enrolled_at: dict[str, list[int]] = {}
    for row in rows:
        if row["event"] == "enrollment":
            enrolled_at.setdefault(row["template_id"], []).append(row["position"])
    if any(len(found) != 1 for found in enrolled_at.values()):
        return "FAIL", set(breach_at)
    revocations: dict[str, int] = {}
    for row in rows:
        kind, template = row["event"], row["template_id"]
        if kind in RESTORATIVE:
            return "FAIL", set(breach_at)
        if template not in enrolled_at or row["position"] < enrolled_at[template][0]:
            return "FAIL", set(breach_at)
        if kind == "enrollment" and (row.get("evidence_class") != "biometric"
                                     or not isinstance(row.get("instrument"), str)
                                     or not row["instrument"].strip()):
            return "FAIL", set(breach_at)
        if kind == "compromise" and row.get("breach") != "permanent":
            return "FAIL", set(breach_at)
        if kind == "revocation":
            revocations[template] = revocations.get(template, 0) + 1
            if (template not in breach_at or breach_at[template] > row["position"]
                    or row["effective_position"] < row["position"]
                    or revocations[template] > 1):
                return "FAIL", set(breach_at)
        if (template in breach_at and row["position"] > breach_at[template]
                and kind != "revocation"):
            return "FAIL", set(breach_at)
    return "PASS", set(breach_at)


def test_permanent_breach_and_distinct_reenrollment_pass_and_recheck():
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    assert oracle(events())[0] == "PASS"
    assert result["template_irreversibility"] == "PASS"
    observed = result["evaluation"]["observations"]["template_log"]
    assert set(observed["breached_templates"]) == oracle(events())[1] == {"template-1"}
    assert observed["event_count"] == len(events())
    for field in ("personhood", "liveness", "biometric_accuracy",
                  "presentation_attack_resistance", "injection_attack_resistance",
                  "uniqueness_claim", "death", "authority", "consent", "privacy",
                  "human_dynamics_tier_conformance", "object_profile_conformance"):
        assert result[field] == "NOT_ESTABLISHED"
    decoded = json.loads(certificate)
    assert decoded["result"] == result
    assert certificate == hti.build_human_template_irreversibility_certificate(
        request, evidence, policy=policy)


def _with(position: int, row: dict) -> list[dict]:
    rows = [item for item in events() if item["position"] != position]
    rows.append(row)
    return sorted(rows, key=lambda item: item["position"])


MUTANTS = {
    "breached_template_reactivated": (_with(6, {
        "position": 6, "event": "reverification", "template_id": "template-1"}),
        "after its breach"),
    "breached_template_reenrolled": (_with(7, {
        "position": 7, "event": "enrollment", "template_id": "template-1",
        "evidence_class": "biometric", "instrument": "iris-capture-station-3"}),
        "after its breach"),
    "remediation_event": (_with(6, {
        "position": 6, "event": "remediation", "template_id": "template-1"}),
        "never admitted"),
    "rotation_event": (_with(6, {
        "position": 6, "event": "rotation", "template_id": "template-1"}),
        "never admitted"),
    "breach_declared_remediated": (_with(4, {
        "position": 4, "event": "compromise", "template_id": "template-1",
        "breach": "remediated"}), "permanent"),
    "retroactive_revocation": (_with(5, {
        "position": 5, "event": "revocation", "template_id": "template-1",
        "effective_position": 3}), "retroactive"),
    "enrollment_without_evidence_class": (_with(1, {
        "position": 1, "event": "enrollment", "template_id": "template-1",
        "evidence_class": None, "instrument": "iris-capture-station-3"}),
        "evidence class"),
    "enrollment_without_instrument": (_with(1, {
        "position": 1, "event": "enrollment", "template_id": "template-1",
        "evidence_class": "biometric", "instrument": None}), "instrument"),
}


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_each_refuting_mutant_fails_for_its_own_reason(name):
    rows, reason = MUTANTS[name]
    assert oracle(rows)[0] == "FAIL"
    request, policy, evidence = selected(rows)
    _, result = replay(request, policy, evidence)
    assert result["status"] == "FAIL"
    assert result["template_irreversibility"] == "NOT_ESTABLISHED"
    assert reason in result["evaluation"]["details"], result["evaluation"]["details"]


def test_label_does_not_make_a_bot_the_selected_human():
    request, policy, evidence = selected(subject_id="human:courier")
    _, result = replay(request, policy, evidence)
    assert result["status"] == "FAIL"
    assert "differs from external selection" in result["evaluation"]["details"]


def test_budget_exhaustion_and_absent_log_remain_unknown():
    request, policy, evidence = selected(limits={"max_operations": 8})
    _, result = replay(request, policy, evidence)
    assert result["status"] == "UNKNOWN"
    request, policy, evidence = selected(include_inputs=False)
    assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN"
    assert replay(request, policy, None)[1]["status"] == "UNKNOWN"


@pytest.mark.parametrize("fraction", [0.1, 0.5, 0.9])
def test_one_bit_flip_in_certificate_is_refused(fraction):
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    flipped = bytearray(certificate)
    flipped[int(len(flipped) * fraction)] ^= 0x01
    with pytest.raises(hti.HumanTemplateIrreversibilityError):
        hti.recheck_human_template_irreversibility_certificate(
            bytes(flipped), expected_request=request, policy=policy)


def test_substituted_subject_request_policy_and_forged_verdict_are_refused():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    other_request = deepcopy(request)
    other_request["subject_id"] = "agent"
    with pytest.raises(hti.HumanTemplateIrreversibilityError):
        hti.recheck_human_template_irreversibility_certificate(
            certificate, expected_request=other_request, policy=policy)
    other_policy = hti.human_template_irreversibility_policy(trust_roots=["other-root"])
    with pytest.raises(hti.HumanTemplateIrreversibilityError):
        hti.recheck_human_template_irreversibility_certificate(
            certificate, expected_request=request, policy=other_policy)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(hti.HumanTemplateIrreversibilityError):
        hti.recheck_human_template_irreversibility_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)
    with pytest.raises(hti.HumanTemplateIrreversibilityError):
        hti.build_human_template_irreversibility_certificate(
            request, evidence + b" ", policy=policy)
    malformed = deepcopy(request)
    malformed["coordinate"] = "HUMAN-2.4"
    with pytest.raises(hti.HumanTemplateIrreversibilityError):
        hti.build_human_template_irreversibility_certificate(
            malformed, evidence, policy=policy)


def test_inventory_slot_names_this_recheck():
    slot = get_slot("HUMAN", 2)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.mechanized_route["artifact_coordinate"] == "HUMAN-2.5"
    assert slot.mechanized_route["checking_mechanism"] == (
        "verifier.domains.contracts.human_template_irreversibility."
        "recheck_human_template_irreversibility_certificate")


def test_public_route_and_command_replay_template_irreversibility(tmp_path: Path, capsys):
    from verifier.runtime.public_cli import main

    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=hti.SEMANTIC_VERSION,
        objective=hti.COORDINATE, represented_kind="HUMAN",
        expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["personhood"] == "NOT_ESTABLISHED"
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(
            certificate, semantic_version=hti.SEMANTIC_VERSION,
            objective=hti.COORDINATE, represented_kind="BOT",
            expected_request=request, policy=policy)
    for name, contents in (("request", canonical_bytes(request)),
                           ("policy", canonical_bytes(policy)),
                           ("certificate", certificate)):
        (tmp_path / (name + ".json")).write_bytes(contents)
    code = main(["current-object", "check", str(tmp_path / "certificate.json"),
                 "--semantic-version", hti.SEMANTIC_VERSION,
                 "--objective", hti.COORDINATE, "--represented-kind", "HUMAN",
                 "--request", str(tmp_path / "request.json"),
                 "--policy", str(tmp_path / "policy.json"), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"


@pytest.mark.parametrize("relative", [
    "domains/contracts/human_template_irreversibility.py",
    "standard/CURRENT_HUMAN_TEMPLATE_IRREVERSIBILITY.md",
    "standard/NAMESPACE_OBJECTS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    target = Path(hti.__file__).parents[2] / relative
    original = Path.read_bytes

    def changed(path):
        data = original(path)
        return data + b"\nchanged selected dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        hti.recheck_human_template_irreversibility_certificate(
            certificate, expected_request=request, policy=policy)


def _obligation_rows() -> dict[str, str]:
    """Requirement cells of the HUMAN table rows, read from the shipped standard."""
    text = (Path(hti.__file__).parents[2] / "standard" / "DOMAIN_OBLIGATIONS.md").read_text(encoding="utf-8")
    rows = {}
    for line in text.splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) >= 3 and cells[0].startswith("HUMAN-"):
            rows[cells[0]] = cells[2]
    return rows


def test_proposition_quotes_its_obligation_rows_verbatim():
    rows = _obligation_rows()
    spec = (Path(hti.__file__).parents[2] / "standard" / "CURRENT_HUMAN_TEMPLATE_IRREVERSIBILITY.md").read_text(encoding="utf-8")
    quoted = {hti.COORDINATE: hti.ROW, **hti.PREREQUISITE_ROWS}
    for coordinate, text in quoted.items():
        assert rows[coordinate] == text, coordinate
        assert '"' + text + '"' in spec, coordinate
    assert hti.registration()["obligation_row"] == rows[hti.COORDINATE]
