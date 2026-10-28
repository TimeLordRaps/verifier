"""HUMAN-4.3 population declaration over every typed HUMAN assertion record.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); command-line interface (CLI). False-match and
false-non-match rates are dimensionless proportions in [0, 1], written as exact
decimal strings. These tests decide only properties of DECLARED humanness
assertions; uniqueness, accountability and HUMAN-4.6 closure are never PASS.
The verdict follows HUMAN-4.3 and its listed dependencies HUMAN-4.1 and
HUMAN-4.2 only; a deduplication mechanism and both rates declared zero are
observations that never decide it.
"""
from __future__ import annotations

from copy import deepcopy
from decimal import Decimal, InvalidOperation
import hashlib
import json
from pathlib import Path
import re

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import human_population_declaration as hpd
from verifier.domains.inventory import get_slot

DECLARATIONS = ("evidence_class", "operating_point", "false_match_rate",
                "false_non_match_rate", "enrollment_population")
NOT_DECIDED_HERE = ("human_3_2", "human_3_5")


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def declared(**overrides) -> dict:
    payload = {"evidence_class": "biometric", "operating_point": "threshold-0.42",
               "false_match_rate": "0.0001", "false_non_match_rate": "0.02",
               "enrollment_population": "pilot-cohort-2026",
               "deduplication_mechanism": "iris-one-to-many-dedup-v3",
               "non_asserted": ["name", "nationality", "civil identity"]}
    payload.update(overrides)
    return {key: value for key, value in payload.items() if value is not ...}


def _make(name: str, kind: str, operands: dict | None = None) -> NamespaceObject:
    return NamespaceObject.create(name, kind, {"label": name}, operands)


def machine_records() -> list[NamespaceObject]:
    """A complete typed BOT composition whose BOT carries a `human:` label."""
    return [
        _make("env", "ENV"), _make("harness", "HARNESS"), _make("data", "DATA"),
        _make("verifier", "VERIFIER"), _make("object", "OBJECT"),
        _make("time", "TIME"), _make("space", "SPACE"), _make("arch", "ARCH"),
        _make("hardware", "HARDWARE"),
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
    ]


def records(person_a: dict | None = None, helper: dict | None = None) -> list[NamespaceObject]:
    return [
        NamespaceObject.create("person-a", "HUMAN", declared() if person_a is None else person_a),
        NamespaceObject.create("bot:helper", "HUMAN", declared(
            evidence_class="in-person", operating_point="registrar-desk-review",
            false_match_rate="0.001", false_non_match_rate="0",
            enrollment_population="county-registry-2026",
            deduplication_mechanism="registrar-ledger-crosscheck") if helper is None else helper),
        *machine_records(),
    ]


def selected(objects: list[NamespaceObject] | None = None, *, subject_id: str = "person-a",
             admitted: list[str] | None = None, limits: dict | None = None):
    objects = records() if objects is None else objects
    subject = next(item for item in objects if item.object_id == subject_id)
    evidence = canonical_bytes({"schema_version": hpd.EVIDENCE_VERSION,
                                "objects": [item.to_dict() for item in objects]})
    policy = hpd.human_population_declaration_policy(
        trust_roots=["human-root"], admitted_evidence_classes=admitted)
    request = hpd.human_population_declaration_request(
        subject_id=subject.object_id, object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        evidence_ref="sha256:" + hashlib.sha256(evidence).hexdigest(),
        policy=policy, limits=limits)
    return request, policy, evidence


def replay(request: dict, policy: dict, evidence: bytes | None):
    certificate = hpd.build_human_population_declaration_certificate(
        request, evidence, policy=policy)
    result = hpd.recheck_human_population_declaration_certificate(
        certificate, expected_request=request, policy=policy)
    return certificate, result


_DECIMAL = re.compile(r"[01](\.[0-9]+)?")


def oracle(objects: list[NamespaceObject], admitted: set[str]) -> str:
    """Independent Decimal-based reading of HUMAN-4.1, 4.2 and 4.3 over typed HUMAN records.

    Neither a deduplication mechanism nor both rates zero enters this reading.
    """
    for item in objects:
        if item.kind.value != "HUMAN":
            continue
        payload = item.payload
        if any(payload.get(key) is None for key in DECLARATIONS):
            return "FAIL"
        if payload["evidence_class"] not in admitted:
            return "FAIL"
        rates = []
        for key in ("false_match_rate", "false_non_match_rate"):
            text = payload[key]
            if not isinstance(text, str) or not _DECIMAL.fullmatch(text):
                return "FAIL"
            try:
                rate = Decimal(text)
            except InvalidOperation:
                return "FAIL"
            if not Decimal(0) <= rate <= Decimal(1):
                return "FAIL"
            rates.append(rate)
        if payload["enrollment_population"].strip().lower() in {
                "global", "worldwide", "all-humans", "all humans"}:
            return "FAIL"
        if any(not str(payload[key]).strip() for key in
               ("operating_point", "enrollment_population")):
            return "FAIL"
    return "PASS"


ALL_CLASSES = {"biometric", "hardware-attested", "in-person", "social-graph"}


def test_every_typed_human_declares_its_population_and_rechecks():
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert oracle(records(), ALL_CLASSES) == "PASS"
    assert result["status"] == "PASS"
    assert result["population_declaration"] == "PASS"
    observed = result["evaluation"]["observations"]["assertions"]
    assert observed["assertion_ids"] == sorted(
        item.object_id for item in records() if item.kind.value == "HUMAN")
    assert "human:courier" not in observed["assertion_ids"]
    for field in ("personhood", "liveness", "biometric_accuracy",
                  "presentation_attack_resistance", "injection_attack_resistance",
                  "uniqueness_claim", "death", "authority", "consent", "privacy",
                  "accountability_termination", "occupancy_termination", "closure_result",
                  "human_closure_tier_conformance", "object_profile_conformance",
                  *NOT_DECIDED_HERE):
        assert result[field] == "NOT_ESTABLISHED"
    assert result["deduplication_mechanism_declared"] == ["bot:helper", "person-a"]
    assert result["both_rates_zero_declared"] == []
    assert json.loads(certificate)["result"] == result


OBSERVED_ONLY = {
    # HUMAN-3.2 is not in HUMAN-4.3's dependency column: both zero is observed, not decided.
    "both_rates_zero": (declared(false_match_rate="0", false_non_match_rate="0.000"),
                        "both_rates_zero_declared", ["person-a"],
                        "deduplication_mechanism_declared", ["bot:helper", "person-a"]),
    # HUMAN-3.5 is not in HUMAN-4.3's dependency column: a mechanism is observed, not required.
    "deduplication_undeclared": (declared(deduplication_mechanism=None),
                                 "deduplication_mechanism_declared", ["bot:helper"],
                                 "both_rates_zero_declared", []),
    "deduplication_key_absent": (declared(deduplication_mechanism=...),
                                 "deduplication_mechanism_declared", ["bot:helper"],
                                 "both_rates_zero_declared", []),
    "deduplication_blank": (declared(deduplication_mechanism="   "),
                            "deduplication_mechanism_declared", ["bot:helper"],
                            "both_rates_zero_declared", []),
}


@pytest.mark.parametrize("name", sorted(OBSERVED_ONLY))
def test_observation_alone_never_decides_the_verdict(name):
    person_a, field, expected, other_field, other_expected = OBSERVED_ONLY[name]
    objects = records(person_a)
    assert oracle(objects, ALL_CLASSES) == "PASS"
    request, policy, evidence = selected(objects)
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    assert result["population_declaration"] == "PASS"
    assert result[field] == expected
    assert result[other_field] == other_expected
    observed = result["evaluation"]["observations"]["assertions"]
    assert observed[field] == expected
    for not_decided in NOT_DECIDED_HERE:
        assert result[not_decided] == "NOT_ESTABLISHED"
    assert result["uniqueness_claim"] == "NOT_ESTABLISHED"
    assert result["closure_result"] == "NOT_ESTABLISHED"
    assert json.loads(certificate)["result"] == result


MUTANTS = {
    "population_undeclared": (records(declared(enrollment_population=None)),
                              ALL_CLASSES, "enrollment population"),
    "population_key_absent": (records(declared(enrollment_population=...)),
                              ALL_CLASSES, "enrollment population"),
    "operating_point_undeclared": (records(declared(operating_point=None)),
                                   ALL_CLASSES, "operating point"),
    "evidence_class_undeclared": (records(declared(evidence_class=None)),
                                  ALL_CLASSES, "evidence class"),
    "evidence_class_not_admitted": (records(), {"biometric"}, "evidence class"),
    "global_population_claim": (records(declared(enrollment_population="Worldwide")),
                                ALL_CLASSES, "not an exact enrollment population (HUMAN-4.3)"),
    "all_humans_population_claim": (records(declared(enrollment_population=" All Humans ")),
                                    ALL_CLASSES, "not an exact enrollment population (HUMAN-4.3)"),
    "rate_as_binary_float": (records(declared(false_match_rate=0.0001)),
                             ALL_CLASSES, "exact decimal"),
    "rate_above_one": (records(declared(false_non_match_rate="1.25")),
                       ALL_CLASSES, "[0, 1]"),
    "bot_labelled_human_record_undeclared": (records(helper=declared(
        enrollment_population=None)), ALL_CLASSES, "bot:helper"),
}


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_each_refuting_mutant_fails_for_its_own_reason(name):
    objects, admitted, reason = MUTANTS[name]
    assert oracle(objects, admitted) == "FAIL"
    request, policy, evidence = selected(objects, admitted=sorted(admitted))
    _, result = replay(request, policy, evidence)
    assert result["status"] == "FAIL"
    assert result["population_declaration"] == "NOT_ESTABLISHED"
    assert result["uniqueness_claim"] == "NOT_ESTABLISHED"
    assert result["closure_result"] == "NOT_ESTABLISHED"
    for not_decided in NOT_DECIDED_HERE:
        assert result[not_decided] == "NOT_ESTABLISHED"
    assert result["deduplication_mechanism_declared"] == "NOT_OBSERVED"
    assert result["both_rates_zero_declared"] == "NOT_OBSERVED"
    details = result["evaluation"]["details"]
    assert reason in details, details
    assert "HUMAN-3.2" not in details and "deduplication" not in details, details


def test_label_does_not_make_a_bot_an_assertion_or_the_subject():
    request, policy, evidence = selected(subject_id="human:courier")
    _, result = replay(request, policy, evidence)
    assert result["status"] == "FAIL"
    assert "differs from external selection" in result["evaluation"]["details"]
    request, policy, evidence = selected(subject_id="bot:helper")
    assert replay(request, policy, evidence)[1]["status"] == "PASS"


def test_budget_exhaustion_remains_unknown():
    request, policy, evidence = selected(limits={"max_operations": 8})
    assert replay(request, policy, evidence)[1]["status"] == "UNKNOWN"
    assert replay(request, policy, None)[1]["status"] == "UNKNOWN"


def test_unsupported_admitted_class_policy_is_rejected_before_replay():
    with pytest.raises(hpd.HumanPopulationDeclarationError):
        hpd.human_population_declaration_policy(
            trust_roots=["human-root"], admitted_evidence_classes=["self-declared"])
    with pytest.raises(hpd.HumanPopulationDeclarationError):
        hpd.human_population_declaration_policy(
            trust_roots=["human-root"], admitted_evidence_classes=[])


@pytest.mark.parametrize("fraction", [0.1, 0.5, 0.9])
def test_one_bit_flip_in_certificate_is_refused(fraction):
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    flipped = bytearray(certificate)
    flipped[int(len(flipped) * fraction)] ^= 0x01
    with pytest.raises(hpd.HumanPopulationDeclarationError):
        hpd.recheck_human_population_declaration_certificate(
            bytes(flipped), expected_request=request, policy=policy)


def test_substituted_subject_request_policy_and_forged_verdict_are_refused():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    other_request = deepcopy(request)
    other_request["subject_id"] = "bot:helper"
    with pytest.raises(hpd.HumanPopulationDeclarationError):
        hpd.recheck_human_population_declaration_certificate(
            certificate, expected_request=other_request, policy=policy)
    narrower = hpd.human_population_declaration_policy(
        trust_roots=["human-root"], admitted_evidence_classes=["biometric"])
    with pytest.raises(hpd.HumanPopulationDeclarationError):
        hpd.recheck_human_population_declaration_certificate(
            certificate, expected_request=request, policy=narrower)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(hpd.HumanPopulationDeclarationError):
        hpd.recheck_human_population_declaration_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)
    malformed = deepcopy(request)
    malformed["coordinate"] = "HUMAN-4.6"
    with pytest.raises(hpd.HumanPopulationDeclarationError):
        hpd.build_human_population_declaration_certificate(malformed, evidence, policy=policy)


def test_inventory_slot_names_this_recheck():
    slot = get_slot("HUMAN", 4)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.mechanized_route["artifact_coordinate"] == "HUMAN-4.3"
    assert slot.mechanized_route["checking_mechanism"] == (
        "verifier.domains.contracts.human_population_declaration."
        "recheck_human_population_declaration_certificate")


def test_public_route_and_command_replay_population_declaration(tmp_path: Path, capsys):
    from verifier.runtime.public_cli import main

    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=hpd.SEMANTIC_VERSION,
        objective=hpd.COORDINATE, represented_kind="HUMAN",
        expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["closure_result"] == "NOT_ESTABLISHED"
    for name, contents in (("request", canonical_bytes(request)),
                           ("policy", canonical_bytes(policy)),
                           ("certificate", certificate)):
        (tmp_path / (name + ".json")).write_bytes(contents)
    code = main(["current-object", "check", str(tmp_path / "certificate.json"),
                 "--semantic-version", hpd.SEMANTIC_VERSION,
                 "--objective", hpd.COORDINATE, "--represented-kind", "HUMAN",
                 "--request", str(tmp_path / "request.json"),
                 "--policy", str(tmp_path / "policy.json"), "--json"])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["computational_status"] == "PASS"


@pytest.mark.parametrize("relative", [
    "domains/contracts/human_population_declaration.py",
    "standard/CURRENT_HUMAN_POPULATION_DECLARATION.md",
    "standard/NAMESPACE_OBJECTS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    target = Path(hpd.__file__).parents[2] / relative
    original = Path.read_bytes

    def changed(path):
        data = original(path)
        return data + b"\nchanged selected dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        hpd.recheck_human_population_declaration_certificate(
            certificate, expected_request=request, policy=policy)


def _obligation_rows() -> dict[str, str]:
    """Requirement cells of the HUMAN table rows, read from the shipped standard."""
    text = (Path(hpd.__file__).parents[2] / "standard" / "DOMAIN_OBLIGATIONS.md").read_text(encoding="utf-8")
    rows = {}
    for line in text.splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if len(cells) >= 3 and cells[0].startswith("HUMAN-"):
            rows[cells[0]] = cells[2]
    return rows


def test_proposition_quotes_its_obligation_rows_verbatim():
    rows = _obligation_rows()
    spec = (Path(hpd.__file__).parents[2] / "standard" / "CURRENT_HUMAN_POPULATION_DECLARATION.md").read_text(encoding="utf-8")
    quoted = {hpd.COORDINATE: hpd.ROW, **hpd.PREREQUISITE_ROWS, **hpd.CITED_ROWS}
    for coordinate, text in quoted.items():
        assert rows[coordinate] == text, coordinate
        assert '"' + text + '"' in spec, coordinate
    assert hpd.registration()["obligation_row"] == rows[hpd.COORDINATE]
    # HUMAN-4.6 is quoted so the spec can say why its closure never PASSes here.
    assert '"' + rows["HUMAN-4.6"] + '"' in spec


def test_verdict_conjuncts_name_only_the_row_and_its_listed_dependencies():
    """The decided proposition draws on HUMAN-4.3, 4.1 and 4.2; 3.2 and 3.5 are never decided."""
    proposition = hpd.registration()["proposition"]
    assert set(hpd.PREREQUISITE_ROWS) == {"HUMAN-4.1", "HUMAN-4.2"}
    assert "deduplication" not in proposition
    assert "both zero" not in proposition and "not both" not in proposition
    assert "HUMAN-3.2" not in proposition
    spec = (Path(hpd.__file__).parents[2] / "standard" / "CURRENT_HUMAN_POPULATION_DECLARATION.md").read_text(encoding="utf-8")
    for field in ("`human_3_2`", "`human_3_5`", "`deduplication_mechanism_declared`",
                  "`both_rates_zero_declared`"):
        assert field in spec, field
