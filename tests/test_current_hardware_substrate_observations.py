"""Current HARDWARE-3.1 retained qualified substrate-observation records.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); platform configuration register (PCR). Instants
and freshness bounds are integer microseconds on one named clock. Register
values and event digests are 32-byte SHA-256 outputs written as 64 lowercase
hexadecimal characters; register indices and counts are dimensionless.

The governing row (DOMAIN_OBLIGATIONS.md, HARDWARE-3.1) reads: "Device
identity, physical capacity, calibration, sensor accuracy and live
availability require qualified observations with explicit freshness and trust
roots; declarations alone remain UNKNOWN."

The oracle below decides each fixture with plain loops, json and hashlib,
independently of the mechanism under test. Nothing here claims a device,
signature, clock or physical quantity is genuine.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import hardware_substrate_observations as obs
from verifier.domains.inventory import get_slot


CLOCK = "lab-monotonic-clock"
AT = 1_500_000
ROOTS = ["lab-attestor", "vendor-root"]
REGISTERS = [0, 4, 7]


def digest(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def exact(value: object) -> str:
    """Exact JSON text, so True and 1 stay different values."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def event(register: int, data: bytes) -> dict:
    return {"register": register,
            "event": base64.b64encode(data).decode("ascii"),
            "event_digest": hashlib.sha256(data).hexdigest()}


def base_events() -> list[dict]:
    return [event(0, b"core root of trust v1.0"),
            event(0, b"platform firmware volume"),
            event(4, b"boot loader stage one"),
            event(4, b"boot loader stage two"),
            event(0, b"option memory configuration")]


def chain(registers: list[int], events: list[dict]) -> dict[int, str] | None:
    """Independent replay: PCR_new = SHA-256(PCR_old || event_digest)."""
    values = {register: b"\x00" * 32 for register in registers}
    for row in events:
        data = base64.b64decode(row["event"])
        if (row["register"] not in values
                or hashlib.sha256(data).hexdigest() != row["event_digest"]):
            return None
        values[row["register"]] = hashlib.sha256(
            values[row["register"]] + bytes.fromhex(row["event_digest"])).digest()
    return {register: value.hex() for register, value in values.items()}


def quote_of(events: list[dict], registers: list[int] = REGISTERS) -> list[dict]:
    values = chain(registers, events)
    return [{"register": register, "value": values[register]} for register in registers]


def base_claims() -> list[dict]:
    return [
        {"claim_id": "boot-measurements", "category": "device_identity",
         "value": quote_of(base_events())},
        {"claim_id": "core-voltage-calibration", "category": "calibration",
         "value": {"unit": "volt", "offset": {"num": 1, "den": 200}}},
        {"claim_id": "memory-capacity", "category": "physical_capacity",
         "value": {"unit": "MEMORY_BYTE", "quantity": 17179869184}},
        {"claim_id": "serial", "category": "device_identity",
         "value": "SN-0042-ALPHA"},
        {"claim_id": "thermal-sensor-accuracy", "category": "sensor_accuracy",
         "value": {"unit": "kelvin", "half_width": {"num": 1, "den": 4}}},
        {"claim_id": "uplink-available", "category": "live_availability",
         "value": True},
    ]


def observation(observation_id: str, claim_id: str, value: object, *,
                root: str = "lab-attestor", clock: str = CLOCK,
                start: int = 1_000_000, end: int = 2_000_000,
                events: list[dict] | None = None) -> dict:
    return {"observation_id": observation_id, "claim_id": claim_id,
            "value": value, "clock": clock, "fresh_from_us": start,
            "fresh_until_us": end, "trust_root": root,
            "measured_boot": None if events is None else {"events": events}}


def base_observations() -> list[dict]:
    rows = []
    for claim in base_claims():
        if claim["claim_id"] == "boot-measurements":
            rows.append(observation("obs-boot", claim["claim_id"], claim["value"],
                                    root="vendor-root", events=base_events()))
        else:
            rows.append(observation("obs-" + claim["claim_id"], claim["claim_id"],
                                    claim["value"]))
    return rows


def qualifies(row: dict, at: int, clock: str, roots: list[str]) -> bool:
    return (row["clock"] == clock and row["fresh_from_us"] <= at <= row["fresh_until_us"]
            and row["trust_root"] in roots)


def oracle(claims: list[dict], observations: list[dict], *, at: int = AT,
           clock: str = CLOCK, roots: list[str] = ROOTS) -> str:
    """FAIL only for what no further retained evidence could repair."""
    declared = {claim["claim_id"]: claim["value"] for claim in claims}
    if not declared:
        return "UNKNOWN"
    for row in observations:
        if row["claim_id"] not in declared or row["fresh_from_us"] > row["fresh_until_us"]:
            return "FAIL"
        if row["measured_boot"] is not None:
            registers = [item["register"] for item in row["value"]]
            values = chain(registers, row["measured_boot"]["events"])
            if values is None or [{"register": r, "value": values[r]}
                                  for r in registers] != row["value"]:
                return "FAIL"
        if (qualifies(row, at, clock, roots)
                and exact(row["value"]) != exact(declared[row["claim_id"]])):
            return "FAIL"
    covered = {row["claim_id"] for row in observations if qualifies(row, at, clock, roots)}
    return "PASS" if covered == set(declared) else "UNKNOWN"


def selected(claims: list[dict] | None = None, observations: list[dict] | None = None,
             *, include_inputs: bool = True, limits: dict | None = None,
             subject_id: str = "hardware-a", at: int = AT, clock: str = CLOCK):
    claims = base_claims() if claims is None else claims
    observations = base_observations() if observations is None else observations
    payload = {"scope": obs.SUBJECT_SCOPE, "claims_digest": digest(claims),
               "observations_digest": digest(observations)}
    subject = NamespaceObject.create("hardware-a", "HARDWARE", payload)
    sibling = NamespaceObject.create("hardware-b", "HARDWARE", payload)
    objects = [subject, sibling]
    evidence = {"schema_version": obs.EVIDENCE_VERSION,
                "objects": [item.to_dict() for item in objects],
                "inputs": {"claims": claims, "observations": observations}
                if include_inputs else None}
    by_id = {item.object_id: item for item in objects}
    policy = obs.hardware_substrate_observations_policy(trust_roots=list(ROOTS))
    request = obs.hardware_substrate_observations_request(
        subject_id=subject_id, object_digest=by_id[subject_id].digest,
        collection_digest=composition_digest(objects), evaluation_clock=clock,
        evaluation_at_us=at, evidence_ref=digest(evidence), policy=policy,
        limits=limits)
    return request, policy, canonical_bytes(evidence)


def replay(request: dict, policy: dict, evidence: bytes):
    certificate = obs.build_hardware_substrate_observations_certificate(
        request, evidence, policy=policy)
    result = obs.recheck_hardware_substrate_observations_certificate(
        certificate, expected_request=request, policy=policy)
    return certificate, result


SCOPE_FIELD = "qualified_observation_record_coverage"
EXCLUDED = ("device_identity", "physical_capacity", "calibration",
            "sensor_accuracy", "live_availability", "observation_authenticity",
            "quote_signature_authenticity", "event_log_completeness",
            "clock_authenticity", "legacy_hardware_statics",
            "hardware_statics_tier_conformance", "object_profile_conformance",
            "privacy", "consent", "governance", "security")


def verdict(claims=None, observations=None, **kwargs) -> dict:
    return replay(*selected(claims, observations, **kwargs))[1]


def test_inventory_selects_qualified_observations_for_hardware_statics_slot():
    slot = get_slot("HARDWARE", 3)
    assert slot.mechanized and slot.status == "REPLAYABLE"
    assert slot.coordinate == obs.COORDINATE == "HARDWARE-3.1"
    assert slot.mechanized_route["artifact_coordinate"] == "HARDWARE-3.1"
    assert slot.mechanized_route["checking_mechanism"] == (
        "verifier.domains.contracts.hardware_substrate_observations."
        "recheck_hardware_substrate_observations_certificate")
    assert slot.mechanized_route["resulting_evidence"] == obs.CERTIFICATE_VERSION


def test_every_claim_qualified_and_replayed_passes_and_rechecks_from_bytes():
    assert oracle(base_claims(), base_observations()) == "PASS"
    # Register 7 has no event and must still equal 32 zero bytes.
    assert base_claims()[0]["value"][2]["value"] == "00" * 32
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS", result["evaluation"]
    assert result[SCOPE_FIELD] == "PASS"
    for field in EXCLUDED:
        assert result[field] == "NOT_ESTABLISHED", field
    assert json.loads(certificate.decode("utf-8"))["result"] == result
    again = obs.recheck_hardware_substrate_observations_certificate(
        bytes(certificate), expected_request=json.loads(canonical_bytes(request)),
        policy=json.loads(canonical_bytes(policy)))
    assert again == result
    assert certificate == obs.build_hardware_substrate_observations_certificate(
        request, evidence, policy=policy)


def test_declarations_alone_remain_unknown_never_pass():
    assert oracle(base_claims(), []) == "UNKNOWN"
    result = verdict(observations=[])
    assert result["status"] == "UNKNOWN", result["evaluation"]
    assert result[SCOPE_FIELD] == "NOT_ESTABLISHED"
    for field in EXCLUDED:
        assert result[field] == "NOT_ESTABLISHED", field
    absent = verdict(include_inputs=False)
    assert absent["status"] == "UNKNOWN" and absent[SCOPE_FIELD] == "NOT_ESTABLISHED"
    empty = verdict(claims=[], observations=[])
    assert empty["status"] == "UNKNOWN" and empty[SCOPE_FIELD] == "NOT_ESTABLISHED"


def _with(index: int, **changes) -> list[dict]:
    rows = base_observations()
    rows[index].update(changes)
    return rows


SERIAL = 3  # index of the serial observation in base_observations()

UNQUALIFIED = {
    "stale_before_instant": _with(SERIAL, fresh_until_us=AT - 1),
    "not_yet_fresh": _with(SERIAL, fresh_from_us=AT + 1),
    "trust_root_not_admitted": _with(SERIAL, trust_root="self-declared"),
    "other_clock": _with(SERIAL, clock="wall-clock"),
    "claim_without_observation": base_observations()[:SERIAL] + base_observations()[SERIAL + 1:],
    "stale_record_disagrees": _with(SERIAL, fresh_until_us=AT - 1, value="SN-9999-OTHER"),
}


@pytest.mark.parametrize("name", sorted(UNQUALIFIED))
def test_unqualified_observation_leaves_claim_on_declaration_unknown(name):
    rows = UNQUALIFIED[name]
    assert oracle(base_claims(), rows) == "UNKNOWN"
    result = verdict(observations=rows)
    assert result["status"] == "UNKNOWN", result["evaluation"]
    assert result[SCOPE_FIELD] == "NOT_ESTABLISHED"


def test_closed_freshness_interval_includes_both_endpoints():
    for rows in (_with(SERIAL, fresh_from_us=AT), _with(SERIAL, fresh_until_us=AT),
                 _with(SERIAL, fresh_from_us=AT, fresh_until_us=AT)):
        assert oracle(base_claims(), rows) == "PASS"
        assert verdict(observations=rows)["status"] == "PASS"


def test_a_later_externally_selected_instant_leaves_every_claim_unknown():
    assert oracle(base_claims(), base_observations(), at=2_000_001) == "UNKNOWN"
    assert verdict(at=2_000_001)["status"] == "UNKNOWN"
    assert verdict(clock="wall-clock")["status"] == "UNKNOWN"


def _boot_events(mutate) -> list[dict]:
    rows = base_observations()
    events = base_events()
    mutate(events)
    rows[0]["measured_boot"] = {"events": events}
    return rows


def _alter_bytes_keep_digest(events):
    events[1]["event"] = base64.b64encode(b"platform firmware volume, patched").decode("ascii")


def _swap_same_register(events):
    events[0], events[1] = events[1], events[0]


def _drop(events):
    del events[2]


def _move_to_quoted_register(events):
    events[3]["register"] = 7


def _extend_unquoted_register(events):
    events[3]["register"] = 9


def _substitute_consistent(events):
    events[2] = event(4, b"unsigned boot loader stage one")


def _flip_quote_bit() -> tuple[list[dict], list[dict]]:
    claims, rows = base_claims(), base_observations()
    flipped = bytearray(bytes.fromhex(claims[0]["value"][1]["value"]))
    flipped[0] ^= 0x01
    claims[0]["value"][1]["value"] = flipped.hex()
    rows[0]["value"] = deepcopy(claims[0]["value"])
    return claims, rows


def _contradict(index: int, value: object) -> tuple[list[dict], list[dict]]:
    return base_claims(), _with(index, value=value)


MUTANTS = {
    "qualified_serial_contradicts_claim": _contradict(SERIAL, "SN-0043-ALPHA"),
    "qualified_capacity_contradicts_claim": _contradict(
        2, {"unit": "MEMORY_BYTE", "quantity": 8589934592}),
    "qualified_availability_true_vs_one": _contradict(5, 1),
    "event_bytes_altered_digest_kept": (base_claims(), _boot_events(_alter_bytes_keep_digest)),
    "same_register_events_swapped": (base_claims(), _boot_events(_swap_same_register)),
    "event_dropped": (base_claims(), _boot_events(_drop)),
    "event_moved_to_other_quoted_register": (base_claims(), _boot_events(_move_to_quoted_register)),
    "event_extends_unquoted_register": (base_claims(), _boot_events(_extend_unquoted_register)),
    "component_substituted_with_consistent_digest": (base_claims(), _boot_events(_substitute_consistent)),
    "quote_bit_flipped_in_claim_and_record": _flip_quote_bit(),
    "observation_names_no_retained_claim": (base_claims(), _with(SERIAL, claim_id="serial-2")),
    "inverted_freshness_interval": (base_claims(), _with(SERIAL, fresh_from_us=AT + 1, fresh_until_us=AT - 1)),
}


@pytest.mark.parametrize("name", sorted(MUTANTS))
def test_refuting_mutants_fail_with_consistent_commitments(name):
    claims, rows = MUTANTS[name]
    assert oracle(claims, rows) == "FAIL"
    result = verdict(claims, rows)
    assert result["status"] == "FAIL", result["evaluation"]
    assert result[SCOPE_FIELD] == "NOT_ESTABLISHED"


def test_stale_measured_boot_record_that_cannot_replay_still_fails():
    rows = _boot_events(_drop)
    rows[0]["fresh_until_us"] = AT - 1
    assert oracle(base_claims(), rows) == "FAIL"
    assert verdict(observations=rows)["status"] == "FAIL"


def test_empty_log_replays_only_to_the_zero_quote():
    zero = [{"register": 0, "value": "00" * 32}]
    claims = [{"claim_id": "boot-measurements", "category": "device_identity", "value": zero}]
    rows = [observation("obs-boot", "boot-measurements", zero, root="vendor-root", events=[])]
    assert oracle(claims, rows) == "PASS"
    assert verdict(claims, rows)["status"] == "PASS"
    nonzero = [{"register": 0, "value": "11" * 32}]
    claims[0]["value"] = nonzero
    rows[0]["value"] = deepcopy(nonzero)
    assert oracle(claims, rows) == "FAIL"
    assert verdict(claims, rows)["status"] == "FAIL"


@pytest.mark.parametrize("limits", [
    {"max_claims": 2}, {"max_observations": 2}, {"max_events": 2},
    {"max_event_bytes": 16}, {"max_operations": 8},
])
def test_exhausted_budget_remains_unknown(limits):
    result = verdict(limits=limits)
    assert result["status"] == "UNKNOWN", result["evaluation"]
    assert result[SCOPE_FIELD] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("fraction", [0.0, 0.25, 0.5, 0.75, 0.999])
def test_one_flipped_certificate_bit_is_rejected(fraction):
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    tampered = bytearray(certificate)
    tampered[int(len(tampered) * fraction)] ^= 0x01
    with pytest.raises(obs.HardwareSubstrateObservationsError):
        obs.recheck_hardware_substrate_observations_certificate(
            bytes(tampered), expected_request=request, policy=policy)


def test_wrong_subject_instant_policy_or_evidence_is_refused():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    for other in (selected(subject_id="hardware-b")[0], selected(at=AT + 1)[0],
                  selected(clock="wall-clock")[0]):
        with pytest.raises(obs.HardwareSubstrateObservationsError):
            obs.recheck_hardware_substrate_observations_certificate(
                certificate, expected_request=other, policy=policy)
    other_policy = obs.hardware_substrate_observations_policy(trust_roots=["lab-attestor"])
    with pytest.raises(obs.HardwareSubstrateObservationsError):
        obs.recheck_hardware_substrate_observations_certificate(
            certificate, expected_request=request, policy=other_policy)
    with pytest.raises(obs.HardwareSubstrateObservationsError):
        obs.build_hardware_substrate_observations_certificate(
            request, evidence + b" ", policy=policy)
    with pytest.raises(obs.HardwareSubstrateObservationsError):
        obs.hardware_substrate_observations_request(
            subject_id="hardware-a", object_digest=request["object_digest"],
            collection_digest=request["collection_digest"], evaluation_clock=CLOCK,
            evaluation_at_us=-1, evidence_ref=request["evidence_ref"], policy=policy)
    forged = json.loads(certificate)
    forged["result"]["status"] = "FAIL"
    forged.pop("digest")
    forged["digest"] = digest(forged)
    with pytest.raises(obs.HardwareSubstrateObservationsError):
        obs.recheck_hardware_substrate_observations_certificate(
            canonical_bytes(forged), expected_request=request, policy=policy)


def test_narrower_admitted_root_set_turns_vendor_record_unknown():
    rows = base_observations()
    assert oracle(base_claims(), rows, roots=["lab-attestor"]) == "UNKNOWN"
    claims = base_claims()
    payload = {"scope": obs.SUBJECT_SCOPE, "claims_digest": digest(claims),
               "observations_digest": digest(rows)}
    objects = [NamespaceObject.create("hardware-a", "HARDWARE", payload)]
    evidence = {"schema_version": obs.EVIDENCE_VERSION,
                "objects": [item.to_dict() for item in objects],
                "inputs": {"claims": claims, "observations": rows}}
    policy = obs.hardware_substrate_observations_policy(trust_roots=["lab-attestor"])
    request = obs.hardware_substrate_observations_request(
        subject_id="hardware-a", object_digest=objects[0].digest,
        collection_digest=composition_digest(objects), evaluation_clock=CLOCK,
        evaluation_at_us=AT, evidence_ref=digest(evidence), policy=policy)
    assert replay(request, policy, canonical_bytes(evidence))[1]["status"] == "UNKNOWN"


def test_public_route_replays_pass_and_refuses_other_kind():
    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    report = routes.replay_current_object_certificate(
        certificate, semantic_version=obs.SEMANTIC_VERSION,
        objective=obs.COORDINATE, represented_kind="HARDWARE",
        expected_request=request, policy=policy)
    assert report["computational_status"] == "PASS"
    assert report["native_result"]["device_identity"] == "NOT_ESTABLISHED"
    assert report["native_result"]["quote_signature_authenticity"] == "NOT_ESTABLISHED"
    with pytest.raises(routes.CurrentObjectRouteRefusal):
        routes.replay_current_object_certificate(
            certificate, semantic_version=obs.SEMANTIC_VERSION,
            objective=obs.COORDINATE, represented_kind="OBJECT",
            expected_request=request, policy=policy)


def test_retained_certificate_refuses_evidence_redaction():
    from verifier.privacy import (DisclosureBound, DisclosureSurface,
        EmissionContext, EmissionEvaluator, EmissionRefusalError, ObserverParty)

    request, policy, evidence = selected()
    certificate, _ = replay(request, policy, evidence)
    retained = json.loads(certificate)
    fields = tuple(key for key in retained if key != "evidence_payloads")
    surface = DisclosureSurface("HARDWARE", fields, ("evidence_payloads",))
    bounds = tuple(DisclosureBound(key, key, admitted_observers=("reader",))
                   for key in fields)
    context = EmissionContext(ObserverParty("reader", "auditor", "inspect"),
                              "test-time")
    with pytest.raises(EmissionRefusalError):
        EmissionEvaluator().evaluate_emission(retained, surface, bounds, context)


@pytest.mark.parametrize("relative", [
    "domains/contracts/hardware_substrate_observations.py",
    "domains/contracts/retained_selection.py",
    "standard/CURRENT_HARDWARE_SUBSTRATE_OBSERVATIONS.md",
    "standard/NAMESPACE_OBJECTS.md",
])
def test_changed_direct_dependency_invalidates_selected_policy(relative, monkeypatch):
    request, policy, evidence = selected()
    certificate, result = replay(request, policy, evidence)
    assert result["status"] == "PASS"
    target = Path(obs.__file__).parents[2] / relative
    original = Path.read_bytes

    def changed(path):
        data = original(path)
        return data + b"\nchanged selected dependency\n" if path == target else data

    monkeypatch.setattr(Path, "read_bytes", changed)
    with pytest.raises(ValueError, match="installed mechanism"):
        obs.recheck_hardware_substrate_observations_certificate(
            certificate, expected_request=request, policy=policy)
