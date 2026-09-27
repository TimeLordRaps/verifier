"""Retained hardware arithmetic is not physical attestation or credit authority.

Terminology: central processing unit (CPU); graphics processing unit (GPU);
quantum processing unit (QPU).
"""
from copy import deepcopy

import pytest

from verifier import domain_policy, domain_request, build_domain_certificate, recheck_domain_certificate
from verifier.domains.common import digest


def specimen():
    devices = [
        {"id": "gpu", "kind": "GPU", "capacities": {"MEMORY_BYTE": 8, "COMPUTE_SLOT": 2}},
        {"id": "disk", "kind": "STORAGE", "capacities": {"STORAGE_BYTE": 20}},
        {"id": "sensor", "kind": "SENSOR", "capacities": {"SAMPLE_SLOT": 1}},
    ]
    topology = [{"parent": "gpu", "child": "sensor"}]
    allocations = [
        {"id": "a", "device": "gpu", "unit": "COMPUTE_SLOT", "quantity": 2, "start_us": 0, "end_us": 10},
        {"id": "b", "device": "gpu", "unit": "COMPUTE_SLOT", "quantity": 2, "start_us": 10, "end_us": 20},
    ]
    measurements = [{"id": "m", "device": "gpu", "unit": "MEMORY_BYTE", "quantity": 4, "at_us": 5}]
    inputs = dict(devices=devices, topology=topology, allocations=allocations, measurements=measurements)
    return {"schema_version": "verifier-domain-evidence-1", "domain": "HARDWARE", "subject_id": "retained:hardware",
            "artifact": {"scope": "retained-hardware-records", "clock": "declared-monotonic-microseconds",
                         **{key + "_digest": digest(value) for key, value in inputs.items()}}, "inputs": inputs}


def certificate(value):
    policy = domain_policy(trust_roots=["test:retained-records-only"])
    request = domain_request(value)
    cert = build_domain_certificate(request, value, policy=policy)
    assert recheck_domain_certificate(cert, expected_request=request, policy=policy)["status"] == cert["result"]["status"]
    return cert


def test_native_hardware_replays_without_physical_promotion():
    cert = certificate(specimen())
    assert cert["result"]["status"] == "PASS"
    assert cert["result"]["domain_depth"] == 4
    assert cert["result"]["object_profile_conformance"] == "NOT_ESTABLISHED"
    observations = cert["result"]["checks"]["HARDWARE-1.1"]["evaluation"]["observations"]
    assert observations["physical_authenticity"] == "NOT_ESTABLISHED"
    assert observations["credit_authority"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("change", ["overbook", "cycle", "unknown_device", "wrong_unit", "negative", "boolean", "empty_interval", "duplicate", "overmeasure"])
def test_rehashed_bad_hardware_records_are_refuted(change):
    value = specimen()
    if change == "overbook": value["inputs"]["allocations"][1]["start_us"] = 9
    if change == "cycle": value["inputs"]["topology"].append({"parent": "sensor", "child": "gpu"})
    if change == "unknown_device": value["inputs"]["allocations"][0]["device"] = "foreign"
    if change == "wrong_unit": value["inputs"]["allocations"][0]["unit"] = "STORAGE_BYTE"
    if change == "negative": value["inputs"]["devices"][0]["capacities"]["MEMORY_BYTE"] = -1
    if change == "boolean": value["inputs"]["allocations"][0]["quantity"] = True
    if change == "empty_interval": value["inputs"]["allocations"][0]["end_us"] = 0
    if change == "duplicate": value["inputs"]["devices"].append(deepcopy(value["inputs"]["devices"][0]))
    if change == "overmeasure": value["inputs"]["measurements"][0]["quantity"] = 9
    for key, records in value["inputs"].items(): value["artifact"][key + "_digest"] = digest(records)
    assert certificate(value)["result"]["status"] == "FAIL"


def test_missing_measurement_stays_unknown_and_tamper_is_rejected():
    value = specimen()
    del value["inputs"]["measurements"]
    assert certificate(value)["result"]["status"] == "UNKNOWN"
    value = specimen()
    value["inputs"]["devices"][0]["kind"] = "CPU"
    assert certificate(value)["result"]["status"] == "FAIL"


def test_physical_attestation_scope_is_not_accepted_as_retained_consistency():
    value = specimen()
    value["artifact"]["scope"] = "physical-hardware-attested"
    assert certificate(value)["result"]["status"] == "UNKNOWN"


def test_reservation_sweep_matches_independent_integer_time_oracle():
    """Enumerate occupancy at every integer instant instead of sorting events."""
    import random

    rng = random.Random(20260927)
    outcomes = set()
    for trial in range(40):
        value = specimen()
        intervals = []
        for index in range(rng.randint(1, 7)):
            start = rng.randrange(8)
            intervals.append({"id": str(index), "device": "gpu", "unit": "COMPUTE_SLOT",
                              "quantity": rng.randint(1, 2), "start_us": start,
                              "end_us": rng.randint(start + 1, 10)})
        expected = all(sum(r["quantity"] for r in intervals
                           if r["start_us"] <= instant < r["end_us"]) <= 2
                       for instant in range(10))
        outcomes.add(expected)
        # A clock-origin shift and record permutation must preserve occupancy.
        if trial % 2:
            rng.shuffle(intervals)
            for row in intervals:
                row["start_us"] += 100
                row["end_us"] += 100
        value["inputs"]["allocations"] = intervals
        value["artifact"]["allocations_digest"] = digest(intervals)
        assert certificate(value)["result"]["status"] == ("PASS" if expected else "FAIL")
    assert outcomes == {False, True}, "the oracle exercises accepted and rejected schedules"


def test_typed_capacities_do_not_pool_across_devices_or_units():
    value = specimen()
    value["inputs"]["devices"].append(
        {"id": "other", "kind": "QPU", "capacities": {"COMPUTE_SLOT": 100}})
    value["inputs"]["allocations"][0]["quantity"] = 3
    for key, records in value["inputs"].items():
        value["artifact"][key + "_digest"] = digest(records)
    assert certificate(value)["result"]["status"] == "FAIL"
