"""Retained execution environment (ENV) resource counts are exact integers.

These checks constrain supplied observations, not operating-system enforcement.
"""
from __future__ import annotations

import base64
import hashlib

import pytest

from verifier.domains.certification import (
    build_domain_certificate, domain_policy, domain_request, recheck_domain_certificate,
)
from verifier.domains.common import digest


def _bundle() -> dict:
    source = b"retained program bytes"
    file_digest = "sha256:" + hashlib.sha256(source).hexdigest()
    inventory = {"program": file_digest}
    configuration = {"collector": "test retained record"}
    inputs, output = [1], [2]
    executions = [
        {"id": identifier, "software_digest": digest(inventory),
         "configuration_digest": digest(configuration), "executable": "program",
         "input": inputs, "output": output, "exit_code": 0}
        for identifier in ("first", "second")
    ]
    return {
        "schema_version": "verifier-domain-evidence-1", "domain": "ENV",
        "subject_id": "test:resource-counts",
        "artifact": {
            "scope": "retained-process-observations", "files": inventory,
            "configuration": configuration, "execution_ids": ["first", "second"],
            "ceilings": {"wall_seconds": 0.75, "memory_bytes": 16, "threads": 2},
            "execution": {"executable": "program", "input_digest": digest(inputs),
                          "output_digest": digest(output)},
        },
        "inputs": {
            "files": {"program": {"sha256": file_digest,
                                    "base64": base64.b64encode(source).decode("ascii")}},
            "configuration": configuration, "executions": executions,
            "measurements": [{"id": identifier, "wall_seconds": 0.25,
                              "memory_bytes": 8, "threads": 1}
                             for identifier in ("first", "second")],
        },
    }


def _assess(bundle: dict) -> tuple[dict, dict, dict]:
    policy = domain_policy(trust_roots=["test:retained-resource-observations"])
    request = domain_request(bundle)
    certificate = build_domain_certificate(request, bundle, policy=policy)
    return certificate, request, policy


@pytest.mark.parametrize("field", ("threads", "memory_bytes"))
@pytest.mark.parametrize("location", ("ceiling", "measurement"))
@pytest.mark.parametrize("value", (0.5, 1.0, True, -1),
                         ids=("fraction", "floating-integer", "boolean", "negative"))
def test_resource_counts_refute_noninteger_or_negative_values(
    field: str, location: str, value: object,
) -> None:
    bundle = _bundle()
    target = (bundle["artifact"]["ceilings"] if location == "ceiling"
              else bundle["inputs"]["measurements"][0])
    target[field] = value
    if location == "ceiling":
        # Isolate the ceiling's type from an unrelated over-limit measurement.
        for row in bundle["inputs"]["measurements"]:
            row[field] = 0
    result = _assess(bundle)[0]["result"]
    assert result["checks"]["ENV-3.3"]["evaluation"]["outcome"] == "FAIL"
    assert result["status"] == "FAIL"


@pytest.mark.parametrize("field", ("threads", "memory_bytes"))
def test_resource_count_ceiling_must_be_positive(field: str) -> None:
    bundle = _bundle()
    bundle["artifact"]["ceilings"][field] = 0
    assert _assess(bundle)[0]["result"]["status"] == "FAIL"


@pytest.mark.parametrize("field", ("threads", "memory_bytes"))
def test_resource_count_cannot_exceed_ceiling(field: str) -> None:
    bundle = _bundle()
    bundle["inputs"]["measurements"][1][field] = bundle["artifact"]["ceilings"][field] + 1
    assert _assess(bundle)[0]["result"]["status"] == "FAIL"


@pytest.mark.parametrize("at_ceiling", (False, True), ids=("zero", "at-ceiling"))
def test_resource_integer_boundaries_and_fractional_wall_time_recheck(at_ceiling: bool) -> None:
    bundle = _bundle()
    for row in bundle["inputs"]["measurements"]:
        for field in ("threads", "memory_bytes"):
            row[field] = bundle["artifact"]["ceilings"][field] if at_ceiling else 0
    certificate, request, policy = _assess(bundle)
    assert certificate["result"]["status"] == "PASS"
    assert certificate["result"]["domain_depth"] == 4
    assert recheck_domain_certificate(certificate, expected_request=request, policy=policy) == certificate["result"]
