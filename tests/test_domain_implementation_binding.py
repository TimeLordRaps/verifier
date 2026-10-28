"""Domain policy readmission after changes to eagerly loaded receipt helpers.

Agent harness (HARNESS) checks here establish only the declared surface.
Scratch resource copies change source bytes without changing the live checkout.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from verifier.domains import certification


@pytest.fixture
def core_copy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    real_files = certification.resources.files
    source = real_files("verifier.core")
    copied = tmp_path / "core"
    copied.mkdir()
    for name in (
        "certificate", "evidence", "receipt", "checker", "provenance", "kernel",
        "grounding", "depth", "signature_keys", "witness",
    ):
        (copied / (name + ".py")).write_bytes(source.joinpath(name + ".py").read_bytes())
    monkeypatch.setattr(
        certification.resources, "files",
        lambda package: copied if package == "verifier.core" else real_files(package),
    )
    return copied


@pytest.mark.parametrize("helper", ["checker", "provenance"])
def test_receipt_helper_change_requires_domain_policy_readmission(core_copy: Path, helper: str) -> None:
    bundle = {
        "schema_version": "verifier-domain-evidence-1",
        "domain": "HARNESS", "subject_id": "test:declared-surface",
        "artifact": {"surface": {"dialog": "instrumented"}, "tools": {}}, "inputs": {},
    }
    request = certification.domain_request(bundle, target_depth=1)
    admitted = certification.domain_policy(trust_roots=["test:receipt-helper-bytes"])
    original = certification.build_domain_certificate(request, bundle, policy=admitted)
    assert original["result"]["status"] == "PASS"
    assert original["result"]["domain_depth"] == 1
    assert original["result"]["object_profile_conformance"] == "NOT_ESTABLISHED"
    assert certification.recheck_domain_certificate(original, expected_request=request, policy=admitted)["status"] == "PASS"

    changed = core_copy / (helper + ".py")
    changed.write_bytes(changed.read_bytes() + b"\n# Scratch source-binding mutation.\n")
    assert certification.implementation_digest() != admitted["mechanism_digest"]
    with pytest.raises(ValueError, match="checker implementation not admitted"):
        certification.build_domain_certificate(request, bundle, policy=admitted)
    rejected = certification.recheck_domain_certificate(original, expected_request=request, policy=admitted)
    assert rejected["status"] == "REJECTED"
    assert "checker implementation not admitted" in rejected["reason"]

    readmitted = certification.domain_policy(trust_roots=admitted["trust_roots"])
    current = certification.build_domain_certificate(request, bundle, policy=readmitted)
    for field in ("status", "domain_depth", "scope", "object_profile_conformance"):
        assert current["result"][field] == original["result"][field]
    for coordinate, old_row in original["result"]["checks"].items():
        new_row = current["result"]["checks"][coordinate]
        for field in ("name", "proposition", "established", "blocked_by"):
            assert new_row[field] == old_row[field]
        for field in ("outcome", "details", "observations"):
            assert new_row["evaluation"][field] == old_row["evaluation"][field]
    assert current["request"] == original["request"] == request
    assert current["mechanism_digest"] != original["mechanism_digest"]
    assert current["evidence"] == original["evidence"] == bundle
    assert certification.recheck_domain_certificate(current, expected_request=request, policy=readmitted)["status"] == "PASS"
    assert certification.recheck_domain_certificate(original, expected_request=request, policy=readmitted)["status"] == "REJECTED"


def test_domain_source_inventory_does_not_expand_to_witness_family(core_copy: Path) -> None:
    before = certification.implementation_digest()
    outside = core_copy / "witness.py"
    outside.write_bytes(outside.read_bytes() + b"\n# Separate witness family mutation.\n")
    assert certification.implementation_digest() == before
