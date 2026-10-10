"""Focused authority-boundary regressions; no authority or release is established."""
from __future__ import annotations

import dataclasses
import json
from pathlib import Path
import re

import pytest

from verifier.runtime import core_application_authority as binding
import test_application_authority_binding as owner


RAW_FIELDS = (
    "profile_bytes", "union_authority_bytes", "union_contributions_bytes")


def _reselect_compiler(inputs, claim, profile, compiler):
    compiler_bytes = owner.cb(compiler)
    subject = compiler["scope_admission"]["subject"]
    profile["compiler_manifest_digest"] = owner.digest(compiler_bytes)
    profile["scope_admission_subject_digest"] = binding.value_digest(subject)
    profile_bytes = owner.cb(profile)
    claim["authority_profile_digest"] = owner.digest(profile_bytes)
    inputs["host_selection"] = dataclasses.replace(
        inputs["host_selection"], profile_bytes=profile_bytes,
        expected_profile_digest=owner.digest(profile_bytes))
    inputs["compiler_manifest_bytes"] = compiler_bytes
    inputs["applicability_claim_bytes"] = owner.cb(claim)


@pytest.mark.parametrize("field", RAW_FIELDS)
def test_raw_host_inputs_are_bounded_before_hashing(field, monkeypatch):
    inputs, *_ = owner.fixture()
    host = inputs["host_selection"]
    limit = max(len(host.profile_bytes), len(host.union_authority_bytes),
                len(host.union_contributions_bytes)) + 16
    oversized = b"x" * (limit + 1)
    inputs["host_selection"] = dataclasses.replace(host, **{field: oversized})
    monkeypatch.setattr(binding, "MAX_RECORD_BYTES", limit)
    observed = []
    original = binding.bytes_digest

    def recording_digest(raw):
        observed.append(raw is oversized)
        return original(raw)

    monkeypatch.setattr(binding, "bytes_digest", recording_digest)
    report = binding.assess_application_authority_binding(**inputs)

    assert True not in observed
    assert report["status"] == "UNKNOWN"
    assert report["binding_status"] == "UNKNOWN"
    assert "AUTHORITY_INPUT_CAPACITY_EXHAUSTED" in report["blockers"]


@pytest.mark.parametrize("field", RAW_FIELDS)
def test_raw_host_inputs_require_exact_bytes_before_hashing(field, monkeypatch):
    inputs, *_ = owner.fixture()
    invalid = bytearray(getattr(inputs["host_selection"], field))
    inputs["host_selection"] = dataclasses.replace(
        inputs["host_selection"], **{field: invalid})
    original = binding.bytes_digest

    def refusing_digest(raw):
        assert raw is not invalid
        return original(raw)

    monkeypatch.setattr(binding, "bytes_digest", refusing_digest)
    report = binding.assess_application_authority_binding(**inputs)

    assert report["status"] == "FAIL"
    assert report["binding_status"] == "FAIL"
    assert "HOST_SELECTION_REQUIRED" in report["blockers"]


def test_self_consistent_subject_cannot_disagree_with_compiler_inputs():
    inputs, _, claim, profile, _ = owner.fixture()
    compiler = json.loads(inputs["compiler_manifest_bytes"])
    closure = compiler["closure_certificate"]
    closure["input_digests"]["selection"] = "sha256:" + "0" * 64
    closure["digest"] = binding.value_digest(
        {key: value for key, value in closure.items() if key != "digest"})
    subject = compiler["scope_admission"]["subject"]
    subject["input_digests"] = closure["input_digests"]
    subject["closure_certificate_digest"] = closure["digest"]
    compiler["scope_admission"]["admission_subject_digest"] = binding.value_digest(subject)
    _reselect_compiler(inputs, claim, profile, compiler)

    report = binding.assess_application_authority_binding(**inputs)

    assert report["status"] == "FAIL"
    assert report["binding_status"] == "FAIL"
    assert "COMPILER_CLOSURE_CERTIFICATE_DIFFERS" in report["blockers"]


def test_known_child_failure_survives_later_resource_failure(monkeypatch):
    inputs, _, claim, _, _ = owner.fixture()
    claim["child_outcomes"][0].update(
        status="FAIL", evidence_digest="sha256:" + "9" * 64)
    inputs["applicability_claim_bytes"] = owner.cb(claim)
    receipt = b"resource-failure-after-known-refutation"
    inputs["host_selection"] = dataclasses.replace(
        inputs["host_selection"], scope_admission_receipt_bytes=receipt,
        expected_scope_admission_receipt_digest=owner.digest(receipt))
    original = binding.bytes_digest

    def exhausted_digest(raw):
        if raw is receipt:
            raise MemoryError
        return original(raw)

    monkeypatch.setattr(binding, "bytes_digest", exhausted_digest)
    report = binding.assess_application_authority_binding(**inputs)

    assert report["status"] == "FAIL"
    assert report["binding_status"] == "FAIL"
    assert "CHILD_REQUIREMENT_FAILED" in report["blockers"]
    assert "AUTHORITY_CHECKING_RESOURCE_UNAVAILABLE" in report["blockers"]
    assert report["authority_status"] == "UNKNOWN"
    assert report["semantic_completeness"] == "UNKNOWN"
    assert report["release_authorized"] is False


def test_known_child_failure_survives_interaction_outcome_exhaustion(monkeypatch):
    inputs, _, claim, _, _ = owner.fixture()
    claim["child_outcomes"][0].update(
        status="FAIL", evidence_digest="sha256:" + "9" * 64)
    inputs["applicability_claim_bytes"] = owner.cb(claim)
    original = binding._outcomes

    def exhausted_after_child(required, supplied, label):
        if label == "INTERACTION":
            raise MemoryError
        return original(required, supplied, label)

    monkeypatch.setattr(binding, "_outcomes", exhausted_after_child)
    report = binding.assess_application_authority_binding(**inputs)

    assert report["status"] == "FAIL"
    assert report["binding_status"] == "FAIL"
    assert report["child_status"] == "FAIL"
    assert "CHILD_REQUIREMENT_FAILED" in report["blockers"]
    assert "AUTHORITY_CHECKING_RESOURCE_UNAVAILABLE" in report["blockers"]
    assert report["authority_status"] == "UNKNOWN"
    assert report["semantic_completeness"] == "UNKNOWN"
    assert report["release_authorized"] is False


def test_installed_authority_digest_resolves_packaged_standard():
    spec = Path(binding.__file__).resolve().parents[1] / "standard" / "CORE_APPLICATION_AUTHORITY.md"
    assert spec.is_file()
    assert binding.mechanism_digest().startswith("sha256:")
    source = Path(binding.__file__).read_text(encoding="utf-8")
    assert "spec_from_file_location" not in source
    assert re.search(r"(?i)(?<![A-Za-z0-9_])[A-Za-z]:[\\/]", source) is None
    assert re.search(r"(?i)[\\/](?:Users|Documents and Settings)[\\/]", source) is None


def test_nominal_binding_keeps_authority_and_release_unknown():
    inputs, *_ = owner.fixture()
    report = binding.assess_application_authority_binding(**inputs)
    assert report["binding_status"] == "PASS"
    assert report["status"] == report["authority_status"] == "UNKNOWN"
    assert report["semantic_completeness"] == "UNKNOWN"
    assert report["full_application_status"] == "UNKNOWN"
    assert report["polished"] is report["release_authorized"] is False


def test_application_consumer_preserves_authority_failure(monkeypatch):
    import test_core_release_private as core

    failure = {
        "status": "FAIL",
        "binding_status": "FAIL",
        "authority_status": "UNKNOWN",
        "child_status": "FAIL",
        "interaction_status": "UNKNOWN",
        "semantic_completeness": "UNKNOWN",
        "full_application_status": "UNKNOWN",
        "profile_digest": "sha256:" + "1" * 64,
        "requirements_digest": "sha256:" + "2" * 64,
        "union_authority_digest": "sha256:" + "3" * 64,
        "union_contributions_digest": "sha256:" + "4" * 64,
        "union_validation": {"status": "FAIL"},
        "blockers": ["CHILD_REQUIREMENT_FAILED"],
        "assessment_digest": "sha256:" + "5" * 64,
    }
    monkeypatch.setattr(
        core.app.application_authority,
        "assess_application_authority_binding",
        lambda **_kwargs: failure,
    )
    monkeypatch.setattr(
        core.app.application_authority,
        "installed_compiler_mechanism_digest",
        lambda: "sha256:" + "6" * 64,
    )
    monkeypatch.setattr(
        core.app.application_authority,
        "installed_union_validator_digest",
        lambda: "sha256:" + "7" * 64,
    )

    report = core.assess_application(
        core.application_input(),
        authority_claim_bytes=b"{}",
        compiler_manifest_bytes=b"{}",
        authority_host_selection=object(),
    )

    assert report["status"] == "FAIL"
    assert report["binding_status"] == "FAIL"
    assert "APPLICATION_AUTHORITY_BINDING_FAILED" in report["blockers"]
    assert report["authority_binding_assessment"] == failure
    assert report["authority_binding_assessment"]["authority_status"] == "UNKNOWN"
    assert report["authority_binding_assessment"]["semantic_completeness"] == "UNKNOWN"
