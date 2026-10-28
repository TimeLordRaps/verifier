"""Verifier Standard (VSTD) finding identity for explicit package obligations.

Terminology: identifier (ID).

An explicit obligation ID owns its coordinate, name, and gate. A blocker code
selects those fields only when no obligation is supplied. Unregistered IDs stay
visibly unresolved and are never rewritten or replaced by a nearby route.
"""
from __future__ import annotations

import pytest

from scripts.check_namespace_closure import namespace_fixture_identifier
from verifier.runtime import manifest_gate


SOURCE_CODE = "PACKAGE_GATE_SOURCE_CHANGED"
MANIFEST_CODE = "PACKAGE_MANIFEST_MISSING"
GRAPH_CODE = "PACKAGE_OBJECT_GRAPH_UNRESOLVED"


def _finding(code: str, status: str = "UNKNOWN", **kwargs) -> dict:
    return manifest_gate.repository_finding(code, status, **kwargs)


def test_explicit_namespace_admission_keeps_its_own_coordinate_and_gate() -> None:
    # The observed defect: a SOURCE token used to select VSTD-T0.7 while the
    # explicit VSTD-T0.2 identifier was retained.
    finding = _finding(SOURCE_CODE, object_id="accounts.py",
                       obligation_id="VSTD-T0.2-namespace-admission")

    assert finding["obligation_id"] == "VSTD-T0.2-namespace-admission"
    assert finding["coordinate"] == "VSTD-T0.2"
    assert finding["gate_id"] == "namespace-admission"
    assert finding["obligation_name"] == "Namespace admission (VSTD-T0.2)"
    assert finding["code"] == SOURCE_CODE
    assert finding["rerun_argv"] == [
        "vstd", "gate", "--object", "accounts.py",
        "--obligation", "VSTD-T0.2-namespace-admission",
    ]


@pytest.mark.parametrize("code", [SOURCE_CODE, MANIFEST_CODE, GRAPH_CODE])
def test_every_registered_tier_zero_identity_ignores_blocker_tokens(code) -> None:
    from verifier.runtime.manifest_gate import _admission_catalog

    for row in _admission_catalog():
        finding = _finding(code, object_id="vstd-simulation",
                           obligation_id=row["obligation_id"])
        assert finding["obligation_id"] == row["obligation_id"]
        assert finding["coordinate"] == row["coordinate"], row["obligation_id"]
        assert finding["gate_id"] == row["gate_id"], row["obligation_id"]
        assert finding["obligation_name"] == row["obligation_name"]
        assert finding["code"] == code


def test_registered_tier_one_route_controls_coordinate_name_and_kind() -> None:
    finding = _finding(MANIFEST_CODE, object_id="vstd-simulation",
                       obligation_id="SIM-1.1-declared-operand-facets")

    assert finding["obligation_id"] == "SIM-1.1-declared-operand-facets"
    assert finding["coordinate"] == "SIM-1.1"
    assert finding["object_kind"] == "SIM"
    assert finding["obligation_name"] == "Declared operand facets"
    assert finding["gate_id"] == "obligation-instance"
    assert finding["gate_id"] != "manifest-admission"


@pytest.mark.parametrize("obligation_id", [
    "SIM-9.9-invented-obligation",
    namespace_fixture_identifier("T0.2-namespace-admisson"),
    namespace_fixture_identifier("T0.N-namespace-admission"),
    namespace_fixture_identifier("T0.2-manifest-object-graph-source"),
    "SIM-1.1-declared-operand-facets-source-manifest",
    namespace_fixture_identifier("T0.1-canonical-manifest-admission-graph"),
])
def test_unregistered_explicit_id_is_visibly_unresolved(obligation_id) -> None:
    finding = _finding(SOURCE_CODE, object_id="accounts.py",
                       obligation_id=obligation_id)

    assert finding["obligation_id"] == obligation_id
    assert finding["coordinate"] is None
    assert finding["gate_id"] == "obligation-resolution"
    assert finding["obligation_name"] == "Unresolved obligation identity"
    assert "is not resolved" in finding["reason"]
    assert obligation_id in finding["reason"]
    assert finding["rerun_argv"] == [
        "vstd", "gate", "--object", "accounts.py", "--obligation", obligation_id,
    ]


def test_unresolved_identity_keeps_the_caller_status_verbatim() -> None:
    # Neither softened to UNKNOWN nor hardened to FAIL by the identity rule.
    failed = _finding(MANIFEST_CODE, "FAIL", object_id="accounts.py",
                      obligation_id="SIM-9.9-invented-obligation")
    unknown = _finding(MANIFEST_CODE, "UNKNOWN", object_id="accounts.py",
                       obligation_id="SIM-9.9-invented-obligation")

    assert failed["status"] == "FAIL"
    assert unknown["status"] == "UNKNOWN"


def test_registered_identity_keeps_a_mismatched_blocker_code_verbatim() -> None:
    finding = _finding(MANIFEST_CODE, object_id="accounts.py",
                       obligation_id="VSTD-T0.7-source-and-mechanism-freshness")

    assert finding["code"] == MANIFEST_CODE
    assert finding["coordinate"] == "VSTD-T0.7"
    assert finding["gate_id"] == "source-freshness"
    assert finding["obligation_name"] == "Source and mechanism freshness"


def test_each_explicit_id_is_reported_exactly_once_without_substitution() -> None:
    ids = [
        "VSTD-T0.2-namespace-admission",
        "SIM-9.9-invented-obligation",
        "SIM-1.1-declared-operand-facets",
        "VSTD-T0.2-object-denominator-closure",
    ]
    findings = [_finding(SOURCE_CODE, object_id="accounts.py", obligation_id=item)
                for item in ids]

    assert [finding["obligation_id"] for finding in findings] == ids
    assert [finding["rerun_argv"][-1] for finding in findings] == ids


def test_registered_tier_controls_the_repository_rerun_not_the_caller_tier() -> None:
    tier_one = _finding(SOURCE_CODE, obligation_id="SIM-1.1-declared-operand-facets",
                        tier=0)
    tier_zero = _finding(SOURCE_CODE, obligation_id="VSTD-T0.2-object-denominator-closure",
                         tier=3)
    unresolved = _finding(SOURCE_CODE, obligation_id="SIM-9.9-invented-obligation",
                          tier=2)

    assert tier_one["rerun_argv"] == ["vstd", "polish", "1", "--json"]
    assert tier_zero["rerun_argv"] == ["vstd", "polish", "0", "--json"]
    assert unresolved["rerun_argv"] == ["vstd", "polish", "2", "--json"]


def test_code_derived_default_without_an_explicit_obligation_is_unchanged() -> None:
    finding = _finding(MANIFEST_CODE)

    assert finding["scope"] == "repository"
    assert finding["object_id"] is None
    assert finding["coordinate"] == "VSTD-T0.1"
    assert finding["gate_id"] == "manifest-admission"
    assert finding["obligation_id"] == "VSTD-T0.1-canonical-manifest-admission"
    assert finding["obligation_name"] == "Canonical manifest admission"
    assert finding["rerun_argv"] == ["vstd", "polish", "0", "--json"]


def _native_report(record: dict) -> dict:
    return {"native_diagnostics": {"nonpass_detail": {"nonpass_records": [record]}}}


def _native_record(**fields) -> dict:
    record = {
        "path": "$.complete_tier_evidence_replay",
        "status": "FAIL",
        "object_id": "accounts.py",
        "object_kind": "SIM",
        "reason": "Producer reason.",
        "blockers": [SOURCE_CODE],
    }
    record.update(fields)
    return record


def test_native_record_cannot_override_a_registered_tier_zero_identity() -> None:
    record = _native_record(obligation_id="VSTD-T0.2-namespace-admission",
                            coordinate="VSTD-T0.7", gate_id="producer-gate")

    (finding,) = manifest_gate._native_nonpass_findings(_native_report(record))

    assert finding["obligation_id"] == "VSTD-T0.2-namespace-admission"
    assert finding["coordinate"] == "VSTD-T0.2"
    assert finding["gate_id"] == "namespace-admission"
    assert finding["obligation_name"] == "Namespace admission (VSTD-T0.2)"


def test_native_record_keeps_the_producer_gate_on_a_registered_route() -> None:
    record = _native_record(obligation_id="SIM-1.1-declared-operand-facets",
                            coordinate="SIM-9.9", gate_id="native-check")

    (finding,) = manifest_gate._native_nonpass_findings(_native_report(record))

    assert finding["coordinate"] == "SIM-1.1"
    assert finding["object_kind"] == "SIM"
    assert finding["gate_id"] == "native-check"


def test_unresolved_native_record_keeps_producer_identity_under_unresolved_name() -> None:
    record = _native_record(obligation_id="SIM-3.1-state-invariants",
                            coordinate="SIM-3.1", gate_id="statics-invariant")

    (finding,) = manifest_gate._native_nonpass_findings(_native_report(record))

    assert finding["obligation_id"] == "SIM-3.1-state-invariants"
    assert finding["coordinate"] == "SIM-3.1"
    assert finding["gate_id"] == "statics-invariant"
    assert finding["object_kind"] == "SIM"
    assert finding["obligation_name"] == "Unresolved obligation identity"
