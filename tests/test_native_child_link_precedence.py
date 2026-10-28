"""Available selected-link refutations survive unrelated missing support.

simulation (SIM); directed acyclic graph (DAG). Real native fixtures are retained;
identity-link outcomes do not establish native replay or exhaustive closure.
"""
from __future__ import annotations

import json
import pytest
from verifier.core.certificate import canonical_bytes
from verifier.domains.contracts import certificate_dag as dag
from test_native_child_links import _case, _assess, _assert_native_pass, _digest


def omit(case, path):
    del case[3][path]
    case[1]["artifact_files_digest"] = dag.artifact_files_digest(case[3])


@pytest.mark.parametrize("path", ["native/trajectory.json", "native/response.json"])
def test_visible_consumed_tuple_refutation_survives_absent_certificate(path):
    case = _case(select_b=True)
    _assert_native_pass(case[-1])
    omit(case, path)
    result = _assess(case)
    assert result["status"] == result["links"][0]["status"] == "FAIL"


@pytest.mark.parametrize("variant", ["unsupported-selector", "unsupported-replay-contract"])
def test_dangling_selected_edge_refutes_before_selector_availability(variant):
    case = _case()
    _assert_native_pass(case[-1])
    case[0]["edges"] = []
    if variant == "unsupported-selector":
        case[2]["links"][0]["selector"] = "unsupported/selected-link"
    else:
        case[0]["nodes"][0]["contract_version"] = "unsupported"
    result = _assess(case)
    assert result["status"] == result["links"][0]["status"] == "FAIL"


@pytest.mark.parametrize("path", ["native/trajectory.json", "native/response.json"])
def test_uncontradicted_missing_certificate_remains_unknown(path):
    case = _case()
    omit(case, path)
    result = _assess(case)
    assert result["status"] == result["links"][0]["status"] == "UNKNOWN"
    assert result["native_replay_status"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("available", [0, 1])
def test_available_malformed_certificate_refutes_despite_absent_sibling(available):
    case = _case()
    node = case[0]["nodes"][available]
    path = node["certificate_path"]
    value = json.loads(case[3][path])
    value["schema_version"] = "wrong-native-certificate-schema"
    raw = canonical_bytes(value)
    case[3][path] = raw
    node["certificate_digest"] = _digest(raw)
    node["artifact_bindings"][0]["digest"] = _digest(raw)
    if available == 1:
        case[0]["nodes"][0]["request"]["trajectory_certificate_digest"] = _digest(raw)
    omit(case, case[0]["nodes"][1 - available]["certificate_path"])
    assert _assess(case)["status"] == "FAIL"


def test_unsupported_selector_with_existing_typed_edge_remains_unknown():
    case = _case()
    case[0]["edges"][0]["operand_role"] = "declared-future-role"
    case[2]["links"][0]["selector"] = "unsupported/selected-link"
    assert _assess(case)["status"] == "UNKNOWN"


def test_authored_selector_requires_its_exact_null_role_edge():
    case = _case()
    case[0]["edges"][0]["operand_role"] = "different-role"
    assert _assess(case)["status"] == "FAIL"
