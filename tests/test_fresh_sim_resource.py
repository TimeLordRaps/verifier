"""Fresh SIM executions bind source and inputs, never a signer's assertion."""
from __future__ import annotations

import base64
from copy import deepcopy

import pytest

from verifier.core.certificate import canonical_bytes
from verifier.domains.contracts import sim_resource_fresh
from verifier.runtime import self_polish_native_cases


def fixture():
    fresh = sim_resource_fresh
    selected = self_polish_native_cases.installed_case_inputs()["SIM:SIM-2.1"]
    request, policy, evidence = fresh.selection_from_trajectory(
        selected["request"], selected["policy"],
        base64.b64decode(selected["evidence_base64"]),
    )
    certificate = fresh.build_sim_resource_fresh_certificate(request, evidence, policy=policy)
    return fresh, request, policy, certificate


def test_fresh_execution_loads_exact_snapshot_without_signer():
    fresh, request, policy, certificate = fixture()
    results = [fresh.recheck_sim_resource_fresh_certificate(
        certificate, expected_request=request, policy=policy) for _ in range(2)]
    for result in results:
        assert result["status"] == "PASS"
        assert result["scope"] == fresh.SCOPE
        assert result["historical_metric_correspondence"] == "NOT_ESTABLISHED"
        assert result["host_attestation"] == "NOT_ESTABLISHED"
        observation = result["observation"]
        assert observation["source_manifest"] == fresh.source_manifest()
        assert observation["loaded_source_manifest"] == observation["source_manifest"]
        assert observation["workload_digest"] == request["workload_digest"]
        assert len(observation["capture"]["steps"]) == request["trajectory_request"]["expected_counts"]["transitions"]
        assert observation["capture"]["process_id"] > 0
        assert observation["source_recheck"] == "PASS"
    assert results[0]["observation"]["challenge"] != results[1]["observation"]["challenge"]
    assert results[0]["observation"]["capture"]["run_id"] != results[1]["observation"]["capture"]["run_id"]


def test_missing_and_malformed_input_do_not_execute(monkeypatch):
    fresh, request, policy, _ = fixture()
    monkeypatch.setattr(fresh, "_execute", lambda *a: pytest.fail("must not execute"))
    for evidence, status in [(None, "UNKNOWN"), (b"{}", "FAIL")]:
        raw = fresh.build_sim_resource_fresh_certificate(request, evidence, policy=policy)
        assert fresh.recheck_sim_resource_fresh_certificate(
            raw, expected_request=request, policy=policy)["status"] == status


@pytest.mark.parametrize("field", ["challenge", "workload_digest", "source_manifest", "loaded_source_manifest"])
def test_substituted_worker_bindings_fail(monkeypatch, field):
    fresh, request, policy, certificate = fixture()
    original = fresh._run
    def substituted(*args):
        value = original(*args)
        value[field] = "substituted"
        return value
    monkeypatch.setattr(fresh, "_run", substituted)
    result = fresh.recheck_sim_resource_fresh_certificate(certificate, expected_request=request, policy=policy)
    assert result["status"] == "FAIL"


def test_changed_meter_dependency_is_refused():
    fresh, request, policy, certificate = fixture()
    policy = deepcopy(policy)
    policy["source_manifest"]["verifier.domains.sim"]["sha256"] = "sha256:" + "0" * 64
    with pytest.raises(ValueError):
        fresh.recheck_sim_resource_fresh_certificate(certificate, expected_request=request, policy=policy)


@pytest.mark.parametrize("field", ["source_manifest", "loaded_source_manifest"])
def test_source_package_flags_are_type_sensitive(monkeypatch, field):
    fresh, request, policy, certificate = fixture()
    original = fresh._run

    def substituted(*args):
        value = original(*args)
        value[field]["verifier"]["package"] = 1
        return value

    monkeypatch.setattr(fresh, "_run", substituted)
    assert fresh.recheck_sim_resource_fresh_certificate(
        certificate, expected_request=request, policy=policy)["status"] == "FAIL"


def test_selected_policy_package_flag_is_not_a_numeric_alias():
    fresh, request, policy, certificate = fixture()
    policy = deepcopy(policy)
    policy["source_manifest"]["verifier"]["package"] = 1
    with pytest.raises(ValueError):
        fresh.recheck_sim_resource_fresh_certificate(certificate, expected_request=request, policy=policy)


def test_retained_observation_is_not_an_execution_request():
    fresh, request, policy, certificate = fixture()
    result = fresh.recheck_sim_resource_fresh_certificate(certificate, expected_request=request, policy=policy)
    with pytest.raises(ValueError):
        fresh.recheck_sim_resource_fresh_certificate(canonical_bytes(result), expected_request=request, policy=policy)


def test_fresh_execution_timeout_is_unknown(monkeypatch):
    import subprocess
    fresh, request, policy, certificate = fixture()
    def unavailable(*args):
        raise subprocess.TimeoutExpired("fixed meter", 15)
    monkeypatch.setattr(fresh, "_run", unavailable)
    assert fresh.recheck_sim_resource_fresh_certificate(
        certificate, expected_request=request, policy=policy)["status"] == "UNKNOWN"


@pytest.mark.parametrize("mutation", ["missing", "extra", "state", "index", "bool_cpu", "negative_bytes", "method", "process"])
def test_measured_step_contradictions_fail(monkeypatch, mutation):
    fresh, request, policy, certificate = fixture()
    original = fresh._run
    def altered(*args):
        value = original(*args)
        capture = value["capture"]
        if mutation == "missing":
            capture["steps"] = []
        elif mutation == "extra":
            capture["steps"].append(deepcopy(capture["steps"][0]))
        elif mutation == "state":
            capture["steps"][0]["output_state_digest"] = "sha256:" + "0" * 64
        elif mutation == "index":
            capture["steps"][0]["step"] = True
        elif mutation == "bool_cpu":
            capture["steps"][0]["thread_cpu_ns"] = False
        elif mutation == "negative_bytes":
            capture["steps"][0]["traced_peak_bytes"] = -1
        elif mutation == "method":
            capture["method"] = "budget-counter"
        else:
            capture["process_id"] = 0
        return value
    monkeypatch.setattr(fresh, "_run", altered)
    assert fresh.recheck_sim_resource_fresh_certificate(
        certificate, expected_request=request, policy=policy)["status"] == "FAIL"


def test_source_change_during_execution_refuses_promotion(monkeypatch):
    fresh, request, policy, certificate = fixture()
    original_run, sources = fresh._run, fresh._sources()
    def changed(*args):
        value = original_run(*args)
        sources["verifier.domains.sim"] += b"\n# changed after snapshot\n"
        monkeypatch.setattr(fresh, "_sources", lambda: sources)
        return value
    monkeypatch.setattr(fresh, "_run", changed)
    assert fresh.recheck_sim_resource_fresh_certificate(
        certificate, expected_request=request, policy=policy)["status"] == "FAIL"


def test_private_import_root_refuses_bytes_different_from_the_manifest():
    from pathlib import Path
    fresh, _, policy, _ = fixture()
    sources = fresh._sources()
    sources["verifier"] += b"\nraise RuntimeError('unselected code')\n"
    payload = canonical_bytes({
        "sources": {k: base64.b64encode(v).decode() for k, v in sources.items()},
        "source_manifest": policy["source_manifest"], "challenge": "test-only",
        "workload": {},
    })
    with pytest.raises(ValueError, match="FRESH_WORKER_REFUSED"):
        fresh._run(Path(fresh.__file__).with_name("sim_fresh_bootstrap.py").read_bytes(), payload, 15)


def test_meter_covers_multiple_transitions_without_a_signature():
    fresh, _, policy, _ = fixture()
    inputs = {"states": [{"x": 0.0}, {"x": 1.0}, {"x": 2.0}],
              "entropy": [1.0, 1.0], "times": [0.0, 1.0, 2.0]}
    artifact = {"transition": {"x": {"op": "add", "args": [{"var": "x"}, {"var": "entropy"}]}},
                "initial_state": inputs["states"][0],
                "trajectory_digest": fresh._digest(inputs["states"]),
                "entropy_digest": fresh._digest(inputs["entropy"]),
                "times_digest": fresh._digest(inputs["times"])}
    value = fresh._execute(dict(artifact=artifact, inputs=inputs, max_operations=100000, max_items=4096), policy)
    assert [row["step"] for row in value["capture"]["steps"]] == [0, 1]


def test_ambient_package_path_cannot_replace_selected_sources(monkeypatch, tmp_path):
    shadow = tmp_path / "verifier"
    shadow.mkdir()
    (shadow / "__init__.py").write_text("raise RuntimeError('wrong package imported')\n")
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    fresh, request, policy, certificate = fixture()
    assert fresh.recheck_sim_resource_fresh_certificate(
        certificate, expected_request=request, policy=policy)["status"] == "PASS"


def test_unsupported_interpreter_is_unknown(monkeypatch):
    fresh, request, policy, certificate = fixture()
    monkeypatch.setattr(fresh.platform, "python_implementation", lambda: "unsupported")
    monkeypatch.setattr(fresh, "_run", lambda *args: pytest.fail("unsupported meter ran"))
    assert fresh.recheck_sim_resource_fresh_certificate(
        certificate, expected_request=request, policy=policy)["status"] == "UNKNOWN"


@pytest.mark.parametrize("returncode,expected", [(3, "UNKNOWN"), (1, "UNKNOWN"), (2, "FAIL")])
def test_worker_failure_classification(monkeypatch, returncode, expected):
    import subprocess
    fresh, request, policy, certificate = fixture()
    monkeypatch.setattr(fresh.subprocess, "run", lambda *a, **k:
                        subprocess.CompletedProcess(a[0], returncode, stdout=b"", stderr=b""))
    assert fresh.recheck_sim_resource_fresh_certificate(
        certificate, expected_request=request, policy=policy)["status"] == expected
