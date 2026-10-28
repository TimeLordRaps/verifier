"""OpenShell transport fault injection; these are NOT live isolation evidence."""
from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest


@pytest.fixture
def backend(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1] / "extensions/openshell/src"))
    import vstd_openshell
    return vstd_openshell


def config() -> dict:
    return {"schema_version": "verifier-openshell-config-1", "gateway": "test", "workspace": "default",
            "image": "example.invalid/test@sha256:" + "a" * 64, "cpu": 1, "memory": "512Mi",
            "reason": "Bounded offline process containment checks, not full object conformance.",
            "lifecycle": "ephemeral-stop-contained"}


def request(tmp_path, kind="AGENT") -> dict:
    from verifier.runtime.language_runners import sandbox_requirements
    (tmp_path / "main.py").write_text("print(42)", encoding="utf-8")
    path = tmp_path / "sandbox.json"
    path.write_text(json.dumps(config()), encoding="utf-8")
    return {"schema_version": "verifier-sandbox-request-1", "root": str(tmp_path), "entry": "main.py",
            "inputs": [], "argv": ["python3", "/sandbox/source/main.py"], "timeout": 10,
            "profile": sandbox_requirements(kind, "check", False), "config": str(path)}


def test_no_cli_is_unknown_without_execution(backend, tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(backend.shutil, "which", lambda _: None)
    result = backend.run(request(tmp_path))
    assert result["status"] == "UNKNOWN"
    assert result["blockers"] == ["RUNNER_OPENSHELL_CLI_MISSING"]
    assert not result["execution_performed"]
    assert result["cleanup"] == "NOT_CREATED"


@pytest.mark.parametrize("field,value", [("image", "example:latest"), ("cpu", True),
    ("cpu", 0), ("memory", "0Mi"), ("reason", ""), ("gateway", "--insecure"), ("host_mount", "/")])
def test_invalid_config_cannot_start_process(backend, tmp_path, monkeypatch, field, value) -> None:
    payload = request(tmp_path)
    settings = config()
    settings[field] = value
    Path(payload["config"]).write_text(json.dumps(settings), encoding="utf-8")
    monkeypatch.setattr(backend, "_capture", lambda *a: pytest.fail("must not execute"))
    assert backend.run(payload)["status"] == "FAIL"


def test_bot_bindings_and_continuity_are_not_inferred(backend, tmp_path) -> None:
    payload = request(tmp_path, "BOT")
    assert backend.run(payload)["blockers"] == ["RUNNER_BOT_EXACT_BINDINGS_REQUIRED"]
    payload["profile"]["availability"] = "REQUIRED_NOT_ESTABLISHED"
    assert backend.run(payload)["blockers"] == ["RUNNER_SANDBOX_CONTINUITY_NOT_IMPLEMENTED"]


def test_snapshot_rejects_escape_and_binds_exact_bytes(backend, tmp_path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    (root / "main.py").write_bytes(b"exact bytes")
    dest = tmp_path / "snapshot"
    dest.mkdir()
    hashes = backend._snapshot(root, ["main.py"], dest)
    assert hashes["main.py"] == backend._digest(b"exact bytes")
    for path in ("../outside", "/etc/passwd", "C:" + "/file", "a\\b", "a/../b"):
        with pytest.raises(ValueError):
            backend._snapshot(root, [path], dest)


def test_capture_bounds_timeout_and_output(backend) -> None:
    timed = backend._capture([sys.executable, "-c", "import time; time.sleep(20)"], 1, dict(backend.os.environ))
    assert timed["timeout"]
    flood = backend._capture([sys.executable, "-c", "print('x'*3000000)"], 10, dict(backend.os.environ))
    assert flood["output_limit"]
    assert len(flood["stdout"]) <= backend.LIMIT


def test_live_specimens_are_distinct_and_have_correct_claim_boundaries(backend) -> None:
    from vstd_openshell.live import specimens
    cases = specimens()
    assert set(cases) == {"MODEL", "AGENT", "BOT", "SIM"}
    assert len({case["main.py"] for case in cases.values()}) == 4
    for case in cases.values():
        for name, source in case.items():
            if name.endswith(".py"):
                compile(source, name, "exec")
    assert "child.terminate()" in cases["MODEL"]["main.py"]
    assert '"model_corrigibility": "UNKNOWN"' in cases["MODEL"]["main.py"]
    assert "NOT_ASSUMED_OPEN_ENDED" in cases["AGENT"]["main.py"]
    assert "outside-sim-channel" in cases["BOT"]["main.py"]
    assert "containment disappeared" in cases["SIM"]["main.py"]


def test_live_suite_never_weakens_known_failure_or_overwrites_receipts(backend, tmp_path, monkeypatch) -> None:
    from verifier.runtime import public_cli
    from vstd_openshell.live import run_suite
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config()), encoding="utf-8")

    def failed_cli(argv):
        kind = argv[argv.index("--object-kind") + 1]
        print(json.dumps({"status": "FAIL" if kind == "MODEL" else "UNKNOWN",
                          "blockers": ["TEST_FAULT_INJECTION"], "execution_performed": False}))
        return 1 if kind == "MODEL" else 2

    monkeypatch.setattr(public_cli, "main", failed_cli)
    output = tmp_path / "receipts"
    result = run_suite(path, output)
    assert result["status"] == "FAIL"
    assert len(list(output.glob("*/receipt.json"))) == 4
    with pytest.raises(FileExistsError):
        run_suite(path, output)


def test_effective_policy_cannot_grow_network_grants(backend) -> None:
    detail = {"labels": {"vstd-run": "test"}, "workspace": "default", "id": "id", "phase": "Ready",
              "policy": {**backend.POLICY, "network_policies": {"internet": {}}}}
    with pytest.raises(ValueError, match="UNEXPECTED_NETWORK_GRANT"):
        backend._binding(detail, config(), "test")


def fake_transport(backend, monkeypatch, *, change=False, cleanup_failure=False, reject_probe=False):
    calls = []
    state = {"token": "", "phase": "Ready", "deleted": False, "gets": 0}
    monkeypatch.setattr(backend.shutil, "which", lambda _: sys.executable)

    def capture(argv, timeout, env):
        assert "OPENSHELL_GATEWAY_INSECURE" not in env
        calls.append(argv)
        output = ""
        code = 0
        if "--version" in argv:
            output = "openshell 0.1.3\n"
        elif "gateway" in argv and "list" in argv:
            output = json.dumps([{"name": "test"}])
        elif "gateway" in argv and "info" in argv:
            output = json.dumps({"gateway": "test", "status": "healthy", "version": "0.1.3"})
        elif "create" in argv:
            state["token"] = argv[argv.index("--label") + 1].split("=", 1)[1]
        elif "get" in argv:
            state["gets"] += 1
            detail = {"id": "sandbox-id", "workspace": "default", "labels": {"vstd-run": state["token"]},
                "phase": state["phase"], "policy": backend.POLICY, "main_process_instance_id": "generation-1",
                "configuration_admission": {"state": "accepted", "policy_hash": "bound-hash", "config_revision": 1}}
            if change and state["gets"] == 2:
                detail["main_process_instance_id"] = "generation-2"
            output = json.dumps(detail)
        elif "exec" in argv:
            if backend.PROBE in argv:
                output = json.dumps({key: not reject_probe for key in backend.CONTROL_NAMES})
                code = int(reject_probe)
            else:
                output = "42\n"
        elif "stop" in argv:
            state["phase"] = "Stopped"
            code = int(cleanup_failure)
        elif "delete" in argv:
            state["deleted"] = True
        elif "list" in argv:
            output = json.dumps({"sandboxes": [] if state["deleted"] else [{}], "next_page_token": ""})
        return {"argv": argv, "exit_code": code, "stdout": output, "stderr": "", "timeout": False,
                "output_limit": False, "output_incomplete": False}

    monkeypatch.setattr(backend, "_capture", capture)
    return calls


def test_transport_success_has_exact_target_and_verified_cleanup(backend, tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("OPENSHELL_GATEWAY_INSECURE", "true")
    calls = fake_transport(backend, monkeypatch)
    result = backend.run(request(tmp_path))
    assert result["status"] == "PASS"
    assert result["cleanup"] == "DELETED"
    assert result["binding_before"] == result["binding_after"]
    assert result["obligation_status"] == "UNKNOWN"
    create = next(c for c in calls if "create" in c)
    assert len(create[create.index("--name") + 1]) <= 19
    assert len(create[create.index("--label") + 1].split("=", 1)[1]) == 32
    assert all("--gateway" in c and "--workspace" in c for c in calls[1:])
    assert all("--no-login-shell" in c for c in calls if "exec" in c)
    assert all("BASH_ENV=/dev/null" in c and "TMPDIR=/sandbox" in c for c in calls if "exec" in c)
    from verifier.core.namespace import NamespaceObject
    env = result["environment"]
    represented = NamespaceObject.create(**env["object"])
    assert represented.kind.value == "ENV"
    assert represented.digest == env["object_digest"] == env["subject_binding"]["target_digest"]
    assert env["subject_binding"]["targets"] == [represented.object_id]
    assert env["subject_binding"]["role"] == "env"
    assert env["subject_binding"]["subject_source_sha256"] == result["source_sha256"]
    assert represented.payload["runtime_before"] == result["binding_before"]
    assert env["obligation_status"] == "UNKNOWN"


@pytest.mark.parametrize("option,expected", [("change", "FAIL"), ("cleanup_failure", "UNKNOWN"),
                                            ("reject_probe", "UNKNOWN")])
def test_failed_binding_denial_or_cleanup_never_passes(backend, tmp_path, monkeypatch, option, expected) -> None:
    calls = fake_transport(backend, monkeypatch, **{option: True})
    result = backend.run(request(tmp_path))
    assert result["status"] == expected
    if option == "reject_probe":
        assert not result["execution_performed"]
        assert not any("/sandbox/source/main.py" in c for c in calls)
    if option == "cleanup_failure":
        assert "RUNNER_SANDBOX_CLEANUP_NOT_ESTABLISHED" in result["blockers"]


def test_live_negative_inventory_is_explicit_and_bounded(backend) -> None:
    from vstd_openshell.live import negative_specimens

    cases = negative_specimens()
    assert set(cases) == {
        "DENIED_FILESYSTEM_ESCAPE",
        "DENIED_NETWORK_ESCAPE",
        "INVALID_BOT_CHANNEL_BINDING",
        "DESCENDANT_PERSISTENCE_CLEANUP",
        "GATEWAY_TRANSPORT_DENIAL",
    }
    assert {case["expected_cleanup"] for case in cases.values()} == {
        "DELETED",
        "NOT_CREATED",
    }
    for case in cases.values():
        assert 1 <= case["timeout_seconds"] <= 20
        assert case["output_limit_bytes"] == backend.LIMIT
        assert case["qualification"] == "NOT_ESTABLISHED"
        for name, source in case["files"].items():
            if name.endswith(".py"):
                compile(source, name, "exec")


def _closed_negative_report(backend, case, files, selected_config, observation):
    hashes = {name: backend._digest(source.encode()) for name, source in files.items()}
    command = {
        "argv": ["openshell", "sandbox", "exec"],
        "exit_code": 0,
        "stdout": "",
        "stderr": "",
        "stdout_sha256": backend._digest(b""),
        "stderr_sha256": backend._digest(b""),
        "timeout": False,
        "output_limit": False,
        "output_incomplete": False,
        "elapsed_seconds": 0.01,
    }
    execution = dict(command)
    execution["stdout"] = json.dumps(observation, sort_keys=True) + "\n"
    execution["stdout_sha256"] = backend._digest(execution["stdout"].encode())
    binding = {
        "id": "sandbox-id",
        "instance": "generation-1",
        "policy_hash": "bound-hash",
        "config_revision": 1,
        "policy": backend.POLICY,
    }
    nested = {
        "schema_version": "verifier-openshell-result-1",
        "status": "PASS",
        "sandbox_status": "BOUNDED_PROBES_PASS",
        "obligation_status": "UNKNOWN",
        "execution_performed": True,
        "blockers": [],
        "commands": [command, execution],
        "cleanup": case["expected_cleanup"],
        "config": dict(selected_config),
        "adapter_sha256": "a" * 64,
        "cli_sha256": "b" * 64,
        "requested_policy_sha256": "c" * 64,
        "source_sha256": dict(hashes),
        "binding_before": binding,
        "binding_after": binding,
        "execution": execution,
    }
    return {
        "schema_version": "verifier-language-runner-1",
        "status": "PASS",
        "blockers": [],
        "execution_performed": True,
        "receipt": nested,
        "cli_exit_code": 0,
    }, hashes


def test_negative_expected_refusal_requires_closed_receipt(backend) -> None:
    from vstd_openshell.live import _evaluate_negative_report, negative_specimens

    case = negative_specimens()["DENIED_FILESYSTEM_ESCAPE"]
    selected = config()
    report, hashes = _closed_negative_report(
        backend,
        case,
        case["files"],
        selected,
        {
            "scenario_id": "DENIED_FILESYSTEM_ESCAPE",
            "observation": "POLICY_DENIED",
            "errno": 13,
        },
    )
    evaluation = _evaluate_negative_report(case, report, selected, hashes)
    assert evaluation["status"] == "PASS"
    assert evaluation["qualification"] == "NOT_ESTABLISHED"

    # A green runner result without the expected denial is not negative evidence.
    report["receipt"]["execution"]["stdout"] = json.dumps({
        "scenario_id": "DENIED_FILESYSTEM_ESCAPE",
        "observation": "ESCAPE_SUCCEEDED",
        "errno": None,
    }) + "\n"
    report["receipt"]["execution"]["stdout_sha256"] = backend._digest(
        report["receipt"]["execution"]["stdout"].encode()
    )
    assert _evaluate_negative_report(case, report, selected, hashes)["status"] == "FAIL"


@pytest.mark.parametrize(
    "mutation",
    ["source", "config", "image", "software", "policy", "binding", "cleanup", "output_limit"],
)
def test_negative_receipt_mutation_or_forgery_is_rejected(backend, mutation) -> None:
    from vstd_openshell.live import _evaluate_negative_report, negative_specimens

    case = negative_specimens()["DENIED_NETWORK_ESCAPE"]
    selected = config()
    report, hashes = _closed_negative_report(
        backend,
        case,
        case["files"],
        selected,
        {
            "scenario_id": "DENIED_NETWORK_ESCAPE",
            "observation": "POLICY_DENIED",
            "errno": 1,
        },
    )
    if mutation == "source":
        report["receipt"]["source_sha256"]["main.py"] = "0" * 64
    elif mutation == "config":
        report["receipt"]["config"]["gateway"] = "forged"
    elif mutation == "image":
        report["receipt"]["config"]["image"] = "forged.invalid/image@sha256:" + "0" * 64
    elif mutation == "software":
        report["receipt"]["adapter_sha256"] = "0" * 63
    elif mutation == "policy":
        report["receipt"]["requested_policy_sha256"] = "0" * 63
    elif mutation == "binding":
        report["receipt"]["binding_after"] = {
            **report["receipt"]["binding_after"],
            "instance": "forged-generation",
        }
    elif mutation == "cleanup":
        report["receipt"]["cleanup"] = "UNKNOWN"
    else:
        report["receipt"]["commands"][0]["output_limit"] = True
    assert _evaluate_negative_report(case, report, selected, hashes)["status"] == "FAIL"


def test_live_negative_suite_constructs_commands_and_closes_receipts(
    backend, tmp_path, monkeypatch
) -> None:
    from verifier.runtime import public_cli
    from vstd_openshell.live import negative_specimens, run_suite

    path = tmp_path / "config.json"
    path.write_text(json.dumps(config()), encoding="utf-8")
    seen = []

    def simulated_cli(argv):
        seen.append(list(argv))
        root = Path(argv[argv.index("--root") + 1])
        kind = argv[argv.index("--object-kind") + 1]
        selected = json.loads(Path(argv[argv.index("--sandbox-config") + 1]).read_text())
        main = (root / "main.py").read_text()
        case = next(
            (item for item in negative_specimens().values() if item["marker"] in main),
            None,
        )
        if case is None:
            print(json.dumps({
                "status": "PASS",
                "blockers": [],
                "execution_performed": True,
                "receipt": {"cleanup": "DELETED"},
            }))
            return 0
        files = {
            name: (root / name).read_text()
            for name in ["main.py", *argv[argv.index("--json") + 1 :]]
            if (root / name).is_file()
        }
        files = {path.name: path.read_text() for path in root.iterdir() if path.name != "sandbox.json"}
        if case["scenario_id"] == "GATEWAY_TRANSPORT_DENIAL":
            command = {
                "argv": ["openshell", "gateway", "list"],
                "exit_code": 0,
                "stdout": "[]",
                "stderr": "",
                "stdout_sha256": backend._digest(b"[]"),
                "stderr_sha256": backend._digest(b""),
                "timeout": False,
                "output_limit": False,
                "output_incomplete": False,
                "elapsed_seconds": 0.01,
            }
            report = {
                "schema_version": "verifier-language-runner-1",
                "status": "UNKNOWN",
                "blockers": ["RUNNER_OPENSHELL_GATEWAY_NOT_REGISTERED"],
                "execution_performed": False,
                "cli_exit_code": 2,
                "receipt": {
                    "schema_version": "verifier-openshell-result-1",
                    "status": "UNKNOWN",
                    "sandbox_status": "NOT_ESTABLISHED",
                    "obligation_status": "UNKNOWN",
                    "blockers": ["RUNNER_OPENSHELL_GATEWAY_NOT_REGISTERED"],
                    "execution_performed": False,
                    "commands": [command],
                    "cleanup": "NOT_CREATED",
                    "config": selected,
                    "adapter_sha256": "a" * 64,
                    "cli_sha256": "b" * 64,
                },
            }
            print(json.dumps(report))
            return 2
        observation = case["test_observation"]
        report, _ = _closed_negative_report(backend, case, files, selected, observation)
        print(json.dumps(report))
        return 0

    monkeypatch.setattr(public_cli, "main", simulated_cli)
    output = tmp_path / "receipts"
    summary = run_suite(path, output)
    assert summary["negative_scenarios"]["status"] == "PASS"
    assert summary["qualification"] == "NOT_ESTABLISHED"
    negative_calls = [call for call in seen if "negative-" in call[call.index("--root") + 1]]
    assert len(negative_calls) == 5
    assert all(call[call.index("--timeout") + 1] == "20" for call in negative_calls)
    assert {call[call.index("--object-kind") + 1] for call in negative_calls} == {"AGENT", "BOT"}
    closures = list((output / "negative").glob("*/closure.json"))
    assert len(closures) == 5
    for closure_path in closures:
        closure = json.loads(closure_path.read_text())
        claimed = closure.pop("closure_sha256")
        assert claimed == backend._digest(json.dumps(closure, sort_keys=True).encode())
        case_root = closure_path.parent
        assert closure["source_sha256"] == {
            name: backend._digest((case_root / name).read_bytes())
            for name in closure["source_sha256"]
        }
        assert closure["config_sha256"] == backend._digest(
            (case_root / "sandbox.json").read_bytes()
        )
        assert closure["image"] == json.loads(
            (case_root / "sandbox.json").read_text()
        )["image"]
        assert closure["report_sha256"] == backend._digest(
            json.dumps(json.loads((case_root / "receipt.json").read_text()), sort_keys=True).encode()
        )
    with pytest.raises(FileExistsError):
        run_suite(path, output)
