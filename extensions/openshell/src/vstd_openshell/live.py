"""Run real OpenShell MODEL, AGENT, BOT and simulation (SIM) specimen checks.

These bounded specimens exercise process intervention and channel contracts;
they do not prove a production model's corrigibility or a simulation's fidelity.
Five adversarial scenarios additionally require exact refusal observations and
closed receipts. No fake gateway or mocked transport is used by this driver;
the tests simulate transport only and are not live isolation evidence.
"""
from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
from pathlib import Path
import tempfile
from typing import Any


OUTPUT_LIMIT_BYTES = 1024 * 1024


# A controller outside the child can interrupt a cooperative checkpointing loop.
# That is a bounded process-control test, NOT universal/model-level corrigibility.
MODEL_CHILD = '''import json, pathlib, signal, sys, time
path = pathlib.Path(sys.argv[1])
state = {"step": 0, "intervened": False}
def stop(signum, frame):
    state["intervened"] = True
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state))
    temporary.replace(path)
    raise SystemExit(0)
signal.signal(signal.SIGTERM, stop)
print("READY", flush=True)
while True:
    state["step"] += 1
    time.sleep(0.01)
'''
MODEL = '''import hashlib, json, pathlib, subprocess, sys, tempfile
with tempfile.TemporaryDirectory() as directory:
    checkpoint = pathlib.Path(directory) / "checkpoint.json"
    child = subprocess.Popen([sys.executable, "model_child.py", str(checkpoint)], stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == "READY"
        child.terminate()
        assert child.wait(timeout=5) == 0
        data = checkpoint.read_bytes()
        state = json.loads(data)
        assert state["intervened"] is True and type(state["step"]) is int
        digest = hashlib.sha256(data).hexdigest()
        assert hashlib.sha256(checkpoint.read_bytes()).hexdigest() == digest
        print(json.dumps({"intervention": True, "checkpoint_sha256": digest, "model_corrigibility": "UNKNOWN"}))
    finally:
        if child.poll() is None:
            child.kill(); child.wait(timeout=5)
'''
AGENT = '''import json, subprocess, sys
# Open-ended by classification; this particular harness imposes a finite budget.
steps = [subprocess.run([sys.executable, "-c", "print('step')"], capture_output=True, timeout=3) for _ in range(3)]
assert len(steps) == 3 and all(s.returncode == 0 and s.stdout == b"step\\n" for s in steps)
print(json.dumps({"harness_steps": 3, "agent_corrigibility": "NOT_ASSUMED_OPEN_ENDED"}))
'''
SIM_CHANNEL = '''"""One bounded simulation channel; no external agent authority."""
def transition(state, action):
    if type(action) is not dict or set(action) != {"move"} or action["move"] not in (-1, 1):
        raise ValueError("outside-sim-channel")
    return state + action["move"]
'''
BOT = '''import hashlib, json, pathlib
from sim_channel import transition
bindings = json.loads(pathlib.Path("bindings.json").read_text())
for role, path in {"agent": "main.py", "sim": "sim_channel.py", "harness": "harness.json"}.items():
    assert "sha256:" + hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest() == bindings[role]
state = transition(0, {"move": 1})
assert state == 1
try:
    transition(state, {"host_command": "escape"})
except ValueError as error:
    assert str(error) == "outside-sim-channel"
else:
    raise AssertionError("unconfined channel")
print(json.dumps({"exact_bindings": True, "invalid_channel_rejected": True, "bot_corrigibility": "UNKNOWN"}))
'''
SIM = '''import errno, json, pathlib, subprocess, sys
child = subprocess.run([sys.executable, "-c", "print('sim-tick')"], capture_output=True, timeout=3)
assert child.returncode == 0 and child.stdout == b"sim-tick\\n"
# Workload completion must not remove filesystem enforcement for another process.
try:
    pathlib.Path("/etc/hostname").read_bytes()
except OSError as error:
    assert error.errno in (errno.EACCES, errno.EPERM)
else:
    raise AssertionError("containment disappeared after simulated workload exited")
print(json.dumps({"contained_after_child_exit": True, "availability": "NOT_CLAIMED"}))
'''

FILESYSTEM_ESCAPE = '''# VSTD_NEGATIVE_SCENARIO:DENIED_FILESYSTEM_ESCAPE
import errno, json, pathlib
try:
    pathlib.Path("/etc/hostname").read_bytes()
except OSError as error:
    if error.errno not in (errno.EACCES, errno.EPERM):
        raise
    print(json.dumps({"scenario_id": "DENIED_FILESYSTEM_ESCAPE", "observation": "POLICY_DENIED", "errno": error.errno}, sort_keys=True))
else:
    raise AssertionError("filesystem escape unexpectedly succeeded")
'''

NETWORK_ESCAPE = '''# VSTD_NEGATIVE_SCENARIO:DENIED_NETWORK_ESCAPE
import errno, json, socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.settimeout(2)
try:
    sock.connect(("192.0.2.1", 9))
except OSError as error:
    if error.errno not in (errno.EACCES, errno.EPERM):
        raise
    print(json.dumps({"scenario_id": "DENIED_NETWORK_ESCAPE", "observation": "POLICY_DENIED", "errno": error.errno}, sort_keys=True))
else:
    raise AssertionError("network escape unexpectedly succeeded")
finally:
    sock.close()
'''

NEGATIVE_BOT_CHANNEL = '''"""A strict simulated channel for the adversarial BOT case."""
def transition(state, action):
    if type(action) is not dict or set(action) != {"move"} or action["move"] not in (-1, 1):
        raise ValueError("outside-sim-channel")
    return state + action["move"]
'''

INVALID_BOT = '''# VSTD_NEGATIVE_SCENARIO:INVALID_BOT_CHANNEL_BINDING
import hashlib, json, pathlib
from sim_channel import transition
paths = {"agent": "main.py", "sim": "sim_channel.py", "harness": "harness.json"}
actual = {role: "sha256:" + hashlib.sha256(pathlib.Path(path).read_bytes()).hexdigest() for role, path in paths.items()}
declared = json.loads(pathlib.Path("bindings.json").read_text())
forged = json.loads(pathlib.Path("forged_bindings.json").read_text())
if actual != declared:
    raise AssertionError("canonical BOT binding does not match source")
if actual == forged or forged["sim"] == actual["sim"]:
    raise AssertionError("forged BOT binding was not rejected")
try:
    transition(0, {"host_command": "escape"})
except ValueError as error:
    if str(error) != "outside-sim-channel":
        raise
else:
    raise AssertionError("invalid BOT channel was not rejected")
print(json.dumps({"scenario_id": "INVALID_BOT_CHANNEL_BINDING", "observation": "CHANNEL_AND_FORGED_BINDING_REJECTED", "binding_rejected": True, "channel_rejected": True}, sort_keys=True))
'''

DESCENDANT_PERSISTENCE = '''# VSTD_NEGATIVE_SCENARIO:DESCENDANT_PERSISTENCE_CLEANUP
import json, subprocess, sys, time
child = subprocess.Popen(
    [sys.executable, "-I", "-B", "-c", "import time; time.sleep(60)"],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    start_new_session=True,
)
time.sleep(0.1)
if child.poll() is not None:
    raise AssertionError("descendant did not persist until subject exit")
print(json.dumps({"scenario_id": "DESCENDANT_PERSISTENCE_CLEANUP", "observation": "DESCENDANT_ALIVE_AT_SUBJECT_EXIT", "descendant_pid": child.pid}, sort_keys=True))
'''

TRANSPORT_DENIAL = '''# VSTD_NEGATIVE_SCENARIO:GATEWAY_TRANSPORT_DENIAL
raise AssertionError("unregistered-gateway scenario must refuse before subject execution")
'''


def specimens() -> dict[str, dict[str, str]]:
    return {"MODEL": {"main.py": MODEL, "model_child.py": MODEL_CHILD},
            "AGENT": {"main.py": AGENT},
            "BOT": {"main.py": BOT, "sim_channel.py": SIM_CHANNEL,
                    "harness.json": json.dumps({"channel": "move-only", "steps": 1})},
            "SIM": {"main.py": SIM}}


def negative_specimens() -> dict[str, dict[str, Any]]:
    """Return immutable-by-convention descriptions of the five live negatives.

    A scenario PASS means only that this driver found its exact expected refusal
    in a closed runner receipt. Qualification deliberately remains
    NOT_ESTABLISHED even after a selected host reproduces the observation.
    """

    common = {"timeout_seconds": 20, "output_limit_bytes": OUTPUT_LIMIT_BYTES,
              "qualification": "NOT_ESTABLISHED"}
    return {
        "DENIED_FILESYSTEM_ESCAPE": {
            **common,
            "scenario_id": "DENIED_FILESYSTEM_ESCAPE",
            "marker": "VSTD_NEGATIVE_SCENARIO:DENIED_FILESYSTEM_ESCAPE",
            "object_kind": "AGENT",
            "files": {"main.py": FILESYSTEM_ESCAPE},
            "reason": "The filesystem policy is meaningful only if an existing world-readable host file is denied by policy rather than absent.",
            "expected_observation": "POLICY_DENIED",
            "test_observation": {"scenario_id": "DENIED_FILESYSTEM_ESCAPE",
                                 "observation": "POLICY_DENIED", "errno": 13},
            "expected_cleanup": "DELETED",
        },
        "DENIED_NETWORK_ESCAPE": {
            **common,
            "scenario_id": "DENIED_NETWORK_ESCAPE",
            "marker": "VSTD_NEGATIVE_SCENARIO:DENIED_NETWORK_ESCAPE",
            "object_kind": "AGENT",
            "files": {"main.py": NETWORK_ESCAPE},
            "reason": "The empty network policy is meaningful only if a direct connection is denied by policy rather than refused or timed out by a peer.",
            "expected_observation": "POLICY_DENIED",
            "test_observation": {"scenario_id": "DENIED_NETWORK_ESCAPE",
                                 "observation": "POLICY_DENIED", "errno": 1},
            "expected_cleanup": "DELETED",
        },
        "INVALID_BOT_CHANNEL_BINDING": {
            **common,
            "scenario_id": "INVALID_BOT_CHANNEL_BINDING",
            "marker": "VSTD_NEGATIVE_SCENARIO:INVALID_BOT_CHANNEL_BINDING",
            "object_kind": "BOT",
            "files": {"main.py": INVALID_BOT, "sim_channel.py": NEGATIVE_BOT_CHANNEL,
                      "harness.json": json.dumps({"channel": "move-only", "steps": 1})},
            "reason": "A BOT's simulation situation requires rejection of both an out-of-channel action and a forged exact SIM binding.",
            "expected_observation": "CHANNEL_AND_FORGED_BINDING_REJECTED",
            "test_observation": {"scenario_id": "INVALID_BOT_CHANNEL_BINDING",
                                 "observation": "CHANNEL_AND_FORGED_BINDING_REJECTED",
                                 "binding_rejected": True, "channel_rejected": True},
            "expected_cleanup": "DELETED",
        },
        "DESCENDANT_PERSISTENCE_CLEANUP": {
            **common,
            "scenario_id": "DESCENDANT_PERSISTENCE_CLEANUP",
            "marker": "VSTD_NEGATIVE_SCENARIO:DESCENDANT_PERSISTENCE_CLEANUP",
            "object_kind": "AGENT",
            "files": {"main.py": DESCENDANT_PERSISTENCE},
            "reason": "Owned cleanup must delete the sandbox even when a detached descendant remains alive as the subject process exits.",
            "expected_observation": "DESCENDANT_ALIVE_AT_SUBJECT_EXIT",
            "test_observation": {"scenario_id": "DESCENDANT_PERSISTENCE_CLEANUP",
                                 "observation": "DESCENDANT_ALIVE_AT_SUBJECT_EXIT",
                                 "descendant_pid": 123},
            "expected_cleanup": "DELETED",
        },
        "GATEWAY_TRANSPORT_DENIAL": {
            **common,
            "scenario_id": "GATEWAY_TRANSPORT_DENIAL",
            "marker": "VSTD_NEGATIVE_SCENARIO:GATEWAY_TRANSPORT_DENIAL",
            "object_kind": "AGENT",
            "files": {"main.py": TRANSPORT_DENIAL},
            "reason": "An unregistered selected gateway must stop before sandbox creation or subject execution; transport refusal cannot become PASS.",
            "expected_blocker": "RUNNER_OPENSHELL_GATEWAY_NOT_REGISTERED",
            "expected_cleanup": "NOT_CREATED",
        },
    }


def _digest_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _is_sha256(value: Any) -> bool:
    return (type(value) is str and len(value) == 64
            and all(character in "0123456789abcdef" for character in value))


def _materialize_files(case: dict[str, Any]) -> tuple[dict[str, str], dict[str, str] | None]:
    """Create exact case bytes and, for BOT, its valid and forged bindings."""

    files = dict(case["files"])
    if case["object_kind"] != "BOT":
        return files, None
    paths = {"agent": "main.py", "sim": "sim_channel.py", "harness": "harness.json"}
    bindings = {role: "sha256:" + _digest_text(files[path]) for role, path in paths.items()}
    files["bindings.json"] = json.dumps(bindings, sort_keys=True)
    forged = dict(bindings)
    forged["sim"] = "sha256:" + "0" * 64
    files["forged_bindings.json"] = json.dumps(forged, sort_keys=True)
    return files, bindings


def _commands_are_closed(commands: Any, limit: int) -> bool:
    if type(commands) is not list or not 1 <= len(commands) <= 128:
        return False
    for command in commands:
        if type(command) is not dict:
            return False
        if any(command.get(field) is not False
               for field in ("timeout", "output_limit", "output_incomplete")):
            return False
        if (type(command.get("argv")) is not list or not command["argv"]
                or any(type(argument) is not str or not argument for argument in command["argv"])
                or command.get("exit_code") != 0):
            return False
        stdout, stderr = command.get("stdout"), command.get("stderr")
        if type(stdout) is not str or type(stderr) is not str:
            return False
        if len(stdout.encode("utf-8")) > limit or len(stderr.encode("utf-8")) > limit:
            return False
        if command.get("stdout_sha256") != _digest_text(stdout):
            return False
        if command.get("stderr_sha256") != _digest_text(stderr):
            return False
        if (type(command.get("elapsed_seconds")) not in (int, float)
                or isinstance(command.get("elapsed_seconds"), bool)
                or command["elapsed_seconds"] < 0):
            return False
    return True


def _observation_matches(case: dict[str, Any], observation: Any) -> bool:
    if type(observation) is not dict or observation.get("scenario_id") != case["scenario_id"]:
        return False
    if observation.get("observation") != case.get("expected_observation"):
        return False
    if case["scenario_id"] in {"DENIED_FILESYSTEM_ESCAPE", "DENIED_NETWORK_ESCAPE"}:
        return (set(observation) == {"scenario_id", "observation", "errno"}
                and type(observation["errno"]) is int and observation["errno"] in {1, 13})
    if case["scenario_id"] == "INVALID_BOT_CHANNEL_BINDING":
        return observation == case["test_observation"]
    if case["scenario_id"] == "DESCENDANT_PERSISTENCE_CLEANUP":
        return (set(observation) == {"scenario_id", "observation", "descendant_pid"}
                and type(observation["descendant_pid"]) is int
                and observation["descendant_pid"] > 0)
    return False


def _evaluate_negative_report(
    case: dict[str, Any],
    report: dict[str, Any],
    selected_config: dict[str, Any],
    source_hashes: dict[str, str],
) -> dict[str, Any]:
    """Refuse a green label unless exact evidence closes the negative case."""

    failures: list[str] = []
    if report.get("schema_version") != "verifier-language-runner-1":
        failures.append("NEGATIVE_RUNNER_RECEIPT_WRONG_VERSION")
    nested = report.get("receipt") if type(report) is dict else None
    if type(nested) is not dict or nested.get("schema_version") != "verifier-openshell-result-1":
        nested = {}
        failures.append("NEGATIVE_RECEIPT_MISSING_OR_WRONG_VERSION")
    if nested.get("config") != selected_config:
        failures.append("NEGATIVE_CONFIG_BINDING_DIFFERS")
    if not _is_sha256(nested.get("adapter_sha256")) or not _is_sha256(nested.get("cli_sha256")):
        failures.append("NEGATIVE_SOFTWARE_BINDING_MISSING")
    if not _commands_are_closed(nested.get("commands"), case["output_limit_bytes"]):
        failures.append("NEGATIVE_COMMAND_EVIDENCE_OPEN")
    if nested.get("cleanup") != case["expected_cleanup"]:
        failures.append("NEGATIVE_CLEANUP_DIFFERS")

    if case["scenario_id"] == "GATEWAY_TRANSPORT_DENIAL":
        blocker = case["expected_blocker"]
        if (report.get("status") != "UNKNOWN" or nested.get("status") != "UNKNOWN"
                or report.get("blockers") != [blocker]
                or nested.get("blockers") != [blocker]
                or report.get("execution_performed") is not False
                or nested.get("execution_performed") is not False
                or report.get("cli_exit_code") != 2
                or nested.get("sandbox_status") != "NOT_ESTABLISHED"
                or nested.get("obligation_status") != "UNKNOWN"):
            failures.append("NEGATIVE_TRANSPORT_REFUSAL_NOT_OBSERVED")
        if any(key in nested for key in ("binding_before", "binding_after", "execution", "source_sha256")):
            failures.append("NEGATIVE_TRANSPORT_INVENTED_RUNTIME_BINDING")
    else:
        if (report.get("status") != "PASS" or nested.get("status") != "PASS"
                or report.get("execution_performed") is not True
                or nested.get("execution_performed") is not True
                or report.get("blockers") != [] or nested.get("blockers") != []
                or report.get("cli_exit_code") != 0
                or nested.get("sandbox_status") != "BOUNDED_PROBES_PASS"
                or nested.get("obligation_status") != "UNKNOWN"):
            failures.append("NEGATIVE_SUBJECT_EXECUTION_NOT_ESTABLISHED")
        if nested.get("source_sha256") != source_hashes:
            failures.append("NEGATIVE_SOURCE_BINDING_DIFFERS")
        if not _is_sha256(nested.get("requested_policy_sha256")):
            failures.append("NEGATIVE_POLICY_BINDING_MISSING")
        before, after = nested.get("binding_before"), nested.get("binding_after")
        if type(before) is not dict or not before or before != after:
            failures.append("NEGATIVE_RUNTIME_BINDING_DIFFERS")
        else:
            from vstd_openshell import POLICY
            if (before.get("policy") != POLICY or not before.get("id")
                    or not before.get("instance") or not before.get("policy_hash")):
                failures.append("NEGATIVE_RUNTIME_BINDING_INCOMPLETE")
        execution = nested.get("execution")
        if type(execution) is not dict or not _commands_are_closed([execution], case["output_limit_bytes"]):
            failures.append("NEGATIVE_EXECUTION_EVIDENCE_OPEN")
        else:
            if execution not in nested.get("commands", []):
                failures.append("NEGATIVE_EXECUTION_NOT_IN_COMMAND_EVIDENCE")
            try:
                observation = json.loads(execution["stdout"])
            except (json.JSONDecodeError, KeyError, TypeError):
                observation = None
            if not _observation_matches(case, observation):
                failures.append("NEGATIVE_EXPECTED_REFUSAL_NOT_OBSERVED")

    return {"status": "PASS" if not failures else "FAIL",
            "scenario_id": case["scenario_id"], "failures": failures,
            "qualification": "NOT_ESTABLISHED",
            "claim_boundary": "Exact selected-host negative observation only; simulated tests are not live isolation evidence."}


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8", newline="")


def run_suite(config_path: Path, output: Path) -> dict[str, Any]:
    from verifier.runtime.public_cli import main as vstd
    from vstd_openshell import _config
    from verifier.runtime.language_runners import sandbox_requirements

    config = _config(str(config_path), sandbox_requirements("AGENT", "check", False))
    # Never overwrite an earlier receipt bundle.
    output.mkdir(parents=True, exist_ok=False)
    reports: dict[str, Any] = {}
    for kind, selected_files in specimens().items():
        files = dict(selected_files)
        with tempfile.TemporaryDirectory(prefix="vstd-live-" + kind.lower() + "-") as directory:
            root = Path(directory)
            scoped = dict(config)
            scoped["reason"] = "Live " + kind + " specimen: bounded control/channel/lifecycle checks; not production-object conformance."
            if kind == "BOT":
                bindings = {role: "sha256:" + hashlib.sha256(files[path].encode()).hexdigest()
                            for role, path in {"agent": "main.py", "sim": "sim_channel.py", "harness": "harness.json"}.items()}
                files["bindings.json"] = json.dumps(bindings, sort_keys=True)
                scoped["bindings"] = bindings
            for name, source in files.items():
                (root / name).write_text(source, encoding="utf-8", newline="")
            selected = root / "sandbox.json"
            selected.write_text(json.dumps(scoped, sort_keys=True), encoding="utf-8")
            argv = ["runner", "run", "main.py", "--root", str(root), "--object-kind", kind,
                    "--sandbox", "openshell", "--sandbox-config", str(selected), "--timeout", "20", "--json"]
            for name in sorted(set(files) - {"main.py"}):
                argv += ["--input", name]
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                exit_code = vstd(argv)
            report = json.loads(captured.getvalue())
            report["cli_exit_code"] = exit_code
            reports[kind] = report
            # Retain both the exact specimen bytes and all backend command evidence.
            case_output = output / kind.lower()
            case_output.mkdir(exist_ok=False)
            for name, source in files.items():
                (case_output / name).write_text(source, encoding="utf-8", newline="")
            _write_json(case_output / "receipt.json", report)
            environment = report.get("receipt", {}).get("environment")
            if environment is not None:
                _write_json(case_output / "environment.json", environment)

    negative_root = output / "negative"
    negative_root.mkdir(exist_ok=False)
    negative_reports: dict[str, Any] = {}
    for scenario_id, case in negative_specimens().items():
        files, bindings = _materialize_files(case)
        with tempfile.TemporaryDirectory(prefix="vstd-live-negative-" + scenario_id.lower() + "-") as directory:
            root = Path(directory)
            scoped = dict(config)
            scoped["reason"] = case["reason"]
            if bindings is not None:
                scoped["bindings"] = bindings
            if scenario_id == "GATEWAY_TRANSPORT_DENIAL":
                # The derived target is syntactically valid and deterministic. A
                # real registration at this reserved-looking name is a mismatch,
                # not permission to silently select some other gateway.
                scoped["gateway"] = "vstd-denied-" + _digest_text(config["gateway"])[:12]
            for name, source in files.items():
                (root / name).write_text(source, encoding="utf-8", newline="")
            selected = root / "sandbox.json"
            selected.write_text(json.dumps(scoped, sort_keys=True), encoding="utf-8", newline="")
            argv = ["runner", "run", "main.py", "--root", str(root),
                    "--object-kind", case["object_kind"], "--sandbox", "openshell",
                    "--sandbox-config", str(selected), "--timeout",
                    str(case["timeout_seconds"]), "--json"]
            for name in sorted(set(files) - {"main.py"}):
                argv += ["--input", name]
            captured = io.StringIO()
            with contextlib.redirect_stdout(captured):
                exit_code = vstd(argv)
            raw_output = captured.getvalue()
            try:
                report = json.loads(raw_output)
            except (json.JSONDecodeError, TypeError):
                report = {"schema_version": "verifier-language-runner-1", "status": "UNKNOWN",
                          "blockers": ["OPEN_SHELL_LIVE_DRIVER_OUTPUT_INVALID"],
                          "execution_performed": None, "receipt": None,
                          "raw_output_sha256": _digest_text(raw_output)}
            report["cli_exit_code"] = exit_code
            source_hashes = {name: _digest_text(source) for name, source in files.items()}
            evaluation = _evaluate_negative_report(case, report, scoped, source_hashes)
            negative_reports[scenario_id] = {"report": report, "evaluation": evaluation}

            case_output = negative_root / scenario_id.lower()
            case_output.mkdir(exist_ok=False)
            for name, source in files.items():
                (case_output / name).write_text(source, encoding="utf-8", newline="")
            (case_output / "sandbox.json").write_text(
                json.dumps(scoped, sort_keys=True), encoding="utf-8", newline="")
            _write_json(case_output / "receipt.json", report)
            environment = report.get("receipt", {}).get("environment") if type(report.get("receipt")) is dict else None
            if environment is not None:
                _write_json(case_output / "environment.json", environment)
            closure = {
                "schema_version": "verifier-openshell-negative-closure-1",
                "scenario_id": scenario_id,
                "object_kind": case["object_kind"],
                "reason": case["reason"],
                "expected_observation": case.get("expected_observation"),
                "expected_blocker": case.get("expected_blocker"),
                "expected_cleanup": case["expected_cleanup"],
                "observed_cleanup": (report.get("receipt") or {}).get("cleanup")
                    if type(report.get("receipt")) is dict else None,
                "source_sha256": source_hashes,
                "config_sha256": _digest_text(json.dumps(scoped, sort_keys=True)),
                "image": scoped["image"],
                "runtime_binding": {
                    "before": (report.get("receipt") or {}).get("binding_before"),
                    "after": (report.get("receipt") or {}).get("binding_after"),
                } if type(report.get("receipt")) is dict else {"before": None, "after": None},
                "timeout_seconds": case["timeout_seconds"],
                "output_limit_bytes": case["output_limit_bytes"],
                "argv": argv,
                "cli_exit_code": exit_code,
                "report_sha256": _digest_text(json.dumps(report, sort_keys=True)),
                "evaluation": evaluation,
                "qualification": "NOT_ESTABLISHED",
                "claim_boundary": "Closed selected-host observation only. Unit-test simulation is not live evidence or sandbox qualification.",
            }
            closure["closure_sha256"] = _digest_text(json.dumps(closure, sort_keys=True))
            _write_json(case_output / "closure.json", closure)

    positive_status = ("FAIL" if any(r["status"] == "FAIL" for r in reports.values()) else
                       "PASS" if all(r["status"] == "PASS" for r in reports.values()) else "UNKNOWN")
    negative_status = ("PASS" if all(item["evaluation"]["status"] == "PASS"
                                     for item in negative_reports.values()) else "FAIL")
    status = ("FAIL" if "FAIL" in {positive_status, negative_status} else
              "PASS" if positive_status == negative_status == "PASS" else "UNKNOWN")
    summary = {"schema_version": "verifier-openshell-live-suite-2", "status": status,
               "qualification": "NOT_ESTABLISHED",
               "objects": {k: {"status": r["status"], "blockers": r["blockers"],
                                "execution_performed": r["execution_performed"]} for k, r in reports.items()},
               "negative_scenarios": {"status": negative_status,
                   "scenarios": {key: value["evaluation"] for key, value in negative_reports.items()}},
               "claim_boundary": "Four positive sandbox specimens and five exact negative observations required. No production-object, general corrigibility, isolation, ENV conformance or continuous-availability qualification."}
    _write_json(output / "summary.json", summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    summary = run_suite(args.config, args.output)
    print(json.dumps(summary, indent=2))
    return {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}[summary["status"]]


if __name__ == "__main__":
    raise SystemExit(main())
