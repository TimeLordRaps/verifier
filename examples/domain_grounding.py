"""Runnable Verifier Standard (VSTD) domain certification specimens.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
Terminology: unsatisfiable (UNSAT).
The datasets, numerical models and simulation are small complete retained
workloads. The environment example measures its actual in-process task using
Python traced-allocation peak bytes, wall seconds and active thread count.
"""
from __future__ import annotations

import base64
import hashlib
import inspect
import json
import threading
import time
import tracemalloc

from verifier.core.certificate import canonical_bytes
from verifier.domains.common import Budget, digest, merkle_root
from verifier.domains.env import collect_configuration


def _task(value: list) -> list:
    return sorted(value)


def token_issuer() -> tuple:
    """Return the example issuing key's public hex and a signer over canonical bytes.

    The key is derived from a public label, so its signatures authenticate nothing
    outside this example. Without the seal extra no signature can be made: a stand-in
    key and placeholder signatures keep every other TOKEN check runnable, and TOKEN.4
    reports UNKNOWN because no signature backend is available to check them.
    """
    seed = hashlib.sha256(b"example:token-issuer").digest()
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    except ImportError:
        placeholder = base64.b64encode(bytes(64)).decode()
        return hashlib.sha256(seed).hexdigest(), lambda body: placeholder
    key = Ed25519PrivateKey.from_private_bytes(seed)
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()
    return public, lambda body: base64.b64encode(key.sign(canonical_bytes(body))).decode()


def token_witness_keys() -> dict:
    """The checker's admission of the example issuing key, derived here and never read from a bundle."""
    return {"example:token-issuer": token_issuer()[0]}


def specimens() -> dict:
    """Produce actual retained inputs with independently calculable expected results."""
    result = {}
    def add(domain: str, artifact: dict, inputs: dict) -> None:
        result[domain] = {"schema_version": "verifier-domain-evidence-1", "domain": domain,
            "subject_id": "example:"+domain.lower(), "artifact": artifact, "inputs": inputs}
    train = [{"id": "a", "text": "red apple"}, {"id": "b", "text": "green pear"}]
    test = [{"id": "c", "text": "blue ocean"}]
    shards = {"source": train, "training": train, "testing": test}
    inventory = {k: {"digest": digest(v), "records": len(v), "bytes": len(canonical_bytes(v)),
                      "record_digests": [digest(r) for r in v], "merkle_root": merkle_root(v, Budget(10000))} for k,v in shards.items()}
    add("DATA", {"shards": inventory, "fields": {"id": "string", "text": "string"},
        "source_shards": ["source", "testing"],
        "transforms": [{"inputs": ["source"], "output": "training", "operation": "deduplicate", "parameters": {}}],
        "final_shards": ["training", "testing"], "splits": {"train": ["training"], "test": ["testing"]},
        "identity_field": "id", "overlap": {"train": "train", "evaluation": "test", "text_field": "text", "ngram": 1, "max_overlap": 0.0}}, {"shards": shards})
    source = inspect.getsource(_task).replace("\r\n", "\n").encode()
    file_digest = "sha256:"+hashlib.sha256(source).hexdigest()
    files = {"task.py": file_digest}
    config = collect_configuration()
    config["memory_measurement"] = "python-tracemalloc-peak-bytes"
    executions, measurements = [], []
    for index in range(2):
        tracemalloc.start()
        start = time.perf_counter()
        output = _task([3, 1, 2])
        elapsed = time.perf_counter()-start
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        measurements.append({"id": str(index), "wall_seconds": elapsed, "memory_bytes": peak, "threads": threading.active_count()})
        executions.append({"id": str(index), "software_digest": digest(files), "configuration_digest": digest(config),
            "executable": "task.py", "input": [3, 1, 2], "output": output, "exit_code": 0})
    add("ENV", {"scope": "retained-process-observations", "files": files, "configuration": config, "execution_ids": ["0", "1"],
        "ceilings": {"wall_seconds": 10.0, "memory_bytes": 1048576, "threads": 128},
        "execution": {"executable": "task.py", "input_digest": digest([3,1,2]), "output_digest": digest([1,2,3])}},
        {"files": {"task.py": {"sha256": file_digest, "base64": base64.b64encode(source).decode()}},
         "configuration": config, "measurements": measurements, "executions": executions})
    problems = [
        {"id": "sat", "kind": "cnf-sat", "specification": {"variables": 2, "clauses": [[1], [-1,2]]}, "weight": 1.0, "timeout_ms": 1000, "memory_bytes": 1000000},
        {"id": "unsat", "kind": "cnf-unsat", "specification": {"variables": 1, "clauses": [[1],[-1]]}, "weight": 1.0, "timeout_ms": 1000, "memory_bytes": 1000000},
        {"id": "linear", "kind": "linear-system", "specification": {"matrix": [[2,1],[1,-1]], "rhs": [5,1], "tolerance": 1e-12}, "weight": 1.0, "timeout_ms": 1000, "memory_bytes": 1000000},
    ]
    # These observations measure candidate construction, not solver performance.
    answers = [[True, True], "UNSAT", [2.0,1.0]]
    runs = []
    for problem, answer in zip(problems, answers):
        tracemalloc.start()
        start = time.perf_counter()
        retained_answer = json.loads(json.dumps(answer))
        elapsed = (time.perf_counter()-start)*1000
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        runs.append({"id": problem["id"], "problem_digest": digest(problem), "answer": retained_answer,
                     "execution_ms": elapsed, "peak_memory_bytes": peak})
    add("BENCH", {"problems": problems, "minimum_score": 1.0}, {"runs": runs, "score": 1.0})
    architecture = {"input_size": 1, "layers": [{"outputs": 1, "activation": "linear"}], "arithmetic": "python-binary64"}
    weights = [{"weight": [[1.0]], "bias": [0.0]}]
    samples = [{"id": "one", "input": [1.0], "target": [1.0], "output": [1.0]},
               {"id": "two", "input": [2.0], "target": [2.0], "output": [2.0]}]
    add("MODEL", {"architecture_digest": digest(architecture), "weights_digest": digest(weights),
        "dependencies": {"training-data": digest(train)}, "samples_digest": digest(samples), "tolerance": 1e-12,
        "metric": "mean_squared_error", "metric_bounds": {"minimum": 0.0, "maximum": 0.0},
        "challenges": [{"id": "negative-input", "input": [-2.0], "condition": {"op": "eq", "args": [{"var": "output.0"}, -2.0]}}]},
        {"architecture": architecture, "weights": weights, "dependencies": {"training-data": train}, "samples": samples, "metric_value": 0.0})
    config = {"optimizer": "sgd", "learning_rate": 0.1, "weight_decay": 0.0, "beta1": 0.9, "beta2": 0.999,
              "epsilon": 1e-8, "momentum": 0.0, "schedule": "constant", "accumulation": 1,
              "max_grad_norm": 100.0, "arithmetic": "python-binary64"}
    checkpoints = [{"weights": weights, "optimizer_state": {"step": 0, "first": [0.0,0.0], "second": [0.0,0.0]}},
        {"weights": [{"weight": [[1.2]], "bias": [0.2]}], "optimizer_state": {"step": 1, "first": [-2.0,-2.0], "second": [0.0,0.0]}}]
    batch = [[{"input": [1.0], "target": [2.0]}]]
    commitments = [digest(c) for c in checkpoints]
    steps = [{"index": 0, "parent": commitments[0], "result": commitments[1], "configuration_digest": digest(config),
              "batch": digest(batch), "gradients": [-2.0,-2.0], "loss": 1.0}]
    add("TRAIN", {"configuration": config, "architecture": architecture, "checkpoint_digests": commitments,
        "steps_digest": digest(steps), "start_step": 0, "tolerance": 1e-12},
        {"checkpoints": checkpoints, "steps": steps, "batches": {digest(batch): batch}})
    states = [{"x": 0.0}, {"x": 1.0}, {"x": 2.0}]
    entropy, times = [0.0,0.0], [0.0,1.0,2.0]
    macro = [{"double": 0.0}, {"double": 2.0}, {"double": 4.0}]
    add("SIM", {"transition": {"x": {"op": "add", "args": [{"var": "x"},1.0]}},
        "initial_state": states[0], "trajectory_digest": digest(states), "entropy_digest": digest(entropy), "times_digest": digest(times),
        "invariants": [{"op": "ge", "args": [{"var": "x"},0.0]}],
        "projection": {"double": {"op": "mul", "args": [{"var": "x"},2.0]}}, "macro_digest": digest(macro), "tolerance": 1e-12,
        "observation": {"x": {"var": "x"}}, "action_bounds": {"move": {"minimum": -1.0, "maximum": 1.0}},
        "shards": {"ids": ["left", "right"], "require_signatures": False,
                   "relations": [{"op": "eq", "args": [{"var": "left.x"}, {"var": "root.x"}]},
                                 {"op": "eq", "args": [{"var": "right.x"}, {"var": "root.x"}]}]}},
        {"states": states, "entropy": entropy, "times": times, "macro_states": macro, "observations": states,
         "actions": [{"move": 0.0},{"move": 1.0}],
         "shards": {key: [{"time": t, "state": s, "signature": None} for t,s in zip(times,states)] for key in ("left","right")}})
    tool_declaration = {"name": "run_tests", "inputs": ["command"], "outputs": ["exit_code"]}
    invocation = {"input": {"command": "pytest -q"}, "output": {"exit_code": 0}}
    conversation = [{"role": "user", "channel": "chat", "payload": {"text": "fix the failing test"}},
                    {"role": "agent", "channel": "chat", "payload": {"text": "running the suite"}},
                    {"role": "tool", "channel": "tool_io", "payload": invocation}]
    records = [{"index": i, "channel": m["channel"], "role": m["role"], "payload": m["payload"],
                "payload_digest": digest(m["payload"])} for i, m in enumerate(conversation)]
    add("HARNESS", {"surface": {"chat": "instrumented", "tool_io": "instrumented",
                                "model_reasoning": "declared-gap", "process_side_effects": "declared-gap"},
        "tools": {"run_tests": digest(tool_declaration)},
        "effects": {"workspace_write": "instrumented", "network": "declared-gap"},
        "record_count": len(records), "transcript_digest": digest(records),
        "transcript_root": merkle_root(records, Budget(10000))},
        {"records": records,
         "invocations": [dict(invocation, index=2, tool="run_tests", declaration_digest=digest(tool_declaration))],
         "effects": [{"index": 2, "channel": "workspace_write", "payload": {"path": "tests/test_case.py"}}]})
    from verifier.domains.certification import build_domain_certificate, domain_policy, domain_request
    harness_policy = domain_policy(trust_roots=["example:retained-inputs", "example:local-checker"])
    harness_certificate = build_domain_certificate(
        domain_request(result["HARNESS"]), result["HARNESS"], policy=harness_policy)
    steps = [{"index": 0, "record": 0, "decision": "read the bound request"},
             {"index": 1, "record": 1, "decision": "select the test suite"},
             {"index": 2, "record": 2, "decision": "observe the retained exit code"}]
    actions = [{"tool": "run_tests", "record": 2}]
    add("AGENT", {"harness_certificate_digest": digest(harness_certificate),
        "harness_subject_id": result["HARNESS"]["subject_id"],
        "required_channels": ["chat", "tool_io"],
        "steps_digest": digest(steps), "actions_digest": digest(actions),
        "outcomes": {"run_tests": "exit_code_0"},
        "claims": [{"id": "claim:suite-ran", "statement": "the bound test command was invoked and returned zero",
                    "support": [2], "channels": ["tool_io"]}]},
        {"harness_certificate": harness_certificate, "steps": steps, "actions": actions,
         "outcomes": {"run_tests": "exit_code_0"}})

    # BOT: one agent driving the SIM specimen's world. Each transition is one tool
    # invocation whose input is the simulation's retained action and whose output is
    # the simulation's own observation projection of the state it reached.
    world_tool = {"name": "step_world", "inputs": ["move"], "outputs": ["x"]}
    world_calls = [{"input": {"move": 0.0}, "output": states[1]},
                   {"input": {"move": 1.0}, "output": states[2]}]
    world_payloads = [{"role": "user", "channel": "world_observation", "payload": states[0]},
                      {"role": "tool", "channel": "world_action", "payload": world_calls[0]},
                      {"role": "tool", "channel": "world_action", "payload": world_calls[1]}]
    world_records = [{"index": i, "channel": m["channel"], "role": m["role"], "payload": m["payload"],
                      "payload_digest": digest(m["payload"])} for i, m in enumerate(world_payloads)]
    world_invocations = [dict(call, index=i+1, tool="step_world", declaration_digest=digest(world_tool))
                         for i, call in enumerate(world_calls)]
    bot_harness = {"surface": {"world_observation": "instrumented", "world_action": "instrumented",
                               "simulator_internals": "declared-gap"},
                   "tools": {"step_world": digest(world_tool)},
                   "effects": {"world_action": "instrumented"},
                   "record_count": len(world_records), "transcript_digest": digest(world_records),
                   "transcript_root": merkle_root(world_records, Budget(10000))}
    bot_harness_inputs = {"records": world_records, "invocations": world_invocations,
                          "effects": [{"index": 1, "channel": "world_action", "payload": world_calls[0]},
                                      {"index": 2, "channel": "world_action", "payload": world_calls[1]}]}
    bot_steps = [{"index": 0, "record": 0, "decision": "observe the initial world state"},
                 {"index": 1, "record": 1, "decision": "hold position"},
                 {"index": 2, "record": 2, "decision": "advance one unit"}]
    bot_actions = [{"tool": "step_world", "record": 1}, {"tool": "step_world", "record": 2}]
    def _environment(name: str, executable: str, identifiers: list) -> tuple:
        source = ("# " + name + " runtime" + chr(10)).encode()
        inventory = {executable: "sha256:" + hashlib.sha256(source).hexdigest()}
        configuration = dict(collect_configuration(), role=name)
        return ({"scope": "retained-process-observations", "files": inventory,
                 "configuration": configuration, "execution_ids": identifiers,
                 "ceilings": {"wall_seconds": 10.0, "memory_bytes": 1048576, "threads": 128},
                 "execution": {"executable": executable, "input_digest": digest([]), "output_digest": digest([])}},
                {"files": {executable: {"sha256": inventory[executable],
                                        "base64": base64.b64encode(source).decode()}},
                 "configuration": configuration, "measurements": [], "executions": []})
    from verifier.domains.certification import build_domain_certificate, domain_policy, domain_request
    loop_policy = domain_policy(trust_roots=["example:retained-inputs", "example:local-checker"])
    def _evidence(domain: str, subject: str, artifact: dict, inputs: dict) -> dict:
        return {"schema_version": "verifier-domain-evidence-1", "domain": domain,
                "subject_id": subject, "artifact": artifact, "inputs": inputs}
    def _certificate(domain: str, subject: str, artifact: dict, inputs: dict, depth: int) -> dict:
        evidence = _evidence(domain, subject, artifact, inputs)
        return build_domain_certificate(domain_request(evidence, target_depth=depth), evidence, policy=loop_policy)
    agent_environment, agent_environment_inputs = _environment("agent", "policy.py", ["agent-0", "agent-1"])
    world_environment, world_environment_inputs = _environment("simulator", "world.py", ["world-0", "world-1"])
    bot_harness_certificate = _certificate("HARNESS", "example:bot-harness", bot_harness, bot_harness_inputs, 5)
    bot_agent = {"harness_certificate_digest": digest(bot_harness_certificate),
                 "harness_subject_id": "example:bot-harness",
                 "required_channels": ["world_action", "world_observation"],
                 "steps_digest": digest(bot_steps), "actions_digest": digest(bot_actions),
                 "outcomes": {"x": "2.0"},
                 "claims": [{"id": "claim:reached-two", "statement": "the world reached x = 2.0 under the retained actions",
                             "support": [2], "channels": ["world_action"]}]}
    bot_agent_inputs = {"harness_certificate": bot_harness_certificate, "steps": bot_steps,
                        "actions": bot_actions, "outcomes": {"x": "2.0"}}
    agent_certificate = _certificate("AGENT", "example:bot-agent", bot_agent, bot_agent_inputs, 5)
    sim_certificate = _certificate("SIM", result["SIM"]["subject_id"], result["SIM"]["artifact"],
                                   result["SIM"]["inputs"], 4)
    agent_env_certificate = _certificate("ENV", "example:agent-runtime", agent_environment,
                                         agent_environment_inputs, 2)
    world_env_certificate = _certificate("ENV", "example:simulator-runtime", world_environment,
                                         world_environment_inputs, 2)
    add("BOT", {"agent_certificate_digest": digest(agent_certificate),
        "sim_certificate_digest": digest(sim_certificate),
        "agent_environment_certificate_digest": digest(agent_env_certificate),
        "sim_environment_certificate_digest": digest(world_env_certificate),
        "step_map": [1, 2], "exogenous_transitions": [],
        "initial_observation_record": 0, "separation": "distinct"},
        {"agent_certificate": agent_certificate, "sim_certificate": sim_certificate,
         "agent_environment_certificate": agent_env_certificate,
         "sim_environment_certificate": world_env_certificate})

    # TOKEN: one holding descending from one birth token. The commitment's opening --
    # the genesis key digest, the birth epoch and the salt -- is used here to make the
    # commitment and never enters the retained evidence.
    issuer_public, sign = token_issuer()
    issuer = digest(issuer_public)
    birth_epoch = 10
    commitment = digest(["sha256:" + hashlib.sha256(b"example:genesis-key").hexdigest(), birth_epoch, "example-salt"])
    epochs, accumulator = [], commitment
    for epoch, status in zip(range(birth_epoch + 1, birth_epoch + 6), ("ACTIVE", "ACTIVE", "SUSPENDED", "ACTIVE", "ACTIVE")):
        accumulator = digest([accumulator, epoch, status])
        epochs.append({"epoch": epoch, "status": status, "digest": accumulator})
    def _token(kind: str, token_id: str, issued_at: int, fields: dict) -> dict:
        body = dict({"kind": kind, "token_id": token_id, "issuing_key_id": issuer, "issued_at": issued_at,
                     "algorithm": "Ed25519", "replay_id": "replay:" + token_id, "audience": ["example:verifier"]}, **fields)
        return dict(body, signature=sign(body))
    audit = {"condition": "audit-log-retained", "discharge": "example:auditor"}
    tokens = [
        _token("birth", "birth", 900, {"birth_epoch": birth_epoch, "commitment": commitment}),
        _token("aging", "tenure", 950, {"birth_token_id": "birth", "epoch_start": birth_epoch + 1,
               "epoch_end": birth_epoch + 5, "accumulated_epochs": 4, "accumulator_digest": accumulator,
               "revocation_status": "ACTIVE"}),
        _token("lifetime", "lease", 1000, {"parent_grant_id": "birth", "delegate_key_id": digest("example:delegate"),
               "permitted_scopes": ["read", "write"], "not_before": 1000, "not_after": 5000, "max_invocations": 100,
               "soulbound": False, "confirmation_key_id": digest("example:holder"), "caveats": [audit]}),
        # The holder narrows its own lease: fewer scopes, a shorter window, fewer
        # invocations, one more caveat, and soulbound from here on.
        _token("lifetime", "attenuated", 1400, {"parent_grant_id": "lease", "delegate_key_id": digest("example:delegate"),
               "permitted_scopes": ["read"], "not_before": 1500, "not_after": 4000, "max_invocations": 10,
               "soulbound": True, "confirmation_key_id": None,
               "caveats": [audit, {"condition": "read-only-mirror", "discharge": None}]}),
    ]
    token_statuses = [{"token_id": t["token_id"], "published_at": 1800, "verdict": "ACTIVE"} for t in tokens]
    add("TOKEN", {"tokens_digest": digest(tokens), "epochs_digest": digest(epochs),
        "statuses_digest": digest(token_statuses), "clock": "example:issuer-clock", "clock_skew": 5,
        "issuing_keys": [{"key_id": issuer, "key_bytes": issuer_public}], "key_retirements": {issuer: 9000},
        "accepted_algorithms": ["Ed25519"], "root_scopes": ["read", "write", "admin"],
        "audience": ["example:verifier", "example:auditor"], "period": {"start": 0, "end": 6000},
        "status_schedule": 500, "observed_at": 2000},
        {"tokens": tokens, "epochs": epochs, "statuses": token_statuses})

    return result


if __name__ == "__main__":
    from verifier.domains.certification import build_domain_certificate, domain_policy, domain_request, recheck_domain_certificate
    policy = domain_policy(trust_roots=["example:retained-inputs", "example:local-checker"],
                           witness_keys=token_witness_keys())
    for domain, evidence in specimens().items():
        request = domain_request(evidence)
        certificate = build_domain_certificate(request, evidence, policy=policy)
        result = recheck_domain_certificate(certificate, expected_request=request, policy=policy)
        print(domain, result["status"], result["domain_depth"], flush=True)
        # Without the seal extra TOKEN.4 cannot check a signature and reports UNKNOWN;
        # every other TOKEN check still has to replay.
        unsigned = (domain == "TOKEN" and result["status"] == "UNKNOWN"
                    and result["checks"]["TOKEN.4"]["evaluation"]["details"] == "signature backend unavailable"
                    and all(row["established"] for key, row in result["checks"].items() if key != "TOKEN.4"))
        if result["status"] != "PASS" and not unsigned:
            raise SystemExit(json.dumps(result, indent=2))
