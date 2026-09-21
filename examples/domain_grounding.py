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


def specimens() -> dict:
    """Produce actual retained inputs with independently calculable expected results."""
    result = {}
    def add(domain: str, artifact: dict, inputs: dict) -> None:
        result[domain] = {"schema_version": "VSTD-DOMAIN-EVIDENCE-1", "domain": domain,
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
    add("HYPER", {"configuration": config, "architecture": architecture, "checkpoint_digests": commitments,
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
    return result


if __name__ == "__main__":
    from verifier.domains.certification import build_domain_certificate, domain_policy, domain_request, recheck_domain_certificate
    policy = domain_policy(trust_roots=["example:retained-inputs", "example:local-checker"])
    for domain, evidence in specimens().items():
        request = domain_request(evidence)
        certificate = build_domain_certificate(request, evidence, policy=policy)
        result = recheck_domain_certificate(certificate, expected_request=request, policy=policy)
        print(domain, result["status"], result["domain_depth"], flush=True)
        if result["status"] != "PASS":
            raise SystemExit(json.dumps(result, indent=2))
