"""Deterministic generator for all 31 Tier-3 native specimens.

Constructs one canonical request, policy, and evidence input per Tier-3 membership
using repository source and contract builders only, without importing tests at runtime.
One fixture records the contract's unsatisfiable (UNSAT) outcome label.

The reviewed source ledger (SOURCE_REVIEW_LEDGER) decides each pin: a coordinate is
re-pinned only when its live mechanism digest equals the reviewed digest, and a
coordinate whose review is not accepted keeps its retained prior case as UNKNOWN.
A second generated overlay (build_prepared_current_payload) carries fresh triads built
from live mechanisms for those retained coordinates. Only the prepared replay surface
reads it; the installed payload and installed source review are unchanged by it.
Run with --write to regenerate the owned runtime module's generated block, or with
--check to verify that block without writing. Never hand-edit the generated block.
"""
from __future__ import annotations

import base64
from copy import deepcopy
import hashlib
import json
import math
import sys
from pathlib import Path
from typing import Any
import zlib

from verifier.core.certificate import canonical_bytes
from verifier.core.checker import IndependentAuditor
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.core.provenance import GitProvenance, ProvenanceRecord, RuntimeEnvironment
from verifier.core.receipt import (
    ClaimSpec,
    EvidencePayload,
    ExecutionMetadata,
    VstdReceipt,
    strict_json_loads,
)

# Domain contract modules
from verifier.domains.contracts import (
    actor_decision_record,
    agent_ceiling_fixity,
    arch_shapes,
    bench_checks,
    bot_inherited_ceiling,
    collective_constraints,
    data_checks,
    data_distribution,
    env_checks,
    event_prerequisites,
    graph_statics,
    hardware_substrate_observations,
    harness_gap_boundary,
    human_no_composition,
    hyper_composed_ceiling,
    identity_scope,
    model_artifact_bytes,
    model_data_citation,
    model_data_lineage,
    model_hardware_observation,
    model_quantization,
    model_train_citation,
    object_statics,
    owner_eligibility,
    receipt_statics,
    role_constraints,
    sim_external_law,
    space_layout,
    time_order,
    time_strict,
    token_checks,
    train_accumulation,
    train_checks,
    typed_facets,
    verifier_run_constraints,
)
from verifier.runtime import core_obligation_union
from verifier.runtime import core_tier_progression


def _digest(data: bytes | str | dict | list) -> str:
    if isinstance(data, bytes):
        raw = data
    else:
        raw = canonical_bytes(data)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


# 1. ACTOR:ACTOR-3.3
def gen_actor_3_3() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    def content(n: int) -> str:
        return "sha256:" + format(n, "064x")

    humans = [
        NamespaceObject.create("alice", "HUMAN", {"fixture": "alice"}),
        NamespaceObject.create("bob", "HUMAN", {"fixture": "bob"}),
    ]
    actors = [
        NamespaceObject.create("p-alice", "ACTOR", {"fixture": "p-alice"}, {"representation": ["alice"], "root_human": ["alice"]}),
        NamespaceObject.create("p-bob", "ACTOR", {"fixture": "p-bob"}, {"representation": ["bob"], "root_human": ["bob"]}),
    ]
    objects = [*humans, *actors]

    earlier = {
        "head_position": 10,
        "decisions": [
            {"decision_id": "x1", "position": 2, "actor": "p-alice", "content_digest": content(1)},
            {"decision_id": "x2", "position": 5, "actor": "p-bob", "content_digest": content(2)},
            {"decision_id": "x3", "position": 8, "actor": "p-alice", "content_digest": content(3)},
        ],
    }
    events = [
        {"position": 11, "event": "delegation", "delegation_id": "d1", "delegator": "p-alice", "delegate": "p-bob", "subset": ["approve"], "interval": [11, 30]},
        {"position": 12, "event": "revocation", "delegation_id": "d1"},
        {"position": 13, "event": "rotation", "actor": "p-alice", "prior_key": content(41), "key": content(42)},
        {"position": 15, "event": "dissolution", "actor": "p-alice"},
    ]
    later = {
        "head_position": 20,
        "decisions": [
            *earlier["decisions"],
            {"decision_id": "x4", "position": 14, "actor": "p-bob", "content_digest": content(4)},
        ],
    }

    evidence = canonical_bytes({
        "schema_version": actor_decision_record.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": {"earlier": earlier, "events": events, "later": later},
    })
    policy = actor_decision_record.actor_decision_record_policy(
        trust_roots=["externally-selected-decision-records"]
    )
    subject = next(item for item in objects if item.object_id == "p-alice")
    request = actor_decision_record.actor_decision_record_request(
        subject_id=subject.object_id,
        object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        earlier_digest=_digest(earlier),
        events_digest=_digest(events),
        later_digest=_digest(later),
        evidence_ref=_digest(json.loads(evidence)),
        policy=policy,
    )
    return request, policy, evidence


# 2. AGENT:AGENT-3.1
def gen_agent_3_1() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    ceiling = 3
    names = ["arch", "data", "env", "hardware", "object", "space", "time", "verifier"]
    objects = [NamespaceObject.create(name, name.upper(), {"fixture": name}) for name in names]
    objects.append(
        NamespaceObject.create(
            "harness", "HARNESS",
            {"fixture": "harness", "observation_ceiling": {"ceiling": ceiling, "observed": ["chat", "effects", "tool_io"]}}
        )
    )
    objects += [
        NamespaceObject.create("event", "EVENT", {"fixture": "event"}, {"time": ["time"], "space": ["space"], "meaning": ["object"]}),
        NamespaceObject.create("bench", "BENCH", {"fixture": "bench"}, {"verifier": ["verifier"], "data": ["data"]}),
        NamespaceObject.create("train", "TRAIN", {"fixture": "train"}, {"data": ["data"], "events": ["event"], "bench": ["bench"], "arch": ["arch"]}),
        NamespaceObject.create("model", "MODEL", {"fixture": "model"}, {"train": ["train"], "data": ["data"], "events": ["event"], "bench": ["bench"], "arch": ["arch"], "env": ["env"], "hardware": ["hardware"]}),
        NamespaceObject.create("agent", "AGENT", {"scope": "retained-agent-ceiling-fixity", "declared_ceiling": ceiling}, {"model": ["model"], "harness": ["harness"], "env": ["env"]}),
    ]
    chosen = next(item for item in objects if item.object_id == "agent")
    evidence = canonical_bytes({
        "schema_version": agent_ceiling_fixity.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in sorted(objects, key=lambda item: item.object_id)],
    })
    policy = agent_ceiling_fixity.agent_ceiling_fixity_policy(trust_roots=["agent-statics-root"])
    request = agent_ceiling_fixity.agent_ceiling_fixity_request(
        subject_id=chosen.object_id,
        object_digest=chosen.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=_digest(json.loads(evidence)),
        policy=policy,
    )
    return request, policy, evidence


# 3. ARCH:ARCH-3.1
def gen_arch_3_1() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    graph = {
        "nodes": [
            {"name": "x", "op": "INPUT", "inputs": [], "shape": [2, 3]},
            {"name": "w", "op": "INPUT", "inputs": [], "shape": [3, 4]},
            {"name": "product", "op": "MATMUL", "inputs": ["x", "w"], "shape": [2, 4]},
            {"name": "bias", "op": "INPUT", "inputs": [], "shape": [2, 4]},
            {"name": "sum", "op": "ADD", "inputs": ["product", "bias"], "shape": [2, 4]},
            {"name": "out", "op": "RELU", "inputs": ["sum"], "shape": [2, 4]},
        ],
        "outputs": ["out"],
    }
    subject = NamespaceObject.create("arch-root", "ARCH", {
        "scope": "retained-static-tensor-graph",
        "graph_digest": _digest(graph),
    })
    evidence = canonical_bytes({
        "schema_version": arch_shapes.EVIDENCE_VERSION,
        "objects": [subject.to_dict()],
        "inputs": {"graph": graph},
    })
    policy = arch_shapes.arch_shapes_policy(trust_roots=["test:selected-graph"])
    request = arch_shapes.arch_shapes_request(
        subject_id=subject.object_id,
        object_digest=subject.digest,
        collection_digest=composition_digest([subject]),
        evidence_ref=_digest(json.loads(evidence)),
        policy=policy,
    )
    return request, policy, evidence


# 4. BENCH:BENCH-3.6
def gen_bench_3_6() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    specifications = [
        ("exact", {"expected": {"answer": 42}}, {"answer": 42}),
        ("cnf-sat", {"variables": 2, "clauses": [[1], [-1, 2]]}, [True, True]),
        ("cnf-unsat", {"variables": 1, "clauses": [[1], [-1]]}, "UNSAT"),
        ("linear-system", {"matrix": [[2, 1], [1, -1]], "rhs": [5, 1], "tolerance": 0}, [2, 1]),
    ]
    problems = [
        {"id": kind, "kind": kind, "specification": spec, "weight": i + 1, "timeout_ms": 100, "memory_bytes": 4096}
        for i, (kind, spec, answer) in enumerate(specifications)
    ]
    retained = {
        "runs": [
            {"id": p["id"], "problem_digest": _digest(p), "answer": answer, "execution_ms": 100, "peak_memory_bytes": 4096}
            for p, (_, _, answer) in zip(problems, specifications)
        ],
        "score": 1,
    }
    artifact = {"problems": problems, "minimum_score": 1}

    subject = NamespaceObject.create("benchmark", "BENCH", artifact, {"verifier": ["checker"], "data": ["problems"]})
    objects = [
        subject,
        NamespaceObject.create("checker", "VERIFIER", {"mechanism_id": bench_checks.MECHANISM_ID, "mechanism_digest": bench_checks.mechanism_digest()}),
        NamespaceObject.create("problems", "DATA", {"problems": deepcopy(artifact["problems"])}),
    ]
    evidence = canonical_bytes({
        "schema_version": "verifier-current-bench-checks-evidence-1",
        "objects": [item.to_dict() for item in objects],
        "inputs": retained,
    })
    policy = bench_checks.bench_checks_policy(trust_roots=["selected-retained-bench-only"])
    request = bench_checks.bench_checks_request(
        check="budgets",
        subject_id=subject.object_id,
        object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=_digest(json.loads(evidence)),
        policy=policy,
    )
    return request, policy, evidence


# 5. BOT:BOT-3.1
def gen_bot_3_1() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    ceiling = 3
    names = ["arch", "data", "env", "hardware", "object", "space", "time", "verifier"]
    objects = [NamespaceObject.create(name, name.upper(), {"fixture": name}) for name in names]
    objects += [
        NamespaceObject.create("harness", "HARNESS", {"fixture": "harness", "observation_ceiling": {"ceiling": ceiling, "observed": ["chat", "effects", "tool_io"]}}),
        NamespaceObject.create("harness-low", "HARNESS", {"fixture": "harness", "observation_ceiling": {"ceiling": 1, "observed": ["chat", "effects", "tool_io"]}}),
        NamespaceObject.create("event", "EVENT", {"fixture": "event"}, {"time": ["time"], "space": ["space"], "meaning": ["object"]}),
        NamespaceObject.create("bench", "BENCH", {"fixture": "bench"}, {"verifier": ["verifier"], "data": ["data"]}),
        NamespaceObject.create("train", "TRAIN", {"fixture": "train"}, {"data": ["data"], "events": ["event"], "bench": ["bench"], "arch": ["arch"]}),
        NamespaceObject.create("model", "MODEL", {"fixture": "model"}, {"train": ["train"], "data": ["data"], "events": ["event"], "bench": ["bench"], "arch": ["arch"], "env": ["env"], "hardware": ["hardware"]}),
        NamespaceObject.create("agent", "AGENT", {"fixture": "agent"}, {"model": ["model"], "harness": ["harness"], "env": ["env"]}),
        NamespaceObject.create("agent-low", "AGENT", {"fixture": "agent"}, {"model": ["model"], "harness": ["harness-low"], "env": ["env"]}),
        NamespaceObject.create("sim", "SIM", {"fixture": "sim"}, {"data": ["data"], "verifier": ["verifier"], "objects": ["object"], "env": ["env"]}),
        NamespaceObject.create("bot", "BOT", {"scope": "retained-bot-inherited-ceiling", "claimed_ceiling": ceiling}, {"agent": ["agent"], "sim": ["sim"], "env": ["env"]}),
    ]
    chosen = next(item for item in objects if item.object_id == "bot")
    evidence = canonical_bytes({
        "schema_version": bot_inherited_ceiling.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in sorted(objects, key=lambda item: item.object_id)],
    })
    policy = bot_inherited_ceiling.bot_inherited_ceiling_policy(trust_roots=["bot-statics-root"])
    request = bot_inherited_ceiling.bot_inherited_ceiling_request(
        subject_id=chosen.object_id,
        object_digest=chosen.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=_digest(json.loads(evidence)),
        policy=policy,
    )
    return request, policy, evidence


# 6. COLLECTIVE:COLLECTIVE-3.1
def gen_collective_3_1() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    charter = b"Research charter: record decisions."
    quorum = 2
    roles = [NamespaceObject.create(name, "ROLE", {"purpose": name}) for name in ("role-a", "role-b")]
    members = [{"role_id": role.object_id, "role_digest": role.digest} for role in roles]
    payload = {
        "static_constraints": {
            "schema_version": collective_constraints.CONSTRAINTS_VERSION,
            "charter_digest": _digest(charter),
            "membership_digest": _digest(members),
            "quorum": quorum,
        }
    }
    collective = NamespaceObject.create("collective", "COLLECTIVE", payload, {"roles": [row["role_id"] for row in members]})
    objects = [collective, *roles]
    policy = collective_constraints.collective_constraints_policy(
        trust_roots=["selected-retained-declarations"],
        selected_members=members,
        charter_digest=_digest(charter),
        quorum=quorum,
    )
    evidence = canonical_bytes({
        "schema_version": collective_constraints.EVIDENCE_VERSION,
        "objects": [obj.to_dict() for obj in objects],
        "inputs": {
            "membership": members,
            "quorum": quorum,
            "charter": {"sha256": _digest(charter), "base64": base64.b64encode(charter).decode("ascii")},
        },
    })
    request = collective_constraints.collective_constraints_request(
        subject_id=collective.object_id,
        object_digest=collective.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=_digest(evidence),
        policy=policy,
    )
    return request, policy, evidence


# 7. DATA:DATA-3.4
def gen_data_3_4() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    values = [1, _digest(1), True, None, "null", [1], {"x": 1}]
    keys = sorted(set(canonical_bytes(v) for v in values))
    classes = [{"value": json.loads(k), "count": sum(canonical_bytes(v) == k for v in values)} for k in keys]
    n = len(values)
    entropy = math.log2(n) - sum(c["count"] * math.log2(c["count"]) for c in classes) / n if n else 0
    summary = {"cardinality": len(classes), "classes": classes, "entropy_bits": entropy}

    shards = {"s": [{"class": v} for v in values]}
    rows = shards["s"]
    # Merkle root calculation or digest
    from verifier.domains.common import Budget, merkle_root
    payload = {
        "shards": {
            "s": {
                "digest": _digest(rows),
                "records": len(rows),
                "bytes": len(canonical_bytes(rows)),
                "record_digests": [_digest(r) for r in rows],
                "merkle_root": merkle_root(rows, Budget(100000)),
            }
        },
        "distribution": {"class": summary},
    }
    subject = NamespaceObject.create("data-root", "DATA", payload)
    evidence = canonical_bytes({
        "schema_version": data_distribution.EVIDENCE_VERSION,
        "objects": [subject.to_dict()],
        "inputs": {"shards": shards},
    })
    policy = data_distribution.data_distribution_policy(
        trust_roots=["selected-retained-data"], entropy_tolerance_bits=1e-12
    )
    request = data_distribution.data_distribution_request(
        subject_id=subject.object_id,
        object_digest=subject.digest,
        collection_digest=composition_digest([subject]),
        evidence_ref=_digest(json.loads(evidence)),
        policy=policy,
    )
    return request, policy, evidence


# 8. ENV:ENV-3.3
def gen_env_3_3() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    files = {
        name: {"base64": base64.b64encode(val).decode(), "sha256": _digest(val)}
        for name, val in {"program.py": b"print(42)\n", "library.py": b"VALUE = 42\n"}.items()
    }
    inventory = {name: record["sha256"] for name, record in files.items()}
    config = {"byteorder": "little", "engine": "retained-test-engine"}
    artifact = {
        "scope": "retained-process-observations",
        "files": inventory,
        "configuration": config,
        "execution_ids": ["first", "second"],
        "ceilings": {"wall_seconds": 2, "memory_bytes": 4096, "threads": 2},
        "execution": {"executable": "program.py", "input_digest": _digest([21]), "output_digest": _digest([42])},
    }
    retained = {
        "files": files,
        "configuration": deepcopy(config),
        "measurements": [
            {"id": name, "wall_seconds": 2, "memory_bytes": 4096, "threads": 2}
            for name in artifact["execution_ids"]
        ],
        "executions": [
            {
                "id": name, "software_digest": _digest(inventory),
                "configuration_digest": _digest(config), "executable": "program.py",
                "input": [21], "output": [42], "exit_code": 0,
            }
            for name in artifact["execution_ids"]
        ],
    }
    subject = NamespaceObject.create("environment", "ENV", artifact)
    objects = [subject]
    evidence = canonical_bytes({
        "schema_version": "verifier-current-env-checks-evidence-1",
        "objects": [obj.to_dict() for obj in objects],
        "inputs": retained,
    })
    policy = env_checks.env_checks_policy(trust_roots=["selected-retained-env-only"])
    request = env_checks.env_checks_request(
        check="resources",
        subject_id="environment",
        object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=_digest(json.loads(evidence)),
        policy=policy,
    )
    return request, policy, evidence


# 9. EVENT:EVENT-3.1
def gen_event_3_1() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    events = [
        ("parent", 1, [], {"value": "first"}),
        ("root", 2, ["parent"], {"value": "second"}),
    ]
    retained_payloads = {name: payload for name, _, _, payload in events}
    fixed = [
        NamespaceObject.create("clock", "TIME", {}),
        NamespaceObject.create("place", "SPACE", {}),
        NamespaceObject.create("meaning", "OBJECT", {}),
    ]
    event_objects = [
        NamespaceObject.create(
            name, "EVENT",
            {"scope": "retained-declared-prerequisites", "sequence": seq, "prerequisites": parents, "payload_digest": _digest(payload)},
            {"time": ["clock"], "space": ["place"], "meaning": ["meaning"]},
        )
        for name, seq, parents, payload in events
    ]
    objects = [*fixed, *event_objects]
    subject = next(obj for obj in event_objects if obj.object_id == "root")
    evidence = canonical_bytes({
        "schema_version": event_prerequisites.EVIDENCE_VERSION,
        "objects": [obj.to_dict() for obj in objects],
        "inputs": {"payloads": retained_payloads},
    })
    policy = event_prerequisites.event_prerequisites_policy(trust_roots=["selected-event-cone"])
    request = event_prerequisites.event_prerequisites_request(
        subject_id=subject.object_id,
        object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=_digest(json.loads(evidence)),
        policy=policy,
    )
    return request, policy, evidence


# 10. GRAPH:GRAPH-3.1
def gen_graph_3_1() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    nodes = ["a", "b"]
    edges = [{"source": "a", "target": "b"}]
    members = [NamespaceObject.create(name, "ENV", {"fixture": name}) for name in nodes]
    graph = NamespaceObject.create("graph", "GRAPH", {
        "element_kind": "ENV", "scope": "retained_directed_graph",
        "nodes_digest": _digest(nodes), "edges_digest": _digest(edges),
    }, {"members": ["a", "b"]})
    objects = [*members, graph]
    evidence = canonical_bytes({
        "schema_version": graph_statics.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": {"nodes": nodes, "edges": edges},
    })
    policy = graph_statics.graph_statics_policy(trust_roots=["externally-selected-graph"])
    request = graph_statics.graph_statics_request(
        subject_id="graph",
        object_digest=graph.digest,
        collection_digest=composition_digest(objects),
        nodes_digest=_digest(nodes),
        edges_digest=_digest(edges),
        evidence_ref=_digest(json.loads(evidence)),
        policy=policy,
    )
    return request, policy, evidence


# 11. HARDWARE:HARDWARE-3.1
def gen_hardware_3_1() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    clock = "lab-monotonic-clock"
    at = 1_500_000
    roots = ["lab-attestor", "vendor-root"]
    registers = [0, 4, 7]

    def event(reg: int, data: bytes) -> dict:
        return {"register": reg, "event": base64.b64encode(data).decode("ascii"), "event_digest": hashlib.sha256(data).hexdigest()}

    base_ev = [
        event(0, b"core root of trust v1.0"),
        event(0, b"platform firmware volume"),
        event(4, b"boot loader stage one"),
        event(4, b"boot loader stage two"),
        event(0, b"option memory configuration"),
    ]

    values = {reg: b"\x00" * 32 for reg in registers}
    for row in base_ev:
        data = base64.b64decode(row["event"])
        values[row["register"]] = hashlib.sha256(values[row["register"]] + bytes.fromhex(row["event_digest"])).digest()
    chain_val = {reg: val.hex() for reg, val in values.items()}
    quote = [{"register": r, "value": chain_val[r]} for r in registers]

    claims = [
        {"claim_id": "boot-measurements", "category": "device_identity", "value": quote},
        {"claim_id": "core-voltage-calibration", "category": "calibration", "value": {"unit": "volt", "offset": {"num": 1, "den": 200}}},
        {"claim_id": "memory-capacity", "category": "physical_capacity", "value": {"unit": "MEMORY_BYTE", "quantity": 17179869184}},
        {"claim_id": "serial", "category": "device_identity", "value": "SN-0042-ALPHA"},
        {"claim_id": "thermal-sensor-accuracy", "category": "sensor_accuracy", "value": {"unit": "kelvin", "half_width": {"num": 1, "den": 4}}},
        {"claim_id": "uplink-available", "category": "live_availability", "value": True},
    ]

    def obs(obs_id: str, claim_id: str, val: object, root: str = "lab-attestor", events: list | None = None) -> dict:
        return {
            "observation_id": obs_id, "claim_id": claim_id, "value": val, "clock": clock,
            "fresh_from_us": 1_000_000, "fresh_until_us": 2_000_000, "trust_root": root,
            "measured_boot": None if events is None else {"events": events},
        }

    observations = [
        obs("obs-boot", "boot-measurements", quote, root="vendor-root", events=base_ev),
        obs("obs-core-voltage-calibration", "core-voltage-calibration", {"unit": "volt", "offset": {"num": 1, "den": 200}}),
        obs("obs-memory-capacity", "memory-capacity", {"unit": "MEMORY_BYTE", "quantity": 17179869184}),
        obs("obs-serial", "serial", "SN-0042-ALPHA"),
        obs("obs-thermal-sensor-accuracy", "thermal-sensor-accuracy", {"unit": "kelvin", "half_width": {"num": 1, "den": 4}}),
        obs("obs-uplink-available", "uplink-available", True),
    ]

    payload = {"scope": hardware_substrate_observations.SUBJECT_SCOPE, "claims_digest": _digest(claims), "observations_digest": _digest(observations)}
    subject = NamespaceObject.create("hardware-a", "HARDWARE", payload)
    sibling = NamespaceObject.create("hardware-b", "HARDWARE", payload)
    objects = [subject, sibling]
    evidence_dict = {
        "schema_version": hardware_substrate_observations.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": {"claims": claims, "observations": observations},
    }
    evidence = canonical_bytes(evidence_dict)
    policy = hardware_substrate_observations.hardware_substrate_observations_policy(trust_roots=list(roots))
    request = hardware_substrate_observations.hardware_substrate_observations_request(
        subject_id="hardware-a",
        object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        evaluation_clock=clock,
        evaluation_at_us=at,
        evidence_ref=_digest(evidence_dict),
        policy=policy,
    )
    return request, policy, evidence


# 12. HARNESS:HARNESS-3.1
def gen_harness_3_1() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    window = {"start": 0, "end": 100}
    placements = [
        {"instrument": "message_tap", "start": 0, "end": 20},
        {"instrument": "tool_tap", "start": 30, "end": 70},
        {"instrument": "final_tap", "start": 70, "end": 90},
    ]
    gaps = [{"name": "pre-tool", "start": 20, "end": 30}, {"name": "post-final", "start": 90, "end": 100}]

    harness = NamespaceObject.create("harness", "HARNESS", {
        "scope": "retained-harness-gap-boundary", "window": window,
        "gaps": gaps, "placements_digest": _digest(placements),
    })
    decoy = NamespaceObject.create("decoy-harness", "HARNESS", {"fixture": "unbound"})
    objects = [harness, decoy]
    evidence = canonical_bytes({
        "schema_version": harness_gap_boundary.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in sorted(objects, key=lambda item: item.object_id)],
        "inputs": {"placements": placements},
    })
    policy = harness_gap_boundary.harness_gap_boundary_policy(trust_roots=["harness-statics-root"])
    request = harness_gap_boundary.harness_gap_boundary_request(
        subject_id=harness.object_id,
        object_digest=harness.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=_digest(json.loads(evidence)),
        policy=policy,
    )
    return request, policy, evidence


# 13. HUMAN:HUMAN-3.6
def gen_human_3_6() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    records = [
        NamespaceObject.create("person-a", "HUMAN", {"fixture": "person-a"}),
        NamespaceObject.create("person-b", "HUMAN", {"fixture": "person-b"}),
        NamespaceObject.create("role", "ROLE", {"purpose": "role"}),
        NamespaceObject.create("arch", "ARCH", {}),
        NamespaceObject.create("data", "DATA", {}),
        NamespaceObject.create("env", "ENV", {}),
        NamespaceObject.create("hardware", "HARDWARE", {}),
        NamespaceObject.create("object", "OBJECT", {}),
        NamespaceObject.create("space", "SPACE", {}),
        NamespaceObject.create("time", "TIME", {}),
        NamespaceObject.create("verifier", "VERIFIER", {}),
        NamespaceObject.create("harness", "HARNESS", {}),
        NamespaceObject.create("event", "EVENT", {}, {"time": ["time"], "space": ["space"], "meaning": ["object"]}),
        NamespaceObject.create("bench", "BENCH", {}, {"verifier": ["verifier"], "data": ["data"]}),
        NamespaceObject.create("train", "TRAIN", {}, {"data": ["data"], "events": ["event"], "bench": ["bench"], "arch": ["arch"]}),
        NamespaceObject.create("model", "MODEL", {}, {"train": ["train"], "data": ["data"], "events": ["event"], "bench": ["bench"], "arch": ["arch"], "env": ["env"], "hardware": ["hardware"]}),
        NamespaceObject.create("agent", "AGENT", {}, {"model": ["model"], "harness": ["harness"], "env": ["env"]}),
        NamespaceObject.create("sim", "SIM", {}, {"data": ["data"], "verifier": ["verifier"], "objects": ["object"], "env": ["env"]}),
        NamespaceObject.create("human:courier", "BOT", {}, {"agent": ["agent"], "sim": ["sim"], "env": ["env"]}),
        NamespaceObject.create("collective", "COLLECTIVE", {}, {"roles": ["role"]}),
        NamespaceObject.create("bot-actor", "ACTOR", {}, {"representation": ["human:courier"], "root_human": ["person-a"]}),
        NamespaceObject.create("derived-data", "DATA", {}),
        NamespaceObject.create("sim-output", "DATA", {}),
        NamespaceObject.create("report", "OBJECT", {}),
        NamespaceObject.create("relay", "OBJECT", {}),
    ]
    arrangements = [
        {"arrangement_id": "arr-1", "arranged": ["agent", "sim"], "output": "human:courier", "declared_output_kind": "BOT", "strength": "full"},
        {"arrangement_id": "arr-2", "arranged": ["data", "model"], "output": "derived-data", "declared_output_kind": "DATA", "strength": "partial"},
        {"arrangement_id": "arr-3", "arranged": ["collective", "derived-data"], "output": "report", "declared_output_kind": "OBJECT", "strength": "statistical"},
    ]
    subject = next(item for item in records if item.object_id == "person-a")
    evidence = canonical_bytes({
        "schema_version": human_no_composition.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in records],
        "inputs": {"arrangements": arrangements},
    })
    policy = human_no_composition.human_no_composition_policy(trust_roots=["human-root"])
    request = human_no_composition.human_no_composition_request(
        subject_id=subject.object_id,
        object_digest=subject.digest,
        collection_digest=composition_digest(records),
        arrangements_digest=_digest(arrangements),
        evidence_ref="sha256:" + hashlib.sha256(evidence).hexdigest(),
        policy=policy,
    )
    return request, policy, evidence


# 14. HYPER:HYPER-3.1
def gen_hyper_3_1() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    good_parts = [
        {"id": "part-0", "start_byte": 0, "end_byte": 16, "alignment_bytes": 16},
        {"id": "part-1", "start_byte": 16, "end_byte": 32, "alignment_bytes": 16},
    ]
    good_samples = [{"id": "s0", "at_us": 2}, {"id": "s1", "at_us": 5}, {"id": "s2", "at_us": 7}]

    place = NamespaceObject.create("space-a", "SPACE", {
        "scope": "retained-logical-byte-partitions", "unit": "byte",
        "extent_bytes": 32, "partitions_digest": _digest(good_parts),
    })
    moment = NamespaceObject.create("time-b", "TIME", {
        "scope": "retained-declared-clock-order", "clock": "test:clock",
        "unit": "microsecond", "span_start_us": 0, "span_end_us": 10,
        "samples_digest": _digest(good_samples),
    })

    # children
    # facets child for place
    ev_pf = canonical_bytes({"schema_version": typed_facets.COLLECTION_VERSION, "objects": [place.to_dict()]})
    pol_pf = typed_facets.typed_facets_policy(trust_roots=["facets-root"])
    req_pf = typed_facets.typed_facets_request(object_kind="SPACE", subject_id=place.object_id, object_digest=place.digest, collection_digest=composition_digest([place]), evidence_ref=_digest(ev_pf), policy=pol_pf)
    cert_pf = typed_facets.build_typed_facets_certificate(req_pf, ev_pf, policy=pol_pf)

    # space child for place
    ev_ps = canonical_bytes({"schema_version": space_layout.EVIDENCE_VERSION, "objects": [place.to_dict()], "inputs": {"partitions": good_parts}})
    pol_ps = space_layout.space_layout_policy(trust_roots=["layout-root"])
    req_ps = space_layout.space_layout_request(subject_id=place.object_id, object_digest=place.digest, collection_digest=composition_digest([place]), evidence_ref=_digest(ev_ps), policy=pol_ps)
    cert_ps = space_layout.build_space_layout_certificate(req_ps, ev_ps, policy=pol_ps)

    # facets child for moment
    ev_mf = canonical_bytes({"schema_version": typed_facets.COLLECTION_VERSION, "objects": [moment.to_dict()]})
    pol_mf = typed_facets.typed_facets_policy(trust_roots=["facets-root"])
    req_mf = typed_facets.typed_facets_request(object_kind="TIME", subject_id=moment.object_id, object_digest=moment.digest, collection_digest=composition_digest([moment]), evidence_ref=_digest(ev_mf), policy=pol_mf)
    cert_mf = typed_facets.build_typed_facets_certificate(req_mf, ev_mf, policy=pol_mf)

    # time child for moment
    ev_mt = canonical_bytes({"schema_version": time_order.EVIDENCE_VERSION, "objects": [moment.to_dict()], "inputs": {"samples": good_samples}})
    pol_mt = time_order.time_order_policy(trust_roots=["clock-root"])
    req_mt = time_order.time_order_request(subject_id=moment.object_id, object_digest=moment.digest, collection_digest=composition_digest([moment]), evidence_ref=_digest(ev_mt), policy=pol_mt)
    cert_mt = time_order.build_time_order_certificate(req_mt, ev_mt, policy=pol_mt)

    children = [
        ("space-a", {"coordinate": typed_facets.coordinate("SPACE"), "request": req_pf, "policy": pol_pf, "certificate": cert_pf}),
        ("space-a", {"coordinate": space_layout.COORDINATE, "request": req_ps, "policy": pol_ps, "certificate": cert_ps}),
        ("time-b", {"coordinate": typed_facets.coordinate("TIME"), "request": req_mf, "policy": pol_mf, "certificate": cert_mf}),
        ("time-b", {"coordinate": time_order.COORDINATE, "request": req_mt, "policy": pol_mt, "certificate": cert_mt}),
    ]

    root = NamespaceObject.create("h", "HYPER", {"label": "place-and-clock", "declared_depth": 1}, {"clock": ["time-b"], "place": ["space-a"]})
    records = [root, place, moment]

    def tier_of(coord: str) -> int:
        return int(coord.split("-", 1)[1].split(".", 1)[0])

    ordered = sorted(children, key=lambda row: (row[0], tier_of(row[1]["coordinate"])))
    selections = [
        {
            "target": target, "coordinate": child["coordinate"],
            "request_digest": _digest(child["request"]),
            "policy_digest": _digest(child["policy"]),
            "certificate_digest": _digest(child["certificate"]),
        }
        for target, child in ordered
    ]
    evidence = canonical_bytes({
        "schema_version": hyper_composed_ceiling.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in sorted(records, key=lambda x: x.object_id)],
        "children": [
            {
                "target": target, "coordinate": child["coordinate"],
                "request": child["request"], "policy": child["policy"],
                "certificate": base64.b64encode(child["certificate"]).decode("ascii"),
            }
            for target, child in ordered
        ],
    })
    policy = hyper_composed_ceiling.hyper_composed_ceiling_policy(trust_roots=["hyper-root"])
    request = hyper_composed_ceiling.hyper_composed_ceiling_request(
        subject_id=root.object_id,
        object_digest=root.digest,
        collection_digest=composition_digest(records),
        child_selections=selections,
        evidence_ref=_digest(evidence),
        policy=policy,
    )
    return request, policy, evidence


# 15. IDENTITY:IDENTITY-3.1
def gen_identity_3_1() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    declaration = {
        "schema_version": "verifier-namespace-identity-evidence-1",
        "identity_id": "identity", "actor_id": "actor", "role_id": "role",
        "collective_id": "collective", "representation_id": "human", "actor_kind": "HUMAN",
        "root_human_id": "human", "scope": "team:research", "evidence_ref": _digest("unresolved-source"),
    }
    objects = [
        NamespaceObject.create("human", "HUMAN", {}),
        NamespaceObject.create("role", "ROLE", {"admitted_scopes": ["team:research"]}),
        NamespaceObject.create("collective", "COLLECTIVE", {}, {"roles": ["role"]}),
        NamespaceObject.create("actor", "ACTOR", {}, {"representation": ["human"], "root_human": ["human"]}),
        NamespaceObject.create("identity", "IDENTITY", {"scope": "team:research", "binding_evidence_digest": _digest(declaration)}, {"actor": ["actor"], "role": ["role"]}),
    ]
    evidence = canonical_bytes({
        "schema_version": "verifier-current-identity-scope-evidence-1",
        "objects": [obj.to_dict() for obj in objects],
        "declaration": declaration,
    })
    policy = identity_scope.identity_scope_policy(trust_roots=["selected-declarations-only"])
    subject = next(obj for obj in objects if obj.object_id == "identity")
    request = identity_scope.identity_scope_request(
        subject_id="identity",
        object_digest=subject.digest,
        collective_id="collective",
        declaration_digest=_digest(declaration),
        collection_digest=composition_digest(objects),
        evidence_ref=_digest(json.loads(evidence)),
        policy=policy,
    )
    return request, policy, evidence


# 16. MODEL:MODEL-3.1
def gen_model_3_1() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    arch = b"open-model-architecture\x00v1"
    weights = bytes(range(32)) + b"\x00weights"
    subject = NamespaceObject.create("model-root", "MODEL", {
        "architecture_bytes_sha256": _digest(arch),
        "architecture_byte_length": len(arch),
        "weights_bytes_sha256": _digest(weights),
        "weights_byte_length": len(weights),
        "format_note": "synthetic opaque bytes",
    }, {
        "arch": ["architecture"], "data": ["dataset"], "events": ["event"],
        "bench": ["benchmark"], "train": ["training"], "env": ["environment"],
        "hardware": ["hardware"],
    })
    objects = [
        subject,
        NamespaceObject.create("architecture", "ARCH", {"artifact_bytes_sha256": _digest(arch)}),
        NamespaceObject.create("dataset", "DATA", {}),
        NamespaceObject.create("benchmark", "BENCH", {}, {"data": ["dataset"], "verifier": ["checker"]}),
        NamespaceObject.create("checker", "VERIFIER", {}),
        NamespaceObject.create("training", "TRAIN", {}, {"arch": ["architecture"], "data": ["dataset"], "bench": ["benchmark"], "events": ["event"]}),
        NamespaceObject.create("event", "EVENT", {}, {"time": ["time"], "space": ["space"], "meaning": ["meaning"]}),
        NamespaceObject.create("time", "TIME", {}),
        NamespaceObject.create("space", "SPACE", {}),
        NamespaceObject.create("meaning", "OBJECT", {}),
        NamespaceObject.create("environment", "ENV", {}),
        NamespaceObject.create("hardware", "HARDWARE", {}),
    ]
    evidence = canonical_bytes({
        "schema_version": model_artifact_bytes.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": {
            "architecture_b64": base64.b64encode(arch).decode("ascii"),
            "weights_b64": base64.b64encode(weights).decode("ascii"),
        },
    })
    policy = model_artifact_bytes.model_artifact_bytes_policy(trust_roots=["externally-selected-retained-model"])
    request = model_artifact_bytes.model_artifact_bytes_request(
        subject_id=subject.object_id,
        object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=_digest(evidence),
        policy=policy,
    )
    return request, policy, evidence


# 17. MODEL:MODEL-3.2
def gen_model_3_2() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    width = 512
    arch = canonical_bytes({
        "input_size": width,
        "layers": [{"outputs": width, "activation": "relu"}, {"outputs": 1, "activation": "linear"}],
        "arithmetic": "python-binary64",
    })
    weights = canonical_bytes([
        {"weight": [[0.125] * width for _ in range(width)], "bias": [0.0] * width},
        {"weight": [[1.0 / width] * width], "bias": [0.0]},
    ])
    subject = NamespaceObject.create("model-root", "MODEL", {
        "architecture_bytes_sha256": _digest(arch),
        "architecture_byte_length": len(arch),
        "weights_bytes_sha256": _digest(weights),
        "weights_byte_length": len(weights),
    }, {
        "arch": ["architecture"], "data": ["dataset"], "events": ["event"],
        "bench": ["benchmark"], "train": ["training"], "env": ["environment"],
        "hardware": ["hardware"],
    })
    objects = [
        subject,
        NamespaceObject.create("architecture", "ARCH", {"artifact_bytes_sha256": _digest(arch)}),
        NamespaceObject.create("dataset", "DATA", {}),
        NamespaceObject.create("benchmark", "BENCH", {}, {"data": ["dataset"], "verifier": ["checker"]}),
        NamespaceObject.create("checker", "VERIFIER", {}),
        NamespaceObject.create("training", "TRAIN", {}, {"arch": ["architecture"], "data": ["dataset"], "bench": ["benchmark"], "events": ["event"]}),
        NamespaceObject.create("event", "EVENT", {}, {"time": ["time"], "space": ["space"], "meaning": ["meaning"]}),
        NamespaceObject.create("time", "TIME", {}),
        NamespaceObject.create("space", "SPACE", {}),
        NamespaceObject.create("meaning", "OBJECT", {}),
        NamespaceObject.create("environment", "ENV", {}),
        # The installed specimen is a Windows x64 fixture.  Binding generator
        # bytes to the host running this script would make the registry differ
        # across the Linux, macOS, and Windows reproduction gates.
        NamespaceObject.create(
            "hardware", "HARDWARE", {
                "process_backend": model_hardware_observation.BACKEND,
                "machine": "AMD64",
            },
        ),
    ]
    evidence = canonical_bytes({
        "schema_version": model_hardware_observation.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": {
            "architecture_b64": base64.b64encode(arch).decode("ascii"),
            "weights_b64": base64.b64encode(weights).decode("ascii"),
            "input": [1.0] * width,
            "expected_output": [64.0],
        },
    })
    policy = model_hardware_observation.model_hardware_policy(trust_roots=["selected-open-model-and-local-job"])
    request = model_hardware_observation.model_hardware_request(
        subject_id=subject.object_id,
        object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=_digest(evidence),
        policy=policy,
        lower_memory_bytes=18 * 1024 * 1024,
        upper_memory_bytes=40 * 1024 * 1024,
        wall_seconds=5,
        trials=2,
        max_native_operations=1000000,
    )
    return request, policy, evidence


# 18. MODEL:MODEL-3.3
def gen_model_3_3() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    weights = b"selected-open-quantized-weight-bytes\x00"
    arch_bytes = b"selected-open-architecture\x00"
    spec = {
        "schema_version": model_quantization.SPECIFICATION_VERSION,
        "weight_artifact_sha256": _digest(weights),
        "scheme": "affine-per-tensor-v1",
        "configuration": {
            "storage_bits": 8, "signed": True, "scale_numerator": 1,
            "scale_denominator": 128, "zero_point": 0,
            "rounding": "ties-to-even", "saturation": "clamp",
        },
    }
    raw = canonical_bytes(spec)
    subject = NamespaceObject.create("model-root", "MODEL", {
        "architecture_bytes_sha256": _digest(arch_bytes),
        "architecture_byte_length": len(arch_bytes),
        "weights_bytes_sha256": _digest(weights),
        "weights_byte_length": len(weights),
        "quantization_spec_sha256": _digest(raw),
        "quantization_spec_byte_length": len(raw),
    }, {
        "arch": ["architecture"], "data": ["dataset"], "events": ["event"],
        "bench": ["benchmark"], "train": ["training"], "env": ["environment"],
        "hardware": ["hardware"],
    })
    objects = [
        subject,
        NamespaceObject.create("architecture", "ARCH", {"artifact_bytes_sha256": _digest(arch_bytes)}),
        NamespaceObject.create("dataset", "DATA", {}),
        NamespaceObject.create("benchmark", "BENCH", {}, {"data": ["dataset"], "verifier": ["checker"]}),
        NamespaceObject.create("checker", "VERIFIER", {}),
        NamespaceObject.create("training", "TRAIN", {}, {"arch": ["architecture"], "data": ["dataset"], "bench": ["benchmark"], "events": ["event"]}),
        NamespaceObject.create("event", "EVENT", {}, {"time": ["time"], "space": ["space"], "meaning": ["meaning"]}),
        NamespaceObject.create("time", "TIME", {}),
        NamespaceObject.create("space", "SPACE", {}),
        NamespaceObject.create("meaning", "OBJECT", {}),
        NamespaceObject.create("environment", "ENV", {}),
        NamespaceObject.create("hardware", "HARDWARE", {}),
    ]
    evidence = canonical_bytes({
        "schema_version": model_quantization.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": {"quantization_spec_b64": base64.b64encode(raw).decode("ascii")},
    })
    policy = model_quantization.model_quantization_policy(trust_roots=["selected-open-model"])
    request = model_quantization.model_quantization_request(
        subject_id=subject.object_id,
        object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=_digest(evidence),
        policy=policy,
    )
    return request, policy, evidence


# 19. MODEL:MODEL-3.4
def gen_model_3_4() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    row = {"id": "sample-1", "text": "open training sample"}
    row_digest = _digest(row)
    rows = [row]
    artifact = {
        "shards": {
            "training": {
                "digest": _digest(rows),
                "records": 1,
                "bytes": len(canonical_bytes(rows)),
                "record_digests": [row_digest],
                "merkle_root": row_digest,
            }
        }
    }
    dataset = NamespaceObject.create("dataset", "DATA", artifact)
    child_objects = [dataset]
    child_evidence = canonical_bytes({
        "schema_version": data_checks.EVIDENCE_VERSION,
        "objects": [dataset.to_dict()],
        "inputs": {"shards": {"training": rows}},
    })
    child_policy = data_checks.data_checks_policy(trust_roots=["selected-open-data"])
    child_request = data_checks.data_checks_request(
        check="inventory",
        subject_id=dataset.object_id,
        object_digest=dataset.digest,
        collection_digest=composition_digest(child_objects),
        evidence_ref=_digest(child_evidence),
        policy=child_policy,
    )
    child_certificate = data_checks.build_data_checks_certificate(
        child_request, child_evidence, policy=child_policy
    )

    model = NamespaceObject.create("model", "MODEL", {}, {
        "arch": ["architecture"], "data": ["dataset"],
        "events": ["event"], "bench": ["benchmark"],
        "train": ["training"], "env": ["environment"],
        "hardware": ["hardware"],
    })
    objects = [
        model, dataset,
        NamespaceObject.create("architecture", "ARCH", {}),
        NamespaceObject.create("benchmark", "BENCH", {}, {"data": ["dataset"], "verifier": ["checker"]}),
        NamespaceObject.create("checker", "VERIFIER", {}),
        NamespaceObject.create("training", "TRAIN", {}, {"arch": ["architecture"], "data": ["dataset"], "bench": ["benchmark"], "events": ["event"]}),
        NamespaceObject.create("event", "EVENT", {}, {"time": ["time"], "space": ["space"], "meaning": ["meaning"]}),
        NamespaceObject.create("time", "TIME", {}),
        NamespaceObject.create("space", "SPACE", {}),
        NamespaceObject.create("meaning", "OBJECT", {}),
        NamespaceObject.create("environment", "ENV", {}),
        NamespaceObject.create("hardware", "HARDWARE", {}),
    ]
    evidence = canonical_bytes({
        "schema_version": model_data_citation.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": {"data_certificate_b64": base64.b64encode(child_certificate).decode("ascii")},
    })
    policy = model_data_citation.model_data_policy(trust_roots=["selected-open-model-data"])
    request = model_data_citation.model_data_request(
        subject_id=model.object_id,
        object_digest=model.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=_digest(evidence),
        policy=policy,
        data_subject_id=dataset.object_id,
        data_object_digest=dataset.digest,
        data_certificate_digest=_digest(child_certificate),
        data_request=child_request,
        data_policy=child_policy,
    )
    return request, policy, evidence


# 20. MODEL:MODEL-3.5
def gen_model_3_5() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    # Need model_data certificate as prerequisite
    m34_req, m34_pol, m34_ev = gen_model_3_4()
    m34_cert = model_data_citation.build_model_data_certificate(m34_req, m34_ev, policy=m34_pol)

    row = {"id": "sample-1", "text": "open training sample"}
    row_digest = _digest(row)
    rows = [row]
    dataset_payload = {
        "shards": {
            "training": {
                "digest": _digest(rows),
                "records": 1,
                "bytes": len(canonical_bytes(rows)),
                "record_digests": [row_digest],
                "merkle_root": row_digest,
            }
        }
    }
    dataset = NamespaceObject.create("dataset", "DATA", dataset_payload)
    training = NamespaceObject.create("training", "TRAIN", {}, {
        "arch": ["architecture"], "data": ["dataset"],
        "bench": ["benchmark"], "events": ["event"],
    })
    model = NamespaceObject.create("model", "MODEL", {}, {
        "arch": ["architecture"], "data": ["dataset"],
        "events": ["event"], "bench": ["benchmark"],
        "train": ["training"], "env": ["environment"],
        "hardware": ["hardware"],
    })
    objects = [
        model, training, dataset,
        NamespaceObject.create("architecture", "ARCH", {}),
        NamespaceObject.create("benchmark", "BENCH", {}, {"data": ["dataset"], "verifier": ["checker"]}),
        NamespaceObject.create("checker", "VERIFIER", {}),
        NamespaceObject.create("event", "EVENT", {}, {"time": ["time"], "space": ["space"], "meaning": ["meaning"]}),
        NamespaceObject.create("time", "TIME", {}),
        NamespaceObject.create("space", "SPACE", {}),
        NamespaceObject.create("meaning", "OBJECT", {}),
        NamespaceObject.create("environment", "ENV", {}),
        NamespaceObject.create("hardware", "HARDWARE", {}),
    ]
    evidence = canonical_bytes({
        "schema_version": model_train_citation.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": {"model_data_certificate_b64": base64.b64encode(m34_cert).decode("ascii")},
    })
    policy = model_train_citation.model_train_policy(trust_roots=["selected-open-model-train"])
    request = model_train_citation.model_train_request(
        subject_id=model.object_id,
        object_digest=model.digest,
        collection_digest=composition_digest(objects),
        evidence_ref=_digest(evidence),
        policy=policy,
        train_subject_id=training.object_id,
        train_object_digest=training.digest,
        data_subject_id=dataset.object_id,
        data_object_digest=dataset.digest,
        model_data_certificate_digest=_digest(m34_cert),
        model_data_request=m34_req,
        model_data_policy=m34_pol,
    )
    return request, policy, evidence


# 21. MODEL:MODEL-3.7
def gen_model_3_7() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    from verifier.domains.contracts import train_data_bridge
    # 1. train lineage check
    config = {
        "optimizer": "sgd", "learning_rate": 0.125, "weight_decay": 0,
        "beta1": 0.5, "beta2": 0.5, "epsilon": 0.125, "momentum": 0,
        "schedule": "constant", "accumulation": 1, "max_grad_norm": 100,
        "arithmetic": "python-binary64",
    }
    architecture = {"input_size": 1, "layers": [{"outputs": 1, "activation": "linear"}], "arithmetic": "python-binary64"}
    checkpoints = [
        {"weights": [{"weight": [[w]], "bias": [b]}], "optimizer_state": {"step": i, "first": [g, g], "second": [0, 0]}}
        for i, (w, b, g) in enumerate([(1, 0, 0), (1.25, 0.25, -2), (1.375, 0.375, -1)])
    ]
    batch = [[{"input": [1], "target": [2]}]]
    commitments = [_digest(c) for c in checkpoints]
    steps = [
        {
            "index": i, "parent": commitments[i], "result": commitments[i+1],
            "configuration_digest": _digest(config), "batch": _digest(batch),
            "gradients": [g, g], "loss": loss,
        }
        for i, (g, loss) in enumerate([(-2, 1), (-1, 0.25)])
    ]
    artifact = {
        "configuration": config, "architecture": architecture, "checkpoint_digests": commitments,
        "steps_digest": _digest(steps), "start_step": 0, "tolerance": 0,
    }
    batches_map = {_digest(batch): batch}
    retained_train = {"checkpoints": checkpoints, "steps": steps, "batches": batches_map}

    events = ["step-" + str(i) for i in range(len(steps))]
    training_obj = NamespaceObject.create("training", "TRAIN", artifact, {"arch": ["architecture"], "data": ["batches"], "bench": ["loss"], "events": events})
    train_objects = [
        training_obj,
        NamespaceObject.create("architecture", "ARCH", deepcopy(architecture)),
        NamespaceObject.create("batches", "DATA", {"batches": deepcopy(batches_map)}),
        NamespaceObject.create("loss", "BENCH", {"loss": "mean-squared-error", "reduction": "mean-samples-and-outputs", "arithmetic": "python-binary64", "relu_derivative_at_zero": 0}, {"data": ["batches"], "verifier": ["checker"]}),
        NamespaceObject.create("checker", "VERIFIER", {"mechanism_id": train_checks.MECHANISM_ID, "mechanism_digest": train_checks.mechanism_digest()}),
        NamespaceObject.create("space", "SPACE", {"scope": "retained-training-trace"}),
        NamespaceObject.create("meaning", "OBJECT", {"operation": "optimizer-update", "configuration_digest": _digest(config)}),
    ]
    for i, step in enumerate(steps):
        train_objects.extend([
            NamespaceObject.create(events[i], "EVENT", {"training_step": deepcopy(step)}, {"time": ["time-" + str(i)], "space": ["space"], "meaning": ["meaning"]}),
            NamespaceObject.create("time-" + str(i), "TIME", {"index": step["index"]}),
        ])

    # build dataset for lineage
    rows = [batches_map[key] for key in sorted(batches_map)]
    commitments_data = {
        "training": {
            "digest": _digest(rows), "records": len(rows), "bytes": len(canonical_bytes(rows)),
            "record_digests": [_digest(row) for row in rows], "merkle_root": _digest(rows[0]),
        }
    }
    inventory = NamespaceObject.create("dataset", "DATA", {"shards": commitments_data})
    model = NamespaceObject.create("model", "MODEL", {}, {
        "arch": ["architecture"], "data": [inventory.object_id],
        "train": [training_obj.object_id], "bench": ["loss"],
        "events": ["step-0", "step-1"], "env": ["environment"],
        "hardware": ["hardware"],
    })
    objects = [
        *train_objects,
        inventory, model,
        NamespaceObject.create("environment", "ENV", {}),
        NamespaceObject.create("hardware", "HARDWARE", {}),
    ]
    collection_dig = composition_digest(objects)

    train_ev = canonical_bytes({
        "schema_version": train_checks.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": retained_train,
    })
    train_pol = train_checks.train_checks_policy(trust_roots=["selected-model-train"])
    train_req = train_checks.train_checks_request(
        check="lineage", subject_id=training_obj.object_id,
        object_digest=training_obj.digest, collection_digest=collection_dig,
        evidence_ref=_digest(train_ev), policy=train_pol,
    )
    train_cert = train_checks.build_train_checks_certificate(train_req, train_ev, policy=train_pol)

    data_ev = canonical_bytes({
        "schema_version": data_checks.EVIDENCE_VERSION,
        "objects": [inventory.to_dict()],
        "inputs": {"shards": {"training": rows}},
    })
    data_pol = data_checks.data_checks_policy(trust_roots=["selected-model-data"])
    data_req = data_checks.data_checks_request(
        check="inventory", subject_id=inventory.object_id,
        object_digest=inventory.digest, collection_digest=composition_digest([inventory]),
        evidence_ref=_digest(data_ev), policy=data_pol,
    )
    data_cert = data_checks.build_data_checks_certificate(data_req, data_ev, policy=data_pol)

    m_data_ev = canonical_bytes({
        "schema_version": model_data_citation.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "inputs": {"data_certificate_b64": base64.b64encode(data_cert).decode("ascii")},
    })
    m_data_pol = model_data_citation.model_data_policy(trust_roots=["selected-model-data-citation"])
    m_data_req = model_data_citation.model_data_request(
        subject_id=model.object_id, object_digest=model.digest,
        collection_digest=collection_dig, evidence_ref=_digest(m_data_ev),
        policy=m_data_pol, data_subject_id=inventory.object_id,
        data_object_digest=inventory.digest, data_certificate_digest=_digest(data_cert),
        data_request=data_req, data_policy=data_pol,
    )
    m_data_cert = model_data_citation.build_model_data_certificate(m_data_req, m_data_ev, policy=m_data_pol)

    bridge_ev = canonical_bytes({
        "schema_version": train_data_bridge.EVIDENCE_VERSION,
        "train_certificate_b64": base64.b64encode(train_cert).decode("ascii"),
        "data_certificate_b64": base64.b64encode(data_cert).decode("ascii"),
    })
    bridge_pol = train_data_bridge.train_data_bridge_policy(trust_roots=["selected-model-bridge"])
    batch_view = next(item for item in objects if item.object_id == "batches")
    bridge_req = train_data_bridge.train_data_bridge_request(
        train_request=train_req, train_policy=train_pol,
        train_certificate_digest=_digest(train_cert),
        data_request=data_req, data_policy=data_pol,
        data_certificate_digest=_digest(data_cert),
        batch_view_id=batch_view.object_id, batch_view_digest=batch_view.digest,
        shard_ids=["training"], evidence_ref=_digest(bridge_ev),
        policy=bridge_pol,
    )
    bridge_cert = train_data_bridge.build_train_data_bridge_certificate(bridge_req, bridge_ev, policy=bridge_pol)

    evidence = canonical_bytes({
        "schema_version": model_data_lineage.EVIDENCE_VERSION,
        "model_data_certificate_b64": base64.b64encode(m_data_cert).decode("ascii"),
        "bridge_certificate_b64": base64.b64encode(bridge_cert).decode("ascii"),
    })
    policy = model_data_lineage.model_data_lineage_policy(trust_roots=["selected-model-lineage"])
    request = model_data_lineage.model_data_lineage_request(
        subject_id=model.object_id, object_digest=model.digest,
        collection_digest=collection_dig, evidence_ref=_digest(evidence),
        train_subject_id=training_obj.object_id, train_object_digest=training_obj.digest,
        model_data_subject_id=inventory.object_id, model_data_object_digest=inventory.digest,
        batch_view_subject_id=batch_view.object_id, batch_view_object_digest=batch_view.digest,
        model_data_certificate_digest=_digest(m_data_cert), model_data_request=m_data_req,
        model_data_policy=m_data_pol, bridge_certificate_digest=_digest(bridge_cert),
        bridge_request=bridge_req, bridge_policy=bridge_pol, policy=policy,
    )
    return request, policy, evidence


# 22. OBJECT:OBJECT-3.1
def gen_object_3_1() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    bounds = {
        "max_records": 8, "max_record_bytes": 4096, "max_payload_depth": 4,
        "max_payload_values": 64, "max_references": 4,
    }
    records = [
        NamespaceObject.create("doc-root", "OBJECT", {"title": "root", "body": {"lines": ["a", "b"], "meta": {"lang": "café"}}}),
        NamespaceObject.create("clock", "TIME", {"unit": "microsecond"}),
        NamespaceObject.create("region", "SPACE", {"unit": "byte", "extent_bytes": 64}),
        NamespaceObject.create("evt", "EVENT", {"label": "write"}, {"meaning": ["doc-root"], "space": ["region"], "time": ["clock"]}),
    ]
    raw_rows = [
        {"address": "sha256:" + hashlib.sha256(canonical_bytes(item.to_dict())).hexdigest(), "bytes": base64.b64encode(canonical_bytes(item.to_dict())).decode("ascii")}
        for item in records
    ]
    subject = next(item for item in records if item.object_id == "doc-root")
    evidence = canonical_bytes({
        "schema_version": object_statics.EVIDENCE_VERSION,
        "records": raw_rows,
    })
    policy = object_statics.object_statics_policy(trust_roots=["statics-root"])
    request = object_statics.object_statics_request(
        subject_id=subject.object_id,
        object_digest=subject.digest,
        collection_digest=composition_digest(records),
        structural_bounds=bounds,
        evidence_ref="sha256:" + hashlib.sha256(evidence).hexdigest(),
        policy=policy,
    )
    return request, policy, evidence


# 23. OWNER:OWNER-3.1
def gen_owner_3_1() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    actor = NamespaceObject.create("actor", "ACTOR", {}, {"representation": ["human"], "root_human": ["human"]})
    owned = NamespaceObject.create("owned", "HARDWARE", {"realm": "physical"})
    owner = NamespaceObject.create("owner", "OWNER", {}, {"actor": ["actor"], "object": ["owned"]})
    human = NamespaceObject.create("human", "HUMAN", {})
    objects = [actor, owned, owner, human]

    raw = canonical_bytes({
        "schema_version": owner_eligibility.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
        "isolation_evidence": None,
    })
    policy = owner_eligibility.owner_eligibility_policy(trust_roots=["test:exact-independent-selection"])
    request = owner_eligibility.owner_eligibility_request(
        subject_id=owner.object_id,
        object_digest=owner.digest,
        collection_digest=composition_digest(objects),
        evidence_ref="sha256:" + hashlib.sha256(raw).hexdigest(),
        isolation_binding=None,
        policy=policy,
    )
    return request, policy, raw


# 24. RECEIPT:RECEIPT-3.1
def gen_receipt_3_1() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    reasons = ({"reason_id": "r1", "proposition": "x1 holds", "evidence_kind": "OBSERVED", "parent_reason_ids": []},)
    audit = IndependentAuditor.audit_claim_derivation(claim_id="claim-1", n_vars=1, clauses=((1,),), atomic_reasons=reasons)
    receipt = VstdReceipt(
        schema_version="VSTD-1", receipt_kind="claim_mechanics", receipt_id="VFY-000001",
        claim=ClaimSpec(id="claim-1", title="unit clause", statement="x1 is satisfiable", status="draft", scope="one clause", limitations=("toy",), falsification_condition="formula unsatisfiable", last_verified="2026-10-01"),
        evidence=EvidencePayload(domain="sat", input_text_or_formula="x1", n_vars=1, clauses=((1,),), atomic_reasons=reasons, assumptions=(), source_artifacts={"formula": "sha256:" + "a" * 64}),
        target_result={"satisfiable": True}, independent_audit=audit,
        provenance=ProvenanceRecord(
            target_name="fixture", portable_repository_id="fixture-repository", local_repository_path="fixture/repository",
            git=GitProvenance("a" * 40, "main", False), runtime=RuntimeEnvironment("3.12", "CPython", "test", "test", "test", "masked"),
            captured_at_utc="2026-10-01T00:00:00+00:00", command_executed="fixture",
        ),
        reproducibility={"level": "CONTENT_IDENTICAL"},
        execution_metadata=ExecutionMetadata("2026-10-01T00:00:00+00:00", 1.5, "fixture", "", ""),
    )
    receipt_dict = receipt.to_dict()
    receipt_bytes = canonical_bytes(receipt_dict)

    record = NamespaceObject.create("receipt-a", "RECEIPT", {
        "receipt_kind": "claim_mechanics", "receipt_schema_version": "VSTD-1",
        "receipt_sha256": _digest(receipt_bytes), "prerequisites": [],
    })
    evidence = canonical_bytes({
        "schema_version": receipt_statics.EVIDENCE_VERSION,
        "receipt_object": record.to_dict(),
        "receipt_base64": base64.b64encode(receipt_bytes).decode("ascii"),
    })
    policy = receipt_statics.receipt_statics_policy(trust_roots=["statics-root"])
    request = receipt_statics.receipt_statics_request(
        subject_id=record.object_id,
        object_digest=record.digest,
        evidence_ref=_digest(evidence),
        policy=policy,
    )
    return request, policy, evidence


# 25. ROLE:ROLE-3.1
def gen_role_3_1() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    matrix = {
        "schema_version": role_constraints.MATRIX_VERSION,
        "collective_id": "team",
        "roles": [
            {"role_id": "author", "allowed_permissions": ["write"], "allowed_scopes": ["project"], "min_occupants": 1, "max_occupants": 1},
            {"role_id": "reviewer", "allowed_permissions": ["approve", "read"], "allowed_scopes": ["project"], "min_occupants": 1, "max_occupants": 1},
        ],
        "actors": [
            {"actor_id": "actor-a", "allowed_roles": ["author"]},
            {"actor_id": "actor-b", "allowed_roles": ["reviewer"]},
        ],
        "occupancies": [
            {"identity_id": "identity-a", "actor_id": "actor-a", "role_id": "author", "scope": "project"},
            {"identity_id": "identity-b", "actor_id": "actor-b", "role_id": "reviewer", "scope": "project"},
        ],
        "exclusive_role_sets": [["author", "reviewer"]],
    }
    objects = [
        NamespaceObject.create("human-a", "HUMAN", {}),
        NamespaceObject.create("human-b", "HUMAN", {}),
        NamespaceObject.create("actor-a", "ACTOR", {}, {"representation": ["human-a"], "root_human": ["human-a"]}),
        NamespaceObject.create("actor-b", "ACTOR", {}, {"representation": ["human-b"], "root_human": ["human-b"]}),
        NamespaceObject.create("author", "ROLE", {"permissions": ["write"], "admitted_scopes": ["project"]}),
        NamespaceObject.create("reviewer", "ROLE", {"permissions": ["approve", "read"], "admitted_scopes": ["project"]}),
        NamespaceObject.create("team", "COLLECTIVE", {}, {"roles": ["author", "reviewer"]}),
        NamespaceObject.create("identity-a", "IDENTITY", {"scope": "project"}, {"actor": ["actor-a"], "role": ["author"]}),
        NamespaceObject.create("identity-b", "IDENTITY", {"scope": "project"}, {"actor": ["actor-b"], "role": ["reviewer"]}),
    ]
    subject = next(item for item in objects if item.object_id == "author")
    evidence = canonical_bytes({
        "schema_version": role_constraints.EVIDENCE_VERSION,
        "objects": [obj.to_dict() for obj in objects],
        "inputs": {"matrix": matrix},
    })
    policy = role_constraints.role_constraints_policy(trust_roots=["selected-role-matrix"])
    request = role_constraints.role_constraints_request(
        subject_id=subject.object_id,
        object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        matrix_digest=_digest(matrix),
        evidence_ref=_digest(json.loads(evidence)),
        policy=policy,
    )
    return request, policy, evidence


# 26. SIM:SIM-3.4
def gen_sim_3_4() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    statement = "A declared closed-system energy balance."
    source_ref = "urn:example:external-law:v1"
    law_payload = {
        "schema_version": "verifier-external-law-statement-1",
        "statement": statement,
        "applicability": "A declared closed system with boundary fluxes accounted for.",
        "source_ref": source_ref,
    }
    law = NamespaceObject.create("law", "OBJECT", law_payload)
    objects = [
        NamespaceObject.create("data", "DATA", {}),
        NamespaceObject.create("checker", "VERIFIER", {}),
        NamespaceObject.create("env", "ENV", {}),
        law,
    ]
    subject = NamespaceObject.create("sim", "SIM", {
        "scope": "selected-external-law-statement",
        "modelled_law_object_id": "law",
    }, {"data": ["data"], "verifier": ["checker"], "objects": ["law"], "env": ["env"]})
    objects.append(subject)
    evidence_dict = {
        "schema_version": sim_external_law.EVIDENCE_VERSION,
        "objects": [item.to_dict() for item in objects],
    }
    evidence = canonical_bytes(evidence_dict)
    policy = sim_external_law.sim_external_law_policy(trust_roots=["selected-law-fixture"])
    request = sim_external_law.sim_external_law_request(
        subject_id=subject.object_id,
        object_digest=subject.digest,
        collection_digest=composition_digest(objects),
        law_object_id=law.object_id,
        law_object_digest=law.digest,
        law_statement_digest=_digest(statement),
        source_ref=source_ref,
        evidence_ref=_digest(evidence_dict),
        policy=policy,
    )
    return request, policy, evidence


# 27. SPACE:SPACE-3.1
def gen_space_3_1() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    partitions = [
        {"id": "first", "start_byte": 0, "end_byte": 128, "alignment_bytes": 64},
        {"id": "second", "start_byte": 256, "end_byte": 320, "alignment_bytes": 128},
    ]
    payload = {
        "scope": "retained-logical-byte-partitions", "unit": "byte",
        "extent_bytes": 1024, "partitions_digest": _digest(partitions),
    }
    subject = NamespaceObject.create("space-root", "SPACE", payload)
    evidence = canonical_bytes({
        "schema_version": space_layout.EVIDENCE_VERSION,
        "objects": [subject.to_dict()],
        "inputs": {"partitions": partitions},
    })
    policy = space_layout.space_layout_policy(trust_roots=["selected-layout"])
    request = space_layout.space_layout_request(
        subject_id=subject.object_id,
        object_digest=subject.digest,
        collection_digest=composition_digest([subject]),
        evidence_ref=_digest(json.loads(evidence)),
        policy=policy,
    )
    return request, policy, evidence


# 28. TIME:TIME-3.1
def gen_time_3_1() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    samples = [{"id": "s0", "at_us": 2}, {"id": "s1", "at_us": 5}, {"id": "s2", "at_us": 7}]
    child_sub = NamespaceObject.create("time-root", "TIME", {
        "scope": "retained-declared-clock-order", "clock": "test:clock",
        "unit": "microsecond", "span_start_us": 0, "span_end_us": 10,
        "samples_digest": _digest(samples),
    })
    child_ev = canonical_bytes({
        "schema_version": time_order.EVIDENCE_VERSION,
        "objects": [child_sub.to_dict()],
        "inputs": {"samples": samples},
    })
    child_pol = time_order.time_order_policy(trust_roots=["selected-retained-clock"])
    child_req = time_order.time_order_request(
        subject_id=child_sub.object_id,
        object_digest=child_sub.digest,
        collection_digest=composition_digest([child_sub]),
        evidence_ref=_digest(json.loads(child_ev)),
        policy=child_pol,
    )
    child_cert = time_order.build_time_order_certificate(child_req, child_ev, policy=child_pol)

    evidence = canonical_bytes({
        "schema_version": time_strict.EVIDENCE_VERSION,
        "child_request": child_req,
        "child_policy": child_pol,
        "child_certificate": base64.b64encode(child_cert).decode("ascii"),
    })
    policy = time_strict.time_strict_policy(trust_roots=["selected-strict-clock"])
    request = time_strict.time_strict_request(
        subject_id=child_req["subject_id"],
        object_digest=child_req["object_digest"],
        collection_digest=child_req["collection_digest"],
        child_request_digest=_digest(child_req),
        child_policy_digest=_digest(child_pol),
        child_certificate_digest=_digest(child_cert),
        evidence_ref=_digest(evidence),
        policy=policy,
    )
    return request, policy, evidence


# 29. TOKEN:TOKEN-3.1
def gen_token_3_1() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    common = {"issuing_key_id": _digest("documentary-key-id"), "issued_at": 100,
              "algorithm": "Ed25519", "audience": ["reader"],
              "signature": "unverified-declaration"}
    birth = {**common, "kind": "birth", "token_id": "birth", "replay_id": "r-birth",
             "birth_epoch": 4, "commitment": _digest("opaque-birth-commitment")}
    root = {**common, "kind": "lifetime", "token_id": "root", "replay_id": "r-root",
            "parent_grant_id": "birth", "delegate_key_id": _digest("delegate-label"),
            "permitted_scopes": ["read", "write"], "not_before": 100, "not_after": 1000,
            "max_invocations": 10, "soulbound": False, "confirmation_key_id": None,
            "caveats": [{"condition": "region=local", "discharge": None}]}
    child = {**root, "token_id": "child", "replay_id": "r-child",
             "parent_grant_id": "root", "permitted_scopes": ["read"],
             "not_before": 200, "not_after": 800, "max_invocations": 2}
    epochs, head = [], birth["commitment"]
    for epoch, status in enumerate(["ACTIVE", "SUSPENDED", "ACTIVE", "REVOKED"], 5):
        head = _digest([head, epoch, status])
        epochs.append({"epoch": epoch, "status": status, "digest": head})
    aging = {**common, "kind": "aging", "token_id": "aging", "replay_id": "r-aging",
             "birth_token_id": "birth", "epoch_start": 5, "epoch_end": 8,
             "accumulated_epochs": 2, "accumulator_digest": head,
             "revocation_status": "REVOKED"}
    inputs = {"tokens": [birth, root, child, aging], "epochs": epochs}
    artifact = {"clock": "fixture:declared-clock", "clock_skew": 30,
                "root_scopes": ["read", "write"],
                "tokens_digest": _digest(inputs["tokens"]), "epochs_digest": _digest(epochs)}
    subject = NamespaceObject.create("token-holding", "TOKEN", {
        "scope": "retained-capability-token-records", "clock_unit": "microsecond",
        "artifact": artifact,
    })
    evidence = canonical_bytes({
        "schema_version": token_checks.EVIDENCE_VERSION,
        "objects": [subject.to_dict()],
        "inputs": inputs,
    })
    policy = token_checks.token_checks_policy(trust_roots=["fixture:retained-selection"])
    request = token_checks.token_checks_request(
        check="windows",
        subject_id=subject.object_id,
        object_digest=subject.digest,
        collection_digest=composition_digest([subject]),
        evidence_ref=_digest(json.loads(evidence)),
        policy=policy,
    )
    return request, policy, evidence


# 30. TRAIN:TRAIN-3.2
def gen_train_3_2() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    rec = {
        'operation': 'binary64-sum-steps-1',
        'values': ['0x1.0000000000000p+0', '0x1.0000000000000p-53', '0x1.0000000000000p-53'],
        'retained_order': [[0, 1], [3, 2]],
        'retained_result': '0x1.0000000000000p+0',
        'alternative_order': [[1, 2], [0, 3]],
        'order_effect_bound': '0x1.0000000000000p-52',
    }
    payload = {"reduction_digest": _digest(rec)}
    rows = [
        NamespaceObject.create("data", "DATA", {}),
        NamespaceObject.create("arch", "ARCH", {}),
        NamespaceObject.create("checker", "VERIFIER", {}),
        NamespaceObject.create("t0", "TIME", {"index": 0}),
        NamespaceObject.create("trace", "SPACE", {"scope": "retained-training-trace"}),
        NamespaceObject.create("meaning", "OBJECT", {"operation": "gradient-reduction"}),
        NamespaceObject.create("e0", "EVENT", {}, {"time": ["t0"], "space": ["trace"], "meaning": ["meaning"]}),
        NamespaceObject.create("loss", "BENCH", {"loss": "mean-squared-error"}, {"verifier": ["checker"], "data": ["data"]}),
        NamespaceObject.create("train", "TRAIN", payload, {"data": ["data"], "events": ["e0"], "bench": ["loss"], "arch": ["arch"]}),
    ]
    subject = next(row for row in rows if row.object_id == "train")
    evidence = canonical_bytes({
        "schema_version": train_accumulation.EVIDENCE_VERSION,
        "objects": [row.to_dict() for row in rows],
        "inputs": {"reduction": rec},
    })
    policy = train_accumulation.train_accumulation_policy(trust_roots=["test:reduction"])
    request = train_accumulation.train_accumulation_request(
        subject_id=subject.object_id,
        object_digest=subject.digest,
        collection_digest=composition_digest(rows),
        evidence_ref=_digest(json.loads(evidence)),
        policy=policy,
    )
    return request, policy, evidence


# 31. VERIFIER:VERIFIER-3.1
def gen_verifier_3_1() -> tuple[dict[str, Any], dict[str, Any], bytes]:
    partitions = [
        {"id": "right", "start_byte": 16, "end_byte": 32, "alignment_bytes": 8},
        {"id": "left", "start_byte": 0, "end_byte": 16, "alignment_bytes": 16},
    ]
    space_payload = {
        "scope": "retained-logical-byte-partitions", "unit": "byte",
        "extent_bytes": 32, "partitions_digest": _digest(partitions),
    }
    space_obj = NamespaceObject.create("space-root", "SPACE", space_payload)
    space_ev = canonical_bytes({
        "schema_version": space_layout.EVIDENCE_VERSION,
        "objects": [space_obj.to_dict()],
        "inputs": {"partitions": partitions},
    })
    space_pol = space_layout.space_layout_policy(trust_roots=["layout-root"])
    space_req = space_layout.space_layout_request(
        subject_id=space_obj.object_id, object_digest=space_obj.digest,
        collection_digest=composition_digest([space_obj]), evidence_ref=_digest(json.loads(space_ev)),
        policy=space_pol,
    )
    space_cert = space_layout.build_space_layout_certificate(space_req, space_ev, policy=space_pol)

    ROUTE = (space_layout.SEMANTIC_VERSION, space_layout.COORDINATE, "SPACE")
    v_obj = NamespaceObject.create("verifier-run", "VERIFIER", {
        "checker_kind": "CURRENT_OBJECT_ROUTE", "semantic_version": ROUTE[0],
        "objective": ROUTE[1], "represented_kind": ROUTE[2],
    })
    constraints = [
        {"constraint_id": "events", "quantity": "traced_python_events", "maximum": 5000000},
        {"constraint_id": "report", "quantity": "replay_report_bytes", "maximum": 1000000},
    ]
    constraints = sorted(constraints, key=lambda row: row["constraint_id"])
    policy = verifier_run_constraints.verifier_run_constraints_policy(trust_roots=["run-root"])
    request = verifier_run_constraints.verifier_run_constraints_request(
        subject_id=v_obj.object_id,
        object_digest=v_obj.digest,
        collection_digest=composition_digest([v_obj]),
        child_semantic_version=ROUTE[0],
        child_objective=ROUTE[1],
        child_represented_kind=ROUTE[2],
        child_request_digest=_digest(space_req),
        child_policy_digest=_digest(space_pol),
        child_certificate_digest="sha256:" + hashlib.sha256(space_cert).hexdigest(),
        declarant="caller:test-selector",
        constraints=constraints,
        evidence_ref="sha256:" + "0" * 64,
        policy=policy,
    )
    evidence = canonical_bytes({
        "schema_version": verifier_run_constraints.EVIDENCE_VERSION,
        "verifier_object": v_obj.to_dict(),
        "child_request": space_req,
        "child_policy": space_pol,
        "child_certificate": base64.b64encode(space_cert).decode("ascii"),
        "declared_observations": [],
    })
    request["evidence_ref"] = "sha256:" + hashlib.sha256(evidence).hexdigest()
    return request, policy, evidence


GENERATORS = {
    "ACTOR:ACTOR-3.3": gen_actor_3_3,
    "AGENT:AGENT-3.1": gen_agent_3_1,
    "ARCH:ARCH-3.1": gen_arch_3_1,
    "BENCH:BENCH-3.6": gen_bench_3_6,
    "BOT:BOT-3.1": gen_bot_3_1,
    "COLLECTIVE:COLLECTIVE-3.1": gen_collective_3_1,
    "DATA:DATA-3.4": gen_data_3_4,
    "ENV:ENV-3.3": gen_env_3_3,
    "EVENT:EVENT-3.1": gen_event_3_1,
    "GRAPH:GRAPH-3.1": gen_graph_3_1,
    "HARDWARE:HARDWARE-3.1": gen_hardware_3_1,
    "HARNESS:HARNESS-3.1": gen_harness_3_1,
    "HUMAN:HUMAN-3.6": gen_human_3_6,
    "HYPER:HYPER-3.1": gen_hyper_3_1,
    "IDENTITY:IDENTITY-3.1": gen_identity_3_1,
    "MODEL:MODEL-3.1": gen_model_3_1,
    "MODEL:MODEL-3.2": gen_model_3_2,
    "MODEL:MODEL-3.3": gen_model_3_3,
    "MODEL:MODEL-3.4": gen_model_3_4,
    "MODEL:MODEL-3.5": gen_model_3_5,
    "MODEL:MODEL-3.7": gen_model_3_7,
    "OBJECT:OBJECT-3.1": gen_object_3_1,
    "OWNER:OWNER-3.1": gen_owner_3_1,
    "RECEIPT:RECEIPT-3.1": gen_receipt_3_1,
    "ROLE:ROLE-3.1": gen_role_3_1,
    "SIM:SIM-3.4": gen_sim_3_4,
    "SPACE:SPACE-3.1": gen_space_3_1,
    "TIME:TIME-3.1": gen_time_3_1,
    "TOKEN:TOKEN-3.1": gen_token_3_1,
    "TRAIN:TRAIN-3.2": gen_train_3_2,
    "VERIFIER:VERIFIER-3.1": gen_verifier_3_1,
}


# Reviewed source ledger. One row per Tier-3 coordinate:
# ACCEPT_REPIN: the freshly generated case is admitted; its policy pin is the
#   reviewed digest of the installed mechanism closure at review time.
# RETAIN_UNKNOWN: the prior embedded case is kept verbatim (digest-checked) and
#   stays refused under its stale pin; the coordinate is reported UNKNOWN.
# change_class names the reviewed closure inputs that differ from HEAD. Any change
# to a closure input changes the live digest and the builder refuses to emit
# until the row is re-reviewed; no pin is refreshed automatically.
SOURCE_REVIEW_LEDGER: dict[str, dict[str, Any]] = {
    "ACTOR:ACTOR-3.3": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION"],
        "prior_mechanism_digest": "sha256:d51b2627c8692e4580abb069f46ff1f7eb580fb3d9a1cdcaa85b8e77781ab66b",
        "reviewed_mechanism_digest": "sha256:87bae2d35924f55a7bd23b890d54a8142afff980020ba1f36710bc06ba28c6c9",
    },
    "AGENT:AGENT-3.1": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION"],
        "prior_mechanism_digest": "sha256:e1d39aeae588a59d299c5920ecf66f9a54440fc103edd1efa144c8fdf6027ddb",
        "reviewed_mechanism_digest": "sha256:8ba93b26764971da92c7330c1047fafa6d9dd802e78f0874c7a193ce2e2d4d7c",
    },
    "ARCH:ARCH-3.1": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION"],
        "prior_mechanism_digest": "sha256:975bbdb21d8361fa6557a93d912c233fd905d31dd3664d90e936d75139b559f6",
        "reviewed_mechanism_digest": "sha256:c341e353daa6a57a8754fc2f4ebdc16b60541c14384d5773cca366a8268ba0be",
    },
    "BENCH:BENCH-3.6": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION", "NESTED_PIN_PROPAGATION"],
        "prior_mechanism_digest": "sha256:13bed0162adfc5e8c49ce990bf3792ca920dbf3ae33df3fd7bbee61e6e133ecc",
        "reviewed_mechanism_digest": "sha256:9757aff18114c875376cad7d5168fb4f8f4c93fb496dce09c526221ff6f6cd6a",
    },
    "BOT:BOT-3.1": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION"],
        "prior_mechanism_digest": "sha256:13a5f5681359a95777051f20e0971f885a76750bc927dd3178748d461219062c",
        "reviewed_mechanism_digest": "sha256:ed0071790f215ac0d689625b071e997d065e0a0ef51696bcc3c997c01cadb261",
    },
    "COLLECTIVE:COLLECTIVE-3.1": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION"],
        "prior_mechanism_digest": "sha256:5bc3877ca3b02cb2cb5d7dae40242ce009b74dfccced88951f6c6db4d1f142cb",
        "reviewed_mechanism_digest": "sha256:5483658740afe78a2654113b4cbb4de9bdfddce7cfe436984d5a47888119d046",
    },
    "DATA:DATA-3.4": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION"],
        "prior_mechanism_digest": "sha256:89e857d4809ec52de013d0f75e53b02081a13a59aba2160e680e227ac0bd9676",
        "reviewed_mechanism_digest": "sha256:18f5fa579d19a9755ee198f5118e370606af6e334e31d98edd4b2d1c3819c69b",
    },
    "ENV:ENV-3.3": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION"],
        "prior_mechanism_digest": "sha256:32b5b1fb4b995048dab7628c43b648193333edb11134ddcef651791883d66082",
        "reviewed_mechanism_digest": "sha256:86f720939308bcbad001840606bf6af20d1af7b22a65d85e327fd1f97e3fe089",
    },
    "EVENT:EVENT-3.1": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION"],
        "prior_mechanism_digest": "sha256:cc085f980314a5341d780f11c916d7b0d021ade39cb7a2bd3675a9228a250413",
        "reviewed_mechanism_digest": "sha256:9d6e1bea763357916a1e7f819a8686f3b358db50aa634613ed73ed34b8e3dc16",
    },
    "GRAPH:GRAPH-3.1": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:CURRENT_GRAPH_STATICS.md", "DOC_ONLY:NAMESPACE_OBJECTS.md", "GRAPH_CEILING_RAISE", "NAMESPACE_LAYOUT_VALIDATION"],
        "prior_mechanism_digest": "sha256:794d899978cb2acfd548a42f8a7a32b9dde41383d8c9ce4d59870bbb09112c93",
        "reviewed_mechanism_digest": "sha256:d59dc2eb4d679bdc9e93cda83012a826218e47bbae9f3caef31201e60c873f9f",
    },
    "HARDWARE:HARDWARE-3.1": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION"],
        "prior_mechanism_digest": "sha256:3952680bb401c7e9fbd0284d37be33f14f77818b932a58afd048b5120d428b94",
        "reviewed_mechanism_digest": "sha256:76c99f4b322395e04ae30c79d267ca18dae1454f3ddab147a90d0a4387d35ba7",
    },
    "HARNESS:HARNESS-3.1": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION"],
        "prior_mechanism_digest": "sha256:fc1fa787b9730fbdab37e80c18b15b05a70758eaa2ca7850cd2a93f0c5fed15f",
        "reviewed_mechanism_digest": "sha256:cf7789a0a12fcb1e32724b8cba683eb7e590702d7b6e0727ca80d43f8d25206a",
    },
    "HUMAN:HUMAN-3.6": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION"],
        "prior_mechanism_digest": "sha256:d3cedf3058be877ebe8389b6c45f5aa3b06ea3c73701ce0bacbe6c576fc973b5",
        "reviewed_mechanism_digest": "sha256:508e8840089d6a363a981fb21af3a3a07805d01cf87d303821403cacb7387ae9",
    },
    "HYPER:HYPER-3.1": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["ADDITIVE_ROUTE_HELPER", "DOC_ONLY:DOMAIN_OBLIGATIONS.md", "DOC_ONLY:META_TIERS.md", "DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION", "NESTED_PIN_PROPAGATION"],
        "prior_mechanism_digest": "sha256:a6ee4eae012cd2052ac84df7e6b575713e091370fe91677f36bded96c1441017",
        "reviewed_mechanism_digest": "sha256:6d7778e9df458bc38f914de75c51cf80e0bed2a27e38a1d24f226842f6ec5592",
    },
    "IDENTITY:IDENTITY-3.1": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION"],
        "prior_mechanism_digest": "sha256:8b3747811207d2206aa726ca62560e1c63a6b43230f9858e2b442679c328b137",
        "reviewed_mechanism_digest": "sha256:f5c9544e1f7d1e1cc3b11adaaf9d3122da959fc7703e740d1ff8c1fbc52b9405",
    },
    "MODEL:MODEL-3.1": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION"],
        "prior_mechanism_digest": "sha256:757540b10358acf3e900f8f8b9db0cb3117777ff19b13b24d93fda3aa1cbb37d",
        "reviewed_mechanism_digest": "sha256:734c18acaf715d8f5667c7c0143f8a23119258d403f9cb510c41038b086ecfb0",
    },
    "MODEL:MODEL-3.2": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:DOMAIN_OBLIGATIONS.md", "DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION"],
        "prior_mechanism_digest": "sha256:9a2ae029a09a2c39eb2bae7c6b41cb4ffa8b6caaf359db1ba9c4c928eb038ac0",
        "reviewed_mechanism_digest": "sha256:23510fe777c5f32b5e0d3d7c4b28e75207c582823e7e97eaa6a5093407d2abef",
    },
    "MODEL:MODEL-3.3": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:DOMAIN_OBLIGATIONS.md", "DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION"],
        "prior_mechanism_digest": "sha256:b570ec150a02f72a3499ef6643012d7b16992b8bb5f6822c82facaa817796d78",
        "reviewed_mechanism_digest": "sha256:cb29ff58f4ea3b83fabc7ab55dcee270145fffd4b520b017f350361f7716cf08",
    },
    "MODEL:MODEL-3.4": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION", "NESTED_PIN_PROPAGATION"],
        "prior_mechanism_digest": "sha256:22fc975e67bad47baf581d9eaa1b12f06ee385bf1da34177f7fbaf0e15d53765",
        "reviewed_mechanism_digest": "sha256:9739bdbe0f4bad1fe7e6ff1e8c3761396412f16f42ea48d6d7fb3a7e2b4ed214",
    },
    "MODEL:MODEL-3.5": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION", "NESTED_PIN_PROPAGATION"],
        "prior_mechanism_digest": "sha256:0d4bc0a9e6f1c086c1070f74f8b73162ab0c765e44230e14ef68900b3b970d50",
        "reviewed_mechanism_digest": "sha256:a37c4c0083e3dee72a2ba1dd10b5b972c9b2cdcb1597c69570a44257de00d467",
    },
    "MODEL:MODEL-3.7": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION", "NESTED_PIN_PROPAGATION"],
        "prior_mechanism_digest": "sha256:30200b3f435529e86912c0592d3050d77de1bde38f0e535ba5a3230661442c17",
        "reviewed_mechanism_digest": "sha256:58433f7f93c1a8493a188ce1fbc269b8a4ec809fca44a04fb837ca9d328144a5",
    },
    "OBJECT:OBJECT-3.1": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION"],
        "prior_mechanism_digest": "sha256:a9ec14fd120606c86e751733ccd6f3d88fe882c5ca4201407d3f4c5e4124cd93",
        "reviewed_mechanism_digest": "sha256:eb93806333b88dfb4771f8d4baabbdcc3038149e51e0b74c4bf51f06b91a4e61",
    },
    "OWNER:OWNER-3.1": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION"],
        "prior_mechanism_digest": "sha256:fa1ac4f7922444d39bd1d5af055085d87af69a9fb2c0207cc7c18194efc26544",
        "reviewed_mechanism_digest": "sha256:afcdea5cabd1c02ae7c62f21d96a8b6d68241ccf959222027e2a58d23664afe5",
    },
    "RECEIPT:RECEIPT-3.1": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:NAMESPACE_OBJECTS.md", "DOC_ONLY:VSTD-1.md", "NAMESPACE_LAYOUT_VALIDATION"],
        "prior_mechanism_digest": "sha256:279b9c75b4a92071c53a8e3bfadb195b14adc3ef05e5097304dcb43075a83ef2",
        "reviewed_mechanism_digest": "sha256:98f2a3ac514f6159d9a8b9ff50f8465e8e0a94b8067a79d9659db941936e0aaa",
    },
    "ROLE:ROLE-3.1": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION"],
        "prior_mechanism_digest": "sha256:cff1aa00e8398aeb832d184212bae6938621043af7e9bd1d2b0a620a1e7e6cb6",
        "reviewed_mechanism_digest": "sha256:15fb2d67038fca43c30775c113d7c0897bd8cf6ba480c39fb8dee528326e15d2",
    },
    "SIM:SIM-3.4": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION"],
        "prior_mechanism_digest": "sha256:bb9d28c4d7674c702d903e5c0e6d354e459d6b68a2e92743b2d51c8678fd955a",
        "reviewed_mechanism_digest": "sha256:b1488869b5ad250cbd43f4731fca7eb37fd3b692c895f8e139553cf8b28a9e9a",
    },
    "SPACE:SPACE-3.1": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION"],
        "prior_mechanism_digest": "sha256:32fdf83a6e48e9f377ad3a8c6eaabb6617a135e99ecb19c1b0f429f9360d28bd",
        "reviewed_mechanism_digest": "sha256:6bf029c5a49bc037b2627cc641ad98c917b5cc5280570923ad2e89080961781f",
    },
    "TIME:TIME-3.1": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION", "NESTED_PIN_PROPAGATION"],
        "prior_mechanism_digest": "sha256:da015f3357f5a465bdf822f9facc5aa2b969d8dbe9633192aa6c616af82928a6",
        "reviewed_mechanism_digest": "sha256:a42ec31070d0af9573c6a0afa83649b9c38281be35727d58fd19be955ef55504",
    },
    "TOKEN:TOKEN-3.1": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:DOMAIN_OBLIGATIONS.md", "DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION"],
        "prior_mechanism_digest": "sha256:32d868105fde9bf0065a35b60bdb29b43ee0f0d07bcf64be5f32172880202524",
        "reviewed_mechanism_digest": "sha256:2782d29a47a0c84015a7f7b08d82654e79d69761b9bcc526950ade7b6c4d5a2c",
    },
    "TRAIN:TRAIN-3.2": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["DOC_ONLY:DOMAIN_OBLIGATIONS.md", "DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION"],
        "prior_mechanism_digest": "sha256:aec91ead3a85b21c748015daebebb99f50edbd6da9bd91b73023dae76d347a9a",
        "reviewed_mechanism_digest": "sha256:338b50ee71e83cbc742ee8ddda038370f78e0ad4a4fe6d3689b4197168442e1e",
    },
    "VERIFIER:VERIFIER-3.1": {
        "disposition": "ACCEPT_REPIN",
        "change_class": ["ADDITIVE_ROUTE_HELPER", "DOC_ONLY:NAMESPACE_OBJECTS.md", "NAMESPACE_LAYOUT_VALIDATION", "NESTED_PIN_PROPAGATION"],
        "prior_mechanism_digest": "sha256:73d1f0ee05c7ae70283be80cf07efcfda9101b47eefd8f50e1af1013c4d0cde2",
        "reviewed_mechanism_digest": "sha256:dde34667d284aa44cddfab322bf5054106dda94e162a24e0f7ab7dd979085f72",
    },
}

RUNTIME_MODULE = (
    Path(__file__).resolve().parents[1]
    / "src" / "verifier" / "runtime" / "self_polish_native_tier3_cases.py"
)
GENERATED_BEGIN = "# BEGIN GENERATED: scripts/build_self_polish_native_tier3_cases.py --write"
GENERATED_END = "# END GENERATED"
CASE_KEYS = (
    "builder_adapter", "checking_mechanism", "evidence_base64",
    "negative_adapter", "policy", "request", "unknown_adapter",
)
DISPOSITIONS = ("ACCEPT_REPIN", "RETAIN_UNKNOWN")


def _embedded_cases() -> dict[str, Any]:
    """Decode the currently installed payload to retain RETAIN_UNKNOWN cases verbatim."""
    from verifier.runtime import self_polish_native_tier3_cases as embedded

    raw = zlib.decompress(base64.b85decode(embedded._PAYLOAD_B85))
    return json.loads(raw.decode("utf-8"))


def build_source_review() -> dict[str, dict[str, Any]]:
    return {identifier: dict(row) for identifier, row in sorted(SOURCE_REVIEW_LEDGER.items())}


def _inventory_memberships() -> list[dict[str, Any]]:
    inventory = core_tier_progression.installed_core_route_inventory()
    memberships = sorted(
        [
            {
                "obligation_id": (
                    f"{cell['object_kind']}:{route['coordinate']}"
                ),
                "object_kind": cell["object_kind"],
                **route,
            }
            for cell in inventory["family_cells"]
            if cell["tier"] == 3
            for route in cell["registered_route_memberships"]
        ],
        key=lambda row: row["obligation_id"],
    )
    if len(memberships) != 31 or set(GENERATORS) != {
            row["obligation_id"] for row in memberships} or set(
            SOURCE_REVIEW_LEDGER) != set(GENERATORS):
        raise RuntimeError("Tier-3 route denominator differs")
    return memberships


def build_payload() -> tuple[bytes, bytes]:
    memberships = _inventory_memberships()
    embedded = (
        _embedded_cases()
        if any(row["disposition"] == "RETAIN_UNKNOWN"
               for row in SOURCE_REVIEW_LEDGER.values())
        else {}
    )
    payload = {}
    for membership in memberships:
        identifier = membership["obligation_id"]
        review = SOURCE_REVIEW_LEDGER[identifier]
        if review["disposition"] not in DISPOSITIONS:
            raise RuntimeError("Tier-3 source review disposition is unknown")
        request, policy, evidence = GENERATORS[identifier]()
        if policy["mechanism_digest"] != review["reviewed_mechanism_digest"]:
            raise RuntimeError(f"Tier-3 source review stale: {identifier}")
        if review["disposition"] == "RETAIN_UNKNOWN":
            if policy["mechanism_digest"] == review["prior_mechanism_digest"]:
                raise RuntimeError(f"Tier-3 retained row is no longer stale: {identifier}")
            retained = {key: embedded[identifier][key] for key in CASE_KEYS}
            if (core_obligation_union.value_digest(retained)
                    != review["retained_case_digest"]
                    or retained["policy"]["mechanism_digest"]
                    != review["prior_mechanism_digest"]):
                raise RuntimeError(f"Tier-3 retained case differs: {identifier}")
            payload[identifier] = retained
            continue
        payload[identifier] = _admitted_case(membership, request, policy, evidence)
    raw = core_obligation_union.canonical_bytes(payload)
    return raw, base64.b85encode(zlib.compress(raw, 9))


def _admitted_case(membership: dict[str, Any], request: dict[str, Any],
                   policy: dict[str, Any], evidence: bytes) -> dict[str, Any]:
    if (
        request["coordinate"] != membership["coordinate"]
        or request["semantic_version"] != membership["semantic_version"]
        or request["proposition_digest"]
            != membership["proposition_digest"]
        or request["policy_digest"]
            != core_obligation_union.value_digest(policy)
    ):
        raise RuntimeError("Tier-3 generated route binding differs")
    return {
        "builder_adapter": (
            "WINDOWS_MODEL_HARDWARE_OBSERVATION"
            if membership["obligation_id"] == "MODEL:MODEL-3.2"
            else "BOUNDED_EVIDENCE_BYTES"
        ),
        "checking_mechanism": membership["checking_mechanism"],
        "evidence_base64": base64.b64encode(evidence).decode("ascii"),
        "negative_adapter": "MALFORMED_EVIDENCE_REBIND",
        "policy": policy,
        "request": request,
        "unknown_adapter": "ABSENT_EVIDENCE",
    }


def build_prepared_current_payload() -> tuple[bytes, bytes]:
    """Fresh live-mechanism triads for every RETAIN_UNKNOWN row, for prepared replay only.

    The installed payload keeps the reviewed stale pin. installed_case_inputs() and
    installed_source_review() never read this overlay, so a retained coordinate stays
    UNKNOWN there. The overlay admits a row only when its live digest equals the
    reviewed digest and differs from the prior pin.
    """
    memberships = {row["obligation_id"]: row for row in _inventory_memberships()}
    payload = {}
    for identifier, review in sorted(SOURCE_REVIEW_LEDGER.items()):
        if review["disposition"] != "RETAIN_UNKNOWN":
            continue
        request, policy, evidence = GENERATORS[identifier]()
        if (policy["mechanism_digest"] != review["reviewed_mechanism_digest"]
                or policy["mechanism_digest"] == review["prior_mechanism_digest"]):
            raise RuntimeError(f"Tier-3 prepared current source differs: {identifier}")
        payload[identifier] = _admitted_case(
            memberships[identifier], request, policy, evidence,
        )
    raw = core_obligation_union.canonical_bytes(payload)
    return raw, base64.b85encode(zlib.compress(raw, 9))


def _encoded_lines(name: str, encoded: bytes) -> list[str]:
    lines = [f"{name} = ("]
    for start in range(0, len(encoded), 96):
        lines.append("    b'" + encoded[start:start + 96].decode("ascii") + "'")
    return [*lines, ")"]


def render_generated_block() -> str:
    raw, encoded = build_payload()
    review = build_source_review()
    prepared_raw, prepared_encoded = build_prepared_current_payload()
    lines = [
        GENERATED_BEGIN,
        f'CASE_REGISTRY_DIGEST = "{core_obligation_union.bytes_digest(raw)}"',
        *_encoded_lines("_PAYLOAD_B85", encoded),
        f'SOURCE_REVIEW_DIGEST = "{core_obligation_union.value_digest(review)}"',
        "SOURCE_REVIEW = " + json.dumps(review, indent=4, sort_keys=True),
        f'PREPARED_CURRENT_CASE_REGISTRY_DIGEST = "{core_obligation_union.bytes_digest(prepared_raw)}"',
        *_encoded_lines("_PREPARED_CURRENT_PAYLOAD_B85", prepared_encoded),
        GENERATED_END,
    ]
    return "\n".join(lines) + "\n"


def _generated_span(text: str) -> tuple[int, int]:
    start = text.index(GENERATED_BEGIN)
    end = text.index(GENERATED_END) + len(GENERATED_END) + 1
    return start, end


def write_runtime_module() -> None:
    text = RUNTIME_MODULE.read_text(encoding="utf-8")
    start, end = _generated_span(text)
    RUNTIME_MODULE.write_text(
        text[:start] + render_generated_block() + text[end:],
        encoding="utf-8", newline="\n",
    )


def runtime_module_is_current() -> bool:
    text = RUNTIME_MODULE.read_text(encoding="utf-8")
    start, end = _generated_span(text)
    return text[start:end] == render_generated_block()


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if set(args) - {"--write", "--check"}:
        raise SystemExit("usage: build_self_polish_native_tier3_cases.py [--write | --check]")
    if "--write" in args:
        write_runtime_module()
    if "--check" in args and not runtime_module_is_current():
        print("NATIVE_TIER3_GENERATED_BLOCK_STALE", file=sys.stderr)
        return 1
    raw, encoded = build_payload()
    review = build_source_review()
    prepared_raw, _ = build_prepared_current_payload()
    print(json.dumps({
        "entry_count": 31,
        "dispositions": {
            name: sum(1 for row in review.values() if row["disposition"] == name)
            for name in DISPOSITIONS
        },
        "raw_bytes": len(raw),
        "encoded_bytes": len(encoded),
        "registry_digest": core_obligation_union.bytes_digest(raw),
        "source_review_digest": core_obligation_union.value_digest(review),
        "prepared_current_entries": sorted(
            identifier for identifier, row in review.items()
            if row["disposition"] == "RETAIN_UNKNOWN"
        ),
        "prepared_current_registry_digest": core_obligation_union.bytes_digest(prepared_raw),
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
