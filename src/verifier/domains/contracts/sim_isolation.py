"""Finite generative simulation specification (SIM) isolation over virtual HARDWARE.

This checker replays one retained, total, finite transition relation under a
checker-selected binding. It proves only closure inside that declared model. A
model can omit a real capability or physical channel; no result here attests host
containment, ownership, consent, governance, or numbered-profile conformance.
JavaScript Object Notation (JSON) inputs and Secure Hash Algorithm 256-bit
(SHA-256) commitments have no physical unit; budgets count items and operations.
"""
from __future__ import annotations

from collections import deque
import hashlib
import json
import re
from typing import Any

from verifier.core.certificate import canonical_bytes

from ..common import Budget, Refuted, Unavailable, digest, inspect_structure, integer, obj, same, seq, text


_SCHEMA = "verifier-sim-isolation-evidence-1"
_RESULT_SCHEMA = "verifier-sim-isolation-assessment-1"
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HARDWARE_KINDS = frozenset({"compute", "memory", "storage", "sensor"})
_INTERNAL_EFFECTS = frozenset({"internal_write", "receipt_record", "data_record"})
_BOUNDARY_EFFECTS = frozenset({"outside_write", "external_actuation", "external_export", "capability_acquire"})
_MAX_EVIDENCE_BYTES = 1024 * 1024
_MAX_ASSESSMENT_BYTES = 2 * 1024 * 1024
_MAX_MISSING_DIAGNOSTIC_CHARACTERS = 256 * 1024


def _check_text_byte_lower_bound(value: Any, budget: Budget, limit: int = _MAX_EVIDENCE_BYTES) -> None:
    """Reject definitely oversized JSON before allocating canonical serialized bytes."""
    pending = [value]
    characters = 0
    while pending:
        budget.tick()
        item = pending.pop()
        if isinstance(item, dict):
            for key, child in item.items():
                if isinstance(key, str):
                    characters += len(key)
                pending.append(child)
        elif isinstance(item, list):
            pending.extend(item)
        elif isinstance(item, str):
            characters += len(item)
        if characters > limit:
            raise Unavailable("finite isolation serialized byte bound exhausted")


def _binding(value: dict) -> dict:
    value = dict(obj(value))
    obj(value, {"sim_id", "evidence_digest", "max_operations", "max_items"})
    if len(text(value["sim_id"])) > 256:
        raise Refuted("simulation identity bound exceeded")
    if not isinstance(value["evidence_digest"], str) or not _HASH.fullmatch(value["evidence_digest"]):
        raise Refuted("expected evidence digest must be canonical sha256")
    integer(value["max_operations"], 1, 10_000_000)
    integer(value["max_items"], 1, 4096)
    return value


def _record(status: str, reason: str, expected_binding: dict,
            observed_digest: str | None, *, reachable_states: int = 0,
            unreachable_states: int = 0, checked_pairs: int = 0,
            checked_outcomes: int = 0, missing_pairs: list[dict[str, str]] | None = None,
            virtual_hardware: list[dict[str, str]] | None = None) -> dict:
    result = {
        "schema_version": _RESULT_SCHEMA,
        "status": status,
        "reason": reason,
        "scope": "finite_declared_transition_model",
        "sim_id": expected_binding["sim_id"],
        "binding_digest": digest(expected_binding),
        "evidence_digest": expected_binding["evidence_digest"],
        "observed_evidence_digest": observed_digest,
        "reachable_states": reachable_states,
        "unreachable_states": unreachable_states,
        "checked_pairs": checked_pairs,
        "checked_outcomes": checked_outcomes,
        "missing_pairs": [] if missing_pairs is None else missing_pairs,
        "virtual_hardware": virtual_hardware if status == "PASS" and virtual_hardware is not None else [],
        "physical_host_containment": "NOT_ESTABLISHED",
        "authority": "NOT_ESTABLISHED",
        "object_profile_conformance": "NOT_ESTABLISHED",
    }
    result["assessment_digest"] = digest(result)
    return result


def _model(evidence: dict, budget: Budget) -> tuple[dict[str, dict], list[str], dict, str, dict[str, str]]:
    obj(evidence, {"schema_version", "sim_id", "initial_state", "virtual_hardware",
                   "states", "actions", "transitions"})
    if evidence["schema_version"] != _SCHEMA:
        raise Unavailable("unsupported finite simulation isolation evidence version")
    text(evidence["sim_id"])
    initial = text(evidence["initial_state"])

    hardware: dict[str, str] = {}
    for item in seq(evidence["virtual_hardware"], budget):
        row = obj(item, {"id", "kind"})
        identifier = text(row["id"])
        if identifier in hardware:
            raise Refuted("duplicate virtual HARDWARE identifier")
        if row["kind"] not in _HARDWARE_KINDS:
            raise Unavailable("unsupported virtual HARDWARE kind")
        hardware[identifier] = row["kind"]

    states: dict[str, dict] = {}
    for item in seq(evidence["states"], budget):
        row = obj(item, {"id", "partition", "capabilities"})
        identifier = text(row["id"])
        if identifier in states:
            raise Refuted("duplicate state identifier")
        if row["partition"] not in ("inside", "outside"):
            raise Refuted("state partition must be inside or outside")
        capabilities = [text(c) for c in seq(row["capabilities"], budget, nonempty=False)]
        if len(set(capabilities)) != len(capabilities):
            raise Refuted("duplicate state capability")
        if row["partition"] == "inside" and not set(capabilities) <= hardware.keys():
            raise Refuted("inside state has capability outside declared virtual HARDWARE")
        states[identifier] = row
    if initial not in states:
        raise Refuted("initial state is not in the finite state set")
    if states[initial]["partition"] != "inside":
        raise Refuted("initial state is outside the simulation partition")

    actions = [text(a) for a in seq(evidence["actions"], budget)]
    if len(set(actions)) != len(actions):
        raise Refuted("duplicate action identifier")

    transitions: dict[tuple[str, str], list] = {}
    for item in seq(evidence["transitions"], budget, nonempty=False):
        row = obj(item, {"source", "action", "outcomes"})
        source, action = text(row["source"]), text(row["action"])
        if source not in states:
            raise Refuted("transition has dangling source state")
        if action not in actions:
            raise Refuted("transition names action outside declared alphabet")
        key = (source, action)
        if key in transitions:
            raise Refuted("duplicate state/action transition row")
        outcomes = seq(row["outcomes"], budget, nonempty=False)
        for outcome in outcomes:
            step = obj(outcome, {"target", "effects"})
            target = text(step["target"])
            if target not in states:
                raise Refuted("transition has dangling target state")
            for effect in seq(step["effects"], budget, nonempty=False):
                effect = obj(effect, {"kind", "target"})
                text(effect["kind"])
                text(effect["target"])
        transitions[key] = outcomes
    return states, actions, transitions, initial, hardware


def assess_sim_isolation(evidence: dict, *, expected_binding: dict) -> dict:
    """Check every reachable outcome of a bounded total finite transition model.

    ``expected_binding`` is selected outside the submitted evidence. Missing
    reachable state/action coverage is UNKNOWN; a represented boundary crossing
    is FAIL. PASS is model-relative and grants no external resource authority.
    """
    selected = _binding(expected_binding)
    budget = Budget(selected["max_operations"], selected["max_items"])
    observed_digest: str | None = None
    try:
        inspect_structure(evidence, budget)
        _check_text_byte_lower_bound(evidence, budget)
        captured = canonical_bytes(evidence)
        if len(captured) > _MAX_EVIDENCE_BYTES:
            raise Unavailable("finite isolation evidence byte bound exhausted")
        observed_digest = "sha256:" + hashlib.sha256(captured).hexdigest()
        if observed_digest != selected["evidence_digest"]:
            raise Refuted("retained evidence differs from checker-selected binding")
        snapshot = json.loads(captured)
        states, actions, transitions, initial, hardware = _model(snapshot, budget)
        if snapshot["sim_id"] != selected["sim_id"]:
            raise Refuted("simulation identity differs from checker-selected binding")

        seen: set[str] = set()
        pending = deque([initial])
        scheduled = {initial}
        missing: list[dict[str, str]] = []
        missing_characters = 0
        checked_pairs = 0
        checked_outcomes = 0
        while pending:
            budget.tick()
            state_id = pending.popleft()
            if state_id in seen:
                continue  # A cycle is valid; every reachable state is checked once.
            seen.add(state_id)
            state = states[state_id]
            if state["partition"] != "inside":
                raise Refuted("reachable state crossed outside simulation partition")
            capabilities = set(state["capabilities"])
            for action in actions:
                budget.tick()
                outcomes = transitions.get((state_id, action))
                if not outcomes:
                    missing_characters += len(state_id) + len(action)
                    if len(missing) >= budget.max_items or missing_characters > _MAX_MISSING_DIAGNOSTIC_CHARACTERS:
                        raise Unavailable("missing transition list bound exhausted")
                    missing.append({"state": state_id, "action": action})
                    continue
                checked_pairs += 1
                for outcome in outcomes:
                    budget.tick()
                    checked_outcomes += 1
                    target_id = outcome["target"]
                    target = states[target_id]
                    if target["partition"] != "inside":
                        raise Refuted("transition reaches outside simulation partition")
                    next_capabilities = set(target["capabilities"])
                    if not next_capabilities <= capabilities:
                        raise Refuted("transition makes a new capability reachable")
                    for effect in outcome["effects"]:
                        budget.tick()
                        kind, resource = effect["kind"], effect["target"]
                        if kind in _BOUNDARY_EFFECTS:
                            label = "capability acquisition" if kind == "capability_acquire" else kind.replace("_", " ")
                            raise Refuted(f"represented {label} crosses isolation boundary")
                        if kind not in _INTERNAL_EFFECTS:
                            raise Unavailable("unsupported transition effect semantics")
                        if resource not in capabilities:
                            raise Refuted("effect target capability is not held inside the simulation")
                        if kind in ("receipt_record", "data_record") and hardware[resource] != "storage":
                            raise Refuted("receipt and data records require held virtual storage")
                    if target_id not in scheduled:
                        scheduled.add(target_id)
                        pending.append(target_id)
        if missing:
            return _record("UNKNOWN", "reachable state/action transition coverage is incomplete",
                           selected, observed_digest, reachable_states=len(seen),
                           unreachable_states=len(states) - len(seen), checked_pairs=checked_pairs,
                           checked_outcomes=checked_outcomes, missing_pairs=missing)
        return _record("PASS", "all reachable transitions remain inside the declared finite model",
                       selected, observed_digest, reachable_states=len(seen),
                       unreachable_states=len(states) - len(seen), checked_pairs=checked_pairs,
                       checked_outcomes=checked_outcomes,
                       virtual_hardware=[{"id": identifier, "kind": hardware[identifier]}
                                         for identifier in sorted(hardware)])
    except Refuted as exc:
        return _record("FAIL", str(exc), selected, observed_digest)
    except Unavailable as exc:
        return _record("UNKNOWN", str(exc), selected, observed_digest)
    except (TypeError, ValueError, KeyError, OverflowError, RecursionError) as exc:
        return _record("FAIL", f"malformed finite isolation evidence: {exc}", selected, observed_digest)


def recheck_sim_isolation(assessment: dict, evidence: dict, *, expected_binding: dict) -> dict:
    """Recompute the complete result against independently selected input bytes."""
    reproduced = assess_sim_isolation(evidence, expected_binding=expected_binding)
    try:
        if not isinstance(assessment, dict) or set(assessment) != set(reproduced):
            raise Refuted("malformed retained assessment")
        _check_text_byte_lower_bound(assessment, Budget(100_000, 4096), _MAX_ASSESSMENT_BYTES)
        same(assessment, reproduced, "finite isolation assessment does not replay")
    except Refuted:
        raise
    except (Unavailable, TypeError, ValueError, OverflowError, RecursionError) as exc:
        raise Refuted("malformed retained assessment") from exc
    return reproduced
