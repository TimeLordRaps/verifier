"""Bounded observational findings for successive Verifier Standard (VSTD) attempts.

Terminology: command-line interface (CLI); identifier (ID);
JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Input digests identify carried report bytes. This
projection neither replays checks nor authenticates evidence or run chronology.
It executes no source, callbacks, fixes or downstream stages. A missing finding
is fixed only as a carried observation when the same pinned check scope reports
an explicit executed PASS; omission, cancellation and deselection never clear it.
Stable IDs describe logical checks, not proof of semantic equivalence. Every
occurrence retains its input digest and JSON pointer, including conflicts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Sequence

from verifier.core.certificate import canonical_bytes
from verifier.core.receipt import strict_json_loads

SCHEMA = "verifier-polish-findings-1"
MAX_BYTES = 8 * 1024 * 1024
MAX_TOTAL_BYTES = 32 * 1024 * 1024
MAX_HISTORY = 16
MAX_RELATED = 16
MAX_NODES = 100000
MAX_DEPTH = 32
MAX_OUTPUT_BYTES = 32 * 1024 * 1024
SUPPORTED = frozenset({
    "verifier-polish-workflow-report-1", "verifier-polish-preparation-1",
    "verifier-polish-assessment-1", "verifier-polish-assessment-2",
    "verifier-polish-requirements-assessment-1", "verifier-quality-report-1",
    "verifier-prdel-report-1", "verifier-prdel-compilation-1", "verifier-prdel-cli-1",
    "verifier-prdel-compilation-report-1",
    "verifier-release-source-binding-assessment-1",
    "verifier-gates-clearance-1", "verifier-gates-clearance-2", "verifier-gates-clearance-3",
})
BOUNDARY = ("Carried bounded diagnostics only; no check replay, evidence authentication, "
            "complete bug discovery, polished-artifact issuance or promotion. "
            "Fixed and regressed describe comparable report observations only.")
_NONPASS = {"FAIL", "UNKNOWN", "NOT_ESTABLISHED", "NOT_RUN", "UNRUN", "REJECTED", "CONFLICTED"}
_LISTS = {"findings", "residuals", "stages", "gates", "objectives", "predicate_results",
          "missing_tiers", "open_required_slots", "unregistered_objectives",
          "mechanism_binding_gaps", "remaining_gates", "exclusions", "changes"}
_REPORTS = {"quality", "verification", "compilation", "native_assessment", "coverage",
            "polish_report", "dependency_assessment", "base", "unit", "integration",
            "regression", "preventative"}
_LOCUS = ("object_id", "object_kind", "coordinate", "semantic_version", "path", "symbol",
          "obligation_id", "predicate", "mechanism_id", "proposition_digest", "policy_digest",
          "tier", "gate_id", "rule", "file_index", "stage")
_PINS = ("policy_sha256", "policy_digest", "profile_digest", "quality_profile_sha256",
         "requirements_sha256", "requirements_digest", "inventory_digest", "registry_digest",
         "mechanism_digest", "implementation_digest", "implementation", "quality_environment_sha256",
         "definition_sha256", "definitions_digest", "definition_digest", "git_base")
_REQUIREMENT_PINS = {"policy_sha256", "policy_digest", "profile_digest", "quality_profile_sha256",
                     "requirements_sha256", "requirements_digest", "inventory_digest"}
_WORKFLOW_MECHANISMS = frozenset({"polish_workflow.py", "explanation_projection.py", "prdel_rules.py",
    "prdel.py", "prdel_graph.py", "prdel_coverage.py", "quality_checks.py", "gate_pipeline.py", "gate.py"})
_EMITTERS = {
    "verifier-polish-workflow-report-1": "runtime/polish_workflow.py:prepare_workflow",
    "verifier-polish-preparation-1": "runtime/polish_prepare.py:prepare_artifact",
    "verifier-polish-assessment-1": "runtime/polish.py:assess_polish",
    "verifier-polish-assessment-2": "runtime/polish_capacity.py:assess",
    "verifier-polish-requirements-assessment-1": "runtime/polish_requirements.py:assess_polish_inventory",
    "verifier-quality-report-1": "runtime/quality_checks.py:run_quality_profile",
    "verifier-prdel-report-1": "runtime/prdel.py:validate_prdel",
    "verifier-prdel-compilation-1": "runtime/prdel_rules.py:compile_prdel",
    "verifier-prdel-compilation-report-1": "runtime/prdel_rules.py:validate_compilation",
    "verifier-prdel-cli-1": "runtime/gate.py:handle_gate_command",
    "verifier-release-source-binding-assessment-1": "runtime/release_source_binding.py:assess_release_source_binding",
    **{"verifier-gates-clearance-" + str(n): "runtime/gates.py:run_gates" for n in (1, 2, 3)},
}


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _hash(value: Any) -> bool:
    return type(value) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", value) is not None


def _binding_validation(value: dict[str, Any]) -> dict[str, Any]:
    """Validate carried workflow bindings structurally, without authenticating them.

    Other report contracts remain diagnostic inputs; their comparison bindings
    are not established by this version. Candidate byte changes are permitted.
    """
    result = {"status": "NOT_ESTABLISHED", "reason": "COMPARISON_BINDING_VALIDATOR_UNAVAILABLE"}
    if value["schema_version"] != "verifier-polish-workflow-report-1":
        return result
    result["reason"] = "WORKFLOW_SOURCE_OR_EVALUATOR_BINDING_INCOMPLETE"
    binding = value.get("binding")
    if type(binding) is not dict or not _hash(binding.get("policy_sha256")):
        return result
    source = binding.get("source")
    implementation = binding.get("implementation")
    if type(source) is not dict or type(implementation) is not dict:
        return result
    rows = source.get("files")
    if type(rows) is not list or not rows or any(type(row) is not dict for row in rows):
        return result
    paths = [row.get("path") for row in rows]
    if (not all(type(path) is str and path.strip() for path in paths)
            or len(set(paths)) != len(paths) or paths != sorted(paths)
            or any(not _hash(row.get("sha256")) or type(row.get("size_bytes")) is not int
                   or row["size_bytes"] < 0 for row in rows)
            or source.get("sha256") != _digest(canonical_bytes(rows))):
        return result
    mechanisms = implementation.get("mechanisms")
    if (type(mechanisms) is not dict or set(mechanisms) != _WORKFLOW_MECHANISMS
            or not all(_hash(pin) for pin in mechanisms.values())
            or not _hash(implementation.get("interpreter_sha256"))
            or not all(type(implementation.get(key)) is str and implementation[key].strip()
                       for key in ("python_version", "platform"))
            or value.get("binding_digest") != _digest(canonical_bytes(binding))):
        return result
    return {"status": "VALID_CARRIED_BINDING", "reason": "STRUCTURAL_WORKFLOW_BINDING_ONLY",
            "source": source, "evaluator": implementation, "authentication": "NOT_ESTABLISHED"}


def _associated(current: dict[str, Any], related: dict[str, Any]) -> bool:
    """Require exact carried candidate association; unrelated observations do not fulfil requirements."""
    if _binding_validation(current)["status"] != "VALID_CARRIED_BINDING":
        return False
    original = current["binding"]["source"]["files"]
    if related["schema_version"] == "verifier-polish-workflow-report-1":
        return (_binding_validation(related)["status"] == "VALID_CARRIED_BINDING"
                and related["binding"]["source"]["files"] == original and _scope(current) == _scope(related))
    if related["schema_version"] == "verifier-quality-report-1":
        rows = related.get("sources")
        if type(rows) is not list or not rows or any(type(row) is not dict for row in rows):
            return False
        normalized = [{"path": row.get("path"), "size_bytes": row.get("size_bytes"), "sha256": row.get("digest")} for row in rows]
        profile = current["binding"].get("quality_profile_sha256")
        return (normalized == original and _hash(profile) and related.get("profile_digest") == profile
                and related.get("source_digest") == _digest(canonical_bytes(rows)))
    return False


def _embedded_comparison_bindings(value: dict[str, Any]) -> bool:
    """Unsupported or unbound embedded checks cannot clear a prior observation."""
    pending = [value]
    while pending:
        node = pending.pop()
        for key, child in node.items():
            if key not in _REPORTS or type(child) is not dict:
                continue
            if any(child.get(name) for name in ("stages", "gates", "objectives", "predicate_results")):
                if (child.get("schema_version") not in SUPPORTED
                        or _binding_validation(child)["status"] != "VALID_CARRIED_BINDING"
                        or not _associated(value, child)):
                    return False
            pending.append(child)
    return True


def _decode(raw: bytes) -> dict[str, Any]:
    if type(raw) is not bytes or len(raw) > MAX_BYTES:
        raise ValueError("bounded immutable report bytes required")
    value = strict_json_loads(raw.decode("utf-8"))
    if type(value) is not dict or value.get("schema_version") not in SUPPORTED:
        raise ValueError("unsupported report contract")
    pending = [(value, 0)]
    nodes = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if nodes > MAX_NODES or depth > MAX_DEPTH:
            raise ValueError("report structure bound exceeded")
        if isinstance(item, (dict, list)):
            pending.extend((child, depth + 1) for child in (item.values() if isinstance(item, dict) else item))
    for key in ("report_digest", "assessment_digest"):
        if key in value and value[key] != _digest(canonical_bytes({k: v for k, v in value.items() if k != key})):
            raise ValueError("carried report digest differs")
    return value


def _scope(value: dict[str, Any]) -> dict[str, Any]:
    binding = value.get("binding") if type(value.get("binding")) is dict else {}
    pins = {key: binding.get(key, value.get(key)) for key in _PINS
            if binding.get(key, value.get(key)) is not None}
    paths = set()
    for source in (binding.get("source"), value.get("sources"), value.get("artifact")):
        if type(source) is dict:
            source = source.get("files", [])
        if type(source) is list:
            paths.update(row["path"] for row in source if type(row) is dict and type(row.get("path")) is str)
    stage_rows = value.get("stages", value.get("gates", []))
    if type(stage_rows) is not list:
        stage_rows = [None]
    selected = sorted(((row.get("id", row.get("gate_id")), row.get("required"),
                        row.get("selected", row.get("execution_status") != "NOT_SELECTED"))
                       for row in stage_rows if type(row) is dict), key=repr)
    stage_ids = [row[0] for row in selected]
    valid_ids = len(selected) == len(stage_rows) and all(type(key) is str and key.strip() for key in stage_ids) \
        and len(set(stage_ids)) == len(stage_ids)
    subjects = sorted({(row.get("object_id"), row.get("object_kind"), row.get("coordinate"), row.get("semantic_version"))
                       for row in value.get("objectives", []) if type(row) is dict}, key=repr)
    valid_subjects = all(all(type(part) is str and part.strip() for part in row) for row in subjects)
    nested = {key: _scope({"schema_version": value["schema_version"], **child})
              for key, child in value.items() if key in _REPORTS and type(child) is dict}
    return {"schema_version": value["schema_version"], "pins": pins,
            "selected_checks": selected, "source_paths": sorted(paths),
            "root_id": value.get("root_id"), "subjects": subjects, "nested_scopes": nested,
            "unambiguous_identities": valid_ids and valid_subjects
                and all(row["unambiguous_identities"] for row in nested.values())}


def _next(code: str, stage: str | None) -> str:
    if "NOT_RUN" in code or "UNRUN" in code:
        return "Clear the recorded prerequisites, then execute this exact selected check and retain its outcome."
    if "CONTRAD" in code or "CONFLICT" in code:
        return "Compare the anchored authoritative claims and resolve the exact inconsistency with evidence."
    if "INVENTORY" in code or "SLOT" in code or "TIER" in code:
        return "Select the applicable requirement set independently, retain its exact policy, and supply each required native binding."
    if "PUBLIC_CHECK" in code or "AUTHORITY" in code or "AUTHENTICAT" in code:
        return "Supply the named independent authority or public-replay evidence; a digest or self-report cannot discharge it."
    if "POLISHED" in code:
        return "Qualify the exact artifact, representation and full application requirements with independently anchored evidence."
    return ("Repair the anchored finding and rerun the exact " + str(stage or "reported")
            + " check with its prerequisites and selected policy; retain all remaining failures and unknowns.")


def _extract(value: dict[str, Any], input_digest: str) -> dict[str, Any]:
    findings: dict[str, dict[str, Any]] = {}
    observations: dict[str, list[dict[str, Any]]] = {}
    controls = []

    def walk(node: dict[str, Any], pointer: str, context: dict[str, Any], role: str) -> None:
        local = {**context, **{key: node[key] for key in _LOCUS if key in node and node[key] is not None}}
        if role in {"stages", "gates"}:
            local["stage"] = node.get("id", node.get("gate_id"))
        schema = node.get("schema_version", local.get("report_contract", value["schema_version"]))
        local["report_contract"] = schema
        identity = {key: local[key] for key in sorted(local)}
        check_id = "check:" + _digest(canonical_bytes(identity)).split(":")[1]
        state = node.get("status", node.get("verdict"))
        execution = node.get("execution_status")
        detail = {key: item for key, item in node.items() if key not in _LISTS | _REPORTS}
        occurrence = {"input_digest": input_digest, "pointer": pointer, "status": state,
                      "execution_status": execution, "detail": detail,
                      "source_anchor": {"contract_emitter": _EMITTERS.get(schema, "UNREGISTERED_EMITTER"),
                                        "declared_path": local.get("path"), "declared_line": node.get("line"),
                                        "authentication": "NOT_ESTABLISHED"}}
        if role in {"stages", "gates", "objectives", "predicate_results"}:
            observations.setdefault(check_id, []).append(occurrence)
        if state == "NOT_SELECTED" or execution == "NOT_SELECTED":
            controls.append({"check_id": check_id, **occurrence})

        def add(code: str, status: str, suffix: str = "", selected_detail: Any = None) -> None:
            fid = "finding:" + _digest(canonical_bytes({"check": check_id, "code": code})).split(":")[1]
            row = findings.setdefault(fid, {"finding_id": fid, "check_id": check_id,
                "code": code, "locus": identity, "next_fix": _next(code, local.get("stage")), "occurrences": []})
            row["occurrences"].append({**occurrence, "pointer": pointer + suffix,
                                       "status": status, "detail": detail if selected_detail is None else selected_detail})

        aggregate = role in {"report", *_REPORTS} and "code" not in node and "reason" not in node \
            and any(type(node.get(key)) is list and node[key] for key in _LISTS)
        if (state in _NONPASS and not aggregate) or (execution in {"NOT_RUN", "UNRUN"} and state != "NOT_SELECTED"):
            reason = node.get("reason")
            code = str(node.get("code", reason if type(reason) is str and re.fullmatch(r"[A-Z][A-Z0-9_]*", reason)
                                else "CHECK_" + str(state or execution)))
            add(code, state if state in _NONPASS else "UNKNOWN")
        elif role in {"findings", "residuals", "unregistered_objectives", "mechanism_binding_gaps"}:
            if state != "PASS":
                reason = node.get("reason")
                add(str(node.get("code", reason if type(reason) is str and re.fullmatch(r"[A-Z][A-Z0-9_]*", reason)
                                    else "REPORTED_FINDING")), "UNKNOWN")
        if role in {"missing_tiers", "open_required_slots"}:
            add("REQUIRED_TIER_MISSING" if role == "missing_tiers" else "OPEN_REQUIRED_SLOT", "UNKNOWN")
        for key, item in node.items():
            if key.endswith("_status") or key in {"objective_inventory_closure", "inventory_authentication",
                "requirement_authority", "execution_provenance", "checker_independence", "declared_coverage",
                "selector_authority", "public_surface_completeness", "source_inventory_completeness",
                "actual_execution", "native_objective_replay"}:
                if type(item) is str and item in _NONPASS:
                    add(key.upper(), item, "/" + key, item)
            if key == "public_checkability" and type(item) is str and item in _NONPASS:
                add("PUBLIC_CHECKABILITY", item, "/" + key, item)
            if key in _LISTS and type(item) is list:
                for index, child in enumerate(item):
                    child_pointer = pointer + "/" + key + "/" + str(index)
                    if type(child) is dict:
                        walk(child, child_pointer, local, key)
                    elif type(child) is str:
                        add(child if key == "remaining_gates" else "REPORTED_" + key.upper(),
                            "UNKNOWN", "/" + key + "/" + str(index), child)
            elif key in _REPORTS and type(item) is dict:
                walk(item, pointer + "/" + key, local, key)
        if node.get("polished") is False:
            add("POLISHED_ARTIFACT_NOT_ESTABLISHED", "UNKNOWN", "/polished", False)
        if node.get("application_profile") == "UNADOPTED":
            add("APPLICATION_PROFILE_UNADOPTED", "UNKNOWN", "/application_profile", "UNADOPTED")

    walk(value, "", {}, "report")
    return {"findings": sorted(findings.values(), key=lambda row: row["finding_id"]),
            "checks": observations, "controls": controls, "scope": _scope(value),
            "binding_validation": _binding_validation(value),
            "embedded_comparison_bindings": _embedded_comparison_bindings(value)}


def _selected_completeness(values: list[dict[str, Any]], input_digests: list[str],
                           required_contracts: Sequence[str], required_stages: Sequence[str],
                           time_bytes: bytes | None, time_path: str) -> dict[str, Any]:
    """Observe completeness of the explicit finite selection; no global guarantee."""
    if (len(required_contracts) > len(SUPPORTED) or len(required_stages) > 256
            or len(set(required_contracts)) != len(required_contracts)
            or len(set(required_stages)) != len(required_stages)
            or any(contract not in SUPPORTED for contract in required_contracts)
            or any(type(stage) is not str or len(stage) > 256 or ":" not in stage
                   or stage.rsplit(":", 1)[0] not in SUPPORTED or not stage.rsplit(":", 1)[1].strip()
                   for stage in required_stages)):
        raise ValueError("invalid bounded diagnostic selection")
    findings = []
    selection_digest = _digest(canonical_bytes({"required_report_contracts": list(required_contracts),
        "required_stages": list(required_stages), "time_path": time_path}))

    def add(code: str, status: str, locus: dict[str, Any], detail: Any, anchor: dict[str, Any]) -> None:
        check_id = "check:" + _digest(canonical_bytes({"diagnostic_selection": locus})).split(":")[1]
        findings.append({"finding_id": "finding:" + _digest(canonical_bytes({"check": check_id, "code": code})).split(":")[1],
            "check_id": check_id, "code": code, "locus": locus, "next_fix": _next(code, locus.get("stage")),
            "occurrences": [{"status": status, "execution_status": "OBSERVED",
                "input_digest": anchor.get("sha256", selection_digest), "pointer": anchor.get("pointer", ""),
                "source_anchor": {"diagnostic_emitter": "runtime/polish_findings.py:_selected_completeness",
                                  "selection_digest": selection_digest, **anchor}, "detail": detail}]})

    contracts = set()
    unassociated = []
    stage_observations: dict[str, list[dict[str, Any]]] = {}
    for value, input_digest in zip(values, input_digests):
        pending = [(value, "")]
        while pending:
            node, pointer = pending.pop()
            if type(node) is not dict:
                continue
            contract = node.get("schema_version")
            associated = pointer == "" or _associated(values[0], node) if contract in SUPPORTED else False
            if contract in SUPPORTED and not associated:
                unassociated.append({"schema_version": contract, "input_digest": input_digest, "pointer": pointer,
                                     "candidate_association": "NOT_ESTABLISHED"})
            if contract in SUPPORTED and associated:
                contracts.add(contract)
                rows_key = "stages" if "stages" in node else "gates"
                rows = node.get(rows_key, [])
                if type(rows) is not list:
                    raise ValueError("invalid carried stage list")
                for index, row in enumerate(rows):
                    if type(row) is dict and type(row.get("id", row.get("gate_id"))) is str:
                        key = contract + ":" + row.get("id", row.get("gate_id"))
                        stage_observations.setdefault(key, []).append({"input_digest": input_digest,
                            "pointer": pointer + "/" + rows_key + "/" + str(index), "observation": row})
            pending.extend((child, pointer + "/" + key) for key, child in node.items() if key in _REPORTS and type(child) is dict)
    if not required_contracts:
        add("REPORT_FAMILY_COMPLETENESS_NOT_ESTABLISHED", "UNKNOWN", {"selection": "report_families"},
            "No independently selected finite required report-family list was supplied.", {"authentication": "NOT_ESTABLISHED"})
    for contract in required_contracts:
        if contract not in contracts:
            add("REQUIRED_REPORT_FAMILY_MISSING", "FAIL", {"report_contract": contract},
                contract, {"authentication": "NOT_ESTABLISHED"})
    for stage in required_stages:
        rows = stage_observations.get(stage, [])
        if not rows or not all(item["observation"].get("status") == "PASS"
                               and item["observation"].get("execution_status") == "EXECUTED"
                               and item["observation"].get("selected", True) is True
                               and item["observation"].get("required") is True for item in rows):
            add("REQUIRED_STAGE_NOT_RUN" if not rows else "REQUIRED_STAGE_UNMET", "FAIL", {"stage": stage},
                {"required_stage": stage, "observations": rows}, {"authentication": "NOT_ESTABLISHED"})
    time_observation = {"path": time_path, "status": "NOT_ASSESSED", "authentication": "NOT_ESTABLISHED"}
    if time_bytes is None:
        add("TIME_NOT_ASSESSED", "UNKNOWN", {"path": time_path}, "Exact TIME bytes were not supplied.", time_observation)
    else:
        if type(time_bytes) is not bytes or len(time_bytes) > MAX_BYTES:
            raise ValueError("bounded immutable TIME bytes required")
        text = time_bytes.decode("utf-8")
        statuses = [(index, line) for index, line in enumerate(text.splitlines(), 1) if line.startswith("Status:")]
        status = statuses[0][1][8:] if len(statuses) == 1 and statuses[0][1] in {"Status: OPEN", "Status: CLEAR"} else "INVALID"
        time_observation.update(sha256=_digest(time_bytes), status=status, text=text,
                                status_line=statuses[0][0] if len(statuses) == 1 else None)
        if status != "CLEAR":
            add("TIME_OPEN" if status == "OPEN" else "TIME_STATUS_INVALID", "FAIL", {"path": time_path},
                {"status": status, "status_lines": statuses},
                {"declared_path": time_path, "declared_line": time_observation["status_line"],
                 "sha256": time_observation["sha256"], "authentication": "NOT_ESTABLISHED"})
    return {"findings": findings, "required_report_contracts": list(required_contracts),
            "observed_report_contracts": sorted(contracts), "required_stages": list(required_stages),
            "unassociated_embedded_reports": unassociated,
            "selection_digest": selection_digest,
            "time": time_observation, "scope": "EXPLICIT_FINITE_DIAGNOSTIC_SELECTION_ONLY",
            "global_completeness": "NOT_ESTABLISHED"}


def project_reports(current_bytes: bytes, *, previous_bytes: bytes | None = None,
                    history_bytes: Sequence[bytes] = (), related_bytes: Sequence[bytes] = (),
                    required_report_contracts: Sequence[str] = (), required_stages: Sequence[str] = (),
                    time_bytes: bytes | None = None, time_path: str = "TIME.md") -> dict[str, Any]:
    """Project selected report observations; never clear a gate or invoke its effects."""
    raw_reports = [*history_bytes, *([previous_bytes] if previous_bytes is not None else []), current_bytes]
    if (len(history_bytes) > MAX_HISTORY or len(related_bytes) > MAX_RELATED
            or sum(len(raw) for raw in [*raw_reports, *related_bytes]) + len(time_bytes or b"") > MAX_TOTAL_BYTES):
        raise ValueError("report history byte or count bound exceeded")
    decoded = [_decode(raw) for raw in raw_reports]
    extracted = [_extract(value, _digest(raw)) for raw, value in zip(raw_reports, decoded)]
    current = extracted[-1]
    related_values = [_decode(raw) for raw in related_bytes]
    related = [_extract(value, _digest(raw)) for raw, value in zip(related_bytes, related_values)]
    associations = [_associated(decoded[-1], value) for value in related_values]
    completeness = _selected_completeness([decoded[-1], *(value for value, associated in zip(related_values, associations) if associated)],
        [_digest(current_bytes), *(_digest(raw) for raw, associated in zip(related_bytes, associations) if associated)],
        required_report_contracts, required_stages, time_bytes, time_path)
    current["findings"] = sorted([*current["findings"], *(row for attempt in related for row in attempt["findings"]),
                                  *completeness["findings"]], key=lambda row: row["finding_id"])
    unresolved = {row["finding_id"]: row for row in current["findings"]}
    delta: dict[str, Any] = {"comparison": "NO_PREVIOUS", "fixed": [], "remaining": [],
                             "new": sorted(unresolved), "regressed": [], "unobserved": []}

    def comparable(left: dict[str, Any], right: dict[str, Any]) -> bool:
        anchored = any(key in _REQUIREMENT_PINS and type(pin) is str
                       and re.fullmatch(r"sha256:[0-9a-f]{64}", pin)
                       for key, pin in left["scope"]["pins"].items())
        return not related_bytes and anchored and left["binding_validation"]["status"] == "VALID_CARRIED_BINDING" \
            and right["binding_validation"]["status"] == "VALID_CARRIED_BINDING" \
            and left["embedded_comparison_bindings"] and right["embedded_comparison_bindings"] \
            and left["scope"]["unambiguous_identities"] \
            and right["scope"]["unambiguous_identities"] and left["scope"] == right["scope"]

    def passed(attempt: dict[str, Any], check_id: str) -> bool:
        rows = attempt["checks"].get(check_id, [])
        return bool(rows) and all(row["status"] == "PASS" and row["execution_status"] == "EXECUTED" for row in rows) \
            and not any(row["check_id"] == check_id for row in attempt["findings"])

    if previous_bytes is not None:
        previous = extracted[-2]
        old = {row["finding_id"]: row for row in previous["findings"]}
        matches = comparable(previous, current)
        delta["remaining"] = sorted(set(old) & set(unresolved)) if matches else []
        delta["new"] = sorted(set(unresolved) - set(old)) if matches else sorted(unresolved)
        delta["comparison"] = "COMPARABLE_OBSERVATIONS" if matches else "INCOMPARABLE_SCOPE"
        if not matches:
            delta["unobserved"] = sorted(old)
        for fid in sorted(set(old) - set(unresolved)):
            if matches:
                delta["fixed" if passed(current, old[fid]["check_id"]) else "unobserved"].append(fid)
        for fid, row in unresolved.items():
            if any(comparable(attempt, current) and passed(attempt, row["check_id"]) for attempt in extracted[:-1]):
                delta["regressed"].append(fid)
    report = {"schema_version": SCHEMA, "projection_status": "PASS",
        "reported_status": decoded[-1].get("status", decoded[-1].get("verdict", "UNKNOWN")),
        "carried_polished": decoded[-1].get("polished"), "polished": "NOT_ASSESSED",
        "authentication": "NOT_ESTABLISHED", "chronology": "CALLER_SELECTED_ORDER",
        "inputs": [{"sha256": _digest(raw), "schema_version": value["schema_version"],
                    "role": "related" if index >= len(raw_reports) else "attempt",
                    "candidate_association": ("MATCHING_CARRIED_BINDING" if associations[index - len(raw_reports)] else "NOT_ESTABLISHED")
                        if index >= len(raw_reports) else "ATTEMPT_INPUT",
                    "binding_validation": _binding_validation(value),
                    "embedded_comparison_bindings": _embedded_comparison_bindings(value),
                    "carried_binding": {key: value[key] for key in ("binding", "artifact", "root_id",
                        "sources", "source_digest", "collection_digest", "bundle_digest", "request_digest", "inventory_digest", "mechanism_digest") if key in value}}
                   for index, (raw, value) in enumerate(zip([*raw_reports, *related_bytes], [*decoded, *related_values]))],
        "diagnostic_selection": {key: item for key, item in completeness.items() if key != "findings"},
        "findings": current["findings"], "controls": current["controls"], "comparison_scope": current["scope"],
        "report_changed": previous_bytes is not None and _digest(previous_bytes) != _digest(current_bytes),
        "projection_mechanism_digest": _digest(Path(__file__).read_bytes()),
        "delta": delta, "claim_boundary": BOUNDARY,
        "comparison_boundary": "This version compares primary workflow attempts only. Related reports or embedded checks without a supported complete comparison binding make attempt matching unavailable."}
    statuses = [occurrence["status"] for row in report["findings"] for occurrence in row["occurrences"]]
    report["diagnostic_status"] = "FAIL" if "FAIL" in statuses or report["reported_status"] == "FAIL" else \
        "UNKNOWN" if statuses or report["reported_status"] != "PASS" else "PASS"
    encoded = canonical_bytes(report)
    if len(encoded) > MAX_OUTPUT_BYTES - 128:
        raise ValueError("projected report output bound exceeded")
    report["report_digest"] = _digest(encoded)
    return report


def render_findings(report: dict[str, Any]) -> str:
    """Render all projected occurrences with escaped text and concrete follow-up actions."""
    lines = ["Observed unresolved findings: " + str(len(report["findings"])), report["claim_boundary"],
             "Diagnostic selection: " + json.dumps(report["diagnostic_selection"], sort_keys=True, ensure_ascii=True)]
    for row in report["findings"]:
        lines.append(row["finding_id"] + " " + json.dumps(row["code"], ensure_ascii=True))
        for occurrence in row["occurrences"]:
            lines.append("  " + json.dumps(occurrence, sort_keys=True, ensure_ascii=True))
        lines.append("  Next: " + json.dumps(row["next_fix"], ensure_ascii=True))
    for control in report["controls"]:
        lines.append("Control state: " + json.dumps(control, sort_keys=True, ensure_ascii=True))
    lines.append("Attempt differences: " + json.dumps(report["delta"], sort_keys=True))
    rendered = "\n".join(lines)
    if len(rendered.encode("utf-8")) > MAX_OUTPUT_BYTES:
        raise ValueError("rendered report output bound exceeded")
    return rendered


def add_report_parser(commands: Any) -> None:
    parser = commands.add_parser("report", help="Display retained unresolved findings and compare selected attempts without running checks.")
    parser.add_argument("report")
    parser.add_argument("--previous", help="Previous carried report; absent findings require explicit comparable PASS observations to be fixed.")
    parser.add_argument("--history", action="append", default=[], help="Earlier carried report in caller-selected order; repeat up to sixteen times.")
    parser.add_argument("--related", action="append", default=[], help="Related current report; repeat up to sixteen times. These are not prior attempts.")
    parser.add_argument("--required-report-contract", action="append", default=[], help="Independently selected required report family; completeness covers only this explicit finite list.")
    parser.add_argument("--required-stage", action="append", default=[], help="Required report family and stage identifier (ID), supplied as FAMILY:ID, with an explicit required executed PASS; omission and deselection remain unmet.")
    parser.add_argument("--time", help="Exact TIME file to observe; OPEN or malformed status remains a diagnostic failure, absent bytes remain unassessed.")
    parser.add_argument("--json", action="store_true")


def handle_report_command(args: argparse.Namespace) -> int:
    def read(name: str) -> bytes:
        with Path(name).open("rb") as stream:
            return stream.read(MAX_BYTES + 1)
    try:
        if len(args.history) > MAX_HISTORY or len(args.related) > MAX_RELATED:
            raise ValueError("history count bound exceeded")
        report = project_reports(read(args.report), previous_bytes=read(args.previous) if args.previous else None,
                                 history_bytes=[read(name) for name in args.history], related_bytes=[read(name) for name in args.related],
                                 required_report_contracts=args.required_report_contract, required_stages=args.required_stage,
                                 time_bytes=read(args.time) if args.time else None, time_path=args.time or "TIME.md")
        code = {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}.get(report["diagnostic_status"], 2)
        rendered = json.dumps(report, sort_keys=True, indent=2, allow_nan=False) if args.json else render_findings(report)
        if len(rendered.encode("utf-8")) > MAX_OUTPUT_BYTES:
            raise ValueError("rendered command output bound exceeded")
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError):
        report = {"schema_version": SCHEMA, "projection_status": "FAIL", "polished": "NOT_ASSESSED",
                  "reason": "INVALID_OR_UNAVAILABLE_REPORT", "claim_boundary": BOUNDARY}
        code = 1
        rendered = json.dumps(report, sort_keys=True, allow_nan=False) if args.json else "[FAIL] " + report["reason"]
    print(rendered)
    return code
