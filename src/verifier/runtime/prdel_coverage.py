"""Bounded Pull Request Domain Explanation Language (PRDEL) coverage.

This Verifier Standard (VSTD) helper compares selected obligations, explanation
records and retained evidence. It discharges no numbered-profile rung. Test
receipts are reported observations, not authenticated execution. A result digest
does not establish execution or semantic truth. The caller must independently
evaluate supported predicates before attaching stronger clearance.

FAIL denotes an unmet selected evidence or coverage obligation, not falsity of
the underlying source behavior. NOT_RUN describes missing or explicitly unrun
required validation in the selected records; it makes no claim about outside
execution. Reported execution remains distinct from authenticated execution.

Preventative notices compare represented abstract syntax tree (AST) relationships.
They identify potential intersections; they neither prove runtime effects nor send
notifications. A missing branch inventory or analysis frontier stays unresolved.
"""

from __future__ import annotations

import hashlib
import json
import re
from typing import Any

LAYERS = ("base", "unit", "integration", "regression", "preventative")
_BINDING_KEYS = ("base", "head", "source_digest", "requirements_digest")
_COMMIT = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_DIGEST = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z")


class _Exhausted(Exception):
    """An explicit operation bound has been reached."""


class _Budget:
    """Mutable counter shared by all bounded traversals in one assessment."""

    def __init__(self, limit: int) -> None:
        self.limit = limit
        self.used = 0

    def step(self) -> None:
        if self.used >= self.limit:
            raise _Exhausted
        self.used += 1


def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip()) and len(value) <= 4096


def _identifiers(value: Any, budget: _Budget) -> bool:
    if not isinstance(value, list):
        return False
    seen: set[str] = set()
    for item in value:
        budget.step()
        if not _text(item) or item in seen:
            return False
        seen.add(item)
    return True


def _valid_binding(binding: Any) -> bool:
    return isinstance(binding, dict) and all(
        isinstance(binding.get(key), str)
        and (_COMMIT if key in ("base", "head") else _DIGEST).fullmatch(binding[key])
        for key in _BINDING_KEYS
    )


def _same_binding(left: dict[str, Any], right: dict[str, Any]) -> bool:
    return all(left.get(key) == right.get(key) for key in _BINDING_KEYS)


def _finding(
    code: str, question: str, *, verdict: str = "UNKNOWN", **coordinates: Any
) -> dict[str, Any]:
    return {"code": code, "verdict": verdict, "question": question, **coordinates}


def _execution_summary(statuses: list[str]) -> str:
    if not statuses:
        return "UNRESOLVED"
    if "NOT_RUN" in statuses:
        return "NOT_RUN"
    active = set(statuses) - {"NOT_REQUIRED"}
    if not active:
        return "NOT_REQUIRED"
    return next(iter(active)) if len(active) == 1 else "MIXED"


# vstd-explanation: begin prdel.self.prdel-coverage
# Authored intent (not verified):
#   Distinguish required absent checks, reported outcomes and authenticated execution.
# Requirements: bounded-source-description
# Invariant (authored): Known unmet required obligations remain FAIL; unsupported
# observations remain UNKNOWN.
# Limit (authored): A result digest and reported pass do not authenticate test
# execution.
# vstd-explanation: end prdel.self.prdel-coverage
def assess_coverage(
    required: list[dict],
    records: list[dict],
    evidence: list[dict],
    binding: dict,
    *,
    max_operations: int = 100000,
    replayed_evidence: tuple[Any, ...] = (),
) -> dict:
    """Assess five independent coverage layers without promoting reported receipts.

    ``required_layers`` and ``applicability_reasons`` belong to externally selected
    generated obligations, never agent-filled records. Without that metadata all
    five layers are required. Each omitted layer needs a generated reason; a
    missing reason fails the applicability obligation. Selecting that policy does
    not authenticate it. Legacy UNRUN and explicit NOT_RUN input statuses both
    describe nonexecuted coverage.

    Valid reported PASS evidence establishes receipt correspondence only. Fresh
    verifier-produced replay results may establish execution for their exact
    selected obligation and layer, but not test adequacy or behavioral truth. Every
    valid retained failed receipt receives a disposition, even if its explanation
    omits it or the selected policy does not require that layer. Failed reports
    and invalid schemas fail closed. Known missing coverage and unrun required
    checks fail their evidence obligations, with execution_status NOT_RUN.
    Unauthenticated reported results and unsupported or exhausted evaluation
    remain UNKNOWN. Inputs are never changed.
    """
    findings: list[dict[str, Any]] = []
    report: dict[str, Any] = {
        "schema_version": "verifier-prdel-coverage-1",
        "binding": binding,
        "verdict": "UNKNOWN",
        "structural_status": "NOT_ESTABLISHED",
        "failure_scope": "SELECTED_EVIDENCE_AND_COVERAGE_OBLIGATIONS",
        "execution_status": "UNRESOLVED",
        "execution_authentication": "NOT_ESTABLISHED",
        "semantic_clearance": "NOT_ESTABLISHED",
        "layers": {
            layer: {
                "verdict": "UNKNOWN",
                "execution_status": "UNRESOLVED",
                "obligations": [],
            }
            for layer in LAYERS
        },
        "findings": findings,
        "bounds": {
            "max_operations": max_operations,
            "operations": 0,
            "complete": False,
        },
        "limits": [
            (
                "Receipt correspondence does not authenticate "
                "execution or establish semantic truth."
            )
        ],
    }
    if (
        isinstance(max_operations, bool)
        or not isinstance(max_operations, int)
        or max_operations < 1
        or not _valid_binding(binding)
        or any(not isinstance(value, list) for value in (required, records, evidence))
        or type(replayed_evidence) is not tuple
    ):
        findings.append(
            _finding(
                "INVALID_INPUT",
                "Supply bounded lists and exact commit/digest bindings.",
                verdict="FAIL",
            )
        )
        report["verdict"] = "FAIL"
        return report
    budget = _Budget(max_operations)
    obligations: dict[str, dict[str, Any]] = {}
    explanations: dict[str, dict[str, Any]] = {}
    receipts: dict[str, dict[str, Any]] = {}
    verifier_produced: set[str] = set()
    verifier_replayed: set[str] = set()
    retained_failures: dict[tuple[str, str], list[str]] = {}
    failed_layers: set[str] = set()

    def invalid(code: str, question: str, **coordinates: Any) -> None:
        findings.append(_finding(code, question, verdict="FAIL", **coordinates))

    try:
        for item in required:
            budget.step()
            if (
                not isinstance(item, dict)
                or not _text(item.get("id"))
                or item.get("kind") not in ("source", "contract", "frontier")
                or not _text(item.get("path"))
                or not _text(item.get("question"))
            ):
                invalid(
                    "INVALID_OBLIGATION",
                    "Supply a unique obligation, kind, path and targeted question.",
                )
                continue
            identifier = item["id"]
            if identifier in obligations:
                invalid(
                    "DUPLICATE_OBLIGATION",
                    "Remove the ambiguous duplicate obligation.",
                    obligation_id=identifier,
                )
                continue
            sources = item.get(
                "source_obligations", item.get("affected_source_ids", [])
            )
            if not _identifiers(sources, budget):
                invalid(
                    "INVALID_SOURCE_REFERENCES",
                    "Use unique source obligation identifiers.",
                    obligation_id=identifier,
                )
                continue
            if (
                "source_obligations" in item
                and "affected_source_ids" in item
                and item["source_obligations"] != item["affected_source_ids"]
            ):
                invalid(
                    "AMBIGUOUS_SOURCE_REFERENCES",
                    (
                        "Use one exact source association instead of "
                        "contradictory aliases."
                    ),
                    obligation_id=identifier,
                )
                continue
            selected = item.get("required_layers", list(LAYERS))
            reasons = item.get("applicability_reasons", {})
            if (
                not _identifiers(selected, budget)
                or any(layer not in LAYERS for layer in selected)
                or not isinstance(reasons, dict)
                or any(layer not in LAYERS for layer in reasons)
                or any(not _text(reason) for reason in reasons.values())
            ):
                invalid(
                    "INVALID_APPLICABILITY",
                    (
                        "Supply generated layer selection and "
                        "nonempty applicability reasons."
                    ),
                    obligation_id=identifier,
                )
                continue
            predicates = item.get("deterministic_predicates", {})
            if (
                not isinstance(predicates, dict)
                or any(layer not in LAYERS for layer in predicates)
                or any(
                    not _identifiers(identifiers, budget)
                    for identifiers in predicates.values()
                )
            ):
                invalid(
                    "INVALID_PREDICATE_SELECTION",
                    (
                        "Supply known layers with unique externally "
                        "selected predicate identifiers."
                    ),
                    obligation_id=identifier,
                )
                continue
            obligations[identifier] = item
        for item in records:
            budget.step()
            if not isinstance(item, dict) or not _text(item.get("id")):
                invalid(
                    "INVALID_RECORD",
                    "Supply an explanation record with its obligation identifier.",
                )
                continue
            identifier = item["id"]
            if identifier in explanations:
                invalid(
                    "DUPLICATE_RECORD",
                    "Remove the ambiguous duplicate explanation.",
                    obligation_id=identifier,
                )
                continue
            if identifier not in obligations:
                invalid(
                    "UNKNOWN_RECORD",
                    "Bind this record to a generated obligation.",
                    obligation_id=identifier,
                )
                continue
            coverage = item.get("coverage")
            if not isinstance(coverage, dict) or any(
                layer not in LAYERS for layer in coverage
            ):
                invalid(
                    "INVALID_COVERAGE",
                    "Use only the five known coverage layers.",
                    obligation_id=identifier,
                )
                continue
            valid = True
            for layer, entry in coverage.items():
                budget.step()
                if (
                    not isinstance(entry, dict)
                    or set(entry) != {"status", "evidence_ids", "reason"}
                    or entry.get("status")
                    not in ("EXECUTED", "UNRUN", "NOT_RUN", "NOT_APPLICABLE")
                    or not isinstance(entry.get("reason"), str)
                    or not _identifiers(entry.get("evidence_ids"), budget)
                    or (entry["status"] == "EXECUTED" and not entry["evidence_ids"])
                    or (
                        entry["status"] != "EXECUTED"
                        and (entry["evidence_ids"] or not _text(entry["reason"]))
                    )
                ):
                    invalid(
                        "INVALID_LAYER_RECORD",
                        (
                            "Supply status, relevant evidence and a "
                            "reason; unrun entries cannot claim "
                            "execution."
                        ),
                        obligation_id=identifier,
                        layer=layer,
                    )
                    valid = False
            if valid:
                explanations[identifier] = item
        for item in evidence:
            budget.step()
            if not isinstance(item, dict) or not _text(item.get("id")):
                invalid(
                    "INVALID_EVIDENCE", "Supply a uniquely identified retained result."
                )
                continue
            identifier = item["id"]
            if identifier in receipts:
                invalid(
                    "DUPLICATE_EVIDENCE",
                    "Remove the ambiguous duplicate receipt.",
                    evidence_id=identifier,
                )
                continue
            if (
                item.get("kind")
                not in ("test_result", "deterministic_predicate_result")
                or item.get("layer") not in LAYERS
                or item.get("status") not in ("PASS", "FAIL", "UNKNOWN")
                or not _text(item.get("command"))
                or not isinstance(item.get("result_digest"), str)
                or not _DIGEST.fullmatch(item["result_digest"])
                or not _valid_binding(item)
                or not _identifiers(item.get("obligation_ids"), budget)
                or not item["obligation_ids"]
                or (
                    item["kind"] == "deterministic_predicate_result"
                    and not _text(item.get("predicate_id"))
                )
            ):
                invalid(
                    "INVALID_EVIDENCE",
                    (
                        "Retain exact bindings, command, result "
                        "digest, known outcome and relevant "
                        "obligations."
                    ),
                    evidence_id=identifier,
                )
                continue
            if not _same_binding(item, binding):
                invalid(
                    "STALE_EVIDENCE",
                    (
                        "Rerun evidence against these exact source "
                        "and requirement revisions."
                    ),
                    evidence_id=identifier,
                )
                continue
            if any(
                identifier not in obligations for identifier in item["obligation_ids"]
            ):
                invalid(
                    "UNKNOWN_EVIDENCE_OBLIGATION",
                    "Bind evidence only to generated obligations.",
                    evidence_id=identifier,
                )
                continue
            receipts[identifier] = item
            if item["status"] == "FAIL":
                failed_layers.add(item["layer"])
                report["layers"][item["layer"]]["verdict"] = "FAIL"
                report["layers"][item["layer"]][
                    "execution_status"
                ] = "EXECUTED_REPORTED"
                findings.append(
                    _finding(
                        "REPORTED_TEST_FAILURE",
                        (
                            "Resolve and rerun the retained failed "
                            "result; omission from an explanation "
                            "cannot dispose of it."
                        ),
                        verdict="FAIL",
                        evidence_id=identifier,
                        layer=item["layer"],
                        execution_status="EXECUTED_REPORTED",
                        obligation_id=(
                            item["obligation_ids"][0]
                            if len(item["obligation_ids"]) == 1
                            else None
                        ),
                        obligation_ids=item["obligation_ids"],
                    )
                )
                for obligation_id in item["obligation_ids"]:
                    budget.step()
                    retained_failures.setdefault(
                        (obligation_id, item["layer"]), []
                    ).append(identifier)
        # This channel is populated only by the caller's just-completed fixed
        # replay. JSON-carried receipts never enter it and cannot authenticate
        # themselves by copying these fields.
        from verifier.runtime.prdel_evidence import ReplayResult

        for result in replayed_evidence:
            budget.step()
            if type(result) is not ReplayResult:
                invalid(
                    "INVALID_REPLAY_RESULT",
                    "Use only results produced by the fixed verifier replay.",
                )
                continue
            item = result.as_evidence()
            identifier = item["id"]
            if identifier in receipts:
                invalid(
                    "AMBIGUOUS_REPLAY_EVIDENCE",
                    "Do not reuse a carried evidence identity for verifier replay.",
                    evidence_id=identifier,
                )
                continue
            if (
                not _same_binding(item, binding)
                or item["layer"] not in LAYERS
                or item["status"] not in ("PASS", "FAIL", "UNKNOWN")
                or not item["obligation_ids"]
                or any(value not in obligations for value in item["obligation_ids"])
            ):
                invalid(
                    "INVALID_REPLAY_RESULT",
                    "Replay must retain the exact binding, layer and obligations.",
                    evidence_id=identifier,
                )
                continue
            receipts[identifier] = item
            verifier_produced.add(identifier)
            if item["status"] in {"PASS", "FAIL"}:
                verifier_replayed.add(identifier)
            if item["status"] == "FAIL":
                failed_layers.add(item["layer"])
                findings.append(
                    _finding(
                        "VERIFIER_REPLAY_FAILURE",
                        "Resolve the fixed replay failure and rerun the exact plan.",
                        verdict="FAIL",
                        evidence_id=identifier,
                        layer=item["layer"],
                        execution_status="EXECUTED_VERIFIER_REPLAY",
                        obligation_id=(
                            item["obligation_ids"][0]
                            if len(item["obligation_ids"]) == 1
                            else None
                        ),
                        obligation_ids=item["obligation_ids"],
                    )
                )
                for obligation_id in item["obligation_ids"]:
                    budget.step()
                    retained_failures.setdefault(
                        (obligation_id, item["layer"]), []
                    ).append(identifier)
        for layer in LAYERS:
            entries: list[dict[str, Any]] = []
            # Keep reached entries visible if a later obligation exhausts the
            # bound. The summary stays unresolved until this layer completes.
            report["layers"][layer]["obligations"] = entries
            for identifier, obligation in obligations.items():
                budget.step()
                selected = obligation.get("required_layers", list(LAYERS))
                reason = obligation.get("applicability_reasons", {}).get(layer)
                failed_ids = retained_failures.get((identifier, layer), [])
                entry: dict[str, Any] = {
                    "obligation_id": identifier,
                    "verdict": "FAIL" if failed_ids else "UNKNOWN",
                    "recorded_verdict": "FAIL" if failed_ids else "UNKNOWN",
                    "evidence_ids": list(failed_ids),
                    "execution_status": (
                        "EXECUTED_REPORTED" if failed_ids else "UNRESOLVED"
                    ),
                    "execution_authentication": "NOT_ESTABLISHED",
                }
                entries.append(entry)
                if layer not in selected:
                    if reason:
                        entry.update(
                            verdict="FAIL" if failed_ids else "PASS",
                            applicability="EXTERNALLY_SELECTED_NOT_REQUIRED",
                            reason=reason,
                            execution_status=(
                                "EXECUTED_REPORTED" if failed_ids else "NOT_REQUIRED"
                            ),
                        )
                    else:
                        entry["verdict"] = "FAIL"
                        if not failed_ids:
                            entry["execution_status"] = "NOT_RUN"
                        invalid(
                            "MISSING_APPLICABILITY_REASON",
                            (
                                "Supply the required generated "
                                "reason before excluding this layer."
                            ),
                            obligation_id=identifier,
                            layer=layer,
                            execution_status="NOT_RUN",
                        )
                    continue
                entry["applicability"] = "REQUIRED"
                record = explanations.get(identifier, {}).get("coverage", {}).get(layer)
                if record is None:
                    entry["verdict"] = "FAIL"
                    if not failed_ids:
                        entry["execution_status"] = "NOT_RUN"
                    invalid(
                        "MISSING_LAYER_COVERAGE",
                        (
                            "Supply this required layer's execution "
                            "evidence; known absent coverage fails "
                            "its evidence obligation."
                        ),
                        obligation_id=identifier,
                        layer=layer,
                        execution_status="NOT_RUN",
                    )
                    continue
                if record["status"] != "EXECUTED":
                    code = (
                        "SELF_REPORTED_WAIVER"
                        if record["status"] == "NOT_APPLICABLE"
                        else "UNRUN_LAYER"
                    )
                    entry["verdict"] = "FAIL"
                    if not failed_ids:
                        entry["execution_status"] = "NOT_RUN"
                    invalid(
                        code,
                        (
                            "Run the required check; explanation "
                            "records cannot waive generated "
                            "applicability."
                        ),
                        obligation_id=identifier,
                        layer=layer,
                        execution_status="NOT_RUN",
                    )
                    continue
                related: list[dict[str, Any]] = []
                for evidence_id in record["evidence_ids"]:
                    budget.step()
                    receipt = receipts.get(evidence_id)
                    if receipt is None:
                        invalid(
                            "MISSING_EVIDENCE",
                            "Retain this result with exact valid bindings.",
                            obligation_id=identifier,
                            layer=layer,
                            evidence_id=evidence_id,
                            execution_status="NOT_RUN",
                        )
                        entry["verdict"] = "FAIL"
                        if not failed_ids:
                            entry["execution_status"] = "NOT_RUN"
                        continue
                    if (
                        receipt["layer"] != layer
                        or identifier not in receipt["obligation_ids"]
                    ):
                        invalid(
                            "IRRELEVANT_EVIDENCE",
                            (
                                "Provide evidence for this "
                                "obligation and this independent "
                                "layer."
                            ),
                            obligation_id=identifier,
                            layer=layer,
                            evidence_id=evidence_id,
                            execution_status="NOT_RUN",
                        )
                        entry["verdict"] = "FAIL"
                        if not failed_ids:
                            entry["execution_status"] = "NOT_RUN"
                        continue
                    if receipt["kind"] == "deterministic_predicate_result":
                        predicates = obligation.get("deterministic_predicates", {}).get(
                            layer, []
                        )
                        if (
                            not isinstance(predicates, list)
                            or receipt["predicate_id"] not in predicates
                        ):
                            invalid(
                                "UNSELECTED_PREDICATE",
                                (
                                    "Select and independently replay "
                                    "a supported predicate for this "
                                    "obligation."
                                ),
                                obligation_id=identifier,
                                layer=layer,
                                evidence_id=evidence_id,
                                execution_status="NOT_RUN",
                            )
                            entry["verdict"] = "FAIL"
                            if not failed_ids:
                                entry["execution_status"] = "NOT_RUN"
                            continue
                    related.append(receipt)
                entry["evidence_ids"] = sorted(
                    set(failed_ids) | {item["id"] for item in related}
                )
                outcomes = {item["status"] for item in related}
                authenticated = {
                    item["id"] for item in related if item["id"] in verifier_replayed
                }
                if authenticated:
                    entry["execution_authentication"] = "VERIFIER_REPLAYED"
                if obligation["kind"] == "frontier" and not authenticated:
                    entry["execution_status"] = (
                        entry["execution_status"]
                        if entry["verdict"] == "FAIL"
                        else "UNRESOLVED"
                    )
                    findings.append(
                        _finding(
                            "ANALYSIS_FRONTIER",
                            obligation["question"],
                            obligation_id=identifier,
                            layer=layer,
                            execution_status="UNRESOLVED",
                        )
                    )
                    continue
                if failed_ids or "FAIL" in outcomes:
                    entry.update(
                        verdict="FAIL",
                        recorded_verdict="FAIL",
                        execution_status=(
                            "EXECUTED_VERIFIER_REPLAY"
                            if authenticated
                            else "EXECUTED_REPORTED"
                        ),
                    )
                elif related and outcomes == {"PASS"}:
                    entry["recorded_verdict"] = "PASS"
                    if authenticated:
                        entry.update(
                            verdict="PASS",
                            execution_status="EXECUTED_VERIFIER_REPLAY",
                        )
                    else:
                        if entry["execution_status"] != "NOT_RUN":
                            entry["execution_status"] = "EXECUTED_REPORTED"
                        findings.append(
                            _finding(
                                "EXECUTION_NOT_ESTABLISHED",
                                (
                                    "Independently authenticate "
                                    "execution or replay the selected "
                                    "predicate; a receipt digest alone "
                                    "is insufficient."
                                ),
                                obligation_id=identifier,
                                layer=layer,
                                execution_status="EXECUTED_REPORTED",
                            )
                        )
                elif related:
                    if entry["execution_status"] != "NOT_RUN":
                        entry["execution_status"] = (
                            "EXECUTED_VERIFIER_REPLAY"
                            if authenticated
                            else (
                                "VERIFIER_REPLAY_INCOMPLETE"
                                if any(
                                    item["id"] in verifier_produced
                                    for item in related
                                )
                                else "EXECUTED_REPORTED"
                            )
                        )
                    findings.append(
                        _finding(
                            "UNKNOWN_TEST_RESULT",
                            "Resolve the reported unknown result.",
                            obligation_id=identifier,
                            layer=layer,
                            execution_status="EXECUTED_REPORTED",
                        )
                    )
            if not obligations:
                findings.append(
                    _finding(
                        "EMPTY_OBLIGATION_INVENTORY",
                        "Establish the complete selected obligation inventory.",
                        layer=layer,
                    )
                )
            status = (
                "FAIL"
                if layer in failed_layers
                or any(item["verdict"] == "FAIL" for item in entries)
                else (
                    "PASS"
                    if entries and all(item["verdict"] == "PASS" for item in entries)
                    else "UNKNOWN"
                )
            )
            report["layers"][layer] = {
                "verdict": status,
                "execution_status": _execution_summary(
                    [entry["execution_status"] for entry in entries]
                ),
                "obligations": entries,
            }
        report["bounds"]["complete"] = True
    except _Exhausted:
        findings.append(
            _finding(
                "BOUND_EXHAUSTED",
                (
                    "Increase the explicit bound and repeat the full "
                    "assessment; unexamined inputs remain unresolved."
                ),
                execution_status="UNRESOLVED",
            )
        )
    report["bounds"]["operations"] = budget.used
    # A reached negative finding survives interruption even when the containing
    # layer never reached its normal summary assignment.
    for finding in findings:
        layer = finding.get("layer")
        if finding["verdict"] == "FAIL" and layer in report["layers"]:
            summary = report["layers"][layer]
            summary["verdict"] = "FAIL"
            summary["execution_status"] = _execution_summary(
                [
                    summary["execution_status"],
                    finding.get("execution_status", "UNRESOLVED"),
                ]
            )
    failures = any(item["verdict"] == "FAIL" for item in findings)
    report["structural_status"] = (
        "FAIL"
        if failures
        else ("PASS" if report["bounds"]["complete"] else "NOT_ESTABLISHED")
    )
    complete_pass = (
        report["bounds"]["complete"]
        and bool(obligations)
        and all(
            layer["verdict"] == "PASS" for layer in report["layers"].values()
        )
    )
    report["verdict"] = "FAIL" if failures else ("PASS" if complete_pass else "UNKNOWN")
    report["execution_status"] = _execution_summary(
        [layer["execution_status"] for layer in report["layers"].values()]
    )
    required_entries = [
        entry
        for layer in report["layers"].values()
        for entry in layer["obligations"]
        if entry.get("applicability") == "REQUIRED"
    ]
    if required_entries and all(
        entry["verdict"] == "PASS"
        and entry.get("execution_authentication") == "VERIFIER_REPLAYED"
        for entry in required_entries
    ):
        report["execution_authentication"] = "VERIFIER_REPLAYED"
    return report


def _notice_id(value: dict[str, Any]) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return "preventative:" + hashlib.sha256(encoded).hexdigest()


def preventative_obligations(
    current_graph: dict, other_graphs: list[dict], *, max_operations: int = 100000
) -> dict:
    """Return deterministic, undelivered notices for represented branch intersections.

    Graphs carry exact ``binding`` plus AST ``nodes``, ``edges`` and ``frontier``.
    Relationships are dependency-to-consumer. Shared paths are potential impacts,
    not demonstrated conflicts. Signature/schema/configuration/state/order rules
    activate only when those facts are directly represented in node metadata.
    """
    findings: list[dict[str, Any]] = []
    notices: list[dict[str, Any]] = []
    report: dict[str, Any] = {
        "schema_version": "verifier-prdel-preventative-1",
        "verdict": "UNKNOWN",
        "notices": notices,
        "findings": findings,
        "delivery": "NOT_SENT",
        "bounds": {
            "max_operations": max_operations,
            "operations": 0,
            "complete": False,
        },
        "limits": [
            "Potential intersections are not runtime conflict proofs.",
            (
                "Only supplied pinned graphs are examined; branch "
                "inventory authority is not established."
            ),
        ],
    }
    if (
        isinstance(max_operations, bool)
        or not isinstance(max_operations, int)
        or max_operations < 1
        or not isinstance(other_graphs, list)
    ):
        findings.append(
            _finding(
                "INVALID_INPUT",
                "Supply pinned graphs and a positive operation bound.",
                verdict="FAIL",
            )
        )
        report["verdict"] = "FAIL"
        return report
    budget = _Budget(max_operations)

    def graph_index(graph: Any, position: int) -> dict[str, Any] | None:
        budget.step()
        if (
            not isinstance(graph, dict)
            or not _valid_binding(graph.get("binding"))
            or any(
                not isinstance(graph.get(key), list)
                for key in ("nodes", "edges", "frontier")
            )
        ):
            findings.append(
                _finding(
                    "UNBOUND_GRAPH",
                    (
                        "Supply an exact-bound graph with retained "
                        "nodes, edges and unknown frontier."
                    ),
                    graph_index=position,
                )
            )
            return None
        nodes: dict[str, dict[str, Any]] = {}
        paths: dict[str, list[dict[str, Any]]] = {}
        valid = True
        for node in graph["nodes"]:
            budget.step()
            if (
                not isinstance(node, dict)
                or not _text(node.get("id"))
                or node["id"] in nodes
                or not _text(node.get("path"))
                or not isinstance(node.get("symbol", ""), str)
                or node.get("side") not in ("before", "after")
                or not isinstance(node.get("changed"), bool)
                or not _identifiers(node.get("source_obligations", []), budget)
            ):
                findings.append(
                    _finding(
                        "INVALID_GRAPH_NODE",
                        (
                            "Supply unique typed nodes and explicit "
                            "change/source associations."
                        ),
                        verdict="FAIL",
                        graph_index=position,
                    )
                )
                valid = False
                continue
            nodes[node["id"]] = node
            if node["changed"] or node.get("source_obligations"):
                paths.setdefault(node["path"], []).append(node)
        edges: dict[str, dict[str, Any]] = {}
        for edge in graph["edges"]:
            budget.step()
            if (
                not isinstance(edge, dict)
                or not _text(edge.get("id"))
                or edge["id"] in edges
                or edge.get("source") not in nodes
                or edge.get("target") not in nodes
                or not _text(edge.get("relationship"))
                or edge.get("side") not in ("before", "after")
                or edge.get("evidence_state")
                not in ("syntactic_candidate", "resolved_relationship")
            ):
                findings.append(
                    _finding(
                        "INVALID_GRAPH_EDGE",
                        (
                            "Retain unique edges, represented "
                            "endpoints and bounded relationship "
                            "evidence."
                        ),
                        verdict="FAIL",
                        graph_index=position,
                    )
                )
                valid = False
                continue
            edges[edge["id"]] = edge
        for frontier in graph["frontier"]:
            budget.step()
            if (
                not isinstance(frontier, dict)
                or not _text(frontier.get("id"))
                or not _text(frontier.get("question"))
            ):
                findings.append(
                    _finding(
                        "INVALID_FRONTIER",
                        "Retain identified unresolved analysis boundaries.",
                        verdict="FAIL",
                        graph_index=position,
                    )
                )
                valid = False
                continue
            findings.append(
                _finding(
                    "UNRESOLVED_GRAPH_FRONTIER",
                    frontier["question"],
                    graph_index=position,
                    frontier_id=frontier["id"],
                    binding=graph["binding"],
                )
            )
        return (
            {"graph": graph, "nodes": nodes, "paths": paths, "edges": edges}
            if valid
            else None
        )

    try:
        current = graph_index(current_graph, -1)
        if not other_graphs:
            findings.append(
                _finding(
                    "BRANCH_INVENTORY_NOT_ESTABLISHED",
                    "Supply the pinned branches or declared task graphs to examine.",
                )
            )
        seen_bindings: set[tuple[str, ...]] = set()
        for position, graph in enumerate(other_graphs):
            target = graph_index(graph, position)
            if current is None or target is None:
                continue
            binding_key = tuple(graph["binding"][key] for key in _BINDING_KEYS)
            if binding_key in seen_bindings:
                findings.append(
                    _finding(
                        "DUPLICATE_BRANCH_GRAPH",
                        "Select each exact branch graph once.",
                        verdict="FAIL",
                        graph_index=position,
                    )
                )
                continue
            seen_bindings.add(binding_key)
            for path in sorted(set(current["paths"]) & set(target["paths"])):
                budget.step()
                left = current["paths"][path]
                right = target["paths"][path]
                symbols = sorted(
                    {node.get("symbol", "") for node in left}
                    & {node.get("symbol", "") for node in right}
                )
                rules = {"SOURCE_PATH_INTERSECTION"}
                if symbols:
                    rules.add("SYMBOL_INTERSECTION")
                represented_fields = {
                    "signature": "SIGNATURE_COMPATIBILITY",
                    "schema": "SCHEMA_COMPATIBILITY",
                    "config_keys": "CONFIGURATION_INTERACTION",
                    "shared_state": "SHARED_STATE_INTERACTION",
                    "ordering": "ORDERING_INTERACTION",
                    "invariants": "INVARIANT_COMPATIBILITY",
                }
                for field, rule in represented_fields.items():
                    budget.step()
                    if any(field in node for node in left) or any(
                        field in node for node in right
                    ):
                        rules.add(rule)
                related_edges: list[dict[str, Any]] = []
                for index in (current, target):
                    for edge in index["edges"].values():
                        budget.step()
                        if (
                            index["nodes"][edge["source"]]["path"] == path
                            or index["nodes"][edge["target"]]["path"] == path
                        ):
                            related_edges.append(
                                {
                                    "edge_id": edge["id"],
                                    "relationship": edge["relationship"],
                                    "source": edge["source"],
                                    "target": edge["target"],
                                    "side": edge["side"],
                                    "evidence_state": edge["evidence_state"],
                                    "binding": index["graph"]["binding"],
                                }
                            )
                if related_edges:
                    rules.add("PRODUCER_CONSUMER_COMPATIBILITY")
                    relationship_sides: dict[tuple[int, str, str, str], set[str]] = {}
                    for branch_number, index in enumerate((current, target)):
                        for edge in index["edges"].values():
                            budget.step()
                            source, consumer = (
                                index["nodes"][edge["source"]],
                                index["nodes"][edge["target"]],
                            )
                            if source["path"] != path and consumer["path"] != path:
                                continue
                            key = (
                                source["path"] + ":" + source.get("symbol", ""),
                                consumer["path"] + ":" + consumer.get("symbol", ""),
                                edge["relationship"],
                            )
                            # Each branch's before/after is independent; never cancel
                            # one branch's removal with another's addition.
                            relationship_sides.setdefault(
                                (branch_number, *key), set()
                            ).add(edge["side"])
                    if any(
                        sides != {"before", "after"}
                        for sides in relationship_sides.values()
                    ):
                        rules.add("ADDED_REMOVED_RELATIONSHIP")
                for rule in sorted(rules):
                    budget.step()
                    notice: dict[str, Any] = {
                        "source_binding": current_graph["binding"],
                        "target_binding": graph["binding"],
                        "rule": rule,
                        "classification": "POTENTIAL",
                        "status": "UNKNOWN",
                        "path": path,
                        "symbols": symbols,
                        "source_node_ids": sorted(node["id"] for node in left),
                        "target_node_ids": sorted(node["id"] for node in right),
                        "dependency_paths": sorted(
                            related_edges,
                            key=lambda edge: (edge["binding"]["head"], edge["edge_id"]),
                        ),
                        "owner": None,
                        "delivery": "NOT_SENT",
                        "question": "Test the combined changes affecting "
                        + path
                        + " under rule "
                        + rule
                        + "; which contract remains valid or fails?",
                        "evidence": [],
                        "test_obligation": {
                            "layer": "preventative",
                            "status": "UNRUN",
                            ("required_binding"): (
                                "Exact isolated patch combination, "
                                "configuration and reproducible seed."
                            ),
                        },
                    }
                    notice["id"] = _notice_id(notice)
                    notices.append(notice)
        report["bounds"]["complete"] = True
    except _Exhausted:
        findings.append(
            _finding(
                "BOUND_EXHAUSTED",
                (
                    "Increase the explicit bound or broaden "
                    "validation; unexamined impact paths remain "
                    "unresolved."
                ),
            )
        )
    report["bounds"]["operations"] = budget.used
    notices.sort(key=lambda notice: notice["id"])
    report["verdict"] = (
        "FAIL" if any(item["verdict"] == "FAIL" for item in findings) else "UNKNOWN"
    )
    return report
