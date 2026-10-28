"""Automatic shipped-gate discovery for the command-line interface (CLI).

Terminology: abstract syntax tree (AST); continuous integration (CI); JavaScript Object
Notation
(JSON); pull request (PR); Unicode Transformation Format, 8-bit (UTF-8);
Verifier Standard (VSTD). Local technical clearance
discharges no numbered profile or full polished-object, quality or safety claim.
Only installed callbacks run; artifact metadata never authorizes execution.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import tempfile
from typing import Any

from verifier.core.certificate import canonical_bytes
from verifier.runtime import gate
from verifier.runtime.artifact_snapshot import (
    Snapshot,
    capture,
    digest,
    implementation_digest,
    output_outside,
    read_bytes,
    record,
    write_new,
)
from verifier.runtime.polish_prepare import validate_preparation

SCHEMA = "verifier-gates-clearance-1"
BOUNDARY = (
    "Local technical clearance for the exact declared artifact "
    "and installed gates only. No complete nine-tier "
    "polished-object issuance, universal quality, safety, "
    "rights, provenance, moderation or publication guarantee."
)
DEFAULT_POLICY = {
    "schema_version": "verifier-gates-policy-1",
    "max_iterations": 1000000,
    "forbidden_terms": [],
    "selections": [],
    "required_gates": [],
}


def _path(value: Any) -> str:
    if (
        type(value) is not str
        or not value
        or len(value) > 1024
        or "\\" in value
        or ":" in value
        or value.startswith("/")
        or any(ord(c) < 32 for c in value)
        or any(p in {"", ".", ".."} for p in value.split("/"))
    ):
        raise ValueError("portable snapshot-relative path required")
    return value


def _policy(raw: bytes) -> dict[str, Any]:
    value = record(raw)
    if (
        set(value) != set(DEFAULT_POLICY)
        or value["schema_version"] != DEFAULT_POLICY["schema_version"]
    ):
        raise ValueError("unsupported exact gates policy")
    if (
        type(value["max_iterations"]) is not int
        or not 1 <= value["max_iterations"] <= 1000000
    ):
        raise ValueError("iteration bound cannot exceed installed ceiling")
    terms, required, selections = (
        value["forbidden_terms"],
        value["required_gates"],
        value["selections"],
    )
    if (
        type(terms) is not list
        or len(terms) > 128
        or any(type(t) is not str or not t.strip() or len(t) > 256 for t in terms)
        or type(required) is not list
        or len(required) > 1024
        or any(type(t) is not str or not t or len(t) > 256 for t in required)
        or len(set(required)) != len(required)
        or type(selections) is not list
        or len(selections) > 64
    ):
        raise ValueError("selection or policy bounds exceeded")
    seen = set()
    for row in selections:
        if type(row) is not dict or set(row) != {
            "gate_id",
            "path",
            "request",
            "policy",
            "represented_kind",
            "contract_version",
        }:
            raise ValueError("exact native replay selection required")
        if (
            type(row["gate_id"]) is not str
            or not row["gate_id"]
            or len(row["gate_id"]) > 256
        ):
            raise ValueError("gate identifier required")
        _path(row["path"])
        if type(row["request"]) is not dict or type(row["policy"]) is not dict:
            raise ValueError("external request and checker policy required")
        if (
            row["represented_kind"] is not None
            and type(row["represented_kind"]) is not str
        ):
            raise ValueError("represented kind required")
        if row["contract_version"] not in {"1", "2"}:
            raise ValueError("explicit supported contract version required")
        if row["policy"].get("witness_keys"):
            raise ValueError(
                "shared secret witness keys cannot be carried in public clearance"
            )
        if row["gate_id"] in {
            "paths",
            "ast",
            "boundary",
            "pr",
            "attest",
            "pipeline-check",
            "artifact-contract",
        }:
            raise ValueError(
                (
                    "native selections cannot redefine a shipped "
                    "scanner or metadata checker"
                )
            )
        identity = row["gate_id"], row["path"]
        if identity in seen:
            raise ValueError("duplicate native selection")
        seen.add(identity)
    text = raw.decode("utf-8")
    if any(pattern.search(text) for _, pattern in gate.SECRET_PATTERNS):
        raise ValueError("secret-bearing policy cannot be retained in clearance")
    return value


def shipped_registry() -> list[dict[str, Any]]:
    """Discover installed selected-gate checkers and current-object route
    registrations."""
    rows = [
        {"id": name, "version": "1", "scope": scope, "evidence_requirement": evidence}
        for name, scope, evidence in (
            (
                "artifact-contract",
                "registered retained artifact format",
                "supported artifact semantics and strict bounded JSON",
            ),
            ("paths", "known absolute-path text patterns", "retained UTF-8 text"),
            (
                "ast",
                "listed Python loop/allocation patterns",
                "retained valid Python source",
            ),
            (
                "boundary",
                "known secret and externally selected forbidden patterns",
                "retained text or supported archive",
            ),
            (
                "pr",
                "exact-source PRDEL description; metadata alone cannot clear",
                (
                    "snapshot PR description (*.pr.md), exact Git "
                    "base/head, selected requirements and supported "
                    "predicates"
                ),
            ),
            (
                "attest",
                "CI attestation integrity; execution remains unverified",
                "selected receipt and independently verified execution evidence",
            ),
            (
                "pipeline-check",
                "retained selected pipeline integrity",
                (
                    "external manifest, executable and interpreter "
                    "context; not artifact commands"
                ),
            ),
            (
                "polish-assess",
                "registered nine-tier prerequisite assessment",
                "external request and retained polish bundle",
            ),
            (
                "domain-check",
                "retained native domain certificate replay",
                "external native request/policy and certificate",
            ),
        )
    ]
    from verifier.domains.contracts.current_object_routes import (
        current_object_route_catalog,
    )

    for route in current_object_route_catalog():
        rows.append(
            {
                "id": "current-object:"
                + route["semantic_version"]
                + ":"
                + route["objective"],
                "version": "1",
                "scope": route["scope"],
                ("evidence_requirement"): (
                    "external request/policy, represented kind and "
                    "exact retained certificate"
                ),
                "route": route,
            }
        )
    return sorted(rows, key=lambda row: row["id"])


def _documents(snapshot: Snapshot) -> dict[str, dict[str, Any]]:
    documents = {}
    for name, raw in sorted(snapshot.files.items()):
        if Path(name).suffix == ".json":
            documents[name] = record(raw)
    return documents


def _row(
    descriptor: dict[str, Any],
    status: str,
    reason: str,
    *,
    applicability: str = "APPLICABLE",
    evidence: list[dict[str, Any]] | None = None,
    results: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "gate_id": descriptor["id"],
        "version": descriptor["version"],
        "applicability": applicability,
        "status": status,
        "reason": reason,
        "evidence_requirement": descriptor["evidence_requirement"],
        "evidence": evidence or [],
        "results": results or [],
    }


def _status(statuses: list[str]) -> str:
    return (
        "FAIL"
        if any(s in {"FAIL", "REJECTED"} for s in statuses)
        else "UNKNOWN" if any(s != "PASS" for s in statuses) else "PASS"
    )


def _format(descriptor: dict[str, Any], snapshot: Snapshot) -> dict[str, Any]:
    documents = _documents(snapshot)
    routes = [r["route"] for r in shipped_registry() if "route" in r]
    known = {r["certificate_schema_version"] for r in routes} | {
        "verifier-ci-attestation-1",
        "verifier-gate-pipeline-receipt-1",
        "verifier-polish-bundle-1",
        "verifier-polish-bundle-2",
    }
    unsupported = [
        p
        for p in snapshot.files
        if not gate._text_candidate(Path(p))
        or p.lower().endswith(gate.ARCHIVE_SUFFIXES)
    ]
    unsupported += [
        p for p, doc in documents.items() if doc.get("schema_version") not in known
    ]
    for p, doc in documents.items():
        family = [
            r
            for r in routes
            if r["certificate_schema_version"] == doc.get("schema_version")
        ]
        if family:
            selection = doc.get("request")
            if type(selection) is not dict or not any(
                selection.get("coordinate") == r["objective"]
                and selection.get("semantic_version") == r["semantic_version"]
                for r in family
            ):
                unsupported.append(p)
    return _row(
        descriptor,
        "UNSUPPORTED" if unsupported else "PASS",
        (
            "ARTIFACT_SEMANTIC_CHECKER_UNREGISTERED"
            if unsupported
            else "RETAINED_FORMAT_RECOGNIZED"
        ),
        evidence=[
            {"path": p, "digest": digest(snapshot.files[p])}
            for p in sorted(set(unsupported))
        ],
    )


def _native(
    descriptor: dict[str, Any],
    snapshot: Snapshot,
    documents: dict[str, dict[str, Any]],
    selections: list[dict[str, Any]],
) -> dict[str, Any]:
    selected = [r for r in selections if r["gate_id"] == descriptor["id"]]
    name = descriptor["id"]
    if name.startswith("current-object:"):
        route = descriptor["route"]
        detected = [
            p
            for p, doc in documents.items()
            if doc.get("schema_version") == route["certificate_schema_version"]
            and (
                not isinstance(doc.get("request"), dict)
                or doc["request"].get("coordinate") in {None, route["objective"]}
            )
        ]
    else:
        identifiers = {
            "domain-check": {
                "verifier-domain-certification-1",
                "verifier-domain-evidence-1",
            },
            "polish-assess": {"verifier-polish-bundle-1", "verifier-polish-bundle-2"},
        }[name]
        detected = [
            p
            for p, doc in documents.items()
            if doc.get("schema_version") in identifiers
        ]
    evidence = [{"path": p, "digest": digest(snapshot.files[p])} for p in detected]
    if not detected and not selected:
        return _row(
            descriptor,
            "SKIP",
            "NO_MATCHING_RETAINED_CONTRACT",
            applicability="NOT_APPLICABLE",
        )
    if name == "domain-check":
        return _row(
            descriptor,
            "UNSUPPORTED",
            "LEGACY_DOMAIN_CERTIFICATION_RETIRED",
            evidence=evidence,
        )
    selected_paths = {r["path"] for r in selected}
    needs_selection = [
        p
        for p in detected
        if documents[p].get("schema_version") != "verifier-domain-evidence-1"
    ]
    if not selected or any(p not in selected_paths for p in needs_selection):
        return _row(
            descriptor,
            "UNKNOWN",
            "EXTERNAL_REPLAY_SELECTION_MISSING",
            evidence=evidence,
        )
    from verifier.domains.contracts.current_object_routes import CurrentObjectRouteUnavailable

    results = []
    for selection in selected:
        raw = snapshot.files.get(selection["path"])
        if raw is None:
            results.append({"status": "UNKNOWN", "reason": "RETAINED_EVIDENCE_MISSING"})
            continue
        binding = {
            "certificate_digest": digest(raw),
            "request_digest": digest(canonical_bytes(selection["request"])),
            "policy_digest": digest(canonical_bytes(selection["policy"])),
        }
        try:
            if name == "polish-assess":
                from verifier.runtime.polish import assess_polish

                result = assess_polish(
                    raw,
                    request_bytes=canonical_bytes(selection["request"]),
                    contract_version=selection["contract_version"],
                )
            else:
                from verifier.domains.contracts.current_object_routes import (
                    replay_current_object_certificate,
                )

                replay = replay_current_object_certificate(
                    raw,
                    semantic_version=route["semantic_version"],
                    objective=route["objective"],
                    represented_kind=selection["represented_kind"],
                    expected_request=selection["request"],
                    policy=selection["policy"],
                )
                if (
                    replay["schema_version"]
                    != "verifier-current-object-route-replay-"
                    + selection["contract_version"]
                ):
                    raise ValueError(
                        (
                            "native replay contract differs from "
                            "externally selected version"
                        )
                    )
                result = {
                    "status": replay["computational_status"],
                    "replay_status": replay["replay_status"],
                }
                if replay["replay_status"] != "REPRODUCED":
                    result["status"] = "UNKNOWN"
            status = result.get("status", "UNKNOWN")
            if status not in {"PASS", "FAIL", "UNKNOWN", "REJECTED"}:
                status = "UNKNOWN"
            results.append(
                {
                    **binding,
                    "status": status,
                    "reason": "NATIVE_REPLAY",
                    "result_digest": digest(canonical_bytes(result)),
                }
            )
        except (CurrentObjectRouteUnavailable, ImportError, OSError):
            results.append(
                {
                    **binding,
                    "status": "UNKNOWN",
                    "reason": "CHECKER_OR_DEPENDENCY_UNAVAILABLE",
                }
            )
        except (ValueError, TypeError, KeyError, RecursionError, OverflowError):
            results.append(
                {**binding, "status": "REJECTED", "reason": "NATIVE_REPLAY_REJECTED"}
            )
    return _row(
        descriptor,
        _status([r["status"] for r in results]),
        "NATIVE_REPLAY",
        evidence=evidence,
        results=results,
    )


def _run(
    descriptor: dict[str, Any],
    snapshot: Snapshot,
    documents: dict[str, dict[str, Any]],
    directory: Path,
    policy: dict[str, Any],
) -> dict[str, Any]:
    name = descriptor["id"]
    if name == "artifact-contract":
        return _format(descriptor, snapshot)
    if name in {"paths", "ast", "boundary"}:
        candidates = [
            p
            for p in snapshot.files
            if gate._text_candidate(Path(p))
            or name == "boundary"
            and p.lower().endswith(gate.ARCHIVE_SUFFIXES)
        ]
        if name == "ast":
            candidates = [p for p in snapshot.files if Path(p).suffix == ".py"]
        if not candidates:
            return _row(
                descriptor,
                "SKIP",
                "NO_MATCHING_RETAINED_FILES",
                applicability="NOT_APPLICABLE",
            )
        if name == "paths":
            scanned, violations = gate.run_paths_gate(
                directory, ignored_parts=frozenset()
            )
        elif name == "ast":
            scanned, violations = gate.run_ast_gate(
                directory,
                max_iterations=policy["max_iterations"],
                ignored_parts=frozenset(),
            )
        else:
            scanned, violations = gate.run_boundary_gate(
                directory,
                forbidden_terms=policy["forbidden_terms"],
                ignored_parts=frozenset(),
            )
        incomplete = any(v.get("kind") == "incomplete_scan" for v in violations)
        substantive = any(v.get("kind") != "incomplete_scan" for v in violations)
        status = (
            "FAIL"
            if substantive
            else "UNKNOWN" if incomplete or not scanned else "PASS"
        )
        results = [
            {
                "line": int(v.get("line", 0)),
                "kind": v.get("kind", "absolute_path"),
                "finding_index": i,
            }
            for i, v in enumerate(violations, 1)
        ]
        return _row(
            descriptor,
            status,
            "RETAINED_SNAPSHOT_SCAN",
            evidence=[
                {
                    "scanned_files": scanned,
                    "input_inventory_digest": digest(
                        canonical_bytes(snapshot.inventory()["files"])
                    ),
                }
            ],
            results=results,
        )
    if name == "pr":
        paths = [p for p in snapshot.files if p.endswith(".pr.md")]
        if not paths:
            return _row(
                descriptor,
                "SKIP",
                "NO_PR_DESCRIPTION_IN_DECLARED_SCOPE",
                applicability="NOT_APPLICABLE",
            )
        results = []
        for p in paths:
            # A generic retained artifact has no independently selected Git
            # context. Never substitute the checker's own current working tree.
            results.append(
                {
                    "status": "UNKNOWN",
                    "input_digest": digest(snapshot.files[p]),
                    "reason": "EXACT_PR_SOURCE_CONTEXT_MISSING",
                    ("question"): (
                        "Use vstd gate pr with the exact repository, "
                        "base/head and selected requirements."
                    ),
                }
            )
        return _row(
            descriptor,
            _status([r["status"] for r in results]),
            "DESCRIPTION_METADATA_ONLY",
            results=results,
        )
    if name in {"attest", "pipeline-check"}:
        schema = (
            "verifier-ci-attestation-1"
            if name == "attest"
            else "verifier-gate-pipeline-receipt-1"
        )
        paths = [
            p for p, doc in documents.items() if doc.get("schema_version") == schema
        ]
        if not paths:
            return _row(
                descriptor,
                "SKIP",
                "NO_MATCHING_RETAINED_CONTRACT",
                applicability="NOT_APPLICABLE",
            )
        results = []
        for p in paths:
            doc = documents[p]
            valid = doc.get("receipt_digest") == digest(
                canonical_bytes({k: v for k, v in doc.items() if k != "receipt_digest"})
            )
            if name == "attest" and doc.get("signer_kind") == "CANONICAL-SHA256":
                valid = valid and gate.verify_ci_attestation_receipt(doc)[0]
            results.append(
                {
                    "input_digest": digest(snapshot.files[p]),
                    "status": "UNKNOWN" if valid else "FAIL",
                }
            )
        if any(r["status"] == "FAIL" for r in results):
            return _row(
                descriptor,
                "FAIL",
                "RETAINED_RECEIPT_INTEGRITY_REJECTED",
                results=results,
            )
        # Self-consistent attestation is not independent execution. Carried pipeline
        # locators cannot select filesystem reads, commands or credentials here.
        return _row(
            descriptor,
            "UNKNOWN",
            (
                "INDEPENDENT_EXECUTION_EVIDENCE_REQUIRED"
                if name == "attest"
                else "EXTERNAL_PIPELINE_CONTEXT_REQUIRED"
            ),
            evidence=[{"path": p, "digest": digest(snapshot.files[p])} for p in paths],
            results=results,
        )
    return _native(descriptor, snapshot, documents, policy["selections"])


def run_gates(
    artifact_path: str | Path,
    *,
    polish_report_bytes: bytes | None,
    policy_bytes: bytes | None = None,
    dependency_bundle_bytes: bytes | None = None,
    dependency_policy_bytes: bytes | None = None,
    preparation_contract_bytes: bytes | None = None,
    expected_preparation_contract_digest: str | None = None,
    git_root: str | Path | None = None,
) -> dict[str, Any]:
    """Run every registered applicable gate over one retained snapshot, serially."""
    raw_policy = (
        canonical_bytes(DEFAULT_POLICY) if policy_bytes is None else policy_bytes
    )
    policy = _policy(raw_policy)
    snapshot = capture(artifact_path)
    implementation = implementation_digest()
    preparation = (
        record(polish_report_bytes) if polish_report_bytes is not None else None
    )
    registry = shipped_registry()
    registry_ids = {row["id"] for row in registry}
    rows = []
    try:
        if polish_report_bytes is None:
            raise ValueError("preparation missing")
        if preparation.get("schema_version") == "verifier-polish-workflow-report-1":
            from verifier.runtime.polish_workflow_replay import (
                validate_workflow_preparation,
            )

            validate_workflow_preparation(
                polish_report_bytes,
                artifact_path,
                snapshot,
                contract_bytes=preparation_contract_bytes,
                expected_contract_digest=expected_preparation_contract_digest,
                git_root=git_root,
            )
        else:
            if (
                preparation_contract_bytes is not None
                or expected_preparation_contract_digest is not None
                or git_root is not None
            ):
                raise ValueError("workflow replay inputs require a workflow report")
            validate_preparation(polish_report_bytes, snapshot)
        preparation_status = "PASS"
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        preparation_status = "UNKNOWN" if preparation is None else "FAIL"
    try:
        documents = _documents(snapshot)
    except (ValueError, UnicodeError, RecursionError):
        documents = {}
    with tempfile.TemporaryDirectory(prefix="vstd-gates-") as temporary:
        directory = Path(temporary)
        snapshot.materialize(directory)
        for descriptor in registry:
            try:
                row = _run(descriptor, snapshot, documents, directory, policy)
            except (ImportError, OSError):
                row = _row(descriptor, "UNKNOWN", "CHECKER_OR_DEPENDENCY_UNAVAILABLE")
            except (
                ValueError,
                TypeError,
                KeyError,
                UnicodeError,
                RecursionError,
                OverflowError,
            ):
                row = _row(descriptor, "FAIL", "CHECKER_INPUT_REFUSED")
            if descriptor["id"] in policy["required_gates"] and row["status"] == "SKIP":
                row = _row(descriptor, "UNKNOWN", "POLICY_REQUIRED_EVIDENCE_MISSING")
            rows.append(row)
    unknown_ids = set(policy["required_gates"]) | {
        s["gate_id"] for s in policy["selections"]
    }
    for identifier in sorted(unknown_ids - registry_ids):
        rows.append(
            {
                "gate_id": identifier,
                "version": None,
                "applicability": "APPLICABLE",
                "status": "UNSUPPORTED",
                "reason": "UNREGISTERED_CHECKER",
                "evidence_requirement": "installed registered checker",
                "evidence": [],
                "results": [],
            }
        )
    rows.sort(key=lambda row: row["gate_id"])
    dependency = None
    if dependency_bundle_bytes is not None or dependency_policy_bytes is not None:
        from verifier.domains.contracts.certificate_dag import (
            assess_certificate_dependencies,
        )

        dependency = assess_certificate_dependencies(
            dependency_bundle_bytes,
            expected_policy_bytes=dependency_policy_bytes,
            artifact_files=snapshot.files,
        )
    try:
        unchanged = (
            capture(artifact_path).inventory() == snapshot.inventory()
            and implementation_digest() == implementation
        )
    except (OSError, ValueError):
        unchanged = False
    status = _status(
        [preparation_status]
        + [r["status"] for r in rows if r["status"] != "SKIP"]
        + ([dependency["status"]] if dependency is not None else [])
    )
    if not unchanged:
        status = "FAIL"
    result = {
        "schema_version": SCHEMA,
        "artifact": snapshot.inventory(),
        "policy_json": raw_policy.decode("utf-8"),
        "policy_digest": digest(raw_policy),
        "registry": registry,
        "registry_digest": digest(canonical_bytes(registry)),
        "implementation_digest": implementation,
        "polish_report": preparation,
        "polish_report_digest": (
            digest(canonical_bytes(preparation)) if preparation is not None else None
        ),
        "gates": rows,
        "coverage": {
            "registered": len(registry),
            "applicable": sum(r["applicability"] == "APPLICABLE" for r in rows),
            "passed": sum(r["status"] == "PASS" for r in rows),
            "preparation_status": preparation_status,
        },
        "exclusions": [
            {
                "gate_id": r["gate_id"],
                "reason": r["reason"],
                "evidence_requirement": r["evidence_requirement"],
            }
            for r in rows
            if r["status"] == "SKIP"
        ],
        "inputs_unchanged": unchanged,
        "status": status,
        "clearance": "CLEAR" if status == "PASS" else "NOT_CLEAR",
        "claim_boundary": BOUNDARY,
    }
    if dependency is not None:
        result.update(
            schema_version="verifier-gates-clearance-2",
            dependency_bundle_json=(
                dependency_bundle_bytes.decode("utf-8")
                if type(dependency_bundle_bytes) is bytes
                else None
            ),
            dependency_policy_digest=(
                digest(dependency_policy_bytes)
                if type(dependency_policy_bytes) is bytes
                else None
            ),
            dependency_assessment=dependency,
            qualification=(
                "SELECTED_CLAIM_DEPENDENCY_CLOSURE"
                if dependency["status"] == "PASS"
                else "NOT_ESTABLISHED"
            ),
            polished=False,
        )
    if (
        preparation is not None
        and preparation.get("schema_version") == "verifier-polish-workflow-report-1"
        or preparation_contract_bytes is not None
        or expected_preparation_contract_digest is not None
    ):
        result.update(
            schema_version="verifier-gates-clearance-3",
            preparation_contract_json=(
                preparation_contract_bytes.decode("utf-8")
                if preparation_contract_bytes is not None
                else None
            ),
            preparation_contract_digest=(
                digest(preparation_contract_bytes)
                if preparation_contract_bytes is not None
                else None
            ),
            preparation_replay_scope="CURRENT_SELECTED_CHECKS_AND_EXISTING_SOURCE_PROSE_ADMISSION",
            execution_authentication="NOT_ESTABLISHED",
            polished=False,
        )
    result["clearance_id"] = digest(canonical_bytes(result))
    return result


def validate_clearance(
    clearance_bytes: bytes,
    artifact_path: str | Path,
    *,
    expected_policy_bytes: bytes | None = None,
    expected_dependency_policy_bytes: bytes | None = None,
    expected_preparation_contract_bytes: bytes | None = None,
    expected_preparation_contract_digest: str | None = None,
    git_root: str | Path | None = None,
) -> dict[str, Any]:
    """Fully replay using the consumer's policy; carried flags and signatures confer no
    trust."""
    stored = record(clearance_bytes)
    expected_policy = (
        canonical_bytes(DEFAULT_POLICY)
        if expected_policy_bytes is None
        else expected_policy_bytes
    )
    if stored.get("policy_json") != expected_policy.decode("utf-8"):
        raise ValueError("clearance policy differs from externally expected policy")
    dependency_bundle = None
    if (
        stored.get("schema_version")
        in {"verifier-gates-clearance-2", "verifier-gates-clearance-3"}
        and "dependency_bundle_json" in stored
    ):
        if expected_dependency_policy_bytes is None:
            raise ValueError(
                "independently selected dependency profile policy required"
            )
        if stored.get("dependency_policy_digest") != digest(
            expected_dependency_policy_bytes
        ):
            raise ValueError(
                "dependency profile policy differs from externally expected policy"
            )
        if type(stored.get("dependency_bundle_json")) is not str:
            raise ValueError("certificate dependency bundle required")
        dependency_bundle = stored["dependency_bundle_json"].encode("utf-8")
    elif expected_dependency_policy_bytes is not None:
        raise ValueError("version 2 certificate dependency clearance required")
    if stored.get("schema_version") == "verifier-gates-clearance-3":
        if (
            expected_preparation_contract_bytes is None
            or expected_preparation_contract_digest is None
        ):
            raise ValueError(
                "independently selected preparation contract and digest required"
            )
        if stored.get(
            "preparation_contract_json"
        ) != expected_preparation_contract_bytes.decode("utf-8"):
            raise ValueError(
                "preparation replay contract differs from independently selected bytes"
            )
    elif (
        expected_preparation_contract_bytes is not None
        or expected_preparation_contract_digest is not None
        or git_root is not None
    ):
        raise ValueError("version 3 workflow preparation clearance required")
    preparation = stored.get("polish_report")
    reproduced = run_gates(
        artifact_path,
        polish_report_bytes=(
            canonical_bytes(preparation) if preparation is not None else None
        ),
        policy_bytes=expected_policy,
        dependency_bundle_bytes=dependency_bundle,
        dependency_policy_bytes=expected_dependency_policy_bytes,
        preparation_contract_bytes=expected_preparation_contract_bytes,
        expected_preparation_contract_digest=expected_preparation_contract_digest,
        git_root=git_root,
    )
    if canonical_bytes(stored) != canonical_bytes(reproduced):
        raise ValueError("clearance is stale, forged, incomplete or does not replay")
    if reproduced["status"] != "PASS" or reproduced["clearance"] != "CLEAR":
        raise ValueError("clearance has unresolved gates")
    return reproduced


def add_gates_parser(subparsers: Any) -> None:
    parser = subparsers.add_parser(
        "gates", help="Run all applicable shipped gates on an exact artifact snapshot."
    )
    parser.add_argument("artifact", nargs="?")
    parser.add_argument(
        "--catalog",
        action="store_true",
        help="List every installed gate and native replay route.",
    )
    parser.add_argument(
        "--polish-report",
        help=(
            "Exact preparation report. Workflow reports require a "
            "separately selected replay contract."
        ),
    )
    parser.add_argument(
        "--preparation-contract",
        help=(
            "Separately selected verifier-gates-workflow-preparation-"
            "contract-1 bytes."
        ),
    )
    parser.add_argument(
        "--preparation-contract-digest",
        help="Exact independently selected preparation contract digest (sha256:...).",
    )
    parser.add_argument(
        "--git-root",
        help=(
            "Git object source for explicitly selected committed "
            "preparation analysis."
        ),
    )
    parser.add_argument(
        "--policy",
        help="External bounded gate policy; omitted selects installed defaults.",
    )
    parser.add_argument(
        "--dependency-bundle",
        help="Exact versioned certificate claim graph; produces clearance version 2.",
    )
    parser.add_argument(
        "--dependency-policy",
        help="Independently selected approved profile and exact claim bindings.",
    )
    parser.add_argument(
        "--check",
        help="Independently replay an existing clearance under the selected policy.",
    )
    parser.add_argument(
        "--output", help="Create a new clearance outside the selected artifact."
    )
    parser.add_argument("--json", action="store_true")


def handle_gates_command(args: argparse.Namespace) -> int:
    try:
        if args.catalog:
            if (
                args.artifact
                or args.check
                or args.output
                or args.polish_report
                or args.policy
                or args.dependency_bundle
                or args.dependency_policy
                or args.preparation_contract
                or args.preparation_contract_digest
                or args.git_root
            ):
                raise ValueError("catalog cannot mix with artifact operations")
            result = {
                "schema_version": "verifier-gates-catalog-1",
                "status": "PASS",
                "gates": shipped_registry(),
                "claim_boundary": BOUNDARY,
            }
        else:
            if not args.artifact:
                raise ValueError("artifact required")
            output_outside(args.output, args.artifact)
            policy = read_bytes(args.policy) if args.policy else None
            dependency_policy = (
                read_bytes(args.dependency_policy) if args.dependency_policy else None
            )
            preparation_contract = (
                read_bytes(args.preparation_contract)
                if args.preparation_contract
                else None
            )
            if args.check:
                if args.dependency_bundle or args.polish_report:
                    raise ValueError("replay uses the exact retained dependency bundle")
                result = validate_clearance(
                    read_bytes(args.check),
                    args.artifact,
                    expected_policy_bytes=policy,
                    expected_dependency_policy_bytes=dependency_policy,
                    expected_preparation_contract_bytes=preparation_contract,
                    expected_preparation_contract_digest=args.preparation_contract_digest,
                    git_root=args.git_root,
                )
            else:
                preparation = (
                    read_bytes(args.polish_report) if args.polish_report else None
                )
                result = run_gates(
                    args.artifact,
                    polish_report_bytes=preparation,
                    policy_bytes=policy,
                    dependency_bundle_bytes=(
                        read_bytes(args.dependency_bundle)
                        if args.dependency_bundle
                        else None
                    ),
                    dependency_policy_bytes=dependency_policy,
                    preparation_contract_bytes=preparation_contract,
                    expected_preparation_contract_digest=args.preparation_contract_digest,
                    git_root=args.git_root,
                )
            write_new(args.output, result)
    except (OSError, ImportError):
        result = {
            "schema_version": SCHEMA,
            "status": "UNKNOWN",
            "clearance": "NOT_CLEAR",
            "reason": "INPUT_OR_CHECKER_UNAVAILABLE",
            "claim_boundary": BOUNDARY,
        }
    except (
        ValueError,
        TypeError,
        KeyError,
        UnicodeError,
        RecursionError,
        OverflowError,
    ):
        result = {
            "schema_version": SCHEMA,
            "status": "FAIL",
            "clearance": "NOT_CLEAR",
            "reason": "CLEARANCE_OR_INPUT_REJECTED",
            "claim_boundary": BOUNDARY,
        }
    if args.json:
        print(json.dumps(result, sort_keys=True, allow_nan=False))
    else:
        print("[" + result["status"] + "] " + result.get("clearance", "CATALOG"))
        for row in result.get("gates", []):
            print(
                row.get("gate_id", row.get("id")),
                row.get("status", "REGISTERED"),
                row.get("reason", row.get("evidence_requirement")),
            )
        print(BOUNDARY)
    return {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}[result["status"]]
