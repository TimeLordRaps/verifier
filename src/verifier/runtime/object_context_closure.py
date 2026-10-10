"""Fail-closed composition for selected object, context, and security evidence.

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). This module composes existing narrow recheckers. It
does not establish authority, permissions, release, actual history, or complete
object or security conformance.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
import re
from typing import Any

from verifier.core.certificate import canonical_bytes
from verifier.domains.contracts import application_requirements as application
from verifier.domains.contracts import certificate_dag as dag
from verifier.domains.contracts import current_object_routes as routes
from verifier.domains.contracts import selected_native_contexts as contexts
from verifier.domains.contracts import subject_security as security

SCHEMA_VERSION = "verifier-object-context-closure-assessment-1"
ANCESTRY_EVIDENCE_SCHEMA = "verifier-object-context-ancestry-evidence-1"
APPLICABILITY_SCHEMA = "verifier-object-context-applicability-denominator-1"
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MAX_BYTES = dag.MAX_BYTES
_COMPONENT_NAMES = ("compiler_manifest", "selected_context", "native_certificates",
                    "subject_security", "ancestry_evidence", "applicability_denominator")


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _hash(value: Any) -> bool:
    return type(value) is str and _HASH.fullmatch(value) is not None


def _component(status: str, reason: str, **details: Any) -> dict[str, Any]:
    return {"status": status, "reason": reason, **details}


def source_bindings() -> dict[str, str]:
    """Identify installed composition dependencies without asserting provenance."""
    paths = {"object_context_closure.py": Path(__file__),
        "OBJECT_CONTEXT_CLOSURE.md": Path(__file__).parents[1] / "standard" / "OBJECT_CONTEXT_CLOSURE.md",
        "application_requirements.py": Path(application.__file__),
        "certificate_dag.py": Path(dag.__file__),
        "current_object_routes.py": Path(routes.__file__),
        "selected_native_contexts.py": Path(contexts.__file__),
        "subject_security.py": Path(security.__file__)}
    return {name: hashlib.sha256(path.read_bytes()).hexdigest()
            for name, path in sorted(paths.items())}


def mechanism_digest() -> str:
    return _digest(canonical_bytes(source_bindings()))


def _strict_record(raw: Any, expected_digest: Any, label: str
        ) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    if raw is None or expected_digest is None:
        return None, _component("UNKNOWN", label.upper() + "_MISSING")
    if type(raw) is not bytes or not _hash(expected_digest):
        return None, _component("FAIL", label.upper() + "_SELECTION_INVALID")
    observed = _digest(raw)
    if observed != expected_digest:
        return None, _component("FAIL", label.upper() + "_DIGEST_DIFFERS",
            expected_digest=expected_digest, observed_digest=observed)
    if len(raw) > _MAX_BYTES:
        return None, _component("UNKNOWN", label.upper() + "_RESOURCE_BOUND_EXHAUSTED",
            expected_digest=expected_digest, observed_digest=observed)
    try:
        value = dag._parse(raw)
    except (RecursionError, OverflowError, MemoryError):
        return None, _component("UNKNOWN", label.upper() + "_PARSER_UNAVAILABLE",
            expected_digest=expected_digest, observed_digest=observed)
    except (ValueError, TypeError, KeyError, UnicodeError):
        return None, _component("FAIL", label.upper() + "_BYTES_REJECTED",
            expected_digest=expected_digest, observed_digest=observed)
    return value, _component("PASS", label.upper() + "_EXACT_BYTES_BOUND",
        expected_digest=expected_digest, observed_digest=observed)


def _compiler_manifest(raw: Any, selected_digest: Any,
                       context_policy: dict[str, Any] | None) -> dict[str, Any]:
    if raw is None or selected_digest is None:
        return _component("UNKNOWN", "COMPILER_MANIFEST_MISSING",
            compiler_closure_status="NOT_ESTABLISHED")
    if type(raw) is not bytes or not _hash(selected_digest):
        return _component("FAIL", "COMPILER_MANIFEST_SELECTION_INVALID",
            compiler_closure_status="NOT_ESTABLISHED")
    retained_bytes_digest = _digest(raw)
    if len(raw) > _MAX_BYTES:
        return _component("UNKNOWN", "COMPILER_MANIFEST_RESOURCE_BOUND_EXHAUSTED",
            manifest_digest=selected_digest, retained_bytes_digest=retained_bytes_digest,
            compiler_closure_status="NOT_ESTABLISHED")
    try:
        manifest = dag._parse(raw)
    except (RecursionError, OverflowError, MemoryError):
        return _component("UNKNOWN", "COMPILER_MANIFEST_PARSER_UNAVAILABLE",
            manifest_digest=selected_digest, retained_bytes_digest=retained_bytes_digest,
            compiler_closure_status="NOT_ESTABLISHED")
    except (ValueError, TypeError, KeyError, UnicodeError):
        return _component("FAIL", "COMPILER_MANIFEST_BYTES_REJECTED",
            manifest_digest=selected_digest, retained_bytes_digest=retained_bytes_digest,
            compiler_closure_status="NOT_ESTABLISHED")
    body = {key: value for key, value in manifest.items() if key != "manifest_digest"}
    if (manifest.get("schema_version") != application.SCHEMA
            or manifest.get("status") not in ("PASS", "FAIL", "UNKNOWN")
            or type(manifest.get("replayable")) is not bool
            or manifest.get("mechanism_digest") is not None
            and not _hash(manifest["mechanism_digest"])
            or manifest.get("manifest_digest") != selected_digest
            or _digest(canonical_bytes(body)) != selected_digest):
        return _component("FAIL", "COMPILER_MANIFEST_CONTRACT_OR_DIGEST_DIFFERS",
            manifest_digest=selected_digest, retained_bytes_digest=retained_bytes_digest,
            compiler_closure_status="NOT_ESTABLISHED")
    if context_policy is None:
        return _component("UNKNOWN", "CONTEXT_POLICY_UNAVAILABLE",
            manifest_digest=selected_digest, retained_bytes_digest=retained_bytes_digest,
            compiler_closure_status="NOT_ESTABLISHED")
    carried = context_policy.get("compiler_manifest_digest")
    if not _hash(carried) or carried != selected_digest:
        return _component("FAIL", "CONTEXT_COMPILER_MANIFEST_DIGEST_DIFFERS",
            manifest_digest=selected_digest, retained_bytes_digest=retained_bytes_digest,
            compiler_closure_status="NOT_ESTABLISHED")
    return _component("PASS", "COMPILER_MANIFEST_EXACT_BYTES_BOUND",
        manifest_digest=selected_digest, retained_bytes_digest=retained_bytes_digest,
        compiler_closure_status="NOT_ESTABLISHED")


def _selected_context(assessment_bytes: Any, expected_digest: Any, *,
        bundle_bytes: Any, dependency_policy_bytes: Any, context_policy_bytes: Any,
        artifact_files: Any) -> tuple[dict[str, Any], dict[str, Any] | None]:
    if assessment_bytes is None or expected_digest is None:
        return _component("UNKNOWN", "SELECTED_CONTEXT_ASSESSMENT_MISSING"), None
    if type(assessment_bytes) is not bytes or not _hash(expected_digest):
        return _component("FAIL", "SELECTED_CONTEXT_SELECTION_INVALID"), None
    if len(assessment_bytes) > _MAX_BYTES:
        return _component("UNKNOWN", "SELECTED_CONTEXT_RESOURCE_BOUND_EXHAUSTED"), None
    try:
        carried = dag._parse(assessment_bytes)
    except (RecursionError, OverflowError, MemoryError):
        return _component("UNKNOWN", "SELECTED_CONTEXT_PARSER_UNAVAILABLE"), None
    except (ValueError, TypeError, KeyError, UnicodeError):
        return _component("FAIL", "SELECTED_CONTEXT_ASSESSMENT_REJECTED"), None
    if carried.get("assessment_digest") != expected_digest:
        return _component("FAIL", "SELECTED_CONTEXT_ASSESSMENT_DIGEST_DIFFERS",
            expected_digest=expected_digest,
            observed_digest=carried.get("assessment_digest")), carried
    try:
        replay = contexts.recheck_selected_native_contexts_assessment(assessment_bytes,
            expected_mechanism_digest=contexts.mechanism_digest(),
            expected_assessment_digest=expected_digest, bundle_bytes=bundle_bytes,
            expected_dependency_policy_bytes=dependency_policy_bytes,
            expected_context_policy_bytes=context_policy_bytes,
            artifact_files=artifact_files)
    except (ImportError, OSError, MemoryError, RecursionError, OverflowError):
        return _component("UNKNOWN", "SELECTED_CONTEXT_RECHECKER_UNAVAILABLE",
            assessment_digest=expected_digest), carried
    except (ValueError, TypeError, KeyError, UnicodeError):
        return _component("FAIL", "SELECTED_CONTEXT_RECHECK_REJECTED",
            assessment_digest=expected_digest), carried
    if replay.get("status") == "FAIL" or replay.get("replay_status") == "REJECTED":
        status, reason = "FAIL", "SELECTED_CONTEXT_RECHECK_REFUTED"
    elif replay.get("status") == "PASS" and replay.get("replay_status") == "REPRODUCED":
        status, reason = "PASS", "SELECTED_CONTEXT_REPRODUCED"
    else:
        status, reason = "UNKNOWN", "SELECTED_CONTEXT_RECHECK_UNAVAILABLE"
    return _component(status, reason, assessment_digest=expected_digest,
        replay_digest=_digest(canonical_bytes(replay))), carried


def _native_certificates(bundle_bytes: Any, dependency_policy_bytes: Any,
                         artifact_files: Any) -> dict[str, Any]:
    try:
        report = dag.assess_certificate_dependencies(bundle_bytes,
            expected_policy_bytes=dependency_policy_bytes, artifact_files=artifact_files)
    except (ImportError, OSError, MemoryError, RecursionError, OverflowError):
        return _component("UNKNOWN", "NATIVE_DEPENDENCY_RECHECKER_UNAVAILABLE")
    except (ValueError, TypeError, KeyError, UnicodeError):
        return _component("FAIL", "NATIVE_DEPENDENCY_RECHECK_REJECTED")
    status = report.get("status")
    nodes = report.get("nodes") if type(report.get("nodes")) is list else []
    if status == "PASS" and nodes and all(type(node) is dict
            and node.get("direct_status") == node.get("qualified_status") == "PASS"
            and _hash(node.get("replay_digest")) for node in nodes):
        return _component("PASS", "ALL_SELECTED_NATIVE_CERTIFICATES_REPRODUCED",
            assessment_digest=report.get("assessment_digest"), node_count=len(nodes))
    if status == "FAIL":
        selected = "FAIL"
        reason = "NATIVE_CERTIFICATE_CONTRADICTION"
    elif status == "PASS":
        selected = "FAIL"
        reason = "NATIVE_PASS_WITHOUT_COMPLETE_REPLAY"
    else:
        selected = "UNKNOWN"
        reason = "NATIVE_CERTIFICATE_OR_MECHANISM_UNAVAILABLE"
    return _component(selected, reason, assessment_digest=report.get("assessment_digest"),
        node_count=len(nodes), blockers=report.get("blockers", []))


def _request_selector(request: Any) -> dict[str, str] | None:
    if type(request) is not dict or any(type(key) is not str for key in request):
        return None
    values = {name: request.get(name) for name in
        ("subject_id", "object_kind", "object_digest", "context_digest")}
    if (type(values["subject_id"]) is not str or not values["subject_id"].strip()
            or type(values["object_kind"]) is not str
            or not _hash(values["object_digest"]) or not _hash(values["context_digest"])):
        return None
    return values  # type: ignore[return-value]


def _subject_security(certificate_bytes: Any, request: Any, policy: Any, *,
        expected_context_digest: Any, context_policy: dict[str, Any] | None,
        context_report: dict[str, Any] | None,
        context_component_status: str) -> tuple[dict[str, Any], dict[str, str] | None]:
    if certificate_bytes is None or request is None or policy is None:
        return _component("UNKNOWN", "SUBJECT_SECURITY_SELECTION_MISSING"), None
    selector = _request_selector(request)
    if (type(certificate_bytes) is not bytes or type(policy) is not dict
            or selector is None):
        return _component("FAIL", "SUBJECT_SECURITY_SELECTION_INVALID"), selector
    if len(certificate_bytes) > _MAX_BYTES:
        return _component("UNKNOWN", "SUBJECT_SECURITY_RESOURCE_BOUND_EXHAUSTED"), selector
    if not _hash(expected_context_digest):
        return _component("UNKNOWN", "REPRODUCED_CONTEXT_DIGEST_UNAVAILABLE"), selector
    if selector["context_digest"] != expected_context_digest:
        return _component("FAIL", "SUBJECT_SECURITY_CONTEXT_DIGEST_DIFFERS",
            selected_context_digest=expected_context_digest,
            security_context_digest=selector["context_digest"]), selector
    try:
        replay = security.recheck_subject_security_certificate(certificate_bytes,
            expected_request=request, policy=policy)
    except (ImportError, OSError, MemoryError, RecursionError, OverflowError):
        return _component("UNKNOWN", "SUBJECT_SECURITY_RECHECKER_UNAVAILABLE"), selector
    except (ValueError, TypeError, KeyError, UnicodeError):
        return _component("FAIL", "SUBJECT_SECURITY_RECHECK_REJECTED"), selector
    if replay.get("status") == "FAIL":
        return _component("FAIL", "SUBJECT_SECURITY_CONTRADICTION",
            replay_digest=_digest(canonical_bytes(replay))), selector
    if replay.get("status") != "PASS":
        return _component("UNKNOWN", "SUBJECT_SECURITY_EVIDENCE_UNAVAILABLE",
            replay_digest=_digest(canonical_bytes(replay))), selector
    if context_component_status != "PASS" or context_policy is None or context_report is None:
        return _component("UNKNOWN", "REPRODUCED_SELECTED_CONTEXT_UNAVAILABLE",
            replay_digest=_digest(canonical_bytes(replay))), selector
    rows = context_policy.get("contexts")
    observations = context_report.get("rows")
    if type(rows) is not list or type(observations) is not list:
        return _component("FAIL", "SELECTED_CONTEXT_SUBJECT_INDEX_INVALID"), selector
    matching = [row for row in rows if type(row) is dict
        and row.get("subject_id") == selector["subject_id"]
        and row.get("object_kind") == selector["object_kind"]
        and row.get("object_digest") == selector["object_digest"]]
    observed = {row.get("node_id"): row for row in observations if type(row) is dict}
    if not matching or not any(type(observed.get(row.get("node_id"))) is dict
            and observed[row["node_id"]].get("status") == "PASS" for row in matching):
        return _component("FAIL", "SECURITY_SUBJECT_ABSENT_FROM_SELECTED_CONTEXT",
            replay_digest=_digest(canonical_bytes(replay))), selector
    return _component("PASS", "SUBJECT_SECURITY_REPRODUCED_AND_CONTEXT_BOUND",
        replay_digest=_digest(canonical_bytes(replay)),
        context_digest=expected_context_digest), selector


def _ancestry_evidence(raw: Any, expected_digest: Any,
                       selector: dict[str, str] | None) -> dict[str, Any]:
    value, result = _strict_record(raw, expected_digest, "ancestry_evidence")
    if result["status"] != "PASS":
        return result
    fields = {"schema_version", "subject_id", "object_digest", "evidence_kind",
              "admission", "actual_revision_history"}
    if (set(value or {}) != fields
            or value.get("schema_version") != ANCESTRY_EVIDENCE_SCHEMA
            or value.get("evidence_kind") != "DECLARED_REVISION_OR_ANCESTRY_EVIDENCE"
            or value.get("admission") != "EXTERNALLY_ADMITTED"
            or value.get("actual_revision_history") != "NOT_ESTABLISHED"):
        return _component("FAIL", "ANCESTRY_EVIDENCE_CONTRACT_DIFFERS",
            expected_digest=expected_digest, observed_digest=result["observed_digest"])
    if selector is None:
        return _component("UNKNOWN", "ANCESTRY_SUBJECT_SELECTION_UNAVAILABLE",
            expected_digest=expected_digest, observed_digest=result["observed_digest"])
    if (value["subject_id"] != selector["subject_id"]
            or value["object_digest"] != selector["object_digest"]):
        return _component("FAIL", "ANCESTRY_EVIDENCE_SUBJECT_DIFFERS",
            expected_digest=expected_digest, observed_digest=result["observed_digest"])
    result["actual_revision_history"] = "NOT_ESTABLISHED"
    return result


def _bundle_node_ids(bundle_bytes: Any) -> list[str] | None:
    if type(bundle_bytes) is not bytes or len(bundle_bytes) > _MAX_BYTES:
        return None
    try:
        bundle = dag._parse(bundle_bytes)
        nodes = bundle.get("nodes")
        if type(nodes) is not list:
            return None
        values = [node.get("node_id") for node in nodes if type(node) is dict]
        if len(values) != len(nodes) or any(type(value) is not str for value in values):
            return None
        return sorted(values)
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError, MemoryError):
        return None


def _applicability(raw: Any, expected_digest: Any, *,
        selector: dict[str, str] | None, context_digest: Any,
        node_ids: list[str] | None) -> dict[str, Any]:
    value, result = _strict_record(raw, expected_digest, "applicability_denominator")
    if result["status"] != "PASS":
        return result
    fields = {"schema_version", "subject_id", "object_digest",
              "context_assessment_digest", "node_ids", "admission",
              "complete_application_applicability"}
    if (set(value or {}) != fields
            or value.get("schema_version") != APPLICABILITY_SCHEMA
            or value.get("admission") != "EXTERNALLY_ADMITTED"
            or value.get("complete_application_applicability") != "NOT_ESTABLISHED"):
        return _component("FAIL", "APPLICABILITY_DENOMINATOR_CONTRACT_DIFFERS",
            expected_digest=expected_digest, observed_digest=result["observed_digest"])
    if selector is None or not _hash(context_digest) or node_ids is None:
        return _component("UNKNOWN", "APPLICABILITY_SELECTION_UNAVAILABLE",
            expected_digest=expected_digest, observed_digest=result["observed_digest"])
    if (value["subject_id"] != selector["subject_id"]
            or value["object_digest"] != selector["object_digest"]
            or value["context_assessment_digest"] != context_digest
            or value["node_ids"] != node_ids):
        return _component("FAIL", "APPLICABILITY_DENOMINATOR_DIFFERS",
            expected_digest=expected_digest, observed_digest=result["observed_digest"])
    result["complete_application_applicability"] = "NOT_ESTABLISHED"
    return result


def assess_object_context_closure(bundle_bytes: bytes, *,
        expected_dependency_policy_bytes: bytes,
        expected_context_policy_bytes: bytes,
        selected_context_assessment_bytes: bytes | None,
        expected_selected_context_assessment_digest: str | None,
        compiler_manifest_bytes: bytes | None,
        expected_compiler_manifest_digest: str | None,
        subject_security_certificate_bytes: bytes | None,
        expected_subject_security_request: dict[str, Any] | None,
        subject_security_policy: dict[str, Any] | None,
        ancestry_evidence_bytes: bytes | None,
        expected_ancestry_evidence_digest: str | None,
        applicability_denominator_bytes: bytes | None,
        expected_applicability_denominator_digest: str | None,
        artifact_files: dict[str, bytes]) -> dict[str, Any]:
    """Compose current exact rechecks; known contradictions dominate UNKNOWN."""
    input_digests = {name: _digest(value) for name, value in (
        ("bundle", bundle_bytes),
        ("dependency_policy", expected_dependency_policy_bytes),
        ("context_policy", expected_context_policy_bytes),
        ("selected_context_assessment", selected_context_assessment_bytes),
        ("compiler_manifest", compiler_manifest_bytes),
        ("subject_security_certificate", subject_security_certificate_bytes),
        ("ancestry_evidence", ancestry_evidence_bytes),
        ("applicability_denominator", applicability_denominator_bytes))
        if type(value) is bytes}
    try:
        installed_mechanism = mechanism_digest()
        installed_bindings = source_bindings()
        mechanism_status = "PASS"
    except (ImportError, OSError, MemoryError, RecursionError, OverflowError):
        installed_mechanism, installed_bindings = None, {}
        mechanism_status = "UNKNOWN"
    try:
        context_policy = (dag._parse(expected_context_policy_bytes)
            if type(expected_context_policy_bytes) is bytes
            and len(expected_context_policy_bytes) <= _MAX_BYTES else None)
    except (ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError, MemoryError):
        context_policy = None
    selected_component, context_report = _selected_context(
        selected_context_assessment_bytes,
        expected_selected_context_assessment_digest,
        bundle_bytes=bundle_bytes,
        dependency_policy_bytes=expected_dependency_policy_bytes,
        context_policy_bytes=expected_context_policy_bytes,
        artifact_files=artifact_files)
    components = {"compiler_manifest": _compiler_manifest(compiler_manifest_bytes,
            expected_compiler_manifest_digest, context_policy),
        "selected_context": selected_component,
        "native_certificates": _native_certificates(bundle_bytes,
            expected_dependency_policy_bytes, artifact_files)}
    security_component, selector = _subject_security(
        subject_security_certificate_bytes, expected_subject_security_request,
        subject_security_policy,
        expected_context_digest=expected_selected_context_assessment_digest,
        context_policy=context_policy, context_report=context_report,
        context_component_status=selected_component["status"])
    components["subject_security"] = security_component
    components["ancestry_evidence"] = _ancestry_evidence(ancestry_evidence_bytes,
        expected_ancestry_evidence_digest, selector)
    components["applicability_denominator"] = _applicability(
        applicability_denominator_bytes, expected_applicability_denominator_digest,
        selector=selector, context_digest=expected_selected_context_assessment_digest,
        node_ids=_bundle_node_ids(bundle_bytes))
    assert tuple(components) == _COMPONENT_NAMES
    statuses = [component["status"] for component in components.values()]
    status = ("FAIL" if "FAIL" in statuses else
              "PASS" if mechanism_status == "PASS" and all(item == "PASS" for item in statuses)
              else "UNKNOWN")
    result: dict[str, Any] = {"schema_version": SCHEMA_VERSION, "status": status,
        "mechanism_status": mechanism_status, "mechanism_digest": installed_mechanism,
        "source_bindings": installed_bindings, "input_digests": input_digests,
        "subject_id": selector["subject_id"] if selector else None,
        "object_digest": selector["object_digest"] if selector else None,
        "components": components,
        "authority": "NOT_ESTABLISHED", "permissions": "NOT_ESTABLISHED",
        "release": "NOT_ESTABLISHED", "whole_object_acceptance": "NOT_ESTABLISHED",
        "whole_security_conformance": "NOT_ESTABLISHED",
        "actual_revision_history": "NOT_ESTABLISHED",
        "object_profile_conformance": "NOT_ESTABLISHED",
        "claim_boundary": "Exact finite selected-context reproduction, native certificate replay, subject-security association, and externally admitted evidence bindings only. No authority, permission, release, source authenticity, actual revision history, complete applicability, whole security, or whole-object conclusion."}
    result["assessment_digest"] = _digest(canonical_bytes(result))
    return result
