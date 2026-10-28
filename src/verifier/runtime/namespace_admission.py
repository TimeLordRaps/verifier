"""Extensible Tier-0 repository admission for Verifier Standard (VSTD).

Conceptual boundaries:
* discovery observes bytes and Python definitions without running the repository;
* classification derives obligations independently of the preferred object label;
* admission checks declarations and bindings, never financial correctness;
* independent reconciliation compares the two interpretations of selected inputs.

JavaScript Object Notation (JSON); command-line interface (CLI).
"""
from __future__ import annotations

from collections import Counter
import os
from pathlib import Path
import json
import re
import shutil
import subprocess
import tempfile
import time
from typing import Any, Sequence

from verifier.runtime import namespace_classification as classification
from verifier.runtime import namespace_contracts as contracts
from verifier.runtime import namespace_consequences as consequences
from verifier.runtime import namespace_discovery as discovery
from verifier.runtime import namespace_manifest as manifests
from verifier.runtime import package_harness_applicability
from verifier.runtime.tier_zero_reasoning import integration as reason_integration
from verifier.runtime.self_polish_estate import bytes_digest
from verifier.runtime.tier_zero_profile import canonical_bytes, value_digest


REPORT_SCHEMA = "verifier-tier-zero-repository-admission-report-2"
PROFILE_ID = "vstd-tier-zero-repository-admission-2"
_STANDARD_RECONCILIATION_TIMEOUT_SECONDS = 20
_PACKAGE_RECONCILIATION_TIMEOUT_SECONDS = 80
BOUNDARY = ("Bounded repository declaration admission, Python static definition coverage and current evidence-reference binding only. "
            "Classification reasons are repository-authored, not independently authenticated semantic proofs. "
            "No Tier-1-plus, financial correctness, safety, release or deployment claim is established.")
_DIMENSIONS = (
    ("Canonical manifest admission", "Ambiguous declarations let different readers assess different systems."),
    ("Object classification and applicability", "A broad or misleading label must not suppress necessary kind obligations."),
    ("Typed base and consequence composition", "Unbound, mistyped or hidden external-effect paths conceal dependencies and necessary roles."),
    ("Exact discovered-surface coverage", "Owning a file or category does not cover an unlisted definition."),
    ("Extensible obligation denominator", "Installed and inherited requirements must survive refinement and relabeling."),
    ("Reasons and source-bound declarations", "Each requirement needs both a standard reason and a current repository-specific explanation."),
    ("Source and mechanism freshness", "Evidence for changing or stale bytes does not describe one reproducible assessment."),
    ("Independent declaration reconciliation", "One implementation must not be the only interpreter of the selected portable declaration."),
    ("Conservative assurance boundary", "Declaration completeness must never be promoted to semantic correctness or permission."),
)


def profile() -> dict[str, Any]:
    rows = [{"coordinate": "VSTD-T0." + str(index), "name": name, "rationale": reason}
            for index, (name, reason) in enumerate(_DIMENSIONS, 1)]
    body = {"profile_id": PROFILE_ID, "manifest_schema": manifests.SCHEMA, "obligations": rows,
            "claim_boundary": BOUNDARY}
    return {**body, "profile_digest": value_digest(body)}


def mechanism_binding() -> dict[str, str]:
    """Bind the installed mechanism, not a same-named file supplied by the subject."""
    root = Path(__file__).parents[1]
    paths = ("runtime/namespace_admission.py", "runtime/namespace_manifest.py",
             "runtime/namespace_contracts.py", "runtime/namespace_discovery.py",
             "runtime/namespace_exports.py", "runtime/namespace_metadata.py",
             "runtime/namespace_javascript.py", "runtime/namespace_javascript_worker.py",
             "runtime/namespace_systems.py", "runtime/namespace_systems_worker.py",
             "runtime/namespace_html.py",
             "runtime/namespace_svg.py", "runtime/namespace_workflows.py", "runtime/namespace_workflow_worker.py",
             "runtime/namespace_classification.py", "runtime/namespace_refutation.py",
             "runtime/tier_zero_reasoning/integration.py",
             "runtime/tier_zero_reasoning/reasons_dsl.py",
             # The closed-effect audit that must be CLOSED before a witness may establish.
             "runtime/package_original_kind_review.py",
             "runtime/namespace_reconcile.mjs",
             "runtime/namespace_consequences.py", "runtime/namespace_consequences.mjs",
             "runtime/namespace_dominance.py",
             "runtime/package_manifest.py",
             "runtime/package_instance_evidence.py",
             "runtime/local_ledger_execution.py",
             "runtime/package_execution.py", "runtime/manifest_write_execution.py",
             "runtime/package_execution_observation.py",
             "runtime/package_harness_applicability.py",
             "runtime/worker_protocol_execution.py",
             "runtime/tier_zero_manifest.py", "runtime/tier_zero_profile.py",
             "runtime/self_polish_estate.py", "core/namespace.py", "core/certificate.py",
             "schemas/verifier-objects-manifest-2.schema.json",
             "schemas/verifier-namespace-manifest-3.schema.json",
             "standard/EXTENSIBLE_NAMESPACE.md")
    paths += (
        "schemas/verifier-objects-manifest-4.schema.json",
        "schemas/verifier-objects-manifest-5.schema.json",
        "schemas/verifier-objects-manifest-6.schema.json",
    )
    return {path: bytes_digest((root / path).read_bytes()) for path in paths}


def build_template(source_root: str | Path = ".", *,
                   extensions: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    """Generate an honest draft. Do not invent reasons or attest non-applicability."""
    root = Path(source_root).resolve(strict=True)
    observed = discovery.discover(root)
    selected_extensions = extensions or []
    registry = contracts.namespace_registry(selected_extensions)
    objects = []
    paths = sorted({row["path"] for row in observed["surfaces"]})
    for path in paths:
        surfaces = [row for row in observed["surfaces"] if row["path"] == path]
        source_kinds = {kind for row in surfaces for kind in row["source_kinds"] if kind in registry}
        extension_kinds = sorted(kind for kind in source_kinds if registry[kind].extends is not None)
        base_kinds = sorted(kind for kind in source_kinds if registry[kind].extends is None and kind != "OBJECT")
        kind = base_kinds[0] if len(base_kinds) == 1 else "OBJECT"
        specialized = [label for label in extension_kinds if contracts.compatible_specialization(registry, kind, label)]
        candidates = source_kinds | {hint for row in surfaces for hint in row["hints"]}
        objects.append({"object_id": path, "kind": kind, "specializations": specialized,
            "payload": {}, "operands": {}, "surfaces": [row["surface_id"] for row in surfaces], "reason": "",
            # Applicability is explicit across the complete installed semantic
            # namespace.  Otherwise a source-owned AGENT, BOT, SIM, or another
            # original kind could be admitted as generic OBJECT merely by
            # omitting a marker.  The draft never guesses: each non-OBJECT kind
            # starts UNRESOLVED until the repository binds APPLIES or a reasoned
            # DOES_NOT_APPLY decision to current owned source bytes.
            "classification": {name: {"status": "UNRESOLVED", "reason": "", "evidence": []}
                               for name in registry if name != "OBJECT"},
            "obligations": {row["id"]: {"reason": "", "evidence": [],
                                       "declaration": {field: "" for field in row["declaration_fields"]}}
                            for row in contracts.requirements_for(registry, candidates)}})
    return {"status": "DRAFT", "manifest": {"schema_version": manifests.SCHEMA,
        "registry_digest": contracts.registry_document(registry)["digest"], "extensions": selected_extensions, "objects": objects},
        "source_evidence": [{"path": row["path"], "sha256": row["sha256"]}
                            for row in observed["census"]["files"] if row["path"] != "objects.vstd"],
        "suggestions": [row for row in observed["surfaces"] if row["hints"] or row["source_kinds"]],
        "discovery_gaps": observed["gaps"], "next_action": "Review classifications, reasons and evidence; then run vstd polish 0.",
        "claim_boundary": BOUNDARY}


def _reconcile(raw: bytes, registry: dict[str, contracts.KindContract], observed: dict[str, Any],
               classified: dict[str, Any], *, representations: dict[str, Any] | None = None,
               package_transport: bool = False,
               established_non_applicability: list[dict[str, Any]] | None = None,
               documented_applicability_answers: Sequence[dict[str, str]] = (),
               reason_ir_digest: str | None = None) -> dict[str, Any]:
    node = shutil.which("node")
    if node is None:
        return {"status": "UNKNOWN", "reason": "Node is unavailable for independent declaration reconciliation."}
    # The independent reconciler re-derives binding support and adoption itself.
    # Only typed ESTABLISHED execution verdicts are supplied: each one is the result
    # of a fresh registered-closure run in this assessment, not a witness digest.
    # The reconciler rejects any omitted, malformed or unbound verdict.
    document = json.loads(raw)
    nonstructural_roles = consequences.nonstructural_role_binding(
        document["objects"]
    )
    payload = {"manifest": raw.decode("utf-8"), "registry": contracts.registry_document(registry),
               "transport_profile": "PACKAGE_GRAPH" if package_transport else "STANDARD",
               "established_non_applicability": established_non_applicability or [],
               "nonstructural_role_decisions": nonstructural_roles,
               "javascript_mechanism": observed.get("javascript_mechanism"),
               "markup_binding": discovery.namespace_html.binding(observed),
               "workflow_binding": observed.get("workflow_binding", discovery.namespace_workflows.EMPTY),
               "systems_mechanism": observed.get("systems_mechanism"),
               "surfaces": observed["surfaces"], "files": observed["census"]["files"]}
    documented_binding = None
    if documented_applicability_answers:
        if (
            type(reason_ir_digest) is not str
            or re.fullmatch(r"sha256:[0-9a-f]{64}", reason_ir_digest) is None
        ):
            raise ValueError("NAMESPACE_REASON_IR_DIGEST_INVALID")
        documented_binding = {
            "reason_ir_digest": reason_ir_digest,
            "answers": [dict(answer) for answer in documented_applicability_answers],
        }
        payload["documented_applicability"] = documented_binding
    if representations is not None:
        payload["representations"] = representations
    wire = canonical_bytes(payload)
    wire_limit = (64 if package_transport else 16) * 1024 * 1024
    if len(wire) > wire_limit:
        return {"status": "UNKNOWN", "reason": (
            "Independent reconciliation input exceeds the selected "
            + str(wire_limit // (1024 * 1024)) + " MiB bound."
        )}
    output_limit = wire_limit
    stderr_limit = 1024 * 1024
    try:
        result = _run_bounded_reconciler(
            [node, str(Path(__file__).with_name("namespace_reconcile.mjs"))],
            wire,
            output_limit=output_limit,
            stderr_limit=stderr_limit,
            timeout_seconds=(
                _PACKAGE_RECONCILIATION_TIMEOUT_SECONDS
                if package_transport
                else _STANDARD_RECONCILIATION_TIMEOUT_SECONDS
            ),
        )
        if result["status"] != "RETURNED":
            return {"status": "UNKNOWN", "reason": result["reason"]}
        receipt = json.loads(result["stdout"])
    except (OSError, subprocess.SubprocessError, ValueError):
        return {"status": "UNKNOWN", "reason": "The independent reconciler did not return a bounded readable result."}
    if (
        result["returncode"] != 0
        and receipt.get("error") == "NAMESPACE_RECONCILIATION_CAPACITY_EXHAUSTED"
    ):
        return {
            "status": "UNKNOWN",
            "reason": "The independent reconciler exhausted its declared finite work or output capacity.",
            "receipt": receipt,
        }
    expected = {"manifest_digest": bytes_digest(raw), "registry_digest": payload["registry"]["digest"],
                "base_composition_digest": manifests.check_composition(json.loads(raw)["objects"], registry)["base_composition_digest"],
                "requirements": {row["object_id"]: row["required_obligation_ids"] for row in classified["objects"]}}
    expected["effective_kinds"] = {row["object_id"]: row["effective_kinds"] for row in classified["objects"]}
    expected["instance_selection_digest"] = value_digest(document.get("instance_checks", []))
    expected["execution_selection_digest"] = value_digest(document.get("execution_checks", []))
    expected["export_binding_digest"] = value_digest(observed["export_bindings"])
    expected["javascript_mechanism_digest"] = value_digest(observed.get("javascript_mechanism"))
    expected["markup_binding_digest"] = value_digest(discovery.namespace_html.binding(observed))
    expected["workflow_binding_digest"] = value_digest(payload["workflow_binding"])
    if observed.get("systems_mechanism") is not None:
        expected["systems_mechanism_digest"] = value_digest(observed["systems_mechanism"])
    expected["consequences"] = consequences.derive_consequences(document["objects"], registry, observed,
        document.get("consequence_graph", consequences.EMPTY))
    expected["nonstructural_role_digest"] = value_digest(nonstructural_roles)
    if representations is not None:
        expected["representation_binding_digest"] = value_digest(representations)
    if documented_binding is not None:
        expected["documented_applicability_digest"] = value_digest(
            documented_binding
        )
    passed = result["returncode"] == 0 and receipt == expected
    return {"status": "PASS" if passed else "FAIL", "reason": (
        "Python and Node reproduce the same manifest, registry, complete base graph digest and per-object inherited requirement sets. The source census and exact catalog-compiled nonstructural-role binding are shared, not independently rediscovered."
        if passed else "Independent declaration interpretation disagrees."), "receipt": receipt}


def _run_bounded_reconciler(
    command: list[str],
    wire: bytes,
    *,
    output_limit: int,
    stderr_limit: int,
    timeout_seconds: float,
) -> dict[str, Any]:
    """Run the independent interpreter without unbounded pipe accumulation."""

    def stop(process: subprocess.Popen[bytes]) -> None:
        try:
            process.kill()
        except OSError:
            pass
        try:
            process.wait(timeout=2)
        except (OSError, subprocess.TimeoutExpired):
            pass

    try:
        with (
            tempfile.TemporaryFile() as input_stream,
            tempfile.TemporaryFile() as output_stream,
            tempfile.TemporaryFile() as error_stream,
        ):
            input_stream.write(wire)
            input_stream.seek(0)
            process = subprocess.Popen(
                command,
                stdin=input_stream,
                stdout=output_stream,
                stderr=error_stream,
            )
            deadline = time.monotonic() + timeout_seconds
            while True:
                returncode = process.poll()
                output_size = os.fstat(output_stream.fileno()).st_size
                error_size = os.fstat(error_stream.fileno()).st_size
                if output_size > output_limit or error_size > stderr_limit:
                    stop(process)
                    return {
                        "status": "UNKNOWN",
                        "reason": "The independent reconciler exceeded its bounded output envelope.",
                    }
                if returncode is not None:
                    break
                if time.monotonic() >= deadline:
                    stop(process)
                    return {
                        "status": "UNKNOWN",
                        "reason": "The independent reconciler exceeded its bounded execution deadline.",
                    }
                time.sleep(0.01)
            output_stream.seek(0)
            return {
                "status": "RETURNED",
                "returncode": returncode,
                "stdout": output_stream.read(output_limit + 1),
            }
    except OSError:
        return {
            "status": "UNKNOWN",
            "reason": "The independent reconciler process or bounded capture was unavailable.",
        }


def _coverage(manifest: dict[str, Any], observed: dict[str, Any]) -> list[dict[str, Any]]:
    owners: dict[str, list[str]] = {}
    findings = []
    for row in manifest["objects"]:
        if not row["surfaces"]:
            findings.append(classification.finding("NAMESPACE_OBJECT_WITHOUT_SURFACES", "UNKNOWN", "VSTD-T0.4",
                "No discovered source represents this object.", "Bind its exact discovered surfaces.", object_id=row["object_id"]))
        for surface in row["surfaces"]:
            owners.setdefault(surface, []).append(row["object_id"])
    discovered = {row["surface_id"] for row in observed["surfaces"]}
    for surface in sorted(discovered | owners.keys()):
        selected = owners.get(surface, [])
        if surface not in discovered or len(selected) != 1:
            code = ("NAMESPACE_SURFACE_UNCOVERED" if not selected else
                    "NAMESPACE_SURFACE_MULTIPLY_OWNED" if len(selected) > 1 else "NAMESPACE_SURFACE_NOT_DISCOVERED")
            findings.append(classification.finding(code, "FAIL", "VSTD-T0.4",
                "Exactly one object must own this discovered identity: " + surface,
                "Map this identity explicitly; file or category ownership is insufficient.",
                object_id=selected[0] if len(selected) == 1 else None, surface_id=surface))
    for gap in observed["gaps"]:
        # A known file owner is the next responsible object, not proof that its
        # generated interfaces are covered. Never guess across absent/ambiguous
        # ownership, and retain the gap in the package-wide prerequisite set.
        selected = owners.get("file:" + gap["path"], [])
        findings.append(classification.finding(gap["code"], "UNKNOWN", "VSTD-T0.4", gap["reason"],
            discovery.namespace_html.next_action(gap["code"], gap["path"]) if gap["code"].startswith("NAMESPACE_HTML_") else
            discovery.namespace_svg.next_action(gap["code"], gap["path"]) if gap["code"].startswith("NAMESPACE_SVG_") else
            discovery.namespace_workflows.next_action(gap["code"], gap["path"]) if gap["code"].startswith(("NAMESPACE_WORKFLOW_", "NAMESPACE_YAML_")) else
            discovery.namespace_systems.next_action(gap["code"], gap["path"]) if gap["code"].startswith(("NAMESPACE_SYSTEMS_", "NAMESPACE_RUST_", "NAMESPACE_SHELL_")) else
            "Install or implement a source discovery adapter for " + gap["path"] + "; file coverage cannot replace definition coverage.",
            object_id=selected[0] if len(selected) == 1 else None,
            surface_id="file:" + gap["path"]))
    return findings


def _source_revision(root: Path) -> str | None:
    """An unborn local repository has bytes but no commit; do not invent one."""
    result = subprocess.run(["git", "--no-optional-locks", "rev-parse", "--verify", "HEAD"],
                            cwd=root, capture_output=True, timeout=10, check=False)
    if result.returncode != 0:
        return None
    revision = result.stdout.decode("ascii").strip()
    if len(revision) not in (40, 64) or any(character not in "0123456789abcdef" for character in revision):
        raise ValueError("NAMESPACE_SOURCE_REVISION_INVALID")
    return revision


def _attach_harness_applicability(report: dict[str, Any], root: Path,
                                  manifest: dict[str, Any],
                                  classified: dict[str, Any]) -> None:
    """Attach the opt-in self profile without adding a tenth Tier-0 coordinate."""
    from verifier.runtime.tier_zero_profile import installed_tier_zero_profile

    canonical_obligations = {
        row["coordinate"]: (
            row["coordinate"] + "-" + row["name"].lower().replace(" ", "-")
        )
        for row in installed_tier_zero_profile()["obligations"]
    }
    selected = package_harness_applicability.assess_selected_repository(
        root, manifest, classified["objects"])
    report["harness_applicability"] = selected
    for row in package_harness_applicability.integration_findings(selected):
        unavailable = row["status"] == "UNKNOWN"
        report["findings"].append(classification.finding(
            row["code"], row["status"], row["coordinate"],
            ("The selected Verifier-self HARNESS launch denominator could not be read completely."
             if unavailable else
             "The selected Verifier-self HARNESS launch denominator contradicts the current exact source or reviewed declaration."),
            ("Restore readable bounded source inputs and rerun without inferring absence."
             if unavailable else
             "Inspect the named launch site and review its necessity, observation boundary and exact source binding before refreshing the frozen denominator."),
            object_id=row["object_id"],
            obligation_id=canonical_obligations[row["coordinate"]]))


def _finish(report: dict[str, Any]) -> dict[str, Any]:
    selected = profile()
    outcomes = []
    for row in selected["obligations"]:
        findings = [finding for finding in report["findings"] if finding["coordinate"] == row["coordinate"]]
        status = "FAIL" if any(item["status"] == "FAIL" for item in findings) else "UNKNOWN" if findings else "PASS"
        outcomes.append({**row, "status": status, "blockers": sorted({item["code"] for item in findings}),
            "assessment_reason": " ".join(item["explanation"] for item in findings) if findings else
                "The version-2 bounded declaration check completed without a contradiction or missing input; " + row["rationale"],
            "claim_boundary": BOUNDARY})
    # If parsing or capture stopped early, unexecuted checks must stay UNKNOWN.
    if not report.get("assessment_executed"):
        for row in outcomes:
            if row["status"] == "PASS" and row["coordinate"] != "VSTD-T0.9":
                row.update(status="UNKNOWN", blockers=["NAMESPACE_PREREQUISITE_UNAVAILABLE"],
                           assessment_reason="This check was not executed because an earlier prerequisite was unavailable.")
    counts = Counter(row["status"] for row in outcomes)
    status = "FAIL" if counts["FAIL"] else "UNKNOWN" if counts["UNKNOWN"] else "PASS"
    report.update(schema_version=REPORT_SCHEMA, status=status, profile_id=PROFILE_ID,
        profile_digest=selected["profile_digest"], obligation_count=len(outcomes), obligations=outcomes,
        obligation_status_counts={name: counts[name] for name in ("PASS", "FAIL", "UNKNOWN")},
        blockers=sorted({code for row in outcomes for code in row["blockers"]}),
        tier_1_plus_status="NOT_ESTABLISHED", polished=False, release_authorized=False, deployment_authorized=False,
        claim_boundary=BOUNDARY)
    report["finalization"] = {"status": status, "complete": status == "PASS", "finalized": status == "PASS",
        "scope": "TIER_ZERO_REPOSITORY_ADMISSION_ONLY", "reason": "Version-2 bounded declaration admission: " + status,
        "profile_digest": selected["profile_digest"], "mechanism_digest": report.get("mechanism_digest"),
        "source_coordinate": report.get("source_coordinate"), "source_census_digest": report.get("source_census_digest"),
        "closed_coordinates": [row["coordinate"] for row in outcomes if row["status"] == "PASS"],
        "unclosed_coordinates": [row["coordinate"] for row in outcomes if row["status"] != "PASS"],
        "claim_boundary": BOUNDARY}
    report["next_obligation"] = next(iter(sorted(report["findings"], key=lambda row: (
        row["status"] != "FAIL", row["coordinate"], row["object_id"] or "", row["obligation_id"]))), None)
    report["report_digest"] = value_digest(report)
    return report


def assess(source_root: str | Path = ".", *, manifest_path: str | Path | None = None) -> dict[str, Any]:
    """Assess the complete declared graph; never import or execute subject code."""
    report: dict[str, Any] = {"findings": [], "required_obligations": [], "object_assessments": [],
                              "assessment_executed": False}
    coordinate = "VSTD-T0.1"
    try:
        root = Path(source_root).resolve(strict=True)
        selected = root / "objects.vstd" if manifest_path is None else Path(manifest_path).absolute()
        raw, manifest = manifests.read_manifest(selected)
        report["manifest_digest"] = bytes_digest(raw)
        namespace_raw = raw
        representations = None
        package_transport = False
        from verifier.runtime import package_manifest
        if manifest.get("schema_version") in package_manifest.SCHEMAS:
            package_transport = manifest["schema_version"] in {
                package_manifest.PACKAGE_REPRESENTATION_SCHEMA,
                package_manifest.COMPACT_PACKAGE_REPRESENTATION_SCHEMA,
            }
            package_manifest.validate_bridge(manifest)
            if manifest["schema_version"] in package_manifest.REPRESENTATION_SCHEMAS:
                representations = {"updates": manifest["representation_updates"],
                    "retained_objects": [item.to_dict() for item in
                        package_manifest.tier_zero_manifest._namespace_objects(manifest["objects"])]}
            manifest = manifest["namespace"]
            if (
                manifest.get("schema_version")
                == manifests.COMPACT_SCHEMA
            ):
                # Compact evidence-set digests are transport selectors, never
                # evidence.  Every admission consumer and the independent
                # reconciler receive the exact validated version-2 semantic
                # document after missing, substituted, and unused selectors
                # have already failed closed.
                manifest = manifests.normalize_manifest(manifest)
            namespace_raw = canonical_bytes(manifest) + b"\n"
        report["namespace_manifest_digest"] = bytes_digest(namespace_raw)
        if manifest.get("schema_version") == "verifier-objects-manifest-1":
            report["findings"].append(classification.finding("NAMESPACE_VERSION_ONE_REQUIRES_MIGRATION", "UNKNOWN", "VSTD-T0.2",
                "Version 1 has no per-object extensible classification or exact definition ownership. Its historical admission does not establish version 2.",
                "For a recognized Verifier root, run default vstd polish 0 for guarded refresh; otherwise run vstd template --json to inspect a draft and preserve and explicitly migrate the existing manifest."))
            return _finish(report)
        documented_answers: tuple[dict[str, str], ...] = ()
        reason_ir_digest: str | None = None
        if (
            selected.resolve(strict=True) == (root / "objects.vstd").resolve(strict=True)
            and (root / "reasons.vstd").is_file()
        ):
            reason_selection = reason_integration.select_root_reasons(root)
            documented_answers = reason_integration.documented_applicability_answers(
                reason_selection, manifest["objects"],
            )
            reason_ir_digest = reason_selection.ir_digest
            answer_binding = {
                "reason_ir_digest": reason_ir_digest,
                "answers": list(documented_answers),
            }
            report["classification_reason_reconciliation"] = {
                "status": "PASS",
                "authority": reason_selection.authority,
                "documented_applicability_answer_count": len(documented_answers),
                "binding_digest": value_digest(answer_binding),
                "claim_boundary": (
                    "Checked APPLIES reasons retain obligations for compiled open "
                    "cells without editing objects.vstd or establishing semantic "
                    "source truth. Denials are not admitted by this retention path."
                ),
            }
        registry = manifests.validate_manifest(manifest)
        report["namespace"] = contracts.registry_document(registry)
        opening_mechanism = mechanism_binding()
        report["mechanism_digest"] = value_digest(opening_mechanism)
        coordinate = "VSTD-T0.7"
        observed = discovery.discover(root)
        opening_revision = _source_revision(root)
        report["source_census_digest"] = observed["census"]["census_digest"]
        report["source_coordinate"] = {"revision": opening_revision,
                                       "source_census_digest": report["source_census_digest"]}
        report["discovery_scope"] = observed["scope"]
        report["export_bindings"] = observed["export_bindings"]
        report["export_binding_digest"] = value_digest(observed["export_bindings"])
        report["javascript_mechanism"] = observed.get("javascript_mechanism")
        report["markup_binding"] = discovery.namespace_html.binding(observed)
        report["workflow_binding"] = observed.get("workflow_binding", discovery.namespace_workflows.EMPTY)
        report["systems_mechanism"] = observed.get("systems_mechanism")
        report["source_files"] = observed["census"]["files"]
        report["findings"].extend(_coverage(manifest, observed))
        # Tier zero binds selected bytes without replaying an instance checker.
        # Even ignored evidence participates, so source census agreement alone
        # cannot conceal a stale or changing request, policy or certificate.
        from verifier.runtime.package_instance_evidence import InstanceEvidence
        selected_inputs = InstanceEvidence(root, (), manifest)
        rows = {row["object_id"]: row for row in manifest["objects"]}
        paths = {row["surface_id"]: row["path"] for row in observed["surfaces"]}
        files = {row["path"]: row["sha256"] for row in observed["census"]["files"]}
        if representations is not None:
            report["representation_bindings"] = []
            for update in representations["updates"]:
                owned = {paths[surface] for surface in rows[update["object_id"]]["surfaces"] if surface in paths}
                status, reason = classification.binding_status(update, files, owned)
                try:
                    for ref in update["evidence"]:
                        selected_inputs.read(ref)
                except OSError as exc:
                    status, reason = "UNKNOWN", "Representation source could not be read: " + type(exc).__name__
                except ValueError as exc:
                    status, reason = "FAIL", str(exc)
                report["representation_bindings"].append({**update, "status": status,
                    "assessment_reason": reason, "semantic_fulfillment": "NOT_ESTABLISHED"})
                if status != "PASS":
                    report["findings"].append(classification.finding("PACKAGE_REPRESENTATION_EVIDENCE_UNRESOLVED",
                        status, "VSTD-T0.6", reason,
                        "Bind the current representation to its exact owned source without transferring historical PASS.",
                        object_id=update["object_id"]))
        for check in manifest.get("instance_checks", []):
            try:
                for ref in [check[name] for name in ("request", "policy", "certificate")] + check["evidence"]:
                    selected_inputs.read(ref)
            except OSError as exc:
                report["findings"].append(classification.finding("PACKAGE_INSTANCE_INPUT_UNAVAILABLE", "UNKNOWN", "VSTD-T0.7",
                    "Selected instance input could not be captured: " + type(exc).__name__,
                    "Restore the selected request, policy, certificate and source references.", object_id=check["object_id"]))
            except ValueError as exc:
                report["findings"].append(classification.finding(str(exc), "FAIL", "VSTD-T0.7",
                    "The selected instance evidence violates its exact byte or path binding.",
                    "Correct the selected evidence without substituting an unrelated passing certificate.", object_id=check["object_id"]))
        report["execution_bindings"] = []
        for check in manifest.get("execution_checks", []):
            from verifier.runtime.package_execution import implementation
            selected_implementation = implementation(check["mechanism"])
            owner = rows[check["object_id"]]
            owned = {paths[surface] for surface in owner["surfaces"] if surface in paths}
            status, reason = classification.binding_status(check, files, owned)
            if status == "PASS" and ("file:" + selected_implementation not in owner["surfaces"]
                    or not any(ref["path"] == selected_implementation for ref in check["evidence"])):
                status, reason = "UNKNOWN", "The selected local execution must bind its exact owned implementation."
            try:
                for ref in check["evidence"]:
                    selected_inputs.read(ref)
            except (OSError, ValueError) as exc:
                status = "UNKNOWN" if isinstance(exc, OSError) else "FAIL"
                reason = "Selected execution evidence could not be bound: " + str(exc)
            # Binding a selection is admission only. No subject or worker runs
            # here, and source identity cannot establish execution semantics.
            report["execution_bindings"].append({**check, "status": status,
                "assessment_reason": reason, "semantic_fulfillment": "NOT_ESTABLISHED"})
            if status != "PASS":
                report["findings"].append(classification.finding("PACKAGE_EXECUTION_SOURCE_UNRESOLVED", status, "VSTD-T0.7",
                    reason,
                    "Restore current owned source references; admission never launches this worker.", object_id=check["object_id"]))
        coordinate = "VSTD-T0.3"
        composition = manifests.check_composition(manifest["objects"], registry)
        report["composition"] = composition
        if composition["status"] != "PASS":
            report["findings"].append(classification.finding("NAMESPACE_BASE_COMPOSITION_UNRESOLVED", composition["status"], coordinate,
                composition["reason"], "Correct the typed base operands without discarding refinement obligations."))
        consequential = consequences.assess_consequences(manifest["objects"], registry, observed,
            manifest.get("consequence_graph"))
        report["consequence_graph"] = consequential
        report["findings"].extend(consequential["findings"])
        coordinate = "VSTD-T0.2"
        classified = classification.assess_classification(
            manifest["objects"],
            registry,
            observed,
            consequence_kinds=consequential["required_kinds"],
            refutation_context=classification.refutation_context(
                observed, value_digest(opening_mechanism), root=root),
            documented_applicability_answers=documented_answers,
            derived_item_limit=classification.MAX_DERIVED_ITEMS,
        )
        report["findings"].extend(classified["findings"])
        report["detail_profiles"] = classified["detail_profiles"]
        report["obligation_contracts"] = classified["obligation_contracts"]
        report["object_assessments"] = classified["objects"]
        report["required_obligations"] = classified["required_obligations"]
        _attach_harness_applicability(report, root, manifest, classified)
        coordinate = "VSTD-T0.8"
        # Typed verdicts exist only for fresh closure PASSes run in this assessment.
        report["independent_reconciliation"] = _reconcile(namespace_raw, registry, observed, classified,
            representations=representations, package_transport=package_transport,
            established_non_applicability=classified["non_applicability_verdicts"],
            documented_applicability_answers=documented_answers,
            reason_ir_digest=reason_ir_digest)
        independent = report["independent_reconciliation"]
        if independent["status"] != "PASS":
            report["findings"].append(classification.finding("NAMESPACE_RECONCILIATION_UNRESOLVED", independent["status"], coordinate,
                independent["reason"], "Provide Node and inspect the independent declaration-reconciliation result."))
        coordinate = "VSTD-T0.7"
        closing = discovery.capture_candidate_source_census(root, allow_untracked_only=True)
        discovery.namespace_javascript.recapture(observed.get("javascript_mechanism"))
        discovery.namespace_html.recapture(observed.get("html_mechanism"))
        discovery.namespace_svg.recapture(observed.get("svg_mechanism"))
        discovery.namespace_workflows.recapture(report["workflow_binding"])
        discovery.namespace_systems.recapture(report["systems_mechanism"])
        selected_inputs.recapture()
        if (closing != observed["census"] or manifests.read_manifest(selected)[0] != raw
                or mechanism_binding() != opening_mechanism or _source_revision(root) != opening_revision):
            report["findings"].append(classification.finding("NAMESPACE_SOURCE_OR_MECHANISM_CHANGED", "FAIL", coordinate,
                "Source, manifest or installed mechanism changed during assessment.", "Rerun on unchanged bytes."))
        report["assessment_executed"] = True
    except (OSError, MemoryError, RecursionError, subprocess.TimeoutExpired) as exc:
        report["findings"].append(classification.finding("NAMESPACE_INPUT_UNAVAILABLE", "UNKNOWN", coordinate,
            "Required input could not be observed: " + type(exc).__name__, "Restore the selected input or bounded resources and rerun."))
    except (ValueError, TypeError, KeyError) as exc:
        unavailable = str(exc).endswith(("_UNAVAILABLE", "_CAPACITY_EXHAUSTED", "_CAPACITY"))
        next_action = ("Run vstd format --write to canonicalize objects.vstd without changing its content."
                       if str(exc) == "TIER_ZERO_MANIFEST_NOT_CANONICAL"
                       else "Correct the exact reported contract violation.")
        report["findings"].append(classification.finding(str(exc), "UNKNOWN" if unavailable else "FAIL", coordinate,
            "The selected declaration or evidence violates its contract: " + str(exc), next_action))
    return _finish(report)


def assess_gate(object_id: str, obligation_id: str, source_root: str | Path = ".") -> dict[str, Any]:
    """Focus diagnostics without allowing an object selector to hide global prerequisites."""
    try:
        _, document = manifests.read_manifest(Path(source_root) / "objects.vstd")
    except (OSError, ValueError):
        document = {}
    from verifier.runtime import package_manifest
    if document.get("schema_version") in package_manifest.SCHEMAS:
        from verifier.runtime import package_admission
        try:
            report = package_admission.assess(source_root)
        except ValueError as exc:
            # Package admission reads one moving repository snapshot.  Preserve
            # its exact refusal at this focused boundary: named source drift is
            # retryable UNKNOWN, while every other contract rejection remains
            # FAIL.  Neither class may escape ``--json`` as an unstructured line.
            from verifier.runtime import self_polish_tiers

            code = str(exc) or "PACKAGE_ADMISSION_CONTRACT_REJECTED"
            source_drift = code in self_polish_tiers.LIVE_SOURCE_DRIFT_CODES
            profile_mismatch = code == "TIER_ZERO_MANIFEST_PROFILE_DIFFERS"
            if source_drift:
                status = "UNKNOWN"
                coordinate = "VSTD-T0.7"
                gate_id = "source-freshness"
                explanation = self_polish_tiers.LIVE_SOURCE_DRIFT_EXPLANATION
                next_action = (
                    "Keep the selected source tree and root objects.vstd unchanged "
                    "until this command finishes, then rerun the exact focused gate "
                    "shown by rerun_argv from the selected repository root."
                )
            elif profile_mismatch:
                status = "FAIL"
                coordinate = "VSTD-T0.1"
                gate_id = "manifest-admission"
                explanation = (
                    "The selected package manifest's retained Tier-0 profile "
                    "differs from the installed Tier-0 profile; a focused PASS "
                    "cannot be selected from stale admission bytes."
                )
                next_action = (
                    "Refresh or remigrate objects.vstd against the installed "
                    "Tier-0 profile, then rerun this exact object and obligation gate."
                )
            else:
                status = "FAIL"
                coordinate = "VSTD-T0.1"
                gate_id = "manifest-admission"
                explanation = (
                    "The selected package admission mechanism rejected its input "
                    f"contract: {code}."
                )
                next_action = (
                    "Correct the exact reported package-admission contract "
                    "violation, then rerun this exact object and obligation gate."
                )
            rejection = classification.finding(
                code,
                status,
                coordinate,
                explanation,
                next_action,
                object_id=object_id,
                obligation_id=obligation_id,
                gate_id=gate_id,
            )
            report = _finish({
                "findings": [rejection],
                "required_obligations": [],
                "object_assessments": [],
                "assessment_executed": False,
            })
            namespace = report
        else:
            namespace = report["namespace_admission"]
            if report.get("schema_version") == package_admission.LEGACY_REPORT_SCHEMA:
                report.update({key: namespace[key] for key in (
                    "object_assessments", "required_obligations", "assessment_executed")})
                report["findings"] = [*report["findings"]]
                from verifier.runtime.manifest_gate import admission_findings
                report["findings"].extend(admission_findings(report["retained_admission"]))
    else:
        report = assess(source_root)
        namespace = report
    had_package_projection = "object_assessments" in report
    if not had_package_projection and report.get("retained_admission"):
        from verifier.runtime.manifest_gate import admission_findings

        report["findings"].extend(
            admission_findings(report["retained_admission"])
        )
    package_status = report["status"]
    object_assessments = report.get(
        "object_assessments", namespace.get("object_assessments", [])
    )
    required_obligations = report.get(
        "required_obligations", namespace.get("required_obligations", [])
    )
    assessment_executed = report.get(
        "assessment_executed", namespace.get("assessment_executed", False)
    )
    report.setdefault("object_assessments", object_assessments)
    report.setdefault("required_obligations", required_obligations)
    report.setdefault("assessment_executed", assessment_executed)
    objects = {row["object_id"] for row in object_assessments}
    obligation = next((row for row in required_obligations
                       if row["object_id"] == object_id and row["id"] == obligation_id), None)
    admission = next((row for row in namespace.get("obligations", [])
                      if obligation_id == row["coordinate"] + "-namespace-admission"), None)
    # Polish prints the retained slug (the tier-0 coordinate followed by its readable
    # name) as the rerun selector, so the gate must resolve it to the row at the
    # same coordinate.  Retained and namespace checks are cumulative: a package report
    # carries the conjoined row, but a namespace-only report never assessed the retained
    # component and so cannot answer a retained selector with PASS (TIME.md T0.1, T0.5).
    retained_unassessed = False
    if obligation is None and admission is None:
        from verifier.runtime import manifest_gate
        identity = manifest_gate._admission_identities().get(obligation_id)
        if identity is not None and identity["gate_id"] != "namespace-admission":
            admission = next((row for row in report.get("obligations", [])
                              if row["coordinate"] == identity["coordinate"]), None)
            retained_unassessed = admission is not None and not report.get("retained_admission")
    selection_status = "PASS"
    if not assessment_executed:
        selection_status = "UNKNOWN"
        report["findings"].append(classification.finding("NAMESPACE_GATE_SELECTION_UNAVAILABLE", "UNKNOWN", "VSTD-T0.5",
            "Admission could not establish the object's requirement set, so selection is not yet checkable.",
            "Resolve the package admission prerequisite first.", object_id=object_id, obligation_id=obligation_id))
    elif object_id not in objects or (obligation is None and admission is None):
        selection_status = "FAIL"
        report["status"] = "FAIL"
        report["findings"].append(classification.finding("NAMESPACE_GATE_SELECTION_INVALID", "FAIL", "VSTD-T0.5",
            "The object or exact obligation is not present in this derived denominator.",
            "Use the object and obligation identifiers printed by vstd polish 0.", object_id=object_id, obligation_id=obligation_id))
    elif retained_unassessed:
        selection_status = "UNKNOWN"
        if report["status"] == "PASS":
            report["status"] = "UNKNOWN"
        report["findings"].append(classification.finding("RETAINED_TIER_ZERO_COMPONENT_NOT_ASSESSED", "UNKNOWN",
            admission["coordinate"],
            "This is a namespace-only result; the retained Tier-0 component at the same coordinate was not assessed.",
            "Run vstd polish 0 against the package manifest so the retained and namespace components are conjoined.",
            object_id=object_id, obligation_id=obligation_id))
    contracts = {
        row["id"]: row
        for row in report.get(
            "obligation_contracts", namespace.get("obligation_contracts", []),
        )
    }
    report.update(object_id=object_id, obligation_id=obligation_id,
                  selected_obligation=obligation or admission,
                  selected_obligation_contract=(
                      contracts.get(obligation_id) if obligation is not None else None
                  ),
                  package_admission_status=package_status,
                  selection_status=selection_status,
                  selection=None, instance=None,
                  rerun_argv=["vstd", "gate", "--object", object_id, "--obligation", obligation_id])
    # Focus the human-facing question, but keep all other blockers in the result
    # and in the overall verdict. A selected green annotation is not admission.
    report["prerequisite_findings"] = [row for row in report["findings"]
                                       if row["object_id"] != object_id or row["obligation_id"] != obligation_id]
    report["findings"] = [row for row in report["findings"]
                           if row["object_id"] == object_id and row["obligation_id"] == obligation_id]
    report.pop("report_digest", None)
    report["report_digest"] = value_digest(report)
    return report
