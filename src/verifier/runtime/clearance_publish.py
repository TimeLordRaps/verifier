"""Local publication preparation from automatic command-line interface (CLI) gates.

JavaScript Object Notation (JSON). The host must independently replay under its own
policy and retain authentication, moderation, rights and provenance checks. This
module performs no transport, credential read, approval or production publication.
"""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path
from typing import Any

from verifier.core.certificate import canonical_bytes
from verifier.runtime.artifact_snapshot import capture, digest, output_outside, read_bytes, write_new
from verifier.runtime.gates import DEFAULT_POLICY, validate_clearance

SCHEMA = "verifier-gates-publication-preparation-3"


class FacetCoverageIncomplete(ValueError):
    """Required facet applicability/obligation coverage remains unestablished."""
    def __init__(self, assessment: dict[str, Any]) -> None:
        super().__init__("independent facet coverage is not established")
        self.assessment = assessment


def prepare_clearance_publication(artifact_path: str | Path, clearance_bytes: bytes, *,
                                  expected_policy_bytes: bytes | None = None,
                                  expected_dependency_policy_bytes: bytes | None = None,
                                  expected_facet_inventory_bytes: bytes | None = None,
                                  expected_facet_specification_bytes: bytes | None = None,
                                  expected_facet_policy_bytes: bytes | None = None) -> dict[str, Any]:
    """Preserve exact bytes and replay clearance; never adopt its policy as consumer policy."""
    if expected_dependency_policy_bytes is None:
        raise ValueError("publication preparation requires independently selected certificate dependency profile policy")
    policy = canonical_bytes(DEFAULT_POLICY) if expected_policy_bytes is None else expected_policy_bytes
    clearance = validate_clearance(clearance_bytes, artifact_path, expected_policy_bytes=policy,
        expected_dependency_policy_bytes=expected_dependency_policy_bytes)
    snapshot = capture(artifact_path)
    if snapshot.inventory() != clearance["artifact"]:
        raise ValueError("artifact changed after clearance replay")
    if any(v is None for v in (expected_facet_inventory_bytes, expected_facet_specification_bytes, expected_facet_policy_bytes)):
        raise FacetCoverageIncomplete({"schema_version": "verifier-facet-coverage-assessment-1",
            "status": "UNKNOWN", "qualification": "NOT_ESTABLISHED",
            "diagnostics": [{"code": "INDEPENDENT_FACET_REQUIREMENT_DENOMINATOR_MISSING",
                "component": "facet inventory/specification/policy",
                "required_resolution": "Select an authoritative facet inventory and applicability/derivation specification independently of the certificate graph."}]})
    from verifier.domains.contracts.facet_coverage import assess_facet_completeness
    coverage = assess_facet_completeness(expected_facet_inventory_bytes, expected_facet_specification_bytes,
        expected_policy_bytes=expected_facet_policy_bytes,
        bundle_bytes=clearance["dependency_bundle_json"].encode("utf-8"),
        expected_dependency_policy_bytes=expected_dependency_policy_bytes, artifact_files=snapshot.files)
    if coverage["status"] != "PASS":
        raise FacetCoverageIncomplete(coverage)
    payload = {"schema_version": SCHEMA, "artifact": {"kind": snapshot.kind,
        "files": [{"path": p, "content_base64": base64.b64encode(raw).decode("ascii")}
                  for p, raw in sorted(snapshot.files.items())]},
        "policy_json": policy.decode("utf-8"), "clearance_json": clearance_bytes.decode("utf-8"),
        "dependency_policy_json": expected_dependency_policy_bytes.decode("utf-8"),
        "qualification": "SOURCE_GROUNDED_FACET_OBLIGATION_CLOSURE", "polished": False,
        "facet_inventory_json": expected_facet_inventory_bytes.decode("utf-8"),
        "facet_specification_json": expected_facet_specification_bytes.decode("utf-8"),
        "facet_policy_json": expected_facet_policy_bytes.decode("utf-8"), "facet_coverage": coverage}
    if capture(artifact_path).inventory() != snapshot.inventory():
        raise ValueError("artifact changed during publication preparation")
    return payload


def handle_clearance_publish(args: argparse.Namespace) -> int:
    try:
        if not args.dry_run or not args.artifact:
            raise ValueError("automatic clearance publication currently requires --artifact and --dry-run")
        if any((args.gated, args.sim_artifact, args.sim_request, args.sim_policy, args.source_digest,
                args.receipt, args.claim, args.expected_head, args.genesis, args.request, args.certificate, args.manifest,
                args.publisher_id, args.credential_file, args.private_review_consent, args.expected_checker_coordinate)):
            raise ValueError("clearance preparation cannot mix with other publication or account modes")
        output_outside(args.output, args.artifact)
        clearance_raw = read_bytes(args.clearance)
        policy = read_bytes(args.policy) if args.policy else None
        payload = prepare_clearance_publication(args.artifact, clearance_raw, expected_policy_bytes=policy,
            expected_dependency_policy_bytes=read_bytes(args.dependency_policy) if args.dependency_policy else None,
            expected_facet_inventory_bytes=read_bytes(args.facet_inventory) if args.facet_inventory else None,
            expected_facet_specification_bytes=read_bytes(args.facet_specification) if args.facet_specification else None,
            expected_facet_policy_bytes=read_bytes(args.facet_policy) if args.facet_policy else None)
        write_new(args.output, payload)
        result = {"status": "PASS", "result": "PREPARED", "schema_version": SCHEMA,
                  "payload_digest": digest(canonical_bytes(payload)),
                  "clearance_id": json.loads(payload["clearance_json"])["clearance_id"],
                  "publication": "NOT_ESTABLISHED", "transport_performed": False,
                  "moderation": "HOST_POLICY_AND_REVIEW_REQUIRED"}
    except FacetCoverageIncomplete as exc:
        result = {"status": exc.assessment["status"], "result": "REJECTED", "reason": "FACET_COVERAGE_NOT_ESTABLISHED",
            "schema_version": SCHEMA, "facet_coverage": exc.assessment, "publication": "NOT_ESTABLISHED", "transport_performed": False}
    except OSError:
        result = {"status": "UNKNOWN", "result": "REJECTED", "reason": "INPUT_OR_OUTPUT_UNAVAILABLE",
                  "publication": "NOT_ESTABLISHED", "transport_performed": False}
    except (ValueError, TypeError, KeyError, ImportError, UnicodeError, RecursionError):
        result = {"status": "FAIL", "result": "REJECTED", "reason": "CLEARANCE_OR_MODE_REJECTED",
                  "publication": "NOT_ESTABLISHED", "transport_performed": False}
    print(json.dumps(result, sort_keys=True, allow_nan=False) if args.json else json.dumps(result, indent=2, sort_keys=True))
    return {"PASS": 0, "FAIL": 1, "UNKNOWN": 2}[result["status"]]
