"""Private provenance POLICY executions for Verifier Standard (VSTD).

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
Only installed code and in-memory synthetic provenance execute. No external
dataset, authority channel, license service or operator policy is consulted.
The parent checks observations; this worker never issues package conformance.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
import tempfile
from typing import Any


def source_pins() -> dict[str, str]:
    # Capture before importing the subject; isolated startup ignores caller paths.
    root = Path(__file__).resolve().parents[1]
    paths = list(root.rglob("*.py"))
    paths.extend(root / name for name in ("standard/POLISH_INVOCATION_LEDGER.md", "standard/PACKAGE_POLISH.md"))
    return {path.relative_to(root).as_posix(): "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(paths) if "__pycache__" not in path.parts}


def observe() -> dict[str, Any]:
    """Exercise public decisions and the actual encoding enforcement boundary."""
    from verifier.data import policy
    from verifier.data.models import (ArtifactNode, ArtifactStatus, ArtifactType,
        HyperedgePort, ProvenanceHypergraph, RightsSpec, TransformationHyperedge, TransformationType)

    methods = {"no_revoked": policy.ProvenancePolicyVerifier.verify_no_revoked_ancestors,
               "all_valid": policy.ProvenancePolicyVerifier.verify_all_ancestors_valid,
               "licenses": policy.ProvenancePolicyVerifier.verify_approved_licenses}

    def edge(name: str, source: str, target: str) -> TransformationHyperedge:
        return TransformationHyperedge(name, name, TransformationType.NORMALIZATION,
            (HyperedgePort(source, "INPUT"),), (HyperedgePort(target, "OUTPUT"),), {}, {}, {})

    def graph(root_status: ArtifactStatus = ArtifactStatus.VALID,
              target_status: ArtifactStatus = ArtifactStatus.VALID,
              license_name: str | None = "MIT", *, target_license: str = "MIT") -> ProvenanceHypergraph:
        result = ProvenanceHypergraph()
        if license_name is not None:
            result.add_rights(RightsSpec("root-rights", license_name))
        result.add_rights(RightsSpec("target-rights", target_license))
        for name, status, rights in (("root", root_status, "root-rights" if license_name is not None else None),
                                     ("target", target_status, "target-rights"),
                                     ("unrelated", ArtifactStatus.REVOKED, None)):
            result.add_artifact(ArtifactNode(name, name, ArtifactType.RAW_SOURCE_FILE,
                hashlib.sha256(name.encode()).hexdigest(), status=status, rights_id=rights))
        result.add_transformation(edge("derive", "root", "target"))
        return result

    statuses = list(ArtifactStatus)
    matrix = [{"root": root.value, "target": target.value,
               **{name: methods[name](graph(root, target), "target").to_dict()
                  for name in ("no_revoked", "all_valid")}}
              for root in statuses for target in statuses]
    missing = {name: method(ProvenanceHypergraph(), "absent").to_dict() for name, method in methods.items()}
    licenses = []
    for license_name, allowed, target_license in (
            ("MIT", None, "MIT"), ("PROPRIETARY", None, "MIT"), (None, None, "MIT"),
            ("PROPRIETARY", ["PROPRIETARY"], "MIT"), ("MIT", [], "MIT"),
            ("MIT", ["Apache-2.0"], "MIT"), ("MIT", None, "PROPRIETARY")):
        selected = graph(license_name=license_name, target_license=target_license)
        args = () if allowed is None else (allowed,)
        licenses.append({"license": license_name, "allowed": allowed, "target_license": target_license,
                         "result": methods["licenses"](selected, "target", *args).to_dict()})
    cyclic = graph()
    cyclic.add_transformation(edge("back", "target", "root"))
    cycle = methods["licenses"](cyclic, "target").to_dict()
    dangling = graph()
    del dangling.artifacts["root"]
    invalid = {}
    for name, method in methods.items():
        try:
            method(dangling, "target")
            invalid[name] = {"returned": True, "exception": None}
        except policy.PolicyEncodingError as exc:
            invalid[name] = {"returned": False, "exception": type(exc).__name__}

    # A known contradictory formula gives the parent a small independent kernel
    # recheck. Missing facts/dependencies must be refused before certification.
    controls = {}
    for name, clauses, sat, direct in (
            ("pass", [[-1, 2], [2], [1]], True, True),
            ("fail", [[-1, 2], [-2], [1]], False, False),
            ("direct-conflict", [[-1, 2], [-2], [1]], False, True),
            ("solver-conflict", [[-1, 2], [-2], [1]], True, False),
            ("missing-fact", [[-1, 2], [1]], True, True),
            ("missing-dependency", [[-2], [1]], True, True),
            ("missing-target", [[-1, 2], [-2]], True, True),
            ("duplicate-fact", [[-1, 2], [2], [-2], [1]], False, False)):
        row = {"returned": False, "exception": None, "passed": None, "certificate": None}
        try:
            passed, certificate = policy.certify_policy_cnf(satisfiable=sat, direct_result=direct,
                policy_id="POL-CONTROL", target_artifact_id="target", clauses=clauses,
                var_map={"TARGET_ADMISSIBLE": 1, "CLEAN_root": 2})
            row.update(returned=True, passed=passed, certificate=certificate.to_dict())
        except policy.PolicyEncodingError as exc:
            row.update(exception=type(exc).__name__,
                       certificate=exc.certificate.to_dict() if exc.certificate is not None else None)
        controls[name] = row
    return {"status_values": [status.value for status in statuses], "matrix": matrix,
            "missing": missing, "licenses": licenses, "cycle": cycle, "invalid": invalid, "controls": controls}


def main() -> int:
    raw = sys.stdin.buffer.read(16385)
    if len(raw) > 16384:
        raise ValueError("worker request exceeds bound")
    request = json.loads(raw)
    if (type(request) is not dict or set(request) != {"schema_version", "nonce", "object_id", "object_digest", "collection_digest"}
            or request["schema_version"] != "verifier-provenance-policy-request-1"
            or any(type(value) is not str or not 1 <= len(value) <= 256 for value in request.values())):
        raise ValueError("closed bounded policy request required")
    before = source_pins()
    with tempfile.TemporaryDirectory(prefix="vstd-policy-check-") as temporary:
        sys.pycache_prefix = str(Path(temporary) / "empty-bytecode")
        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        observations = observe()
    if before != source_pins():
        raise ValueError("worker source changed")
    sys.stdout.write(json.dumps({"schema_version": "verifier-provenance-policy-observations-1",
        "request": request, "source_pins": before, "observations": observations},
        sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
