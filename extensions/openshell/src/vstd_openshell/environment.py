"""Optional OpenShell execution environment (ENV) object projection.

Use the existing Verifier Standard (VSTD) namespace object contract. Secure Hash
Algorithm 256-bit (SHA-256) binds selected records; this is not ENV conformance,
complete software inventory, hardware attestation or full subject composition.
This module is loaded only by an explicitly selected OpenShell execution.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any


def represent_environment(result: dict[str, Any], profile: dict[str, Any], token: str) -> dict[str, Any]:
    from verifier.core.certificate import canonical_digest
    from verifier.core.namespace import NamespaceObject

    environment = NamespaceObject.create("openshell-env-" + token, "ENV", {
        "scope": "selected-openshell-runtime-observations",
        "backend": "openshell",
        "applicability": {"condition": "explicit --sandbox openshell selection",
                          "reason": "The selected backend supplies the subject's execution environment; no OpenShell requirement is imposed on the basic runner."},
        "configuration": result["config"],
        "software_commitments": {**{key: result.get(key) for key in ("adapter_sha256", "cli_sha256")},
            "env_projection_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest()},
        "gateway_observation": result.get("gateway_observation"),
        "runtime_before": result.get("binding_before"),
        "runtime_after": result.get("binding_after"),
        "controls": result.get("controls", {}),
        "execution_performed": result["execution_performed"],
        "cleanup": result["cleanup"],
        "command_evidence_digest": "sha256:" + canonical_digest(result["commands"]),
        "qualification": "NOT_ESTABLISHED",
        "limitations": ["Gateway state is a runtime report, not independent attestation.",
                        "The image is a requested content pin; complete image, host and toolchain closure are not established.",
                        "Named live probes do not discharge all ENV obligations or the subject's other required operands."],
    })
    kind = profile["object_kind"]
    return {"object": environment.to_dict(), "object_digest": environment.digest,
            "subject_binding": {"subject_kind": kind,
                "subject_source_sha256": result.get("source_sha256", {}),
                "role": "env" if kind in {"MODEL", "AGENT", "BOT", "SIM"} else "execution-context",
                "targets": [environment.object_id], "target_digest": environment.digest,
                "scope": "selected execution context, not a complete subject GRAPH"},
            "obligation_status": "UNKNOWN"}
