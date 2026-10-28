"""Private retained-token experiments for the ASSET package adapter.

The child returns source-bound certificates and raw retained selections.  It
does not decide any package gate; the parent independently rechecks every
certificate and inspects the finite effects before assigning a route result.
"""
from __future__ import annotations

import base64
import json
from pathlib import Path
import sys
import tempfile
from typing import Any, Callable


def source_pins() -> dict[str, str]:
    from verifier.runtime.local_ledger_worker import source_pins as capture

    return capture()


def _holding() -> tuple[dict[str, Any], dict[str, Any]]:
    from verifier.domains.common import digest

    common = {
        "issuing_key_id": digest("documentary-key-id"),
        "issued_at": 100,
        "algorithm": "Ed25519",
        "audience": ["reader"],
        "signature": "unverified-declaration",
    }
    birth = {
        **common, "kind": "birth", "token_id": "birth", "replay_id": "r-birth",
        "birth_epoch": 4, "commitment": digest("opaque-birth-commitment"),
    }
    root = {
        **common, "kind": "lifetime", "token_id": "root", "replay_id": "r-root",
        "parent_grant_id": "birth", "delegate_key_id": digest("delegate-label"),
        "permitted_scopes": ["read", "write"], "not_before": 100, "not_after": 1000,
        "max_invocations": 10, "soulbound": False, "confirmation_key_id": None,
        "caveats": [{"condition": "region=local", "discharge": None}],
    }
    child = {
        **root, "token_id": "child", "replay_id": "r-child", "parent_grant_id": "root",
        "permitted_scopes": ["read"], "not_before": 200, "not_after": 800,
        "max_invocations": 2,
    }
    epochs, head = [], birth["commitment"]
    for epoch, status in enumerate(("ACTIVE", "SUSPENDED", "ACTIVE", "REVOKED"), 5):
        head = digest([head, epoch, status])
        epochs.append({"epoch": epoch, "status": status, "digest": head})
    aging = {
        **common, "kind": "aging", "token_id": "aging", "replay_id": "r-aging",
        "birth_token_id": "birth", "epoch_start": 5, "epoch_end": 8,
        "accumulated_epochs": 2, "accumulator_digest": head,
        "revocation_status": "REVOKED",
    }
    inputs = {"tokens": [birth, root, child, aging], "epochs": epochs}
    artifact = {
        "clock": "fixture:declared-clock", "clock_skew": 30,
        "root_scopes": ["read", "write"], "tokens_digest": digest(inputs["tokens"]),
        "epochs_digest": digest(epochs),
    }
    return artifact, inputs


def _bundle(check: str, *, unit: str = "microsecond",
            mutate: Callable[[dict[str, Any], dict[str, Any]], None] | None = None) -> dict[str, Any]:
    from verifier.core.certificate import canonical_bytes
    from verifier.core.namespace import NamespaceObject, composition_digest
    from verifier.domains.common import digest
    from verifier.domains.contracts import token_checks

    artifact, inputs = _holding()
    if mutate is not None:
        mutate(artifact, inputs)
    # Mutations change the selected finite evidence, so commitments are always
    # recomputed.  This prevents a digest mismatch from hiding the intended
    # semantic counterexample.
    if "tokens" in inputs:
        artifact["tokens_digest"] = digest(inputs["tokens"])
    if "epochs" in inputs:
        artifact["epochs_digest"] = digest(inputs["epochs"])
    subject = NamespaceObject.create(
        "package-token-asset-fixture", "TOKEN",
        {"scope": "retained-capability-token-records", "clock_unit": unit,
         "artifact": artifact},
    )
    evidence = canonical_bytes({
        "schema_version": token_checks.EVIDENCE_VERSION,
        "objects": [subject.to_dict()],
        "inputs": inputs,
    })
    policy = token_checks.token_checks_policy(
        trust_roots=["package:source-bound-token-asset-fixture"]
    )
    request = token_checks.token_checks_request(
        check=check,
        subject_id=subject.object_id,
        object_digest=subject.digest,
        collection_digest=composition_digest([subject]),
        evidence_ref=digest(json.loads(evidence)),
        policy=policy,
    )
    certificate = token_checks.build_token_checks_certificate(
        request, evidence, policy=policy
    )
    result = token_checks.recheck_token_checks_certificate(
        certificate, expected_request=request, policy=policy
    )
    return {
        "check": check,
        "request": request,
        "policy": policy,
        "certificate": base64.b64encode(certificate).decode("ascii"),
        "reported_result": result,
    }


def _revival(artifact: dict[str, Any], inputs: dict[str, Any]) -> None:
    from verifier.domains.common import digest

    prior = inputs["epochs"][-1]["digest"]
    inputs["epochs"].append({
        "epoch": 9, "status": "ACTIVE", "digest": digest([prior, 9, "ACTIVE"])
    })


def _widened_scope(artifact: dict[str, Any], inputs: dict[str, Any]) -> None:
    inputs["tokens"][2]["permitted_scopes"] = ["admin"]


def _boolean_integer(artifact: dict[str, Any], inputs: dict[str, Any]) -> None:
    inputs["tokens"][1]["not_before"] = True


def _unsupported_asset(artifact: dict[str, Any], inputs: dict[str, Any]) -> None:
    inputs["tokens"][0]["kind"] = "fungible-balance"


def observe() -> dict[str, Any]:
    from verifier.runtime.token_asset_execution import CLAIM_BOUNDARY

    return {
        "boundary": dict(CLAIM_BOUNDARY),
        "declaration": {
            "record_model": "retained-capability-token-records",
            "window_unit": "declared-microsecond-integer",
            "quantity_unit": "dimensionless-integer",
            "precision": "exact-integer-replay",
        },
        "checks": {name: _bundle(name) for name in ("tenure", "windows", "delegation")},
        "controls": {
            "boolean_integer": _bundle("windows", mutate=_boolean_integer),
            "unadmitted_unit": _bundle("windows", unit="millisecond"),
            "revival": _bundle("tenure", mutate=_revival),
            "widened_scope": _bundle("delegation", mutate=_widened_scope),
            "unsupported_asset": _bundle("tenure", mutate=_unsupported_asset),
        },
    }


def main() -> int:
    raw = sys.stdin.buffer.read(16385)
    if len(raw) > 16384:
        raise ValueError("worker request exceeds bound")
    request = json.loads(raw)
    if (
        type(request) is not dict
        or set(request) != {
            "schema_version", "nonce", "object_id", "object_digest", "collection_digest"
        }
        or request["schema_version"] != "verifier-token-asset-request-1"
        or any(type(value) is not str or not 1 <= len(value) <= 256 for value in request.values())
    ):
        raise ValueError("closed bounded token ASSET request required")
    # The worker runs with -I -S.  Admit only this installed source package,
    # and keep all generated bytecode in a disposable external directory.
    with tempfile.TemporaryDirectory(prefix="vstd-token-asset-check-") as temporary:
        sys.pycache_prefix = str(Path(temporary) / "empty-bytecode")
        sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
        before = source_pins()
        observations = observe()
        after = source_pins()
    if before != after:
        raise ValueError("worker source changed")
    report = {
        "schema_version": "verifier-token-asset-observations-1",
        "request": request,
        "source_pins": before,
        "observations": observations,
    }
    sys.stdout.write(json.dumps(
        report, sort_keys=True, separators=(",", ":"), allow_nan=False
    ) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

