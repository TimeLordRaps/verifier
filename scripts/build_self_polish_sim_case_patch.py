"""Regenerate the SIM-2.1 through SIM-2.5 native case dependency closure.

The installed case payload predates the reviewed composable SIM scope. This
tool retains its selected evidence, rebuilds every affected child certificate,
and emits a compressed exact-entry overlay for source review. It never changes
verdicts or accepts a stale mechanism commitment.

The public Ed25519 seed used by the SIM-2.4 collector is a fixture. Its
signature proves only that the retained fixture bytes are self-consistent; it
cannot satisfy provenance or authority, so the overlay labels it explicitly.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path
import sys
import zlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from verifier.domains.contracts import sim_dynamics  # noqa: E402
from verifier.domains.contracts import sim_internal_state  # noqa: E402
from verifier.domains.contracts import current_object_routes  # noqa: E402
from verifier.runtime import core_obligation_union  # noqa: E402
from verifier.runtime import self_polish_native_cases  # noqa: E402


TARGETS = (
    "SIM:SIM-2.1",
    "SIM:SIM-2.2",
    "SIM:SIM-2.3",
    "SIM:SIM-2.4",
    "SIM:SIM-2.5",
)
FIXTURE_AUTHORITY = "NON_AUTHORITATIVE_PUBLIC_TEST_SEED"
FIXTURE_SEED = bytes(range(32))


def _fixture_collector_key() -> str:
    signing_key = Ed25519PrivateKey.from_private_bytes(FIXTURE_SEED)
    return signing_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ).hex()


FIXTURE_COLLECTOR_KEY = _fixture_collector_key()


def _canonical(value: object) -> bytes:
    return core_obligation_union.canonical_bytes(value)


def _digest(raw: bytes) -> str:
    return core_obligation_union.bytes_digest(raw)


def _decode_base(base_raw: bytes | None = None) -> tuple[dict, bytes]:
    """Return the base registry, from the argument or the installed module."""

    if base_raw is None:
        compressed = base64.b85decode(self_polish_native_cases._PAYLOAD_B85)
        base_raw = self_polish_native_cases._bounded_decompress(compressed)
    return json.loads(base_raw.decode("utf-8")), base_raw


def _rebind(policy: dict, request: dict, module: object) -> tuple[dict, dict]:
    selected_policy = dict(policy)
    selected_policy["mechanism_digest"] = module.mechanism_digest()
    selected_request = dict(request)
    selected_request["policy_digest"] = core_obligation_union.value_digest(
        selected_policy
    )
    return selected_policy, selected_request


def _one_embedded_payload(certificate: bytes) -> bytes:
    envelope = json.loads(certificate.decode("utf-8"))
    payloads = envelope["evidence_payloads"]
    if len(payloads) != 1:
        raise RuntimeError("expected one embedded evidence payload")
    return base64.b64decode(next(iter(payloads.values())), validate=True)


def _refresh_trajectory(
        request: dict, policy: dict, certificate_b64: str,
        ) -> tuple[dict, dict, bytes]:
    old_certificate = base64.b64decode(certificate_b64, validate=True)
    evidence = _one_embedded_payload(old_certificate)
    selected_policy, selected_request = _rebind(
        policy, request, sim_dynamics
    )
    certificate = sim_dynamics.build_sim_dynamics_certificate(
        selected_request, evidence, policy=selected_policy
    )
    result = sim_dynamics.recheck_sim_dynamics_certificate(
        certificate,
        expected_request=selected_request,
        policy=selected_policy,
    )
    if result["status"] != "PASS":
        raise RuntimeError("rebuilt trajectory did not replay PASS")
    return selected_request, selected_policy, certificate


def _refresh_direct(entry: dict) -> dict:
    policy, request = _rebind(
        entry["policy"], entry["request"], sim_dynamics
    )
    refreshed = {**entry, "policy": policy, "request": request}
    _validate_entry(refreshed, "PASS")
    return refreshed


def _refresh_trajectory_parent(entry: dict, expected: str) -> dict:
    request = dict(entry["request"])
    evidence = json.loads(base64.b64decode(
        entry["evidence_base64"], validate=True
    ).decode("utf-8"))
    child_request, child_policy, child_certificate = _refresh_trajectory(
        request["trajectory_request"],
        request["trajectory_policy"],
        evidence["trajectory_certificate"],
    )
    request["trajectory_request"] = child_request
    request["trajectory_policy"] = child_policy
    request["trajectory_certificate_digest"] = _digest(child_certificate)
    evidence["trajectory_certificate"] = base64.b64encode(
        child_certificate
    ).decode("ascii")
    if request["coordinate"] == "SIM-2.4":
        signing_key = Ed25519PrivateKey.from_private_bytes(FIXTURE_SEED)
        if evidence["collector_key"] != FIXTURE_COLLECTOR_KEY:
            raise RuntimeError("stored collector does not match fixture key")
        signed = {
            name: item for name, item in evidence.items()
            if name != "signature"
        }
        evidence["signature"] = base64.b64encode(
            signing_key.sign(_canonical(signed))
        ).decode("ascii")
    evidence_bytes = _canonical(evidence)
    request["evidence_ref"] = _digest(evidence_bytes)
    module = current_object_routes.registered_mechanism_module(
        entry["checking_mechanism"]
    )
    policy, request = _rebind(entry["policy"], request, module)
    refreshed = {
        **entry,
        "policy": policy,
        "request": request,
        "evidence_base64": base64.b64encode(evidence_bytes).decode("ascii"),
    }
    _validate_entry(refreshed, expected)
    return refreshed


def _refresh_perspective(entry: dict) -> dict:
    request = dict(entry["request"])
    evidence = json.loads(base64.b64decode(
        entry["evidence_base64"], validate=True
    ).decode("utf-8"))
    old_internal_certificate = base64.b64decode(
        evidence["internal_state_certificate"], validate=True
    )
    internal_evidence = json.loads(
        _one_embedded_payload(old_internal_certificate).decode("utf-8")
    )
    internal_request = dict(request["internal_state_request"])
    trajectory_request, trajectory_policy, trajectory_certificate = (
        _refresh_trajectory(
            internal_request["trajectory_request"],
            internal_request["trajectory_policy"],
            internal_evidence["trajectory_certificate"],
        )
    )
    internal_request["trajectory_request"] = trajectory_request
    internal_request["trajectory_policy"] = trajectory_policy
    internal_request["trajectory_certificate_digest"] = _digest(
        trajectory_certificate
    )
    internal_evidence["trajectory_certificate"] = base64.b64encode(
        trajectory_certificate
    ).decode("ascii")
    internal_evidence_bytes = _canonical(internal_evidence)
    internal_request["evidence_ref"] = _digest(internal_evidence_bytes)
    internal_policy, internal_request = _rebind(
        request["internal_state_policy"],
        internal_request,
        sim_internal_state,
    )
    internal_certificate = (
        sim_internal_state.build_sim_internal_state_certificate(
            internal_request,
            internal_evidence_bytes,
            policy=internal_policy,
        )
    )
    internal_result = (
        sim_internal_state.recheck_sim_internal_state_certificate(
            internal_certificate,
            expected_request=internal_request,
            policy=internal_policy,
        )
    )
    if internal_result["status"] != "PASS":
        raise RuntimeError("rebuilt internal-state child did not replay PASS")
    request["internal_state_request"] = internal_request
    request["internal_state_policy"] = internal_policy
    request["internal_state_certificate_digest"] = _digest(
        internal_certificate
    )
    evidence["internal_state_certificate"] = base64.b64encode(
        internal_certificate
    ).decode("ascii")
    evidence_bytes = _canonical(evidence)
    request["evidence_ref"] = _digest(evidence_bytes)
    module = current_object_routes.registered_mechanism_module(
        entry["checking_mechanism"]
    )
    policy, request = _rebind(entry["policy"], request, module)
    refreshed = {
        **entry,
        "policy": policy,
        "request": request,
        "evidence_base64": base64.b64encode(evidence_bytes).decode("ascii"),
    }
    _validate_entry(refreshed, "PASS")
    return refreshed


def _validate_entry(entry: dict, expected: str) -> None:
    _, checker_name = entry["checking_mechanism"].rsplit(".", 1)
    module = current_object_routes.registered_mechanism_module(
        entry["checking_mechanism"]
    )
    builder = getattr(module, checker_name.replace("recheck_", "build_", 1))
    checker = getattr(module, checker_name)
    evidence = base64.b64decode(entry["evidence_base64"], validate=True)
    certificate = builder(entry["request"], evidence, policy=entry["policy"])
    result = checker(
        certificate,
        expected_request=entry["request"],
        policy=entry["policy"],
    )
    if result["status"] != expected:
        raise RuntimeError(
            f"{entry['request']['coordinate']} replayed {result['status']}"
        )


def build_patch(base_raw: bytes | None = None) -> tuple[dict, str]:
    """Rebuild the five SIM entries from the base registry bytes.

    Passing ``base_raw`` lets the orchestrator derive the overlay for a freshly
    generated base in one process, before any module is rewritten.
    """
    value, raw = _decode_base(base_raw)
    patch = {
        TARGETS[0]: _refresh_direct(value[TARGETS[0]]),
        TARGETS[1]: _refresh_trajectory_parent(value[TARGETS[1]], "PASS"),
        TARGETS[2]: _refresh_trajectory_parent(value[TARGETS[2]], "PASS"),
        TARGETS[3]: _refresh_trajectory_parent(value[TARGETS[3]], "UNKNOWN"),
        TARGETS[4]: _refresh_perspective(value[TARGETS[4]]),
    }
    return patch, "sha256:" + hashlib.sha256(raw).hexdigest()


_MODULE_TEMPLATE = '''"""Generated reviewed SIM native-case dependency-closure patch.

The original five specimens reproduce from ``bc19a6c0``. Their selected
mechanisms bind the installed source dependency closure, so a source change in
that closure requires deterministic certificate regeneration rather than a
digest-only edit. This patch rebuilds only SIM-2.1 through SIM-2.5 from the
already retained evidence, including nested certificates and the deterministic
SIM-2.4 fixture signature. Base-to-current outer mechanism digest prefixes are:
@@TRANSITIONS@@. The other 77 entries are unchanged.

``FIXTURE_AUTHORITY`` labels the SIM-2.4 collector key: it is a public test seed
whose signature cannot establish provenance, authority, or PASS.

Regenerate with ``scripts/build_self_polish_native_cases.py``. The exact base
registry digest prevents applying these entries to any other installed payload.
"""
from __future__ import annotations

import base64
import hashlib
import json
import zlib


BASE_REGISTRY_DIGEST = @@BASE_DIGEST@@
PATCH_DIGEST = @@PATCH_DIGEST@@
PATCH_ENTRY_COUNT = @@ENTRY_COUNT@@
MAX_PATCH_BYTES = 2 * 1024 * 1024
FIXTURE_AUTHORITY = @@FIXTURE_AUTHORITY@@
FIXTURE_COLLECTOR_KEY = @@FIXTURE_COLLECTOR_KEY@@
_PAYLOAD_B85 = (
@@CHUNKS@@
)


def _bounded_decompress(compressed: bytes) -> bytes:
    if not compressed or len(compressed) > MAX_PATCH_BYTES:
        raise ValueError("NATIVE_CASE_PATCH_CAPACITY_EXHAUSTED")
    decoder = zlib.decompressobj()
    output = decoder.decompress(compressed, MAX_PATCH_BYTES + 1)
    if (len(output) > MAX_PATCH_BYTES or decoder.unconsumed_tail
            or not decoder.eof or decoder.unused_data):
        raise ValueError("NATIVE_CASE_PATCH_CAPACITY_EXHAUSTED")
    return output


def installed_case_patch(base_raw: bytes) -> dict:
    if (type(base_raw) is not bytes
            or "sha256:" + hashlib.sha256(base_raw).hexdigest()
                != BASE_REGISTRY_DIGEST):
        raise ValueError("NATIVE_CASE_PATCH_BASE_DIFFERS")
    try:
        compressed = base64.b85decode(_PAYLOAD_B85)
        raw = _bounded_decompress(compressed)
        value = json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, zlib.error, json.JSONDecodeError) as exc:
        raise ValueError("NATIVE_CASE_PATCH_INVALID") from exc
    canonical = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    if (len(raw) > MAX_PATCH_BYTES or canonical != raw
            or type(value) is not dict
            or len(value) != PATCH_ENTRY_COUNT
            or "sha256:" + hashlib.sha256(raw).hexdigest() != PATCH_DIGEST):
        raise ValueError("NATIVE_CASE_PATCH_INVALID")
    return value


__all__ = [
    "BASE_REGISTRY_DIGEST", "FIXTURE_AUTHORITY", "FIXTURE_COLLECTOR_KEY",
    "PATCH_DIGEST", "PATCH_ENTRY_COUNT", "installed_case_patch",
]
'''


def render_patch_module(base_raw: bytes | None = None) -> tuple[bytes, dict]:
    """Return the complete overlay module bytes and the rebuilt entries."""

    patch, base_digest = build_patch(base_raw)
    base, _ = _decode_base(base_raw)
    raw = _canonical(patch)
    encoded = base64.b85encode(zlib.compress(raw, level=9)).decode("ascii")
    transitions = ";\n".join(
        f"{coordinate.removeprefix('SIM:SIM-')} "
        f"{base[coordinate]['policy']['mechanism_digest'][7:15]} to "
        f"{patch[coordinate]['policy']['mechanism_digest'][7:15]}"
        for coordinate in TARGETS
    )
    chunks = "\n".join(
        f"    {encoded[index:index + 88].encode('ascii')!r}"
        for index in range(0, len(encoded), 88)
    )
    source = (
        _MODULE_TEMPLATE
        .replace("@@TRANSITIONS@@", transitions)
        .replace("@@BASE_DIGEST@@", repr(base_digest))
        .replace("@@PATCH_DIGEST@@", repr(_digest(raw)))
        .replace("@@ENTRY_COUNT@@", str(len(patch)))
        .replace("@@FIXTURE_AUTHORITY@@", repr(FIXTURE_AUTHORITY))
        .replace("@@FIXTURE_COLLECTOR_KEY@@", repr(FIXTURE_COLLECTOR_KEY))
        .replace("@@CHUNKS@@", chunks)
    )
    return source.encode("utf-8"), patch


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    rendered, patch = render_patch_module()
    raw = _canonical(patch)
    encoded = base64.b85encode(zlib.compress(raw, level=9)).decode("ascii")
    result = {
        "entry_count": len(patch),
        "patch_digest": _digest(raw),
        "payload_b85": encoded,
    }
    if args.output is not None:
        args.output.resolve().write_bytes(rendered)
    print(json.dumps(result, sort_keys=True) if args.json else encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
