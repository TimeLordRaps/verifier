"""Render a JavaScript Object Notation (JSON)-bound native-case payload module."""
from __future__ import annotations

import argparse
import base64
import hashlib
import inspect
import json
from pathlib import Path
from types import ModuleType
from typing import Any

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.domains import certification as domain_certification
from verifier.domains.contracts.certificate_dag import artifact_files_digest
from verifier.domains.contracts import current_object_routes
from verifier.runtime import core_obligation_union
from verifier.runtime import core_tier_progression


def _load(path: Path) -> ModuleType:
    selected = path.resolve()
    scripts = Path(__file__).resolve().parent
    if selected.parent != scripts:
        raise RuntimeError("native case builder is outside the selected scripts root")
    name = selected.name
    if name == "build_self_polish_native_cases.py":
        if __package__:
            from scripts import build_self_polish_native_cases as module
        else:
            import build_self_polish_native_cases as module
    elif name == "build_self_polish_native_full_candidate.py":
        if __package__:
            from scripts import build_self_polish_native_full_candidate as module
        else:
            import build_self_polish_native_full_candidate as module
    elif name == "build_self_polish_native_tier3_cases.py":
        if __package__:
            from scripts import build_self_polish_native_tier3_cases as module
        else:
            import build_self_polish_native_tier3_cases as module
    elif name == "build_self_polish_native_tier4_cases.py":
        if __package__:
            from scripts import build_self_polish_native_tier4_cases as module
        else:
            import build_self_polish_native_tier4_cases as module
    elif name == "build_self_polish_native_tier5_cases.py":
        if __package__:
            from scripts import build_self_polish_native_tier5_cases as module
        else:
            import build_self_polish_native_tier5_cases as module
    elif name == "build_self_polish_native_tier6_cases.py":
        if __package__:
            from scripts import build_self_polish_native_tier6_cases as module
        else:
            import build_self_polish_native_tier6_cases as module
    elif name == "build_self_polish_native_tier7_cases.py":
        if __package__:
            from scripts import build_self_polish_native_tier7_cases as module
        else:
            import build_self_polish_native_tier7_cases as module
    elif name == "build_self_polish_native_tier8_cases.py":
        if __package__:
            from scripts import build_self_polish_native_tier8_cases as module
        else:
            import build_self_polish_native_tier8_cases as module
    elif name == "build_self_polish_native_tier9_cases.py":
        if __package__:
            from scripts import build_self_polish_native_tier9_cases as module
        else:
            import build_self_polish_native_tier9_cases as module
    else:
        raise RuntimeError("native case builder is not registered")
    return module


def _public_contract_functions(
        checking_mechanism: str,
        ) -> tuple[ModuleType, Any, Any, Any, Any]:
    """Resolve a route's public application programming interface (API)."""

    module_name, recheck_name = checking_mechanism.rsplit(".", 1)
    if not (
        module_name.startswith("verifier.domains.contracts.")
        and recheck_name.startswith("recheck_")
        and recheck_name.endswith("_certificate")
    ):
        raise RuntimeError("native case checking mechanism is not canonical")
    stem = recheck_name[len("recheck_"):-len("_certificate")]
    module = current_object_routes.registered_mechanism_module(
        checking_mechanism
    )
    try:
        policy = getattr(module, stem + "_policy")
        request = getattr(module, stem + "_request")
        builder = getattr(module, "build_" + stem + "_certificate")
        rechecker = getattr(module, recheck_name)
    except AttributeError as exc:
        raise RuntimeError("native case public contract API is unavailable") from exc
    if not all(callable(item) for item in (policy, request, builder, rechecker)):
        raise RuntimeError("native case public contract API is unavailable")
    return module, policy, request, builder, rechecker


def _invoke_from_seed(
        function: Any, seed: dict[str, Any], *,
        overrides: dict[str, Any] | None = None,
        ) -> Any:
    """Call a public constructor from preserved semantic inputs only."""

    selected = {} if overrides is None else dict(overrides)
    arguments: dict[str, Any] = {}
    for name, parameter in inspect.signature(function).parameters.items():
        if name in selected:
            arguments[name] = selected[name]
        elif name in seed:
            arguments[name] = seed[name]
        elif parameter.default is inspect.Parameter.empty:
            raise RuntimeError(
                "native case semantic seed lacks constructor input: " + name
            )
    return function(**arguments)


def _is_policy(value: Any) -> bool:
    return (
        type(value) is dict
        and type(value.get("mechanism_id")) is str
        and type(value.get("mechanism_digest")) is str
        and type(value.get("schema_version")) is str
        and "policy" in value["schema_version"]
    )


def _is_request(value: Any) -> bool:
    return (
        type(value) is dict
        and type(value.get("coordinate")) is str
        and type(value.get("policy_digest")) is str
        and type(value.get("schema_version")) is str
        and "request" in value["schema_version"]
    )


def _is_certificate(value: Any) -> bool:
    return (
        type(value) is dict
        and type(value.get("request")) is dict
        and type(value.get("policy_digest")) is str
        and type(value.get("mechanism_digest")) is str
        and type(value.get("evidence_payloads")) is dict
        and type(value.get("result")) is dict
        and type(value.get("digest")) is str
        and type(value.get("schema_version")) is str
        and "certificate" in value["schema_version"]
    )


def _is_domain_certificate(value: Any) -> bool:
    return (
        type(value) is dict
        and value.get("schema_version") == "verifier-domain-certification-1"
        and type(value.get("request")) is dict
        and type(value.get("evidence")) is dict
        and type(value.get("policy_digest")) is str
        and type(value.get("mechanism_digest")) is str
        and type(value.get("specification_digest")) is str
        and type(value.get("result")) is dict
        and type(value.get("certificate_digest")) is str
    )


def _is_namespace_object(value: Any) -> bool:
    return (
        type(value) is dict
        and set(value) == {"kind", "object_id", "operands", "payload"}
        and type(value.get("kind")) is str
        and type(value.get("object_id")) is str
        and type(value.get("operands")) is dict
        and type(value.get("payload")) is dict
    )


def _namespace_object(value: dict[str, Any]) -> NamespaceObject:
    return NamespaceObject.create(
        value["object_id"], value["kind"], value["payload"],
        value["operands"],
    )


class SourceCaseRebinder:
    """Rebuild source-derived case bindings while retaining reviewed semantics.

    The rebinder never edits digest-looking text in place. It resolves every
    policy and request through the route's public constructors and rebuilds
    embedded prerequisite certificates from their retained evidence payloads.
    The caller must still replay the resulting PASS/FAIL/UNKNOWN triad.
    """

    def __init__(self, cases: dict[str, dict[str, Any]]) -> None:
        inventory = core_tier_progression.installed_core_route_inventory()
        if inventory.get("status") != "PASS":
            raise RuntimeError("native case route inventory is not PASS")
        self._mechanism_by_coordinate: dict[str, str] = {}
        self._contract_by_mechanism_id: dict[str, str] = {}
        for cell in inventory.get("family_cells", []):
            if type(cell) is not dict:
                continue
            for row in cell.get("registered_route_memberships", []):
                if type(row) is not dict:
                    continue
                coordinate = row.get("coordinate")
                mechanism = row.get("checking_mechanism")
                if type(coordinate) is not str or type(mechanism) is not str:
                    continue
                prior = self._mechanism_by_coordinate.setdefault(
                    coordinate, mechanism
                )
                if prior != mechanism:
                    raise RuntimeError("native case route mechanism is ambiguous")
                module, _, _, _, _ = _public_contract_functions(mechanism)
                mechanism_id = getattr(module, "MECHANISM_ID", None)
                if type(mechanism_id) is not str:
                    raise RuntimeError("native case mechanism identifier is unavailable")
                prior = self._contract_by_mechanism_id.setdefault(
                    mechanism_id, mechanism
                )
                if prior != mechanism:
                    raise RuntimeError("native case mechanism identifier is ambiguous")

        self._policy_seed_by_digest: dict[str, dict[str, Any]] = {}
        self._policy_cache: dict[str, dict[str, Any]] = {}
        self._request_cache: dict[str, dict[str, Any]] = {}
        self._digest_replacements: dict[str, str] = {}
        self._active_policy: dict[str, Any] | None = None
        self._active_request: dict[str, Any] | None = None
        for case in cases.values():
            self._scan(case)
        # Establish every reviewed policy's current source binding before any
        # evidence object that declares one of those mechanisms is rebuilt.
        for seed in list(self._policy_seed_by_digest.values()):
            self.refresh_policy(seed)

    @staticmethod
    def _bytes_digest(raw: bytes) -> str:
        return "sha256:" + hashlib.sha256(raw).hexdigest()

    def _remember_digest(self, old: str, new: str) -> None:
        if old == new:
            return
        prior = self._digest_replacements.setdefault(old, new)
        if prior != new:
            raise RuntimeError("native case derived digest mapping is ambiguous")

    def _scan(self, value: Any) -> None:
        if _is_policy(value):
            digest = core_obligation_union.value_digest(value)
            prior = self._policy_seed_by_digest.setdefault(digest, value)
            if canonical_bytes(prior) != canonical_bytes(value):
                raise RuntimeError("native case policy digest collision")
        if type(value) is dict:
            for item in value.values():
                self._scan(item)
            return
        if type(value) is list:
            for item in value:
                self._scan(item)
            return
        if type(value) is not str:
            return
        try:
            raw = base64.b64decode(value, validate=True)
            decoded = json.loads(raw.decode("utf-8"))
        except (ValueError, TypeError, UnicodeError, json.JSONDecodeError):
            return
        self._scan(decoded)

    def _replace_digest(self, value: Any) -> Any:
        if type(value) is str:
            seen: set[str] = set()
            while value in self._digest_replacements and value not in seen:
                seen.add(value)
                value = self._digest_replacements[value]
            return value
        if _is_policy(value):
            return self.refresh_policy(value)
        if _is_request(value):
            return self.refresh_request(value)
        if type(value) is dict:
            return {
                key: self._replace_digest(item)
                for key, item in value.items()
            }
        if type(value) is list:
            return [self._replace_digest(item) for item in value]
        return value

    def refresh_policy(self, seed: dict[str, Any]) -> dict[str, Any]:
        old_digest = core_obligation_union.value_digest(seed)
        cached = self._policy_cache.get(old_digest)
        if cached is not None:
            return cached
        mechanism = self._contract_by_mechanism_id.get(seed["mechanism_id"])
        if mechanism is None:
            raise RuntimeError("native case policy mechanism is not installed")
        _, policy_function, _, _, _ = _public_contract_functions(mechanism)
        semantic_seed = {
            key: self._replace_digest(value)
            for key, value in seed.items()
            if key not in {
                "schema_version", "mechanism_id", "mechanism_digest",
            }
        }
        refreshed = _invoke_from_seed(policy_function, semantic_seed)
        if not _is_policy(refreshed):
            raise RuntimeError("native case policy constructor output is invalid")
        self._policy_cache[old_digest] = refreshed
        self._remember_digest(
            seed["mechanism_digest"], refreshed["mechanism_digest"]
        )
        self._remember_digest(
            old_digest, core_obligation_union.value_digest(refreshed)
        )
        return refreshed

    def _policy_for_request(
            self, request: dict[str, Any],
            override: dict[str, Any] | None,
            ) -> dict[str, Any]:
        if override is not None:
            return override
        seed = self._policy_seed_by_digest.get(request["policy_digest"])
        if seed is None:
            raise RuntimeError("native case request policy seed is unavailable")
        return self.refresh_policy(seed)

    def refresh_request(
            self, seed: dict[str, Any], *,
            policy: dict[str, Any] | None = None,
            evidence_ref: str | None = None,
            ) -> dict[str, Any]:
        old_digest = core_obligation_union.value_digest(seed)
        cached = self._request_cache.get(old_digest)
        if cached is not None and evidence_ref is None and policy is None:
            return cached
        mechanism = self._mechanism_by_coordinate.get(seed["coordinate"])
        if mechanism is None:
            raise RuntimeError("native case request route is not installed")
        _, _, request_function, _, _ = _public_contract_functions(mechanism)
        selected_policy = self._policy_for_request(seed, policy)
        semantic_seed = {
            key: self._replace_digest(value)
            for key, value in seed.items()
            if key not in {
                "schema_version", "semantic_version", "coordinate",
                "proposition_digest", "policy_digest",
            }
        }
        overrides: dict[str, Any] = {"policy": selected_policy}
        if evidence_ref is not None:
            overrides["evidence_ref"] = evidence_ref
        refreshed = _invoke_from_seed(
            request_function, semantic_seed, overrides=overrides
        )
        if not _is_request(refreshed):
            raise RuntimeError("native case request constructor output is invalid")
        new_digest = core_obligation_union.value_digest(refreshed)
        self._request_cache[old_digest] = refreshed
        self._remember_digest(old_digest, new_digest)
        return refreshed

    def _refresh_embedded_value(self, value: Any) -> Any:
        if _is_domain_certificate(value):
            return self.refresh_domain_certificate(value)
        if _is_certificate(value):
            return json.loads(self.refresh_certificate(canonical_bytes(value)))
        if _is_policy(value):
            return self.refresh_policy(value)
        if _is_request(value):
            return self.refresh_request(value)
        if _is_namespace_object(value):
            old_object = _namespace_object(value)
            refreshed = {
                key: self._refresh_embedded_value(item)
                for key, item in value.items()
            }
            new_object = _namespace_object(refreshed)
            self._remember_digest(old_object.digest, new_object.digest)
            return new_object.to_dict()
        if type(value) is dict:
            refreshed: dict[str, Any] = {}
            # Rebuild retained dependencies before records whose payloads bind
            # their resulting digests. Canonical JSON key order places an
            # ``artifact`` before ``inputs``, so ordinary iteration is not a
            # dependency order for nested native-domain certificates.
            for dependency_key in ("artifact_files", "inputs"):
                if dependency_key in value:
                    refreshed[dependency_key] = self._refresh_embedded_value(
                        value[dependency_key]
                    )
            old_files = value.get("artifact_files")
            new_files = refreshed.get("artifact_files")
            if (
                type(old_files) is dict
                and type(new_files) is dict
                and all(type(item) is str for item in old_files.values())
                and all(type(item) is str for item in new_files.values())
            ):
                try:
                    old_raw_files = {
                        path: base64.b64decode(item, validate=True)
                        for path, item in old_files.items()
                    }
                    new_raw_files = {
                        path: base64.b64decode(item, validate=True)
                        for path, item in new_files.items()
                    }
                except (ValueError, TypeError):
                    pass
                else:
                    self._remember_digest(
                        artifact_files_digest(old_raw_files),
                        artifact_files_digest(new_raw_files),
                    )
            for key, item in value.items():
                if key not in {"artifact_files", "inputs"}:
                    refreshed[key] = self._refresh_embedded_value(item)
            old_objects = value.get("objects")
            new_objects = refreshed.get("objects")
            if (
                type(old_objects) is list
                and type(new_objects) is list
                and all(_is_namespace_object(item) for item in old_objects)
                and all(_is_namespace_object(item) for item in new_objects)
            ):
                old_collection = [
                    _namespace_object(item) for item in old_objects
                ]
                new_collection = [
                    _namespace_object(item) for item in new_objects
                ]
                self._remember_digest(
                    composition_digest(old_collection),
                    composition_digest(new_collection),
                )
            return refreshed
        if type(value) is list:
            return [self._refresh_embedded_value(item) for item in value]
        if type(value) is not str:
            return self._replace_digest(value)
        try:
            raw = base64.b64decode(value, validate=True)
            decoded = json.loads(raw.decode("utf-8"))
        except (ValueError, TypeError, UnicodeError, json.JSONDecodeError):
            return self._replace_digest(value)
        refreshed = self._refresh_embedded_value(decoded)
        if canonical_bytes(refreshed) == raw:
            return value
        new_raw = canonical_bytes(refreshed)
        self._remember_digest(self._bytes_digest(raw), self._bytes_digest(new_raw))
        return base64.b64encode(new_raw).decode("ascii")

    def refresh_evidence(self, raw: bytes) -> bytes:
        try:
            decoded = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            return raw
        refreshed = self._refresh_embedded_value(decoded)
        new_raw = canonical_bytes(refreshed)
        self._remember_digest(self._bytes_digest(raw), self._bytes_digest(new_raw))
        return new_raw

    def _refresh_evidence_with_context(
            self, raw: bytes, *, policy: dict[str, Any],
            request: dict[str, Any],
            ) -> bytes:
        prior_policy, prior_request = self._active_policy, self._active_request
        self._active_policy, self._active_request = policy, request
        try:
            return self.refresh_evidence(raw)
        finally:
            self._active_policy, self._active_request = (
                prior_policy, prior_request
            )

    def refresh_domain_certificate(
            self, certificate: dict[str, Any],
            ) -> dict[str, Any]:
        """Rebuild one legacy native-domain child under its parent bounds."""

        policy, request = self._active_policy, self._active_request
        if policy is None or request is None:
            raise RuntimeError("native domain certificate parent is unavailable")
        limits = request.get("limits")
        if type(limits) is not dict:
            raise RuntimeError("native domain certificate bounds are unavailable")
        required_limits = {
            "max_operations", "max_items", "max_evidence_bytes",
        }
        if not required_limits <= set(limits):
            raise RuntimeError("native domain certificate bounds are unavailable")
        roots = policy.get("trust_roots")
        if type(roots) is not list:
            raise RuntimeError("native domain certificate roots are unavailable")
        witness_keys = policy.get("witness_keys", {})
        if type(witness_keys) is not dict:
            raise RuntimeError("native domain certificate keys are unavailable")
        child_policy = domain_certification.domain_policy(
            trust_roots=roots,
            witness_keys=witness_keys,
            max_operations=limits["max_operations"],
            max_items=limits["max_items"],
            max_evidence_bytes=limits["max_evidence_bytes"],
            max_tolerance=policy.get("max_tolerance", 0),
        )
        refreshed_evidence = self._refresh_embedded_value(
            certificate["evidence"]
        )
        child_request = domain_certification.domain_request(
            refreshed_evidence,
            target_depth=certificate["request"]["target_depth"],
        )
        rebuilt = domain_certification.build_domain_certificate(
            child_request, refreshed_evidence, policy=child_policy
        )
        old_status = certificate["result"].get("status")
        new_status = rebuilt["result"].get("status")
        if old_status not in {"PASS", "FAIL", "UNKNOWN"} \
                or new_status != old_status:
            raise RuntimeError(
                "native domain certificate outcome changed: "
                f"{certificate['request'].get('domain')} "
                f"depth {certificate['request'].get('target_depth')} "
                f"expected {old_status} observed {new_status}"
            )
        for old, new in (
            (certificate["certificate_digest"], rebuilt["certificate_digest"]),
            (certificate["mechanism_digest"], rebuilt["mechanism_digest"]),
            (certificate["policy_digest"], rebuilt["policy_digest"]),
            (
                certificate["specification_digest"],
                rebuilt["specification_digest"],
            ),
            (
                core_obligation_union.value_digest(certificate),
                core_obligation_union.value_digest(rebuilt),
            ),
        ):
            self._remember_digest(old, new)
        return rebuilt

    def refresh_certificate(self, raw: bytes) -> bytes:
        try:
            certificate = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise RuntimeError("native prerequisite certificate is invalid") from exc
        if not _is_certificate(certificate):
            raise RuntimeError("native prerequisite certificate is invalid")
        old_request = certificate["request"]
        mechanism = self._mechanism_by_coordinate.get(old_request["coordinate"])
        if mechanism is None:
            raise RuntimeError("native prerequisite route is not installed")
        _, _, _, builder, rechecker = _public_contract_functions(mechanism)
        policy_seed = self._policy_seed_by_digest.get(
            certificate["policy_digest"]
        )
        if policy_seed is None:
            raise RuntimeError("native prerequisite policy seed is unavailable")
        policy = self.refresh_policy(policy_seed)
        evidence_ref = old_request.get("evidence_ref")
        payloads = certificate["evidence_payloads"]
        if type(evidence_ref) is not str or type(payloads.get(evidence_ref)) is not str:
            raise RuntimeError("native prerequisite evidence payload is unavailable")
        try:
            old_evidence = base64.b64decode(
                payloads[evidence_ref], validate=True
            )
        except (ValueError, TypeError) as exc:
            raise RuntimeError("native prerequisite evidence payload is invalid") from exc
        evidence = self._refresh_evidence_with_context(
            old_evidence, policy=policy, request=old_request
        )
        new_evidence_ref = self._bytes_digest(evidence)
        self._remember_digest(evidence_ref, new_evidence_ref)
        request = self.refresh_request(
            old_request, policy=policy, evidence_ref=new_evidence_ref
        )
        rebuilt = builder(request, evidence, policy=policy)
        result = rechecker(
            rebuilt, expected_request=request, policy=policy
        )
        expected_status = certificate["result"].get("status")
        if (
            expected_status not in {"PASS", "FAIL", "UNKNOWN"}
            or result.get("status") != expected_status
        ):
            raise RuntimeError(
                "native prerequisite certificate outcome changed"
            )
        rebuilt_value = json.loads(rebuilt)
        self._remember_digest(
            certificate["digest"], rebuilt_value["digest"]
        )
        self._remember_digest(
            core_obligation_union.value_digest(certificate),
            core_obligation_union.value_digest(rebuilt_value),
        )
        self._remember_digest(self._bytes_digest(raw), self._bytes_digest(rebuilt))
        return rebuilt

    def refresh_case(self, case: dict[str, Any]) -> dict[str, Any]:
        """Return one case rebuilt against current source through public APIs."""

        selected = dict(case)
        policy = self.refresh_policy(selected["policy"])
        evidence = base64.b64decode(
            selected["evidence_base64"], validate=True
        )
        refreshed_evidence = self._refresh_evidence_with_context(
            evidence, policy=policy, request=selected["request"]
        )
        new_evidence_ref = self._bytes_digest(refreshed_evidence)
        old_evidence_ref = selected["request"].get("evidence_ref")
        if type(old_evidence_ref) is str:
            self._remember_digest(old_evidence_ref, new_evidence_ref)
        request = self.refresh_request(
            selected["request"], policy=policy,
            evidence_ref=(
                new_evidence_ref if type(old_evidence_ref) is str else None
            ),
        )
        selected.update({
            "evidence_base64": base64.b64encode(
                refreshed_evidence
            ).decode("ascii"),
            "policy": policy,
            "request": request,
        })
        return selected


def render(
        *, builder_path: Path, target_path: Path, tier: int,
        entry_count: int, expected_digest: str,
        max_encoded_bytes: int, max_decompressed_bytes: int,
        adapter_metadata: bool = False,
        ) -> bytes:
    builder = _load(builder_path)
    raw, encoded = builder.build_payload()
    if (
        type(raw) is not bytes
        or type(encoded) is not bytes
        or core_obligation_union.bytes_digest(raw) != expected_digest
        or len(encoded) > max_encoded_bytes
        or len(raw) > max_decompressed_bytes
    ):
        raise RuntimeError("native case builder output differs")
    chunks = "\n".join(
        "    b'" + encoded[offset:offset + 88].decode("ascii") + "'"
        for offset in range(0, len(encoded), 88)
    )
    entry_keys = (
        '{"builder_adapter", "checking_mechanism", "evidence_base64", '
        '"negative_adapter", "policy", "request", "unknown_adapter"}'
        if adapter_metadata
        else '{"checking_mechanism", "request", "policy", '
        '"evidence_base64"}'
    )
    adapter_checks = (
        '''\n            and type(item["builder_adapter"]) is str
            and bool(item["builder_adapter"])
            and type(item["negative_adapter"]) is str
            and bool(item["negative_adapter"])
            and type(item["unknown_adapter"]) is str
            and bool(item["unknown_adapter"])'''
        if adapter_metadata else ""
    )
    source = f'''"""Source-bound installed Tier-{tier} specimens for native replay.

This generated module only decodes reviewed inputs. It does not register them
or claim Tier-{tier} conformance by itself.
"""
from __future__ import annotations

import base64
import binascii
import json
import zlib
from typing import Any

from verifier.runtime import core_obligation_union


CASE_REGISTRY_SCHEMA = "verifier-self-polish-native-tier{tier}-case-registry-1"
CASE_REGISTRY_ENTRY_COUNT = {entry_count}
CASE_REGISTRY_DIGEST = "{expected_digest}"
MAX_ENCODED_PAYLOAD_BYTES = {max_encoded_bytes}
MAX_COMPRESSED_PAYLOAD_BYTES = {max_encoded_bytes}
MAX_DECOMPRESSED_PAYLOAD_BYTES = {max_decompressed_bytes}
_PAYLOAD_B85 = (
{chunks}
)


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {{}}
    for key, item in pairs:
        if key in value:
            raise ValueError("NATIVE_CASE_REGISTRY_DUPLICATE_KEY")
        value[key] = item
    return value


def _bounded_decompress(raw: bytes) -> bytes:
    if not raw or len(raw) > MAX_COMPRESSED_PAYLOAD_BYTES:
        raise ValueError("NATIVE_CASE_REGISTRY_CAPACITY_EXHAUSTED")
    decoder = zlib.decompressobj()
    output = bytearray()
    offset = 0
    try:
        while offset < len(raw):
            chunk = raw[offset:offset + 64 * 1024]
            offset += len(chunk)
            while chunk:
                remaining = MAX_DECOMPRESSED_PAYLOAD_BYTES - len(output)
                if remaining <= 0:
                    raise ValueError("NATIVE_CASE_REGISTRY_CAPACITY_EXHAUSTED")
                output.extend(decoder.decompress(chunk, remaining + 1))
                if len(output) > MAX_DECOMPRESSED_PAYLOAD_BYTES:
                    raise ValueError("NATIVE_CASE_REGISTRY_CAPACITY_EXHAUSTED")
                chunk = decoder.unconsumed_tail
        remaining = MAX_DECOMPRESSED_PAYLOAD_BYTES - len(output)
        output.extend(decoder.flush(remaining + 1))
    except zlib.error as exc:
        raise ValueError("NATIVE_CASE_REGISTRY_INVALID") from exc
    if len(output) > MAX_DECOMPRESSED_PAYLOAD_BYTES:
        raise ValueError("NATIVE_CASE_REGISTRY_CAPACITY_EXHAUSTED")
    if not decoder.eof or decoder.unused_data:
        raise ValueError("NATIVE_CASE_REGISTRY_INVALID")
    return bytes(output)


def installed_case_inputs() -> dict[str, dict[str, Any]]:
    if not _PAYLOAD_B85 or len(_PAYLOAD_B85) > MAX_ENCODED_PAYLOAD_BYTES:
        raise ValueError("NATIVE_CASE_REGISTRY_CAPACITY_EXHAUSTED")
    try:
        compressed = base64.b85decode(_PAYLOAD_B85)
        raw = _bounded_decompress(compressed)
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except (binascii.Error, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("NATIVE_CASE_REGISTRY_INVALID") from exc
    if (
        type(value) is not dict
        or len(value) != CASE_REGISTRY_ENTRY_COUNT
        or core_obligation_union.bytes_digest(raw) != CASE_REGISTRY_DIGEST
        or json.dumps(
            value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8") != raw
        or not all(
            type(identifier) is str
            and bool(identifier)
            and type(item) is dict
            and set(item) == {entry_keys}
            and type(item["checking_mechanism"]) is str
            and bool(item["checking_mechanism"])
            and type(item["request"]) is dict
            and type(item["policy"]) is dict
            and type(item["evidence_base64"]) is str{adapter_checks}
            for identifier, item in value.items()
        )
    ):
        raise ValueError("NATIVE_CASE_REGISTRY_INVALID")
    return value


__all__ = [
    "CASE_REGISTRY_DIGEST", "CASE_REGISTRY_ENTRY_COUNT",
    "CASE_REGISTRY_SCHEMA", "MAX_COMPRESSED_PAYLOAD_BYTES",
    "MAX_DECOMPRESSED_PAYLOAD_BYTES", "MAX_ENCODED_PAYLOAD_BYTES",
    "installed_case_inputs",
]
'''
    target_path.write_bytes(source.encode("utf-8"))
    return source.encode("utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--builder", type=Path, required=True)
    parser.add_argument("--target", type=Path, required=True)
    parser.add_argument("--tier", type=int, required=True)
    parser.add_argument("--entry-count", type=int, required=True)
    parser.add_argument("--expected-digest", required=True)
    parser.add_argument("--max-encoded-bytes", type=int, required=True)
    parser.add_argument("--max-decompressed-bytes", type=int, required=True)
    parser.add_argument("--adapter-metadata", action="store_true")
    args = parser.parse_args()
    rendered = render(
        builder_path=args.builder,
        target_path=args.target,
        tier=args.tier,
        entry_count=args.entry_count,
        expected_digest=args.expected_digest,
        max_encoded_bytes=args.max_encoded_bytes,
        max_decompressed_bytes=args.max_decompressed_bytes,
        adapter_metadata=args.adapter_metadata,
    )
    print(f"rendered_bytes={len(rendered)} target={args.target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
