"""Prepared, uninstalled native replay extensions.

This module composes independently decoded extension payloads without changing
the frozen Tier-1/Tier-2 registry or its SIM-2.1 patch.  Prepared inputs are not
reachable from package replay until a separate integration change admits them.
"""
from __future__ import annotations

import base64
import binascii
from collections import Counter
from pathlib import Path
from types import ModuleType
from typing import Any

from verifier.runtime import core_obligation_union
from verifier.runtime import core_tier_progression
from verifier.runtime import self_polish_native_tier3_cases
from verifier.runtime import self_polish_native_tier4_cases
from verifier.runtime import self_polish_native_tier5_cases
from verifier.runtime import self_polish_native_tier6_cases
from verifier.runtime import self_polish_native_tier7_cases
from verifier.runtime import self_polish_native_tier8_cases
from verifier.runtime import self_polish_native_tier9_cases


REGISTRY_SCHEMA = "verifier-self-polish-native-extension-registry-1"
MAX_EVIDENCE_BYTES = 8 * 1024 * 1024
_ENTRY_KEYS = {
    "builder_adapter", "checking_mechanism", "evidence_base64",
    "negative_adapter", "policy", "request", "unknown_adapter",
}
_TIER_MODULES: dict[int, ModuleType] = {
    3: self_polish_native_tier3_cases,
    4: self_polish_native_tier4_cases,
    5: self_polish_native_tier5_cases,
    6: self_polish_native_tier6_cases,
    7: self_polish_native_tier7_cases,
    8: self_polish_native_tier8_cases,
    9: self_polish_native_tier9_cases,
}
_TIER_COUNTS = {
    3: 31, 4: 32, 5: 26, 6: 26, 7: 156, 8: 26, 9: 29,
}


class NativeExtensionError(ValueError):
    """A prepared extension payload differs from its source route inventory."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise NativeExtensionError(code)


def _digest(value: Any) -> str:
    return core_obligation_union.value_digest(value)


def _tier_case_inputs(tier: int, module: ModuleType) -> dict[str, dict[str, Any]]:
    """Return prepared inputs; tier 3 retained rows carry fresh live-mechanism triads."""

    if tier == 3:
        return self_polish_native_tier3_cases.prepared_case_inputs()
    return module.installed_case_inputs()


def _prepared_overlays() -> list[dict[str, Any]]:
    review = self_polish_native_tier3_cases.installed_source_review()
    return [{
        "tier": 3,
        "coordinates": sorted(
            identifier for identifier, row in review.items()
            if row["disposition"] == "RETAIN_UNKNOWN"
        ),
        "overlay_registry_digest": (
            self_polish_native_tier3_cases.PREPARED_CURRENT_CASE_REGISTRY_DIGEST
        ),
    }]


def _membership_rows(tier: int) -> list[dict[str, Any]]:
    expected_count = _TIER_COUNTS.get(tier)
    _require(expected_count is not None, "NATIVE_EXTENSION_TIER_INVALID")
    inventory = core_tier_progression.installed_core_route_inventory()
    _require(
        inventory.get("status") == "PASS",
        "NATIVE_EXTENSION_ROUTE_INVENTORY_NOT_PASS",
    )
    rows = [
        {
            "obligation_id": f"{cell['object_kind']}:{member['coordinate']}",
            "object_kind": cell["object_kind"],
            "tier": tier,
            "coordinate": member["coordinate"],
            "proposition_digest": member["proposition_digest"],
            "semantic_version": member["semantic_version"],
            "certificate_schema_version": member[
                "certificate_schema_version"
            ],
            "checking_mechanism": member["checking_mechanism"],
            "scope": member["scope"],
            "required_case_kinds": ["POSITIVE", "NEGATIVE", "UNKNOWN"],
        }
        for cell in inventory.get("family_cells", [])
        if type(cell) is dict and cell.get("tier") == tier
        for member in cell.get("registered_route_memberships", [])
        if type(member) is dict
    ]
    rows.sort(key=lambda row: row["obligation_id"])
    _require(
        len(rows) == expected_count
        and len({row["obligation_id"] for row in rows}) == expected_count,
        "NATIVE_EXTENSION_MEMBERSHIP_DENOMINATOR_DIFFERS",
    )
    return rows


def prepared_extension_case_inputs() -> dict[str, dict[str, Any]]:
    """Return exact prepared inputs after source and route binding checks."""

    combined: dict[str, dict[str, Any]] = {}
    for tier, module in _TIER_MODULES.items():
        rows = _membership_rows(tier)
        expected = {row["obligation_id"]: row for row in rows}
        selected = _tier_case_inputs(tier, module)
        _require(
            type(selected) is dict and set(selected) == set(expected),
            "NATIVE_EXTENSION_CASE_DENOMINATOR_DIFFERS",
        )
        for identifier, case in selected.items():
            row = expected[identifier]
            _require(
                type(case) is dict
                and set(case) == _ENTRY_KEYS
                and case["checking_mechanism"]
                    == row["checking_mechanism"]
                and type(case["request"]) is dict
                and type(case["policy"]) is dict
                and type(case["evidence_base64"]) is str
                and all(
                    type(case[key]) is str and bool(case[key])
                    for key in (
                        "builder_adapter", "negative_adapter",
                        "unknown_adapter",
                    )
                ),
                "NATIVE_EXTENSION_CASE_BINDING_DIFFERS",
            )
            request = case["request"]
            _require(
                request.get("coordinate") == row["coordinate"]
                and request.get("semantic_version")
                    == row["semantic_version"]
                and request.get("proposition_digest")
                    == row["proposition_digest"]
                and request.get("policy_digest") == _digest(case["policy"]),
                "NATIVE_EXTENSION_REQUEST_BINDING_DIFFERS",
            )
            try:
                evidence = base64.b64decode(
                    case["evidence_base64"], validate=True
                )
            except (ValueError, binascii.Error) as exc:
                raise NativeExtensionError(
                    "NATIVE_EXTENSION_EVIDENCE_INVALID"
                ) from exc
            _require(
                0 < len(evidence) <= MAX_EVIDENCE_BYTES,
                "NATIVE_EXTENSION_EVIDENCE_CAPACITY_EXHAUSTED",
            )
            _require(
                identifier not in combined,
                "NATIVE_EXTENSION_CASE_IDENTITY_DUPLICATED",
            )
            combined[identifier] = case
    return combined


def prepared_extension_registry() -> dict[str, Any]:
    """Describe prepared inputs without promoting them to installed replay."""

    memberships = {
        str(tier): _membership_rows(tier) for tier in _TIER_MODULES
    }
    cases = prepared_extension_case_inputs()
    builder_counts = Counter(
        case["builder_adapter"] for case in cases.values()
    )
    negative_counts = Counter(
        case["negative_adapter"] for case in cases.values()
    )
    unknown_counts = Counter(
        case["unknown_adapter"] for case in cases.values()
    )
    sources = [
        {
            "tier": tier,
            "module": module.__name__,
            "module_digest": core_obligation_union.bytes_digest(
                Path(module.__file__).read_bytes()
            ),
            "case_registry_schema": module.CASE_REGISTRY_SCHEMA,
            "case_registry_digest": module.CASE_REGISTRY_DIGEST,
            "case_registry_entry_count": module.CASE_REGISTRY_ENTRY_COUNT,
        }
        for tier, module in _TIER_MODULES.items()
    ]
    membership_count = len(cases)
    body = {
        "schema_version": REGISTRY_SCHEMA,
        "status": "PREPARED_NOT_INSTALLED",
        "tiers": list(_TIER_MODULES),
        "tier_membership_counts": {
            str(tier): count for tier, count in _TIER_COUNTS.items()
        },
        "membership_count": membership_count,
        "case_count": membership_count * 3,
        "memberships_by_tier": memberships,
        "case_input_digest": _digest(cases),
        "source_modules": sources,
        "prepared_current_overlays": _prepared_overlays(),
        "builder_adapter_counts": dict(sorted(builder_counts.items())),
        "negative_adapter_counts": dict(sorted(negative_counts.items())),
        "unknown_adapter_counts": dict(sorted(unknown_counts.items())),
        "whole_tier_conformance": "NOT_ESTABLISHED",
        "release_authority": "NONE",
        "claim_boundary": (
            "Prepared source-bound inputs are not reachable from installed "
            "package replay and establish no tier or release qualification."
        ),
    }
    body["registry_digest"] = _digest(body)
    return body


__all__ = [
    "MAX_EVIDENCE_BYTES", "REGISTRY_SCHEMA", "NativeExtensionError",
    "prepared_extension_case_inputs", "prepared_extension_registry",
]
