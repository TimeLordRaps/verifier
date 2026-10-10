"""Installed native replay and registry closure for numeric self-polish.

This module deliberately does not treat a green regression test as evidence for
an obligation.  A replay bundle contains native certificate bytes plus the
exact request and policy used by the obligation's installed rechecker.  The
rechecker result must exhibit the native PASS, FAIL, or UNKNOWN outcome named by
the case.  All membership identities and callable locations are re-derived from
the installed registries before any caller bytes are considered.
"""
from __future__ import annotations

import base64
import binascii
import importlib
import inspect
from pathlib import Path
from typing import Any

from verifier.core.namespace import ObjectKind
from verifier.core.receipt import strict_json_loads
from verifier.domains.contracts import application_requirements
from verifier.runtime import core_obligation_union
from verifier.runtime import core_tier_progression
from verifier.runtime import polish
from verifier.runtime import self_polish_native_cases


REGISTRY_SCHEMA = "verifier-self-polish-native-replay-registry-2"
CLOSURE_SCHEMA = "verifier-self-polish-installed-registry-closure-2"
MANIFEST_SCHEMA = "verifier-self-polish-native-replay-manifest-2"
RECEIPT_SCHEMA = "verifier-self-polish-native-replay-receipt-2"
CASE_KINDS = ("POSITIVE", "NEGATIVE", "UNKNOWN")
CASE_OUTCOMES = {"POSITIVE": "PASS", "NEGATIVE": "FAIL", "UNKNOWN": "UNKNOWN"}
MAX_MANIFEST_BYTES = 32 * 1024 * 1024
MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024


class NativeReplayError(ValueError):
    """A stable native-replay refusal code."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise NativeReplayError(code)


def _canonical(value: Any) -> bytes:
    return core_obligation_union.canonical_bytes(value)


def _digest(value: Any) -> str:
    return core_obligation_union.value_digest(value)


def mechanism_digest() -> str:
    """Bind the replay implementation and its installed native case inputs."""

    return _digest({
        "module_digest": core_obligation_union.bytes_digest(
            Path(__file__).read_bytes()
        ),
        "case_module_digest": core_obligation_union.bytes_digest(
            Path(self_polish_native_cases.__file__).read_bytes()
        ),
        "case_registry_schema": self_polish_native_cases.CASE_REGISTRY_SCHEMA,
    })


def _membership_rows(tier: int) -> list[dict[str, Any]]:
    inventory = core_tier_progression.installed_core_route_inventory()
    _require(inventory.get("status") == "PASS", "INSTALLED_ROUTE_INVENTORY_NOT_PASS")
    rows: list[dict[str, Any]] = []
    for cell in inventory.get("family_cells", []):
        if type(cell) is not dict or cell.get("tier") != tier:
            continue
        for member in cell.get("registered_route_memberships", []):
            _require(type(member) is dict, "INSTALLED_ROUTE_MEMBERSHIP_INVALID")
            rows.append({
                "obligation_id": f"{cell['object_kind']}:{member['coordinate']}",
                "object_kind": cell["object_kind"],
                "tier": tier,
                "coordinate": member["coordinate"],
                "proposition_digest": member["proposition_digest"],
                "semantic_version": member["semantic_version"],
                "certificate_schema_version": member["certificate_schema_version"],
                "checking_mechanism": member["checking_mechanism"],
                "scope": member["scope"],
                "required_case_kinds": list(CASE_KINDS),
            })
    rows.sort(key=lambda row: row["obligation_id"])
    expected = {1: 45, 2: 37}[tier]
    _require(len(rows) == expected
             and len({row["obligation_id"] for row in rows}) == expected,
             "INSTALLED_NATIVE_REPLAY_DENOMINATOR_DIFFERS")
    return rows


def installed_native_replay_registry() -> dict[str, Any]:
    """Return the versioned exact 45/37 native replay registry."""

    tiers = {str(tier): _membership_rows(tier) for tier in (1, 2)}
    cases = _installed_case_inputs(tiers)
    body = {
        "schema_version": REGISTRY_SCHEMA,
        "case_semantics": dict(CASE_OUTCOMES),
        "tier_membership_counts": {"1": 45, "2": 37},
        "case_input_registry_schema": (
            self_polish_native_cases.CASE_REGISTRY_SCHEMA
        ),
        "case_input_registry_digest": _digest(cases),
        "tiers": tiers,
    }
    body["registry_digest"] = _digest(body)
    return body


def _installed_case_inputs(
        tiers: dict[str, list[dict[str, Any]]] | None = None,
        ) -> dict[str, dict[str, Any]]:
    """Validate the installed builder inputs against the exact route registry."""

    selected = self_polish_native_cases.installed_case_inputs()
    _require(type(selected) is dict, "NATIVE_CASE_REGISTRY_INVALID")
    if tiers is None:
        tiers = {str(tier): _membership_rows(tier) for tier in (1, 2)}
    expected = {
        row["obligation_id"]: row
        for rows in tiers.values() for row in rows
    }
    _require(set(selected) == set(expected),
             "NATIVE_CASE_REGISTRY_DENOMINATOR_DIFFERS")
    for identifier, value in selected.items():
        _require(
            type(value) is dict
            and set(value) == {
                "checking_mechanism", "request", "policy",
                "evidence_base64",
            }
            and value["checking_mechanism"]
                == expected[identifier]["checking_mechanism"]
            and type(value["request"]) is dict
            and type(value["policy"]) is dict
            and type(value["evidence_base64"]) is str,
            "NATIVE_CASE_REGISTRY_BINDING_DIFFERS",
        )
        try:
            evidence = base64.b64decode(
                value["evidence_base64"], validate=True
            )
        except (ValueError, binascii.Error) as exc:
            raise NativeReplayError("NATIVE_CASE_REGISTRY_INVALID") from exc
        _require(0 < len(evidence) <= MAX_CERTIFICATE_BYTES,
                 "NATIVE_CASE_REGISTRY_CAPACITY_EXHAUSTED")
    return selected


def installed_registry_closure() -> dict[str, Any]:
    """Derive installed structural-to-route and catalog closure.

    The result is intentionally scoped to the installed Tier 1 and Tier 2
    registries.  It does not claim that the repository/package estate is closed.
    """

    kinds = [kind.value for kind in ObjectKind]
    families = application_requirements.installed_families(kinds)
    _require(type(families) is list and len(families) == 26,
             "INSTALLED_STRUCTURAL_FAMILY_DENOMINATOR_DIFFERS")
    structural: list[dict[str, Any]] = []
    for family in families:
        _require(type(family) is dict and type(family.get("members")) is list
                 and len(family["members"]) == 2,
                 "INSTALLED_STRUCTURAL_FAMILY_INVALID")
        for member in family["members"]:
            structural.append({
                "object_kind": family["represented_kind"],
                "coordinate": member["coordinate"],
                "proposition_digest": member["proposition_digest"],
                "rule_digest": member["rule_digest"],
            })
    structural.sort(key=lambda row: (row["object_kind"], row["coordinate"]))
    _require(len(structural) == 52, "INSTALLED_STRUCTURAL_MEMBERSHIP_DENOMINATOR_DIFFERS")

    registry = installed_native_replay_registry()
    route_rows = registry["tiers"]["1"]
    route_by_identity = {
        (row["object_kind"], row["coordinate"]): row for row in route_rows
    }
    object_base = route_by_identity.get(("OBJECT", "OBJECT-1.1"))
    _require(object_base is not None, "INSTALLED_OBJECT_BASE_ROUTE_MISSING")
    crosswalk: list[dict[str, Any]] = []
    for row in structural:
        direct = route_by_identity.get((row["object_kind"], row["coordinate"]))
        if direct is not None:
            _require(direct["proposition_digest"] == row["proposition_digest"],
                     "INSTALLED_STRUCTURAL_ROUTE_PROPOSITION_DIFFERS")
            route_ids = [direct["obligation_id"]]
            mode = "DIRECT"
        else:
            _require(row["coordinate"] == "OBJECT-1.1",
                     "INSTALLED_STRUCTURAL_ROUTE_UNMAPPED")
            kind_route = route_by_identity.get(
                (row["object_kind"], f"{row['object_kind']}-1.1")
            )
            _require(kind_route is not None
                     and row["proposition_digest"] == object_base["proposition_digest"],
                     "INSTALLED_STRUCTURAL_INHERITANCE_UNMAPPED")
            route_ids = [object_base["obligation_id"], kind_route["obligation_id"]]
            mode = "OBJECT_BASE_PLUS_KIND_SPECIALIZATION"
        crosswalk.append({
            "structural_identity": {
                "object_kind": row["object_kind"],
                "coordinate": row["coordinate"],
                "proposition_digest": row["proposition_digest"],
            },
            "route_obligation_ids": route_ids,
            "coverage_mode": mode,
        })

    catalog = polish.polish_catalog()
    catalog_rows = catalog.get("routes")
    _require(type(catalog_rows) is list, "INSTALLED_OBJECTIVE_CATALOG_INVALID")
    catalog_by_identity: dict[tuple[Any, Any], dict[str, Any]] = {}
    duplicate_catalog_identities: set[tuple[Any, Any]] = set()
    for row in catalog_rows:
        if type(row) is not dict:
            continue
        identity = (
            "OBJECT" if row.get("represented_kind_rule")
                == "externally_selected_admitted_kind"
                else row.get("represented_kind_rule"),
            row.get("objective"),
        )
        if identity in catalog_by_identity:
            duplicate_catalog_identities.add(identity)
        catalog_by_identity[identity] = row
    required_catalog_identities = {
        (route["object_kind"], route["coordinate"])
        for tier in (1, 2) for route in registry["tiers"][str(tier)]
    }
    _require(
        not (duplicate_catalog_identities & required_catalog_identities),
        "INSTALLED_OBJECTIVE_ROUTE_IDENTITY_DUPLICATED",
    )
    objective_bindings: list[dict[str, Any]] = []
    for tier in (1, 2):
        for route in registry["tiers"][str(tier)]:
            catalog_row = catalog_by_identity.get(
                (route["object_kind"], route["coordinate"])
            )
            _require(catalog_row is not None
                     and catalog_row.get("proposition_digest")
                         == route["proposition_digest"]
                     and catalog_row.get("semantic_version")
                         == route["semantic_version"]
                     and catalog_row.get("certificate_schema_version")
                         == route["certificate_schema_version"]
                     and catalog_row.get("scope") == route["scope"],
                     "INSTALLED_OBJECTIVE_ROUTE_BINDING_DIFFERS")
            objective_bindings.append({
                "obligation_id": route["obligation_id"],
                "tier": tier,
                "catalog_identity_digest": _digest(catalog_row),
            })
    body = {
        "schema_version": CLOSURE_SCHEMA,
        "status": "PASS",
        "scope": "INSTALLED_TIER1_TIER2_REGISTRIES_ONLY",
        "structural_membership_count": 52,
        "tier1_route_membership_count": 45,
        "tier2_route_membership_count": 37,
        "structural_route_crosswalk_status": "PASS",
        "installed_route_normative_closure": "PASS",
        "objective_inventory_closure": "PASS",
        "structural_membership_digest": _digest(structural),
        "crosswalk_digest": _digest(crosswalk),
        "objective_binding_digest": _digest(objective_bindings),
        "native_replay_registry_digest": registry["registry_digest"],
        "claim_boundary": (
            "PASS covers exact installed Tier 1 and Tier 2 registry structure, "
            "crosswalks, and catalog bindings only. Repository/package estate "
            "closure and per-obligation native outcomes remain separate gates."
        ),
    }
    body["closure_digest"] = _digest(body)
    return body


def _decode_manifest(raw: bytes) -> dict[str, Any]:
    _require(type(raw) is bytes and len(raw) <= MAX_MANIFEST_BYTES,
             "NATIVE_REPLAY_MANIFEST_CAPACITY_EXHAUSTED")
    try:
        value = strict_json_loads(raw.decode("utf-8"))
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        raise NativeReplayError("NATIVE_REPLAY_MANIFEST_INVALID") from exc
    _require(type(value) is dict and _canonical(value) == raw,
             "NATIVE_REPLAY_MANIFEST_INVALID")
    return value


def _resolve_mechanism(source_root: Path, dotted: str) -> tuple[Any, str, str]:
    module_name, symbol = dotted.rsplit(".", 1)
    module = importlib.import_module(module_name)
    function = getattr(module, symbol, None)
    _require(callable(function), "NATIVE_REPLAY_MECHANISM_UNAVAILABLE")
    expected = source_root.joinpath("src", *module_name.split(".")).with_suffix(".py").resolve()
    actual = Path(inspect.getsourcefile(function) or "").resolve()
    _require(actual == expected and expected.is_file(),
             "NATIVE_REPLAY_MECHANISM_SOURCE_DIFFERS")
    return (
        function,
        expected.relative_to(source_root).as_posix(),
        core_obligation_union.bytes_digest(expected.read_bytes()),
    )


def _negative_case(
        module: Any, obligation_id: str, request: dict[str, Any],
        ) -> tuple[dict[str, Any], bytes]:
    """Derive a real native refutation from a bound malformed evidence record."""

    selected = strict_json_loads(_canonical(request).decode("utf-8"))
    malformed = b"{}"
    malformed_digest = core_obligation_union.bytes_digest(malformed)
    if "evidence_ref" in selected:
        selected["evidence_ref"] = malformed_digest
    elif "evidence_digest" in selected:
        selected["evidence_digest"] = malformed_digest
    else:
        raise NativeReplayError("NATIVE_CASE_EVIDENCE_BINDING_UNAVAILABLE")
    if obligation_id == "OBJECT:OBJECT-1.1":
        malformed = _canonical({
            "kind": "OBJECT",
            "object_id": "different-object",
            "operands": {},
            "payload": {"x": 1},
        })
        malformed_digest = core_obligation_union.bytes_digest(malformed)
        selected["evidence_ref"] = malformed_digest
        selected["record_digest"] = malformed_digest
        address = module._address(
            object_id=selected["object_id"],
            object_kind=selected["object_kind"],
            record_digest=malformed_digest,
        )
        selected["address_digest"] = _digest(address)
    return selected, malformed


def build_installed_replay_manifest(
        tier: int, source_root: str | Path, *,
        source_coordinate_digest: str,
        ) -> bytes:
    """Build exact PASS/FAIL/UNKNOWN certificates from installed case inputs.

    No caller outcome is accepted. Positive and unavailable certificates are
    emitted by each obligation's installed builder. Negative certificates bind
    a malformed evidence record and must return the rechecker's native FAIL.
    """

    _require(tier in (1, 2), "NATIVE_REPLAY_TIER_INVALID")
    root = Path(source_root).resolve(strict=True)
    _require(root.is_dir(), "NATIVE_REPLAY_SOURCE_ROOT_UNAVAILABLE")
    registry = installed_native_replay_registry()
    installed_inputs = _installed_case_inputs(registry["tiers"])
    cases: list[dict[str, Any]] = []
    for membership in registry["tiers"][str(tier)]:
        identifier = membership["obligation_id"]
        selected = installed_inputs[identifier]
        module_name, recheck_symbol = membership[
            "checking_mechanism"
        ].rsplit(".", 1)
        build_symbol = recheck_symbol.replace("recheck_", "build_", 1)
        _require(build_symbol != recheck_symbol,
                 "NATIVE_CASE_BUILDER_UNAVAILABLE")
        builder, _, _ = _resolve_mechanism(
            root, module_name + "." + build_symbol
        )
        module = importlib.import_module(module_name)
        request = selected["request"]
        policy = selected["policy"]
        try:
            positive_evidence = base64.b64decode(
                selected["evidence_base64"], validate=True
            )
            negative_request, negative_evidence = _negative_case(
                module, identifier, request
            )
            built = {
                "POSITIVE": (
                    builder(request, positive_evidence, policy=policy),
                    request,
                ),
                "NEGATIVE": (
                    builder(
                        negative_request, negative_evidence, policy=policy
                    ),
                    negative_request,
                ),
                "UNKNOWN": (builder(request, None, policy=policy), request),
            }
        except NativeReplayError:
            raise
        except (ValueError, TypeError, KeyError, AttributeError,
                UnicodeError, binascii.Error) as exc:
            raise NativeReplayError("NATIVE_CASE_BUILD_REFUSED") from exc
        for case_kind in CASE_KINDS:
            certificate, expected_request = built[case_kind]
            _require(type(certificate) is bytes
                     and len(certificate) <= MAX_CERTIFICATE_BYTES,
                     "NATIVE_REPLAY_CERTIFICATE_CAPACITY_EXHAUSTED")
            cases.append({
                "obligation_id": identifier,
                "case_kind": case_kind,
                "checking_mechanism": membership["checking_mechanism"],
                "certificate_base64": base64.b64encode(certificate).decode(
                    "ascii"
                ),
                "expected_request": expected_request,
                "policy": policy,
            })
    return _canonical({
        "schema_version": MANIFEST_SCHEMA,
        "tier": tier,
        "source_coordinate_digest": source_coordinate_digest,
        "registry_digest": registry["registry_digest"],
        "cases": cases,
    })


def replay_native_obligations(manifest_bytes: bytes, source_root: str | Path,
                              *, tier: int, expected_manifest_digest: str,
                              expected_source_coordinate_digest: str) -> dict[str, Any]:
    """Replay all exact native PASS/FAIL/UNKNOWN cases for one tier."""

    receipt: dict[str, Any] = {
        "schema_version": RECEIPT_SCHEMA,
        "tier": tier,
        "status": "UNKNOWN",
        "manifest_digest": (
            core_obligation_union.bytes_digest(manifest_bytes)
            if type(manifest_bytes) is bytes else None
        ),
        "source_coordinate_digest": expected_source_coordinate_digest,
        "registry_digest": None,
        "registry_closure_digest": None,
        "memberships": [],
        "membership_count": 0,
        "case_count": 0,
        "invalidators": [],
        "polished": False,
        "release_authority": "NONE",
        "whole_tier_conformance": "NOT_ESTABLISHED",
    }
    try:
        _require(tier in (1, 2), "NATIVE_REPLAY_TIER_INVALID")
        _require(receipt["manifest_digest"] == expected_manifest_digest,
                 "NATIVE_REPLAY_MANIFEST_DIGEST_DIFFERS")
        root = Path(source_root).resolve(strict=True)
        _require(root.is_dir(), "NATIVE_REPLAY_SOURCE_ROOT_UNAVAILABLE")
        value = _decode_manifest(manifest_bytes)
        registry = installed_native_replay_registry()
        closure = installed_registry_closure()
        expected_rows = registry["tiers"][str(tier)]
        _require(set(value) == {
            "schema_version", "tier", "source_coordinate_digest",
            "registry_digest", "cases",
        } and value["schema_version"] == MANIFEST_SCHEMA
           and value["tier"] == tier
           and value["source_coordinate_digest"] == expected_source_coordinate_digest
           and value["registry_digest"] == registry["registry_digest"],
           "NATIVE_REPLAY_MANIFEST_CONTRACT_DIFFERS")
        cases = value["cases"]
        _require(type(cases) is list
                 and len(cases) == len(expected_rows) * len(CASE_KINDS),
                 "NATIVE_REPLAY_CASE_DENOMINATOR_DIFFERS")
        expected_by_id = {row["obligation_id"]: row for row in expected_rows}
        expected_order = [
            (row["obligation_id"], case_kind)
            for row in expected_rows for case_kind in CASE_KINDS
        ]
        observed_order: list[tuple[str, str]] = []
        grouped: dict[str, list[dict[str, Any]]] = {
            row["obligation_id"]: [] for row in expected_rows
        }
        mechanism_cache: dict[str, tuple[Any, str, str]] = {}
        for case in cases:
            _require(type(case) is dict and set(case) == {
                "obligation_id", "case_kind", "checking_mechanism",
                "certificate_base64", "expected_request", "policy",
            }, "NATIVE_REPLAY_CASE_INVALID")
            identifier = case["obligation_id"]
            case_kind = case["case_kind"]
            row = expected_by_id.get(identifier)
            _require(row is not None and case_kind in CASE_KINDS
                     and case["checking_mechanism"] == row["checking_mechanism"]
                     and type(case["expected_request"]) is dict
                     and type(case["policy"]) is dict
                     and type(case["certificate_base64"]) is str,
                     "NATIVE_REPLAY_CASE_BINDING_DIFFERS")
            observed_order.append((identifier, case_kind))
            try:
                certificate = base64.b64decode(
                    case["certificate_base64"], validate=True
                )
            except (ValueError, binascii.Error) as exc:
                raise NativeReplayError("NATIVE_REPLAY_CERTIFICATE_INVALID") from exc
            _require(len(certificate) <= MAX_CERTIFICATE_BYTES,
                     "NATIVE_REPLAY_CERTIFICATE_CAPACITY_EXHAUSTED")
            mechanism = mechanism_cache.get(row["checking_mechanism"])
            if mechanism is None:
                mechanism = _resolve_mechanism(root, row["checking_mechanism"])
                mechanism_cache[row["checking_mechanism"]] = mechanism
            function, source_path, source_digest = mechanism
            try:
                native = function(
                    certificate,
                    expected_request=case["expected_request"],
                    policy=case["policy"],
                )
                native_status = native.get("status") if type(native) is dict else None
                _require(native_status in ("PASS", "FAIL", "UNKNOWN"),
                         "NATIVE_REPLAY_OUTCOME_INVALID")
                if identifier == "SIM:SIM-2.4" \
                        and case_kind == "POSITIVE" \
                        and native_status == "UNKNOWN":
                    _require(
                        native.get("collector_honesty") == "NOT_ESTABLISHED"
                        and native.get("actual_consumption_correspondence")
                            == "NOT_ESTABLISHED",
                        "SIM_RESOURCE_UNKNOWN_BOUNDARY_DIFFERS",
                    )
                    receipt["invalidators"].extend([
                        "SIM_RESOURCE_COLLECTOR_HONESTY_NOT_ESTABLISHED",
                        (
                            "SIM_RESOURCE_ACTUAL_CONSUMPTION_"
                            "CORRESPONDENCE_NOT_ESTABLISHED"
                        ),
                    ])
                derived = (
                    "PASS" if native_status == CASE_OUTCOMES[case_kind] else
                    "UNKNOWN" if native_status == "UNKNOWN" else "FAIL"
                )
                native_digest = _digest(native)
            except NativeReplayError:
                raise
            except (OSError, ImportError, MemoryError, RecursionError,
                    OverflowError) as exc:
                grouped[identifier].append({
                    "case_kind": case_kind,
                    "expected_native_status": CASE_OUTCOMES[case_kind],
                    "native_status": "UNKNOWN",
                    "status": "UNKNOWN",
                    "native_result_digest": None,
                    "mechanism_source_path": source_path,
                    "mechanism_source_digest": source_digest,
                })
                continue
            except (ValueError, TypeError, KeyError, AttributeError,
                    UnicodeError) as exc:
                raise NativeReplayError("NATIVE_REPLAY_CERTIFICATE_REFUSED") from exc
            grouped[identifier].append({
                "case_kind": case_kind,
                "expected_native_status": CASE_OUTCOMES[case_kind],
                "native_status": native_status,
                "status": derived,
                "native_result_digest": native_digest,
                "mechanism_source_path": source_path,
                "mechanism_source_digest": source_digest,
            })
        _require(observed_order == expected_order,
                 "NATIVE_REPLAY_CASE_ORDER_DIFFERS")
        memberships: list[dict[str, Any]] = []
        for row in expected_rows:
            results = grouped[row["obligation_id"]]
            statuses = [case["status"] for case in results]
            status = (
                "FAIL" if "FAIL" in statuses else
                "UNKNOWN" if "UNKNOWN" in statuses else "PASS"
            )
            membership = {
                "obligation_id": row["obligation_id"],
                "membership": {
                    key: row[key] for key in (
                        "object_kind", "tier", "coordinate", "proposition_digest",
                        "semantic_version", "certificate_schema_version",
                        "checking_mechanism", "scope",
                    )
                },
                "cases": results,
                "status": status,
            }
            membership["native_replay_digest"] = _digest(membership)
            memberships.append(membership)
        statuses = [row["status"] for row in memberships]
        receipt.update({
            "status": (
                "FAIL" if "FAIL" in statuses else
                "UNKNOWN" if "UNKNOWN" in statuses else "PASS"
            ),
            "registry_digest": registry["registry_digest"],
            "registry_closure_digest": closure["closure_digest"],
            "memberships": memberships,
            "membership_count": len(memberships),
            "case_count": len(cases),
        })
    except NativeReplayError as exc:
        receipt["status"] = "FAIL"
        receipt["invalidators"].append(str(exc))
    except (OSError, ImportError, MemoryError, RecursionError, OverflowError):
        receipt["status"] = "UNKNOWN"
        receipt["invalidators"].append("NATIVE_REPLAY_MECHANISM_UNAVAILABLE")
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError):
        receipt["status"] = "FAIL"
        receipt["invalidators"].append("NATIVE_REPLAY_CONTRACT_REJECTED")
    receipt["invalidators"] = sorted(set(receipt["invalidators"]))
    receipt["receipt_digest"] = _digest(receipt)
    return receipt


__all__ = [
    "CASE_KINDS", "CLOSURE_SCHEMA", "MANIFEST_SCHEMA", "RECEIPT_SCHEMA",
    "REGISTRY_SCHEMA", "NativeReplayError", "build_installed_replay_manifest",
    "installed_native_replay_registry", "installed_registry_closure",
    "mechanism_digest",
    "replay_native_obligations",
]
