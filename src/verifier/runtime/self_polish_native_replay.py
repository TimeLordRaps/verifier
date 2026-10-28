"""Installed native replay and registry closure for numeric self-polish.

This module deliberately does not treat a green regression test as evidence for
an obligation.  A replay bundle contains native certificate bytes plus the
exact request and policy used by the obligation's installed rechecker.  The
rechecker result must exhibit the native PASS, FAIL, or UNKNOWN outcome named by
the case.  All membership identities and callable locations are re-derived from
the installed registries before any caller bytes are considered.

A NEGATIVE case establishes discrimination only when the installed rechecker
returns FAIL whose refusal detail is the exact intended refusal recorded for that
obligation.  Every other NEGATIVE reply is a nonpass with a typed reason.  The
installed source-review ledger is consumed for each tier row; a row whose
disposition is not accepted keeps its membership from conformance and keeps the
receipt from PASS, while the per-case mechanism outcomes remain separate.  A
callable that is not the installed registered mechanism (for example a fixture
echo) is plumbing-only and cannot yield a PASS.  The receipt schema cannot yet
carry the ledger digest at its top level; it is bound through each membership.
"""
from __future__ import annotations

import base64
import binascii
import inspect
import re
from copy import deepcopy
from pathlib import Path
from typing import Any

from verifier.core.namespace import ObjectKind
from verifier.core.receipt import strict_json_loads
from verifier.domains.contracts import application_requirements
from verifier.domains.contracts import current_object_routes
from verifier.domains.contracts import sim_resource_fresh
from verifier.runtime import core_obligation_union
from verifier.runtime import core_tier_progression
from verifier.runtime import polish
from verifier.runtime import self_polish_native_cases
from verifier.runtime import self_polish_native_sim_case_patch


REGISTRY_SCHEMA = "verifier-self-polish-native-replay-registry-3"
CLOSURE_SCHEMA = "verifier-self-polish-installed-registry-closure-3"
# Generic envelopes are unchanged; the registry and selected native contract
# carry the versioned variant, including its retained execution result.
MANIFEST_SCHEMA = "verifier-self-polish-native-replay-manifest-2"
RECEIPT_SCHEMA = "verifier-self-polish-native-replay-receipt-2"
CASE_KINDS = ("POSITIVE", "NEGATIVE", "UNKNOWN")
CASE_OUTCOMES = {"POSITIVE": "PASS", "NEGATIVE": "FAIL", "UNKNOWN": "UNKNOWN"}
MAX_MANIFEST_BYTES = 32 * 1024 * 1024
MAX_CERTIFICATE_BYTES = 8 * 1024 * 1024
SOURCE_LAYOUTS = ("repository", "loaded-distribution")
# The generated review ledger verifies the exact accepted identifier set before
# replay reaches this module. Numeric Tier 2 additionally selects a distinct
# source-bound fresh SIM-2.4 variant, whose review overlay is derived below from
# the verified legacy row and exact current fresh mechanism closure. Every
# UNKNOWN_* disposition remains fail-closed and cannot establish conformance.
SOURCE_REVIEW_ACCEPTED_DISPOSITIONS: frozenset[str] = frozenset({
    "ACCEPT_REPIN", "ACCEPT_FRESH_EXECUTION_VARIANT",
})
SOURCE_REVIEW_NEXT_ACTION = {
    "UNKNOWN_BASELINE_UNRESOLVED": (
        "Human acceptance or repin of the stored policy digest at a reproduced revision."
    ),
    "UNKNOWN_SEMANTIC_DELTA_CODE": (
        "Human acceptance of the recorded closure-code semantic delta."
    ),
    "UNKNOWN_FIXTURE_ONLY_RESOURCE": (
        "Supply an authoritative collector key; the public fixture seed never establishes PASS."
    ),
    "UNKNOWN_NON_AUTHORITATIVE_PROVENANCE": (
        "Bind authoritative repository provenance; the historical fixture label never establishes PASS."
    ),
    "UNKNOWN_SPEC_DOC_DELTA": (
        "Review the changed normative specification text bound by the closure."
    ),
}
# Typed nonpass reasons, one per distinct cause.
NEGATIVE_REFUSAL_CODE_MISSING = "NEGATIVE_REFUSAL_CODE_MISSING"
NEGATIVE_REFUSAL_CODE_DIFFERS = "NEGATIVE_REFUSAL_CODE_DIFFERS"
NEGATIVE_ACCEPTED_BY_CHECKER = "NEGATIVE_ACCEPTED_BY_CHECKER"
NEGATIVE_NATIVE_UNKNOWN = "NEGATIVE_NATIVE_UNKNOWN_NOT_DISCRIMINATION"
NEGATIVE_NATIVE_REPLY_MALFORMED = "NEGATIVE_NATIVE_REPLY_MALFORMED"
NEGATIVE_CHECKER_EXCEPTION = "NEGATIVE_CHECKER_EXCEPTION"
POSITIVE_NATIVE_FAIL = "POSITIVE_NATIVE_FAIL_CONTRADICTS_CERTIFICATE"
POSITIVE_NATIVE_UNKNOWN = "POSITIVE_NATIVE_UNKNOWN"
UNKNOWN_CASE_NATIVE_RESULT_DIFFERS = "UNKNOWN_CASE_NATIVE_RESULT_DIFFERS"
NOT_INSTALLED_PLUMBING_ONLY = "MECHANISM_NOT_INSTALLED_PLUMBING_ONLY"
MECHANISM_UNAVAILABLE = "NATIVE_REPLAY_MECHANISM_UNAVAILABLE"
SOURCE_REVIEW_NOT_ACCEPTED = "SOURCE_REVIEW_NOT_ACCEPTED"
_CODE_SHAPE = re.compile(r"[A-Z][A-Z0-9_]*")


class NativeReplayError(ValueError):
    """A stable native-replay refusal code."""


class NativeReplayResourceError(OSError):
    """Digest/resource failure carrying whether a FAIL was already observed."""

    def __init__(self, *, failure_observed: bool) -> None:
        super().__init__("NATIVE_REPLAY_MECHANISM_UNAVAILABLE")
        self.failure_observed = failure_observed


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise NativeReplayError(code)


def _canonical(value: Any) -> bytes:
    return core_obligation_union.canonical_bytes(value)


def _digest(value: Any) -> str:
    return core_obligation_union.value_digest(value)


def _typed_reason(exc: BaseException) -> str:
    """Keep a stable refusal code from a contract error, never arbitrary text."""
    text = str(exc)
    return text if _CODE_SHAPE.fullmatch(text) else "NATIVE_REPLAY_CONTRACT_REJECTED"


def mechanism_digest() -> str:
    """Bind the replay implementation and its installed native case inputs."""

    return _digest({
        "module_digest": core_obligation_union.bytes_digest(
            Path(__file__).read_bytes()
        ),
        "case_module_digest": core_obligation_union.bytes_digest(
            Path(self_polish_native_cases.__file__).read_bytes()
        ),
        "case_patch_module_digest": core_obligation_union.bytes_digest(
            Path(self_polish_native_sim_case_patch.__file__).read_bytes()
        ),
        "case_registry_schema": self_polish_native_cases.CASE_REGISTRY_SCHEMA,
        "fresh_sim_variant": sim_resource_fresh.mechanism_digest(),
    })


def _membership_rows(tier: int, *, fresh_execution: bool = False) -> list[dict[str, Any]]:
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
    if fresh_execution:
        for row in rows:
            if row["obligation_id"] == "SIM:SIM-2.4":
                row.update({
                    "semantic_version": sim_resource_fresh.SEMANTIC_VERSION,
                    "certificate_schema_version": sim_resource_fresh.CERTIFICATE_VERSION,
                    "checking_mechanism": sim_resource_fresh.CHECKING_MECHANISM,
                    "scope": sim_resource_fresh.SCOPE,
                    "proposition_digest": sim_resource_fresh.PROPOSITION_DIGEST,
                })
    return rows


def installed_native_replay_registry(*, fresh_execution: bool = False) -> dict[str, Any]:
    """Return the versioned exact 45/37 native replay registry."""

    tiers = {str(tier): _membership_rows(tier, fresh_execution=fresh_execution) for tier in (1, 2)}
    cases = _installed_case_inputs(tiers, fresh_execution=fresh_execution)
    body = {
        "schema_version": REGISTRY_SCHEMA,
        "case_semantics": dict(CASE_OUTCOMES),
        "tier_membership_counts": {"1": 45, "2": 37},
        "case_input_registry_schema": (
            self_polish_native_cases.CASE_REGISTRY_SCHEMA
        ),
        "case_input_registry_digest": _digest(cases),
        "tiers": tiers,
        "sim_resource_variant": (
            {"semantic_version": sim_resource_fresh.SEMANTIC_VERSION,
             "reasons": sim_resource_fresh.REASONS,
             "historical_route_disposition": "RETAINED_NOT_PROMOTED"}
            if fresh_execution else None
        ),
    }
    body["registry_digest"] = _digest(body)
    return body


def _installed_case_inputs(
        tiers: dict[str, list[dict[str, Any]]] | None = None,
        *, fresh_execution: bool = False,
        ) -> dict[str, dict[str, Any]]:
    """Validate the installed builder inputs against the exact route registry."""

    selected = self_polish_native_cases.installed_case_inputs()
    _require(type(selected) is dict, "NATIVE_CASE_REGISTRY_INVALID")
    if tiers is None:
        tiers = {str(tier): _membership_rows(tier, fresh_execution=fresh_execution) for tier in (1, 2)}
    if fresh_execution:
        trajectory = selected["SIM:SIM-2.1"]
        request, policy, evidence = sim_resource_fresh.selection_from_trajectory(
            trajectory["request"], trajectory["policy"],
            base64.b64decode(trajectory["evidence_base64"], validate=True),
        )
        selected["SIM:SIM-2.4"] = {
            "checking_mechanism": sim_resource_fresh.CHECKING_MECHANISM,
            "request": request, "policy": policy,
            "evidence_base64": base64.b64encode(evidence).decode("ascii"),
        }
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


def installed_registry_closure(*, fresh_execution: bool = False) -> dict[str, Any]:
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

    registry = installed_native_replay_registry(fresh_execution=fresh_execution)
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
    legacy_rows = {row["obligation_id"]: row for row in _membership_rows(2)}
    for tier in (1, 2):
        for route in registry["tiers"][str(tier)]:
            selected_variant = route
            if fresh_execution and route["obligation_id"] == "SIM:SIM-2.4":
                # The registered historical contract is still checked against
                # its catalog; the explicit numeric profile selects a distinct
                # fresh-execution fulfillment. Never rewrite historical claims.
                route = legacy_rows[route["obligation_id"]]
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
                "selected_variant_digest": _digest(selected_variant),
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
        "sim_resource_variant": registry["sim_resource_variant"],
        "claim_boundary": (
            "PASS covers exact installed Tier 1 and Tier 2 registry structure, "
            "crosswalks, and catalog bindings only. Repository/package estate "
            "closure and per-obligation native outcomes remain separate gates."
        ),
    }
    body["closure_digest"] = _digest(body)
    return body


def _source_review_binding(
        tier: int, *, fresh_execution: bool = False,
        ) -> dict[str, Any]:
    """Bind one tier to the installed 82-row source-review ledger.

    The ledger is read from its verified installed accessor, never from the
    manifest. Each tier row must name the same mechanism and coordinate as the
    installed membership, and every row whose disposition is not accepted is
    reported with its exact coordinate, object, obligation, reason, and next
    action. Tier 1 and Tier 2 partition the ledger exactly.
    """

    rows = self_polish_native_cases.installed_source_review()
    _require(len(rows) == self_polish_native_cases.SOURCE_REVIEW_ROW_COUNT,
             "NATIVE_REPLAY_SOURCE_REVIEW_DENOMINATOR_DIFFERS")
    ledger = {row["identifier"]: row for row in rows}
    _require(set(ledger) == set(self_polish_native_cases.NEGATIVE_REFUSAL_CODES),
             "NATIVE_REPLAY_REFUSAL_CODES_DIFFER")
    members = _membership_rows(tier, fresh_execution=fresh_execution)
    other = {
        row["obligation_id"]
        for row in _membership_rows(3 - tier, fresh_execution=fresh_execution)
    }
    tier_ids = {row["obligation_id"] for row in members}
    _require(not tier_ids & other and tier_ids | other == set(ledger),
             "NATIVE_REPLAY_SOURCE_REVIEW_DENOMINATOR_DIFFERS")
    entries: dict[str, dict[str, Any]] = {}
    for member in members:
        entry = ledger[member["obligation_id"]]
        fresh_sim = (
            fresh_execution
            and member["obligation_id"] == "SIM:SIM-2.4"
        )
        if fresh_sim:
            _require(
                entry.get("checking_mechanism")
                    != member["checking_mechanism"]
                and entry.get("coordinate") == member["coordinate"]
                and entry.get("disposition")
                    == "UNKNOWN_FIXTURE_ONLY_RESOURCE",
                "NATIVE_REPLAY_FRESH_SOURCE_REVIEW_BASE_DIFFERS",
            )
            boundary = (
                "Acceptance covers the exact numeric Tier 2 fresh-execution "
                "SIM-2.4 variant and its current selected-source closure only. "
                "The legacy public-seed fixture remains unaccepted. Historical "
                "execution, host honesty, physical calibration, and total "
                "physical resource use remain NOT_ESTABLISHED."
            )
            reviewed_binding = {
                "schema_version": (
                    "verifier-self-polish-native-fresh-source-review-1"
                ),
                "base_ledger_digest": (
                    self_polish_native_cases.SOURCE_REVIEW_DIGEST
                ),
                "legacy_row_digest": _digest(entry),
                "selected_membership_digest": _digest(member),
                "fresh_mechanism_digest": (
                    sim_resource_fresh.mechanism_digest()
                ),
                "fresh_source_manifest_digest": _digest(
                    sim_resource_fresh.source_manifest()
                ),
                "claim_boundary": boundary,
            }
            reviewed_binding["review_digest"] = _digest(reviewed_binding)
            entries[member["obligation_id"]] = {
                "ledger_digest": self_polish_native_cases.SOURCE_REVIEW_DIGEST,
                "row_count": self_polish_native_cases.SOURCE_REVIEW_ROW_COUNT,
                "obligation_id": member["obligation_id"],
                "object_kind": member["object_kind"],
                "coordinate": member["coordinate"],
                "disposition": "ACCEPT_FRESH_EXECUTION_VARIANT",
                "accepted": True,
                "reason": (
                    "the exact fresh-execution membership, mechanism closure, "
                    "and selected source manifest are digest-bound to the "
                    "reviewed legacy fixture boundary"
                ),
                "next_action": None,
                "reviewed_binding": reviewed_binding,
            }
            continue
        _require(entry.get("checking_mechanism") == member["checking_mechanism"]
                 and entry.get("coordinate") == member["coordinate"],
                 "NATIVE_REPLAY_SOURCE_REVIEW_BINDING_DIFFERS")
        accepted = entry.get("disposition") in SOURCE_REVIEW_ACCEPTED_DISPOSITIONS
        entries[member["obligation_id"]] = {
            "ledger_digest": self_polish_native_cases.SOURCE_REVIEW_DIGEST,
            "row_count": self_polish_native_cases.SOURCE_REVIEW_ROW_COUNT,
            "obligation_id": member["obligation_id"],
            "object_kind": member["object_kind"],
            "coordinate": member["coordinate"],
            "disposition": entry["disposition"],
            "accepted": accepted,
            "reason": entry["reason"],
            "next_action": None if accepted else SOURCE_REVIEW_NEXT_ACTION.get(
                entry["disposition"], "Human disposition required."
            ),
        }
    return {"entries": entries, "ledger": ledger}


def _installed_callable(dotted: str) -> Any:
    """Return the installed registered callable, or None when it is not installed."""

    module_name, symbol = dotted.rsplit(".", 1)
    try:
        module = (
            sim_resource_fresh
            if module_name == sim_resource_fresh.__name__
            else current_object_routes.registered_mechanism_module(dotted)
        )
    except current_object_routes.CurrentObjectRouteRefusal:
        return None
    return getattr(module, symbol, None)


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


def _resolve_mechanism(
        source_root: Path, dotted: str, *, source_layout: str = "repository",
        ) -> tuple[Any, str, str]:
    """Bind a package-owned callable to exact explicitly selected bytes."""
    _require(source_layout in SOURCE_LAYOUTS,
             "NATIVE_REPLAY_SOURCE_LAYOUT_INVALID")
    root = Path(source_root).resolve(strict=True)
    _require(root.is_dir(), "NATIVE_REPLAY_SOURCE_ROOT_UNAVAILABLE")
    module_name, symbol = dotted.rsplit(".", 1)
    try:
        module = (
            sim_resource_fresh
            if module_name == sim_resource_fresh.__name__
            else current_object_routes.registered_mechanism_module(dotted)
        )
    except current_object_routes.CurrentObjectRouteRefusal as exc:
        raise NativeReplayError("NATIVE_REPLAY_MECHANISM_UNAVAILABLE") from exc
    function = getattr(module, symbol, None)
    _require(callable(function), "NATIVE_REPLAY_MECHANISM_UNAVAILABLE")
    parts = module_name.split(".")
    loaded_root = Path(__file__).resolve().parents[2]
    loaded = loaded_root.joinpath(*parts).with_suffix(".py").resolve()
    if source_layout == "repository":
        expected = root.joinpath("src", *parts).with_suffix(".py").resolve()
        source_path = expected.relative_to(root).as_posix()
    else:
        # A wheel has no repository ``src`` directory. Loaded-distribution
        # mode is exact: it accepts only this import root, while receipts keep
        # the stable repository-coordinate spelling used by checkout replay.
        _require(root == loaded_root,
                 "NATIVE_REPLAY_MECHANISM_SOURCE_DIFFERS")
        expected = root.joinpath(*parts).with_suffix(".py").resolve()
        source_path = (Path("src") / expected.relative_to(root)).as_posix()
    actual = Path(inspect.getsourcefile(function) or "").resolve()
    _require(parts[0] == "verifier" and actual == loaded
             and expected.is_relative_to(root)
             and expected.is_file() and actual.is_file(),
             "NATIVE_REPLAY_MECHANISM_SOURCE_DIFFERS")
    selected_bytes = expected.read_bytes()
    _require(actual.read_bytes() == selected_bytes,
             "NATIVE_REPLAY_MECHANISM_SOURCE_DIFFERS")
    return (
        function,
        source_path,
        core_obligation_union.bytes_digest(selected_bytes),
    )


def _resolve_selected_mechanism(
        source_root: Path, dotted: str, source_layout: str,
        ) -> tuple[Any, str, str]:
    """Keep the historical two-argument resolver seam for repository replay."""
    if source_layout == "repository":
        return _resolve_mechanism(source_root, dotted)
    return _resolve_mechanism(
        source_root, dotted, source_layout=source_layout
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
        fresh_execution: bool = False,
        source_layout: str = "repository",
        ) -> bytes:
    """Build exact PASS/FAIL/UNKNOWN certificates from installed case inputs.

    No caller outcome is accepted. Positive and unavailable certificates are
    emitted by each obligation's installed builder. Negative certificates bind
    a malformed evidence record and must return the rechecker's native FAIL.
    The installed source-review denominator for the tier is validated here, and
    replay re-derives it from the installed ledger rather than trusting bytes.
    """

    _require(tier in (1, 2), "NATIVE_REPLAY_TIER_INVALID")
    _require(source_layout in SOURCE_LAYOUTS,
             "NATIVE_REPLAY_SOURCE_LAYOUT_INVALID")
    root = Path(source_root).resolve(strict=True)
    _require(root.is_dir(), "NATIVE_REPLAY_SOURCE_ROOT_UNAVAILABLE")
    registry = installed_native_replay_registry(fresh_execution=fresh_execution)
    _source_review_binding(tier, fresh_execution=fresh_execution)
    installed_inputs = _installed_case_inputs(registry["tiers"], fresh_execution=fresh_execution)
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
        builder, _, _ = _resolve_selected_mechanism(
            root, module_name + "." + build_symbol, source_layout
        )
        try:
            module = (
                sim_resource_fresh
                if module_name == sim_resource_fresh.__name__
                else current_object_routes.registered_mechanism_module(
                    membership["checking_mechanism"]
                )
            )
        except current_object_routes.CurrentObjectRouteRefusal as exc:
            raise NativeReplayError("NATIVE_REPLAY_MECHANISM_UNAVAILABLE") from exc
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


def _refusal_detail(native: dict[str, Any]) -> str | None:
    """Return the checker's refusal detail string, or None when absent."""
    evaluation = native.get("evaluation")
    if type(evaluation) is not dict:
        return None
    details = evaluation.get("details")
    return details if type(details) is str else None


def _installed_pass(installed: bool) -> tuple[str, str | None]:
    """A native PASS counts only from the installed registered callable."""
    return ("PASS", None) if installed else ("UNKNOWN", NOT_INSTALLED_PLUMBING_ONLY)


def _case_outcome(
        case_kind: str, identifier: str, native: Any, *, installed: bool,
        ) -> tuple[str, str | None]:
    """Map one native reply to ``(status, reason)``; reason is None only for PASS.

    NEGATIVE establishes discrimination only from the installed callable's FAIL
    whose refusal detail equals the exact intended refusal for ``identifier``.
    Every other NEGATIVE reply is a typed nonpass.
    """
    native_status = native.get("status") if type(native) is dict else None
    if case_kind == "NEGATIVE":
        if native_status == "FAIL":
            detail = _refusal_detail(native)
            if detail is None:
                return "FAIL", NEGATIVE_REFUSAL_CODE_MISSING
            if detail != self_polish_native_cases.NEGATIVE_REFUSAL_CODES.get(identifier):
                return "FAIL", NEGATIVE_REFUSAL_CODE_DIFFERS
            return _installed_pass(installed)
        if native_status == "PASS":
            return "FAIL", NEGATIVE_ACCEPTED_BY_CHECKER
        if native_status == "UNKNOWN":
            return "FAIL", NEGATIVE_NATIVE_UNKNOWN
        return "FAIL", NEGATIVE_NATIVE_REPLY_MALFORMED
    _require(native_status in ("PASS", "FAIL", "UNKNOWN"),
             "NATIVE_REPLAY_OUTCOME_INVALID")
    if case_kind == "UNKNOWN":
        if native_status == "UNKNOWN":
            return _installed_pass(installed)
        return "FAIL", UNKNOWN_CASE_NATIVE_RESULT_DIFFERS
    if native_status == "PASS":
        return _installed_pass(installed)
    if native_status == "FAIL":
        return "FAIL", POSITIVE_NATIVE_FAIL
    return "UNKNOWN", POSITIVE_NATIVE_UNKNOWN


def replay_native_obligations(manifest_bytes: bytes, source_root: str | Path,
                              *, tier: int, expected_manifest_digest: str,
                              expected_source_coordinate_digest: str,
                               fresh_execution: bool = False,
                               source_layout: str = "repository") -> dict[str, Any]:
    """Replay all exact native PASS/FAIL/UNKNOWN cases for one tier.

    The receipt status is FAIL when any mechanism result is FAIL. It is UNKNOWN
    when any mechanism result is UNKNOWN or any applicable ledger row is not
    accepted. PASS requires both. Per-membership mechanism status is preserved
    separately from its conformance status.
    """

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
    grouped: dict[str, list[dict[str, Any]]] = {}
    try:
        _require(tier in (1, 2), "NATIVE_REPLAY_TIER_INVALID")
        _require(source_layout in SOURCE_LAYOUTS,
                 "NATIVE_REPLAY_SOURCE_LAYOUT_INVALID")
        _require(receipt["manifest_digest"] == expected_manifest_digest,
                 "NATIVE_REPLAY_MANIFEST_DIGEST_DIFFERS")
        root = Path(source_root).resolve(strict=True)
        _require(root.is_dir(), "NATIVE_REPLAY_SOURCE_ROOT_UNAVAILABLE")
        value = _decode_manifest(manifest_bytes)
        registry = installed_native_replay_registry(fresh_execution=fresh_execution)
        closure = installed_registry_closure(fresh_execution=fresh_execution)
        source = _source_review_binding(
            tier, fresh_execution=fresh_execution
        )
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
        grouped = {
            row["obligation_id"]: [] for row in expected_rows
        }
        mechanism_cache: dict[str, tuple[Any, str, str, bool]] = {}
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
                function, source_path, source_digest = _resolve_selected_mechanism(
                    root, row["checking_mechanism"], source_layout
                )
                # A caller-substituted resolver returns a different callable;
                # its PASS is plumbing and must never become semantic PASS.
                mechanism = (
                    function, source_path, source_digest,
                    function is _installed_callable(row["checking_mechanism"]),
                )
                mechanism_cache[row["checking_mechanism"]] = mechanism
            function, source_path, source_digest, installed = mechanism
            fresh_sim = row["checking_mechanism"] == sim_resource_fresh.CHECKING_MECHANISM
            if fresh_sim:
                # Pin every executed package dependency to the selected source,
                # including byte-identical installed-wheel execution.
                for entry in sim_resource_fresh.source_manifest().values():
                    if not entry["path"].endswith("/"):
                        selected_path = Path(entry["path"])
                        if source_layout == "loaded-distribution":
                            selected_path = selected_path.relative_to("src")
                        _require(core_obligation_union.bytes_digest(
                            root.joinpath(selected_path).read_bytes()
                        ) == entry["sha256"],
                            "FRESH_SIM_SELECTED_SOURCE_DIFFERS")
                bootstrap_path = Path(
                    "src/verifier/domains/contracts/sim_fresh_bootstrap.py"
                )
                if source_layout == "loaded-distribution":
                    bootstrap_path = bootstrap_path.relative_to("src")
                _require(root.joinpath(bootstrap_path).read_bytes()
                         == Path(sim_resource_fresh.__file__).with_name("sim_fresh_bootstrap.py").read_bytes(),
                         "FRESH_SIM_BOOTSTRAP_SOURCE_DIFFERS")
            native_status = None
            refusal_detail = None
            native_digest = None
            try:
                native = function(
                    certificate,
                    expected_request=case["expected_request"],
                    policy=case["policy"],
                )
                native_status = native.get("status") if type(native) is dict else None
                if case_kind != "NEGATIVE":
                    _require(native_status in ("PASS", "FAIL", "UNKNOWN"),
                             "NATIVE_REPLAY_OUTCOME_INVALID")
                if fresh_sim and case_kind == "POSITIVE" and native_status != "PASS":
                    receipt["invalidators"].extend(native["invalidators"])
                if identifier == "SIM:SIM-2.4" \
                        and not fresh_sim \
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
                status, reason = _case_outcome(
                    case_kind, identifier, native, installed=installed
                )
                refusal_detail = _refusal_detail(native) if type(native) is dict else None
                native_digest = _digest(native)
            except NativeReplayError:
                raise
            except (OSError, ImportError, MemoryError, RecursionError,
                    OverflowError):
                receipt["invalidators"].append(MECHANISM_UNAVAILABLE)
                status, reason = "UNKNOWN", MECHANISM_UNAVAILABLE
            except (ValueError, TypeError, KeyError, AttributeError,
                    UnicodeError) as exc:
                if case_kind != "NEGATIVE":
                    raise NativeReplayError("NATIVE_REPLAY_CERTIFICATE_REFUSED") from exc
                status, reason = "FAIL", NEGATIVE_CHECKER_EXCEPTION
            grouped[identifier].append({
                "case_kind": case_kind,
                "coordinate": row["coordinate"],
                "expected_native_status": CASE_OUTCOMES[case_kind],
                "intended_refusal_codes": (
                    [self_polish_native_cases.NEGATIVE_REFUSAL_CODES[identifier]]
                    if case_kind == "NEGATIVE" else []
                ),
                "policy_digest": _digest(case["policy"]),
                "request_digest": _digest(case["expected_request"]),
                "evidence_digest": core_obligation_union.bytes_digest(certificate),
                "native_status": native_status,
                "refusal_detail": refusal_detail,
                "reason": reason,
                "status": status,
                "native_result_digest": native_digest,
                "mechanism_source_path": source_path,
                "mechanism_source_digest": source_digest,
                **({"fresh_execution_result": native}
                   if fresh_sim and native_digest is not None else {}),
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
            review = source["entries"][row["obligation_id"]]
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
                "source_review": review,
                "conformance_status": (
                    "PASS" if status == "PASS" and review["accepted"]
                    else "NOT_ESTABLISHED"
                ),
            }
            membership["native_replay_digest"] = _digest(membership)
            memberships.append(membership)
        statuses = [row["status"] for row in memberships]
        pending_review = [
            row["source_review"] for row in memberships
            if not row["source_review"]["accepted"]
        ]
        receipt.update({
            "status": (
                "FAIL" if "FAIL" in statuses else
                "UNKNOWN" if "UNKNOWN" in statuses or pending_review else "PASS"
            ),
            "registry_digest": registry["registry_digest"],
            "registry_closure_digest": closure["closure_digest"],
            "memberships": memberships,
            "membership_count": len(memberships),
            "case_count": len(cases),
        })
        if pending_review:
            receipt["invalidators"].append(SOURCE_REVIEW_NOT_ACCEPTED)
    except NativeReplayError as exc:
        receipt["status"] = "FAIL"
        receipt["invalidators"].append(str(exc))
    except (OSError, ImportError, MemoryError, RecursionError, OverflowError):
        prior_failure = any(
            case.get("status") == "FAIL"
            for cases in grouped.values() for case in cases
            if type(case) is dict
        )
        receipt["status"] = "FAIL" if prior_failure else "UNKNOWN"
        receipt["invalidators"].append(MECHANISM_UNAVAILABLE)
    except (ValueError, TypeError, KeyError, AttributeError, UnicodeError) as exc:
        receipt["status"] = "FAIL"
        receipt["invalidators"].append(_typed_reason(exc))
    receipt["invalidators"] = sorted(set(receipt["invalidators"]))
    try:
        receipt["receipt_digest"] = _digest(receipt)
    except (OSError, MemoryError, RecursionError, OverflowError) as exc:
        raise NativeReplayResourceError(
            failure_observed=receipt["status"] == "FAIL"
        ) from exc
    return receipt


def same_execution_selection(left: dict, right: dict) -> bool:
    """Compare two freshly produced receipts, not authenticate retained metrics.

    All deterministic inputs, statuses, source pins and result boundaries must
    agree. Only the observation of the explicitly versioned fresh positive run
    may differ. Both originals retain their measurements and digest chains.
    Callers must execute both replays; this is NOT a portable receipt verifier.
    """
    def project(receipt: dict) -> dict:
        value = deepcopy(receipt)
        _require(value.pop("receipt_digest") == _digest(value), "FRESH_RECEIPT_DIGEST_DIFFERS")
        for member in value["memberships"]:
            _require(member.pop("native_replay_digest") == _digest(member), "FRESH_MEMBERSHIP_DIGEST_DIFFERS")
            for case in member["cases"]:
                result = case.get("fresh_execution_result")
                if result is None:
                    continue
                _require(case["native_result_digest"] == _digest(result), "FRESH_RESULT_DIGEST_DIFFERS")
                if case["case_kind"] == "POSITIVE" and result["status"] == "PASS":
                    _require(result["semantic_version"] == sim_resource_fresh.SEMANTIC_VERSION
                             and type(result["observation"]) is dict,
                             "FRESH_OBSERVATION_INVALID")
                    result["observation"] = "SEPARATE_FRESH_OBSERVATION_RETAINED_IN_ORIGINAL"
                case["native_result_digest"] = _digest(result)
        return value
    return project(left) == project(right)


__all__ = [
    "CASE_KINDS", "CLOSURE_SCHEMA", "MANIFEST_SCHEMA", "RECEIPT_SCHEMA",
    "REGISTRY_SCHEMA", "NativeReplayError", "NativeReplayResourceError",
    "build_installed_replay_manifest",
    "installed_native_replay_registry", "installed_registry_closure",
    "mechanism_digest",
    "replay_native_obligations",
]
