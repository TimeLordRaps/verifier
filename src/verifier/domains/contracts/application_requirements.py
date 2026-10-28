"""Additive exact declared-namespace requirements compiler; no issuance.

Terminology: directed acyclic graph (DAG); Secure Hash Algorithm 256-bit
(SHA-256); identifier (ID).

The closed installed scope covers only the five retained structural propositions.
Full current application, domain payload semantics and higher families remain
UNKNOWN. An exact source-language census is not source authority or source truth.
"""
from __future__ import annotations

from asyncio import CancelledError

import base64
from hashlib import sha256
from pathlib import Path
from typing import Any

from verifier.core.certificate import canonical_bytes
from verifier.core.namespace import NamespaceObject, ObjectKind, assess_composition, composition_digest
from verifier.domains.contracts import certificate_dag as dag, facet_coverage, object_facets, typed_facets

SCHEMA = "verifier-current-application-obligations-1"
POLICY = "verifier-application-compiler-policy-1"
SOURCE = "verifier-application-source-scope-1"
SELECTION = "verifier-application-selection-1"
LANGUAGE = "CANONICAL_NAMESPACE_COLLECTION_1"
STRUCTURAL = "retained-namespace-structure-1"
FULL = "full-current-application-1"
SEMANTIC = "verifier-current-object-obligations-1"
MECHANISM = "verifier.current-application.exact-declared-namespace-compiler.1"
CEILINGS = {"objects": 256, "source_units": 64, "facets": 32768,
    "interactions": 4096, "requirements": 512, "operations": 1000000,
    "output_bytes": 8 * 1024**2}
_PINS = {
    "core/namespace.py": "8b308b945300ba024315875dd9fcd455db72309e269dffc15d5ee47a671358b6",
    "domains/contracts/object_facets.py": "ee31efbeceb35b756957a56e4b24d357263a575fc7b3c76a6bb7332c81884a1c",
    "domains/contracts/typed_facets.py": "9a90258e2ca02271bf4aa980709d595e338ceff095657401a65d14b29bd8c516",
    "standard/NAMESPACE_OBJECTS.md": "d9ac55edfb09554d4c37da2f6059b01b3570816d68f1c6cf1109781ad3a57960",
    "standard/CURRENT_OBJECT_FACETS.md": "5c36d8816bc063c49c40d3c3787f6e2bec7db134c70165f0ec036823b420571d",
    "standard/CURRENT_TYPED_FACETS.md": "d23990c62e75cb723684f9998e4cb959b01664f20f42c568385f3cfb8f251cdd",
}
BOUNDARY = ("Exact declared source-language and namespace structural-proposition census only; "
    "full application/all-tier applicability, payload truth/domain semantics, source authority, "
    "native objective truth, public checkability, human acceptance and polished admission are not established.")


def _digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def _value_digest(value: Any) -> str:
    return _digest(canonical_bytes(value))


def _keys(value: Any, fields: str) -> dict[str, Any]:
    if type(value) is not dict or set(value) != set(fields.split()):
        raise ValueError("exact fields required")
    return value


def _hash(value: Any) -> str:
    if (type(value) is not str or len(value) != 71 or not value.startswith("sha256:")
            or any(c not in "0123456789abcdef" for c in value[7:])):
        raise ValueError("canonical SHA-256 required")
    return value


def _text(value: Any) -> str:
    if type(value) is not str or not value.strip() or len(value) > 256:
        raise ValueError("bounded plain identifier required")
    return value


def source_bindings() -> dict[str, str]:
    root = Path(__file__).parents[2]
    paths = {*_PINS, "domains/contracts/application_requirements.py",
        "domains/contracts/certificate_dag.py", "core/certificate.py", "core/receipt.py",
        "core/evidence.py", "domains/common.py", "standard/CURRENT_APPLICATION_REQUIREMENTS.md"}
    paths.add("domains/contracts/facet_coverage.py")
    return {name: _digest((root / name).read_bytes()) for name in sorted(paths)}


def mechanism_digest() -> str:
    return _value_digest({"schema_version": "verifier-application-compiler-mechanism-1",
        "mechanism_id": MECHANISM, "source_bindings": source_bindings()})


def installed_rules() -> dict[str, Any]:
    """Only actual authored structural predicates, no per-kind route heuristic."""
    rows = [{"rule_id": "canonical-namespace-record/1", "kind": "*",
        "property": "identifier_kind_payload_ordered_operands", "coordinate": "OBJECT-1.1",
        "proposition_digest": object_facets.PROPOSITION_DIGEST,
        "scope": object_facets.REGISTRATION["scope"], "sources": dict(_PINS),
        "native_consumers": [], "inline_checks": ["exact_record_and_address_reconstruction"]}]
    for kind in ObjectKind:
        native = typed_facets.registration(kind.value)
        rows.append({"rule_id": "declared-typed-composition/1:" + kind.value,
            "kind": kind.value, "property": "declared_typed_composition",
            "coordinate": native["coordinate"],
            "proposition_digest": _value_digest(native), "scope": typed_facets.SCOPE,
            "sources": dict(_PINS), "native_consumers": [],
            "inline_checks": ["exact_selected_collection_composition"]})
    for row in rows:
        row["rule_digest"] = _value_digest(row)
    return {"schema_version": "verifier-application-installed-rules-1", "rules": rows,
        "closed_scope": STRUCTURAL, "full_current_application_profiles": 0}


def installed_families(kinds: list[str]) -> list[dict[str, Any]]:
    rules = installed_rules()["rules"]
    return [{"family_id": "retained-structural:" + kind, "scope": STRUCTURAL,
        "semantic_version": SEMANTIC, "represented_kind": kind,
        "members": [{"coordinate": r["coordinate"], "proposition_digest": r["proposition_digest"],
                     "rule_digest": r["rule_digest"]} for r in rules if r["kind"] in ("*", kind)]}
        for kind in sorted(kinds)]


def installed_interaction_generators() -> list[dict[str, str]]:
    body = {"generator_id": "declared-operand-occurrences/1",
        "scope": "ordered_declared_namespace_roles_and_targets_only",
        "source_digest": _value_digest(_PINS)}
    return [{**body, "generator_digest": _value_digest(body)}]


def normative_family_census() -> list[dict[str, Any]]:
    """Retain all234 semantic-family holes, not one invented obligation per slot."""
    selected = {row["represented_kind"]: row["members"]
        for row in installed_families([kind.value for kind in ObjectKind])}
    return [{"family_id": "current-family:" + kind.value + ":" + str(tier),
        "semantic_version": SEMANTIC, "represented_kind": kind.value, "tier": tier,
        "scope_kind": STRUCTURAL, "selected_scope_members": selected[kind.value] if tier == 1 else [],
        "selected_scope_family_closure": "PASS" if tier == 1 else "OUTSIDE_SELECTED_SCOPE",
        "full_family_members": None, "full_family_closure": "UNKNOWN"}
        for kind in ObjectKind for tier in range(1, 10)]


class _Exhausted(Exception):
    pass


class _Meter:
    def __init__(self, limits: dict[str, int]) -> None:
        self.limits, self.used = limits, {key: 0 for key in limits}

    def take(self, name: str, amount: int = 1) -> None:
        if amount > self.limits[name] - self.used[name]:
            raise _Exhausted(name)
        self.used[name] += amount


def _objects(value: Any, meter: _Meter) -> list[NamespaceObject]:
    if type(value) is not list or not value:
        raise ValueError("nonempty exact records required")
    meter.take("objects", len(value))
    result, seen = [], set()
    for row in value:
        _keys(row, "object_id kind payload operands")
        if type(row["operands"]) is not dict:
            raise ValueError("plain operand map required")
        for role, targets in row["operands"].items():
            _text(role)
            if type(targets) is not list:
                raise ValueError("plain ordered targets required")
        item = NamespaceObject.create(**row)
        if item.object_id in seen or canonical_bytes(item.to_dict()) != canonical_bytes(row):
            raise ValueError("duplicate or changed namespace record")
        seen.add(item.object_id); result.append(item)
    return sorted(result, key=lambda item: item.object_id)


def _fields(objects: list[NamespaceObject], meter: _Meter, *, source_id: str | None = None) -> list[dict[str, Any]]:
    rows = []
    for item in objects:
        record_digest = item.digest
        pending = [(item.to_dict(), [])]
        while pending:
            value, path = pending.pop()
            meter.take("operations")
            if path:
                meter.take("facets")
                encoded_value = canonical_bytes(value)
                meter.take("operations", len(encoded_value))
                row = {"object_id": item.object_id, "object_kind": item.kind.value,
                    "record_digest": record_digest, "path": path, "value_digest": _digest(encoded_value)}
                if source_id is not None:
                    row["source_unit_id"] = source_id
                row["facet_id"] = _value_digest([source_id, item.object_id, path])
                rows.append(row)
            if type(value) is dict:
                pending.extend((child, path + [key]) for key, child in sorted(value.items(), reverse=True))
            elif type(value) is list:
                pending.extend((value[i], path + [i]) for i in reversed(range(len(value))))
    return sorted(rows, key=lambda row: row["facet_id"])


def _decode_source(row: Any) -> tuple[str, bytes]:
    _keys(row, "unit_id language bytes_b64 bytes_digest")
    name = _text(row["unit_id"])
    if row["language"] != LANGUAGE:
        raise _Exhausted("unsupported_source_language")
    encoded = row["bytes_b64"]
    if type(encoded) is not str or len(encoded) > 4 * dag.MAX_BYTES // 3 + 4:
        raise _Exhausted("source_bytes")
    raw = base64.b64decode(encoded, validate=True)
    if len(raw) > dag.MAX_BYTES:
        raise _Exhausted("source_bytes")
    if base64.b64encode(raw).decode("ascii") != encoded or _hash(row["bytes_digest"]) != _digest(raw):
        raise ValueError("source bytes changed or noncanonical base64")
    return name, raw


def _native_intent(row: dict[str, Any], item: NamespaceObject, coordinate: str,
                   collection_digest: str) -> tuple[dict[str, Any], dict[str, Any], str, str]:
    _keys(row, "object_id coordinate request checker_policy")
    if row["object_id"] != item.object_id or row["coordinate"] != coordinate:
        raise ValueError("native intent differs")
    if coordinate == "OBJECT-1.1":
        request, policy = object_facets._request(row["request"]), object_facets._policy(row["checker_policy"])
        if (request["object_id"] != item.object_id or request["object_kind"] != item.kind.value
                or request["record_digest"] != item.digest
                or request["payload_digest"] != _digest(item.payload_bytes)
                or request["operands_digest"] != _value_digest(item.to_dict()["operands"])):
            raise ValueError("generic native intent subject/facets differ")
        mechanism, schema = object_facets.MECHANISM_ID, object_facets.CERTIFICATE_VERSION
    else:
        request, policy = typed_facets._request(row["request"]), typed_facets._policy(row["checker_policy"])
        if (request["subject_id"] != item.object_id or request["object_kind"] != item.kind.value
                or request["object_digest"] != item.digest or request["collection_digest"] != collection_digest):
            raise ValueError("typed native intent subject/collection differs")
        mechanism, schema = typed_facets.MECHANISM_ID, typed_facets.CERTIFICATE_VERSION
    if request["coordinate"] != coordinate or request["policy_digest"] != _value_digest(policy):
        raise ValueError("native intent policy/coordinate differs")
    return request, policy, mechanism, schema


def _discard_census(report: dict[str, Any]) -> None:
    """Discard unbounded/partial ledgers without upgrading a known FAIL."""
    for name in ("source_census", "namespace_census", "normative_family_census",
                 "semantic_facet_census", "interaction_census", "applicability_ledger",
                 "required_objectives", "native_dependency_profiles", "native_projection",
                 "native_dependency_inventory", "consumer_requirements", "unresolved_cells"):
        report[name] = []
    for name in ("derivation_status", "source_census_status", "namespace_census_status",
                 "normative_objective_census_status", "applicability_status", "interaction_census_status",
                 "native_projection_status", "native_dependency_inventory_status",
                 "consumer_census_status"):
        report[name] = "UNKNOWN"
    report["native_dependency_inventory_digest"] = None
    report["closure_certificate"] = None
    report["scope_admission"] = {"authority_status": "NOT_EVALUATED"}


def derive_current_application_requirements(source_scope_bytes: bytes, collection_bytes: bytes,
        selection_bytes: bytes, *, expected_compiler_policy_bytes: bytes) -> dict[str, Any]:
    """Compile before certificate outcomes; never infer complete application meaning."""
    report: dict[str, Any] = {"schema_version": SCHEMA, "mechanism_id": MECHANISM,
        "replayable": False, "status": "UNKNOWN", "derivation_status": "UNKNOWN",
        "source_census_status": "UNKNOWN", "namespace_census_status": "UNKNOWN",
        "normative_objective_census_status": "UNKNOWN", "applicability_status": "UNKNOWN",
        "interaction_census_status": "UNKNOWN", "native_projection_status": "UNKNOWN",
        "native_dependency_inventory_status": "UNKNOWN", "consumer_census_status": "UNKNOWN",
        "closure_status": "UNKNOWN",
        "full_application_status": "UNKNOWN", "polished": False,
        "scope_kind": None, "scope_admission": {"authority_status": "NOT_EVALUATED"},
        "source_census": [], "namespace_census": [], "normative_family_census": [],
        "semantic_facet_census": [], "interaction_census": [], "applicability_ledger": [],
        "required_objectives": [], "native_dependency_profiles": [], "native_projection": [],
        "native_dependency_inventory": [], "native_dependency_inventory_digest": None,
        "consumer_requirements": [], "unresolved_cells": [], "claim_boundary": BOUNDARY,
        "closure_certificate": None, "complete_bounds": False, "resource_usage": {}}
    try:
        inputs = {"source_scope": source_scope_bytes, "collection": collection_bytes,
            "selection": selection_bytes, "compiler_policy": expected_compiler_policy_bytes}
        for raw in inputs.values():
            if type(raw) is not bytes or len(raw) > dag.MAX_BYTES:
                raise _Exhausted("immutable_transport")
        report["input_digests"] = {key: _digest(raw) for key, raw in inputs.items()}
        bindings = source_bindings()
        dependency_inventory = facet_coverage.installed_native_dependency_inventory()
        dependency_inventory_digest = _value_digest(dependency_inventory)
        report.update(source_bindings=bindings, mechanism_digest=mechanism_digest(), replayable=True,
            native_dependency_inventory=dependency_inventory,
            native_dependency_inventory_digest=dependency_inventory_digest,
            native_dependency_inventory_status="REVIEWED_SOURCE_LOWER_BOUND")
        scope, collection, selection, policy = (dag._parse(inputs[key]) for key in inputs)
        _keys(scope, "schema_version scope_id revision source_units normative_families semantic_mappings interaction_generators census_evidence")
        _keys(collection, "schema_version objects")
        _keys(selection, "schema_version application_profile_id application_profile_version root_id semantic_version source_scope_digest collection_bytes_digest collection_digest selectors native_intents")
        _keys(policy, "schema_version mechanism_digest source_scope_digest collection_bytes_digest selection_digest installed_rule_set_digest normative_family_set_digest allowed_frontend_digests admitted_rule_digests limits")
        if (scope["schema_version"] != SOURCE or collection["schema_version"] != "verifier-polish-object-collection-1"
                or selection["schema_version"] != SELECTION or policy["schema_version"] != POLICY):
            raise ValueError("contract differs")
        _text(scope["scope_id"]); _text(scope["revision"])
        for name, observed in (("mechanism_digest", report["mechanism_digest"]),
                ("source_scope_digest", _digest(source_scope_bytes)),
                ("collection_bytes_digest", _digest(collection_bytes)), ("selection_digest", _digest(selection_bytes))):
            if _hash(policy[name]) != observed:
                raise ValueError("external input or installed mechanism differs")
        if any(bindings[path] != "sha256:" + pin for path, pin in _PINS.items()):
            raise _Exhausted("authored_rule_source_drift")
        limits = _keys(policy["limits"], " ".join(CEILINGS))
        if any(type(limits[key]) is not int or not 1 <= limits[key] <= maximum for key, maximum in CEILINGS.items()):
            raise ValueError("unsupported selected bounds")
        if limits["output_bytes"] < 8192:
            raise ValueError("bounded diagnostic output reservation required")
        meter = _Meter(limits)
        rules = installed_rules()
        if _hash(policy["installed_rule_set_digest"]) != _value_digest(rules):
            raise ValueError("installed rules changed")
        approved = policy["admitted_rule_digests"]
        if type(approved) is not list or approved != sorted(set(approved)):
            raise ValueError("sorted unique rule admission required")
        for pin in approved:
            _hash(pin)
        objects = _objects(collection["objects"], meter)
        by_id = {item.object_id: item for item in objects}
        selected_collection = composition_digest(objects)
        if (selection["semantic_version"] != SEMANTIC or selection["application_profile_version"] != "1"
                or selection["root_id"] not in by_id
                or selection["source_scope_digest"] != _digest(source_scope_bytes)
                or selection["collection_bytes_digest"] != _digest(collection_bytes)
                or selection["collection_digest"] != selected_collection):
            raise ValueError("selection differs from exact collection/source")
        mode = selection["application_profile_id"]
        report["scope_kind"] = mode
        if mode not in (STRUCTURAL, FULL):
            raise _Exhausted("unsupported_application_profile")
        composition = assess_composition(objects, expected_digest=selected_collection,
            max_objects=limits["objects"], max_operations=limits["operations"])
        if composition.verdict.value == "FAIL":
            raise ValueError("typed composition refuted")
        if composition.verdict.value != "PASS":
            raise _Exhausted("composition")
        namespace = _fields(objects, meter)
        report.update(namespace_census=namespace, namespace_census_status="PASS")
        units = scope["source_units"]
        if type(units) is not list or not units:
            raise _Exhausted("source_census_absent")
        meter.take("source_units", len(units))
        frontend = _value_digest({"language": LANGUAGE, "source_pins": _PINS})
        if policy["allowed_frontend_digests"] != [frontend]:
            raise _Exhausted("source_frontend_not_admitted")
        source_members, source_objects, names = [], {}, set()
        for unit in units:
            unit_id, raw = _decode_source(unit)
            if unit_id in names:
                raise ValueError("duplicate source unit")
            names.add(unit_id)
            parsed = _keys(dag._parse(raw), "schema_version objects")
            if parsed["schema_version"] != "verifier-polish-object-collection-1":
                raise ValueError("source language shape differs")
            # Source record budgets are separately charged against the same selected ceiling.
            unit_meter = _Meter(limits)
            members = _objects(parsed["objects"], unit_meter)
            meter.take("operations", unit_meter.used["objects"])
            for item in members:
                if item.object_id in source_objects:
                    raise ValueError("duplicate source object origin")
                source_objects[item.object_id] = item
            source_members.extend(_fields(members, meter, source_id=unit_id))
        if ({name: item.to_dict() for name, item in source_objects.items()}
                != {name: item.to_dict() for name, item in by_id.items()}):
            raise ValueError("exact source/namespace object census differs")
        _keys(scope["census_evidence"], "source_member_census_digest")
        if _hash(scope["census_evidence"]["source_member_census_digest"]) != _value_digest(source_members):
            raise ValueError("supplied source census differs from complete frontend replay")
        report.update(source_census=source_members, source_census_status="PASS")
        families = installed_families(sorted({item.kind.value for item in objects}))
        full_family_census = normative_family_census()
        if _hash(policy["normative_family_set_digest"]) != _value_digest(full_family_census):
            raise ValueError("normative family pin differs")
        report["normative_family_census"] = full_family_census
        unresolved = report["unresolved_cells"]
        if scope["normative_families"] != families:
            unresolved.append({"code": "NORMATIVE_FAMILY_SOURCE_UNSUPPORTED", "status": "UNKNOWN"})
        if scope["semantic_mappings"] != []:
            unresolved.append({"code": "APPLICATION_SEMANTIC_MAPPING_UNSUPPORTED", "status": "UNKNOWN"})
        if scope["interaction_generators"] != installed_interaction_generators():
            unresolved.append({"code": "INTERACTION_GENERATOR_UNSUPPORTED", "status": "UNKNOWN"})
        selectors = selection["selectors"]
        if type(selectors) is not list:
            raise ValueError("plain selector list required")
        for selector in selectors:
            if type(selector) is not dict or set(selector) != {"object_kind", "tier", "objective"}:
                unresolved.append({"code": "SELECTOR_UNSUPPORTED", "status": "UNKNOWN"}); continue
            if (type(selector["tier"]) is not int or not 1 <= selector["tier"] <= 9
                    or selector["object_kind"] not in {"*", *(k.value for k in ObjectKind)}):
                raise ValueError("selector kind/tier malformed")
            if selector["objective"] != "all.m" or selector["tier"] != 1:
                unresolved.append({"code": "OBJECTIVE_FAMILY_ENDPOINT_UNKNOWN", "status": "UNKNOWN"})
        intents = selection["native_intents"]
        if type(intents) is not list or len(intents) > limits["requirements"]:
            raise _Exhausted("native_intents")
        indexed = {}
        for intent in intents:
            _keys(intent, "object_id coordinate request checker_policy")
            identity = (_text(intent["object_id"]), _text(intent["coordinate"]))
            if identity in indexed:
                raise ValueError("duplicate native intent")
            indexed[identity] = intent
        used_intents = set()
        for item in objects:
            selected_rules = [r for r in rules["rules"] if r["kind"] in ("*", item.kind.value)]
            fields = [row for row in namespace if row["object_id"] == item.object_id]
            source_fields = [row for row in source_members if row["object_id"] == item.object_id]
            semantic_facets = []
            for name, prefix in (("identifier", "object_id"), ("admitted_kind", "kind"),
                    ("canonical_payload", "payload"), ("named_ordered_operand_map", "operands"),
                    ("declared_typed_composition", None)):
                row = {"semantic_facet_id": _value_digest([item.object_id, item.digest, name]),
                    "object_id": item.object_id, "name": name,
                    "namespace_field_ids": sorted(f["facet_id"] for f in fields if prefix is None or f["path"][0] == prefix),
                    "source_facet_ids": sorted(f["facet_id"] for f in source_fields if prefix is None or f["path"][0] == prefix)}
                semantic_facets.append(row)
            report["semantic_facet_census"].extend(semantic_facets)
            for role, targets in item.operands:
                for index, target in enumerate(targets):
                    meter.take("interactions"); meter.take("operations")
                    body = {"object_id": item.object_id, "record_digest": item.digest,
                        "role": role, "target_index": index, "target_id": target,
                        "target_record_digest": by_id[target].digest,
                        "generator_digest": installed_interaction_generators()[0]["generator_digest"]}
                    report["interaction_census"].append({"interaction_id": _value_digest(body), **body})
            obligations = []
            for rule in selected_rules:
                meter.take("requirements"); meter.take("operations")
                coordinate = rule["coordinate"]
                direct = coordinate == "OBJECT-1.1"
                context = {"adapter_id": "object-record/1" if direct else "typed-collection/1",
                    "subject_id": item.object_id, "object_kind": item.kind.value,
                    "object_digest": item.digest, "collection_digest": None if direct else selected_collection,
                    "member_ids": [item.object_id] if direct else sorted(by_id)}
                context_id = _value_digest(context)
                origin_ids = sorted(row["semantic_facet_id"] for row in semantic_facets
                    if (row["name"] == "declared_typed_composition") != direct)
                identity = {"object_id": item.object_id, "record_digest": item.digest,
                    "semantic_version": SEMANTIC, "coordinate": coordinate,
                    "proposition_digest": rule["proposition_digest"], "scope": rule["scope"],
                    "native_context_id": context_id, "rule_digest": rule["rule_digest"], "origin_ids": origin_ids}
                claim = _value_digest(identity)
                requirement = {"requirement_id": claim, "object_kind": item.kind.value,
                    "rule_id": rule["rule_id"], "origins": origin_ids, "binding_status": "UNKNOWN", **identity}
                report["required_objectives"].append(requirement)
                report["applicability_ledger"].append({"object_id": item.object_id,
                    "object_kind": item.kind.value, "record_digest": item.digest,
                    "semantic_version": SEMANTIC, "tier": 1, "coordinate": coordinate,
                    "requirement_id": claim, "applicability": "REQUIRED",
                    "applicability_scope": STRUCTURAL, "rule_digest": rule["rule_digest"],
                    "origin_ids": origin_ids, "native_context_id": context_id,
                    "inapplicability_evidence": None})
                obligations.append({"claim_id": claim, "semantic_version": SEMANTIC, "objective": coordinate,
                    "proposition_digest": rule["proposition_digest"], "scope": rule["scope"],
                    "assumptions": [], "dependencies": []})
                if rule["rule_digest"] not in approved:
                    unresolved.append({"requirement_id": claim, "code": "RULE_NOT_ADMITTED", "status": "UNKNOWN"})
                key = (item.object_id, coordinate)
                intent = indexed.get(key)
                if intent is None:
                    unresolved.append({"requirement_id": claim, "code": "NATIVE_INTENT_MISSING", "status": "UNKNOWN"})
                    continue
                used_intents.add(key)
                req, pol, native_id, cert_schema = _native_intent(intent, item, coordinate, selected_collection)
                requirement["binding_status"] = "PASS"
                report["native_projection"].append({"requirement_id": claim, "node_id": claim,
                    "object_id": item.object_id, "claim_id": claim, "native_context": context,
                    "semantic_version": SEMANTIC, "coordinate": coordinate, "scope": rule["scope"],
                    "proposition_digest": rule["proposition_digest"], "request": req, "checker_policy": pol,
                    "request_digest": _value_digest(req), "policy_digest": _value_digest(pol),
                    "mechanism_id": native_id, "mechanism_digest": pol["mechanism_digest"],
                    "certificate_schema_version": cert_schema, "binding_status": "PASS"})
            profile = {"schema_version": "verifier-certificate-dag-profile-1", "profile_id": item.object_id + ":structural",
                "profile_version": "1", "object_kind": item.kind.value, "obligations": obligations}
            report["native_dependency_profiles"].append({"object_id": item.object_id,
                "profile": profile, "profile_digest": _value_digest(profile)})
            for projection in report["native_projection"]:
                if projection["object_id"] == item.object_id:
                    projection["profile_digest"] = _value_digest(profile)
            for tier in range(1, 10):
                report["applicability_ledger"].append({"object_id": item.object_id, "tier": tier,
                    "semantic_version": SEMANTIC, "object_kind": item.kind.value,
                    "record_digest": item.digest, "coordinate": None, "requirement_id": None,
                    "applicability": "UNKNOWN", "applicability_scope": FULL,
                    "inapplicability_evidence": None,
                    "selected_structural_scope": "REQUIRED" if tier == 1 else "OUTSIDE_SELECTED_SCOPE",
                    "full_application_applicability": "UNKNOWN",
                    "full_objective_family_closure": "UNKNOWN"})
        if set(indexed) != used_intents:
            if mode == STRUCTURAL:
                raise ValueError("native intent outside independently derived requirement denominator")
            unresolved.extend({"object_id": key[0], "coordinate": key[1],
                "code": "NATIVE_INTENT_APPLICABILITY_OR_CONTEXT_UNSUPPORTED", "status": "UNKNOWN"}
                for key in sorted(set(indexed) - used_intents))
        if mode == FULL:
            # All family endpoints must close normatively, including absent kinds;
            # runtime registrations and a submitted family list do not close them.
            unresolved.extend({"family_id": row["family_id"], "represented_kind": row["represented_kind"],
                "tier": row["tier"], "code": "CURRENT_FULL_NORMATIVE_FAMILY_OPEN", "status": "UNKNOWN"}
                for row in full_family_census)
            unresolved.extend({"object_id": item.object_id, "tier": tier,
                "code": "FULL_APPLICATION_FAMILY_OR_SEMANTIC_CLOSURE_UNKNOWN", "status": "UNKNOWN"}
                for item in objects for tier in range(1, 10))
        report.update(derivation_status="PASS", resource_usage=meter.used, complete_bounds=True)
        closed = not unresolved
        for field in ("normative_objective_census_status", "applicability_status", "interaction_census_status",
                      "native_projection_status", "consumer_census_status"):
            report[field] = "PASS" if closed else "UNKNOWN"
        report.update(status="PASS" if closed else "UNKNOWN",
            closure_status="CLOSED_FOR_EXACT_SELECTED_FINITE_SCOPE" if closed else "UNKNOWN")
        certificate = {"schema_version": "verifier-application-census-closure-1",
            "scope_kind": mode, "source_scope_digest": _digest(source_scope_bytes),
            "input_digests": report["input_digests"], "mechanism_digest": report["mechanism_digest"],
            "member_set_digests": {key: _value_digest(report[key]) for key in (
                "source_census", "namespace_census", "normative_family_census", "semantic_facet_census",
                "interaction_census", "applicability_ledger", "required_objectives", "native_dependency_profiles",
                "native_projection", "native_dependency_inventory", "consumer_requirements",
                "unresolved_cells")},
            "conservation_status": "PASS" if closed else "UNKNOWN", "complete_bounds": True,
            "full_application_status": "UNKNOWN", "claim_boundary": BOUNDARY}
        certificate["digest"] = _value_digest(certificate)
        report["closure_certificate"] = certificate
        subject = {"schema_version": "verifier-application-scope-admission-subject-1",
            "operation": "ADMIT_APPLICATION_REQUIREMENT_SCOPE", "scope_kind": mode,
            "closure_certificate_digest": certificate["digest"], "input_digests": report["input_digests"],
            "mechanism_digest": report["mechanism_digest"], "admitted_inapplicability": []}
        report["scope_admission"] = {"authority_status": "NOT_EVALUATED",
            "subject": subject, "admission_subject_digest": _value_digest(subject)}
        output_size = len(canonical_bytes(report)) + 512
        meter.take("output_bytes", output_size)
    except (OSError, ImportError):
        report.update(status="UNKNOWN", replayable=False, reason="MECHANISM_UNAVAILABLE")
    except (_Exhausted, dag._Exhausted) as exc:
        report.update(status="UNKNOWN", complete_bounds=False, closure_status="UNKNOWN",
            reason="RESOURCE_OR_SUPPORTED_SCOPE_UNAVAILABLE", exhausted_resource=str(exc))
        # No partial ledger is emitted as a completed census, and selected output
        # exhaustion must not return the very over-bound payload it refused.
        _discard_census(report)
        if "input_digests" not in report:
            report["replayable"] = False
    except (RecursionError, OverflowError, CancelledError):
        known_fail = report["status"] == "FAIL"
        report.update(status="FAIL" if known_fail else "UNKNOWN", replayable=False,
            complete_bounds=False, closure_status="REFUTED" if known_fail else "UNKNOWN",
            reason="CHECKING_RESOURCE_OR_CANCELLED_UNAVAILABLE")
        _discard_census(report)
    except (ValueError, TypeError, KeyError, UnicodeError):
        report.update(status="FAIL", closure_status="REFUTED", reason="INVALID_OR_SUBSTITUTED_INPUT")
    # Enforce the same selected output ceiling on late FAIL/UNKNOWN diagnostics,
    # including paths that never reach the successful output charging above.
    output_limit = meter.limits["output_bytes"] if "meter" in locals() else CEILINGS["output_bytes"]
    if len(canonical_bytes(report)) + 512 > output_limit:
        known_fail = report["status"] == "FAIL"
        report.update(status="FAIL" if known_fail else "UNKNOWN", complete_bounds=False,
            closure_status="REFUTED" if known_fail else "UNKNOWN",
            reason="REFUTED_INPUT_OUTPUT_COMPACTED" if known_fail else "OUTPUT_BOUND_UNAVAILABLE",
            exhausted_resource="output_bytes")
        _discard_census(report)
    report["manifest_digest"] = _value_digest(report)
    return report


def recheck_current_application_requirements(manifest_bytes: bytes, *, expected_mechanism_digest: str,
        expected_manifest_digest: str, source_scope_bytes: bytes, collection_bytes: bytes,
        selection_bytes: bytes, expected_compiler_policy_bytes: bytes) -> dict[str, Any]:
    result = {"schema_version": "verifier-current-application-obligations-replay-1",
        "status": "FAIL", "replay_status": "REJECTED", "polished": False}
    try:
        inputs = {"source_scope": source_scope_bytes, "collection": collection_bytes,
            "selection": selection_bytes, "compiler_policy": expected_compiler_policy_bytes}
        for raw in inputs.values():
            if type(raw) is not bytes or len(raw) > dag.MAX_BYTES:
                raise dag._Exhausted("immutable_transport")
        stored = dag._parse(manifest_bytes)
        _hash(expected_mechanism_digest); _hash(expected_manifest_digest)
        if (stored.get("schema_version") != SCHEMA or stored.get("status") not in ("PASS", "FAIL", "UNKNOWN")
                or type(stored.get("replayable")) is not bool
                or stored.get("mechanism_digest") is not None and stored["mechanism_digest"] != expected_mechanism_digest
                or stored.get("manifest_digest") != expected_manifest_digest
                or _value_digest({k: v for k, v in stored.items() if k != "manifest_digest"}) != expected_manifest_digest):
            return result
        if "input_digests" not in stored:
            if stored["status"] != "PASS":
                result.update(status="UNKNOWN", replay_status="UNAVAILABLE", reason="COMPILER_INPUT_BINDINGS_UNAVAILABLE")
            return result
        if stored["input_digests"] != {name: _digest(raw) for name, raw in inputs.items()}:
            return result
        current = derive_current_application_requirements(source_scope_bytes, collection_bytes,
            selection_bytes, expected_compiler_policy_bytes=expected_compiler_policy_bytes)
        if current.get("mechanism_digest") is not None and current["mechanism_digest"] != expected_mechanism_digest:
            return result
        if current["replayable"] is not True:
            result.update(status="FAIL" if current["status"] == "FAIL" else "UNKNOWN", replay_status="UNAVAILABLE",
                reason=current.get("reason", "COMPILER_RECONSTRUCTION_UNAVAILABLE"),
                expected_manifest_digest=expected_manifest_digest, observed_manifest_digest=current["manifest_digest"],
                full_application_status="UNKNOWN")
            for name in ("input_digests", "source_bindings", "mechanism_digest", "scope_kind", "closure_status"):
                if name in current:
                    result[name] = current[name]
            return result
        if (current["replayable"] is True and current.get("mechanism_digest") == expected_mechanism_digest
                and canonical_bytes(current) == manifest_bytes):
            result.update(status=current["status"], replay_status="REPRODUCED",
                manifest_digest=current["manifest_digest"], closure_status=current["closure_status"],
                scope_kind=current["scope_kind"], full_application_status="UNKNOWN")
    except dag._Exhausted:
        result.update(status="UNKNOWN", replay_status="UNAVAILABLE", reason="COMPILER_REPLAY_RESOURCE_UNAVAILABLE")
    except (RecursionError, OverflowError, CancelledError):
        known_fail = "current" in locals() and current.get("status") == "FAIL"
        result.update(status="FAIL" if known_fail else "UNKNOWN", replay_status="UNAVAILABLE",
            reason="COMPILER_REPLAY_RESOURCE_OR_CANCELLED_UNAVAILABLE")
    except (ValueError, TypeError, KeyError, UnicodeError):
        pass
    return result
