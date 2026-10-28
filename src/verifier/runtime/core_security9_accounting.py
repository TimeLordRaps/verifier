"""Source-bound structural accounting for core Security-9 requirements.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
This mechanism checks an exact finite selection.  It never authenticates that the
selection is semantically complete and never authorizes release.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
from typing import Any

from verifier.core.namespace import ObjectKind
from verifier.runtime import core_tier_progression


SELECTION_SCHEMA = "verifier-core-security9-accounting-selection-1"
ASSESSMENT_SCHEMA = "verifier-core-security9-accounting-assessment-1"
CORE_REQUIREMENTS_SCHEMA = "verifier-core-application-required-instances-1"
CORE_PROFILE = "verifier-core-nine-tier-application-release-1"
SECURITY_TIER = 9
SECURITY_NAME = "SECURITY"
MAX_RECORD_BYTES = 16 * 1024 * 1024
MAX_ROWS = 16384
_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")
_INSTANCE_FIELDS = {
    "instance_id", "object_id", "operation_id", "context_digest", "instruction_digest",
    "generation", "shard_id", "node_id", "tier", "semantic_version", "objective",
    "proposition_digest", "request_digest", "checker_policy_digest",
}


class _Refuted(ValueError):
    pass


class _Unavailable(ValueError):
    pass


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def bytes_digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def value_digest(value: Any) -> str:
    return bytes_digest(canonical_bytes(value))


def mechanism_digest() -> str:
    root = Path(__file__).resolve().parents[1]
    names = (
        "runtime/core_security9_accounting.py",
        "runtime/core_application_release.py",
        "runtime/core_tier_progression.py",
        "standard/CORE_SECURITY9_ACCOUNTING.md",
        "standard/CORE_SECURITY9_REQUIREMENTS.md",
        "standard/CORE_NINE_TIER_RELEASE.md",
    )
    return value_digest({"schema_version": "verifier-core-security9-accounting-mechanism-1",
                         "direct_sources": {
                             name: bytes_digest((root / name).read_bytes()) for name in names
                         },
                         "installed_route_inventory_mechanism_digest": (
                             core_tier_progression.mechanism_digest())})


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise _Refuted(code)


def _keys(value: Any, fields: set[str], code: str) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == fields, code)
    return value


def _text(value: Any, code: str) -> str:
    _require(type(value) is str and 0 < len(value) <= 4096 and bool(value.strip()), code)
    return value


def _hash(value: Any, code: str) -> str:
    _require(type(value) is str and _HASH.fullmatch(value) is not None, code)
    return value


def _rows(value: Any, code: str) -> list[Any]:
    _require(type(value) is list, code)
    if len(value) > MAX_ROWS:
        raise _Unavailable("SECURITY9_ACCOUNTING_CAPACITY_EXHAUSTED")
    return value


def _decode(raw: bytes, code: str) -> dict[str, Any]:
    _require(type(raw) is bytes, code)
    if len(raw) > MAX_RECORD_BYTES:
        raise _Unavailable("SECURITY9_ACCOUNTING_CAPACITY_EXHAUSTED")

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result = {}
        for key, value in items:
            if key in result:
                raise _Refuted(code)
            result[key] = value
        return result

    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(_Refuted(code)))
    except _Refuted:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError, TypeError) as exc:
        raise _Refuted(code) from exc
    _require(type(value) is dict and canonical_bytes(value) == raw, code)
    return value


def _source(value: Any, code: str) -> None:
    _keys(value, {"uri", "sha256"}, code)
    _text(value["uri"], code)
    _hash(value["sha256"], code)


def _checker(value: Any, code: str) -> None:
    _keys(value, {"identifier", "mechanism_digest", "request_digest", "policy_digest"}, code)
    _text(value["identifier"], code)
    for field in ("mechanism_digest", "request_digest", "policy_digest"):
        _hash(value[field], code)


def _falsifiers(value: Any, code: str, *, checker_identifier: str) -> None:
    rows = _rows(value, code)
    _require(bool(rows), "SECURITY9_FALSIFIER_REQUIRED")
    seen = set()
    for row in rows:
        _keys(row, {"identifier", "source", "claim_sha256", "checker_identifier"}, code)
        identifier = _text(row["identifier"], code)
        _require(identifier not in seen, "SECURITY9_DUPLICATE_FALSIFIER")
        seen.add(identifier)
        _source(row["source"], code)
        _hash(row["claim_sha256"], code)
        _require(_text(row["checker_identifier"], code) == checker_identifier,
                 "SECURITY9_FALSIFIER_CHECKER_DIFFERS")


def _dependency(value: Any, code: str) -> str:
    _keys(value, {"requirement_id", "required_status", "source", "claim_sha256",
                  "checker", "falsifiers"}, code)
    _text(value["requirement_id"], code)
    _require(value["required_status"] in ("REQUIRED", "UNKNOWN"), code)
    _source(value["source"], code)
    _hash(value["claim_sha256"], code)
    _checker(value["checker"], code)
    _falsifiers(value["falsifiers"], code,
                checker_identifier=value["checker"]["identifier"])
    return value["required_status"]


def _initial_report() -> dict[str, Any]:
    return {
        "schema_version": ASSESSMENT_SCHEMA,
        "status": "UNKNOWN",
        "structural_status": "UNKNOWN",
        "family_accounting": "UNKNOWN",
        "checker_accounting": "UNKNOWN",
        "falsifier_accounting": "UNKNOWN",
        "interaction_accounting": "UNKNOWN",
        "security9_applicability": "UNKNOWN",
        "semantic_completeness": "UNKNOWN",
        "public_checkability": "UNKNOWN",
        "human_acceptance": "UNKNOWN",
        "release_admissible": False,
        "selection_digest": None,
        "requirements_digest": None,
        "consumer_source_coordinate_digest": None,
        "selected_family_count": None,
        "selected_instance_count": None,
        "selected_child_count": None,
        "selected_interaction_count": None,
        "blockers": [],
        "claim_boundary": (
            "Exact finite Security-9 family, native instance, threat-model, trusted-root, "
            "checker, falsifier, child and interaction bindings only. The selected rows do "
            "not authenticate exhaustive applicability, semantic completeness, public "
            "checkability, human acceptance, overall safety or release authority."
        ),
    }


def assess_security9_accounting(selection_bytes: bytes, *, requirements_bytes: bytes,
        expected_selection_digest: str, expected_requirements_digest: str,
        expected_consumer_source_coordinate: dict[str, Any],
        expected_consumer_source_coordinate_digest: str,
        expected_mechanism_digest: str, cancelled: bool = False) -> dict[str, Any]:
    """Validate a host-pinned finite Security-9 accounting selection."""
    report = _initial_report()
    try:
        _require(type(cancelled) is bool, "SECURITY9_CANCEL_FLAG")
        if cancelled:
            report["blockers"].append("SECURITY9_ACCOUNTING_CANCELLED")
            raise _Unavailable("SECURITY9_ACCOUNTING_NOT_RUN")
        _require(type(expected_consumer_source_coordinate) is dict
                 and bool(expected_consumer_source_coordinate), "SECURITY9_SOURCE_COORDINATE_REQUIRED")
        for value, code in (
            (expected_selection_digest, "SECURITY9_SELECTION_DIGEST_DIFFERS"),
            (expected_requirements_digest, "SECURITY9_REQUIREMENTS_DIGEST_DIFFERS"),
            (expected_consumer_source_coordinate_digest, "SECURITY9_SOURCE_COORDINATE_DIGEST_DIFFERS"),
            (expected_mechanism_digest, "SECURITY9_MECHANISM_DIFFERS"),
        ):
            _hash(value, code)
        _require(value_digest(expected_consumer_source_coordinate)
                 == expected_consumer_source_coordinate_digest,
                 "SECURITY9_SOURCE_COORDINATE_DIGEST_DIFFERS")

        selection = _decode(selection_bytes, "SECURITY9_SELECTION_FIELDS")
        requirements = _decode(requirements_bytes, "SECURITY9_REQUIREMENTS_FIELDS")
        report["selection_digest"] = bytes_digest(selection_bytes)
        report["requirements_digest"] = bytes_digest(requirements_bytes)
        report["consumer_source_coordinate_digest"] = expected_consumer_source_coordinate_digest
        _require(report["selection_digest"] == expected_selection_digest,
                 "SECURITY9_SELECTION_DIGEST_DIFFERS")
        _require(report["requirements_digest"] == expected_requirements_digest,
                 "SECURITY9_REQUIREMENTS_DIGEST_DIFFERS")
        _require(mechanism_digest() == expected_mechanism_digest, "SECURITY9_MECHANISM_DIFFERS")

        _keys(selection, {"schema_version", "candidate_status", "semantic_completeness",
                          "profile_id", "consumer_source_coordinate",
                          "consumer_source_coordinate_digest", "requirements_digest",
                          "security_requirements_spec_digest", "families", "instances",
                          "child_requirements", "interaction_requirements"},
              "SECURITY9_SELECTION_FIELDS")
        _require(selection["schema_version"] == SELECTION_SCHEMA
                 and selection["candidate_status"] == "CANDIDATE"
                 and selection["semantic_completeness"] == "UNKNOWN"
                 and selection["profile_id"] == CORE_PROFILE,
                 "SECURITY9_SELECTION_VERSION")
        _require(selection["consumer_source_coordinate"] == expected_consumer_source_coordinate
                 and selection["consumer_source_coordinate_digest"]
                 == expected_consumer_source_coordinate_digest,
                 "SECURITY9_SOURCE_COORDINATE_DIFFERS")
        _require(selection["requirements_digest"] == expected_requirements_digest,
                 "SECURITY9_REQUIREMENTS_DIGEST_DIFFERS")
        spec = Path(__file__).resolve().parents[1] / "standard" / "CORE_SECURITY9_REQUIREMENTS.md"
        _require(selection["security_requirements_spec_digest"] == bytes_digest(spec.read_bytes()),
                 "SECURITY9_SPECIFICATION_DIFFERS")

        _keys(requirements, {"schema_version", "profile_id", "root", "tiers", "families",
                             "instances", "extension"}, "SECURITY9_REQUIREMENTS_FIELDS")
        _require(requirements["schema_version"] == CORE_REQUIREMENTS_SCHEMA
                 and requirements["profile_id"] == CORE_PROFILE,
                 "SECURITY9_REQUIREMENTS_VERSION")
        native_instances = {}
        for row in _rows(requirements["instances"], "SECURITY9_REQUIREMENTS_FIELDS"):
            _keys(row, _INSTANCE_FIELDS, "SECURITY9_REQUIREMENT_INSTANCE_FIELDS")
            if row["tier"] != SECURITY_TIER:
                continue
            identifier = _text(row["instance_id"], "SECURITY9_REQUIREMENT_INSTANCE_FIELDS")
            _require(identifier not in native_instances, "SECURITY9_DUPLICATE_INSTANCE")
            native_instances[identifier] = row

        expected_families = {}
        covered = set()
        for row in _rows(requirements["families"], "SECURITY9_REQUIREMENTS_FIELDS"):
            _keys(row, {"object_kind", "tier", "tier_name", "census", "required_instances"},
                  "SECURITY9_REQUIREMENT_FAMILY_FIELDS")
            if row["tier"] != SECURITY_TIER:
                continue
            kind = ObjectKind(row["object_kind"]).value
            _require(row["tier_name"] == SECURITY_NAME
                     and row["census"] in ("COMPLETE", "UNKNOWN"),
                     "SECURITY9_REQUIREMENT_FAMILY_FIELDS")
            identifiers = [_text(value, "SECURITY9_REQUIREMENT_FAMILY_FIELDS")
                           for value in _rows(row["required_instances"],
                                              "SECURITY9_REQUIREMENT_FAMILY_FIELDS")]
            _require(kind not in expected_families and len(identifiers) == len(set(identifiers))
                     and not set(identifiers) & covered
                     and all(value in native_instances for value in identifiers),
                     "SECURITY9_REQUIREMENT_CONSERVATION_DIFFERS")
            expected_families[kind] = row
            covered.update(identifiers)
        _require(set(expected_families) == {kind.value for kind in ObjectKind}
                 and covered == set(native_instances),
                 "SECURITY9_REQUIREMENT_CONSERVATION_DIFFERS")

        selected_families = {}
        for row in _rows(selection["families"], "SECURITY9_FAMILY_FIELDS"):
            _keys(row, {"object_kind", "tier", "tier_name", "census", "required_instances",
                        "applicability_source"}, "SECURITY9_FAMILY_FIELDS")
            kind = ObjectKind(row["object_kind"]).value
            _require(kind not in selected_families and row["tier"] == SECURITY_TIER
                     and row["tier_name"] == SECURITY_NAME, "SECURITY9_FAMILY_FIELDS")
            _source(row["applicability_source"], "SECURITY9_FAMILY_FIELDS")
            expected = expected_families.get(kind)
            _require(expected is not None and row["census"] == expected["census"]
                     and type(row["required_instances"]) is list
                     and len(row["required_instances"]) == len(set(row["required_instances"]))
                     and set(row["required_instances"]) == set(expected["required_instances"]),
                     "SECURITY9_FAMILY_BINDING_DIFFERS")
            selected_families[kind] = row
        _require(set(selected_families) == set(expected_families),
                 "SECURITY9_FAMILY_SET_DIFFERS")

        selected_instances = {}
        instance_children = {}
        instance_interactions = {}
        dependency_unknown = False
        interaction_unknown = False
        for row in _rows(selection["instances"], "SECURITY9_INSTANCE_FIELDS"):
            _keys(row, {"instance_id", "instance_binding_digest", "threat_model",
                        "trusted_roots", "scope", "checker", "falsifiers",
                        "dependency_census", "child_requirement_ids",
                        "interaction_census", "interaction_requirement_ids"},
                  "SECURITY9_INSTANCE_FIELDS")
            identifier = _text(row["instance_id"], "SECURITY9_INSTANCE_FIELDS")
            expected = native_instances.get(identifier)
            _require(expected is not None and identifier not in selected_instances
                     and row["instance_binding_digest"] == value_digest(expected),
                     "SECURITY9_INSTANCE_BINDING_DIFFERS")
            _keys(row["threat_model"], {"identifier", "source", "claim_sha256"},
                  "SECURITY9_THREAT_MODEL_FIELDS")
            _text(row["threat_model"]["identifier"], "SECURITY9_THREAT_MODEL_FIELDS")
            _source(row["threat_model"]["source"], "SECURITY9_THREAT_MODEL_FIELDS")
            _hash(row["threat_model"]["claim_sha256"], "SECURITY9_THREAT_MODEL_FIELDS")
            roots = _rows(row["trusted_roots"], "SECURITY9_TRUSTED_ROOT_FIELDS")
            _require(bool(roots), "SECURITY9_TRUSTED_ROOT_REQUIRED")
            root_ids = set()
            for root in roots:
                _keys(root, {"identifier", "role", "artifact_digest"},
                      "SECURITY9_TRUSTED_ROOT_FIELDS")
                root_id = _text(root["identifier"], "SECURITY9_TRUSTED_ROOT_FIELDS")
                _require(root_id not in root_ids, "SECURITY9_DUPLICATE_TRUSTED_ROOT")
                root_ids.add(root_id)
                _text(root["role"], "SECURITY9_TRUSTED_ROOT_FIELDS")
                _hash(root["artifact_digest"], "SECURITY9_TRUSTED_ROOT_FIELDS")
            scope_fields = {"object_id", "operation_id", "context_digest", "instruction_digest",
                            "generation", "semantic_version", "objective", "proposition_digest"}
            _keys(row["scope"], scope_fields, "SECURITY9_SCOPE_FIELDS")
            _require(row["scope"] == {field: expected[field] for field in scope_fields},
                     "SECURITY9_SCOPE_DIFFERS")
            _checker(row["checker"], "SECURITY9_CHECKER_FIELDS")
            _require(row["checker"]["request_digest"] == expected["request_digest"]
                     and row["checker"]["policy_digest"] == expected["checker_policy_digest"],
                     "SECURITY9_CHECKER_BINDING_DIFFERS")
            _falsifiers(row["falsifiers"], "SECURITY9_FALSIFIER_FIELDS",
                        checker_identifier=row["checker"]["identifier"])
            _require(row["dependency_census"] in ("COMPLETE", "UNKNOWN")
                     and row["interaction_census"] in ("COMPLETE", "UNKNOWN"),
                     "SECURITY9_CENSUS_FIELDS")
            children = [_text(value, "SECURITY9_CHILD_BINDING_FIELDS") for value in
                        _rows(row["child_requirement_ids"], "SECURITY9_CHILD_BINDING_FIELDS")]
            interactions = [_text(value, "SECURITY9_INTERACTION_BINDING_FIELDS") for value in
                            _rows(row["interaction_requirement_ids"],
                                  "SECURITY9_INTERACTION_BINDING_FIELDS")]
            _require(len(children) == len(set(children))
                     and len(interactions) == len(set(interactions)),
                     "SECURITY9_DUPLICATE_DEPENDENCY_BINDING")
            dependency_unknown |= row["dependency_census"] == "UNKNOWN"
            interaction_unknown |= row["interaction_census"] == "UNKNOWN"
            selected_instances[identifier] = row
            instance_children[identifier] = set(children)
            instance_interactions[identifier] = set(interactions)
        _require(set(selected_instances) == set(native_instances),
                 "SECURITY9_INSTANCE_SET_DIFFERS")

        children = {}
        for row in _rows(selection["child_requirements"], "SECURITY9_CHILD_FIELDS"):
            _keys(row, {"subject_instance_id", "requirement"}, "SECURITY9_CHILD_FIELDS")
            subject = _text(row["subject_instance_id"], "SECURITY9_CHILD_FIELDS")
            _require(subject in selected_instances, "SECURITY9_CHILD_SUBJECT_DIFFERS")
            dependency_unknown |= (_dependency(
                row["requirement"], "SECURITY9_CHILD_FIELDS") == "UNKNOWN")
            identifier = row["requirement"]["requirement_id"]
            _require(identifier not in children, "SECURITY9_DUPLICATE_CHILD_REQUIREMENT")
            children[identifier] = subject
        _require(all(instance_children[subject] == {identifier for identifier, owner in children.items()
                                                    if owner == subject}
                     for subject in selected_instances), "SECURITY9_CHILD_BINDING_DIFFERS")

        interactions = {}
        for row in _rows(selection["interaction_requirements"], "SECURITY9_INTERACTION_FIELDS"):
            _keys(row, {"participant_instance_ids", "requirement"},
                  "SECURITY9_INTERACTION_FIELDS")
            participants = [_text(value, "SECURITY9_INTERACTION_FIELDS") for value in
                            _rows(row["participant_instance_ids"], "SECURITY9_INTERACTION_FIELDS")]
            _require(bool(participants) and len(participants) == len(set(participants))
                     and all(value in selected_instances for value in participants),
                     "SECURITY9_INTERACTION_PARTICIPANTS_DIFFER")
            interaction_unknown |= (_dependency(
                row["requirement"], "SECURITY9_INTERACTION_FIELDS") == "UNKNOWN")
            identifier = row["requirement"]["requirement_id"]
            _require(identifier not in interactions, "SECURITY9_DUPLICATE_INTERACTION_REQUIREMENT")
            interactions[identifier] = set(participants)
        _require(all(instance_interactions[subject]
                     == {identifier for identifier, participants in interactions.items()
                         if subject in participants} for subject in selected_instances),
                 "SECURITY9_INTERACTION_BINDING_DIFFERS")

        report.update(structural_status="PASS", family_accounting="PASS",
                      checker_accounting="PASS", falsifier_accounting="PASS",
                      interaction_accounting="PASS",
                      selected_family_count=len(selected_families),
                      selected_instance_count=len(selected_instances),
                      selected_child_count=len(children),
                      selected_interaction_count=len(interactions))
        if any(row["census"] == "UNKNOWN" for row in selected_families.values()):
            report["blockers"].append("SECURITY9_APPLICABILITY_UNKNOWN")
        if dependency_unknown:
            report["blockers"].append("SECURITY9_DEPENDENCY_CENSUS_UNKNOWN")
        if interaction_unknown:
            report["blockers"].append("SECURITY9_INTERACTION_CENSUS_UNKNOWN")
        report["blockers"].extend(("SECURITY9_AUTHORITY_NOT_ESTABLISHED",
                                   "SECURITY9_SEMANTIC_COMPLETENESS_UNKNOWN",
                                   "SECURITY9_PUBLIC_CHECKABILITY_UNKNOWN",
                                   "SECURITY9_HUMAN_ACCEPTANCE_UNKNOWN"))
    except _Unavailable as exc:
        report["blockers"].append(str(exc))
    except (MemoryError, RecursionError, OverflowError):
        report["blockers"].append("SECURITY9_ACCOUNTING_RESOURCE_UNAVAILABLE")
    except (_Refuted, KeyError, TypeError, ValueError, UnicodeError, OSError) as exc:
        report["status"] = "FAIL"
        report["structural_status"] = "FAIL"
        report["blockers"].append(str(exc) if isinstance(exc, _Refuted)
                                  else "SECURITY9_ACCOUNTING_CONTRACT_REJECTED")
    report["blockers"] = sorted(set(report["blockers"]))
    report["assessment_digest"] = value_digest(report)
    return report


__all__ = [
    "ASSESSMENT_SCHEMA", "CORE_PROFILE", "SELECTION_SCHEMA",
    "assess_security9_accounting", "bytes_digest", "canonical_bytes",
    "mechanism_digest", "value_digest",
]
