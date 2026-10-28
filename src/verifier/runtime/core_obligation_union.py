"""Private candidate-union checker for core Verifier obligation contributions.

Secure Hash Algorithm 256-bit (SHA-256) digests bind supplied bytes, and JavaScript
Object Notation (JSON) supplies the canonical structured encoding. A clean structural
report is never semantic completeness, release admission, or source authority. Family
source maps and their expected-member authority stay external.
"""
from __future__ import annotations

from hashlib import sha256
import json
import re
from typing import Any


AUTHORITY_SCHEMA = "verifier-core-obligation-union-authority-candidate-1"
CONTRIBUTION_SCHEMA = "verifier-core-obligation-contribution-candidate-1"
REPORT_SCHEMA = "verifier-core-obligation-union-report-1"
HARNESS_CANDIDATE_SCHEMA = "times-harness-private-nine-core-census-candidate-1"
RELEASE_EVIDENCE_SCHEMA = "verifier-v2-core-release-evidence-ledger-1"

_HASH = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX40 = re.compile(r"^[0-9a-f]{40}$")
_MECHANISM_KINDS = {"UNKNOWN", "UNREGISTERED", "REGISTERED", "HOST_REVIEW", "DECLARED_TEST"}
_EVIDENCE_STATES = {"UNKNOWN", "AVAILABLE", "PASS", "FAIL"}


def canonical_bytes(value: Any) -> bytes:
    """Encode one bounded logical value deterministically; this is not authentication."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                      allow_nan=False).encode("utf-8")


def value_digest(value: Any) -> str:
    return "sha256:" + sha256(canonical_bytes(value)).hexdigest()


def bytes_digest(raw: bytes) -> str:
    return "sha256:" + sha256(raw).hexdigest()


def text_digest(text: str) -> str:
    return "sha256:" + sha256(text.encode("utf-8")).hexdigest()


def _hash(value: Any, *, optional: bool = False) -> bool:
    return (value is None and optional) or (type(value) is str and _HASH.fullmatch(value) is not None)


def _text(value: Any) -> bool:
    return type(value) is str and bool(value.strip()) and len(value) <= 4096


def _coordinate(value: Any) -> bool:
    if _hash(value):
        return True
    if type(value) is not dict or not value:
        return False
    try:
        return len(canonical_bytes(value)) <= 65536
    except (TypeError, ValueError, UnicodeError):
        return False


def _keys(value: Any, required: set[str], optional: set[str] | None = None) -> bool:
    if type(value) is not dict:
        return False
    optional = optional or set()
    return required <= set(value) <= required | optional


def _issue(issues: list[dict[str, str]], code: str, location: str, detail: str) -> None:
    issues.append({"code": code, "location": location, "detail": detail})


def _candidate_markers(value: dict[str, Any], location: str,
                       issues: list[dict[str, str]]) -> None:
    if value.get("candidate_status") != "CANDIDATE":
        _issue(issues, "UNSUPPORTED_CANDIDATE_STATUS", location,
               "candidate_status must remain CANDIDATE")
    if value.get("completeness") != "UNKNOWN":
        _issue(issues, "UNSUPPORTED_COMPLETENESS_ASSERTION", location,
               "completeness must remain UNKNOWN")


def _source(value: Any) -> bool:
    return (_keys(value, {"uri", "sha256"}) and _text(value["uri"])
            and _hash(value["sha256"]))


def _dependency(value: Any, *, producer: Any, consumer: Any, location: str,
                issues: list[dict[str, str]]) -> bool:
    fields = {"status", "producer_source_coordinate_digest", "consumer_source_coordinate_digest",
              "candidate_input_digest", "package_digest", "mechanism_digest"}
    if not _keys(value, fields):
        _issue(issues, "INVALID_DEPENDENCY_BINDING", location,
               "dependency binding has unsupported shape")
        return False
    valid = True
    if value["status"] != "UNKNOWN":
        _issue(issues, "UNSUPPORTED_COMPLETENESS_ASSERTION", location,
               "dependency status must remain UNKNOWN")
        valid = False
    for field in ("producer_source_coordinate_digest", "consumer_source_coordinate_digest",
                  "candidate_input_digest"):
        if not _hash(value[field]):
            _issue(issues, "INVALID_DEPENDENCY_BINDING", location, f"{field} is not SHA-256")
            valid = False
    for field in ("package_digest", "mechanism_digest"):
        if not _hash(value[field], optional=True):
            _issue(issues, "INVALID_DEPENDENCY_BINDING", location, f"{field} is not SHA-256 or null")
            valid = False
    if value.get("producer_source_coordinate_digest") != value_digest(producer):
        _issue(issues, "DEPENDENCY_COORDINATE_MISMATCH", location,
               "producer coordinate digest does not bind the contribution producer")
        valid = False
    if value.get("consumer_source_coordinate_digest") != value_digest(consumer):
        _issue(issues, "DEPENDENCY_COORDINATE_MISMATCH", location,
               "consumer coordinate digest does not bind the selected consumer")
        valid = False
    if value.get("package_digest") is None or value.get("mechanism_digest") is None:
        _issue(issues, "DEPENDENCY_SELECTION_INCOMPLETE", location,
               "host-selected package and mechanism digests are still required")
        valid = False
    return valid


def _requirement(value: Any, location: str, issues: list[dict[str, str]]) -> tuple | None:
    fields = {"object_kind", "tier", "member_id", "source", "claim_sha256"}
    if not _keys(value, fields):
        _issue(issues, "INVALID_EXPECTED_MEMBER", location, "expected member has unsupported shape")
        return None
    if (not _text(value["object_kind"]) or type(value["tier"]) is not int
            or not 1 <= value["tier"] <= 9 or not _text(value["member_id"])
            or not _source(value["source"]) or not _hash(value["claim_sha256"])):
        _issue(issues, "INVALID_EXPECTED_MEMBER", location,
               "expected member lacks exact object, core tier, identity, source, or claim digest")
        return None
    return value["object_kind"], value["tier"], value["member_id"]


def _mechanism(value: Any, location: str, issues: list[dict[str, str]]) -> bool:
    if not _keys(value, {"kind", "identifier"}):
        _issue(issues, "INVALID_ACCEPTANCE_MECHANISM", location, "unsupported mechanism shape")
        return False
    kind, identifier = value["kind"], value["identifier"]
    if kind not in _MECHANISM_KINDS:
        _issue(issues, "INVALID_ACCEPTANCE_MECHANISM", location, "unknown mechanism kind")
        return False
    needs_id = kind in {"REGISTERED", "HOST_REVIEW", "DECLARED_TEST"}
    if (needs_id and not _text(identifier)) or (not needs_id and identifier is not None):
        _issue(issues, "INVALID_ACCEPTANCE_MECHANISM", location,
               "mechanism identifier does not match its kind")
        return False
    return True


def _evidence(value: Any, *, row: dict[str, Any], producer: Any, consumer: Any,
              location: str, issues: list[dict[str, str]], evidence_ids: set[str]) -> bool:
    if not _keys(value, {"status", "bindings"}, {"reported"}):
        _issue(issues, "INVALID_CURRENT_EVIDENCE", location, "unsupported current-evidence shape")
        return False
    valid = True
    if value["status"] not in _EVIDENCE_STATES or type(value["bindings"]) is not list:
        _issue(issues, "INVALID_CURRENT_EVIDENCE", location, "invalid evidence status or bindings")
        return False
    if "reported" in value and type(value["reported"]) is not dict:
        _issue(issues, "INVALID_CURRENT_EVIDENCE", location, "reported evidence must be an object")
        valid = False
    if value["status"] != "UNKNOWN" and not value["bindings"]:
        _issue(issues, "EVIDENCE_REQUIRED", location, "non-UNKNOWN evidence status needs an exact binding")
        valid = False
    fields = {"evidence_id", "uri", "sha256", "producer_source_coordinate_digest",
              "consumer_source_coordinate_digest", "source_sha256", "claim_sha256",
              "object_kind", "tier", "member_id"}
    for index, binding in enumerate(value["bindings"]):
        here = f"{location}.bindings[{index}]"
        if not _keys(binding, fields) or not _text(binding.get("evidence_id")) \
                or not _text(binding.get("uri")) or not _hash(binding.get("sha256")):
            _issue(issues, "INVALID_EVIDENCE_BINDING", here, "unsupported evidence binding")
            valid = False
            continue
        if binding["evidence_id"] in evidence_ids:
            _issue(issues, "DUPLICATE_EVIDENCE", here, "evidence identity is reused")
            valid = False
        evidence_ids.add(binding["evidence_id"])
        expected = {
            "producer_source_coordinate_digest": value_digest(producer),
            "consumer_source_coordinate_digest": value_digest(consumer),
            "source_sha256": row["source"].get("sha256"),
            "claim_sha256": row["claim"].get("sha256"),
            "object_kind": row.get("object_kind"),
            "tier": row.get("tier"),
            "member_id": row.get("member_id"),
        }
        if any(binding.get(key) != expected_value for key, expected_value in expected.items()):
            _issue(issues, "EVIDENCE_BINDING_MISMATCH", here,
                   "evidence does not bind the exact producer, consumer, source, claim, object, tier, and member")
            valid = False
    return valid


def validate_union(authority: dict[str, Any] | None, contributions: list[dict[str, Any]], *,
                   expected_authority_digest: str | None,
                   expected_source_coordinate: Any | None) -> dict[str, Any]:
    """Check one candidate union without upgrading candidate evidence or completeness."""
    issues: list[dict[str, str]] = []
    report: dict[str, Any] = {
        "schema_version": REPORT_SCHEMA,
        "candidate_status": "CANDIDATE",
        "authority_binding": "UNKNOWN",
        "source_coordinate_binding": "UNKNOWN",
        "dependency_binding": "UNKNOWN",
        "candidate_coverage": "UNKNOWN",
        "structural_union": "FAIL",
        "semantic_completeness": "UNKNOWN",
        "release_admissible": False,
        "issues": issues,
        "counts": {"expected_families": 0, "received_families": 0,
                   "expected_members": 0, "received_members": 0},
    }
    if type(contributions) is not list:
        _issue(issues, "INVALID_CONTRIBUTIONS", "contributions", "contributions must be a list")
        contributions = []
    if expected_source_coordinate is None or not _coordinate(expected_source_coordinate):
        _issue(issues, "SOURCE_COORDINATE_SELECTION_REQUIRED", "expected_source_coordinate",
               "an independently selected consumer coordinate is required")

    authority_families: dict[str, dict[str, Any]] = {}
    expected_by_family: dict[str, dict[tuple, dict[str, Any]]] = {}
    expected_global: dict[tuple, str] = {}
    authority_consumer: Any = expected_source_coordinate
    authority_valid = True
    authority_fields = {"schema_version", "candidate_status", "completeness",
                        "consumer_source_coordinate", "families"}
    if authority is None:
        _issue(issues, "AUTHORITY_REQUIRED", "authority",
               "candidate contributions cannot authenticate their expected-member denominator")
        authority_valid = False
    elif not _keys(authority, authority_fields):
        _issue(issues, "INVALID_AUTHORITY", "authority", "authority candidate has unsupported shape")
        authority_valid = False
    else:
        _candidate_markers(authority, "authority", issues)
        if authority["schema_version"] != AUTHORITY_SCHEMA:
            _issue(issues, "INVALID_AUTHORITY", "authority.schema_version", "unsupported schema")
            authority_valid = False
        authority_consumer = authority["consumer_source_coordinate"]
        if not _coordinate(authority_consumer):
            _issue(issues, "INVALID_SOURCE_COORDINATE", "authority.consumer_source_coordinate",
                   "consumer coordinate is invalid")
            authority_valid = False
        if expected_source_coordinate is not None:
            if authority_consumer == expected_source_coordinate:
                report["source_coordinate_binding"] = "MATCHED"
            else:
                report["source_coordinate_binding"] = "MISMATCH"
                _issue(issues, "FOREIGN_SOURCE_COORDINATE", "authority.consumer_source_coordinate",
                       "authority names a different consumer coordinate")
        if expected_authority_digest is None:
            _issue(issues, "AUTHORITY_SELECTION_REQUIRED", "expected_authority_digest",
                   "authority bytes require a separately supplied digest")
        elif not _hash(expected_authority_digest) or value_digest(authority) != expected_authority_digest:
            report["authority_binding"] = "MISMATCH"
            _issue(issues, "AUTHORITY_DIGEST_MISMATCH", "authority",
                   "authority candidate differs from the independently supplied digest")
        else:
            report["authority_binding"] = "MATCHED"
        families = authority.get("families")
        if type(families) is not list:
            _issue(issues, "INVALID_AUTHORITY", "authority.families", "family authority must be a list")
            authority_valid = False
            families = []
        for index, family in enumerate(families):
            location = f"authority.families[{index}]"
            fields = {"family_id", "source_map_digest", "producer_source_coordinate",
                      "dependency_selection", "requirements"}
            if not _keys(family, fields) or not _text(family.get("family_id")) \
                    or not _hash(family.get("source_map_digest")) \
                    or not _coordinate(family.get("producer_source_coordinate")) \
                    or type(family.get("requirements")) is not list:
                _issue(issues, "INVALID_FAMILY_AUTHORITY", location, "family authority has unsupported shape")
                authority_valid = False
                continue
            family_id = family["family_id"]
            if family_id in authority_families:
                _issue(issues, "DUPLICATE_FAMILY", location, "family authority is duplicated")
                authority_valid = False
                continue
            _dependency(family["dependency_selection"], producer=family["producer_source_coordinate"],
                        consumer=authority_consumer, location=location + ".dependency_selection", issues=issues)
            authority_families[family_id] = family
            required: dict[tuple, dict[str, Any]] = {}
            for ridx, requirement in enumerate(family["requirements"]):
                key = _requirement(requirement, f"{location}.requirements[{ridx}]", issues)
                if key is None:
                    authority_valid = False
                    continue
                if key in required:
                    _issue(issues, "DUPLICATE_EXPECTED_MEMBER", location, "expected member is duplicated")
                    authority_valid = False
                if key in expected_global and expected_global[key] != family_id:
                    _issue(issues, "OVERLAPPING_FAMILY_REQUIREMENT", location,
                           "two families claim the same object/tier/member")
                    authority_valid = False
                required[key] = requirement
                expected_global[key] = family_id
            expected_by_family[family_id] = required

    report["counts"]["expected_families"] = len(authority_families)
    report["counts"]["expected_members"] = sum(len(rows) for rows in expected_by_family.values())

    contribution_families: dict[str, list[dict[str, Any]]] = {}
    received_by_family: dict[str, set[tuple]] = {}
    global_members: dict[tuple, str] = {}
    evidence_ids: set[str] = set()
    dependency_ok = True
    contribution_fields = {"schema_version", "candidate_status", "completeness",
                           "producer_source_coordinate", "consumer_source_coordinate", "family_id",
                           "source_map_digest", "dependency_binding", "rows"}
    row_fields = {"source", "claim", "object_kind", "tier", "member_id",
                  "acceptance_mechanism", "current_evidence", "uncovered_action"}
    for index, contribution in enumerate(contributions):
        location = f"contributions[{index}]"
        if not _keys(contribution, contribution_fields):
            _issue(issues, "INVALID_CONTRIBUTION", location, "contribution has unsupported shape")
            dependency_ok = False
            continue
        _candidate_markers(contribution, location, issues)
        if contribution["schema_version"] != CONTRIBUTION_SCHEMA:
            _issue(issues, "INVALID_CONTRIBUTION", location + ".schema_version", "unsupported schema")
        family_id = contribution["family_id"]
        producer = contribution["producer_source_coordinate"]
        consumer = contribution["consumer_source_coordinate"]
        if not _text(family_id) or not _coordinate(producer) or not _coordinate(consumer) \
                or not _hash(contribution["source_map_digest"]) or type(contribution["rows"]) is not list:
            _issue(issues, "INVALID_CONTRIBUTION", location, "family, coordinates, source map, or rows are invalid")
            dependency_ok = False
            continue
        contribution_families.setdefault(family_id, []).append(contribution)
        if len(contribution_families[family_id]) > 1:
            _issue(issues, "DUPLICATE_FAMILY", location, "more than one contribution owns the family")
        expected_consumer = expected_source_coordinate if expected_source_coordinate is not None else authority_consumer
        if consumer != expected_consumer:
            _issue(issues, "FOREIGN_SOURCE_COORDINATE", location + ".consumer_source_coordinate",
                   "contribution names a different consumer coordinate")
            dependency_ok = False
        dep_ok = _dependency(contribution["dependency_binding"], producer=producer, consumer=consumer,
                             location=location + ".dependency_binding", issues=issues)
        dependency_ok = dependency_ok and dep_ok
        expected_family = authority_families.get(family_id)
        if expected_family is not None:
            if producer != expected_family["producer_source_coordinate"]:
                _issue(issues, "FOREIGN_SOURCE_COORDINATE", location + ".producer_source_coordinate",
                       "contribution producer differs from the selected family producer")
                dependency_ok = False
            if contribution["source_map_digest"] != expected_family["source_map_digest"]:
                _issue(issues, "SOURCE_MAP_BINDING_MISMATCH", location + ".source_map_digest",
                       "contribution source map differs from family authority")
            if contribution["dependency_binding"] != expected_family["dependency_selection"]:
                _issue(issues, "DEPENDENCY_BINDING_MISMATCH", location + ".dependency_binding",
                       "contribution dependency binding differs from family selection")
                dependency_ok = False
        elif authority is not None:
            _issue(issues, "UNEXPECTED_FAMILY", location, "family is absent from selected authority")
        found = received_by_family.setdefault(family_id, set())
        for ridx, item in enumerate(contribution["rows"]):
            here = f"{location}.rows[{ridx}]"
            if not _keys(item, row_fields):
                _issue(issues, "INVALID_MEMBER", here, "member row has unsupported shape")
                continue
            if (not _source(item["source"]) or not _keys(item["claim"], {"text", "sha256"})
                    or not _text(item["claim"].get("text")) or not _hash(item["claim"].get("sha256"))
                    or text_digest(item["claim"]["text"]) != item["claim"]["sha256"]
                    or not _text(item["object_kind"]) or type(item["tier"]) is not int
                    or not 1 <= item["tier"] <= 9 or not _text(item["member_id"])):
                _issue(issues, "INVALID_MEMBER", here,
                       "member lacks exact source, claim, core object/tier, or identity")
                continue
            _mechanism(item["acceptance_mechanism"], here + ".acceptance_mechanism", issues)
            if not _text(item["uncovered_action"]):
                _issue(issues, "UNCOVERED_ACTION_REQUIRED", here, "every row needs an uncovered action")
            key = (item["object_kind"], item["tier"], item["member_id"])
            if key in global_members:
                _issue(issues, "DUPLICATE_MEMBER", here,
                       "object/tier/member is already owned by another row")
            else:
                global_members[key] = family_id
            found.add(key)
            requirement = expected_by_family.get(family_id, {}).get(key)
            if requirement is None and authority is not None:
                _issue(issues, "UNEXPECTED_MEMBER", here, "member is absent from selected family authority")
            elif requirement is not None:
                if item["source"] != requirement["source"]:
                    _issue(issues, "SOURCE_BINDING_MISMATCH", here + ".source",
                           "row source differs from selected requirement source")
                if item["claim"]["sha256"] != requirement["claim_sha256"]:
                    _issue(issues, "CLAIM_BINDING_MISMATCH", here + ".claim",
                           "row claim differs from selected requirement claim")
            _evidence(item["current_evidence"], row=item, producer=producer, consumer=consumer,
                      location=here + ".current_evidence", issues=issues, evidence_ids=evidence_ids)

    report["counts"]["received_families"] = len(contribution_families)
    report["counts"]["received_members"] = len(global_members)
    if authority is not None:
        for family_id, requirements in expected_by_family.items():
            docs = contribution_families.get(family_id, [])
            found = received_by_family.get(family_id, set())
            if not docs:
                _issue(issues, "MISSING_FAMILY", f"family:{family_id}", "required family contribution is absent")
            expected_tiers = {(key[0], key[1]) for key in requirements}
            found_tiers = {(key[0], key[1]) for key in found}
            for object_kind, tier in sorted(expected_tiers - found_tiers):
                _issue(issues, "MISSING_TIER", f"family:{family_id}/{object_kind}-{tier}",
                       "required object tier has no contributed member")
            for key in sorted(set(requirements) - found):
                _issue(issues, "MISSING_MEMBER", f"family:{family_id}/{key[2]}",
                       "required object/tier/member is absent")
    coverage_codes = {"MISSING_FAMILY", "MISSING_TIER", "MISSING_MEMBER", "UNEXPECTED_FAMILY",
                      "UNEXPECTED_MEMBER", "DUPLICATE_FAMILY", "DUPLICATE_MEMBER",
                      "OVERLAPPING_FAMILY_REQUIREMENT", "DUPLICATE_EXPECTED_MEMBER"}
    report["candidate_coverage"] = ("MATCHED" if authority is not None
                                    and not any(issue["code"] in coverage_codes for issue in issues)
                                    else "MISMATCH" if authority is not None else "UNKNOWN")
    if authority is not None:
        report["dependency_binding"] = "MATCHED" if dependency_ok else "MISMATCH"
    if not issues and authority_valid:
        report["structural_union"] = "PASS"
    report["issues"] = sorted(issues, key=lambda row: (row["code"], row["location"], row["detail"]))
    report["report_digest"] = value_digest(report)
    return report


def _normalized_hash(value: Any) -> str | None:
    if value is None:
        return None
    if type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value):
        value = "sha256:" + value
    if not _hash(value):
        raise ValueError("SHA-256 digest required")
    return value


def _json_document(raw: bytes, unavailable: str) -> Any:
    """Decode portable JSON without last-key-wins or non-finite extensions."""
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            if key in result:
                raise ValueError(unavailable)
            result[key] = value
        return result

    def non_finite(_: str) -> Any:
        raise ValueError(unavailable)

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs,
                          parse_constant=non_finite)
    except (UnicodeError, ValueError) as exc:
        raise ValueError(unavailable) from exc


def adapt_harness_candidate(candidate_bytes: bytes, *, consumer_source_coordinate: Any,
                            expected_package_digest: str | None,
                            expected_mechanism_digest: str | None) -> dict[str, Any]:
    """Project the private HARNESS candidate without granting completeness or authority."""
    if type(candidate_bytes) is not bytes or not candidate_bytes or len(candidate_bytes) > 8 * 1024 * 1024:
        raise ValueError("bounded candidate bytes required")
    if not _coordinate(consumer_source_coordinate):
        raise ValueError("consumer source coordinate required")
    candidate = _json_document(candidate_bytes, "candidate JSON unavailable")
    required = {"schema_version", "source_coordinate", "candidate_member_count",
                "claim_sources", "members", "completeness"}
    if type(candidate) is not dict or not required <= set(candidate) \
            or candidate["schema_version"] != HARNESS_CANDIDATE_SCHEMA \
            or not _coordinate(candidate["source_coordinate"]) \
            or type(candidate["members"]) is not list \
            or type(candidate["candidate_member_count"]) is not int \
            or candidate["candidate_member_count"] != len(candidate["members"]) \
            or type(candidate["claim_sources"]) is not dict:
        raise ValueError("unsupported HARNESS candidate")
    producer = candidate["source_coordinate"]
    package_digest = _normalized_hash(expected_package_digest)
    mechanism_digest = _normalized_hash(expected_mechanism_digest)
    dependency = {
        "status": "UNKNOWN",
        "producer_source_coordinate_digest": value_digest(producer),
        "consumer_source_coordinate_digest": value_digest(consumer_source_coordinate),
        "candidate_input_digest": bytes_digest(candidate_bytes),
        "package_digest": package_digest,
        "mechanism_digest": mechanism_digest,
    }
    rows = []
    for index, item in enumerate(candidate["members"]):
        fields = {"member_id", "claim", "claim_source", "object", "member_identity",
                  "acceptance_mechanism", "current_evidence", "uncovered_action"}
        if type(item) is not dict or not fields <= set(item):
            raise ValueError(f"unsupported HARNESS candidate member {index}")
        source_name = item["claim_source"].split("#", 1)[0]
        options = (source_name, "docs/" + source_name)
        selected_name = next((name for name in options if name in candidate["claim_sources"]), None)
        if selected_name is None:
            raise ValueError(f"claim source absent for HARNESS candidate member {index}")
        source_meta = candidate["claim_sources"][selected_name]
        if type(source_meta) is not dict or "sha256" not in source_meta:
            raise ValueError(f"claim source digest absent for HARNESS candidate member {index}")
        source_sha = _normalized_hash(source_meta["sha256"])
        obj = item["object"]
        mech = item["acceptance_mechanism"]
        current = item["current_evidence"]
        if (type(obj) is not dict or type(obj.get("tier")) is not int
                or not _text(obj.get("kind")) or not 1 <= obj["tier"] <= 9
                or type(mech) is not dict or not _text(mech.get("test"))
                or not _text(mech.get("node")) or not _text(mech.get("predicate"))
                or type(current) is not dict):
            raise ValueError(f"HARNESS candidate member binding invalid at {index}")
        rows.append({
            "source": {"uri": "candidate-source://" + selected_name, "sha256": source_sha},
            "claim": {"text": item["claim"], "sha256": text_digest(item["claim"])},
            "object_kind": obj["kind"],
            "tier": obj["tier"],
            "member_id": item["member_id"],
            "acceptance_mechanism": {
                "kind": "DECLARED_TEST",
                "identifier": mech["test"] + "::" + mech["node"],
            },
            "current_evidence": {"status": "UNKNOWN", "bindings": [], "reported": current},
            "uncovered_action": item["uncovered_action"],
        })
    return {
        "schema_version": CONTRIBUTION_SCHEMA,
        "candidate_status": "CANDIDATE",
        "completeness": "UNKNOWN",
        "producer_source_coordinate": producer,
        "consumer_source_coordinate": consumer_source_coordinate,
        "family_id": "HARNESS_CORE",
        "source_map_digest": bytes_digest(candidate_bytes),
        "dependency_binding": dependency,
        "rows": rows,
    }


def adapt_release_evidence_ledger(candidate_bytes: bytes, *, consumer_source_coordinate: Any,
                                  expected_package_digest: str | None,
                                  expected_mechanism_digest: str | None) -> list[dict[str, Any]]:
    """Project a source-registration ledger as candidate families with zero runtime credit."""
    if type(candidate_bytes) is not bytes or not candidate_bytes or len(candidate_bytes) > 16 * 1024 * 1024:
        raise ValueError("bounded release ledger bytes required")
    if not _coordinate(consumer_source_coordinate):
        raise ValueError("consumer source coordinate required")
    ledger = _json_document(candidate_bytes, "release ledger JSON unavailable")
    required = {"schema_version", "source_coordinate", "selection", "inventory", "rows",
                "source_bindings", "gap_summary"}
    if type(ledger) is not dict or not required <= set(ledger) \
            or ledger.get("schema_version") != RELEASE_EVIDENCE_SCHEMA \
            or not _coordinate(ledger.get("source_coordinate")) \
            or type(ledger.get("selection")) is not dict \
            or type(ledger.get("inventory")) is not dict \
            or type(ledger.get("rows")) is not list \
            or type(ledger.get("source_bindings")) is not dict:
        raise ValueError("unsupported release evidence ledger")
    selected = ledger["selection"].get("selected_slice")
    if type(selected) is not list or not selected or any(not _text(item) for item in selected) \
            or len(set(selected)) != len(selected):
        raise ValueError("selected family slice is invalid")
    inventory = ledger["inventory"]
    if inventory.get("registered_member_row_count") != len(ledger["rows"]):
        raise ValueError("release ledger row count does not bind supplied rows")
    if inventory.get("candidate_member_set_authenticates_completeness") is not False:
        raise ValueError("release ledger must disclaim completeness authority")
    producer = ledger["source_coordinate"]
    dependency = {
        "status": "UNKNOWN",
        "producer_source_coordinate_digest": value_digest(producer),
        "consumer_source_coordinate_digest": value_digest(consumer_source_coordinate),
        "candidate_input_digest": bytes_digest(candidate_bytes),
        "package_digest": _normalized_hash(expected_package_digest),
        "mechanism_digest": _normalized_hash(expected_mechanism_digest),
    }
    grouped: dict[str, list[dict[str, Any]]] = {kind: [] for kind in selected}
    identities: set[tuple[str, int, str]] = set()
    for index, item in enumerate(ledger["rows"]):
        required_row = {"source_claim", "object_tier", "member_identity",
                        "acceptance_mechanism", "current_evidence", "uncovered_action"}
        if type(item) is not dict or not required_row <= set(item):
            raise ValueError(f"unsupported release ledger row {index}")
        source_claim = item["source_claim"]
        object_tier = item["object_tier"]
        identity = item["member_identity"]
        mechanism = item["acceptance_mechanism"]
        current = item["current_evidence"]
        uncovered = item["uncovered_action"]
        if (type(source_claim) is not dict or not _text(source_claim.get("exact_claim"))
                or type(source_claim.get("normative_sources")) is not list
                or type(object_tier) is not dict or not _text(object_tier.get("object"))
                or type(object_tier.get("tier")) is not int or not 1 <= object_tier["tier"] <= 9
                or type(identity) is not dict or not _text(identity.get("coordinate"))
                or type(mechanism) is not dict or not _text(mechanism.get("checker_symbol"))
                or type(current) is not dict or type(uncovered) is not dict):
            raise ValueError(f"release ledger row binding invalid at {index}")
        object_kind = object_tier["object"]
        if object_kind not in grouped:
            raise ValueError(f"row {index} is outside selected family slice")
        key = (object_kind, object_tier["tier"], identity["coordinate"])
        if key in identities:
            raise ValueError(f"duplicate release ledger member at {index}")
        identities.add(key)
        source_path = None
        source_sha = None
        for source in source_claim["normative_sources"]:
            if type(source) is not dict or not _text(source.get("path")):
                continue
            binding = ledger["source_bindings"].get(source["path"])
            if type(binding) is dict and binding.get("exists") is True:
                try:
                    candidate_sha = _normalized_hash(binding.get("sha256"))
                except ValueError:
                    continue
                source_path, source_sha = source["path"], candidate_sha
                break
        if source_path is None or source_sha is None:
            raise ValueError(f"source binding unavailable for release ledger row {index}")
        uncovered_text = " ".join(
            str(uncovered[key]).strip() for key in ("member_evidence", "family_closure", "release_gate")
            if _text(uncovered.get(key))
        )
        if not uncovered_text:
            raise ValueError(f"uncovered action unavailable for release ledger row {index}")
        grouped[object_kind].append({
            "source": {"uri": "producer-source://" + source_path, "sha256": source_sha},
            "claim": {"text": source_claim["exact_claim"],
                      "sha256": text_digest(source_claim["exact_claim"])},
            "object_kind": object_kind,
            "tier": object_tier["tier"],
            "member_id": identity["coordinate"],
            "acceptance_mechanism": {"kind": "REGISTERED",
                                     "identifier": mechanism["checker_symbol"]},
            "current_evidence": {"status": "UNKNOWN", "bindings": [], "reported": current},
            "uncovered_action": uncovered_text,
        })
    missing = [kind for kind, rows in grouped.items() if not rows]
    if missing:
        raise ValueError("selected family has no release ledger rows: " + ",".join(missing))
    input_digest = bytes_digest(candidate_bytes)
    contributions = []
    for object_kind in selected:
        rows = grouped[object_kind]
        source_map_digest = value_digest({
            "candidate_input_digest": input_digest,
            "family_id": object_kind,
            "members": [[row["tier"], row["member_id"], row["source"]["sha256"],
                         row["claim"]["sha256"]] for row in rows],
        })
        contributions.append({
            "schema_version": CONTRIBUTION_SCHEMA,
            "candidate_status": "CANDIDATE",
            "completeness": "UNKNOWN",
            "producer_source_coordinate": producer,
            "consumer_source_coordinate": consumer_source_coordinate,
            "family_id": "VERIFIER_CURRENT_OBJECT:" + object_kind,
            "source_map_digest": source_map_digest,
            "dependency_binding": dict(dependency),
            "rows": rows,
        })
    return contributions


def adapt_core_family_slice(candidate_bytes: bytes, *, consumer_source_coordinate: Any,
                            expected_package_digest: str | None,
                            expected_mechanism_digest: str | None) -> list[dict[str, Any]]:
    """Project a static core-family review while retaining its unestablished closure."""
    if type(candidate_bytes) is not bytes or not candidate_bytes or len(candidate_bytes) > 16 * 1024 * 1024:
        raise ValueError("bounded core family slice bytes required")
    if not _coordinate(consumer_source_coordinate):
        raise ValueError("consumer source coordinate required")
    candidate = _json_document(candidate_bytes, "core family slice JSON unavailable")
    required = {"record_type", "status", "partition", "rows", "source_observations",
                "counterexample", "claim_limits"}
    if type(candidate) is not dict or not required <= set(candidate) \
            or candidate.get("record_type") != "v2_core_family_slice_read_only_review" \
            or candidate.get("status") != "ACTIVE_GAPS_FOUND_STATIC_EVIDENCE_ONLY" \
            or type(candidate.get("partition")) is not dict \
            or type(candidate.get("rows")) is not list \
            or not _coordinate(candidate.get("source_observations")):
        raise ValueError("unsupported core family slice")
    selection = candidate["partition"].get("selected_slice")
    if type(selection) is not list or not selection:
        raise ValueError("core family selection unavailable")
    selected = []
    for index, item in enumerate(selection):
        if type(item) is not dict or not _text(item.get("object")):
            raise ValueError(f"invalid selected family at {index}")
        selected.append(item["object"])
    if len(set(selected)) != len(selected):
        raise ValueError("selected family is duplicated")
    producer = candidate["source_observations"]
    dependency = {
        "status": "UNKNOWN",
        "producer_source_coordinate_digest": value_digest(producer),
        "consumer_source_coordinate_digest": value_digest(consumer_source_coordinate),
        "candidate_input_digest": bytes_digest(candidate_bytes),
        "package_digest": _normalized_hash(expected_package_digest),
        "mechanism_digest": _normalized_hash(expected_mechanism_digest),
    }
    grouped: dict[str, list[dict[str, Any]]] = {kind: [] for kind in selected}
    tiers: dict[str, set[int]] = {kind: set() for kind in selected}
    identities: set[tuple[str, int, str]] = set()
    for index, slot in enumerate(candidate["rows"]):
        if type(slot) is not dict or not {"exact_object_and_tier", "members", "current_evidence",
                                          "uncovered_action"} <= set(slot):
            raise ValueError(f"unsupported core family slot {index}")
        object_tier = slot["exact_object_and_tier"]
        members = slot["members"]
        uncovered = slot["uncovered_action"]
        if (type(object_tier) is not dict or not _text(object_tier.get("object"))
                or type(object_tier.get("tier")) is not int or not 1 <= object_tier["tier"] <= 9
                or type(members) is not list or not members or type(uncovered) is not dict):
            raise ValueError(f"core family slot binding invalid at {index}")
        object_kind, tier = object_tier["object"], object_tier["tier"]
        if object_kind not in grouped:
            raise ValueError(f"slot {index} is outside selected family slice")
        if tier in tiers[object_kind]:
            raise ValueError(f"duplicate selected tier at slot {index}")
        tiers[object_kind].add(tier)
        uncovered_text = " ".join(
            str(uncovered[key]).strip() for key in ("action", "candidate_boundary", "prohibited_inference")
            if _text(uncovered.get(key))
        )
        if not uncovered_text:
            raise ValueError(f"uncovered action unavailable for core family slot {index}")
        for member_index, member in enumerate(members):
            if type(member) is not dict or not {"identity", "source_claim", "acceptance_mechanism",
                                                "current_evidence"} <= set(member):
                raise ValueError(f"unsupported member at slot {index}/{member_index}")
            identity = member["identity"]
            source_claim = member["source_claim"]
            mechanism = member["acceptance_mechanism"]
            current = member["current_evidence"]
            if (type(identity) is not dict or not _text(identity.get("coordinate"))
                    or type(source_claim) is not dict or not _text(source_claim.get("exact_claim"))
                    or type(source_claim.get("normative_sources_named_by_checker")) is not list
                    or type(mechanism) is not dict or not _text(mechanism.get("recheck_function"))
                    or type(current) is not dict):
                raise ValueError(f"core family member binding invalid at {index}/{member_index}")
            source = next((value for value in source_claim["normative_sources_named_by_checker"]
                           if type(value) is dict and _text(value.get("path"))
                           and _normalized_hash(value.get("sha256"))), None)
            if source is None:
                raise ValueError(f"source binding unavailable for core family member {index}/{member_index}")
            member_id = identity["coordinate"]
            key = (object_kind, tier, member_id)
            if key in identities:
                raise ValueError(f"duplicate core family member at {index}/{member_index}")
            identities.add(key)
            grouped[object_kind].append({
                "source": {"uri": "producer-source://" + source["path"],
                           "sha256": _normalized_hash(source["sha256"])},
                "claim": {"text": source_claim["exact_claim"],
                          "sha256": text_digest(source_claim["exact_claim"])},
                "object_kind": object_kind,
                "tier": tier,
                "member_id": member_id,
                "acceptance_mechanism": {"kind": "REGISTERED",
                                         "identifier": mechanism["recheck_function"]},
                "current_evidence": {"status": "UNKNOWN", "bindings": [], "reported": current},
                "uncovered_action": uncovered_text,
            })
    missing = {kind: sorted(set(range(1, 10)) - tiers[kind]) for kind in selected
               if tiers[kind] != set(range(1, 10))}
    if missing:
        raise ValueError("selected family tier coverage is incomplete: " + repr(missing))
    reported_count = candidate["counterexample"].get("registered_member_identities") \
        if type(candidate["counterexample"]) is dict else None
    if reported_count != len(identities):
        raise ValueError("core family member count does not bind supplied rows")
    input_digest = bytes_digest(candidate_bytes)
    contributions = []
    for object_kind in selected:
        rows = grouped[object_kind]
        contributions.append({
            "schema_version": CONTRIBUTION_SCHEMA,
            "candidate_status": "CANDIDATE",
            "completeness": "UNKNOWN",
            "producer_source_coordinate": producer,
            "consumer_source_coordinate": consumer_source_coordinate,
            "family_id": "VERIFIER_CURRENT_OBJECT:" + object_kind,
            "source_map_digest": value_digest({
                "candidate_input_digest": input_digest,
                "family_id": object_kind,
                "members": [[row["tier"], row["member_id"], row["source"]["sha256"],
                             row["claim"]["sha256"]] for row in rows],
            }),
            "dependency_binding": dict(dependency),
            "rows": rows,
        })
    return contributions


def adapt_selected_family_matrix(candidate_bytes: bytes, *, consumer_source_coordinate: Any,
                                 expected_package_digest: str | None,
                                 expected_mechanism_digest: str | None) -> list[dict[str, Any]]:
    """Project a selected-family matrix without promoting registration to evidence credit."""
    if type(candidate_bytes) is not bytes or not candidate_bytes or len(candidate_bytes) > 16 * 1024 * 1024:
        raise ValueError("bounded selected family matrix bytes required")
    if not _coordinate(consumer_source_coordinate):
        raise ValueError("consumer source coordinate required")
    matrix = _json_document(candidate_bytes, "selected family matrix JSON unavailable")
    required = {"schema", "generated_from", "owned_object_kinds", "rows"}
    if type(matrix) is not dict or not required <= set(matrix) \
            or matrix.get("schema") != "verifier-v2-selected-family-obligation-matrix-1" \
            or not _coordinate(matrix.get("generated_from")) \
            or type(matrix.get("owned_object_kinds")) is not list \
            or type(matrix.get("rows")) is not list:
        raise ValueError("unsupported selected family matrix")
    selected = matrix["owned_object_kinds"]
    if not selected or any(not _text(item) for item in selected) or len(set(selected)) != len(selected):
        raise ValueError("owned family selection is invalid")
    producer = matrix["generated_from"]
    source_hashes = producer.get("source_file_sha256")
    if type(source_hashes) is not dict:
        raise ValueError("source hash map is unavailable")
    dependency = {
        "status": "UNKNOWN",
        "producer_source_coordinate_digest": value_digest(producer),
        "consumer_source_coordinate_digest": value_digest(consumer_source_coordinate),
        "candidate_input_digest": bytes_digest(candidate_bytes),
        "package_digest": _normalized_hash(expected_package_digest),
        "mechanism_digest": _normalized_hash(expected_mechanism_digest),
    }
    grouped: dict[str, list[dict[str, Any]]] = {kind: [] for kind in selected}
    tiers: dict[str, set[int]] = {kind: set() for kind in selected}
    identities: set[tuple[str, int, str]] = set()
    for index, slot in enumerate(matrix["rows"]):
        required_slot = {"object_kind", "tier", "source_files", "claim", "member_identities",
                         "acceptance_mechanism", "current_evidence", "uncovered_action"}
        if type(slot) is not dict or not required_slot <= set(slot):
            raise ValueError(f"unsupported selected family row {index}")
        object_kind, tier = slot["object_kind"], slot["tier"]
        if (object_kind not in grouped or type(tier) is not int or not 1 <= tier <= 9
                or type(slot["source_files"]) is not list or not _text(slot["claim"])
                or type(slot["member_identities"]) is not list or not slot["member_identities"]
                or not _text(slot["acceptance_mechanism"])
                or not _text(slot["current_evidence"]) or not _text(slot["uncovered_action"])):
            raise ValueError(f"selected family row binding invalid at {index}")
        if tier in tiers[object_kind]:
            raise ValueError(f"duplicate selected family tier at {index}")
        tiers[object_kind].add(tier)
        source_path = next((path for path in slot["source_files"]
                            if _text(path) and path in source_hashes), None)
        if source_path is None:
            raise ValueError(f"source binding unavailable for selected family row {index}")
        source_sha = _normalized_hash(source_hashes[source_path])
        for member_index, identity in enumerate(slot["member_identities"]):
            if (type(identity) is not dict or not _text(identity.get("objective"))
                    or not _text(identity.get("certificate_schema_version"))
                    or identity.get("object_profile_conformance") != "NOT_ESTABLISHED"):
                raise ValueError(f"selected member binding invalid at {index}/{member_index}")
            member_id = identity["objective"]
            key = (object_kind, tier, member_id)
            if key in identities:
                raise ValueError(f"duplicate selected family member at {index}/{member_index}")
            identities.add(key)
            grouped[object_kind].append({
                "source": {"uri": "producer-source://" + source_path, "sha256": source_sha},
                "claim": {"text": slot["claim"], "sha256": text_digest(slot["claim"])},
                "object_kind": object_kind,
                "tier": tier,
                "member_id": member_id,
                "acceptance_mechanism": {
                    "kind": "REGISTERED",
                    "identifier": member_id + "|" + identity["certificate_schema_version"],
                },
                "current_evidence": {
                    "status": "UNKNOWN",
                    "bindings": [],
                    "reported": {"slot": slot["current_evidence"],
                                 "member_identity": identity,
                                 "mechanism": slot["acceptance_mechanism"]},
                },
                "uncovered_action": slot["uncovered_action"],
            })
    missing = {kind: sorted(set(range(1, 10)) - tiers[kind]) for kind in selected
               if tiers[kind] != set(range(1, 10))}
    if missing:
        raise ValueError("selected family tier coverage is incomplete: " + repr(missing))
    input_digest = bytes_digest(candidate_bytes)
    contributions = []
    for object_kind in selected:
        rows = grouped[object_kind]
        contributions.append({
            "schema_version": CONTRIBUTION_SCHEMA,
            "candidate_status": "CANDIDATE",
            "completeness": "UNKNOWN",
            "producer_source_coordinate": producer,
            "consumer_source_coordinate": consumer_source_coordinate,
            "family_id": "VERIFIER_CURRENT_OBJECT:" + object_kind,
            "source_map_digest": value_digest({
                "candidate_input_digest": input_digest,
                "family_id": object_kind,
                "members": [[row["tier"], row["member_id"], row["source"]["sha256"],
                             row["claim"]["sha256"]] for row in rows],
            }),
            "dependency_binding": dict(dependency),
            "rows": rows,
        })
    return contributions


def adapt_interaction_map(candidate_bytes: bytes, *, consumer_source_coordinate: Any,
                          expected_package_digest: str | None,
                          expected_mechanism_digest: str | None) -> list[dict[str, Any]]:
    """Project DATA/RECEIPT/GRAPH registrations without inventing application instances."""
    if type(candidate_bytes) is not bytes or not candidate_bytes or len(candidate_bytes) > 16 * 1024 * 1024:
        raise ValueError("bounded interaction map bytes required")
    if not _coordinate(consumer_source_coordinate):
        raise ValueError("consumer source coordinate required")
    candidate = _json_document(candidate_bytes, "interaction map JSON unavailable")
    required = {"schema_version", "status", "claim_boundary", "counts", "slot_rows",
                "registered_candidate_member_rows", "source_binding", "source_snapshot"}
    if type(candidate) is not dict or not required <= set(candidate) \
            or candidate.get("schema_version") != "reviewer-b-core-obligation-interaction-map-1" \
            or candidate.get("status") != "SOURCE_BOUND_MAP_COMPLETE; FULL_APPLICATION_AND_RELEASE_ADMISSION_UNKNOWN":
        raise ValueError("unsupported interaction map")
    boundary, counts = candidate["claim_boundary"], candidate["counts"]
    if (type(boundary) is not dict or boundary.get("candidate_registry_completeness") != "NOT_AUTHENTICATED"
            or boundary.get("full_current_application") != "UNKNOWN"
            or type(counts) is not dict or counts.get("actual_instantiated_source_requirements") != 0):
        raise ValueError("interaction map overclaims application authority")
    kinds = ["DATA", "RECEIPT", "GRAPH"]
    slots = candidate["slot_rows"]
    member_rows = candidate["registered_candidate_member_rows"]
    if type(slots) is not list or counts.get("slot_rows") != len(slots) \
            or type(member_rows) is not list \
            or counts.get("registered_candidate_member_rows") != len(member_rows):
        raise ValueError("interaction map row count mismatch")
    tier_sets = {kind: set() for kind in kinds}
    for index, slot in enumerate(slots):
        if (type(slot) is not dict or slot.get("object_kind") not in tier_sets
                or type(slot.get("tier")) is not int or not 1 <= slot["tier"] <= 9):
            raise ValueError(f"invalid interaction slot {index}")
        if slot.get("full_family_closure") != "UNKNOWN" or slot.get("full_family_members") is not None:
            raise ValueError(f"interaction slot closure must remain UNKNOWN at {index}")
        if slot["tier"] in tier_sets[slot["object_kind"]]:
            raise ValueError(f"duplicate interaction tier at {index}")
        tier_sets[slot["object_kind"]].add(slot["tier"])
    missing = {kind: sorted(set(range(1, 10)) - tiers) for kind, tiers in tier_sets.items()
               if tiers != set(range(1, 10))}
    if missing:
        raise ValueError("interaction tier coverage is incomplete: " + repr(missing))
    snapshot = candidate["source_snapshot"]
    binding = candidate["source_binding"]
    if type(snapshot) is not dict or type(binding) is not dict \
            or not _hash(_normalized_hash(snapshot.get("manifest_digest"))) \
            or not _coordinate(binding.get("retained_source_coordinate")):
        raise ValueError("interaction source coordinate is invalid")
    for index, item in enumerate(snapshot.get("files", [])):
        if type(item) is not dict or item.get("exists") is not True \
                or item.get("matches_retained_source_coordinate") is not True \
                or not _text(item.get("path")) or not _hash(_normalized_hash(item.get("sha256"))):
            raise ValueError(f"interaction source snapshot mismatch at {index}")
    producer = {
        "retained_source_coordinate": binding["retained_source_coordinate"],
        "source_root": binding.get("source_root"),
        "direct_git_metadata": binding.get("direct_git_metadata"),
        "source_snapshot_manifest_digest": _normalized_hash(snapshot["manifest_digest"]),
    }
    dependency = {
        "status": "UNKNOWN",
        "producer_source_coordinate_digest": value_digest(producer),
        "consumer_source_coordinate_digest": value_digest(consumer_source_coordinate),
        "candidate_input_digest": bytes_digest(candidate_bytes),
        "package_digest": _normalized_hash(expected_package_digest),
        "mechanism_digest": _normalized_hash(expected_mechanism_digest),
    }
    grouped: dict[str, list[dict[str, Any]]] = {kind: [] for kind in kinds}
    identities: set[tuple[str, int, str]] = set()
    for index, item in enumerate(member_rows):
        required_row = {"object_kind", "tier", "member_identity", "membership_status",
                        "source_claim", "acceptance_mechanism", "current_evidence",
                        "uncovered_action"}
        if type(item) is not dict or not required_row <= set(item):
            raise ValueError(f"unsupported interaction member {index}")
        kind, tier = item["object_kind"], item["tier"]
        identity, claim = item["member_identity"], item["source_claim"]
        mechanism, current = item["acceptance_mechanism"], item["current_evidence"]
        if (kind not in grouped or type(tier) is not int or not 1 <= tier <= 9
                or type(identity) is not dict or not _text(identity.get("coordinate"))
                or type(claim) is not dict or not _text(claim.get("exact_claim"))
                or type(claim.get("specification")) is not dict
                or type(mechanism) is not dict or not _text(mechanism.get("checker"))
                or type(current) is not dict or not _text(item["uncovered_action"])):
            raise ValueError(f"interaction member binding invalid at {index}")
        source = claim["specification"]
        if source.get("exists") is not True or not _text(source.get("path")) \
                or not _hash(_normalized_hash(source.get("sha256"))):
            raise ValueError(f"interaction source binding unavailable at {index}")
        member_id = identity["coordinate"]
        key = (kind, tier, member_id)
        if key in identities:
            raise ValueError(f"duplicate interaction member at {index}")
        identities.add(key)
        grouped[kind].append({
            "source": {"uri": "producer-source://" + source["path"],
                       "sha256": _normalized_hash(source["sha256"])},
            "claim": {"text": claim["exact_claim"], "sha256": text_digest(claim["exact_claim"])},
            "object_kind": kind,
            "tier": tier,
            "member_id": member_id,
            "acceptance_mechanism": {"kind": "REGISTERED", "identifier": mechanism["checker"]},
            "current_evidence": {"status": "UNKNOWN", "bindings": [],
                                 "reported": {"member_identity": identity,
                                              "membership_status": item["membership_status"],
                                              "current_evidence": current}},
            "uncovered_action": item["uncovered_action"],
        })
    by_kind = counts.get("candidate_by_kind")
    if type(by_kind) is not dict or any(by_kind.get(kind) != len(grouped[kind]) for kind in kinds):
        raise ValueError("interaction per-kind count mismatch")
    input_digest = bytes_digest(candidate_bytes)
    return [{
        "schema_version": CONTRIBUTION_SCHEMA,
        "candidate_status": "CANDIDATE",
        "completeness": "UNKNOWN",
        "producer_source_coordinate": producer,
        "consumer_source_coordinate": consumer_source_coordinate,
        "family_id": "VERIFIER_CURRENT_OBJECT:" + kind,
        "source_map_digest": value_digest({
            "candidate_input_digest": input_digest,
            "family_id": kind,
            "members": [[row["tier"], row["member_id"], row["source"]["sha256"],
                         row["claim"]["sha256"]] for row in grouped[kind]],
        }),
        "dependency_binding": dict(dependency),
        "rows": grouped[kind],
    } for kind in kinds]


def adapt_model_train_bundle(census_bytes: bytes, reconciliation_bytes: bytes,
                             public_release_bytes: bytes, sealed_manifest_bytes: bytes, *,
                             consumer_source_coordinate: Any,
                             expected_package_digest: str | None,
                             expected_mechanism_digest: str | None) -> dict[str, Any]:
    """Project MODEL/TRAIN legacy and current identities without collapsing reused names."""
    raw = {
        "CENSUS.json": census_bytes,
        "RECONCILIATION.json": reconciliation_bytes,
        "PUBLIC-RELEASE-OBLIGATIONS.json": public_release_bytes,
    }
    if not _coordinate(consumer_source_coordinate) or any(
            type(value) is not bytes or not value or len(value) > 16 * 1024 * 1024
            for value in [*raw.values(), sealed_manifest_bytes]):
        raise ValueError("bounded MODEL/TRAIN bundle and consumer coordinate required")
    sealed = _json_document(sealed_manifest_bytes, "sealed manifest JSON unavailable")
    if (type(sealed) is not dict
            or sealed.get("schema_version") != "private-verifier-core-v2-census-sealed-manifest-1"
            or sealed.get("outcome") != "NOT_READY" or type(sealed.get("members")) is not list
            or sealed.get("member_count") != len(sealed["members"])):
        raise ValueError("unsupported sealed manifest")
    manifest_members = {item.get("path"): item for item in sealed["members"] if type(item) is dict}
    for name, value in raw.items():
        member = manifest_members.get(name)
        if (type(member) is not dict or member.get("sha256") != sha256(value).hexdigest()
                or member.get("bytes") != len(value)):
            raise ValueError(f"sealed manifest mismatch for {name}")
    census = _json_document(census_bytes, "MODEL/TRAIN bundle JSON unavailable")
    reconciliation = _json_document(reconciliation_bytes,
                                    "MODEL/TRAIN bundle JSON unavailable")
    public = _json_document(public_release_bytes, "MODEL/TRAIN bundle JSON unavailable")
    if (type(census) is not dict
            or census.get("schema_version") != "private-verifier-core-v2-model-train-tier-census-1"
            or census.get("candidate_completeness_claim") != "NONE"
            or census.get("normative_inventory_completeness") != "NOT_ESTABLISHED"
            or census.get("required_subject_instance_denominator") != "UNKNOWN"
            or type(census.get("rows")) is not list or census.get("row_count") != len(census["rows"])):
        raise ValueError("unsupported MODEL/TRAIN census")
    tier_sets = {"MODEL": set(), "TRAIN": set()}
    for index, item in enumerate(census["rows"]):
        exact = item.get("exact_object_tier") if type(item) is dict else None
        current = item.get("current_evidence") if type(item) is dict else None
        if (type(exact) is not dict or exact.get("kind") not in tier_sets
                or type(exact.get("tier")) is not int or not 1 <= exact["tier"] <= 9
                or type(current) is not dict or current.get("tier_closure") != "NOT_ESTABLISHED"):
            raise ValueError(f"invalid MODEL/TRAIN census row {index}")
        if exact["tier"] in tier_sets[exact["kind"]]:
            raise ValueError(f"duplicate MODEL/TRAIN tier {index}")
        tier_sets[exact["kind"]].add(exact["tier"])
    if any(tiers != set(range(1, 10)) for tiers in tier_sets.values()):
        raise ValueError("MODEL/TRAIN tier coverage is incomplete")
    if (type(reconciliation) is not dict
            or reconciliation.get("schema_version") != "private-verifier-core-v2-model-train-obligation-reconciliation-1"
            or "not aliases" not in str(reconciliation.get("coordinate_reuse_rule", ""))
            or type(reconciliation.get("legacy_original_obligations")) is not list
            or type(reconciliation.get("registered_current_objectives")) is not list
            or reconciliation.get("legacy_original_obligation_count") != len(reconciliation["legacy_original_obligations"])
            or reconciliation.get("registered_current_objective_count") != len(reconciliation["registered_current_objectives"])):
        raise ValueError("MODEL/TRAIN coordinates must remain nonaliases with bound row counts")
    if (type(public) is not dict
            or public.get("schema_version") != "private-verifier-core-v2-public-release-obligations-1"
            or public.get("overall") != "NOT_READY" or type(public.get("rows")) is not list
            or public.get("row_count") != len(public["rows"])):
        raise ValueError("unsupported public release obligation bundle")
    input_hashes = {name: bytes_digest(value) for name, value in raw.items()}
    input_hashes["SEALED-MANIFEST.json"] = bytes_digest(sealed_manifest_bytes)
    bundle_digest = value_digest(input_hashes)
    producer = {
        "source_coordinate": sealed.get("source_coordinate"),
        "source_head": sealed.get("source_head"),
        "sealed_manifest_digest": bytes_digest(sealed_manifest_bytes),
        "bundle_member_digests": input_hashes,
    }
    dependency = {
        "status": "UNKNOWN",
        "producer_source_coordinate_digest": value_digest(producer),
        "consumer_source_coordinate_digest": value_digest(consumer_source_coordinate),
        "candidate_input_digest": bundle_digest,
        "package_digest": _normalized_hash(expected_package_digest),
        "mechanism_digest": _normalized_hash(expected_mechanism_digest),
    }
    grouped: dict[str, list[dict[str, Any]]] = {"MODEL": [], "TRAIN": []}
    identities: set[tuple[str, int, str]] = set()
    sources = [
        ("legacy-domain-catalogue", reconciliation["legacy_original_obligations"], False),
        ("verifier-current-object-obligations-1", reconciliation["registered_current_objectives"], True),
    ]
    for default_family, rows, registered in sources:
        for index, item in enumerate(rows):
            required_row = {"exact_object_tier", "member_identity", "source_claim",
                            "acceptance_mechanism", "current_evidence", "uncovered_action"}
            if type(item) is not dict or not required_row <= set(item):
                raise ValueError(f"unsupported {default_family} row {index}")
            exact, identity, source_claim = item["exact_object_tier"], item["member_identity"], item["source_claim"]
            if (type(exact) is not dict or exact.get("kind") not in grouped
                    or type(exact.get("tier")) is not int or not 1 <= exact["tier"] <= 9
                    or type(identity) is not dict or not _text(identity.get("coordinate"))
                    or type(source_claim) is not dict or not _text(source_claim.get("claim"))
                    or type(source_claim.get("source")) is not dict
                    or type(item["current_evidence"]) is not dict):
                raise ValueError(f"invalid {default_family} row {index}")
            semantic_family = exact.get("semantic_version") if registered else exact.get("semantic_family")
            if semantic_family != default_family:
                raise ValueError(f"semantic family mismatch at {default_family}/{index}")
            source = source_claim["source"]
            if not _text(source.get("path")) or not _hash(_normalized_hash(source.get("sha256"))):
                raise ValueError(f"source binding unavailable at {default_family}/{index}")
            coordinate = identity["coordinate"]
            member_id = semantic_family + "::" + coordinate
            key = (exact["kind"], exact["tier"], member_id)
            if key in identities:
                raise ValueError(f"duplicate MODEL/TRAIN member at {default_family}/{index}")
            identities.add(key)
            action = item["uncovered_action"]
            action_text = " ".join(action) if type(action) is list else action
            if not _text(action_text):
                raise ValueError(f"uncovered action unavailable at {default_family}/{index}")
            if registered:
                schema = identity.get("certificate_schema_version")
                if not _text(schema):
                    raise ValueError(f"current certificate schema unavailable at {index}")
                mechanism = {"kind": "REGISTERED", "identifier": coordinate + "|" + schema}
            else:
                mechanism = {"kind": "UNKNOWN", "identifier": None}
            grouped[exact["kind"]].append({
                "source": {"uri": "producer-source://" + source["path"],
                           "sha256": _normalized_hash(source["sha256"])},
                "claim": {"text": source_claim["claim"],
                          "sha256": text_digest(source_claim["claim"])},
                "object_kind": exact["kind"],
                "tier": exact["tier"],
                "member_id": member_id,
                "acceptance_mechanism": mechanism,
                "current_evidence": {
                    "status": "UNKNOWN", "bindings": [],
                    "reported": {"semantic_family": semantic_family,
                                 "original_member_identity": identity,
                                 "source_current_evidence": item["current_evidence"],
                                 "source_acceptance_mechanism": item["acceptance_mechanism"]},
                },
                "uncovered_action": action_text,
            })
    if any({row["tier"] for row in grouped[kind]} != set(range(1, 10)) for kind in grouped):
        raise ValueError("MODEL/TRAIN reconciliation tier coverage is incomplete")
    contributions = []
    for kind in ["MODEL", "TRAIN"]:
        rows = grouped[kind]
        contributions.append({
            "schema_version": CONTRIBUTION_SCHEMA,
            "candidate_status": "CANDIDATE",
            "completeness": "UNKNOWN",
            "producer_source_coordinate": producer,
            "consumer_source_coordinate": consumer_source_coordinate,
            "family_id": "VERIFIER_CURRENT_OBJECT:" + kind,
            "source_map_digest": value_digest({
                "candidate_input_digest": bundle_digest,
                "family_id": kind,
                "members": [[row["tier"], row["member_id"], row["source"]["sha256"],
                             row["claim"]["sha256"]] for row in rows],
            }),
            "dependency_binding": dict(dependency),
            "rows": rows,
        })
    return {
        "contributions": contributions,
        "release_obligations": public,
        "bundle_metadata": {
            "candidate_status": "CANDIDATE",
            "completeness": "UNKNOWN",
            "bundle_digest": bundle_digest,
            "census_tier_rows": len(census["rows"]),
            "legacy_obligations": len(reconciliation["legacy_original_obligations"]),
            "current_objectives": len(reconciliation["registered_current_objectives"]),
            "public_release_obligations": len(public["rows"]),
        },
    }


__all__ = [
    "AUTHORITY_SCHEMA", "CONTRIBUTION_SCHEMA", "REPORT_SCHEMA", "RELEASE_EVIDENCE_SCHEMA",
    "adapt_core_family_slice", "adapt_harness_candidate", "adapt_release_evidence_ledger",
    "adapt_interaction_map", "adapt_model_train_bundle", "adapt_selected_family_matrix",
    "bytes_digest", "canonical_bytes", "text_digest",
    "validate_union", "value_digest",
]
