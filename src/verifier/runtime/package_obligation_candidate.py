"""Fail-closed binding of candidate obligation cards to installed routes.

The selected cards are evidence about a proposed classification and mechanism
assessment.  Mechanical validity does not make those proposals normative and
does not establish any obligation instance as passing or failing.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
Verifier Standard (VSTD).
"""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re
from typing import Any, Iterable

from verifier.core.namespace import ObjectKind
from verifier.domains import inventory as domain_inventory
from verifier.runtime import core_obligation_union


SELECTION_SCHEMA = "verifier-package-obligation-candidate-selection-1"
MAX_CARD_BYTES = 1 << 20
MAX_TOTAL_CARD_BYTES = 16 << 20
MAX_MANIFEST_BYTES = 1 << 20
MAX_REASON_LEDGER_BYTES = 4 << 20
REASON_LEDGER_SCHEMA = "verifier-obligation-reason-ledger-1"

_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_MANIFEST_ROW = re.compile(
    r"(?P<digest>[0-9a-f]{64})  out/cards/(?P<kind>[A-Z]+)\.json\Z"
)
_OBJECTIVE = re.compile(r"(?P<kind>[A-Z]+)-(?P<tier>[1-9])\.[0-9]+\Z")
_FACET = re.compile(r"(?P<kind>[A-Z]+)\.F[1-9][0-9]*\Z")
_CARD_FIELDS = {
    "definition", "facet_coverage", "facets", "findings", "kind",
    "obligation_map", "questions",
}
_OBLIGATION_FIELDS = {
    "objective", "tier", "serves", "role", "rev3_class", "rev4_class",
    "rev4_condition", "mechanism", "reason_verdict", "failed_tests",
    "reason_rewrite", "note",
}
_FACET_FIELDS = {
    "id", "name", "defined", "reason", "class", "condition", "basis",
    "quote_ref", "contained_kind",
}
_FINDING_FIELDS = {"id", "type", "text", "refs", "evidence"}
_FINDING_EVIDENCE_REQUIRED_FIELDS = {"at", "says"}
_FINDING_EVIDENCE_OPTIONAL_FIELDS = {"how"}
_FINDING_TYPES = {
    "conflict", "definition", "gap", "mechanism", "orphan",
    "reason_defect", "slot",
}
_FACET_COVERAGE_FIELDS = {"facet", "objectives", "mechanism", "note"}
_ROW_CONDITION_FIELDS = {
    "type", "required_when", "not_required_because", "if_silent", "decided_by",
}
_FACET_CONDITION_FIELDS = {
    "type", "required_when", "not_required_because", "if_silent",
}
_REASON_LEDGER_FIELDS = {
    "schema_version", "authored", "rule", "objectives", "slots",
}
_REASON_ROW_REQUIRED_FIELDS = {
    "reason", "reason_source", "disposition", "author", "bound_digest",
    "repository_realization",
}
_REASON_ROW_OPTIONAL_FIELDS = {"proposed_reason"}
_REALIZATION_FIELDS = {
    "class", "explanation", "adaptation_necessity",
    "obligation_semantic_digest", "discovered_surface_ids",
    "mechanism_bindings", "evidence_requirements", "preserved_semantics",
    "unpreserved_semantics", "residual_obligations", "falsifiers",
    "decision_authority",
}
_MECHANISM_BINDING_FIELDS = {
    "checking_mechanism", "source_path", "source_digest", "symbol",
}
_REALIZATION_CLASSES = {
    "DIRECT", "SPECIALIZATION", "TRANSLATION", "CONDITIONAL",
    "NOT_APPLICABLE", "UNREALIZED",
}
_ADAPTATION_CLASSES = {"SPECIALIZATION", "TRANSLATION", "CONDITIONAL"}
_CLASSES = {"NECESSARY", "CONDITIONALLY_NECESSARY", "REASON_PENDING"}
_FACET_CLASSES = {"NECESSARY", "CONDITIONALLY_NECESSARY"}
_FACET_BASES = {"DOCUMENTED", "USER-STATED", "INFERRED"}
_MECHANISMS = {
    "BOUNDED", "COVERS", "DEFECTIVE", "NOT_ASSESSED", "PARTIAL", "UNSOUND",
}
_REASON_VERDICTS = {"ADEQUATE", "REWRITE"}
_ROLES = {"cross-cutting", "facet", "orphan"}
_CROSS_KIND_DECISIONS = (
    ("CTC-1", "triage method and candidate dispositions", "ALL_CORE"),
    ("CTC-2", "consent stages and tier-7 root holder", "TIER_7"),
    ("CTC-3", "reason-pending gate and absent reasons", "REASON_GAPS"),
    ("CTC-4", "corrigibility code set and grader integrity", "CORRIGIBILITY"),
    ("CTC-5", "generic record choices in tier zero or facets", "TIER_0_AND_1"),
    ("CTC-6", "MODEL data relation and card questions", "MODEL_AND_QUESTIONS"),
)


class CandidateLedgerError(ValueError):
    """A stable fail-closed candidate selection error."""


class CandidateLedgerUnavailable(OSError):
    """Selected external candidate bytes could not be observed."""


def _require(condition: bool, code: str) -> None:
    if not condition:
        raise CandidateLedgerError(code)


def _unique_object(pairs: Iterable[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CandidateLedgerError("PACKAGE_CANDIDATE_JSON_DUPLICATE_KEY")
        result[key] = value
    return result


def _strict_json(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(
                CandidateLedgerError("PACKAGE_CANDIDATE_JSON_NONFINITE")
            ),
        )
    except CandidateLedgerError:
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise CandidateLedgerError("PACKAGE_CANDIDATE_JSON_INVALID") from exc
    _require(type(value) is dict, "PACKAGE_CANDIDATE_CARD_NOT_OBJECT")
    return value


def _read_bounded(path: Path, *, maximum: int, code: str) -> bytes:
    try:
        if path.is_symlink():
            raise CandidateLedgerError(code)
        if not path.is_file():
            raise CandidateLedgerUnavailable(code)
        size = path.stat().st_size
    except CandidateLedgerError:
        raise
    except CandidateLedgerUnavailable:
        raise
    except OSError as exc:
        raise CandidateLedgerUnavailable(code) from exc
    _require(0 < size <= maximum, code)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise CandidateLedgerUnavailable(code) from exc
    _require(len(raw) == size, code)
    return raw


def _installed_routes(inventory: dict[str, Any]) -> dict[tuple[str, str], dict[str, Any]]:
    _require(type(inventory) is dict, "PACKAGE_CANDIDATE_INVENTORY_INVALID")
    _require(inventory.get("status") == "PASS",
             "PACKAGE_CANDIDATE_INVENTORY_NOT_PASS")
    cells = inventory.get("family_cells")
    _require(type(cells) is list, "PACKAGE_CANDIDATE_INVENTORY_INVALID")
    routes: dict[tuple[str, str], dict[str, Any]] = {}
    for cell in cells:
        _require(type(cell) is dict, "PACKAGE_CANDIDATE_INVENTORY_INVALID")
        kind = cell.get("object_kind")
        tier = cell.get("tier")
        memberships = cell.get("registered_route_memberships")
        _require(type(kind) is str and type(tier) is int
                 and type(memberships) is list,
                 "PACKAGE_CANDIDATE_INVENTORY_INVALID")
        for route in memberships:
            _require(type(route) is dict and type(route.get("coordinate")) is str,
                     "PACKAGE_CANDIDATE_INVENTORY_INVALID")
            key = kind, route["coordinate"]
            _require(key not in routes,
                     "PACKAGE_CANDIDATE_INVENTORY_DUPLICATE_ROUTE")
            routes[key] = {**route, "object_kind": kind, "tier": tier}
    _require(len(routes) == inventory.get("registered_route_membership_count"),
             "PACKAGE_CANDIDATE_INVENTORY_COUNT_DIFFERS")
    return routes


def _selected_source_root(source_root: str | Path | None) -> Path:
    candidate = (
        Path(source_root) if source_root is not None
        else Path(__file__).resolve().parents[2]
    )
    try:
        resolved = candidate.resolve(strict=True)
    except OSError as exc:
        raise CandidateLedgerUnavailable(
            "PACKAGE_REASON_LEDGER_SOURCE_ROOT_UNAVAILABLE"
        ) from exc
    if not resolved.is_dir():
        raise CandidateLedgerUnavailable(
            "PACKAGE_REASON_LEDGER_SOURCE_ROOT_UNAVAILABLE"
        )
    return resolved


def _checking_mechanism_binding(
        coordinate: str, *, source_root: str | Path | None = None,
        ) -> dict[str, str]:
    binding = domain_inventory.MECHANIZED_12_POINT_BINDINGS.get(coordinate)
    _require(type(binding) is dict,
             "PACKAGE_REASON_LEDGER_OBJECTIVE_NOT_MECHANIZED")
    mechanism = binding.get("checking_mechanism")
    _require(type(mechanism) is str and "." in mechanism,
             "PACKAGE_REASON_LEDGER_MECHANISM_INVALID")
    module_name = mechanism.rsplit(".", 1)[0]
    _require(module_name.startswith("verifier.")
             and all(part.isidentifier() for part in module_name.split(".")),
             "PACKAGE_REASON_LEDGER_MECHANISM_INVALID")
    root = _selected_source_root(source_root)
    relative = Path(*module_name.split("."))
    # An explicit root selects repository bytes below ``src``.  The default
    # selects the distribution that supplied this module, whose physical root
    # is either checkout ``src`` or installed ``site-packages``.  Both modes
    # retain the same repository-coordinate spelling without borrowing bytes
    # from one selection when the other is missing.
    lookup_root = root / "src" if source_root is not None else root
    module_path = lookup_root / relative.with_suffix(".py")
    package_path = lookup_root / relative / "__init__.py"
    selected = module_path if module_path.is_file() else package_path
    try:
        resolved = selected.resolve(strict=True)
    except OSError as exc:
        raise CandidateLedgerUnavailable(
            "PACKAGE_REASON_LEDGER_MECHANISM_UNAVAILABLE"
        ) from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise CandidateLedgerError(
            "PACKAGE_REASON_LEDGER_MECHANISM_ESCAPES_SOURCE_ROOT"
        ) from exc
    try:
        source_digest = core_obligation_union.bytes_digest(resolved.read_bytes())
    except OSError as exc:
        raise CandidateLedgerUnavailable(
            "PACKAGE_REASON_LEDGER_MECHANISM_UNAVAILABLE"
        ) from exc
    source_path = resolved.relative_to(root)
    if source_root is None:
        source_path = Path("src") / source_path
    return {
        "checking_mechanism": mechanism,
        "source_path": source_path.as_posix(),
        "source_digest": source_digest,
        "symbol": mechanism.rsplit(".", 1)[1],
    }


def _checking_mechanism_digest(
        coordinate: str, *, source_root: str | Path | None) -> str:
    return _checking_mechanism_binding(
        coordinate, source_root=source_root,
    )["source_digest"]


def _obligation_semantic_identity(
        coordinate: str, route: dict[str, Any], *,
        source_root: str | Path | None = None) -> str:
    binding = domain_inventory.MECHANIZED_12_POINT_BINDINGS.get(coordinate)
    _require(type(binding) is dict,
             "PACKAGE_REASON_LEDGER_OBJECTIVE_NOT_MECHANIZED")
    required = {
        "exact_claim", "checking_mechanism", "resulting_evidence",
        "facet_examined",
    }
    _require(required <= set(binding),
             "PACKAGE_REASON_LEDGER_BINDING_INVALID")
    return core_obligation_union.value_digest({
        "coordinate": coordinate,
        "exact_claim": binding["exact_claim"],
        "checking_mechanism": binding["checking_mechanism"],
        "checking_mechanism_digest": _checking_mechanism_digest(
            coordinate, source_root=source_root
        ),
        "resulting_evidence": binding["resulting_evidence"],
        "facet_examined": binding["facet_examined"],
        "semantic_version": route["semantic_version"],
        "proposition_digest": route["proposition_digest"],
    })


def _slot_semantic_identity(slot_coordinate: str) -> str:
    match = re.fullmatch(r"(?P<kind>[A-Z]+)-(?P<tier>[1-9])", slot_coordinate)
    _require(match is not None, "PACKAGE_REASON_LEDGER_SLOT_INVALID")
    try:
        slot = domain_inventory.get_slot(
            match.group("kind"), int(match.group("tier"))
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise CandidateLedgerError(
            "PACKAGE_REASON_LEDGER_SLOT_INVALID"
        ) from exc
    return _slot_record_semantic_identity(slot)


def _slot_record_semantic_identity(slot: domain_inventory.SlotRequirement) -> str:
    """Bind a freshly selected slot without reconstructing the whole inventory."""
    return core_obligation_union.value_digest({
        "slot": f"{slot.object_kind.value}-{slot.tier.value}",
        "object_kind": slot.object_kind.value,
        "tier": slot.tier.value,
        "governing_question": slot.governing_question,
        "rationale": slot.rationale,
        "applicability": slot.applicability,
    })


def _string_list(value: Any, *, code: str, required: bool = False) -> list[str]:
    _require(type(value) is list
             and (bool(value) or not required)
             and all(type(item) is str and bool(item.strip())
                     and len(item) <= 4096 for item in value)
             and len(value) == len(set(value)), code)
    return value


def _repository_realization(
        value: Any, *, expected_digest: str,
        expected_mechanism: dict[str, str] | None,
        ) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == _REALIZATION_FIELDS,
             "PACKAGE_REASON_LEDGER_REPOSITORY_REALIZATION_FIELDS_DIFFER")
    realization_class = value["class"]
    _require(type(realization_class) is str
             and realization_class in _REALIZATION_CLASSES,
             "PACKAGE_REASON_LEDGER_REPOSITORY_REALIZATION_CLASS_INVALID")
    for name in ("explanation", "decision_authority"):
        _require(type(value[name]) is str and bool(value[name].strip())
                 and len(value[name]) <= 4096,
                 "PACKAGE_REASON_LEDGER_REPOSITORY_REALIZATION_INVALID")
    adaptation = value["adaptation_necessity"]
    if realization_class in _ADAPTATION_CLASSES:
        _require(type(adaptation) is str and bool(adaptation.strip())
                 and len(adaptation) <= 4096,
                 "PACKAGE_REASON_LEDGER_ADAPTATION_NECESSITY_REQUIRED")
    else:
        _require(adaptation is None,
                 "PACKAGE_REASON_LEDGER_ADAPTATION_NECESSITY_UNEXPECTED")
    semantic_digest = value["obligation_semantic_digest"]
    _require(type(semantic_digest) is str
             and _SHA256.fullmatch(semantic_digest) is not None
             and semantic_digest == expected_digest,
             "PACKAGE_REASON_LEDGER_REALIZATION_SEMANTIC_IDENTITY_DIFFERS")
    surface_ids = _string_list(
        value["discovered_surface_ids"],
        code="PACKAGE_REASON_LEDGER_DISCOVERED_SURFACES_INVALID",
        required=realization_class not in {"NOT_APPLICABLE", "UNREALIZED"},
    )
    for name in ("evidence_requirements", "preserved_semantics", "falsifiers"):
        _string_list(
            value[name],
            code="PACKAGE_REASON_LEDGER_REPOSITORY_REALIZATION_INVALID",
            required=True,
        )
    for name in ("unpreserved_semantics", "residual_obligations"):
        _string_list(
            value[name],
            code="PACKAGE_REASON_LEDGER_REPOSITORY_REALIZATION_INVALID",
        )
    bindings = value["mechanism_bindings"]
    _require(type(bindings) is list,
             "PACKAGE_REASON_LEDGER_MECHANISM_BINDINGS_INVALID")
    for binding in bindings:
        _require(type(binding) is dict
                 and set(binding) == _MECHANISM_BINDING_FIELDS
                 and all(type(item) is str and bool(item.strip())
                         for item in binding.values())
                 and _SHA256.fullmatch(binding["source_digest"]) is not None,
                 "PACKAGE_REASON_LEDGER_MECHANISM_BINDINGS_INVALID")
    _require(len(bindings) == len({
        (row["checking_mechanism"], row["source_path"], row["symbol"])
        for row in bindings
    }), "PACKAGE_REASON_LEDGER_MECHANISM_BINDINGS_INVALID")
    if expected_mechanism is not None:
        _require(bindings == [expected_mechanism],
                 "PACKAGE_REASON_LEDGER_MECHANISM_BINDING_DIFFERS")
    else:
        _require(bindings == [],
                 "PACKAGE_REASON_LEDGER_SLOT_MECHANISM_UNEXPECTED")
    return {
        "realization_class": realization_class,
        "realization_digest": core_obligation_union.value_digest(value),
        "obligation_semantic_digest": semantic_digest,
        "discovered_surface_identity_digest": (
            core_obligation_union.value_digest(surface_ids)
        ),
        "mechanism_binding_digest": core_obligation_union.value_digest(bindings),
        "binding_status": "PASS",
        "claim_status": "UNKNOWN",
    }


def _reason_row(
        value: Any, *, expected_digest: str,
        expected_mechanism: dict[str, str] | None = None,
        ) -> dict[str, Any]:
    _require(type(value) is dict,
             "PACKAGE_REASON_LEDGER_ROW_FIELDS_DIFFER")
    _require("repository_realization" in value,
             "PACKAGE_REASON_LEDGER_REPOSITORY_REALIZATION_FIELDS_DIFFER")
    _require(_REASON_ROW_REQUIRED_FIELDS <= set(value)
             and set(value) <= (_REASON_ROW_REQUIRED_FIELDS
                                | _REASON_ROW_OPTIONAL_FIELDS),
             "PACKAGE_REASON_LEDGER_ROW_FIELDS_DIFFER")
    _require(type(value["disposition"]) is str
             and value["disposition"] in {"INFERRED", "NO_REASON_FOUND"}
             and all(type(item) is str and len(item) <= 4096
                     for field, item in value.items()
                     if field != "repository_realization"),
             "PACKAGE_REASON_LEDGER_ROW_INVALID")
    _require(_SHA256.fullmatch(value["bound_digest"]) is not None,
             "PACKAGE_REASON_LEDGER_BOUND_DIGEST_INVALID")
    _require(value["bound_digest"] == expected_digest,
             "PACKAGE_REASON_LEDGER_SEMANTIC_IDENTITY_DIFFERS")
    return {
        **value,
        "repository_realization_summary": _repository_realization(
            value["repository_realization"],
            expected_digest=expected_digest,
            expected_mechanism=expected_mechanism,
        ),
    }


def _reason_ledger(
        path: str | Path | None, *, expected_digest: str | None,
        installed: dict[tuple[str, str], dict[str, Any]],
        source_root: str | Path | None,
        ) -> dict[str, Any]:
    if path is None and expected_digest is None:
        return {
            "status": "NOT_SELECTED",
            "ledger_digest": None,
            "objectives": {},
            "objective_count": 0,
            "slot_count": 0,
            "disposition_counts": {},
        }
    _require(path is not None and expected_digest is not None,
             "PACKAGE_REASON_LEDGER_SELECTION_INCOMPLETE")
    _require(type(expected_digest) is str
             and _SHA256.fullmatch(expected_digest) is not None,
             "PACKAGE_REASON_LEDGER_EXPECTED_DIGEST_INVALID")
    raw = _read_bounded(
        Path(path), maximum=MAX_REASON_LEDGER_BYTES,
        code="PACKAGE_REASON_LEDGER_INVALID",
    )
    digest = core_obligation_union.bytes_digest(raw)
    _require(digest == expected_digest,
             "PACKAGE_REASON_LEDGER_DIGEST_DIFFERS")
    value = _strict_json(raw)
    _require(set(value) == _REASON_LEDGER_FIELDS
             and value["schema_version"] == REASON_LEDGER_SCHEMA
             and type(value["authored"]) is str and value["authored"]
             and type(value["rule"]) is str and value["rule"]
             and type(value["objectives"]) is dict
             and type(value["slots"]) is dict,
             "PACKAGE_REASON_LEDGER_SCHEMA_INVALID")
    installed_by_coordinate = {
        coordinate: route for (_kind, coordinate), route in installed.items()
    }
    _require(set(value["objectives"]) == set(installed_by_coordinate),
             "PACKAGE_REASON_LEDGER_OBJECTIVE_SET_DIFFERS")
    expected_slots = {
        f"{kind.value}-{tier}"
        for kind in ObjectKind for tier in range(1, 10)
    }
    _require(set(value["slots"]) == expected_slots,
             "PACKAGE_REASON_LEDGER_SLOT_SET_DIFFERS")
    objectives: dict[str, dict[str, Any]] = {}
    for coordinate, row in value["objectives"].items():
        selected = _reason_row(
            row,
            expected_digest=_obligation_semantic_identity(
                coordinate, installed_by_coordinate[coordinate],
                source_root=source_root,
            ),
            expected_mechanism=_checking_mechanism_binding(
                coordinate, source_root=source_root,
            ),
        )
        realization = selected["repository_realization_summary"]
        objectives[coordinate] = {
            "bound_digest": selected["bound_digest"],
            "reason_digest": core_obligation_union.value_digest(
                selected["reason"]
            ),
            "reason_source_digest": core_obligation_union.value_digest(
                selected["reason_source"]
            ),
            "disposition": selected["disposition"],
            "semantic_identity_status": "PASS",
            **realization,
        }
    slot_realizations: list[dict[str, Any]] = []
    for coordinate, row in value["slots"].items():
        selected = _reason_row(
            row, expected_digest=_slot_semantic_identity(coordinate)
        )
        slot_realizations.append(selected["repository_realization_summary"])
    dispositions = Counter(
        row["disposition"] for row in value["objectives"].values()
    )
    realization_classes = Counter(
        row["realization_class"] for row in objectives.values()
    )
    realization_classes.update(
        row["realization_class"] for row in slot_realizations
    )
    return {
        "status": "PASS",
        "ledger_digest": digest,
        "objectives": objectives,
        "objective_count": len(objectives),
        "slot_count": len(value["slots"]),
        "disposition_counts": dict(sorted(dispositions.items())),
        "realization_binding_status": "PASS",
        "realization_claim_status": "UNKNOWN",
        "realization_class_counts": dict(sorted(realization_classes.items())),
    }


def _manifest_card_digests(raw: bytes) -> dict[str, str]:
    try:
        text = raw.decode("utf-8")
    except UnicodeError as exc:
        raise CandidateLedgerError("PACKAGE_CANDIDATE_MANIFEST_INVALID") from exc
    result: dict[str, str] = {}
    for line in text.splitlines():
        match = _MANIFEST_ROW.fullmatch(line)
        if match is None:
            _require(re.search(r"out/cards/[A-Z]+\.json(?:\s|\Z)", line) is None,
                     "PACKAGE_CANDIDATE_MANIFEST_CARD_ROW_INVALID")
            continue
        kind = match.group("kind")
        _require(kind not in result,
                 "PACKAGE_CANDIDATE_MANIFEST_DUPLICATE_CARD")
        result[kind] = "sha256:" + match.group("digest")
    expected = {kind.value for kind in ObjectKind}
    _require(set(result) == expected,
             "PACKAGE_CANDIDATE_MANIFEST_CARD_SET_DIFFERS")
    return result


def _validate_condition(
        value: Any, *, fields: set[str],
        facet_ids: set[str] | None = None,
        ) -> dict[str, Any]:
    _require(type(value) is dict and set(value) == fields,
             "PACKAGE_CANDIDATE_CONDITION_FIELDS_DIFFER")
    _require(type(value["type"]) is str
             and value["type"] in {"presence", "type"}
             and value["if_silent"] == "UNKNOWN"
             and type(value["required_when"]) is str
             and bool(value["required_when"].strip())
             and type(value["not_required_because"]) is str
             and bool(value["not_required_because"].strip()),
             "PACKAGE_CANDIDATE_CONDITION_INVALID")
    if "decided_by" in fields:
        decided_by = value["decided_by"]
        _require(type(decided_by) is list and bool(decided_by)
                 and all(type(item) is str for item in decided_by)
                 and len(decided_by) == len(set(decided_by))
                 and facet_ids is not None
                 and set(decided_by) <= facet_ids,
                 "PACKAGE_CANDIDATE_CONDITION_DECIDER_INVALID")
    return value


def _validate_definition(value: Any) -> int:
    _require(type(value) is dict
             and set(value) == {
                 "user_stated", "standard_description", "reading"
             }
             and type(value["user_stated"]) is list
             and all(
                 type(row) is dict
                 and set(row) == {"quote", "date", "source"}
                 and all(type(row[field]) is str and row[field].strip()
                         for field in ("quote", "date", "source"))
                 for row in value["user_stated"]
             )
             and all(type(value[field]) is str and value[field].strip()
                     for field in ("standard_description", "reading")),
             "PACKAGE_CANDIDATE_DEFINITION_INVALID")
    return len(value["user_stated"])


def _validate_facets(
        value: Any, *, kind: str, quote_count: int) -> set[str]:
    _require(type(value) is list and bool(value),
             "PACKAGE_CANDIDATE_FACETS_INVALID")
    result: set[str] = set()
    admitted_kinds = {item.value for item in ObjectKind}
    for facet in value:
        _require(type(facet) is dict and set(facet) == _FACET_FIELDS,
                 "PACKAGE_CANDIDATE_FACET_FIELDS_DIFFER")
        facet_id = facet["id"]
        match = _FACET.fullmatch(facet_id) if type(facet_id) is str else None
        _require(match is not None and match.group("kind") == kind
                 and facet_id not in result,
                 "PACKAGE_CANDIDATE_FACET_ID_INVALID")
        _require(type(facet["class"]) is str
                 and facet["class"] in _FACET_CLASSES,
                 "PACKAGE_CANDIDATE_FACET_CLASS_INVALID")
        _require(type(facet["basis"]) is str
                 and facet["basis"] in _FACET_BASES,
                 "PACKAGE_CANDIDATE_FACET_BASIS_INVALID")
        _require(facet["contained_kind"] is None
                 or (type(facet["contained_kind"]) is str
                     and facet["contained_kind"] in admitted_kinds),
                 "PACKAGE_CANDIDATE_FACET_CONTAINED_KIND_INVALID")
        _require(facet["quote_ref"] is None
                 or (type(facet["quote_ref"]) is int
                     and 0 <= facet["quote_ref"] < quote_count),
                 "PACKAGE_CANDIDATE_FACET_QUOTE_REF_INVALID")
        _require(all(type(facet[field]) is str and bool(facet[field].strip())
                     for field in ("name", "defined", "reason")),
                 "PACKAGE_CANDIDATE_FACET_TEXT_INVALID")
        condition = facet["condition"]
        if facet["class"] == "CONDITIONALLY_NECESSARY":
            _validate_condition(condition, fields=_FACET_CONDITION_FIELDS)
        else:
            _require(condition is None,
                     "PACKAGE_CANDIDATE_FACET_CONDITION_UNEXPECTED")
        result.add(facet_id)
    return result


def _validate_findings(value: Any) -> None:
    _require(type(value) is list,
             "PACKAGE_CANDIDATE_FINDINGS_INVALID")
    identifiers: set[str] = set()
    for finding in value:
        _require(type(finding) is dict and set(finding) == _FINDING_FIELDS,
                 "PACKAGE_CANDIDATE_FINDING_FIELDS_DIFFER")
        identifier = finding["id"]
        _require(type(identifier) is str and bool(identifier.strip())
                 and identifier not in identifiers,
                 "PACKAGE_CANDIDATE_FINDING_ID_INVALID")
        _require(type(finding["type"]) is str
                 and finding["type"] in _FINDING_TYPES
                 and type(finding["text"]) is str
                 and bool(finding["text"].strip()),
                 "PACKAGE_CANDIDATE_FINDING_INVALID")
        _require(type(finding["refs"]) is list
                 and all(type(item) is str and bool(item.strip())
                         for item in finding["refs"])
                 and len(finding["refs"]) == len(set(finding["refs"])),
                 "PACKAGE_CANDIDATE_FINDING_REFS_INVALID")
        evidence = finding["evidence"]
        _require(type(evidence) is list and bool(evidence),
                 "PACKAGE_CANDIDATE_FINDING_EVIDENCE_INVALID")
        for row in evidence:
            _require(
                type(row) is dict
                and _FINDING_EVIDENCE_REQUIRED_FIELDS <= set(row)
                and set(row) <= (
                    _FINDING_EVIDENCE_REQUIRED_FIELDS
                    | _FINDING_EVIDENCE_OPTIONAL_FIELDS
                )
                and all(type(item) is str and bool(item.strip())
                        for item in row.values()),
                "PACKAGE_CANDIDATE_FINDING_EVIDENCE_INVALID",
            )
        identifiers.add(identifier)


def _validate_facet_coverage(
        value: Any, *, kind: str, facet_ids: set[str],
        installed: dict[tuple[str, str], dict[str, Any]]) -> None:
    _require(type(value) is list and len(value) == len(facet_ids),
             "PACKAGE_CANDIDATE_FACET_COVERAGE_INVALID")
    admitted_objectives = {
        coordinate for (object_kind, coordinate) in installed
        if object_kind == kind
    }
    observed_facets: set[str] = set()
    for row in value:
        _require(type(row) is dict and set(row) == _FACET_COVERAGE_FIELDS,
                 "PACKAGE_CANDIDATE_FACET_COVERAGE_FIELDS_DIFFER")
        facet = row["facet"]
        _require(type(facet) is str and facet in facet_ids
                 and facet not in observed_facets,
                 "PACKAGE_CANDIDATE_FACET_COVERAGE_FACET_INVALID")
        objectives = row["objectives"]
        _require(type(objectives) is list
                 and all(type(item) is str for item in objectives)
                 and len(objectives) == len(set(objectives))
                 and set(objectives) <= admitted_objectives,
                 "PACKAGE_CANDIDATE_FACET_COVERAGE_OBJECTIVES_INVALID")
        mechanism = row["mechanism"]
        _require(type(mechanism) is str
                 and mechanism in (_MECHANISMS | {"ABSENT"})
                 and (mechanism != "ABSENT" or objectives == [])
                 and type(row["note"]) is str and bool(row["note"].strip()),
                 "PACKAGE_CANDIDATE_FACET_COVERAGE_INVALID")
        observed_facets.add(facet)
    _require(observed_facets == facet_ids,
             "PACKAGE_CANDIDATE_FACET_COVERAGE_SET_DIFFERS")


def _validate_obligation(
        row: Any, *, kind: str,
        installed: dict[tuple[str, str], dict[str, Any]],
        card_digest: str,
        facet_ids: set[str],
        reason_identity: dict[str, Any] | None,
        ) -> dict[str, Any]:
    _require(type(row) is dict and set(row) == _OBLIGATION_FIELDS,
             "PACKAGE_CANDIDATE_OBLIGATION_FIELDS_DIFFER")
    objective = row["objective"]
    match = _OBJECTIVE.fullmatch(objective) if type(objective) is str else None
    _require(match is not None and match.group("kind") == kind,
             "PACKAGE_CANDIDATE_OBJECTIVE_INVALID")
    tier = row["tier"]
    _require(type(tier) is int and tier == int(match.group("tier")),
             "PACKAGE_CANDIDATE_OBJECTIVE_TIER_DIFFERS")
    route = installed.get((kind, objective))
    _require(route is not None and route["tier"] == tier,
             "PACKAGE_CANDIDATE_OBJECTIVE_NOT_INSTALLED")
    _require(type(row["rev3_class"]) is str
             and type(row["rev4_class"]) is str
             and row["rev3_class"] in _CLASSES
             and row["rev4_class"] in _CLASSES,
             "PACKAGE_CANDIDATE_CLASS_INVALID")
    _require(type(row["mechanism"]) is str
             and row["mechanism"] in _MECHANISMS,
             "PACKAGE_CANDIDATE_MECHANISM_INVALID")
    _require(type(row["reason_verdict"]) is str
             and row["reason_verdict"] in _REASON_VERDICTS,
             "PACKAGE_CANDIDATE_REASON_VERDICT_INVALID")
    _require(
        (row["reason_verdict"] == "REWRITE"
         and type(row["reason_rewrite"]) is str
         and bool(row["reason_rewrite"].strip()))
        or (row["reason_verdict"] == "ADEQUATE"
            and row["reason_rewrite"] is None),
        "PACKAGE_CANDIDATE_REASON_REWRITE_INVALID",
    )
    _require(type(row["note"]) is str and bool(row["note"].strip()),
             "PACKAGE_CANDIDATE_OBLIGATION_NOTE_INVALID")
    _require(type(row["role"]) is str and row["role"] in _ROLES,
             "PACKAGE_CANDIDATE_ROLE_INVALID")
    _require(type(row["serves"]) is list
             and all(type(value) is str for value in row["serves"])
             and len(row["serves"]) == len(set(row["serves"]))
             and set(row["serves"]) <= facet_ids,
             "PACKAGE_CANDIDATE_SERVED_FACETS_INVALID")
    _require(type(row["failed_tests"]) is list
             and all(type(value) is str for value in row["failed_tests"])
             and len(row["failed_tests"]) == len(set(row["failed_tests"]))
             and set(row["failed_tests"]) <= {f"R{index}" for index in range(1, 7)},
             "PACKAGE_CANDIDATE_FAILED_TESTS_INVALID")
    condition = row["rev4_condition"]
    if row["rev4_class"] == "CONDITIONALLY_NECESSARY":
        _validate_condition(
            condition, fields=_ROW_CONDITION_FIELDS, facet_ids=facet_ids,
        )
    else:
        _require(condition is None,
                 "PACKAGE_CANDIDATE_CONDITION_UNEXPECTED")
    return {
        "object_kind": kind,
        "tier": tier,
        "coordinate": objective,
        "semantic_version": route["semantic_version"],
        "proposition_digest": route["proposition_digest"],
        "certificate_schema_version": route["certificate_schema_version"],
        "checking_mechanism": route["checking_mechanism"],
        "scope": route["scope"],
        "candidate_rev3_class": row["rev3_class"],
        "candidate_rev4_class": row["rev4_class"],
        "candidate_condition": condition,
        "candidate_mechanism_assessment": row["mechanism"],
        "candidate_reason_verdict": row["reason_verdict"],
        "candidate_role": row["role"],
        "candidate_served_facets": row["serves"],
        "candidate_failed_tests": row["failed_tests"],
        "candidate_class_epistemic_type": "INFERRED",
        "candidate_semantic_identity_status": (
            reason_identity["semantic_identity_status"]
            if reason_identity is not None else "NOT_ESTABLISHED"
        ),
        "reason_bound_digest": (
            reason_identity["bound_digest"]
            if reason_identity is not None else None
        ),
        "reason_text_digest": (
            reason_identity["reason_digest"]
            if reason_identity is not None else None
        ),
        "reason_source_digest": (
            reason_identity["reason_source_digest"]
            if reason_identity is not None else None
        ),
        "reason_disposition": (
            reason_identity["disposition"]
            if reason_identity is not None else None
        ),
        "repository_realization_class": (
            reason_identity["realization_class"]
            if reason_identity is not None else None
        ),
        "repository_realization_binding_status": (
            reason_identity["binding_status"]
            if reason_identity is not None else "NOT_ESTABLISHED"
        ),
        "repository_realization_claim_status": (
            reason_identity["claim_status"]
            if reason_identity is not None else "NOT_ESTABLISHED"
        ),
        "repository_realization_digest": (
            reason_identity["realization_digest"]
            if reason_identity is not None else None
        ),
        "repository_surface_identity_digest": (
            reason_identity["discovered_surface_identity_digest"]
            if reason_identity is not None else None
        ),
        "repository_mechanism_binding_digest": (
            reason_identity["mechanism_binding_digest"]
            if reason_identity is not None else None
        ),
        "candidate_row_digest": core_obligation_union.value_digest(row),
        "candidate_card_digest": card_digest,
        "owner_disposition_status": "NOT_ESTABLISHED",
        "normative_closure": "NOT_ESTABLISHED",
        "status": "UNKNOWN",
    }


def load_candidate_obligation_ledger(
        cards_root: str | Path,
        manifest_path: str | Path,
        inventory: dict[str, Any], *,
        expected_manifest_digest: str,
        reason_ledger_path: str | Path | None = None,
        expected_reason_ledger_digest: str | None = None,
        source_root: str | Path | None = None,
        ) -> dict[str, Any]:
    """Validate and bind exactly 26 candidate cards to 408 installed routes."""
    root = Path(cards_root)
    manifest = Path(manifest_path)
    try:
        if root.is_symlink():
            raise CandidateLedgerError("PACKAGE_CANDIDATE_CARDS_ROOT_INVALID")
        if not root.is_dir():
            raise CandidateLedgerUnavailable(
                "PACKAGE_CANDIDATE_CARDS_ROOT_INVALID"
            )
    except CandidateLedgerError:
        raise
    except CandidateLedgerUnavailable:
        raise
    except OSError as exc:
        raise CandidateLedgerUnavailable(
            "PACKAGE_CANDIDATE_CARDS_ROOT_INVALID"
        ) from exc
    manifest_raw = _read_bounded(
        manifest, maximum=MAX_MANIFEST_BYTES,
        code="PACKAGE_CANDIDATE_MANIFEST_INVALID",
    )
    manifest_digest = core_obligation_union.bytes_digest(manifest_raw)
    _require(type(expected_manifest_digest) is str
             and _SHA256.fullmatch(expected_manifest_digest) is not None,
             "PACKAGE_CANDIDATE_EXPECTED_MANIFEST_DIGEST_INVALID")
    _require(manifest_digest == expected_manifest_digest,
             "PACKAGE_CANDIDATE_MANIFEST_DIGEST_DIFFERS")
    manifest_cards = _manifest_card_digests(manifest_raw)
    expected_names = {kind.value + ".json" for kind in ObjectKind}
    try:
        json_paths = [
            path for path in root.iterdir()
            if path.suffix.lower() == ".json"
        ]
        actual_names = {
            path.name for path in json_paths if path.is_file()
        }
    except OSError as exc:
        raise CandidateLedgerUnavailable(
            "PACKAGE_CANDIDATE_CARD_FILE_SET_UNAVAILABLE"
        ) from exc
    _require(actual_names == expected_names,
             "PACKAGE_CANDIDATE_CARD_FILE_SET_DIFFERS")

    installed = _installed_routes(inventory)
    reasons = _reason_ledger(
        reason_ledger_path,
        expected_digest=expected_reason_ledger_digest,
        installed=installed,
        source_root=source_root,
    )
    rows: list[dict[str, Any]] = []
    card_questions: list[dict[str, Any]] = []
    card_bindings: list[dict[str, str]] = []
    total_bytes = 0
    for kind in sorted(item.value for item in ObjectKind):
        path = root / f"{kind}.json"
        raw = _read_bounded(
            path, maximum=MAX_CARD_BYTES,
            code="PACKAGE_CANDIDATE_CARD_INVALID",
        )
        total_bytes += len(raw)
        _require(total_bytes <= MAX_TOTAL_CARD_BYTES,
                 "PACKAGE_CANDIDATE_CARD_CAPACITY_EXHAUSTED")
        card_digest = core_obligation_union.bytes_digest(raw)
        _require(card_digest == manifest_cards[kind],
                 "PACKAGE_CANDIDATE_CARD_DIGEST_DIFFERS")
        card = _strict_json(raw)
        _require(set(card) == _CARD_FIELDS and card["kind"] == kind,
                 "PACKAGE_CANDIDATE_CARD_FIELDS_DIFFER")
        _require(type(card["findings"]) is list
                 and type(card["facet_coverage"]) is list,
                 "PACKAGE_CANDIDATE_CARD_CONTENT_INVALID")
        quote_count = _validate_definition(card["definition"])
        facet_ids = _validate_facets(
            card["facets"], kind=kind, quote_count=quote_count
        )
        _validate_findings(card["findings"])
        _validate_facet_coverage(
            card["facet_coverage"], kind=kind, facet_ids=facet_ids,
            installed=installed,
        )
        obligations = card["obligation_map"]
        questions = card["questions"]
        _require(type(obligations) is list and type(questions) is list,
                 "PACKAGE_CANDIDATE_CARD_CONTENT_INVALID")
        _require(len(questions) == 4,
                 "PACKAGE_CANDIDATE_OWNER_QUESTION_COUNT_DIFFERS")
        for row in obligations:
            objective = (
                row.get("objective") if type(row) is dict else None
            )
            rows.append(_validate_obligation(
                row, kind=kind, installed=installed, card_digest=card_digest,
                facet_ids=facet_ids,
                reason_identity=(
                    reasons["objectives"].get(objective)
                    if type(objective) is str else None
                ),
            ))
        for index, question in enumerate(questions, start=1):
            _require(type(question) is dict
                     and set(question) == {"q", "default"}
                     and type(question["q"]) is str
                     and type(question["default"]) is str,
                     "PACKAGE_CANDIDATE_OWNER_QUESTION_INVALID")
            card_questions.append({
                "decision_id": f"{kind}-Q{index}",
                "object_kind": kind,
                "question_digest": core_obligation_union.value_digest(question),
                "scope_basis": "INFERRED_CANDIDATE_CARD_SCOPE",
                "status": "NOT_ESTABLISHED",
            })
        card_bindings.append({
            "object_kind": kind,
            "card_digest": card_digest,
        })

    identities = [(row["object_kind"], row["coordinate"]) for row in rows]
    _require(len(identities) == len(set(identities)),
             "PACKAGE_CANDIDATE_OBJECTIVE_DUPLICATE")
    _require(set(identities) == set(installed),
             "PACKAGE_CANDIDATE_OBJECTIVE_SET_DIFFERS")
    rows.sort(key=lambda row: (row["object_kind"], row["tier"], row["coordinate"]))
    expected_count = inventory["registered_route_membership_count"]
    _require(len(rows) == expected_count,
             "PACKAGE_CANDIDATE_OBJECTIVE_COUNT_DIFFERS")

    class_counts = Counter(row["candidate_rev4_class"] for row in rows)
    mechanism_counts = Counter(
        row["candidate_mechanism_assessment"] for row in rows
    )
    reason_counts = Counter(row["candidate_reason_verdict"] for row in rows)
    cross_kind_decisions = [
        {
            "decision_id": decision_id,
            "topic": topic,
            "scope": scope,
            "scope_basis": "INFERRED_IMPLEMENTER_MAPPING",
            "status": "NOT_ESTABLISHED",
        }
        for decision_id, topic, scope in _CROSS_KIND_DECISIONS
    ]
    owner_decisions = cross_kind_decisions + card_questions
    result = {
        "schema_version": SELECTION_SCHEMA,
        "status": "PASS",
        "selection_validation_status": "PASS",
        "candidate_epistemic_status": "INFERRED",
        "semantic_identity_status": (
            "PASS" if reasons["status"] == "PASS" else "NOT_ESTABLISHED"
        ),
        "owner_adoption_status": "NOT_ESTABLISHED",
        "normative_closure": "NOT_ESTABLISHED",
        "manifest_name": manifest.name,
        "manifest_digest": manifest_digest,
        "card_count": len(card_bindings),
        "card_set_digest": core_obligation_union.value_digest(card_bindings),
        "objective_count": len(rows),
        "installed_inventory_digest": core_obligation_union.value_digest(inventory),
        "reason_ledger_selection_status": reasons["status"],
        "reason_ledger_digest": reasons["ledger_digest"],
        "reason_identity_count": reasons["objective_count"],
        "reason_slot_identity_count": reasons["slot_count"],
        "reason_disposition_counts": reasons["disposition_counts"],
        "repository_realization_binding_status": reasons.get(
            "realization_binding_status", "NOT_ESTABLISHED"
        ),
        "repository_realization_claim_status": reasons.get(
            "realization_claim_status", "NOT_ESTABLISHED"
        ),
        "repository_realization_class_counts": reasons.get(
            "realization_class_counts", {}
        ),
        "candidate_rev4_class_counts": dict(sorted(class_counts.items())),
        "candidate_mechanism_counts": dict(sorted(mechanism_counts.items())),
        "candidate_reason_verdict_counts": dict(sorted(reason_counts.items())),
        "card_question_count": len(card_questions),
        "cross_kind_decision_count": len(cross_kind_decisions),
        "owner_decision_count": len(owner_decisions),
        "owner_decisions": owner_decisions,
        "rows": rows,
        "claim_boundary": (
            "PASS establishes exact byte and coordinate binding of the selected "
            "candidate cards to the installed 408-route registry. Semantic "
            "identity is PASS only when a separately selected reason ledger binds "
            "all 408 obligations and 234 slots to current route, claim, facet, "
            "evidence, and executable-mechanism bytes, and every reason carries "
            "a repository-realization annotation bound to the exact semantic "
            "identity and current mechanism bytes. Realization binding PASS "
            "validates the annotation, not its semantic claim; realization claims "
            "remain UNKNOWN until independent surface reconciliation. Candidate "
            "classes, mechanism assessments, reasons, conditions, and defaults "
            "remain INFERRED proposals; owner adoption and normative closure "
            "remain NOT_ESTABLISHED, and every obligation status remains UNKNOWN."
        ),
    }
    result["selection_digest"] = core_obligation_union.value_digest(result)
    return result


def not_selected_candidate_obligation_ledger() -> dict[str, Any]:
    """Return the explicit no-selection state without inventing evidence."""
    return {
        "schema_version": SELECTION_SCHEMA,
        "status": "NOT_SELECTED",
        "selection_validation_status": "NOT_ESTABLISHED",
        "candidate_epistemic_status": "NOT_ESTABLISHED",
        "semantic_identity_status": "NOT_ESTABLISHED",
        "owner_adoption_status": "NOT_ESTABLISHED",
        "normative_closure": "NOT_ESTABLISHED",
        "objective_count": 0,
        "owner_decision_count": 0,
        "rows": [],
        "claim_boundary": "No candidate obligation-card bundle was selected.",
    }


def failed_candidate_obligation_ledger(code: str) -> dict[str, Any]:
    """Return a bounded failure without leaking local paths or malformed bytes."""
    return {
        "schema_version": SELECTION_SCHEMA,
        "status": "FAIL",
        "selection_validation_status": "FAIL",
        "candidate_epistemic_status": "NOT_ESTABLISHED",
        "semantic_identity_status": "NOT_ESTABLISHED",
        "owner_adoption_status": "NOT_ESTABLISHED",
        "normative_closure": "NOT_ESTABLISHED",
        "objective_count": 0,
        "owner_decision_count": 0,
        "rows": [],
        "error": code,
        "claim_boundary": (
            "The selected candidate obligation bundle failed mechanical validation; "
            "no candidate classifications or mechanism assessments were retained."
        ),
    }


def unavailable_candidate_obligation_ledger(code: str) -> dict[str, Any]:
    """Preserve unavailable selected bytes as UNKNOWN rather than contradiction."""
    return {
        "schema_version": SELECTION_SCHEMA,
        "status": "UNKNOWN",
        "selection_validation_status": "UNKNOWN",
        "candidate_epistemic_status": "NOT_ESTABLISHED",
        "semantic_identity_status": "NOT_ESTABLISHED",
        "owner_adoption_status": "NOT_ESTABLISHED",
        "normative_closure": "NOT_ESTABLISHED",
        "objective_count": 0,
        "owner_decision_count": 0,
        "rows": [],
        "error": code,
        "claim_boundary": (
            "Selected candidate obligation bytes were unavailable; absence is not "
            "a contradiction and no candidate rows were retained."
        ),
    }


__all__ = [
    "CandidateLedgerError", "CandidateLedgerUnavailable", "SELECTION_SCHEMA",
    "failed_candidate_obligation_ledger",
    "load_candidate_obligation_ledger", "not_selected_candidate_obligation_ledger",
    "unavailable_candidate_obligation_ledger",
]
