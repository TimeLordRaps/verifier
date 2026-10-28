"""Source-representation contracts for package GRAPH polish through Tier 3.

Terminology: identifier (ID).

The native object routes describe retained runtime-domain records.  Verifier's
root package graph instead contains source-owned representations of installed
implementations and data assets.  This module supplies the necessary adaptation:
it checks those exact source representations without pretending that source
text is a runtime DATA set, physical HARDWARE, a live SENSOR, or another native
domain specimen.

The adaptation is deliberately closed over installed review catalogs.  A
repository-authored label, reason, digest, or PASS string cannot add an object
to that catalog.  Unsupported objects remain unresolved and their native routes
are not waived.  JavaScript Object Notation (JSON); Secure Hash Algorithm
256-bit (SHA-256).
"""
from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, Mapping, TYPE_CHECKING

from verifier.core.namespace import NamespaceObject, composition_digest
from verifier.runtime import (
    namespace_consequences,
    package_namespace_review,
    package_original_kind_catalog_retained,
    package_original_review_computation,
    package_original_review_people,
    package_original_review_systems,
    package_semantic_review_admission,
    package_semantic_review_commands,
    package_semantic_review_core,
    package_semantic_review_hardware_cli,
    package_semantic_review_operations,
    package_semantic_review_package_object,
    package_semantic_review_partitions,
    package_semantic_review_polish,
    package_semantic_review_records,
    package_semantic_review_scripts,
    package_semantic_review_self_polish,
    package_semantic_review_subjects,
    package_semantic_review_verifier,
)
from verifier.runtime.namespace_contracts import ancestors, namespace_registry
from verifier.runtime.tier_zero_profile import (
    applicability_declaration,
    applicability_digest,
    validate_applicability_binding,
    value_digest,
)

if TYPE_CHECKING:
    from verifier.runtime.package_kind_requirements import KindRequirements


ADAPTER = "verifier-package-source-contracts-1"
_OWNED_GAPS_UNRESOLVED = "owned source has unresolved discovery gaps"
# A manifest cell that is still an open question (UNRESOLVED, no evidence) beside an
# installed review that answers it has not yet adopted the audited answer.  Nothing
# contradicts the review, so the route is unestablished rather than refuted.
_UNADOPTED_ANSWER = "installed review answer is not adopted by the manifest: "
_UNADOPTED_LABEL = "specialization label has no standing claim in the manifest: "
SEMANTIC_VERSION = "verifier-package-source-contracts-1"
COORDINATE_NUMBER = 90
_TIERS = {
    1: ("source-representation-facets", "Source representation facets"),
    2: ("source-representation-dynamics", "Source representation dynamics"),
    3: ("source-representation-statics", "Source representation statics"),
}
_REVIEW_MODULES = (
    package_namespace_review,
    package_original_review_computation,
    package_original_review_people,
    package_original_review_systems,
    package_semantic_review_admission,
    package_semantic_review_commands,
    package_semantic_review_core,
    package_semantic_review_hardware_cli,
    package_semantic_review_operations,
    package_semantic_review_package_object,
    package_semantic_review_partitions,
    package_semantic_review_polish,
    package_semantic_review_records,
    package_semantic_review_scripts,
    package_semantic_review_self_polish,
    package_semantic_review_subjects,
    package_semantic_review_verifier,
)
_ADDED = frozenset(
    kind for kind, contract in namespace_registry().items()
    if contract.extends is not None
)


def _validate_admission_ledger(value: Any) -> list[str]:
    """Return ordered IDs only for an exact, nonempty, unique reason ledger."""
    if type(value) is not list or not value:
        raise ValueError("PACKAGE_SOURCE_ADMISSION_LEDGER_INVALID")
    identifiers: list[str] = []
    for row in value:
        if (type(row) is not dict
                or set(row) != {"obligation_id", "reason", "claim_boundary"}
                or any(type(row[field]) is not str or not row[field].strip()
                       for field in row)):
            raise ValueError("PACKAGE_SOURCE_ADMISSION_LEDGER_INVALID")
        identifiers.append(row["obligation_id"])
    if len(identifiers) != len(set(identifiers)):
        raise ValueError("PACKAGE_SOURCE_ADMISSION_LEDGER_DUPLICATED")
    return identifiers


def _admission_contract(kind: str) -> list[dict[str, str]]:
    """Return the atomic admission reason ledger owned by this adapter.

    The legacy namespace deliberately has no per-kind 0.x obligations.  A
    source adapter still needs a nonempty proposition before its Tier 1-3
    result can mean anything, but that proposition must not be mislabeled as
    repository-wide VSTD-T0 credit.  The synthetic ``SOURCE-0.1`` proposition
    is therefore owned and bounded here.  Added kinds keep their installed
    namespace obligations and reasons unchanged.
    """
    contract = namespace_registry()[kind]
    if contract.obligations:
        ledger = [
            {
                "obligation_id": obligation.id,
                "reason": obligation.reason,
                "claim_boundary": (
                    f"This installed {kind} admission obligation establishes only "
                    "the declared contract and its current owned-source binding; it "
                    "does not establish the declared behavior, effects, authority, "
                    "safety, release, or deployment."
                ),
            }
            for obligation in contract.obligations
        ]
        _validate_admission_ledger(ledger)
        return ledger

    identifier = f"{kind}-SOURCE-0.1-installed-review-binding"
    ledger = [
        {
            "obligation_id": identifier,
            "reason": (
                f"A {kind} source-representation result requires the exact installed "
                "review and current owned-source denominator so that a repository "
                "label, stale review, or unrelated same-named object cannot acquire "
                "source-adapter conformance."
            ),
            "claim_boundary": (
                f"This adapter-owned {kind} proposition establishes only installed-"
                "review and current owned-source binding for the selected source "
                "representation. It grants no repository-wide VSTD-T0 credit and "
                "does not establish typed composition, Facets, Dynamics, or Statics "
                "behavior, kind semantics, a native runtime-domain instance, external "
                "authority, release, or deployment."
            ),
        }
    ]
    _validate_admission_ledger(ledger)
    return ledger


def _review_catalog() -> dict[str, dict[str, Any]]:
    """Load installed reviews and compose retained-root ownership explicitly.

    A consequence review may cover a strict subset of a retained root's current
    fallback ownership. The original-kind audit owns that full path denominator;
    the consequence review owns only its named role decisions. Keeping both
    scopes explicit lets source adaptation recapture every owned file without
    silently widening a narrower semantic claim.
    """
    result: dict[str, dict[str, Any]] = {}
    for module in _REVIEW_MODULES:
        document = module.review_document()
        if type(document) is not dict:
            raise ValueError("PACKAGE_SOURCE_REVIEW_DOCUMENT_INVALID")
        for object_id, row in document.items():
            if object_id in result:
                raise ValueError("PACKAGE_SOURCE_REVIEW_OBJECT_DUPLICATED:" + object_id)
            if type(object_id) is not str or type(row) is not dict:
                raise ValueError("PACKAGE_SOURCE_REVIEW_DOCUMENT_INVALID")
            result[object_id] = row
    retained = package_original_kind_catalog_retained.review_document()
    for object_id, row in list(result.items()):
        original = retained.get(object_id)
        if original is None:
            continue
        consequence_paths = row.get("owned_paths")
        owned_paths = original.get("expected_owned_paths")
        if (
            type(consequence_paths) is not list
            or not consequence_paths
            or any(type(path) is not str or not path for path in consequence_paths)
            or len(consequence_paths) != len(set(consequence_paths))
            or type(owned_paths) is not list
            or not owned_paths
            or any(type(path) is not str or not path for path in owned_paths)
            or len(owned_paths) != len(set(owned_paths))
            or original.get("expected_primary") != row.get("primary_kind")
        ):
            raise ValueError(
                "PACKAGE_SOURCE_RETAINED_OWNERSHIP_REVIEW_INVALID:" + object_id
            )
        if set(consequence_paths) == set(owned_paths):
            continue
        if not set(consequence_paths) < set(owned_paths):
            raise ValueError(
                "PACKAGE_SOURCE_RETAINED_OWNERSHIP_SCOPE_INVALID:" + object_id
            )
        composed = deepcopy(row)
        composed["classification_scope_paths"] = list(consequence_paths)
        composed["owned_paths"] = list(owned_paths)
        composed["ownership_review"] = {
            "profile": "verifier-package-original-kind-retained-partial",
            "owned_path_set_digest": original[
                "expected_owned_path_set_digest"
            ],
            "scope_reason": original["scope_reason"],
            "claim_boundary": original["claim_boundary"],
        }
        result[object_id] = composed
    return result


# Membership and the owned-source denominator are installed authority, not a
# manifest-supplied extension point. Object identifiers alone are deliberately
# insufficient: tests, forks, and unrelated repositories may legitimately use
# the same readable identifiers without becoming Verifier's reviewed package.
# The full documents are still loaded afresh into each assessment so their
# values and mechanism bytes participate in current-source recapture.
_INSTALLED_REVIEWS = _review_catalog()
_INSTALLED_REVIEW_IDS = frozenset(_INSTALLED_REVIEWS)


# Each tier names only the mechanism it checks; cumulative tiers repeat lower scope.
_TIER_SCOPE = {
    1: ("the installed review binding, exact owned-file denominator, and current "
        "source digests, with the admission ledger"),
    2: ("the discovered source interfaces, imports, and exports of the reviewed "
        "source, cumulative with the Tier 1 binding"),
    3: ("the complete installed classification review within its explicit semantic "
        "scope, the full owned-source denominator, specialization set after projecting "
        "exact compiler-owned whole-graph consequence roles, and live negative "
        "controls, cumulative with the Tier 2 interfaces"),
}


def _route_reason(kind: str, tier: int) -> str:
    """Return the tier's bounded source-only claim and its excluded claims."""
    return (
        f"The {kind} source-representation route establishes only {_TIER_SCOPE[tier]} "
        "for the selected package object. It does not establish typed composition, "
        "which the package graph gate checks separately, nor the Facets, Dynamics, or "
        f"Statics behavior or the {kind} kind semantics. Behavioral applicability "
        "remains an independent necessary or conditional route."
    )


def _route(kind: str, tier: int) -> dict[str, Any]:
    slug, name = _TIERS[tier]
    covered = _admission_contract(kind)
    coordinate = f"{kind}-{tier}.{COORDINATE_NUMBER}"
    exact_claims = {
        1: (
            "The installed review's exact owned-file denominator, applicable kind, "
            "repository reason, declaration fields, and current source digests match "
            "this manifest object."
        ),
        2: (
            "Every discovered source interface, source import, and export belonging to "
            "the reviewed object is represented at current bytes, with no owned parser "
            "or dynamic-surface gap."
        ),
        3: (
            "The complete installed scoped kind/refutation review, full owned-source "
            "denominator, specialization set, consequence selection, and live "
            "omission/substitution controls agree for this exact source-owned object."
        ),
    }
    reason = _route_reason(kind, tier)
    applicability = applicability_declaration(
        mode="NECESSARY",
        condition=(
            f"The admitted object is selected into the installed {kind} source-"
            f"representation profile evaluated at Tier {tier}."
        ),
        reason=reason,
    )
    declaration_digest = applicability_digest(applicability)
    identity = {
        "semantic_version": SEMANTIC_VERSION,
        "coordinate": coordinate,
        "object_kind": kind,
        "tier": tier,
        "covered_admission_obligations": covered,
        "exact_claim": exact_claims[tier],
        "applicability": applicability,
        "applicability_digest": declaration_digest,
    }
    return {
        "coordinate": coordinate,
        "obligation_id": coordinate + "-" + slug,
        "obligation_name": name,
        "object_kind": kind,
        "tier": tier,
        "reason": reason,
        "applicability": applicability,
        "applicability_digest": declaration_digest,
        "exact_claim": exact_claims[tier],
        "semantic_version": SEMANTIC_VERSION,
        "proposition_digest": value_digest(identity),
        "checking_mechanism": "verifier.runtime.package_source_contracts.SourceContractAssessment.evaluate",
        "scope": "exact_installed_source_representation_" + slug.replace("-", "_"),
        "adapter": ADAPTER,
        "covered_admission_obligations": covered,
    }


def catalog() -> list[dict[str, Any]]:
    """Return one readable cumulative source route per installed kind and tier."""
    kinds = sorted(namespace_registry())
    return [_route(kind, tier) for tier in sorted(_TIERS) for kind in kinds]


_CATALOG = {(row["object_kind"], row["tier"]): row for row in catalog()}


def is_route(route: Mapping[str, Any]) -> bool:
    return route.get("adapter") == ADAPTER and route == _CATALOG.get(
        (route.get("object_kind"), route.get("tier"))
    )


def source_route_for_obligation(obligation_id: Any) -> dict[str, Any] | None:
    """Return one immutable-copy view of an installed source adaptation route."""

    if type(obligation_id) is not str:
        return None
    selected = [
        route for route in _CATALOG.values()
        if route.get("obligation_id") == obligation_id
    ]
    return deepcopy(selected[0]) if len(selected) == 1 else None


def can_refute_native_runtime_variant(route: Mapping[str, Any]) -> bool:
    """Return whether source evidence may attempt this route's non-trigger.

    This is an eligibility predicate, not proof of a refutation.  Source-owned,
    generic representation, and necessary routes cannot produce conditional
    source authority.  Malformed applicability deliberately raises so callers
    can preserve their own fail-closed boundary.
    """

    if is_route(route) or route.get("scope") == (
        "generic_canonical_representation_and_address"
    ):
        return False
    return validate_applicability_binding(route)["mode"] == "CONDITIONAL"


def applies_to(item: NamespaceObject, declaration: Mapping[str, Any],
               route: Mapping[str, Any], kinds: KindRequirements) -> bool:
    """Added roles accumulate; legacy source routes belong to the primary kind."""
    if not is_route(route):
        return False
    review = _INSTALLED_REVIEWS.get(item.object_id)
    if review is None or review.get("primary_kind") != declaration.get("kind"):
        return False
    file_surfaces = {surface.removeprefix("file:")
                     for surface in declaration.get("surfaces", [])
                     if type(surface) is str and surface.startswith("file:")}
    if file_surfaces != set(review.get("owned_paths", [])):
        return False
    kind = route["object_kind"]
    if kind in _ADDED:
        expected = review.get("classification", {}).get(kind)
        selected = declaration.get("classification", {}).get(kind)
        return (kind in kinds.kinds(item.object_id)
                and type(expected) is dict and expected.get("status") == "APPLIES"
                and type(selected) is dict and selected.get("status") == "APPLIES")
    if kind == "OBJECT":
        return "OBJECT" in kinds.kinds(item.object_id)
    if item.kind.value == kind and declaration.get("kind") == kind:
        return True
    selected = declaration.get("classification", {}).get(kind)
    return (kind in kinds.kinds(item.object_id)
            and type(selected) is dict and selected.get("status") == "APPLIES")


def _is_open_cell(cell: Any) -> bool:
    """Return whether a manifest cell is still an unanswered, evidence-free question."""
    return (
        type(cell) is dict
        and cell.get("status") == "UNRESOLVED"
        and not cell.get("evidence")
    )


def _compiled_consequence_kinds(declaration: Mapping[str, Any]) -> set[str]:
    """Return exact whole-graph roles that the one-object review does not own."""

    object_id = declaration.get("object_id")
    decisions = declaration.get("classification")
    if type(object_id) is not str or type(decisions) is not dict:
        return set()
    return {
        kind
        for kind, decision in decisions.items()
        if type(kind) is str
        and namespace_consequences.is_compiled_role_decision(
            object_id, kind, decision
        )
    }


def _documented_obligation_retention_keys(
        root: Path, declarations: Mapping[str, Mapping[str, Any]],
        ) -> frozenset[tuple[str, str]]:
    """Select exact reasons.vstd answers that retain demand, not source roles.

    The compiled registry intentionally preserves the original open or denied
    cell.  Its separately bound root-reason answer is therefore the authority
    for this projection; guessing from the cell's prose would conflate
    ``objects.vstd`` with the sole authored ``reasons.vstd`` ledger.
    """

    if not (root / "reasons.vstd").is_file():
        return frozenset()
    from verifier.runtime.tier_zero_reasoning import integration as reason_integration

    selection = reason_integration.select_root_reasons(root)
    answers = reason_integration.documented_applicability_answers(
        selection, list(declarations.values())
    )
    return frozenset(
        (answer["object_id"], answer["object_kind"])
        for answer in answers
    )


def _is_unestablished(error: str) -> bool:
    """Return whether an error names missing evidence rather than a contradiction."""
    return error == _OWNED_GAPS_UNRESOLVED or error.startswith(
        (_UNADOPTED_ANSWER, _UNADOPTED_LABEL)
    )


def _evidence_matches(value: Any, paths: set[str], files: Mapping[str, str]) -> bool:
    if type(value) is not list or len(value) != len(paths):
        return False
    selected: dict[str, str] = {}
    for row in value:
        if (type(row) is not dict or set(row) != {"path", "sha256"}
                or type(row["path"]) is not str or type(row["sha256"]) is not str
                or row["path"] in selected):
            return False
        selected[row["path"]] = row["sha256"]
    return set(selected) == paths and all(files.get(path) == digest
                                           for path, digest in selected.items())


_NEGATIVE_CONTROL_SCHEMA = "verifier-source-denominator-negative-control-1"


def _unique_strings(value: Any) -> tuple[str, ...] | None:
    """Return a nonempty, duplicate-free string sequence or fail closed."""
    if type(value) is not list or not value or any(
            type(item) is not str or not item for item in value):
        return None
    selected = tuple(value)
    return selected if len(selected) == len(set(selected)) else None


def _owned_path_denominator_matches(owned_paths: Any, declared_surfaces: Any,
                                    files: Mapping[str, str]) -> bool:
    """The one predicate used by admission and its owned-path negative probes."""
    expected = _unique_strings(owned_paths)
    selected = _unique_strings(declared_surfaces)
    if expected is None or selected is None or not isinstance(files, Mapping):
        return False
    file_paths = tuple(
        surface.removeprefix("file:") for surface in selected
        if surface.startswith("file:")
    )
    return (len(file_paths) == len(set(file_paths))
            and set(file_paths) == set(expected)
            and all(path in files for path in expected))


def _surface_index(discovered: Any) -> dict[str, frozenset[str]] | None:
    """Validate every discovered surface once and group the identifiers by owning path.

    The mapping holds every surface of the repository, and each route of each object
    asks for the surfaces of a few owned files. Validating and bucketing the whole
    denominator once keeps that question proportional to the owned files instead of
    to the repository. A malformed row refuses the whole denominator, as before.
    """
    if not isinstance(discovered, Mapping):
        return None
    by_path: dict[str, set[str]] = {}
    for identifier, row in discovered.items():
        if (type(identifier) is not str or not identifier
                or type(row) is not dict
                or row.get("surface_id") != identifier
                or type(row.get("path")) is not str
                or not row["path"]):
            return None
        by_path.setdefault(row["path"], set()).add(identifier)
    return {path: frozenset(identifiers) for path, identifiers in by_path.items()}


def _expected_declared_surfaces(discovered: Any, owned_paths: set[str],
                                *, index: Mapping[str, frozenset[str]] | None = None
                                ) -> set[str] | None:
    if (type(owned_paths) is not set or not owned_paths
            or any(type(path) is not str or not path for path in owned_paths)):
        return None
    if index is None:
        index = _surface_index(discovered)
        if index is None:
            return None
    expected: set[str] = set()
    for path in owned_paths:
        expected.update(index.get(path, ()))
    return expected or None


def _declared_surface_denominator_matches(declared_surfaces: Any,
                                          discovered: Any,
                                          owned_paths: set[str],
                                          *, index: Mapping[str, frozenset[str]] | None = None
                                          ) -> bool:
    """The one predicate used by interface coverage and its surface probes."""
    selected = _unique_strings(declared_surfaces)
    expected = _expected_declared_surfaces(discovered, owned_paths, index=index)
    return selected is not None and expected is not None and set(selected) == expected


def _control_evidence(control: str, predicate: str, baseline: bool,
                      denominator: Mapping[str, Any],
                      probes: list[tuple[str, Any, bool]]) -> dict[str, Any]:
    rows = [
        {
            "mutation": mutation,
            "candidate_digest": value_digest(candidate),
            "accepted": accepted,
            "status": "FAIL" if accepted else "PASS",
        }
        for mutation, candidate, accepted in probes
    ]
    status = "PASS" if baseline and all(row["status"] == "PASS" for row in rows) else "FAIL"
    return {
        "schema": _NEGATIVE_CONTROL_SCHEMA,
        "control": control,
        "predicate": predicate,
        "status": status,
        "baseline": {"accepted": baseline, "status": "PASS" if baseline else "FAIL"},
        "probes": rows,
        "denominator_digest": value_digest(dict(denominator)),
    }


def _owned_path_negative_control(owned_paths: Any, declared_surfaces: Any,
                                 files: Mapping[str, str]) -> dict[str, Any]:
    """Execute omission and substitution against the admission predicate itself."""
    baseline = _owned_path_denominator_matches(owned_paths, declared_surfaces, files)
    selected = list(_unique_strings(declared_surfaces) or ())
    expected = list(_unique_strings(owned_paths) or ())
    target = "file:" + expected[0] if expected else None
    if target not in selected:
        target = next((surface for surface in selected if surface.startswith("file:")), None)
    omitted = list(selected)
    if target in omitted:
        omitted.remove(target)
    duplicated = [*selected, target] if target is not None else ["file:invalid", "file:invalid"]
    substitute_path = "__vstd_negative_control_substitution__.py"
    while substitute_path in files or substitute_path in set(expected):
        substitute_path = "_" + substitute_path
    substituted = [
        "file:" + substitute_path if surface == target else surface
        for surface in selected
    ]
    substituted_files = dict(files)
    original_path = target.removeprefix("file:") if target is not None else None
    substituted_files[substitute_path] = files.get(original_path, "sha256:" + "0" * 64)
    cases = [
        ("OMITTED", {"surfaces": omitted},
         _owned_path_denominator_matches(owned_paths, omitted, files)),
        ("EMPTY", {"surfaces": []},
         _owned_path_denominator_matches(owned_paths, [], files)),
        ("MALFORMED", {"surfaces": [None]},
         _owned_path_denominator_matches(owned_paths, [None], files)),
        ("DUPLICATED", {"surfaces": duplicated},
         _owned_path_denominator_matches(owned_paths, duplicated, files)),
        ("DIGEST_PRESERVING_SUBSTITUTION", {
            "surfaces": substituted,
            "substituted_path": substitute_path,
            "substituted_sha256": substituted_files[substitute_path],
        }, _owned_path_denominator_matches(owned_paths, substituted, substituted_files)),
    ]
    return _control_evidence(
        "missing_owned_source_refused",
        "_owned_path_denominator_matches",
        baseline,
        {"owned_paths": owned_paths, "declared_surfaces": declared_surfaces},
        cases,
    )


def _declared_surface_negative_control(declared_surfaces: Any, discovered: Any,
                                       owned_paths: set[str],
                                       *, index: Mapping[str, frozenset[str]] | None = None
                                       ) -> dict[str, Any]:
    """Execute omission and metadata substitution against the interface predicate."""
    if index is None:
        index = _surface_index(discovered)
    baseline = _declared_surface_denominator_matches(
        declared_surfaces, discovered, owned_paths, index=index)
    selected = list(_unique_strings(declared_surfaces) or ())
    expected = _expected_declared_surfaces(discovered, owned_paths, index=index) or set()
    target = sorted(expected)[0] if expected else (selected[0] if selected else None)
    omitted = list(selected)
    if target in omitted:
        omitted.remove(target)
    duplicated = [*selected, target] if target is not None else ["invalid", "invalid"]
    substitute = "surface:__vstd_negative_control_substitution__"
    while substitute in expected or substitute in selected:
        substitute = "_" + substitute
    substituted = [substitute if surface == target else surface for surface in selected]
    cases = [
        ("OMITTED", {"surfaces": omitted},
         _declared_surface_denominator_matches(
             omitted, discovered, owned_paths, index=index)),
        ("EMPTY", {"surfaces": []},
         _declared_surface_denominator_matches(
             [], discovered, owned_paths, index=index)),
        ("MALFORMED", {"surfaces": [None]},
         _declared_surface_denominator_matches(
             [None], discovered, owned_paths, index=index)),
        ("DUPLICATED", {"surfaces": duplicated},
         _declared_surface_denominator_matches(
             duplicated, discovered, owned_paths, index=index)),
        ("DIGEST_PRESERVING_SUBSTITUTION", {
            "surfaces": substituted,
            "owned_paths": sorted(owned_paths),
        }, _declared_surface_denominator_matches(
             substituted, discovered, owned_paths, index=index)),
    ]
    return _control_evidence(
        "omitted_surface_refused",
        "_declared_surface_denominator_matches",
        baseline,
        {"owned_paths": sorted(owned_paths), "declared_surfaces": declared_surfaces,
         "expected_surfaces": sorted(expected)},
        cases,
    )


class SourceContractAssessment:
    """One immutable source/discovery snapshot shared by all adapted routes."""

    def __init__(self, root: Path, objects: tuple[NamespaceObject, ...],
                 kinds: KindRequirements) -> None:
        self.root = root.resolve(strict=True)
        self.objects = {item.object_id: item for item in objects}
        self.collection_digest = composition_digest(objects)
        self.kinds = kinds
        self.declarations = kinds.declarations
        self.documented_obligation_retention_keys = (
            _documented_obligation_retention_keys(self.root, self.declarations)
        )
        self.reviews = _review_catalog()
        self.files = {row["path"]: row["sha256"] for row in kinds.census["files"]}
        observed = kinds.observed
        self.discovered = {row["surface_id"]: row for row in observed["surfaces"]}
        self._surface_paths = _surface_index(self.discovered)
        self.all_declared_surfaces: set[str] = set()
        for row in self.declarations.values():
            selected = _unique_strings(row.get("surfaces")) if type(row) is dict else None
            if selected is not None:
                self.all_declared_surfaces.update(selected)
        self.gaps_by_path: dict[str, list[dict[str, Any]]] = {}
        for gap in observed["gaps"]:
            self.gaps_by_path.setdefault(gap["path"], []).append(gap)
        self.imports_by_path: dict[str, list[dict[str, Any]]] = {}
        for row in observed["source_import_bindings"]:
            path = self.discovered[row["surface_id"]]["path"]
            self.imports_by_path.setdefault(path, []).append(row)
        self.exports_by_path: dict[str, list[dict[str, Any]]] = {}
        for row in observed["export_bindings"]:
            path = self.discovered[row["surface_id"]]["path"]
            self.exports_by_path.setdefault(path, []).append(row)
        self._cache: dict[tuple[str, str, int], dict[str, Any]] = {}
        # Native route declarations are installed-process state for the life of
        # this immutable source snapshot.  Build their validated index lazily:
        # source-only routes never need it, while package replay may ask the
        # same question thousands of times across object instances.
        self._core_runtime_route_cells: dict[
            tuple[str, int, str], list[tuple[dict[str, Any], dict[str, Any]]]
        ] | None = None
        self._core_runtime_route_declarations: dict[
            tuple[str, int, str], dict[str, Any]
        ] | None = None
        self._core_runtime_public_routes: dict[
            tuple[str, int, str], list[dict[str, Any]]
        ] | None = None

    def _installed_core_runtime_routes(self) -> tuple[
        dict[tuple[str, int, str], list[tuple[dict[str, Any], dict[str, Any]]]],
        dict[tuple[str, int, str], dict[str, Any]],
    ]:
        """Return one assessment-local, fully validated core route index."""

        if (
            self._core_runtime_route_cells is None
            or self._core_runtime_route_declarations is None
        ):
            from verifier.runtime import core_tier_progression

            inventory = core_tier_progression.installed_core_route_inventory()
            declarations = core_tier_progression.installed_core_route_declarations()
            cells: dict[
                tuple[str, int, str],
                list[tuple[dict[str, Any], dict[str, Any]]],
            ] = {}
            for cell in inventory["family_cells"]:
                for route in cell["registered_route_memberships"]:
                    key = cell["object_kind"], cell["tier"], route["coordinate"]
                    cells.setdefault(key, []).append((cell, route))
            # Cache the readable facade beside the production-shape index.
            # This is validation authority only; the enclosing preflight cell
            # remains the source of selected kind/tier.
            from verifier.runtime import manifest_gate

            public: dict[
                tuple[str, int, str], list[dict[str, Any]]
            ] = {}
            for route in manifest_gate.obligation_catalog():
                key = (
                    route.get("object_kind"),
                    route.get("tier"),
                    route.get("coordinate"),
                )
                if key in cells:
                    public.setdefault(key, []).append(route)
            # Treat the three related views as one immutable snapshot.  A
            # facade-build exception must not leave the production cells and
            # declarations installed without their whole-row validation view;
            # the next call must be able to rebuild all three from scratch.
            if any(len(public.get(key, [])) != 1 for key in cells):
                raise ValueError("INSTALLED_CORE_RUNTIME_FACADE_DIFFERS")
            self._core_runtime_route_cells = cells
            self._core_runtime_route_declarations = declarations
            self._core_runtime_public_routes = public
        return (
            self._core_runtime_route_cells,
            self._core_runtime_route_declarations,
        )

    def _base(self, item: NamespaceObject) -> tuple[dict[str, Any], dict[str, Any], set[str], list[str]]:
        declaration = self.declarations[item.object_id]
        review = self.reviews.get(item.object_id)
        errors: list[str] = []
        if type(review) is not dict:
            return declaration, {}, set(), ["installed object review is absent"]
        owned_paths = review.get("owned_paths")
        selected_paths = _unique_strings(owned_paths)
        paths = set(selected_paths or ())
        scope_values = review.get("classification_scope_paths", owned_paths)
        selected_scope = _unique_strings(scope_values)
        scope_paths = set(selected_scope or ())
        declared_kind = declaration.get("kind")
        expected_base = (ancestors(self.kinds.registry, declared_kind)[-1]
                         if type(declared_kind) is str and declared_kind in self.kinds.registry
                         else None)
        if review.get("primary_kind") != declared_kind or item.kind.value != expected_base:
            errors.append("reviewed primary kind differs")
        if not _owned_path_denominator_matches(
                owned_paths, declaration.get("surfaces"), self.files):
            errors.append("reviewed owned-file denominator differs")
        if not scope_paths or not scope_paths <= paths:
            errors.append("reviewed classification scope differs")
        if paths and any(path not in self.files for path in paths):
            errors.append("reviewed source is absent from the current census")
        return declaration, review, paths, errors

    def _reviewed_conditional_kind_refutation(
        self,
        item: NamespaceObject,
        kind: str,
    ) -> dict[str, Any] | None:
        """Bind one hinted kind's non-trigger without erasing its denominator.

        Namespace discovery deliberately retains source hints after a clean
        ``DOES_NOT_APPLY`` because static discovery cannot establish universal
        semantic absence.  A package route asks a narrower question: whether
        this exact source representation is the conditional retained-domain
        subject.  The installed review may answer that question only when its
        negative cell, current evidence, source ownership, and conditional
        requirement basis all agree exactly.
        """

        declaration, review, paths, errors = self._base(item)
        if errors or kind not in self.kinds.kinds(item.object_id):
            return None
        try:
            basis = self.kinds.basis(item.object_id, kind)
        except (KeyError, TypeError, ValueError, AttributeError):
            return None
        classified = getattr(self.kinds, "objects", {}).get(item.object_id, {})
        assessment_rows = classified.get("classification", [])
        assessed = next(
            (
                row for row in assessment_rows
                if type(row) is dict and row.get("kind") == kind
            ),
            None,
        )
        basis_reasons = basis.get("reasons") if type(basis) is dict else None
        actual = declaration.get("classification", {}).get(kind)
        retention_only = bool(
            type(assessed) is dict
            and assessed.get("detail_profile")
                == "DOCUMENTED_APPLIES_RETENTION"
            and assessed.get("reason_decision") == "APPLIES"
            and assessed.get("reason_status") == "DOCUMENTED"
            and assessed.get("semantic_classification_status")
                == "NOT_ESTABLISHED"
            and assessed.get("declared") is False
            and assessed.get("source_declared") is False
            and type(basis_reasons) is list
            and basis_reasons
            and all(
                type(reason) is str
                and reason.startswith((
                    "reasons.vstd: APPLIES;",
                    "Unrefuted source hint at ",
                    "Repository selected ",
                ))
                for reason in basis_reasons
            )
        )
        nonstructural_retention = bool(
            type(assessed) is dict
            and assessed.get("decision") == "APPLIES"
            and assessed.get("support_status") == "PASS"
            and assessed.get("source_declared") is False
            and assessed.get("non_applicability") == "NOT_ESTABLISHED"
            and assessed.get("semantic_classification_status")
                == "NOT_ESTABLISHED"
            and namespace_consequences.is_nonstructural_role_decision(
                item.object_id, kind, actual,
            )
        )
        if (
            type(basis) is not dict
            or basis.get("kind") != kind
            or (
                basis.get("necessity") != "CONDITIONAL_UNRESOLVED"
                and not retention_only
                and not nonstructural_retention
            )
            or declaration.get("kind") == kind
            or (
                kind in declaration.get("specializations", [])
                and not nonstructural_retention
            )
        ):
            return None
        documented_refutation = False
        if type(assessed) is dict:
            documented_refutation = bool(
                assessed.get("decision") == "DOES_NOT_APPLY"
                and assessed.get("support_status") == "PASS"
                and assessed.get("non_applicability") == "DOCUMENTED"
                and assessed.get("refutation_status") == "DOCUMENTED"
                and assessed.get("refutation_code")
                    == "DOCUMENTED_BOUNDED_ABSENCE"
                and type(assessed.get("refutation_receipt_digest")) is str
                and assessed["refutation_receipt_digest"].startswith("sha256:")
                and assessed.get("semantic_classification_status")
                    == "NOT_ESTABLISHED"
            )
        if (
            not documented_refutation
            and not retention_only
            and not nonstructural_retention
        ):
            return None
        allowed_statuses = (
            {"APPLIES"}
            if nonstructural_retention else
            {"DOES_NOT_APPLY"}
            if documented_refutation else
            {"UNRESOLVED", "DOES_NOT_APPLY"}
        )
        if (
            type(actual) is not dict
            or actual.get("status") not in allowed_statuses
            or type(actual.get("reason")) is not str
            or not actual["reason"].strip()
        ):
            return None
        evidence = actual.get("evidence")
        expected_paths = {
            row.get("path") for row in evidence
        } if type(evidence) is list else set()
        selected_scope = _unique_strings(
            review.get("classification_scope_paths", review.get("owned_paths"))
        )
        classification_scope = set(selected_scope or ())
        if not classification_scope or not classification_scope <= paths:
            return None
        if documented_refutation and (
            not expected_paths
            or not expected_paths <= classification_scope
            or not _evidence_matches(evidence, expected_paths, self.files)
        ):
            return None
        decision = {
            "object_id": item.object_id,
            "object_digest": item.digest,
            "kind": kind,
            "status": actual["status"],
            "reason": actual["reason"],
            "evidence": evidence,
            "requirement_basis": basis,
            "classification_assessment": assessed,
            "decision_type": (
                "DOCUMENTED_DOES_NOT_APPLY"
                if documented_refutation
                else "NONSTRUCTURAL_ROLE_RETENTION"
                if nonstructural_retention
                else "DOCUMENTED_APPLIES_RETENTION"
            ),
            "source_census_digest": self.kinds.report["source_census_digest"],
        }
        return {
            **decision,
            "decision_digest": value_digest(decision),
        }

    def _kind_facets(self, declaration: Mapping[str, Any], review: Mapping[str, Any],
                     paths: set[str], kind: str, errors: list[str]) -> list[str]:
        covered: list[str] = []
        if kind not in _ADDED:
            if kind != "OBJECT" and declaration.get("kind") != kind:
                selected = declaration.get("classification", {}).get(kind)
                selected_paths = {
                    row.get("path") for row in selected.get("evidence", [])
                } if type(selected) is dict else set()
                if (type(selected) is not dict
                        or selected.get("status") != "APPLIES"
                        or type(selected.get("reason")) is not str
                        or not selected["reason"].strip()
                        or not selected_paths
                        or not selected_paths <= paths
                        or not _evidence_matches(
                            selected.get("evidence"), selected_paths, self.files
                        )):
                    errors.append(
                        "legacy cross-root source classification is not current and owned"
                    )
            # Legacy namespace contracts intentionally have no native 0.x
            # obligations.  Their source routes instead cover the explicit,
            # adapter-owned SOURCE-0.1 proposition; this is source admission,
            # never repository-wide Tier 0 credit.
            covered.extend(_validate_admission_ledger(_admission_contract(kind)))
            return covered
        expected = review.get("classification", {}).get(kind)
        actual = declaration.get("classification", {}).get(kind)
        if type(expected) is not dict or expected.get("status") != "APPLIES":
            errors.append("installed review does not make this added kind applicable")
            return covered
        expected_paths = set(expected.get("evidence_paths", []))
        expected_reason = namespace_consequences.compiled_classification_reason(
            expected.get("status"), expected.get("reason")
        )
        if (type(actual) is not dict or actual.get("status") != "APPLIES"
                or actual.get("reason") != expected_reason
                or not _evidence_matches(actual.get("evidence"), expected_paths, self.files)):
            errors.append("selected applicability decision differs from the installed review")
        if not expected_paths or not expected_paths <= paths:
            errors.append("kind evidence is outside the reviewed source owner")
        declarations = review.get("declarations", {})
        obligations = declaration.get("obligations", {})
        contract = namespace_registry()[kind]
        for obligation in contract.obligations:
            covered.append(obligation.id)
            expected_declaration = declarations.get(obligation.id)
            selected = obligations.get(obligation.id)
            if (type(expected_declaration) is not dict or type(selected) is not dict
                    or selected.get("declaration") != expected_declaration
                    or type(selected.get("reason")) is not str
                    or not selected["reason"].strip()
                    or not _evidence_matches(selected.get("evidence"), expected_paths, self.files)):
                errors.append("reviewed obligation differs: " + obligation.id)
        return covered

    def _interfaces(self, declaration: Mapping[str, Any], paths: set[str],
                    errors: list[str]) -> dict[str, int]:
        expected = _expected_declared_surfaces(
            self.discovered, paths, index=self._surface_paths) or set()
        selected_values = _unique_strings(declaration.get("surfaces"))
        selected = set(selected_values or ())
        if not _declared_surface_denominator_matches(
                declaration.get("surfaces"), self.discovered, paths,
                index=self._surface_paths):
            errors.append("discovered source-interface denominator differs")
        owned_gaps = [gap for path in paths for gap in self.gaps_by_path.get(path, [])]
        if owned_gaps:
            errors.append(_OWNED_GAPS_UNRESOLVED)
        imports = [row for path in paths for row in self.imports_by_path.get(path, [])]
        exports = [row for path in paths for row in self.exports_by_path.get(path, [])]
        for row in imports + exports:
            target = self.discovered.get(row["target_surface_id"])
            if (row["surface_id"] not in selected
                    or row["target_surface_id"] not in self.all_declared_surfaces
                    or target is None
                    or row["target_source_digest"] != self.files.get(target["path"])):
                errors.append("source import/export binding differs")
                break
        return {"surface_count": len(expected), "import_count": len(imports),
                "export_count": len(exports), "owned_gap_count": len(owned_gaps)}

    def _statics(self, declaration: Mapping[str, Any], review: Mapping[str, Any],
                 paths: set[str], kind: str, errors: list[str]) -> dict[str, Any]:
        decisions = declaration.get("classification", {})
        expected_decisions = review.get("classification", {})
        compiled_consequence_kinds = _compiled_consequence_kinds(declaration)
        object_id = declaration.get("object_id")
        documented_retention_kinds = {
            retained_kind
            for retained_object, retained_kind in
            self.documented_obligation_retention_keys
            if retained_object == object_id
        }
        nonlocal_role_kinds = (
            compiled_consequence_kinds | documented_retention_kinds
        )
        scope_values = review.get(
            "classification_scope_paths", review.get("owned_paths")
        )
        selected_scope = _unique_strings(scope_values)
        classification_scope = set(selected_scope or ())
        if not classification_scope or not classification_scope <= paths:
            errors.append("reviewed classification scope differs")
        for reviewed_kind, expected in expected_decisions.items():
            if reviewed_kind in nonlocal_role_kinds:
                continue
            actual = decisions.get(reviewed_kind)
            expected_paths = set(expected.get("evidence_paths", []))
            expected_reason = namespace_consequences.compiled_classification_reason(
                expected.get("status"), expected.get("reason")
            )
            if not expected_paths <= classification_scope:
                errors.append(
                    "classification evidence is outside the reviewed semantic scope: "
                    + reviewed_kind
                )
            if _is_open_cell(actual) and (
                    expected.get("status") != "UNRESOLVED"
                    or actual.get("reason") != expected_reason):
                # Either the review answered a question the manifest still holds open,
                # or both sides are unanswered and only the review words it afresh.
                errors.append(_UNADOPTED_ANSWER + reviewed_kind)
            elif (type(actual) is not dict or actual.get("status") != expected.get("status")
                    or actual.get("reason") != expected_reason
                    or not _evidence_matches(actual.get("evidence"), expected_paths, self.files)):
                errors.append("complete installed classification review differs: " + reviewed_kind)
        expected_specializations = sorted(
            name for name, row in expected_decisions.items()
            if row.get("status") == "APPLIES"
            and name != declaration.get("kind")
            and name not in nonlocal_role_kinds
        )
        selected_specializations = declaration.get("specializations")
        if (type(selected_specializations) is not list
                or any(type(name) is not str for name in selected_specializations)
                or len(selected_specializations) != len(set(selected_specializations))):
            errors.append("reviewed specialization set differs")
        else:
            # A label the review does not support is only unadopted while its own cell
            # is still open; a missing reviewed label or a label whose cell answers
            # otherwise is a contradiction.
            selected_local_specializations = (
                set(selected_specializations) - nonlocal_role_kinds
            )
            extra = sorted(
                selected_local_specializations - set(expected_specializations)
            )
            unadopted = [name for name in extra if _is_open_cell(decisions.get(name))]
            missing = set(expected_specializations) - selected_local_specializations
            if missing or len(unadopted) != len(extra):
                errors.append("reviewed specialization set differs")
            errors.extend(_UNADOPTED_LABEL + name for name in unadopted)

        # Execute mutations through the same predicates used by _base and
        # _interfaces. Typed evidence records both the accepted baseline and
        # every refused candidate; a missing or malformed denominator therefore
        # fails the control instead of making a tautological boolean true.
        controls = {
            "missing_owned_source_refused": _owned_path_negative_control(
                review.get("owned_paths"), declaration.get("surfaces"), self.files),
            "omitted_surface_refused": _declared_surface_negative_control(
                declaration.get("surfaces"), self.discovered, paths,
                index=self._surface_paths),
        }
        if any(row["status"] != "PASS" for row in controls.values()):
            errors.append("source-contract negative control unavailable")
        return {
            "negative_controls": controls,
            "reviewed_kind_count": len(expected_decisions),
            "reviewed_path_count": len(paths),
            "classification_scope_path_count": len(classification_scope),
            "compiled_consequence_roles": sorted(compiled_consequence_kinds),
            "documented_obligation_retention_roles": sorted(
                documented_retention_kinds
            ),
        }

    def evaluate(self, item: NamespaceObject, route: Mapping[str, Any]) -> dict[str, Any]:
        if not is_route(route):
            raise ValueError("PACKAGE_SOURCE_CONTRACT_ROUTE_DIFFERS")
        key = item.object_id, route["object_kind"], route["tier"]
        cached = self._cache.get(key)
        if cached is not None:
            return deepcopy(cached)
        declaration, review, paths, errors = self._base(item)
        covered = self._kind_facets(declaration, review, paths, route["object_kind"], errors)
        route_covered = _validate_admission_ledger(
            route["covered_admission_obligations"]
        )
        # JSON Schema owns row shape. Runtime owns the semantic equality to the
        # installed catalog: an extra otherwise-complete row is still refused.
        if covered != route_covered:
            errors.append("source-route admission denominator differs")
        observations: dict[str, Any] = {
            "owned_path_count": len(paths),
            "source_census_digest": self.kinds.report["source_census_digest"],
        }
        if route["tier"] >= 2:
            observations.update(self._interfaces(declaration, paths, errors))
        if route["tier"] >= 3:
            observations.update(self._statics(declaration, review, paths,
                                              route["object_kind"], errors))
        # An unresolved discovery gap means the census cannot enumerate what
        # dynamic construction might expose: the claim is unestablished, not
        # refuted. It stays UNKNOWN unless a different error actually refutes
        # the route, so it never hides a real refutation and never stops the
        # higher package gates the way a contradicted lower gate does.
        refuted = any(not _is_unestablished(error) for error in errors)
        result = {
            "status": "FAIL" if refuted else "UNKNOWN" if errors else "PASS",
            "evidence_origin": "INSTALLED_SOURCE_REVIEW_AND_FRESH_DISCOVERY",
            "object_id": item.object_id,
            "object_digest": item.digest,
            "collection_digest": self.collection_digest,
            "reason": "; ".join(errors) if errors else route["exact_claim"],
            "applicability_established": not errors,
            "applicability_reason": (
                "The exact installed review classifies this object/kind variant as a "
                "source-owned package representation and binds its complete current "
                "owned-source denominator."
            ),
            "adapter": ADAPTER,
            "coordinate": route["coordinate"],
            "covered_admission_obligations": deepcopy(
                route["covered_admission_obligations"]
            ),
            "review_digest": value_digest(review) if review else None,
            "observations": observations,
            "claim_boundary": (
                "Exact Verifier source-representation conformance at the selected tier, "
                "bounded to the installed review and current source. It does not establish "
                "typed composition (checked separately at the package graph gate), Facets, "
                "Dynamics, or Statics behavioral conformance, kind semantics, a retained "
                "runtime-domain instance, physical or financial effect, external "
                "authority, release, or deployment."
            ),
        }
        result["result_digest"] = value_digest(result)
        self._cache[key] = result
        return deepcopy(result)

    def refute_native_runtime_variant(
        self,
        item: NamespaceObject,
        route: Mapping[str, Any],
        *,
        object_kind: str | None = None,
        tier: int | None = None,
    ) -> dict[str, Any] | None:
        """Prove a non-source variant condition false only after adaptation PASS.

        Native retained records and implementation-specific execution routes
        have different triggers.  The former requires a runtime-domain subject;
        the latter requires ownership of one exact installed implementation.
        Both refutations remain explicit, digest-bound applicability evidence.
        """
        # A source adaptation may refute only a route whose installed
        # declaration actually admits a conditional variant.  Valid-looking
        # caller prose and a self-consistent digest do not create that
        # authority, and a NECESSARY route can never be converted into a
        # non-trigger here.
        try:
            if not can_refute_native_runtime_variant(route):
                return None
            route_applicability = validate_applicability_binding(route)
        except (TypeError, ValueError):
            return None

        # Core preflight deliberately keeps family identity on the enclosing
        # cell, while the public catalog repeats it on each readable route.
        # Accept either representation only after binding the selected cell to
        # the exact installed route.  An embedded kind/tier may confirm that
        # binding, but it may never override it.
        selected_kind = (
            object_kind if type(object_kind) is str else route.get("object_kind")
        )
        selected_tier = tier if type(tier) is int else route.get("tier")
        if type(selected_kind) is not str or type(selected_tier) is not int:
            return None
        if (
            ("object_kind" in route and route.get("object_kind") != selected_kind)
            or ("tier" in route and route.get("tier") != selected_tier)
        ):
            return None

        from verifier.runtime import (
            added_kind_behavioral_routes,
            package_execution,
        )
        execution = None
        try:
            execution = package_execution.route_mechanism(dict(route))
        except ValueError:
            return None
        if execution is None and added_kind_behavioral_routes.is_route(route):
            # The aggregate catalog contains three exact installed adapter
            # families: its legacy default, agency-surface, and POLICY.  The
            # family-specific adapter identifiers are intentional and are not
            # weaker authority.  Recognize the canonical row through the
            # catalog's own exact matcher before deciding whether this source
            # representation refutes the retained runtime variant.
            canonical_added = [
                candidate for candidate in added_kind_behavioral_routes.catalog()
                if candidate.get("obligation_id") == route.get("obligation_id")
            ]
            if len(canonical_added) != 1:
                return None
            expected = dict(canonical_added[0])
            expected["applicability_digest"] = applicability_digest(
                expected["applicability"]
            )
            if dict(route) != expected:
                return None
        elif execution is None:
            core_routes, core_declarations = self._installed_core_runtime_routes()
            key = selected_kind, selected_tier, route.get("coordinate")
            candidates = core_routes.get(key, [])
            if len(candidates) != 1:
                return None
            cell, canonical_route = candidates[0]
            canonical_declaration = core_declarations.get(key)
            if type(canonical_declaration) is not dict:
                return None
            production_route = {**canonical_route, **canonical_declaration}
            if dict(route) != production_route:
                # The public manifest catalog is a readable, fully enriched
                # view of this same installed route.  Its additional name and
                # exact-claim fields are accepted only by whole-row equality;
                # arbitrary extra keys or count-preserving field swaps are not.
                public_candidates = (
                    self._core_runtime_public_routes or {}
                ).get(key, [])
                if len(public_candidates) != 1 or dict(route) != public_candidates[0]:
                    return None
        declaration = self.declarations[item.object_id]
        classification_refutation = None
        if execution is not None:
            # Execution routes select one exact installed implementation, not
            # every implementation of their broad role.  Establish this
            # object's reviewed source identity through its primary kind, then
            # decide the route trigger directly from exact file ownership.  A
            # real MEASUREMENT or TRANSACTION role therefore remains real while
            # a different implementation-specific proposition is NOT_TRIGGERED.
            source_route = _CATALOG.get((declaration.get("kind"), selected_tier))
            if (
                source_route is None
                or not applies_to(item, declaration, source_route, self.kinds)
            ):
                return None
        else:
            source_route = _CATALOG.get((selected_kind, selected_tier))
            if source_route is None or not applies_to(
                    item, declaration, source_route, self.kinds):
                classification_refutation = (
                    self._reviewed_conditional_kind_refutation(
                        item, selected_kind,
                    )
                )
                source_route = _CATALOG.get(
                    (declaration.get("kind"), selected_tier)
                )
                if (
                    classification_refutation is None
                    or source_route is None
                    or not applies_to(
                        item, declaration, source_route, self.kinds
                    )
                ):
                    return None
        adapted = self.evaluate(item, source_route)
        if adapted["status"] != "PASS":
            return None
        if classification_refutation is not None:
            if (
                classification_refutation["decision_type"]
                == "DOCUMENTED_DOES_NOT_APPLY"
            ):
                decision_reason = (
                    "its current source-bound DOES_NOT_APPLY decision proves that "
                    "it is not"
                )
            elif (
                classification_refutation["decision_type"]
                == "NONSTRUCTURAL_ROLE_RETENTION"
            ):
                decision_reason = (
                    "its exact compiled demand-retention decision keeps the role's "
                    "obligations without structural role evidence, so it does not "
                    "select"
                )
            else:
                decision_reason = (
                    "the sole reasons ledger retains assessment without adopting "
                    "that source role, so it does not select"
                )
            reason = (
                "The exact reviewed source representation retains this "
                f"{selected_kind} obligation in the denominator, but "
                + decision_reason
                + " the conditional retained runtime-domain subject required by "
                  "this native route. Its declared-kind source adaptation passed at "
                + source_route["obligation_id"] + ". This is a route-specific "
                  "non-trigger, not a claim that source discovery or reasons erased "
                  "the obligation."
            )
        elif execution is not None:
            object_declaration = declaration
            if package_execution.owns_route_implementation(
                object_declaration, dict(route)
            ):
                return None
            reason = (
                "The exact reviewed source representation does not own the installed "
                f"{execution.IMPLEMENTATION} implementation required by this finite "
                "execution route. Its necessary source adaptation passed at "
                + source_route["obligation_id"] + ". This refutes only the named "
                  "implementation-specific route; it does not discharge the applicable "
                  "obligation family for another implementation variant."
            )
        else:
            reason = (
                "The selected package object is the exact reviewed source representation, "
                "not the retained runtime-domain record required by this native route. "
                "Its necessary adaptation passed at " + source_route["obligation_id"] + "."
            )
        result = {
            "status": "PASS",
            "evidence_origin": "INSTALLED_SOURCE_VARIANT_APPLICABILITY_REVIEW",
            "object_id": item.object_id,
            "object_digest": item.digest,
            "collection_digest": self.collection_digest,
            "reason": reason,
            "applicability_established": True,
            "applicability_classification": "CONDITION_NOT_MET",
            "fulfillment_required": False,
            "native_coordinate": route["coordinate"],
            "conditional_coordinate": route["coordinate"],
            "adaptation_obligation_id": source_route["obligation_id"],
            # Bind the complete source assessment, including its own result
            # digest.  Projection already retains this exact value as the
            # companion source row's ``full_check_digest``, so publication can
            # cross-check conditional provenance without another per-row field.
            "adaptation_result_digest": value_digest(adapted),
            "condition": route_applicability["condition"],
            "applicability_digest": route["applicability_digest"],
            "condition_status": "NOT_TRIGGERED",
        }
        if classification_refutation is not None:
            digest_field = (
                "classification_decision_digest"
                if classification_refutation["decision_type"]
                    == "DOCUMENTED_DOES_NOT_APPLY"
                else "applicability_retention_digest"
            )
            result[digest_field] = classification_refutation["decision_digest"]
        return {**result, "result_digest": value_digest(result)}


def source_prefix_satisfies(kind: str, tier: int, clauses: list[dict[str, Any]]) -> bool:
    """Require every cumulative source route; never imply behavioral closure."""
    expected = {_CATALOG[(kind, depth)]["obligation_id"] for depth in range(1, tier + 1)
                if (kind, depth) in _CATALOG}
    selected = {row["obligation_id"] for row in clauses
                if row["obligation_id"] in expected and row["status"] == "PASS"}
    return bool(expected) and selected == expected


# Retain the historical helper name for callers that only ask about the source
# prefix.  Package normative coverage no longer consumes it as whole-contract
# evidence; the installed package-variant profile owns that stronger question.
coverage_satisfies = source_prefix_satisfies


__all__ = [
    "ADAPTER", "SEMANTIC_VERSION", "SourceContractAssessment", "applies_to",
    "can_refute_native_runtime_variant", "catalog", "coverage_satisfies",
    "source_prefix_satisfies", "source_route_for_obligation", "is_route",
]
