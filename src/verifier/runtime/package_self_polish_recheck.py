"""Independent structural recheck for retained package self-polish reports.

The rechecker does not import the package report producer.  It reconstructs
the typed package graph and derives cross-section invariants from retained
bytes.  Its ``PASS`` means only that the retained report is internally
consistent under the current installed mechanisms; it never promotes the
project verdict.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
Verifier Standard (VSTD).
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
import re
from typing import Any

from verifier.core.namespace import (
    NamespaceObject,
    ObjectKind,
    assess_composition,
    composition_digest,
)
from verifier.core.receipt import strict_json_loads
from verifier.domains.contracts import object_facets
from verifier.domains.contracts import typed_facets
from verifier.domains.contracts import verifier_replacement
from verifier.runtime import core_obligation_union
from verifier.runtime import core_tier_progression
from verifier.runtime import package_obligation_candidate
from verifier.runtime import package_owner_decision
from verifier.runtime import polish_requirements
from verifier.runtime import self_polish_native_cases
from verifier.runtime import self_polish_native_full_candidate
from verifier.runtime import self_polish_native_replay
from verifier.runtime import self_polish_tiers
from verifier.runtime import tier_zero


RECHECK_SCHEMA = "verifier-package-graph-self-polish-recheck-1"
REPORT_SCHEMA = "verifier-package-graph-self-polish-assessment-1"
MAX_PACKAGE_REPORT_BYTES = 16 * 1024 * 1024

_REPORT_FIELDS = {
    "schema_version", "status", "project_gate_status", "polished",
    "release_authorized", "source_coordinate", "source_coordinate_digest",
    "source_recapture_binding", "package_graph", "denominators",
    "tier_zero_repository_admission",
    "tier_zero_representation_cells", "native_facets_replay",
    "installed_native_case_replay", "core_installed_inventory_digest",
    "full_native_candidate",
    "candidate_obligation_ledger", "owner_decision_admission",
    "core_route_projection", "core_route_memberships", "core_family_cells",
    "corrigibility_extension_selection", "corrigibility_research_evidence",
    "corrigibility_extension_cells", "self_verifier_tier1", "blockers",
    "mechanism_digest", "claim_boundary", "report_digest",
}
_NULL_WITHOUT_GRAPH = {
    "source_recapture_binding", "denominators",
    "tier_zero_repository_admission", "tier_zero_representation_cells",
    "native_facets_replay", "installed_native_case_replay",
    "full_native_candidate",
    "core_installed_inventory_digest", "candidate_obligation_ledger",
    "owner_decision_admission", "core_route_projection",
    "core_route_memberships", "core_family_cells",
    "corrigibility_extension_selection", "corrigibility_research_evidence",
    "corrigibility_extension_cells",
}
_SOURCE_FIELDS = {
    "source_head",
    "source_tree",
    "source_worktree_status_digest",
    "source_manifest_digest",
}
_GIT_OBJECT = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_NUMERIC_BLOCKER = re.compile(r"NUMERIC_TIER1_BLOCKER:[A-Z][A-Z0-9_]*\Z")
_MEMBER_TIER_INVALIDATORS = frozenset({
    "NATIVE_REPLAY_MECHANISM_UNAVAILABLE",
    "SIM_RESOURCE_ACTUAL_CONSUMPTION_CORRESPONDENCE_NOT_ESTABLISHED",
    "SIM_RESOURCE_COLLECTOR_HONESTY_NOT_ESTABLISHED",
})
_SIM_TIER_INVALIDATORS = frozenset({
    "SIM_RESOURCE_ACTUAL_CONSUMPTION_CORRESPONDENCE_NOT_ESTABLISHED",
    "SIM_RESOURCE_COLLECTOR_HONESTY_NOT_ESTABLISHED",
})
_OUTAGE_MASKABLE_CONTRACT_INVALIDATORS = frozenset({
    "NATIVE_REPLAY_CERTIFICATE_REFUSED",
    "NATIVE_REPLAY_OUTCOME_INVALID",
    "SIM_RESOURCE_UNKNOWN_BOUNDARY_DIFFERS",
})
_KNOWN_BLOCKERS = {
    "CORE_FAMILY_CELL_CLOSURE_NOT_ESTABLISHED",
    "CORE_ROUTE_NATIVE_PROJECTION_FAILED",
    "CORE_ROUTE_NATIVE_PROJECTION_NOT_ESTABLISHED",
    "CORRIGIBILITY_EXTENSION_NOT_ESTABLISHED",
    "PACKAGE_CANDIDATE_EXPECTED_MANIFEST_DIGEST_REQUIRED",
    "PACKAGE_CANDIDATE_SELECTION_INCOMPLETE",
    "PACKAGE_CORE_ROUTE_INVENTORY_CONTRADICTION",
    "PACKAGE_GATE_MECHANISM_RECAPTURE_FAILED",
    "PACKAGE_GATE_MECHANISM_RECAPTURE_UNAVAILABLE",
    "PACKAGE_GRAPH_COMPOSITION_NOT_PASS",
    "PACKAGE_GRAPH_COMPOSITION_FAILED",
    "PACKAGE_GRAPH_NON_GRAPH_KIND_COUNT_DIFFERS",
    "PACKAGE_GRAPH_OBJECT_KIND_CENSUS_DIFFERS",
    "PACKAGE_FULL_NATIVE_CANDIDATE_FAILED",
    "PACKAGE_FULL_NATIVE_CANDIDATE_NOT_PASS",
    "PACKAGE_FULL_NATIVE_CANDIDATE_NOT_SELECTED",
    "PACKAGE_INSTALLED_NATIVE_CASE_REPLAY_FAILED",
    "PACKAGE_INSTALLED_NATIVE_CASE_REPLAY_NOT_PASS",
    "PACKAGE_NATIVE_FACETS_REPLAY_FAILED",
    "PACKAGE_NATIVE_FACETS_REPLAY_NOT_PASS",
    "PACKAGE_OBLIGATION_CANDIDATE_NOT_OWNER_ADOPTED",
    "PACKAGE_OBLIGATION_CANDIDATE_NOT_SELECTED",
    "PACKAGE_OBLIGATION_CANDIDATE_SELECTION_FAILED",
    "PACKAGE_OBLIGATION_CANDIDATE_SEMANTIC_IDENTITY_NOT_ESTABLISHED",
    "PACKAGE_OBLIGATION_CANDIDATE_UNAVAILABLE",
    "PACKAGE_OWNER_DECISION_ADMISSION_FAILED",
    "PACKAGE_OWNER_DECISION_ADMISSION_UNAVAILABLE",
    "PACKAGE_REPORT_TRANSPORT_CAPACITY_EXHAUSTED",
    "PACKAGE_SELF_POLISH_ASSESSMENT_UNAVAILABLE",
    "PACKAGE_SELF_POLISH_CONTRACT_VIOLATION",
    "PACKAGE_SOURCE_COORDINATE_UNAVAILABLE",
    "PACKAGE_SOURCE_RECAPTURE_FAILED",
    "PACKAGE_SOURCE_RECAPTURE_UNAVAILABLE",
    "SELF_VERIFIER_TIER1_FAILED",
    "SELF_VERIFIER_TIER1_NOT_PASS",
    "SELF_VERIFIER_TIER1_REPORT_INVALID",
    "SELF_VERIFIER_TIER1_REPORT_UNAVAILABLE",
    "SELF_VERIFIER_TIER1_SOURCE_DIFFERS",
    "TIER_ZERO_REPRESENTATION_NOT_PASS",
    "TIER_ZERO_OBJECT_ADMISSION_NOT_ESTABLISHED",
    "TIER_ZERO_REPOSITORY_ADMISSION_FAILED",
    "TIER_ZERO_REPOSITORY_ADMISSION_NOT_ESTABLISHED",
    "NUMERIC_SELF_VERIFIER_TIER1_FAILED",
}
_FALLBACK_ROOT_BLOCKERS = {
    "PACKAGE_CORE_ROUTE_INVENTORY_CONTRADICTION",
    "PACKAGE_GRAPH_NON_GRAPH_KIND_COUNT_DIFFERS",
    "PACKAGE_GRAPH_OBJECT_KIND_CENSUS_DIFFERS",
    "PACKAGE_REPORT_TRANSPORT_CAPACITY_EXHAUSTED",
    "PACKAGE_SELF_POLISH_ASSESSMENT_UNAVAILABLE",
    "PACKAGE_SELF_POLISH_CONTRACT_VIOLATION",
    "PACKAGE_SOURCE_COORDINATE_UNAVAILABLE",
}
_FALLBACK_FAILURE_BLOCKERS = {
    "PACKAGE_CORE_ROUTE_INVENTORY_CONTRADICTION",
    "PACKAGE_GRAPH_NON_GRAPH_KIND_COUNT_DIFFERS",
    "PACKAGE_GRAPH_OBJECT_KIND_CENSUS_DIFFERS",
    "PACKAGE_SELF_POLISH_CONTRACT_VIOLATION",
    "NUMERIC_SELF_VERIFIER_TIER1_FAILED",
}
_CLAIM_BOUNDARY = (
    "Recheck PASS establishes internal consistency of the retained report "
    "under the current installed mechanisms only. It reconstructs the typed "
    "graph and reruns the generic, typed, and installed specimen mechanisms; "
    "the retained numeric Tier-1 report, configured-key owner signature, source "
    "observations, the bound Tier-0 report, and candidate card, manifest, and "
    "reason-ledger byte bindings "
    "are shape-, digest-, and pointer-checked but are not independently reread, "
    "rerun, or authenticated. The full native candidate's routes, cases, counts, "
    "digests, and installation boundaries are checked for internal consistency; "
    "its prepared Tier-3-through-9 specimens are not independently rerun. "
    "It does not establish source truth, "
    "candidate semantics, owner real-world authority, or normative closure. "
    "The retained project verdict is preserved; recheck PASS is not package "
    "polish, release, or deployment authority."
)
_PACKAGE_CLAIM_BOUNDARY = (
    "This report keeps structural package representation, the separate tier-zero "
    "admission layer, the 26-by-9 core grid, and the cross-kind corrigibility "
    "extension distinct. Structural PASS grants no semantic obligation, authority, "
    "corrigibility, polished, release, or deployment status."
)
_GRAPH_CLAIM_BOUNDARY = (
    "PASS establishes the exact finite typed composition only; it does not "
    "establish any represented record's semantic truth."
)
_TIER_ZERO_CLAIM_BOUNDARY = (
    "PASS establishes this unique object record's inclusion in the finalized "
    "Tier-0 repository declaration, typed graph composition, and native "
    "facet-checker discrimination only. Payload truth and all Tier-1-plus "
    "object semantics remain NOT_ESTABLISHED."
)
_TIER_ZERO_BINDING_BOUNDARY = (
    "PASS binds one finalized vstd polish 0 repository-admission report to the "
    "selected package source and graph. It does not establish any Tier-1-plus "
    "semantic obligation, package polish, owner authority, release, or deployment."
)
_NATIVE_CLAIM_BOUNDARY = (
    "PASS establishes checker discrimination of exact positive, malformed negative, "
    "and unavailable evidence for the selected generic and typed facet requests. "
    "Payload truth, object profile conformance, normative family closure, and "
    "authority remain NOT_ESTABLISHED."
)
_INSTALLED_CLAIM_BOUNDARY = (
    "PASS establishes installed specimen discrimination for all 82 registered "
    "tier-1 and tier-2 routes. It does not establish that the selected package "
    "graph is a passing instance of those routes."
)
_FULL_NATIVE_CANDIDATE_BOUNDARY = (
    "The candidate covers all registered route specimens at the selected source "
    "coordinate. Tiers 3-9 remain uninstalled, the SIM-2.4 positive case remains "
    "UNKNOWN, and no whole-tier, package, release, or deployment qualification "
    "is established."
)
_PROJECTION_CLAIM_BOUNDARY = (
    "route_identity_projection_status establishes only exact identity projection "
    "for selected native requests and retained specimens. The aggregate status "
    "also includes checker discrimination and installed-specimen outcomes; "
    "unknown_causes attributes those unresolved outcomes without promoting them. "
    "Every route obligation remains UNKNOWN until its semantic instance and "
    "normative family closure are established."
)
_SELF_VERIFIER_CLAIM_BOUNDARY = (
    "PASS binds the selected numeric Tier-1 VERIFIER report only; it does not close "
    "the package graph or any other denominator."
)
_OWNER_CLAIM_BOUNDARY = (
    "PASS authenticates exact adoption of the selected 110 candidate decision "
    "subjects under separately supplied and digest-pinned configured-key policy "
    "bytes. It does not prove personhood, legal authority, candidate truth, "
    "normative closure, corrigibility, release, or deployment authority."
)
_CANDIDATE_PASS_CLAIM_BOUNDARY = (
    "PASS establishes exact byte and coordinate binding of the selected candidate "
    "cards to the installed 408-route registry. Semantic identity is PASS only "
    "when a separately selected reason ledger binds all 408 obligations and 234 "
    "slots to current route, claim, facet, evidence, and executable-mechanism "
    "bytes. Candidate classes, mechanism assessments, reasons, conditions, and "
    "defaults remain INFERRED proposals; owner adoption and normative closure "
    "remain NOT_ESTABLISHED, and every obligation status remains UNKNOWN."
)
_CORRIGIBILITY_RESEARCH_CLAIM_BOUNDARY = (
    "These exact research bytes and the finite VERIFIER-10.1 mechanism are bound "
    "as inputs only. They do not establish any all-kind corrigibility instance, "
    "authority, foresight frontier, or extension qualification."
)
_GRAPH_TEMPLATE: dict[str, tuple[str, str, dict[str, list[str]]]] = {
    "HUMAN": ("vstd-human", "responsible-human", {}),
    "ROLE": ("vstd-role", "package-maintainer-role", {}),
    "OBJECT": ("vstd-package-object", "package-subject", {}),
    "HARDWARE": ("vstd-hardware", "execution-hardware", {}),
    "SPACE": ("vstd-space", "execution-space", {}),
    "TIME": ("vstd-time", "assessment-time", {}),
    "ENV": ("vstd-environment", "execution-environment", {}),
    "DATA": ("vstd-data", "package-data", {}),
    "VERIFIER": (
        "verifier-core-self", "vstd-polish-1-and-package-gate-mechanisms",
        {"harness": ["vstd-harness"]}
    ),
    "ARCH": ("vstd-architecture", "package-architecture", {}),
    "HARNESS": ("vstd-harness", "verification-harness", {}),
    "TOKEN": ("vstd-token", "bounded-token", {}),
    "ACTOR": (
        "vstd-actor", "responsible-actor",
        {"representation": ["vstd-human"], "root_human": ["vstd-human"]},
    ),
    "COLLECTIVE": (
        "vstd-collective", "maintainer-collective", {"roles": ["vstd-role"]}
    ),
    "IDENTITY": (
        "vstd-identity", "actor-role-identity",
        {"actor": ["vstd-actor"], "role": ["vstd-role"]},
    ),
    "OWNER": (
        "vstd-owner", "package-owner-binding",
        {"actor": ["vstd-actor"], "object": ["vstd-package-object"]},
    ),
    "RECEIPT": (
        "vstd-receipt", "assessment-receipt",
        {"hardware": ["vstd-hardware"], "subject": ["vstd-package-object"]},
    ),
    "EVENT": (
        "vstd-event", "polish-assessment-event",
        {
            "meaning": ["vstd-package-object"], "space": ["vstd-space"],
            "time": ["vstd-time"],
        },
    ),
    "BENCH": (
        "vstd-benchmark", "package-benchmark",
        {"data": ["vstd-data"], "verifier": ["verifier-core-self"]},
    ),
    "TRAIN": (
        "vstd-training", "training-representation",
        {
            "arch": ["vstd-architecture"], "bench": ["vstd-benchmark"],
            "data": ["vstd-data"], "events": ["vstd-event"],
        },
    ),
    "HYPER": (
        "vstd-hypergraph", "package-relation",
        {"subjects": ["vstd-package-object", "verifier-core-self"]},
    ),
    "MODEL": (
        "vstd-model", "model-representation",
        {
            "arch": ["vstd-architecture"], "bench": ["vstd-benchmark"],
            "data": ["vstd-data"], "env": ["vstd-environment"],
            "events": ["vstd-event"], "hardware": ["vstd-hardware"],
            "train": ["vstd-training"],
        },
    ),
    "AGENT": (
        "vstd-agent", "agent-representation",
        {
            "env": ["vstd-environment"], "harness": ["vstd-harness"],
            "model": ["vstd-model"],
        },
    ),
    "SIM": (
        "vstd-simulation", "simulation-representation",
        {
            "data": ["vstd-data"], "env": ["vstd-environment"],
            "objects": ["vstd-package-object"],
            "verifier": ["verifier-core-self"],
        },
    ),
    "BOT": (
        "vstd-bot", "situated-agent-representation",
        {
            "agent": ["vstd-agent"], "env": ["vstd-environment"],
            "sim": ["vstd-simulation"],
        },
    ),
    "GRAPH": (
        "vstd-package-graph", "complete-vstd-package-representation", {}
    ),
}


def _package_root() -> Path:
    return Path(__file__).parents[1]


def _valid_source_coordinate(value: Any) -> bool:
    return (
        type(value) is dict
        and set(value) == _SOURCE_FIELDS
        and type(value.get("source_head")) is str
        and _GIT_OBJECT.fullmatch(value["source_head"]) is not None
        and type(value.get("source_tree")) is str
        and _GIT_OBJECT.fullmatch(value["source_tree"]) is not None
        and all(
            type(value.get(name)) is str
            and _SHA256.fullmatch(value[name]) is not None
            for name in (
                "source_worktree_status_digest",
                "source_manifest_digest",
            )
        )
    )


def _blocker_implies_failure(value: str) -> bool:
    if _NUMERIC_BLOCKER.fullmatch(value) is not None:
        return False
    return (
        value in _FALLBACK_FAILURE_BLOCKERS
        or value.endswith("_FAILED")
        or value.endswith("_INVALID")
        or value.endswith("_DIFFERS")
        or "CONTRADICTION" in value
    )


def _check_fallback_report(report: dict[str, Any],
                           invalidators: set[str], *,
                           contract_current: bool) -> None:
    _fail(invalidators,
          all(report.get(field) is None for field in _NULL_WITHOUT_GRAPH),
          "PACKAGE_RECHECK_FALLBACK_SECTION_DIFFERS")
    blockers = report.get("blockers")
    blocker_set = set(blockers) if type(blockers) is list and all(
        type(value) is str for value in blockers
    ) else set()
    fallback_shape_valid = False
    blockers_known = all(
        value in _KNOWN_BLOCKERS
        or _NUMERIC_BLOCKER.fullmatch(value) is not None
        for value in blocker_set
    )
    if type(blockers) is list and len(blockers) == len(blocker_set):
        if not contract_current:
            fallback_shape_valid = bool(blockers)
        else:
            fallback_shape_valid = (
                blockers_known
                and bool(blocker_set & _FALLBACK_ROOT_BLOCKERS)
            )
    _fail(invalidators,
          fallback_shape_valid
              and (not contract_current or (
                  blockers_known
                  and bool(blocker_set & _FALLBACK_ROOT_BLOCKERS)
              )),
          "PACKAGE_RECHECK_BLOCKER_SET_DIFFERS")
    self_verifier = report.get("self_verifier_tier1")
    mechanism = report.get("mechanism_digest")
    self_fields = {
        "status", "retention_status", "report_digest", "source_binding_status",
        "subject", "represented_tiers", "claim_boundary",
    }
    subject = (
        self_verifier.get("subject") if type(self_verifier) is dict else None
    )
    represented_tiers = (
        self_verifier.get("represented_tiers")
        if type(self_verifier) is dict else None
    )
    self_shape_valid = (
        type(self_verifier) is dict
        and set(self_verifier) == self_fields
        and self_verifier.get("claim_boundary")
            == _SELF_VERIFIER_CLAIM_BOUNDARY
        and subject in (
            None,
            {"object_id": "verifier-core-self", "object_kind": "VERIFIER"},
        )
        and type(represented_tiers) is list
        and len(represented_tiers) == len(set(represented_tiers))
        and all(type(value) is int and not isinstance(value, bool)
                and 1 <= value <= 9 for value in represented_tiers)
    )
    self_shape_valid = (
        self_shape_valid
        and self_verifier.get("status")
            in ("PASS", "FAIL", "UNKNOWN", "NOT_ESTABLISHED")
        and self_verifier.get("retention_status")
            in ("RETAINED", "UNAVAILABLE", "NOT_SELECTED", "REJECTED")
        and (
            self_verifier.get("report_digest") is None
            or type(self_verifier.get("report_digest")) is str
            and _SHA256.fullmatch(self_verifier["report_digest"]) is not None
        )
    )
    retention_status = (
        self_verifier.get("retention_status")
        if type(self_verifier) is dict else None
    )
    numeric_failed = (
        type(self_verifier) is dict
        and self_verifier.get("status") == "FAIL"
        and retention_status in ("RETAINED", "UNAVAILABLE")
    )
    self_shape_valid = self_shape_valid and (
        (
            retention_status == "REJECTED"
            and self_verifier.get("status") == "FAIL"
            and self_verifier.get("source_binding_status")
                in ("FAIL", "NOT_ESTABLISHED")
            and subject is None
            and represented_tiers == []
            and "NUMERIC_SELF_VERIFIER_TIER1_FAILED" not in blocker_set
            and bool(blocker_set & {
                "SELF_VERIFIER_TIER1_REPORT_INVALID",
                "SELF_VERIFIER_TIER1_SOURCE_DIFFERS",
            })
        ) or (
            retention_status == "NOT_SELECTED"
            and self_verifier.get("status") == "NOT_ESTABLISHED"
            and self_verifier.get("source_binding_status") != "PASS"
            and represented_tiers == []
            and "NUMERIC_SELF_VERIFIER_TIER1_FAILED" not in blocker_set
        ) or (
            retention_status == "UNAVAILABLE"
            and self_verifier.get("status") in ("FAIL", "UNKNOWN")
            and self_verifier.get("source_binding_status") != "PASS"
            and represented_tiers == []
            and (
                "NUMERIC_SELF_VERIFIER_TIER1_FAILED" in blocker_set
            ) == numeric_failed
        ) or (
            retention_status == "RETAINED"
            and self_verifier.get("status") in ("FAIL", "UNKNOWN")
            and type(self_verifier.get("report_digest")) is str
            and self_verifier.get("source_binding_status") != "PASS"
            and subject is None
            and represented_tiers == []
            and (
                "NUMERIC_SELF_VERIFIER_TIER1_FAILED" in blocker_set
            ) == numeric_failed
        )
    )
    _fail(invalidators,
          report.get("claim_boundary") == _PACKAGE_CLAIM_BOUNDARY
              and (mechanism is None or (
                  type(mechanism) is str
                  and _SHA256.fullmatch(mechanism) is not None
              ))
              and self_shape_valid,
          "PACKAGE_RECHECK_FALLBACK_CONSTANTS_DIFFER")
    expected_status = "FAIL" if (
        any(_blocker_implies_failure(value) for value in blocker_set)
        or (type(self_verifier) is dict
            and self_verifier.get("status") == "FAIL")
        or (
            "PACKAGE_REPORT_TRANSPORT_CAPACITY_EXHAUSTED" in blocker_set
            and type(self_verifier) is dict
            and self_verifier.get("status") == "FAIL"
        )
    ) else "UNKNOWN"
    _fail(invalidators,
          report.get("status") == report.get("project_gate_status")
              and report.get("status") in ("FAIL", "UNKNOWN")
              and (not contract_current or report.get("status") == expected_status)
              and (not any(
                  _blocker_implies_failure(value) for value in blocker_set
              ) or report.get("status") == "FAIL")
              and (self_verifier.get("status") != "FAIL"
                   or report.get("status") == "FAIL")
              and report.get("polished") is False
              and report.get("release_authorized") is False,
          "PACKAGE_RECHECK_PROJECT_STATUS_DIFFERS")


def _check_stable_project_envelope(report: dict[str, Any],
                                   invalidators: set[str]) -> None:
    blockers = report.get("blockers")
    blocker_set = set(blockers) if type(blockers) is list and all(
        type(value) is str for value in blockers
    ) else set()
    sections = [
        report.get(name) for name in (
            "package_graph", "self_verifier_tier1", "native_facets_replay",
            "installed_native_case_replay", "core_route_projection",
            "candidate_obligation_ledger", "owner_decision_admission",
            "source_recapture_binding", "tier_zero_repository_admission",
            "full_native_candidate",
        )
    ]
    row_sections = []
    for name in (
            "tier_zero_representation_cells", "core_route_memberships",
            "core_family_cells", "corrigibility_extension_cells"):
        selected = report.get(name)
        if type(selected) is list:
            row_sections.extend(selected)
    full_candidate = report.get("full_native_candidate")
    if type(full_candidate) is dict and type(full_candidate.get("routes")) is list:
        row_sections.extend(full_candidate["routes"])
    for section_name, rows_name in (
            ("native_facets_replay", "results"),
            ("installed_native_case_replay", "tier_results"),
            ("installed_native_case_replay", "memberships")):
        selected = report.get(section_name)
        if type(selected) is dict and type(selected.get(rows_name)) is list:
            row_sections.extend(selected[rows_name])
    definite_failure = any(
        type(section) is dict and section.get("status") == "FAIL"
        for section in sections
    ) or any(
        type(row) is dict and row.get("status") == "FAIL"
        for row in row_sections
    ) or any(_blocker_implies_failure(value) for value in blocker_set)
    _fail(invalidators,
          type(blockers) is list
              and bool(blockers)
              and blockers == sorted(blocker_set)
              and report.get("status") == report.get("project_gate_status")
              and report.get("status") in ("FAIL", "UNKNOWN")
              and (not definite_failure or report.get("status") == "FAIL")
              and report.get("polished") is False
              and report.get("release_authorized") is False
              and report.get("claim_boundary") == _PACKAGE_CLAIM_BOUNDARY,
          "PACKAGE_RECHECK_STABLE_PROJECT_ENVELOPE_DIFFERS")


def _current_package_mechanism_digest() -> str:
    """Reproduce the producer's mechanism commitment without importing it."""
    root = _package_root()
    return core_obligation_union.value_digest({
        "package_gate": core_obligation_union.bytes_digest(
            root.joinpath("runtime", "package_self_polish.py").read_bytes()
        ),
        "specification": core_obligation_union.bytes_digest(
            root.joinpath("standard", "PACKAGE_SELF_POLISH.md").read_bytes()
        ),
        "report_schema": core_obligation_union.bytes_digest(
            root.joinpath(
                "schemas",
                "verifier-package-graph-self-polish-assessment-1.schema.json",
            ).read_bytes()
        ),
        "candidate_obligation_schema": core_obligation_union.bytes_digest(
            root.joinpath(
                "schemas",
                "verifier-package-obligation-candidate-selection-1.schema.json",
            ).read_bytes()
        ),
        "namespace": core_obligation_union.bytes_digest(
            root.joinpath("core", "namespace.py").read_bytes()
        ),
        "core_inventory": core_tier_progression.mechanism_digest(),
        "candidate_obligation_selector": core_obligation_union.bytes_digest(
            Path(package_obligation_candidate.__file__).read_bytes()
        ),
        "owner_decision_admission": package_owner_decision.mechanism_digest(),
        "numeric_self_polish": self_polish_tiers.mechanism_digest(),
        "tier_zero_admission": tier_zero.mechanism_digest(),
        "full_native_candidate": (
            self_polish_native_full_candidate.mechanism_digest()
        ),
        "native_case_registry": core_obligation_union.bytes_digest(
            Path(self_polish_native_cases.__file__).read_bytes()
        ),
        "native_case_replay": self_polish_native_replay.mechanism_digest(),
        "source_capture": core_obligation_union.bytes_digest(
            Path(polish_requirements.__file__).read_bytes()
        ),
        "obligation_union": core_obligation_union.bytes_digest(
            Path(core_obligation_union.__file__).read_bytes()
        ),
        "generic_object_facets": object_facets.mechanism_digest(),
        "typed_facets": typed_facets.mechanism_digest(),
        "corrigibility_research": core_obligation_union.bytes_digest(
            root.joinpath("standard", "CORRIGIBILITY_RESEARCH.md").read_bytes()
        ),
        "corrigibility_module_set": core_obligation_union.value_digest([
            {
                "path": path.name,
                "digest": core_obligation_union.bytes_digest(path.read_bytes()),
            }
            for path in sorted(root.joinpath("corrigibility").glob("*.py"))
        ]),
        "verifier_10_1_research_input": verifier_replacement.mechanism_digest(),
    })


def mechanism_digest() -> str:
    """Bind the rechecker, its output schema, and its independent inputs."""
    root = _package_root()
    return core_obligation_union.value_digest({
        "rechecker": core_obligation_union.bytes_digest(Path(__file__).read_bytes()),
        "recheck_schema": core_obligation_union.bytes_digest(
            root.joinpath(
                "schemas", "verifier-package-graph-self-polish-recheck-1.schema.json"
            ).read_bytes()
        ),
        "namespace": core_obligation_union.bytes_digest(
            root.joinpath("core", "namespace.py").read_bytes()
        ),
        "core_inventory": core_tier_progression.mechanism_digest(),
        "obligation_union": core_obligation_union.bytes_digest(
            Path(core_obligation_union.__file__).read_bytes()
        ),
        "strict_json": core_obligation_union.bytes_digest(
            root.joinpath("core", "receipt.py").read_bytes()
        ),
    })


def _result(*, report_bytes_digest: str | None,
            selected_report_digest: str | None,
            reported_project_status: str | None,
            reported_mechanism_digest: str | None,
            current_mechanism_digest: str | None,
            invalidators: set[str], unknowns: set[str]) -> dict[str, Any]:
    try:
        recheck_mechanism_digest = mechanism_digest()
    except (OSError, MemoryError, RecursionError, OverflowError):
        recheck_mechanism_digest = None
        unknowns.add("PACKAGE_RECHECK_MECHANISM_UNAVAILABLE")
    status = "FAIL" if invalidators else "UNKNOWN" if unknowns else "PASS"
    body = {
        "schema_version": RECHECK_SCHEMA,
        "status": status,
        "rechecked_project_status": (
            None if invalidators or unknowns else reported_project_status
        ),
        "selected_report_digest": selected_report_digest,
        "selected_report_bytes_digest": report_bytes_digest,
        "reported_package_mechanism_digest": reported_mechanism_digest,
        "current_package_mechanism_digest": current_mechanism_digest,
        "invalidators": sorted(invalidators),
        "unknowns": sorted(unknowns),
        "mechanism_digest": recheck_mechanism_digest,
        "claim_boundary": _CLAIM_BOUNDARY,
    }
    body["recheck_digest"] = core_obligation_union.value_digest(body)
    return body


def _fail(invalidators: set[str], condition: bool, code: str) -> None:
    if not condition:
        invalidators.add(code)


def _body_digest(value: dict[str, Any], field: str) -> str:
    return core_obligation_union.value_digest({
        key: item for key, item in value.items() if key != field
    })


def _strict_number_types(value: Any) -> bool:
    allowed_boolean_paths = {
        ("polished",),
        ("release_authorized",),
        ("full_native_candidate", "polished"),
        ("source_recapture_binding", "matches_selected_source"),
        (
            "source_recapture_binding", "opening_binding",
            "matches_selected_source",
        ),
    }
    pending: list[tuple[Any, tuple[str, ...]]] = [(value, ())]
    while pending:
        selected, path = pending.pop()
        if type(selected) is float:
            return False
        if type(selected) is bool:
            if path not in allowed_boolean_paths:
                return False
            continue
        if type(selected) is dict:
            pending.extend(
                (item, path + (key,)) for key, item in selected.items()
            )
        elif type(selected) is list:
            pending.extend((item, path + ("*",)) for item in selected)
    return True


def _reconstruct_graph(report: dict[str, Any], invalidators: set[str],
                       unknowns: set[str]) \
        -> tuple[NamespaceObject, ...] | None:
    graph = report.get("package_graph")
    if type(graph) is not dict or type(graph.get("object_records")) is not list:
        invalidators.add("PACKAGE_RECHECK_GRAPH_FIELDS")
        return None
    records = graph["object_records"]
    try:
        objects = tuple(
            NamespaceObject.create(
                row["object_id"], row["kind"], row["payload"], row["operands"]
            )
            for row in records
        )
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeError,
            RecursionError, OverflowError):
        invalidators.add("PACKAGE_RECHECK_GRAPH_RECONSTRUCTION")
        return None
    _fail(invalidators, [item.to_dict() for item in objects] == records,
          "PACKAGE_RECHECK_GRAPH_RECORD_DIFFERS")
    _fail(invalidators,
          [item.object_id for item in objects]
              == sorted(item.object_id for item in objects),
          "PACKAGE_RECHECK_GRAPH_ORDER_DIFFERS")
    _fail(invalidators, len(objects) == len(ObjectKind),
          "PACKAGE_RECHECK_OBJECT_COUNT_DIFFERS")
    _fail(invalidators, len({item.object_id for item in objects}) == len(objects),
          "PACKAGE_RECHECK_OBJECT_IDENTITY_DUPLICATED")
    _fail(invalidators, {item.kind for item in objects} == set(ObjectKind),
          "PACKAGE_RECHECK_OBJECT_KIND_CENSUS_DIFFERS")
    digest = composition_digest(objects)
    assessment = assess_composition(objects, expected_digest=digest)
    wire = core_obligation_union.canonical_bytes({
        "schema_version": "verifier-package-graph-wire-1",
        "objects": records,
    })
    graph_resource_unknown = (
        graph.get("status") == "UNKNOWN"
        and graph.get("collection_digest") is None
        and graph.get("canonical_round_trip_status") == "UNKNOWN"
    )
    if graph_resource_unknown:
        unknowns.add("PACKAGE_RECHECK_GRAPH_RECONSTRUCTION_UNAVAILABLE")
        _fail(invalidators,
              graph.get("reason")
                  == "canonical graph record round trip was unavailable"
              and graph.get("object_count") == 0,
              "PACKAGE_RECHECK_GRAPH_RESOURCE_STATE_DIFFERS")
    else:
        _fail(invalidators, graph.get("collection_digest") == digest,
              "PACKAGE_RECHECK_COLLECTION_DIGEST_DIFFERS")
    _fail(invalidators,
          graph.get("canonical_wire_digest")
              == core_obligation_union.bytes_digest(wire),
          "PACKAGE_RECHECK_WIRE_DIGEST_DIFFERS")
    if not graph_resource_unknown:
        _fail(invalidators, graph.get("status") == assessment.verdict.value,
              "PACKAGE_RECHECK_GRAPH_STATUS_DIFFERS")
        _fail(invalidators, graph.get("reason") == assessment.reason,
              "PACKAGE_RECHECK_GRAPH_REASON_DIFFERS")
        _fail(invalidators,
              graph.get("object_count") == assessment.objects_checked,
              "PACKAGE_RECHECK_GRAPH_COUNT_DIFFERS")
        _fail(invalidators,
              graph.get("canonical_round_trip_status") == "PASS",
              "PACKAGE_RECHECK_ROUND_TRIP_STATUS_DIFFERS")
    return objects


def _check_graph_bindings(report: dict[str, Any],
                          objects: tuple[NamespaceObject, ...],
                          invalidators: set[str]) -> None:
    by_kind = {item.kind.value: item for item in objects}
    source_digest = report.get("source_coordinate_digest")
    _fail(invalidators, all(
        item.payload.get("source_coordinate_digest") == source_digest
        for item in objects
    ), "PACKAGE_RECHECK_GRAPH_SOURCE_BINDING_DIFFERS")
    verifier = by_kind.get("VERIFIER")
    owner = by_kind.get("OWNER")
    receipt = by_kind.get("RECEIPT")
    event = by_kind.get("EVENT")
    if None in (verifier, owner, receipt, event):
        invalidators.add("PACKAGE_RECHECK_BOUND_OBJECT_MISSING")
        return
    assert verifier is not None and owner is not None
    assert receipt is not None and event is not None
    candidate = report.get("candidate_obligation_ledger")
    admission = report.get("owner_decision_admission")
    self_verifier = report.get("self_verifier_tier1")
    tier_zero_admission = report.get("tier_zero_repository_admission")
    full_native_candidate = report.get("full_native_candidate")
    if type(candidate) is not dict or type(admission) is not dict \
            or type(self_verifier) is not dict \
            or type(tier_zero_admission) is not dict:
        invalidators.add("PACKAGE_RECHECK_BOUND_SECTION_MISSING")
        return
    candidate_digest = core_obligation_union.value_digest(candidate)
    _fail(invalidators,
          verifier.payload.get("candidate_selection_digest") == candidate_digest,
          "PACKAGE_RECHECK_CANDIDATE_GRAPH_BINDING_DIFFERS")
    _fail(invalidators,
          verifier.payload.get("candidate_selection_status")
              == candidate.get("status"),
          "PACKAGE_RECHECK_CANDIDATE_STATUS_DIFFERS")
    _fail(invalidators,
          admission.get("admission_digest")
              == _body_digest(admission, "admission_digest"),
          "PACKAGE_RECHECK_OWNER_ADMISSION_DIGEST_DIFFERS")
    _fail(invalidators,
          verifier.payload.get("owner_decision_admission_digest")
              == admission.get("admission_digest")
          and owner.payload.get("owner_decision_admission_digest")
              == admission.get("admission_digest"),
          "PACKAGE_RECHECK_OWNER_GRAPH_BINDING_DIFFERS")
    _fail(invalidators,
          verifier.payload.get("owner_decision_admission_status")
              == admission.get("status")
          and owner.payload.get("owner_decision_admission_status")
              == admission.get("status"),
          "PACKAGE_RECHECK_OWNER_STATUS_DIFFERS")
    retained = self_verifier.get("retention_status") == "RETAINED"
    expected_digest = self_verifier.get("report_digest") if retained else None
    expected_status = self_verifier.get("status") if retained else None
    _fail(invalidators,
          verifier.payload.get("self_verifier_report_digest") == expected_digest
          and receipt.payload.get("retained_report_digest") == expected_digest
          and event.payload.get("execution_report_digest") == expected_digest,
          "PACKAGE_RECHECK_SELF_VERIFIER_DIGEST_BINDING_DIFFERS")
    _fail(invalidators,
          verifier.payload.get("self_verifier_report_status") == expected_status
          and receipt.payload.get("retained_report_status") == expected_status,
          "PACKAGE_RECHECK_SELF_VERIFIER_STATUS_BINDING_DIFFERS")
    _fail(invalidators,
          report.get("mechanism_digest")
              == verifier.payload.get("package_gate_mechanism_digest"),
          "PACKAGE_RECHECK_MECHANISM_GRAPH_BINDING_DIFFERS")
    tier_zero_digest = tier_zero_admission.get("report_digest")
    tier_zero_status = tier_zero_admission.get("status")
    tier_zero_profile = tier_zero_admission.get("profile_digest")
    _fail(invalidators,
          verifier.payload.get("tier_zero_report_digest") == tier_zero_digest
          and verifier.payload.get("tier_zero_report_status") == tier_zero_status
          and verifier.payload.get("tier_zero_profile_digest")
              == tier_zero_profile
          and receipt.payload.get("tier_zero_retained_report_digest")
              == tier_zero_digest
          and receipt.payload.get("tier_zero_retained_report_status")
              == tier_zero_status
          and event.payload.get("tier_zero_execution_report_digest")
              == tier_zero_digest
          and event.payload.get("tier_zero_execution_status")
              == tier_zero_status,
          "PACKAGE_RECHECK_TIER_ZERO_GRAPH_BINDING_DIFFERS")
    full_candidate_digest = (
        full_native_candidate.get("candidate_digest")
        if type(full_native_candidate) is dict else None
    )
    full_candidate_status = (
        full_native_candidate.get("status")
        if type(full_native_candidate) is dict else (
            "NOT_SELECTED"
            if "PACKAGE_FULL_NATIVE_CANDIDATE_NOT_SELECTED"
                in report.get("blockers", [])
            else "FAIL"
            if "PACKAGE_FULL_NATIVE_CANDIDATE_FAILED"
                in report.get("blockers", [])
            else "UNKNOWN"
        )
    )
    _fail(invalidators,
          verifier.payload.get("full_native_candidate_digest")
              == full_candidate_digest
          and verifier.payload.get("full_native_candidate_status")
              == full_candidate_status
          and receipt.payload.get("full_native_candidate_digest")
              == full_candidate_digest
          and receipt.payload.get("full_native_candidate_status")
              == full_candidate_status
          and event.payload.get("full_native_candidate_digest")
              == full_candidate_digest
          and event.payload.get("full_native_candidate_status")
              == full_candidate_status,
          "PACKAGE_RECHECK_FULL_NATIVE_CANDIDATE_GRAPH_BINDING_DIFFERS")


def _source_evidence_valid(evidence: Any, observed: Any) -> bool:
    return (
        type(evidence) is dict
        and set(evidence) == {
            "source_manifest_digest", "candidate_source_census_digest",
            "candidate_source_file_count", "candidate_source_bytes",
            "tracked_file_count", "untracked_nonignored_file_count",
        }
        and _valid_source_coordinate(observed)
        and evidence.get("source_manifest_digest")
            == observed.get("source_manifest_digest")
        and all(
            type(evidence.get(field)) is int
            and not isinstance(evidence.get(field), bool)
            and evidence.get(field) >= 0
            for field in (
                "candidate_source_file_count", "candidate_source_bytes",
                "tracked_file_count", "untracked_nonignored_file_count",
            )
        )
        and type(evidence.get("candidate_source_census_digest")) is str
        and _SHA256.fullmatch(
            evidence["candidate_source_census_digest"]
        ) is not None
    )


def _source_observation_valid(value: Any, selected: Any) -> bool:
    if type(value) is not dict:
        return False
    status = value.get("status")
    matches = value.get("matches_selected_source")
    observed = value.get("observed_source_coordinate")
    evidence = value.get("observed_source_evidence")
    expected_fields = {
        "status", "matches_selected_source", "observed_source_coordinate",
        "observed_source_evidence", "claim_boundary",
    }
    if observed is not None:
        expected_fields.add("observed_source_coordinate_digest")
    if set(value) != expected_fields:
        return False
    coordinate_valid = (
        "observed_source_coordinate_digest" not in value
        if observed is None else
        _valid_source_coordinate(observed)
        and value.get("observed_source_coordinate_digest")
            == core_obligation_union.value_digest(observed)
    )
    if not coordinate_valid:
        return False
    pass_boundary = (
        "PASS establishes exact equality between a later recapture by the same "
        "mechanism and the selected numeric report coordinate; it is not "
        "independent evidence."
    )
    if status == "PASS":
        return (
            matches is True
            and observed == selected
            and _source_evidence_valid(evidence, observed)
            and value.get("claim_boundary") == pass_boundary
        )
    if status == "FAIL":
        return matches is False and (
            observed is None
            and evidence is None
            and value.get("claim_boundary") == (
                "The selected source root did not satisfy the later whole-source "
                "recapture contract."
            )
            or observed != selected
            and _source_evidence_valid(evidence, observed)
            and value.get("claim_boundary") == pass_boundary
        )
    if status in ("UNKNOWN", "NOT_ESTABLISHED"):
        return (
            matches == "UNKNOWN"
            and observed is None
            and evidence is None
            and value.get("claim_boundary") == (
                "A later source recapture was not selected for this call."
                if status == "NOT_ESTABLISHED" else
                "The later source recapture was unavailable."
            )
        )
    return False


def _check_source_recapture(report: dict[str, Any],
                            objects: tuple[NamespaceObject, ...],
                            invalidators: set[str]) -> None:
    binding = report.get("source_recapture_binding")
    if type(binding) is not dict:
        invalidators.add("PACKAGE_RECHECK_SOURCE_RECAPTURE_FIELDS")
        return
    opening = binding.get("opening_binding")
    final_observation = {
        key: value for key, value in binding.items()
        if key != "opening_binding"
    }
    _fail(invalidators,
          set(binding) == set(final_observation) | {"opening_binding"},
          "PACKAGE_RECHECK_SOURCE_RECAPTURE_FIELDS")
    _fail(invalidators,
          _source_observation_valid(final_observation,
                                    report.get("source_coordinate")),
          "PACKAGE_RECHECK_SOURCE_RECAPTURE_STATUS_DIFFERS")
    _fail(invalidators,
          _source_observation_valid(opening, report.get("source_coordinate")),
          "PACKAGE_RECHECK_SOURCE_OPENING_BINDING_DIFFERS")
    severity = {"PASS": 0, "UNKNOWN": 1, "NOT_ESTABLISHED": 1, "FAIL": 2}
    status = final_observation.get("status")
    opening_status = opening.get("status") if type(opening) is dict else None
    _fail(invalidators,
          status in severity
              and opening_status in severity
              and severity[status] >= severity[opening_status]
              and (final_observation == opening
                   or severity[status] > severity[opening_status]),
          "PACKAGE_RECHECK_SOURCE_OPENING_BINDING_DIFFERS")
    installed = report.get("installed_native_case_replay")
    _fail(invalidators,
          (status == "NOT_ESTABLISHED")
              == (type(installed) is dict
                  and installed.get("status") == "NOT_SELECTED"),
          "PACKAGE_RECHECK_SOURCE_RECAPTURE_SELECTION_DIFFERS")
    opening_evidence = (
        opening.get("observed_source_evidence")
        if type(opening) is dict else None
    )
    expected_evidence_status = (
        "BOUND" if opening_status == "PASS" else "NOT_SELECTED"
    )
    expected_evidence_digest = (
        core_obligation_union.value_digest(opening_evidence)
        if opening_status == "PASS" else None
    )
    _fail(invalidators, all(
        item.payload.get("source_evidence_status") == expected_evidence_status
        and item.payload.get("source_evidence_digest") == expected_evidence_digest
        for item in objects
    ), "PACKAGE_RECHECK_SOURCE_EVIDENCE_GRAPH_BINDING_DIFFERS")


def _check_pinned_constants(report: dict[str, Any],
                            objects: tuple[NamespaceObject, ...],
                            invalidators: set[str]) -> None:
    graph = report.get("package_graph")
    native = report.get("native_facets_replay")
    installed = report.get("installed_native_case_replay")
    projection = report.get("core_route_projection")
    self_verifier = report.get("self_verifier_tier1")
    admission = report.get("owner_decision_admission")
    tier_zero_admission = report.get("tier_zero_repository_admission")
    if not all(type(value) is dict for value in (
            graph, native, installed, projection, self_verifier, admission,
            tier_zero_admission)):
        invalidators.add("PACKAGE_RECHECK_PINNED_CONSTANT_FIELDS")
        return
    exact_section_fields = (
        (graph, {
            "status", "collection_digest", "canonical_wire_digest",
            "canonical_round_trip_status", "object_count", "object_kind_count",
            "represented_object_kinds", "root_id", "root_kind",
            "polish_object_id", "polish_object_kind", "object_records", "reason",
            "claim_boundary",
        }),
        (native, {
            "schema_version", "status", "source_coordinate_digest",
            "collection_digest", "collection_bytes_digest",
            "generic_mechanism_digest", "typed_mechanism_digest", "object_count",
            "objective_count", "case_count", "positive_case_count",
            "negative_case_count", "unknown_case_count", "pass_count",
            "fail_count", "unknown_count", "policy_anchor_class", "results",
            "claim_boundary", "replay_digest",
        }),
        (installed, {
            "schema_version", "status", "resource_status",
            "source_coordinate_digest",
            "tier_results", "memberships", "membership_count", "case_count",
            "claim_boundary", "replay_digest",
        }),
        (projection, {
            "schema_version", "status", "route_identity_projection_status",
            "unknown_causes", "membership_count",
            "mapped_checker_discrimination_count",
            "expected_mapped_checker_discrimination_count", "not_run_count",
            "unavailable_selected_count", "installed_specimen_membership_count",
            "installed_specimen_pass_count", "installed_specimen_unknown_count",
            "installed_specimen_fail_count", "claim_boundary",
        }),
        (self_verifier, {
            "status", "retention_status", "report_digest", "source_binding_status",
            "subject", "represented_tiers", "claim_boundary",
        }),
        (admission, {
            "schema_version", "status", "authority_scope", "owner_id", "policy_id",
            "policy_revision", "policy_digest", "decision_envelope_digest",
            "candidate_selection_digest", "source_coordinate_digest",
            "decision_set_digest", "decision_count", "adopted_decision_ids",
            "evaluation_time", "mechanism_digest", "error", "claim_boundary",
            "admission_digest",
        }),
        (tier_zero_admission, {
            "schema_version", "status", "report_schema_version",
            "report_digest", "profile_id", "profile_digest",
            "manifest_digest", "mechanism_digest", "obligation_count",
            "obligation_status_counts", "assessment_reason_count",
            "finalization_status", "closed_coordinates",
            "unclosed_coordinates", "source_repository", "source_revision",
            "source_census_digest", "source_binding_status", "error",
            "claim_boundary",
        }),
    )
    _fail(invalidators,
          all(set(section) == fields for section, fields in exact_section_fields),
          "PACKAGE_RECHECK_SECTION_FIELDS_DIFFER")
    expected_kinds = sorted(kind.value for kind in ObjectKind)
    _fail(invalidators,
          report.get("claim_boundary") == _PACKAGE_CLAIM_BOUNDARY
          and graph.get("object_kind_count") == 26
          and graph.get("represented_object_kinds") == expected_kinds
          and graph.get("root_id") == "vstd-package-graph"
          and graph.get("root_kind") == "GRAPH"
          and graph.get("polish_object_id") == "verifier-core-self"
          and graph.get("polish_object_kind") == "VERIFIER"
          and graph.get("claim_boundary") == _GRAPH_CLAIM_BOUNDARY
          and native.get("schema_version")
              == "verifier-package-native-facets-replay-1"
          and native.get("policy_anchor_class")
              == "SELF_SELECTED_SOURCE_BINDING_NOT_AUTHORITY"
          and native.get("claim_boundary") == _NATIVE_CLAIM_BOUNDARY
          and installed.get("claim_boundary") == _INSTALLED_CLAIM_BOUNDARY
          and installed.get("schema_version")
              == "verifier-package-installed-native-case-replay-1"
          and projection.get("claim_boundary") == _PROJECTION_CLAIM_BOUNDARY
          and projection.get("schema_version")
              == "verifier-package-core-route-projection-1"
          and self_verifier.get("claim_boundary")
              == _SELF_VERIFIER_CLAIM_BOUNDARY
          and admission.get("claim_boundary") == _OWNER_CLAIM_BOUNDARY
          and tier_zero_admission.get("claim_boundary")
              == _TIER_ZERO_BINDING_BOUNDARY,
          "PACKAGE_RECHECK_PINNED_CONSTANTS_DIFFER")
    _fail(invalidators,
          all(
              item.payload.get("schema_version")
                  == "verifier-package-graph-representation-1"
              and item.payload.get("semantic_status") == "NOT_ESTABLISHED"
              for item in objects
          ),
          "PACKAGE_RECHECK_GRAPH_PAYLOAD_CONSTANTS_DIFFER")
    by_kind = {item.kind.value: item for item in objects}
    common_payload_fields = {
        "schema_version", "representation_role", "source_coordinate_digest",
        "semantic_status", "source_evidence_status", "source_evidence_digest",
    }
    extra_payload_fields = {
        "VERIFIER": {
            "selected_numeric_tier", "numeric_self_polish_mechanism_digest",
            "package_gate_mechanism_digest",
            "candidate_selector_mechanism_digest",
            "owner_decision_mechanism_digest", "candidate_selection_digest",
            "candidate_selection_status", "owner_decision_admission_digest",
            "owner_decision_admission_status", "self_verifier_report_digest",
            "self_verifier_report_status", "retained_numeric_mechanism_digest",
            "package_gate_tier1_status",
            "tier_zero_report_digest", "tier_zero_report_status",
            "tier_zero_profile_digest",
            "full_native_candidate_digest", "full_native_candidate_status",
            "full_native_candidate_mechanism_digest",
        },
        "OWNER": {
            "owner_decision_admission_digest",
            "owner_decision_admission_status",
        },
        "RECEIPT": {
            "retained_report_digest", "retained_report_status",
            "tier_zero_retained_report_digest",
            "tier_zero_retained_report_status",
            "full_native_candidate_digest", "full_native_candidate_status",
        },
        "EVENT": {
            "execution_status", "execution_report_digest",
            "tier_zero_execution_status", "tier_zero_execution_report_digest",
            "full_native_candidate_digest", "full_native_candidate_status",
        },
        "GRAPH": {"element_kind"},
    }
    expected_member_ids = sorted(
        object_id for kind, (object_id, _, _) in _GRAPH_TEMPLATE.items()
        if kind != "GRAPH"
    )
    template_valid = True
    for kind, (object_id, role, operands) in _GRAPH_TEMPLATE.items():
        item = by_kind.get(kind)
        expected_operands = (
            {"members": expected_member_ids} if kind == "GRAPH" else operands
        )
        if (item is None or item.object_id != object_id
                or item.payload.get("representation_role") != role
                or item.to_dict()["operands"] != expected_operands
                or set(item.payload) != common_payload_fields
                    | extra_payload_fields.get(kind, set())
                or (kind == "GRAPH"
                    and item.payload.get("element_kind") != "OBJECT")):
            template_valid = False
            break
    _fail(invalidators,
          template_valid
              and graph.get("root_id") == _GRAPH_TEMPLATE["GRAPH"][0]
              and graph.get("polish_object_id") == _GRAPH_TEMPLATE["VERIFIER"][0],
          "PACKAGE_RECHECK_GRAPH_TEMPLATE_DIFFERS")
    verifier = by_kind.get("VERIFIER")
    event = by_kind.get("EVENT")
    if verifier is None or event is None:
        invalidators.add("PACKAGE_RECHECK_BOUND_OBJECT_MISSING")
    else:
        retained = self_verifier.get("retention_status") == "RETAINED"
        expected_execution = (
            self_verifier.get("status") if retained
            else self_verifier.get("retention_status")
        )
        _fail(invalidators,
              verifier.payload.get("selected_numeric_tier") == 1
              and verifier.payload.get("numeric_self_polish_mechanism_digest")
                  == self_polish_tiers.mechanism_digest()
              and verifier.payload.get("candidate_selector_mechanism_digest")
                  == core_obligation_union.bytes_digest(
                      Path(package_obligation_candidate.__file__).read_bytes()
                  )
              and verifier.payload.get("owner_decision_mechanism_digest")
                  == package_owner_decision.mechanism_digest()
              and verifier.payload.get("full_native_candidate_mechanism_digest")
                  == self_polish_native_full_candidate.mechanism_digest()
              and verifier.payload.get("package_gate_tier1_status")
                  == "NOT_ESTABLISHED"
              and verifier.payload.get("retained_numeric_mechanism_digest")
                  == (
                      self_polish_tiers.mechanism_digest()
                      if retained else None
                  )
              and (not retained or (
                  type(verifier.payload.get("retained_numeric_mechanism_digest"))
                      is str
                  and _SHA256.fullmatch(
                      verifier.payload["retained_numeric_mechanism_digest"]
                  ) is not None
              ))
              and event.payload.get("execution_status") == expected_execution,
              "PACKAGE_RECHECK_GRAPH_MECHANISM_CONSTANTS_DIFFER")
    represented_tiers = self_verifier.get("represented_tiers")
    self_status = self_verifier.get("status")
    self_retention = self_verifier.get("retention_status")
    self_invariants = (
        type(represented_tiers) is list
        and len(represented_tiers) == len(set(represented_tiers))
        and all(type(value) is int and not isinstance(value, bool)
                and 1 <= value <= 9 for value in represented_tiers)
        and self_verifier.get("subject") in (
            None,
            {"object_id": "verifier-core-self", "object_kind": "VERIFIER"},
        )
    )
    if self_status != "PASS":
        self_invariants = (
            self_invariants
            and represented_tiers == []
            and self_verifier.get("source_binding_status") != "PASS"
        )
    if self_retention != "RETAINED":
        self_invariants = self_invariants and self_status != "PASS"
    if self_status == "PASS":
        self_invariants = self_invariants and self_verifier.get("subject") == {
            "object_id": "verifier-core-self", "object_kind": "VERIFIER",
        }
    _fail(invalidators, self_invariants,
          "PACKAGE_RECHECK_SELF_VERIFIER_CONSTANTS_DIFFER")
    tier_zero = report.get("tier_zero_representation_cells")
    _fail(invalidators,
          type(tier_zero) is list and all(
              type(row) is dict
              and row.get("claim_boundary") == _TIER_ZERO_CLAIM_BOUNDARY
              for row in tier_zero
          ),
          "PACKAGE_RECHECK_TIER_ZERO_CLAIM_BOUNDARY_DIFFERS")


def _check_denominators(report: dict[str, Any],
                        invalidators: set[str],
                        unknowns: set[str]) -> dict[str, Any] | None:
    try:
        inventory = core_tier_progression.installed_core_route_inventory()
    except (OSError, ImportError, MemoryError, RecursionError, OverflowError):
        unknowns.add("PACKAGE_RECHECK_INSTALLED_INVENTORY_UNAVAILABLE")
        return None
    except RuntimeError:
        invalidators.add("PACKAGE_RECHECK_INSTALLED_INVENTORY_UNAVAILABLE")
        return None
    denominators = report.get("denominators")
    if type(denominators) is not dict:
        invalidators.add("PACKAGE_RECHECK_DENOMINATORS_MISSING")
        return inventory
    expected = {
        "object_kind_count": 26,
        "tier_zero_representation_cell_count": 26,
        "core_tier_count": 9,
        "core_family_cell_count": 234,
        "registered_core_route_membership_count": inventory[
            "registered_route_membership_count"
        ],
        "corrigibility_extension_cell_count": 26,
        "core_and_tier_zero_cell_count": 260,
        "tracked_assessment_cell_count": 286,
    }
    _fail(invalidators, denominators == expected,
          "PACKAGE_RECHECK_DENOMINATORS_DIFFER")
    _fail(invalidators,
          report.get("core_installed_inventory_digest")
              == core_obligation_union.value_digest(inventory),
          "PACKAGE_RECHECK_INVENTORY_DIGEST_DIFFERS")
    return inventory


def _check_candidate_and_owner(report: dict[str, Any],
                               inventory: dict[str, Any],
                               invalidators: set[str]) -> None:
    candidate = report.get("candidate_obligation_ledger")
    if type(candidate) is not dict:
        invalidators.add("PACKAGE_RECHECK_CANDIDATE_FIELDS")
        return
    candidate_status = candidate.get("status")
    if candidate_status == "NOT_SELECTED":
        _fail(invalidators,
              candidate == (
                  package_obligation_candidate
                  .not_selected_candidate_obligation_ledger()
              ),
              "PACKAGE_RECHECK_CANDIDATE_NOT_SELECTED_DIFFERS")
    elif candidate_status in ("FAIL", "UNKNOWN"):
        error = candidate.get("error")
        expected = (
            package_obligation_candidate.failed_candidate_obligation_ledger(error)
            if candidate_status == "FAIL" else
            package_obligation_candidate.unavailable_candidate_obligation_ledger(error)
        )
        _fail(invalidators, type(error) is str and candidate == expected,
              "PACKAGE_RECHECK_CANDIDATE_FALLBACK_DIFFERS")
    elif candidate_status == "PASS":
        rows = candidate.get("rows")
        owner_decisions = candidate.get("owner_decisions")
        candidate_fields = {
            "schema_version", "status", "selection_validation_status",
            "candidate_epistemic_status", "semantic_identity_status",
            "owner_adoption_status", "normative_closure", "manifest_name",
            "manifest_digest", "card_count", "card_set_digest",
            "objective_count", "installed_inventory_digest",
            "reason_ledger_selection_status", "reason_ledger_digest",
            "reason_identity_count", "reason_slot_identity_count",
            "reason_disposition_counts", "candidate_rev4_class_counts",
            "candidate_mechanism_counts", "candidate_reason_verdict_counts",
            "card_question_count", "cross_kind_decision_count",
            "owner_decision_count", "owner_decisions", "rows",
            "claim_boundary", "selection_digest",
        }
        if type(rows) is not list or type(owner_decisions) is not list:
            invalidators.add("PACKAGE_RECHECK_CANDIDATE_FIELDS")
        else:
            inventory_rows = {
                (cell["object_kind"], route["coordinate"]): {
                    **route, "tier": cell["tier"]
                }
                for cell in inventory["family_cells"]
                for route in cell["registered_route_memberships"]
            }
            identities = [
                (row.get("object_kind"), row.get("coordinate"))
                for row in rows if type(row) is dict
            ]
            rows_valid = len(identities) == len(rows)
            row_fields = {
                "object_kind", "tier", "coordinate", "semantic_version",
                "proposition_digest", "certificate_schema_version",
                "checking_mechanism", "scope", "candidate_rev3_class",
                "candidate_rev4_class", "candidate_condition",
                "candidate_mechanism_assessment", "candidate_reason_verdict",
                "candidate_role", "candidate_served_facets",
                "candidate_failed_tests", "candidate_class_epistemic_type",
                "candidate_semantic_identity_status", "reason_bound_digest",
                "reason_text_digest", "reason_source_digest",
                "reason_disposition", "candidate_row_digest",
                "candidate_card_digest", "owner_disposition_status",
                "normative_closure", "status",
            }
            card_digests: dict[str, set[str]] = {}
            for row in rows:
                if type(row) is not dict:
                    continue
                kind = row.get("object_kind")
                card_digest = row.get("candidate_card_digest")
                if type(kind) is str and type(card_digest) is str:
                    card_digests.setdefault(kind, set()).add(card_digest)
                route = inventory_rows.get((
                    kind, row.get("coordinate")
                ))
                served_facets = row.get("candidate_served_facets")
                failed_tests = row.get("candidate_failed_tests")
                condition = row.get("candidate_condition")
                condition_valid = (
                    condition is None
                    if row.get("candidate_rev4_class")
                        != "CONDITIONALLY_NECESSARY" else
                    type(condition) is dict
                    and set(condition) == {
                        "type", "required_when", "not_required_because",
                        "if_silent", "decided_by",
                    }
                    and condition.get("type") in ("presence", "type")
                    and condition.get("if_silent") == "UNKNOWN"
                    and all(
                        type(condition.get(field)) is str
                        and bool(condition[field].strip())
                        for field in (
                            "required_when", "not_required_because",
                        )
                    )
                    and type(condition.get("decided_by")) is list
                    and bool(condition["decided_by"])
                    and all(type(value) is str
                            for value in condition["decided_by"])
                    and len(condition["decided_by"])
                        == len(set(condition["decided_by"]))
                    and type(kind) is str
                    and all(
                        re.fullmatch(
                            rf"{re.escape(kind)}\.F[1-9][0-9]*", value
                        ) is not None
                        for value in condition["decided_by"]
                    )
                )
                reason_selected_for_row = (
                    row.get("candidate_semantic_identity_status") == "PASS"
                )
                reason_binding_valid = (
                    all(
                        type(row.get(field)) is str
                        and _SHA256.fullmatch(row[field]) is not None
                        for field in (
                            "reason_bound_digest", "reason_text_digest",
                            "reason_source_digest",
                        )
                    )
                    and type(row.get("reason_disposition")) is str
                    and bool(row["reason_disposition"].strip())
                    if reason_selected_for_row else
                    row.get("candidate_semantic_identity_status")
                        == "NOT_ESTABLISHED"
                    and all(row.get(field) is None for field in (
                        "reason_bound_digest", "reason_text_digest",
                        "reason_source_digest", "reason_disposition",
                    ))
                )
                if (set(row) != row_fields or route is None or any(
                    row.get(field) != route.get(field)
                    for field in (
                        "tier", "semantic_version", "proposition_digest",
                        "certificate_schema_version", "checking_mechanism", "scope",
                    )
                ) or row.get("candidate_rev3_class") not in {
                    "NECESSARY", "CONDITIONALLY_NECESSARY", "REASON_PENDING",
                }
                        or row.get("candidate_rev4_class") not in {
                            "NECESSARY", "CONDITIONALLY_NECESSARY",
                            "REASON_PENDING",
                        }
                        or row.get("candidate_mechanism_assessment") not in {
                            "BOUNDED", "COVERS", "DEFECTIVE", "NOT_ASSESSED",
                            "PARTIAL", "UNSOUND",
                        }
                        or row.get("candidate_reason_verdict")
                            not in {"ADEQUATE", "REWRITE"}
                        or row.get("candidate_role")
                            not in {"cross-cutting", "facet", "orphan"}
                        or type(served_facets) is not list
                        or len(served_facets) != len(set(served_facets))
                        or not all(
                            type(value) is str
                            and type(kind) is str
                            and re.fullmatch(
                                rf"{re.escape(kind)}\.F[1-9][0-9]*", value
                            ) is not None
                            for value in served_facets
                        )
                        or type(failed_tests) is not list
                        or len(failed_tests) != len(set(failed_tests))
                        or not all(
                            type(value) is str
                            and value in {f"R{index}" for index in range(1, 7)}
                            for value in failed_tests
                        )
                        or not condition_valid
                        or not reason_binding_valid
                        or type(row.get("candidate_row_digest")) is not str
                        or _SHA256.fullmatch(
                            row["candidate_row_digest"]
                        ) is None
                        or type(card_digest) is not str
                        or _SHA256.fullmatch(card_digest) is None
                        or row.get("candidate_class_epistemic_type") != "INFERRED"
                        or row.get("owner_disposition_status")
                            != "NOT_ESTABLISHED"
                        or row.get("normative_closure") != "NOT_ESTABLISHED"
                        or row.get("status") != "UNKNOWN"):
                    rows_valid = False
            class_counts = dict(sorted(Counter(
                row.get("candidate_rev4_class") for row in rows
                if type(row) is dict
            ).items()))
            mechanism_counts = dict(sorted(Counter(
                row.get("candidate_mechanism_assessment") for row in rows
                if type(row) is dict
            ).items()))
            reason_counts = dict(sorted(Counter(
                row.get("candidate_reason_verdict") for row in rows
                if type(row) is dict
            ).items()))
            reason_dispositions = dict(sorted(Counter(
                row.get("reason_disposition") for row in rows
                if type(row) is dict and row.get("reason_disposition") is not None
            ).items()))
            card_bindings = [
                {"object_kind": kind, "card_digest": next(iter(digests))}
                for kind, digests in sorted(card_digests.items())
                if len(digests) == 1
            ]
            expected_cross_decisions = [
                {
                    "decision_id": "CTC-1",
                    "topic": "triage method and candidate dispositions",
                    "scope": "ALL_CORE",
                    "scope_basis": "INFERRED_IMPLEMENTER_MAPPING",
                    "status": "NOT_ESTABLISHED",
                },
                {
                    "decision_id": "CTC-2",
                    "topic": "consent stages and tier-7 root holder",
                    "scope": "TIER_7",
                    "scope_basis": "INFERRED_IMPLEMENTER_MAPPING",
                    "status": "NOT_ESTABLISHED",
                },
                {
                    "decision_id": "CTC-3",
                    "topic": "reason-pending gate and absent reasons",
                    "scope": "REASON_GAPS",
                    "scope_basis": "INFERRED_IMPLEMENTER_MAPPING",
                    "status": "NOT_ESTABLISHED",
                },
                {
                    "decision_id": "CTC-4",
                    "topic": "corrigibility code set and grader integrity",
                    "scope": "CORRIGIBILITY",
                    "scope_basis": "INFERRED_IMPLEMENTER_MAPPING",
                    "status": "NOT_ESTABLISHED",
                },
                {
                    "decision_id": "CTC-5",
                    "topic": "generic record choices in tier zero or facets",
                    "scope": "TIER_0_AND_1",
                    "scope_basis": "INFERRED_IMPLEMENTER_MAPPING",
                    "status": "NOT_ESTABLISHED",
                },
                {
                    "decision_id": "CTC-6",
                    "topic": "MODEL data relation and card questions",
                    "scope": "MODEL_AND_QUESTIONS",
                    "scope_basis": "INFERRED_IMPLEMENTER_MAPPING",
                    "status": "NOT_ESTABLISHED",
                },
            ]
            expected_question_ids = [
                f"{kind.value}-Q{index}"
                for kind in sorted(ObjectKind, key=lambda value: value.value)
                for index in range(1, 5)
            ]
            question_decisions = owner_decisions[6:]
            questions_valid = (
                owner_decisions[:6] == expected_cross_decisions
                and len(question_decisions) == len(expected_question_ids)
                and all(
                    type(row) is dict
                    and set(row) == {
                        "decision_id", "object_kind", "question_digest",
                        "scope_basis", "status",
                    }
                    and row.get("decision_id") == decision_id
                    and row.get("object_kind") == decision_id.split("-Q", 1)[0]
                    and type(row.get("question_digest")) is str
                    and _SHA256.fullmatch(row["question_digest"]) is not None
                    and row.get("scope_basis")
                        == "INFERRED_CANDIDATE_CARD_SCOPE"
                    and row.get("status") == "NOT_ESTABLISHED"
                    for row, decision_id in zip(
                        question_decisions, expected_question_ids, strict=True
                    )
                )
            )
            reason_selected = (
                candidate.get("reason_ledger_selection_status") == "PASS"
            )
            _fail(invalidators,
                  rows_valid
                      and set(candidate) == candidate_fields
                      and len(identities) == len(set(identities))
                      and set(identities) == set(inventory_rows)
                      and candidate.get("schema_version")
                          == package_obligation_candidate.SELECTION_SCHEMA
                      and candidate.get("selection_validation_status") == "PASS"
                      and candidate.get("candidate_epistemic_status") == "INFERRED"
                      and candidate.get("owner_adoption_status")
                          == "NOT_ESTABLISHED"
                      and candidate.get("normative_closure") == "NOT_ESTABLISHED"
                      and candidate.get("claim_boundary")
                          == _CANDIDATE_PASS_CLAIM_BOUNDARY
                      and type(candidate.get("manifest_name")) is str
                      and bool(candidate["manifest_name"])
                      and type(candidate.get("manifest_digest")) is str
                      and _SHA256.fullmatch(
                          candidate["manifest_digest"]
                      ) is not None
                      and candidate.get("card_count") == 26
                      and set(card_digests)
                          == {kind.value for kind in ObjectKind}
                      and all(len(digests) == 1
                              for digests in card_digests.values())
                      and candidate.get("card_set_digest")
                          == core_obligation_union.value_digest(card_bindings)
                      and candidate.get("objective_count") == len(rows)
                      and candidate.get("candidate_rev4_class_counts")
                          == class_counts
                      and candidate.get("candidate_mechanism_counts")
                          == mechanism_counts
                      and candidate.get("candidate_reason_verdict_counts")
                          == reason_counts
                      and candidate.get("reason_disposition_counts")
                          == reason_dispositions
                      and candidate.get("semantic_identity_status")
                          == ("PASS" if reason_selected else "NOT_ESTABLISHED")
                      and all(
                          type(row) is dict
                          and row.get("candidate_semantic_identity_status")
                              == ("PASS" if reason_selected else
                                  "NOT_ESTABLISHED")
                          for row in rows
                      )
                      and candidate.get("reason_identity_count")
                          == (len(rows) if reason_selected else 0)
                      and candidate.get("reason_slot_identity_count")
                          == (234 if reason_selected else 0)
                      and (
                          type(candidate.get("reason_ledger_digest")) is str
                          and _SHA256.fullmatch(
                              candidate["reason_ledger_digest"]
                          ) is not None
                          if reason_selected else
                          candidate.get("reason_ledger_selection_status")
                              == "NOT_SELECTED"
                          and candidate.get("reason_ledger_digest") is None
                      )
                      and candidate.get("card_question_count") == 104
                      and candidate.get("cross_kind_decision_count") == 6
                      and candidate.get("owner_decision_count") == 110
                      and candidate.get("owner_decision_count")
                          == len(owner_decisions)
                      and questions_valid
                      and candidate.get("installed_inventory_digest")
                          == core_obligation_union.value_digest(inventory)
                      and candidate.get("selection_digest")
                          == _body_digest(candidate, "selection_digest"),
                  "PACKAGE_RECHECK_CANDIDATE_BINDING_DIFFERS")
    else:
        invalidators.add("PACKAGE_RECHECK_CANDIDATE_STATUS_DIFFERS")

    admission = report.get("owner_decision_admission")
    if type(admission) is not dict:
        invalidators.add("PACKAGE_RECHECK_OWNER_ADMISSION_FIELDS")
        return
    admission_status = admission.get("status")
    if admission_status in ("NOT_SELECTED", "FAIL", "UNKNOWN"):
        if admission_status == "NOT_SELECTED":
            expected_admission = (
                package_owner_decision.not_selected_owner_decision_admission()
            )
        elif admission_status == "FAIL":
            expected_admission = (
                package_owner_decision.failed_owner_decision_admission(
                    admission.get("error")
                )
            )
        else:
            expected_admission = (
                package_owner_decision.unavailable_owner_decision_admission(
                    admission.get("error")
                )
            )
        _fail(invalidators,
              type(admission.get("error")) is str
                  if admission_status in ("FAIL", "UNKNOWN") else
                  admission.get("error") is None,
              "PACKAGE_RECHECK_OWNER_ADMISSION_ERROR_DIFFERS")
        _fail(invalidators, admission == expected_admission,
              "PACKAGE_RECHECK_OWNER_ADMISSION_FALLBACK_DIFFERS")
    elif admission_status == "PASS":
        adopted = admission.get("adopted_decision_ids")
        expected_decisions = (
            package_owner_decision.expected_owner_decisions(candidate)
            if candidate_status == "PASS" else []
        )
        expected_ids = [row["decision_id"] for row in expected_decisions]
        expected_set_digest = core_obligation_union.bytes_digest(
            core_obligation_union.canonical_bytes(expected_decisions)
        )
        _fail(invalidators,
              candidate_status == "PASS"
                  and candidate.get("semantic_identity_status") == "PASS"
                  and admission.get("schema_version")
                      == package_owner_decision.ADMISSION_SCHEMA
                  and admission.get("authority_scope")
                      == "CONFIGURED_KEY_OWNER_STATEMENT_ONLY"
                  and admission.get("candidate_selection_digest")
                      == candidate.get("selection_digest")
                  and admission.get("source_coordinate_digest")
                      == report.get("source_coordinate_digest")
                  and admission.get("decision_set_digest") == expected_set_digest
                  and admission.get("decision_count") == len(expected_decisions)
                  and adopted == expected_ids
                  and admission.get("mechanism_digest")
                      == package_owner_decision.mechanism_digest()
                  and admission.get("error") is None,
              "PACKAGE_RECHECK_OWNER_ADMISSION_BINDING_DIFFERS")
    else:
        invalidators.add("PACKAGE_RECHECK_OWNER_ADMISSION_STATUS_DIFFERS")


def _branch_status(branch: Any) -> str | None:
    if type(branch) is not dict or type(branch.get("case_statuses")) is not dict:
        return None
    cases = branch["case_statuses"]
    if set(cases) != {"POSITIVE", "NEGATIVE", "UNKNOWN"}:
        return None
    return (
        "FAIL" if cases["NEGATIVE"] != "FAIL"
        or cases["UNKNOWN"] != "UNKNOWN"
        or cases["POSITIVE"] == "FAIL"
        else "PASS" if cases["POSITIVE"] == "PASS" else "UNKNOWN"
    )


def _reproduce_native_results(
        objects: tuple[NamespaceObject, ...], source_digest: str,
        ) -> list[dict[str, Any]]:
    records = [item.to_dict() for item in objects]
    collection_bytes = core_obligation_union.canonical_bytes({
        "schema_version": typed_facets.COLLECTION_VERSION,
        "objects": records,
    })
    collection_digest = composition_digest(objects)
    evidence_ref = core_obligation_union.bytes_digest(collection_bytes)
    generic_policy = object_facets.object_facets_policy(
        trust_roots=[source_digest]
    )
    typed_policy = typed_facets.typed_facets_policy(
        trust_roots=[source_digest]
    )

    def branch(*, request: dict[str, Any], cases: dict[str, Any],
               builder: Any, rechecker: Any, policy: dict[str, Any],
               result_fields: tuple[str, ...], checking_mechanism: str,
               certificate_schema_version: str) -> dict[str, Any]:
        observed = {}
        certificates = {}
        positive_result = None
        for case_kind in ("POSITIVE", "NEGATIVE", "UNKNOWN"):
            selected_request, evidence = cases[case_kind]
            try:
                certificate = builder(selected_request, evidence, policy=policy)
                replayed = rechecker(
                    certificate, expected_request=selected_request, policy=policy
                )
                observed[case_kind] = replayed["status"]
                certificates[case_kind] = core_obligation_union.bytes_digest(
                    certificate
                )
                if case_kind == "POSITIVE":
                    positive_result = replayed
            except (OSError, ImportError, MemoryError, RecursionError,
                    OverflowError) as exc:
                failure_observed = any(
                    (kind == "POSITIVE" and status == "FAIL")
                    or (kind == "NEGATIVE" and status != "FAIL")
                    or (kind == "UNKNOWN" and status != "UNKNOWN")
                    for kind, status in observed.items()
                )
                if failure_observed:
                    raise self_polish_native_replay.NativeReplayResourceError(
                        failure_observed=True
                    ) from exc
                raise
        status = (
            "FAIL" if observed["NEGATIVE"] != "FAIL"
            or observed["UNKNOWN"] != "UNKNOWN"
            or observed["POSITIVE"] == "FAIL"
            else "PASS" if observed["POSITIVE"] == "PASS" else "UNKNOWN"
        )
        if type(positive_result) is not dict:
            raise ValueError("positive native replay result unavailable")
        try:
            request_digest = core_obligation_union.value_digest(request)
        except (OSError, MemoryError, RecursionError, OverflowError) as exc:
            raise self_polish_native_replay.NativeReplayResourceError(
                failure_observed=status == "FAIL"
            ) from exc
        return {
            "coordinate": request["coordinate"],
            "semantic_version": request["semantic_version"],
            "proposition_digest": request["proposition_digest"],
            "checking_mechanism": checking_mechanism,
            "certificate_schema_version": certificate_schema_version,
            "status": status,
            "case_statuses": observed,
            "request_digest": request_digest,
            "certificate_digests": certificates,
            **{name: positive_result[name] for name in result_fields},
        }

    results = []
    for item in sorted(objects, key=lambda value: value.kind.value):
        generic_result = None
        typed_result = None
        try:
            generic_request = object_facets.object_facets_request(
                item, policy=generic_policy
            )
            generic_negative = self_polish_native_replay._negative_case(
                object_facets, "OBJECT:OBJECT-1.1", generic_request
            )
            generic_cases = {
                "POSITIVE": (
                    generic_request,
                    core_obligation_union.canonical_bytes(item.to_dict()),
                ),
                "NEGATIVE": generic_negative,
                "UNKNOWN": (generic_request, None),
            }
            typed_request = typed_facets.typed_facets_request(
                object_kind=item.kind.value,
                subject_id=item.object_id,
                object_digest=item.digest,
                collection_digest=collection_digest,
                evidence_ref=evidence_ref,
                policy=typed_policy,
            )
            typed_negative = self_polish_native_replay._negative_case(
                typed_facets,
                f"{item.kind.value}:{typed_request['coordinate']}",
                typed_request,
            )
            typed_cases = {
                "POSITIVE": (typed_request, collection_bytes),
                "NEGATIVE": typed_negative,
                "UNKNOWN": (typed_request, None),
            }
            generic_result = branch(
                request=generic_request, cases=generic_cases,
                builder=object_facets.build_object_facets_certificate,
                rechecker=object_facets.recheck_object_facets_certificate,
                policy=generic_policy,
                result_fields=("authority", "kind_specific_tier_1_conformance"),
                checking_mechanism=(
                    "verifier.domains.contracts.object_facets."
                    "recheck_object_facets_certificate"
                ),
                certificate_schema_version=object_facets.CERTIFICATE_VERSION,
            )
            typed_result = branch(
                request=typed_request, cases=typed_cases,
                builder=typed_facets.build_typed_facets_certificate,
                rechecker=typed_facets.recheck_typed_facets_certificate,
                policy=typed_policy,
                result_fields=("authority", "payload_semantics"),
                checking_mechanism=(
                    "verifier.domains.contracts.typed_facets."
                    "recheck_typed_facets_certificate"
                ),
                certificate_schema_version=typed_facets.CERTIFICATE_VERSION,
            )
            statuses = {generic_result["status"], typed_result["status"]}
            results.append({
                "object_id": item.object_id,
                "object_kind": item.kind.value,
                "status": (
                    "FAIL" if "FAIL" in statuses else
                    "PASS" if statuses == {"PASS"} else "UNKNOWN"
                ),
                "generic_object_facets": generic_result,
                "typed_facets": typed_result,
                "resource_status": "AVAILABLE",
            })
        except self_polish_native_replay.NativeReplayResourceError as exc:
            completed = [
                branch_result for branch_result in (
                    generic_result, typed_result
                ) if type(branch_result) is dict
            ]
            preserved_failure = exc.failure_observed or any(
                branch_result.get("status") == "FAIL"
                for branch_result in completed
            )
            results.append({
                "object_id": item.object_id,
                "object_kind": item.kind.value,
                "status": "FAIL" if preserved_failure else "UNKNOWN",
                "generic_object_facets": generic_result,
                "typed_facets": typed_result,
                "resource_status": "UNAVAILABLE",
            })
        except (OSError, ImportError, MemoryError, RecursionError,
                OverflowError):
            completed = [
                branch_result for branch_result in (
                    generic_result, typed_result
                ) if type(branch_result) is dict
            ]
            preserved_failure = any(
                branch_result.get("status") == "FAIL"
                for branch_result in completed
            )
            results.append({
                "object_id": item.object_id,
                "object_kind": item.kind.value,
                "status": "FAIL" if preserved_failure else "UNKNOWN",
                "generic_object_facets": generic_result,
                "typed_facets": typed_result,
                "resource_status": "UNAVAILABLE",
            })
        except (AttributeError, KeyError, RuntimeError, TypeError, ValueError,
                UnicodeError):
            results.append({
                "object_id": item.object_id,
                "object_kind": item.kind.value,
                "status": "FAIL",
                "generic_object_facets": generic_result,
                "typed_facets": typed_result,
                "resource_status": "AVAILABLE",
            })
    return results


def _reproduce_installed_replay(
        source_coordinate_digest: str) -> dict[str, Any]:
    """Rerun tier-1 and tier-2 specimens from this loaded distribution."""
    source_root = _package_root().parent
    tier_results: list[dict[str, Any]] = []
    memberships: list[dict[str, Any]] = []
    tier_outages: dict[int, bool] = {}
    tier_failures: dict[int, str] = {}
    for tier in (1, 2):
        try:
            manifest = self_polish_native_replay.build_installed_replay_manifest(
                tier,
                source_root,
                source_coordinate_digest=source_coordinate_digest,
                source_layout="loaded-distribution",
            )
            receipt = self_polish_native_replay.replay_native_obligations(
                manifest,
                source_root,
                tier=tier,
                expected_manifest_digest=core_obligation_union.bytes_digest(
                    manifest
                ),
                expected_source_coordinate_digest=source_coordinate_digest,
                source_layout="loaded-distribution",
            )
        except self_polish_native_replay.NativeReplayResourceError as exc:
            tier_outages[tier] = exc.failure_observed
            break
        except self_polish_native_replay.NativeReplayError as exc:
            tier_failures[tier] = str(exc)
            break
        except (OSError, ImportError, MemoryError, RecursionError,
                OverflowError):
            tier_outages[tier] = False
            break
        tier_results.append({
            "tier": tier,
            "status": receipt["status"],
            "manifest_digest": receipt["manifest_digest"],
            "receipt_digest": receipt["receipt_digest"],
            "membership_count": receipt["membership_count"],
            "case_count": receipt["case_count"],
            "invalidators": receipt["invalidators"],
        })
        memberships.extend(receipt["memberships"])
    return {
        "tier_results": tier_results,
        "memberships": memberships,
        "tier_outages": tier_outages,
        "tier_failures": tier_failures,
    }


def _installed_case_statuses(case: dict[str, Any]) -> set[str]:
    """Return conservative statuses valid for one retained installed case."""
    case_kind = case.get("case_kind")
    native_status = case.get("native_status")
    expected_native = self_polish_native_replay.CASE_OUTCOMES.get(case_kind)
    derived = (
        "PASS" if native_status == expected_native else
        "UNKNOWN" if case_kind == "POSITIVE"
        and native_status == "UNKNOWN" else "FAIL"
    )
    if case.get("native_result_digest") is not None:
        return {derived}
    if derived == "FAIL":
        return {"FAIL", "UNKNOWN"} if native_status == "UNKNOWN" else {"FAIL"}
    return {"UNKNOWN"}


def _member_mismatch_is_resource_explained(
        retained_row: dict[str, Any], reproduced_row: dict[str, Any]) -> bool:
    """Allow only the exact installed cases whose native result was unavailable."""
    if (retained_row.get("obligation_id") != reproduced_row.get("obligation_id")
            or retained_row.get("membership")
                != reproduced_row.get("membership")):
        return False
    retained_cases = {
        case.get("case_kind"): case for case in retained_row.get("cases", [])
        if type(case) is dict
    }
    reproduced_cases = {
        case.get("case_kind"): case for case in reproduced_row.get("cases", [])
        if type(case) is dict
    }
    if set(retained_cases) != set(reproduced_cases):
        return False
    explained = False
    stable_case_fields = (
        "case_kind", "expected_native_status", "mechanism_source_path",
        "mechanism_source_digest",
    )
    for case_kind in retained_cases:
        retained_case = retained_cases[case_kind]
        reproduced_case = reproduced_cases[case_kind]
        if retained_case == reproduced_case:
            continue
        if any(
            retained_case.get(field) != reproduced_case.get(field)
            for field in stable_case_fields
        ):
            return False
        retained_null = retained_case.get("native_result_digest") is None
        reproduced_null = reproduced_case.get("native_result_digest") is None
        unknown_outage = (
            retained_null
            and retained_case.get("native_status") == "UNKNOWN"
            and retained_case.get("status") == "UNKNOWN"
        ) or (
            reproduced_null
            and reproduced_case.get("native_status") == "UNKNOWN"
            and reproduced_case.get("status") == "UNKNOWN"
        )
        matching_preserved_failure = (
            (retained_null or reproduced_null)
            and retained_case.get("status") == "FAIL"
            and reproduced_case.get("status") == "FAIL"
            and retained_case.get("native_status")
                == reproduced_case.get("native_status")
        )
        if not (unknown_outage or matching_preserved_failure):
            return False
        explained = True
    if not explained:
        return False
    stable_member_fields = ("obligation_id", "membership", "cases")
    return all(
        retained_row.get(field) == reproduced_row.get(field)
        for field in stable_member_fields
        if field != "cases"
    )


def _native_row_mismatch_is_resource_explained(
        retained_row: dict[str, Any], reproduced_row: dict[str, Any]) -> bool:
    """Allow a native mismatch only on a branch explicitly absent by outage."""
    if (retained_row.get("object_id") != reproduced_row.get("object_id")
            or retained_row.get("object_kind")
                != reproduced_row.get("object_kind")):
        return False
    for outage_row, other_row in (
            (retained_row, reproduced_row),
            (reproduced_row, retained_row)):
        if (outage_row.get("resource_status") == "UNAVAILABLE"
                and outage_row.get("status") == "FAIL"
                and other_row.get("status") != "FAIL"
                and other_row.get("resource_status") != "UNAVAILABLE"):
            return False
    def failure_branches(row: dict[str, Any]) -> set[str]:
        branches = {
            field for field in ("generic_object_facets", "typed_facets")
            if type(row.get(field)) is dict
            and row[field].get("status") == "FAIL"
        }
        if branches or row.get("status") != "FAIL":
            return branches
        if row.get("generic_object_facets") is None:
            return {"generic_object_facets"}
        if row.get("typed_facets") is None:
            return {"typed_facets"}
        return set()

    for failure_row, other_row in (
            (retained_row, reproduced_row),
            (reproduced_row, retained_row)):
        for failure_branch in failure_branches(failure_row):
            other_branch = other_row.get(failure_branch)
            if (type(other_branch) is dict
                    and other_branch.get("status") != "FAIL"):
                return False
    resource_unavailable = (
        retained_row.get("resource_status") == "UNAVAILABLE"
        or reproduced_row.get("resource_status") == "UNAVAILABLE"
    )
    explained = (
        resource_unavailable
        and (
            retained_row.get("status") != reproduced_row.get("status")
            or retained_row.get("resource_status")
                != reproduced_row.get("resource_status")
        )
        and any(
            retained_row.get(field) is None
            and reproduced_row.get(field) is None
            for field in ("generic_object_facets", "typed_facets")
        )
    )
    for field in ("generic_object_facets", "typed_facets"):
        retained_branch = retained_row.get(field)
        reproduced_branch = reproduced_row.get(field)
        if retained_branch == reproduced_branch:
            continue
        retained_outage = (
            retained_branch is None
            and retained_row.get("resource_status") == "UNAVAILABLE"
        )
        reproduced_outage = (
            reproduced_branch is None
            and reproduced_row.get("resource_status") == "UNAVAILABLE"
        )
        if not (retained_outage or reproduced_outage):
            return False
        explained = True
    return explained


def _installed_replay_mismatch_is_resource_explained(
        retained: dict[str, Any], reproduced: dict[str, Any]) -> bool:
    """Require every differing tier/member to carry its own outage evidence."""
    retained_tiers = {
        row.get("tier"): row for row in retained.get("tier_results", [])
        if type(row) is dict
    }
    reproduced_tiers = {
        row.get("tier"): row for row in reproduced.get("tier_results", [])
        if type(row) is dict
    }
    retained_members = {
        row.get("obligation_id"): row for row in retained.get("memberships", [])
        if type(row) is dict
    }
    reproduced_members = {
        row.get("obligation_id"): row
        for row in reproduced.get("memberships", []) if type(row) is dict
    }
    any_difference = False
    for tier in (1, 2):
        retained_tier = retained_tiers.get(tier)
        reproduced_tier = reproduced_tiers.get(tier)
        retained_for_tier = {
            key: row for key, row in retained_members.items()
            if type(row.get("membership")) is dict
            and row["membership"].get("tier") == tier
        }
        reproduced_for_tier = {
            key: row for key, row in reproduced_members.items()
            if type(row.get("membership")) is dict
            and row["membership"].get("tier") == tier
        }
        if (retained_tier == reproduced_tier
                and retained_for_tier == reproduced_for_tier):
            continue
        any_difference = True
        if retained_tier is None or reproduced_tier is None:
            return False
        def tier_has_resource_outage(
                tier_row: dict[str, Any],
                members: dict[Any, dict[str, Any]],
                ) -> bool:
            marker = (
                type(tier_row.get("invalidators")) is list
                and "NATIVE_REPLAY_MECHANISM_UNAVAILABLE"
                    in tier_row["invalidators"]
            )
            if not marker:
                return False
            return not members or any(
                type(case) is dict
                and case.get("native_result_digest") is None
                for member in members.values()
                for case in member.get("cases", [])
            )

        def maskable_contract_failure(
                tier_row: dict[str, Any],
                members: dict[Any, dict[str, Any]],
                ) -> bool:
            invalidator_rows = tier_row.get("invalidators")
            if (members or tier_row.get("status") != "FAIL"
                    or type(invalidator_rows) is not list):
                return False
            contract_invalidators = set(invalidator_rows) - (
                {"NATIVE_REPLAY_MECHANISM_UNAVAILABLE"}
                | _SIM_TIER_INVALIDATORS
            )
            return (
                bool(contract_invalidators)
                and contract_invalidators
                    <= _OUTAGE_MASKABLE_CONTRACT_INVALIDATORS
            )

        def carries_sim_unknown_boundary(tier_row: dict[str, Any]) -> bool:
            invalidator_rows = tier_row.get("invalidators")
            return (
                type(invalidator_rows) is list
                and _SIM_TIER_INVALIDATORS <= set(invalidator_rows)
            )

        def completed_sim_positive_contradiction(
                members: dict[Any, dict[str, Any]],
                ) -> bool:
            sim_member = members.get("SIM:SIM-2.4")
            if type(sim_member) is not dict:
                return False
            positive = next((
                case for case in sim_member.get("cases", [])
                if type(case) is dict and case.get("case_kind") == "POSITIVE"
            ), None)
            return (
                type(positive) is dict
                and positive.get("native_result_digest") is not None
                and positive.get("native_status") in ("PASS", "FAIL")
            )

        retained_tier_outage = tier_has_resource_outage(
            retained_tier, retained_for_tier
        )
        reproduced_tier_outage = tier_has_resource_outage(
            reproduced_tier, reproduced_for_tier
        )
        tier_outage = retained_tier_outage or reproduced_tier_outage
        if (
            not retained_for_tier
            and carries_sim_unknown_boundary(retained_tier)
            and completed_sim_positive_contradiction(reproduced_for_tier)
        ) or (
            not reproduced_for_tier
            and carries_sim_unknown_boundary(reproduced_tier)
            and completed_sim_positive_contradiction(retained_for_tier)
        ):
            return False
        retained_whole_tier_outage = (
            retained_tier_outage and not retained_for_tier
            and set(retained_tier.get("invalidators", []))
                <= _MEMBER_TIER_INVALIDATORS
        )
        reproduced_whole_tier_outage = (
            reproduced_tier_outage and not reproduced_for_tier
            and set(reproduced_tier.get("invalidators", []))
                <= _MEMBER_TIER_INVALIDATORS
        )
        whole_tier_outage = (
            retained_whole_tier_outage or reproduced_whole_tier_outage
        )
        contract_outage_pair = (
            maskable_contract_failure(retained_tier, retained_for_tier)
            and reproduced_tier_outage
        ) or (
            maskable_contract_failure(reproduced_tier, reproduced_for_tier)
            and retained_tier_outage
        )
        if any(
            members and (
                type(tier_row.get("invalidators")) is not list
                or set(tier_row["invalidators"])
                    - _MEMBER_TIER_INVALIDATORS
            )
            for tier_row, members in (
                (retained_tier, retained_for_tier),
                (reproduced_tier, reproduced_for_tier),
            )
        ):
            return False
        if any(
            retained_tier.get(field) != reproduced_tier.get(field)
            for field in ("tier", "manifest_digest")
        ) or (
            not (whole_tier_outage or contract_outage_pair) and any(
                retained_tier.get(field) != reproduced_tier.get(field)
                for field in ("membership_count", "case_count")
            )
        ):
            return False
        if (retained_tier_outage
                and retained_tier.get("status") == "FAIL"
                and reproduced_tier.get("status") != "FAIL"
                and not reproduced_tier_outage):
            return False
        if (reproduced_tier_outage
                and reproduced_tier.get("status") == "FAIL"
                and retained_tier.get("status") != "FAIL"
                and not retained_tier_outage):
            return False
        member_difference = False
        for key in set(retained_for_tier) | set(reproduced_for_tier):
            retained_row = retained_for_tier.get(key)
            reproduced_row = reproduced_for_tier.get(key)
            if retained_row == reproduced_row:
                continue
            member_difference = True
            if retained_row is None or reproduced_row is None:
                if whole_tier_outage or contract_outage_pair:
                    continue
                return False
            if not _member_mismatch_is_resource_explained(
                    retained_row, reproduced_row):
                return False
        if retained_tier != reproduced_tier:
            if not tier_outage:
                if any(
                    retained_tier.get(field) != reproduced_tier.get(field)
                    for field in ("invalidators",)
                ) or not member_difference:
                    return False
            elif (not member_difference and retained_for_tier
                  and reproduced_for_tier):
                return False
    return any_difference


def _check_replay_sections(report: dict[str, Any],
                           objects: tuple[NamespaceObject, ...] | None,
                           invalidators: set[str], unknowns: set[str]) -> None:
    native = report.get("native_facets_replay")
    if type(native) is not dict or type(native.get("results")) is not list:
        invalidators.add("PACKAGE_RECHECK_NATIVE_REPLAY_FIELDS")
    else:
        results = native["results"]
        branches: list[Any] = []
        observed_kinds: list[Any] = []
        by_kind = (
            {item.kind.value: item for item in objects}
            if objects is not None else {}
        )
        rows_valid = True
        for row in results:
            if type(row) is not dict:
                rows_valid = False
                continue
            kind = row.get("object_kind")
            observed_kinds.append(kind)
            item = by_kind.get(kind)
            if item is None or row.get("object_id") != item.object_id:
                rows_valid = False
            generic = row.get("generic_object_facets")
            typed = row.get("typed_facets")
            resource_unavailable = row.get("resource_status") == "UNAVAILABLE"
            if row.get("resource_status") not in ("AVAILABLE", "UNAVAILABLE"):
                rows_valid = False
            if (generic is None or typed is None) and not resource_unavailable \
                    and row.get("status") != "FAIL":
                rows_valid = False
            if (generic is None or typed is None) \
                    and row.get("status") == "PASS":
                rows_valid = False
            if generic is not None and typed is not None \
                    and resource_unavailable:
                rows_valid = False
            if generic is None and typed is None:
                if row.get("status") not in ("FAIL", "UNKNOWN"):
                    rows_valid = False
                branches.extend(["UNKNOWN", "UNKNOWN"])
                continue
            if generic is None and typed is not None:
                rows_valid = False
            expected_branch_statuses = []
            for branch, branch_kind in (
                    (generic, "generic"), (typed, "typed")):
                if branch is None:
                    expected_branch_statuses.append(row.get("status"))
                    branches.append("UNKNOWN")
                    continue
                derived = _branch_status(branch)
                if derived is None or branch.get("status") != derived:
                    rows_valid = False
                expected_branch_statuses.append(derived)
                branches.append(branch.get("status"))
                if branch_kind == "generic":
                    if (branch.get("coordinate") != "OBJECT-1.1"
                            or branch.get("semantic_version")
                                != object_facets.SEMANTIC_VERSION
                            or branch.get("proposition_digest")
                                != object_facets.PROPOSITION_DIGEST
                            or branch.get("certificate_schema_version")
                                != object_facets.CERTIFICATE_VERSION
                            or branch.get("checking_mechanism") != (
                                "verifier.domains.contracts.object_facets."
                                "recheck_object_facets_certificate"
                            )
                            or branch.get("authority") != "NOT_ESTABLISHED"
                            or branch.get("kind_specific_tier_1_conformance")
                                != "NOT_ESTABLISHED"):
                        rows_valid = False
                elif type(kind) is not str or (
                    branch.get("coordinate") != typed_facets.coordinate(kind)
                    or branch.get("semantic_version")
                        != typed_facets.SEMANTIC_VERSION
                    or branch.get("proposition_digest")
                        != typed_facets.FacetDescriptor(kind).PROPOSITION_DIGEST
                    or branch.get("certificate_schema_version")
                        != typed_facets.CERTIFICATE_VERSION
                    or branch.get("checking_mechanism") != (
                        "verifier.domains.contracts.typed_facets."
                        "recheck_typed_facets_certificate"
                    )
                    or branch.get("authority") != "NOT_ESTABLISHED"
                    or branch.get("payload_semantics") != "NOT_ESTABLISHED"
                ):
                    rows_valid = False
            expected_row = (
                "FAIL" if "FAIL" in expected_branch_statuses else
                "PASS" if expected_branch_statuses == ["PASS", "PASS"]
                else "UNKNOWN"
            )
            if row.get("status") != expected_row:
                rows_valid = False
        _fail(invalidators,
              rows_valid
                  and len(observed_kinds) == len(set(observed_kinds)) == 26
                  and set(observed_kinds) == {kind.value for kind in ObjectKind},
              "PACKAGE_RECHECK_NATIVE_REPLAY_ROWS_DIFFER")
        counts = {name: branches.count(name) for name in ("PASS", "FAIL", "UNKNOWN")}
        expected_status = (
            "FAIL" if any(row.get("status") == "FAIL" for row in results) else
            "PASS" if counts["PASS"] == 52 else "UNKNOWN"
        )
        _fail(invalidators, len(results) == 26 and len(branches) == 52,
              "PACKAGE_RECHECK_NATIVE_REPLAY_COUNT_DIFFERS")
        _fail(invalidators,
              native.get("pass_count") == counts["PASS"]
              and native.get("fail_count") == counts["FAIL"]
              and native.get("unknown_count") == counts["UNKNOWN"]
              and native.get("status") == expected_status,
              "PACKAGE_RECHECK_NATIVE_REPLAY_STATUS_DIFFERS")
        if objects is not None:
            records = [item.to_dict() for item in objects]
            collection_bytes = core_obligation_union.canonical_bytes({
                "schema_version": typed_facets.COLLECTION_VERSION,
                "objects": records,
            })
            _fail(invalidators,
                  native.get("source_coordinate_digest")
                      == report.get("source_coordinate_digest")
                  and native.get("collection_digest")
                      == composition_digest(objects)
                  and native.get("collection_bytes_digest")
                      == core_obligation_union.bytes_digest(collection_bytes)
                  and native.get("generic_mechanism_digest")
                      == object_facets.mechanism_digest()
                  and native.get("typed_mechanism_digest")
                      == typed_facets.mechanism_digest(),
                  "PACKAGE_RECHECK_NATIVE_REPLAY_BINDING_DIFFERS")
            try:
                reproduced = _reproduce_native_results(
                    objects, report.get("source_coordinate_digest")
                )
            except self_polish_native_replay.NativeReplayResourceError as exc:
                if exc.failure_observed:
                    invalidators.add(
                        "PACKAGE_RECHECK_NATIVE_REPLAY_REPRODUCTION_FAILED"
                    )
                else:
                    unknowns.add(
                        "PACKAGE_RECHECK_NATIVE_REPLAY_REPRODUCTION_UNAVAILABLE"
                    )
                reproduced = None
            except (OSError, ImportError, MemoryError, RecursionError,
                    OverflowError):
                unknowns.add(
                    "PACKAGE_RECHECK_NATIVE_REPLAY_REPRODUCTION_UNAVAILABLE"
                )
                reproduced = None
            if reproduced is not None and reproduced != results:
                mismatches = [
                    (retained_row, reproduced_row)
                    for retained_row, reproduced_row in zip(
                        results, reproduced, strict=True
                    )
                    if retained_row != reproduced_row
                ]
                resource_unknown = bool(mismatches) and all(
                    _native_row_mismatch_is_resource_explained(
                        retained_row, reproduced_row
                    )
                    for retained_row, reproduced_row in mismatches
                )
                if resource_unknown:
                    unknowns.add(
                        "PACKAGE_RECHECK_NATIVE_REPLAY_REPRODUCTION_DIFFERS"
                    )
                else:
                    invalidators.add(
                        "PACKAGE_RECHECK_NATIVE_REPLAY_REPRODUCTION_DIFFERS"
                    )
        _fail(invalidators,
              native.get("object_count") == 26
                  and native.get("objective_count") == 52
                  and native.get("case_count") == 156
                  and native.get("positive_case_count") == 52
                  and native.get("negative_case_count") == 52
                  and native.get("unknown_case_count") == 52,
              "PACKAGE_RECHECK_NATIVE_REPLAY_COUNT_DIFFERS")
        _fail(invalidators,
              native.get("replay_digest") == _body_digest(native, "replay_digest"),
              "PACKAGE_RECHECK_NATIVE_REPLAY_DIGEST_DIFFERS")
    installed = report.get("installed_native_case_replay")
    if type(installed) is not dict or type(installed.get("tier_results")) is not list \
            or type(installed.get("memberships")) is not list:
        invalidators.add("PACKAGE_RECHECK_INSTALLED_REPLAY_FIELDS")
    else:
        tier_results = installed["tier_results"]
        valid_tiers = all(
            type(row) is dict
            and type(row.get("tier")) is int
            and not isinstance(row.get("tier"), bool)
            and row.get("tier") in (1, 2)
            and type(row.get("case_count")) is int
            and not isinstance(row.get("case_count"), bool)
            and row.get("case_count") >= 0
            and type(row.get("membership_count")) is int
            and not isinstance(row.get("membership_count"), bool)
            and row.get("membership_count") >= 0
            for row in tier_results
        )
        tiers = [row.get("tier") for row in tier_results if type(row) is dict]
        statuses = [row.get("status") for row in tier_results if type(row) is dict]
        complete = valid_tiers and tiers == [1, 2]
        producible_tier_prefix = tiers in ([], [1], [1, 2])
        aggregate = (
            "FAIL" if "FAIL" in statuses else
            "UNKNOWN" if "UNKNOWN" in statuses else
            "PASS" if statuses else "NOT_SELECTED"
        )
        reported_status = installed.get("status")
        resource_status = installed.get("resource_status")
        status_valid = (
            reported_status == aggregate if complete else
            reported_status in ("UNKNOWN", "FAIL") if tier_results else
            reported_status in ("NOT_SELECTED", "UNKNOWN", "FAIL")
        )
        if "FAIL" in statuses:
            status_valid = status_valid and reported_status == "FAIL"
        resource_marker_valid = (
            resource_status == "NOT_SELECTED"
            and reported_status == "NOT_SELECTED"
            and not tier_results
            and not installed["memberships"]
        ) or (
            resource_status == "UNAVAILABLE"
            and (
                not complete
                or any(
                    type(row) is dict
                    and type(row.get("invalidators")) is list
                    and "NATIVE_REPLAY_MECHANISM_UNAVAILABLE"
                        in row["invalidators"]
                    for row in tier_results
                )
            )
        ) or (
            resource_status == "AVAILABLE"
            and not any(
                type(row) is dict
                and type(row.get("invalidators")) is list
                and "NATIVE_REPLAY_MECHANISM_UNAVAILABLE"
                    in row["invalidators"]
                for row in tier_results
            )
            and (complete or reported_status == "FAIL")
        )
        expected_cases = sum(
            row["case_count"] for row in tier_results
            if type(row) is dict and type(row.get("case_count")) is int
            and not isinstance(row.get("case_count"), bool)
        )
        expected_memberships = sum(
            row["membership_count"] for row in tier_results
            if type(row) is dict and type(row.get("membership_count")) is int
            and not isinstance(row.get("membership_count"), bool)
        )
        membership_rows_valid = True
        case_outage_tiers: set[int] = set()
        membership_keys: list[tuple[Any, Any, Any]] = []
        try:
            registry = self_polish_native_replay.installed_native_replay_registry()
            registry_closure = (
                self_polish_native_replay.installed_registry_closure()
            )
        except (OSError, ImportError, MemoryError, RecursionError,
                OverflowError):
            unknowns.add("PACKAGE_RECHECK_INSTALLED_REPLAY_UNAVAILABLE")
            return
        except RuntimeError:
            invalidators.add(
                "PACKAGE_RECHECK_INSTALLED_REPLAY_MECHANISM_CONTRADICTION"
            )
            return
        registry_by_id = {
            row["obligation_id"]: row
            for tier_rows in registry["tiers"].values() for row in tier_rows
        }
        memberships_by_tier: dict[int, list[dict[str, Any]]] = {1: [], 2: []}
        for row in installed["memberships"]:
            if (type(row) is not dict or type(row.get("membership")) is not dict
                    or type(row.get("cases")) is not list):
                membership_rows_valid = False
                continue
            membership = row["membership"]
            obligation_id = row.get("obligation_id")
            registered = registry_by_id.get(obligation_id)
            key = (
                membership.get("object_kind"), membership.get("tier"),
                membership.get("coordinate"),
            )
            membership_keys.append(key)
            tier = membership.get("tier")
            if tier in memberships_by_tier:
                memberships_by_tier[tier].append(row)
            cases_valid = len(row["cases"]) == 3
            case_statuses = []
            observed_case_kinds = []
            member_has_case_outage = False
            for case in row["cases"]:
                if type(case) is not dict or set(case) != {
                        "case_kind", "expected_native_status", "native_status",
                        "status", "native_result_digest", "mechanism_source_path",
                        "mechanism_source_digest",
                        }:
                    cases_valid = False
                    continue
                case_kind = case.get("case_kind")
                expected_native = self_polish_native_replay.CASE_OUTCOMES.get(
                    case_kind
                )
                if (case.get("expected_native_status") != expected_native
                        or case.get("native_status")
                            not in ("PASS", "FAIL", "UNKNOWN")
                        or case.get("status")
                            not in _installed_case_statuses(case)
                        or (
                            case.get("native_result_digest") is not None
                            and (
                                type(case.get("native_result_digest")) is not str
                                or _SHA256.fullmatch(
                                    case["native_result_digest"]
                                ) is None
                            )
                        )
                        or type(case.get("mechanism_source_path")) is not str
                        or not case.get("mechanism_source_path")
                        or type(case.get("mechanism_source_digest")) is not str
                        or _SHA256.fullmatch(
                            case["mechanism_source_digest"]
                        ) is None):
                    cases_valid = False
                observed_case_kinds.append(case_kind)
                case_statuses.append(case.get("status"))
                if case.get("native_result_digest") is None:
                    member_has_case_outage = True
            if member_has_case_outage and tier in memberships_by_tier:
                case_outage_tiers.add(tier)
            derived = (
                "FAIL" if "FAIL" in case_statuses else
                "UNKNOWN" if "UNKNOWN" in case_statuses else
                "PASS" if case_statuses else "FAIL"
            )
            if (set(row) != {
                    "obligation_id", "membership", "cases", "status",
                    "native_replay_digest",
                    }
                    or registered is None
                    or obligation_id != (
                        f"{membership.get('object_kind')}:"
                        f"{membership.get('coordinate')}"
                    )
                    or set(membership) != {
                        "object_kind", "tier", "coordinate", "proposition_digest",
                        "semantic_version", "certificate_schema_version",
                        "checking_mechanism", "scope",
                    }
                    or any(
                        membership.get(field) != registered.get(field)
                        for field in membership
                    )
                    or observed_case_kinds
                        != list(self_polish_native_replay.CASE_KINDS)
                    or not cases_valid
                    or len(case_statuses) != len(row["cases"])
                    or row.get("status") != derived
                    or row.get("native_replay_digest")
                        != _body_digest(row, "native_replay_digest")):
                membership_rows_valid = False
        tier_rows_valid = True
        for tier_row in tier_results:
            if type(tier_row) is not dict:
                tier_rows_valid = False
                continue
            tier = tier_row.get("tier")
            selected_memberships = memberships_by_tier.get(tier, [])
            selected_statuses = [row.get("status") for row in selected_memberships]
            invalidator_rows = tier_row.get("invalidators")
            outage_marker = (
                type(invalidator_rows) is list
                and "NATIVE_REPLAY_MECHANISM_UNAVAILABLE"
                    in invalidator_rows
            )
            whole_tier_outage = selected_statuses == [] and outage_marker
            case_level_outage = tier in case_outage_tiers
            sim_codes = (
                set(invalidator_rows) & _SIM_TIER_INVALIDATORS
                if type(invalidator_rows) is list else set()
            )
            sim_member = next((
                row for row in selected_memberships
                if row.get("obligation_id") == "SIM:SIM-2.4"
            ), None)
            sim_positive_case = next((
                case for case in sim_member.get("cases", [])
                if type(case) is dict and case.get("case_kind") == "POSITIVE"
            ), None) if type(sim_member) is dict else None
            sim_positive_unknown = (
                type(sim_positive_case) is dict
                and sim_positive_case.get("native_status") == "UNKNOWN"
            )
            sim_boundary_valid = (
                (not sim_codes or sim_codes == _SIM_TIER_INVALIDATORS)
                and (
                    not sim_codes
                    or tier == 2 and (
                        sim_positive_unknown or not selected_memberships
                    )
                )
                and (
                    tier != 2
                    or not sim_positive_unknown
                    or sim_positive_case.get("native_result_digest") is None
                    or sim_codes == _SIM_TIER_INVALIDATORS
                )
            )
            derived_tier_status = (
                "FAIL" if "FAIL" in selected_statuses else
                "UNKNOWN" if "UNKNOWN" in selected_statuses else
                "PASS" if selected_statuses else
                "FAIL" if whole_tier_outage
                and tier_row.get("status") == "FAIL" else
                "UNKNOWN" if whole_tier_outage else "FAIL"
            )
            registry_ids = {
                row["obligation_id"] for row in registry["tiers"].get(
                    str(tier), []
                )
            }
            selected_ids = {
                row.get("obligation_id") for row in selected_memberships
            }
            reconstructed_receipt = {
                "schema_version": self_polish_native_replay.RECEIPT_SCHEMA,
                "tier": tier,
                "status": tier_row.get("status"),
                "manifest_digest": tier_row.get("manifest_digest"),
                "source_coordinate_digest": report.get(
                    "source_coordinate_digest"
                ),
                "registry_digest": (
                    None if whole_tier_outage
                    else registry.get("registry_digest")
                ),
                "registry_closure_digest": (
                    None if whole_tier_outage else registry_closure.get(
                        "closure_digest"
                    )
                ),
                "memberships": selected_memberships,
                "membership_count": tier_row.get("membership_count"),
                "case_count": tier_row.get("case_count"),
                "invalidators": invalidator_rows,
                "polished": False,
                "release_authority": "NONE",
                "whole_tier_conformance": "NOT_ESTABLISHED",
            }
            admissible_receipt_digests = {
                core_obligation_union.value_digest(reconstructed_receipt)
            }
            if derived_tier_status == "FAIL" and not selected_memberships:
                null_registry_receipt = dict(reconstructed_receipt)
                null_registry_receipt["registry_digest"] = None
                null_registry_receipt["registry_closure_digest"] = None
                admissible_receipt_digests.add(
                    core_obligation_union.value_digest(null_registry_receipt)
                )
            if (set(tier_row) != {
                    "tier", "status", "manifest_digest", "receipt_digest",
                    "membership_count", "case_count", "invalidators",
                    }
                    or tier_row.get("status") != derived_tier_status
                    or tier_row.get("membership_count")
                        != len(selected_memberships)
                    or tier_row.get("case_count")
                        != 3 * len(selected_memberships)
                    or type(invalidator_rows) is not list
                    or invalidator_rows != sorted(set(invalidator_rows))
                    or (
                        selected_memberships
                        and set(invalidator_rows)
                            - _MEMBER_TIER_INVALIDATORS
                    )
                    or (
                        whole_tier_outage
                        and tier_row.get("status") != "FAIL"
                        and set(invalidator_rows)
                            - _MEMBER_TIER_INVALIDATORS
                    )
                    or not sim_boundary_valid
                    or outage_marker != (
                        whole_tier_outage or case_level_outage
                    )
                    or (
                        selected_memberships
                        and selected_ids != registry_ids
                    )
                    or (derived_tier_status == "PASS"
                        and invalidator_rows != [])
                    or type(tier_row.get("receipt_digest")) is not str
                    or _SHA256.fullmatch(tier_row["receipt_digest"]) is None
                    or tier_row.get("receipt_digest")
                        not in admissible_receipt_digests
                    or type(tier_row.get("manifest_digest")) is not str
                    or _SHA256.fullmatch(tier_row["manifest_digest"]) is None):
                tier_rows_valid = False
        _fail(invalidators,
              valid_tiers and len(tiers) == len(set(tiers))
              and producible_tier_prefix
              and status_valid
              and resource_marker_valid
              and membership_rows_valid
              and tier_rows_valid
              and len(membership_keys) == len(set(membership_keys))
              and installed.get("membership_count")
                  == len(installed["memberships"])
              and expected_memberships == len(installed["memberships"])
              and installed.get("case_count") == expected_cases,
              "PACKAGE_RECHECK_INSTALLED_REPLAY_STATUS_DIFFERS")
        _fail(invalidators,
              installed.get("source_coordinate_digest")
                  == report.get("source_coordinate_digest"),
              "PACKAGE_RECHECK_INSTALLED_REPLAY_BINDING_DIFFERS")
        _fail(invalidators,
              installed.get("replay_digest")
                  == _body_digest(installed, "replay_digest"),
              "PACKAGE_RECHECK_INSTALLED_REPLAY_DIGEST_DIFFERS")
        if reported_status != "NOT_SELECTED":
            try:
                reproduced_replay = _reproduce_installed_replay(
                    report.get("source_coordinate_digest")
                )
            except (OSError, ImportError, MemoryError, RecursionError,
                    OverflowError):
                unknowns.add("PACKAGE_RECHECK_INSTALLED_REPLAY_UNAVAILABLE")
            else:
                tier_failures = reproduced_replay.pop("tier_failures", {})
                tier_outages = reproduced_replay.pop("tier_outages", {})
                comparison_ceiling = 3
                first_outage_tier = min(tier_outages, default=3)
                observable_failures = {
                    tier: failure for tier, failure in tier_failures.items()
                    if tier < first_outage_tier
                }
                if observable_failures:
                    first_failure_tier = min(observable_failures)
                    expected_prefix = list(range(1, first_failure_tier))
                    contract_failure_shape_matches = (
                        reported_status == "FAIL"
                        and tiers == expected_prefix
                    )
                    contract_failure_matches = (
                        contract_failure_shape_matches
                        and resource_status in ("AVAILABLE", "UNAVAILABLE")
                    )
                    if (contract_failure_shape_matches
                            and resource_status == "UNAVAILABLE"):
                        unknowns.add(
                            "PACKAGE_RECHECK_INSTALLED_REPLAY_"
                            "REPRODUCTION_DIFFERS"
                        )
                    comparison_ceiling = first_failure_tier
                else:
                    contract_failure_matches = True
                if not contract_failure_matches:
                    invalidators.add(
                        "PACKAGE_RECHECK_INSTALLED_REPLAY_REPRODUCTION_FAILED"
                    )
                retained_tiers_by_id = {
                    row.get("tier"): row for row in tier_results
                    if type(row) is dict
                }
                retained_outer_failure_tier = (
                    len(tiers) + 1
                    if reported_status == "FAIL"
                    and resource_status == "UNAVAILABLE"
                    and "FAIL" not in statuses
                    and tiers in ([], [1]) else None
                )
                for tier, failure_observed in tier_outages.items():
                    if tier >= comparison_ceiling:
                        continue
                    retained_tier = retained_tiers_by_id.get(tier)
                    retained_tier_outage = (
                        type(retained_tier) is dict
                        and type(retained_tier.get("invalidators")) is list
                        and "NATIVE_REPLAY_MECHANISM_UNAVAILABLE"
                            in retained_tier["invalidators"]
                    )
                    retained_outer_outage = (
                        retained_tier is None
                        and resource_status == "UNAVAILABLE"
                    )
                    if failure_observed and (
                        retained_tier is None and not retained_outer_outage
                        or type(retained_tier) is dict
                        and retained_tier.get("status") != "FAIL"
                        and not retained_tier_outage
                    ):
                        invalidators.add(
                            "PACKAGE_RECHECK_INSTALLED_REPLAY_"
                            "REPRODUCTION_FAILED"
                        )
                    else:
                        unknowns.add(
                            "PACKAGE_RECHECK_INSTALLED_REPLAY_UNAVAILABLE"
                        )
                comparison_ceiling = min(
                    comparison_ceiling, first_outage_tier
                )
                available_tiers = {
                    row.get("tier")
                    for row in reproduced_replay.get("tier_results", [])
                    if type(row) is dict
                    and row.get("tier", 3) < comparison_ceiling
                }
                reproduced_tiers_by_id = {
                    row.get("tier"): row
                    for row in reproduced_replay.get("tier_results", [])
                    if type(row) is dict
                }
                if retained_outer_failure_tier in available_tiers:
                    reproduced_failure_tier = reproduced_tiers_by_id.get(
                        retained_outer_failure_tier
                    )
                    if (type(reproduced_failure_tier) is dict
                            and reproduced_failure_tier.get("status")
                                != "FAIL"
                            and "NATIVE_REPLAY_MECHANISM_UNAVAILABLE" not in
                                reproduced_failure_tier.get(
                                    "invalidators", []
                                )):
                        invalidators.add(
                            "PACKAGE_RECHECK_INSTALLED_REPLAY_"
                            "REPRODUCTION_DIFFERS"
                        )
                retained_available = {
                    "tier_results": [
                        row for row in tier_results
                        if type(row) is dict
                        and row.get("tier") in available_tiers
                    ],
                    "memberships": [
                        row for row in installed["memberships"]
                        if type(row) is dict
                        and type(row.get("membership")) is dict
                        and row["membership"].get("tier") in available_tiers
                    ],
                }
                retained_tier_ids = set(retained_tiers_by_id)
                missing_retained_tiers = available_tiers - retained_tier_ids
                reproduced_shared = {
                    "tier_results": [
                        row for row in reproduced_replay.get(
                            "tier_results", []
                        ) if type(row) is dict
                        and row.get("tier") in retained_tier_ids
                        and row.get("tier", 3) < comparison_ceiling
                    ],
                    "memberships": [
                        row for row in reproduced_replay.get("memberships", [])
                        if type(row) is dict
                        and type(row.get("membership")) is dict
                        and row["membership"].get("tier")
                            in retained_tier_ids
                        and row["membership"].get("tier", 3)
                            < comparison_ceiling
                    ],
                }
                retained_shared = {
                    "tier_results": [
                        row for row in retained_available["tier_results"]
                        if row.get("tier") in retained_tier_ids
                    ],
                    "memberships": [
                        row for row in retained_available["memberships"]
                        if row["membership"].get("tier")
                            in retained_tier_ids
                    ],
                }
                if missing_retained_tiers:
                    if resource_status == "UNAVAILABLE":
                        unknowns.add(
                            "PACKAGE_RECHECK_INSTALLED_REPLAY_REPRODUCTION_DIFFERS"
                        )
                    else:
                        invalidators.add(
                            "PACKAGE_RECHECK_INSTALLED_REPLAY_REPRODUCTION_DIFFERS"
                        )
                if reproduced_shared != retained_shared:
                    if _installed_replay_mismatch_is_resource_explained(
                            retained_shared, reproduced_shared):
                        unknowns.add(
                            "PACKAGE_RECHECK_INSTALLED_REPLAY_REPRODUCTION_DIFFERS"
                        )
                    else:
                        invalidators.add(
                            "PACKAGE_RECHECK_INSTALLED_REPLAY_REPRODUCTION_DIFFERS"
                        )


def _check_route_projection(report: dict[str, Any], inventory: dict[str, Any],
                            invalidators: set[str]) -> None:
    projection = report.get("core_route_projection")
    memberships = report.get("core_route_memberships")
    cells = report.get("core_family_cells")
    if type(projection) is not dict or type(memberships) is not list \
            or type(cells) is not list:
        invalidators.add("PACKAGE_RECHECK_CORE_PROJECTION_FIELDS")
        return
    inventory_keys = {
        (cell["object_kind"], cell["tier"], route["coordinate"])
        for cell in inventory["family_cells"]
        for route in cell["registered_route_memberships"]
    }
    inventory_rows = {
        (cell["object_kind"], cell["tier"], route["coordinate"]): {
            **route,
            "object_kind": cell["object_kind"],
            "tier": cell["tier"],
            "tier_name": cell["tier_name"],
        }
        for cell in inventory["family_cells"]
        for route in cell["registered_route_memberships"]
    }
    observed_keys = [
        (row.get("object_kind"), row.get("tier"), row.get("coordinate"))
        for row in memberships if type(row) is dict
    ]
    _fail(invalidators,
          len(observed_keys) == len(set(observed_keys))
              and set(observed_keys) == inventory_keys,
          "PACKAGE_RECHECK_CORE_MEMBERSHIP_CENSUS_DIFFERS")
    native = report.get("native_facets_replay")
    native_rows = native.get("results") if type(native) is dict else None
    native_by_key: dict[tuple[Any, Any], dict[str, Any]] = {}
    unresolved_native: dict[tuple[Any, Any], Any] = {}
    duplicate_native_identity = False
    if type(native_rows) is list:
        for native_row in native_rows:
            if type(native_row) is not dict:
                continue
            kind = native_row.get("object_kind")
            generic = native_row.get("generic_object_facets")
            typed = native_row.get("typed_facets")
            if kind == "OBJECT":
                if type(generic) is dict:
                    if (kind, generic.get("coordinate")) in native_by_key:
                        duplicate_native_identity = True
                    native_by_key[(kind, generic.get("coordinate"))] = generic
                else:
                    unresolved_native[(kind, "OBJECT-1.1")] = native_row.get("status")
            if type(kind) is str:
                typed_coordinate = typed_facets.coordinate(kind)
                if type(typed) is dict:
                    if (kind, typed.get("coordinate")) in native_by_key:
                        duplicate_native_identity = True
                    native_by_key[(kind, typed.get("coordinate"))] = typed
                else:
                    unresolved_native[(kind, typed_coordinate)] = native_row.get("status")
    expected_native_keys = {
        (kind.value, typed_facets.coordinate(kind.value)) for kind in ObjectKind
    } | {("OBJECT", "OBJECT-1.1")}
    installed = report.get("installed_native_case_replay")
    installed_memberships = (
        installed.get("memberships") if type(installed) is dict else None
    )
    specimen_by_key: dict[tuple[Any, Any], dict[str, Any]] = {}
    duplicate_specimen_identity = False
    if type(installed_memberships) is list:
        for specimen in installed_memberships:
            member = specimen.get("membership") if type(specimen) is dict else None
            if type(member) is dict:
                specimen_key = (
                    member.get("object_kind"), member.get("coordinate")
                )
                if specimen_key in specimen_by_key:
                    duplicate_specimen_identity = True
                specimen_by_key[specimen_key] = specimen
    installed_tier_statuses = {
        row.get("tier"): row.get("status")
        for row in (
            installed.get("tier_results", []) if type(installed) is dict else []
        ) if type(row) is dict
    }
    candidate = report.get("candidate_obligation_ledger")
    candidate_rows = {
        (row.get("object_kind"), row.get("coordinate")): row
        for row in (
            candidate.get("rows", []) if type(candidate) is dict
            and candidate.get("status") == "PASS" else []
        ) if type(row) is dict
    }
    admission = report.get("owner_decision_admission")
    adopted = set(
        admission.get("adopted_decision_ids", [])
        if type(admission) is dict and admission.get("status") == "PASS" else []
    )
    rows_bound = True
    mapped_native_count = 0
    identity_failure = (
        duplicate_native_identity or duplicate_specimen_identity
    )
    identity_unknown = False
    membership_fields = {
        "object_kind", "tier", "tier_name", "semantic_version", "coordinate",
        "checking_mechanism", "proposition_digest", "certificate_schema_version",
        "scope", "native_route_identity_status",
        "selected_package_native_replay_status",
        "installed_specimen_replay_status", "installed_specimen_replay_digest",
        "installed_specimen_case_count", "native_replay_request_digest",
        "normative_full_family_closure", "candidate_obligation_identity_status",
        "candidate_semantic_identity_status", "candidate_obligation_row_digest",
        "candidate_rev4_class", "candidate_mechanism_assessment",
        "candidate_owner_disposition_status", "owner_decision_refs", "status",
    }
    for row in memberships:
        if type(row) is not dict:
            rows_bound = False
            continue
        if set(row) != membership_fields:
            rows_bound = False
        key = (row.get("object_kind"), row.get("tier"), row.get("coordinate"))
        route = inventory_rows.get(key)
        if route is None or any(
            row.get(field) != route.get(field)
            for field in (
                "object_kind", "tier", "tier_name", "semantic_version",
                "coordinate", "checking_mechanism", "proposition_digest",
                "certificate_schema_version", "scope",
            )
        ):
            rows_bound = False
            continue
        native_key = (row.get("object_kind"), row.get("coordinate"))
        replay = native_by_key.get(native_key)
        selected_native = native_key in expected_native_keys
        if replay is not None:
            mapped_native_count += 1
            native_identity = "PASS" if all(
                replay.get(field) == route.get(field)
                for field in (
                    "semantic_version", "coordinate", "checking_mechanism",
                    "proposition_digest", "certificate_schema_version",
                )
            ) and row.get("tier") == 1 else "FAIL"
            replay_status = (
                replay.get("status") if native_identity == "PASS" else "FAIL"
            )
            replay_digest = replay.get("request_digest")
            if native_identity == "FAIL":
                identity_failure = True
        elif selected_native:
            native_identity = "NOT_ESTABLISHED"
            replay_status = (
                "FAIL" if unresolved_native.get(native_key) == "FAIL" else "UNKNOWN"
            )
            replay_digest = None
            identity_unknown = True
        else:
            native_identity = "NOT_RUN"
            replay_status = "NOT_RUN"
            replay_digest = None
        specimen = specimen_by_key.get(native_key)
        if specimen is not None:
            member = specimen.get("membership")
            specimen_exact = type(member) is dict and all(
                member.get(field) == route.get(field)
                for field in (
                    "object_kind", "tier", "semantic_version", "coordinate",
                    "proposition_digest", "certificate_schema_version",
                    "checking_mechanism", "scope",
                )
            )
            specimen_status = specimen.get("status") if specimen_exact else "FAIL"
            specimen_digest = (
                specimen.get("native_replay_digest") if specimen_exact else None
            )
            specimen_case_count = (
                len(specimen.get("cases"))
                if specimen_exact and type(specimen.get("cases")) is list else 0
            )
            if not specimen_exact:
                identity_failure = True
        elif row.get("tier") in (1, 2):
            selected_tier_status = installed_tier_statuses.get(
                row.get("tier")
            )
            if selected_tier_status is None:
                selected_tier_status = (
                    "NOT_SELECTED"
                    if type(installed) is dict
                    and installed.get("status") == "NOT_SELECTED"
                    else "UNKNOWN"
                )
            specimen_status = (
                "FAIL" if selected_tier_status == "PASS" else
                "UNKNOWN" if selected_tier_status in ("FAIL", "UNKNOWN")
                else "NOT_RUN"
            )
            specimen_digest = None
            specimen_case_count = 0
            if selected_tier_status == "PASS":
                identity_failure = True
            elif selected_tier_status in ("FAIL", "UNKNOWN"):
                identity_unknown = True
        else:
            specimen_status = "NOT_RUN"
            specimen_digest = None
            specimen_case_count = 0
        candidate_row = candidate_rows.get(native_key)
        candidate_identity = (
            "PASS" if candidate_row is not None
            and candidate_row.get("candidate_semantic_identity_status") == "PASS"
            else "UNKNOWN" if candidate_row is not None else
            "NOT_SELECTED" if type(candidate) is dict
            and candidate.get("status") == "NOT_SELECTED" else "NOT_RETAINED"
        )
        expected_owner_refs = []
        for decision_id, applies in (
                ("CTC-1", True),
                ("CTC-2", row.get("tier") == 7),
                ("CTC-3", candidate_row is not None
                 and candidate_row.get("candidate_rev4_class") == "REASON_PENDING"),
                ("CTC-5", row.get("tier") == 1),
                ("CTC-6", row.get("object_kind") == "MODEL")):
            if applies and decision_id in adopted:
                expected_owner_refs.append(decision_id)
        expected_owner_refs.extend(
            decision_id for decision_id in (
                f"{row.get('object_kind')}-Q{index}" for index in range(1, 5)
            ) if decision_id in adopted
        )
        expected_status = (
            "FAIL" if "FAIL" in (
                native_identity, replay_status, specimen_status
            ) else "UNKNOWN"
        )
        if not (
            row.get("native_route_identity_status") == native_identity
            and row.get("selected_package_native_replay_status") == replay_status
            and row.get("native_replay_request_digest") == replay_digest
            and row.get("installed_specimen_replay_status") == specimen_status
            and row.get("installed_specimen_replay_digest") == specimen_digest
            and row.get("installed_specimen_case_count") == specimen_case_count
            and row.get("normative_full_family_closure") == "NOT_ESTABLISHED"
            and row.get("candidate_obligation_identity_status")
                == candidate_identity
            and row.get("candidate_semantic_identity_status") == (
                candidate_row.get("candidate_semantic_identity_status")
                if candidate_row is not None else "NOT_ESTABLISHED"
            )
            and row.get("candidate_obligation_row_digest") == (
                candidate_row.get("candidate_row_digest")
                if candidate_row is not None else None
            )
            and row.get("candidate_rev4_class") == (
                candidate_row.get("candidate_rev4_class")
                if candidate_row is not None else None
            )
            and row.get("candidate_mechanism_assessment") == (
                candidate_row.get("candidate_mechanism_assessment")
                if candidate_row is not None else None
            )
            and row.get("candidate_owner_disposition_status") == (
                candidate_row.get("owner_disposition_status")
                if candidate_row is not None else "NOT_ESTABLISHED"
            )
            and row.get("owner_decision_refs")
                == sorted(set(expected_owner_refs))
            and row.get("status") == expected_status
        ):
            rows_bound = False
    _fail(invalidators, rows_bound,
          "PACKAGE_RECHECK_CORE_MEMBERSHIP_BINDING_DIFFERS")
    native_status = native.get("status") if type(native) is dict else None
    if mapped_native_count != 27:
        if native_status == "PASS":
            identity_failure = True
        else:
            identity_unknown = True
    expected_identity_status = (
        "FAIL" if identity_failure else
        "UNKNOWN" if identity_unknown else "PASS"
    )
    expected_unknown_causes = sorted({
        f"{row.get('object_kind')}:{row.get('coordinate')}"
        for row in memberships
        if row.get("selected_package_native_replay_status") == "UNKNOWN"
        or row.get("installed_specimen_replay_status") == "UNKNOWN"
    })
    failed = any(row.get("status") == "FAIL" for row in memberships)
    unknown = bool(expected_unknown_causes)
    expected_status = "FAIL" if failed else "UNKNOWN" if unknown else "PASS"
    _fail(invalidators,
          projection.get("status") == expected_status
              and projection.get("route_identity_projection_status")
                  == expected_identity_status
              and projection.get("unknown_causes") == expected_unknown_causes,
          "PACKAGE_RECHECK_CORE_PROJECTION_STATUS_DIFFERS")
    _fail(invalidators,
          projection.get("membership_count") == len(memberships)
          and projection.get("mapped_checker_discrimination_count")
              == mapped_native_count
          and projection.get("expected_mapped_checker_discrimination_count") == 27
          and projection.get("not_run_count") == sum(
              row.get("selected_package_native_replay_status") == "NOT_RUN"
              for row in memberships
          )
          and projection.get("unavailable_selected_count") == sum(
              row.get("selected_package_native_replay_status") == "UNKNOWN"
              for row in memberships
          )
          and projection.get("installed_specimen_pass_count") == sum(
              row.get("installed_specimen_replay_status") == "PASS"
              for row in memberships
          )
          and projection.get("installed_specimen_unknown_count") == sum(
              row.get("installed_specimen_replay_status") == "UNKNOWN"
              for row in memberships
          )
          and projection.get("installed_specimen_fail_count") == sum(
              row.get("installed_specimen_replay_status") == "FAIL"
              for row in memberships
          )
          and projection.get("installed_specimen_membership_count")
              == len(specimen_by_key),
          "PACKAGE_RECHECK_CORE_PROJECTION_COUNTS_DIFFER")
    by_cell: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for row in memberships:
        if type(row) is dict:
            by_cell.setdefault((row.get("object_kind"), row.get("tier")), []).append(row)
    expected_cell_keys = {
        (row["object_kind"], row["tier"]) for row in inventory["family_cells"]
    }
    observed_cell_keys = [
        (row.get("object_kind"), row.get("tier"))
        for row in cells if type(row) is dict
    ]
    _fail(invalidators,
          len(observed_cell_keys) == len(set(observed_cell_keys))
              and set(observed_cell_keys) == expected_cell_keys,
          "PACKAGE_RECHECK_CORE_CELL_CENSUS_DIFFERS")
    for cell in cells:
        if type(cell) is not dict or set(cell) != {
                "object_kind", "tier", "tier_name",
                "installed_denominator_status", "registered_route_membership_count",
                "normative_full_family_closure",
                "selected_package_native_replay_status", "candidate_coverage_status",
                "candidate_class_counts", "candidate_mechanism_counts",
                "reason_pending_coordinates", "owner_decision_refs", "status",
                }:
            invalidators.add("PACKAGE_RECHECK_CORE_CELL_STATUS_DIFFERS")
            break
        selected = by_cell.get((cell.get("object_kind"), cell.get("tier")), [])
        inventory_cell = next((
            row for row in inventory["family_cells"]
            if row["object_kind"] == cell.get("object_kind")
            and row["tier"] == cell.get("tier")
        ), None)
        expected_cell_status = (
            "FAIL" if any(row.get("status") == "FAIL" for row in selected)
            else "UNKNOWN"
        )
        replay_statuses = [
            row.get("selected_package_native_replay_status") for row in selected
        ]
        expected_replay = (
            "FAIL" if "FAIL" in replay_statuses else
            "PASS" if replay_statuses
                and all(value == "PASS" for value in replay_statuses)
            else "NOT_ESTABLISHED"
        )
        candidate_identities = [
            row.get("candidate_obligation_identity_status") for row in selected
        ]
        candidate_classes = [
            row.get("candidate_rev4_class") for row in selected
            if row.get("candidate_rev4_class") is not None
        ]
        candidate_mechanisms = [
            row.get("candidate_mechanism_assessment") for row in selected
            if row.get("candidate_mechanism_assessment") is not None
        ]
        expected_refs = sorted({
            reference for row in selected
            for reference in row.get("owner_decision_refs", [])
        })
        if (inventory_cell is None
                or cell.get("tier_name") != inventory_cell.get("tier_name")
                or cell.get("installed_denominator_status")
                    != inventory_cell.get("denominator_status")
                or cell.get("registered_route_membership_count")
                    != inventory_cell.get("registered_route_membership_count")
                or cell.get("normative_full_family_closure")
                    != "NOT_ESTABLISHED"
                or cell.get("status") != expected_cell_status
                or cell.get("selected_package_native_replay_status")
                    != expected_replay
                or cell.get("candidate_coverage_status") != (
                    "PASS" if candidate_identities
                    and all(value == "PASS" for value in candidate_identities)
                    else "UNKNOWN"
                )
                or cell.get("candidate_class_counts") != {
                    value: candidate_classes.count(value)
                    for value in sorted(set(candidate_classes))
                }
                or cell.get("candidate_mechanism_counts") != {
                    value: candidate_mechanisms.count(value)
                    for value in sorted(set(candidate_mechanisms))
                }
                or cell.get("reason_pending_coordinates") != [
                    row.get("coordinate") for row in selected
                    if row.get("candidate_rev4_class") == "REASON_PENDING"
                ]
                or cell.get("owner_decision_refs") != expected_refs):
            invalidators.add("PACKAGE_RECHECK_CORE_CELL_STATUS_DIFFERS")
            break


def _check_full_native_candidate(
        report: dict[str, Any], inventory: dict[str, Any],
        invalidators: set[str]) -> None:
    candidate = report.get("full_native_candidate")
    if candidate is None:
        return
    top_fields = {
        "schema_version", "status", "source_coordinate_digest",
        "mechanism_digest", "tiers", "tier_membership_counts",
        "membership_count", "case_count", "installed_membership_count",
        "prepared_membership_count", "route_status_counts",
        "case_status_counts", "native_status_counts", "installed_tier_replays",
        "prepared_extension_replay_digest", "routes", "invalidators",
        "extension_installation_status", "whole_tier_conformance", "polished",
        "release_authority", "claim_boundary", "candidate_digest",
    }
    if type(candidate) is not dict or set(candidate) != top_fields:
        invalidators.add("PACKAGE_RECHECK_FULL_NATIVE_CANDIDATE_FIELDS")
        return
    routes = candidate.get("routes")
    if type(routes) is not list:
        invalidators.add("PACKAGE_RECHECK_FULL_NATIVE_CANDIDATE_FIELDS")
        return
    expected: dict[str, dict[str, Any]] = {}
    for cell in inventory["family_cells"]:
        for route in cell["registered_route_memberships"]:
            obligation_id = f"{cell['object_kind']}:{route['coordinate']}"
            expected[obligation_id] = {
                "object_kind": cell["object_kind"],
                "tier": cell["tier"],
                "coordinate": route["coordinate"],
                "proposition_digest": route["proposition_digest"],
                "checking_mechanism": route["checking_mechanism"],
            }
    route_fields = {
        "obligation_id", "object_kind", "tier", "coordinate",
        "proposition_digest", "checking_mechanism", "lifecycle", "status",
        "route_replay_digest", "cases",
    }
    case_fields = {
        "case_kind", "expected_native_status", "native_status", "status",
        "native_result_digest",
    }
    valid_routes = len(routes) == len(expected) == 408
    observed_ids: list[str] = []
    for row in routes:
        if type(row) is not dict or set(row) != route_fields:
            valid_routes = False
            continue
        obligation_id = row.get("obligation_id")
        observed_ids.append(obligation_id)
        selected = expected.get(obligation_id)
        cases = row.get("cases")
        expected_lifecycle = (
            "INSTALLED" if row.get("tier") in (1, 2)
            else "PREPARED_NOT_INSTALLED"
        )
        if (selected is None
                or any(row.get(key) != value for key, value in selected.items())
                or row.get("lifecycle") != expected_lifecycle
                or type(row.get("route_replay_digest")) is not str
                or _SHA256.fullmatch(row["route_replay_digest"]) is None
                or type(cases) is not list or len(cases) != 3
                or [case.get("case_kind") for case in cases
                    if type(case) is dict]
                    != ["POSITIVE", "NEGATIVE", "UNKNOWN"]):
            valid_routes = False
            continue
        case_statuses = []
        for case in cases:
            if (type(case) is not dict or set(case) != case_fields
                    or case.get("expected_native_status")
                        not in ("PASS", "FAIL", "UNKNOWN")
                    or case.get("native_status")
                        not in ("PASS", "FAIL", "UNKNOWN")
                    or case.get("status") not in ("PASS", "FAIL", "UNKNOWN")
                    or (case.get("native_result_digest") is not None and (
                        type(case["native_result_digest"]) is not str
                        or _SHA256.fullmatch(case["native_result_digest"]) is None
                    ))):
                valid_routes = False
                continue
            expected_native = {
                "POSITIVE": "PASS", "NEGATIVE": "FAIL", "UNKNOWN": "UNKNOWN",
            }[case["case_kind"]]
            expected_case_status = (
                "PASS" if case["native_status"] == expected_native else
                "UNKNOWN" if row["tier"] in (1, 2)
                and case["case_kind"] == "POSITIVE"
                and case["native_status"] == "UNKNOWN" else "FAIL"
            )
            if case["native_result_digest"] is None:
                outage = (
                    row["tier"] in (1, 2)
                    and "NATIVE_REPLAY_MECHANISM_UNAVAILABLE"
                        in candidate["invalidators"]
                )
                if not outage:
                    valid_routes = False
                elif case["status"] == "UNKNOWN" and case["native_status"] == "UNKNOWN":
                    expected_case_status = "UNKNOWN"
            if (case["expected_native_status"] != expected_native
                    or case["status"] != expected_case_status):
                valid_routes = False
            case_statuses.append(case["status"])
        expected_route_status = (
            "FAIL" if "FAIL" in case_statuses else
            "UNKNOWN" if "UNKNOWN" in case_statuses else "PASS"
        )
        if row.get("status") != expected_route_status:
            valid_routes = False
    _fail(invalidators,
          valid_routes
              and len(observed_ids) == len(set(observed_ids)) == 408
              and set(observed_ids) == set(expected)
              and routes == sorted(
                  routes, key=lambda row: (row["tier"], row["obligation_id"])
              ),
          "PACKAGE_RECHECK_FULL_NATIVE_CANDIDATE_ROUTES_DIFFER")
    route_counts = Counter(
        row.get("status") for row in routes if type(row) is dict
    )
    cases = [
        case for row in routes if type(row) is dict
        for case in row.get("cases", []) if type(case) is dict
    ]
    case_counts = Counter(case.get("status") for case in cases)
    native_counts = Counter(case.get("native_status") for case in cases)
    tier_counts = Counter(
        str(row.get("tier")) for row in routes if type(row) is dict
    )
    installed_count = sum(
        row.get("lifecycle") == "INSTALLED"
        for row in routes if type(row) is dict
    )
    prepared_count = sum(
        row.get("lifecycle") == "PREPARED_NOT_INSTALLED"
        for row in routes if type(row) is dict
    )
    expected_status = (
        "FAIL" if route_counts["FAIL"] else
        "UNKNOWN" if route_counts["UNKNOWN"] else "PASS"
    )
    installed_summaries = candidate.get("installed_tier_replays")
    summaries_valid = (
        type(installed_summaries) is list
        and [row.get("tier") for row in installed_summaries
             if type(row) is dict] == [1, 2]
        and all(
            type(row) is dict and set(row) == {
                "tier", "status", "manifest_digest", "receipt_digest",
                "membership_count", "case_count", "invalidators",
                "whole_tier_conformance",
            }
            and type(row.get("manifest_digest")) is str
            and _SHA256.fullmatch(row["manifest_digest"]) is not None
            and type(row.get("receipt_digest")) is str
            and _SHA256.fullmatch(row["receipt_digest"]) is not None
            and row.get("membership_count")
                == sum(route["tier"] == row["tier"] for route in routes)
            and row.get("case_count") == 3 * row["membership_count"]
            and row.get("status") == (
                "FAIL" if any(route["status"] == "FAIL" for route in routes
                              if route["tier"] == row["tier"]) else
                "UNKNOWN" if any(route["status"] == "UNKNOWN" for route in routes
                                 if route["tier"] == row["tier"]) else "PASS"
            )
            and type(row.get("invalidators")) is list
            and all(type(code) is str for code in row["invalidators"])
            and row.get("whole_tier_conformance") == "NOT_ESTABLISHED"
            for row in installed_summaries
        )
    )
    invalidator_rows = candidate.get("invalidators")
    aggregates_valid = (
        candidate.get("schema_version")
            == self_polish_native_full_candidate.CANDIDATE_SCHEMA
        and candidate.get("source_coordinate_digest")
            == report.get("source_coordinate_digest")
        and candidate.get("mechanism_digest")
            == self_polish_native_full_candidate.mechanism_digest()
        and candidate.get("tiers") == list(range(1, 10))
        and candidate.get("tier_membership_counts")
            == dict(sorted(tier_counts.items()))
        and candidate.get("membership_count") == len(routes) == 408
        and candidate.get("case_count") == len(cases) == 1224
        and candidate.get("installed_membership_count") == installed_count == 82
        and candidate.get("prepared_membership_count") == prepared_count == 326
        and candidate.get("route_status_counts")
            == dict(sorted(route_counts.items()))
        and candidate.get("case_status_counts")
            == dict(sorted(case_counts.items()))
        and candidate.get("native_status_counts")
            == dict(sorted(native_counts.items()))
        and candidate.get("status") == expected_status
        and summaries_valid
        and type(candidate.get("prepared_extension_replay_digest")) is str
        and _SHA256.fullmatch(
            candidate["prepared_extension_replay_digest"]
        ) is not None
        and type(invalidator_rows) is list
        and invalidator_rows == sorted(set(invalidator_rows))
        and all(value in _MEMBER_TIER_INVALIDATORS for value in invalidator_rows)
        and invalidator_rows == sorted({
            code for row in installed_summaries for code in row["invalidators"]
        })
        and candidate.get("extension_installation_status")
            == "PREPARED_NOT_INSTALLED"
        and candidate.get("whole_tier_conformance") == "NOT_ESTABLISHED"
        and candidate.get("polished") is False
        and candidate.get("release_authority") == "NONE"
        and candidate.get("claim_boundary") == _FULL_NATIVE_CANDIDATE_BOUNDARY
        and candidate.get("candidate_digest")
            == _body_digest(candidate, "candidate_digest")
    )
    _fail(invalidators, aggregates_valid,
          "PACKAGE_RECHECK_FULL_NATIVE_CANDIDATE_AGGREGATES_DIFFER")


def _check_tier_zero_repository_admission(
        report: dict[str, Any], invalidators: set[str]) -> None:
    binding = report.get("tier_zero_repository_admission")
    if type(binding) is not dict:
        invalidators.add("PACKAGE_RECHECK_TIER_ZERO_ADMISSION_FIELDS")
        return
    fields = {
        "schema_version", "status", "report_schema_version", "report_digest",
        "profile_id", "profile_digest", "manifest_digest", "mechanism_digest",
        "obligation_count", "obligation_status_counts",
        "assessment_reason_count", "finalization_status",
        "closed_coordinates", "unclosed_coordinates", "source_repository",
        "source_revision", "source_census_digest", "source_binding_status",
        "error", "claim_boundary",
    }
    exact_coordinates = [f"VSTD-T0.{index}" for index in range(1, 10)]
    closed = binding.get("closed_coordinates")
    unclosed = binding.get("unclosed_coordinates")
    counts = binding.get("obligation_status_counts")
    status = binding.get("status")
    _fail(invalidators,
          set(binding) == fields
          and binding.get("schema_version")
              == "verifier-package-tier-zero-admission-binding-1"
          and status in ("PASS", "FAIL", "UNKNOWN", "NOT_ESTABLISHED")
          and binding.get("claim_boundary") == _TIER_ZERO_BINDING_BOUNDARY
          and type(closed) is list and type(unclosed) is list
          and len(closed) == len(set(closed))
          and len(unclosed) == len(set(unclosed))
          and set(closed).isdisjoint(unclosed)
          and sorted(closed + unclosed) == exact_coordinates
          and type(counts) is dict
          and set(counts) == {"PASS", "FAIL", "UNKNOWN"}
          and all(type(value) is int and not isinstance(value, bool)
                  and 0 <= value <= 9 for value in counts.values())
          and sum(counts.values()) == binding.get("obligation_count")
          and type(binding.get("assessment_reason_count")) is int
          and not isinstance(binding.get("assessment_reason_count"), bool)
          and 0 <= binding["assessment_reason_count"] <= 9,
          "PACKAGE_RECHECK_TIER_ZERO_ADMISSION_FIELDS")
    if status == "PASS":
        from verifier.runtime import package_admission
        additive = binding.get("report_schema_version") == package_admission.REPORT_SCHEMA
        source = report.get("source_coordinate")
        recapture = report.get("source_recapture_binding")
        opening = (
            recapture.get("opening_binding")
            if type(recapture) is dict else None
        )
        evidence = (
            opening.get("observed_source_evidence")
            if type(opening) is dict else None
        )
        _fail(invalidators,
              binding.get("report_schema_version")
                  in (tier_zero.REPORT_SCHEMA, package_admission.REPORT_SCHEMA)
              and type(binding.get("report_digest")) is str
              and _SHA256.fullmatch(binding["report_digest"]) is not None
              and type(binding.get("profile_id")) is str
              and type(binding.get("profile_digest")) is str
              and _SHA256.fullmatch(binding["profile_digest"]) is not None
              and type(binding.get("manifest_digest")) is str
              and _SHA256.fullmatch(binding["manifest_digest"]) is not None
              and binding.get("mechanism_digest")
                  == (package_admission.mechanism_digest() if additive else tier_zero.mechanism_digest())
              and (not additive or (binding.get("profile_digest") == package_admission.profile_digest()
                   and binding.get("profile_id") == "vstd-package-admission-3"))
              and binding.get("obligation_count") == 9
              and counts == {"PASS": 9, "FAIL": 0, "UNKNOWN": 0}
              and binding.get("assessment_reason_count") == 9
              and binding.get("finalization_status") == "PASS"
              and closed == exact_coordinates and unclosed == []
              and type(binding.get("source_repository")) is str
              and type(source) is dict
              and binding.get("source_revision") == source.get("source_head")
              and type(evidence) is dict
              and binding.get("source_census_digest")
                  == evidence.get("candidate_source_census_digest")
              and binding.get("source_binding_status") == "PASS"
              and binding.get("error") is None,
              "PACKAGE_RECHECK_TIER_ZERO_ADMISSION_STATUS_DIFFERS")
    else:
        _fail(invalidators,
              binding.get("source_binding_status") != "PASS"
                  or binding.get("finalization_status") != "PASS"
                  or status == "FAIL",
              "PACKAGE_RECHECK_TIER_ZERO_ADMISSION_STATUS_DIFFERS")


def _check_tier_zero_and_corrigibility(
        report: dict[str, Any], objects: tuple[NamespaceObject, ...] | None,
        invalidators: set[str]) -> None:
    tier_zero = report.get("tier_zero_representation_cells")
    native = report.get("native_facets_replay")
    graph = report.get("package_graph")
    admission = report.get("owner_decision_admission")
    repository_admission = report.get("tier_zero_repository_admission")
    adopted = set(
        admission.get("adopted_decision_ids", [])
        if type(admission) is dict and admission.get("status") == "PASS"
        else []
    )
    if type(tier_zero) is not list or type(native) is not dict \
            or type(graph) is not dict or type(repository_admission) is not dict:
        invalidators.add("PACKAGE_RECHECK_TIER_ZERO_FIELDS")
    else:
        native_by_kind = {
            row.get("object_kind"): row
            for row in native.get("results", []) if type(row) is dict
        }
        object_by_kind = (
            {item.kind.value: item for item in objects}
            if objects is not None else {}
        )
        observed = [row.get("object_kind") for row in tier_zero]
        _fail(invalidators,
              len(observed) == len(set(observed)) == 26
                  and set(observed) == {kind.value for kind in ObjectKind},
              "PACKAGE_RECHECK_TIER_ZERO_CENSUS_DIFFERS")
        for row in tier_zero:
            kind = row.get("object_kind")
            item = object_by_kind.get(kind)
            native_status = (
                native_by_kind[kind].get("status")
                if kind in native_by_kind else "NOT_ESTABLISHED"
            )
            admission_status = repository_admission.get("status")
            expected = (
                "FAIL" if graph.get("status") == "FAIL"
                or kind not in native_by_kind
                or native_status == "FAIL"
                or admission_status == "FAIL"
                else "PASS" if graph.get("status") == "PASS"
                and native_status == "PASS"
                and admission_status == "PASS"
                else "UNKNOWN"
            )
            if (item is None
                    or set(row) != {
                        "schema_version", "object_kind", "tier", "tier_name",
                        "object_id", "record_digest", "status",
                        "structural_representation_status",
                        "native_facets_discrimination_status",
                        "repository_admission_status",
                        "repository_admission_report_digest",
                        "semantic_obligation_status", "denominator_decision_status",
                        "owner_decision_refs", "assessment_reason",
                        "claim_boundary",
                    }
                    or row.get("schema_version")
                        != "verifier-package-object-admission-tier-2"
                    or row.get("tier") != 0
                    or row.get("tier_name") != "REPRESENTATION_ADMISSION"
                    or row.get("object_id") != item.object_id
                    or row.get("record_digest") != item.digest
                    or row.get("status") != expected
                    or row.get("structural_representation_status") != (
                        graph.get("status") if kind in native_by_kind else "FAIL"
                    )
                    or row.get("native_facets_discrimination_status") != (
                        native_status
                    )
                    or row.get("repository_admission_status")
                        != admission_status
                    or row.get("repository_admission_report_digest")
                        != repository_admission.get("report_digest")
                    or row.get("semantic_obligation_status")
                        != "NOT_ESTABLISHED"
                    or row.get("denominator_decision_status")
                        != "NOT_ESTABLISHED"
                    or row.get("owner_decision_refs") != (
                        ["CTC-5"] if "CTC-5" in adopted else []
                    )
                    or type(row.get("assessment_reason")) is not str
                    or not row["assessment_reason"].strip()):
                invalidators.add("PACKAGE_RECHECK_TIER_ZERO_STATUS_DIFFERS")
                break
    evidence = report.get("corrigibility_research_evidence")
    cells = report.get("corrigibility_extension_cells")
    selection = report.get("corrigibility_extension_selection")
    if type(evidence) is not dict or type(cells) is not list \
            or type(selection) is not dict:
        invalidators.add("PACKAGE_RECHECK_CORRIGIBILITY_FIELDS")
        return
    _fail(invalidators,
          evidence.get("evidence_digest") == _body_digest(evidence, "evidence_digest"),
          "PACKAGE_RECHECK_CORRIGIBILITY_EVIDENCE_DIGEST_DIFFERS")
    observed = [row.get("object_kind") for row in cells]
    _fail(invalidators,
              len(observed) == len(set(observed)) == 26
              and set(observed) == {kind.value for kind in ObjectKind}
              and all(
                  set(row) == {
                      "schema_version", "object_kind", "declared_status",
                      "native_status", "qualification", "status",
                      "authority_status", "research_evidence_digest",
                      "research_surface_status",
                      "verifier_10_1_research_input_status", "code_set_status",
                      "owner_decision_refs",
                  }
                  and row.get("schema_version")
                      == "verifier-package-corrigibility-cell-selection-1"
                  and row.get("declared_status") == "WIP"
                  and row.get("native_status") == "NOT_RUN"
                  and row.get("qualification") == "NOT_ESTABLISHED"
                  and row.get("status") == "UNKNOWN"
                  and row.get("authority_status") == "NOT_ESTABLISHED"
                  and row.get("research_evidence_digest")
                      == evidence.get("evidence_digest")
                  and row.get("research_surface_status")
                      == "BOUND_RESEARCH_INPUTS_NOT_QUALIFICATION"
                  and row.get("verifier_10_1_research_input_status") == (
                      "BOUND_NOT_EXTENSION_CREDIT"
                      if row.get("object_kind") == "VERIFIER"
                      else "NOT_APPLICABLE"
                  )
                  and row.get("code_set_status")
                      == "RESEARCH_SURFACES_BOUND_OWNER_DECISION_PENDING"
                  and row.get("owner_decision_refs") == (
                      ["CTC-4"] if "CTC-4" in adopted else []
                  )
                  for row in cells if type(row) is dict
              )
              and all(type(row) is dict for row in cells),
          "PACKAGE_RECHECK_CORRIGIBILITY_CELL_STATUS_DIFFERS")
    expected_binding = core_obligation_union.value_digest({
        "cells": cells,
        "research_evidence_digest": evidence.get("evidence_digest"),
    })
    _fail(invalidators, selection.get("binding_digest") == expected_binding,
          "PACKAGE_RECHECK_CORRIGIBILITY_BINDING_DIFFERS")
    _fail(invalidators,
          set(selection) == {
              "schema_version", "profile_id", "declared_status",
              "binding_digest",
          }
          and selection.get("schema_version")
              == "verifier-corrigibility-extension-selection-1"
          and selection.get("profile_id")
              == "verifier-corrigibility-extension-selection-1"
          and selection.get("declared_status") == "WIP"
          and evidence.get("status")
              == "BOUND_RESEARCH_INPUTS_NOT_QUALIFICATION"
          and evidence.get("schema_version")
              == "verifier-corrigibility-research-evidence-1"
          and evidence.get("represented_object_kind_count") == 26
          and set(evidence) == {
              "schema_version", "status", "research_spec_digest", "module_count",
              "module_set_digest", "represented_object_kind_count",
              "verifier_10_1", "claim_boundary", "evidence_digest",
          }
          and evidence.get("claim_boundary")
              == _CORRIGIBILITY_RESEARCH_CLAIM_BOUNDARY
          and type(evidence.get("verifier_10_1")) is dict
          and set(evidence["verifier_10_1"]) == {
              "semantic_version", "coordinate", "proposition_digest",
              "mechanism_digest", "status",
          }
          and evidence["verifier_10_1"].get("status")
              == "RESEARCH_INPUT_ONLY_NOT_EXTENSION_CREDIT"
          and evidence["verifier_10_1"].get("coordinate") == "VERIFIER-10.1",
          "PACKAGE_RECHECK_CORRIGIBILITY_CONSTANTS_DIFFER")
    root = _package_root()
    module_rows = [
        {
            "path": path.relative_to(root).as_posix(),
            "digest": core_obligation_union.bytes_digest(path.read_bytes()),
        }
        for path in sorted(root.joinpath("corrigibility").glob("*.py"))
    ]
    verifier_input = evidence.get("verifier_10_1")
    _fail(invalidators,
          evidence.get("research_spec_digest")
              == core_obligation_union.bytes_digest(
                  root.joinpath(
                      "standard", "CORRIGIBILITY_RESEARCH.md"
                  ).read_bytes()
              )
          and evidence.get("module_count") == len(module_rows)
          and evidence.get("module_set_digest")
              == core_obligation_union.value_digest(module_rows)
          and type(verifier_input) is dict
          and verifier_input.get("semantic_version")
              == verifier_replacement.SEMANTIC_VERSION
          and verifier_input.get("coordinate") == verifier_replacement.COORDINATE
          and verifier_input.get("proposition_digest")
              == verifier_replacement.PROPOSITION_DIGEST
          and verifier_input.get("mechanism_digest")
              == verifier_replacement.mechanism_digest(),
          "PACKAGE_RECHECK_CORRIGIBILITY_CURRENT_BINDING_DIFFERS")


def _required_blockers(report: dict[str, Any]) -> set[str]:
    required = {
        "CORE_FAMILY_CELL_CLOSURE_NOT_ESTABLISHED",
        "CORRIGIBILITY_EXTENSION_NOT_ESTABLISHED",
    }
    source = report.get("source_recapture_binding")
    if type(source) is dict and source.get("status") == "FAIL":
        required.add("PACKAGE_SOURCE_RECAPTURE_FAILED")
    elif type(source) is dict and source.get("status") == "UNKNOWN":
        required.add("PACKAGE_SOURCE_RECAPTURE_UNAVAILABLE")
    self_verifier = report.get("self_verifier_tier1")
    if type(self_verifier) is dict:
        retention = self_verifier.get("retention_status")
        status = self_verifier.get("status")
        if retention in ("NOT_SELECTED", "UNAVAILABLE"):
            required.add("SELF_VERIFIER_TIER1_REPORT_UNAVAILABLE")
            if retention == "UNAVAILABLE" and status == "FAIL":
                required.add("NUMERIC_SELF_VERIFIER_TIER1_FAILED")
        elif retention == "RETAINED" and status == "FAIL":
            required.add("SELF_VERIFIER_TIER1_FAILED")
        elif retention == "RETAINED" and status != "PASS":
            required.add("SELF_VERIFIER_TIER1_NOT_PASS")
    native = report.get("native_facets_replay")
    if type(native) is dict and native.get("status") == "FAIL":
        required.add("PACKAGE_NATIVE_FACETS_REPLAY_FAILED")
    elif type(native) is dict and native.get("status") != "PASS":
        required.add("PACKAGE_NATIVE_FACETS_REPLAY_NOT_PASS")
    installed = report.get("installed_native_case_replay")
    if type(installed) is dict and installed.get("status") == "FAIL":
        required.add("PACKAGE_INSTALLED_NATIVE_CASE_REPLAY_FAILED")
    elif type(installed) is dict and installed.get("status") != "PASS":
        required.add("PACKAGE_INSTALLED_NATIVE_CASE_REPLAY_NOT_PASS")
    full_candidate = report.get("full_native_candidate")
    if type(full_candidate) is dict:
        if full_candidate.get("status") == "FAIL":
            required.add("PACKAGE_FULL_NATIVE_CANDIDATE_FAILED")
        elif full_candidate.get("status") != "PASS":
            required.add("PACKAGE_FULL_NATIVE_CANDIDATE_NOT_PASS")
    elif "PACKAGE_FULL_NATIVE_CANDIDATE_FAILED" not in report.get("blockers", []) \
            and "PACKAGE_FULL_NATIVE_CANDIDATE_NOT_PASS" not in report.get(
                "blockers", []
            ):
        required.add("PACKAGE_FULL_NATIVE_CANDIDATE_NOT_SELECTED")
    projection = report.get("core_route_projection")
    if type(projection) is dict and projection.get("status") == "FAIL":
        required.add("CORE_ROUTE_NATIVE_PROJECTION_FAILED")
    elif type(projection) is dict and projection.get("status") == "UNKNOWN":
        required.add("CORE_ROUTE_NATIVE_PROJECTION_NOT_ESTABLISHED")
    candidate = report.get("candidate_obligation_ledger")
    if type(candidate) is dict:
        if candidate.get("status") == "FAIL":
            required.add("PACKAGE_OBLIGATION_CANDIDATE_SELECTION_FAILED")
        elif candidate.get("status") == "UNKNOWN":
            required.add("PACKAGE_OBLIGATION_CANDIDATE_UNAVAILABLE")
        elif candidate.get("status") == "NOT_SELECTED":
            required.add("PACKAGE_OBLIGATION_CANDIDATE_NOT_SELECTED")
        elif candidate.get("semantic_identity_status") != "PASS":
            required.add(
                "PACKAGE_OBLIGATION_CANDIDATE_SEMANTIC_IDENTITY_NOT_ESTABLISHED"
            )
    owner = report.get("owner_decision_admission")
    if type(owner) is dict:
        if owner.get("status") == "FAIL":
            required.add("PACKAGE_OWNER_DECISION_ADMISSION_FAILED")
        elif owner.get("status") == "UNKNOWN":
            required.add("PACKAGE_OWNER_DECISION_ADMISSION_UNAVAILABLE")
        elif owner.get("status") == "NOT_SELECTED" \
                and type(candidate) is dict and candidate.get("status") == "PASS":
            required.add("PACKAGE_OBLIGATION_CANDIDATE_NOT_OWNER_ADOPTED")
    tier_zero_admission = report.get("tier_zero_repository_admission")
    if type(tier_zero_admission) is dict:
        if tier_zero_admission.get("status") == "FAIL":
            required.add("TIER_ZERO_REPOSITORY_ADMISSION_FAILED")
        elif tier_zero_admission.get("status") != "PASS":
            required.add("TIER_ZERO_REPOSITORY_ADMISSION_NOT_ESTABLISHED")
    graph = report.get("package_graph")
    if type(graph) is dict and graph.get("status") != "PASS":
        required.update({
            "PACKAGE_GRAPH_COMPOSITION_NOT_PASS",
            "TIER_ZERO_REPRESENTATION_NOT_PASS",
        })
        if graph.get("status") == "FAIL":
            required.add("PACKAGE_GRAPH_COMPOSITION_FAILED")
    tier_zero = report.get("tier_zero_representation_cells")
    if type(tier_zero) is list and any(row.get("status") != "PASS" for row in tier_zero):
        required.add("TIER_ZERO_OBJECT_ADMISSION_NOT_ESTABLISHED")
    return required


def _check_blockers_and_status(report: dict[str, Any],
                               invalidators: set[str]) -> None:
    blockers = report.get("blockers")
    if type(blockers) is not list or any(type(value) is not str for value in blockers):
        invalidators.add("PACKAGE_RECHECK_BLOCKER_FIELDS")
        return
    required = _required_blockers(report)
    self_verifier = report.get("self_verifier_tier1")
    rejected_self_verifier_has_reason = (
        type(self_verifier) is not dict
        or self_verifier.get("retention_status") != "REJECTED"
        or bool({
            "SELF_VERIFIER_TIER1_REPORT_INVALID",
            "SELF_VERIFIER_TIER1_SOURCE_DIFFERS",
        } & set(blockers))
    )
    numeric_failure_blocker_required = (
        type(self_verifier) is dict
        and self_verifier.get("retention_status") == "UNAVAILABLE"
        and self_verifier.get("status") == "FAIL"
    )
    _fail(invalidators,
          blockers == sorted(set(blockers))
              and required <= set(blockers)
              and set(blockers) <= _KNOWN_BLOCKERS
              and rejected_self_verifier_has_reason
              and (
                  "NUMERIC_SELF_VERIFIER_TIER1_FAILED" in set(blockers)
              ) == numeric_failure_blocker_required,
          "PACKAGE_RECHECK_BLOCKER_SET_DIFFERS")
    failed_sections = [
        report.get("package_graph", {}).get("status"),
        report.get("self_verifier_tier1", {}).get("status"),
        report.get("native_facets_replay", {}).get("status"),
        report.get("installed_native_case_replay", {}).get("status"),
        report.get("core_route_projection", {}).get("status"),
        report.get("candidate_obligation_ledger", {}).get("status"),
        report.get("owner_decision_admission", {}).get("status"),
        report.get("source_recapture_binding", {}).get("status"),
    ]
    expected_status = "FAIL" if "FAIL" in failed_sections or any(
        _blocker_implies_failure(value) for value in blockers
    ) else "UNKNOWN"
    _fail(invalidators,
          report.get("status") == expected_status
              and report.get("project_gate_status") == expected_status
              and report.get("polished") is False
              and report.get("release_authorized") is False,
          "PACKAGE_RECHECK_PROJECT_STATUS_DIFFERS")


def recheck_package_self_polish_report(
        report_bytes: bytes, *, expected_report_digest: str,
        expected_report_bytes_digest: str) -> dict[str, Any]:
    """Recheck one retained report without promoting its project verdict."""
    invalidators: set[str] = set()
    unknowns: set[str] = set()
    report_bytes_digest = (
        core_obligation_union.bytes_digest(report_bytes)
        if type(report_bytes) is bytes else None
    )
    if type(report_bytes) is not bytes:
        invalidators.add("PACKAGE_RECHECK_IMMUTABLE_BYTES_REQUIRED")
        return _result(
            report_bytes_digest=None, selected_report_digest=None,
            reported_project_status=None, reported_mechanism_digest=None,
            current_mechanism_digest=None, invalidators=invalidators,
            unknowns=unknowns,
        )
    if len(report_bytes) > MAX_PACKAGE_REPORT_BYTES:
        unknowns.add("PACKAGE_RECHECK_REPORT_CAPACITY_EXHAUSTED")
        return _result(
            report_bytes_digest=report_bytes_digest, selected_report_digest=None,
            reported_project_status=None, reported_mechanism_digest=None,
            current_mechanism_digest=None, invalidators=invalidators,
            unknowns=unknowns,
        )
    _fail(invalidators,
          type(expected_report_bytes_digest) is str
              and _SHA256.fullmatch(expected_report_bytes_digest) is not None
              and report_bytes_digest == expected_report_bytes_digest,
          "PACKAGE_RECHECK_REPORT_BYTES_DIGEST_DIFFERS")
    try:
        value = strict_json_loads(report_bytes.decode("utf-8"))
    except (UnicodeError, ValueError, TypeError, RecursionError, OverflowError):
        invalidators.add("PACKAGE_RECHECK_STRICT_JSON_INVALID")
        return _result(
            report_bytes_digest=report_bytes_digest, selected_report_digest=None,
            reported_project_status=None, reported_mechanism_digest=None,
            current_mechanism_digest=None, invalidators=invalidators,
            unknowns=unknowns,
        )
    except MemoryError:
        unknowns.add("PACKAGE_RECHECK_REPORT_VALIDATION_UNAVAILABLE")
        return _result(
            report_bytes_digest=report_bytes_digest, selected_report_digest=None,
            reported_project_status=None, reported_mechanism_digest=None,
            current_mechanism_digest=None, invalidators=invalidators,
            unknowns=unknowns,
        )
    if type(value) is not dict:
        invalidators.add("PACKAGE_RECHECK_REPORT_FIELDS")
        return _result(
            report_bytes_digest=report_bytes_digest, selected_report_digest=None,
            reported_project_status=None, reported_mechanism_digest=None,
            current_mechanism_digest=None, invalidators=invalidators,
            unknowns=unknowns,
        )
    report = value
    _fail(invalidators, _strict_number_types(report),
          "PACKAGE_RECHECK_JSON_NUMBER_TYPE_INVALID")
    selected_digest = report.get("report_digest")
    reported_status = report.get("status")
    reported_mechanism = report.get("mechanism_digest")
    try:
        current_mechanism = _current_package_mechanism_digest()
    except (OSError, MemoryError, RecursionError, OverflowError):
        current_mechanism = None
        unknowns.add("PACKAGE_RECHECK_CURRENT_MECHANISM_UNAVAILABLE")
    _fail(invalidators, set(report) == _REPORT_FIELDS,
          "PACKAGE_RECHECK_REPORT_FIELDS")
    _fail(invalidators, report.get("schema_version") == REPORT_SCHEMA,
          "PACKAGE_RECHECK_REPORT_SCHEMA_DIFFERS")
    try:
        computed_report_digest = _body_digest(report, "report_digest")
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeError,
            RecursionError, OverflowError):
        computed_report_digest = None
        invalidators.add("PACKAGE_RECHECK_REPORT_STRUCTURE_INVALID")
    except (OSError, MemoryError):
        computed_report_digest = None
        unknowns.add("PACKAGE_RECHECK_REPORT_VALIDATION_UNAVAILABLE")
    _fail(invalidators,
          type(selected_digest) is str
              and selected_digest == computed_report_digest
              and expected_report_digest == selected_digest,
          "PACKAGE_RECHECK_REPORT_DIGEST_DIFFERS")
    reported_mechanism_valid = (
        type(reported_mechanism) is str
        and _SHA256.fullmatch(reported_mechanism) is not None
    )
    mechanism_current = (
        current_mechanism is not None
        and reported_mechanism_valid
        and reported_mechanism == current_mechanism
    )
    if current_mechanism is not None and reported_mechanism_valid \
            and not mechanism_current:
        unknowns.add("PACKAGE_RECHECK_STALE_MECHANISM")
    if reported_mechanism is None:
        unknowns.add("PACKAGE_RECHECK_REPORTED_MECHANISM_UNAVAILABLE")
    try:
        source = report.get("source_coordinate")
        if source is None:
            _fail(invalidators,
                  report.get("source_coordinate_digest") is None,
                  "PACKAGE_RECHECK_SOURCE_DIGEST_DIFFERS")
        else:
            _fail(invalidators,
                  _valid_source_coordinate(source),
                  "PACKAGE_RECHECK_SOURCE_COORDINATE_INVALID")
            if _valid_source_coordinate(source):
                _fail(invalidators,
                      report.get("source_coordinate_digest")
                          == core_obligation_union.value_digest(source),
                      "PACKAGE_RECHECK_SOURCE_DIGEST_DIFFERS")
        graph = report.get("package_graph")
        if graph is None:
            _check_fallback_report(
                report, invalidators,
                contract_current=(mechanism_current or reported_mechanism is None),
            )
        else:
            _fail(invalidators, reported_mechanism_valid,
                  "PACKAGE_RECHECK_MECHANISM_DIGEST_INVALID")
            _fail(invalidators, _valid_source_coordinate(source),
                  "PACKAGE_RECHECK_SOURCE_COORDINATE_INVALID")
            _check_stable_project_envelope(report, invalidators)
            if mechanism_current:
                objects = _reconstruct_graph(report, invalidators, unknowns)
                if objects is not None:
                    _check_graph_bindings(report, objects, invalidators)
                    _check_source_recapture(report, objects, invalidators)
                    _check_pinned_constants(report, objects, invalidators)
                inventory = _check_denominators(
                    report, invalidators, unknowns
                )
                _check_replay_sections(
                    report, objects, invalidators, unknowns
                )
                if inventory is not None:
                    _check_candidate_and_owner(report, inventory, invalidators)
                    _check_route_projection(report, inventory, invalidators)
                    _check_full_native_candidate(
                        report, inventory, invalidators
                    )
                _check_tier_zero_repository_admission(report, invalidators)
                _check_tier_zero_and_corrigibility(
                    report, objects, invalidators
                )
                _check_blockers_and_status(report, invalidators)
    except (AttributeError, KeyError, TypeError, ValueError, UnicodeError):
        invalidators.add("PACKAGE_RECHECK_REPORT_STRUCTURE_INVALID")
    except (OSError, ImportError, MemoryError, RecursionError, OverflowError):
        unknowns.add("PACKAGE_RECHECK_REPORT_VALIDATION_UNAVAILABLE")
    return _result(
        report_bytes_digest=report_bytes_digest,
        selected_report_digest=(
            selected_digest if type(selected_digest) is str
            and _SHA256.fullmatch(selected_digest) is not None else None
        ),
        reported_project_status=(
            reported_status if reported_status in ("FAIL", "UNKNOWN") else None
        ),
        reported_mechanism_digest=(
            reported_mechanism if reported_mechanism_valid else None
        ),
        current_mechanism_digest=current_mechanism,
        invalidators=invalidators,
        unknowns=unknowns,
    )


def unavailable_package_self_polish_recheck(
        reason: str = "PACKAGE_RECHECK_INPUT_UNAVAILABLE") -> dict[str, Any]:
    """Return a bounded UNKNOWN when selected report bytes cannot be read."""
    return _result(
        report_bytes_digest=None,
        selected_report_digest=None,
        reported_project_status=None,
        reported_mechanism_digest=None,
        current_mechanism_digest=None,
        invalidators=set(),
        unknowns={reason},
    )


__all__ = [
    "MAX_PACKAGE_REPORT_BYTES",
    "RECHECK_SCHEMA",
    "mechanism_digest",
    "recheck_package_self_polish_report",
    "unavailable_package_self_polish_recheck",
]
