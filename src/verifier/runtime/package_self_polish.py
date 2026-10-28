"""Fail-closed project gate for recursive Verifier Standard package self-polish.

The package is represented as one finite typed ``GRAPH`` containing exactly one
record for every currently admitted object kind.  The numeric polish mechanism
is itself the graph's ``VERIFIER`` record.  Tier zero below names a separate
representation/admission layer; it does not add a value to ``MetaTier`` or
silently redefine the nine core tiers.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
Verifier Standard (VSTD).
"""
from __future__ import annotations

from collections import Counter
import json
from pathlib import Path
import re
from typing import Any, Iterable, Mapping

from verifier.core.namespace import (
    CompositionAssessment,
    NamespaceObject,
    ObjectKind,
    Verdict,
    assess_composition,
    composition_digest,
)
from verifier.domains.contracts import object_facets
from verifier.domains.contracts import typed_facets
from verifier.domains.contracts import verifier_replacement
from verifier.runtime import core_obligation_union
from verifier.runtime import core_tier_progression
from verifier.runtime import package_obligation_candidate
from verifier.runtime import package_owner_decision
from verifier.runtime import polish_requirements
from verifier.runtime import self_polish_estate
from verifier.runtime import self_polish_native_cases
from verifier.runtime import self_polish_native_full_candidate
from verifier.runtime import self_polish_native_replay
from verifier.runtime import self_polish_tiers
from verifier.runtime import tier_zero


REPORT_SCHEMA = "verifier-package-graph-self-polish-assessment-1"
MAX_PACKAGE_REPORT_BYTES = 16 * 1024 * 1024
GRAPH_SCHEMA = "verifier-package-graph-representation-1"
TIER_ZERO_SCHEMA = "verifier-package-object-admission-tier-2"
TIER_ZERO_BINDING_SCHEMA = "verifier-package-tier-zero-admission-binding-1"
CORRIGIBILITY_CELL_SCHEMA = "verifier-package-corrigibility-cell-selection-1"
CORRIGIBILITY_EXTENSION_SCHEMA = "verifier-corrigibility-extension-selection-1"
PACKAGE_GRAPH_ID = "vstd-package-graph"
POLISH_VERIFIER_ID = "verifier-core-self"

_SOURCE_FIELDS = {
    "source_head",
    "source_tree",
    "source_worktree_status_digest",
    "source_manifest_digest",
}
_GIT_OBJECT = re.compile(r"[0-9a-f]{40}\Z")
_SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
_SELF_VERIFIER_BOUNDARY = (
    "PASS binds the selected numeric Tier-1 VERIFIER report only; "
    "it does not close the package graph or any other denominator."
)
_TIER_ZERO_BINDING_BOUNDARY = (
    "PASS binds one finalized vstd polish 0 repository-admission report to the "
    "selected package source and graph. It does not establish any Tier-1-plus "
    "semantic obligation, package polish, owner authority, release, or deployment."
)
_BOUNDARY = (
    "This report keeps structural package representation, the separate tier-zero "
    "admission layer, the 26-by-9 core grid, and the cross-kind corrigibility "
    "extension distinct. Structural PASS grants no semantic obligation, authority, "
    "corrigibility, polished, release, or deployment status."
)


class PackageAssessmentContradiction(RuntimeError):
    """A detected package invariant violation that must remain a FAIL."""


class PackageAssessmentUnavailable(RuntimeError):
    """A resource interruption carrying already observed failure blockers."""

    def __init__(self, *blockers: str) -> None:
        super().__init__("PACKAGE_SELF_POLISH_ASSESSMENT_UNAVAILABLE")
        self.blockers = tuple(blockers)


def _source_coordinate(value: Mapping[str, Any]) -> dict[str, str]:
    if type(value) is not dict or set(value) != _SOURCE_FIELDS:
        raise ValueError("PACKAGE_SOURCE_COORDINATE_FIELDS")
    coordinate = dict(value)
    if (type(coordinate["source_head"]) is not str
            or _GIT_OBJECT.fullmatch(coordinate["source_head"]) is None
            or type(coordinate["source_tree"]) is not str
            or _GIT_OBJECT.fullmatch(coordinate["source_tree"]) is None
            or any(
                type(coordinate[name]) is not str
                or _SHA256.fullmatch(coordinate[name]) is None
                for name in (
                    "source_worktree_status_digest",
                    "source_manifest_digest",
                )
            )):
        raise ValueError("PACKAGE_SOURCE_COORDINATE_INVALID")
    return coordinate


def _payload(role: str, source_coordinate_digest: str, **extra: Any) -> dict[str, Any]:
    return {
        "schema_version": GRAPH_SCHEMA,
        "representation_role": role,
        "source_coordinate_digest": source_coordinate_digest,
        "semantic_status": "NOT_ESTABLISHED",
        **extra,
    }


def _source_evidence_summary(observed: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "source_manifest_digest": (
            polish_requirements.source_manifest_digest(observed)
        ),
        "candidate_source_census_digest": observed[
            "candidate_source_census_digest"
        ],
        "candidate_source_file_count": observed[
            "candidate_source_file_count"
        ],
        "candidate_source_bytes": observed["candidate_source_bytes"],
        "tracked_file_count": observed["tracked_file_count"],
        "untracked_nonignored_file_count": observed[
            "untracked_nonignored_file_count"
        ],
    }


def build_package_graph(
        source_coordinate: Mapping[str, Any], *,
        self_verifier_report_digest: str | None = None,
        self_verifier_report_status: str | None = None,
        self_verifier_retention_status: str = "NOT_SELECTED",
        self_verifier_mechanism_digest: str | None = None,
        source_evidence: Mapping[str, Any] | None = None,
        candidate_selection_digest: str | None = None,
        candidate_selection_status: str = "NOT_SELECTED",
        owner_decision_admission_digest: str | None = None,
        owner_decision_admission_status: str = "NOT_SELECTED",
        package_gate_mechanism_digest: str | None = None,
        tier_zero_report_digest: str | None = None,
        tier_zero_report_status: str = "NOT_ESTABLISHED",
        tier_zero_profile_digest: str | None = None,
        full_native_candidate_digest: str | None = None,
        full_native_candidate_status: str = "NOT_SELECTED",
        ) -> tuple[NamespaceObject, ...]:
    """Build the exact 26-kind typed directed acyclic graph (DAG)."""
    coordinate = _source_coordinate(source_coordinate)
    if (self_verifier_report_digest is not None
            and (type(self_verifier_report_digest) is not str
                 or _SHA256.fullmatch(self_verifier_report_digest) is None)):
        raise ValueError("PACKAGE_SELF_VERIFIER_REPORT_DIGEST_INVALID")
    if self_verifier_report_status not in (None, "PASS", "FAIL", "UNKNOWN"):
        raise ValueError("PACKAGE_SELF_VERIFIER_REPORT_STATUS_INVALID")
    if self_verifier_retention_status not in (
            "RETAINED", "NOT_SELECTED", "UNAVAILABLE", "REJECTED"):
        raise ValueError("PACKAGE_SELF_VERIFIER_RETENTION_STATUS_INVALID")
    if (self_verifier_mechanism_digest is not None
            and (type(self_verifier_mechanism_digest) is not str
                 or _SHA256.fullmatch(self_verifier_mechanism_digest) is None)):
        raise ValueError("PACKAGE_SELF_VERIFIER_MECHANISM_DIGEST_INVALID")
    if (candidate_selection_digest is not None
            and (type(candidate_selection_digest) is not str
                 or _SHA256.fullmatch(candidate_selection_digest) is None)):
        raise ValueError("PACKAGE_CANDIDATE_SELECTION_DIGEST_INVALID")
    if (type(candidate_selection_status) is not str
            or candidate_selection_status not in (
                "PASS", "FAIL", "UNKNOWN", "NOT_SELECTED")):
        raise ValueError("PACKAGE_CANDIDATE_SELECTION_STATUS_INVALID")
    if (owner_decision_admission_digest is not None
            and (type(owner_decision_admission_digest) is not str
                 or _SHA256.fullmatch(owner_decision_admission_digest) is None)):
        raise ValueError("PACKAGE_OWNER_DECISION_ADMISSION_DIGEST_INVALID")
    if (type(owner_decision_admission_status) is not str
            or owner_decision_admission_status not in (
                "PASS", "FAIL", "UNKNOWN", "NOT_SELECTED")):
        raise ValueError("PACKAGE_OWNER_DECISION_ADMISSION_STATUS_INVALID")
    if (owner_decision_admission_status == "PASS"
            and candidate_selection_status != "PASS"):
        raise ValueError("PACKAGE_OWNER_DECISION_WITHOUT_CANDIDATE_PASS")
    if package_gate_mechanism_digest is None:
        package_gate_mechanism_digest = mechanism_digest()
    elif (type(package_gate_mechanism_digest) is not str
          or _SHA256.fullmatch(package_gate_mechanism_digest) is None):
        raise ValueError("PACKAGE_GATE_MECHANISM_DIGEST_INVALID")
    if (tier_zero_report_digest is not None
            and (type(tier_zero_report_digest) is not str
                 or _SHA256.fullmatch(tier_zero_report_digest) is None)):
        raise ValueError("PACKAGE_TIER_ZERO_REPORT_DIGEST_INVALID")
    if tier_zero_report_status not in (
            "PASS", "FAIL", "UNKNOWN", "NOT_ESTABLISHED"):
        raise ValueError("PACKAGE_TIER_ZERO_REPORT_STATUS_INVALID")
    if (tier_zero_profile_digest is not None
            and (type(tier_zero_profile_digest) is not str
                 or _SHA256.fullmatch(tier_zero_profile_digest) is None)):
        raise ValueError("PACKAGE_TIER_ZERO_PROFILE_DIGEST_INVALID")
    if tier_zero_report_status == "PASS" and (
            tier_zero_report_digest is None or tier_zero_profile_digest is None):
        raise ValueError("PACKAGE_TIER_ZERO_PASS_BINDING_INCOMPLETE")
    if (full_native_candidate_digest is not None
            and (type(full_native_candidate_digest) is not str
                 or _SHA256.fullmatch(full_native_candidate_digest) is None)):
        raise ValueError("PACKAGE_FULL_NATIVE_CANDIDATE_DIGEST_INVALID")
    if full_native_candidate_status not in (
            "PASS", "FAIL", "UNKNOWN", "NOT_SELECTED"):
        raise ValueError("PACKAGE_FULL_NATIVE_CANDIDATE_STATUS_INVALID")
    if full_native_candidate_status == "PASS" \
            and full_native_candidate_digest is None:
        raise ValueError("PACKAGE_FULL_NATIVE_CANDIDATE_BINDING_INCOMPLETE")
    source_digest = core_obligation_union.value_digest(coordinate)
    source_evidence_digest = (
        core_obligation_union.value_digest(dict(source_evidence))
        if source_evidence is not None else None
    )
    source_evidence_status = (
        "BOUND" if source_evidence is not None else "NOT_SELECTED"
    )

    def payload(role: str, **extra: Any) -> dict[str, Any]:
        return _payload(
            role, source_digest,
            source_evidence_status=source_evidence_status,
            source_evidence_digest=source_evidence_digest,
            **extra,
        )

    make = NamespaceObject.create
    objects = [
        make("vstd-human", "HUMAN", payload("responsible-human")),
        make("vstd-role", "ROLE", payload("package-maintainer-role")),
        make("vstd-package-object", "OBJECT", payload("package-subject")),
        make("vstd-hardware", "HARDWARE", payload("execution-hardware")),
        make("vstd-space", "SPACE", payload("execution-space")),
        make("vstd-time", "TIME", payload("assessment-time")),
        make("vstd-environment", "ENV", payload("execution-environment")),
        make("vstd-data", "DATA", payload("package-data")),
        make(POLISH_VERIFIER_ID, "VERIFIER", payload(
            "vstd-polish-1-and-package-gate-mechanisms",
            selected_numeric_tier=1,
            numeric_self_polish_mechanism_digest=
                self_polish_tiers.mechanism_digest(),
            package_gate_mechanism_digest=package_gate_mechanism_digest,
            candidate_selector_mechanism_digest=(
                core_obligation_union.bytes_digest(
                    Path(package_obligation_candidate.__file__).read_bytes()
                )
            ),
            owner_decision_mechanism_digest=(
                package_owner_decision.mechanism_digest()
            ),
            candidate_selection_digest=candidate_selection_digest,
            candidate_selection_status=candidate_selection_status,
            owner_decision_admission_digest=(
                owner_decision_admission_digest
            ),
            owner_decision_admission_status=(
                owner_decision_admission_status
            ),
            self_verifier_report_digest=self_verifier_report_digest,
            self_verifier_report_status=self_verifier_report_status,
            retained_numeric_mechanism_digest=self_verifier_mechanism_digest,
            package_gate_tier1_status="NOT_ESTABLISHED",
            tier_zero_report_digest=tier_zero_report_digest,
            tier_zero_report_status=tier_zero_report_status,
            tier_zero_profile_digest=tier_zero_profile_digest,
            full_native_candidate_digest=full_native_candidate_digest,
            full_native_candidate_status=full_native_candidate_status,
            full_native_candidate_mechanism_digest=(
                self_polish_native_full_candidate.mechanism_digest()
            ),
        )),
        make("vstd-architecture", "ARCH", payload("package-architecture")),
        make("vstd-harness", "HARNESS", payload("verification-harness")),
        make("vstd-token", "TOKEN", payload("bounded-token")),
    ]
    objects.extend([
        make("vstd-actor", "ACTOR", payload("responsible-actor"), {
            "representation": ["vstd-human"],
            "root_human": ["vstd-human"],
        }),
        make("vstd-collective", "COLLECTIVE", payload("maintainer-collective"), {
            "roles": ["vstd-role"],
        }),
        make("vstd-identity", "IDENTITY", payload("actor-role-identity"), {
            "actor": ["vstd-actor"],
            "role": ["vstd-role"],
        }),
        make("vstd-owner", "OWNER", payload(
            "package-owner-binding",
            owner_decision_admission_digest=(
                owner_decision_admission_digest
            ),
            owner_decision_admission_status=(
                owner_decision_admission_status
            ),
        ), {
            "actor": ["vstd-actor"],
            "object": ["vstd-package-object"],
        }),
        make("vstd-receipt", "RECEIPT", payload(
            "assessment-receipt",
            retained_report_digest=self_verifier_report_digest,
            retained_report_status=self_verifier_report_status,
            tier_zero_retained_report_digest=tier_zero_report_digest,
            tier_zero_retained_report_status=tier_zero_report_status,
            full_native_candidate_digest=full_native_candidate_digest,
            full_native_candidate_status=full_native_candidate_status,
        ), {
            "hardware": ["vstd-hardware"],
            "subject": ["vstd-package-object"],
        }),
        make("vstd-event", "EVENT", payload(
            "polish-assessment-event",
            execution_status=(
                self_verifier_report_status
                if self_verifier_report_status is not None
                else self_verifier_retention_status
            ),
            execution_report_digest=self_verifier_report_digest,
            tier_zero_execution_status=tier_zero_report_status,
            tier_zero_execution_report_digest=tier_zero_report_digest,
            full_native_candidate_digest=full_native_candidate_digest,
            full_native_candidate_status=full_native_candidate_status,
        ), {
            "meaning": ["vstd-package-object"],
            "space": ["vstd-space"],
            "time": ["vstd-time"],
        }),
        make("vstd-benchmark", "BENCH", payload("package-benchmark"), {
            "data": ["vstd-data"],
            "verifier": [POLISH_VERIFIER_ID],
        }),
        make("vstd-training", "TRAIN", payload("training-representation"), {
            "arch": ["vstd-architecture"],
            "bench": ["vstd-benchmark"],
            "data": ["vstd-data"],
            "events": ["vstd-event"],
        }),
        make("vstd-hypergraph", "HYPER", payload("package-relation"), {
            "subjects": ["vstd-package-object", POLISH_VERIFIER_ID],
        }),
        make("vstd-model", "MODEL", payload("model-representation"), {
            "arch": ["vstd-architecture"],
            "bench": ["vstd-benchmark"],
            "data": ["vstd-data"],
            "env": ["vstd-environment"],
            "events": ["vstd-event"],
            "hardware": ["vstd-hardware"],
            "train": ["vstd-training"],
        }),
        make("vstd-agent", "AGENT", payload("agent-representation"), {
            "env": ["vstd-environment"],
            "harness": ["vstd-harness"],
            "model": ["vstd-model"],
        }),
        make("vstd-simulation", "SIM", payload("simulation-representation"), {
            "data": ["vstd-data"],
            "env": ["vstd-environment"],
            "objects": ["vstd-package-object"],
            "verifier": [POLISH_VERIFIER_ID],
        }),
        make("vstd-bot", "BOT", payload("situated-agent-representation"), {
            "agent": ["vstd-agent"],
            "env": ["vstd-environment"],
            "sim": ["vstd-simulation"],
        }),
    ])
    if len(objects) != len(ObjectKind) - 1:
        raise PackageAssessmentContradiction(
            "PACKAGE_GRAPH_NON_GRAPH_KIND_COUNT_DIFFERS"
        )
    members = sorted(item.object_id for item in objects)
    objects.append(make(
        PACKAGE_GRAPH_ID,
        "GRAPH",
        payload(
            "complete-vstd-package-representation",
            element_kind="OBJECT",
        ),
        {"members": members},
    ))
    result = tuple(sorted(objects, key=lambda item: item.object_id))
    if ({item.kind for item in result} != set(ObjectKind)
            or len({item.kind for item in result}) != len(result)):
        raise PackageAssessmentContradiction(
            "PACKAGE_GRAPH_OBJECT_KIND_CENSUS_DIFFERS"
        )
    return result


def _round_trip_composition(
        objects: tuple[NamespaceObject, ...],
        expected_digest: str) -> tuple[CompositionAssessment, str, bool]:
    """Assess independently reconstructed canonical graph records."""
    records = [item.to_dict() for item in objects]
    wire = core_obligation_union.canonical_bytes({
        "schema_version": "verifier-package-graph-wire-1",
        "objects": records,
    })
    wire_digest = core_obligation_union.bytes_digest(wire)
    try:
        decoded = json.loads(wire)
        reconstructed = tuple(
            NamespaceObject.create(
                row["object_id"], row["kind"], row["payload"],
                row["operands"],
            )
            for row in decoded["objects"]
        )
        exact = (
            [item.to_dict() for item in reconstructed] == records
            and composition_digest(reconstructed) == expected_digest
        )
        if not exact:
            return (
                CompositionAssessment(
                    Verdict.FAIL,
                    composition_digest(reconstructed),
                    "canonical graph record round trip differs",
                ),
                wire_digest,
                False,
            )
        return (
            assess_composition(
                reconstructed, expected_digest=expected_digest
            ),
            wire_digest,
            True,
        )
    except (MemoryError, RecursionError, OverflowError):
        return (
            CompositionAssessment(
                Verdict.UNKNOWN, None,
                "canonical graph record round trip was unavailable"
            ),
            wire_digest,
            False,
        )
    except (KeyError, TypeError, ValueError, UnicodeError):
        return (
            CompositionAssessment(
                Verdict.FAIL, None, "canonical graph record round trip failed"
            ),
            wire_digest,
            False,
        )


def mechanism_digest() -> str:
    """Bind this gate and the mechanisms that define its graph and grid."""
    return core_obligation_union.value_digest({
        "package_gate": core_obligation_union.bytes_digest(
            Path(__file__).read_bytes()
        ),
        "specification": core_obligation_union.bytes_digest(
            Path(__file__).parents[1].joinpath(
                "standard", "PACKAGE_SELF_POLISH.md"
            ).read_bytes()
        ),
        "report_schema": core_obligation_union.bytes_digest(
            Path(__file__).parents[1].joinpath(
                "schemas",
                "verifier-package-graph-self-polish-assessment-1.schema.json",
            ).read_bytes()
        ),
        "candidate_obligation_schema": core_obligation_union.bytes_digest(
            Path(__file__).parents[1].joinpath(
                "schemas",
                "verifier-package-obligation-candidate-selection-1.schema.json",
            ).read_bytes()
        ),
        "namespace": core_obligation_union.bytes_digest(
            Path(__file__).parents[1].joinpath("core", "namespace.py").read_bytes()
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
            Path(__file__).parents[1].joinpath(
                "standard", "CORRIGIBILITY_RESEARCH.md"
            ).read_bytes()
        ),
        "corrigibility_module_set": core_obligation_union.value_digest([
            {
                "path": path.name,
                "digest": core_obligation_union.bytes_digest(
                    path.read_bytes()
                ),
            }
            for path in sorted(
                Path(__file__).parents[1].joinpath("corrigibility").glob("*.py")
            )
        ]),
        "verifier_10_1_research_input": verifier_replacement.mechanism_digest(),
    })


def _native_facets_replay(
        objects: tuple[NamespaceObject, ...],
        source_coordinate_digest: str, *, selected_object_id: str | None = None) -> dict[str, Any]:
    """Discriminate PASS, FAIL, and UNKNOWN for both native facets per object."""
    records = [item.to_dict() for item in objects]
    collection_bytes = core_obligation_union.canonical_bytes({
        "schema_version": typed_facets.COLLECTION_VERSION,
        "objects": records,
    })
    collection_digest = composition_digest(objects)
    evidence_ref = core_obligation_union.bytes_digest(collection_bytes)
    selection_anchors = [source_coordinate_digest]
    generic_policy = object_facets.object_facets_policy(
        trust_roots=selection_anchors
    )
    typed_policy = typed_facets.typed_facets_policy(
        trust_roots=selection_anchors
    )
    results = []
    if selected_object_id is not None and not any(item.object_id == selected_object_id for item in objects):
        raise ValueError("PACKAGE_FACET_SUBJECT_NOT_DECLARED")
    for item in sorted(objects, key=lambda value: value.kind.value):
        if selected_object_id is not None and item.object_id != selected_object_id:
            continue
        generic_result = None
        typed_result = None
        try:
            generic_request = object_facets.object_facets_request(
                item, policy=generic_policy
            )
            generic_evidence = core_obligation_union.canonical_bytes(
                item.to_dict()
            )
            generic_negative_request, generic_negative_evidence = (
                self_polish_native_replay._negative_case(
                    object_facets,
                    "OBJECT:OBJECT-1.1",
                    generic_request,
                )
            )
            generic_cases = {
                "POSITIVE": (generic_request, generic_evidence),
                "NEGATIVE": (
                    generic_negative_request, generic_negative_evidence
                ),
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
            typed_negative_request, typed_negative_evidence = (
                self_polish_native_replay._negative_case(
                    typed_facets,
                    f"{item.kind.value}:{typed_request['coordinate']}",
                    typed_request,
                )
            )
            typed_cases = {
                "POSITIVE": (typed_request, collection_bytes),
                "NEGATIVE": (typed_negative_request, typed_negative_evidence),
                "UNKNOWN": (typed_request, None),
            }

            def replay_branch(
                    *, request: dict[str, Any], cases: dict[str, Any],
                    builder: Any, rechecker: Any, policy: dict[str, Any],
                    result_fields: tuple[str, ...],
                    checking_mechanism: str,
                    certificate_schema_version: str) -> dict[str, Any]:
                observed = {}
                certificates = {}
                positive_result = None
                for case_kind in ("POSITIVE", "NEGATIVE", "UNKNOWN"):
                    selected_request, evidence = cases[case_kind]
                    try:
                        certificate = builder(
                            selected_request, evidence, policy=policy
                        )
                        replayed = rechecker(
                            certificate,
                            expected_request=selected_request,
                            policy=policy,
                        )
                        observed[case_kind] = replayed["status"]
                        certificates[case_kind] = (
                            core_obligation_union.bytes_digest(certificate)
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
                            raise PackageAssessmentUnavailable(
                                "PACKAGE_NATIVE_FACETS_REPLAY_FAILED"
                            ) from exc
                        raise
                discrimination_status = (
                    "FAIL" if observed["NEGATIVE"] != "FAIL"
                    or observed["UNKNOWN"] != "UNKNOWN"
                    or observed["POSITIVE"] == "FAIL"
                    else "PASS" if observed["POSITIVE"] == "PASS"
                    else "UNKNOWN"
                )
                try:
                    request_digest = core_obligation_union.value_digest(
                        request
                    )
                except (OSError, MemoryError, RecursionError,
                        OverflowError) as exc:
                    if discrimination_status == "FAIL":
                        raise PackageAssessmentUnavailable(
                            "PACKAGE_NATIVE_FACETS_REPLAY_FAILED"
                        ) from exc
                    raise
                return {
                    "coordinate": request["coordinate"],
                    "semantic_version": request["semantic_version"],
                    "proposition_digest": request["proposition_digest"],
                    "checking_mechanism": checking_mechanism,
                    "certificate_schema_version": certificate_schema_version,
                    "status": discrimination_status,
                    "case_statuses": observed,
                    "request_digest": request_digest,
                    "certificate_digests": certificates,
                    **{
                        name: positive_result[name]
                        for name in result_fields
                    },
                }

            generic_result = replay_branch(
                request=generic_request,
                cases=generic_cases,
                builder=object_facets.build_object_facets_certificate,
                rechecker=object_facets.recheck_object_facets_certificate,
                policy=generic_policy,
                result_fields=(
                    "authority", "kind_specific_tier_1_conformance"
                ),
                checking_mechanism=(
                    "verifier.domains.contracts.object_facets."
                    "recheck_object_facets_certificate"
                ),
                certificate_schema_version=object_facets.CERTIFICATE_VERSION,
            )
            typed_result = replay_branch(
                request=typed_request,
                cases=typed_cases,
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
            branch_statuses = {
                generic_result["status"], typed_result["status"]
            }
            status = (
                "FAIL" if "FAIL" in branch_statuses else
                "PASS" if branch_statuses == {"PASS"} else "UNKNOWN"
            )
            results.append({
                "object_id": item.object_id,
                "object_kind": item.kind.value,
                "status": status,
                "generic_object_facets": generic_result,
                "typed_facets": typed_result,
                "resource_status": "AVAILABLE",
            })
        except PackageAssessmentUnavailable:
            results.append({
                "object_id": item.object_id,
                "object_kind": item.kind.value,
                "status": "FAIL",
                "generic_object_facets": generic_result,
                "typed_facets": typed_result,
                "resource_status": "UNAVAILABLE",
            })
        except (OSError, ImportError, MemoryError, RecursionError,
                OverflowError):
            completed = [
                branch for branch in (generic_result, typed_result)
                if type(branch) is dict
            ]
            preserved_failure = any(
                branch.get("status") == "FAIL" for branch in completed
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
    branch_statuses = [
        branch["status"] if branch is not None else "UNKNOWN"
        for row in results
        for branch in (
            row["generic_object_facets"], row["typed_facets"]
        )
    ]
    pass_count = branch_statuses.count("PASS")
    fail_count = branch_statuses.count("FAIL")
    unknown_count = branch_statuses.count("UNKNOWN")
    status = (
        "FAIL" if any(row["status"] == "FAIL" for row in results) else
        "PASS" if pass_count == len(results) * 2 else "UNKNOWN"
    )
    try:
        generic_mechanism_digest = object_facets.mechanism_digest()
        typed_mechanism_digest = typed_facets.mechanism_digest()
    except (OSError, MemoryError, RecursionError, OverflowError) as exc:
        raise PackageAssessmentUnavailable(*(
            ("PACKAGE_NATIVE_FACETS_REPLAY_FAILED",) if status == "FAIL" else ()
        )) from exc
    body = {
        "schema_version": "verifier-package-native-facets-replay-1",
        "status": status,
        "source_coordinate_digest": source_coordinate_digest,
        "collection_digest": collection_digest,
        "collection_bytes_digest": evidence_ref,
        "generic_mechanism_digest": generic_mechanism_digest,
        "typed_mechanism_digest": typed_mechanism_digest,
        "object_count": len(results),
        "objective_count": len(results) * 2,
        "case_count": len(results) * 2 * 3,
        "positive_case_count": len(results) * 2,
        "negative_case_count": len(results) * 2,
        "unknown_case_count": len(results) * 2,
        "pass_count": pass_count,
        "fail_count": fail_count,
        "unknown_count": unknown_count,
        "policy_anchor_class": "SELF_SELECTED_SOURCE_BINDING_NOT_AUTHORITY",
        "results": results,
        "claim_boundary": (
            "PASS establishes checker discrimination of exact positive, malformed "
            "negative, and unavailable evidence for the selected generic and typed "
            "facet requests. Payload truth, object profile conformance, normative "
            "family closure, and authority remain NOT_ESTABLISHED."
        ),
    }
    try:
        body["replay_digest"] = core_obligation_union.value_digest(body)
    except (OSError, MemoryError, RecursionError, OverflowError) as exc:
        raise PackageAssessmentUnavailable(*(
            ("PACKAGE_NATIVE_FACETS_REPLAY_FAILED",) if status == "FAIL" else ()
        )) from exc
    return body


def _installed_native_case_replay(
        source_root: str | Path | None,
        source_coordinate_digest: str) -> dict[str, Any]:
    """Replay every installed tier-1 and tier-2 specimen without promotion."""
    body: dict[str, Any] = {
        "schema_version": "verifier-package-installed-native-case-replay-1",
        "status": "NOT_SELECTED" if source_root is None else "UNKNOWN",
        "resource_status": (
            "NOT_SELECTED" if source_root is None else "AVAILABLE"
        ),
        "source_coordinate_digest": source_coordinate_digest,
        "tier_results": [],
        "memberships": [],
        "membership_count": 0,
        "case_count": 0,
        "claim_boundary": (
            "PASS establishes installed specimen discrimination for all 82 "
            "registered tier-1 and tier-2 routes. It does not establish that "
            "the selected package graph is a passing instance of those routes."
        ),
    }
    if source_root is None:
        body["replay_digest"] = core_obligation_union.value_digest(body)
        return body
    try:
        root = Path(source_root).resolve(strict=True)
        if not root.is_dir():
            raise OSError("source root unavailable")
        for tier in (1, 2):
            manifest = self_polish_native_replay.build_installed_replay_manifest(
                tier, root, source_coordinate_digest=source_coordinate_digest,
            )
            receipt = self_polish_native_replay.replay_native_obligations(
                manifest,
                root,
                tier=tier,
                expected_manifest_digest=(
                    core_obligation_union.bytes_digest(manifest)
                ),
                expected_source_coordinate_digest=source_coordinate_digest,
            )
            body["tier_results"].append({
                "tier": tier,
                "status": receipt["status"],
                "manifest_digest": receipt["manifest_digest"],
                "receipt_digest": receipt["receipt_digest"],
                "membership_count": receipt["membership_count"],
                "case_count": receipt["case_count"],
                "invalidators": receipt["invalidators"],
            })
            body["memberships"].extend(receipt["memberships"])
            if "NATIVE_REPLAY_MECHANISM_UNAVAILABLE" in receipt["invalidators"]:
                body["resource_status"] = "UNAVAILABLE"
        statuses = [row["status"] for row in body["tier_results"]]
        body["status"] = (
            "FAIL" if "FAIL" in statuses else
            "UNKNOWN" if "UNKNOWN" in statuses else "PASS"
        )
        body["membership_count"] = len(body["memberships"])
        body["case_count"] = sum(
            row["case_count"] for row in body["tier_results"]
        )
    except self_polish_native_replay.NativeReplayResourceError as exc:
        body["resource_status"] = "UNAVAILABLE"
        body["status"] = (
            "FAIL" if exc.failure_observed or any(
                row.get("status") == "FAIL"
                for row in body["tier_results"] if type(row) is dict
            ) else "UNKNOWN"
        )
    except (OSError, ImportError, MemoryError, RecursionError, OverflowError):
        body["resource_status"] = "UNAVAILABLE"
        body["status"] = (
            "FAIL" if any(
                row.get("status") == "FAIL"
                for row in body["tier_results"] if type(row) is dict
            ) else "UNKNOWN"
        )
    except (self_polish_native_replay.NativeReplayError, AttributeError,
            KeyError, RuntimeError, TypeError, ValueError, UnicodeError):
        body["status"] = "FAIL"
    body["membership_count"] = len(body["memberships"])
    body["case_count"] = sum(
        row["case_count"] for row in body["tier_results"]
    )
    try:
        body["replay_digest"] = core_obligation_union.value_digest(body)
    except (OSError, MemoryError, RecursionError, OverflowError) as exc:
        raise self_polish_native_replay.NativeReplayResourceError(
            failure_observed=body["status"] == "FAIL"
        ) from exc
    return body


def _selected_owner_decision_ids(
        owner_decision_admission: Mapping[str, Any] | None) -> set[str]:
    if (owner_decision_admission is None
            or owner_decision_admission.get("status") != "PASS"):
        return set()
    selected = owner_decision_admission.get("adopted_decision_ids")
    return set(selected) if type(selected) is list else set()


def _empty_tier_zero_admission(status: str, error: str) -> dict[str, Any]:
    return {
        "schema_version": TIER_ZERO_BINDING_SCHEMA,
        "status": status,
        "report_schema_version": None,
        "report_digest": None,
        "profile_id": None,
        "profile_digest": None,
        "manifest_digest": None,
        "mechanism_digest": None,
        "obligation_count": 0,
        "obligation_status_counts": {"PASS": 0, "FAIL": 0, "UNKNOWN": 0},
        "assessment_reason_count": 0,
        "finalization_status": "NOT_ESTABLISHED",
        "closed_coordinates": [],
        "unclosed_coordinates": [f"VSTD-T0.{index}" for index in range(1, 10)],
        "source_repository": None,
        "source_revision": None,
        "source_census_digest": None,
        "source_binding_status": "NOT_ESTABLISHED",
        "error": error,
        "claim_boundary": _TIER_ZERO_BINDING_BOUNDARY,
    }


def _tier_zero_repository_admission(
        source_root: str | Path | None,
        coordinate: Mapping[str, Any],
        source_evidence: Mapping[str, Any] | None,
        ) -> dict[str, Any]:
    """Bind one exact vstd polish 0 report to the selected package source."""
    if source_root is None:
        return _empty_tier_zero_admission(
            "NOT_ESTABLISHED", "TIER_ZERO_SOURCE_ROOT_NOT_SELECTED"
        )
    try:
        report = tier_zero.assess_tier_zero(source_root)
    except (OSError, ImportError, MemoryError, RecursionError, OverflowError):
        return _empty_tier_zero_admission(
            "UNKNOWN", "TIER_ZERO_ASSESSMENT_UNAVAILABLE"
        )
    except (AttributeError, KeyError, RuntimeError, TypeError, ValueError,
            UnicodeError):
        return _empty_tier_zero_admission(
            "FAIL", "TIER_ZERO_ASSESSMENT_INVALID"
        )
    if type(report) is not dict:
        return _empty_tier_zero_admission("FAIL", "TIER_ZERO_REPORT_INVALID")
    from verifier.runtime import namespace_admission, package_admission
    is_extensible = report.get("schema_version") == namespace_admission.REPORT_SCHEMA
    is_package = report.get("schema_version") in package_admission.REPORT_SCHEMAS
    if is_extensible:
        # A bounded namespace receipt does not check the retained 234/408
        # denominator. It can never alone discharge whole-package admission.
        return _empty_tier_zero_admission(
            "FAIL" if report.get("status") == "FAIL" else "UNKNOWN",
            next(iter(report.get("blockers", [])), "PACKAGE_ADDITIVE_ADMISSION_REQUIRED"),
        )
    finalization = report.get("finalization")
    obligations = report.get("obligations")
    selected_coordinate = report.get("source_coordinate")
    selected_census = (
        finalization.get("source_census_digest")
        if type(finalization) is dict else None
    )
    expected_census = (
        source_evidence.get("candidate_source_census_digest")
        if type(source_evidence) is dict else None
    )
    source_binding_status = (
        "PASS" if type(selected_coordinate) is dict
        and selected_coordinate.get("revision") == coordinate["source_head"]
        and type(selected_census) is str
        and selected_census == expected_census
        else "FAIL" if expected_census is not None else "NOT_ESTABLISHED"
    )
    report_digest = report.get("report_digest")
    report_body = {
        key: value for key, value in report.items() if key != "report_digest"
    }
    report_digest_valid = (
        type(report_digest) is str
        and _SHA256.fullmatch(report_digest) is not None
        and report_digest == core_obligation_union.value_digest(report_body)
    )
    exact_coordinates = [f"VSTD-T0.{index}" for index in range(1, 10)]
    assessment_reason_count = (
        sum(
            type(row) is dict
            and type(row.get("assessment_reason")) is str
            and bool(row["assessment_reason"].strip())
            for row in obligations
        ) if type(obligations) is list else 0
    )
    if type(obligations) is not list or any(
            type(row) is not dict
            or type(row.get("coordinate")) is not str
            or row.get("status") not in ("PASS", "FAIL", "UNKNOWN")
            or type(row.get("blockers")) is not list
            or any(type(code) is not str for code in row["blockers"])
            for row in obligations):
        return _empty_tier_zero_admission("FAIL", "TIER_ZERO_REPORT_INVALID")
    counts = Counter(row["status"] for row in obligations)
    expected_status = (
        "FAIL" if counts["FAIL"] else "UNKNOWN" if counts["UNKNOWN"] else "PASS"
    )
    closed = [row["coordinate"] for row in obligations if row["status"] == "PASS"]
    unclosed = [row["coordinate"] for row in obligations if row["status"] != "PASS"]
    finalization_valid = (
        type(finalization) is dict
        and finalization.get("status") == expected_status
        and finalization.get("complete") is (expected_status == "PASS")
        and finalization.get("finalized") is (expected_status == "PASS")
        and finalization.get("scope") == "TIER_ZERO_REPOSITORY_ADMISSION_ONLY"
        and finalization.get("profile_digest") == report.get("profile_digest")
        and finalization.get("mechanism_digest") == report.get("mechanism_digest")
        and finalization.get("closed_coordinates") == closed
        and finalization.get("unclosed_coordinates") == unclosed
        and finalization.get("source_coordinate") == selected_coordinate
        and type(finalization.get("reason")) is str
        and bool(finalization["reason"].strip())
    )
    report_shape_valid = (
        (
            report.get("schema_version") == tier_zero.REPORT_SCHEMA
            or report.get("schema_version") in package_admission.REPORT_SCHEMAS
        )
        and report.get("status") == expected_status
        and report.get("obligation_count") == 9
        and report.get("obligation_status_counts")
            == {key: counts[key] for key in ("PASS", "FAIL", "UNKNOWN")}
        and type(obligations) is list
        and [row.get("coordinate") for row in obligations] == exact_coordinates
        and assessment_reason_count == 9
        and report.get("blockers") == sorted({
            code for row in obligations for code in row["blockers"]
        })
        and all(
            not row["blockers"] if row["status"] == "PASS" else bool(row["blockers"])
            for row in obligations
        )
        and report.get("tier_1_plus_status") == "NOT_ESTABLISHED"
        and report.get("polished") is False
        and report.get("release_authorized") is False
        and report.get("deployment_authorized") is False
        and type(report.get("profile_digest")) is str
        and _SHA256.fullmatch(report["profile_digest"]) is not None
        and type(report.get("manifest_digest")) is str
        and _SHA256.fullmatch(report["manifest_digest"]) is not None
        and type(report.get("mechanism_digest")) is str
        and report.get("mechanism_digest") == (
            package_admission.mechanism_digest() if is_package else tier_zero.mechanism_digest())
        and (not is_package or report.get("profile_digest") == package_admission.profile_digest())
        and report_digest_valid
        and finalization_valid
    )
    if not report_shape_valid:
        return _empty_tier_zero_admission("FAIL", "TIER_ZERO_REPORT_INVALID")
    if report.get("status") == "FAIL" or source_binding_status == "FAIL":
        status = "FAIL"
    elif report.get("status") == "PASS" and finalization_valid \
            and source_binding_status == "PASS":
        status = "PASS"
    else:
        status = "UNKNOWN"
    return {
        "schema_version": TIER_ZERO_BINDING_SCHEMA,
        "status": status,
        "report_schema_version": report.get("schema_version"),
        "report_digest": report_digest if report_digest_valid else None,
        "profile_id": report.get("profile_id"),
        "profile_digest": report.get("profile_digest"),
        "manifest_digest": report.get("manifest_digest"),
        "mechanism_digest": report.get("mechanism_digest"),
        "obligation_count": report.get("obligation_count", 0),
        "obligation_status_counts": report.get(
            "obligation_status_counts",
            {"PASS": 0, "FAIL": 0, "UNKNOWN": 0},
        ),
        "assessment_reason_count": assessment_reason_count,
        "finalization_status": (
            finalization.get("status")
            if type(finalization) is dict else "NOT_ESTABLISHED"
        ),
        "closed_coordinates": (
            finalization.get("closed_coordinates", [])
            if type(finalization) is dict else []
        ),
        "unclosed_coordinates": (
            finalization.get("unclosed_coordinates", exact_coordinates)
            if type(finalization) is dict else exact_coordinates
        ),
        "source_repository": (
            selected_coordinate.get("repository")
            if type(selected_coordinate) is dict else None
        ),
        "source_revision": (
            selected_coordinate.get("revision")
            if type(selected_coordinate) is dict else None
        ),
        "source_census_digest": selected_census,
        "source_binding_status": source_binding_status,
        "error": None if status == "PASS" else (
            "TIER_ZERO_SOURCE_BINDING_DIFFERS" if source_binding_status == "FAIL"
            else "TIER_ZERO_REPORT_NOT_FINALIZED"
        ),
        "claim_boundary": _TIER_ZERO_BINDING_BOUNDARY,
    }


def _tier_zero_cells(
        objects: tuple[NamespaceObject, ...], composition_status: str,
        native_replay: Mapping[str, Any],
        repository_admission: Mapping[str, Any],
        candidate_ledger: Mapping[str, Any],
        owner_decision_admission: Mapping[str, Any] | None = None,
        ) -> list[dict[str, Any]]:
    by_kind = {item.kind: item for item in objects}
    native_by_kind = {
        row["object_kind"]: row for row in native_replay["results"]
    }
    owner_decisions = _selected_owner_decision_ids(
        owner_decision_admission
    )
    cells = []
    for kind in ObjectKind:
        native_status = (
            native_by_kind[kind.value]["status"]
            if kind.value in native_by_kind else "NOT_ESTABLISHED"
        )
        admission_status = repository_admission.get("status")
        status = (
            "FAIL" if composition_status == "FAIL"
            or kind.value not in native_by_kind
            or native_status == "FAIL"
            or admission_status == "FAIL"
            else "PASS" if composition_status == "PASS"
            and native_status == "PASS"
            and admission_status == "PASS"
            else "UNKNOWN"
        )
        cells.append({
            "schema_version": TIER_ZERO_SCHEMA,
            "object_kind": kind.value,
            "tier": 0,
            "tier_name": "REPRESENTATION_ADMISSION",
            "object_id": by_kind[kind].object_id,
            "record_digest": by_kind[kind].digest,
            "status": status,
            "structural_representation_status": (
                composition_status
                if kind.value in native_by_kind else "FAIL"
            ),
            "native_facets_discrimination_status": native_status,
            "repository_admission_status": admission_status,
            "repository_admission_report_digest": repository_admission.get(
                "report_digest"
            ),
            "semantic_obligation_status": "NOT_ESTABLISHED",
            "denominator_decision_status": "NOT_ESTABLISHED",
            "owner_decision_refs": (
                ["CTC-5"] if "CTC-5" in owner_decisions else []
            ),
            "assessment_reason": (
                f"{kind.value} is represented by the unique object record "
                f"{by_kind[kind].object_id}; the typed package graph status is "
                f"{composition_status}, native facet discrimination is "
                f"{native_status}, and the bound Tier-0 repository admission "
                f"status is {admission_status}."
            ),
            "claim_boundary": (
                "PASS establishes this unique object record's inclusion in the "
                "finalized Tier-0 repository declaration, typed graph composition, "
                "and native facet-checker discrimination only. Payload truth and "
                "all Tier-1-plus object semantics remain NOT_ESTABLISHED."
            ),
        })
    return cells


def _core_route_memberships(
        inventory: dict[str, Any], native_replay: dict[str, Any],
        installed_case_replay: dict[str, Any],
        candidate_ledger: dict[str, Any] | None = None,
        owner_decision_admission: Mapping[str, Any] | None = None,
        ) -> dict[str, Any]:
    if candidate_ledger is None:
        candidate_ledger = (
            package_obligation_candidate.not_selected_candidate_obligation_ledger()
        )
    observed: dict[tuple[str, str], dict[str, Any]] = {}
    unresolved_native_statuses: dict[tuple[str, str], str] = {}
    duplicate_observed_identities: set[tuple[str, str]] = set()
    for row in native_replay["results"]:
        generic = row["generic_object_facets"]
        typed = row["typed_facets"]
        if generic is not None and row["object_kind"] == "OBJECT":
            key = row["object_kind"], generic["coordinate"]
            if key in observed:
                duplicate_observed_identities.add(key)
            observed[key] = generic
        elif row["object_kind"] == "OBJECT":
            unresolved_native_statuses[("OBJECT", "OBJECT-1.1")] = row[
                "status"
            ]
        if typed is not None:
            key = row["object_kind"], typed["coordinate"]
            if key in observed:
                duplicate_observed_identities.add(key)
            observed[key] = typed
        else:
            unresolved_native_statuses[(
                row["object_kind"],
                typed_facets.coordinate(row["object_kind"]),
            )] = row["status"]

    candidate_rows = {
        (row["object_kind"], row["coordinate"]): row
        for row in candidate_ledger["rows"]
    } if candidate_ledger["status"] == "PASS" else {}
    selected_owner_decisions = _selected_owner_decision_ids(
        owner_decision_admission
    )
    specimen_rows: dict[tuple[str, str], dict[str, Any]] = {}
    duplicate_specimen_identities: set[tuple[str, str]] = set()
    for row in installed_case_replay["memberships"]:
        membership = row["membership"]
        key = membership["object_kind"], membership["coordinate"]
        if key in specimen_rows:
            duplicate_specimen_identities.add(key)
        specimen_rows[key] = row
    installed_tier_statuses = {
        row["tier"]: row["status"]
        for row in installed_case_replay["tier_results"]
    }
    memberships = []
    mapped_count = 0
    projection_failed = bool(
        duplicate_observed_identities or duplicate_specimen_identities
    )
    projection_unknown = False
    identity_projection_failed = projection_failed
    identity_projection_unknown = False
    unknown_causes: set[str] = set()
    expected_native_keys = {
        (kind.value, typed_facets.coordinate(kind.value)) for kind in ObjectKind
    } | {("OBJECT", "OBJECT-1.1")}
    inventory_keys = {
        (cell["object_kind"], route["coordinate"])
        for cell in inventory["family_cells"]
        for route in cell["registered_route_memberships"]
    }
    if not expected_native_keys <= inventory_keys:
        projection_failed = True
        identity_projection_failed = True
    for cell in inventory["family_cells"]:
        for route in cell["registered_route_memberships"]:
            key = cell["object_kind"], route["coordinate"]
            native = observed.get(key)
            selected_for_native_replay = key in expected_native_keys
            identity_matches = native is not None and (
                cell["tier"] == 1
                and native["semantic_version"] == route["semantic_version"]
                and native["proposition_digest"] == route["proposition_digest"]
                and native["checking_mechanism"]
                    == route["checking_mechanism"]
                and native["certificate_schema_version"]
                    == route["certificate_schema_version"]
            )
            if native is not None:
                mapped_count += 1
            if native is not None and not identity_matches:
                projection_failed = True
                identity_projection_failed = True
            if native is not None:
                native_identity_status = (
                    "PASS" if identity_matches else "FAIL"
                )
                discrimination = (
                    native["status"] if identity_matches else "FAIL"
                )
                if discrimination == "FAIL":
                    projection_failed = True
                elif discrimination == "UNKNOWN":
                    projection_unknown = True
                    unknown_causes.add(f"{key[0]}:{key[1]}")
            elif selected_for_native_replay:
                native_identity_status = "NOT_ESTABLISHED"
                identity_projection_unknown = True
                discrimination = unresolved_native_statuses.get(
                    key, "UNKNOWN"
                )
                if discrimination == "FAIL":
                    projection_failed = True
                else:
                    discrimination = "UNKNOWN"
                    projection_unknown = True
                    unknown_causes.add(f"{key[0]}:{key[1]}")
            else:
                native_identity_status = "NOT_RUN"
                discrimination = "NOT_RUN"
            candidate = candidate_rows.get(
                key
            )
            specimen = specimen_rows.get(key)
            specimen_identity_matches = specimen is not None and all(
                specimen["membership"].get(field) == route.get(field)
                for field in (
                    "semantic_version", "coordinate", "proposition_digest",
                    "certificate_schema_version", "checking_mechanism", "scope",
                )
            ) and specimen["membership"].get("object_kind") == cell["object_kind"] \
                and specimen["membership"].get("tier") == cell["tier"]
            if specimen is not None and not specimen_identity_matches:
                projection_failed = True
                identity_projection_failed = True
            if specimen_identity_matches:
                installed_specimen_status = specimen["status"]
            elif specimen is not None:
                installed_specimen_status = "FAIL"
            elif cell["tier"] in (1, 2):
                selected_tier_status = installed_tier_statuses.get(
                    cell["tier"]
                )
                if selected_tier_status is None:
                    selected_tier_status = (
                        "NOT_SELECTED"
                        if installed_case_replay["status"] == "NOT_SELECTED"
                        else "UNKNOWN"
                    )
                installed_specimen_status = (
                    "FAIL" if selected_tier_status == "PASS"
                    else "UNKNOWN"
                    if selected_tier_status in ("FAIL", "UNKNOWN")
                    else "NOT_RUN"
                )
                if selected_tier_status == "PASS":
                    identity_projection_failed = True
                elif selected_tier_status in ("FAIL", "UNKNOWN"):
                    identity_projection_unknown = True
            else:
                installed_specimen_status = "NOT_RUN"
            if installed_specimen_status == "FAIL":
                projection_failed = True
            elif installed_specimen_status == "UNKNOWN":
                projection_unknown = True
                unknown_causes.add(
                    specimen["obligation_id"]
                    if specimen_identity_matches else f"{key[0]}:{key[1]}"
                )
            owner_refs = []
            for decision_id, applies in (
                    ("CTC-1", True),
                    ("CTC-2", cell["tier"] == 7),
                    ("CTC-3", candidate is not None and
                     candidate["candidate_rev4_class"] == "REASON_PENDING"),
                    ("CTC-5", cell["tier"] == 1),
                    ("CTC-6", cell["object_kind"] == "MODEL")):
                if applies and decision_id in selected_owner_decisions:
                    owner_refs.append(decision_id)
            owner_refs.extend(
                question for question in (
                    f"{cell['object_kind']}-Q{index}"
                    for index in range(1, 5)
                ) if question in selected_owner_decisions
            )
            memberships.append({
                "object_kind": cell["object_kind"],
                "tier": cell["tier"],
                "tier_name": cell["tier_name"],
                "semantic_version": route["semantic_version"],
                "coordinate": route["coordinate"],
                "checking_mechanism": route["checking_mechanism"],
                "proposition_digest": route["proposition_digest"],
                "certificate_schema_version": route[
                    "certificate_schema_version"
                ],
                "scope": route["scope"],
                "native_route_identity_status": native_identity_status,
                "selected_package_native_replay_status": discrimination,
                "installed_specimen_replay_status": (
                    installed_specimen_status
                ),
                "installed_specimen_replay_digest": (
                    specimen["native_replay_digest"]
                    if specimen_identity_matches else None
                ),
                "installed_specimen_case_count": (
                    len(specimen["cases"])
                    if specimen_identity_matches else 0
                ),
                "native_replay_request_digest": (
                    native["request_digest"] if native is not None else None
                ),
                "normative_full_family_closure": "NOT_ESTABLISHED",
                "candidate_obligation_identity_status": (
                    "PASS" if candidate is not None
                    and candidate["candidate_semantic_identity_status"] == "PASS"
                    else "UNKNOWN" if candidate is not None else
                    "NOT_SELECTED" if candidate_ledger["status"] == "NOT_SELECTED"
                    else "NOT_RETAINED"
                ),
                "candidate_semantic_identity_status": (
                    candidate["candidate_semantic_identity_status"]
                    if candidate is not None else "NOT_ESTABLISHED"
                ),
                "candidate_obligation_row_digest": (
                    candidate["candidate_row_digest"]
                    if candidate is not None else None
                ),
                "candidate_rev4_class": (
                    candidate["candidate_rev4_class"]
                    if candidate is not None else None
                ),
                "candidate_mechanism_assessment": (
                    candidate["candidate_mechanism_assessment"]
                    if candidate is not None else None
                ),
                "candidate_owner_disposition_status": (
                    candidate["owner_disposition_status"]
                    if candidate is not None else "NOT_ESTABLISHED"
                ),
                "owner_decision_refs": sorted(set(owner_refs)),
                "status": (
                    "FAIL" if native_identity_status == "FAIL"
                    or discrimination == "FAIL"
                    or installed_specimen_status == "FAIL"
                    else "UNKNOWN"
                ),
            })
    expected_mapped_count = len(ObjectKind) + 1
    if (native_replay["status"] == "PASS"
            and mapped_count != expected_mapped_count):
        projection_failed = True
        identity_projection_failed = True
    elif mapped_count != expected_mapped_count:
        projection_unknown = True
        identity_projection_unknown = True
    projection_status = (
        "FAIL" if projection_failed else
        "UNKNOWN" if projection_unknown else "PASS"
    )
    route_identity_projection_status = (
        "FAIL" if identity_projection_failed else
        "UNKNOWN" if identity_projection_unknown else "PASS"
    )
    return {
        "schema_version": "verifier-package-core-route-projection-1",
        "status": projection_status,
        "route_identity_projection_status": (
            route_identity_projection_status
        ),
        "unknown_causes": sorted(unknown_causes),
        "membership_count": len(memberships),
        "mapped_checker_discrimination_count": mapped_count,
        "expected_mapped_checker_discrimination_count": expected_mapped_count,
        "not_run_count": sum(
            row["selected_package_native_replay_status"] == "NOT_RUN"
            for row in memberships
        ),
        "unavailable_selected_count": sum(
            row["selected_package_native_replay_status"] == "UNKNOWN"
            for row in memberships
        ),
        "installed_specimen_membership_count": len(specimen_rows),
        "installed_specimen_pass_count": sum(
            row["installed_specimen_replay_status"] == "PASS"
            for row in memberships
        ),
        "installed_specimen_unknown_count": sum(
            row["installed_specimen_replay_status"] == "UNKNOWN"
            for row in memberships
        ),
        "installed_specimen_fail_count": sum(
            row["installed_specimen_replay_status"] == "FAIL"
            for row in memberships
        ),
        "memberships": memberships,
        "claim_boundary": (
            "route_identity_projection_status establishes only exact identity "
            "projection for selected native requests and retained specimens. "
            "The aggregate status also includes checker discrimination and "
            "installed-specimen outcomes; unknown_causes attributes those "
            "unresolved outcomes without promoting them. Every route obligation "
            "remains UNKNOWN until its semantic instance and normative family "
            "closure are established."
        ),
    }


def _core_cells(
        inventory: dict[str, Any], memberships: list[dict[str, Any]]
        ) -> list[dict[str, Any]]:
    by_cell: dict[tuple[str, int], list[dict[str, Any]]] = {}
    for row in memberships:
        by_cell.setdefault((row["object_kind"], row["tier"]), []).append(row)
    cells = []
    for row in inventory["family_cells"]:
        selected = by_cell.get((row["object_kind"], row["tier"]), [])
        replay_statuses = [
            item["selected_package_native_replay_status"]
            for item in selected
        ]
        observed_status = (
            "FAIL" if "FAIL" in replay_statuses else
            "PASS" if replay_statuses
            and all(value == "PASS" for value in replay_statuses)
            else "NOT_ESTABLISHED"
        )
        membership_statuses = [item["status"] for item in selected]
        candidate_identity_statuses = [
            item["candidate_obligation_identity_status"] for item in selected
        ]
        candidate_classes = [
            item["candidate_rev4_class"] for item in selected
            if item["candidate_rev4_class"] is not None
        ]
        candidate_mechanisms = [
            item["candidate_mechanism_assessment"] for item in selected
            if item["candidate_mechanism_assessment"] is not None
        ]
        cells.append({
            "object_kind": row["object_kind"],
            "tier": row["tier"],
            "tier_name": row["tier_name"],
            "installed_denominator_status": row["denominator_status"],
            "registered_route_membership_count": row[
                "registered_route_membership_count"
            ],
            "normative_full_family_closure": row[
                "normative_full_family_closure"
            ],
            "selected_package_native_replay_status": observed_status,
            "candidate_coverage_status": (
                "PASS" if candidate_identity_statuses
                and all(value == "PASS" for value in candidate_identity_statuses)
                else "UNKNOWN"
            ),
            "candidate_class_counts": {
                value: candidate_classes.count(value)
                for value in sorted(set(candidate_classes))
            },
            "candidate_mechanism_counts": {
                value: candidate_mechanisms.count(value)
                for value in sorted(set(candidate_mechanisms))
            },
            "reason_pending_coordinates": [
                item["coordinate"] for item in selected
                if item["candidate_rev4_class"] == "REASON_PENDING"
            ],
            "owner_decision_refs": sorted({
                reference for item in selected
                for reference in item["owner_decision_refs"]
            }),
            "status": (
                "FAIL" if "FAIL" in membership_statuses else "UNKNOWN"
            ),
        })
    return cells


def _corrigibility_research_evidence() -> dict[str, Any]:
    root = Path(__file__).parents[1]
    module_rows = [
        {
            "path": path.relative_to(root).as_posix(),
            "digest": core_obligation_union.bytes_digest(path.read_bytes()),
        }
        for path in sorted(root.joinpath("corrigibility").glob("*.py"))
    ]
    body = {
        "schema_version": "verifier-corrigibility-research-evidence-1",
        "status": "BOUND_RESEARCH_INPUTS_NOT_QUALIFICATION",
        "research_spec_digest": core_obligation_union.bytes_digest(
            root.joinpath(
                "standard", "CORRIGIBILITY_RESEARCH.md"
            ).read_bytes()
        ),
        "module_count": len(module_rows),
        "module_set_digest": core_obligation_union.value_digest(module_rows),
        "represented_object_kind_count": len(ObjectKind),
        "verifier_10_1": {
            "semantic_version": verifier_replacement.SEMANTIC_VERSION,
            "coordinate": verifier_replacement.COORDINATE,
            "proposition_digest": verifier_replacement.PROPOSITION_DIGEST,
            "mechanism_digest": verifier_replacement.mechanism_digest(),
            "status": "RESEARCH_INPUT_ONLY_NOT_EXTENSION_CREDIT",
        },
        "claim_boundary": (
            "These exact research bytes and the finite VERIFIER-10.1 mechanism "
            "are bound as inputs only. They do not establish any all-kind "
            "corrigibility instance, authority, foresight frontier, or extension "
            "qualification."
        ),
    }
    body["evidence_digest"] = core_obligation_union.value_digest(body)
    return body


def _corrigibility_cells(
        candidate_ledger: Mapping[str, Any],
        research_evidence: Mapping[str, Any],
        owner_decision_admission: Mapping[str, Any] | None = None,
        ) -> list[dict[str, Any]]:
    owner_decisions = _selected_owner_decision_ids(
        owner_decision_admission
    )
    return [
        {
            "schema_version": CORRIGIBILITY_CELL_SCHEMA,
            "object_kind": kind.value,
            "declared_status": "WIP",
            "native_status": "NOT_RUN",
            "qualification": "NOT_ESTABLISHED",
            "status": "UNKNOWN",
            "authority_status": "NOT_ESTABLISHED",
            "research_evidence_digest": research_evidence["evidence_digest"],
            "research_surface_status": (
                "BOUND_RESEARCH_INPUTS_NOT_QUALIFICATION"
            ),
            "verifier_10_1_research_input_status": (
                "BOUND_NOT_EXTENSION_CREDIT"
                if kind is ObjectKind.VERIFIER else "NOT_APPLICABLE"
            ),
            "code_set_status": (
                "RESEARCH_SURFACES_BOUND_OWNER_DECISION_PENDING"
            ),
            "owner_decision_refs": (
                ["CTC-4"] if "CTC-4" in owner_decisions else []
            ),
        }
        for kind in ObjectKind
    ]


def _corrigibility_extension_selection(
        cells: list[dict[str, Any]],
        research_evidence: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": CORRIGIBILITY_EXTENSION_SCHEMA,
        "profile_id": CORRIGIBILITY_EXTENSION_SCHEMA,
        "declared_status": "WIP",
        "binding_digest": core_obligation_union.value_digest({
            "cells": cells,
            "research_evidence_digest": research_evidence["evidence_digest"],
        }),
    }


def _candidate_obligation_ledger(
        inventory: dict[str, Any], *,
        source_root: str | Path | None,
        cards_root: str | Path | None,
        manifest_path: str | Path | None,
        expected_manifest_digest: str | None,
        reason_ledger_path: str | Path | None,
        expected_reason_ledger_digest: str | None,
        ) -> dict[str, Any]:
    selected = (
        cards_root, manifest_path, expected_manifest_digest,
        reason_ledger_path, expected_reason_ledger_digest,
    )
    if all(value is None for value in selected):
        return package_obligation_candidate.not_selected_candidate_obligation_ledger()
    if cards_root is None or manifest_path is None:
        return package_obligation_candidate.failed_candidate_obligation_ledger(
            "PACKAGE_CANDIDATE_SELECTION_INCOMPLETE"
        )
    if expected_manifest_digest is None:
        return package_obligation_candidate.failed_candidate_obligation_ledger(
            "PACKAGE_CANDIDATE_EXPECTED_MANIFEST_DIGEST_REQUIRED"
        )
    try:
        return package_obligation_candidate.load_candidate_obligation_ledger(
            cards_root,
            manifest_path,
            inventory,
            expected_manifest_digest=expected_manifest_digest,
            reason_ledger_path=reason_ledger_path,
            expected_reason_ledger_digest=expected_reason_ledger_digest,
            source_root=source_root,
        )
    except package_obligation_candidate.CandidateLedgerUnavailable as exc:
        return package_obligation_candidate.unavailable_candidate_obligation_ledger(
            str(exc)
        )
    except package_obligation_candidate.CandidateLedgerError as exc:
        return package_obligation_candidate.failed_candidate_obligation_ledger(
            str(exc)
        )
    except (OSError, ImportError, MemoryError, RecursionError, OverflowError):
        return package_obligation_candidate.unavailable_candidate_obligation_ledger(
            "PACKAGE_CANDIDATE_SELECTION_UNAVAILABLE"
        )


def _owner_decision_admission(
        candidate_ledger: Mapping[str, Any], *,
        source_coordinate_digest: str,
        policy_path: str | Path | None,
        expected_policy_digest: str | None,
        decision_path: str | Path | None,
        expected_decision_digest: str | None,
        ) -> dict[str, Any]:
    """Load one exact configured-key owner statement without self-selection."""
    try:
        return package_owner_decision.load_owner_decision_admission(
            candidate_ledger,
            source_coordinate_digest=source_coordinate_digest,
            policy_path=policy_path,
            expected_policy_digest=expected_policy_digest,
            decision_path=decision_path,
            expected_decision_digest=expected_decision_digest,
        )
    except package_owner_decision.OwnerDecisionUnavailable as exc:
        return package_owner_decision.unavailable_owner_decision_admission(
            str(exc)
        )
    except package_owner_decision.OwnerDecisionError as exc:
        return package_owner_decision.failed_owner_decision_admission(
            str(exc)
        )
    except (OSError, ImportError, MemoryError, RecursionError, OverflowError):
        return package_owner_decision.unavailable_owner_decision_admission(
            "PACKAGE_OWNER_DECISION_ADMISSION_UNAVAILABLE"
        )


def _source_recapture_binding(
        source_root: str | Path | None,
        selected_coordinate: dict[str, str]) -> dict[str, Any]:
    if source_root is None:
        return {
            "status": "NOT_ESTABLISHED",
            "matches_selected_source": "UNKNOWN",
            "observed_source_coordinate": None,
            "observed_source_evidence": None,
            "claim_boundary": (
                "A later source recapture was not selected for this call."
            ),
        }
    try:
        observed = polish_requirements.capture_core_self_polish_source(
            source_root
        )
        observed_coordinate = {
            "source_head": observed["git_head"],
            "source_tree": observed["git_tree"],
            "source_worktree_status_digest": observed[
                "worktree_status_digest"
            ],
            "source_manifest_digest": (
                polish_requirements.source_manifest_digest(observed)
            ),
        }
        observed_evidence = _source_evidence_summary(observed)
    except polish_requirements.MechanismBindingUnavailable:
        return {
            "status": "UNKNOWN",
            "matches_selected_source": "UNKNOWN",
            "observed_source_coordinate": None,
            "observed_source_evidence": None,
            "claim_boundary": "The later source recapture was unavailable.",
        }
    except (OSError, ImportError, MemoryError, RecursionError, OverflowError):
        return {
            "status": "UNKNOWN",
            "matches_selected_source": "UNKNOWN",
            "observed_source_coordinate": None,
            "observed_source_evidence": None,
            "claim_boundary": "The later source recapture was unavailable.",
        }
    except (polish_requirements.RequirementRefusal, AttributeError, KeyError,
            RuntimeError, TypeError, ValueError, UnicodeError):
        return {
            "status": "FAIL",
            "matches_selected_source": False,
            "observed_source_coordinate": None,
            "observed_source_evidence": None,
            "claim_boundary": (
                "The selected source root did not satisfy the later "
                "whole-source recapture contract."
            ),
        }
    try:
        observed_coordinate_digest = core_obligation_union.value_digest(
            observed_coordinate
        )
    except (OSError, MemoryError, RecursionError, OverflowError):
        return {
            "status": "UNKNOWN",
            "matches_selected_source": "UNKNOWN",
            "observed_source_coordinate": None,
            "observed_source_evidence": None,
            "claim_boundary": "The later source recapture was unavailable.",
        }
    matches = observed_coordinate == selected_coordinate
    return {
        "status": "PASS" if matches else "FAIL",
        "matches_selected_source": matches,
        "observed_source_coordinate": observed_coordinate,
        "observed_source_evidence": observed_evidence,
        "observed_source_coordinate_digest": observed_coordinate_digest,
        "claim_boundary": (
            "PASS establishes exact equality between a later recapture by the "
            "same mechanism and the selected numeric report coordinate; it is "
            "not independent evidence."
        ),
    }


def _self_verifier_result(
        value: Mapping[str, Any] | None,
        source_coordinate: dict[str, str],
        blockers: list[str], *,
        source_root: str | Path | None) -> dict[str, Any]:
    if value is None:
        blockers.append("SELF_VERIFIER_TIER1_REPORT_UNAVAILABLE")
        return {
            "status": "NOT_ESTABLISHED",
            "retention_status": "NOT_SELECTED",
            "report_digest": None,
            "source_binding_status": "NOT_ESTABLISHED",
            "subject": None,
            "represented_tiers": [],
            "claim_boundary": _SELF_VERIFIER_BOUNDARY,
        }
    if type(value) is not dict:
        blockers.append("SELF_VERIFIER_TIER1_REPORT_INVALID")
        return {"status": "FAIL", "retention_status": "REJECTED",
                "report_digest": None,
                "source_binding_status": "FAIL", "subject": None,
                "represented_tiers": [], "claim_boundary": _SELF_VERIFIER_BOUNDARY}
    report = dict(value)
    report_digest = report.get("report_digest")

    def unavailable_retention(*, keep_digest: bool = True) -> dict[str, Any]:
        numeric_failed = report.get("status") == "FAIL"
        blockers.append("SELF_VERIFIER_TIER1_REPORT_UNAVAILABLE")
        if numeric_failed:
            blockers.append("NUMERIC_SELF_VERIFIER_TIER1_FAILED")
        return {
            "status": "FAIL" if numeric_failed else "UNKNOWN",
            "retention_status": "UNAVAILABLE",
            "report_digest": (
                report_digest if keep_digest and type(report_digest) is str
                and _SHA256.fullmatch(report_digest) is not None else None
            ),
            "source_binding_status": "NOT_ESTABLISHED",
            "subject": None,
            "represented_tiers": [],
            "claim_boundary": _SELF_VERIFIER_BOUNDARY,
        }

    try:
        coordinate_digest = core_obligation_union.value_digest(
            source_coordinate
        )
    except (OSError, MemoryError, RecursionError, OverflowError):
        return unavailable_retention(keep_digest=False)
    source_matches = (
        report.get("source_coordinate") == source_coordinate
        and report.get("source_coordinate_digest") == coordinate_digest
    )
    if not source_matches:
        blockers.append("SELF_VERIFIER_TIER1_SOURCE_DIFFERS")
        return {"status": "FAIL", "retention_status": "REJECTED",
                "report_digest": (
                    report_digest if type(report_digest) is str
                    and _SHA256.fullmatch(report_digest) is not None else None
                ),
                "source_binding_status": "FAIL", "subject": None,
                "represented_tiers": [], "claim_boundary": _SELF_VERIFIER_BOUNDARY}
    try:
        retained = self_polish_tiers._retained_tier1(
            core_obligation_union.canonical_bytes(report),
            report_digest,
            installed_denominators=self_polish_tiers._denominators(
                POLISH_VERIFIER_ID
            ),
            source_root=source_root,
        )
    except OSError:
        return unavailable_retention()
    except self_polish_tiers._ContractError as exc:
        unavailable = str(exc) in {
            "TIER1_CANDIDATE_ESTATE_SOURCE_UNAVAILABLE",
            "TIER1_SOURCE_RECAPTURE_UNAVAILABLE",
        }
        if unavailable:
            return unavailable_retention()
        blockers.append("SELF_VERIFIER_TIER1_REPORT_INVALID")
        return {
            "status": "FAIL",
            "retention_status": "REJECTED",
            "report_digest": (
                report_digest if type(report_digest) is str
                and _SHA256.fullmatch(report_digest) is not None else None
            ),
            "source_binding_status": "NOT_ESTABLISHED",
            "subject": None,
            "represented_tiers": [],
            "claim_boundary": _SELF_VERIFIER_BOUNDARY,
        }
    except (MemoryError, RecursionError, OverflowError):
        return unavailable_retention()
    except polish_requirements.MechanismBindingUnavailable:
        return unavailable_retention()
    except self_polish_estate.EstateError as exc:
        if str(exc) == "GIT_STATE_UNAVAILABLE":
            return unavailable_retention()
        blockers.append("SELF_VERIFIER_TIER1_REPORT_INVALID")
        return {
            "status": "FAIL",
            "retention_status": "REJECTED",
            "report_digest": (
                report_digest if type(report_digest) is str
                and _SHA256.fullmatch(report_digest) is not None else None
            ),
            "source_binding_status": "NOT_ESTABLISHED",
            "subject": None,
            "represented_tiers": [],
            "claim_boundary": _SELF_VERIFIER_BOUNDARY,
        }
    except (AttributeError, KeyError, RuntimeError, TypeError, ValueError,
            UnicodeError):
        blockers.append("SELF_VERIFIER_TIER1_REPORT_INVALID")
        return {"status": "FAIL",
                "retention_status": "REJECTED",
                "report_digest": (
                    report_digest if type(report_digest) is str
                    and _SHA256.fullmatch(report_digest) is not None else None
                ),
                "source_binding_status": "NOT_ESTABLISHED", "subject": None,
                "represented_tiers": [],
                "claim_boundary": _SELF_VERIFIER_BOUNDARY}
    if retained is None:
        blockers.append("SELF_VERIFIER_TIER1_REPORT_INVALID")
        return {"status": "FAIL", "retention_status": "REJECTED",
                "report_digest": report_digest,
                "source_binding_status": "NOT_ESTABLISHED", "subject": None,
                "represented_tiers": [],
                "claim_boundary": _SELF_VERIFIER_BOUNDARY}
    retained_status = retained["status"]
    representation = retained.get("complete_self_representation")
    subject = (
        representation.get("subject")
        if retained_status == "PASS" and type(representation) is dict
        else None
    )
    represented_tiers = (
        representation.get("represented_tiers", [])
        if retained_status == "PASS" and type(representation) is dict
        else []
    )
    if retained_status == "FAIL":
        blockers.append("SELF_VERIFIER_TIER1_FAILED")
    elif retained_status != "PASS":
        blockers.append("SELF_VERIFIER_TIER1_NOT_PASS")
    return {
        "status": retained_status,
        "retention_status": "RETAINED",
        "report_digest": report_digest,
        "source_binding_status": (
            retained["source_binding_status"]
            if retained_status == "PASS" else "NOT_ESTABLISHED"
        ),
        "subject": subject,
        "represented_tiers": represented_tiers,
        "claim_boundary": _SELF_VERIFIER_BOUNDARY,
    }


def assess_package_self_polish(
        source_coordinate: Mapping[str, Any], *,
        self_verifier_tier1_report: Mapping[str, Any] | None = None,
        source_root: str | Path | None = None,
        candidate_obligation_cards_root: str | Path | None = None,
        candidate_obligation_manifest_path: str | Path | None = None,
        expected_candidate_obligation_manifest_digest: str | None = None,
        candidate_obligation_reason_ledger_path: str | Path | None = None,
        expected_candidate_obligation_reason_ledger_digest: str | None = None,
        owner_decision_policy_path: str | Path | None = None,
        expected_owner_decision_policy_digest: str | None = None,
        owner_decision_path: str | Path | None = None,
        expected_owner_decision_digest: str | None = None,
        ) -> dict[str, Any]:
    """Assess the current executable project denominator without overclaiming."""
    coordinate = _source_coordinate(source_coordinate)
    source_digest = core_obligation_union.value_digest(coordinate)
    blockers = [
        "CORE_FAMILY_CELL_CLOSURE_NOT_ESTABLISHED",
        "CORRIGIBILITY_EXTENSION_NOT_ESTABLISHED",
    ]
    opening_source_recapture = _source_recapture_binding(source_root, coordinate)
    opening_source_evidence = opening_source_recapture.get(
        "observed_source_evidence"
    )
    source_recapture = {
        **opening_source_recapture,
        "opening_binding": dict(opening_source_recapture),
    }
    if source_recapture["status"] == "FAIL":
        blockers.append("PACKAGE_SOURCE_RECAPTURE_FAILED")
    elif source_recapture["status"] == "UNKNOWN":
        blockers.append("PACKAGE_SOURCE_RECAPTURE_UNAVAILABLE")
    tier_zero_admission = _tier_zero_repository_admission(
        source_root, coordinate, opening_source_evidence
    )
    if tier_zero_admission["status"] == "FAIL":
        blockers.append("TIER_ZERO_REPOSITORY_ADMISSION_FAILED")
    elif tier_zero_admission["status"] != "PASS":
        blockers.append("TIER_ZERO_REPOSITORY_ADMISSION_NOT_ESTABLISHED")
    self_verifier = _self_verifier_result(
        self_verifier_tier1_report,
        coordinate,
        blockers,
        source_root=source_root,
    )
    report_retained = self_verifier["retention_status"] == "RETAINED"
    try:
        inventory = core_tier_progression.installed_core_route_inventory()
    except (OSError, ImportError, MemoryError, RecursionError, OverflowError):
        return package_assessment_unavailable_report(
            numeric_tier1_report=(
                self_verifier_tier1_report
                if self_verifier_tier1_report is not None else {}
            ),
            source_coordinate=coordinate,
            prior_blockers=blockers,
            classified_self_verifier=self_verifier,
        )
    except RuntimeError:
        return package_assessment_contradiction_report(
            numeric_tier1_report=(
                self_verifier_tier1_report
                if self_verifier_tier1_report is not None else {}
            ),
            source_coordinate=coordinate,
            blocker="PACKAGE_CORE_ROUTE_INVENTORY_CONTRADICTION",
            prior_blockers=blockers,
            classified_self_verifier=self_verifier,
        )
    candidate_ledger = _candidate_obligation_ledger(
        inventory,
        source_root=source_root,
        cards_root=candidate_obligation_cards_root,
        manifest_path=candidate_obligation_manifest_path,
        expected_manifest_digest=expected_candidate_obligation_manifest_digest,
        reason_ledger_path=candidate_obligation_reason_ledger_path,
        expected_reason_ledger_digest=(
            expected_candidate_obligation_reason_ledger_digest
        ),
    )
    owner_decision_admission = _owner_decision_admission(
        candidate_ledger,
        source_coordinate_digest=source_digest,
        policy_path=owner_decision_policy_path,
        expected_policy_digest=expected_owner_decision_policy_digest,
        decision_path=owner_decision_path,
        expected_decision_digest=expected_owner_decision_digest,
    )
    if candidate_ledger["status"] == "FAIL":
        blockers.append("PACKAGE_OBLIGATION_CANDIDATE_SELECTION_FAILED")
    elif candidate_ledger["status"] == "UNKNOWN":
        blockers.append("PACKAGE_OBLIGATION_CANDIDATE_UNAVAILABLE")
    elif candidate_ledger["status"] == "NOT_SELECTED":
        blockers.append("PACKAGE_OBLIGATION_CANDIDATE_NOT_SELECTED")
    elif candidate_ledger["semantic_identity_status"] != "PASS":
        blockers.append(
            "PACKAGE_OBLIGATION_CANDIDATE_SEMANTIC_IDENTITY_NOT_ESTABLISHED"
        )
    if owner_decision_admission["status"] == "FAIL":
        blockers.append("PACKAGE_OWNER_DECISION_ADMISSION_FAILED")
    elif owner_decision_admission["status"] == "UNKNOWN":
        blockers.append("PACKAGE_OWNER_DECISION_ADMISSION_UNAVAILABLE")
    elif (owner_decision_admission["status"] == "NOT_SELECTED"
          and candidate_ledger["status"] == "PASS"):
        blockers.append("PACKAGE_OBLIGATION_CANDIDATE_NOT_OWNER_ADOPTED")

    def interrupted(*extra_blockers: str) -> dict[str, Any]:
        return package_assessment_unavailable_report(
            numeric_tier1_report=(
                self_verifier_tier1_report
                if self_verifier_tier1_report is not None else {}
            ),
            source_coordinate=coordinate,
            prior_blockers=tuple(blockers) + tuple(extra_blockers),
            classified_self_verifier=self_verifier,
        )

    try:
        package_gate_mechanism = mechanism_digest()
    except (OSError, MemoryError, RecursionError, OverflowError):
        return interrupted("PACKAGE_GATE_MECHANISM_RECAPTURE_UNAVAILABLE")
    full_native_candidate = None
    full_native_candidate_status = "NOT_SELECTED"
    if source_root is not None:
        try:
            full_native_candidate = (
                self_polish_native_full_candidate.replay_full_native_candidate(
                    source_root,
                    source_coordinate_digest=source_digest,
                )
            )
            full_native_candidate_status = full_native_candidate["status"]
        except self_polish_native_replay.NativeReplayResourceError as exc:
            full_native_candidate_status = (
                "FAIL" if exc.failure_observed else "UNKNOWN"
            )
        except self_polish_native_full_candidate.FullNativeCandidateError:
            full_native_candidate_status = "FAIL"
        except (OSError, ImportError, MemoryError, RecursionError,
                OverflowError):
            full_native_candidate_status = "UNKNOWN"
        except (AttributeError, KeyError, RuntimeError, TypeError, ValueError,
                UnicodeError):
            full_native_candidate_status = "FAIL"
    if full_native_candidate_status == "FAIL":
        blockers.append("PACKAGE_FULL_NATIVE_CANDIDATE_FAILED")
    elif full_native_candidate_status == "UNKNOWN":
        blockers.append("PACKAGE_FULL_NATIVE_CANDIDATE_NOT_PASS")
    elif full_native_candidate_status == "NOT_SELECTED":
        blockers.append("PACKAGE_FULL_NATIVE_CANDIDATE_NOT_SELECTED")
    try:
        objects = build_package_graph(
            coordinate,
            self_verifier_report_digest=(
                self_verifier["report_digest"] if report_retained else None
            ),
            self_verifier_report_status=(
                self_verifier["status"] if report_retained else None
            ),
            self_verifier_retention_status=self_verifier["retention_status"],
            self_verifier_mechanism_digest=(
                self_verifier_tier1_report.get("mechanism_digest")
                if report_retained
                and type(self_verifier_tier1_report) is dict else None
            ),
            source_evidence=(
                opening_source_evidence
                if opening_source_recapture["status"] == "PASS" else None
            ),
            candidate_selection_digest=core_obligation_union.value_digest(
                candidate_ledger
            ),
            candidate_selection_status=candidate_ledger["status"],
            owner_decision_admission_digest=owner_decision_admission[
                "admission_digest"
            ],
            owner_decision_admission_status=owner_decision_admission[
                "status"
            ],
            package_gate_mechanism_digest=package_gate_mechanism,
            tier_zero_report_digest=tier_zero_admission["report_digest"],
            tier_zero_report_status=tier_zero_admission["status"],
            tier_zero_profile_digest=tier_zero_admission["profile_digest"],
            full_native_candidate_digest=(
                full_native_candidate.get("candidate_digest")
                if type(full_native_candidate) is dict else None
            ),
            full_native_candidate_status=full_native_candidate_status,
        )
    except PackageAssessmentContradiction as exc:
        return package_assessment_contradiction_report(
            numeric_tier1_report=(
                self_verifier_tier1_report
                if self_verifier_tier1_report is not None else {}
            ),
            source_coordinate=coordinate,
            blocker=str(exc),
            prior_blockers=blockers,
            classified_self_verifier=self_verifier,
        )
    except (OSError, ImportError, MemoryError, RecursionError, OverflowError):
        return interrupted()
    try:
        graph_digest = composition_digest(objects)
        composition, graph_wire_digest, graph_round_trip_exact = (
            _round_trip_composition(objects, graph_digest)
        )
    except (OSError, ImportError, MemoryError, RecursionError, OverflowError):
        return interrupted()
    graph_status = composition.verdict.value
    if graph_status != "PASS":
        blockers.append("PACKAGE_GRAPH_COMPOSITION_NOT_PASS")
        if graph_status == "FAIL":
            blockers.append("PACKAGE_GRAPH_COMPOSITION_FAILED")
        blockers.append("TIER_ZERO_REPRESENTATION_NOT_PASS")
    try:
        native_replay = _native_facets_replay(objects, source_digest)
    except PackageAssessmentUnavailable as exc:
        return interrupted(*exc.blockers)
    except (OSError, ImportError, MemoryError, RecursionError, OverflowError):
        return interrupted()
    if native_replay["status"] == "FAIL":
        blockers.append("PACKAGE_NATIVE_FACETS_REPLAY_FAILED")
    elif native_replay["status"] != "PASS":
        blockers.append("PACKAGE_NATIVE_FACETS_REPLAY_NOT_PASS")
    try:
        installed_case_replay = _installed_native_case_replay(
            source_root, source_digest
        )
    except self_polish_native_replay.NativeReplayResourceError as exc:
        return interrupted(*(
            ("PACKAGE_INSTALLED_NATIVE_CASE_REPLAY_FAILED",)
            if exc.failure_observed else ()
        ))
    except (OSError, ImportError, MemoryError, RecursionError, OverflowError):
        return interrupted()
    if installed_case_replay["status"] == "FAIL":
        blockers.append("PACKAGE_INSTALLED_NATIVE_CASE_REPLAY_FAILED")
    elif installed_case_replay["status"] != "PASS":
        blockers.append("PACKAGE_INSTALLED_NATIVE_CASE_REPLAY_NOT_PASS")
    if full_native_candidate_status == "FAIL":
        blockers.append("PACKAGE_FULL_NATIVE_CANDIDATE_FAILED")
    elif full_native_candidate_status == "UNKNOWN":
        blockers.append("PACKAGE_FULL_NATIVE_CANDIDATE_NOT_PASS")
    elif full_native_candidate_status == "NOT_SELECTED":
        blockers.append("PACKAGE_FULL_NATIVE_CANDIDATE_NOT_SELECTED")
    try:
        tier_zero = _tier_zero_cells(
            objects, graph_status, native_replay, tier_zero_admission,
            candidate_ledger,
            owner_decision_admission,
        )
        core_projection = _core_route_memberships(
            inventory, native_replay, installed_case_replay, candidate_ledger,
            owner_decision_admission,
        )
        core_memberships = core_projection["memberships"]
    except (OSError, MemoryError, RecursionError, OverflowError):
        return interrupted()
    if core_projection["status"] == "FAIL":
        blockers.append("CORE_ROUTE_NATIVE_PROJECTION_FAILED")
    elif core_projection["status"] == "UNKNOWN":
        blockers.append("CORE_ROUTE_NATIVE_PROJECTION_NOT_ESTABLISHED")
    try:
        core_cells = _core_cells(inventory, core_memberships)
    except (OSError, MemoryError, RecursionError, OverflowError):
        return interrupted()
    try:
        corrigibility_research = _corrigibility_research_evidence()
        corrigibility = _corrigibility_cells(
            candidate_ledger, corrigibility_research,
            owner_decision_admission,
        )
        corrigibility_selection = _corrigibility_extension_selection(
            corrigibility, corrigibility_research
        )
    except (OSError, MemoryError, RecursionError, OverflowError):
        return interrupted()
    mechanism_recapture_failed = False
    try:
        closing_package_gate_mechanism = mechanism_digest()
    except (OSError, MemoryError, RecursionError, OverflowError):
        closing_package_gate_mechanism = None
        blockers.append("PACKAGE_GATE_MECHANISM_RECAPTURE_UNAVAILABLE")
    if closing_package_gate_mechanism is not None \
            and closing_package_gate_mechanism != package_gate_mechanism:
        mechanism_recapture_failed = True
        blockers.append("PACKAGE_GATE_MECHANISM_RECAPTURE_FAILED")
    if source_root is not None:
        closing_source_recapture = _source_recapture_binding(
            source_root, coordinate
        )
        severity = {"PASS": 0, "UNKNOWN": 1, "NOT_ESTABLISHED": 1,
                    "FAIL": 2}
        if severity.get(closing_source_recapture["status"], 2) \
                > severity.get(source_recapture["status"], 2):
            source_recapture = {
                **closing_source_recapture,
                "opening_binding": dict(opening_source_recapture),
            }
        if closing_source_recapture["status"] == "FAIL":
            blockers.append("PACKAGE_SOURCE_RECAPTURE_FAILED")
        elif closing_source_recapture["status"] == "UNKNOWN":
            blockers.append("PACKAGE_SOURCE_RECAPTURE_UNAVAILABLE")
    if native_replay["status"] == "FAIL":
        blockers.append("PACKAGE_NATIVE_FACETS_REPLAY_FAILED")
    elif native_replay["status"] != "PASS":
        blockers.append("PACKAGE_NATIVE_FACETS_REPLAY_NOT_PASS")
    if installed_case_replay["status"] == "FAIL":
        blockers.append("PACKAGE_INSTALLED_NATIVE_CASE_REPLAY_FAILED")
    elif installed_case_replay["status"] != "PASS":
        blockers.append("PACKAGE_INSTALLED_NATIVE_CASE_REPLAY_NOT_PASS")
    if core_projection["status"] == "FAIL":
        blockers.append("CORE_ROUTE_NATIVE_PROJECTION_FAILED")
    elif core_projection["status"] == "UNKNOWN":
        blockers.append("CORE_ROUTE_NATIVE_PROJECTION_NOT_ESTABLISHED")
    if candidate_ledger["status"] == "FAIL":
        blockers.append("PACKAGE_OBLIGATION_CANDIDATE_SELECTION_FAILED")
    elif candidate_ledger["status"] == "UNKNOWN":
        blockers.append("PACKAGE_OBLIGATION_CANDIDATE_UNAVAILABLE")
    elif candidate_ledger["status"] == "NOT_SELECTED":
        blockers.append("PACKAGE_OBLIGATION_CANDIDATE_NOT_SELECTED")
    elif candidate_ledger["semantic_identity_status"] != "PASS":
        blockers.append(
            "PACKAGE_OBLIGATION_CANDIDATE_SEMANTIC_IDENTITY_NOT_ESTABLISHED"
        )
    if owner_decision_admission["status"] == "FAIL":
        blockers.append("PACKAGE_OWNER_DECISION_ADMISSION_FAILED")
    elif owner_decision_admission["status"] == "UNKNOWN":
        blockers.append("PACKAGE_OWNER_DECISION_ADMISSION_UNAVAILABLE")
    elif (owner_decision_admission["status"] == "NOT_SELECTED"
          and candidate_ledger["status"] == "PASS"):
        blockers.append("PACKAGE_OBLIGATION_CANDIDATE_NOT_OWNER_ADOPTED")
    if graph_status != "PASS":
        blockers.append("PACKAGE_GRAPH_COMPOSITION_NOT_PASS")
        if graph_status == "FAIL":
            blockers.append("PACKAGE_GRAPH_COMPOSITION_FAILED")
        blockers.append("TIER_ZERO_REPRESENTATION_NOT_PASS")
    if any(row["status"] != "PASS" for row in tier_zero):
        blockers.append("TIER_ZERO_OBJECT_ADMISSION_NOT_ESTABLISHED")
    status = "FAIL" if (graph_status == "FAIL"
        or self_verifier["status"] == "FAIL"
        or native_replay["status"] == "FAIL"
        or installed_case_replay["status"] == "FAIL"
        or full_native_candidate_status == "FAIL"
        or core_projection["status"] == "FAIL"
        or candidate_ledger["status"] == "FAIL"
        or owner_decision_admission["status"] == "FAIL"
        or source_recapture["status"] == "FAIL"
        or tier_zero_admission["status"] == "FAIL"
        or mechanism_recapture_failed) \
        else "UNKNOWN"
    try:
        records = [item.to_dict() for item in objects]
        installed_inventory_digest = core_obligation_union.value_digest(
            inventory
        )
    except (OSError, MemoryError, RecursionError, OverflowError):
        return interrupted()
    report = {
        "schema_version": REPORT_SCHEMA,
        "status": status,
        "project_gate_status": status,
        "polished": False,
        "release_authorized": False,
        "source_coordinate": coordinate,
        "source_coordinate_digest": source_digest,
        "source_recapture_binding": source_recapture,
        "package_graph": {
            "status": graph_status,
            "collection_digest": composition.collection_digest,
            "canonical_wire_digest": graph_wire_digest,
            "canonical_round_trip_status": (
                "PASS" if graph_round_trip_exact else
                "UNKNOWN" if graph_status == "UNKNOWN" else "FAIL"
            ),
            "object_count": composition.objects_checked,
            "object_kind_count": len({item.kind for item in objects}),
            "represented_object_kinds": sorted(item.kind.value for item in objects),
            "root_id": PACKAGE_GRAPH_ID,
            "root_kind": "GRAPH",
            "polish_object_id": POLISH_VERIFIER_ID,
            "polish_object_kind": "VERIFIER",
            "object_records": records,
            "reason": composition.reason,
            "claim_boundary": (
                "PASS establishes the exact finite typed composition only; it does "
                "not establish any represented record's semantic truth."
            ),
        },
        "denominators": {
            "object_kind_count": len(ObjectKind),
            "tier_zero_representation_cell_count": len(tier_zero),
            "core_tier_count": len(core_tier_progression.CoreTier),
            "core_family_cell_count": len(core_cells),
            "registered_core_route_membership_count": inventory[
                "registered_route_membership_count"
            ],
            "corrigibility_extension_cell_count": len(corrigibility),
            "core_and_tier_zero_cell_count": len(tier_zero) + len(core_cells),
            "tracked_assessment_cell_count": (
                len(tier_zero) + len(core_cells) + len(corrigibility)
            ),
        },
        "tier_zero_repository_admission": tier_zero_admission,
        "tier_zero_representation_cells": tier_zero,
        "native_facets_replay": native_replay,
        "installed_native_case_replay": installed_case_replay,
        "full_native_candidate": full_native_candidate,
        "core_installed_inventory_digest": installed_inventory_digest,
        "candidate_obligation_ledger": candidate_ledger,
        "owner_decision_admission": owner_decision_admission,
        "core_route_projection": {
            key: value for key, value in core_projection.items()
            if key != "memberships"
        },
        "core_route_memberships": core_memberships,
        "core_family_cells": core_cells,
        "corrigibility_extension_selection": corrigibility_selection,
        "corrigibility_research_evidence": corrigibility_research,
        "corrigibility_extension_cells": corrigibility,
        "self_verifier_tier1": self_verifier,
        "blockers": sorted(set(blockers)),
        "mechanism_digest": package_gate_mechanism,
        "claim_boundary": _BOUNDARY,
    }
    try:
        report["report_digest"] = core_obligation_union.value_digest(report)
    except (OSError, MemoryError, RecursionError, OverflowError):
        return interrupted()
    return report


def _available_mechanism_digest() -> str | None:
    """Return no digest when package mechanism bytes cannot be read."""
    try:
        return mechanism_digest()
    except (OSError, MemoryError, RecursionError, OverflowError):
        return None


def _fallback_blocker_implies_failure(value: str) -> bool:
    """Classify package blockers without promoting namespaced numeric context."""
    if value.startswith("NUMERIC_TIER1_BLOCKER:"):
        return False
    return (
        value.endswith("_FAILED")
        or value.endswith("_INVALID")
        or value.endswith("_DIFFERS")
        or "CONTRADICTION" in value
    )


def unavailable_package_report(
        *, numeric_tier1_report: Mapping[str, Any],
        prior_blockers: Iterable[str] = (),
        ) -> dict[str, Any]:
    """Return a bounded project result when no exact source coordinate exists."""
    numeric_digest = None
    if type(numeric_tier1_report) is dict:
        candidate = numeric_tier1_report.get("report_digest")
        if type(candidate) is str and _SHA256.fullmatch(candidate) is not None:
            numeric_digest = candidate
    numeric_status = (
        numeric_tier1_report.get("status")
        if type(numeric_tier1_report) is dict else None
    )
    failed = numeric_status == "FAIL"
    blockers = ["PACKAGE_SOURCE_COORDINATE_UNAVAILABLE"]
    if failed:
        blockers.append("NUMERIC_SELF_VERIFIER_TIER1_FAILED")
    blockers.extend(
        value for value in prior_blockers if type(value) is str
    )
    blockers = sorted(set(blockers))
    report = {
        "schema_version": REPORT_SCHEMA,
        "status": "FAIL" if failed else "UNKNOWN",
        "project_gate_status": "FAIL" if failed else "UNKNOWN",
        "polished": False,
        "release_authorized": False,
        "source_coordinate": None,
        "source_coordinate_digest": None,
        "source_recapture_binding": None,
        "package_graph": None,
        "denominators": None,
        "tier_zero_repository_admission": None,
        "tier_zero_representation_cells": None,
        "native_facets_replay": None,
        "installed_native_case_replay": None,
        "full_native_candidate": None,
        "core_installed_inventory_digest": None,
        "candidate_obligation_ledger": None,
        "owner_decision_admission": None,
        "core_route_projection": None,
        "core_route_memberships": None,
        "core_family_cells": None,
        "corrigibility_extension_selection": None,
        "corrigibility_research_evidence": None,
        "corrigibility_extension_cells": None,
        "self_verifier_tier1": {
            "status": (
                "FAIL" if failed else
                "UNKNOWN" if numeric_status in ("PASS", "UNKNOWN") else
                "NOT_ESTABLISHED"
            ),
            "retention_status": (
                "UNAVAILABLE"
                if numeric_status in ("PASS", "FAIL", "UNKNOWN")
                else "NOT_SELECTED"
            ),
            "report_digest": numeric_digest,
            "source_binding_status": "NOT_ESTABLISHED",
            "subject": None,
            "represented_tiers": [],
            "claim_boundary": _SELF_VERIFIER_BOUNDARY,
        },
        "blockers": blockers,
        "mechanism_digest": _available_mechanism_digest(),
        "claim_boundary": _BOUNDARY,
    }
    report["report_digest"] = core_obligation_union.value_digest(report)
    return report


def package_assessment_unavailable_report(
        *, numeric_tier1_report: Mapping[str, Any],
        source_coordinate: Mapping[str, Any] | None = None,
        prior_blockers: Iterable[str] = (),
        classified_self_verifier: Mapping[str, Any] | None = None,
        ) -> dict[str, Any]:
    """Preserve the numeric verdict when package assessment cannot run."""
    report = unavailable_package_report(
        numeric_tier1_report=numeric_tier1_report
    )
    coordinate = None
    if source_coordinate is not None:
        candidate = source_coordinate
    elif type(numeric_tier1_report) is dict:
        candidate = numeric_tier1_report.get("source_coordinate")
    else:
        candidate = None
    if candidate is not None:
        try:
            coordinate = _source_coordinate(candidate)
        except (TypeError, ValueError):
            coordinate = None
    classified = (
        dict(classified_self_verifier)
        if type(classified_self_verifier) is dict else None
    )
    if (classified is not None
            and classified.get("retention_status") == "RETAINED"
            and classified.get("status") == "PASS"):
        classified.update(
            status="UNKNOWN",
            source_binding_status="NOT_ESTABLISHED",
            subject=None,
            represented_tiers=[],
        )
    numeric_status = (
        classified.get("status") if classified is not None else
        numeric_tier1_report.get("status")
        if type(numeric_tier1_report) is dict else None
    )
    retention_status = (
        classified.get("retention_status")
        if classified is not None else
        "UNAVAILABLE" if numeric_status in ("PASS", "FAIL", "UNKNOWN")
        else "NOT_SELECTED"
    )
    report["source_coordinate"] = coordinate
    report["source_coordinate_digest"] = (
        core_obligation_union.value_digest(coordinate)
        if coordinate is not None else None
    )
    if classified is not None:
        report["self_verifier_tier1"] = classified
    else:
        report["self_verifier_tier1"]["status"] = (
            "FAIL" if numeric_status == "FAIL" else
            "UNKNOWN" if numeric_status in ("PASS", "UNKNOWN")
            else "NOT_ESTABLISHED"
        )
        report["self_verifier_tier1"]["retention_status"] = retention_status
    retained_blockers = [
        value for value in prior_blockers if type(value) is str
    ]
    report["blockers"] = ["PACKAGE_SELF_POLISH_ASSESSMENT_UNAVAILABLE"]
    numeric_failed = (
        numeric_status == "FAIL"
        and retention_status in ("RETAINED", "UNAVAILABLE")
    )
    if numeric_failed:
        report["blockers"].append("NUMERIC_SELF_VERIFIER_TIER1_FAILED")
    report["blockers"] = sorted(set(report["blockers"] + retained_blockers))
    preserved_failure = numeric_failed or any(
        _fallback_blocker_implies_failure(value)
        for value in retained_blockers
    )
    if preserved_failure:
        report["status"] = report["project_gate_status"] = "FAIL"
    report.pop("report_digest", None)
    report["report_digest"] = core_obligation_union.value_digest(report)
    return report


def package_assessment_contradiction_report(
        *, numeric_tier1_report: Mapping[str, Any],
        source_coordinate: Mapping[str, Any], blocker: str,
        prior_blockers: Iterable[str] = (),
        classified_self_verifier: Mapping[str, Any] | None = None,
        ) -> dict[str, Any]:
    """Return a bounded FAIL for an observed package invariant violation."""
    try:
        coordinate = _source_coordinate(source_coordinate)
    except (TypeError, ValueError):
        coordinate = None
    report = package_assessment_unavailable_report(
        numeric_tier1_report=numeric_tier1_report,
        source_coordinate=source_coordinate,
        prior_blockers=(blocker,),
        classified_self_verifier=classified_self_verifier,
    )
    report["status"] = report["project_gate_status"] = "FAIL"
    report["source_coordinate"] = coordinate
    report["source_coordinate_digest"] = (
        core_obligation_union.value_digest(coordinate)
        if coordinate is not None else None
    )
    report["blockers"] = [
        value for value in prior_blockers if type(value) is str
    ] + [blocker]
    selected_self_verifier = report["self_verifier_tier1"]
    if (selected_self_verifier.get("status") == "FAIL"
            and selected_self_verifier.get("retention_status")
                in ("RETAINED", "UNAVAILABLE")):
        report["blockers"].append("NUMERIC_SELF_VERIFIER_TIER1_FAILED")
    report["blockers"] = sorted(set(report["blockers"]))
    report.pop("report_digest", None)
    report["report_digest"] = core_obligation_union.value_digest(report)
    return report


def package_report_capacity_exhausted_report(
        attempted_report: Mapping[str, Any]) -> dict[str, Any]:
    """Return a bounded fail-closed result when the full wire report is too large."""
    report = unavailable_package_report(
        numeric_tier1_report=attempted_report
    )
    coordinate = attempted_report.get("source_coordinate")
    try:
        coordinate = _source_coordinate(coordinate)
    except (TypeError, ValueError):
        coordinate = None
    failed = attempted_report.get("status") == "FAIL"
    report["status"] = report["project_gate_status"] = (
        "FAIL" if failed else "UNKNOWN"
    )
    report["source_coordinate"] = coordinate
    report["source_coordinate_digest"] = (
        core_obligation_union.value_digest(coordinate)
        if coordinate is not None else None
    )
    retained = attempted_report.get("self_verifier_tier1")
    retained_status = (
        retained.get("status") if type(retained) is dict else None
    )
    retained_digest = (
        retained.get("report_digest") if type(retained) is dict else None
    )
    retained_lifecycle = (
        retained.get("retention_status") if type(retained) is dict else None
    )
    prior_blockers = attempted_report.get("blockers")
    selected_blockers = (
        [value for value in prior_blockers if type(value) is str]
        if type(prior_blockers) is list else []
    )
    numeric_failed = (
        "NUMERIC_SELF_VERIFIER_TIER1_FAILED" in selected_blockers
        or (
            retained_lifecycle == "RETAINED"
            and retained_status == "FAIL"
            and "SELF_VERIFIER_TIER1_FAILED" in selected_blockers
        )
    )
    retention_rejected = retained_lifecycle == "REJECTED"
    fallback_lifecycle = (
        retained_lifecycle
        if retained_lifecycle in (
            "RETAINED", "UNAVAILABLE", "NOT_SELECTED", "REJECTED"
        ) else "UNAVAILABLE"
    )
    report["self_verifier_tier1"] = {
        "status": (
            "FAIL" if numeric_failed or retention_rejected
            else "UNKNOWN" if fallback_lifecycle in ("RETAINED", "UNAVAILABLE")
            and retained_status in ("PASS", "UNKNOWN")
            else "NOT_ESTABLISHED"
        ),
        "retention_status": fallback_lifecycle,
        "report_digest": (
            retained_digest if type(retained_digest) is str
            and _SHA256.fullmatch(retained_digest) is not None else None
        ),
        "source_binding_status": (
            "FAIL" if retention_rejected
            and retained.get("source_binding_status") == "FAIL"
            else "NOT_ESTABLISHED"
        ),
        "subject": None,
        "represented_tiers": [],
        "claim_boundary": _SELF_VERIFIER_BOUNDARY,
    }
    report["blockers"] = sorted(set(
        ["PACKAGE_REPORT_TRANSPORT_CAPACITY_EXHAUSTED"]
        + selected_blockers
    ))
    if numeric_failed:
        report["blockers"] = sorted(set(
            report["blockers"] + ["NUMERIC_SELF_VERIFIER_TIER1_FAILED"]
        ))
    report.pop("report_digest", None)
    report["report_digest"] = core_obligation_union.value_digest(report)
    return report


__all__ = [
    "MAX_PACKAGE_REPORT_BYTES", "REPORT_SCHEMA", "build_package_graph",
    "assess_package_self_polish", "unavailable_package_report",
    "package_assessment_unavailable_report",
    "package_assessment_contradiction_report",
    "package_report_capacity_exhausted_report", "mechanism_digest",
]
