"""Adversarial tests for bounded untraversability over a composed Verifier Standard (VSTD) graph.

Terminology: JavaScript Object Notation (JSON);
Secure Hash Algorithm 256-bit (SHA-256).
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from typing import Any

import pytest

from verifier.core.evidence import (
    BoundProposition,
    EvidenceBounds,
    EvidenceStore,
    MechanismDecision,
    MechanismOutcome,
    VerificationSession,
)
from verifier.data.models import ArtifactNode, ArtifactType, ProvenanceHypergraph
from verifier.interoperability.graph_topology import graph_topology_binding_digest
from verifier.interoperability.untraversable import (
    DisclosureChannel,
    TraversalMode,
    UntraversabilityStatus,
    UntraversableContract,
    UntraversableError,
    analyze_untraversability,
)


def _digest(label: str) -> str:
    return "sha256:" + hashlib.sha256(label.encode("utf-8")).hexdigest()


def _canonical_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


class ExactBooleanMechanism:
    """Test mechanism whose evidence supports one exact Boolean proposition."""

    mechanism_id = "test.exact-boolean"
    mechanism_digest = _digest("tests.ExactBooleanMechanism:v1")

    def evaluate(self, binding, evidence):
        if len(evidence) != 1:
            return MechanismDecision(MechanismOutcome.UNKNOWN, "one item required")
        try:
            observed = json.loads(evidence[0])
        except (UnicodeDecodeError, json.JSONDecodeError):
            return MechanismDecision(MechanismOutcome.UNKNOWN, "invalid JSON evidence")
        expected = {
            "subject_id": binding.subject_id,
            "predicate": binding.predicate,
            "expected": binding.expected,
            "parameters": dict(binding.parameters),
        }
        outcome = MechanismOutcome.PASS if observed == expected else MechanismOutcome.FAIL
        return MechanismDecision(outcome, f"exact Boolean comparison: {outcome.value}")


def _session() -> tuple[EvidenceStore, VerificationSession]:
    store = EvidenceStore()
    session = VerificationSession(store)
    session.register(ExactBooleanMechanism())
    return store, session


def _proposition(
    store: EvidenceStore,
    subject_id: str,
    predicate: str,
    expected: Any = True,
    *,
    supported: bool = True,
) -> BoundProposition:
    if supported:
        observed = expected
    elif type(expected) is bool:
        observed = not expected
    else:
        observed = {"unsupported": True}
    evidence_ref = store.add(
        json.dumps(
            {
                "subject_id": subject_id,
                "predicate": predicate,
                "expected": observed,
                "parameters": {},
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    return BoundProposition(
        subject_id=subject_id,
        predicate=predicate,
        expected=expected,
        mechanism_id=ExactBooleanMechanism.mechanism_id,
        mechanism_digest=ExactBooleanMechanism.mechanism_digest,
        evidence_refs=(evidence_ref,),
        trust_roots=("test:untraversability-policy",),
        bounds=EvidenceBounds(max_evidence_items=1, max_evidence_bytes=2_000),
    )


def _graph(*artifact_ids: str) -> ProvenanceHypergraph:
    graph = ProvenanceHypergraph()
    for artifact_id in artifact_ids or ("artifact:source",):
        graph.add_artifact(
            ArtifactNode(
                artifact_id=artifact_id,
                label=artifact_id,
                artifact_type=ArtifactType.CONFIG,
                content_digest=hashlib.sha256(artifact_id.encode("utf-8")).hexdigest(),
            )
        )
    return graph


def _fact(
    fact_id: str,
    source_artifact_id: str,
    channel: str = DisclosureChannel.CONTENT.value,
) -> dict[str, Any]:
    return {
        "fact_id": fact_id,
        "commitment_digest": _digest("commitment:" + fact_id),
        "source_artifact_ids": [source_artifact_id],
        "channel": channel,
    }


def _mutate_fact(payload: dict[str, Any], fact_id: str, field: str) -> None:
    fact = next(item for item in payload["facts"] if item["fact_id"] == fact_id)
    if field == "commitment_digest":
        fact[field] = _digest("substituted-commitment:" + fact_id)
    elif field == "channel":
        fact[field] = DisclosureChannel.METADATA.value
    elif field == "source_artifact_ids":
        current = fact[field][0]
        fact[field] = [
            "artifact:right" if current != "artifact:right" else "artifact:left"
        ]
    else:  # pragma: no cover - helper is closed over the parametrization below.
        raise AssertionError(f"unsupported fact mutation: {field}")


def _contract_payload(
    graph: ProvenanceHypergraph,
    store: EvidenceStore,
    *,
    accessible_interfaces: tuple[str, ...] = ("interface:left", "interface:right"),
    initial_facts: tuple[str, ...] = (),
    capabilities: tuple[str, ...] = (),
    mode: TraversalMode = TraversalMode.POTENTIAL_INFERENCE,
    facts: list[dict[str, Any]] | None = None,
    interfaces: list[dict[str, Any]] | None = None,
    hyperedges: list[dict[str, Any]] | None = None,
    completeness_supported: bool = True,
    semantics_id: str = "finite-monotone-knowledge-hypergraph-v1",
    observation_interval: dict[str, Any] | None = None,
    query_count: int = 0,
    limits: dict[str, int] | None = None,
) -> dict[str, Any]:
    bound_graph_digest = graph_topology_binding_digest(graph)
    interval = observation_interval or {
        "clock_id": "clock:fixture",
        "start": 0,
        "end": 10,
        "unit": "tick",
    }
    facts = facts or [
        _fact("fact:left", "artifact:left"),
        _fact("fact:right", "artifact:right"),
        _fact("fact:protected", "artifact:protected"),
    ]
    canonical_facts = sorted(
        (
            {
                **item,
                "source_artifact_ids": sorted(item["source_artifact_ids"]),
            }
            for item in facts
        ),
        key=lambda item: item["fact_id"],
    )
    facts_by_id = {item["fact_id"]: item for item in canonical_facts}
    interfaces = interfaces or [
        {
            "interface_id": "interface:left",
            "abstraction_mechanism_id": "abstraction:left",
            "source_artifact_ids": ["artifact:left"],
            "exposed_fact_ids": ["fact:left"],
            "control_signal_fact_ids": ["fact:left"],
            "required_capability_ids": [],
        },
        {
            "interface_id": "interface:right",
            "abstraction_mechanism_id": "abstraction:right",
            "source_artifact_ids": ["artifact:right"],
            "exposed_fact_ids": ["fact:right"],
            "control_signal_fact_ids": ["fact:right"],
            "required_capability_ids": [],
        },
    ]
    hyperedges = hyperedges or [
        {
            "hyperedge_id": "hyperedge:combine",
            "required_fact_ids": ["fact:left", "fact:right"],
            "produced_fact_ids": ["fact:protected"],
            "relation_id": "relation:conjunctive-combination",
            "transformation_id": None,
            "required_capability_ids": [],
        }
    ]
    interface_skeletons = []
    for source in interfaces:
        row = {
            "interface_id": source["interface_id"],
            "mode": mode.value,
            "abstraction_mechanism_id": source["abstraction_mechanism_id"],
            "source_artifact_ids": sorted(source["source_artifact_ids"]),
            "exposed_fact_ids": sorted(source["exposed_fact_ids"]),
            "control_signal_fact_ids": sorted(source["control_signal_fact_ids"]),
            "required_capability_ids": sorted(source["required_capability_ids"]),
        }
        interface_skeletons.append(row)
    interface_skeletons.sort(key=lambda item: item["interface_id"])
    interfaces = [
        {
            **skeleton,
            "coverage_proposition": _proposition(
                store,
                skeleton["interface_id"],
                "interface_disclosure_channels_complete",
                {
                    "covered_channels": [item.value for item in DisclosureChannel],
                    "exposed_facts": [
                        facts_by_id[item]
                        for item in skeleton["exposed_fact_ids"]
                    ],
                    "graph_digest": bound_graph_digest,
                    "interface": skeleton,
                },
            ).to_dict(),
        }
        for skeleton in interface_skeletons
    ]
    hyperedge_skeletons = []
    for source in hyperedges:
        row = {
            "hyperedge_id": source["hyperedge_id"],
            "mode": mode.value,
            "required_fact_ids": sorted(source["required_fact_ids"]),
            "produced_fact_ids": sorted(source["produced_fact_ids"]),
            "relation_id": source["relation_id"],
            "transformation_id": source["transformation_id"],
            "required_capability_ids": sorted(source["required_capability_ids"]),
        }
        hyperedge_skeletons.append(row)
    hyperedge_skeletons.sort(key=lambda item: item["hyperedge_id"])
    hyperedges = [
        {
            **skeleton,
            "activation_propositions": [
                _proposition(
                    store,
                    skeleton["hyperedge_id"],
                    "knowledge_hyperedge_active",
                    {
                        "active": True,
                        "graph_digest": bound_graph_digest,
                        "hyperedge": skeleton,
                        "produced_facts": [
                            facts_by_id[item]
                            for item in skeleton["produced_fact_ids"]
                        ],
                        "required_facts": [
                            facts_by_id[item]
                            for item in skeleton["required_fact_ids"]
                        ],
                    },
                ).to_dict()
            ],
        }
        for skeleton in hyperedge_skeletons
    ]
    completeness_expected = {
        "complete": True,
        "model": {
            "graph_digest": bound_graph_digest,
            "mode": mode.value,
            "protected_fact_ids": ["fact:protected"],
            "facts": canonical_facts,
            "interfaces": interface_skeletons,
            "knowledge_hyperedges": hyperedge_skeletons,
        },
    }
    return {
        "schema_version": "VSTD-UNTRAVERSABLE-EXPERIMENTAL-0.1",
        "contract_id": "untraversable:fixture",
        "graph_digest": bound_graph_digest,
        "semantics_id": semantics_id,
        "mode": mode.value,
        "observation_interval": interval,
        "observer": {
            "observer_id": "observer:bounded-controller",
            "accessible_interface_ids": list(accessible_interfaces),
            "initial_fact_ids": list(initial_facts),
            "capability_ids": list(capabilities),
            "query_transcript_digest": _digest("query-transcript:empty"),
            "query_count": query_count,
            "state_proposition": _proposition(
                store,
                "observer:bounded-controller",
                "observer_knowledge_coordinate",
                {
                    "accessible_interface_ids": sorted(accessible_interfaces),
                    "capability_ids": sorted(capabilities),
                    "graph_digest": bound_graph_digest,
                    "initial_fact_ids": sorted(initial_facts),
                    "initial_facts": [
                        facts_by_id[item] for item in sorted(initial_facts)
                    ],
                    "mode": mode.value,
                    "observation_interval": interval,
                    "query_transcript_digest": _digest("query-transcript:empty"),
                    "query_count": query_count,
                },
            ).to_dict(),
        },
        "protected_fact_ids": ["fact:protected"],
        "facts": facts,
        "interfaces": interfaces,
        "knowledge_hyperedges": hyperedges,
        "rule_set_completeness": _proposition(
            store,
            "untraversable:fixture",
            "knowledge_rule_set_complete",
            completeness_expected,
            supported=completeness_supported,
        ).to_dict(),
        "resource_limits": limits
        or {
            "max_fact_count": 64,
            "max_hyperedge_count": 64,
            "max_rule_firings": 64,
            "max_hyperpath_depth": 16,
            "max_query_count": 64,
            "max_evidence_items": 64,
            "max_evidence_bytes": 64_000,
        },
    }


def _fixture() -> tuple[ProvenanceHypergraph, EvidenceStore, VerificationSession]:
    graph = _graph("artifact:left", "artifact:right", "artifact:protected")
    store, session = _session()
    return graph, store, session


def test_conjunctive_hyperedge_requires_every_input_and_composition_reveals_leakage() -> None:
    graph, store, session = _fixture()

    left_only = UntraversableContract.from_dict(
        _contract_payload(graph, store, accessible_interfaces=("interface:left",))
    )
    right_only = UntraversableContract.from_dict(
        _contract_payload(graph, store, accessible_interfaces=("interface:right",))
    )
    composed = UntraversableContract.from_dict(_contract_payload(graph, store))

    assert analyze_untraversability(graph, left_only, session).status is UntraversabilityStatus.MATCH
    assert analyze_untraversability(graph, right_only, session).status is UntraversabilityStatus.MATCH

    report = analyze_untraversability(graph, composed, session)
    assert report.status is UntraversabilityStatus.FAIL
    assert "fact:protected" in report.reached_fact_ids
    witness = report.witnesses[0]
    assert witness["protected_fact_id"] == "fact:protected"
    assert witness["initial_fact_ids"] == ["fact:left", "fact:right"]
    assert len(witness["steps"]) == 1
    assert witness["steps"][0]["hyperedge_id"] == "hyperedge:combine"
    assert witness["steps"][0]["consumed_fact_ids"] == ["fact:left", "fact:right"]
    assert witness["steps"][0]["produced_fact_ids"] == ["fact:protected"]
    body = {key: value for key, value in witness.items() if key != "witness_digest"}
    assert witness["witness_digest"] == _canonical_digest(body)


def test_witness_seed_origins_bind_fact_and_support_evaluation_provenance() -> None:
    graph, store, session = _fixture()
    contract = UntraversableContract.from_dict(
        _contract_payload(
            graph,
            store,
            accessible_interfaces=("interface:right",),
            initial_facts=("fact:left",),
        )
    )

    report = analyze_untraversability(graph, contract, session)

    assert report.status is UntraversabilityStatus.FAIL
    origins = {
        item["fact_id"]: item for item in report.witnesses[0]["seed_origins"]
    }
    facts = {item.fact_id: item for item in contract.facts}
    assert origins["fact:left"] == {
        "fact_id": "fact:left",
        "fact_binding_digest": _canonical_digest(facts["fact:left"].to_dict()),
        "source_kind": "OBSERVER_STATE",
        "source_id": "observer:bounded-controller",
        "evaluation_digest": origins["fact:left"]["evaluation_digest"],
    }
    assert origins["fact:right"] == {
        "fact_id": "fact:right",
        "fact_binding_digest": _canonical_digest(facts["fact:right"].to_dict()),
        "source_kind": "INTERFACE_DISCLOSURE",
        "source_id": "interface:right",
        "evaluation_digest": origins["fact:right"]["evaluation_digest"],
    }
    assert origins["fact:left"]["evaluation_digest"].startswith("sha256:")
    assert origins["fact:right"]["evaluation_digest"].startswith("sha256:")


def test_unseeded_cycle_does_not_create_knowledge() -> None:
    graph, store, session = _fixture()
    facts = [
        _fact("fact:cycle-a", "artifact:left"),
        _fact("fact:protected", "artifact:protected"),
    ]
    interface = {
        "interface_id": "interface:empty",
        "abstraction_mechanism_id": "abstraction:empty",
        "source_artifact_ids": [],
        "exposed_fact_ids": [],
        "control_signal_fact_ids": [],
        "required_capability_ids": [],
        "coverage_proposition": _proposition(
            store,
            "interface:empty",
            "interface_disclosure_channels_complete",
            [item.value for item in DisclosureChannel],
        ).to_dict(),
    }
    hyperedges = [
        {
            "hyperedge_id": "hyperedge:a-to-protected",
            "required_fact_ids": ["fact:cycle-a"],
            "produced_fact_ids": ["fact:protected"],
            "relation_id": "relation:cycle-forward",
            "transformation_id": None,
            "required_capability_ids": [],
            "activation_propositions": [
                _proposition(
                    store,
                    "hyperedge:a-to-protected",
                    "knowledge_hyperedge_active",
                ).to_dict()
            ],
        },
        {
            "hyperedge_id": "hyperedge:protected-to-a",
            "required_fact_ids": ["fact:protected"],
            "produced_fact_ids": ["fact:cycle-a"],
            "relation_id": "relation:cycle-backward",
            "transformation_id": None,
            "required_capability_ids": [],
            "activation_propositions": [
                _proposition(
                    store,
                    "hyperedge:protected-to-a",
                    "knowledge_hyperedge_active",
                ).to_dict()
            ],
        },
    ]
    contract = UntraversableContract.from_dict(
        _contract_payload(
            graph,
            store,
            accessible_interfaces=("interface:empty",),
            facts=facts,
            interfaces=[interface],
            hyperedges=hyperedges,
        )
    )

    report = analyze_untraversability(graph, contract, session)

    assert report.status is UntraversabilityStatus.MATCH
    assert "fact:protected" not in report.reached_fact_ids


@pytest.mark.parametrize("unsupported", ("coverage", "completeness"))
def test_match_requires_supported_interface_coverage_and_rule_completeness(unsupported: str) -> None:
    graph, store, session = _fixture()
    payload = _contract_payload(
        graph,
        store,
        accessible_interfaces=("interface:left",),
        completeness_supported=unsupported != "completeness",
    )
    if unsupported == "coverage":
        expected = payload["interfaces"][0]["coverage_proposition"]["expected"]
        payload["interfaces"][0]["coverage_proposition"] = _proposition(
            store,
            "interface:left",
            "interface_disclosure_channels_complete",
            expected,
            supported=False,
        ).to_dict()

    report = analyze_untraversability(
        graph, UntraversableContract.from_dict(payload), session
    )

    assert report.status is UntraversabilityStatus.UNKNOWN


def test_missing_mechanism_and_exhausted_limits_remain_unknown() -> None:
    graph, store, session = _fixture()
    contract = UntraversableContract.from_dict(
        _contract_payload(graph, store, accessible_interfaces=("interface:left",))
    )

    missing_mechanism = analyze_untraversability(
        graph, contract, VerificationSession(store)
    )
    assert missing_mechanism.status is UntraversabilityStatus.UNKNOWN

    limited_payload = _contract_payload(graph, store)
    limited_payload["resource_limits"]["max_rule_firings"] = 0
    exhausted = analyze_untraversability(
        graph, UntraversableContract.from_dict(limited_payload), session
    )
    assert exhausted.status is UntraversabilityStatus.UNKNOWN


def test_opposite_supported_activation_states_are_conflicted() -> None:
    graph, store, session = _fixture()
    payload = _contract_payload(graph, store)
    facts_by_id = {item["fact_id"]: item for item in payload["facts"]}
    hyperedge = {
        key: value
        for key, value in payload["knowledge_hyperedges"][0].items()
        if key != "activation_propositions"
    }
    payload["knowledge_hyperedges"][0]["activation_propositions"].append(
        _proposition(
            store,
            "hyperedge:combine",
            "knowledge_hyperedge_active",
            expected={
                "active": False,
                "graph_digest": payload["graph_digest"],
                "hyperedge": hyperedge,
                "produced_facts": [facts_by_id["fact:protected"]],
                "required_facts": [
                    facts_by_id["fact:left"],
                    facts_by_id["fact:right"],
                ],
            },
        ).to_dict()
    )

    report = analyze_untraversability(
        graph, UntraversableContract.from_dict(payload), session
    )

    assert report.status is UntraversabilityStatus.CONFLICTED
    assert report.conflicted_hyperedge_ids == ("hyperedge:combine",)


def test_failed_active_proposition_is_unresolved_not_supported_inactive() -> None:
    graph, store, session = _fixture()
    payload = _contract_payload(graph, store)
    facts_by_id = {item["fact_id"]: item for item in payload["facts"]}
    hyperedge = {
        key: value
        for key, value in payload["knowledge_hyperedges"][0].items()
        if key != "activation_propositions"
    }
    payload["knowledge_hyperedges"][0]["activation_propositions"] = [
        _proposition(
            store,
            "hyperedge:combine",
            "knowledge_hyperedge_active",
            expected={
                "active": True,
                "graph_digest": payload["graph_digest"],
                "hyperedge": hyperedge,
                "produced_facts": [facts_by_id["fact:protected"]],
                "required_facts": [
                    facts_by_id["fact:left"],
                    facts_by_id["fact:right"],
                ],
            },
            supported=False,
        ).to_dict()
    ]
    contract = UntraversableContract.from_dict(payload)

    report = analyze_untraversability(graph, contract, session)

    assert report.status is UntraversabilityStatus.UNKNOWN
    assert report.to_dict()["unresolved_hyperedge_ids"] == ["hyperedge:combine"]
    assert report.conflicted_hyperedge_ids == ()
    assert "fact:protected" not in report.reached_fact_ids


def test_graph_substitution_is_refused_before_traversal() -> None:
    graph, store, session = _fixture()
    contract = UntraversableContract.from_dict(_contract_payload(graph, store))
    substituted = ProvenanceHypergraph.from_dict(graph.to_dict())
    substituted.add_artifact(
        ArtifactNode(
            artifact_id="artifact:substituted",
            label="substituted",
            artifact_type=ArtifactType.CONFIG,
            content_digest="f" * 64,
        )
    )

    with pytest.raises(UntraversableError, match="graph digest substitution"):
        analyze_untraversability(substituted, contract, session)


def test_nested_bound_proposition_scalars_are_strictly_typed() -> None:
    graph, store, _ = _fixture()
    payload = _contract_payload(graph, store)
    payload["interfaces"][0]["coverage_proposition"]["bounds"][
        "max_evidence_items"
    ] = True

    with pytest.raises(UntraversableError, match="max_evidence_items must be an integer"):
        UntraversableContract.from_dict(payload)


@pytest.mark.parametrize("missing_reference", ("artifact", "transformation"))
def test_unsupported_semantics_still_rejects_absent_graph_references(
    missing_reference: str,
) -> None:
    graph, store, session = _fixture()
    facts = [
        _fact(
            "fact:left",
            "artifact:absent" if missing_reference == "artifact" else "artifact:left",
        ),
        _fact("fact:right", "artifact:right"),
        _fact("fact:protected", "artifact:protected"),
    ]
    hyperedges = [
        {
            "hyperedge_id": "hyperedge:combine",
            "required_fact_ids": ["fact:left", "fact:right"],
            "produced_fact_ids": ["fact:protected"],
            "relation_id": "relation:conjunctive-combination",
            "transformation_id": (
                "transformation:absent"
                if missing_reference == "transformation"
                else None
            ),
            "required_capability_ids": [],
        }
    ]
    contract = UntraversableContract.from_dict(
        _contract_payload(
            graph,
            store,
            facts=facts,
            hyperedges=hyperedges,
            semantics_id="unsupported-semantics:v1",
        )
    )

    with pytest.raises(UntraversableError, match="absent from the bound graph"):
        analyze_untraversability(graph, contract, session)


def test_over_depth_branch_does_not_suppress_shorter_protected_witness() -> None:
    graph, store, session = _fixture()
    facts = [
        _fact("fact:left", "artifact:left"),
        _fact("fact:mid", "artifact:left"),
        _fact("fact:protected", "artifact:protected"),
    ]
    interface = {
        "interface_id": "interface:start",
        "abstraction_mechanism_id": "abstraction:start",
        "source_artifact_ids": ["artifact:left"],
        "exposed_fact_ids": ["fact:left"],
        "control_signal_fact_ids": ["fact:left"],
        "required_capability_ids": [],
    }
    hyperedges = [
        {
            "hyperedge_id": "hyperedge:a-long-first",
            "required_fact_ids": ["fact:left"],
            "produced_fact_ids": ["fact:mid"],
            "relation_id": "relation:long-first",
            "transformation_id": None,
            "required_capability_ids": [],
        },
        {
            "hyperedge_id": "hyperedge:b-too-deep",
            "required_fact_ids": ["fact:mid"],
            "produced_fact_ids": ["fact:protected"],
            "relation_id": "relation:too-deep",
            "transformation_id": None,
            "required_capability_ids": [],
        },
        {
            "hyperedge_id": "hyperedge:z-short",
            "required_fact_ids": ["fact:left"],
            "produced_fact_ids": ["fact:protected"],
            "relation_id": "relation:short",
            "transformation_id": None,
            "required_capability_ids": [],
        },
    ]
    contract = UntraversableContract.from_dict(
        _contract_payload(
            graph,
            store,
            accessible_interfaces=("interface:start",),
            facts=facts,
            interfaces=[interface],
            hyperedges=hyperedges,
            limits={
                "max_fact_count": 64,
                "max_hyperedge_count": 64,
                "max_rule_firings": 64,
                "max_hyperpath_depth": 1,
                "max_query_count": 64,
                "max_evidence_items": 64,
                "max_evidence_bytes": 64_000,
            },
        )
    )

    report = analyze_untraversability(graph, contract, session)

    assert report.status is UntraversabilityStatus.FAIL
    assert [
        step["hyperedge_id"] for step in report.witnesses[0]["steps"]
    ] == ["hyperedge:z-short"]


def test_single_firing_budget_prioritizes_direct_protected_path_over_decoy() -> None:
    graph, store, session = _fixture()
    facts = [
        _fact("fact:left", "artifact:left"),
        _fact("fact:decoy", "artifact:left"),
        _fact("fact:protected", "artifact:protected"),
    ]
    interface = {
        "interface_id": "interface:start",
        "abstraction_mechanism_id": "abstraction:start",
        "source_artifact_ids": ["artifact:left"],
        "exposed_fact_ids": ["fact:left"],
        "control_signal_fact_ids": ["fact:left"],
        "required_capability_ids": [],
    }
    hyperedges = [
        {
            "hyperedge_id": "hyperedge:a-decoy-first-by-name",
            "required_fact_ids": ["fact:left"],
            "produced_fact_ids": ["fact:decoy"],
            "relation_id": "relation:decoy",
            "transformation_id": None,
            "required_capability_ids": [],
        },
        {
            "hyperedge_id": "hyperedge:b-decoy-to-protected",
            "required_fact_ids": ["fact:decoy"],
            "produced_fact_ids": ["fact:protected"],
            "relation_id": "relation:indirect",
            "transformation_id": None,
            "required_capability_ids": [],
        },
        {
            "hyperedge_id": "hyperedge:z-direct",
            "required_fact_ids": ["fact:left"],
            "produced_fact_ids": ["fact:protected"],
            "relation_id": "relation:direct",
            "transformation_id": None,
            "required_capability_ids": [],
        },
    ]
    contract = UntraversableContract.from_dict(
        _contract_payload(
            graph,
            store,
            accessible_interfaces=("interface:start",),
            facts=facts,
            interfaces=[interface],
            hyperedges=hyperedges,
            limits={
                "max_fact_count": 64,
                "max_hyperedge_count": 64,
                "max_rule_firings": 1,
                "max_hyperpath_depth": 16,
                "max_query_count": 64,
                "max_evidence_items": 64,
                "max_evidence_bytes": 64_000,
            },
        )
    )

    report = analyze_untraversability(graph, contract, session)

    assert report.status is UntraversabilityStatus.FAIL
    assert [
        step["hyperedge_id"] for step in report.witnesses[0]["steps"]
    ] == ["hyperedge:z-direct"]


def test_report_serialization_is_immutable_across_caller_mutation() -> None:
    graph, store, session = _fixture()
    report = analyze_untraversability(
        graph,
        UntraversableContract.from_dict(_contract_payload(graph, store)),
        session,
    )
    first = report.to_dict()
    first["witnesses"][0]["steps"][0]["consumed_fact_ids"].append("fact:forged")
    first["findings"].append("caller mutation")

    restored = report.to_dict()

    assert "fact:forged" not in restored["witnesses"][0]["steps"][0][
        "consumed_fact_ids"
    ]
    assert "caller mutation" not in restored["findings"]


def test_witness_steps_are_topological_and_digest_bound() -> None:
    graph, store, session = _fixture()
    facts = [
        _fact("fact:left", "artifact:left"),
        _fact("fact:mid", "artifact:left"),
        _fact("fact:protected", "artifact:protected"),
    ]
    interface = {
        "interface_id": "interface:start",
        "abstraction_mechanism_id": "abstraction:start",
        "source_artifact_ids": ["artifact:left"],
        "exposed_fact_ids": ["fact:left"],
        "control_signal_fact_ids": ["fact:left"],
        "required_capability_ids": [],
    }
    hyperedges = [
        {
            "hyperedge_id": "hyperedge:z-first",
            "required_fact_ids": ["fact:left"],
            "produced_fact_ids": ["fact:mid"],
            "relation_id": "relation:first",
            "transformation_id": None,
            "required_capability_ids": [],
        },
        {
            "hyperedge_id": "hyperedge:a-second",
            "required_fact_ids": ["fact:mid"],
            "produced_fact_ids": ["fact:protected"],
            "relation_id": "relation:second",
            "transformation_id": None,
            "required_capability_ids": [],
        },
    ]
    report = analyze_untraversability(
        graph,
        UntraversableContract.from_dict(
            _contract_payload(
                graph,
                store,
                accessible_interfaces=("interface:start",),
                facts=facts,
                interfaces=[interface],
                hyperedges=hyperedges,
            )
        ),
        session,
    )

    witness = report.witnesses[0]
    assert [step["hyperedge_id"] for step in witness["steps"]] == [
        "hyperedge:z-first",
        "hyperedge:a-second",
    ]
    body = {key: value for key, value in witness.items() if key != "witness_digest"}
    assert witness["witness_digest"] == _canonical_digest(body)


@pytest.mark.parametrize("mutation", ("delete-rule", "add-leaking-rule"))
def test_rule_set_mutation_cannot_reuse_old_completeness_evidence(mutation: str) -> None:
    graph, store, _ = _fixture()
    original = _contract_payload(graph, store)
    old_completeness = deepcopy(original["rule_set_completeness"])
    if mutation == "delete-rule":
        changed = deepcopy(original)
        changed["knowledge_hyperedges"] = []
    else:
        changed = _contract_payload(
            graph,
            store,
            hyperedges=[
                {
                    "hyperedge_id": "hyperedge:combine",
                    "required_fact_ids": ["fact:left", "fact:right"],
                    "produced_fact_ids": ["fact:protected"],
                    "relation_id": "relation:conjunctive-combination",
                    "transformation_id": None,
                    "required_capability_ids": [],
                },
                {
                    "hyperedge_id": "hyperedge:new-leak",
                    "required_fact_ids": ["fact:left"],
                    "produced_fact_ids": ["fact:protected"],
                    "relation_id": "relation:new-leak",
                    "transformation_id": None,
                    "required_capability_ids": [],
                },
            ],
        )
    changed["rule_set_completeness"] = old_completeness

    with pytest.raises(UntraversableError, match="rule-set completeness proposition"):
        UntraversableContract.from_dict(changed)


@pytest.mark.parametrize(
    ("field", "replacement"),
    (
        ("exposed_fact_ids", ["fact:right"]),
        ("abstraction_mechanism_id", "abstraction:substituted"),
    ),
)
def test_interface_mutation_cannot_reuse_old_coverage_evidence(
    field: str, replacement: Any
) -> None:
    graph, store, _ = _fixture()
    payload = _contract_payload(graph, store)
    payload["interfaces"][0][field] = replacement

    with pytest.raises(UntraversableError, match="coverage proposition"):
        UntraversableContract.from_dict(payload)


@pytest.mark.parametrize(
    "field", ("commitment_digest", "channel", "source_artifact_ids")
)
def test_observer_support_cannot_reuse_stale_initial_fact_binding(field: str) -> None:
    graph, store, _ = _fixture()
    payload = _contract_payload(graph, store, initial_facts=("fact:left",))
    _mutate_fact(payload, "fact:left", field)

    with pytest.raises(UntraversableError, match="observer state proposition"):
        UntraversableContract.from_dict(payload)


@pytest.mark.parametrize(
    "field", ("commitment_digest", "channel", "source_artifact_ids")
)
def test_interface_support_cannot_reuse_stale_exposed_fact_binding(field: str) -> None:
    graph, store, _ = _fixture()
    payload = _contract_payload(graph, store)
    _mutate_fact(payload, "fact:left", field)

    with pytest.raises(UntraversableError, match="coverage proposition"):
        UntraversableContract.from_dict(payload)


@pytest.mark.parametrize(
    "field", ("commitment_digest", "channel", "source_artifact_ids")
)
def test_edge_support_cannot_reuse_stale_produced_fact_binding(field: str) -> None:
    graph, store, _ = _fixture()
    payload = _contract_payload(graph, store)
    _mutate_fact(payload, "fact:protected", field)

    with pytest.raises(UntraversableError, match="activation proposition"):
        UntraversableContract.from_dict(payload)


def test_contract_mode_cannot_reuse_other_mode_interface_or_rule_evidence() -> None:
    graph, store, _ = _fixture()
    payload = _contract_payload(graph, store)
    payload["mode"] = TraversalMode.ACTUAL_AWARENESS.value
    observer = payload["observer"]
    observer["state_proposition"] = _proposition(
        store,
        observer["observer_id"],
        "observer_knowledge_coordinate",
        {
            "accessible_interface_ids": observer["accessible_interface_ids"],
            "capability_ids": observer["capability_ids"],
            "graph_digest": payload["graph_digest"],
            "initial_fact_ids": observer["initial_fact_ids"],
            "initial_facts": [],
            "mode": TraversalMode.ACTUAL_AWARENESS.value,
            "observation_interval": payload["observation_interval"],
            "query_transcript_digest": observer["query_transcript_digest"],
            "query_count": observer["query_count"],
        },
    ).to_dict()

    with pytest.raises(UntraversableError, match="mode-specific interface"):
        UntraversableContract.from_dict(payload)


def test_permission_actual_awareness_and_potential_inference_are_separate_coordinates() -> None:
    graph, store, session = _fixture()
    reports = {}
    digests = {}
    for mode in TraversalMode:
        payload = _contract_payload(
            graph,
            store,
            accessible_interfaces=("interface:left",),
            mode=mode,
        )
        contract = UntraversableContract.from_dict(payload)
        reports[mode] = analyze_untraversability(graph, contract, session)
        digests[mode] = contract.digest()

    assert len(set(digests.values())) == 3
    assert {report.status for report in reports.values()} == {
        UntraversabilityStatus.MATCH
    }
    assert {
        report.to_dict()["mode"] for report in reports.values()
    } == {mode.value for mode in TraversalMode}


def test_observation_interval_and_query_count_are_identity_bearing_coordinates() -> None:
    graph, store, session = _fixture()
    baseline = UntraversableContract.from_dict(_contract_payload(graph, store))
    later_interval = UntraversableContract.from_dict(
        _contract_payload(
            graph,
            store,
            observation_interval={
                "clock_id": "clock:fixture",
                "start": 0,
                "end": 11,
                "unit": "tick",
            },
        )
    )
    one_query = UntraversableContract.from_dict(
        _contract_payload(graph, store, query_count=1)
    )

    assert len({baseline.digest(), later_interval.digest(), one_query.digest()}) == 3
    reports = [
        analyze_untraversability(graph, contract, session)
        for contract in (baseline, later_interval, one_query)
    ]
    assert len({report.observer_coordinate_digest for report in reports}) == 3


def test_query_count_above_declared_bound_is_unknown() -> None:
    graph, store, session = _fixture()
    contract = UntraversableContract.from_dict(
        _contract_payload(graph, store, query_count=65)
    )

    report = analyze_untraversability(graph, contract, session)

    assert report.status is UntraversabilityStatus.UNKNOWN
    assert report.resource_exhausted is True


def test_unsupported_named_semantics_is_admitted_but_not_interpreted() -> None:
    graph, store, session = _fixture()
    contract = UntraversableContract.from_dict(
        _contract_payload(
            graph,
            store,
            semantics_id="finite-nonmonotone-knowledge-hypergraph-v2",
        )
    )

    assert contract.semantics_id == "finite-nonmonotone-knowledge-hypergraph-v2"
    report = analyze_untraversability(graph, contract, session)
    assert report.status is UntraversabilityStatus.UNKNOWN
    assert "unsupported" in " ".join(report.to_dict()["findings"]).lower()


def test_capability_is_required_before_a_rule_can_fire() -> None:
    graph, store, session = _fixture()
    payload = _contract_payload(
        graph,
        store,
        hyperedges=[
            {
                "hyperedge_id": "hyperedge:combine",
                "required_fact_ids": ["fact:left", "fact:right"],
                "produced_fact_ids": ["fact:protected"],
                "relation_id": "relation:conjunctive-combination",
                "transformation_id": None,
                "required_capability_ids": ["capability:combine"],
            }
        ],
    )
    without_capability = UntraversableContract.from_dict(payload)

    assert (
        analyze_untraversability(graph, without_capability, session).status
        is UntraversabilityStatus.MATCH
    )

    payload["observer"]["capability_ids"] = ["capability:combine"]
    payload["observer"]["state_proposition"] = _proposition(
        store,
        "observer:bounded-controller",
        "observer_knowledge_coordinate",
        {
            "accessible_interface_ids": ["interface:left", "interface:right"],
            "capability_ids": ["capability:combine"],
            "graph_digest": payload["graph_digest"],
            "initial_fact_ids": [],
            "initial_facts": [],
            "mode": TraversalMode.POTENTIAL_INFERENCE.value,
            "observation_interval": {
                "clock_id": "clock:fixture",
                "start": 0,
                "end": 10,
                "unit": "tick",
            },
            "query_transcript_digest": _digest("query-transcript:empty"),
            "query_count": 0,
        },
    ).to_dict()
    with_capability = UntraversableContract.from_dict(payload)
    assert (
        analyze_untraversability(graph, with_capability, session).status
        is UntraversabilityStatus.FAIL
    )


def test_serialization_is_deterministic_and_contains_commitments_not_protected_contents() -> None:
    graph, store, session = _fixture()
    payload = _contract_payload(graph, store, accessible_interfaces=("interface:left",))
    contract = UntraversableContract.from_dict(deepcopy(payload))
    restored = UntraversableContract.from_dict(contract.to_dict())

    assert restored.to_dict() == contract.to_dict()
    assert restored.digest() == contract.digest()

    report = analyze_untraversability(graph, restored, session)
    serialized = json.dumps(
        {"contract": restored.to_dict(), "report": report.to_dict()},
        sort_keys=True,
        separators=(",", ":"),
    )
    assert "protected lower-order contents" not in serialized
    assert "natural-person-id" not in serialized
    assert "person_id" not in serialized
    assert _digest("commitment:fact:protected") in serialized


def test_surface_detection_and_planning_match_without_running_analyzer(monkeypatch) -> None:
    from test_control_surface import horizon_geometry
    from verifier.interoperability import untraversable
    from verifier.interoperability.control_surface import (
        analyze_verification_surface,
        plan_validation,
    )
    from verifier.interoperability.reference_catalog import reference_component_registry

    mechanism_id = "mechanism:composed-untraversability-analysis"
    relation_id = "relation:composed-untraversability"
    geometry = horizon_geometry()
    geometry.mechanisms[0] = replace(
        geometry.mechanisms[0], mechanism_id=mechanism_id
    )
    geometry.judgments[0] = replace(
        geometry.judgments[0], mechanism_ids=(mechanism_id,)
    )
    geometry.valences[0] = replace(
        geometry.valences[0], required_relation=relation_id
    )
    geometry.verification_layers[0] = replace(
        geometry.verification_layers[0], mechanism_ids=(mechanism_id,)
    )
    assert geometry.validate() == []

    def forbidden(*args, **kwargs):
        raise AssertionError("detection and planning must not execute the analyzer")

    monkeypatch.setattr(untraversable, "analyze_untraversability", forbidden)
    analysis = analyze_verification_surface(geometry)
    plan = plan_validation(analysis, reference_component_registry())

    candidates = [
        item
        for item in plan.candidates
        if item.component_id == "component:composed-untraversability-analyzer"
    ]
    assert candidates
    assert any(
        item.relation_id == relation_id and item.mechanism_id == mechanism_id
        for item in candidates
    )
    assert all(item.mechanism_id == mechanism_id for item in candidates)
    assert plan.execution_performed is False
