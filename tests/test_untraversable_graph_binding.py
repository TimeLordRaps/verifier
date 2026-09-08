"""Graph-incidence regressions for experimental untraversability analysis.

Terminology: Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD).
"""

from __future__ import annotations

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
from verifier.data.models import (
    ArtifactNode,
    ArtifactType,
    HyperedgePort,
    ProvenanceHypergraph,
    TransformationHyperedge,
    TransformationType,
)
from verifier.interoperability.graph_topology import graph_topology_binding_digest
from verifier.interoperability.untraversable import (
    DisclosureChannel,
    TraversalMode,
    UNTRAVERSABLE_SCHEMA_VERSION,
    UntraversabilityStatus,
    UntraversableContract,
    UntraversableError,
    analyze_untraversability,
)


class PassingEvidenceMechanism:
    """Fixture mechanism that establishes only its supplied bound proposition."""

    mechanism_id = "mechanism:test-graph-binding"
    mechanism_digest = "sha256:" + "a" * 64

    def evaluate(
        self, binding: BoundProposition, evidence: tuple[bytes, ...]
    ) -> MechanismDecision:
        assert evidence
        return MechanismDecision(MechanismOutcome.PASS, "fixture proposition matched")


def _digest(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode("utf-8")).hexdigest()


def _binding_digest(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _proposition(
    store: EvidenceStore,
    subject_id: str,
    predicate: str,
    expected: Any,
) -> BoundProposition:
    evidence_ref = store.add(f"{subject_id}:{predicate}".encode("utf-8"))
    return BoundProposition(
        subject_id=subject_id,
        predicate=predicate,
        expected=expected,
        mechanism_id=PassingEvidenceMechanism.mechanism_id,
        mechanism_digest=PassingEvidenceMechanism.mechanism_digest,
        evidence_refs=(evidence_ref,),
        trust_roots=("test:graph-binding",),
        bounds=EvidenceBounds(max_evidence_items=1, max_evidence_bytes=1_000),
    )


def _graph() -> ProvenanceHypergraph:
    graph = ProvenanceHypergraph()
    for artifact_id in (
        "artifact:left",
        "artifact:right",
        "artifact:protected",
        "artifact:unrelated",
    ):
        graph.add_artifact(
            ArtifactNode(
                artifact_id=artifact_id,
                label=artifact_id,
                artifact_type=ArtifactType.CONFIG,
                content_digest=hashlib.sha256(artifact_id.encode("utf-8")).hexdigest(),
            )
        )
    graph.add_transformation(
        TransformationHyperedge(
            transformation_id="transformation:combine",
            label="Combine two exposed facts",
            transformation_type=TransformationType.EVIDENCE_BINDING,
            inputs=(
                HyperedgePort("artifact:left", "LEFT"),
                HyperedgePort("artifact:right", "RIGHT"),
            ),
            outputs=(HyperedgePort("artifact:protected", "RESULT"),),
            software_provenance={},
            parameters={},
            execution_environment={},
        )
    )
    return graph


def _fact(fact_id: str, artifact_id: str) -> dict[str, Any]:
    return {
        "fact_id": fact_id,
        "commitment_digest": _digest("commitment:" + fact_id),
        "source_artifact_ids": [artifact_id],
        "channel": DisclosureChannel.CONTENT.value,
    }


def _contract(
    graph: ProvenanceHypergraph,
    store: EvidenceStore,
    *,
    left_interface_sources: tuple[str, ...] = ("artifact:left",),
    required_fact_ids: tuple[str, ...] = ("fact:left", "fact:right"),
    produced_fact_ids: tuple[str, ...] = ("fact:protected",),
) -> UntraversableContract:
    graph_digest = graph_topology_binding_digest(graph)
    mode = TraversalMode.POTENTIAL_INFERENCE
    interval = {"clock_id": "clock:test", "start": 0, "end": 1, "unit": "tick"}
    facts = sorted(
        (
            _fact("fact:left", "artifact:left"),
            _fact("fact:right", "artifact:right"),
            _fact("fact:protected", "artifact:protected"),
            _fact("fact:unrelated", "artifact:unrelated"),
        ),
        key=lambda item: item["fact_id"],
    )
    facts_by_id = {item["fact_id"]: item for item in facts}

    interface_skeletons = sorted(
        (
            {
                "interface_id": "interface:left",
                "mode": mode.value,
                "abstraction_mechanism_id": "abstraction:left",
                "source_artifact_ids": sorted(left_interface_sources),
                "exposed_fact_ids": ["fact:left"],
                "control_signal_fact_ids": ["fact:left"],
                "required_capability_ids": [],
            },
            {
                "interface_id": "interface:right",
                "mode": mode.value,
                "abstraction_mechanism_id": "abstraction:right",
                "source_artifact_ids": ["artifact:right"],
                "exposed_fact_ids": ["fact:right"],
                "control_signal_fact_ids": ["fact:right"],
                "required_capability_ids": [],
            },
        ),
        key=lambda item: item["interface_id"],
    )
    interfaces = [
        {
            **skeleton,
            "coverage_proposition": _proposition(
                store,
                skeleton["interface_id"],
                "interface_disclosure_channels_complete",
                {
                    "covered_channels": [channel.value for channel in DisclosureChannel],
                    "exposed_facts": [
                        facts_by_id[item]
                        for item in skeleton["exposed_fact_ids"]
                    ],
                    "graph_digest": graph_digest,
                    "interface": skeleton,
                },
            ).to_dict(),
        }
        for skeleton in interface_skeletons
    ]

    edge_skeleton = {
        "hyperedge_id": "hyperedge:combine",
        "mode": mode.value,
        "required_fact_ids": sorted(required_fact_ids),
        "produced_fact_ids": sorted(produced_fact_ids),
        "relation_id": "relation:combine",
        "transformation_id": "transformation:combine",
        "required_capability_ids": [],
    }
    edges = [
        {
            **edge_skeleton,
            "activation_propositions": [
                _proposition(
                    store,
                    edge_skeleton["hyperedge_id"],
                    "knowledge_hyperedge_active",
                    {
                        "active": True,
                        "graph_digest": graph_digest,
                        "hyperedge": edge_skeleton,
                        "produced_facts": [
                            facts_by_id[item]
                            for item in edge_skeleton["produced_fact_ids"]
                        ],
                        "required_facts": [
                            facts_by_id[item]
                            for item in edge_skeleton["required_fact_ids"]
                        ],
                    },
                ).to_dict()
            ],
        }
    ]

    observer_skeleton = {
        "accessible_interface_ids": ["interface:left", "interface:right"],
        "capability_ids": [],
        "graph_digest": graph_digest,
        "initial_fact_ids": [],
        "initial_facts": [],
        "mode": mode.value,
        "observation_interval": interval,
        "query_transcript_digest": _digest("empty query transcript"),
        "query_count": 0,
    }
    observer = {
        "observer_id": "observer:test",
        "accessible_interface_ids": observer_skeleton["accessible_interface_ids"],
        "initial_fact_ids": observer_skeleton["initial_fact_ids"],
        "capability_ids": observer_skeleton["capability_ids"],
        "query_transcript_digest": observer_skeleton["query_transcript_digest"],
        "query_count": observer_skeleton["query_count"],
        "state_proposition": _proposition(
            store,
            "observer:test",
            "observer_knowledge_coordinate",
            observer_skeleton,
        ).to_dict(),
    }
    protected = ["fact:protected"]
    model = {
        "graph_digest": graph_digest,
        "mode": mode.value,
        "protected_fact_ids": protected,
        "facts": facts,
        "interfaces": interface_skeletons,
        "knowledge_hyperedges": [edge_skeleton],
    }
    payload = {
        "schema_version": UNTRAVERSABLE_SCHEMA_VERSION,
        "contract_id": "contract:graph-binding",
        "graph_digest": graph_digest,
        "semantics_id": "finite-monotone-knowledge-hypergraph-v1",
        "mode": mode.value,
        "observation_interval": interval,
        "observer": observer,
        "protected_fact_ids": protected,
        "facts": facts,
        "interfaces": interfaces,
        "knowledge_hyperedges": edges,
        "rule_set_completeness": _proposition(
            store,
            "contract:graph-binding",
            "knowledge_rule_set_complete",
            {"complete": True, "model": model},
        ).to_dict(),
        "resource_limits": {
            "max_fact_count": 16,
            "max_hyperedge_count": 8,
            "max_rule_firings": 8,
            "max_hyperpath_depth": 8,
            "max_query_count": 8,
            "max_evidence_items": 32,
            "max_evidence_bytes": 32_000,
        },
    }
    return UntraversableContract.from_dict(payload)


def _session(store: EvidenceStore) -> VerificationSession:
    session = VerificationSession(store)
    session.register(PassingEvidenceMechanism())
    return session


@pytest.mark.parametrize(
    "sources",
    ((), ("artifact:left", "artifact:unrelated")),
    ids=("missing", "extra"),
)
def test_interface_sources_exactly_equal_exposed_fact_sources(
    sources: tuple[str, ...],
) -> None:
    graph = _graph()
    store = EvidenceStore()
    contract = _contract(graph, store, left_interface_sources=sources)

    with pytest.raises(UntraversableError, match="exactly cover"):
        analyze_untraversability(graph, contract, _session(store))


@pytest.mark.parametrize(
    ("required", "produced"),
    (
        (("fact:left",), ("fact:protected",)),
        (("fact:left", "fact:right"), ("fact:left",)),
        (("fact:unrelated", "fact:right"), ("fact:protected",)),
    ),
    ids=("missing-input", "wrong-output", "wrong-input"),
)
def test_graph_backed_edge_requires_exact_input_and_output_source_sets(
    required: tuple[str, ...], produced: tuple[str, ...]
) -> None:
    graph = _graph()
    store = EvidenceStore()
    contract = _contract(
        graph,
        store,
        required_fact_ids=required,
        produced_fact_ids=produced,
    )

    with pytest.raises(UntraversableError, match="exactly match"):
        analyze_untraversability(graph, contract, _session(store))


@pytest.mark.parametrize("second_role", ("LEFT", "ALTERNATE"))
def test_graph_backed_edge_refuses_repeated_artifact_ports(second_role: str) -> None:
    graph = _graph()
    graph.transformations["transformation:combine"].inputs = (
        HyperedgePort("artifact:left", "LEFT"),
        HyperedgePort("artifact:left", second_role),
    )
    store = EvidenceStore()
    contract = _contract(
        graph,
        store,
        required_fact_ids=("fact:left",),
    )

    with pytest.raises(UntraversableError, match="repeated artifact ports"):
        analyze_untraversability(graph, contract, _session(store))


def test_invalid_graph_is_refused_before_knowledge_binding() -> None:
    graph = _graph()
    graph.transformations["transformation:combine"].inputs = ()
    store = EvidenceStore()
    contract = _contract(graph, store, required_fact_ids=("fact:left",))

    with pytest.raises(UntraversableError, match="admitted and bound"):
        analyze_untraversability(graph, contract, _session(store))


def test_invalid_original_graph_artifact_map_key_is_refused() -> None:
    graph = _graph()
    artifact = graph.artifacts.pop("artifact:left")
    graph.artifacts["artifact:not-left"] = artifact
    store = EvidenceStore()
    contract = _contract(graph, store)

    with pytest.raises(UntraversableError, match="admitted and bound"):
        analyze_untraversability(graph, contract, _session(store))


def test_graph_mutation_refuses_the_old_contract_digest() -> None:
    graph = _graph()
    store = EvidenceStore()
    contract = _contract(graph, store)
    graph.artifacts["artifact:left"].attributes["changed"] = True

    with pytest.raises(UntraversableError, match="graph digest substitution"):
        analyze_untraversability(graph, contract, _session(store))


def test_valid_transformation_backed_hyperedge_reaches_protected_fact() -> None:
    graph = _graph()
    store = EvidenceStore()
    contract = _contract(graph, store)

    report = analyze_untraversability(graph, contract, _session(store))

    assert report.status is UntraversabilityStatus.FAIL
    assert report.reached_fact_ids == (
        "fact:left",
        "fact:protected",
        "fact:right",
    )
    assert report.witnesses[0]["seed_origins"] == [
        {
            "fact_id": "fact:left",
            "fact_binding_digest": _binding_digest(
                _fact("fact:left", "artifact:left")
            ),
            "source_kind": "INTERFACE_DISCLOSURE",
            "source_id": "interface:left",
            "evaluation_digest": report.witnesses[0]["seed_origins"][0][
                "evaluation_digest"
            ],
        },
        {
            "fact_id": "fact:right",
            "fact_binding_digest": _binding_digest(
                _fact("fact:right", "artifact:right")
            ),
            "source_kind": "INTERFACE_DISCLOSURE",
            "source_id": "interface:right",
            "evaluation_digest": report.witnesses[0]["seed_origins"][1][
                "evaluation_digest"
            ],
        },
    ]
    assert all(
        origin["evaluation_digest"].startswith("sha256:")
        for origin in report.witnesses[0]["seed_origins"]
    )
    step, = report.witnesses[0]["steps"]
    assert step["hyperedge_id"] == "hyperedge:combine"
    assert step["consumed_fact_ids"] == ["fact:left", "fact:right"]
    assert step["produced_fact_ids"] == ["fact:protected"]
    assert step["transformation_ports"] == {
        "transformation_id": "transformation:combine",
        "inputs": [
            {"artifact_id": "artifact:left", "role": "LEFT"},
            {"artifact_id": "artifact:right", "role": "RIGHT"},
        ],
        "outputs": [
            {"artifact_id": "artifact:protected", "role": "RESULT"},
        ],
    }
    assert len(step["activation_evaluation_digests"]) == 1
    assert step["activation_evaluation_digests"][0].startswith("sha256:")
