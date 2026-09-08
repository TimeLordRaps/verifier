"""Bounded composed-graph analysis for confidentiality of awareness.

Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit
(SHA-256); Verifier Standard (VSTD). A byte is eight bits. A fact is a
caller-selected identifier plus a commitment. Protected contents need not be
carried by this module, but identifiers, relationships, and reports can
themselves disclose information and require the source graph's confidentiality
handling.

``MATCH`` means only that exhaustive closure of the declared, evidence-backed,
finite knowledge model did not reach a protected fact for the exact observer,
mode, graph, transcript, capabilities, evidence, and resource coordinate.
``FAIL`` requires a concrete all-input hyperpath. ``UNKNOWN`` preserves missing
evidence, incomplete channel or rule coverage, unsupported mechanisms, and
exhausted bounds. ``CONFLICTED`` preserves incompatible evidence about a
target-relevant inference rule. No result establishes permission, intent,
identity, guilt, universal secrecy, computational hardness, VSTD conformance,
or execution authority.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import json
import re
from typing import Any, Mapping, Sequence

from verifier.core.evidence import (
    BoundProposition,
    EvaluatedProposition,
    MechanismOutcome,
    VerificationSession,
    implementation_file_digest,
)
from verifier.data.models import ProvenanceHypergraph
from verifier.interoperability.graph_topology import graph_topology_binding_digest


UNTRAVERSABLE_SCHEMA_VERSION = "VSTD-UNTRAVERSABLE-EXPERIMENTAL-0.1"
UNTRAVERSABLE_REPORT_SCHEMA_VERSION = (
    "VSTD-UNTRAVERSABLE-REPORT-EXPERIMENTAL-0.1"
)
SUPPORTED_SEMANTICS = "finite-monotone-knowledge-hypergraph-v1"
TRAVERSAL_SCHEDULE = "goal-distance-then-depth-then-hyperedge-id-v1"
MAX_FACTS = 4096
MAX_INTERFACES = 1024
MAX_HYPEREDGES = 4096
MAX_PROPOSITIONS = 8192
MAX_DOCUMENT_BYTES = 2 * 1024 * 1024
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class UntraversableError(ValueError):
    """A contract is malformed or its exact graph coordinate was substituted."""


class TraversalMode(str, Enum):
    """Separate knowledge relations; none implies either of the others."""

    ACTUAL_AWARENESS = "ACTUAL_AWARENESS"
    PERMITTED_AWARENESS = "PERMITTED_AWARENESS"
    POTENTIAL_INFERENCE = "POTENTIAL_INFERENCE"


class DisclosureChannel(str, Enum):
    """Modeled ways in which an interface can disclose a fact."""

    CONTENT = "CONTENT"
    METADATA = "METADATA"
    IDENTIFIER = "IDENTIFIER"
    DEPENDENCY = "DEPENDENCY"
    TIMING = "TIMING"
    ERROR = "ERROR"
    QUERY_TRANSCRIPT = "QUERY_TRANSCRIPT"
    AWARENESS_RELATION = "AWARENESS_RELATION"
    CONTROL_SIGNAL = "CONTROL_SIGNAL"


class UntraversabilityStatus(str, Enum):
    """Native bounded-analysis results, separate from VSTD receipt verdicts."""

    MATCH = "MATCH"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    CONFLICTED = "CONFLICTED"


class ObservationUnit(str, Enum):
    """Dimension of an observation coordinate; one nanosecond is 1e-9 seconds."""

    TICK = "tick"
    NANOSECOND = "nanosecond"


def _json_bytes(value: Any) -> bytes:
    try:
        encoded = json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError, RecursionError, UnicodeError) as exc:
        raise UntraversableError("contract is not bounded canonical JSON") from exc
    if len(encoded) > MAX_DOCUMENT_BYTES:
        raise UntraversableError("contract exceeds the document byte bound")
    return encoded


def _digest(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_json_bytes(value)).hexdigest()


def _object(value: Any, keys: set[str], label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or set(value) != keys:
        raise UntraversableError(f"{label} must have exactly {sorted(keys)}")
    return value


def _text(value: Any, label: str, *, limit: int = 512) -> str:
    if (
        type(value) is not str
        or not value
        or value != value.strip()
        or len(value) > limit
    ):
        raise UntraversableError(
            f"{label} must be a nonempty trimmed string <= {limit} characters"
        )
    return value


def _digest_text(value: Any, label: str) -> str:
    result = _text(value, label)
    if _DIGEST.fullmatch(result) is None:
        raise UntraversableError(f"{label} must be a lowercase sha256: digest")
    return result


def _strings(value: Any, label: str, *, allow_empty: bool = True) -> tuple[str, ...]:
    if type(value) is not list:
        raise UntraversableError(f"{label} must be an array")
    result = tuple(_text(item, label) for item in value)
    if not allow_empty and not result:
        raise UntraversableError(f"{label} must not be empty")
    if len(result) != len(set(result)):
        raise UntraversableError(f"{label} must not contain duplicates")
    return tuple(sorted(result))


def _limit(value: Any, label: str, ceiling: int) -> int:
    if type(value) is not int or value < 0 or value > ceiling:
        raise UntraversableError(
            f"{label} must be an integer from 0 through {ceiling}"
        )
    return value


_PROPOSITION_KEYS = {
    "subject_id",
    "predicate",
    "expected",
    "mechanism_id",
    "mechanism_digest",
    "evidence_refs",
    "trust_roots",
    "bounds",
    "parameters",
}


def _proposition(value: Any, label: str) -> BoundProposition:
    data = _object(value, _PROPOSITION_KEYS, label)
    bounds = _object(
        data["bounds"],
        {"max_evidence_items", "max_evidence_bytes"},
        f"{label}.bounds",
    )
    _text(data["subject_id"], f"{label}.subject_id")
    _text(data["predicate"], f"{label}.predicate")
    _text(data["mechanism_id"], f"{label}.mechanism_id")
    _digest_text(data["mechanism_digest"], f"{label}.mechanism_digest")
    references = _strings(
        data["evidence_refs"], f"{label}.evidence_refs", allow_empty=False
    )
    for index, reference in enumerate(references):
        _digest_text(reference, f"{label}.evidence_refs[{index}]")
    _strings(data["trust_roots"], f"{label}.trust_roots", allow_empty=False)
    _limit(
        bounds["max_evidence_items"],
        f"{label}.bounds.max_evidence_items",
        MAX_PROPOSITIONS * 16,
    )
    _limit(
        bounds["max_evidence_bytes"],
        f"{label}.bounds.max_evidence_bytes",
        MAX_DOCUMENT_BYTES * 16,
    )
    if type(data["parameters"]) is not dict:
        raise UntraversableError(f"{label}.parameters must be an object")
    if any(
        type(key) is not str
        or type(item) is not str
        or len(key) > 512
        or len(item) > 4096
        for key, item in data["parameters"].items()
    ):
        raise UntraversableError(
            f"{label}.parameters keys and values must be bounded strings"
        )
    _json_bytes(data["expected"])
    try:
        return BoundProposition.from_dict(data)
    except (KeyError, TypeError, ValueError) as exc:
        raise UntraversableError(f"{label} is not a valid bound proposition") from exc


@dataclass(frozen=True)
class FactBinding:
    """Opaque knowledge-fact identity without protected content."""

    fact_id: str
    commitment_digest: str
    source_artifact_ids: tuple[str, ...]
    channel: DisclosureChannel

    def to_dict(self) -> dict[str, Any]:
        return {
            "fact_id": self.fact_id,
            "commitment_digest": self.commitment_digest,
            "source_artifact_ids": list(self.source_artifact_ids),
            "channel": self.channel.value,
        }


@dataclass(frozen=True)
class ObserverCoordinate:
    """Opaque observer-relative knowledge, capability, and query coordinate."""

    observer_id: str
    accessible_interface_ids: tuple[str, ...]
    initial_fact_ids: tuple[str, ...]
    capability_ids: tuple[str, ...]
    query_transcript_digest: str
    query_count: int
    state_proposition: BoundProposition

    def to_dict(self) -> dict[str, Any]:
        return {
            "observer_id": self.observer_id,
            "accessible_interface_ids": list(self.accessible_interface_ids),
            "initial_fact_ids": list(self.initial_fact_ids),
            "capability_ids": list(self.capability_ids),
            "query_transcript_digest": self.query_transcript_digest,
            "query_count": self.query_count,
            "state_proposition": self.state_proposition.to_dict(),
        }


@dataclass(frozen=True)
class HigherOrderComplexityInterface:
    """Many-to-one control surface whose disclosures are explicit facts."""

    interface_id: str
    mode: TraversalMode
    abstraction_mechanism_id: str
    source_artifact_ids: tuple[str, ...]
    exposed_fact_ids: tuple[str, ...]
    control_signal_fact_ids: tuple[str, ...]
    required_capability_ids: tuple[str, ...]
    coverage_proposition: BoundProposition

    def skeleton(self) -> dict[str, Any]:
        return {
            "interface_id": self.interface_id,
            "mode": self.mode.value,
            "abstraction_mechanism_id": self.abstraction_mechanism_id,
            "source_artifact_ids": list(self.source_artifact_ids),
            "exposed_fact_ids": list(self.exposed_fact_ids),
            "control_signal_fact_ids": list(self.control_signal_fact_ids),
            "required_capability_ids": list(self.required_capability_ids),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.skeleton(),
            "coverage_proposition": self.coverage_proposition.to_dict(),
        }


@dataclass(frozen=True)
class KnowledgeHyperedge:
    """Conjunctive derivation rule; every required fact is necessary."""

    hyperedge_id: str
    mode: TraversalMode
    required_fact_ids: tuple[str, ...]
    produced_fact_ids: tuple[str, ...]
    relation_id: str
    transformation_id: str | None
    required_capability_ids: tuple[str, ...]
    activation_propositions: tuple[BoundProposition, ...]

    def skeleton(self) -> dict[str, Any]:
        return {
            "hyperedge_id": self.hyperedge_id,
            "mode": self.mode.value,
            "required_fact_ids": list(self.required_fact_ids),
            "produced_fact_ids": list(self.produced_fact_ids),
            "relation_id": self.relation_id,
            "transformation_id": self.transformation_id,
            "required_capability_ids": list(self.required_capability_ids),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.skeleton(),
            "activation_propositions": [
                item.to_dict() for item in self.activation_propositions
            ],
        }


@dataclass(frozen=True)
class TraversalResourceCoordinate:
    """Finite search and unique-evidence-bundle ceilings for one invocation.

    Evidence items and bytes count each content-addressed payload once. They do
    not bound repeated mechanism processing work, which requires an independent
    execution constraint outside this experimental analyzer.
    """

    max_fact_count: int
    max_hyperedge_count: int
    max_rule_firings: int
    max_hyperpath_depth: int
    max_query_count: int
    max_evidence_items: int
    max_evidence_bytes: int

    def to_dict(self) -> dict[str, int]:
        return {
            "max_fact_count": self.max_fact_count,
            "max_hyperedge_count": self.max_hyperedge_count,
            "max_rule_firings": self.max_rule_firings,
            "max_hyperpath_depth": self.max_hyperpath_depth,
            "max_query_count": self.max_query_count,
            "max_evidence_items": self.max_evidence_items,
            "max_evidence_bytes": self.max_evidence_bytes,
        }


@dataclass(frozen=True)
class ObservationInterval:
    """Inclusive integer interval on one named clock and declared unit."""

    clock_id: str
    start: int
    end: int
    unit: ObservationUnit

    def to_dict(self) -> dict[str, Any]:
        return {
            "clock_id": self.clock_id,
            "start": self.start,
            "end": self.end,
            "unit": self.unit.value,
        }


@dataclass(frozen=True)
class UntraversableContract:
    """Exact bounded proposition evaluated across all accessible interfaces."""

    schema_version: str
    contract_id: str
    graph_digest: str
    semantics_id: str
    mode: TraversalMode
    observation_interval: ObservationInterval
    observer: ObserverCoordinate
    protected_fact_ids: tuple[str, ...]
    facts: tuple[FactBinding, ...]
    interfaces: tuple[HigherOrderComplexityInterface, ...]
    knowledge_hyperedges: tuple[KnowledgeHyperedge, ...]
    rule_set_completeness: BoundProposition
    resource_limits: TraversalResourceCoordinate

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "UntraversableContract":
        _json_bytes(value)
        data = _object(
            value,
            {
                "schema_version",
                "contract_id",
                "graph_digest",
                "semantics_id",
                "mode",
                "observation_interval",
                "observer",
                "protected_fact_ids",
                "facts",
                "interfaces",
                "knowledge_hyperedges",
                "rule_set_completeness",
                "resource_limits",
            },
            "contract",
        )
        if data["schema_version"] != UNTRAVERSABLE_SCHEMA_VERSION:
            raise UntraversableError("unsupported untraversability schema_version")
        try:
            mode = TraversalMode(data["mode"])
        except (TypeError, ValueError) as exc:
            raise UntraversableError("unsupported traversal mode") from exc
        interval_data = _object(
            data["observation_interval"],
            {"clock_id", "start", "end", "unit"},
            "observation_interval",
        )
        try:
            observation_unit = ObservationUnit(interval_data["unit"])
        except (TypeError, ValueError) as exc:
            raise UntraversableError("unsupported observation interval unit") from exc
        start = interval_data["start"]
        end = interval_data["end"]
        if type(start) is not int or type(end) is not int or start < 0 or end < start:
            raise UntraversableError(
                "observation interval coordinates must be ordered nonnegative integers"
            )
        observation_interval = ObservationInterval(
            _text(interval_data["clock_id"], "observation_interval.clock_id"),
            start,
            end,
            observation_unit,
        )

        observer_data = _object(
            data["observer"],
            {
                "observer_id",
                "accessible_interface_ids",
                "initial_fact_ids",
                "capability_ids",
                "query_transcript_digest",
                "query_count",
                "state_proposition",
            },
            "observer",
        )
        observer = ObserverCoordinate(
            _text(observer_data["observer_id"], "observer_id"),
            _strings(observer_data["accessible_interface_ids"], "accessible_interface_ids"),
            _strings(observer_data["initial_fact_ids"], "initial_fact_ids"),
            _strings(observer_data["capability_ids"], "capability_ids"),
            _digest_text(observer_data["query_transcript_digest"], "query_transcript_digest"),
            _limit(observer_data["query_count"], "query_count", MAX_PROPOSITIONS * 16),
            _proposition(observer_data["state_proposition"], "state_proposition"),
        )
        raw_facts = data["facts"]
        if type(raw_facts) is not list or len(raw_facts) > MAX_FACTS:
            raise UntraversableError("facts must be an array within the structural bound")
        facts: list[FactBinding] = []
        for index, item in enumerate(raw_facts):
            row = _object(
                item,
                {"fact_id", "commitment_digest", "source_artifact_ids", "channel"},
                f"facts[{index}]",
            )
            try:
                channel = DisclosureChannel(row["channel"])
            except (TypeError, ValueError) as exc:
                raise UntraversableError("unsupported disclosure channel") from exc
            facts.append(
                FactBinding(
                    _text(row["fact_id"], "fact_id"),
                    _digest_text(row["commitment_digest"], "commitment_digest"),
                    _strings(row["source_artifact_ids"], "source_artifact_ids", allow_empty=False),
                    channel,
                )
            )
        facts.sort(key=lambda item: item.fact_id)
        fact_ids = {item.fact_id for item in facts}
        if len(fact_ids) != len(facts):
            raise UntraversableError("duplicate fact_id")
        facts_by_id = {item.fact_id: item for item in facts}
        if not set(observer.initial_fact_ids) <= fact_ids:
            raise UntraversableError("observer references an unknown initial fact")
        if (
            observer.state_proposition.subject_id != observer.observer_id
            or observer.state_proposition.predicate != "observer_knowledge_coordinate"
            or observer.state_proposition.expected
            != {
                "accessible_interface_ids": list(observer.accessible_interface_ids),
                "capability_ids": list(observer.capability_ids),
                "graph_digest": data["graph_digest"],
                "initial_fact_ids": list(observer.initial_fact_ids),
                "initial_facts": [
                    facts_by_id[item].to_dict()
                    for item in observer.initial_fact_ids
                ],
                "mode": mode.value,
                "observation_interval": observation_interval.to_dict(),
                "query_transcript_digest": observer.query_transcript_digest,
                "query_count": observer.query_count,
            }
        ):
            raise UntraversableError(
                "observer state proposition must bind the exact observer coordinate and initial facts"
            )

        raw_interfaces = data["interfaces"]
        if type(raw_interfaces) is not list or len(raw_interfaces) > MAX_INTERFACES:
            raise UntraversableError("interfaces must be an array within the structural bound")
        interfaces: list[HigherOrderComplexityInterface] = []
        for index, item in enumerate(raw_interfaces):
            row = _object(
                item,
                {
                    "interface_id",
                    "mode",
                    "abstraction_mechanism_id",
                    "source_artifact_ids",
                    "exposed_fact_ids",
                    "control_signal_fact_ids",
                    "required_capability_ids",
                    "coverage_proposition",
                },
                f"interfaces[{index}]",
            )
            try:
                interface_mode = TraversalMode(row["mode"])
            except (TypeError, ValueError) as exc:
                raise UntraversableError("unsupported interface traversal mode") from exc
            interface = HigherOrderComplexityInterface(
                _text(row["interface_id"], "interface_id"),
                interface_mode,
                _text(row["abstraction_mechanism_id"], "abstraction_mechanism_id"),
                _strings(
                    row["source_artifact_ids"],
                    "interface.source_artifact_ids",
                ),
                _strings(row["exposed_fact_ids"], "exposed_fact_ids"),
                _strings(row["control_signal_fact_ids"], "control_signal_fact_ids"),
                _strings(row["required_capability_ids"], "required_capability_ids"),
                _proposition(row["coverage_proposition"], "coverage_proposition"),
            )
            expected_channels = [item.value for item in DisclosureChannel]
            if (
                interface.mode is not mode
                or
                interface.coverage_proposition.subject_id != interface.interface_id
                or interface.coverage_proposition.predicate
                != "interface_disclosure_channels_complete"
                or interface.coverage_proposition.expected
                != {
                    "covered_channels": expected_channels,
                    "exposed_facts": [
                        facts_by_id[item].to_dict()
                        for item in interface.exposed_fact_ids
                    ],
                    "graph_digest": data["graph_digest"],
                    "interface": interface.skeleton(),
                }
            ):
                raise UntraversableError(
                    "coverage proposition must bind this mode-specific interface and every modeled disclosure channel"
                )
            if not set(interface.control_signal_fact_ids) <= set(interface.exposed_fact_ids):
                raise UntraversableError("control signals must be exposed facts")
            if not set(interface.exposed_fact_ids) <= fact_ids:
                raise UntraversableError("interface references an unknown fact")
            interfaces.append(interface)
        interfaces.sort(key=lambda item: item.interface_id)
        interface_ids = {item.interface_id for item in interfaces}
        if len(interface_ids) != len(interfaces):
            raise UntraversableError("duplicate interface_id")
        if not set(observer.accessible_interface_ids) <= interface_ids:
            raise UntraversableError("observer references an unknown interface")
        raw_edges = data["knowledge_hyperedges"]
        if type(raw_edges) is not list or len(raw_edges) > MAX_HYPEREDGES:
            raise UntraversableError(
                "knowledge_hyperedges must be an array within the structural bound"
            )
        edges: list[KnowledgeHyperedge] = []
        proposition_count = 0
        for index, item in enumerate(raw_edges):
            row = _object(
                item,
                {
                    "hyperedge_id",
                    "mode",
                    "required_fact_ids",
                    "produced_fact_ids",
                    "relation_id",
                    "transformation_id",
                    "required_capability_ids",
                    "activation_propositions",
                },
                f"knowledge_hyperedges[{index}]",
            )
            raw_activation = row["activation_propositions"]
            if type(raw_activation) is not list or not raw_activation:
                raise UntraversableError("activation_propositions must be a nonempty array")
            propositions = tuple(
                _proposition(entry, "activation_proposition")
                for entry in raw_activation
            )
            proposition_count += len(propositions)
            edge_id = _text(row["hyperedge_id"], "hyperedge_id")
            try:
                edge_mode = TraversalMode(row["mode"])
            except (TypeError, ValueError) as exc:
                raise UntraversableError("unsupported hyperedge traversal mode") from exc
            transformation_id = row["transformation_id"]
            if transformation_id is not None:
                transformation_id = _text(transformation_id, "transformation_id")
            edge = KnowledgeHyperedge(
                edge_id,
                edge_mode,
                _strings(row["required_fact_ids"], "required_fact_ids", allow_empty=False),
                _strings(row["produced_fact_ids"], "produced_fact_ids", allow_empty=False),
                _text(row["relation_id"], "relation_id"),
                transformation_id,
                _strings(row["required_capability_ids"], "required_capability_ids"),
                tuple(sorted(propositions, key=lambda item: item.digest())),
            )
            for binding in propositions:
                expected = binding.expected
                if (
                    edge.mode is not mode
                    or binding.subject_id != edge_id
                    or binding.predicate != "knowledge_hyperedge_active"
                    or not isinstance(expected, Mapping)
                    or set(expected)
                    != {
                        "active",
                        "graph_digest",
                        "hyperedge",
                        "produced_facts",
                        "required_facts",
                    }
                    or type(expected["active"]) is not bool
                    or expected["graph_digest"] != data["graph_digest"]
                    or expected["hyperedge"] != edge.skeleton()
                    or expected["required_facts"]
                    != [facts_by_id[item].to_dict() for item in edge.required_fact_ids]
                    or expected["produced_facts"]
                    != [facts_by_id[item].to_dict() for item in edge.produced_fact_ids]
                ):
                    raise UntraversableError(
                        "activation proposition must bind this mode-specific hyperedge and exact active state"
                    )
            if not set(edge.required_fact_ids + edge.produced_fact_ids) <= fact_ids:
                raise UntraversableError("knowledge hyperedge references an unknown fact")
            edges.append(edge)
        edges.sort(key=lambda item: item.hyperedge_id)
        if len({item.hyperedge_id for item in edges}) != len(edges):
            raise UntraversableError("duplicate hyperedge_id")
        if proposition_count > MAX_PROPOSITIONS:
            raise UntraversableError("activation proposition structural bound exceeded")

        protected = _strings(
            data["protected_fact_ids"], "protected_fact_ids", allow_empty=False
        )
        if not set(protected) <= fact_ids:
            raise UntraversableError("protected_fact_ids references an unknown fact")
        completeness = _proposition(
            data["rule_set_completeness"], "rule_set_completeness"
        )
        contract_id = _text(data["contract_id"], "contract_id")
        model = {
            "graph_digest": data["graph_digest"],
            "mode": mode.value,
            "protected_fact_ids": list(protected),
            "facts": [item.to_dict() for item in facts],
            "interfaces": [item.skeleton() for item in interfaces],
            "knowledge_hyperedges": [item.skeleton() for item in edges],
        }
        if (
            completeness.subject_id != contract_id
            or completeness.predicate != "knowledge_rule_set_complete"
            or completeness.expected != {"complete": True, "model": model}
        ):
            raise UntraversableError(
                "rule-set completeness proposition must bind the exact modeled rule set to true"
            )

        limits_data = _object(
            data["resource_limits"],
            {
                "max_fact_count",
                "max_hyperedge_count",
                "max_rule_firings",
                "max_hyperpath_depth",
                "max_query_count",
                "max_evidence_items",
                "max_evidence_bytes",
            },
            "resource_limits",
        )
        limits = TraversalResourceCoordinate(
            _limit(limits_data["max_fact_count"], "max_fact_count", MAX_FACTS),
            _limit(limits_data["max_hyperedge_count"], "max_hyperedge_count", MAX_HYPEREDGES),
            _limit(limits_data["max_rule_firings"], "max_rule_firings", MAX_HYPEREDGES),
            _limit(limits_data["max_hyperpath_depth"], "max_hyperpath_depth", MAX_HYPEREDGES),
            _limit(limits_data["max_query_count"], "max_query_count", MAX_PROPOSITIONS * 16),
            _limit(limits_data["max_evidence_items"], "max_evidence_items", MAX_PROPOSITIONS * 16),
            _limit(limits_data["max_evidence_bytes"], "max_evidence_bytes", MAX_DOCUMENT_BYTES * 16),
        )
        return cls(
            data["schema_version"],
            contract_id,
            _digest_text(data["graph_digest"], "graph_digest"),
            _text(data["semantics_id"], "semantics_id"),
            mode,
            observation_interval,
            observer,
            protected,
            tuple(facts),
            tuple(interfaces),
            tuple(edges),
            completeness,
            limits,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "contract_id": self.contract_id,
            "graph_digest": self.graph_digest,
            "semantics_id": self.semantics_id,
            "mode": self.mode.value,
            "observation_interval": self.observation_interval.to_dict(),
            "observer": self.observer.to_dict(),
            "protected_fact_ids": list(self.protected_fact_ids),
            "facts": [item.to_dict() for item in self.facts],
            "interfaces": [item.to_dict() for item in self.interfaces],
            "knowledge_hyperedges": [item.to_dict() for item in self.knowledge_hyperedges],
            "rule_set_completeness": self.rule_set_completeness.to_dict(),
            "resource_limits": self.resource_limits.to_dict(),
        }

    def digest(self) -> str:
        """Return the SHA-256 digest of canonical contract bytes."""

        return _digest(self.to_dict())


@dataclass(frozen=True)
class UntraversabilityReport:
    """Canonical retained report bytes; native output is not self-authenticating."""

    _document: bytes

    def to_dict(self) -> dict[str, Any]:
        value = json.loads(self._document)
        if type(value) is not dict:  # Defensive: only _report constructs instances.
            raise UntraversableError("stored report is not an object")
        return value

    @property
    def contract_digest(self) -> str:
        return str(self.to_dict()["contract_digest"])

    @property
    def observer_coordinate_digest(self) -> str:
        return str(self.to_dict()["observer_coordinate_digest"])

    @property
    def mode(self) -> TraversalMode:
        return TraversalMode(self.to_dict()["mode"])

    @property
    def status(self) -> UntraversabilityStatus:
        return UntraversabilityStatus(self.to_dict()["status"])

    @property
    def reached_fact_ids(self) -> tuple[str, ...]:
        return tuple(self.to_dict()["reached_fact_ids"])

    @property
    def witnesses(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(self.to_dict()["witnesses"])

    @property
    def conflicted_hyperedge_ids(self) -> tuple[str, ...]:
        return tuple(self.to_dict()["conflicted_hyperedge_ids"])

    @property
    def resource_exhausted(self) -> bool:
        return bool(self.to_dict()["resource_exhausted"])


def _evaluate_once(
    session: VerificationSession,
    bindings: Sequence[BoundProposition],
) -> tuple[dict[str, EvaluatedProposition], int, int]:
    evaluations: dict[str, EvaluatedProposition] = {}
    evidence_refs: set[str] = set()
    evidence_bytes = 0
    for binding in bindings:
        digest = binding.digest()
        if digest in evaluations:
            continue
        evaluation = session.evaluate(binding)
        evaluations[digest] = evaluation
        evidence_refs.update(evaluation.evidence_refs)
        evidence_bytes += evaluation.observed_evidence_bytes
    return evaluations, len(evidence_refs), evidence_bytes


def _evidence_preflight(
    session: VerificationSession,
    bindings: Sequence[BoundProposition],
    limits: TraversalResourceCoordinate,
) -> tuple[bool, bool, str]:
    references = sorted(
        {reference for binding in bindings for reference in binding.evidence_refs}
    )
    if len(references) > limits.max_evidence_items:
        return False, True, "The aggregate evidence-item bound was exhausted."
    observed_bytes = 0
    for reference in references:
        try:
            payload = session.evidence.resolve(reference)
        except (TypeError, ValueError) as exc:
            return False, False, f"Evidence preflight is unresolved: {exc}"
        observed_bytes += len(payload)
        if observed_bytes > limits.max_evidence_bytes:
            return False, True, "The aggregate evidence-byte bound was exhausted."
    return True, False, ""


def _asserted_state(
    bindings: Sequence[BoundProposition],
    evaluations: Mapping[str, EvaluatedProposition],
) -> tuple[bool | None, bool]:
    active_support = inactive_support = unresolved = False
    for binding in bindings:
        outcome = evaluations[binding.digest()].outcome
        if outcome is not MechanismOutcome.PASS:
            unresolved = True
            continue
        asserted_active = binding.expected["active"]
        active_support |= asserted_active is True
        inactive_support |= asserted_active is False
    if active_support and inactive_support:
        return None, True
    if active_support:
        return True, False
    if inactive_support and not unresolved:
        return False, False
    return None, False


def _relevant_edges(
    protected: Sequence[str], edges: Sequence[KnowledgeHyperedge]
) -> tuple[KnowledgeHyperedge, ...]:
    needed = set(protected)
    selected: set[str] = set()
    changed = True
    while changed:
        changed = False
        for edge in reversed(edges):
            if edge.hyperedge_id in selected or not (set(edge.produced_fact_ids) & needed):
                continue
            selected.add(edge.hyperedge_id)
            needed.update(edge.required_fact_ids)
            changed = True
    return tuple(item for item in edges if item.hyperedge_id in selected)


def _goal_distances(
    protected: Sequence[str], edges: Sequence[KnowledgeHyperedge]
) -> dict[str, int]:
    """Return a deterministic backward hop heuristic for bounded leak search."""

    distances = {fact_id: 0 for fact_id in protected}
    changed = True
    while changed:
        changed = False
        for edge in reversed(edges):
            produced_distances = [
                distances[item]
                for item in edge.produced_fact_ids
                if item in distances
            ]
            if not produced_distances:
                continue
            required_distance = 1 + min(produced_distances)
            for fact_id in edge.required_fact_ids:
                previous = distances.get(fact_id)
                if previous is None or required_distance < previous:
                    distances[fact_id] = required_distance
                    changed = True
    return distances


@dataclass(frozen=True)
class _SeedOrigin:
    source_kind: str
    source_id: str
    evaluation_digest: str


@dataclass(frozen=True)
class _EdgeOrigin:
    hyperedge_id: str
    required_fact_ids: tuple[str, ...]


def _witness(
    protected_fact_id: str,
    origins: Mapping[str, _SeedOrigin | _EdgeOrigin],
    edge_by_id: Mapping[str, KnowledgeHyperedge],
    evaluations: Mapping[str, EvaluatedProposition],
    contract: UntraversableContract,
    graph_digest: str,
    fact_depth: Mapping[str, int],
    graph: ProvenanceHypergraph,
) -> Mapping[str, Any]:
    facts_by_id = {fact.fact_id: fact for fact in contract.facts}
    edge_steps: dict[str, tuple[tuple[str, ...], set[str]]] = {}
    initial: set[str] = set()
    seed_origins: dict[str, _SeedOrigin] = {}
    pending = [protected_fact_id]
    seen: set[str] = set()
    while pending:
        fact_id = pending.pop()
        if fact_id in seen:
            continue
        seen.add(fact_id)
        origin = origins.get(fact_id)
        if origin is None:
            raise UntraversableError("witness fact has no retained origin")
        if isinstance(origin, _SeedOrigin):
            initial.add(fact_id)
            seed_origins[fact_id] = origin
            continue
        edge_id = origin.hyperedge_id
        inputs = origin.required_fact_ids
        if edge_id not in edge_steps:
            edge_steps[edge_id] = (inputs, set())
        edge_steps[edge_id][1].add(fact_id)
        pending.extend(inputs)
    steps = []
    ordered_edges = sorted(
        edge_steps,
        key=lambda edge_id: (
            1 + max(fact_depth[item] for item in edge_steps[edge_id][0]),
            edge_id,
        ),
    )
    for edge_id in ordered_edges:
        edge = edge_by_id[edge_id]
        transformation_ports: Mapping[str, Any] | None = None
        if edge.transformation_id is not None:
            transformation = graph.transformations[edge.transformation_id]
            transformation_ports = {
                "transformation_id": edge.transformation_id,
                "inputs": [
                    {"artifact_id": port.artifact_id, "role": port.role}
                    for port in transformation.inputs
                ],
                "outputs": [
                    {"artifact_id": port.artifact_id, "role": port.role}
                    for port in transformation.outputs
                ],
            }
        steps.append(
            {
                "hyperedge_id": edge_id,
                "hyperedge": edge.skeleton(),
                "depth": 1
                + max(fact_depth[item] for item in edge_steps[edge_id][0]),
                "consumed_fact_ids": list(edge_steps[edge_id][0]),
                "produced_fact_ids": sorted(edge_steps[edge_id][1]),
                "activation_evaluation_digests": sorted(
                    _digest(evaluations[item.digest()].to_dict())
                    for item in edge.activation_propositions
                ),
                "transformation_ports": transformation_ports,
            }
        )
    body = {
        "contract_digest": contract.digest(),
        "graph_digest": graph_digest,
        "observer_coordinate_digest": _digest(contract.observer.to_dict()),
        "mode": contract.mode.value,
        "traversal_schedule": TRAVERSAL_SCHEDULE,
        "observation_interval": contract.observation_interval.to_dict(),
        "protected_fact_id": protected_fact_id,
        "initial_fact_ids": sorted(initial),
        "seed_origins": [
            {
                "fact_id": fact_id,
                "fact_binding_digest": _digest(facts_by_id[fact_id].to_dict()),
                "source_kind": seed_origins[fact_id].source_kind,
                "source_id": seed_origins[fact_id].source_id,
                "evaluation_digest": seed_origins[fact_id].evaluation_digest,
            }
            for fact_id in sorted(seed_origins)
        ],
        "steps": steps,
    }
    return {**body, "witness_digest": _digest(body)}


def _report(
    contract: UntraversableContract,
    graph_digest: str,
    status: UntraversabilityStatus,
    *,
    reached: Sequence[str] = (),
    witnesses: Sequence[Mapping[str, Any]] = (),
    unresolved: Sequence[str] = (),
    conflicted: Sequence[str] = (),
    resource_exhausted: bool = False,
    findings: Sequence[str],
) -> UntraversabilityReport:
    payload = {
        "schema_version": UNTRAVERSABLE_REPORT_SCHEMA_VERSION,
        "contract_digest": contract.digest(),
        "graph_digest": graph_digest,
        "observer_coordinate_digest": _digest(contract.observer.to_dict()),
        "analyzer_implementation_digest": implementation_file_digest(__file__),
        "mode": contract.mode.value,
        "traversal_schedule": TRAVERSAL_SCHEDULE,
        "accessible_interface_ids": list(contract.observer.accessible_interface_ids),
        "protected_fact_ids": list(contract.protected_fact_ids),
        "status": status.value,
        "reached_fact_ids": sorted(reached),
        "witnesses": list(witnesses),
        "unresolved_hyperedge_ids": sorted(unresolved),
        "conflicted_hyperedge_ids": sorted(conflicted),
        "resource_exhausted": resource_exhausted,
        "findings": list(findings),
        "verification_effect": "NONE",
    }
    return UntraversabilityReport(_json_bytes(payload))


def analyze_untraversability(
    graph: ProvenanceHypergraph,
    contract: UntraversableContract,
    session: VerificationSession,
) -> UntraversabilityReport:
    """Evaluate bounded observer-relative closure over the composed VSTD graph."""

    if not isinstance(contract, UntraversableContract):
        raise UntraversableError("contract must be an UntraversableContract")
    if not isinstance(session, VerificationSession):
        raise UntraversableError("session must be a VerificationSession")
    # Direct dataclass construction is not an admission path. Reparse the exact
    # public representation so analysis cannot bypass strict field validation.
    contract = UntraversableContract.from_dict(contract.to_dict())
    try:
        if not isinstance(graph, ProvenanceHypergraph):
            raise TypeError("graph must be a ProvenanceHypergraph")
        original_structure_errors = graph.validate_structure(
            allow_legacy_identifier_overlap=False
        )
        if original_structure_errors:
            raise ValueError("; ".join(original_structure_errors))
        snapshot_payload = graph.to_dict()
        snapshot = ProvenanceHypergraph.from_dict(
            snapshot_payload,
            allow_legacy_identifier_overlap=False,
        )
        structure_errors = snapshot.validate_structure(
            allow_legacy_identifier_overlap=False
        )
        if structure_errors:
            raise ValueError("; ".join(structure_errors))
        observed_graph_digest = graph_topology_binding_digest(snapshot)
    except (AttributeError, KeyError, TypeError, ValueError) as exc:
        raise UntraversableError("graph cannot be admitted and bound exactly") from exc
    if observed_graph_digest != contract.graph_digest:
        raise UntraversableError("graph digest substitution refused")
    artifact_ids = set(snapshot.artifacts)
    transformation_ids = set(snapshot.transformations)
    if any(not set(fact.source_artifact_ids) <= artifact_ids for fact in contract.facts):
        raise UntraversableError("fact source artifact is absent from the bound graph")
    facts_by_id = {fact.fact_id: fact for fact in contract.facts}
    for interface in contract.interfaces:
        expected_sources = {
            artifact_id
            for fact_id in interface.exposed_fact_ids
            for artifact_id in facts_by_id[fact_id].source_artifact_ids
        }
        if set(interface.source_artifact_ids) != expected_sources:
            raise UntraversableError(
                "interface source artifacts must exactly cover its exposed facts"
            )
        if not set(interface.source_artifact_ids) <= artifact_ids:
            raise UntraversableError(
                "interface source artifact is absent from the bound graph"
            )
    if any(
        edge.transformation_id is not None
        and edge.transformation_id not in transformation_ids
        for edge in contract.knowledge_hyperedges
    ):
        raise UntraversableError("knowledge hyperedge transformation is absent from the bound graph")
    for edge in contract.knowledge_hyperedges:
        if edge.transformation_id is None:
            continue
        transformation = snapshot.transformations[edge.transformation_id]
        input_ids = [port.artifact_id for port in transformation.inputs]
        output_ids = [port.artifact_id for port in transformation.outputs]
        if len(input_ids) != len(set(input_ids)) or len(output_ids) != len(
            set(output_ids)
        ):
            raise UntraversableError(
                "graph-backed knowledge hyperedges do not support repeated artifact ports"
            )
        required_sources = {
            artifact_id
            for fact_id in edge.required_fact_ids
            for artifact_id in facts_by_id[fact_id].source_artifact_ids
        }
        produced_sources = {
            artifact_id
            for fact_id in edge.produced_fact_ids
            for artifact_id in facts_by_id[fact_id].source_artifact_ids
        }
        if required_sources != set(input_ids) or produced_sources != set(output_ids):
            raise UntraversableError(
                "knowledge hyperedge fact sources must exactly match its transformation inputs and outputs"
            )
    if contract.semantics_id != SUPPORTED_SEMANTICS:
        return _report(
            contract,
            observed_graph_digest,
            UntraversabilityStatus.UNKNOWN,
            unresolved=tuple(
                item.hyperedge_id for item in contract.knowledge_hyperedges
            ),
            findings=(
                "The declared knowledge-closure semantics are unsupported.",
                "The result grants no verification, conformance, authorization, identity, intent, or universal confidentiality claim.",
            ),
        )

    relevant = _relevant_edges(contract.protected_fact_ids, contract.knowledge_hyperedges)
    accessible = tuple(
        item
        for item in contract.interfaces
        if item.interface_id in contract.observer.accessible_interface_ids
    )
    bindings = [contract.observer.state_proposition, contract.rule_set_completeness]
    bindings.extend(item.coverage_proposition for item in accessible)
    bindings.extend(
        proposition for edge in relevant for proposition in edge.activation_propositions
    )
    structural_exhausted = (
        len(contract.facts) > contract.resource_limits.max_fact_count
        or len(contract.knowledge_hyperedges)
        > contract.resource_limits.max_hyperedge_count
        or contract.observer.query_count > contract.resource_limits.max_query_count
    )
    if structural_exhausted:
        return _report(
            contract,
            observed_graph_digest,
            UntraversabilityStatus.UNKNOWN,
            unresolved=tuple(item.hyperedge_id for item in relevant),
            resource_exhausted=True,
            findings=(
                "A declared fact, hyperedge, query, or evidence resource bound was exhausted before mechanism execution.",
                "The result grants no verification, conformance, authorization, identity, intent, or universal confidentiality claim.",
            ),
        )
    evidence_ready, evidence_exhausted, evidence_detail = _evidence_preflight(
        session, bindings, contract.resource_limits
    )
    if not evidence_ready:
        return _report(
            contract,
            observed_graph_digest,
            UntraversabilityStatus.UNKNOWN,
            unresolved=tuple(item.hyperedge_id for item in relevant),
            resource_exhausted=evidence_exhausted,
            findings=(
                evidence_detail,
                "The result grants no verification, conformance, authorization, identity, intent, or universal confidentiality claim.",
            ),
        )
    evaluations, _, _ = _evaluate_once(session, bindings)

    observer_evaluation = evaluations[contract.observer.state_proposition.digest()]
    observer_unknown = observer_evaluation.outcome is not MechanismOutcome.PASS
    interface_coverage: dict[str, bool] = {}
    for interface in accessible:
        interface_coverage[interface.interface_id] = (
            evaluations[interface.coverage_proposition.digest()].outcome
            is MechanismOutcome.PASS
        )
    coverage_unknown = observer_unknown or not all(interface_coverage.values())

    reached: set[str] = set()
    origins: dict[str, _SeedOrigin | _EdgeOrigin] = {}
    if not observer_unknown:
        observer_evaluation_digest = _digest(observer_evaluation.to_dict())
        for fact_id in contract.observer.initial_fact_ids:
            reached.add(fact_id)
            origins[fact_id] = _SeedOrigin(
                "OBSERVER_STATE",
                contract.observer.observer_id,
                observer_evaluation_digest,
            )
        capabilities = set(contract.observer.capability_ids)
        for interface in accessible:
            if (
                interface_coverage[interface.interface_id]
                and set(interface.required_capability_ids) <= capabilities
            ):
                interface_evaluation = evaluations[
                    interface.coverage_proposition.digest()
                ]
                for fact_id in interface.exposed_fact_ids:
                    reached.add(fact_id)
                    origins.setdefault(
                        fact_id,
                        _SeedOrigin(
                            "INTERFACE_DISCLOSURE",
                            interface.interface_id,
                            _digest(interface_evaluation.to_dict()),
                        ),
                    )
    else:
        capabilities = set(contract.observer.capability_ids)

    active_edges: list[KnowledgeHyperedge] = []
    unresolved: list[str] = []
    conflicted: list[str] = []
    for edge in relevant:
        state, conflict = _asserted_state(edge.activation_propositions, evaluations)
        if conflict:
            conflicted.append(edge.hyperedge_id)
        elif state is True:
            active_edges.append(edge)
        elif state is None:
            unresolved.append(edge.hyperedge_id)

    firings = 0
    depth: dict[str, int] = {item: 0 for item in reached}
    depth_exhausted = False
    firing_exhausted = False
    usable_active_edges = tuple(
        edge
        for edge in active_edges
        if set(edge.required_capability_ids) <= capabilities
    )
    goal_distances = _goal_distances(
        contract.protected_fact_ids, usable_active_edges
    )
    while not firing_exhausted:
        candidates: list[tuple[int, int, str, KnowledgeHyperedge]] = []
        for edge in usable_active_edges:
            if not set(edge.required_fact_ids) <= reached:
                continue
            new_facts = [item for item in edge.produced_fact_ids if item not in reached]
            if not new_facts:
                continue
            next_depth = 1 + max(depth[item] for item in edge.required_fact_ids)
            if next_depth > contract.resource_limits.max_hyperpath_depth:
                depth_exhausted = True
                continue
            distance_to_goal = min(
                (
                    goal_distances[item]
                    for item in edge.produced_fact_ids
                    if item in goal_distances
                ),
                default=MAX_HYPEREDGES + 1,
            )
            candidates.append(
                (distance_to_goal, next_depth, edge.hyperedge_id, edge)
            )
        if not candidates:
            break
        progressed = False
        for _, _, _, edge in sorted(candidates):
            if not set(edge.required_fact_ids) <= reached:
                continue
            new_facts = [item for item in edge.produced_fact_ids if item not in reached]
            if not new_facts:
                continue
            next_depth = 1 + max(depth[item] for item in edge.required_fact_ids)
            if next_depth > contract.resource_limits.max_hyperpath_depth:
                depth_exhausted = True
                continue
            if firings >= contract.resource_limits.max_rule_firings:
                firing_exhausted = True
                break
            firings += 1
            for fact_id in new_facts:
                reached.add(fact_id)
                depth[fact_id] = next_depth
                origins[fact_id] = _EdgeOrigin(
                    edge.hyperedge_id, edge.required_fact_ids
                )
            progressed = True
        if not progressed:
            break

    protected_reached = sorted(set(contract.protected_fact_ids) & reached)
    edge_by_id = {edge.hyperedge_id: edge for edge in active_edges}
    witnesses = tuple(
        _witness(
            item,
            origins,
            edge_by_id,
            evaluations,
            contract,
            observed_graph_digest,
            depth,
            snapshot,
        )
        for item in protected_reached
    )
    search_exhausted = depth_exhausted or firing_exhausted
    completeness = evaluations[contract.rule_set_completeness.digest()].outcome
    findings: list[str] = []
    if protected_reached:
        status = UntraversabilityStatus.FAIL
        findings.append("A complete evidence-supported hyperpath reached protected knowledge.")
    elif conflicted:
        status = UntraversabilityStatus.CONFLICTED
        findings.append("Target-relevant inference-rule evidence is incompatible.")
    elif coverage_unknown or unresolved or completeness is not MechanismOutcome.PASS:
        status = UntraversabilityStatus.UNKNOWN
        findings.append("Observer, disclosure, inference-rule, or completeness evidence is unresolved.")
    elif search_exhausted:
        status = UntraversabilityStatus.UNKNOWN
        findings.append("A declared traversal or evidence resource bound was exhausted.")
    else:
        status = UntraversabilityStatus.MATCH
        findings.append(
            "Complete bounded closure of the declared model did not reach protected knowledge."
        )
    findings.append(
        "The result grants no verification, conformance, authorization, identity, intent, or universal confidentiality claim."
    )
    return _report(
        contract,
        observed_graph_digest,
        status,
        reached=tuple(reached),
        witnesses=witnesses,
        unresolved=unresolved,
        conflicted=conflicted,
        resource_exhausted=search_exhausted,
        findings=findings,
    )


__all__ = [
    "DisclosureChannel",
    "FactBinding",
    "HigherOrderComplexityInterface",
    "KnowledgeHyperedge",
    "ObservationInterval",
    "ObservationUnit",
    "ObserverCoordinate",
    "SUPPORTED_SEMANTICS",
    "TRAVERSAL_SCHEDULE",
    "TraversalMode",
    "TraversalResourceCoordinate",
    "UNTRAVERSABLE_REPORT_SCHEMA_VERSION",
    "UNTRAVERSABLE_SCHEMA_VERSION",
    "UntraversabilityReport",
    "UntraversabilityStatus",
    "UntraversableContract",
    "UntraversableError",
    "analyze_untraversability",
]
