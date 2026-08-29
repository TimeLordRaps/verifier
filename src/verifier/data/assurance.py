"""Terminology: Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD).

Executable VSTD-Graph artifact-state propagation.

``TRUST`` is mechanism-earned forward artifact support. ``RUST`` is reverse
diagnostic traversal from a verified descendant deviation toward recorded
ancestors. ``ROT`` is typed degradation of current admissibility without
rewriting historical graph bytes.  These names are formal semantic terms, not
acronyms, scalar scores, actor reputation, or references to the Rust language.

The ledger is additive and hash chained.  It can project a challenge ledger into
a current Graph view, preserve conflict resolutions as new records, deduplicate
support and reachability, compute structural RUST concentration, and perform
bounded artifact-relative diagnostic attribution.  RUST reachability alone
never establishes falsity, causality, blame, guilt, or responsibility.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from enum import Enum
from typing import Any, Iterable, Mapping, Optional

from verifier.core.certificate import canonical_bytes, canonical_digest
from verifier.core.evidence import (
    BoundProposition,
    EvidenceBounds,
    EvidenceStore,
    EvaluatedProposition,
    MechanismDecision,
    MechanismOutcome,
    VerificationMechanism,
    VerificationSession,
    implementation_file_digest,
)
from verifier.layer4.challenge import (
    ChallengeLedger,
    ChallengeOutcome,
    DEGRADATION_ORDER,
    most_degraded,
)

from .models import ArtifactStatus, ConflictRecord, ProvenanceHypergraph


class AssuranceFlowError(ValueError):
    """A requested propagation would exceed recorded topology or evidence."""


class AssuranceEventKind(str, Enum):
    TRUST = "TRUST"
    ROT = "ROT"
    RUST = "RUST"
    STATUS_PROJECTION = "STATUS_PROJECTION"
    CONFLICT_DECLARATION = "CONFLICT_DECLARATION"
    CONFLICT_RESOLUTION = "CONFLICT_RESOLUTION"
    CAUSAL_LOCALIZATION = "CAUSAL_LOCALIZATION"
    DIAGNOSTIC_ATTRIBUTION = "DIAGNOSTIC_ATTRIBUTION"


class DiagnosticKind(str, Enum):
    BLAME = "BLAME"
    GUILT = "GUILT"


class ChallengeProjectionMechanism:
    """Recompute one artifact's status from embedded challenge-ledger records."""

    mechanism_id = "vstd.challenge-ledger.projection"
    mechanism_digest = implementation_file_digest(__file__)

    def evaluate(
        self, binding: BoundProposition, evidence: tuple[bytes, ...]
    ) -> MechanismDecision:
        if binding.predicate != "vstd.graph.current_status":
            return MechanismDecision(
                MechanismOutcome.UNKNOWN,
                "this mechanism checks one projected challenge-ledger status",
            )
        try:
            records = [json.loads(payload.decode("utf-8")) for payload in evidence]
            status, details = _status_from_challenge_records(
                binding.subject_id, records
            )
        except (KeyError, TypeError, ValueError, UnicodeError, json.JSONDecodeError) as exc:
            return MechanismDecision(
                MechanismOutcome.FAIL,
                f"challenge-ledger projection evidence is invalid: {exc}",
            )
        expected = ArtifactStatus(str(binding.expected))
        return MechanismDecision(
            MechanismOutcome.PASS if status is expected else MechanismOutcome.FAIL,
            details,
            {"observed_status": status.value},
        )


def _status_from_challenge_records(
    subject_id: str, records: Iterable[Mapping[str, Any]]
) -> tuple[ArtifactStatus, str]:
    """Independent projection over serialized records; no mutable ledger state."""

    ordered = sorted(records, key=lambda item: int(item["sequence"]))
    if len({int(item["sequence"]) for item in ordered}) != len(ordered):
        raise ValueError("challenge records repeat a sequence number")
    filed: dict[str, ArtifactStatus] = {}
    outcomes: dict[str, ChallengeOutcome] = {}
    for record in ordered:
        if str(record["claim_id"]) != subject_id:
            raise ValueError("challenge record targets a neighboring artifact")
        kind = str(record["kind"])
        payload = record["payload"]
        if not isinstance(payload, Mapping):
            raise ValueError("challenge record payload is not an object")
        if kind == "REFUSED":
            continue
        if kind == "FILED":
            challenge = payload["challenge"]
            admission = payload["admission"]
            if not isinstance(challenge, Mapping) or not isinstance(admission, Mapping):
                raise ValueError("filed challenge record is malformed")
            challenge_id = str(challenge["challenge_id"])
            if challenge_id in filed:
                raise ValueError("challenge identifier is repeated")
            if not bool(admission["admitted"]):
                raise ValueError("a FILED record carries a refused admission")
            filed[challenge_id] = ArtifactStatus(
                str(admission.get("resulting_status", ArtifactStatus.REVOKED.value))
            )
            continue
        if kind == "ADJUDICATED":
            adjudication = payload["adjudication"]
            if not isinstance(adjudication, Mapping):
                raise ValueError("adjudication record is malformed")
            challenge_id = str(adjudication["challenge_id"])
            if challenge_id not in filed:
                raise ValueError("adjudication precedes its filed challenge")
            if challenge_id in outcomes:
                raise ValueError("challenge has multiple adjudications")
            outcomes[challenge_id] = ChallengeOutcome(str(adjudication["outcome"]))
            continue
        raise ValueError(f"unknown challenge record kind {kind!r}")

    confirmed = tuple(
        sorted(
            challenge_id
            for challenge_id, outcome in outcomes.items()
            if outcome is ChallengeOutcome.ACCEPTED
        )
    )
    open_ids = tuple(
        sorted(
            challenge_id
            for challenge_id in filed
            if outcomes.get(challenge_id)
            in (None, ChallengeOutcome.UNRESOLVED)
        )
    )
    if confirmed:
        return (
            most_degraded(filed[challenge_id] for challenge_id in confirmed),
            f"{len(confirmed)} confirmed refutation(s); status is terminal",
        )
    if open_ids:
        return (
            ArtifactStatus.CHALLENGED,
            f"{len(open_ids)} open credible challenge(s); an unadjudicated "
            "challenge is not evidence of validity",
        )
    if filed:
        return (
            ArtifactStatus.VALID,
            f"all {len(filed)} challenge(s) adjudicated and disproven",
        )
    return ArtifactStatus.VALID, "no challenges filed"


@dataclass(frozen=True)
class AssuranceEvent:
    sequence: int
    kind: AssuranceEventKind
    subject_id: str
    source_ids: tuple[str, ...]
    proposition: str
    binding: Mapping[str, Any]
    recorded_at: str
    outcome: MechanismOutcome
    mechanism_id: str
    mechanism_digest: str
    evidence_refs: tuple[str, ...]
    evidence_payloads: Mapping[str, str]
    trust_roots: tuple[str, ...]
    details: str
    previous_event_digest: str = ""
    attributes: Mapping[str, Any] = field(default_factory=dict)

    def payload(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "kind": self.kind.value,
            "subject_id": self.subject_id,
            "source_ids": list(self.source_ids),
            "proposition": self.proposition,
            "binding": dict(self.binding),
            "recorded_at": self.recorded_at,
            "outcome": self.outcome.value,
            "mechanism_id": self.mechanism_id,
            "mechanism_digest": self.mechanism_digest,
            "evidence_refs": list(self.evidence_refs),
            "evidence_payloads": dict(self.evidence_payloads),
            "trust_roots": list(self.trust_roots),
            "details": self.details,
            "previous_event_digest": self.previous_event_digest,
            "attributes": dict(self.attributes),
        }

    def digest(self) -> str:
        return canonical_digest(self.payload())

    def to_dict(self) -> dict[str, Any]:
        result = self.payload()
        result["event_digest"] = self.digest()
        return result


@dataclass(frozen=True)
class ConflictResolution:
    resolution_id: str
    conflict_id: str
    selected_value: str
    recorded_at: str
    evaluation: EvaluatedProposition

    def to_dict(self) -> dict[str, Any]:
        return {
            "resolution_id": self.resolution_id,
            "conflict_id": self.conflict_id,
            "selected_value": self.selected_value,
            "recorded_at": self.recorded_at,
            "evaluation": self.evaluation.to_dict(),
        }


@dataclass(frozen=True)
class StructuralConcentration:
    ancestor_id: str
    deviating_descendants: tuple[str, ...]

    @property
    def count(self) -> int:
        return len(self.deviating_descendants)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ancestor_id": self.ancestor_id,
            "deviating_descendants": list(self.deviating_descendants),
            "count": self.count,
            "meaning": "unique diagnostic reachability roots; not causal strength",
        }


@dataclass(frozen=True)
class DiagnosticAttribution:
    kind: DiagnosticKind
    ancestor_id: str
    descendant_id: str
    status: str
    localization_event_digest: str
    evaluation: Optional[EvaluatedProposition]
    details: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "ancestor_id": self.ancestor_id,
            "descendant_id": self.descendant_id,
            "status": self.status,
            "localization_event_digest": self.localization_event_digest,
            "evaluation": None if self.evaluation is None else self.evaluation.to_dict(),
            "details": self.details,
        }


class AssuranceLedger:
    """Append-only current-state overlay for an immutable provenance graph."""

    FORMAT = "VSTD-GRAPH-ASSURANCE-1"

    def __init__(self, graph: ProvenanceHypergraph) -> None:
        errors = graph.validate_structure()
        if errors:
            raise AssuranceFlowError("invalid source graph: " + "; ".join(errors))
        if not graph.verify_acyclicity():
            raise AssuranceFlowError(
                "cyclic provenance cannot carry recursive assurance propagation"
            )
        self.graph = ProvenanceHypergraph.from_dict(graph.to_dict())
        self._graph_digest = canonical_digest(self.graph.to_dict())
        self._events: list[AssuranceEvent] = []
        self._conflicts: dict[str, ConflictRecord] = dict(self.graph.conflicts)
        self._resolutions: dict[str, ConflictResolution] = {}

    @property
    def graph_digest(self) -> str:
        return self._graph_digest

    def events(self) -> tuple[AssuranceEvent, ...]:
        return tuple(self._events)

    def resolutions(self) -> tuple[ConflictResolution, ...]:
        return tuple(self._resolutions.values())

    def _append(
        self,
        *,
        kind: AssuranceEventKind,
        subject_id: str,
        source_ids: Iterable[str],
        proposition: str,
        binding: Mapping[str, Any],
        recorded_at: str,
        evaluation: EvaluatedProposition,
        evidence_payloads: Mapping[str, str],
        attributes: Optional[Mapping[str, Any]] = None,
    ) -> AssuranceEvent:
        sources = tuple(sorted(set(source_ids)))
        semantic_key = (
            kind.value,
            subject_id,
            sources,
            proposition,
            evaluation.binding_digest,
            tuple(sorted((attributes or {}).items())),
        )
        for event in self._events:
            other_key = (
                event.kind.value,
                event.subject_id,
                event.source_ids,
                event.proposition,
                event.attributes.get("binding_digest", ""),
                tuple(sorted((k, v) for k, v in event.attributes.items() if k != "binding_digest")),
            )
            if semantic_key == other_key:
                return event
        previous = "" if not self._events else self._events[-1].digest()
        combined_attributes = dict(attributes or {})
        combined_attributes["binding_digest"] = evaluation.binding_digest
        event = AssuranceEvent(
            len(self._events),
            kind,
            subject_id,
            sources,
            proposition,
            dict(binding),
            recorded_at,
            evaluation.outcome,
            evaluation.mechanism_id,
            evaluation.mechanism_digest,
            evaluation.evidence_refs,
            dict(evidence_payloads),
            evaluation.trust_roots,
            evaluation.details,
            previous,
            combined_attributes,
        )
        self._events.append(event)
        return event

    def current_status(self, artifact_id: str) -> ArtifactStatus:
        node = self.graph.artifacts.get(artifact_id)
        if node is None:
            return ArtifactStatus.UNKNOWN
        latest_projection: Optional[ArtifactStatus] = None
        rot_statuses: list[ArtifactStatus] = []
        for event in self._events:
            if event.subject_id != artifact_id or event.outcome is not MechanismOutcome.PASS:
                continue
            if event.kind is AssuranceEventKind.STATUS_PROJECTION:
                candidate = event.attributes.get("resulting_status")
                if candidate is not None:
                    latest_projection = ArtifactStatus(str(candidate))
            elif event.kind is AssuranceEventKind.ROT:
                candidate = event.attributes.get("resulting_status")
                if candidate is not None:
                    rot_statuses.append(ArtifactStatus(str(candidate)))
        statuses = [node.status, *rot_statuses]
        if latest_projection is not None:
            statuses.append(latest_projection)
        return most_degraded(statuses)

    def impacted_descendants(self, artifact_id: str) -> tuple[str, ...]:
        """Return the deduplicated recorded forward impact set, not a verdict."""
        if artifact_id not in self.graph.artifacts:
            raise AssuranceFlowError(f"unknown impact origin {artifact_id}")
        return tuple(sorted(self.graph.descendants((artifact_id,)) - {artifact_id}))

    def current_trust_events(self) -> tuple[AssuranceEvent, ...]:
        """Return recursively current edge-local TRUST records."""
        if canonical_digest(self.graph.to_dict()) != self.graph_digest:
            return ()
        unresolved_subjects = {item.subject_id for item in self.unresolved_conflicts()}
        trust_events = {
            event.digest(): event
            for event in self._events
            if event.kind is AssuranceEventKind.TRUST
        }
        memo: dict[str, bool] = {}

        def is_current(event_digest: str, visiting: set[str]) -> bool:
            cached = memo.get(event_digest)
            if cached is not None:
                return cached
            if event_digest in visiting:
                memo[event_digest] = False
                return False
            event = trust_events.get(event_digest)
            if event is None or event.outcome is not MechanismOutcome.PASS:
                memo[event_digest] = False
                return False
            visiting.add(event_digest)
            try:
                transformation_id = str(event.attributes["transformation_id"])
                historical_graph_digest = str(
                    event.attributes["historical_graph_digest"]
                )
                attribute_inputs = tuple(str(item) for item in event.attributes["inputs"])
                attribute_output = str(event.attributes["output"])
                prerequisite_digests = tuple(
                    str(item)
                    for item in event.attributes["prerequisite_trust_event_digests"]
                )
                transform = self.graph.transformations[transformation_id]
            except (KeyError, TypeError):
                memo[event_digest] = False
                return False

            exact_inputs = tuple(sorted({port.artifact_id for port in transform.inputs}))
            output_ids = {port.artifact_id for port in transform.outputs}
            expected = {
                "historical_graph_digest": self.graph_digest,
                "inputs": list(exact_inputs),
                "output": event.subject_id,
                "prerequisite_trust_event_digests": list(prerequisite_digests),
                "transformation_id": transformation_id,
            }
            required_prerequisite_targets = {
                source
                for source in exact_inputs
                if self.graph.incoming_hyperedges(source)
            }
            prerequisite_targets: list[str] = []
            valid = (
                historical_graph_digest == self.graph_digest
                and attribute_inputs == exact_inputs
                and attribute_output == event.subject_id
                and event.source_ids == exact_inputs
                and event.subject_id in output_ids
                and transform.status == "COMPLETED"
                and event.subject_id not in unresolved_subjects
                and transformation_id not in unresolved_subjects
                and all(source not in unresolved_subjects for source in exact_inputs)
                and self.current_status(event.subject_id) is ArtifactStatus.VALID
                and all(
                    self.current_status(source) is ArtifactStatus.VALID
                    for source in exact_inputs
                )
                and event.binding.get("subject_id") == event.subject_id
                and event.binding.get("predicate") == "vstd.graph.support"
                and event.binding.get("expected") == expected
                and len(set(prerequisite_digests)) == len(prerequisite_digests)
            )
            if valid:
                for prerequisite_digest in prerequisite_digests:
                    prerequisite = trust_events.get(prerequisite_digest)
                    if (
                        prerequisite is None
                        or prerequisite.sequence >= event.sequence
                        or not is_current(prerequisite_digest, visiting)
                    ):
                        valid = False
                        break
                    prerequisite_targets.append(prerequisite.subject_id)
            if valid:
                valid = (
                    len(prerequisite_targets) == len(required_prerequisite_targets)
                    and set(prerequisite_targets) == required_prerequisite_targets
                )
            memo[event_digest] = valid
            return valid

        return tuple(
            event
            for event_digest, event in trust_events.items()
            if is_current(event_digest, set())
        )

    def unresolved_conflicts(self) -> tuple[ConflictRecord, ...]:
        resolved = {item.conflict_id for item in self._resolutions.values()}
        return tuple(
            conflict
            for conflict_id, conflict in self._conflicts.items()
            if conflict_id not in resolved
        )

    def materialize_current_graph(self) -> ProvenanceHypergraph:
        """Create a derived current view; never mutate the historical graph."""
        current = ProvenanceHypergraph.from_dict(self.graph.to_dict())
        for conflict_id, conflict in self._conflicts.items():
            if conflict_id not in current.conflicts:
                current.add_conflict(conflict)
        for artifact_id, node in tuple(current.artifacts.items()):
            current.artifacts[artifact_id] = replace(
                node, status=self.current_status(artifact_id)
            )
        resolved = {item.conflict_id for item in self._resolutions.values()}
        for conflict_id in resolved:
            current.conflicts.pop(conflict_id, None)
        return current

    def project_challenges(
        self,
        challenges: ChallengeLedger,
        *,
        recorded_at: str,
    ) -> tuple[AssuranceEvent, ...]:
        """Project challenge state into an additive current Graph overlay."""
        projected: list[AssuranceEvent] = []
        mechanism = ChallengeProjectionMechanism()
        for artifact_id in sorted(self.graph.artifacts):
            records = challenges.records(artifact_id)
            if not records:
                continue
            claim_status = challenges.status(artifact_id)
            store = EvidenceStore()
            references = tuple(
                store.add(canonical_bytes(record.to_dict())) for record in records
            )
            binding = BoundProposition(
                artifact_id,
                "vstd.graph.current_status",
                claim_status.status.value,
                mechanism.mechanism_id,
                mechanism.mechanism_digest,
                references,
                ("verifier.layer4.challenge.ChallengeLedger",),
                EvidenceBounds(
                    len(references),
                    sum(len(canonical_bytes(record.to_dict())) for record in records),
                ),
            )
            session = VerificationSession(store)
            session.register(mechanism)
            event = self.record_status_projection(
                artifact_id,
                binding,
                session=session,
                recorded_at=recorded_at,
            )
            if event.outcome is not MechanismOutcome.PASS:
                raise AssuranceFlowError(
                    f"challenge projection failed for {artifact_id}: {event.details}"
                )
            projected.append(event)
        return tuple(projected)

    def record_status_projection(
        self,
        artifact_id: str,
        proposition: BoundProposition,
        *,
        session: VerificationSession,
        recorded_at: str,
    ) -> AssuranceEvent:
        """Record a mechanism-checked current-status projection additively."""
        if artifact_id not in self.graph.artifacts:
            raise AssuranceFlowError(f"unknown status projection subject {artifact_id}")
        if (
            proposition.subject_id != artifact_id
            or proposition.predicate != "vstd.graph.current_status"
            or proposition.mechanism_id
            != ChallengeProjectionMechanism.mechanism_id
        ):
            raise AssuranceFlowError(
                "status projection is not bound to the challenge projection mechanism"
            )
        resulting_status = ArtifactStatus(str(proposition.expected))
        evaluation = session.evaluate(proposition)
        return self._append(
            kind=AssuranceEventKind.STATUS_PROJECTION,
            subject_id=artifact_id,
            source_ids=(),
            proposition=proposition.predicate,
            binding=proposition.to_dict(),
            recorded_at=recorded_at,
            evaluation=evaluation,
            evidence_payloads=session.evidence.export_base64(evaluation.evidence_refs),
            attributes={"resulting_status": resulting_status.value},
        )

    def record_conflict(
        self,
        conflict: ConflictRecord,
        proposition: BoundProposition,
        *,
        session: VerificationSession,
        recorded_at: str,
    ) -> AssuranceEvent:
        """Add mechanism-established current conflict evidence without rewriting Graph."""
        if (
            conflict.subject_id not in self.graph.artifacts
            and conflict.subject_id not in self.graph.transformations
        ):
            raise AssuranceFlowError(
                f"unknown conflict subject {conflict.subject_id}"
            )
        if (
            not conflict.conflict_id
            or not conflict.predicate
            or len(conflict.competing_values) < 2
            or len(set(conflict.competing_values)) != len(conflict.competing_values)
            or not conflict.evidence_refs
            or len(set(conflict.evidence_refs)) != len(conflict.evidence_refs)
        ):
            raise AssuranceFlowError(
                "conflict requires an identifier, predicate, distinct competing values, "
                "and distinct evidence references"
            )
        prior = self._conflicts.get(conflict.conflict_id)
        if prior is not None:
            raise AssuranceFlowError(
                f"conflict identifier {conflict.conflict_id} is already bound"
            )
        expected = conflict.to_dict()
        if (
            proposition.subject_id != conflict.subject_id
            or proposition.predicate != "vstd.graph.conflict"
            or proposition.expected != expected
        ):
            raise AssuranceFlowError("conflict evidence is not exactly record-bound")
        evaluation = session.evaluate(proposition)
        event = self._append(
            kind=AssuranceEventKind.CONFLICT_DECLARATION,
            subject_id=conflict.subject_id,
            source_ids=conflict.evidence_refs,
            proposition=proposition.predicate,
            binding=proposition.to_dict(),
            recorded_at=recorded_at,
            evaluation=evaluation,
            evidence_payloads=session.evidence.export_base64(evaluation.evidence_refs),
            attributes={"conflict": conflict.to_dict()},
        )
        if evaluation.outcome is MechanismOutcome.PASS:
            self._conflicts[conflict.conflict_id] = conflict
        return event

    def resolve_conflict(
        self,
        conflict_id: str,
        selected_value: str,
        proposition: BoundProposition,
        *,
        session: VerificationSession,
        recorded_at: str,
    ) -> ConflictResolution:
        conflict = self._conflicts.get(conflict_id)
        if conflict is None:
            raise AssuranceFlowError(f"unknown conflict {conflict_id}")
        if conflict_id in {item.conflict_id for item in self._resolutions.values()}:
            raise AssuranceFlowError(f"conflict {conflict_id} is already resolved additively")
        if selected_value not in conflict.competing_values:
            raise AssuranceFlowError("resolution must select one retained competing value")
        if (
            proposition.subject_id != conflict.subject_id
            or proposition.predicate != f"vstd.graph.resolve.{conflict.predicate}"
            or proposition.expected != selected_value
            or proposition.parameters.get("conflict_id") != conflict_id
        ):
            raise AssuranceFlowError("resolution evidence is not exactly conflict-bound")
        evaluation = session.evaluate(proposition)
        if not evaluation.passed:
            raise AssuranceFlowError(
                f"conflict remains unresolved: mechanism returned {evaluation.outcome.value}"
            )
        resolution = ConflictResolution(
            "resolution:" + canonical_digest(
                [conflict_id, selected_value, evaluation.binding_digest]
            ),
            conflict_id,
            selected_value,
            recorded_at,
            evaluation,
        )
        self._resolutions[resolution.resolution_id] = resolution
        self._append(
            kind=AssuranceEventKind.CONFLICT_RESOLUTION,
            subject_id=conflict.subject_id,
            source_ids=(conflict_id,),
            proposition=proposition.predicate,
            binding=proposition.to_dict(),
            recorded_at=recorded_at,
            evaluation=evaluation,
            evidence_payloads=session.evidence.export_base64(evaluation.evidence_refs),
            attributes={
                "conflict_id": conflict_id,
                "selected_value": selected_value,
                "resolution_id": resolution.resolution_id,
            },
        )
        return resolution

    def record_trust(
        self,
        target_id: str,
        source_ids: Iterable[str],
        proposition: BoundProposition,
        *,
        transformation_id: str,
        prerequisite_trust_event_digests: Iterable[str] = (),
        session: VerificationSession,
        recorded_at: str,
    ) -> AssuranceEvent:
        sources = tuple(sorted(set(source_ids)))
        if not sources:
            raise AssuranceFlowError("TRUST requires at least one recorded source")
        if canonical_digest(self.graph.to_dict()) != self.graph_digest:
            raise AssuranceFlowError("historical Graph changed after ledger creation")
        if target_id not in self.graph.artifacts:
            raise AssuranceFlowError(f"unknown TRUST target {target_id}")
        transform = self.graph.transformations.get(transformation_id)
        if transform is None:
            raise AssuranceFlowError(f"unknown TRUST transformation {transformation_id}")
        exact_inputs = tuple(sorted({port.artifact_id for port in transform.inputs}))
        if sources != exact_inputs:
            raise AssuranceFlowError(
                "TRUST sources must equal the exact transformation input set"
            )
        if target_id not in {port.artifact_id for port in transform.outputs}:
            raise AssuranceFlowError(
                "TRUST target must be an output of the bound transformation"
            )
        if transform.status != "COMPLETED":
            raise AssuranceFlowError("incomplete transformation cannot provide TRUST")
        if self.current_status(target_id) is not ArtifactStatus.VALID or any(
            self.current_status(source) is not ArtifactStatus.VALID
            for source in sources
        ):
            raise AssuranceFlowError(
                "inadmissible target or transformation input cannot provide current TRUST"
            )
        unresolved_subjects = {item.subject_id for item in self.unresolved_conflicts()}
        if (
            target_id in unresolved_subjects
            or transformation_id in unresolved_subjects
            or any(source in unresolved_subjects for source in sources)
        ):
            raise AssuranceFlowError("unresolved conflict blocks clean TRUST")

        prerequisite_digests = tuple(sorted(set(prerequisite_trust_event_digests)))
        current_by_digest = {
            event.digest(): event for event in self.current_trust_events()
        }
        required_prerequisite_targets = {
            source for source in sources if self.graph.incoming_hyperedges(source)
        }
        prerequisite_targets: list[str] = []
        for event_digest in prerequisite_digests:
            prerequisite = current_by_digest.get(event_digest)
            if prerequisite is None:
                raise AssuranceFlowError(
                    "TRUST prerequisite is not a current passing TRUST event"
                )
            prerequisite_targets.append(prerequisite.subject_id)
        if (
            len(prerequisite_targets) != len(required_prerequisite_targets)
            or set(prerequisite_targets) != required_prerequisite_targets
        ):
            raise AssuranceFlowError(
                "TRUST requires exactly one current prerequisite for each derived input"
            )

        expected = {
            "historical_graph_digest": self.graph_digest,
            "inputs": list(sources),
            "output": target_id,
            "prerequisite_trust_event_digests": list(prerequisite_digests),
            "transformation_id": transformation_id,
        }
        if (
            proposition.subject_id != target_id
            or proposition.predicate != "vstd.graph.support"
            or proposition.expected != expected
        ):
            raise AssuranceFlowError("TRUST proposition is not exactly topology-bound")
        evaluation = session.evaluate(proposition)
        return self._append(
            kind=AssuranceEventKind.TRUST,
            subject_id=target_id,
            source_ids=sources,
            proposition=proposition.predicate,
            binding=proposition.to_dict(),
            recorded_at=recorded_at,
            evaluation=evaluation,
            evidence_payloads=session.evidence.export_base64(evaluation.evidence_refs),
            attributes={
                "historical_graph_digest": self.graph_digest,
                "inputs": list(sources),
                "output": target_id,
                "prerequisite_trust_event_digests": list(prerequisite_digests),
                "transformation_id": transformation_id,
            },
        )

    def record_rot(
        self,
        artifact_id: str,
        resulting_status: ArtifactStatus,
        proposition: BoundProposition,
        *,
        session: VerificationSession,
        recorded_at: str,
    ) -> AssuranceEvent:
        if artifact_id not in self.graph.artifacts:
            raise AssuranceFlowError(f"unknown ROT subject {artifact_id}")
        current = self.current_status(artifact_id)
        if DEGRADATION_ORDER.index(resulting_status) <= DEGRADATION_ORDER.index(current):
            raise AssuranceFlowError(
                "ROT must strictly degrade current admissibility"
            )
        if (
            proposition.subject_id != artifact_id
            or proposition.predicate != "vstd.graph.current_status"
            or proposition.expected != resulting_status.value
        ):
            raise AssuranceFlowError("ROT evidence is not exactly status-bound")
        evaluation = session.evaluate(proposition)
        return self._append(
            kind=AssuranceEventKind.ROT,
            subject_id=artifact_id,
            source_ids=(),
            proposition=proposition.predicate,
            binding=proposition.to_dict(),
            recorded_at=recorded_at,
            evaluation=evaluation,
            evidence_payloads=session.evidence.export_base64(evaluation.evidence_refs),
            attributes={"resulting_status": resulting_status.value},
        )

    def record_rust(
        self,
        descendant_id: str,
        deviation: BoundProposition,
        *,
        session: VerificationSession,
        recorded_at: str,
    ) -> AssuranceEvent:
        if descendant_id not in self.graph.artifacts:
            raise AssuranceFlowError(f"unknown RUST origin {descendant_id}")
        if (
            deviation.subject_id != descendant_id
            or deviation.predicate != "vstd.graph.descendant_deviation"
            or deviation.expected is not True
        ):
            raise AssuranceFlowError("RUST origin requires an exact deviation proposition")
        evaluation = session.evaluate(deviation)
        ancestors = tuple(sorted(self.graph.ancestors((descendant_id,)) - {descendant_id}))
        return self._append(
            kind=AssuranceEventKind.RUST,
            subject_id=descendant_id,
            source_ids=ancestors,
            proposition=deviation.predicate,
            binding=deviation.to_dict(),
            recorded_at=recorded_at,
            evaluation=evaluation,
            evidence_payloads=session.evidence.export_base64(evaluation.evidence_refs),
            attributes={
                "meaning": "diagnostic reachability only",
                "causal_localization": "NOT_ESTABLISHED",
            },
        )

    def rust_concentration(self) -> tuple[StructuralConcentration, ...]:
        reached_by: dict[str, set[str]] = {}
        for event in self._events:
            if event.kind is not AssuranceEventKind.RUST or event.outcome is not MechanismOutcome.PASS:
                continue
            for ancestor in event.source_ids:
                reached_by.setdefault(ancestor, set()).add(event.subject_id)
        return tuple(
            StructuralConcentration(ancestor, tuple(sorted(descendants)))
            for ancestor, descendants in sorted(reached_by.items())
        )

    def localize_cause(
        self,
        ancestor_id: str,
        descendant_id: str,
        proposition: BoundProposition,
        *,
        session: VerificationSession,
        recorded_at: str,
    ) -> AssuranceEvent:
        if ancestor_id not in self.graph.ancestors((descendant_id,)) - {descendant_id}:
            raise AssuranceFlowError("causal candidate is not a recorded ancestor")
        rust_exists = any(
            event.kind is AssuranceEventKind.RUST
            and event.subject_id == descendant_id
            and event.outcome is MechanismOutcome.PASS
            for event in self._events
        )
        if not rust_exists:
            raise AssuranceFlowError("localization requires a verified descendant deviation")
        expected = {"ancestor": ancestor_id, "descendant": descendant_id}
        if (
            proposition.subject_id != descendant_id
            or proposition.predicate != "vstd.graph.causal_localization"
            or proposition.expected != expected
        ):
            raise AssuranceFlowError("causal localization is not exactly relation-bound")
        evaluation = session.evaluate(proposition)
        return self._append(
            kind=AssuranceEventKind.CAUSAL_LOCALIZATION,
            subject_id=descendant_id,
            source_ids=(ancestor_id,),
            proposition=proposition.predicate,
            binding=proposition.to_dict(),
            recorded_at=recorded_at,
            evaluation=evaluation,
            evidence_payloads=session.evidence.export_base64(evaluation.evidence_refs),
        )

    def diagnose(
        self,
        kind: DiagnosticKind,
        ancestor_id: str,
        descendant_id: str,
        proposition: Optional[BoundProposition],
        *,
        session: VerificationSession,
        recorded_at: str,
    ) -> DiagnosticAttribution:
        """Compute bounded artifact-relative BLAME or GUILT just in time.

        BLAME means only that the named artifact-relative responsibility
        proposition passed. GUILT is not its directional opposite: it checks
        that same localized responsibility together with an exact violated
        obligation. Neither result concerns an actor's moral character,
        reputation, or general trust.
        """
        localization = next(
            (
                event
                for event in reversed(self._events)
                if event.kind is AssuranceEventKind.CAUSAL_LOCALIZATION
                and event.subject_id == descendant_id
                and event.source_ids == (ancestor_id,)
                and event.outcome is MechanismOutcome.PASS
            ),
            None,
        )
        if localization is None:
            return DiagnosticAttribution(
                kind,
                ancestor_id,
                descendant_id,
                "NOT_ESTABLISHED",
                "",
                None,
                "RUST reachability does not establish causal localization",
            )
        if proposition is None:
            return DiagnosticAttribution(
                kind,
                ancestor_id,
                descendant_id,
                "NOT_ESTABLISHED",
                localization.digest(),
                None,
                "diagnostic attribution requires a separate exact mechanism",
            )
        obligation = proposition.parameters.get("obligation", "")
        if kind is DiagnosticKind.GUILT and not obligation:
            raise AssuranceFlowError("GUILT requires an exact violated obligation")
        expected = {
            "ancestor": ancestor_id,
            "descendant": descendant_id,
            "localization_event_digest": localization.digest(),
        }
        if kind is DiagnosticKind.GUILT:
            expected["violated_obligation"] = obligation
        if (
            proposition.subject_id != ancestor_id
            or proposition.predicate != f"vstd.graph.diagnostic.{kind.value.lower()}"
            or proposition.expected != expected
        ):
            raise AssuranceFlowError("diagnostic proposition is not exactly relation-bound")
        evaluation = session.evaluate(proposition)
        event = self._append(
            kind=AssuranceEventKind.DIAGNOSTIC_ATTRIBUTION,
            subject_id=ancestor_id,
            source_ids=(descendant_id,),
            proposition=proposition.predicate,
            binding=proposition.to_dict(),
            recorded_at=recorded_at,
            evaluation=evaluation,
            evidence_payloads=session.evidence.export_base64(evaluation.evidence_refs),
            attributes={
                "diagnostic_kind": kind.value,
                "localization_event_digest": localization.digest(),
                "obligation": obligation,
            },
        )
        return DiagnosticAttribution(
            kind,
            ancestor_id,
            descendant_id,
            "ESTABLISHED" if evaluation.passed else "NOT_ESTABLISHED",
            localization.digest(),
            evaluation,
            event.details,
        )

    def verify_hash_chain(self) -> bool:
        previous = ""
        for sequence, event in enumerate(self._events):
            if event.sequence != sequence or event.previous_event_digest != previous:
                return False
            previous = event.digest()
        return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.FORMAT,
            "historical_graph_digest": self.graph_digest,
            "historical_graph": self.graph.to_dict(),
            "events": [event.to_dict() for event in self._events],
            "conflict_resolutions": [item.to_dict() for item in self._resolutions.values()],
            "current_view_digest": canonical_digest(self.materialize_current_graph().to_dict()),
        }


def recheck_assurance_log(
    payload: Mapping[str, Any],
    *,
    mechanisms: Iterable[VerificationMechanism],
) -> AssuranceLedger:
    """Rebuild and replay a portable assurance log from its embedded bytes."""
    if payload.get("schema_version") != AssuranceLedger.FORMAT:
        raise AssuranceFlowError("not a VSTD-Graph assurance log")
    graph_data = payload.get("historical_graph")
    events_data = payload.get("events")
    if not isinstance(graph_data, Mapping) or not isinstance(events_data, list):
        raise AssuranceFlowError("assurance log is missing its Graph or events")
    graph = ProvenanceHypergraph.from_dict(graph_data)
    if canonical_digest(graph.to_dict()) != payload.get("historical_graph_digest"):
        raise AssuranceFlowError("historical Graph digest does not match embedded bytes")
    ledger = AssuranceLedger(graph)
    store = EvidenceStore()
    for event_data in events_data:
        if not isinstance(event_data, Mapping):
            raise AssuranceFlowError("assurance event is not an object")
        embedded = event_data.get("evidence_payloads")
        if not isinstance(embedded, Mapping):
            raise AssuranceFlowError("assurance event has no embedded evidence")
        store.import_base64(
            {str(reference): str(encoded) for reference, encoded in embedded.items()}
        )
    session = VerificationSession(store)
    builtin = ChallengeProjectionMechanism()
    session.register(builtin)
    for mechanism in mechanisms:
        if mechanism.mechanism_id == builtin.mechanism_id:
            raise AssuranceFlowError(
                "the built-in challenge projection mechanism cannot be replaced"
            )
        session.register(mechanism)

    for expected in events_data:
        try:
            kind = AssuranceEventKind(str(expected["kind"]))
            subject_id = str(expected["subject_id"])
            source_ids = tuple(str(item) for item in expected["source_ids"])
            binding_data = expected["binding"]
            if not isinstance(binding_data, Mapping):
                raise TypeError("event binding is not an object")
            proposition = BoundProposition.from_dict(binding_data)
            recorded_at = str(expected["recorded_at"])
            attributes = expected.get("attributes", {})
            if not isinstance(attributes, Mapping):
                raise TypeError("event attributes are not an object")

            if kind is AssuranceEventKind.TRUST:
                event = ledger.record_trust(
                    subject_id,
                    source_ids,
                    proposition,
                    transformation_id=str(attributes["transformation_id"]),
                    prerequisite_trust_event_digests=tuple(
                        str(item)
                        for item in attributes[
                            "prerequisite_trust_event_digests"
                        ]
                    ),
                    session=session,
                    recorded_at=recorded_at,
                )
            elif kind is AssuranceEventKind.ROT:
                event = ledger.record_rot(
                    subject_id,
                    ArtifactStatus(str(attributes["resulting_status"])),
                    proposition,
                    session=session,
                    recorded_at=recorded_at,
                )
            elif kind is AssuranceEventKind.RUST:
                event = ledger.record_rust(
                    subject_id,
                    proposition,
                    session=session,
                    recorded_at=recorded_at,
                )
            elif kind is AssuranceEventKind.STATUS_PROJECTION:
                event = ledger.record_status_projection(
                    subject_id,
                    proposition,
                    session=session,
                    recorded_at=recorded_at,
                )
            elif kind is AssuranceEventKind.CONFLICT_DECLARATION:
                conflict_data = attributes["conflict"]
                if not isinstance(conflict_data, Mapping):
                    raise TypeError("conflict declaration is not an object")
                event = ledger.record_conflict(
                    ConflictRecord(
                        str(conflict_data["conflict_id"]),
                        str(conflict_data["subject_id"]),
                        str(conflict_data["predicate"]),
                        tuple(str(item) for item in conflict_data["competing_values"]),
                        tuple(str(item) for item in conflict_data["evidence_refs"]),
                    ),
                    proposition,
                    session=session,
                    recorded_at=recorded_at,
                )
            elif kind is AssuranceEventKind.CONFLICT_RESOLUTION:
                ledger.resolve_conflict(
                    str(attributes["conflict_id"]),
                    str(attributes["selected_value"]),
                    proposition,
                    session=session,
                    recorded_at=recorded_at,
                )
                event = ledger.events()[-1]
            elif kind is AssuranceEventKind.CAUSAL_LOCALIZATION:
                if len(source_ids) != 1:
                    raise AssuranceFlowError(
                        "causal localization must name exactly one ancestor"
                    )
                event = ledger.localize_cause(
                    source_ids[0],
                    subject_id,
                    proposition,
                    session=session,
                    recorded_at=recorded_at,
                )
            else:
                if len(source_ids) != 1:
                    raise AssuranceFlowError(
                        "diagnostic attribution must name exactly one descendant"
                    )
                ledger.diagnose(
                    DiagnosticKind(str(attributes["diagnostic_kind"])),
                    subject_id,
                    source_ids[0],
                    proposition,
                    session=session,
                    recorded_at=recorded_at,
                )
                event = ledger.events()[-1]
        except (KeyError, TypeError, ValueError) as exc:
            raise AssuranceFlowError(f"cannot replay assurance event: {exc}") from exc
        if event.to_dict() != dict(expected):
            raise AssuranceFlowError(
                f"recomputed assurance event {event.sequence} does not match the log"
            )

    if ledger.to_dict() != dict(payload):
        raise AssuranceFlowError(
            "recomputed assurance state does not match the serialized log"
        )
    return ledger


__all__ = [
    "AssuranceEvent",
    "AssuranceEventKind",
    "AssuranceFlowError",
    "AssuranceLedger",
    "ChallengeProjectionMechanism",
    "ConflictResolution",
    "DiagnosticAttribution",
    "DiagnosticKind",
    "StructuralConcentration",
    "recheck_assurance_log",
]
