"""HUMAN retained assertion checks; no declaration authenticates a living person.

These checks bind metadata and replay a declared event order. They do not certify
personhood, witness independence, biometric performance, or numbered profiles.
All counts are dimensionless; event times use the assertion's declared clock.
"""
from __future__ import annotations

import re
from typing import Any

from .common import Budget, Refuted, Unavailable, digest, integer, need, obj, same, seq, text


EVIDENCE_CLASSES = frozenset({"biometric", "hardware-attested", "in-person", "social-graph"})
UNASSERTED_FLOOR = frozenset({"name", "nationality", "civil_identity"})


def _assertion(artifact: dict, inputs: dict, budget: Budget) -> dict:
    subject = text(need(artifact, "subject_ref"))
    evidence_class = text(need(artifact, "evidence_class"))
    if evidence_class not in EVIDENCE_CLASSES:
        raise Unavailable("unsupported humanness evidence class")
    pipeline = text(need(artifact, "capture_pipeline"))
    liveness, uniqueness = need(artifact, "liveness_claim"), need(artifact, "uniqueness_claim")
    if type(liveness) is not bool or type(uniqueness) is not bool:
        raise Refuted("liveness and uniqueness claims must be distinct booleans")
    population = text(need(artifact, "enrollment_population"))
    text(need(artifact, "deduplication_mechanism"))
    if population.lower() in {"global", "worldwide", "all-humans", "all humans"}:
        raise Refuted("global person uniqueness cannot be established")
    excluded = [text(value) for value in seq(need(artifact, "unasserted_attributes"), budget)]
    if len(set(excluded)) != len(excluded) or not UNASSERTED_FLOOR <= set(excluded):
        raise Refuted("identity attributes must remain explicitly unasserted")
    validity = obj(need(artifact, "validity"), {"start", "end"})
    start, end = integer(validity["start"]), integer(validity["end"])
    if end <= start:
        raise Refuted("assertion validity interval must be nonempty")
    records = seq(need(inputs, "evidence_records"), budget)
    same(digest(records), need(artifact, "evidence_digest"), "retained evidence commitment differs")
    identifiers = set()
    for record in records:
        obj(record, {"id", "class", "capture_pipeline", "witness_id", "record_digest"})
        identifier = text(record["id"])
        if identifier in identifiers:
            raise Refuted("duplicate retained evidence identifier")
        identifiers.add(identifier)
        same(record["class"], evidence_class, "retained evidence class differs")
        same(record["capture_pipeline"], pipeline, "retained capture pipeline differs")
        if text(record["witness_id"]) == subject:
            raise Refuted("subject cannot be the sole named witness")
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", text(record["record_digest"])):
            raise Refuted("retained evidence record needs a digest reference")
    return {"subject_ref": subject, "evidence_class": evidence_class,
            "enrollment_population": population, "evidence_records": len(records),
            "evidence_ids": identifiers, "validity": (start, end),
            "personhood": "NOT_ESTABLISHED", "witness_independence": "NOT_ESTABLISHED"}


def evaluate(check: str, artifact: dict, inputs: dict, budget: Budget, **_: Any) -> dict:
    bound = _assertion(artifact, inputs, budget)
    if check == "assertion":
        return {k: v for k, v in bound.items() if k not in {"evidence_ids", "validity"}}
    if check == "closure":
        raise Unavailable("independent personhood, liveness, error-rate and accountability evidence absent")
    if check != "lifecycle":
        raise Unavailable(f"unsupported HUMAN check: {check}")
    events = seq(need(inputs, "events"), budget)
    same(digest(events), need(artifact, "events_digest"), "human event commitment differs")
    start, end = bound["validity"]
    state, previous_at, compromised = "UNENROLLED", None, False
    for position, event in enumerate(events):
        obj(event, {"position", "event", "at", "evidence_id", "instrument"})
        if integer(event["position"]) != position:
            raise Refuted("human events are not contiguous")
        at = integer(event["at"])
        if previous_at is not None and at < previous_at:
            raise Refuted("human event time moved backward")
        if at >= end:
            raise Unavailable("human event lies outside declared validity")
        previous_at = at
        if text(event["evidence_id"]) not in bound["evidence_ids"]:
            raise Refuted("human event names unretained evidence")
        text(event["instrument"])
        kind = text(event["event"])
        if position == 0 and (kind != "enrollment" or at != start):
            raise Refuted("human enrollment must begin the declared validity")
        if kind == "enrollment":
            if state != "UNENROLLED":
                raise Refuted("human assertion cannot silently re-enroll")
            state = "DECLARED_ACTIVE"
        elif kind == "reverification":
            if state != "DECLARED_ACTIVE":
                raise Refuted("re-verification requires an active assertion")
        elif kind == "compromise":
            if state != "DECLARED_ACTIVE":
                raise Refuted("compromise requires an active assertion")
            compromised = True
            state = "WITHDRAWN"
        elif kind == "revocation":
            if state not in {"DECLARED_ACTIVE", "WITHDRAWN"}:
                raise Refuted("revocation requires a prior assertion")
            state = "WITHDRAWN"
        elif kind == "death":
            if state == "UNENROLLED" or state == "DEAD":
                raise Refuted("death event requires a prior assertion")
            state = "DEAD"
        else:
            raise Refuted("unknown human assertion event")
    if state != "DECLARED_ACTIVE":
        raise Unavailable("human assertion withdrawn or ended; historical events remain retained")
    if previous_at is None or previous_at >= end:
        raise Unavailable("retained event lies outside declared validity")
    return {"events_replayed": len(events), "declared_state": state,
            "biometric_compromise_permanent": compromised,
            "physical_liveness": "NOT_ESTABLISHED", "current_time": "NOT_OBSERVED"}
