"""IDENTITY occupancy checks between a HUMAN or BOT bearer and a ROLE seat.

Verifier Standard (VSTD) retained-record consistency is separate from bearer
authenticity, role authority and a numbered-profile claim. Times use the
occupancy's declared clock; event and presentation counts are dimensionless.
"""
from __future__ import annotations

import re
from typing import Any

from .common import (Budget, Refuted, Unavailable, bind_certificate, digest, integer,
                     need, obj, same, seq, text)


def _occupancy(artifact: dict, inputs: dict, budget: Budget) -> dict:
    bearer_class = text(need(artifact, "bearer_class"))
    if bearer_class not in {"HUMAN", "BOT"}:
        raise Refuted("occupancy bearer must be HUMAN or BOT; a bare AGENT is inadmissible")
    bearer_subject = text(need(artifact, "bearer_subject_id"))
    role_subject = text(need(artifact, "role_subject_id"))
    role_coordinate = text(need(artifact, "role_coordinate"))
    if not re.fullmatch(r"ROLE-[1-6]\.[1-9][0-9]*", role_coordinate):
        raise Refuted("role binding requires an explicit ROLE coordinate")
    if text(need(artifact, "assurance_level")) != "declared":
        raise Unavailable("stronger occupancy assurance requires a separately admitted evidence mechanism")
    inherited_scope = text(need(artifact, "inherited_scope"))
    text(need(artifact, "revocation_surface"))
    if need(artifact, "disclosure") not in {"held", "disclosed"}:
        raise Refuted("occupancy disclosure must be held or disclosed")
    validity = obj(need(artifact, "validity"), {"start", "end"})
    start, end = integer(validity["start"]), integer(validity["end"])
    if end <= start:
        raise Refuted("occupancy validity interval must be nonempty")
    if bearer_class == "BOT":
        simulation_id = text(need(artifact, "simulation_id"))
        same(inherited_scope, "simulation:" + simulation_id,
             "bot occupancy scope differs from its simulation")
    elif "simulation_id" in artifact:
        raise Refuted("human occupancy cannot silently inherit a simulation scope")
    bearer = obj(need(inputs, "bearer_certificate"))
    role = obj(need(inputs, "role_certificate"))
    role_class_id = text(need(artifact, "role_class_id"))
    for certificate, expected_domain, expected_subject, label in (
        (bearer, bearer_class, bearer_subject, "bearer"),
        (role, "ROLE", role_subject, "role"),
    ):
        same(need(certificate, "schema_version"), "verifier-domain-certification-1",
             f"{label} certificate schema differs")
        child = obj(need(certificate, "evidence"))
        same(need(child, "domain"), expected_domain, f"{label} certificate domain differs")
        same(need(child, "subject_id"), expected_subject, f"{label} certificate subject differs")
    same(need(obj(need(obj(need(role, "evidence")), "artifact")), "role_class_id"),
         role_class_id, "role class differs from retained child declaration")
    same(digest(bearer), need(artifact, "bearer_certificate_digest"),
         "bearer certificate commitment differs")
    same(digest(role), need(artifact, "role_certificate_digest"),
         "role certificate commitment differs")
    occupancy = obj(need(inputs, "occupancy_evidence"),
                    {"bearer_subject_id", "role_subject_id", "role_coordinate", "evidence_ref"})
    same(digest(occupancy), need(artifact, "occupancy_digest"),
         "occupancy evidence commitment differs")
    same(occupancy["bearer_subject_id"], bearer_subject, "occupancy bearer differs")
    same(occupancy["role_subject_id"], role_subject, "occupancy role differs")
    same(occupancy["role_coordinate"], role_coordinate, "occupancy role coordinate differs")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", text(occupancy["evidence_ref"])):
        raise Refuted("occupancy evidence needs a retained digest reference")
    budget.tick()
    return {"bearer_class": bearer_class, "bearer_subject_id": bearer_subject,
            "role_subject_id": role_subject, "role_class_id": role_class_id,
            "role_coordinate": role_coordinate,
            "validity": (start, end), "bearer_authenticity": "NOT_ESTABLISHED",
            "role_authority": "NOT_ESTABLISHED", "occupancy_authority": "NOT_ESTABLISHED",
            "occupancy_evidence_ref_resolution": "NOT_ESTABLISHED"}


def evaluate(check: str, artifact: dict, inputs: dict, budget: Budget, *,
             mechanism_digest: str | None = None, policy: dict | None = None,
             nesting: int = 0, **_: Any) -> dict:
    bound = _occupancy(artifact, inputs, budget)
    if check == "occupancy":
        return {k: v for k, v in bound.items() if k != "validity"}
    if check == "lifecycle":
        events = seq(need(inputs, "events"), budget)
        same(digest(events), need(artifact, "events_digest"), "occupancy event commitment differs")
        start, end = bound["validity"]
        active, previous_at, presentations = False, None, 0
        for position, event in enumerate(events):
            obj(event, {"position", "event", "at", "bearer_subject_id"})
            if integer(event["position"]) != position:
                raise Refuted("occupancy events are not contiguous")
            at = integer(event["at"])
            if previous_at is not None and at < previous_at:
                raise Refuted("occupancy event time moved backward")
            previous_at = at
            same(event["bearer_subject_id"], bound["bearer_subject_id"],
                 "occupancy event changes bearer")
            kind = text(event["event"])
            if position == 0 and (kind != "enrollment" or at != start):
                raise Refuted("occupancy enrollment must begin the declared validity")
            if kind == "enrollment":
                if active or position != 0:
                    raise Refuted("occupancy cannot re-enroll or transfer a binding")
                active = True
            elif kind in {"reverification", "renewal", "presentation"}:
                if not active or at >= end:
                    raise Refuted("inactive or expired occupancy cannot be presented or renewed")
                if kind == "presentation":
                    presentations += 1
            elif kind in {"handover", "revocation", "simulation_end"}:
                if not active:
                    raise Refuted("occupancy termination requires active binding")
                if kind == "simulation_end" and bound["bearer_class"] != "BOT":
                    raise Refuted("only a bot occupancy can end with its simulation")
                active = False
            else:
                raise Refuted("unknown occupancy event")
        if not active:
            raise Unavailable("occupancy lapsed or revoked; historical presentations remain")
        return {"events_replayed": len(events), "presentations": presentations,
                "declared_state": "ACTIVE", "bearer_authenticity": "NOT_ESTABLISHED",
                "role_authority": "NOT_ESTABLISHED", "current_time": "NOT_OBSERVED"}
    if check == "support":
        if mechanism_digest is None or policy is None:
            raise Unavailable("checker-selected policy and mechanism needed for child replay")
        if bound["bearer_class"] == "HUMAN":
            raise Unavailable("retained HUMAN declaration cannot establish living bearer authenticity")
        bearer = bind_certificate(inputs, artifact, "bearer", "BOT", mechanism_digest, 1,
                                  policy=policy, budget=budget, nesting=nesting)
        role = bind_certificate(inputs, artifact, "role", "ROLE", mechanism_digest, 2,
                                policy=policy, budget=budget, nesting=nesting)
        same(bearer["subject_id"], bound["bearer_subject_id"], "replayed bearer differs")
        same(role["subject_id"], bound["role_subject_id"], "replayed role differs")
        role_artifact = obj(need(role, "artifact"))
        same(need(role_artifact, "role_class_id"), bound["role_class_id"],
             "replayed role class differs")
        admitted = {text(value) for value in seq(need(role_artifact, "admissible_bearer_classes"), budget)}
        if bound["bearer_class"].lower() not in admitted:
            raise Refuted("bearer class is inadmissible for the replayed role")
        if bound["bearer_subject_id"] not in seq(need(role_artifact, "current_occupants"), budget):
            raise Refuted("bearer is not in the replayed role occupancy")
        occupants: dict[str, str] = {}
        for event in seq(need(obj(need(role, "inputs")), "occupancy_events"), budget):
            kind = need(obj(event), "event")
            if kind == "take":
                occupants[text(event["bearer_id"])] = text(event["bearer_class"])
            elif kind == "leave":
                occupants.pop(text(event["bearer_id"]), None)
            elif kind == "handover":
                occupants.pop(text(event["leaving"]), None)
                occupants[text(event["taking"])] = text(event["bearer_class"])
        if occupants.get(bound["bearer_subject_id"]) != bound["bearer_class"].lower():
            raise Refuted("bearer class differs from replayed seat occupancy")
        nested_sim = obj(need(obj(need(bearer, "inputs")), "sim_certificate"))
        sim_evidence = obj(need(nested_sim, "evidence"))
        same(need(sim_evidence, "domain"), "SIM", "BOT child contains non-SIM world")
        same(need(sim_evidence, "subject_id"), need(artifact, "simulation_id"),
             "bot occupancy simulation differs from replayed BOT world")
        # bind_certificate has replayed the complete child result under current
        # checker policy; only now may its established coordinate be relied on.
        role_certificate = obj(need(inputs, "role_certificate"))
        role_checks = obj(need(obj(need(role_certificate, "result")), "checks"))
        role_row = obj(need(role_checks, bound["role_coordinate"]))
        if need(role_row, "established") is not True:
            raise Unavailable("declared role coordinate was not established by child replay")
        return {"nested_computations_replayed": 2,
                "bearer_authenticity": "NOT_ESTABLISHED",
                "role_authority": "NOT_ESTABLISHED",
                "occupancy_authority": "NOT_ESTABLISHED",
                "occupancy_evidence_ref_resolution": "NOT_ESTABLISHED"}
    raise Unavailable(f"unsupported IDENTITY check: {check}")
