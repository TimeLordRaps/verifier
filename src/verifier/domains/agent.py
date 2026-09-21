"""Agent trajectory (AGENT): decisions bounded by a harness observation ceiling.

An AGENT certificate cannot establish more than its bound HARNESS declared
observable. A claim resting on a declared gap or an undeclared channel yields
UNKNOWN; it is never reconstructed and never passed. Counts are dimensionless.
"""
from __future__ import annotations

from .common import (Budget, Refuted, Unavailable, digest, need, obj, same, seq, text)

CERTIFICATE_FIELDS = {"schema_version", "request", "evidence", "policy_digest",
                      "mechanism_digest", "specification_digest", "result", "certificate_digest"}


def ceiling(artifact: dict, inputs: dict, mechanism_digest: str) -> dict:
    """Re-derive the observation ceiling from the bound harness certificate."""
    certificate = obj(need(inputs, "harness_certificate"), CERTIFICATE_FIELDS)
    same(certificate["schema_version"], "VSTD-DOMAIN-CERTIFICATION-1", "unsupported harness certificate")
    body = {k: v for k, v in certificate.items() if k != "certificate_digest"}
    same(digest(body), certificate["certificate_digest"], "harness certificate digest differs")
    same(digest(certificate), need(artifact, "harness_certificate_digest"),
         "bound harness certificate differs from the retained one")
    if certificate["mechanism_digest"] != mechanism_digest:
        raise Unavailable("harness certificate was produced by a different mechanism")
    evidence = obj(certificate["evidence"], {"schema_version", "domain", "subject_id", "artifact", "inputs"})
    if evidence["domain"] != "HARNESS":
        raise Refuted("bound certificate is not a harness certificate")
    same(evidence["subject_id"], need(artifact, "harness_subject_id"), "harness subject differs")
    result = obj(certificate["result"])
    if result.get("object_profile_conformance") != "NOT_ESTABLISHED":
        raise Refuted("harness certificate misreports object profile conformance")
    if result.get("status") != "PASS" or result.get("domain_depth") != 5:
        raise Unavailable("bound harness did not establish its complete observation surface")
    declared = obj(need(evidence["artifact"], "surface"))
    instrumented = {c for c, d in declared.items() if d == "instrumented"}
    required = seq(need(artifact, "required_channels"), budget=Budget(1024, 1024))
    names = {text(c) for c in required}
    if len(names) != len(required):
        raise Refuted("duplicate required channel")
    outside = names - instrumented
    if outside:
        raise Unavailable("required channel was not instrumented: " + " ".join(sorted(outside)))
    return {"instrumented": instrumented, "required": names,
            "records": seq(need(evidence["inputs"], "records"), Budget(1000000, 100000)),
            "invocations": evidence["inputs"].get("invocations", [])}


def witnessed(bound: dict, index: object, budget: Budget) -> dict:
    budget.tick()
    if type(index) is not int or not 0 <= index < len(bound["records"]):
        raise Refuted("step or claim names no record in the bound transcript")
    record = bound["records"][index]
    if record["channel"] not in bound["required"]:
        raise Unavailable("record lies outside the channels this agent claim was bound to")
    return record


def evaluate(check: str, artifact: dict, inputs: dict, budget: Budget, *, mechanism_digest: str) -> dict:
    bound = ceiling(artifact, inputs, mechanism_digest)
    steps, actions = [], []
    if check != "harness":
        steps = seq(need(inputs, "steps"), budget)
        same(digest(steps), need(artifact, "steps_digest"), "trajectory differs")
        for index, step in enumerate(steps):
            obj(step, {"index", "record", "decision"})
            if step["index"] != index:
                raise Refuted("trajectory indices are not contiguous from zero")
            text(step["decision"])
            witnessed(bound, step["record"], budget)
    if check == "actions":
        actions = seq(need(inputs, "actions"), budget, nonempty=False)
        same(digest(actions), need(artifact, "actions_digest"), "action inventory differs")
        invocations = {(i.get("tool"), i.get("index")) for i in bound["invocations"] if isinstance(i, dict)}
        for action in actions:
            obj(action, {"tool", "record"})
            witnessed(bound, action["record"], budget)
            if (text(action["tool"]), action["record"]) not in invocations:
                raise Refuted("declared action has no witnessed tool invocation in the bound harness")
    elif check == "outcomes":
        contract = obj(need(artifact, "outcomes"))
        if not contract:
            raise Unavailable("outcome contract empty")
        same(need(inputs, "outcomes"), contract, "retained outcomes differ from the bound contract")
    elif check == "claims":
        claims = seq(need(artifact, "claims"), budget)
        for claim in claims:
            obj(claim, {"id", "statement", "support", "channels"})
            text(claim["id"])
            text(claim["statement"])
            support = seq(claim["support"], budget)
            for index in support:
                witnessed(bound, index, budget)
            channels = {text(c) for c in seq(claim["channels"], budget)}
            outside = channels - bound["required"]
            if outside:
                raise Unavailable("claim rests on a channel outside its bound observation surface: "
                                  + " ".join(sorted(outside)))
    return {"observation_ceiling": sorted(bound["required"]),
            "instrumented_channels": sorted(bound["instrumented"]),
            "steps": len(steps), "actions": len(actions)}
