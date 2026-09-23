"""Agent harness (HARNESS): the instrumented observation surface, not the actor.

A harness certificate establishes what was observable, including the channels the
deployment declared it could not observe. Declared gaps are named, never absent.
Counts are dimensionless; retained payload sizes count bytes. No input loads code.
"""
from __future__ import annotations

from .common import (Budget, Refuted, Unavailable, digest, merkle_root, need, obj,
                     same, seq, text, unique)

DISPOSITIONS = ("instrumented", "declared-gap")
ROLES = ("user", "agent", "tool")


def surface(artifact: dict) -> tuple[set[str], set[str]]:
    """Partition the declared channels; an undeclared channel is not a gap."""
    declared = obj(need(artifact, "surface"))
    if not declared:
        raise Unavailable("observation surface empty")
    for channel, disposition in declared.items():
        text(channel)
        if disposition not in DISPOSITIONS:
            raise Refuted("channel disposition must be instrumented or declared-gap")
    instrumented = {c for c, d in declared.items() if d == "instrumented"}
    if not instrumented:
        raise Unavailable("no instrumented channel; nothing is observable")
    return instrumented, set(declared) - instrumented


def effect_surface(artifact: dict) -> tuple[set[str], set[str]]:
    declared = obj(need(artifact, "effects"))
    for channel, disposition in declared.items():
        text(channel)
        if disposition not in DISPOSITIONS:
            raise Refuted("effect disposition must be instrumented or declared-gap")
    instrumented = {c for c, d in declared.items() if d == "instrumented"}
    return instrumented, set(declared) - instrumented


def transcript(artifact: dict, inputs: dict, instrumented: set[str], budget: Budget) -> list:
    """Re-check every retained record against the declared instrumented surface."""
    records = seq(need(inputs, "records"), budget)
    if len(records) != need(artifact, "record_count"):
        raise Refuted("retained record count differs from the bound transcript")
    for index, record in enumerate(records):
        obj(record, {"index", "channel", "role", "payload", "payload_digest"})
        if record["index"] != index:
            raise Refuted("transcript indices are not contiguous from zero")
        if text(record["role"]) not in ROLES:
            raise Refuted("unsupported transcript role")
        channel = text(record["channel"])
        if channel not in instrumented:
            raise Refuted("retained record occupies a channel that was not instrumented")
        same(digest(record["payload"]), record["payload_digest"], "record payload differs")
    return records


def evaluate(check: str, artifact: dict, inputs: dict, budget: Budget) -> dict:
    instrumented, gaps = surface(artifact)
    tools = obj(need(artifact, "tools"))
    records = transcript(artifact, inputs, instrumented, budget) if check != "surface" else []
    if check == "tools":
        if not tools:
            raise Unavailable("no tool was registered; tool observation establishes nothing")
        invocations = seq(need(inputs, "invocations"), budget, nonempty=False)
        for invocation in invocations:
            obj(invocation, {"index", "tool", "input", "output", "declaration_digest"})
            name = text(invocation["tool"])
            if name not in tools:
                raise Refuted("tool invocation names an unregistered tool")
            same(invocation["declaration_digest"], tools[name], "registered tool declaration differs")
            index = invocation["index"]
            if type(index) is not int or not 0 <= index < len(records):
                raise Refuted("tool invocation names no retained record")
            record = records[index]
            if record["role"] != "tool":
                raise Refuted("tool invocation bound to a record that is not a tool record")
            same(digest({"input": invocation["input"], "output": invocation["output"]}),
                 record["payload_digest"], "tool invocation differs from its retained record")
    elif check == "effects":
        instrumented_effects, effect_gaps = effect_surface(artifact)
        retained = seq(need(inputs, "effects"), budget, nonempty=False)
        for effect in retained:
            obj(effect, {"index", "channel", "payload"})
            channel = text(effect["channel"])
            if channel in effect_gaps:
                raise Refuted("retained effect occupies a declared uninstrumented effect channel")
            if channel not in instrumented_effects:
                raise Refuted("retained effect occupies an undeclared effect channel")
            index = effect["index"]
            if type(index) is not int or not 0 <= index < len(records):
                raise Refuted("effect names no retained record")
        unique([{"key": digest(e)} for e in retained], "key")
    elif check == "transcript":
        same(digest(records), need(artifact, "transcript_digest"), "transcript differs")
        same(merkle_root(records, budget), need(artifact, "transcript_root"),
             "transcript commitment differs; a record was omitted or substituted")
    return {"instrumented_channels": sorted(instrumented), "declared_gaps": sorted(gaps),
            "records": len(records), "registered_tools": len(tools)}
