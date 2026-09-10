"""Bounded typed-formation wire rules for Verifier Standard (VSTD).

JavaScript Object Notation (JSON) records use the existing canonical byte codec.
This module shares only grammar, byte identity and fixed resource declarations;
it contains no type inference or certificate acceptance algorithm. Counts are
dimensionless; record limits are bytes. Context digests name declared ground and
authority axiom agency, not evidence that either has been established.

An integer identifier (ID) is a node's construction position. The serialized
ID tag instead names the identity-path constructor.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .network import NetworkError, canonical_bytes, digest_bytes


class FormationError(ValueError):
    """A known formation record or rule is invalid."""


class FormationLimitError(FormationError):
    """The bounded mechanism could not finish; this is not a refutation."""


class UnsupportedFormation(FormationError):
    """The submitted record requires an unsupported interpretation."""


SUBJECT_SCHEMA = "VSTD-TYPED-FORMATION-0.1"
CERTIFICATE_SCHEMA = "VSTD-TYPED-FORMATION-CERTIFICATE-0.1"
MAX_NODES = 1024
MAX_DEPTH = 64
MAX_PATH_STEPS = 4096
MAX_RECORD_BYTES = 262144
MAX_JSON_DEPTH = 16
MAX_JSON_CONTAINERS = 8192
RESIDUAL_OBLIGATIONS = (
    "SOURCE_INTERPRETATION_NOT_ESTABLISHED",
    "GROUND_DERIVATION_NOT_ESTABLISHED",
    "SOURCE_TRACE_RELATION_NOT_ESTABLISHED",
    "SOURCE_LAYER_BOUNDARY_NOT_ESTABLISHED",
    "SELF_STATUS_NOT_ESTABLISHED",
    "GLOBAL_CYCLE_NOT_ESTABLISHED",
    "COMPLETENESS_NOT_ESTABLISHED",
    "AGENCY_NOT_CHECKED",
)
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REF_FIELDS = {
    "ATOM": (), "APPLY": ("argument",), "ID": ("at",),
    "APPLY_STEP": ("source", "target"), "COMPOSE": ("left", "right"),
    "QUOTE": ("value",), "READ": ("code",),
}
_PROFILE_BYTES = canonical_bytes({
    "schema_version": "VSTD-TYPED-FORMATION-PROFILE-0.1",
    "subject_schema": SUBJECT_SCHEMA,
    "certificate_schema": CERTIFICATE_SCHEMA,
    "context_fields": ["ground_artifact_digest", "authority_axiom_agency_digest"],
    "context_meaning": "declared byte coordinates only; no grounding or agency proof",
    "rules": [
        "ATOM(payload_digest): opaque FORM symbol, not retrieved artifact",
        "APPLY(FORM): syntactic FORM application, not computation execution",
        "ID(FORM): empty PATH with equal endpoints",
        "APPLY_STEP(source:FORM,target:FORM): target exactly APPLY(source)",
        "COMPOSE(left:PATH,right:PATH): equal connecting endpoints; ordered trace concatenation",
        "QUOTE(value:T): CODE(T) bound to exact subject, node and dependency closure",
        "READ(code:CODE(T)): retained value T; preserve formation history and quotation rank",
    ],
    "node_order": "all references are strictly earlier integer node indices",
    "certificate_steps": "one ordered tag and exact ordered premises for every declared node",
    "identity": "normalized denotation and exact formation identity remain distinct",
    "limits": {
        "max_nodes": MAX_NODES, "max_depth": MAX_DEPTH,
        "max_path_steps": MAX_PATH_STEPS, "max_record_bytes": MAX_RECORD_BYTES,
        "max_json_depth": MAX_JSON_DEPTH, "max_json_containers": MAX_JSON_CONTAINERS,
    },
    "residual_obligations": list(RESIDUAL_OBLIGATIONS),
})


def profile_bytes() -> bytes:
    """Return the fixed inert rule declaration, never submitted executable code."""

    return _PROFILE_BYTES


def profile_digest() -> str:
    """Identify the fixed declaration; not a proof of its implementation."""

    return digest_bytes(_PROFILE_BYTES)


def _scan(data: bytes) -> None:
    depth = containers = 0
    quoted = escaped = False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            containers += 1
            if depth > MAX_JSON_DEPTH or containers > MAX_JSON_CONTAINERS:
                raise FormationLimitError("formation syntax budget exceeded")
        elif byte in (93, 125):
            depth -= 1
            if depth < 0:
                raise FormationError("unbalanced formation record")


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise FormationError("duplicate formation record field")
        result[key] = value
    return result


def _decode(data: bytes, schema: str) -> dict[str, Any]:
    if type(data) is not bytes:
        raise FormationError("formation input must be immutable bytes")
    if len(data) > MAX_RECORD_BYTES:
        raise FormationLimitError("formation record byte bound exceeded")
    _scan(data)
    try:
        value = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs)
        if canonical_bytes(value) != data:
            raise FormationError("formation record must have canonical bytes")
    except (ValueError, UnicodeError, NetworkError) as exc:
        raise FormationError("formation record is not canonical JSON") from exc
    if type(value) is not dict or type(value.get("schema_version")) is not str:
        raise FormationError("formation record needs a schema discriminator")
    if value["schema_version"] != schema:
        raise UnsupportedFormation("formation schema is unsupported")
    return value


def _fields(value: Any, fields: set[str]) -> None:
    if type(value) is not dict or set(value) != fields:
        raise FormationError("formation record fields do not match the schema")


def _digest(value: Any) -> None:
    if type(value) is not str or _DIGEST.fullmatch(value) is None:
        raise FormationError("formation coordinate is not a canonical digest")


def _index(value: Any, stop: int) -> None:
    if type(value) is not int or not 0 <= value < stop:
        raise FormationError("formation index is outside its admitted range")


def references(node: dict[str, Any]) -> tuple[int, ...]:
    """Return the ordered constructor references from an already decoded node."""

    return tuple(node[field] for field in _REF_FIELDS[node["tag"]])


def decode_subject(data: bytes) -> dict[str, Any]:
    """Admit finite syntax only; formation rules are checked independently."""

    value = _decode(data, SUBJECT_SCHEMA)
    _fields(value, {"schema_version", "profile_digest", "context", "nodes", "root"})
    _digest(value["profile_digest"])
    _fields(value["context"], {"ground_artifact_digest", "authority_axiom_agency_digest"})
    for coordinate in value["context"].values():
        _digest(coordinate)
    nodes = value["nodes"]
    if type(nodes) is not list or not nodes:
        raise FormationError("formation subject needs a nonempty node list")
    if len(nodes) > MAX_NODES:
        raise FormationLimitError("formation node bound exceeded")
    _index(value["root"], len(nodes))
    for index, node in enumerate(nodes):
        if type(node) is not dict or type(node.get("tag")) is not str:
            raise FormationError("formation node needs a constructor tag")
        tag = node["tag"]
        if tag not in _REF_FIELDS:
            raise FormationError("unknown constructor in a known formation schema")
        _fields(node, {"tag", *_REF_FIELDS[tag]} | ({"payload_digest"} if tag == "ATOM" else set()))
        if tag == "ATOM":
            _digest(node["payload_digest"])
        for reference in references(node):
            _index(reference, index)
    return value


def decode_certificate(data: bytes) -> dict[str, Any]:
    """Admit proof-step syntax, not a producer verdict or type assertion."""

    value = _decode(data, CERTIFICATE_SCHEMA)
    _fields(value, {"schema_version", "subject_digest", "profile_digest", "steps", "root"})
    _digest(value["subject_digest"])
    _digest(value["profile_digest"])
    steps = value["steps"]
    if type(steps) is not list or not steps:
        raise FormationError("formation certificate needs a nonempty step list")
    if len(steps) > MAX_NODES:
        raise FormationLimitError("formation certificate step bound exceeded")
    _index(value["root"], MAX_NODES)
    for step in steps:
        _fields(step, {"node", "rule", "premises"})
        _index(step["node"], MAX_NODES)
        if type(step["rule"]) is not str or step["rule"] not in _REF_FIELDS:
            raise FormationError("certificate rule must name a known constructor")
        if type(step["premises"]) is not list or len(step["premises"]) > 2:
            raise FormationError("certificate premises must be a bounded list")
        for premise in step["premises"]:
            _index(premise, MAX_NODES)
    return value
