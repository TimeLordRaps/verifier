"""Independent finite typed-formation checking for Verifier Standard (VSTD).

This checker reconstructs typed values and ordered formation paths from retained
syntax and a fixed rule profile. It imports no producer or shared inference
routine. A checked construction is not evidence that it historically executed,
originated from the Hypermath ground, or establishes self-derivation, source
trace relations, completeness, or authority axiom agency.

Quotation retains its checked value and dependency history. Reading it preserves
that history and its quotation rank; normalized value identity never substitutes
for exact formation identity. All quantities here are dimensionless counts or
byte identities, not physical measurements.
An integer identifier (ID) selects a node; the ID tag constructs an identity path.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from .formation_wire import (
    FormationError,
    FormationLimitError,
    MAX_DEPTH,
    MAX_PATH_STEPS,
    RESIDUAL_OBLIGATIONS,
    UnsupportedFormation,
    canonical_bytes,
    decode_certificate,
    decode_subject,
    digest_bytes,
    profile_digest,
    references,
)


@dataclass(frozen=True)
class _Value:
    type: str
    denotation_digest: str
    source_digest: str | None = None
    target_digest: str | None = None
    path_steps: tuple[tuple[str, str], ...] = ()
    quoted_value: _Value | None = None


@dataclass(frozen=True)
class _CheckedNode:
    value: _Value
    quote_rank: int
    required_depth: int
    dependency_nodes: frozenset[int]
    quote_origins: frozenset[int]


def _digest(value: dict[str, Any]) -> str:
    return digest_bytes(canonical_bytes(value))


def _path(
    source: str, target: str, steps: tuple[tuple[str, str], ...]
) -> _Value:
    return _Value(
        "PATH",
        _digest({
            "kind": "PATH",
            "source_digest": source,
            "target_digest": target,
            "path_steps": [
                {"source_digest": start, "target_digest": end}
                for start, end in steps
            ],
        }),
        source,
        target,
        steps,
    )


def _require_type(value: _Value, expected: str) -> None:
    if value.type != expected:
        raise FormationError("formation rule has an incompatible input type")


def _infer_value(
    node: dict[str, Any], inputs: tuple[_CheckedNode, ...], subject_digest: str
) -> _Value:
    """Infer a value directly; certificate fields never supply a typed result."""

    tag = node["tag"]
    if tag == "ATOM":
        return _Value("FORM", _digest({
            "kind": "ATOM", "payload_digest": node["payload_digest"],
        }))
    if tag == "APPLY":
        argument = inputs[0].value
        _require_type(argument, "FORM")
        return _Value("FORM", _digest({
            "kind": "APPLY", "argument_digest": argument.denotation_digest,
        }))
    if tag == "ID":
        at = inputs[0].value
        _require_type(at, "FORM")
        return _path(at.denotation_digest, at.denotation_digest, ())
    if tag == "APPLY_STEP":
        source, target = (item.value for item in inputs)
        _require_type(source, "FORM")
        _require_type(target, "FORM")
        expected = _digest({
            "kind": "APPLY", "argument_digest": source.denotation_digest,
        })
        if target.denotation_digest != expected:
            raise FormationError("application step does not reach its exact application")
        if MAX_PATH_STEPS < 1:
            raise FormationLimitError("expanded path step bound exceeded")
        return _path(
            source.denotation_digest,
            target.denotation_digest,
            ((source.denotation_digest, target.denotation_digest),),
        )
    if tag == "COMPOSE":
        left, right = (item.value for item in inputs)
        _require_type(left, "PATH")
        _require_type(right, "PATH")
        if left.target_digest != right.source_digest:
            raise FormationError("composition endpoints do not agree")
        if len(left.path_steps) + len(right.path_steps) > MAX_PATH_STEPS:
            raise FormationLimitError("expanded path step bound exceeded")
        assert left.source_digest is not None and right.target_digest is not None
        return _path(
            left.source_digest, right.target_digest,
            left.path_steps + right.path_steps,
        )
    if tag == "QUOTE":
        original = inputs[0]
        return _Value(
            "CODE(" + original.value.type + ")",
            _digest({
                "kind": "CODE",
                "subject_digest": subject_digest,
                "node": node["value"],
                "dependency_nodes": sorted(original.dependency_nodes),
            }),
            quoted_value=original.value,
        )
    if tag == "READ":
        code = inputs[0].value
        if code.quoted_value is None or code.type != "CODE(" + code.quoted_value.type + ")":
            raise FormationError("read requires a checked quoted value")
        return code.quoted_value
    raise UnsupportedFormation("formation constructor is unsupported")


def check_formation(subject_bytes: bytes, certificate_bytes: bytes) -> dict[str, Any]:
    """Check the exact finite formation claim without executing uploaded code.

    Cheap whole-record and certificate bindings precede source-order inference.
    An inference or resource failure stops this bounded check; later semantic
    errors are not claimed to have been examined. No partial observation is
    promoted to a checked root. Residual source obligations remain on every result.
    """

    compiled_profile = profile_digest()
    result: dict[str, Any] = {
        "status": "UNKNOWN",
        "subject_digest": None,
        "profile_digest": compiled_profile,
        "root": None,
        "observation": None,
        "reason_codes": [],
        "residual_obligations": list(RESIDUAL_OBLIGATIONS),
    }
    invalid_reason = "FORMATION_RECORD_INVALID"
    try:
        subject = decode_subject(subject_bytes)
        subject_digest = digest_bytes(subject_bytes)
        result["subject_digest"] = subject_digest
        result["root"] = subject["root"]
        certificate = decode_certificate(certificate_bytes)
        if subject["profile_digest"] != compiled_profile:
            raise UnsupportedFormation("formation rule profile is unsupported")
        invalid_reason = "FORMATION_CERTIFICATE_BINDING_INVALID"
        if (
            certificate["subject_digest"] != subject_digest
            or certificate["profile_digest"] != compiled_profile
            or certificate["root"] != subject["root"]
        ):
            raise FormationError("certificate does not bind the exact subject and profile")
        invalid_reason = "FORMATION_CERTIFICATE_STEP_INVALID"
        nodes = subject["nodes"]
        steps = certificate["steps"]
        if len(steps) != len(nodes):
            raise FormationError("certificate must justify every declared node")
        for index, (node, step) in enumerate(zip(nodes, steps)):
            if (
                step["node"] != index
                or step["rule"] != node["tag"]
                or tuple(step["premises"]) != references(node)
            ):
                raise FormationError("certificate step does not match its constructor")

        invalid_reason = "FORMATION_RULE_INVALID"
        checked: list[_CheckedNode] = []
        for index, node in enumerate(nodes):
            inputs = tuple(checked[reference] for reference in references(node))
            depth = 1 + max((item.required_depth for item in inputs), default=0)
            if depth > MAX_DEPTH:
                raise FormationLimitError("formation dependency depth bound exceeded")
            rank = max((item.quote_rank for item in inputs), default=0)
            dependencies = frozenset((index,)).union(
                *(item.dependency_nodes for item in inputs)
            )
            origins = frozenset().union(*(item.quote_origins for item in inputs))
            if node["tag"] == "QUOTE":
                rank += 1
                origins = origins | {index}
            value = _infer_value(node, inputs, subject_digest)
            checked.append(_CheckedNode(value, rank, depth, dependencies, origins))

        root = checked[subject["root"]]
        value = root.value
        result["status"] = "CHECKED"
        result["observation"] = {
            "type": value.type,
            "denotation_digest": value.denotation_digest,
            "source_digest": value.source_digest,
            "target_digest": value.target_digest,
            "path_steps": [
                {"source_digest": start, "target_digest": end}
                for start, end in value.path_steps
            ],
            "quote_rank": root.quote_rank,
            "required_depth": root.required_depth,
            "formation_digest": _digest({
                "subject_digest": subject_digest, "node": subject["root"],
            }),
            "dependency_nodes": sorted(root.dependency_nodes),
            "quote_origins": sorted(root.quote_origins),
        }
    except UnsupportedFormation:
        result["reason_codes"] = ["FORMATION_PROFILE_UNSUPPORTED"]
    except FormationLimitError:
        result["reason_codes"] = ["FORMATION_LIMIT_EXCEEDED"]
    except FormationError:
        result["status"] = "INVALID"
        result["reason_codes"] = [invalid_reason]
    return result
