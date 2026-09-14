"""Proof-step production for experimental Verifier Standard (VSTD) formation.

The producer constructs typed finite terms before emitting a certificate. It
shares no inference or normalization routine with the checker, and emitted steps
contain no acceptance flag. This calculus does not derive source ground, complete
Hypermath self-return, completeness, historical execution, or agency preservation.
An integer identifier (ID) selects a node; the ID tag constructs an identity path.
"""

from __future__ import annotations

from dataclasses import dataclass

from .formation_wire import (
    CERTIFICATE_SCHEMA, FormationError, FormationLimitError, MAX_DEPTH,
    MAX_PATH_STEPS, MAX_RECORD_BYTES, UnsupportedFormation, canonical_bytes,
    decode_subject, digest_bytes, profile_digest, references,
)


@dataclass(frozen=True)
class _Term:
    sort: str
    form: str | None = None
    start: str | None = None
    end: str | None = None
    trace: tuple[tuple[str, str], ...] = ()
    quotation: _Term | None = None


def produce_formation_certificate(subject_bytes: bytes) -> bytes:
    """Construct every admitted node or refuse; never call the checker."""

    subject = decode_subject(subject_bytes)
    if subject["profile_digest"] != profile_digest():
        raise UnsupportedFormation("producer does not implement this rule profile")
    terms: list[_Term] = []
    depths: list[int] = []
    steps: list[dict[str, object]] = []
    for index, node in enumerate(subject["nodes"]):
        premises = references(node)
        depth = 1 + max((depths[parent] for parent in premises), default=0)
        if depth > MAX_DEPTH:
            raise FormationLimitError("producer dependency depth exceeded")
        arguments = [terms[parent] for parent in premises]
        tag = node["tag"]
        if tag == "ATOM":
            term = _Term("FORM", form=digest_bytes(canonical_bytes({
                "kind": "ATOM", "payload_digest": node["payload_digest"],
            })))
        elif tag in {"APPLY", "ID", "APPLY_STEP"}:
            if any(argument.sort != "FORM" for argument in arguments):
                raise FormationError("producer requires form arguments")
            source = arguments[0].form
            if tag == "ID":
                term = _Term("PATH", start=source, end=source)
            else:
                application = digest_bytes(canonical_bytes({
                    "kind": "APPLY", "argument_digest": source,
                }))
                if tag == "APPLY":
                    term = _Term("FORM", form=application)
                else:
                    if arguments[1].form != application:
                        raise FormationError("producer application target differs")
                    if MAX_PATH_STEPS < 1:
                        raise FormationLimitError("producer path step bound exceeded")
                    assert source is not None
                    term = _Term("PATH", start=source, end=application,
                                 trace=((source, application),))
        elif tag == "COMPOSE":
            before, after = arguments
            if before.sort != "PATH" or after.sort != "PATH":
                raise FormationError("producer composition requires paths")
            if before.end != after.start:
                raise FormationError("producer composition endpoints differ")
            if len(before.trace) + len(after.trace) > MAX_PATH_STEPS:
                raise FormationLimitError("producer path step bound exceeded")
            term = _Term("PATH", start=before.start, end=after.end,
                         trace=before.trace + after.trace)
        elif tag == "QUOTE":
            term = _Term("CODE(" + arguments[0].sort + ")", quotation=arguments[0])
        elif tag == "READ":
            retained = arguments[0].quotation
            if retained is None or arguments[0].sort != "CODE(" + retained.sort + ")":
                raise FormationError("producer read requires quotation")
            term = retained
        else:
            raise UnsupportedFormation("producer constructor unsupported")
        terms.append(term)
        depths.append(depth)
        steps.append({"node": index, "rule": tag, "premises": list(premises)})
    encoded = canonical_bytes({
        "schema_version": CERTIFICATE_SCHEMA,
        "subject_digest": digest_bytes(subject_bytes),
        "profile_digest": profile_digest(),
        "steps": steps,
        "root": subject["root"],
    })
    if len(encoded) > MAX_RECORD_BYTES:
        raise FormationLimitError("produced certificate byte bound exceeded")
    return encoded
