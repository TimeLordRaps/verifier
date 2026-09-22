"""Verifier Standard (VSTD) bounded domain checking primitives.

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).
Numbers have the units declared by their domain contract; operation/item counts
are dimensionless and retained payload sizes count bytes. No input loads code.
"""
from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import math
from typing import Any

from verifier.core.certificate import canonical_bytes, canonical_digest


class Unavailable(ValueError):
    """Absent support, unsupported semantics, or exhausted checking budget."""


class Refuted(ValueError):
    """A bound proposition contradicts the supplied checked evidence."""


@dataclass
class Budget:
    limit: int
    max_items: int = 4096
    used: int = 0

    def tick(self, count: int = 1) -> None:
        self.used += count
        if self.used > self.limit:
            raise Unavailable("domain operation bound exhausted")


def need(value: dict, key: str) -> Any:
    if key not in value:
        raise Unavailable(f"required evidence absent: {key}")
    return value[key]


def obj(value: Any, keys: set[str] | None = None) -> dict:
    if not isinstance(value, dict) or (keys is not None and set(value) != keys):
        raise Refuted("unexpected object shape")
    return value


def seq(value: Any, budget: Budget, *, nonempty: bool = True) -> list:
    if not isinstance(value, list):
        raise Refuted("array required")
    if nonempty and not value:
        raise Unavailable("empty evidence cannot establish this proposition")
    if len(value) > budget.max_items:
        raise Unavailable("domain item bound exhausted")
    budget.tick(len(value))
    return value


def text(value: Any) -> str:
    if not isinstance(value, str) or not value.strip():
        raise Refuted("nonempty text required")
    return value


def number(value: Any) -> float:
    if type(value) not in (int, float) or abs(value) > 1e100 or not math.isfinite(value):
        raise Refuted("bounded finite real number required")
    return float(value)


def inspect_structure(value: Any, budget: Budget) -> None:
    """Charge input traversal before domain work without interpreting user field names."""
    pending = [value]
    while pending:
        item = pending.pop()
        budget.tick()
        if isinstance(item, (dict, list)):
            if len(item) > budget.max_items:
                raise Unavailable("domain collection bound exhausted")
            pending.extend(item.values() if isinstance(item, dict) else item)


def merkle_root(records: list, budget: Budget) -> str:
    """Ordered canonical record commitments; duplicate an unpaired leaf at each fold."""
    leaves = [digest(record) for record in records]
    if not leaves:
        return digest([])
    while len(leaves) > 1:
        budget.tick(len(leaves))
        leaves = [digest({"left": leaves[i], "right": leaves[min(i+1,len(leaves)-1)]})
                  for i in range(0,len(leaves),2)]
    return leaves[0]


def integer(value: Any, minimum: int = 0, maximum: int = 2**53-1) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise Refuted("bounded integer required")
    return value


def digest(value: Any) -> str:
    return "sha256:" + canonical_digest(value)


def same(actual: Any, expected: Any, reason: str) -> None:
    if canonical_bytes(actual) != canonical_bytes(expected):
        raise Refuted(reason)


def close(actual: Any, expected: Any, tolerance: Any, reason: str) -> None:
    tol = number(tolerance)
    if tol < 0 or abs(number(actual)-number(expected)) > tol:
        raise Refuted(reason)


def materialize(record: Any, budget: Budget) -> bytes:
    value = obj(record, {"sha256", "base64"})
    try:
        data = base64.b64decode(value["base64"], validate=True)
    except (TypeError, ValueError) as exc:
        raise Refuted("invalid retained byte encoding") from exc
    budget.tick(len(data))
    if "sha256:" + hashlib.sha256(data).hexdigest() != value["sha256"]:
        raise Refuted("retained artifact digest mismatch")
    return data


def legacy(value: Any, cls: Any, schema: str | None = None) -> Any:
    """Reuse existing records while rejecting coercions, extras and stale digests."""
    value = obj(value)
    if schema is not None and value.get("schema_version") != schema:
        raise Unavailable("unsupported domain record version")
    result = cls.from_dict(value)
    same(result.to_dict(), value, "domain record is noncanonical or its digest differs")
    return result


CERTIFICATE_FIELDS = {"schema_version", "request", "evidence", "policy_digest", "mechanism_digest",
                      "specification_digest", "result", "certificate_digest"}
EVIDENCE_FIELDS = {"schema_version", "domain", "subject_id", "artifact", "inputs"}


def bind_certificate(inputs: dict, artifact: dict, key: str, domain: str,
                     mechanism_digest: str, depth: int) -> dict:
    """Re-derive one bound domain certificate from its retained bytes and return its evidence.

    A certificate carrying a different mechanism digest is `Unavailable`, not a weaker
    witness. Binding supplies no assurance of its own: the bound result is a ceiling on
    what the binding certificate may establish, never a floor beneath it.
    """
    certificate = obj(need(inputs, key + "_certificate"), CERTIFICATE_FIELDS)
    same(certificate["schema_version"], "verifier-domain-certification-1", "unsupported bound certificate")
    body = {k: v for k, v in certificate.items() if k != "certificate_digest"}
    same(digest(body), certificate["certificate_digest"], "bound certificate digest differs")
    same(digest(certificate), need(artifact, key + "_certificate_digest"),
         "bound certificate differs from the retained one")
    if certificate["mechanism_digest"] != mechanism_digest:
        raise Unavailable("bound certificate was produced by a different mechanism")
    evidence = obj(certificate["evidence"], EVIDENCE_FIELDS)
    if evidence["domain"] != domain:
        raise Refuted("bound certificate certifies a different domain")
    result = obj(certificate["result"])
    if result.get("object_profile_conformance") != "NOT_ESTABLISHED":
        raise Refuted("bound certificate misreports object profile conformance")
    if result.get("status") != "PASS":
        raise Unavailable("bound certificate did not establish its own domain")
    established = result.get("domain_depth")
    if type(established) is not int or established < depth:
        raise Unavailable("bound certificate did not reach the domain depth this binding requires")
    return evidence


def unique(records: list, key: str) -> dict:
    result = {}
    for record in records:
        identifier = text(obj(record)[key])
        if identifier in result:
            raise Refuted(f"duplicate {key}")
        result[identifier] = record
    return result


def expression(node: Any, variables: dict, budget: Budget, depth: int = 0) -> Any:
    """Interpret a finite expression tree without imports, eval, loops or calls."""
    budget.tick()
    if depth > 32:
        raise Unavailable("expression nesting bound exhausted")
    if type(node) in (int, float):
        return number(node)
    node = obj(node)
    if set(node) == {"var"}:
        return number(need(variables, text(node["var"])))
    obj(node, {"op", "args"})
    op = node["op"]
    args = seq(node["args"], budget)
    arity = 1 if op in ("abs", "neg") else 2
    if len(args) != arity:
        raise Refuted("expression arity mismatch")
    values = [expression(arg, variables, budget, depth+1) for arg in args]
    a = values[0]
    b = values[-1]
    if op in ("and", "or"):
        if any(type(v) is not bool for v in values):
            raise Refuted("Boolean expression operands required")
        return a and b if op == "and" else a or b
    if any(type(v) is bool for v in values):
        raise Refuted("Boolean value cannot substitute for a real number")
    operators = {"add": lambda: a+b, "sub": lambda: a-b, "mul": lambda: a*b,
                 "div": lambda: a/b, "min": lambda: min(a,b), "max": lambda: max(a,b),
                 "abs": lambda: abs(a), "neg": lambda: -a,
                 "le": lambda: a<=b, "lt": lambda: a<b, "eq": lambda: a==b,
                 "ge": lambda: a>=b, "gt": lambda: a>b}
    if op not in operators:
        raise Unavailable("unsupported expression operator")
    result = operators[op]()
    return result if type(result) is bool else number(result)
