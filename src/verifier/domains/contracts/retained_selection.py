"""Plain-value selection shared by retained TIME, SPACE and EVENT checkers.

Secure Hash Algorithm 256-bit (SHA-256) commits exact selected bytes.
Certificate limits are bytes; checker budgets and identifiers are dimensionless.
This module captures selection and policy infrastructure, not native evidence
evaluation. Error types, versions, ceilings and the installed-source reader are
trusted adapter configuration, not values admitted from evidence.
"""
from __future__ import annotations

import re
from typing import Any, Callable, Mapping

from verifier.core.certificate import canonical_digest

_HASH = re.compile(r"sha256:[0-9a-f]{64}\Z")


def record(value: Any, fields: set[str], label: str,
           error_type: type[ValueError]) -> dict[str, Any]:
    """Copy an exact plain record without invoking foreign key callbacks."""
    if (type(value) is not dict or any(type(key) is not str for key in value)
            or set(value) != fields):
        raise error_type(label + " fields differ")
    return dict(value)


def commitment(value: Any, error_type: type[ValueError]) -> str:
    """Capture a canonical prefixed commitment without string coercion."""
    if type(value) is not str or _HASH.fullmatch(value) is None:
        raise error_type("canonical SHA-256 commitment required")
    return value


def policy(value: Any, *, error_type: type[ValueError], version: str,
           mechanism_id: str, current_digest: Callable[[], str],
           max_certificate_bytes: int) -> dict[str, Any]:
    """Capture selected policy before comparing installed code or root labels."""
    selected = record(value, {
        "schema_version", "mechanism_id", "mechanism_digest",
        "trust_roots", "max_certificate_bytes",
    }, "policy", error_type)
    if (type(selected["schema_version"]) is not str
            or type(selected["mechanism_id"]) is not str
            or selected["schema_version"] != version
            or selected["mechanism_id"] != mechanism_id):
        raise error_type("policy mechanism differs")
    if commitment(selected["mechanism_digest"], error_type) != current_digest():
        raise error_type("policy differs from installed mechanism")
    roots = selected["trust_roots"]
    if (type(roots) is not list or not 1 <= len(roots) <= 16
            or any(type(root) is not str or not root.strip() or len(root) > 256 for root in roots)
            or roots != sorted(set(roots))):
        raise error_type("bounded sorted unique trust-root labels required")
    size = selected["max_certificate_bytes"]
    if type(size) is not int or not 1 <= size <= max_certificate_bytes:
        raise error_type("certificate byte bound is unsupported")
    selected["trust_roots"] = list(roots)
    return selected


def limits(value: Any, ceilings: Mapping[str, int],
           error_type: type[ValueError]) -> dict[str, int]:
    """Own the exact finite plain-integer checker limits."""
    selected = record(value, set(ceilings), "limits", error_type)
    if any(type(selected[key]) is not int or not 1 <= selected[key] <= ceiling
           for key, ceiling in ceilings.items()):
        raise error_type("finite checker limit is unsupported")
    return selected


def parameters(request: dict[str, Any]) -> dict[str, str]:
    """Bind previously captured request fields and the exact checker limits."""
    return {
        **{key: request[key] for key in (
            "semantic_version", "proposition_digest", "object_kind",
            "object_digest", "collection_digest", "policy_digest",
        )},
        "limits_digest": "sha256:" + canonical_digest(request["limits"]),
    }
