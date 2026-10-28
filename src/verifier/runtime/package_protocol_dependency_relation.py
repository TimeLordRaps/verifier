"""Source-owned package relation for the shared worker protocol dependency.

The ledger and manifest-write objects are OBJECT-based consequence carriers, so
their layouts must remain operand-free.  This HYPER object carries the literal
package-graph relation instead: two dependent objects share one protocol
exchange.  It is structural source data only.  The relation does not claim that
the endpoints execute, that the protocol obligations are discharged, or that a
runtime call follows the declared edges.
"""

from __future__ import annotations

from typing import Final


OBJECT_ID: Final = "vstd-package-worker-dependency-relation"
PRIMARY_KIND: Final = "HYPER"
SOURCE_PATH: Final = "src/verifier/runtime/package_protocol_dependency_relation.py"
OWNED_PATHS: Final = (SOURCE_PATH,)

# Keep each endpoint tuple on one line.  The package namespace review binds
# these exact source anchors so a renamed or silently substituted endpoint
# reopens review instead of leaving stale dependency prose in objects.vstd.
DEPENDENT_OBJECT_IDS: Final = ("vstd-invocation-ledger", "vstd-manifest-write")
PROTOCOL_EXCHANGE_OBJECT_IDS: Final = ("vstd-package-worker-exchange",)
OPERANDS: Final = (
    ("dependents", DEPENDENT_OBJECT_IDS),
    ("protocol_exchange", PROTOCOL_EXCHANGE_OBJECT_IDS),
)

REPRESENTATION_ROLE: Final = (
    "Literal package HYPER relation from the invocation-ledger and manifest-write "
    "dependents to their shared package-worker protocol exchange."
)
NECESSITY_REASON: Final = (
    "The two base-OBJECT participants cannot carry typed dependency operands, "
    "while review-only dependency annotations are not package-graph edges; one "
    "source-owned HYPER relation is therefore necessary to preserve the literal "
    "three-edge dependency in the admitted graph."
)
CONSEQUENCE_BOUNDARY: Final = (
    "The relation declares only direct package composition. It transfers no source "
    "ownership, proves no runtime call or protocol behavior, discharges no HYPER or "
    "PROTOCOL obligation, and gives no participant an operand of its own."
)
PARTICIPANT_DEPENDENCY_REASON: Final = (
    "The local adapter delegates its fixed request/reply transport to the uniquely "
    "owned package worker exchange, and the source-owned HYPER dependency relation "
    "carries that direct package-graph edge; dependency does not transfer source "
    "ownership or make the transport an owned local endpoint."
)
SOURCE_ANCHORS: Final = (
    'DEPENDENT_OBJECT_IDS: Final = ("vstd-invocation-ledger", "vstd-manifest-write")',
    'PROTOCOL_EXCHANGE_OBJECT_IDS: Final = ("vstd-package-worker-exchange",)',
)


def validate_operands(
    operands: tuple[tuple[str, tuple[str, ...]], ...],
) -> tuple[tuple[str, tuple[str, ...]], ...]:
    """Accept only the reviewed literal endpoints; unknown never means exemption."""
    if type(operands) is not tuple or operands != OPERANDS:
        raise ValueError("PACKAGE_PROTOCOL_DEPENDENCY_RELATION_OPERANDS_DIFFER")
    return operands


__all__ = [
    "CONSEQUENCE_BOUNDARY",
    "DEPENDENT_OBJECT_IDS",
    "NECESSITY_REASON",
    "OBJECT_ID",
    "OPERANDS",
    "OWNED_PATHS",
    "PARTICIPANT_DEPENDENCY_REASON",
    "PRIMARY_KIND",
    "PROTOCOL_EXCHANGE_OBJECT_IDS",
    "REPRESENTATION_ROLE",
    "SOURCE_ANCHORS",
    "SOURCE_PATH",
    "validate_operands",
]
