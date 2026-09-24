"""Composition delta analysis for Level 6 disclosure bounds (obligation 6.5).

Acronyms:
    JavaScript Object Notation (JSON);
    Verifier Standard (VSTD).
"""

from __future__ import annotations

from typing import Any

from .models import ObserverParty


HIGH_RISK_JOIN_PAIRS: tuple[tuple[str, str, str], ...] = (
    ("ACTOR", "OWNER", "locates party in structure of holdings"),
    ("TOKEN", "ACTOR", "singles party out via birth epoch and tenure uniqueness"),
    ("DATA", "TRAIN", "reveals training distribution and dataset membership"),
    ("MODEL", "SIM", "exposes simulation dynamics and transition policies"),
    ("BOT", "AGENT", "correlates autonomous agent execution harness"),
)


class CompositionDeltaEvaluator:
    """Evaluates information leakage over relational joins of co-emitted certificates (obligation 6.5).

    Disclosure is the join of the operands rather than bounded by either alone.
    Two certificates that are individually admissible to an observer may, when
    emitted together, disclose a correlation that violates disclosure bounds.
    """

    def __init__(self, custom_join_rules: tuple[tuple[str, str, str], ...] | None = None) -> None:
        self.join_rules = HIGH_RISK_JOIN_PAIRS if custom_join_rules is None else custom_join_rules

    def evaluate_composition_delta(
        self,
        primary_cert: dict[str, Any],
        co_emitted: tuple[dict[str, Any], ...],
        observer: ObserverParty,
    ) -> tuple[bool, str, dict[str, Any]]:
        """Evaluate whether co-emitting certificates leaks relational join information.

        Returns:
            tuple of (is_admissible, failure_reason, join_details).
        """
        primary_object = (
            primary_cert.get("object_name")
            or primary_cert.get("domain")
            or primary_cert.get("object")
            or ""
        ).upper()

        if not co_emitted:
            return True, "", {"joins_detected": [], "primary_object": primary_object}

        detected_joins: list[dict[str, str]] = []
        for other in co_emitted:
            other_object = (
                other.get("object_name")
                or other.get("domain")
                or other.get("object")
                or ""
            ).upper()
            if not other_object:
                continue

            for obj_a, obj_b, reason in self.join_rules:
                if (primary_object == obj_a and other_object == obj_b) or (
                    primary_object == obj_b and other_object == obj_a
                ):
                    # Check if observer has explicit role authorization to join these two objects
                    authorized_roles = {"auditor", "verifier_admin", "compliance_officer"}
                    if observer.role.lower() not in authorized_roles:
                        detected_joins.append({
                            "object_a": primary_object,
                            "object_b": other_object,
                            "risk": reason,
                        })

        if detected_joins:
            reasons = "; ".join(f"{j['object_a']}+{j['object_b']}: {j['risk']}" for j in detected_joins)
            return (
                False,
                f"Unauthorized relational join detected: {reasons}",
                {"joins_detected": detected_joins, "primary_object": primary_object},
            )

        return True, "", {"joins_detected": [], "primary_object": primary_object}
