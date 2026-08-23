"""Grounding validation for ``VSTD4-GDC-1`` -- rung 4.2, semantic binding.

A resolution proof establishes a fact about a *formula*. A VSTD claim is about
the *world*. The gap between them is an encoding, and an encoding is exactly
where a certificate can be flawless and still worthless.

That failure is not hypothetical. ``ProvenancePolicyVerifier`` in
:mod:`verifier.data.policy` computes ``passed = bool(sat and not
revoked_nodes)`` -- hedging the SAT result against a Python list, because its
author had no way to check that the encoding said what the policy meant. The
right fix is not to distrust the solver; it is to make the encoding checkable.

This module does that. Every variable is bound to a content-addressed fact,
every clause is bound to an instance of a named encoding rule, and the kernel
confirms that the two agree about *which subject* each literal is talking
about. A certificate that proves a perfectly valid statement about the wrong
artifact is then rejected on structure alone.

Like :mod:`verifier.core.certificate`, this module sits inside the trusted
computing base and imports nothing that produces verdicts.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Sequence

from .certificate import (
    CertificateError,
    ClauseGrounding,
    Grounding,
    normalize_clause,
)


@dataclass(frozen=True)
class GroundingResult:
    accepted: bool
    variables_checked: int
    clauses_checked: int
    details: str

    def to_dict(self) -> dict[str, object]:
        return {
            "accepted": self.accepted,
            "variables_checked": self.variables_checked,
            "clauses_checked": self.clauses_checked,
            "details": self.details,
        }


def _reject(message: str, variables: int = 0, clauses: int = 0) -> GroundingResult:
    return GroundingResult(False, variables, clauses, message)


def verify_grounding(
    formula: Sequence[Sequence[int]],
    grounding: Grounding,
) -> GroundingResult:
    """Confirm the formula is an honest encoding of the facts it claims to encode."""

    facts: dict[int, object] = {}
    subjects: dict[int, str] = {}
    for variable in grounding.variables:
        if variable.var in facts:
            return _reject(f"variable {variable.var} is grounded more than once")
        if variable.var <= 0:
            return _reject(f"variable {variable.var} is not a positive index")
        facts[variable.var] = variable.fact
        subjects[variable.var] = variable.fact.subject

    rules = {}
    for declared_rule in grounding.rules:
        if declared_rule.rule_id in rules:
            return _reject(
                f"encoding rule {declared_rule.rule_id!r} is declared more than once"
            )
        if len(set(declared_rule.roles)) != len(declared_rule.roles):
            return _reject(
                f"encoding rule {declared_rule.rule_id!r} repeats a role name"
            )
        for _, role in declared_rule.template:
            if role not in declared_rule.roles:
                return _reject(
                    f"encoding rule {declared_rule.rule_id!r} templates undeclared role {role!r}"
                )
        rules[declared_rule.rule_id] = declared_rule

    # Every variable the formula mentions must be grounded. An ungrounded
    # variable is a free-floating proposition: it can be assigned whatever the
    # proof needs without anyone being able to say what it asserted.
    mentioned = {abs(int(literal)) for clause in formula for literal in clause}
    ungrounded = sorted(mentioned - set(facts))
    if ungrounded:
        return _reject(
            "formula mentions variables with no grounded fact: "
            + ", ".join(str(var) for var in ungrounded)
        )

    by_index: dict[int, ClauseGrounding] = {}
    for clause_record in grounding.clauses:
        if clause_record.clause_index in by_index:
            return _reject(
                f"clause {clause_record.clause_index} is grounded more than once"
            )
        by_index[clause_record.clause_index] = clause_record

    missing = sorted(set(range(len(formula))) - set(by_index))
    if missing:
        return _reject(
            "clauses have no grounding: " + ", ".join(str(index) for index in missing)
        )
    extra = sorted(set(by_index) - set(range(len(formula))))
    if extra:
        return _reject(
            "grounding refers to clauses not in the formula: "
            + ", ".join(str(index) for index in extra)
        )

    for index in range(len(formula)):
        clause_record = by_index[index]
        rule = rules.get(clause_record.rule_id)
        if rule is None:
            return _reject(
                f"clause {index} cites undeclared encoding rule {clause_record.rule_id!r}",
                len(facts),
                index,
            )
        if set(clause_record.bindings) != set(rule.roles):
            return _reject(
                f"clause {index} binds roles {sorted(clause_record.bindings)} but rule "
                f"{rule.rule_id!r} declares {sorted(rule.roles)}",
                len(facts),
                index,
            )
        if set(clause_record.subjects) != set(rule.roles):
            return _reject(
                f"clause {index} names subjects for {sorted(clause_record.subjects)} but rule "
                f"{rule.rule_id!r} declares {sorted(rule.roles)}",
                len(facts),
                index,
            )

        try:
            instantiated = rule.instantiate(clause_record.bindings)
        except CertificateError as exc:
            return _reject(f"clause {index}: {exc}", len(facts), index)

        actual = normalize_clause(formula[index])
        if instantiated != actual:
            return _reject(
                f"clause {index} {list(actual)} is not an instance of "
                f"{rule.rule_id!r}, which yields {list(instantiated)}",
                len(facts),
                index,
            )

        # The keystone check. The clause says it is about these subjects; the
        # variables it uses say they are about those. If the two disagree, the
        # proof below is proving something true about the wrong thing.
        for role in rule.roles:
            var = clause_record.bindings[role]
            if var not in subjects:
                return _reject(
                    f"clause {index} binds role {role!r} to ungrounded variable {var}",
                    len(facts),
                    index,
                )
            if subjects[var] != clause_record.subjects[role]:
                return _reject(
                    f"clause {index} claims role {role!r} is about "
                    f"{clause_record.subjects[role]!r}, but variable {var} is grounded in a fact "
                    f"about {subjects[var]!r}",
                    len(facts),
                    index,
                )

    return GroundingResult(
        True,
        len(facts),
        len(formula),
        f"{len(facts)} variables and {len(formula)} clauses grounded in declared facts and rules",
    )
