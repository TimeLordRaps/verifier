"""Carry derived Verifier Standard (VSTD) kinds into package obligations.

Admission and higher-tier selection use the same classification and consequence
mechanisms. A required role adds checks; it never casts an existing record into
a different typed subject. Unavailable discovery leaves selection unresolved,
not an empty successful denominator or evidence of absence of additional roles.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from verifier.domains.contracts import current_object_routes
from verifier.runtime import namespace_admission
from verifier.runtime import namespace_classification as classification
from verifier.runtime import namespace_consequences as consequences
from verifier.runtime import namespace_contracts as contracts
from verifier.runtime import namespace_discovery as discovery
from verifier.runtime import package_harness_applicability
from verifier.runtime.tier_zero_profile import value_digest


def accepts_subject(route: dict[str, Any], kind: str) -> bool:
    """Use native kind rules; generic record checks deliberately accept any kind."""
    try:
        current_object_routes.select_current_object_route(semantic_version=route["semantic_version"],
            objective=route["coordinate"], represented_kind=kind)
    except current_object_routes.CurrentObjectRouteRefusal:
        return False
    return True


class KindRequirements:
    """One source snapshot and its additive requirement basis; no subject runs."""

    def __init__(self, root: Path, declaration: dict[str, Any]) -> None:
        self.root = root
        self.registry = contracts.namespace_registry(declaration["extensions"])
        self.declarations = {row["object_id"]: row for row in declaration["objects"]}
        self.execution_mechanisms: dict[str, frozenset[str]] = {
            identifier: frozenset(
                row["mechanism"]
                for row in declaration.get("execution_checks", [])
                if row.get("object_id") == identifier
                and type(row.get("mechanism")) is str
            )
            for identifier in self.declarations
        }
        try:
            observed = discovery.discover(root)
        except ValueError as exc:
            if not str(exc).endswith(("_UNAVAILABLE", "_CAPACITY", "_CAPACITY_EXHAUSTED")):
                raise
            raise OSError("PACKAGE_KIND_REQUIREMENTS_UNAVAILABLE: " + str(exc)) from exc
        # Retain this exact in-memory discovery snapshot for package-tier source
        # adapters.  Re-running discovery per object would create thousands of
        # inconsistent coordinates and make graph cost dominate subject work.
        # ``recapture`` below still closes the snapshot against current bytes.
        self.observed = observed
        self.census = observed["census"]
        self.javascript_mechanism = observed.get("javascript_mechanism")
        self.systems_mechanism = observed.get("systems_mechanism")
        self.markup_binding = discovery.namespace_html.binding(observed)
        self.workflow_binding = observed.get("workflow_binding", discovery.namespace_workflows.EMPTY)
        consequential = consequences.assess_consequences(declaration["objects"], self.registry,
            observed, declaration.get("consequence_graph"))
        # The same fresh closure context as admission: a package path cannot establish
        # a DOES_NOT_APPLY that admission would refuse, and vice versa.
        refutation_context = classification.refutation_context(
            observed, value_digest(namespace_admission.mechanism_binding()), root=root)
        documented_answers: tuple[dict[str, str], ...] = ()
        if (root / "reasons.vstd").is_file():
            from verifier.runtime.tier_zero_reasoning import integration as reason_integration

            reason_selection = reason_integration.select_root_reasons(root)
            documented_answers = reason_integration.documented_applicability_answers(
                reason_selection, declaration["objects"]
            )
        classified = classification.assess_classification(declaration["objects"], self.registry,
            observed, consequence_kinds=consequential["required_kinds"],
            refutation_context=refutation_context,
            documented_applicability_answers=documented_answers)
        self.harness_applicability = package_harness_applicability.assess_selected_repository(
            root, declaration, classified["objects"])
        self.objects = {row["object_id"]: row for row in classified["objects"]}
        findings = consequential["findings"] + classified["findings"]
        status = ("FAIL" if any(row["status"] == "FAIL" for row in findings)
                  else "UNKNOWN" if findings or observed["gaps"] else "PASS")
        if self.harness_applicability["selection_status"] == "SELECTED":
            if self.harness_applicability["status"] == "FAIL":
                status = "FAIL"
            elif self.harness_applicability["status"] != "PASS" and status == "PASS":
                status = "UNKNOWN"
        self.report = {"status": status, "discovery_status": "PASS",
            "export_binding_digest": value_digest(observed.get("export_bindings", [])),
            "javascript_mechanism": self.javascript_mechanism,
            "systems_mechanism": self.systems_mechanism,
            "markup_binding": self.markup_binding,
            "workflow_binding": self.workflow_binding,
            "source_census_digest": self.census["census_digest"],
            "discovery_gaps": observed["gaps"], "findings": findings, "objects": classified["objects"],
            "harness_applicability": self.harness_applicability,
            "consequence_graph": consequential,
            "claim_boundary": "Derived obligation selection only; no typed-record conversion, domain applicability proof, execution or confinement claim."}

    def kinds(self, object_id: str) -> set[str]:
        """Return the full effective set, including unrefuted conditional hints."""
        return set(self.objects[object_id]["effective_kinds"])

    def basis(self, object_id: str, kind: str) -> dict[str, Any]:
        row = self.objects[object_id]
        return {"kind": kind, "declared": kind in row["declared_kinds"],
            "necessity": "NECESSARY" if kind in row["necessary_kinds"] else "CONDITIONAL_UNRESOLVED",
            "reasons": row["kind_reasons"][kind],
            "source_census_digest": self.report["source_census_digest"]}

    def refinements(self, tier: int) -> list[dict[str, Any]]:
        """Missing specialized contracts stay separate from registered instances."""
        return [{"object_id": identifier, "kind": kind, "through_tier": tier, "status": "UNKNOWN",
                 "reason": self.registry[kind].reason,
                 "blocker": "PACKAGE_REFINEMENT_HIGHER_TIER_CONTRACT_NOT_ESTABLISHED",
                 "base_obligations_inherited": True, "kind_requirement": self.basis(identifier, kind)}
                for identifier in self.objects for kind in sorted(self.kinds(identifier))
                if self.registry[kind].extends is not None]

    def recapture(self) -> None:
        """Retain the exact discovery snapshot through package or focused replay."""
        discovery.namespace_javascript.recapture(self.javascript_mechanism)
        discovery.namespace_systems.recapture(self.systems_mechanism)
        discovery.namespace_html.recapture(self.markup_binding["mechanism"])
        discovery.namespace_svg.recapture(self.markup_binding["svg_mechanism"])
        discovery.namespace_workflows.recapture(self.workflow_binding)
        if discovery.capture_candidate_source_census(
                self.root, allow_untracked_only=True) != self.census:
            raise ValueError("PACKAGE_KIND_SOURCE_CHANGED")
