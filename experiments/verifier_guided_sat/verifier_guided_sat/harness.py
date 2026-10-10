# Acronyms: JavaScript Object Notation (JSON); Boolean satisfiability problem (SAT).
"""Unchanged verifier-first harness shared by development and held-out domains."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from time import perf_counter_ns
from typing import Any, Protocol

from .baselines import canonical_route
from .contracts import NativeVerdict
from .external_verifiers import ExternalVerifier
from .independent_validation import independently_validate_record
from .lm_backend import LmObservation, LmResponseError
from .route import RouteError, compile_route
from .sat_backend import CadicalBackend, SatObservation, SatStatus
from .vstd_binding import build_record, validate_record


DEFAULT_RESOURCE_BOUNDS = {
    "max_slots": 128,
    "max_domain_values_per_slot": 256,
    "max_constraints": 20_000,
    "max_compiled_clauses": 500_000,
    "lm_requests_per_arm_instance": 1,
    "outer_native_verifier_timeout": "not implemented; bounded benchmark instances only",
}


class LmBackend(Protocol):
    """Generic completion boundary implemented by real backends and test fixtures."""

    def complete_json(self, system_prompt: str, user_prompt: str) -> LmObservation:
        """Return one observed JSON completion or raise ``LmResponseError``."""
        ...


@dataclass(frozen=True)
class Trial:
    arm: str
    domain: str
    instance_id: str
    record: dict[str, Any]
    metrics: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "arm": self.arm,
            "domain": self.domain,
            "instance_id": self.instance_id,
            "record": self.record,
            "metrics": self.metrics,
        }


class VerifierGuidedHarness:
    def __init__(self, experiment_root: Path, solver: CadicalBackend | None = None) -> None:
        self.experiment_root = experiment_root
        self.solver = solver or CadicalBackend()

    def run_arm_a(
        self,
        instance_id: str,
        verifier: ExternalVerifier,
        instance: dict[str, Any],
        preparation_ns: int = 0,
    ) -> Trial:
        trial_started = perf_counter_ns()
        route = canonical_route(verifier.domain, instance)
        return self._run_route(
            "A",
            instance_id,
            verifier,
            instance,
            route,
            None,
            trial_started_ns=trial_started,
            harness_started_ns=trial_started,
            preparation_ns=preparation_ns,
        )

    def run_arm_b(
        self,
        instance_id: str,
        verifier: ExternalVerifier,
        instance: dict[str, Any],
        lm: LmBackend,
        system_prompt: str,
        user_prompt: str,
        preparation_ns: int = 0,
    ) -> Trial:
        trial_started = perf_counter_ns()
        try:
            lm_observation = lm.complete_json(system_prompt, user_prompt)
        except LmResponseError as exc:
            return self._finish(
                arm="B",
                instance_id=instance_id,
                verifier=verifier,
                instance=instance,
                proposal={"lm_failure": {"type": type(exc).__name__}},
                formula=None,
                solver_observation=None,
                candidate=None,
                native=None,
                lm_observation=None,
                harness_ns=preparation_ns,
                generate_and_check_equivalent=True,
                failure_observation={
                    "stage": "lm_generation",
                    "status": "ERROR",
                    "diagnostic": str(exc),
                },
                lm_failure_elapsed_ns=exc.elapsed_ns,
                trial_started_ns=trial_started,
                preparation_ns=preparation_ns,
            )
        harness_started = perf_counter_ns()
        if set(lm_observation.structured_output) != {"candidate"}:
            return self._finish(
                arm="B",
                instance_id=instance_id,
                verifier=verifier,
                instance=instance,
                proposal=lm_observation.structured_output,
                formula=None,
                solver_observation=None,
                candidate=None,
                native=None,
                lm_observation=lm_observation,
                harness_ns=preparation_ns + perf_counter_ns() - harness_started,
                generate_and_check_equivalent=True,
                failure_observation={
                    "stage": "proposal_contract",
                    "status": "REJECTED",
                    "diagnostic": "Arm B requires exactly one candidate field",
                },
                trial_started_ns=trial_started,
                preparation_ns=preparation_ns,
            )
        candidate_raw = lm_observation.structured_output.get("candidate")
        candidate = candidate_raw if isinstance(candidate_raw, dict) else None
        harness_ns = preparation_ns + perf_counter_ns() - harness_started
        native = verifier.verify(instance, candidate) if candidate is not None else None
        return self._finish(
            arm="B",
            instance_id=instance_id,
            verifier=verifier,
            instance=instance,
            proposal=lm_observation.structured_output,
            formula=None,
            solver_observation=None,
            candidate=candidate,
            native=native,
            lm_observation=lm_observation,
            harness_ns=harness_ns,
            generate_and_check_equivalent=True,
            failure_observation=(
                None
                if native is not None and native.verdict is NativeVerdict.ACCEPTED
                else (
                    {
                        "stage": "native_verifier",
                        "status": native.verdict.value,
                        "diagnostic": "complete candidate was not accepted",
                    }
                    if native is not None
                    else {
                        "stage": "proposal_contract",
                        "status": "REJECTED",
                        "diagnostic": "Arm B candidate must be an object",
                    }
                )
            ),
            trial_started_ns=trial_started,
            preparation_ns=preparation_ns,
        )

    def run_arm_c(
        self,
        instance_id: str,
        verifier: ExternalVerifier,
        instance: dict[str, Any],
        lm: LmBackend,
        system_prompt: str,
        user_prompt: str,
        preparation_ns: int = 0,
    ) -> Trial:
        trial_started = perf_counter_ns()
        try:
            lm_observation = lm.complete_json(system_prompt, user_prompt)
        except LmResponseError as exc:
            return self._finish(
                arm="C",
                instance_id=instance_id,
                verifier=verifier,
                instance=instance,
                proposal={"lm_failure": {"type": type(exc).__name__}},
                formula=None,
                solver_observation=None,
                candidate=None,
                native=None,
                lm_observation=None,
                harness_ns=preparation_ns,
                generate_and_check_equivalent=False,
                failure_observation={
                    "stage": "lm_generation",
                    "status": "ERROR",
                    "diagnostic": str(exc),
                },
                lm_failure_elapsed_ns=exc.elapsed_ns,
                trial_started_ns=trial_started,
                preparation_ns=preparation_ns,
            )
        harness_started = perf_counter_ns()
        if set(lm_observation.structured_output) != {"route"}:
            return self._finish(
                arm="C",
                instance_id=instance_id,
                verifier=verifier,
                instance=instance,
                proposal=lm_observation.structured_output,
                formula=None,
                solver_observation=None,
                candidate=None,
                native=None,
                lm_observation=lm_observation,
                harness_ns=preparation_ns + perf_counter_ns() - harness_started,
                generate_and_check_equivalent=False,
                failure_observation={
                    "stage": "proposal_contract",
                    "status": "REJECTED",
                    "diagnostic": "Arm C requires exactly one route field",
                },
                trial_started_ns=trial_started,
                preparation_ns=preparation_ns,
            )
        route = lm_observation.structured_output.get("route")
        if not isinstance(route, dict):
            return self._finish(
                arm="C",
                instance_id=instance_id,
                verifier=verifier,
                instance=instance,
                proposal=lm_observation.structured_output,
                formula=None,
                solver_observation=None,
                candidate=None,
                native=None,
                lm_observation=lm_observation,
                harness_ns=preparation_ns + perf_counter_ns() - harness_started,
                generate_and_check_equivalent=False,
                failure_observation={
                    "stage": "proposal_contract",
                    "status": "REJECTED",
                    "diagnostic": "Arm C route must be an object",
                },
                trial_started_ns=trial_started,
                preparation_ns=preparation_ns,
            )
        return self._run_route(
            "C",
            instance_id,
            verifier,
            instance,
            route,
            lm_observation,
            trial_started_ns=trial_started,
            harness_started_ns=harness_started,
            preparation_ns=preparation_ns,
        )

    def _run_route(
        self,
        arm: str,
        instance_id: str,
        verifier: ExternalVerifier,
        instance: dict[str, Any],
        route: dict[str, Any],
        lm_observation: LmObservation | None,
        *,
        trial_started_ns: int,
        harness_started_ns: int,
        preparation_ns: int,
    ) -> Trial:
        try:
            compiled = compile_route(route)
        except RouteError as exc:
            return self._finish(
                arm=arm,
                instance_id=instance_id,
                verifier=verifier,
                instance=instance,
                proposal=route,
                formula=None,
                solver_observation=None,
                candidate=None,
                native=None,
                lm_observation=lm_observation,
                harness_ns=preparation_ns + perf_counter_ns() - harness_started_ns,
                generate_and_check_equivalent=False,
                failure_observation={
                    "stage": "route_compilation",
                    "status": "REJECTED",
                    "diagnostic": str(exc),
                },
                trial_started_ns=trial_started_ns,
                preparation_ns=preparation_ns,
            )
        harness_ns = preparation_ns + perf_counter_ns() - harness_started_ns
        sat = self.solver.solve(compiled)
        candidate = sat.candidate if sat.status is SatStatus.SAT else None
        native = verifier.verify(instance, candidate) if candidate is not None else None
        return self._finish(
            arm=arm,
            instance_id=instance_id,
            verifier=verifier,
            instance=instance,
            proposal=compiled.route,
            formula=compiled.formula_payload(),
            solver_observation=sat,
            candidate=candidate,
            native=native,
            lm_observation=lm_observation,
            harness_ns=harness_ns,
            generate_and_check_equivalent=_fixes_every_slot(compiled.route),
            failure_observation=(
                None
                if native is not None and native.verdict is NativeVerdict.ACCEPTED
                else (
                    {
                        "stage": "native_verifier",
                        "status": native.verdict.value,
                        "diagnostic": "SAT candidate was not accepted",
                    }
                    if native is not None
                    else {
                        "stage": "route_execution",
                        "status": sat.status.value,
                        "diagnostic": sat.error or "no native-verifier candidate was produced",
                    }
                )
            ),
            trial_started_ns=trial_started_ns,
            preparation_ns=preparation_ns,
        )

    def _finish(
        self,
        *,
        arm: str,
        instance_id: str,
        verifier: ExternalVerifier,
        instance: dict[str, Any],
        proposal: dict[str, Any] | None,
        formula: dict[str, Any] | None,
        solver_observation: SatObservation | None,
        candidate: dict[str, Any] | None,
        native: Any,
        lm_observation: LmObservation | None,
        harness_ns: int,
        generate_and_check_equivalent: bool,
        failure_observation: dict[str, Any] | None,
        trial_started_ns: int,
        preparation_ns: int,
        lm_failure_elapsed_ns: int = 0,
    ) -> Trial:
        native_dict = native.to_dict() if native is not None else None
        solver_dict = solver_observation.to_dict() if solver_observation is not None else None
        pre_receipt_ns = preparation_ns + perf_counter_ns() - trial_started_ns
        component_ns = (
            (lm_observation.elapsed_ns if lm_observation else lm_failure_elapsed_ns)
            + harness_ns
            + (solver_observation.elapsed_ns if solver_observation else 0)
            + (native.elapsed_ns if native else 0)
        )
        timings = {
            "lm_generation": (
                lm_observation.elapsed_ns if lm_observation else lm_failure_elapsed_ns
            ),
            "harness": harness_ns,
            "sat": solver_observation.elapsed_ns if solver_observation else 0,
            "native_verifier": native.elapsed_ns if native else 0,
            "orchestration_unattributed": max(0, pre_receipt_ns - component_ns),
            "vstd_creation_probe": None,
            "vstd_reverification_probe": None,
            "total_system_probe": None,
        }
        # Same-input probes allow the final record to bind one observed creation
        # and one full reverification without claiming recursive self-timing.
        probe_started = perf_counter_ns()
        probe_record = build_record(
            instance_id=instance_id,
            domain=verifier.domain,
            arm=arm,
            instance=instance,
            contract=verifier.contract.to_dict(),
            lm_observation=lm_observation.to_dict() if lm_observation else None,
            proposal=proposal,
            formula=formula,
            solver_configuration=self.solver.configuration,
            solver_observation=solver_dict,
            candidate=candidate,
            native_observation=native_dict,
            timings=timings,
            resource_bounds=DEFAULT_RESOURCE_BOUNDS,
            failure_observation=failure_observation,
        )
        timings["vstd_creation_probe"] = perf_counter_ns() - probe_started
        reverify_started = perf_counter_ns()
        probe_errors = validate_record(self.experiment_root, probe_record, reexecute=True)
        probe_errors.extend(
            independently_validate_record(self.experiment_root, probe_record, reexecute=True)
        )
        reverification_ns = perf_counter_ns() - reverify_started
        timings["vstd_reverification_probe"] = reverification_ns
        timings["total_system_probe"] = (
            pre_receipt_ns + int(timings["vstd_creation_probe"]) + reverification_ns
        )
        record = build_record(
            instance_id=instance_id,
            domain=verifier.domain,
            arm=arm,
            instance=instance,
            contract=verifier.contract.to_dict(),
            lm_observation=lm_observation.to_dict() if lm_observation else None,
            proposal=proposal,
            formula=formula,
            solver_configuration=self.solver.configuration,
            solver_observation=solver_dict,
            candidate=candidate,
            native_observation=native_dict,
            timings=timings,
            resource_bounds=DEFAULT_RESOURCE_BOUNDS,
            failure_observation=failure_observation,
        )
        final_errors = validate_record(self.experiment_root, record, reexecute=True)
        final_errors.extend(
            independently_validate_record(self.experiment_root, record, reexecute=True)
        )
        validation_errors = list(dict.fromkeys([*probe_errors, *final_errors]))
        accepted = native is not None and native.verdict is NativeVerdict.ACCEPTED
        sat_metrics = solver_observation.to_dict(include_model=False) if solver_observation else {}
        total_ns = int(timings["total_system_probe"])
        metrics = {
            "accepted": accepted,
            "false_acceptance": accepted and bool(validation_errors),
            "final_unknown": not accepted,
            "lm_tokens_input": lm_observation.input_tokens if lm_observation else None,
            "lm_tokens_output": lm_observation.output_tokens if lm_observation else None,
            "native_verifier_calls": 1 if native else 0,
            "routes": 1 if arm in {"A", "C"} else 0,
            "failed_routes": 0 if accepted else (1 if arm in {"A", "C"} else 0),
            "repeated_routes": 0,
            "generate_and_check_equivalent": generate_and_check_equivalent,
            "vstd_reverification_ns": reverification_ns,
            "vstd_reverification_errors": validation_errors,
            "total_time_to_outcome_ns": total_ns,
            **sat_metrics,
        }
        return Trial(arm, verifier.domain, instance_id, record, metrics)


def _fixes_every_slot(route: dict[str, Any]) -> bool:
    unfixed = {slot["id"] for slot in route.get("slots", []) if len(slot.get("domain", [])) > 1}
    for constraint in route.get("constraints", []):
        if constraint.get("kind") == "fixed":
            unfixed.discard(constraint.get("slot"))
        if constraint.get("kind") == "allowed_values" and len(constraint.get("values", [])) == 1:
            unfixed.discard(constraint.get("slot"))
    return not unfixed
