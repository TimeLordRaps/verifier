"""Verifier engine specification (VERIFIER): computational verifier integrity and bounds.

Terminology: identifier (ID); Verifier Standard (VSTD);
conjunctive normal form (CNF); unit propagation (UP).

Checks distinguish content-bound inventory, retained proof instances and local
kernel replay from producer execution, class-wide soundness, operating-system
resource enforcement and bootstrap authority. The latter are not established
by caller declarations. No submitted code is executed.
"""
from __future__ import annotations

from typing import Any
from verifier.core.certificate import certificate_from_dict, CostTier, Verdict
from verifier.core.depth import claim_binding_from_dict
from verifier.core.kernel import check as kernel_check, KernelOutcome, reference_descriptor
from .common import (
    Budget,
    Refuted,
    Unavailable,
    digest,
    integer,
    inspect_structure,
    need,
    number,
    obj,
    same,
    seq,
    text,
)

VERIFIER_KINDS = frozenset({"PROVER", "CERTIFIER", "COMPILER", "CHECKER", "SOLVER"})

UNBOUNDED_PROPOSITIONS = frozenset({
    "unbounded_omniscience",
    "halting_problem",
    "universal_truth",
    "unbounded_safety",
    "infinite_search",
    "general_induction",
    "arbitrary_first_order_truth",
    "ex_falso_omniscience",
    "unbounded_computation",
})


def _proofs(artifact: dict, inputs: dict, budget: Budget) -> list[dict]:
    """Replay exact retained unit-propagation proofs/models, not submitted engines.

    Conjunctive normal form (CNF); unit propagation (UP). Results concern the
    supplied formula and encoding rules, not the truth of external facts or the
    correctness of an arbitrary prose claim/producer implementation.
    """
    claims = seq(need(inputs, "soundness_claims"), budget)
    same(digest(claims), need(artifact, "soundness_claims_digest"), "proof requests digest mismatch")
    descriptor = reference_descriptor().to_dict()
    same(digest(descriptor), need(artifact, "toolchain_digest"), "native checker toolchain differs")
    results = []
    for claim in claims:
        witness = claim["refutation_witness"]
        if not isinstance(witness, dict):
            raise Unavailable("proof text is not a supported retained decision certificate")
        obj(witness, {"binding", "certificate"})
        before = budget.used
        inspect_structure(witness, budget)
        structure_cost = budget.used - before
        raw_binding = obj(witness["binding"])
        binding = claim_binding_from_dict(raw_binding)
        same(binding.to_dict(), raw_binding, "noncanonical claim binding")
        same(binding.verifier.to_dict(), descriptor, "claim names a different checker implementation")
        # Binding bounds are dimensions of kernel work, retained clauses and bytes;
        # they are not wall-time or process-memory guarantees.
        for value in raw_binding["bounds"].values():
            integer(value, minimum=1)
        certificate = certificate_from_dict(obj(witness["certificate"]))
        same(certificate.to_dict(), witness["certificate"], "noncanonical retained certificate")
        if claim["class"] != "cnf_sat" or certificate.header.tier is not CostTier.UP:
            raise Unavailable("only retained cnf_sat unit-propagation certificates are implemented")
        if certificate.header.verdict is Verdict.UNKNOWN:
            raise Unavailable("an indeterminacy transcript does not establish a proof instance")
        limits = obj(artifact["refutation_boundaries"][claim["class"]])
        if set(limits) - {"max_vars", "max_clauses", "max_steps"}:
            raise Unavailable("unsupported native proof boundary dimension")
        max_vars = integer(need(limits, "max_vars"), minimum=1)
        max_clauses = integer(need(limits, "max_clauses"), minimum=1)
        n_vars = max((abs(lit) for clause in certificate.formula for lit in clause), default=0)
        steps = len(certificate.decision.propagation.steps) if certificate.decision.propagation else 0
        if n_vars > claim["boundary_limit"] or claim["boundary_limit"] > max_vars:
            raise Refuted("proof variable count exceeds declared boundary")
        if len(certificate.formula) > max_clauses or ("max_steps" in limits and steps > limits["max_steps"]):
            raise Refuted("retained proof exceeds declared clause or step boundary")
        # Conservatively precharge scans of retained clauses, grounding templates
        # and proof steps before kernel replay. No solver/search is invoked.
        literals = sum(map(len, certificate.formula))
        cost = (n_vars + 1) * (steps + 1) * (literals + 1) + structure_cost * (len(certificate.formula) + 1)
        budget.tick(cost)
        result = kernel_check(certificate, binding=binding, budget=cost)
        if result.outcome is KernelOutcome.REJECTED:
            raise Refuted("retained proof rejected: " + result.details)
        if result.outcome is KernelOutcome.REFUSED:
            raise Unavailable("retained proof unavailable: " + result.details)
        results.append({"certificate_digest": digest(witness["certificate"]),
                        "binding_digest": digest(raw_binding), "result": result.to_dict()})
    return results


def evaluate(check: str, artifact: dict, inputs: dict, budget: Budget, **context: Any) -> dict:
    # Check 1: identity (VERIFIER-1.1)
    if check == "identity":
        verifier_kind = text(need(artifact, "verifier_kind")).upper()
        toolchain_digest = text(need(artifact, "toolchain_digest"))
        version = text(need(artifact, "version"))
        if verifier_kind not in VERIFIER_KINDS:
            raise Refuted(f"unknown verifier kind {verifier_kind}; must be one of {sorted(VERIFIER_KINDS)}")
        toolchain = obj(need(inputs, "toolchain"))
        same(digest(toolchain), toolchain_digest, "toolchain digest mismatch")
        return {
            "verifier_kind": verifier_kind,
            "version": version,
            "toolchain_digest": toolchain_digest,
            "components": len(toolchain.get("components", [])),
        }

    # Check 2: soundness (VERIFIER-1.2)
    elif check == "soundness":
        proposition_classes = [text(c) for c in seq(need(artifact, "proposition_classes"), budget)]
        for c in proposition_classes:
            lowered = c.lower()
            if lowered in UNBOUNDED_PROPOSITIONS or "unbounded" in lowered or "omniscience" in lowered:
                raise Refuted(f"unbounded proposition class rejected: {c}")
        boundaries = obj(need(artifact, "refutation_boundaries"))
        if not boundaries:
            raise Refuted("refutation boundaries must be non-empty to reject unbounded omniscience")
        for k, v in boundaries.items():
            lowered = text(k).lower()
            if lowered in UNBOUNDED_PROPOSITIONS or "unbounded" in lowered or "omniscience" in lowered:
                raise Refuted(f"refutation boundary attempts to admit unbounded class: {k}")
            b_limits = obj(v)
            if not b_limits:
                raise Refuted(f"refutation boundary for {k} must define non-empty limits")
            for lim_key, lim_val in b_limits.items():
                text(lim_key)
                if isinstance(lim_val, int):
                    integer(lim_val, minimum=1)
                else:
                    raise Refuted(f"refutation boundary limit {lim_key} must be a positive integer")
        soundness_claims = seq(need(inputs, "soundness_claims"), budget)
        verified = 0
        for claim in soundness_claims:
            obj(claim, {"class", "boundary_limit", "refutation_witness"})
            cls_name = text(claim["class"])
            if cls_name not in proposition_classes:
                raise Refuted(f"soundness claim class {cls_name} not in declared proposition classes")
            lowered = cls_name.lower()
            if lowered in UNBOUNDED_PROPOSITIONS or "unbounded" in lowered or "omniscience" in lowered:
                raise Refuted(f"soundness claim asserts unbounded proposition: {cls_name}")
            integer(claim["boundary_limit"], minimum=1)
            limits = obj(need(boundaries, cls_name))
            if "max_vars" in limits and claim["boundary_limit"] > limits["max_vars"]:
                raise Refuted("claim boundary exceeds declared maximum variables")
            verified += 1
        results = _proofs(artifact, inputs, budget)
        return {"proposition_classes": proposition_classes,
                "proof_instances_checked": verified, "proof_results": results,
                "scope": "retained formula and encoding-rule instances only",
                "class_wide_soundness": "NOT_ESTABLISHED"}

    # Check 3: determinism (VERIFIER-1.3)
    elif check == "determinism":
        runs = seq(need(inputs, "runs"), budget)
        same(digest(runs), need(artifact, "runs_digest"), "runs digest mismatch")
        if len(runs) < 2:
            raise Refuted("at least 2 runs required to establish reproducibility")
        run_ids: list[str] = []
        first_run = obj(runs[0])
        expected_input = need(first_run, "input_digest")
        expected_software = need(first_run, "software_digest")
        expected_output = need(first_run, "output_digest")
        for r in runs:
            obj(r, {"run_id", "input_digest", "software_digest", "output_digest", "entropy_leakage"})
            rid = text(r["run_id"])
            run_ids.append(rid)
            same(r["input_digest"], expected_input, "input digest mismatch across runs")
            same(r["software_digest"], expected_software, "software digest mismatch across runs")
            same(r["software_digest"], need(artifact, "toolchain_digest"), "run software differs from verifier toolchain")
            same(r["output_digest"], expected_output, "non-deterministic output deviation detected across runs")
            entropy = r["entropy_leakage"]
            if isinstance(entropy, (int, float)):
                if entropy != 0:
                    raise Refuted("non-deterministic entropy leakage detected (must be 0)")
            elif isinstance(entropy, (list, dict, str, bytes)):
                if len(entropy) != 0:
                    raise Refuted("non-deterministic entropy leakage detected (must be empty)")
            else:
                raise Refuted("invalid entropy_leakage field type")
        if len(set(run_ids)) != len(run_ids):
            raise Refuted("distinct run IDs required to establish reproducibility")
        # Records alone are not observations. Recheck the exact retained proof
        # request once per record and bind both its input and computed output.
        evaluate("soundness", artifact, inputs, budget)
        results = []
        for run in runs:
            same(run["input_digest"], digest(inputs["soundness_claims"]), "run input is not the retained proof request")
            replayed = _proofs(artifact, inputs, budget)
            same(run["output_digest"], digest(replayed), "run output differs from native proof replay")
            results.append(digest(replayed))
        return {"local_kernel_replays": len(results), "output_digest": results[0],
                "scope": "repeated local kernel replay of retained proof requests",
                "producer_execution": "NOT_ESTABLISHED", "universal_determinism": "NOT_ESTABLISHED",
                "entropy_freedom": "NOT_ESTABLISHED"}

    # Check 4: resources (VERIFIER-1.4)
    elif check == "resources":
        if "resource_execution" in inputs:
            from .verifier_execution import evaluate_resources
            return evaluate_resources(artifact, inputs, budget)
        ceilings = obj(need(artifact, "ceilings"), {"max_memory_bytes", "max_wall_seconds", "max_loop_iterations"})
        max_mem = integer(ceilings["max_memory_bytes"], minimum=1)
        max_wall = number(ceilings["max_wall_seconds"])
        if max_wall <= 0:
            raise Refuted("time ceiling must be positive")
        max_iter = integer(ceilings["max_loop_iterations"], minimum=1)
        measurements = seq(need(inputs, "measurements"), budget)
        for m in measurements:
            obj(m, {"memory_bytes", "wall_seconds", "loop_iterations"})
            mem = integer(m["memory_bytes"], minimum=0)
            wall = number(m["wall_seconds"])
            if wall < 0:
                raise Refuted("execution time must be non-negative")
            iters = integer(m["loop_iterations"], minimum=0)
            if mem > max_mem:
                raise Refuted(f"memory footprint {mem} bytes exceeds cap of {max_mem} bytes (anti-OOM violation)")
            if wall > max_wall:
                raise Refuted(f"execution time {wall}s exceeds ceiling of {max_wall}s")
            if iters > max_iter:
                raise Refuted(f"loop iterations {iters} exceeds bound of {max_iter} (anti-infinite-loop violation)")
        raise Unavailable("caller measurements do not establish observed execution or enforced process memory, wall-time and loop ceilings")

    # Check 5: meta (VERIFIER-1.5)
    elif check == "meta":
        toolchain_digest = text(need(artifact, "toolchain_digest"))
        bootstrap_receipt = obj(need(inputs, "bootstrap_receipt"))
        same(digest(bootstrap_receipt), need(artifact, "bootstrap_digest"), "parent bootstrap digest mismatch")
        nested_result = obj(bootstrap_receipt["result"]) if "result" in bootstrap_receipt else {}
        status = bootstrap_receipt.get("status") or nested_result.get("status")
        if status != "PASS":
            raise Refuted(f"parent bootstrap receipt status is {status}, expected PASS")
        self_attestation = obj(need(inputs, "self_attestation"), {"attested_verifier_id", "toolchain_digest", "attestation_verdict"})
        same(digest(self_attestation), need(artifact, "self_attestation_digest"), "self attestation digest mismatch")
        text(self_attestation["attested_verifier_id"])
        if "verifier_id" in artifact:
            same(self_attestation["attested_verifier_id"], text(artifact["verifier_id"]), "self-attestation verifier identity differs")
        if "verifier_id" in bootstrap_receipt and "verifier_id" in artifact:
            same(bootstrap_receipt["verifier_id"], artifact["verifier_id"], "bootstrap verifier identity differs")
        if self_attestation["toolchain_digest"] != toolchain_digest:
            raise Refuted("self-attestation toolchain digest mismatch with verifier identity")
        verdict = text(self_attestation["attestation_verdict"])
        if verdict not in ("SELF_VERIFIED", "PASS"):
            raise Refuted(f"self-verification attestation verdict is {verdict}, expected SELF_VERIFIED or PASS")
        if bootstrap_receipt.get("schema_version") == "verifier-native-bootstrap-1":
            from .verifier_bootstrap import evaluate_bootstrap
            observed = evaluate_bootstrap(artifact, inputs, budget, witness_keys=context.get("witness_keys", {}))
            _proofs(artifact, inputs, budget)
            return observed
        raise Unavailable("no admitted bootstrap or self-verification mechanism; retained PASS labels and digests supply no authority")

    raise Unavailable(f"unsupported VERIFIER check: {check}")
