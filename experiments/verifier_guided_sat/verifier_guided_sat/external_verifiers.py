# Acronyms: American Standard Code for Information Interchange (ASCII);
# JavaScript Object Notation (JSON); Unicode Transformation Format, 8-bit (UTF-8).
"""Invoke three exact, source-visible vendored AlgoTune verifier objects."""

from __future__ import annotations

import io
import logging
from dataclasses import dataclass
from pathlib import Path
from time import perf_counter_ns
from typing import Any

from .canonical import canonical_digest, file_digest
from .contracts import NativeVerdict, VerificationObservation, VerifierObjectContract


SOURCE_COMMIT = "dff9914c10800c7a031c9e8c3d4d1c8cd1b38906"


@dataclass(frozen=True)
class ExternalVerifier:
    """Loaded verifier plus its public experimental contract."""

    domain: str
    task: Any
    source_path: Path
    contract: VerifierObjectContract

    def generate_problem(self, n: int, seed: int) -> Any:
        problem = self.task.generate_problem(n=n, random_seed=seed)
        if self.domain == "stable_matching":
            return {
                "proposer_prefs": [problem["proposer_prefs"][i] for i in range(n)],
                "receiver_prefs": [problem["receiver_prefs"][i] for i in range(n)],
            }
        return problem

    def verify(self, instance: Any, candidate: Any) -> VerificationObservation:
        stream = io.StringIO()
        handler = logging.StreamHandler(stream)
        handler.setLevel(logging.INFO)
        root = logging.getLogger()
        old_level = root.level
        root.addHandler(handler)
        root.setLevel(min(old_level, logging.INFO))
        started = perf_counter_ns()
        try:
            accepted = bool(self.task.is_solution(instance, candidate))
            verdict = NativeVerdict.ACCEPTED if accepted else NativeVerdict.REJECTED
        except Exception as exc:  # external code is an explicit trust boundary
            verdict = NativeVerdict.ERROR
            stream.write(f"{type(exc).__name__}: {exc}\n")
        finally:
            elapsed = perf_counter_ns() - started
            root.removeHandler(handler)
            root.setLevel(old_level)
        diagnostics = tuple(line.strip() for line in stream.getvalue().splitlines() if line.strip())
        return VerificationObservation(
            verdict,
            elapsed,
            diagnostics[-4:],
            canonical_digest(instance),
            canonical_digest(candidate),
        )


_DOMAIN_CLASS = {
    "stable_matching": "StableMatchingTask",
    "graph_isomorphism": "GraphIsomorphism",
    "integer_factorization": "IntegerFactorization",
}
def _contract(domain: str, source_path: Path) -> VerifierObjectContract:
    common_neither = (
        "global nonexistence of a witness",
        "soundness of the verifier implementation",
        "actor independence, authorization, or identity",
        "generalization beyond the supplied instance",
    )
    if domain == "stable_matching":
        instance_schema = "complete proposer and receiver preference lists"
        witness_schema = "object with matching permutation"
        acceptance = "the supplied permutation is a stable matching for the supplied preferences"
        rejection = "the supplied candidate failed at least one implemented format, permutation, or stability check"
    elif domain == "graph_isomorphism":
        instance_schema = "two finite undirected graphs with an equal declared node count"
        witness_schema = "object with a node-mapping permutation"
        acceptance = "the supplied mapping passes the implemented bijection, edge, and degree checks"
        rejection = "the supplied candidate failed at least one implemented mapping check"
    elif domain == "integer_factorization":
        instance_schema = "object containing one decimal composite integer"
        witness_schema = "object containing p and q integer-like values"
        acceptance = "p and q are nontrivial primes whose exact product is the supplied composite"
        rejection = "the supplied candidate failed format, product, positivity, or primality checks"
    else:
        raise KeyError(domain)
    return VerifierObjectContract(
        identifier=f"algotune:{domain}:is_solution@{SOURCE_COMMIT}",
        domain=domain,
        source_commit=SOURCE_COMMIT,
        source_digest=file_digest(source_path),
        instance_schema=instance_schema,
        witness_schema=witness_schema,
        invocation=f"{_DOMAIN_CLASS[domain]}.is_solution(problem, solution)",
        deterministic=True,
        configuration={"logging_capture": "last_four_nonempty_lines", "mutation": "none"},
        resource_limits={
            "timeout": "none in-process; bounded benchmark instances only",
            "memory": "none in-process; bounded benchmark instances only",
        },
        result_semantics={
            "accepted": "is_solution returned truthy",
            "rejected": "is_solution returned falsey",
            "error": "invocation raised an exception",
            "indeterminate": "outer limit or missing execution evidence; represented as UNKNOWN",
        },
        diagnostics="captured Python logging plus exception type; diagnostics may be empty",
        candidate_canonicalization="UTF-8 canonical JSON: sorted keys, compact separators, ASCII escapes, finite numbers",
        verification_cost="measured elapsed nanoseconds per invocation; asymptotic cost follows exact vendored predicate",
        trust_roots=(
            "exact vendored AlgoTune source bytes",
            "Python runtime and imported numerical libraries",
            "the implemented verifier predicate",
        ),
        acceptance_proves=acceptance,
        rejection_proves=rejection,
        neither_proves=common_neither,
    )


def load_verifier(experiment_root: Path, domain: str) -> ExternalVerifier:
    """Load one exact vendored verifier module by domain name."""

    if domain not in _DOMAIN_CLASS:
        raise KeyError(f"unsupported external verifier domain: {domain}")
    selected_root = experiment_root.resolve()
    source_root = Path(__file__).resolve().parents[1]
    if selected_root != source_root:
        raise ValueError("external verifier root differs from selected source package")
    source_path = experiment_root / "vendor" / "algotune" / domain / f"{domain}.py"
    if domain == "stable_matching":
        from vendor.algotune.stable_matching.stable_matching import StableMatchingTask

        task_class = StableMatchingTask
    elif domain == "graph_isomorphism":
        from vendor.algotune.graph_isomorphism.graph_isomorphism import GraphIsomorphism

        task_class = GraphIsomorphism
    else:
        from vendor.algotune.integer_factorization.integer_factorization import IntegerFactorization

        task_class = IntegerFactorization
    task = task_class()
    return ExternalVerifier(domain, task, source_path, _contract(domain, source_path))
