"""Verifier Standard (VSTD) domain mainstays and their precise checking scopes.

DATA means dataset integrity and lineage; ENV means verifiable execution environment;
BENCH means benchmark specification graph; HYPER means hyperparameters and training
lineage; MODEL means model reproducibility specification; SIM means generative
simulation specification. Domain depths are dimensionless prerequisite counts,
separate from the VSTD object and Graph numbered profiles.
"""
from __future__ import annotations

from importlib.resources import files
import hashlib

from verifier.core.certificate import canonical_digest

CHECKS = {
    "DATA": (
        ("inventory", "Rehash every retained shard and record; recompute byte/count and digest-tree commitments."),
        ("schema", "Check each retained record against the bound field types and required columns."),
        ("lineage", "Re-execute every declared retained-data transformation and check its exact output."),
        ("splits", "Check complete declared split membership and record-identity separation."),
        ("overlap", "Recompute exact and lexical overlap over the complete retained train/evaluation inventory."),
    ),
    "ENV": (
        ("closure", "Materialize and rehash all files in the selected software inventory."),
        ("configuration", "Compare the complete required configuration with retained collector observations."),
        ("resources", "Check retained resource measurements against the exact declared ceilings."),
        ("reproduction", "Compare inputs, executable/software coordinates and results of two retained executions."),
    ),
    "BENCH": (
        ("problems", "Bind each finite problem to its exact specification and candidate answer."),
        ("oracles", "Execute the named built-in problem oracle; never accept a supplied solved flag."),
        ("coverage", "Recompute weighted score over every problem with no missing, duplicate or substituted run."),
        ("budgets", "Check complete retained timing and memory observations against the problem ceilings."),
    ),
    "HYPER": (
        ("configuration", "Validate the bound optimizer, schedule, accumulation and precision contract."),
        ("checkpoints", "Rehash all retained weights and optimizer states in the checkpoint inventory."),
        ("lineage", "Check contiguous steps and exact parent, batch, hyperparameter and result bindings."),
        ("updates", "Recompute every supported optimizer update from retained gradients and state."),
        ("training", "Recompute dense-network losses and gradients from bound batches, then replay training."),
    ),
    "MODEL": (
        ("artifacts", "Rehash the exact architecture, weights and named dependency artifacts."),
        ("tensors", "Check complete finite tensor shapes and architecture compatibility."),
        ("inference", "Execute the bound dense network and compare every retained output."),
        ("evaluation", "Recompute regression or classification metrics over the complete named evaluation set."),
        ("challenges", "Execute the declared finite counterexample probes and check their bound output conditions."),
    ),
    "SIM": (
        ("replay", "Execute the bound transition expressions and entropy stream to reproduce the retained trajectory."),
        ("invariants", "Check bound invariant/conservation expressions on every retained state; optionally check a closed finite state set."),
        ("refinement", "Execute the bound projection and compare aligned macro states within the declared tolerance."),
        ("channels", "Recompute every observation projection and check every declared action channel."),
        ("shards", "Check complete aligned shard coverage and bound cross-shard relations; verify signatures when required."),
    ),
}

SCOPES = {
    "DATA": "complete retained dataset and declared transformation boundary",
    "ENV": "retained software inventory and named collector observations",
    "BENCH": "complete retained finite problem suite and its named oracles",
    "HYPER": "retained dense-network training trace and declared numerical semantics",
    "MODEL": "retained dense network, evaluation set and finite challenge set",
    "SIM": "retained transition model, trace and explicitly enumerated state boundary",
}


def domain_catalog() -> dict:
    """Describe all native domain propositions, scopes and cumulative prerequisites."""
    return {"schema_version": "VSTD-DOMAIN-CATALOG-1", "domains": {
        domain: {"scope": SCOPES[domain], "checks": [
            {"id": f"{domain}.{i}", "name": name, "proposition": statement,
             "depends_on": [] if i == 1 else [f"{domain}.{i-1}"]}
            for i, (name, statement) in enumerate(checks, 1)]}
        for domain, checks in CHECKS.items()}}


def domain_specification_digest() -> str:
    data = files("verifier.specifications").joinpath("DOMAIN_GROUNDING.md").read_bytes()
    return canonical_digest({"catalog": domain_catalog(), "specification": hashlib.sha256(data).hexdigest()})
