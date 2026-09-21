"""Verifier Standard (VSTD) domain mainstays and their precise checking scopes.

DATA means dataset integrity and lineage; ENV means verifiable execution environment;
BENCH means benchmark specification graph; HYPER means hyperparameters and training
lineage; MODEL means model reproducibility specification; SIM means generative
simulation specification; HARNESS means an instrumented agent observation surface;
AGENT means an agent trajectory bounded by that surface. Domain depths are dimensionless
prerequisite counts, separate from the VSTD object and Graph numbered profiles.

Each check carries the exact set of lower checks its own evaluation re-executes or
presupposes. This is a directed acyclic graph, not a chain: most domains fan out
from a shared prologue, so a check is not blocked by an unrelated sibling. Only
HYPER is genuinely linear.
"""
from __future__ import annotations

from importlib.resources import files
import hashlib

from verifier.core.certificate import canonical_digest

CHECKS = {
    "DATA": (
        ("inventory", "Rehash every retained shard and record; recompute byte/count and digest-tree commitments.", ()),
        ("schema", "Check each retained record against the bound field types and required columns.", (1,)),
        ("lineage", "Re-execute every declared retained-data transformation and check its exact output.", (1,)),
        ("splits", "Check complete declared split membership and record-identity separation.", (1,)),
        ("overlap", "Recompute exact and lexical overlap over the complete retained train/evaluation inventory.", (1, 4)),
    ),
    "ENV": (
        ("closure", "Materialize and rehash all files in the selected software inventory.", ()),
        ("configuration", "Compare the complete required configuration with retained collector observations.", (1,)),
        ("resources", "Check retained resource measurements against the exact declared ceilings.", (1,)),
        ("reproduction", "Compare inputs, executable/software coordinates and results of two retained executions.", (1, 2)),
    ),
    "BENCH": (
        ("problems", "Bind each finite problem to its exact specification and candidate answer.", ()),
        ("oracles", "Execute the named built-in problem oracle; never accept a supplied solved flag.", (1,)),
        ("coverage", "Recompute weighted score over every problem with no missing, duplicate or substituted run.", (1, 2)),
        ("budgets", "Check complete retained timing and memory observations against the problem ceilings.", (1,)),
    ),
    "HYPER": (
        ("configuration", "Validate the bound optimizer, schedule, accumulation and precision contract.", ()),
        ("checkpoints", "Rehash all retained weights and optimizer states in the checkpoint inventory.", (1,)),
        ("lineage", "Check contiguous steps and exact parent, batch, hyperparameter and result bindings.", (1, 2)),
        ("updates", "Recompute every supported optimizer update from retained gradients and state.", (1, 2, 3)),
        ("training", "Recompute dense-network losses and gradients from bound batches, then replay training.", (1, 2, 3, 4)),
    ),
    "MODEL": (
        ("artifacts", "Rehash the exact architecture, weights and named dependency artifacts.", ()),
        ("tensors", "Check complete finite tensor shapes and architecture compatibility.", (1,)),
        ("inference", "Execute the bound dense network and compare every retained output.", (1, 2)),
        ("evaluation", "Recompute regression or classification metrics over the complete named evaluation set.", (1, 2, 3)),
        ("challenges", "Execute the declared finite counterexample probes and check their bound output conditions.", (1, 2)),
    ),
    "SIM": (
        ("replay", "Execute the bound transition expressions and entropy stream to reproduce the retained trajectory.", ()),
        ("invariants", "Check bound invariant/conservation expressions on every retained state; optionally check a closed finite state set.", (1,)),
        ("refinement", "Execute the bound projection and compare aligned macro states within the declared tolerance.", (1,)),
        ("channels", "Recompute every observation projection and check every declared action channel.", (1,)),
        ("shards", "Check complete aligned shard coverage and bound cross-shard relations; verify signatures when required.", (1,)),
    ),
    "HARNESS": (
        ("surface", "Partition every declared channel into instrumented observation and named uninstrumented gap.", ()),
        ("messages", "Check contiguous retained user, agent and tool records against the instrumented surface.", (1,)),
        ("tools", "Bind every tool invocation to a registered declaration and its exact retained record.", (1, 2)),
        ("effects", "Check every retained side effect against the declared instrumented effect channels.", (1,)),
        ("transcript", "Recompute the ordered transcript commitment; refuse an omitted or substituted record.", (1, 2, 3, 4)),
    ),
    "AGENT": (
        ("harness", "Re-derive the observation ceiling from the bound harness certificate and its required channels.", ()),
        ("trajectory", "Check contiguous decisions, each witnessed by a record inside the bound observation ceiling.", (1,)),
        ("actions", "Bind every declared action to a witnessed tool invocation in the bound harness.", (1, 2)),
        ("outcomes", "Compare the complete retained outcome inventory with the bound outcome contract.", (1, 2)),
        ("claims", "Check that every final claim rests only on records inside the bound observation ceiling.", (1, 2, 3, 4)),
    ),
}

SCOPES = {
    "DATA": "complete retained dataset and declared transformation boundary",
    "ENV": "retained software inventory and named collector observations",
    "BENCH": "complete retained finite problem suite and its named oracles",
    "HYPER": "retained dense-network training trace and declared numerical semantics",
    "MODEL": "retained dense network, evaluation set and finite challenge set",
    "SIM": "retained transition model, trace and explicitly enumerated state boundary",
    "HARNESS": "declared instrumented observation surface and its retained transcript",
    "AGENT": "retained trajectory inside the observation ceiling of one bound harness certificate",
}


def domain_catalog() -> dict:
    """Describe all native domain propositions, scopes and cumulative prerequisites."""
    return {"schema_version": "VSTD-DOMAIN-CATALOG-1", "domains": {
        domain: {"scope": SCOPES[domain], "checks": [
            {"id": f"{domain}.{i}", "name": name, "proposition": statement,
             "depends_on": [f"{domain}.{d}" for d in depends]}
            for i, (name, statement, depends) in enumerate(checks, 1)]}
        for domain, checks in CHECKS.items()}}


def domain_specification_digest() -> str:
    data = files("verifier.specifications").joinpath("DOMAIN_GROUNDING.md").read_bytes()
    return canonical_digest({"catalog": domain_catalog(), "specification": hashlib.sha256(data).hexdigest()})
