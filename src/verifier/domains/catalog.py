"""Verifier Standard (VSTD) domain mainstays and their precise checking scopes.

DATA means dataset integrity and lineage; ENV means verifiable execution environment;
BENCH means benchmark specification graph; TRAIN means training run
specification; MODEL means model reproducibility specification; SIM means generative
simulation specification; HARNESS means an instrumented agent observation surface;
AGENT means an agent trajectory bounded by that surface; BOT means one agent situated
in one simulation; TOKEN means one zero-identity zero-knowledge token holding descending
from one birth token; HARDWARE names retained physical-device records. Domain depths are dimensionless
prerequisite counts, separate from the VSTD object and Graph numbered profiles.

Each check carries the exact set of lower checks its own evaluation re-executes or
presupposes. This is a directed acyclic graph, not a chain: most domains fan out
from a shared prologue, so a check is not blocked by an unrelated sibling. Only
TRAIN is genuinely linear.
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
    "TRAIN": (
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
    "BOT": (
        ("binding", "Re-derive the bound agent, simulation and two environment certificates from their retained bytes.", ()),
        ("alignment", "Bind every simulation transition to one retained record; refuse an undeclared unattributed transition.", (1,)),
        ("observation", "Check that every retained observation is the simulation's own projection of that state.", (1, 2)),
        ("actuation", "Check that every replayed simulation action is an action the agent actually invoked.", (1, 2, 3)),
        ("containment", "Check the declared separation of the agent and simulator execution environments.", (1,)),
    ),
    "TOKEN": (
        ("inventory", "Rehash the complete token inventory; check each token's kind, bound fields, unique identifiers and single birth token, and the named clock its instants are on.", ()),
        ("tenure", "Refold every retained epoch from the birth commitment and check each aging token's interval, accrual and revocation status.", (1,)),
        ("leases", "Resolve every lease to its parent grant and check that no delegation step widens scope, window, invocations or caveats.", (1,)),
        ("signatures", "Verify every token signature over its canonical preimage under a bound, unretired, checker-admitted issuing key.", (1,)),
        ("closure", "Check audience closure, report window coverage and clock-undetermined leases, and require a fresh status for every token.", (1,)),
    ),
    "VERIFIER": (
        ("identity", "Bind declared verifier kind, version and retained toolchain inventory digests; do not execute the submitted verifier.", ()),
        ("soundness", "Recheck the retained native grounded decision certificate against its exact expected binding; no class-wide soundness theorem.", (1,)),
        ("determinism", "Repeat local native-kernel replay of the retained decision certificate; no submitted-process determinism or entropy guarantee.", (1, 2)),
        ("resources", "Enforce bounded checker-owned native replay with Windows Job Object allocation/time limits and charged native work; unavailable capability remains UNKNOWN.", (1,)),
        ("meta", "Independently recompute finite native Boolean results under an externally admitted exact-scope signature; no general soundness or organizational independence.", (1, 2, 3, 4)),
    ),
    "HARDWARE": (
        ("inventory", "Rehash retained device inventory and validate explicitly typed integer capacities; no physical authenticity.", ()),
        ("topology", "Check complete declared containment edges resolve and form an acyclic graph.", (1,)),
        ("allocations", "Recompute simultaneous occupancy of half-open intervals without exceeding declared per-device capacities.", (1,)),
        ("measurements", "Check retained integer observations against their device, unit and declared capacity; no observation authenticity.", (1,)),
    ),
}

COORDINATES = {
    "HARDWARE": ("HARDWARE-1.1", "HARDWARE-1.2", "HARDWARE-2.1", "HARDWARE-2.2"),
    "DATA": ("DATA-1.2", "DATA-1.4", "DATA-2.1", "DATA-4.1", "DATA-4.4"),
    "ENV": ("ENV-1.2", "ENV-1.4", "ENV-3.3", "ENV-2.3"),
    "BENCH": ("BENCH-1.2", "BENCH-1.4", "BENCH-4.1", "BENCH-3.6"),
    "TRAIN": ("TRAIN-1.1", "TRAIN-1.3", "TRAIN-4.1", "TRAIN-2.3", "TRAIN-2.1"),
    "MODEL": ("MODEL-1.5", "MODEL-1.1", "MODEL-2.1", "MODEL-4.1", "MODEL-4.3"),
    "SIM": ("SIM-2.1", "SIM-3.1", "SIM-2.5", "SIM-1.4", "SIM-4.1"),
    "HARNESS": ("HARNESS-1.1", "HARNESS-2.1", "HARNESS-2.2", "HARNESS-2.3", "HARNESS-4.1"),
    "AGENT": ("AGENT-1.1", "AGENT-2.1", "AGENT-2.3", "AGENT-4.1", "AGENT-4.3"),
    "BOT": ("BOT-1.1", "BOT-2.1", "BOT-2.2", "BOT-2.3", "BOT-4.1"),
    "TOKEN": ("TOKEN-1.1", "TOKEN-1.4", "TOKEN-2.4", "TOKEN-1.2", "TOKEN-2.12"),
    "VERIFIER": ("VERIFIER-1.1", "VERIFIER-1.2", "VERIFIER-1.3", "VERIFIER-1.4", "VERIFIER-1.5"),
    "ACTOR": ("ACTOR-1.1", "ACTOR-2.1", "ACTOR-3.2", "ACTOR-4.2"),
    "OWNER": ("OWNER-1.3", "OWNER-2.1", "OWNER-3.1", "OWNER-4.5"),
    "HUMAN": ("HUMAN-1.1", "HUMAN-2.1", "HUMAN-4.4"),
    "IDENTITY": ("IDENTITY-1.3", "IDENTITY-2.1", "IDENTITY-4.2"),
    "ROLE": ("ROLE-1.1", "ROLE-2.1"),
    "COLLECTIVE": ("COLLECTIVE-1.1", "COLLECTIVE-2.5"),
}

# Named diagnostic routes have no positive establishment mechanism.
UNKNOWN_ONLY_CHECKS: dict[str, dict[str, str]] = {}

ACCOUNTABLE_CHECKS = {
    "ACTOR": (
        ("identity", "Verify bound control keys match artifact control surface and ensure instrument boundary does not overlap actor boundary.", ()),
        ("delegation", "Replay delegation events from declared digest and verify no delegation conveys authority outside actor's decision classes.", (1,)),
        ("accountability", "Verify witness attributions bind the declared actor and reject sole witness self-attribution.", (1,)),
        ("attribution", "Verify decisions trace contiguously, attribute to declared actor within decision classes, and use verified external instruments.", (1, 2)),
    ),
    "OWNER": (
        ("limbs", "Verify consequence limbs are within recognized consequence set, limb kinds are valid, and term interval is well-ordered.", ()),
        ("lifecycle", "Replay lifecycle events (freeze, seal, thaw, transfer, revocation, lapse) and verify valid sequence and limb holding.", (1,)),
        ("independence", "Verify holding consequence boundaries never alters computational verdicts, digests, or evidence bytes.", (1,)),
        ("accountability", "Verify accountability floor and discharge-duty terminate in an accountable person with valid witness binding.", (1, 2, 3)),
    ),
    "HUMAN": (
        ("assertion", "Bind a declared human-subject assertion, capture class, evidence inventory, and non-asserted civil attributes; do not infer living personhood or witness independence.", ()),
        ("lifecycle", "Replay retained enrollment and later assertion events in declared order and validity; do not infer current physical liveness.", (1,)),
        ("closure", "Require independent personhood, liveness, error-rate, and accountability evidence; report UNKNOWN while those mechanisms are absent.", (1, 2)),
    ),
    "IDENTITY": (
        ("occupancy", "Bind declared HUMAN-or-BOT bearer, ROLE seat, retained occupancy record, and an unverified evidence reference; do not infer bearer authenticity or authority.", ()),
        ("lifecycle", "Replay declared enrollment, presentation, renewal, revocation, and simulation-end events without transferring bearer identity.", (1,)),
        ("support", "Replay bound bearer and ROLE child certificates under checker-selected policy where supported; never infer living personhood or role authority.", (1, 2)),
    ),
    "ROLE": (
        ("facets", "Validate the retained role-class declaration, admissible bearer classes, and simultaneous bearer limit; do not authenticate qualifications or authority.", ()),
        ("occupancy", "Replay digest-bound take, leave, and atomic handover events against the declared class and bearer limit; the final trace state is not live occupancy.", (1,)),
    ),
    "COLLECTIVE": (
        ("graph", "Rehash a finite typed role graph and its declared class boundary; edges do not establish occupancy, personhood, legal existence, or consent.", ()),
        ("decisions", "Replay digest-bound finite role-decision assembly against declared required-role sets; role decisions and bearers remain unauthenticated declarations.", (1,)),
    ),
}

ALL_CHECKS = {**CHECKS, **ACCOUNTABLE_CHECKS}

SCOPES = {
    "HARDWARE": "finite retained hardware declarations, topology, allocation arithmetic and observation envelopes; not physical attestation",
    "DATA": "complete retained dataset and declared transformation boundary",
    "ENV": "retained software inventory and named collector observations",
    "BENCH": "complete retained finite problem suite and its named oracles",
    "TRAIN": "retained dense-network training trace and declared numerical semantics",
    "MODEL": "retained dense network, evaluation set and finite challenge set",
    "SIM": "retained transition model, trace and explicitly enumerated state boundary",
    "HARNESS": "declared instrumented observation surface and its retained transcript",
    "AGENT": "retained trajectory inside the observation ceiling of one bound harness certificate",
    "BOT": "closed loop between one bound agent certificate and one bound simulation certificate",
    "TOKEN": "complete retained token holding descending from one birth token under checker-admitted issuing keys",
    "VERIFIER": "retained verifier identity and native proof replay; opt-in Windows bounded replay and externally admitted finite bootstrap",
}

ACCOUNTABLE_SCOPES = {
    "ACTOR": "accountable party identity, control surface, delegation trace and decision attribution",
    "OWNER": "artifact consequence limbs, lifecycle holding, and accountability floor terminating in natural persons",
    "HUMAN": "retained human-assertion metadata and event replay; no physical personhood, liveness, uniqueness, or natural-person accountability proof",
    "IDENTITY": "retained bearer/role/occupancy bindings and event replay; nested child replay only where checker-admitted, without authority promotion",
    "ROLE": "retained role-class facets and finite occupancy-event replay; no credential, qualification, or legal authority authentication",
    "COLLECTIVE": "retained typed role graph and finite decision-assembly replay; no independent occupancy, quorum, personhood, or legal existence proof",
}

ALL_SCOPES = {**SCOPES, **ACCOUNTABLE_SCOPES}


def domain_catalog(include_accountable: bool = False) -> dict:
    """Describe all native domain propositions, scopes and cumulative prerequisites."""
    checks_map = ALL_CHECKS if include_accountable else CHECKS
    scopes_map = ALL_SCOPES if include_accountable else SCOPES
    return {"schema_version": "verifier-domain-catalog-1", "domains": {
        domain: {"scope": scopes_map[domain], "checks": [
            {"id": COORDINATES[domain][i - 1], "name": name, "proposition": statement,
             "depends_on": [COORDINATES[domain][d - 1] for d in depends]}
            for i, (name, statement, depends) in enumerate(checks, 1)]}
        for domain, checks in checks_map.items()}}


def domain_specification_digest() -> str:
    data = files("verifier.standard").joinpath("DOMAIN_GROUNDING.md").read_bytes()
    return canonical_digest({"catalog": domain_catalog(include_accountable=True),
                             "specification": hashlib.sha256(data).hexdigest()})
