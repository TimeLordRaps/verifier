"""Audited semantic ownership for ten current untracked source files.

The ten paths are the nonignored untracked source additions in the shared dirty
Verifier Standard (VSTD) worktree that the Polish-0 census reports and the central
semantic ownership catalog does not yet own. Each path gets one standalone
``SemanticOwnershipSpec`` row. This module is data-only: it imports no aggregate
catalog and no third-party package, and this batch does not edit the aggregate.

Roles follow what each source does, not what its name suggests. A HARNESS primary means
the file contains execution of a subject or a worker, by process launch or by in-process
case execution. Launching or stopping a process, including taskkill, a process group or a
local worker, is HARNESS process control. ACTUATOR is reserved for a real command-to-effect
endpoint with an explicit physical binding; no row here has one, so no row is an ACTUATOR.
PROTOCOL means a parent/worker or request/receipt schema with closed fields. POLICY means an
admission, classification or gating decision. TRANSACTION means a state machine over
resource writes. VERIFIER as a retained root means the file itself emits PASS, FAIL or UNKNOWN
verdicts in code. OBJECT is never used as a fallback.

Retained-root decisions are recorded only where the source addresses the root. A root
without a decision stays UNKNOWN and is not exempt. ``applicability_records`` expands every
row over the 38 registered kinds, so each unestablished cell is an explicit UNKNOWN with a
basis rather than a silent gap. Specializations are limited to the refined kinds, and a
retained root must be a core kind. Every primary used here declares an empty operand layout,
so no target identifier is invented; ``INTEGRATION_BLOCKERS`` states what remains before
aggregate admission.

Terminology: JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
hash-based message authentication code (HMAC).

Claim boundary: these rows assign source ownership only. They claim no mechanism
truth, obligation closure, sandboxing, isolation, physical actuation, financial effect,
external atomicity or finality, route conformance, release, or publication authority.
Repository admission is a separate gate.
"""

from __future__ import annotations

from typing import NamedTuple

from verifier.runtime.package_semantic_ownership_model import (
    SemanticOwnershipSpec,
    ownership_spec,
    root_role_decision,
)


# Full-file SHA-256 of each audited path at the time these rows were written. Drift is a
# failure: a changed source must be re-audited before its row changes.
AUDITED_SOURCE_DIGESTS = {
    "extensions/languages/src/vstd_languages/extended_batch_two.py": "sha256:a94772e220435566910fd07a8d49474aefc59c70f16fb218237443fb107f7e29",
    "extensions/languages/src/vstd_languages/extended_batch_three.py": "sha256:7b19b78a0ef3bf3dc2e570355bd1bc98f7fd9d64e0436a19f8c71a5cdd7594fc",
    "src/verifier/core/owned_process.py": "sha256:3bbc6610b122384130a205228a1e93c844e879174f0e5306dbe42014207fb4e2",
    "src/verifier/domains/contracts/agency_surface.py": "sha256:d7030f608c82578ff62e7fcd74d22ac2457a2656634f40a0dfca769fb2eed297",
    "src/verifier/runtime/namespace_refutation.py": "sha256:31e404c5e6f27bddcded32757f5eb26835e283ba507c73b2b94527fae7f85285",
    "src/verifier/runtime/package_checker_worker.py": "sha256:94ed8c2cce120a3c936a0f918a1c815dcb59b7482f5c1a332e9c77e192972fac",
    "src/verifier/runtime/policy_enforcement_execution.py": "sha256:f868d74e9c353b8a2c4b469cc0b79b72d2ab9d2439e97646890954be93a80e92",
    "src/verifier/runtime/policy_enforcement_routes.py": "sha256:06504a355e697833626b332aaac345d78a384f2f51ea9cdb832163070d4d9a49",
    "src/verifier/runtime/policy_enforcement_worker.py": "sha256:7bd79141d43403cb49c7cfd5e94c2de4bdc3874296ae7ed678cb76707bd919cd",
    "src/verifier/runtime/transaction_execution.py": "sha256:abcddfd6a14c05120982137b501a39bc6a32777850d055a4eb7b23940d06c62c",
}

INTEGRATION_BLOCKERS: tuple[str, ...] = (
    "Aggregate admission is pending: these rows are exported standalone and are not yet "
    "listed in the central semantic ownership aggregate, which this batch does not edit.",
    "No operand slot is bound: every primary used here declares an empty operand layout, "
    "so no target identifier is supplied and none is invented.",
    "The shared RootRoleDecision model encodes only APPLIES or DOES_NOT_APPLY. UNKNOWN is "
    "therefore derived by ``applicability_records`` and is not a decision; the model is not edited.",
)

# The 38 kinds of the namespace registry, sorted. The refined kinds are the twelve that
# extend another kind; the other 26 are core kinds and the only ones a retained root may be.
REGISTERED_KINDS: tuple[str, ...] = (
    "ACTOR", "ACTUATOR", "AGENT", "ARCH", "ASSET", "BENCH", "BOT", "COLLECTIVE", "CONTROLLER",
    "DATA", "ENV", "EVENT", "FINBOT", "GRAPH", "HARDWARE", "HARNESS", "HUMAN", "HYPER",
    "IDENTITY", "LEDGER", "MARKET", "MEASUREMENT", "MODEL", "OBJECT", "OWNER", "POLICY",
    "PROTOCOL", "RECEIPT", "ROBOT", "ROLE", "SENSOR", "SIM", "SPACE", "TIME", "TOKEN",
    "TRAIN", "TRANSACTION", "VERIFIER",
)
REFINED_KINDS: frozenset[str] = frozenset({
    "ACTUATOR", "ASSET", "CONTROLLER", "FINBOT", "LEDGER", "MARKET", "MEASUREMENT", "POLICY",
    "PROTOCOL", "ROBOT", "SENSOR", "TRANSACTION",
})

_ADAPTER_VERIFIER_BASIS = (
    "EXIT_CODE_ONLY: the adapter emits exit codes and no PASS, FAIL or UNKNOWN verdict in code; "
    "the host reader that maps codes to candidate verdicts is outside these files and unverified "
    "here, so applicability is not established."
)


class ApplicabilityRecord(NamedTuple):
    """One kind's applicability for one row.

    Status is PRIMARY, SPECIALIZATION, APPLIES, DOES_NOT_APPLY or UNKNOWN. UNKNOWN is a recorded
    denominator with a basis, never an exemption. The basis names why a cell is not established.
    """

    object_id: str
    kind: str
    status: str
    basis: str


# Typed local UNKNOWN bases for cells a row would otherwise leave silent.
LOCAL_UNKNOWN_BASIS: dict[tuple[str, str], str] = {
    ("vstd-language-extended-batch-two-adapters", "VERIFIER"): _ADAPTER_VERIFIER_BASIS,
    ("vstd-language-extended-batch-three-adapters", "VERIFIER"): _ADAPTER_VERIFIER_BASIS,
}


def _default_unknown_basis(kind: str) -> str:
    if kind == "OBJECT":
        return "OBJECT_FORBIDDEN_FALLBACK: never a primary, specialization or retained root; no decision recorded"
    if kind in REFINED_KINDS:
        return "REFINED_KIND_NOT_CLAIMED: not established for this row"
    return "NO_ROOT_ROLE_DECISION_RECORDED: not established, not exempt"


def applicability_records(spec: SemanticOwnershipSpec) -> tuple[ApplicabilityRecord, ...]:
    """Return one record per registered kind for one row, in sorted kind order."""
    decisions = {decision.kind: decision for decision in spec.root_role_decisions}
    records: list[ApplicabilityRecord] = []
    for kind in REGISTERED_KINDS:
        if kind == spec.primary_kind:
            status, basis = "PRIMARY", "PRIMARY_KIND"
        elif kind in spec.specializations:
            status, basis = "SPECIALIZATION", "CLAIMED_REFINEMENT"
        elif kind in decisions:
            status, basis = decisions[kind].status, "ROOT_ROLE_DECISION"
        else:
            status = "UNKNOWN"
            basis = LOCAL_UNKNOWN_BASIS.get((spec.object_id, kind)) or _default_unknown_basis(kind)
        records.append(ApplicabilityRecord(spec.object_id, kind, status, basis))
    return tuple(records)


_ROWS: tuple[SemanticOwnershipSpec, ...] = (
    ownership_spec(
        "vstd-language-extended-batch-two-adapters",
        "HARNESS",
        ("extensions/languages/src/vstd_languages/extended_batch_two.py",),
        "Native language runner adapter for COBOL, Object Pascal, Ada, Objective-C and "
        "Assembly, with a closed verifier-language-runner-1 argv shape.",
        "The embedded WORKER starts a fixed compiler (cobc, fpc, gnatmake, clang or the GCC assembler "
        "driver) in a fresh temporary directory, then starts the built artifact only after a successful "
        "compile, each under a deadline and a per-stream byte cap. Starting and stopping those children is "
        "HARNESS execution and process control, not ACTUATOR, because no physical command-to-effect endpoint "
        "is bound. The environment refusal and dialect admission are POLICY gates, and the argv and "
        "exit-code contract is PROTOCOL.",
        "Runs the compiler and the compiled subject artifact on the host with the inherited environment: no "
        "filesystem, network or syscall confinement and no isolation claim. Windows descendant cleanup is "
        "UNKNOWN beyond the child's taskkill /T /F. Sandboxed execution belongs to the core OpenShell path, "
        "which this file does not establish. Host registry admission is absent, so these names are "
        "unreachable from the installed command-line interface.",
        "POLICY", "PROTOCOL",
        root_role_decisions=(
            root_role_decision(
                "AGENT", "DOES_NOT_APPLY",
                "The command( function selects a fixed toolchain by table lookup and returns argv for the "
                "worker, which then executes that compiler and the compiled artifact. The S + decider + "
                "HARNESS composition an agent requires is absent: the toolchain is not chosen by a decider "
                "over state.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-language-extended-batch-three-adapters",
        "HARNESS",
        ("extensions/languages/src/vstd_languages/extended_batch_three.py",),
        "Native language runner adapter for Visual Basic .NET, Scratch 3, MATLAB and SAS, with "
        "a refused Classic Visual Basic (VB6) declaration.",
        "The embedded WORKER starts dotnet build, which is a compiler invocation, and then dotnet run as "
        "children, a headless Scratch runner, matlab -batch and sas -sysin, each under a deadline and a "
        "file-size cap. Starting and stopping those children is HARNESS execution and process control, not "
        "ACTUATOR, because no physical command-to-effect endpoint is bound. The SB3_CHECK archive-shape gate "
        "and the environment refusal are POLICY, and the closed argv and exit-code contract is PROTOCOL.",
        "Runs the dotnet build compiler, the dotnet run child, the Scratch runner, MATLAB and SAS with the "
        "inherited environment and no isolation. The dotnet restore uses an empty private NuGet source with "
        "audit off, which is configuration, not confinement. Scratch needs an explicitly installed headless "
        "runner, and its static archive check is never reported as execution. Classic Visual Basic (VB6) is "
        "NOT_ESTABLISHED and is refused before any lookup. Windows descendant cleanup is UNKNOWN, and host "
        "registry admission is absent.",
        "POLICY", "PROTOCOL",
        root_role_decisions=(
            root_role_decision(
                "AGENT", "DOES_NOT_APPLY",
                "The command( function resolves only the requested runner and returns argv for the worker, "
                "which then executes the dotnet build compiler and the selected toolchain. The S + decider + "
                "HARNESS composition an agent requires is absent: the runner is resolved by table lookup, not "
                "chosen by a decider over state.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-core-owned-process-tree",
        "HARNESS",
        ("src/verifier/core/owned_process.py",),
        "Owned subprocess-tree launch, observation and termination primitive with bounded stream retention.",
        "run_owned_process( starts one argv in a kill-on-close Job Object on Windows, or in a new session and "
        "process group on POSIX, polls exit, deadline and output caps, and terminates the owned Job Object or "
        "process group on every exit path. Starting and stopping that process lifetime is HARNESS "
        "process-lifetime control, not ACTUATOR: no physical command-to-effect endpoint is bound, and ordinary "
        "subprocess start and stop never makes a source an actuator. MEASUREMENT is not claimed because no "
        "physical quantity or uncertainty is produced.",
        "Controls process lifetime and retains stream prefixes. CLEANUP_CONFIRMED means only that the owned "
        "members were observed empty after termination. On POSIX the owned unit is a process group, not a "
        "guaranteed tree: a descendant that calls setsid or setpgid leaves that group, and whether such an "
        "escape is available on the host is unverified here, so killpg and owned_members_remain( establish "
        "nothing about escaped processes. The module docstring's whole-tree wording overstates the POSIX "
        "primitive. The primitive does not isolate filesystem, network, syscalls or a hostile host, and it "
        "establishes nothing about subject-internal state, outputs or correctness. Termination attempts "
        "through TerminateJobObject, killpg and close are not proof of processes outside the owned unit.",
        root_role_decisions=(
            root_role_decision(
                "AGENT", "DOES_NOT_APPLY",
                "run_owned_process( lacks the S + decider + HARNESS composition an agent requires: it starts and "
                "watches one argv, holds no state space S, and selects no action from a decider.",
            ),
            root_role_decision(
                "VERIFIER", "DOES_NOT_APPLY",
                "The primitive returns status EXITED, TIMEOUT or OUTPUT_CAP and cleanup CONFIRMED, NOT_CONFIRMED "
                "or UNKNOWN. These are process observations. The module emits no PASS, FAIL or UNKNOWN verdict "
                "about any claim, and CLEANUP_CONFIRMED is not a verdict.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-agency-surface-crosswalk",
        "POLICY",
        ("src/verifier/domains/contracts/agency_surface.py",),
        "Classification and cross-route crosswalk over retained BOT, ROBOT and FINBOT agency-surface certificates.",
        "_evaluate classifies effect domains (SIMULATED, REAL_PHYSICAL, REAL_FINANCIAL) and admits a route only "
        "when independently replayed child certificates name one agent_id, one harness_id and one trace effect "
        "key. That classification and its join gate are POLICY. The crosswalk does not establish that any "
        "classified effect occurred, so no ROBOT, FINBOT, ACTUATOR or BOT consequence role is accumulated.",
        "A passing crosswalk establishes a bounded relation among retained records. It is not evidence that a "
        "physical actuation, financial transfer, simulated effect or agent action occurred. It does not establish "
        "authentic observations, adequate limits, successful recovery, physical safety, legal authority or "
        "real-world correspondence. The file has no decider and runs no simulated coupling of its own, so BOT is "
        "recorded DOES_NOT_APPLY for this source only; that is not a finding about any other BOT source.",
        root_role_decisions=(
            root_role_decision(
                "AGENT", "DOES_NOT_APPLY",
                "_actual_ids( reads the actual agent_id from independently replayed AGENT or BOT child records. The "
                "file lacks the S + decider + HARNESS composition an agent requires: it has no decider, and it "
                "compares child agent_id values only for cross-route identity.",
            ),
            root_role_decision(
                "BOT", "DOES_NOT_APPLY",
                "_replay_child( replays BOT child certificates through their own recheck mechanisms. The file composes "
                "no BOT instance: it has no decider and no simulated coupling of its own, so a BOT label it verifies "
                "is not a BOT instance. This decision is for this source only.",
            ),
            root_role_decision(
                "HARNESS", "DOES_NOT_APPLY",
                "_replay_child( replays child certificates through their own recheck mechanisms. It launches no "
                "process, instruments no channel and observes no subject, and each child carries its own "
                "harness status.",
            ),
            root_role_decision(
                "VERIFIER", "APPLIES",
                "recheck_agency_surface_certificate and recheck_package_certificate return PASS, FAIL or UNKNOWN "
                "for the cumulative cross-route identity and trace joins they replay. The evidence is bounded and "
                "never establishes object-profile conformance.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-namespace-refutation-witness",
        "POLICY",
        ("src/verifier/runtime/namespace_refutation.py",),
        "Fail-closed admission and refutation witness for DOES_NOT_APPLY namespace decisions.",
        "Each DOES_NOT_APPLY claim is admitted only through a fresh boundary-absence scan of its anchored census, "
        "run by run_closure, and bound to an exact identity. Admission over namespace applicability is POLICY. "
        "No consequence role is accumulated because the boundary identifiers appear only as text to be scanned.",
        "A closure PASS establishes only that the anchored census contains no registered boundary identifier and no "
        "dynamic, external or unsupported-language gate hit. It is a bounded text scan, not a semantic proof, and a "
        "mention in a comment counts against it. A witness is not an exemption from ownership: this row remains "
        "required, and a FAIL, UNKNOWN or absent witness leaves the kind's obligations in force. An ESTABLISHED "
        "witness resolves applicability only for its bound kind and census.",
        root_role_decisions=(
            root_role_decision(
                "AGENT", "DOES_NOT_APPLY",
                "_scan_boundary_references( reads only anchored text for registered identifiers. The module lacks the "
                "S + decider + HARNESS composition an agent requires: it composes no decider and no state space S, and "
                "its own HARNESS role is DOES_NOT_APPLY.",
            ),
            root_role_decision(
                "HARNESS", "DOES_NOT_APPLY",
                "The module states that a registered closure is a fixed scan of anchored text, so no subject code "
                "is imported, launched or executed and nothing is instrumented.",
            ),
            root_role_decision(
                "VERIFIER", "APPLIES",
                "run_closure returns PASS, FAIL or UNKNOWN closure receipts, and establish_dne_witness maps them to "
                "ESTABLISHED, FAIL or UNKNOWN verdicts for each DOES_NOT_APPLY witness.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-package-checker-worker",
        "HARNESS",
        ("src/verifier/runtime/package_checker_worker.py",),
        "Fresh source-bound checker worker that compiles and runs one held checker module and writes a bounded receipt.",
        "main() reads one JSON request on stdin, compiles the exact bytes it hashed without a bytecode cache, executes "
        "the checker under bounded diagnostics, and writes a canonical receipt. Executing held checker code in a "
        "separate process is actual containment, so HARNESS is primary. The parent and worker request-receipt "
        "schema is PROTOCOL.",
        "Executes checker source in a separate process started by its parent, with the parent's privileges and "
        "inherited environment. It is not an isolation sandbox, and a checker is trusted only through its digest. "
        "Diagnostics are bounded and discarded. The worker launches nothing and changes no external state, so "
        "ACTUATOR does not apply. The receipt is a local checker verdict and never package conformance.",
        "PROTOCOL",
        root_role_decisions=(
            root_role_decision(
                "AGENT", "DOES_NOT_APPLY",
                "_load_held_checker( executes one parent-selected checker against supplied observations. The worker "
                "selects no actor and takes no decision of its own.",
            ),
            root_role_decision(
                "VERIFIER", "APPLIES",
                "main() writes a verifier-package-checker-receipt-1 whose status is PASS for an exact Boolean true, "
                "FAIL for an exact Boolean false, and UNKNOWN for any exception or source change. "
                "PACKAGE_EXECUTION_OBSERVATION_REFUTED marks the FAIL case.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-policy-enforcement-execution",
        "POLICY",
        ("src/verifier/runtime/policy_enforcement_execution.py",),
        "Source-bound in-memory POLICY enforcement engine with hash-chained receipts and auxiliary route field checks.",
        "enforce() decides each request under verified authority, exceptions, revisions, decision evidence and "
        "consequence roles, and appends one receipt per call. That is POLICY. FINANCIAL and PHYSICAL roles are "
        "enforced as gates only: the engine performs no transfer or motion, so FINBOT, ROBOT and ACTUATOR are not "
        "accumulated. The read-only git status observation in _repository_state is a HARNESS launch that changes "
        "no state; it is not ACTUATOR and not a consequence role.",
        "Decides caller-supplied requests in process and observes only calls made through enforce. It does not execute "
        "downstream effects, prove key custody or signer identity, establish publication or currentness of revisions, "
        "or establish the truth of facts behind decision evidence. Receipts are hash-chained, not signed. An ALLOWED "
        "receipt is not an effect, and any effect not supplied stays UNKNOWN.",
        root_role_decisions=(
            root_role_decision(
                "AGENT", "DOES_NOT_APPLY",
                "issue_authorization( and the route authorities are HMAC key holders over fixture payloads. enforce( is "
                "a decider over caller-supplied requests, but the row lacks the S + decider + HARNESS composition an "
                "agent requires: no agent state S is composed with that decider, and its HARNESS role is an in-process "
                "fixture observation rather than an agent loop.",
            ),
            root_role_decision(
                "HARNESS", "APPLIES",
                "def _execute( runs every route's field cases in process, maps evaluator faults to UNKNOWN, and compares "
                "observed outcomes with expectations. That is an in-process observation harness over enforce(). It starts "
                "no subject process; its one launch is the read-only git status observation in _repository_state, which "
                "changes no state.",
            ),
            root_role_decision(
                "VERIFIER", "APPLIES",
                "auxiliary_evaluate( and build_report emit auxiliary PASS, FAIL or UNKNOWN verdicts from fresh execution, "
                "always with route_conformance NOT_ESTABLISHED.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-policy-enforcement-routes",
        "HARNESS",
        ("src/verifier/runtime/policy_enforcement_routes.py",),
        "Route cases and parent-side evaluation for three POLICY enforcement coordinates.",
        "The module builds real enforcement cases, injects faults into the engine in process, and starts the isolated "
        "worker with python -I -S -B under a timeout. In-process fault execution is HARNESS. Starting that child and "
        "stopping it on timeout is HARNESS process control, not ACTUATOR, because no physical command-to-effect endpoint "
        "is bound. The nonce and source-pin exchange is PROTOCOL. evaluate_routes( judges the worker's observations "
        "through the oracle.",
        "Runs the enforcement engine in a child interpreter started by this module, isolated from the parent's import "
        "path only. It is not isolation from the filesystem, network or host. Fault injection patches engine attributes "
        "and restores them before observation. Central registration is matched by exact key and never upgrades a route. "
        "route_conformance and obligation_closure are always NOT_ESTABLISHED.",
        "PROTOCOL",
        root_role_decisions=(
            root_role_decision(
                "AGENT", "DOES_NOT_APPLY",
                "_CASES is a fixed table of cases and fault injections. The module takes no agent decision, plan or action.",
            ),
            root_role_decision(
                "VERIFIER", "APPLIES",
                "evaluate_routes( emits auxiliary PASS, FAIL or UNKNOWN for each route and an aggregate, always with "
                "route_conformance NOT_ESTABLISHED.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-policy-enforcement-worker",
        "HARNESS",
        ("src/verifier/runtime/policy_enforcement_worker.py",),
        "Isolated POLICY enforcement worker with an independent observation oracle.",
        "main() reads one bounded nonce request, checks its own source pins before and after, and collects raw "
        "observations from routes.observe_all() in a separate interpreter. Executing the engine cases is HARNESS. The "
        "request, nonce and pin exchange is PROTOCOL. Independence is module-level and parent-side: this file imports "
        "no engine at module level, and check_all( runs in the parent process that imports it as the oracle through "
        "evaluate_routes(, so the engine does not grade its own observations.",
        "The worker runs enforcement cases in process with fixed public fixture keys, which are not trust roots. Its PASS "
        "is local field evidence in an isolated interpreter, not route conformance, and it does not register the route. "
        "It launches no process and performs no external effect; the parent owns the launch.",
        "PROTOCOL",
        root_role_decisions=(
            root_role_decision(
                "AGENT", "DOES_NOT_APPLY",
                "source_pins( and the fixed case table only read this file's dependencies. The worker takes no agent "
                "decision, plan or action.",
            ),
            root_role_decision(
                "VERIFIER", "APPLIES",
                "check_all( judges each route with literal expectations and a closed-form rule table, and returns PASS "
                "or FAIL per route plus set-level refusals; evaluate_routes( in the parent process calls it.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-transaction-execution-coordinator",
        "TRANSACTION",
        ("src/verifier/runtime/transaction_execution.py",),
        "Deterministic in-memory two-resource transaction coordinator with a hash-chained journal, keyed authorization "
        "and reconciliation.",
        "prepare, commit, abort, compensate and reconcile are state transitions over an append-only hash-chained journal "
        "with retry and compensation rules, which is TRANSACTION. The closed phase and replay state machine is PROTOCOL. "
        "The keyed authorization over canonical request bodies and the precondition gating are POLICY. The coordinator "
        "performs no external actuation, so ACTUATOR is not accumulated.",
        "Mutates only in-memory LocalResource dictionaries. It establishes precondition snapshot binding, keyed "
        "authorization, replay and bounded retry inside this model only. Durability, concurrent writers, external "
        "settlement, external atomicity, real authorizer identity and any finality beyond the local FINAL_LOCAL_RECORD "
        "are NOT_ESTABLISHED. It is not proof of external atomicity or finality.",
        "POLICY", "PROTOCOL",
        root_role_decisions=(
            root_role_decision(
                "AGENT", "DOES_NOT_APPLY",
                "_authorize( checks a keyed tag over one request body against an in-process registry. The coordinator "
                "chooses no action and holds no agent identity.",
            ),
            root_role_decision(
                "HARNESS", "APPLIES",
                "def observe() drives the coordinator with injected resource faults and simulated process stops through "
                "_attempt, recording each step. That is instrumented in-process execution of the subject, not a sandbox.",
            ),
            root_role_decision(
                "VERIFIER", "APPLIES",
                "_receipt( emits a PASS, FAIL or UNKNOWN status on each coordinator receipt: PASS for accepted or "
                "replayed operations and FAIL for refusals. check_observations( returns only a bool over a fresh "
                "observation and emits no receipt, so it is not the verdict emitter.",
            ),
        ),
    ),
)

CURRENT_UNTRACKED_OWNERSHIP_SPECS: tuple[SemanticOwnershipSpec, ...] = tuple(
    sorted(_ROWS, key=lambda spec: spec.object_id)
)


__all__ = [
    "ApplicabilityRecord",
    "AUDITED_SOURCE_DIGESTS",
    "CURRENT_UNTRACKED_OWNERSHIP_SPECS",
    "INTEGRATION_BLOCKERS",
    "LOCAL_UNKNOWN_BASIS",
    "REFINED_KINDS",
    "REGISTERED_KINDS",
    "applicability_records",
]
