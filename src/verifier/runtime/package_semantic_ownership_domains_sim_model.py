"""Audited SIM and MODEL domain source-ownership partition.

Terminology: central processing unit (CPU); graphics processing unit (GPU); identifier (ID);
JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).

The declarations cover the 26 residual source paths root-admitted without
semantic ownership: 18 SIM files (``domains/sim.py`` and 17 contracts) and 8
MODEL files (``domains/model.py`` and 7 contracts).  Primary kinds stay SIM or
MODEL.  Accumulated consequence roles and retained-root applicability decisions
come from each file's own source and its declared registration scope.  They
assign ownership only; they claim no obligation fulfillment, mechanism truth,
physical effect, authority, release, or deployment.

A role is recorded only when the source supplies a mechanism for it.  A file
name, a named real-world concept (``physical law``, a ``sensor`` kind, a signed
``lineage``), or a fresh-process launch does not establish a role by itself.  A
retained root with no recorded decision is UNKNOWN and is not exempt.  OBJECT is
never used as a fallback.  Process and worker files record HARNESS as
DOES_NOT_APPLY because a launched interpreter is not a harness.

SIM and MODEL typed layouts require every composition slot to be nonempty.  This
source audit establishes no exact target object for any of those slots.  The
slots therefore remain empty and are exported as typed aggregation blockers.
Invented target identifiers are forbidden: whole-graph integration must bind an
exact audited owner of the required kind or keep the batch non-aggregable.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from pathlib import Path, PurePosixPath
from typing import Iterable, Mapping

from verifier.runtime.package_semantic_ownership_model import (
    SemanticOwnershipSpec,
    ownership_spec,
    root_role_decision,
)


_REQUIRED_OPERAND_KINDS: dict[str, tuple[tuple[str, str], ...]] = {
    "SIM": (
        ("data", "DATA"),
        ("env", "ENV"),
        ("objects", "OBJECT"),
        ("verifier", "VERIFIER"),
    ),
    "MODEL": (
        ("arch", "ARCH"),
        ("bench", "BENCH"),
        ("data", "DATA"),
        ("env", "ENV"),
        ("events", "EVENT"),
        ("hardware", "HARDWARE"),
        ("train", "TRAIN"),
    ),
}


@dataclass(frozen=True)
class AggregationBlocker:
    """One typed reason this standalone ownership batch cannot aggregate."""

    code: str
    object_id: str
    operand_role: str | None
    required_kind: str | None
    target_id: str | None
    source_path: str | None
    reason: str


# Simulation specification core and its checker contracts.  Each contract owns
# one bounded proposition family; the replayed child certificates are named in
# the reasons rather than inherited as ownership.
_OWNERSHIP_DECLARATIONS: tuple[SemanticOwnershipSpec, ...] = (
    ownership_spec(
        "vstd-sim-specification-core",
        "SIM",
        ("src/verifier/domains/sim.py",),
        "Finite generative simulation specification core for transition replay, invariants, refinement, channel bounds, and shard closure.",
        "The evaluate function dispatches one of five finite checks. It replays the selected transition program over retained trajectories under an explicit Budget, compares refinement projections within a declared tolerance, checks supplied observation rows against the selected projection and action bounds, and verifies Ed25519 witness signatures over canonical shard rows when signatures are required.",
        "Model-relative replay and signature checks establish neither physical execution, observer completeness, historical trajectories, nor witness origin, and grant no privacy, consent, governance, or publication authority.",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "evaluate raises Refuted for each replay, invariant, refinement, channel, or shard mismatch and Unavailable for unsupported selections, so this module is the native checking core for the SIM checks.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-sim-native-checker-correspondence",
        "SIM",
        ("src/verifier/domains/contracts/sim_checker.py",),
        "Bounded correspondence between installed native SIM checks and selected expected outcomes.",
        "For each selected case, the mechanism runs one of the five native SIM checks through the installed evaluator and compares the canonical outcome with the expected positive result or explicit refutation, retaining a per-case observation list under the selected policy.",
        "This is finite outcome correspondence over the selected cases only. It is not class-wide checker soundness, an independent oracle, or evidence that unselected inputs are handled correctly.",
        "POLICY",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "The mechanism's evaluate method returns PASS, FAIL, or UNKNOWN from the per-case canonical comparison, and the module header names this file as VERIFIER dynamics.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-sim-dynamics-replay-verifier",
        "SIM",
        ("src/verifier/domains/contracts/sim_dynamics.py",),
        "Native SIM dynamics replay of one exact finite transition trajectory.",
        "_evaluate replays every selected transition of the retained state, entropy, and causal-time sequence through the installed interpreter and returns the selected state and transition counts under the selected policy and operation budget.",
        "Replay is not historical execution, actual causal-time truth, collector authenticity, action responsiveness, observation projection, resource consumption, or a complete dynamics tier.",
        "POLICY",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "_evaluate returns a MechanismDecision over the exact replay, and recheck_sim_dynamics_certificate reproduces that decision from the retained certificate.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-sim-external-law-statement",
        "SIM",
        ("src/verifier/domains/contracts/sim_external_law.py",),
        "Exact selected statement of an external modelled law referenced by a distinct typed OBJECT operand.",
        "The registration requires a distinct typed OBJECT operand whose bounded statement, applicability, and source reference are selected outside the SIM record. _evaluate checks that exact statement under the selected policy; it does not decide the physical law itself.",
        "The record asserts a represented statement only. It establishes no physical truth, dimensional correctness, source authority, actual simulation correspondence, or whole SIM statics tier.",
        "POLICY",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "_evaluate returns a MechanismDecision over the selected statement, and recheck_sim_external_law_certificate replays that decision from retained bytes.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-sim-fresh-source-loader",
        "SIM",
        ("src/verifier/domains/contracts/sim_fresh_bootstrap.py",),
        "Isolated fresh-process loader that materializes one selected SIM source closure before measurement.",
        "main reads one bounded JSON payload from standard input, checks each source's SHA-256 digest, writes the exact bytes into a private temporary import root, installs a finder that refuses verifier imports outside the selected closure, and then calls the fixed fresh meter under a fixed 8 MiB input bound.",
        "The temporary import root and inserted import path are process effects, not a hostile-host sandbox. The loader establishes source-byte identity for one interpreter run and grants no authority over the measured result.",
        "ACTUATOR",
        "POLICY",
        "PROTOCOL",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "DOES_NOT_APPLY",
                "The loader raises on digest, closure, or escape mismatch and emits a measurement envelope without PASS, FAIL, or UNKNOWN; verdict formation belongs to the parent certificate module.",
            ),
            root_role_decision(
                "HARNESS",
                "DOES_NOT_APPLY",
                "It loads one selected closure and makes one measure call; it selects no subjects, runs no test suite, aggregates no trials, and retries nothing.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-sim-fresh-process-meter",
        "SIM",
        ("src/verifier/domains/contracts/sim_fresh_worker.py",),
        "Fresh-process CPython thread-clock and traced-allocation meter over one loaded finite SIM transition sequence.",
        "measure validates one selected trajectory under bounded limits, then for each transition starts tracemalloc, reads perf_counter_ns and thread_time_ns around sim.transition, and binds each raw row to the challenge, source digest, run identifier, and process identifier. _cleanup_tracing refuses on a cleanup fault rather than producing a sample.",
        "CPU values are raw CPython thread-clock deltas and allocation values are traced Python bytes. They are not device time, resident memory, transition-exclusive cost, physical latency, or total resource use.",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        "TRANSACTION",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "DOES_NOT_APPLY",
                "measure returns raw step rows and frame fields and raises on replay or metered-state mismatch; it emits no PASS, FAIL, or UNKNOWN verdict, which sim_resource_fresh assigns from these rows.",
            ),
            root_role_decision(
                "HARNESS",
                "DOES_NOT_APPLY",
                "It meters one loaded transition sequence in one fresh process and does not dispatch subjects, compare suites, or orchestrate repeated trials.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-sim-internal-hidden-change-enumerator",
        "SIM",
        ("src/verifier/domains/contracts/sim_internal_core.py",),
        "Finite selected-channel enumeration of state-key changes invisible to declared observation projections.",
        "enumerate_hidden_changes, for each changed key, toggles that key alone across the endpoint hybrids of the other changed keys and lists it only when every declared projection remains numerically equal.",
        "Results are relative to the supplied finite state and channel inventory, whose completeness the caller must bind. No physical observer, undeclared channel, or unselected transition is covered.",
        "POLICY",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "DOES_NOT_APPLY",
                "enumerate_hidden_changes returns a list of hidden-change records and raises Refuted on bound or shape violations; it emits no PASS, FAIL, or UNKNOWN verdict, which the sim_internal_state certificate supplies.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-sim-internal-state-verifier",
        "SIM",
        ("src/verifier/domains/contracts/sim_internal_state.py",),
        "Source-bound SIM internal-state verifier over an exact PASS trajectory and a declared observation-channel inventory.",
        "_evaluate decodes the selected trajectory child when present and checks the retained observation artifact and declared hidden-change record against their selected digests under the selected limits; the registration binds these to a complete finite observation-channel inventory.",
        "The channel inventory is declared rather than observed. The result is model-relative and establishes no physical observation, undeclared-channel closure, or complete dynamics tier.",
        "POLICY",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "_evaluate returns the native PASS, FAIL, or UNKNOWN outcome, and recheck_sim_internal_state_certificate reproduces it from the retained child.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-sim-model-isolation-verifier",
        "SIM",
        ("src/verifier/domains/contracts/sim_isolation.py",),
        "Finite SIM isolation closure over declared virtual hardware, actions, and transitions.",
        "assess_sim_isolation parses a total finite model whose virtual HARDWARE kinds are compute, memory, storage, and sensor, rejects inside states that use undeclared capabilities, enumerates reachable state-action outcomes, and returns PASS inside the declared model, UNKNOWN for incomplete coverage, or FAIL for a represented boundary crossing.",
        "PASS is model-relative and grants no external resource authority. A declared virtual HARDWARE label is not a device, processor, or sensor observation, and the model can omit a real capability or physical channel.",
        "POLICY",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "assess_sim_isolation returns the PASS, UNKNOWN, or FAIL record for the selected binding, and recheck_sim_isolation recomputes the complete result from the same evidence.",
            ),
            root_role_decision(
                "HARDWARE",
                "DOES_NOT_APPLY",
                "The evidence declares virtual HARDWARE kinds as labels; no device, processor, inventory, or hardware observation is read, and the docstring states that no result attests host containment or ownership.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-sim-macro-projection-verifier",
        "SIM",
        ("src/verifier/domains/contracts/sim_perspective.py",),
        "Selected finite macro-projection alignment over an exact SIM-2.3 child and its embedded SIM-2.1 trajectory.",
        "_evaluate executes the child-bound finite projection on every retained micro state and compares each aligned retained macro state within the externally selected absolute tolerance and declared common macro unit.",
        "Numeric agreement under a selected tolerance is not physical correspondence, historical execution, independent macro-state production, unit-declaration authority, or whole dynamics conformance.",
        "MEASUREMENT",
        "POLICY",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "_evaluate returns the aligned-comparison MechanismDecision, and recheck_sim_perspective_certificate replays it from the retained child.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-sim-signed-resource-capture-verifier",
        "SIM",
        ("src/verifier/domains/contracts/sim_resource.py",),
        "Signed per-step local resource-capture verifier over an exact replayed SIM transition sequence.",
        "assess_fresh_sim_resource runs the fixed sim_resource_worker in a fresh interpreter under a timeout and checks its output shape against the selected trace. capture_sim_resource_evidence signs the canonical capture body with an admitted collector key, and _verify_signature checks that Ed25519 signature during recheck.",
        "The signature binds the selected collector statement only. Collector honesty, host attestation, historical execution, physical device attribution, and whole-device resource use are not established, and neither a limit nor Budget.used is a measurement.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "_evaluate returns PASS, FAIL, or UNKNOWN MechanismDecisions after recomputing the signature and capture shape, and recheck_sim_resource_certificate reproduces them from retained bytes.",
            ),
            root_role_decision(
                "HARNESS",
                "DOES_NOT_APPLY",
                "It invokes one fixed meter for one selected workload and rejects malformed output; it runs no repeated trials, subject selection, or test suite.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-sim-fresh-resource-execution-verifier",
        "SIM",
        ("src/verifier/domains/contracts/sim_resource_fresh.py",),
        "SIM-2.4 fresh execution verifier that launches a new source-loaded process and checks its challenge-bound per-step observations.",
        "_execute launches the bootstrap through subprocess with the -I, -S, and -B interpreter flags, checks the challenge, run, and process identifiers, rechecks each step binding digest and interval ordering, and recomputes the native trajectory before recheck_sim_resource_fresh_certificate can return PASS.",
        "The observation trusts the invoking mechanism, CPython, the standard library, pipes, clocks, the allocation tracer, and the operating system. It establishes no historical execution, host attestation, physical calibration, or total resource use, and retained metrics never earn PASS.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "recheck_sim_resource_fresh_certificate returns PASS, FAIL, or UNKNOWN after re-executing the native trajectory recheck and a new fresh run.",
            ),
            root_role_decision(
                "HARNESS",
                "DOES_NOT_APPLY",
                "Each invocation launches one new source-loaded process for one selected trajectory; it runs no test suite or subject comparison, and its reasons explicitly deny any earlier-run claim.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-sim-resource-meter-process",
        "SIM",
        ("src/verifier/domains/contracts/sim_resource_worker.py",),
        "Fixed isolated-process meter that measures one retained SIM transition sequence from standard-input data.",
        "main reads one bounded JSON request whose keys are exactly artifact, inputs, max_operations, and max_items, runs the selected replay with thread-clock and tracemalloc observations around each transition under bounded limits, and writes canonical measurement bytes to standard output with exit code 0 or 2.",
        "The process accepts data and never source code. Its CPU and allocation values are not total utilization, energy, GPU use, or historical customer work.",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "DOES_NOT_APPLY",
                "measure returns raw measurement fields and main returns an exit code; it emits no PASS, FAIL, or UNKNOWN verdict, which the parent certificate module assigns.",
            ),
            root_role_decision(
                "HARNESS",
                "DOES_NOT_APPLY",
                "main reads one request and calls measure once; it is a fixed single-request meter with no subject, suite, or repeated-run orchestration.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-sim-action-response-verifier",
        "SIM",
        ("src/verifier/domains/contracts/sim_response.py",),
        "Model-relative SIM action-response verifier over an exact SIM-2.1 PASS trajectory and a declared baseline action.",
        "_evaluate checks that each selected in-bounds action yields its exact next state under the action-aware transition expression, differs from the declared baseline action's next state, and responds within the selected simulated-time delay limit.",
        "The claim is a model-relative action effect only. It establishes no historical or physical causality, intervention outside the selected model, unselected actions, hidden state, or feedback-control correctness.",
        "MEASUREMENT",
        "POLICY",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "_evaluate returns the MechanismDecision for the selected actions, and recheck_sim_response_certificate replays it from the retained certificate.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-sim-shard-coverage-verifier",
        "SIM",
        ("src/verifier/domains/contracts/sim_shard_coverage.py",),
        "Finite SIM shard-time coverage over an exact passing SIM-2.1 trajectory.",
        "The selected declared shard identifiers must equal the retained shard inventory, and every selected shard must carry exactly one retained finite state row at every selected trajectory time, in the same order.",
        "Coverage establishes no physical execution, undeclared-shard closure, cross-shard relation truth, signature validity, independent producer authority, or whole simulated-surface closure.",
        "POLICY",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "_evaluate returns the coverage MechanismDecision, and recheck_sim_shard_coverage_certificate replays it from the retained certificate.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-sim-shard-relations-verifier",
        "SIM",
        ("src/verifier/domains/contracts/sim_shard_relations.py",),
        "Finite cross-shard relation evaluation over an exact SIM-4.1 shard-time certificate.",
        "Every selected nonempty finite relation that references at least two distinct declared shards must evaluate true at every retained aligned shard time.",
        "Unselected relations, dimensional validity, physical truth, undeclared shards, signatures, and independent shard-producer authority are not established.",
        "POLICY",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "_evaluate returns the relation MechanismDecision, and recheck_sim_shard_relations_certificate replays it from the retained certificate.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-sim-shard-signature-verifier",
        "SIM",
        ("src/verifier/domains/contracts/sim_shard_signatures.py",),
        "Ed25519 signature verification over selected retained SIM shard rows bound to admitted public keys.",
        "_message rebuilds each domain-separated shard-row message from the selected request and policy, and _verify_signature checks each retained row's canonical 64-byte signature under its selected admitted key with the pinned cryptography backend version. The registration requires every nonempty required shard to carry valid row signatures, and each verified row is a producer-signed per-shard state observation.",
        "This establishes key and message validity for the selected rows only. It does not establish signer origin, key custody, authority, freshness, revocation, anti-equivocation, or actual shard execution.",
        "PROTOCOL",
        "POLICY",
        "SENSOR",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "_evaluate returns a MechanismDecision whose outcome is PASS, FAIL, or UNKNOWN for the selected rows, and recheck_sim_shard_signatures_certificate reproduces it.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-sim-surface-partition-verifier",
        "SIM",
        ("src/verifier/domains/contracts/sim_surface_partition.py",),
        "Exact finite declared state-partition accounting over an exact SIM-4.3 child.",
        "The selected finite map must biject root state variables with retained shard fields, preserve canonical values at every aligned retained time, and attribute each mapped transition to its replayed root transition expression. The carried shard-signature child is decoded from retained bytes and rebuilt through build_sim_shard_signatures_certificate, and only its digests and verdict fields are bound here.",
        "Hidden runtime or physical state, unretained states, nonlinear projections, entropy, action or observation channel completeness, independent signature origin, and the whole runtime surface are not established. Signature verification is delegated to the rebuilt child.",
        "POLICY",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "_evaluate returns the partition MechanismDecision, and recheck_sim_surface_partition_certificate replays it from the retained certificate.",
            ),
        ),
    ),

    # Model reproducibility core and its contracts.  Dependency payloads that a
    # contract only compares for equality are recorded as DOES_NOT_APPLY so that
    # a name such as ``hardware`` or ``environment`` is not promoted to a root.
    ownership_spec(
        "vstd-model-reproducibility-root-checker",
        "MODEL",
        ("src/verifier/domains/model.py",),
        "Model reproducibility specification core for architecture and weight digests, dense inference, metrics, and finite counterexample probes.",
        "evaluate checks the architecture, weight, and dependency digests, rebuilds the dense network from the selected architecture, recomputes per-sample outputs and mean-squared, mean-absolute, or accuracy metrics under a declared tolerance and metric bounds, and checks each challenge condition against the recomputed output.",
        "This is ordered Python binary64 replay only. It establishes no training, deployment, hardware authenticity, accelerator arithmetic, empirical generalization, or whole-model behavioral correctness.",
        "MEASUREMENT",
        "POLICY",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "evaluate raises Refuted for each digest, output, metric, or challenge mismatch and Unavailable for unsupported checks, so this module is the native checking core for the MODEL checks.",
            ),
            root_role_decision(
                "ARCH",
                "APPLIES",
                "The architecture input is digest-checked and passed to network(), which builds the dense model that every inference, evaluation, and challenge check executes.",
            ),
            root_role_decision(
                "DATA",
                "DOES_NOT_APPLY",
                "Evaluation samples arrive as raw inputs checked by digest; the module reads no DATA record and performs no dataset integrity or lineage check.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-model-artifact-byte-commitment",
        "MODEL",
        ("src/verifier/domains/contracts/model_artifact_bytes.py",),
        "Raw architecture and weight byte commitment certificate for one selected MODEL record.",
        "_evaluate requires one exact ARCH operand whose artifact-byte commitment equals the MODEL's, then checks the retained nonempty architecture and weight bytes against exact SHA-256 commitments and byte lengths under explicit policy and limits.",
        "Raw byte commitments only. The mechanism parses no architecture or weight format, establishes no training, checkpoint, or hardware authenticity, makes no artifact-author or ownership claim, and observes no hash-collision resistance.",
        "POLICY",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "_evaluate returns the byte-commitment MechanismDecision, and recheck_model_artifact_bytes_certificate replays it from retained bytes.",
            ),
            root_role_decision(
                "ARCH",
                "DOES_NOT_APPLY",
                "The ARCH operand is consulted only for its raw-byte commitment; the module does not parse, validate, or execute architecture semantics, which the registration excludes.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-model-native-check-certificate",
        "MODEL",
        ("src/verifier/domains/contracts/model_checks.py",),
        "Native MODEL check certificate for artifacts, tensors, inference, evaluation, and challenge probes over one selected model.",
        "_evaluate requires one direct record for each of the ARCH, DATA, BENCH, TRAIN, ENV, and HARDWARE roles, compares the dependency payloads and the selected training record's final checkpoint, rebuilds the dense network for tensor and inference checks, recomputes metrics against the parsed thresholds, and executes the finite challenge probes under the selected policy.",
        "Retained observations establish no actual training, deployment, event observation, hardware authenticity, accelerator or distributed arithmetic, training-gradient correctness, history completeness, or empirical generalization.",
        "MEASUREMENT",
        "POLICY",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "_evaluate returns the selected check's MechanismDecision, and recheck_model_checks_certificate replays it from the retained certificate.",
            ),
            root_role_decision(
                "ARCH",
                "APPLIES",
                "The selected architecture payload is equality-bound to the model input and used to construct the dense network whose outputs every check recomputes.",
            ),
            root_role_decision(
                "BENCH",
                "APPLIES",
                "_evaluate requires the selected BENCH record, equality-binds its DATA and VERIFIER operands, and requires benchmark.payload to equal the MODEL metric, metric_bounds, tolerance, and challenges before executing the finite evaluation and challenge checks.",
            ),
            root_role_decision(
                "TRAIN",
                "DOES_NOT_APPLY",
                "The artifacts objective reads the selected TRAIN payload's architecture and final checkpoint digest only for equality; training execution, checkpoint validity, and history are excluded by the registration.",
            ),
            root_role_decision(
                "DATA",
                "DOES_NOT_APPLY",
                "The DATA payload supplies only the sample list whose digest and event order are compared with the MODEL commitment; no DATA-1.2 certificate is replayed and no dataset integrity or lineage is claimed.",
            ),
            root_role_decision(
                "ENV",
                "DOES_NOT_APPLY",
                "The ENV payload is equality-bound as a dependency value; no pins, installed packages, or runtime environment are verified here.",
            ),
            root_role_decision(
                "HARDWARE",
                "DOES_NOT_APPLY",
                "The HARDWARE payload is equality-bound as a dependency value; no hardware is observed here, and observed hardware belongs to vstd-model-observed-hardware-bracket.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-model-data-citation-verifier",
        "MODEL",
        ("src/verifier/domains/contracts/model_data_citation.py",),
        "MODEL data-operand citation bound to one replayed retained DATA inventory.",
        "_evaluate requires the selected MODEL's exact typed DATA operand and binds that same DATA record's retained shard inventory to the citation, which the registration requires to be independently replayed under an exact selected DATA-1.2 certificate, under explicit policy and limits.",
        "An artifact citation only. It establishes no actual training use of the records, record origin, rights, consent, sampling quality, complete corpus, or disclosure authority.",
        "POLICY",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "_evaluate returns the citation MechanismDecision, and recheck_model_data_certificate replays it from the retained certificate.",
            ),
            root_role_decision(
                "DATA",
                "DOES_NOT_APPLY",
                "The cited DATA record is replayed only as a selected DATA-1.2 child; this MODEL citation owns no dataset integrity, origin, or lineage claim, which its registration excludes.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-model-data-lineage-verifier",
        "MODEL",
        ("src/verifier/domains/contracts/model_data_lineage.py",),
        "Replayed MODEL, TRAIN-to-DATA bridge, and two-view DATA lineage relation.",
        "_evaluate replays the MODEL-3.4 data citation and a TRAIN-to-DATA bridge certificate over identical collection records and one identical DATA-1.2 child selection and bytes, and checks that the TRAIN batches view binds to the MODEL inventory under explicit policy.",
        "Lineage here is a relation between retained certificates, not authoritative history. No historical training, actual DATA consumption, weight derivation, DATA origin, or LEDGER ownership is established.",
        "POLICY",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "_evaluate returns the lineage MechanismDecision, and recheck_model_data_lineage_certificate replays it from retained bytes.",
            ),
            root_role_decision(
                "TRAIN",
                "DOES_NOT_APPLY",
                "TRAIN is consumed through a replayed TRAIN-to-DATA bridge certificate; the module does not execute, validate, or own a training run, and its registration excludes historical training.",
            ),
            root_role_decision(
                "DATA",
                "DOES_NOT_APPLY",
                "Two exact DATA views are compared through their replayed DATA-1.2 selection and bytes; the module asserts no DATA origin, rights, consent, or consumption.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-model-quantization-spec-verifier",
        "MODEL",
        ("src/verifier/domains/contracts/model_quantization.py",),
        "Retained MODEL quantization specification bytes bound to one selected weight artifact.",
        "_evaluate requires the selected MODEL record to occur once in the collection, checks the retained canonical quantization specification bytes against their SHA-256 and length commitments, requires the selected weight artifact commitment, and accepts only the supported exact affine-per-tensor configuration under explicit policy.",
        "This is a specification check only. It performs no weight-tensor parsing, quantizer execution, dequantized-value or accuracy check, hardware requirement check, format-provenance claim, or ownership claim.",
        "POLICY",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "_evaluate returns the specification MechanismDecision, and recheck_model_quantization_certificate replays it from retained bytes.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-model-train-citation-verifier",
        "MODEL",
        ("src/verifier/domains/contracts/model_train_citation.py",),
        "MODEL training-operand citation bound to a replayed MODEL-to-DATA citation.",
        "_evaluate requires one exact typed TRAIN operand whose DATA operand equals the MODEL's exact DATA operand, and replays the same MODEL-to-DATA citation under the selected MODEL-3.4 certificate under explicit policy.",
        "Artifact citation only. It establishes no training execution, checkpoint validity, complete history, weight derivation, proof that the cited DATA was used, or artifact authenticity.",
        "POLICY",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "_evaluate returns the citation MechanismDecision, and recheck_model_train_certificate replays it from the retained certificate.",
            ),
            root_role_decision(
                "TRAIN",
                "DOES_NOT_APPLY",
                "The TRAIN operand is consulted for its DATA operand identity; the module neither executes nor validates a training run, which its registration excludes.",
            ),
            root_role_decision(
                "DATA",
                "DOES_NOT_APPLY",
                "DATA identity is compared exactly and its inventory is reached only through the replayed MODEL-3.4 child; the module owns no dataset integrity or lineage claim.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-model-observed-hardware-bracket",
        "MODEL",
        ("src/verifier/domains/contracts/model_hardware_observation.py",),
        "Observed bounded MODEL execution bracket on one installed Windows CPython processor runtime.",
        "_evaluate requires one selected HARDWARE operand whose declared process backend and machine match the local runtime. For each selected trial, _native_observation launches a fixed native child through _run_windows under a committed-memory Job Object cap and a wall-clock bound and verifies the applied limits and an emptied job before accepting its result; the lower cap must exhaust the workload and the upper cap must complete it with the selected output.",
        "The bracket is local to one Windows processor runtime and one selected workload. It establishes no universal hardware minimum, cross-runtime hardware behavior, storage, network, power, or thermal profile, and no resident-memory claim, since the job limit counts committed bytes.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        "TRANSACTION",
        root_role_decisions=(
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "_evaluate returns the bracket MechanismDecision, and recheck_model_hardware_certificate replays it from retained bytes.",
            ),
            root_role_decision(
                "HARDWARE",
                "APPLIES",
                "The subject is bound to one selected HARDWARE operand, and its declared backend and machine are compared with the local runtime, so the observation is a property of that installed processor runtime.",
            ),
            root_role_decision(
                "HARNESS",
                "DOES_NOT_APPLY",
                "It launches one fixed native child per observation and classifies its single result; it runs no test suite, subject selection, or repeated comparison.",
            ),
        ),
    ),
)


# These digests bind the role audit above to the exact source bytes reviewed.
# A changed file must be re-audited; rebinding an aggregate digest is insufficient.
SOURCE_DIGESTS: dict[str, str] = {
    "src/verifier/domains/contracts/model_artifact_bytes.py": "sha256:aae4dfc64fc34055320127ecbffbfe6a995e20dfac1db2adb5758853d1e5a4c3",
    "src/verifier/domains/contracts/model_checks.py": "sha256:832c411794f580e69626c88a71c0c1b4a451ea87c0429a3ffcad6ca1616c8e03",
    "src/verifier/domains/contracts/model_data_citation.py": "sha256:062b90e5764905e745e996012574631b413cefc96622e33ab1edf2f6f5c18bb2",
    "src/verifier/domains/contracts/model_data_lineage.py": "sha256:eb59369693ce9bcd6f338eacb880580f93b922276619a65179c73b695a7adf4a",
    "src/verifier/domains/contracts/model_hardware_observation.py": "sha256:10b569f2098caf2d89abe2b882b6243275b89ec587630f2f73e583e293e0f97b",
    "src/verifier/domains/contracts/model_quantization.py": "sha256:da17938ca763368bb31046c3d97272fb1ccc3f592804b7f3265f5bbf5080925a",
    "src/verifier/domains/contracts/model_train_citation.py": "sha256:14c25e1ded33ac0a481f02a91478f4402196296f02ac408f1adfad2962c60796",
    "src/verifier/domains/contracts/sim_checker.py": "sha256:8500764157b9af0ebf2643a09a41f0a2755fcb91a30fb525ad6724fefc7da2aa",
    "src/verifier/domains/contracts/sim_dynamics.py": "sha256:72c786f691d39658c464c59da94b6f6e1e2d601543340d4bdb0e53c99c9c256e",
    "src/verifier/domains/contracts/sim_external_law.py": "sha256:1ae09656fdf1405d025145bc79ac7cca30a9f5af67249820b0fbfa7399b90ca5",
    "src/verifier/domains/contracts/sim_fresh_bootstrap.py": "sha256:c1a5c46fffb060b5678009a756280923b370375b828b61d2401ecf75d77d0598",
    "src/verifier/domains/contracts/sim_fresh_worker.py": "sha256:937a96ee1afe6c86616364d561426e0cb3a832f96ea789c489ffae1c5124a015",
    "src/verifier/domains/contracts/sim_internal_core.py": "sha256:ffd2da61c0b889099e2167199653f8336ffd54558a91c3e7212107f5637dbc42",
    "src/verifier/domains/contracts/sim_internal_state.py": "sha256:967163ac95db3df7c2421682e95a4d8938b5e46ce7e870e1a9fdbde707633791",
    "src/verifier/domains/contracts/sim_isolation.py": "sha256:a179957ed9678c885f23a93138fada26ba8568ff11480b3d3dae71aedcd99f4d",
    "src/verifier/domains/contracts/sim_perspective.py": "sha256:adcd447253f6cd6c53a01043539347635ab45a1be33e1443cd76bf67ce4827ad",
    "src/verifier/domains/contracts/sim_resource.py": "sha256:838da6f7729ff4559bd13163ab2bb2586059750ecc113b9037d6746cca3dfde1",
    "src/verifier/domains/contracts/sim_resource_fresh.py": "sha256:d254cd1ea4ad229dd5eafcffe246d4d9afe89f4436eb7dcf979fd3b701c9a4f3",
    "src/verifier/domains/contracts/sim_resource_worker.py": "sha256:357b6aaf79b445a3a8686eb73fa02944b09e3166c71394a5ab6b15720fabc021",
    "src/verifier/domains/contracts/sim_response.py": "sha256:0d9afe7a445286a7a2fe116cdbaeb59ccf7a957c14e5ecb168e521e4c998a4cf",
    "src/verifier/domains/contracts/sim_shard_coverage.py": "sha256:5cb8239f19186181e95a7feaba4aa86a2f69c6459f8e6a24e9689928955c9395",
    "src/verifier/domains/contracts/sim_shard_relations.py": "sha256:47d095097d19584652f8d641596e4294b10774aaba722d19887aaecd34c63cfc",
    "src/verifier/domains/contracts/sim_shard_signatures.py": "sha256:81ece70f90346273c9cacbad1e36a8e30d6d732c770684c7ccd0d24bd3dfabc4",
    "src/verifier/domains/contracts/sim_surface_partition.py": "sha256:d17e50068b7b0960346b270d6c02c79694a851ad2c491bcf8a758d4bb444af9a",
    "src/verifier/domains/model.py": "sha256:82ed1aaa4825001af5e10aaf9cf4edafce5c6998ae044879b3fb0226043c5d99",
    "src/verifier/domains/sim.py": "sha256:f47eb43833c249869416e6b6e88456e3b4712bf53e9e17eff7d7ac6b29d8fc70",
}

# These are source-specific negative findings, not a declaration that all
# unlisted roles are exempt.  An unlisted role remains UNKNOWN.
SOURCE_REFUTED_SPECIALIZATIONS: dict[str, frozenset[str]] = {
    "vstd-sim-external-law-statement": frozenset({"MEASUREMENT", "SENSOR"}),
    "vstd-sim-model-isolation-verifier": frozenset({"SENSOR"}),
    "vstd-sim-internal-state-verifier": frozenset({"SENSOR"}),
    "vstd-sim-internal-hidden-change-enumerator": frozenset({"MEASUREMENT", "SENSOR"}),
    "vstd-sim-dynamics-replay-verifier": frozenset({"MEASUREMENT"}),
    "vstd-sim-action-response-verifier": frozenset({"ACTUATOR", "CONTROLLER"}),
    "vstd-sim-surface-partition-verifier": frozenset({"PROTOCOL", "SENSOR"}),
    "vstd-sim-shard-coverage-verifier": frozenset({"SENSOR"}),
    "vstd-sim-shard-relations-verifier": frozenset({"PROTOCOL"}),
    "vstd-model-data-lineage-verifier": frozenset({"LEDGER"}),
    "vstd-model-artifact-byte-commitment": frozenset({"ASSET"}),
    "vstd-model-quantization-spec-verifier": frozenset({"MEASUREMENT"}),
}


# No operand is bound: this batch establishes source ownership, not exact graph
# membership.  Integration must replace emptiness with real audited IDs.
SIM_MODEL_OWNERSHIP_SPECS: tuple[SemanticOwnershipSpec, ...] = tuple(
    sorted(_OWNERSHIP_DECLARATIONS, key=lambda spec: spec.object_id)
)


def _typed_blocker(
    code: str,
    object_id: str,
    reason: str,
    *,
    operand_role: str | None = None,
    required_kind: str | None = None,
    target_id: str | None = None,
    source_path: str | None = None,
) -> AggregationBlocker:
    return AggregationBlocker(
        code=code,
        object_id=object_id,
        operand_role=operand_role,
        required_kind=required_kind,
        target_id=target_id,
        source_path=source_path,
        reason=reason,
    )


def _cycle_members(graph: Mapping[str, tuple[str, ...]]) -> tuple[str, ...]:
    """Return graph members participating in at least one directed cycle."""
    state: dict[str, int] = {}
    stack: list[str] = []
    members: set[str] = set()

    def visit(node: str) -> None:
        state[node] = 1
        stack.append(node)
        for target in graph.get(node, ()):
            if target not in graph:
                continue
            if state.get(target, 0) == 0:
                visit(target)
            elif state.get(target) == 1:
                members.update(stack[stack.index(target):])
        stack.pop()
        state[node] = 2

    for node in sorted(graph):
        if state.get(node, 0) == 0:
            visit(node)
    return tuple(sorted(members))


def aggregation_blockers(
    specs: Iterable[SemanticOwnershipSpec] | None = None,
    available_specs: Iterable[SemanticOwnershipSpec] = (),
) -> tuple[AggregationBlocker, ...]:
    """Return typed blockers without pretending an unbound slot has a target.

    ``available_specs`` is the independently audited owner inventory supplied by
    an integrator.  A target is accepted only when its exact ID exists and its
    primary kind equals the slot's required kind.  This function does not choose
    targets: choosing by kind alone would erase the source-specific relation.
    """
    selected = SIM_MODEL_OWNERSHIP_SPECS if specs is None else tuple(specs)
    available = tuple(available_specs)
    canonical = {item.object_id: item for item in SIM_MODEL_OWNERSHIP_SPECS}
    all_rows = selected + available
    by_id: dict[str, SemanticOwnershipSpec] = {}
    blockers: list[AggregationBlocker] = []
    for item in all_rows:
        if item.object_id in by_id:
            blockers.append(_typed_blocker(
                "OBJECT_ID_DUPLICATED",
                item.object_id,
                "An exact target ID must identify one audited owner, not multiple rows.",
            ))
        else:
            by_id[item.object_id] = item

    selected_ids = {item.object_id for item in selected}
    for missing in sorted(set(canonical) - selected_ids):
        blockers.append(_typed_blocker(
            "SOURCE_OWNER_MISSING",
            missing,
            "The audited 26-path partition is incomplete; absence is not an exemption.",
        ))

    for item in selected:
        expected = canonical.get(item.object_id)
        if expected is not None:
            if item.owned_paths != expected.owned_paths:
                blockers.append(_typed_blocker(
                    "SOURCE_OWNER_DIFFERS", item.object_id,
                    "The owned source path differs from the audited path assignment.",
                ))
            if item.primary_kind != expected.primary_kind:
                blockers.append(_typed_blocker(
                    "PRIMARY_KIND_DIFFERS", item.object_id,
                    f"The audited primary kind is {expected.primary_kind}, not {item.primary_kind}.",
                ))
            if item.specializations != expected.specializations:
                blockers.append(_typed_blocker(
                    "SOURCE_ROLE_DIFFERS", item.object_id,
                    "Accumulated roles differ from the source-specific audit.",
                ))
            if item.root_role_decisions != expected.root_role_decisions:
                blockers.append(_typed_blocker(
                    "ROOT_ROLE_DECISION_DIFFERS", item.object_id,
                    "Retained-root applicability differs from the source-specific audit.",
                ))

        if item.primary_kind in {"OBJECT", "BOT", "ROBOT", "FINBOT"}:
            code = (
                "OBJECT_FALLBACK_FORBIDDEN"
                if item.primary_kind == "OBJECT"
                else "CONSEQUENCE_PROMOTION_UNSUPPORTED"
            )
            blockers.append(_typed_blocker(
                code, item.object_id,
                "SIM/MODEL source ownership cannot be promoted to a generic, simulated-agent, physical, or financial consequence kind without source evidence.",
            ))
        promoted = set(item.specializations) & {"BOT", "ROBOT", "FINBOT"}
        for role in sorted(promoted):
            blockers.append(_typed_blocker(
                "CONSEQUENCE_PROMOTION_UNSUPPORTED", item.object_id,
                f"The audited source establishes no {role} consequence path.",
                required_kind=role,
            ))
        for role in sorted(
            set(item.specializations) & SOURCE_REFUTED_SPECIALIZATIONS.get(item.object_id, frozenset())
        ):
            blockers.append(_typed_blocker(
                "SOURCE_REFUTATION_VIOLATED", item.object_id,
                f"The owned source was audited as not establishing the {role} specialization.",
                required_kind=role,
            ))

        expected_primary = expected.primary_kind if expected is not None else item.primary_kind
        required = dict(_REQUIRED_OPERAND_KINDS.get(expected_primary, ()))
        operands = dict(item.operands)
        for role in sorted(set(operands) - set(required)):
            blockers.append(_typed_blocker(
                "OPERAND_ROLE_UNKNOWN", item.object_id,
                "The operand role is not part of the audited typed layout.",
                operand_role=role,
            ))
        for role, required_kind in sorted(required.items()):
            targets = operands.get(role, ())
            if not targets:
                blockers.append(_typed_blocker(
                    "OPERAND_UNBOUND", item.object_id,
                    "No exact source-audited target owner is established; UNKNOWN is not exemption.",
                    operand_role=role,
                    required_kind=required_kind,
                ))
                continue
            for target_id in targets:
                lowered = target_id.lower()
                if any(token in lowered for token in ("unresolved", "placeholder", "invented")):
                    blockers.append(_typed_blocker(
                        "OPERAND_TARGET_INVENTED", item.object_id,
                        "A shaped placeholder is not an audited graph object.",
                        operand_role=role,
                        required_kind=required_kind,
                        target_id=target_id,
                    ))
                    continue
                target = by_id.get(target_id)
                if target is None:
                    blockers.append(_typed_blocker(
                        "OPERAND_TARGET_MISSING", item.object_id,
                        "The named target has no independently audited owner row.",
                        operand_role=role,
                        required_kind=required_kind,
                        target_id=target_id,
                    ))
                elif target.primary_kind != required_kind:
                    blockers.append(_typed_blocker(
                        "OPERAND_TARGET_KIND_DIFFERS", item.object_id,
                        f"The target primary kind is {target.primary_kind}; the slot requires {required_kind}.",
                        operand_role=role,
                        required_kind=required_kind,
                        target_id=target_id,
                    ))

    graph = {
        item.object_id: tuple(
            target
            for _role, targets in item.operands
            for target in targets
            if target in by_id
        )
        for item in all_rows
    }
    for object_id in _cycle_members(graph):
        blockers.append(_typed_blocker(
            "OPERAND_CYCLE", object_id,
            "The candidate operand graph contains a directed cycle.",
        ))

    key = lambda item: (
        item.code,
        item.object_id,
        item.operand_role or "",
        item.required_kind or "",
        item.target_id or "",
        item.source_path or "",
        item.reason,
    )
    return tuple(sorted(set(blockers), key=key))


def source_drift_failures(root: str | Path) -> tuple[AggregationBlocker, ...]:
    """Return typed blockers for missing or changed bytes in the 26-path audit."""
    base = Path(root).resolve(strict=True)
    blockers: list[AggregationBlocker] = []
    owner_by_path = {
        path: item.object_id
        for item in SIM_MODEL_OWNERSHIP_SPECS
        for path in item.owned_paths
    }
    for relative, expected in sorted(SOURCE_DIGESTS.items()):
        portable = PurePosixPath(relative)
        target = base.joinpath(*portable.parts).resolve(strict=False)
        if not target.is_relative_to(base) or not target.is_file():
            blockers.append(_typed_blocker(
                "SOURCE_MISSING", owner_by_path[relative],
                "The source path bound to this ownership audit is missing.",
                source_path=relative,
            ))
            continue
        observed = "sha256:" + hashlib.sha256(target.read_bytes()).hexdigest()
        if observed != expected:
            blockers.append(_typed_blocker(
                "SOURCE_DRIFT", owner_by_path[relative],
                f"Expected {expected}; observed {observed}; semantic re-audit is required.",
                source_path=relative,
            ))
    return tuple(blockers)


def aggregation_ready(
    specs: Iterable[SemanticOwnershipSpec] | None = None,
    available_specs: Iterable[SemanticOwnershipSpec] = (),
) -> bool:
    """True only when exact targets satisfy every source and typed-layout gate."""
    return not aggregation_blockers(specs, available_specs)


INTEGRATION_BLOCKERS: tuple[AggregationBlocker, ...] = aggregation_blockers()


__all__ = [
    "AggregationBlocker",
    "INTEGRATION_BLOCKERS",
    "SIM_MODEL_OWNERSHIP_SPECS",
    "SOURCE_DIGESTS",
    "SOURCE_REFUTED_SPECIALIZATIONS",
    "aggregation_blockers",
    "aggregation_ready",
    "source_drift_failures",
]
