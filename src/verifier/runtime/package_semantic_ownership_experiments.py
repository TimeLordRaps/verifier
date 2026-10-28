"""Audited semantic ownership for the repository experiment estate.

Terminology: command-line interface (CLI); JavaScript Object Notation (JSON);
unsatisfiable (UNSAT); Coordinated Universal Time (UTC).

Terminology: Boolean satisfiability problem (SAT); conjunctive normal form
(CNF); language model (LM); Verifier Standard (VSTD).

This partition covers the exact residual ``experiments/**`` files in the
current package-object denominator.  It separates static study records from
the executable verifier-guided SAT benchmark, and separates the benchmark's
MODEL, BENCH, TIME, GRAPH, verifier, filesystem and network consequences.

No owned path is a BOT in a SIM, a ROBOT connected to real-world ACTUATORs, or
a FINBOT making real-money decisions.  The one-shot LM request is bounded by a
HARNESS; it is not evidence of confinement, model correctness or agency.  The
software ACTUATOR and CONTROLLER roles below address process, network and local
file effects only and never assert physical actuation.
"""

from __future__ import annotations

from verifier.runtime.package_semantic_ownership_model import (
    SemanticOwnershipSpec,
    ownership_spec,
    root_role_decision,
)


# Repository-level experiment records are static declarations.  Their study
# status and recorded observations do not become fresh execution evidence just
# because the bytes are present in the current checkout.
_STUDY_RECORD_SPECS: tuple[SemanticOwnershipSpec, ...] = (
    ownership_spec(
        "vstd-experiment-catalog-records",
        "DATA",
        (
            "experiments/INDEX.md",
            "experiments/README.md",
        ),
        "Repository experiment navigation, declared study state and interpretation boundary.",
        "The experiment estate needs an exact catalog owner so generated index membership cannot be mistaken for normative or executable package coverage.",
        "Catalog presence proves no hypothesis, reproduction, publication, current execution or VSTD verdict.",
        "POLICY",
    ),
    ownership_spec(
        "vstd-artifact-first-mechanism-study",
        "POLICY",
        (
            "experiments/artifact_first_mechanisms/README.md",
            "experiments/artifact_first_mechanisms/experiment.json",
            "experiments/artifact_first_mechanisms/reverification/ROUND2_DESIGN_NOTE.md",
        ),
        "Non-normative artifact-first mechanism hypotheses, workflow record and second-round design boundary.",
        "Open TRUST, ROT, RUST and hidden-witness questions require explicit hypotheses, falsification conditions and non-claims rather than inheriting normative status from adjacent VSTD mechanisms.",
        "These files implement none of the open mechanisms, authenticate no observation and do not change the normative architecture or serialized receipt vocabulary.",
        "PROTOCOL",
    ),
    ownership_spec(
        "vstd-github-verdict-neutrality-study-record",
        "DATA",
        ("experiments/github_verdict_neutrality/experiment.json",),
        "Retained bounded study record for verdict-neutral normalized GitHub events.",
        "The completed study records exact platform-event inputs and the rule that platform success has no verification effect, so it must remain distinct from generic documentation and live platform observation.",
        "The checked-in record is not a fresh GitHub observation, authenticated platform history, correctness verdict, publication event or release authority.",
        "POLICY",
        "PROTOCOL",
        root_role_decisions=(
            root_role_decision(
                "RECEIPT",
                "APPLIES",
                "The checked-in experiment JSON preserves bounded observation and workflow-event claims, so receipt obligations remain necessary even though the file is not a structurally typed namespace RECEIPT.",
            ),
        ),
    ),
)


# These checked-in files define and report the benchmark but do not themselves
# run a model, solver or verifier.  Retained result prose and JSON remain
# historical receipts, not a current rerun.
_BENCHMARK_ASSET_SPECS: tuple[SemanticOwnershipSpec, ...] = (
    ownership_spec(
        "vstd-vgsat-package-marker",
        "DATA",
        ("experiments/verifier_guided_sat/verifier_guided_sat/__init__.py",),
        "Inert non-normative experiment package marker.",
        "The marker needs an exact owner so it cannot inherit live MODEL, solver, verifier or effect roles from a directory catch-all.",
        "It performs no benchmark, inference, verification, observation, write, network request, physical action or financial action.",
    ),
    ownership_spec(
        "vstd-vgsat-architecture-documents",
        "ARCH",
        (
            "experiments/verifier_guided_sat/ARCHITECTURE.md",
            "experiments/verifier_guided_sat/README.md",
            "experiments/verifier_guided_sat/VERIFIER_OBJECT_CONTRACT.md",
        ),
        "Verifier-guided SAT dataflow, public layout and experiment-local verifier-object contract.",
        "The benchmark's LM, route, solver, native-verifier and record boundaries need one readable architecture that preserves their distinct evidence and failure semantics.",
        "Architecture and contract prose neither invokes a MODEL nor proves a solver, verifier, endpoint, dependency, benchmark result or VSTD conformance claim.",
        "POLICY",
        "PROTOCOL",
        root_role_decisions=(
            root_role_decision(
                "BENCH",
                "DOES_NOT_APPLY",
                "These files describe the verifier-guided SAT benchmark but do not execute a comparison, bind benchmark data to a verifier, or emit a benchmark result.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-vgsat-study-governance",
        "POLICY",
        (
            "experiments/verifier_guided_sat/CLAIM_BOUNDARY.md",
            "experiments/verifier_guided_sat/PREREGISTRATION.md",
            "experiments/verifier_guided_sat/RESEARCH.md",
            "experiments/verifier_guided_sat/THREAT_MODEL.md",
        ),
        "Preregistered benchmark question, claim boundary, tool research, threat model and negative classifications.",
        "Held-out evaluation and performance claims require frozen precedence, failure handling, non-claims and change rules that cannot be recovered from result bytes alone.",
        "Declared governance does not show that the frozen rules were enforced for an unrecorded run, that a tool is sound, or that a live-model hypothesis was evaluated.",
        "PROTOCOL",
        root_role_decisions=(
            root_role_decision(
                "BENCH",
                "DOES_NOT_APPLY",
                "The claim boundary, preregistration, research notes, and threat model govern a BENCH but neither run nor constitute the benchmark they constrain.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-vgsat-public-result-records",
        "DATA",
        (
            "experiments/verifier_guided_sat/PUBLIC_AUDIT.md",
            "experiments/verifier_guided_sat/PUBLIC_RESULT.md",
            "experiments/verifier_guided_sat/results/baseline.json.gz",
            "experiments/verifier_guided_sat/results/live-blocked.json",
        ),
        "Retained public audit, compressed baseline result, baseline report and fail-closed live-runtime blocker record.",
        "Public claims depend on preserving measured baseline evidence separately from the zero-trial blocked LM result and its explicit UNKNOWN hypotheses.",
        "These historical bytes are not a current rerun, live endpoint observation, model benchmark, solver-hardness proof, independent audit, publication authorization or release evidence.",
        "MEASUREMENT",
        "POLICY",
        root_role_decisions=(
            root_role_decision(
                "BENCH",
                "APPLIES",
                "PUBLIC_RESULT.md and the retained blocked-result envelope make bounded claims about the benchmark denominator and outcomes, so BENCH obligations apply to their interpretation.",
            ),
            root_role_decision(
                "RECEIPT",
                "APPLIES",
                "The selected files are retained evidence records for baseline execution and a zero-trial blocker, so receipt obligations are necessary without pretending they have RECEIPT operand layout.",
            ),
            root_role_decision(
                "TIME",
                "APPLIES",
                "The public audit and result bind dated execution history and timing claims whose units, coordinate, and freshness affect interpretation.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-vgsat-environment-declarations",
        "ENV",
        (
            "experiments/verifier_guided_sat/.gitignore",
            "experiments/verifier_guided_sat/requirements-experiment.txt",
            "experiments/verifier_guided_sat/selected-tools.lock",
        ),
        "Experiment-local generated-file exclusions, dependency pins and selected runtime/tool records.",
        "Reproduction and blocked-runtime interpretation require explicit tool and dependency coordinates without importing them into Verifier's mandatory runtime.",
        "Declarations do not install, authenticate, load or isolate any dependency, MODEL, solver or verifier and do not prove the recorded environment existed for a run.",
        "POLICY",
        "PROTOCOL",
        root_role_decisions=(
            root_role_decision(
                "BENCH",
                "DOES_NOT_APPLY",
                "Dependency pins, tool selections, and ignore rules describe an experiment environment but do not bind DATA to a VERIFIER or perform a benchmark comparison.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-vgsat-vendored-license-policy",
        "POLICY",
        ("experiments/verifier_guided_sat/vendor/algotune/LICENSE",),
        "Retained upstream license terms for the exact vendored verifier source files.",
        "Vendored code needs a separate legal-policy owner so source execution evidence cannot substitute for the governing redistribution terms.",
        "License text does not establish provenance, compliance, authorship, endorsement, source identity, verifier soundness or permission for any unrelated artifact.",
    ),
    ownership_spec(
        "vstd-vgsat-model-prompt-policy",
        "POLICY",
        (
            "experiments/verifier_guided_sat/prompts/arm_b.txt",
            "experiments/verifier_guided_sat/prompts/arm_c.txt",
            "experiments/verifier_guided_sat/prompts/system.txt",
            "experiments/verifier_guided_sat/verifier_guided_sat/prompts.py",
        ),
        "Frozen generic MODEL prompt templates, selected-input rendering and one-request arm contract.",
        "Prompt bytes directly shape the bounded MODEL interaction and held-out comparison, so their scope and freeze policy must remain explicit even though they perform no request themselves.",
        "Rendering text does not execute or confine a MODEL, establish model identity, create an AGENT or BOT, validate output, or support a performance or safety claim.",
        "PROTOCOL",
        root_role_decisions=(
            root_role_decision(
                "BENCH",
                "DOES_NOT_APPLY",
                "The prompt templates are frozen benchmark inputs, not an execution or result of the benchmark itself.",
            ),
            root_role_decision(
                "HARNESS",
                "DOES_NOT_APPLY",
                "Prompt loading and rendering prepare text but do not invoke, bound, retry, or isolate the MODEL execution path.",
            ),
            root_role_decision(
                "MODEL",
                "DOES_NOT_APPLY",
                "Prompt text and its renderer influence a MODEL request but contain no model weights, inference engine, or model execution.",
            ),
        ),
    ),
)


# Data-producing support mechanisms are split by the state they observe and
# mutate.  A timing record is not a freeze ledger, and neither is a fresh result
# unless the corresponding executable path ran at a bound coordinate.
_BENCHMARK_RECORD_SPECS: tuple[SemanticOwnershipSpec, ...] = (
    ownership_spec(
        "vstd-vgsat-artifact-audit",
        "VERIFIER",
        (
            "experiments/verifier_guided_sat/artifact-manifest.json",
            "experiments/verifier_guided_sat/engineering-surface.json",
            "experiments/verifier_guided_sat/verifier_guided_sat/audit.py",
        ),
        "Public-text leakage scan, engineering-surface census and exact experiment-artifact digest manifest materialization.",
        "Distributable experiment boundaries depend on current file acquisition, explicit exclusion policy and deterministic derived records rather than an unchecked directory copy.",
        "The scanner and retained outputs cover only enumerated patterns and files; they are not confidentiality proof, code review, current rerun, publication, release or benchmark validity.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
        "TRANSACTION",
        root_role_decisions=(
            root_role_decision(
                "BENCH",
                "DOES_NOT_APPLY",
                "The audit inventories benchmark artifacts and scans public text, but it neither executes benchmark arms nor compares a bound verifier and dataset.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-vgsat-freeze-ledger",
        "LEDGER",
        (
            "experiments/verifier_guided_sat/freeze-lineage.json",
            "experiments/verifier_guided_sat/freeze-manifest.json",
            "experiments/verifier_guided_sat/verifier_guided_sat/freeze.py",
        ),
        "Pre-held-out file, verifier-contract, solver-configuration and threshold freeze creation, validation and retained lineage.",
        "The benchmark's anti-tuning claim depends on an ordered digest-bound history, explicit authority boundary and mismatch handling rather than a mutable status label.",
        "Local replacement of the freeze file is not append-only, externally witnessed or tamper-proof; retained lineage does not prove no omitted run, current enforcement, model identity or benchmark success.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        "TRANSACTION",
        root_role_decisions=(
            root_role_decision(
                "BENCH",
                "DOES_NOT_APPLY",
                "The freeze ledger constrains later held-out benchmark execution but does not itself run a benchmark trial or compute a benchmark result.",
            ),
            root_role_decision(
                "RECEIPT",
                "APPLIES",
                "freeze-manifest.json and freeze-lineage.json retain digest-bound evidence of the selected files, contracts, solver configuration, thresholds, and lineage.",
            ),
            root_role_decision(
                "TIME",
                "APPLIES",
                "create_freeze records a UTC freeze date and preserves the benchmark timing procedure whose temporal boundary is part of the anti-tuning claim.",
            ),
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "validate_freeze recomputes file, verifier-contract, and solver-configuration digests and returns explicit mismatches fail closed.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-vgsat-instance-corpus",
        "DATA",
        (
            "experiments/verifier_guided_sat/instances/manifest.json",
            "experiments/verifier_guided_sat/verifier_guided_sat/instances.py",
        ),
        "Deterministic 60-instance benchmark corpus materialization, digest binding, loading and role selection.",
        "Development and held-out denominators must be explicit and byte-bound so missing, duplicated or mutated instances cannot silently change the benchmark question.",
        "Seeded materialization and digest checks do not establish distribution representativeness, hidden-answer absence, native-verifier soundness, independent selection or current execution.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
        "TRANSACTION",
        root_role_decisions=(
            root_role_decision(
                "BENCH",
                "DOES_NOT_APPLY",
                "The manifest and loader own the benchmark DATA denominator but perform no solver/verifier comparison and therefore are not themselves a BENCH.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-vgsat-metric-contract",
        "MEASUREMENT",
        (
            "experiments/verifier_guided_sat/metrics.schema.json",
            "experiments/verifier_guided_sat/verifier_guided_sat/metrics.py",
        ),
        "Trial-metric schema and correctness-first aggregation across arms and domains.",
        "Performance interpretation requires explicit units, missing-value behavior, domain grouping and aggregation rules instead of treating every available number as comparable evidence.",
        "Schema-valid or aggregated telemetry does not prove measurement accuracy, clock comparability, causal speedup, solver difficulty, accepted-candidate correctness or a complete trial denominator.",
        "POLICY",
        "PROTOCOL",
        root_role_decisions=(
            root_role_decision(
                "BENCH",
                "DOES_NOT_APPLY",
                "The metric schema and aggregator interpret supplied trial rows but do not execute the verifier/data comparison that produces those rows.",
            ),
            root_role_decision(
                "TIME",
                "APPLIES",
                "The schema and aggregator define nanosecond timing fields, component medians, missing-value behavior, and end-to-end temporal summaries.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-vgsat-noise-measurement",
        "MEASUREMENT",
        (
            "experiments/verifier_guided_sat/development-noise.json",
            "experiments/verifier_guided_sat/verifier_guided_sat/noise.py",
        ),
        "Repeated development-domain timing observations and preregistered aggregate-improvement threshold derivation.",
        "A speed hypothesis needs an explicit clock, repeated sample policy and uncertainty threshold rather than a single unqualified elapsed duration.",
        "The retained machine-local sample is not fresh, cross-machine calibration, held-out evidence, a live-load estimate or proof that future timing variance remains inside the threshold.",
        "ACTUATOR",
        "POLICY",
        "SENSOR",
        root_role_decisions=(
            root_role_decision(
                "BENCH",
                "APPLIES",
                "measure_development_noise repeatedly executes the Arm-A verifier/data path across the development corpus to establish a benchmark variability threshold.",
            ),
            root_role_decision(
                "HARNESS",
                "APPLIES",
                "The measurement loop selects instances, loads their verifier, repeats bounded trials, and aggregates their observations under one fixed procedure.",
            ),
            root_role_decision(
                "TIME",
                "APPLIES",
                "The mechanism samples perf_counter_ns, derives per-instance medians and relative median absolute deviation, and emits an explicit timing threshold.",
            ),
            root_role_decision(
                "VERIFIER",
                "DOES_NOT_APPLY",
                "The noise procedure invokes existing native verifiers through the trial harness but adds no independent acceptance predicate or verifier verdict of its own.",
            ),
        ),
    ),
)


# Executable sources are partitioned at their trust and effect boundaries.  In
# particular, MODEL transport, SAT execution and native-verifier acceptance are
# independent evidence classes even when the trial harness composes them.
_BENCHMARK_EXECUTION_SPECS: tuple[SemanticOwnershipSpec, ...] = (
    ownership_spec(
        "vstd-vgsat-result-classification-policy",
        "POLICY",
        ("experiments/verifier_guided_sat/verifier_guided_sat/analysis.py",),
        "Preregistered live-trial coverage, correctness, solver-work and end-to-end result classification.",
        "The benchmark verdict depends on closed denominator, duplicate, failure, work-comparison and threshold precedence that must remain separate from a caller-supplied status string.",
        "Classification over supplied trials does not authenticate them, repair missing telemetry, prove causality or convert blocked, rejected, route-UNSAT or MODEL-failure evidence into success.",
        "MEASUREMENT",
        root_role_decisions=(
            root_role_decision(
                "BENCH",
                "APPLIES",
                "classify_result closes the expected arm/domain/instance denominator and computes the benchmark's bounded outcome from accepted trials and comparisons.",
            ),
            root_role_decision(
                "TIME",
                "APPLIES",
                "The classifier compares matched total_time_to_outcome_ns values and applies the preregistered end-to-end improvement threshold.",
            ),
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "The classifier rejects incomplete, duplicated, false-acceptance, unknown, or threshold-insufficient evidence before it can support the success classification.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-vgsat-baseline-encoding-policy",
        "POLICY",
        ("experiments/verifier_guided_sat/verifier_guided_sat/baselines.py",),
        "Complete bounded Arm-A route encodings for stable matching, graph isomorphism and integer factorization.",
        "A comparison baseline needs independently justified domain-complete encodings within the selected generator bounds rather than using a held-out MODEL proposal as its own control.",
        "Route construction does not execute SAT, prove an encoding theorem, establish native-verifier soundness or generalize beyond the three bounded generators.",
        root_role_decisions=(
            root_role_decision(
                "BENCH",
                "DOES_NOT_APPLY",
                "canonical_route supplies one input policy for Arm A but does not execute or compare any benchmark trial.",
            ),
            root_role_decision(
                "HARNESS",
                "DOES_NOT_APPLY",
                "The module constructs deterministic routes but does not orchestrate their solver or native-verifier execution.",
            ),
            root_role_decision(
                "VERIFIER",
                "DOES_NOT_APPLY",
                "The baseline encoders emit route declarations and contain no acceptance predicate for a candidate or result envelope.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-vgsat-benchmark-controller",
        "BENCH",
        ("experiments/verifier_guided_sat/verifier_guided_sat/benchmark.py",),
        "Mode-selected corpus, freeze, MODEL, harness, verifier, metric and result-file orchestration.",
        "A benchmark controller chooses consequential execution order, one-request stop conditions and output publication, so model transport, current observations and partial failure cannot be hidden behind a CLI success code.",
        "The controller is unsandboxed and writes local files; it does not authorize an endpoint, prove MODEL confinement or identity, create a BOT, control physical hardware, transact money, publish results or establish any success classification without validated trial evidence.",
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        "TRANSACTION",
        operands=(
            ("data", ("vstd-vgsat-instance-corpus",)),
            ("verifier", ("vstd-vgsat-native-verifier-adapters",)),
        ),
        root_role_decisions=(
            root_role_decision(
                "HARNESS",
                "APPLIES",
                "benchmark.main selects modes, corpus rows, prompts, MODEL transport, trial execution, aggregation, validation, and bounded stop behavior.",
            ),
            root_role_decision(
                "MODEL",
                "DOES_NOT_APPLY",
                "The controller can instantiate and call an environment-selected backend, but it contains no MODEL weights or inference implementation and explicitly withholds model identity.",
            ),
            root_role_decision(
                "RECEIPT",
                "APPLIES",
                "The controller materializes baseline and live result envelopes to a selected local output only after composing their trial records and aggregate fields.",
            ),
            root_role_decision(
                "TIME",
                "APPLIES",
                "The controller captures UTC start/completion coordinates and perf_counter_ns preparation and end-to-end durations for the result envelope.",
            ),
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "Its validate mode invokes fail-closed result replay and converts any reported validation error into a nonzero command outcome.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-vgsat-canonical-artifact-io",
        "TRANSACTION",
        ("experiments/verifier_guided_sat/verifier_guided_sat/canonical.py",),
        "Deterministic JSON serialization, hashing and plain or gzip local artifact reads and writes.",
        "Digest binding and artifact publication require exact byte, path, replacement and decoding semantics rather than generic data ownership.",
        "Writes are neither exclusive nor atomic or fsync-durable, digests authenticate no source, reads trust the selected path, and no physical or financial effect is claimed.",
        "ACTUATOR",
        "MEASUREMENT",
        "SENSOR",
    ),
    ownership_spec(
        "vstd-vgsat-verifier-contract-protocol",
        "PROTOCOL",
        ("experiments/verifier_guided_sat/verifier_guided_sat/contracts.py",),
        "Experiment-local verifier contract, native verdict, route verdict and observation records.",
        "Native-verifier invocation and evidence exchange need explicit result semantics, trust roots, bounds and canonical representation distinct from a VSTD wire receipt.",
        "Typed records execute nothing, establish no verifier soundness or authority and do not turn ERROR, UNKNOWN, rejection or route-local UNSAT into a domain verdict.",
        "POLICY",
        root_role_decisions=(
            root_role_decision(
                "BENCH",
                "DOES_NOT_APPLY",
                "The dataclasses specify experiment-local interfaces and verdict vocabulary but perform no benchmark execution or comparison.",
            ),
            root_role_decision(
                "VERIFIER",
                "DOES_NOT_APPLY",
                "VerifierObjectContract and NativeVerdict are inert typed records; no predicate or replay mechanism executes in this module.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-vgsat-native-verifier-adapters",
        "VERIFIER",
        (
            "experiments/verifier_guided_sat/AlgoTuneTasks/__init__.py",
            "experiments/verifier_guided_sat/AlgoTuneTasks/base.py",
            "experiments/verifier_guided_sat/vendor/algotune/graph_isomorphism/graph_isomorphism.py",
            "experiments/verifier_guided_sat/vendor/algotune/integer_factorization/integer_factorization.py",
            "experiments/verifier_guided_sat/vendor/algotune/stable_matching/stable_matching.py",
            "experiments/verifier_guided_sat/verifier_guided_sat/external_verifiers.py",
        ),
        "Exact vendored AlgoTune predicates, source-visible compatibility namespace, candidate invocation and bounded observation wrapper.",
        "Accepted-candidate evidence depends on the exact dynamically loaded predicate, instance and candidate bytes, diagnostic capture and explicit exception handling.",
        "In-process execution has no hard timeout or memory sandbox; acceptance is bounded to the implemented predicate and proves neither predicate soundness, global witness existence, domain specification equivalence nor independent authority.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        root_role_decisions=(
            root_role_decision(
                "BENCH",
                "DOES_NOT_APPLY",
                "These adapters supply the benchmark's native acceptance predicates but do not own the corpus, arm comparison, or aggregate benchmark conclusion.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-vgsat-trial-harness",
        "HARNESS",
        ("experiments/verifier_guided_sat/verifier_guided_sat/harness.py",),
        "Bounded Arm-A/B/C MODEL proposal, route compilation, SAT completion, native verification, evidence binding and independent replay harness.",
        "The harness composes distinct MODEL, verifier and solver surfaces under resource and one-request rules, so execution authority, missing evidence and failure stages must accumulate rather than collapse into one status.",
        "The in-process harness is not a security sandbox or MODEL confinement proof, creates no AGENT or BOT, has no real-world actuator or financial authority, and establishes only an exact accepted candidate when all bound checks succeed.",
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        "TRANSACTION",
        root_role_decisions=(
            root_role_decision(
                "BENCH",
                "APPLIES",
                "VerifierGuidedHarness executes Arm A, B, or C for one bound instance and produces the trial metrics consumed by the benchmark comparison.",
            ),
            root_role_decision(
                "GRAPH",
                "APPLIES",
                "Each completed trial asks build_record to bind its causal artifact stages into a provenance hypergraph and rejects graph-validation failures.",
            ),
            root_role_decision(
                "MODEL",
                "DOES_NOT_APPLY",
                "The harness accepts an LmBackend capability and records its observation but contains neither model weights nor an inference engine and does not establish model identity.",
            ),
            root_role_decision(
                "RECEIPT",
                "APPLIES",
                "The harness creates and revalidates a digest-bound experiment record for every success and failure path before returning the Trial.",
            ),
            root_role_decision(
                "TIME",
                "APPLIES",
                "The harness observes preparation, MODEL, solver, native-verifier, record-creation, reverification, and total-system durations with perf_counter_ns.",
            ),
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "The harness invokes the native predicate and two record validators and exposes validation disagreement as false_acceptance rather than silently accepting it.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-vgsat-independent-record-validator",
        "VERIFIER",
        ("experiments/verifier_guided_sat/verifier_guided_sat/independent_validation.py",),
        "Separately implemented record rehash, graph validation, SAT replay, candidate decoding and native-verdict replay.",
        "Producer and consumer agreement is useful only when the consumer avoids the producer's canonicalizer, compiler, binding and solver-adapter code and preserves replay failures explicitly.",
        "The consumer still shares the selected SAT binary and native verifier, runs in process without hostile isolation, and proves neither implementation independence in general nor semantic truth beyond its exact checks.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
        root_role_decisions=(
            root_role_decision(
                "BENCH",
                "DOES_NOT_APPLY",
                "The independent consumer replays one supplied benchmark record but does not select the corpus, execute benchmark arms, or classify aggregate results.",
            ),
            root_role_decision(
                "GRAPH",
                "APPLIES",
                "_validate_graph independently checks artifact and transformation arrays, payload bindings, ports, references, sizes, digests, and claim statuses.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-vgsat-model-endpoint-harness",
        "HARNESS",
        ("experiments/verifier_guided_sat/verifier_guided_sat/lm_backend.py",),
        "Environment-configured one-shot OpenAI-compatible MODEL request, response parsing and usage/timing observation.",
        "A real MODEL boundary crosses credential, endpoint, request, timeout, response-shape and telemetry semantics that static prompts or fixture completions cannot discharge.",
        "The unsandboxed client neither identifies nor confines the MODEL, proves response truth or determinism, creates an AGENT or BOT, controls physical hardware, makes financial decisions, retries requests or establishes a completed benchmark trial.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        "TRANSACTION",
        root_role_decisions=(
            root_role_decision(
                "BENCH",
                "DOES_NOT_APPLY",
                "The client provides MODEL transport for benchmark arms but neither selects instances nor executes solver/verifier comparisons or aggregates outcomes.",
            ),
            root_role_decision(
                "MODEL",
                "DOES_NOT_APPLY",
                "OpenAICompatibleBackend sends requests to a separately configured endpoint; it is not the remote model, and its public configuration withholds model identity.",
            ),
            root_role_decision(
                "TIME",
                "APPLIES",
                "complete_json measures request latency with perf_counter_ns on both successful and failed transport paths.",
            ),
            root_role_decision(
                "TOKEN",
                "APPLIES",
                "LmObservation preserves separately typed prompt-token and completion-token counts when the endpoint returns integer usage telemetry.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-vgsat-reserve-verifiers",
        "VERIFIER",
        ("experiments/verifier_guided_sat/verifier_guided_sat/reserve_verifiers.py",),
        "Predeclared alternate stable-matching, graph-isomorphism and factorization verifier adapters.",
        "Reserve predicates need separate source and dependency boundaries so post-result selection or agreement cannot be mistaken for independent proof.",
        "Reserve agreement is corroboration only; it proves neither independence, external specification equivalence, primary-verifier soundness nor a benchmark result, and the selected functions have no hard process isolation.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
        root_role_decisions=(
            root_role_decision(
                "BENCH",
                "DOES_NOT_APPLY",
                "The reserve adapters compute corroborating candidate verdicts but do not own benchmark data selection, arm execution, comparison, or aggregate classification.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-vgsat-result-validator",
        "VERIFIER",
        ("experiments/verifier_guided_sat/verifier_guided_sat/result_validator.py",),
        "Fail-closed schema, digest, replay, metric, freeze and classifier validation for blocked and completed result envelopes.",
        "A stored status is admissible only when its trial denominator, bound records, telemetry, aggregate and preregistered classification recompute from current selected evidence.",
        "Successful validation is bounded to the selected files and shared solver/native-verifier trust roots; it is not an independent audit, MODEL rerun, endpoint evidence, scientific replication or VSTD package conformance.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        root_role_decisions=(
            root_role_decision(
                "BENCH",
                "APPLIES",
                "validate_result enforces the benchmark result status, trial denominator, recomputed aggregate, false-acceptance, and blocked-runtime rules that govern admissibility.",
            ),
            root_role_decision(
                "RECEIPT",
                "APPLIES",
                "The validator replays every bound trial record and checks that its metrics, timings, token observations, and artifact manifest agree with retained evidence.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-vgsat-route-compiler",
        "HARNESS",
        ("experiments/verifier_guided_sat/verifier_guided_sat/route.py",),
        "Closed bounded finite-domain route validation, deterministic one-hot CNF compilation and model decoding.",
        "MODEL-proposed routes need strict field, size, constraint and decoder policy before they can reach the SAT backend or native verifier.",
        "Compilation does not solve the formula, establish domain completeness or global UNSAT, validate a decoded candidate, prove the encoding correct for untested routes or make the proposing MODEL safe.",
        "POLICY",
        root_role_decisions=(
            root_role_decision(
                "BENCH",
                "DOES_NOT_APPLY",
                "Route compilation is one bounded preprocessing stage and does not execute or aggregate a benchmark trial.",
            ),
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "compile_route rejects unknown keys, malformed domains, unsupported constraints, oversized formulas, and invalid decoder bindings before deterministic CNF emission.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-vgsat-sat-backend",
        "VERIFIER",
        ("experiments/verifier_guided_sat/verifier_guided_sat/sat_backend.py",),
        "Pinned CaDiCaL invocation, conflict-budget handling, SAT witness decoding and solver telemetry capture.",
        "SAT, route-UNSAT and resource-bounded UNKNOWN outcomes depend on exact engine configuration, formula, limits and observations rather than a generic success boolean.",
        "The in-process binding has no hostile sandbox or independent UNSAT certificate; route-local UNSAT is not domain UNSAT, telemetry is machine-local, and a decoded candidate requires separate native verification.",
        "ACTUATOR",
        "CONTROLLER",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
        root_role_decisions=(
            root_role_decision(
                "BENCH",
                "DOES_NOT_APPLY",
                "CadicalBackend solves one supplied compiled route and emits telemetry but does not select benchmark data, compare arms, or classify results.",
            ),
            root_role_decision(
                "TIME",
                "APPLIES",
                "The backend measures each solver invocation with perf_counter_ns and binds elapsed_ns to SAT, UNSAT, UNKNOWN, and error observations.",
            ),
        ),
    ),
    ownership_spec(
        "vstd-vgsat-provenance-record-binding",
        "VERIFIER",
        ("experiments/verifier_guided_sat/verifier_guided_sat/vstd_binding.py",),
        "Non-normative experiment record, artifact-payload provenance graph, bounded claim status and producer-side replay validation.",
        "Instance, MODEL observation, route, formula, solver, candidate and native verdict need exact digest and causal-stage binding so one artifact cannot be transplanted into another trial.",
        "The record is not a new VSTD wire receipt, durable ledger, independent witness or proof of native-verifier soundness; graph VALID authenticates stored bytes only and every unsuccessful route remains UNKNOWN about the domain.",
        "ACTUATOR",
        "LEDGER",
        "MEASUREMENT",
        "POLICY",
        "SENSOR",
        root_role_decisions=(
            root_role_decision(
                "BENCH",
                "DOES_NOT_APPLY",
                "The binding module serializes and replays one trial record but does not execute the benchmark denominator or compare its arms.",
            ),
            root_role_decision(
                "EVENT",
                "APPLIES",
                "_build_graph records ordered workload-execution and evaluation transformations that connect each causal stage of the observed trial.",
            ),
            root_role_decision(
                "GRAPH",
                "APPLIES",
                "The module builds a ProvenanceHypergraph, binds every artifact payload, checks structure and acyclicity, and rejects unknown graph references.",
            ),
            root_role_decision(
                "RECEIPT",
                "APPLIES",
                "build_record emits a digest-bound evidence record and validate_record replays it, so receipt obligations remain applicable despite the explicit non-normative wire format.",
            ),
            root_role_decision(
                "TIME",
                "APPLIES",
                "The stable payload binds named nanosecond timings for MODEL, harness, SAT, native verification, record creation, reverification, and total execution.",
            ),
        ),
    ),
)


# The tests exercise model fixtures, solver/native execution and retained
# records, but deliberately do not contact a real MODEL endpoint.  Their owner
# therefore carries the tested consequence roles while denying fresh live-model
# or external-world evidence.
_BENCHMARK_TEST_SPECS: tuple[SemanticOwnershipSpec, ...] = (
    ownership_spec(
        "vstd-vgsat-regression-harness",
        "HARNESS",
        (
            "experiments/verifier_guided_sat/tests/conftest.py",
            "experiments/verifier_guided_sat/tests/test_analysis.py",
            "experiments/verifier_guided_sat/tests/test_freeze.py",
            "experiments/verifier_guided_sat/tests/test_independent_validation.py",
            "experiments/verifier_guided_sat/tests/test_lm_boundary.py",
            "experiments/verifier_guided_sat/tests/test_manifests_and_audit.py",
            "experiments/verifier_guided_sat/tests/test_result_validator.py",
            "experiments/verifier_guided_sat/tests/test_route.py",
            "experiments/verifier_guided_sat/tests/test_verifiers.py",
            "experiments/verifier_guided_sat/tests/test_vstd_binding.py",
        ),
        "Adversarial benchmark classification, freeze, MODEL-boundary, route, solver, verifier, record and audit regression harness.",
        "Failure cases must demonstrate that mutations, malformed proposals, route-local UNSAT, missing MODEL runtime and false status promotion are rejected for the intended reasons.",
        "Tests use a fixture LM and bounded local dependencies; passing them is not a real MODEL completion, full adversarial coverage, endpoint or hardware observation, scientific replication, current retained-result replay or package conformance.",
        "ACTUATOR",
        "MEASUREMENT",
        "POLICY",
        "PROTOCOL",
        "SENSOR",
        root_role_decisions=(
            root_role_decision(
                "BENCH",
                "APPLIES",
                "The suite executes bounded Arm-A trials and recomputes benchmark classifications, aggregates, freeze state, and failure precedence against controlled fixtures.",
            ),
            root_role_decision(
                "GRAPH",
                "APPLIES",
                "The tests build current provenance graphs, mutate their bound artifacts and transformations, and require graph replay to reject the intended defects.",
            ),
            root_role_decision(
                "MODEL",
                "DOES_NOT_APPLY",
                "FixtureLm returns authored dictionaries or errors and no test contacts a live inference endpoint or supplies MODEL weights or identity evidence.",
            ),
            root_role_decision(
                "RECEIPT",
                "APPLIES",
                "Fresh trial records are constructed, mutated, independently replayed, and required to fail closed when their bound evidence changes.",
            ),
            root_role_decision(
                "TIME",
                "APPLIES",
                "The suite produces and checks fresh nanosecond timing records, including request failures, creation/reverification probes, and aggregate timing fields.",
            ),
            root_role_decision(
                "VERIFIER",
                "APPLIES",
                "Assertions exercise independent replay, native predicates, result validation, schema rejection, and mutation failures as executable verification checks.",
            ),
        ),
    ),
)


EXPERIMENT_OWNERSHIP_SPECS: tuple[SemanticOwnershipSpec, ...] = tuple(
    sorted(
        (
            *_STUDY_RECORD_SPECS,
            *_BENCHMARK_ASSET_SPECS,
            *_BENCHMARK_RECORD_SPECS,
            *_BENCHMARK_EXECUTION_SPECS,
            *_BENCHMARK_TEST_SPECS,
        ),
        key=lambda item: item.object_id,
    )
)


__all__ = ["EXPERIMENT_OWNERSHIP_SPECS", "SemanticOwnershipSpec"]
