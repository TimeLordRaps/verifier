"""Verifier Standard (VSTD) tier-5 domain adaptation: mainstay formats as adapters.

Tier 5 was empty on every object, and the reason was not that the tier is hard.
It is that the other four tiers describe an object in this standard's own terms,
while tier 5 has to describe it in the terms the domain already uses. There is
no adapter to write until the mainstay representation is named.

This module names them. For each object it records the file formats, wire
protocols and runtime interfaces that the domain actually publishes in, and for
each one a **meta-surface**: the entity kinds the format carries, the relations
it holds between them, and the coordinates of this standard it can express. The
adapter is then format-independent -- binding, mapping, round trip, residual --
because every mainstay has been reduced to the same shape first.

Reverse-engineering all of them produced one finding worth stating up front:
**mainstay formats encode facets and dynamics, and almost never encode statics
or closure.** A Parquet footer holds column statistics but not the sampling
frame; an Open Neural Network Exchange (ONNX) graph holds operators but not the
conditions under which the model may be refuted. The residual is therefore not
an oversight in any of these formats -- it is the part of an object that only a
verification standard was ever going to carry, and tier 5 computes it rather
than accepting a declaration of it.

Secure Hash Algorithm 256-bit (SHA-256); JavaScript Object Notation (JSON);
JSON Lines (JSONL); artificial intelligence (AI); Extensible Markup Language (XML);
Hypertext Transfer Protocol (HTTP); Software Package Data Exchange (SPDX);
Stable High-Level Optimizer (StableHLO); YAML Ain't Markup Language (YAML).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from verifier.core.certificate import canonical_digest
from verifier.core.profile_obligations import DOMAIN_BY_ID, DOMAIN_OBLIGATIONS
from .common import Budget, Refuted, Unavailable, need, obj, same, seq, text

#: Every adaptation check is exposed as ``mainstay:<name>``, disjoint from both
#: the behavioural adapter checks and the tier-3 statics mechanism.
PREFIX = "mainstay:"


@dataclass(frozen=True)
class Mainstay:
    """One domain representation, reduced to a checkable meta-surface."""

    format_id: str
    display: str
    carrier: str                      # the artifact the format is actually carried in
    entities: tuple[str, ...]         # the meta-surface's nodes
    relations: tuple[str, ...]        # "<subject> <relation> <object>" over those nodes
    expresses: tuple[str, ...]        # coordinates of tiers 1-4 the format can carry

    def residual(self) -> tuple[str, ...]:
        """What this object carries that the format structurally cannot."""
        return tuple(o.id for o in DOMAIN_OBLIGATIONS
                     if o.object_name == self.format_owner and o.profile < 5
                     and o.id not in self.expresses)

    @property
    def format_owner(self) -> str:
        return DOMAIN_BY_ID[self.expresses[0]].object_name


def _m(*args: Any) -> Mainstay:
    return Mainstay(*args)


MAINSTAYS: dict[str, tuple[Mainstay, ...]] = {
    "DATA": (
        _m("apache-parquet", "Apache Parquet", "file footer FileMetaData",
           ("file", "row-group", "column-chunk", "page", "column-statistics"),
           ("file contains row-group", "row-group contains column-chunk",
            "column-chunk contains page", "column-chunk summarizes column-statistics",
            "schema types leaf-column"),
           ("DATA-1.1", "DATA-1.2", "DATA-1.4", "DATA-2.1", "DATA-3.4")),
        _m("apache-arrow-ipc", "Apache Arrow inter-process communication", "stream or file format",
           ("schema", "record-batch", "buffer", "dictionary"),
           ("schema types field", "record-batch carries buffer",
            "dictionary encodes field"),
           ("DATA-1.1", "DATA-1.2", "DATA-2.1")),
        _m("webdataset", "WebDataset tar shards", "POSIX tar shard sequence",
           ("shard", "sample", "member"),
           ("shard contains sample", "sample groups member by extension",
            "shard sequence orders sample"),
           ("DATA-1.1", "DATA-1.3", "DATA-2.2")),
        _m("mlcommons-croissant", "MLCommons Croissant", "JSON-LD metadata record",
           ("Dataset", "RecordSet", "Field", "FileObject", "FileSet", "Distribution"),
           ("Dataset declares RecordSet", "RecordSet types Field",
            "Field extracts-from FileObject", "Dataset licenses Distribution",
            "Dataset provenance-of FileSet"),
           ("DATA-1.1", "DATA-1.2", "DATA-1.5", "DATA-2.1", "DATA-2.5",
            "DATA-3.1", "DATA-3.5", "DATA-4.1")),
        _m("huggingface-datasets", "Hugging Face datasets", "dataset_infos.json and card front matter",
           ("DatasetInfo", "Features", "Split", "DownloadChecksum"),
           ("DatasetInfo declares Features", "DatasetInfo partitions Split",
            "DatasetInfo pins DownloadChecksum"),
           ("DATA-1.1", "DATA-1.2", "DATA-1.6", "DATA-2.1", "DATA-4.3")),
        _m("apache-iceberg", "Apache Iceberg table format", "metadata.json, manifest lists and manifests",
           ("table", "snapshot", "manifest", "data-file", "partition-spec"),
           ("table versions snapshot", "snapshot lists manifest",
            "manifest tracks data-file", "partition-spec partitions data-file",
            "snapshot parent-of snapshot"),
           ("DATA-1.1", "DATA-1.4", "DATA-2.1", "DATA-2.3", "DATA-2.4")),
    ),
    "ENV": (
        _m("oci-image", "Open Container Initiative image", "image index, manifest and config descriptors",
           ("index", "manifest", "config", "layer", "annotation"),
           ("index selects manifest by platform", "manifest references config",
            "manifest orders layer", "layer digests content",
            "annotation labels manifest"),
           ("ENV-1.1", "ENV-1.2", "ENV-1.4", "ENV-2.1")),
        _m("nix-derivation", "Nix derivation", ".drv store object",
           ("derivation", "input-derivation", "input-source", "output-path", "builder", "environment"),
           ("derivation depends-on input-derivation", "derivation reads input-source",
            "derivation produces output-path", "derivation runs builder",
            "environment parameterizes builder", "output-path hashes closure"),
           ("ENV-1.1", "ENV-1.2", "ENV-1.3", "ENV-1.5", "ENV-2.1", "ENV-2.2", "ENV-4.1")),
        _m("lockfile", "Resolved dependency lockfile", "uv.lock, poetry.lock or hashed requirements",
           ("package", "version", "artifact-hash", "marker", "resolution"),
           ("resolution pins package", "package fixes version",
            "package digests artifact-hash", "marker conditions package"),
           ("ENV-1.1", "ENV-1.2", "ENV-2.1")),
        _m("sbom", "Software bill of materials", "SPDX or CycloneDX document",
           ("component", "relationship", "licence", "supplier"),
           ("component depends-on component", "component declares licence",
            "supplier ships component", "relationship types component pair"),
           ("ENV-1.1", "ENV-1.6", "ENV-2.1", "ENV-4.2")),
        _m("in-toto-attestation", "in-toto attestation", "DSSE envelope over a predicate",
           ("statement", "subject", "predicate", "builder", "material", "byproduct"),
           ("statement binds subject", "statement carries predicate",
            "predicate names builder", "predicate consumes material",
            "predicate emits byproduct"),
           ("ENV-1.1", "ENV-2.2", "ENV-4.1", "ENV-4.2", "ENV-4.3")),
    ),
    "BENCH": (
        _m("lm-evaluation-harness", "EleutherAI language model evaluation harness", "task YAML",
           ("task", "dataset-reference", "document-template", "metric", "filter", "fewshot-context"),
           ("task reads dataset-reference", "document-template renders task item",
            "task scores-with metric", "filter post-processes response",
            "fewshot-context conditions task"),
           ("BENCH-1.1", "BENCH-1.2", "BENCH-1.4", "BENCH-2.1", "BENCH-2.3")),
        _m("helm", "Stanford Holistic Evaluation of Language Models", "run specification records",
           ("RunSpec", "Scenario", "Adapter", "Metric", "Instance", "Reference"),
           ("RunSpec selects Scenario", "Scenario enumerates Instance",
            "Instance carries Reference", "RunSpec adapts-with Adapter",
            "RunSpec measures Metric"),
           ("BENCH-1.1", "BENCH-1.2", "BENCH-1.3", "BENCH-2.1", "BENCH-2.4", "BENCH-3.2")),
        _m("bigbench", "BIG-bench task", "task.json or programmatic task",
           ("task", "example", "metric", "keyword"),
           ("task enumerates example", "example pairs input and target",
            "task scores-with metric", "keyword classifies task"),
           ("BENCH-1.1", "BENCH-1.2", "BENCH-2.1")),
        _m("swe-bench", "SWE-bench instance record", "instance JSONL",
           ("instance", "repository", "base-commit", "patch", "test-patch", "test-status-set"),
           ("instance pins repository at base-commit", "instance carries patch",
            "test-patch defines test-status-set", "test-status-set oracles instance"),
           ("BENCH-1.1", "BENCH-1.2", "BENCH-1.5", "BENCH-2.1", "BENCH-2.2", "BENCH-4.1")),
        _m("mlperf", "MLPerf result log", "result summary and detail logs",
           ("benchmark", "scenario", "division", "system", "result", "constraint"),
           ("benchmark runs-under scenario", "division constrains system",
            "system produces result", "constraint bounds result"),
           ("BENCH-1.1", "BENCH-2.1", "BENCH-4.2", "BENCH-4.3")),
    ),
    "TRAIN": (
        _m("pytorch-training-loop", "PyTorch optimizer and module state", "state_dict objects",
           ("module", "parameter", "optimizer", "param-group", "optimizer-state", "scheduler"),
           ("module owns parameter", "optimizer updates param-group",
            "param-group contains parameter", "optimizer-state accumulates per parameter",
            "scheduler drives param-group"),
           ("TRAIN-1.1", "TRAIN-1.2", "TRAIN-2.1", "TRAIN-2.2")),
        _m("huggingface-trainer", "Hugging Face Trainer state", "trainer_state.json and training_args",
           ("TrainerState", "global-step", "log-entry", "checkpoint", "TrainingArguments"),
           ("TrainerState counts global-step", "TrainerState appends log-entry",
            "TrainerState names checkpoint", "TrainingArguments configures TrainerState"),
           ("TRAIN-1.1", "TRAIN-1.3", "TRAIN-2.1", "TRAIN-2.3")),
        _m("sharded-checkpoint", "DeepSpeed and fully sharded data parallel checkpoints", "shard files plus index",
           ("checkpoint", "shard", "tensor-slice", "rank", "index"),
           ("checkpoint partitions into shard", "shard holds tensor-slice",
            "rank owns shard", "index maps tensor to shard"),
           ("TRAIN-1.2", "TRAIN-1.4", "TRAIN-2.2")),
        _m("mlflow-run", "MLflow tracking run", "run metadata, params, metrics and artifacts",
           ("run", "parameter", "metric-point", "tag", "artifact", "experiment"),
           ("experiment contains run", "run records parameter",
            "run appends metric-point at step", "run stores artifact",
            "run parent-of run"),
           ("TRAIN-1.1", "TRAIN-1.3", "TRAIN-2.1", "TRAIN-2.4", "TRAIN-4.2")),
        _m("tensorboard-event", "TensorBoard event file", "tfevents protocol buffer stream",
           ("event", "summary", "step", "wall-time", "tag"),
           ("event carries summary", "summary indexed-by tag",
            "event stamps step and wall-time"),
           ("TRAIN-1.3", "TRAIN-2.1")),
    ),
    "TOKEN": (
        _m("jose-jwt", "JSON Web Token over JOSE", "compact or JSON serialization",
           ("JWS-header", "claim-set", "issuer", "subject", "expiry", "not-before", "signature"),
           ("JWS-header names signature algorithm", "claim-set carries issuer and subject",
            "expiry and not-before bound claim-set", "signature covers header and claim-set"),
           ("TOKEN-1.1", "TOKEN-1.2", "TOKEN-1.6", "TOKEN-4.5")),
        _m("cose-cwt", "Concise Binary Object Representation (CBOR) Web Token over CBOR Object Signing and Encryption (COSE)", "COSE_Sign1 structure",
           ("protected-header", "claim-set", "key-identifier", "expiry", "signature"),
           ("protected-header names key-identifier", "claim-set carries expiry",
            "signature covers protected-header and claim-set"),
           ("TOKEN-1.2", "TOKEN-1.6", "TOKEN-4.5")),
        _m("w3c-verifiable-credential", "World Wide Web Consortium (W3C) Verifiable Credential", "credential document plus proof",
           ("credential", "issuer", "credentialSubject", "proof", "status-entry", "validity-period"),
           ("issuer asserts credential", "credential describes credentialSubject",
            "proof covers credential", "status-entry revokes credential",
            "validity-period bounds credential"),
           ("TOKEN-1.1", "TOKEN-1.6", "TOKEN-2.3", "TOKEN-4.5")),
        _m("macaroon", "Macaroon and Biscuit attenuable credentials", "caveat chain over a root key",
           ("macaroon", "caveat", "root-key", "chained-signature", "discharge"),
           ("macaroon accumulates caveat", "caveat attenuates macaroon",
            "chained-signature binds caveat order", "discharge satisfies third-party caveat"),
           ("TOKEN-1.5", "TOKEN-2.4", "TOKEN-4.3", "TOKEN-4.4")),
        _m("spiffe-svid", "SPIFFE verifiable identity document", "X.509 or JWT SVID",
           ("SVID", "trust-domain", "workload-identifier", "validity-window", "trust-bundle"),
           ("trust-domain scopes workload-identifier", "SVID names workload-identifier",
            "validity-window bounds SVID", "trust-bundle verifies SVID"),
           ("TOKEN-1.5", "TOKEN-1.6", "TOKEN-4.5")),
    ),
    "HYPER": (
        _m("in-toto-layout", "in-toto layout and link metadata", "layout file plus link files",
           ("layout", "step", "inspection", "functionary", "threshold", "link", "artifact-rule"),
           ("layout authorizes step", "functionary signs link for step",
            "threshold bounds functionary count", "artifact-rule matches materials to products",
            "inspection verifies final product"),
           ("HYPER-1.1", "HYPER-1.2", "HYPER-2.1", "HYPER-2.2", "HYPER-4.1", "HYPER-4.2")),
        _m("slsa-provenance", "Supply-chain Levels for Software Artifacts provenance", "provenance predicate",
           ("subject", "buildDefinition", "runDetails", "resolvedDependency", "builder"),
           ("subject produced-by buildDefinition", "buildDefinition consumes resolvedDependency",
            "runDetails names builder", "builder attests subject"),
           ("HYPER-1.1", "HYPER-2.1", "HYPER-4.1")),
        _m("sigstore-bundle", "Sigstore bundle", "verification material and DSSE envelope",
           ("bundle", "envelope", "certificate", "transparency-entry", "identity"),
           ("bundle wraps envelope", "certificate binds identity",
            "transparency-entry witnesses certificate", "envelope covers subject"),
           ("HYPER-1.3", "HYPER-4.3")),
        _m("oci-referrers", "Open Container Initiative image index and referrers", "index plus subject descriptors",
           ("index", "manifest", "subject-descriptor", "artifact-type"),
           ("manifest refers-to subject-descriptor", "index assembles manifest",
            "artifact-type classifies manifest"),
           ("HYPER-1.1", "HYPER-1.4", "HYPER-2.3")),
    ),
    "MODEL": (
        _m("onnx", "Open Neural Network Exchange", "ModelProto",
           ("ModelProto", "GraphProto", "NodeProto", "TensorProto", "ValueInfoProto", "OperatorSetId"),
           ("ModelProto contains GraphProto", "GraphProto orders NodeProto topologically",
            "NodeProto instantiates operator from OperatorSetId",
            "GraphProto initializes TensorProto", "ValueInfoProto types graph edge"),
           ("MODEL-1.1", "MODEL-1.2", "MODEL-1.3", "MODEL-2.1", "MODEL-2.2")),
        _m("safetensors", "safetensors tensor container", "JSON header plus contiguous payload",
           ("header", "tensor-entry", "dtype", "shape", "data-offset"),
           ("header maps name to tensor-entry", "tensor-entry declares dtype and shape",
            "tensor-entry locates data-offset", "payload stores tensor bytes"),
           ("MODEL-1.1", "MODEL-1.2", "MODEL-2.1")),
        _m("gguf", "GGUF model container", "key-value metadata plus tensor table",
           ("metadata-kv", "tensor-info", "tensor-data", "quantization-type", "alignment"),
           ("metadata-kv describes model", "tensor-info names tensor-data",
            "quantization-type encodes tensor-data", "alignment positions tensor-data"),
           ("MODEL-1.1", "MODEL-1.2", "MODEL-2.1", "MODEL-2.3")),
        _m("huggingface-model-repository", "Hugging Face model repository", "config.json, weight index and model card",
           ("config", "weight-index", "tokenizer", "model-card", "shard"),
           ("config declares architecture", "weight-index maps tensor to shard",
            "tokenizer pairs-with config", "model-card documents config"),
           ("MODEL-1.1", "MODEL-1.4", "MODEL-2.1", "MODEL-4.1")),
        _m("stablehlo", "StableHLO portable operation set", "MLIR module with versioned opset",
           ("module", "function", "operation", "opset-version", "type"),
           ("module defines function", "function sequences operation",
            "opset-version stabilizes operation", "type annotates operation"),
           ("MODEL-1.3", "MODEL-2.1", "MODEL-2.4")),
    ),
    "SIM": (
        _m("gymnasium", "Gymnasium environment interface", "Env class with space algebra",
           ("Env", "observation-space", "action-space", "step-result", "seed", "space-composite"),
           ("Env exposes observation-space and action-space",
            "space-composite nests space", "Env step produces step-result",
            "seed initializes Env reset", "step-result carries terminated and truncated"),
           ("SIM-1.4", "SIM-1.5", "SIM-2.1", "SIM-2.2", "SIM-2.4")),
        _m("fmi", "Functional Mock-up Interface", "FMU with modelDescription.xml",
           ("FMU", "scalar-variable", "causality", "variability", "model-exchange", "co-simulation", "solver-step"),
           ("FMU declares scalar-variable", "causality types scalar-variable",
            "variability types scalar-variable", "model-exchange exposes derivative",
            "co-simulation advances solver-step", "FMU pins tolerance"),
           ("SIM-1.1", "SIM-1.2", "SIM-2.1", "SIM-2.3", "SIM-3.1", "SIM-4.1")),
        _m("mujoco-mjcf", "MuJoCo MJCF scene description", "MJCF XML",
           ("worldbody", "body", "joint", "geom", "actuator", "sensor", "option"),
           ("worldbody nests body", "body articulates joint", "body bounds geom",
            "actuator drives joint", "sensor observes body", "option fixes solver"),
           ("SIM-1.1", "SIM-1.2", "SIM-1.5", "SIM-3.1", "SIM-3.2")),
        _m("openusd", "OpenUSD stage", "layered stage with composition arcs",
           ("stage", "prim", "attribute", "relationship", "layer", "composition-arc"),
           ("stage composes layer", "composition-arc resolves prim opinion",
            "prim owns attribute", "relationship links prim", "layer overrides layer"),
           ("SIM-1.1", "SIM-1.6", "SIM-2.5")),
        _m("ros2-bag", "ROS 2 bag recording", "storage plus metadata.yaml",
           ("bag", "topic", "message", "timestamp", "qos-profile"),
           ("bag records topic", "topic carries message",
            "timestamp orders message", "qos-profile governs topic"),
           ("SIM-1.4", "SIM-2.1", "SIM-2.6")),
    ),
    "HARNESS": (
        _m("opentelemetry", "OpenTelemetry tracing", "OTLP trace payload",
           ("trace", "span", "attribute", "event", "link", "status", "resource"),
           ("trace contains span", "span parent-of span", "span carries attribute",
            "span emits event", "link relates span across trace",
            "resource identifies span producer"),
           ("HARNESS-1.1", "HARNESS-1.2", "HARNESS-2.1", "HARNESS-2.2")),
        _m("opentelemetry-genai", "OpenTelemetry generative AI semantic conventions", "span attribute set",
           ("llm-span", "tool-span", "prompt-attribute", "completion-attribute", "token-usage"),
           ("llm-span records prompt-attribute and completion-attribute",
            "tool-span names invoked tool", "token-usage meters llm-span"),
           ("HARNESS-1.3", "HARNESS-2.1", "HARNESS-2.3")),
        _m("model-context-protocol", "Model Context Protocol", "JSON-RPC over a transport",
           ("server", "tool", "resource", "prompt", "call", "result", "capability"),
           ("server advertises tool and resource", "capability negotiates server",
            "call invokes tool", "result answers call", "prompt templates call"),
           ("HARNESS-1.3", "HARNESS-1.4", "HARNESS-2.3", "HARNESS-2.4")),
        _m("har", "HTTP Archive", "HAR log",
           ("log", "entry", "request", "response", "timing"),
           ("log orders entry", "entry pairs request and response",
            "timing decomposes entry"),
           ("HARNESS-1.2", "HARNESS-2.1")),
    ),
    "AGENT": (
        _m("langgraph", "LangGraph state graph", "compiled graph plus checkpointer",
           ("graph", "node", "edge", "conditional-edge", "state-channel", "checkpoint", "thread"),
           ("graph wires node with edge", "conditional-edge branches on state-channel",
            "node reduces state-channel", "checkpoint snapshots thread",
            "thread sequences checkpoint"),
           ("AGENT-1.1", "AGENT-1.2", "AGENT-2.1", "AGENT-2.2")),
        _m("run-tree", "Nested run tree", "LangSmith-style run records",
           ("run", "parent-run", "run-type", "inputs", "outputs", "error"),
           ("run child-of parent-run", "run-type classifies run",
            "run carries inputs and outputs", "error terminates run"),
           ("AGENT-1.2", "AGENT-1.3", "AGENT-2.1")),
        _m("agent-trajectory", "Step trajectory record", "trajectory JSONL",
           ("trajectory", "step", "thought", "action", "observation", "terminal"),
           ("trajectory orders step", "step pairs action and observation",
            "thought precedes action", "terminal closes trajectory"),
           ("AGENT-1.1", "AGENT-1.4", "AGENT-2.1", "AGENT-2.3")),
        _m("opentelemetry-genai-agent", "OpenTelemetry generative AI agent spans", "agent and tool span tree",
           ("agent-span", "tool-span", "decision-attribute", "outcome-status"),
           ("agent-span parent-of tool-span", "decision-attribute annotates agent-span",
            "outcome-status closes agent-span"),
           ("AGENT-1.2", "AGENT-2.1", "AGENT-4.1")),
    ),
    "BOT": (
        _m("embodied-interaction-graph", "Interaction graph over a bound simulation surface",
           "composed agent trajectory and simulation trace",
           ("interaction-node", "observation-edge", "action-edge", "disclosure-set",
            "indisclosure-set", "awareness-level"),
           ("action-edge couples interaction-node to simulation state",
            "observation-edge exposes simulation state to interaction-node",
            "disclosure-set enumerates what the composed object reveals",
            "indisclosure-set names what stays unestablished",
            "awareness-level grades inclusion awareness"),
           ("BOT-1.1", "BOT-1.2", "BOT-2.1", "BOT-2.2")),
        _m("urdf", "Unified Robot Description Format", "URDF or SDFormat model",
           ("robot", "link", "joint", "inertial", "collision", "transmission"),
           ("robot assembles link", "joint connects link pair",
            "inertial masses link", "transmission actuates joint"),
           ("BOT-1.1", "BOT-1.3", "BOT-2.1")),
    ),
}

BY_FORMAT = {object_name: {m.format_id: m for m in rows} for object_name, rows in MAINSTAYS.items()}

#: Which meta-surface relation each adaptation check maps onto. ``binding``,
#: ``roundtrip`` and ``residual`` are structural and name no single relation.
CHECKS = {
    "binding": "The format is named from this object's registry, version-pinned, and its carrier digest bound.",
    "layout": "Every retained inventory item maps to exactly one mainstay entity of the declared kind.",
    "schema": "The bound field or type contract maps onto the mainstay's type system, with unrepresentable types named.",
    "metadata": "Declared provenance and statics map onto the mainstay's metadata record.",
    "recipe": "Build steps map onto the mainstay's derivation or recipe model.",
    "attestation": "The provenance attestation maps onto the mainstay's attestation format.",
    "limits": "Declared ceilings map onto the mainstay's limit model.",
    "upstream": "The batch binding maps onto the inventory an upstream object's tier-5 surface exposes.",
    "authorization": "Slot filling maps onto the mainstay's step-authorization model.",
    "operators": "Operators the mainstay's versioned operation set cannot express are named.",
    "backend": "Transition expressions map onto the mainstay's solver or model-exchange interface.",
    "stepping": "The mainstay's stepping and reset semantics map onto the retained trajectory.",
    "protocol": "The tool registry and its invocations map onto the mainstay's protocol.",
    "slot": "The decider slot maps onto the mainstay's policy binding without pinning the slot to a model.",
    "gap": "The uninstrumented gap is represented in the mainstay or named unrepresentable there.",
    "interaction": "The interaction graph over the bound simulation's surface is bound.",
    "disclosed": "What the composed object discloses about itself is enumerated.",
    "indisclosed": "What it does not disclose is named as unestablished rather than absent.",
    "inclusion": "Inclusion awareness is recorded rather than inferred.",
    "awareness": "The specification surfaces the object is aware of are recorded.",
    "accounting": "Disclosed and indisclosed awareness are accounted for without inferring either from the other.",
    "roundtrip": "Export and re-import reproduces the retained commitment, or names its loss exactly.",
    "residual": "The residual is recomputed from the meta-surface rather than declared.",
}


def _bound(object_name: str, artifact: dict, budget: Budget) -> Mainstay:
    binding = obj(need(artifact, "mainstay"), {"format_id", "version", "carrier_digest"})
    registry = BY_FORMAT.get(object_name)
    if registry is None:
        raise Unavailable(f"no mainstay registry for object: {object_name}")
    mainstay = registry.get(text(binding["format_id"]))
    if mainstay is None:
        raise Refuted(f"the named format is not a registered mainstay of {object_name}")
    text(binding["version"])
    if not str(binding["carrier_digest"]).startswith("sha256:"):
        raise Refuted("the mainstay carrier must be bound by a canonical digest")
    budget.tick()
    return mainstay


def _mapping(mainstay: Mainstay, artifact: dict, inputs: dict, check: str, budget: Budget) -> dict:
    """A mapping is admitted only when it is total over the retained inventory."""
    mapping = obj(need(artifact, "mapping"))
    if check not in mapping:
        raise Unavailable(f"no declared mapping for {check}")
    declared = obj(mapping[check], {"relation", "entity", "pairs"})
    if text(declared["relation"]) not in mainstay.relations:
        raise Refuted("the mapping names a relation the meta-surface does not carry")
    if text(declared["entity"]) not in mainstay.entities:
        raise Refuted("the mapping names an entity the meta-surface does not carry")
    retained = seq(need(inputs, "inventory"), budget)
    pairs = obj(declared["pairs"])
    budget.tick(len(retained))
    unmapped = [text(item) for item in retained if text(item) not in pairs]
    if unmapped:
        raise Refuted(f"the mapping is not total over the retained inventory: {unmapped[0]}")
    if set(pairs) - {text(item) for item in retained}:
        raise Refuted("the mapping covers items outside the retained inventory")
    return {"relation": declared["relation"], "entity": declared["entity"],
            "mapped": len(pairs), "distinct_targets": len(set(map(str, pairs.values())))}


def _roundtrip(artifact: dict, inputs: dict, budget: Budget) -> dict:
    record = obj(need(artifact, "round_trip"), {"exported", "reimported", "loss"})
    loss = seq(record["loss"], budget, nonempty=False)
    budget.tick()
    if record["exported"] == record["reimported"]:
        if loss:
            raise Refuted("a lossless round trip names a loss")
        return {"lossless": True, "commitment": record["exported"]}
    if not loss:
        raise Refuted("a lossy round trip names no loss")
    for item in loss:
        text(item)
    return {"lossless": False, "loss": [text(i) for i in loss]}


def _residual(object_name: str, mainstay: Mainstay, artifact: dict, budget: Budget) -> dict:
    computed = list(mainstay.residual())
    budget.tick(len(computed))
    same(computed, need(artifact, "residual"),
         "the declared residual is not the complement of what the meta-surface expresses")
    by_tier: dict[str, int] = {}
    for coordinate in computed:
        tier = str(DOMAIN_BY_ID[coordinate].profile)
        by_tier[tier] = by_tier.get(tier, 0) + 1
    return {"residual": computed, "by_tier": by_tier,
            "expressed": len(mainstay.expresses), "format_id": mainstay.format_id}


def evaluate(object_name: str, check: str, artifact: dict, inputs: dict,
             budget: Budget, **_: Any) -> dict:
    """Establish one tier-5 adaptation obligation against a named mainstay."""
    if check not in CHECKS:
        raise Unavailable(f"unsupported adaptation check: {check}")
    mainstay = _bound(object_name, artifact, budget)
    if check == "binding":
        return {"format_id": mainstay.format_id, "display": mainstay.display,
                "carrier": mainstay.carrier, "entities": list(mainstay.entities),
                "relations": list(mainstay.relations)}
    if check == "roundtrip":
        return _roundtrip(artifact, inputs, budget)
    if check == "residual":
        return _residual(object_name, mainstay, artifact, budget)
    return _mapping(mainstay, artifact, inputs, check, budget)


def mainstay_catalog() -> dict:
    """Describe every registered mainstay and the coordinates it can express."""
    return {"schema_version": "verifier-mainstay-catalog-1", "tier": 5,
            "checks": {PREFIX + name: statement for name, statement in CHECKS.items()},
            "objects": {object_name: [
                {"format_id": m.format_id, "display": m.display, "carrier": m.carrier,
                 "entities": list(m.entities), "relations": list(m.relations),
                 "expresses": list(m.expresses), "residual": list(m.residual())}
                for m in rows] for object_name, rows in MAINSTAYS.items()}}

def mainstay_digest() -> str:
    """Pin this mechanism family's bytes, separately from the behavioural adapters."""
    import hashlib
    from importlib.resources import files
    data = files("verifier.domains").joinpath("mainstays.py").read_bytes()
    return canonical_digest({"catalog": mainstay_catalog(),
                             "implementation": hashlib.sha256(data).hexdigest()})
