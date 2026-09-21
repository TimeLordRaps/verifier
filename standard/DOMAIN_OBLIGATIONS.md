# Grounded certification obligations of the thirteen certified objects

> **Acronyms:** artificial intelligence (AI);
> benchmark specification graph (VSTD-BENCH);
> dataset integrity and lineage (VSTD-DATA);
> directed acyclic graph (DAG);
> Extensible Markup Language (XML);
> generative simulation specification (VSTD-SIM);
> Hypertext Transfer Protocol (HTTP);
> JavaScript Object Notation (JSON);
> JSON Lines (JSONL);
> model reproducibility specification (VSTD-MODEL);
> object composition specification (VSTD-HYPER);
> Software Package Data Exchange (SPDX);
> Stable High-Level Optimizer (StableHLO);
> training run specification (VSTD-TRAIN);
> Verifier Standard (VSTD);
> verifiable execution environment (VSTD-ENV);
> YAML Ain't Markup Language (YAML).

**Status:** project specification (normative for the eleven domain objects' obligations)
**Editor:** TimeLordRaps
**License:** Apache-2.0
**Date:** 2026-09-21

The object axis carries `1.1`-`5.11` and the Graph axis carries `Graph-1.1`-`Graph-5.6`.
This file carries the third namespace: the eleven domain objects, coordinate
`<object>-<tier>.<index>`, 303 obligations. The three namespaces are disjoint.
`DATA-4.2` never aliases `4.2` or `Graph-4.2`, no catalogue admits another's identifiers,
and each carries its own digest, so extending one cannot move another.

Ten of the eleven are **grounded**: an adapter executes them. The eleventh, `VSTD-OWNER`,
is **relational and ungrounded** -- it certifies a holding between a bound actor and a
bound object, and no adapter executes it, so all 29 of its obligations report
`UNKNOWN`. The relational objects are `VSTD-GRAPH`, `VSTD-HYPER` and `VSTD-OWNER`; the
first carries its own axis and the other two sit on this one.

Each obligation binds a predicate `vstd.<object>.obligation.<tier>.<index>`. The
**mechanism** column names the check that establishes the obligation. An obligation
with no mechanism is specified and unmechanized: it is reported `UNKNOWN`, never absent
and never passed. Dependencies are within one numbered profile; cumulative profile
prerequisites apply across tiers as they do on both other axes.

## Three mechanism families

A mechanism name is prefixed by the family it belongs to, and the three families are
disjoint. They differ in what kind of evidence can establish an obligation at all.

| Family | Prefix | What establishes an obligation | Where | Bound |
|---|---|---|---|---|
| Behavioural | *(none)* | Re-executing what the subject declared: rehash, replay, recompute | [`DOMAIN_GROUNDING.md`](DOMAIN_GROUNDING.md) | 92 |
| Statics | `statics:` | A witness probe, a recomputation over the retained inventory, or invariance under perturbation of the subject's own choices | this file, tier 3 | 27 |
| Adaptation | `mainstay:` | Binding, mapping, round trip and residual against a named mainstay representation of the domain | this file, tier 5 | 58 |

The split is not organizational. Tiers 1, 2 and 4 are established by re-executing a
declaration, and that is exactly the mechanism a **static** cannot use, because
re-executing a declaration can only confirm the declaration. Tier 3 therefore needs
evidence the subject did not author -- a probe recorded by someone else, a statistic
recomputed from the retained records, or a demonstration that the fact does not move
when the subject's choices are perturbed. The last of these is the direct mechanization
of *the facts an object does not choose*, and it is why every statics profile ends with
an independence obligation.

Tier 5 needs a third kind again, because it describes an object in the terms its domain
already publishes in rather than in this standard's terms. Nothing can be checked there
until the mainstay representation is named, which is what the adaptation registry does.

## VSTD-DATA

### VSTD-DATA-1: Facets

`DATA-1.1` through `DATA-1.6`; topological depth 4; 5 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| DATA-1.1 | Retention boundary | The boundary between what was kept and what was seen is declared, with the discarded volume stated. | none | none |
| DATA-1.2 | Shard and record inventory | Every retained shard and record is enumerated and rehashed, and byte and count commitments are recomputed. | DATA-1.1 | inventory |
| DATA-1.3 | Record identity | Each retained record carries a stable identity that is unique within the inventory. | DATA-1.2 | inventory |
| DATA-1.4 | Field contract | The declared field types and required columns are bound for every retained record. | DATA-1.1 | schema |
| DATA-1.5 | Schema conformance | Each retained record is checked against the bound field contract. | DATA-1.3, DATA-1.4 | schema |
| DATA-1.6 | Digest tree commitment | The inventory's digest tree is recomputed from retained bytes and compared with the declared root. | DATA-1.2 | inventory |

### VSTD-DATA-2: Dynamics

`DATA-2.1` through `DATA-2.6`; topological depth 4; 3 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| DATA-2.1 | Transformation declaration | Every declared transformation is bound with its inputs, outputs and position in the order. | none | lineage |
| DATA-2.2 | Exact re-execution | Each declared transformation is re-executed and its exact output compared. | DATA-2.1 | lineage |
| DATA-2.3 | Pipeline ordering | Applying the transformations in the declared order reproduces the retained corpus. | DATA-2.2 | lineage |
| DATA-2.4 | Idempotence | Re-applying the pipeline to its own output changes nothing, or the change is localized. | DATA-2.3 | none |
| DATA-2.5 | Raw-to-retained path | Every retained record is traced to a raw input through the executed transformations. | DATA-2.2 | none |
| DATA-2.6 | Rebuild drift | A second rebuild is compared against the retained corpus and any divergence is localized. | DATA-2.3, DATA-2.5 | none |

### VSTD-DATA-3: Statics

`DATA-3.1` through `DATA-3.6`; topological depth 3; 6 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| DATA-3.1 | Sampling frame | The population sampled from, and the frame's coverage of it, are witnessed by a party other than the retaining pipeline. | none | statics:frame |
| DATA-3.2 | Measurement instrument | The unit and resolution of each measured field are witnessed, and every retained value lies on that resolution and inside its range. | none | statics:instrument |
| DATA-3.3 | Censoring and truncation | Censoring and truncation are declared and evidenced against the retained distribution. | DATA-3.1, DATA-3.2 | statics:censoring |
| DATA-3.4 | Distribution statics | Class balance, cardinality and entropy are recomputed over the retained inventory. | DATA-3.1 | statics:distribution |
| DATA-3.5 | Origin rights | Licence and legal facts of origin are bound per source, and the composite redistribution term is the meet of its sources. | none | statics:rights |
| DATA-3.6 | Pipeline independence | The facts above are unchanged when the retaining pipeline's declarations are perturbed. | DATA-3.3, DATA-3.4, DATA-3.5 | statics:independence |

### VSTD-DATA-4: Closure

`DATA-4.1` through `DATA-4.6`; topological depth 5; 5 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| DATA-4.1 | Split declaration | Every split is named with its membership predicate. | none | splits |
| DATA-4.2 | Complete membership | Every retained record is assigned to exactly one declared split. | DATA-4.1 | splits |
| DATA-4.3 | Identity separation | No record identity appears in two splits. | DATA-4.2 | splits |
| DATA-4.4 | Exact overlap | Exact train and evaluation overlap is recomputed over the complete inventory. | DATA-4.2 | overlap |
| DATA-4.5 | Lexical overlap | Near-duplicate overlap is recomputed under the declared similarity bound. | DATA-4.4 | overlap |
| DATA-4.6 | No unaccounted record | The inventory admits no record outside the declared splits and retention boundary. | DATA-4.3, DATA-4.5 | none |

### VSTD-DATA-5: Domain adaptation

`DATA-5.1` through `DATA-5.6`; topological depth 4; 6 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| DATA-5.1 | Mainstay binding | The columnar or catalogue representation the dataset is published in is named and version-pinned. | none | mainstay:binding |
| DATA-5.2 | Columnar shard mapping | The retained shard inventory is mapped onto the mainstay's physical layout. | DATA-5.1 | mainstay:layout |
| DATA-5.3 | Schema mapping | The bound field contract is mapped onto the mainstay's type system, with unrepresentable types named. | DATA-5.1 | mainstay:schema |
| DATA-5.4 | Dataset card mapping | Declared provenance, licence and statics are mapped onto the mainstay's metadata record. | DATA-5.1 | mainstay:metadata |
| DATA-5.5 | Round trip | Export and re-import reproduces the retained inventory byte for byte, or names its loss. | DATA-5.2, DATA-5.3, DATA-5.4 | mainstay:roundtrip |
| DATA-5.6 | Inference upward | What the mainstay cannot express is stated as the residual this object carries over it. | DATA-5.5 | mainstay:residual |

### Registered mainstays of VSTD-DATA

| Format | Carried in | Meta-surface entities | Expresses | Residual |
|---|---|---|---|---|
| Apache Parquet (`apache-parquet`) | file footer FileMetaData | file, row-group, column-chunk, page, column-statistics | 5 coordinates | 19 coordinates |
| Apache Arrow inter-process communication (`apache-arrow-ipc`) | stream or file format | schema, record-batch, buffer, dictionary | 3 coordinates | 21 coordinates |
| WebDataset tar shards (`webdataset`) | POSIX tar shard sequence | shard, sample, member | 3 coordinates | 21 coordinates |
| MLCommons Croissant (`mlcommons-croissant`) | JSON-LD metadata record | Dataset, RecordSet, Field, FileObject, FileSet, Distribution | 8 coordinates | 16 coordinates |
| Hugging Face datasets (`huggingface-datasets`) | dataset_infos.json and card front matter | DatasetInfo, Features, Split, DownloadChecksum | 5 coordinates | 19 coordinates |
| Apache Iceberg table format (`apache-iceberg`) | metadata.json, manifest lists and manifests | table, snapshot, manifest, data-file, partition-spec | 5 coordinates | 19 coordinates |

## VSTD-ENV

### VSTD-ENV-1: Facets

`ENV-1.1` through `ENV-1.6`; topological depth 4; 4 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| ENV-1.1 | Environment boundary | What is inside the environment and what is host is declared. | none | none |
| ENV-1.2 | Software inventory | Every file in the selected software inventory is materialized and rehashed. | ENV-1.1 | closure |
| ENV-1.3 | Executable coordinates | The entry point, interpreter and their versions are bound. | ENV-1.2 | closure |
| ENV-1.4 | Configuration surface | The complete required configuration is declared with its value domain. | ENV-1.1 | configuration |
| ENV-1.5 | Observed configuration | Retained collector observations are compared with the required configuration surface. | ENV-1.4 | configuration |
| ENV-1.6 | Unpinned residue | Every inventory element without a pinned digest is named rather than assumed absent. | ENV-1.2, ENV-1.5 | none |

### VSTD-ENV-2: Dynamics

`ENV-2.1` through `ENV-2.6`; topological depth 4; 3 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| ENV-2.1 | Nondeterminism declaration | Every nondeterminism source -- clock, entropy, thread interleaving, allocator -- is declared. | none | none |
| ENV-2.2 | Scheduling surface | Concurrency and scheduling policy are bound for the retained executions. | ENV-2.1 | none |
| ENV-2.3 | Execution pair | Two retained executions are bound with their inputs, coordinates and results. | none | reproduction |
| ENV-2.4 | Input agreement | The two executions are compared input for input. | ENV-2.3 | reproduction |
| ENV-2.5 | Result agreement | The two executions are compared result for result and divergence is localized. | ENV-2.4 | reproduction |
| ENV-2.6 | Divergence attribution | Each divergence is attributed to a declared nondeterminism source or reported unattributed. | ENV-2.1, ENV-2.2, ENV-2.5 | none |

### VSTD-ENV-3: Statics

`ENV-3.1` through `ENV-3.5`; topological depth 3; 1 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| ENV-3.1 | Instruction set | The architecture and its extension set are observed rather than declared. | none | none |
| ENV-3.2 | Floating-point semantics | Format, rounding mode and fused-operation behaviour are observed on the executing machine. | ENV-3.1 | none |
| ENV-3.3 | Resource ceilings | Retained resource measurements are checked against the exact declared ceilings. | none | resources |
| ENV-3.4 | Physical envelope | Memory, clock, thermal and power limits of the machine are recorded. | ENV-3.3 | none |
| ENV-3.5 | Envelope independence | The envelope holds whether or not the specification declares it. | ENV-3.1, ENV-3.2, ENV-3.4 | none |

### VSTD-ENV-4: Closure

`ENV-4.1` through `ENV-4.5`; topological depth 4; 0 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| ENV-4.1 | Pin completeness | Nothing in the inventory resolves outside the pinned set. | none | none |
| ENV-4.2 | Host isolation | No implicit host state -- environment variables, paths, network, wall clock -- leaks into the execution. | ENV-4.1 | none |
| ENV-4.3 | Network closure | Every external fetch is either pinned by digest or declared absent. | ENV-4.1 | none |
| ENV-4.4 | Standup sufficiency | A second party can stand the environment up from the record alone. | ENV-4.2, ENV-4.3 | none |
| ENV-4.5 | Standup evidence | A retained independent standup is compared against the original. | ENV-4.4 | none |

### VSTD-ENV-5: Domain adaptation

`ENV-5.1` through `ENV-5.6`; topological depth 5; 6 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| ENV-5.1 | Mainstay binding | The image, derivation or lockfile format is named and version-pinned. | none | mainstay:binding |
| ENV-5.2 | Image closure mapping | The inventory is mapped onto the mainstay's layer or store-path model. | ENV-5.1 | mainstay:layout |
| ENV-5.3 | Derivation mapping | The build steps are mapped onto the mainstay's derivation or recipe model. | ENV-5.1 | mainstay:recipe |
| ENV-5.4 | Build provenance mapping | The provenance attestation is mapped onto the mainstay's attestation format. | ENV-5.2, ENV-5.3 | mainstay:attestation |
| ENV-5.5 | Round trip | Rebuilding from the mainstay representation reproduces the pinned inventory. | ENV-5.4 | mainstay:roundtrip |
| ENV-5.6 | Inference upward | What the mainstay cannot pin is stated as the residual this object carries over it. | ENV-5.5 | mainstay:residual |

### Registered mainstays of VSTD-ENV

| Format | Carried in | Meta-surface entities | Expresses | Residual |
|---|---|---|---|---|
| Open Container Initiative image (`oci-image`) | image index, manifest and config descriptors | index, manifest, config, layer, annotation | 4 coordinates | 18 coordinates |
| Nix derivation (`nix-derivation`) | .drv store object | derivation, input-derivation, input-source, output-path, builder, environment | 7 coordinates | 15 coordinates |
| Resolved dependency lockfile (`lockfile`) | uv.lock, poetry.lock or hashed requirements | package, version, artifact-hash, marker, resolution | 3 coordinates | 19 coordinates |
| Software bill of materials (`sbom`) | SPDX or CycloneDX document | component, relationship, licence, supplier | 4 coordinates | 18 coordinates |
| in-toto attestation (`in-toto-attestation`) | DSSE envelope over a predicate | statement, subject, predicate, builder, material, byproduct | 5 coordinates | 17 coordinates |

## VSTD-BENCH

### VSTD-BENCH-1: Facets

`BENCH-1.1` through `BENCH-1.7`; topological depth 5; 3 of 7 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| BENCH-1.1 | Domain declaration | The domain or set of domains the bench measures is declared. | none | none |
| BENCH-1.2 | Problem set | Each finite problem is bound to its exact specification and candidate answer. | BENCH-1.1 | problems |
| BENCH-1.3 | Solution deducibility | What a solution is deducible from is declared for each problem. | BENCH-1.2 | problems |
| BENCH-1.4 | Oracle binding | The named built-in oracle is executed; a supplied solved flag is never accepted. | BENCH-1.3 | oracles |
| BENCH-1.5 | Sampling procedure | How the problems were drawn from the domain is declared. | BENCH-1.1, BENCH-1.2 | none |
| BENCH-1.6 | Baseline mechanics | The baseline a score is read against is bound and executable. | BENCH-1.4 | none |
| BENCH-1.7 | Feature representation | The representational spaces or categories the problems are typed by are declared. | BENCH-1.1 | none |

### VSTD-BENCH-2: Dynamics

`BENCH-2.1` through `BENCH-2.6`; topological depth 4; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| BENCH-2.1 | Attempt policy | Repeated attempts and best-of-N selection are declared and bounded per problem. | none | none |
| BENCH-2.2 | Attempt inventory | Every attempt is retained; none is discarded on selection. | BENCH-2.1 | none |
| BENCH-2.3 | Sequential adaptivity | Whether later problems depend on earlier results is declared and evidenced. | BENCH-2.2 | none |
| BENCH-2.4 | Contamination accumulation | Corpus exposure is accumulated against a dated boundary rather than assumed absent. | none | none |
| BENCH-2.5 | Response curve | Score as a function of budget is recomputed over the retained attempts. | BENCH-2.2 | none |
| BENCH-2.6 | Measurement feedback | The effect of publication on the systems measured is declared as an uncontrolled dynamic. | BENCH-2.3, BENCH-2.4, BENCH-2.5 | none |

### VSTD-BENCH-3: Statics

`BENCH-3.1` through `BENCH-3.7`; topological depth 4; 1 of 7 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| BENCH-3.1 | Chance floor | The score a null strategy attains is computed from the problem family. | none | none |
| BENCH-3.2 | Oracle ceiling | The maximum score attainable given the bound oracles is computed. | none | none |
| BENCH-3.3 | Label noise | Irreducible disagreement in the ground truth is estimated rather than assumed zero. | BENCH-3.2 | none |
| BENCH-3.4 | Hardness classes | The intrinsic hardness classes of the problem family are named. | BENCH-3.1, BENCH-3.2 | none |
| BENCH-3.5 | Natural distribution | The domain's own task distribution is stated separately from the bench's sample of it. | BENCH-3.4 | none |
| BENCH-3.6 | Budget ceilings | Retained timing and memory observations are checked against the problem ceilings. | none | budgets |
| BENCH-3.7 | Harness independence | The facts above hold when the harness changes. | BENCH-3.3, BENCH-3.5, BENCH-3.6 | none |

### VSTD-BENCH-4: Closure

`BENCH-4.1` through `BENCH-4.5`; topological depth 4; 4 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| BENCH-4.1 | Run inventory | One retained run per problem is enumerated. | none | coverage |
| BENCH-4.2 | No missing run | Every problem in the bound set has a retained run. | BENCH-4.1 | coverage |
| BENCH-4.3 | No duplicate or substituted run | Each run binds to exactly one problem specification. | BENCH-4.1 | coverage |
| BENCH-4.4 | Weighted score | The weighted score is recomputed over the complete inventory under the declared weights. | BENCH-4.2, BENCH-4.3 | coverage |
| BENCH-4.5 | Surface completeness | The scored set covers the whole declared measurement surface. | BENCH-4.4 | none |

### VSTD-BENCH-5: Domain adaptation

`BENCH-5.1` through `BENCH-5.6`; topological depth 5; 6 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| BENCH-5.1 | Mainstay binding | The evaluation harness or task-specification format is named and version-pinned. | none | mainstay:binding |
| BENCH-5.2 | Task specification mapping | Problems and oracles are mapped onto the mainstay's task record. | BENCH-5.1 | mainstay:layout |
| BENCH-5.3 | Scoring contract mapping | Weights, aggregation and reporting are mapped onto the mainstay's metric contract. | BENCH-5.1 | mainstay:schema |
| BENCH-5.4 | Budget mapping | Problem ceilings are mapped onto the mainstay's limit model. | BENCH-5.2 | mainstay:limits |
| BENCH-5.5 | Round trip | Running the mainstay's export reproduces the retained scores. | BENCH-5.2, BENCH-5.3, BENCH-5.4 | mainstay:roundtrip |
| BENCH-5.6 | Inference upward | What the mainstay cannot express is stated as the residual this object carries over it. | BENCH-5.5 | mainstay:residual |

### Registered mainstays of VSTD-BENCH

| Format | Carried in | Meta-surface entities | Expresses | Residual |
|---|---|---|---|---|
| EleutherAI language model evaluation harness (`lm-evaluation-harness`) | task YAML | task, dataset-reference, document-template, metric, filter, fewshot-context | 5 coordinates | 20 coordinates |
| Stanford Holistic Evaluation of Language Models (`helm`) | run specification records | RunSpec, Scenario, Adapter, Metric, Instance, Reference | 6 coordinates | 19 coordinates |
| BIG-bench task (`bigbench`) | task.json or programmatic task | task, example, metric, keyword | 3 coordinates | 22 coordinates |
| SWE-bench instance record (`swe-bench`) | instance JSONL | instance, repository, base-commit, patch, test-patch, test-status-set | 6 coordinates | 19 coordinates |
| MLPerf result log (`mlperf`) | result summary and detail logs | benchmark, scenario, division, system, result, constraint | 4 coordinates | 21 coordinates |

## VSTD-TRAIN

### VSTD-TRAIN-1: Facets

`TRAIN-1.1` through `TRAIN-1.6`; topological depth 4; 5 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| TRAIN-1.1 | Optimizer contract | The optimizer, schedule, accumulation and precision contract is bound. | none | configuration |
| TRAIN-1.2 | Numerical semantics | The declared floating-point format and accumulation order are bound. | TRAIN-1.1 | configuration |
| TRAIN-1.3 | Checkpoint inventory | Every retained weight and optimizer state is rehashed. | none | checkpoints |
| TRAIN-1.4 | Step index | A contiguous step index is bound over the retained trace. | TRAIN-1.3 | checkpoints |
| TRAIN-1.5 | Batch binding | Each step is bound to the batch it consumed. | TRAIN-1.4 | checkpoints |
| TRAIN-1.6 | Retention boundary | Which steps and states are retained, and which were discarded, is declared. | TRAIN-1.1, TRAIN-1.5 | none |

### VSTD-TRAIN-2: Dynamics

`TRAIN-2.1` through `TRAIN-2.6`; topological depth 5; 5 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| TRAIN-2.1 | Loss replay | Dense-network losses are recomputed from the bound batches. | none | training |
| TRAIN-2.2 | Gradient replay | Analytic gradients are recomputed and compared with the retained ones. | TRAIN-2.1 | training |
| TRAIN-2.3 | Optimizer update | Every supported optimizer update is recomputed from retained gradients and state. | TRAIN-2.2 | updates |
| TRAIN-2.4 | State advance | Applying the recomputed update reproduces the next retained state. | TRAIN-2.3 | updates |
| TRAIN-2.5 | Step-by-step advance | The run is replayed step by step across the retained trace. | TRAIN-2.4 | training |
| TRAIN-2.6 | Unsupported update reporting | An unsupported optimizer is reported UNKNOWN and never passed. | TRAIN-2.3 | none |

### VSTD-TRAIN-3: Statics

`TRAIN-3.1` through `TRAIN-3.5`; topological depth 3; 5 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| TRAIN-3.1 | Arithmetic semantics | The executing hardware's floating-point behaviour is observed rather than declared. | none | statics:arithmetic |
| TRAIN-3.2 | Accumulation order | The order reductions actually occur in is observed by reducing a retained sequence two ways, and its effect is bounded. | TRAIN-3.1 | statics:accumulation |
| TRAIN-3.3 | True gradient | The gradient the bound objective has is stated independently of what the run computed. | none | statics:objective |
| TRAIN-3.4 | Objective geometry | The curvature and conditioning that the architecture and data together fix are stated. | TRAIN-3.3 | statics:geometry |
| TRAIN-3.5 | Choice independence | The facts above are unchanged when the run's configuration is perturbed. | TRAIN-3.2, TRAIN-3.4 | statics:independence |

### VSTD-TRAIN-4: Closure

`TRAIN-4.1` through `TRAIN-4.6`; topological depth 6; 4 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| TRAIN-4.1 | Contiguity | The retained steps form an uninterrupted sequence with no gap. | none | lineage |
| TRAIN-4.2 | Parent binding | Each step binds to its exact parent state. | TRAIN-4.1 | lineage |
| TRAIN-4.3 | Batch and hyperparameter binding | Each step binds its exact batch and hyperparameter values. | TRAIN-4.2 | lineage |
| TRAIN-4.4 | Result binding | Each step binds its exact result. | TRAIN-4.3 | lineage |
| TRAIN-4.5 | No reordering | The retained order is the executed order, and a reordered pair is detectable. | TRAIN-4.4 | none |
| TRAIN-4.6 | Whole-run accounting | The trace accounts for the whole run rather than a selected prefix of it. | TRAIN-4.5 | none |

### VSTD-TRAIN-5: Domain adaptation

`TRAIN-5.1` through `TRAIN-5.6`; topological depth 5; 6 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| TRAIN-5.1 | Mainstay binding | The training-loop framework is named and version-pinned. | none | mainstay:binding |
| TRAIN-5.2 | Training-loop mapping | The retained trace is mapped onto the mainstay's loop and callback model. | TRAIN-5.1 | mainstay:layout |
| TRAIN-5.3 | Checkpoint-format mapping | The checkpoint inventory is mapped onto the mainstay's serialization format. | TRAIN-5.1 | mainstay:schema |
| TRAIN-5.4 | Batch source mapping | The batch binding is mapped onto the retained inventory a VSTD-DATA-5 object exposes. | TRAIN-5.2 | mainstay:upstream |
| TRAIN-5.5 | Round trip | Resuming from the mapped checkpoint reproduces the retained next step. | TRAIN-5.3, TRAIN-5.4 | mainstay:roundtrip |
| TRAIN-5.6 | Inference upward | What the mainstay cannot express is stated as the residual this object carries over it. | TRAIN-5.5 | mainstay:residual |

### Registered mainstays of VSTD-TRAIN

| Format | Carried in | Meta-surface entities | Expresses | Residual |
|---|---|---|---|---|
| PyTorch optimizer and module state (`pytorch-training-loop`) | state_dict objects | module, parameter, optimizer, param-group, optimizer-state, scheduler | 4 coordinates | 19 coordinates |
| Hugging Face Trainer state (`huggingface-trainer`) | trainer_state.json and training_args | TrainerState, global-step, log-entry, checkpoint, TrainingArguments | 4 coordinates | 19 coordinates |
| DeepSpeed and fully sharded data parallel checkpoints (`sharded-checkpoint`) | shard files plus index | checkpoint, shard, tensor-slice, rank, index | 3 coordinates | 20 coordinates |
| MLflow tracking run (`mlflow-run`) | run metadata, params, metrics and artifacts | run, parameter, metric-point, tag, artifact, experiment | 5 coordinates | 18 coordinates |
| TensorBoard event file (`tensorboard-event`) | tfevents protocol buffer stream | event, summary, step, wall-time, tag | 2 coordinates | 21 coordinates |

## VSTD-HYPER

### VSTD-HYPER-1: Facets

`HYPER-1.1` through `HYPER-1.6`; topological depth 5; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| HYPER-1.1 | Operand set | The set of bound certificates entering the composition, and its arity, is declared. | none | none |
| HYPER-1.2 | Slot schema | Which slot each operand fills, and which slots are unfilled, is declared. | HYPER-1.1 | none |
| HYPER-1.3 | Slot versus operand | The distinction between a slot, which is a role, and an operand, which is a certificate, is made explicit. | HYPER-1.2 | none |
| HYPER-1.4 | Substrate presence | The substrate each operand carries is identified once per arm of the composition. | HYPER-1.1 | none |
| HYPER-1.5 | Composed identity | The identity of the composed object is derived from its operands and its filled slots. | HYPER-1.3, HYPER-1.4 | none |
| HYPER-1.6 | Operand admissibility | Each operand is admitted under the composed object's own policy. | HYPER-1.5 | none |

### VSTD-HYPER-2: Dynamics

`HYPER-2.1` through `HYPER-2.6`; topological depth 4; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| HYPER-2.1 | Strength ordering | A total order on operand strengths is defined. | none | none |
| HYPER-2.2 | Non-increase | The composition's strength is no greater than that of its weakest operand. | HYPER-2.1 | none |
| HYPER-2.3 | UNKNOWN absorption | One UNKNOWN operand makes the composition UNKNOWN. | HYPER-2.2 | none |
| HYPER-2.4 | Recomposition | Recomposing from retained bytes lands on the same composed object. | none | none |
| HYPER-2.5 | Associativity | Which regroupings of operands are equivalent, and which are not, is stated. | HYPER-2.4 | none |
| HYPER-2.6 | Depth propagation | The composed object's depth is bounded by its operands' established depths. | HYPER-2.2, HYPER-2.3, HYPER-2.5 | none |

### VSTD-HYPER-3: Statics

`HYPER-3.1` through `HYPER-3.5`; topological depth 3; 5 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| HYPER-3.1 | Composed ceiling | The weakest operand bound is the composed ceiling, whatever the composed object declares. | none | statics:ceiling |
| HYPER-3.2 | Substrate recurrence | The substrate recurs at every level rather than being consumed by a composition. | none | statics:recurrence |
| HYPER-3.3 | Decider exteriority | The decider stays outside the certified surface at every level. | none | statics:exteriority |
| HYPER-3.4 | Manufacture impossibility | No composition manufactures evidence absent from its operands. | HYPER-3.1, HYPER-3.2 | statics:conservation |
| HYPER-3.5 | Level independence | The facts above hold at every depth of nesting and are unchanged when the composition's own declarations are perturbed. | HYPER-3.3, HYPER-3.4 | statics:independence |

### VSTD-HYPER-4: Closure

`HYPER-4.1` through `HYPER-4.5`; topological depth 5; 0 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| HYPER-4.1 | Saturation | Every slot of the composition is filled by a bound operand. | none | none |
| HYPER-4.2 | Collapse | An agent bound inside a simulation is written as one composed object and re-expanded. | HYPER-4.1 | none |
| HYPER-4.3 | Expansion fidelity | The re-expansion recovers the operand set byte for byte. | HYPER-4.2 | none |
| HYPER-4.4 | Fractal re-representation | The substrate is exhibited recurring identically at every level. | HYPER-4.3 | none |
| HYPER-4.5 | Boundary completeness | The composition's boundary admits no unbound operand. | HYPER-4.1, HYPER-4.4 | none |

### VSTD-HYPER-5: Domain adaptation

`HYPER-5.1` through `HYPER-5.5`; topological depth 5; 5 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| HYPER-5.1 | Mainstay binding | The composition formalism is named and version-pinned. | none | mainstay:binding |
| HYPER-5.2 | Layout mapping | The operand set and its slots are mapped onto the mainstay's layout or assembly relation. | HYPER-5.1 | mainstay:layout |
| HYPER-5.3 | Authorization mapping | Slot filling is mapped onto the mainstay's step-authorization model. | HYPER-5.2 | mainstay:authorization |
| HYPER-5.4 | Round trip | The mainstay's verifier accepts the mapped composition and rejects a substituted operand. | HYPER-5.3 | mainstay:roundtrip |
| HYPER-5.5 | Inference upward | What the mainstay cannot express is stated as the residual this object carries over it. | HYPER-5.4 | mainstay:residual |

### Registered mainstays of VSTD-HYPER

| Format | Carried in | Meta-surface entities | Expresses | Residual |
|---|---|---|---|---|
| in-toto layout and link metadata (`in-toto-layout`) | layout file plus link files | layout, step, inspection, functionary, threshold, link, artifact-rule | 6 coordinates | 16 coordinates |
| Supply-chain Levels for Software Artifacts provenance (`slsa-provenance`) | provenance predicate | subject, buildDefinition, runDetails, resolvedDependency, builder | 3 coordinates | 19 coordinates |
| Sigstore bundle (`sigstore-bundle`) | verification material and DSSE envelope | bundle, envelope, certificate, transparency-entry, identity | 2 coordinates | 20 coordinates |
| Open Container Initiative image index and referrers (`oci-referrers`) | index plus subject descriptors | index, manifest, subject-descriptor, artifact-type | 3 coordinates | 19 coordinates |

## VSTD-MODEL

### VSTD-MODEL-1: Facets

`MODEL-1.1` through `MODEL-1.5`; topological depth 3; 3 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| MODEL-1.1 | Tensor inventory | Complete finite tensor shapes are bound. | none | tensors |
| MODEL-1.2 | Architecture compatibility | Shapes are checked compatible across the declared computation graph. | MODEL-1.1 | tensors |
| MODEL-1.3 | Module decomposition | The model's module structure is declared. | MODEL-1.2 | none |
| MODEL-1.4 | Input and output surface | The declared input and output surface is bound with its types. | MODEL-1.2 | none |
| MODEL-1.5 | Dependency artifacts | The named dependency artifacts are bound by digest. | none | artifacts |

### VSTD-MODEL-2: Dynamics

`MODEL-2.1` through `MODEL-2.5`; topological depth 4; 2 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| MODEL-2.1 | Forward execution | The bound dense network is executed on the retained inputs. | none | inference |
| MODEL-2.2 | Output agreement | Every retained output is compared with the executed one. | MODEL-2.1 | inference |
| MODEL-2.3 | Batching behaviour | Results are invariant to the declared batching, or the variance is localized. | MODEL-2.2 | none |
| MODEL-2.4 | Precision behaviour | Results under the declared precision are bounded, with divergence localized. | MODEL-2.2 | none |
| MODEL-2.5 | Sampling and decoding | The decoding procedure and its entropy source are bound and replayed. | MODEL-2.3, MODEL-2.4 | none |

### VSTD-MODEL-3: Statics

`MODEL-3.1` through `MODEL-3.6`; topological depth 3; 1 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| MODEL-3.1 | Weight bytes | The exact architecture and weight artifacts are rehashed as retained bytes. | none | artifacts |
| MODEL-3.2 | Hardware requirements | The hardware the model requires in order to execute is observed. | MODEL-3.1 | none |
| MODEL-3.3 | Quantization specification | The quantization scheme and its configuration are bound. | MODEL-3.1 | none |
| MODEL-3.4 | Training-data citation | The retained-data object the model's training data is bound through is cited. | none | none |
| MODEL-3.5 | Provenance citation | The training-run object the model's provenance is bound through is cited. | MODEL-3.4 | none |
| MODEL-3.6 | Artifact immutability | The facts above are properties of the artifact rather than of any deployment of it. | MODEL-3.2, MODEL-3.3, MODEL-3.5 | none |

### VSTD-MODEL-4: Closure

`MODEL-4.1` through `MODEL-4.5`; topological depth 3; 4 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| MODEL-4.1 | Evaluation set | The named evaluation set is bound and complete. | none | evaluation |
| MODEL-4.2 | Metric recomputation | Regression or classification metrics are recomputed over the whole named set. | MODEL-4.1 | evaluation |
| MODEL-4.3 | Probe inventory | The declared finite counterexample probes are enumerated. | none | challenges |
| MODEL-4.4 | Probe execution | Each probe is executed against its bound output condition. | MODEL-4.3 | challenges |
| MODEL-4.5 | Refutability | The claimed behaviour is refutable rather than merely unrefuted. | MODEL-4.2, MODEL-4.4 | none |

### VSTD-MODEL-5: Domain adaptation

`MODEL-5.1` through `MODEL-5.6`; topological depth 5; 6 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| MODEL-5.1 | Mainstay binding | The module-graph and tensor-serialization formats are named and version-pinned. | none | mainstay:binding |
| MODEL-5.2 | Module-graph mapping | The module decomposition is mapped onto the mainstay's graph model. | MODEL-5.1 | mainstay:layout |
| MODEL-5.3 | Serialized-weights mapping | The weight inventory is mapped onto the mainstay's tensor container. | MODEL-5.1 | mainstay:schema |
| MODEL-5.4 | Operator coverage | Operators the mainstay cannot express are named. | MODEL-5.2 | mainstay:operators |
| MODEL-5.5 | Round trip | Export and re-import reproduces the retained outputs within the declared tolerance. | MODEL-5.3, MODEL-5.4 | mainstay:roundtrip |
| MODEL-5.6 | Inference upward | The residual this object carries over the mainstay is stated. | MODEL-5.5 | mainstay:residual |

### Registered mainstays of VSTD-MODEL

| Format | Carried in | Meta-surface entities | Expresses | Residual |
|---|---|---|---|---|
| Open Neural Network Exchange (`onnx`) | ModelProto | ModelProto, GraphProto, NodeProto, TensorProto, ValueInfoProto, OperatorSetId | 5 coordinates | 16 coordinates |
| safetensors tensor container (`safetensors`) | JSON header plus contiguous payload | header, tensor-entry, dtype, shape, data-offset | 3 coordinates | 18 coordinates |
| GGUF model container (`gguf`) | key-value metadata plus tensor table | metadata-kv, tensor-info, tensor-data, quantization-type, alignment | 4 coordinates | 17 coordinates |
| Hugging Face model repository (`huggingface-model-repository`) | config.json, weight index and model card | config, weight-index, tokenizer, model-card, shard | 4 coordinates | 17 coordinates |
| StableHLO portable operation set (`stablehlo`) | MLIR module with versioned opset | module, function, operation, opset-version, type | 3 coordinates | 18 coordinates |

## VSTD-SIM

### VSTD-SIM-1: Facets

`SIM-1.1` through `SIM-1.7`; topological depth 3; 2 of 7 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| SIM-1.1 | State space | The state space and its encoding are bound. | none | none |
| SIM-1.2 | Transition expressions | The bound transition expressions are declared over that space. | SIM-1.1 | none |
| SIM-1.3 | Entropy stream | The entropy source is bound and reproducible. | SIM-1.2 | none |
| SIM-1.4 | Observation channels | Every observation projection is declared. | SIM-1.1 | channels |
| SIM-1.5 | Action channels | Every declared action channel is bound. | SIM-1.4 | channels |
| SIM-1.6 | Shard decomposition | The shard partition of the state space is declared. | SIM-1.1 | none |
| SIM-1.7 | Macro and micro projection | The projection relating macro states to micro states is bound. | SIM-1.6 | none |

### VSTD-SIM-2: Dynamics

`SIM-2.1` through `SIM-2.6`; topological depth 4; 2 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| SIM-2.1 | Trajectory replay | The transition expressions and entropy stream are executed to reproduce the retained trajectory. | none | replay |
| SIM-2.2 | Responsiveness | Each action's effect on the next state is observed and bounded in simulated time. | SIM-2.1 | none |
| SIM-2.3 | Internal state change | State changes exposed through no observation channel are enumerated. | SIM-2.1 | none |
| SIM-2.4 | Computational space | The resources the transition actually consumes per step are recorded. | SIM-2.1 | none |
| SIM-2.5 | Perspective shift | The bound projection is executed and aligned macro states are compared within the declared tolerance. | SIM-2.3 | refinement |
| SIM-2.6 | Perspective agreement | A shift of perspective preserves the trajectory's identity. | SIM-2.2, SIM-2.4, SIM-2.5 | none |

### VSTD-SIM-3: Statics

`SIM-3.1` through `SIM-3.5`; topological depth 4; 3 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| SIM-3.1 | Invariant expressions | The bound invariant and conservation expressions are declared. | none | invariants |
| SIM-3.2 | Per-state holding | Each expression is checked on every retained state. | SIM-3.1 | invariants |
| SIM-3.3 | Closed state set | The closed finite state set is checked where one exists. | SIM-3.2 | invariants |
| SIM-3.4 | Modelled law | The physical law the simulation is a model of is stated as external to the simulation. | none | none |
| SIM-3.5 | Law independence | The law holds whether or not the simulation represents it correctly. | SIM-3.3, SIM-3.4 | none |

### VSTD-SIM-4: Closure

`SIM-4.1` through `SIM-4.5`; topological depth 4; 3 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| SIM-4.1 | Shard coverage | Every shard is present and aligned across the retained trajectory. | none | shards |
| SIM-4.2 | Cross-shard relations | The bound relations between shards are checked. | SIM-4.1 | shards |
| SIM-4.3 | Signatures | Shard signatures are verified where the policy requires them. | SIM-4.2 | shards |
| SIM-4.4 | No unattributed transition | Every transition is attributed to a bound transition expression. | SIM-4.1 | none |
| SIM-4.5 | Whole-surface accounting | The retained trajectory accounts for the whole simulated surface. | SIM-4.3, SIM-4.4 | none |

### VSTD-SIM-5: Domain adaptation

`SIM-5.1` through `SIM-5.6`; topological depth 5; 6 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| SIM-5.1 | Mainstay binding | The interaction or co-simulation interface is named and version-pinned. | none | mainstay:binding |
| SIM-5.2 | Interaction-surface mapping | Observation and action channels are mapped onto the mainstay's space model. | SIM-5.1 | mainstay:layout |
| SIM-5.3 | Physical-backend mapping | The transition expressions are mapped onto the mainstay's solver or model-exchange interface. | SIM-5.1 | mainstay:backend |
| SIM-5.4 | Stepping contract | The mainstay's stepping and reset semantics are mapped onto the retained trajectory. | SIM-5.2, SIM-5.3 | mainstay:stepping |
| SIM-5.5 | Round trip | Driving the mainstay reproduces the retained trajectory within the declared tolerance. | SIM-5.4 | mainstay:roundtrip |
| SIM-5.6 | Inference upward | The residual this object carries over the mainstay is stated. | SIM-5.5 | mainstay:residual |

### Registered mainstays of VSTD-SIM

| Format | Carried in | Meta-surface entities | Expresses | Residual |
|---|---|---|---|---|
| Gymnasium environment interface (`gymnasium`) | Env class with space algebra | Env, observation-space, action-space, step-result, seed, space-composite | 5 coordinates | 18 coordinates |
| Functional Mock-up Interface (`fmi`) | FMU with modelDescription.xml | FMU, scalar-variable, causality, variability, model-exchange, co-simulation, solver-step | 6 coordinates | 17 coordinates |
| MuJoCo MJCF scene description (`mujoco-mjcf`) | MJCF XML | worldbody, body, joint, geom, actuator, sensor, option | 5 coordinates | 18 coordinates |
| OpenUSD stage (`openusd`) | layered stage with composition arcs | stage, prim, attribute, relationship, layer, composition-arc | 3 coordinates | 20 coordinates |
| ROS 2 bag recording (`ros2-bag`) | storage plus metadata.yaml | bag, topic, message, timestamp, qos-profile | 3 coordinates | 20 coordinates |

## VSTD-HARNESS  
*On the open release branch; no behavioural adapter in this tree.*

### VSTD-HARNESS-1: Facets

`HARNESS-1.1` through `HARNESS-1.5`; topological depth 4; 2 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| HARNESS-1.1 | Channel partition | Every declared channel is partitioned into instrumented observation and named uninstrumented gap. | none | surface |
| HARNESS-1.2 | Record types | The user, agent and tool record types are bound. | HARNESS-1.1 | surface |
| HARNESS-1.3 | Tool registry | The registry of tool declarations is bound. | HARNESS-1.2 | none |
| HARNESS-1.4 | Side-effect channels | The declared side-effect channels are enumerated. | HARNESS-1.3 | none |
| HARNESS-1.5 | Transcript commitment shape | The shape of the ordered transcript commitment is declared. | HARNESS-1.2 | none |

### VSTD-HARNESS-2: Dynamics

`HARNESS-2.1` through `HARNESS-2.5`; topological depth 4; 4 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| HARNESS-2.1 | Record contiguity | Retained records form an uninterrupted ordered sequence. | none | messages |
| HARNESS-2.2 | Invocation pairing | Each tool invocation is paired with its response. | HARNESS-2.1 | tools |
| HARNESS-2.3 | Side-effect interleaving | Declared side effects are placed in the record order. | HARNESS-2.2 | effects |
| HARNESS-2.4 | Session advance | The session is replayed record by record. | HARNESS-2.1 | messages |
| HARNESS-2.5 | Retry and resumption | What a retry or a resumption does to the sequence is declared and evidenced. | HARNESS-2.3, HARNESS-2.4 | none |

### VSTD-HARNESS-3: Statics

`HARNESS-3.1` through `HARNESS-3.4`; topological depth 3; 4 of 4 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| HARNESS-3.1 | Gap boundary | The named uninstrumented gap is stated as a property of where the instrument was placed. | none | statics:gap |
| HARNESS-3.2 | Timestamp resolution | The clock's resolution is probed, and no ordering is admitted between events it cannot separate. | none | statics:clock |
| HARNESS-3.3 | Channel capacity | The capacity and truncation behaviour of each instrumented channel is recorded. | HARNESS-3.1 | statics:capacity |
| HARNESS-3.4 | Instrument fixity | The facts above are unchanged when the recorded session content is perturbed. | HARNESS-3.1, HARNESS-3.2, HARNESS-3.3 | statics:fixity |

### VSTD-HARNESS-4: Closure

`HARNESS-4.1` through `HARNESS-4.5`; topological depth 4; 3 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| HARNESS-4.1 | Commitment recomputation | The ordered transcript commitment is recomputed from retained bytes. | none | transcript |
| HARNESS-4.2 | Omission detection | A dropped record changes the commitment. | HARNESS-4.1 | transcript |
| HARNESS-4.3 | Substitution detection | A replaced record changes the commitment. | HARNESS-4.1 | transcript |
| HARNESS-4.4 | Reordering detection | A reordered pair changes the commitment. | HARNESS-4.2, HARNESS-4.3 | none |
| HARNESS-4.5 | Whole-session accounting | The session is wholly accounted for under the commitment. | HARNESS-4.4 | none |

### VSTD-HARNESS-5: Domain adaptation

`HARNESS-5.1` through `HARNESS-5.6`; topological depth 5; 6 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| HARNESS-5.1 | Mainstay binding | The trace and tool-protocol formats are named and version-pinned. | none | mainstay:binding |
| HARNESS-5.2 | Trace-span mapping | Records are mapped onto the mainstay's trace and span model. | HARNESS-5.1 | mainstay:layout |
| HARNESS-5.3 | Tool-protocol mapping | The tool registry and its invocations are mapped onto the mainstay's protocol. | HARNESS-5.1 | mainstay:protocol |
| HARNESS-5.4 | Gap representation | The uninstrumented gap is represented in the mainstay, or named unrepresentable there. | HARNESS-5.2, HARNESS-5.3 | mainstay:gap |
| HARNESS-5.5 | Round trip | Re-importing the mainstay export reproduces the transcript commitment. | HARNESS-5.4 | mainstay:roundtrip |
| HARNESS-5.6 | Inference upward | The residual this object carries over the mainstay is stated. | HARNESS-5.5 | mainstay:residual |

### Registered mainstays of VSTD-HARNESS

| Format | Carried in | Meta-surface entities | Expresses | Residual |
|---|---|---|---|---|
| OpenTelemetry tracing (`opentelemetry`) | OTLP trace payload | trace, span, attribute, event, link, status, resource | 4 coordinates | 15 coordinates |
| OpenTelemetry generative AI semantic conventions (`opentelemetry-genai`) | span attribute set | llm-span, tool-span, prompt-attribute, completion-attribute, token-usage | 3 coordinates | 16 coordinates |
| Model Context Protocol (`model-context-protocol`) | JSON-RPC over a transport | server, tool, resource, prompt, call, result, capability | 4 coordinates | 15 coordinates |
| HTTP Archive (`har`) | HAR log | log, entry, request, response, timing | 2 coordinates | 17 coordinates |

## VSTD-AGENT  
*On the open release branch; no behavioural adapter in this tree.*

### VSTD-AGENT-1: Facets

`AGENT-1.1` through `AGENT-1.7`; topological depth 6; 3 of 7 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| AGENT-1.1 | Harness binding | The harness certificate is re-derived from its retained bytes. | none | harness |
| AGENT-1.2 | Required channels | The channels the agent's account requires are present in the bound harness surface. | AGENT-1.1 | harness |
| AGENT-1.3 | Observation ceiling | The observation ceiling is re-derived from the bound harness and its channels. | AGENT-1.2 | harness |
| AGENT-1.4 | Decision inventory | The retained decisions are enumerated. | AGENT-1.3 | none |
| AGENT-1.5 | Declared actions | The actions the agent declares it took are bound. | AGENT-1.4 | none |
| AGENT-1.6 | Outcome contract | The contract outcomes are read against is bound. | AGENT-1.3 | none |
| AGENT-1.7 | Final claims | The agent's final claims are bound. | AGENT-1.5, AGENT-1.6 | none |

### VSTD-AGENT-2: Dynamics

`AGENT-2.1` through `AGENT-2.5`; topological depth 4; 4 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| AGENT-2.1 | Trajectory contiguity | The retained decisions form a contiguous trajectory. | none | trajectory |
| AGENT-2.2 | Decision witnessing | Each decision is witnessed by a record inside the observation ceiling. | AGENT-2.1 | trajectory |
| AGENT-2.3 | Action witnessing | Each declared action is bound to a witnessed tool invocation. | AGENT-2.2 | actions |
| AGENT-2.4 | Unwitnessed action reporting | A declared action with no witness is reported and never passed. | AGENT-2.3 | none |
| AGENT-2.5 | Trajectory advance | The trajectory is replayed decision by decision. | AGENT-2.3 | trajectory |

### VSTD-AGENT-3: Statics

`AGENT-3.1` through `AGENT-3.3`; topological depth 3; 3 of 3 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| AGENT-3.1 | Ceiling fixity | The observation ceiling is fixed by the harness, not by the agent. | none | statics:ceiling |
| AGENT-3.2 | Unknowability | What the agent could not have known is stated regardless of what it asserts it knew. | AGENT-3.1 | statics:unknowability |
| AGENT-3.3 | Declaration impotence | No agent declaration raises the ceiling, and perturbing its declarations moves none of the facts above. | AGENT-3.2 | statics:impotence |

### VSTD-AGENT-4: Closure

`AGENT-4.1` through `AGENT-4.4`; topological depth 4; 3 of 4 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| AGENT-4.1 | Outcome inventory | The complete retained outcome inventory is enumerated. | none | outcomes |
| AGENT-4.2 | Contract comparison | The inventory is compared against the bound outcome contract. | AGENT-4.1 | outcomes |
| AGENT-4.3 | Claim support | Every final claim rests only on records inside the observation ceiling. | AGENT-4.2 | claims |
| AGENT-4.4 | No unsupported claim | The agent's account of itself admits no unsupported claim. | AGENT-4.3 | none |

### VSTD-AGENT-5: Domain adaptation

`AGENT-5.1` through `AGENT-5.5`; topological depth 5; 5 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| AGENT-5.1 | Mainstay binding | The agent-loop runtime is named and version-pinned. | none | mainstay:binding |
| AGENT-5.2 | Decision-loop mapping | The trajectory is mapped onto the mainstay's loop or graph model. | AGENT-5.1 | mainstay:layout |
| AGENT-5.3 | Slot mapping | The decider slot is mapped onto the mainstay's policy binding without pinning the slot to a model. | AGENT-5.2 | mainstay:slot |
| AGENT-5.4 | Round trip | Replaying through the mainstay reproduces the retained trajectory. | AGENT-5.3 | mainstay:roundtrip |
| AGENT-5.5 | Inference upward | The residual this object carries over the mainstay is stated. | AGENT-5.4 | mainstay:residual |

### Registered mainstays of VSTD-AGENT

| Format | Carried in | Meta-surface entities | Expresses | Residual |
|---|---|---|---|---|
| LangGraph state graph (`langgraph`) | compiled graph plus checkpointer | graph, node, edge, conditional-edge, state-channel, checkpoint, thread | 4 coordinates | 15 coordinates |
| Nested run tree (`run-tree`) | LangSmith-style run records | run, parent-run, run-type, inputs, outputs, error | 3 coordinates | 16 coordinates |
| Step trajectory record (`agent-trajectory`) | trajectory JSONL | trajectory, step, thought, action, observation, terminal | 4 coordinates | 15 coordinates |
| OpenTelemetry generative AI agent spans (`opentelemetry-genai-agent`) | agent and tool span tree | agent-span, tool-span, decision-attribute, outcome-status | 3 coordinates | 16 coordinates |

## VSTD-BOT  
*On the open release branch; no behavioural adapter in this tree.*

### VSTD-BOT-1: Facets

`BOT-1.1` through `BOT-1.5`; topological depth 3; 3 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| BOT-1.1 | Agent binding | The agent certificate is re-derived from its retained bytes. | none | binding |
| BOT-1.2 | Simulation binding | The simulation certificate is re-derived from its retained bytes. | none | binding |
| BOT-1.3 | Environment bindings | Both environment certificates are re-derived, one per arm of the coupling. | BOT-1.1, BOT-1.2 | binding |
| BOT-1.4 | Coupling surface | The facets of the coupling itself, rather than of either side, are declared. | BOT-1.3 | none |
| BOT-1.5 | Operand depths | Each operand's established depth is recorded for the composition ceiling. | BOT-1.3 | none |

### VSTD-BOT-2: Dynamics

`BOT-2.1` through `BOT-2.5`; topological depth 4; 4 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| BOT-2.1 | Transition binding | Every simulation transition is bound to one retained record. | none | alignment |
| BOT-2.2 | Observation projection | Every retained observation is shown to be the simulation's own projection of that state. | BOT-2.1 | observation |
| BOT-2.3 | Action authenticity | Every replayed action is shown to be one the agent actually invoked. | BOT-2.1 | actuation |
| BOT-2.4 | One-to-one coupling | No transition lacks a record and no record lacks a transition. | BOT-2.2, BOT-2.3 | alignment |
| BOT-2.5 | Coupling advance | The coupled run is replayed step by step. | BOT-2.4 | none |

### VSTD-BOT-3: Statics

`BOT-3.1` through `BOT-3.4`; topological depth 3; 4 of 4 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| BOT-3.1 | Inherited ceiling | The observation ceiling exists whatever the agent claims about it. | none | statics:inherited |
| BOT-3.2 | Coupling latency | The latency and ordering the coupling imposes are probed from the retained action and effect times. | none | statics:latency |
| BOT-3.3 | Disclosure limit | The information the simulation cannot expose regardless of policy is stated. | BOT-3.1 | statics:disclosure |
| BOT-3.4 | Policy impotence | The facts above are unchanged when either side's policy is perturbed. | BOT-3.2, BOT-3.3 | statics:impotence |

### VSTD-BOT-4: Closure

`BOT-4.1` through `BOT-4.4`; topological depth 3; 3 of 4 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| BOT-4.1 | Separation declaration | The agent and simulator execution environments are declared separate or fused. | none | containment |
| BOT-4.2 | Separation evidence | A separate declaration is evidenced by the two bound environment certificates. | BOT-4.1 | containment |
| BOT-4.3 | Fused honesty | A fused declaration is honest and yields UNKNOWN, never FAIL. | BOT-4.1 | containment |
| BOT-4.4 | Containment accounting | Containment is established or explicitly not established, and never assumed. | BOT-4.2, BOT-4.3 | none |

### VSTD-BOT-5: Domain adaptation

`BOT-5.1` through `BOT-5.6`; topological depth 5; 6 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| BOT-5.1 | Interaction-graph binding | The interaction graph over the bound simulation's interaction surface is bound. | none | mainstay:interaction |
| BOT-5.2 | Disclosure inventory | What the composed object discloses about itself is enumerated. | BOT-5.1 | mainstay:disclosed |
| BOT-5.3 | Indisclosure inventory | What it does not disclose is named as unestablished rather than absent. | BOT-5.2 | mainstay:indisclosed |
| BOT-5.4 | Inclusion awareness | Whether it is aware of being inside a simulation, and to what degree, is recorded. | BOT-5.2 | mainstay:inclusion |
| BOT-5.5 | Specification awareness | Which simulation specification surfaces it is aware of is recorded. | BOT-5.4 | mainstay:awareness |
| BOT-5.6 | Awareness accounting | Disclosed and indisclosed awareness are accounted for without inferring either from the other. | BOT-5.3, BOT-5.5 | mainstay:accounting |

### Registered mainstays of VSTD-BOT

| Format | Carried in | Meta-surface entities | Expresses | Residual |
|---|---|---|---|---|
| Interaction graph over a bound simulation surface (`embodied-interaction-graph`) | composed agent trajectory and simulation trace | interaction-node, observation-edge, action-edge, disclosure-set, indisclosure-set, awareness-level | 4 coordinates | 14 coordinates |
| Unified Robot Description Format (`urdf`) | URDF or SDFormat model | robot, link, joint, inertial, collision, transmission | 3 coordinates | 15 coordinates |

## VSTD-OWNER

A **relational** object. It does not certify a substrate of its own; it certifies a
holding that stands *between* a bound actor and a bound object. Of the three
relational objects -- `VSTD-GRAPH`, `VSTD-HYPER` and `VSTD-OWNER` -- only this one is
**ungrounded**: no adapter executes it, so every obligation below is specified with no
mechanism and reports `UNKNOWN`. That is the honest report of a specified holding that
nothing yet checks, and it is why `OWNER` is excluded from the grounded-object
invariants that require tiers 3 and 5 to be mechanized.

The holder is bound by the actor-binding token `VSTD-ACTOR-BINDING-1`, already
specified in [`VSTD-ZIZK-TOKENS.md`](VSTD-ZIZK-TOKENS.md), so a holding names a bound
actor rather than a string. A holding never reaches a verdict: `OWNER-3.1` makes that
normative, and it is the ownership twin of the Prime Invariant.

### VSTD-OWNER-1: Facets

`OWNER-1.1` through `OWNER-1.6`; topological depth 4; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| OWNER-1.1 | Holder binding | The holder is bound as an actor by an actor-binding token, never named in free text. | none | none |
| OWNER-1.2 | Held-object binding | The held object is bound by its own object certificate at a stated coordinate. | none | none |
| OWNER-1.3 | Limb inventory | Every limb of the holding is enumerated, and a limb the inventory omits is unheld rather than permitted. | OWNER-1.1, OWNER-1.2 | none |
| OWNER-1.4 | Instrument | The instrument that establishes the holding is bound together with the authority that issued it. | OWNER-1.3 | none |
| OWNER-1.5 | Term | The holding's start, and its end or its declared non-expiry, are stated on the instrument's own clock. | OWNER-1.4 | none |
| OWNER-1.6 | Bearer capability | The holder's kind scopes which limbs it can bear, and a limb its kind cannot bear is unheld rather than held and unexercised. | OWNER-1.1, OWNER-1.3 | none |

### VSTD-OWNER-2: Dynamics

`OWNER-2.1` through `OWNER-2.6`; topological depth 4; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| OWNER-2.1 | Event declaration | Every event that changes the holding is declared with its instrument and its position in the order. | none | none |
| OWNER-2.2 | Transfer conveyance | Each declared transfer conveys only the limbs the transferor held at that position in the order. | OWNER-2.1 | none |
| OWNER-2.3 | Delegation bound | Each delegation conveys a subset of the delegator's limbs and leaves the delegator's own holding intact. | OWNER-2.1 | none |
| OWNER-2.4 | Revocation effect | Each revocation withdraws exactly the limbs it names, from the position in the order at which it takes effect. | OWNER-2.2, OWNER-2.3 | none |
| OWNER-2.5 | Lapse | A holding whose term has ended lapses by the clock rather than by an event, and lapse is distinguished from revocation. | OWNER-2.1 | none |
| OWNER-2.6 | Ordered replay | Replaying the declared events from the origin in the declared order reproduces the current holding. | OWNER-2.4, OWNER-2.5 | none |

### VSTD-OWNER-3: Statics

`OWNER-3.1` through `OWNER-3.6`; topological depth 3; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| OWNER-3.1 | Verdict independence | The holding never changes any verdict the held object's own certificate reaches. | none | none |
| OWNER-3.2 | Evidence immutability | Ownership events never alter, retract or re-date the held object's evidence. | OWNER-3.1 | none |
| OWNER-3.3 | Ancestry immutability | Ownership events never alter the held object's ancestry or its coordinate. | OWNER-3.1 | none |
| OWNER-3.4 | Asymmetry | Holding is asymmetric: two holders cannot hold the same limb over the same object at the same position in the order unless that limb is declared shared. | none | none |
| OWNER-3.5 | Non-transitivity of authority | Holding an object confers no holding over the objects it was composed from, nor over the objects composed from it. | OWNER-3.4 | none |
| OWNER-3.6 | Duty-only over an actor | Where the held object is itself an actor, only the duty limb is holdable and every other limb is unheld. | OWNER-3.4, OWNER-3.5 | none |

### VSTD-OWNER-4: Closure

`OWNER-4.1` through `OWNER-4.5`; topological depth 4; 0 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| OWNER-4.1 | Chain origin | The chain of holdings begins at a declared origin whose instrument is bound. | none | none |
| OWNER-4.2 | Gapless chain | Every position in the order between the origin and the head is covered by exactly one holding. | OWNER-4.1 | none |
| OWNER-4.3 | Fork detection | No two holdings claim the same limb over the same object at the same position, and a fork is reported rather than resolved. | OWNER-4.2 | none |
| OWNER-4.4 | Admissibility at issue time | Each instrument is admissible under the authority in force when it issued, not under the authority in force now. | OWNER-4.1 | none |
| OWNER-4.5 | Closure result | The chain is closed only when origin, gaplessness, fork-freedom and admissibility at issue time all hold; otherwise the result is UNKNOWN and never FAIL. | OWNER-4.2, OWNER-4.3, OWNER-4.4 | none |

### VSTD-OWNER-5: Domain adaptation

`OWNER-5.1` through `OWNER-5.6`; topological depth 3; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| OWNER-5.1 | Licence holding | Licence holdings over a corpus or a model are bound per source, and the composite redistribution term is the meet of its sources. | none | none |
| OWNER-5.2 | Registry maintainer record | Package-registry maintainer and owner records are bound as holdings, with the registry as the issuing authority. | none | none |
| OWNER-5.3 | Register entry | Corporate and beneficial-ownership register entries are bound as holdings, with the register as the issuing authority. | none | none |
| OWNER-5.4 | Declared code ownership | Declared repository code-ownership entries are bound as delegated review duties, never as transferable limbs. | OWNER-5.2 | none |
| OWNER-5.5 | Custody chain | Physical and cryptographic custody transfers are bound as ordered events on the custody clock. | none | none |
| OWNER-5.6 | Adaptation accounting | Each adaptation above is reported as established or unestablished, and an absent register is unestablished rather than unheld. | OWNER-5.1, OWNER-5.2, OWNER-5.3, OWNER-5.4, OWNER-5.5 | none |

### Registered mainstays of VSTD-OWNER

None. A mainstay is a representation a domain already publishes in, bound by an
executing adapter; `VSTD-OWNER` has no adapter, so it registers none. The formats its
tier 5 names -- licence expressions, registry maintainer records, corporate and
beneficial-ownership registers, declared code ownership and custody chains -- are
named as unestablished rather than registered.
## Depth, not count

`m` in `VSTD-<object>-<tier>.<m>` is the depth of complete modules represented, so the
largest `m` a certificate can reach for a numbered profile is that profile's topological
depth -- the longest chain of obligations each of which is a prerequisite of the next --
and not the number of obligations it holds. Where the two differ, the coordinates above
the depth are unreachable. `verifier.core.profile_obligations.tier_depth` computes it.
