# Grounded certification obligations of the seventeen domain objects

> **Acronyms:** artificial intelligence (AI);
> benchmark specification graph (BENCH);
> Concise Binary Object Representation (CBOR);
> CBOR Object Signing and Encryption (COSE);
> dataset integrity and lineage (DATA);
> directed acyclic graph (DAG);
> Extensible Markup Language (XML);
> generative simulation specification (SIM);
> Hypertext Transfer Protocol (HTTP);
> JavaScript Object Notation (JSON);
> JSON Lines (JSONL);
> JSON Object Signing and Encryption (JOSE);
> JSON Web Signature (JWS);
> JSON Web Token (JWT);
> model reproducibility specification (MODEL);
> object composition specification (HYPER);
> Secure Production Identity Framework for Everyone (SPIFFE);
> Software Package Data Exchange (SPDX);
> SPIFFE verifiable identity document (SVID);
> Stable High-Level Optimizer (StableHLO);
> training run specification (TRAIN);
> Verifier Standard (VSTD);
> verifiable execution environment (ENV);
> YAML Ain't Markup Language (YAML);
> zero-identity zero-knowledge token (TOKEN).

**Status:** project specification (normative for the seventeen domain objects' obligations)
**Editor:** TimeLordRaps
**License:** Apache-2.0
**Date:** 2026-09-21

The object axis carries `1.1`-`5.11` and the Graph axis carries `GRAPH-1.1`-`GRAPH-5.6`;
neither carries a level 6, because both are corroboration ladders and disclosure has no
rungs. Level 6 exists on the domain objects only.
This file carries the third namespace: the seventeen domain objects, coordinate
`<object>-<tier>.<index>`, 626 obligations. The three namespaces are disjoint.
`DATA-4.2` never aliases `4.2` or `GRAPH-4.2`, no catalogue admits another's identifiers,
and each carries its own digest, so extending one cannot move another.

**Ten of the seventeen are certifiable, and the partition has three parts rather than
two.** A *behavioural* adapter is keyed in `verifier.domains.catalog.CHECKS`, and
`build_domain_certificate` rejects any domain absent from it, so those ten -- `DATA`,
`ENV`, `BENCH`, `TRAIN`, `MODEL`, `SIM`, `HARNESS`,
`AGENT`, `BOT` and `TOKEN` -- are the objects a domain certificate can be built for at
all.

`HYPER` is **catalogued but not certifiable**. Its statics and adaptation
mechanisms resolve and execute, so 10 of its 33 obligations are mechanized, but it has
no behavioural adapter and no `CHECKS` entry, so no certificate over it can be produced
at all, and its facets, dynamics and closure obligations are specified with no mechanism.
**Partial mechanization is not grounding.** That distinction is invisible in a two-part
partition, which is how `HYPER` came to be published as the most heavily mechanized
object on the axis while no certificate over it could be built at all.

The other six -- `OWNER` and the five identity objects `HUMAN`, `ROLE`,
`COLLECTIVE`, `IDENTITY` and `ACTOR` -- are **ungrounded**: no adapter
executes them in any family, so all 216 of their obligations report `UNKNOWN`.

**A mechanism name is a promise that something executes it.** Every name in the
**mechanism** column is resolved against the registered checks of that obligation's own
object. Resolution is object-scoped deliberately: a name that resolves under a different
object resolves to the wrong check.

**Ungrounded and relational are independent properties.** A relational object holds
*between* certified objects instead of certifying a substrate of its own; the relational
objects are `GRAPH`, `HYPER`, `OWNER` and `IDENTITY`, of which the
first carries its own axis and the other three sit on this one. `HYPER` is
relational and grounded; `HUMAN`, `ROLE`, `COLLECTIVE` and `ACTOR`
are ungrounded and not relational -- an actor is a party, not a relation between
certified objects, even though it is the operand `OWNER` holds against. Until the identity family was catalogued the two properties could not
be distinguished here, because `OWNER` was the only ungrounded object and it was
relational too -- a containment that held by coincidence of there being one.

Each obligation binds a predicate `vstd.<object>.obligation.<tier>.<index>`. The
**mechanism** column names the check that establishes the obligation. An obligation
with no mechanism is specified and unmechanized: it is reported `UNKNOWN`, never absent
and never passed. Dependencies are within one numbered profile; cumulative profile
prerequisites apply across tiers as they do on both other axes.

## Tiers 1-5 corroborate; level 6 discloses

Tiers 1 through 5 are a **corroboration ladder**. Each rung is evidence that raises
what the object is known to satisfy, every rung is settled by the act of certifying,
and the rung totals and composition figures in
[`META_TIERS.md`](META_TIERS.md) count reachable states on that ladder.

**Level 6 is not a rung.** It bounds what a certificate may *emit* rather than what it
establishes. Three things follow, and each is a row below:

- It runs on a different clock. Every other level is decided once, when the object is
  certified; a disclosure bound is decided again at **every emission** of the
  certificate (`<object>-6.4`), so a certificate that was admissible when it was made
  can stop being admissible without anything about the object changing.
- It is the only level that is **not monotone under composition**. Everywhere else a
  composition is bounded by its operands; disclosure is the **join** of its operands
  and is bounded by neither, so two certificates each strictly within bound can compose
  to one that is not (`<object>-6.5`, stated in general at `HYPER-6.5`).
- It **cannot move a verdict**. `<object>-6.6` is the twin of the Prime Invariant: a
  disclosure bound never changes a computational verdict, neither upward nor downward.
  Redaction that moves a result makes the certificate malformed rather than private.
  This is also why level 6 is excluded from the rung totals -- a level that by its own
  statement cannot change what is established is not evidence, and counting it as a
  rung would inflate every reachability figure the grid publishes.

Four of the six rows -- `6.2`, `6.3`, `6.4` and `6.6` -- are the **same proposition at
every object**, and that uniformity is the argument that disclosure is a level rather
than an object of its own: an object contributes rows that differ, a level contributes the
same row everywhere. Only `6.1` (what this object emits) and `6.5` (what composing it
reveals) are object-specific. All 96 rows are specified with no mechanism and
report `UNKNOWN`: no adapter runs at emission time, and no observer model is
established anywhere in the implementation, so a `PASS` here would be a claim nothing
supports. Level 6 therefore adds no module to `verifier.domains` and **does not move**
`implementation_digest()`.

## Three mechanism families

A mechanism name is prefixed by the family it belongs to, and the three families are
disjoint. They differ in what kind of evidence can establish an obligation at all.

| Family | Prefix | What establishes an obligation | Where | Bound |
|---|---|---|---|---|
| Behavioural | *(none)* | Re-executing what the subject declared: rehash, replay, recompute | [`DOMAIN_GROUNDING.md`](DOMAIN_GROUNDING.md) | 123 |
| Statics | `statics:` | A witness probe, a recomputation over the retained inventory, or invariance under perturbation of the subject's own choices | this file, tier 3 | 41 |
| Adaptation | `mainstay:` | Binding, mapping, round trip and residual against a named mainstay representation of the domain | this file, tier 5 | 72 |

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

## DATA

### DATA-1: Facets

`DATA-1.1` through `DATA-1.6`; topological depth 4; 5 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| DATA-1.1 | Retention boundary | The boundary between what was kept and what was seen is declared, with the discarded volume stated. | none | none |
| DATA-1.2 | Shard and record inventory | Every retained shard and record is enumerated and rehashed, and byte and count commitments are recomputed. | DATA-1.1 | inventory |
| DATA-1.3 | Record identity | Each retained record carries a stable identity that is unique within the inventory. | DATA-1.2 | inventory |
| DATA-1.4 | Field contract | The declared field types and required columns are bound for every retained record. | DATA-1.1 | schema |
| DATA-1.5 | Schema conformance | Each retained record is checked against the bound field contract. | DATA-1.3, DATA-1.4 | schema |
| DATA-1.6 | Digest tree commitment | The inventory's digest tree is recomputed from retained bytes and compared with the declared root. | DATA-1.2 | inventory |

### DATA-2: Dynamics

`DATA-2.1` through `DATA-2.6`; topological depth 4; 3 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| DATA-2.1 | Transformation declaration | Every declared transformation is bound with its inputs, outputs and position in the order. | none | lineage |
| DATA-2.2 | Exact re-execution | Each declared transformation is re-executed and its exact output compared. | DATA-2.1 | lineage |
| DATA-2.3 | Pipeline ordering | Applying the transformations in the declared order reproduces the retained corpus. | DATA-2.2 | lineage |
| DATA-2.4 | Idempotence | Re-applying the pipeline to its own output changes nothing, or the change is localized. | DATA-2.3 | none |
| DATA-2.5 | Raw-to-retained path | Every retained record is traced to a raw input through the executed transformations. | DATA-2.2 | none |
| DATA-2.6 | Rebuild drift | A second rebuild is compared against the retained corpus and any divergence is localized. | DATA-2.3, DATA-2.5 | none |

### DATA-3: Statics

`DATA-3.1` through `DATA-3.6`; topological depth 3; 6 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| DATA-3.1 | Sampling frame | The population sampled from, and the frame's coverage of it, are witnessed by a party other than the retaining pipeline. | none | statics:frame |
| DATA-3.2 | Measurement instrument | The unit and resolution of each measured field are witnessed, and every retained value lies on that resolution and inside its range. | none | statics:instrument |
| DATA-3.3 | Censoring and truncation | Censoring and truncation are declared and evidenced against the retained distribution. | DATA-3.1, DATA-3.2 | statics:censoring |
| DATA-3.4 | Distribution statics | Class balance, cardinality and entropy are recomputed over the retained inventory. | DATA-3.1 | statics:distribution |
| DATA-3.5 | Origin rights | Licence and legal facts of origin are bound per source, and the composite redistribution term is the meet of its sources. | none | statics:rights |
| DATA-3.6 | Pipeline independence | The facts above are unchanged when the retaining pipeline's declarations are perturbed. | DATA-3.3, DATA-3.4, DATA-3.5 | statics:independence |

### DATA-4: Closure

`DATA-4.1` through `DATA-4.6`; topological depth 5; 5 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| DATA-4.1 | Split declaration | Every split is named with its membership predicate. | none | splits |
| DATA-4.2 | Complete membership | Every retained record is assigned to exactly one declared split. | DATA-4.1 | splits |
| DATA-4.3 | Identity separation | No record identity appears in two splits. | DATA-4.2 | splits |
| DATA-4.4 | Exact overlap | Exact train and evaluation overlap is recomputed over the complete inventory. | DATA-4.2 | overlap |
| DATA-4.5 | Lexical overlap | Near-duplicate overlap is recomputed under the declared similarity bound. | DATA-4.4 | overlap |
| DATA-4.6 | No unaccounted record | The inventory admits no record outside the declared splits and retention boundary. | DATA-4.3, DATA-4.5 | none |

### DATA-5: Domain adaptation

`DATA-5.1` through `DATA-5.6`; topological depth 4; 6 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| DATA-5.1 | Mainstay binding | The columnar or catalogue representation the dataset is published in is named and version-pinned. | none | mainstay:binding |
| DATA-5.2 | Columnar shard mapping | The retained shard inventory is mapped onto the mainstay's physical layout. | DATA-5.1 | mainstay:layout |
| DATA-5.3 | Schema mapping | The bound field contract is mapped onto the mainstay's type system, with unrepresentable types named. | DATA-5.1 | mainstay:schema |
| DATA-5.4 | Dataset card mapping | Declared provenance, licence and statics are mapped onto the mainstay's metadata record. | DATA-5.1 | mainstay:metadata |
| DATA-5.5 | Round trip | Export and re-import reproduces the retained inventory byte for byte, or names its loss. | DATA-5.2, DATA-5.3, DATA-5.4 | mainstay:roundtrip |
| DATA-5.6 | Inference upward | What the mainstay cannot express is stated as the residual this object carries over it. | DATA-5.5 | mainstay:residual |

### Registered mainstays of DATA

| Format | Carried in | Meta-surface entities | Expresses | Residual |
|---|---|---|---|---|
| Apache Parquet (`apache-parquet`) | file footer FileMetaData | file, row-group, column-chunk, page, column-statistics | 5 coordinates | 19 coordinates |
| Apache Arrow inter-process communication (`apache-arrow-ipc`) | stream or file format | schema, record-batch, buffer, dictionary | 3 coordinates | 21 coordinates |
| WebDataset tar shards (`webdataset`) | POSIX tar shard sequence | shard, sample, member | 3 coordinates | 21 coordinates |
| MLCommons Croissant (`mlcommons-croissant`) | JSON-LD metadata record | Dataset, RecordSet, Field, FileObject, FileSet, Distribution | 8 coordinates | 16 coordinates |
| Hugging Face datasets (`huggingface-datasets`) | dataset_infos.json and card front matter | DatasetInfo, Features, Split, DownloadChecksum | 5 coordinates | 19 coordinates |
| Apache Iceberg table format (`apache-iceberg`) | metadata.json, manifest lists and manifests | table, snapshot, manifest, data-file, partition-spec | 5 coordinates | 19 coordinates |

### DATA-6: Disclosure

`DATA-6.1` through `DATA-6.6`; topological depth 5; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| DATA-6.1 | Disclosure surface | What the certificate emits about this object is enumerated -- counts, digests, the bound field contract, split membership and distribution statics -- and is separated from the retained record contents those figures were computed over. | none | none |
| DATA-6.2 | Bound declaration | Every field enumerated at 6.1 carries a declared disclosure bound naming the observers it is admissible to; a field emitted without a bound is not admissible, and the absence of a bound is never read as an open one. | DATA-6.1 | none |
| DATA-6.3 | Observer identification | The observer each bound is stated against is identified as a party rather than as a channel, since a channel can be relayed and a party cannot; where no observer model is established the level reports UNKNOWN and never PASS. | DATA-6.1 | none |
| DATA-6.4 | Emission-time evaluation | Each bound is evaluated at every emission of the certificate rather than once when the certificate was made. A bound satisfied at certification and violated at a later emission is not satisfied, and this is the only level in the grid that is not settled by the act of certifying. | DATA-6.2, DATA-6.3 | none |
| DATA-6.5 | Composition delta | Emitting this certificate beside another DATA certificate over an overlapping corpus discloses the intersection: two split memberships and two inventories can each be within bound while the pair identifies which records are shared, so the join is evaluated against both operands and not against either alone. | DATA-6.2, DATA-6.4 | none |
| DATA-6.6 | Verdict independence | Redacting any emitted field to satisfy its bound leaves every verdict this object carries at tiers 1 through 5 unchanged. A disclosure bound never changes a computational verdict -- neither upward nor downward -- and a redaction that moves one makes the certificate malformed rather than more private. | DATA-6.2, DATA-6.4, DATA-6.5 | none |

## ENV

### ENV-1: Facets

`ENV-1.1` through `ENV-1.6`; topological depth 4; 4 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| ENV-1.1 | Environment boundary | What is inside the environment and what is host is declared. | none | none |
| ENV-1.2 | Software inventory | Every file in the selected software inventory is materialized and rehashed. | ENV-1.1 | closure |
| ENV-1.3 | Executable coordinates | The entry point, interpreter and their versions are bound. | ENV-1.2 | closure |
| ENV-1.4 | Configuration surface | The complete required configuration is declared with its value domain. | ENV-1.1 | configuration |
| ENV-1.5 | Observed configuration | Retained collector observations are compared with the required configuration surface. | ENV-1.4 | configuration |
| ENV-1.6 | Unpinned residue | Every inventory element without a pinned digest is named rather than assumed absent. | ENV-1.2, ENV-1.5 | none |

### ENV-2: Dynamics

`ENV-2.1` through `ENV-2.6`; topological depth 4; 3 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| ENV-2.1 | Nondeterminism declaration | Every nondeterminism source -- clock, entropy, thread interleaving, allocator -- is declared. | none | none |
| ENV-2.2 | Scheduling surface | Concurrency and scheduling policy are bound for the retained executions. | ENV-2.1 | none |
| ENV-2.3 | Execution pair | Two retained executions are bound with their inputs, coordinates and results. | none | reproduction |
| ENV-2.4 | Input agreement | The two executions are compared input for input. | ENV-2.3 | reproduction |
| ENV-2.5 | Result agreement | The two executions are compared result for result and divergence is localized. | ENV-2.4 | reproduction |
| ENV-2.6 | Divergence attribution | Each divergence is attributed to a declared nondeterminism source or reported unattributed. | ENV-2.1, ENV-2.2, ENV-2.5 | none |

### ENV-3: Statics

`ENV-3.1` through `ENV-3.5`; topological depth 3; 1 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| ENV-3.1 | Instruction set | The architecture and its extension set are observed rather than declared. | none | none |
| ENV-3.2 | Floating-point semantics | Format, rounding mode and fused-operation behaviour are observed on the executing machine. | ENV-3.1 | none |
| ENV-3.3 | Resource ceilings | Retained resource measurements are checked against the exact declared ceilings. | none | resources |
| ENV-3.4 | Physical envelope | Memory, clock, thermal and power limits of the machine are recorded. | ENV-3.3 | none |
| ENV-3.5 | Envelope independence | The envelope holds whether or not the specification declares it. | ENV-3.1, ENV-3.2, ENV-3.4 | none |

### ENV-4: Closure

`ENV-4.1` through `ENV-4.5`; topological depth 4; 0 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| ENV-4.1 | Pin completeness | Nothing in the inventory resolves outside the pinned set. | none | none |
| ENV-4.2 | Host isolation | No implicit host state -- environment variables, paths, network, wall clock -- leaks into the execution. | ENV-4.1 | none |
| ENV-4.3 | Network closure | Every external fetch is either pinned by digest or declared absent. | ENV-4.1 | none |
| ENV-4.4 | Standup sufficiency | A second party can stand the environment up from the record alone. | ENV-4.2, ENV-4.3 | none |
| ENV-4.5 | Standup evidence | A retained independent standup is compared against the original. | ENV-4.4 | none |

### ENV-5: Domain adaptation

`ENV-5.1` through `ENV-5.6`; topological depth 5; 6 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| ENV-5.1 | Mainstay binding | The image, derivation or lockfile format is named and version-pinned. | none | mainstay:binding |
| ENV-5.2 | Image closure mapping | The inventory is mapped onto the mainstay's layer or store-path model. | ENV-5.1 | mainstay:layout |
| ENV-5.3 | Derivation mapping | The build steps are mapped onto the mainstay's derivation or recipe model. | ENV-5.1 | mainstay:recipe |
| ENV-5.4 | Build provenance mapping | The provenance attestation is mapped onto the mainstay's attestation format. | ENV-5.2, ENV-5.3 | mainstay:attestation |
| ENV-5.5 | Round trip | Rebuilding from the mainstay representation reproduces the pinned inventory. | ENV-5.4 | mainstay:roundtrip |
| ENV-5.6 | Inference upward | What the mainstay cannot pin is stated as the residual this object carries over it. | ENV-5.5 | mainstay:residual |

### Registered mainstays of ENV

| Format | Carried in | Meta-surface entities | Expresses | Residual |
|---|---|---|---|---|
| Open Container Initiative image (`oci-image`) | image index, manifest and config descriptors | index, manifest, config, layer, annotation | 4 coordinates | 18 coordinates |
| Nix derivation (`nix-derivation`) | .drv store object | derivation, input-derivation, input-source, output-path, builder, environment | 7 coordinates | 15 coordinates |
| Resolved dependency lockfile (`lockfile`) | uv.lock, poetry.lock or hashed requirements | package, version, artifact-hash, marker, resolution | 3 coordinates | 19 coordinates |
| Software bill of materials (`sbom`) | SPDX or CycloneDX document | component, relationship, licence, supplier | 4 coordinates | 18 coordinates |
| in-toto attestation (`in-toto-attestation`) | DSSE envelope over a predicate | statement, subject, predicate, builder, material, byproduct | 5 coordinates | 17 coordinates |

### ENV-6: Disclosure

`ENV-6.1` through `ENV-6.6`; topological depth 5; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| ENV-6.1 | Disclosure surface | What the certificate emits about this object is enumerated -- the software inventory, executable coordinates, configuration surface, instruction set and resource ceilings -- and is separated from host identifiers, operator accounts and network topology the adapter observed but does not emit. | none | none |
| ENV-6.2 | Bound declaration | Every field enumerated at 6.1 carries a declared disclosure bound naming the observers it is admissible to; a field emitted without a bound is not admissible, and the absence of a bound is never read as an open one. | ENV-6.1 | none |
| ENV-6.3 | Observer identification | The observer each bound is stated against is identified as a party rather than as a channel, since a channel can be relayed and a party cannot; where no observer model is established the level reports UNKNOWN and never PASS. | ENV-6.1 | none |
| ENV-6.4 | Emission-time evaluation | Each bound is evaluated at every emission of the certificate rather than once when the certificate was made. A bound satisfied at certification and violated at a later emission is not satisfied, and this is the only level in the grid that is not settled by the act of certifying. | ENV-6.2, ENV-6.3 | none |
| ENV-6.5 | Composition delta | Emitting this certificate beside a TRAIN or MODEL certificate discloses the machine: a pinned toolchain and a pinned resource ceiling are each ordinary in isolation and together name one fleet, so the join is evaluated against both operands and not against either alone. | ENV-6.2, ENV-6.4 | none |
| ENV-6.6 | Verdict independence | Redacting any emitted field to satisfy its bound leaves every verdict this object carries at tiers 1 through 5 unchanged. A disclosure bound never changes a computational verdict -- neither upward nor downward -- and a redaction that moves one makes the certificate malformed rather than more private. | ENV-6.2, ENV-6.4, ENV-6.5 | none |

## BENCH

### BENCH-1: Facets

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

### BENCH-2: Dynamics

`BENCH-2.1` through `BENCH-2.6`; topological depth 4; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| BENCH-2.1 | Attempt policy | Repeated attempts and best-of-N selection are declared and bounded per problem. | none | none |
| BENCH-2.2 | Attempt inventory | Every attempt is retained; none is discarded on selection. | BENCH-2.1 | none |
| BENCH-2.3 | Sequential adaptivity | Whether later problems depend on earlier results is declared and evidenced. | BENCH-2.2 | none |
| BENCH-2.4 | Contamination accumulation | Corpus exposure is accumulated against a dated boundary rather than assumed absent. | none | none |
| BENCH-2.5 | Response curve | Score as a function of budget is recomputed over the retained attempts. | BENCH-2.2 | none |
| BENCH-2.6 | Measurement feedback | The effect of publication on the systems measured is declared as an uncontrolled dynamic. | BENCH-2.3, BENCH-2.4, BENCH-2.5 | none |

### BENCH-3: Statics

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

### BENCH-4: Closure

`BENCH-4.1` through `BENCH-4.5`; topological depth 4; 4 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| BENCH-4.1 | Run inventory | One retained run per problem is enumerated. | none | coverage |
| BENCH-4.2 | No missing run | Every problem in the bound set has a retained run. | BENCH-4.1 | coverage |
| BENCH-4.3 | No duplicate or substituted run | Each run binds to exactly one problem specification. | BENCH-4.1 | coverage |
| BENCH-4.4 | Weighted score | The weighted score is recomputed over the complete inventory under the declared weights. | BENCH-4.2, BENCH-4.3 | coverage |
| BENCH-4.5 | Surface completeness | The scored set covers the whole declared measurement surface. | BENCH-4.4 | none |

### BENCH-5: Domain adaptation

`BENCH-5.1` through `BENCH-5.6`; topological depth 5; 6 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| BENCH-5.1 | Mainstay binding | The evaluation harness or task-specification format is named and version-pinned. | none | mainstay:binding |
| BENCH-5.2 | Task specification mapping | Problems and oracles are mapped onto the mainstay's task record. | BENCH-5.1 | mainstay:layout |
| BENCH-5.3 | Scoring contract mapping | Weights, aggregation and reporting are mapped onto the mainstay's metric contract. | BENCH-5.1 | mainstay:schema |
| BENCH-5.4 | Budget mapping | Problem ceilings are mapped onto the mainstay's limit model. | BENCH-5.2 | mainstay:limits |
| BENCH-5.5 | Round trip | Running the mainstay's export reproduces the retained scores. | BENCH-5.2, BENCH-5.3, BENCH-5.4 | mainstay:roundtrip |
| BENCH-5.6 | Inference upward | What the mainstay cannot express is stated as the residual this object carries over it. | BENCH-5.5 | mainstay:residual |

### Registered mainstays of BENCH

| Format | Carried in | Meta-surface entities | Expresses | Residual |
|---|---|---|---|---|
| EleutherAI language model evaluation harness (`lm-evaluation-harness`) | task YAML | task, dataset-reference, document-template, metric, filter, fewshot-context | 5 coordinates | 20 coordinates |
| Stanford Holistic Evaluation of Language Models (`helm`) | run specification records | RunSpec, Scenario, Adapter, Metric, Instance, Reference | 6 coordinates | 19 coordinates |
| BIG-bench task (`bigbench`) | task.json or programmatic task | task, example, metric, keyword | 3 coordinates | 22 coordinates |
| SWE-bench instance record (`swe-bench`) | instance JSONL | instance, repository, base-commit, patch, test-patch, test-status-set | 6 coordinates | 19 coordinates |
| MLPerf result log (`mlperf`) | result summary and detail logs | benchmark, scenario, division, system, result, constraint | 4 coordinates | 21 coordinates |

### BENCH-6: Disclosure

`BENCH-6.1` through `BENCH-6.6`; topological depth 5; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| BENCH-6.1 | Disclosure surface | What the certificate emits about this object is enumerated -- the problem set identity, sampling procedure, scoring contract, budget ceilings and per-run outcomes -- and is separated from the oracle answers, which the adapter binds and never emits. | none | none |
| BENCH-6.2 | Bound declaration | Every field enumerated at 6.1 carries a declared disclosure bound naming the observers it is admissible to; a field emitted without a bound is not admissible, and the absence of a bound is never read as an open one. | BENCH-6.1 | none |
| BENCH-6.3 | Observer identification | The observer each bound is stated against is identified as a party rather than as a channel, since a channel can be relayed and a party cannot; where no observer model is established the level reports UNKNOWN and never PASS. | BENCH-6.1 | none |
| BENCH-6.4 | Emission-time evaluation | Each bound is evaluated at every emission of the certificate rather than once when the certificate was made. A bound satisfied at certification and violated at a later emission is not satisfied, and this is the only level in the grid that is not settled by the act of certifying. | BENCH-6.2, BENCH-6.3 | none |
| BENCH-6.5 | Composition delta | Repeated emission is itself composition: each emitted outcome vector is a bounded observation of the oracle, and a sufficient number of them reconstructs it. The bound is therefore evaluated over the accumulated sequence of emissions rather than over one, and a bound that holds for every single emission while the sequence reconstructs the oracle is not satisfied. | BENCH-6.2, BENCH-6.4 | none |
| BENCH-6.6 | Verdict independence | Redacting any emitted field to satisfy its bound leaves every verdict this object carries at tiers 1 through 5 unchanged. A disclosure bound never changes a computational verdict -- neither upward nor downward -- and a redaction that moves one makes the certificate malformed rather than more private. | BENCH-6.2, BENCH-6.4, BENCH-6.5 | none |

## TRAIN

**TRAIN is a composition, and it is a member of the VSTD-NAMESPACE.** The namespace is
`VSTD` plus eighteen objects, and TRAIN is one of them -- admitted 2026-09-22. A
training run is `HYPER(VSTD, MODEL, DATA, ENV, SIM, BENCH, GRAPH)` indexed by a
`GRAPH-1` recorded lineage, where `VSTD` is the model and training-loop algorithms and
`GRAPH-1` carries the order the data was consumed in -- the one fact no operand states,
since `DATA` certifies what the corpus is and never the sequence it was read in.

`GRAPH` is there twice, in two roles. As the index it is the data order; as an operand it
is the architecture of the model or algorithm being trained, with its layers as members
and its operators as the relation between them. The Graph axis has no vocabulary for the
second role yet: the artifact and transformation types of `GRAPH-1` are provenance kinds,
and none of them names a layer or an operator. Until one does, the architecture travels in
TRAIN's own evidence as the `architecture` field every checkpoint is checked against, and
no `GRAPH` certificate over an architecture can be built.

The obligations below are what that composition must satisfy. Being written over other
objects is a property TRAIN has, not a reason it is not one.

This is also why TRAIN is certifiable, which it was not recorded as being until
2026-09-22. A composition inherits its operands' substrates, but a training run also
carries one of its own -- the checkpoint inventory and the step trace -- and
`verifier.domains.train` replays it under `CHECKS["TRAIN"]`. That module shipped for the
whole life of this catalogue under the name `hyper`, left over from before `HYPER` was
formalized as the composition operator, which is why the partition recorded TRAIN in
`HYPER`'s place. `HYPER` is the entry that is grounded without being certifiable: the
operator holds *between* certified objects and has no substrate of its own for an
adapter to bind to. `TOKEN` held the only other position in that residue, for the
opposite reason -- a substrate of its own whose mechanics were not yet wired into
`verifier.domains` -- which is why the two reasons are enumerated as `OPERATOR_OBJECTS`
and `ADAPTER_PENDING_OBJECTS` rather than as one residue. HYPER's is the permanent one:
an adapter could be written for TOKEN and never for an operator. Every other
uncertifiable entry is ungrounded and carries no mechanism in any family at all. Ruled
2026-09-22. `TOKEN`'s adapter was written on 2026-09-22, which left
`ADAPTER_PENDING_OBJECTS` empty; see [`TOKEN`](#token).

### TRAIN-1: Facets

`TRAIN-1.1` through `TRAIN-1.6`; topological depth 4; 5 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| TRAIN-1.1 | Optimizer contract | The optimizer, schedule, accumulation and precision contract is bound. | none | configuration |
| TRAIN-1.2 | Numerical semantics | The declared floating-point format and accumulation order are bound. | TRAIN-1.1 | configuration |
| TRAIN-1.3 | Checkpoint inventory | Every retained weight and optimizer state is rehashed. | none | checkpoints |
| TRAIN-1.4 | Step index | A contiguous step index is bound over the retained trace. | TRAIN-1.3 | checkpoints |
| TRAIN-1.5 | Batch binding | Each step is bound to the batch it consumed. | TRAIN-1.4 | checkpoints |
| TRAIN-1.6 | Retention boundary | Which steps and states are retained, and which were discarded, is declared. | TRAIN-1.1, TRAIN-1.5 | none |

### TRAIN-2: Dynamics

`TRAIN-2.1` through `TRAIN-2.6`; topological depth 5; 5 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| TRAIN-2.1 | Loss replay | Dense-network losses are recomputed from the bound batches. | none | training |
| TRAIN-2.2 | Gradient replay | Analytic gradients are recomputed and compared with the retained ones. | TRAIN-2.1 | training |
| TRAIN-2.3 | Optimizer update | Every supported optimizer update is recomputed from retained gradients and state. | TRAIN-2.2 | updates |
| TRAIN-2.4 | State advance | Applying the recomputed update reproduces the next retained state. | TRAIN-2.3 | updates |
| TRAIN-2.5 | Step-by-step advance | The run is replayed step by step across the retained trace. | TRAIN-2.4 | training |
| TRAIN-2.6 | Unsupported update reporting | An unsupported optimizer is reported UNKNOWN and never passed. | TRAIN-2.3 | none |

### TRAIN-3: Statics

`TRAIN-3.1` through `TRAIN-3.5`; topological depth 3; 5 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| TRAIN-3.1 | Arithmetic semantics | The executing hardware's floating-point behaviour is observed rather than declared. | none | statics:arithmetic |
| TRAIN-3.2 | Accumulation order | The order reductions actually occur in is observed by reducing a retained sequence two ways, and its effect is bounded. | TRAIN-3.1 | statics:accumulation |
| TRAIN-3.3 | True gradient | The gradient the bound objective has is stated independently of what the run computed. | none | statics:objective |
| TRAIN-3.4 | Objective geometry | The curvature and conditioning that the architecture and data together fix are stated. | TRAIN-3.3 | statics:geometry |
| TRAIN-3.5 | Choice independence | The facts above are unchanged when the run's configuration is perturbed. | TRAIN-3.2, TRAIN-3.4 | statics:independence |

### TRAIN-4: Closure

`TRAIN-4.1` through `TRAIN-4.6`; topological depth 6; 4 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| TRAIN-4.1 | Contiguity | The retained steps form an uninterrupted sequence with no gap. | none | lineage |
| TRAIN-4.2 | Parent binding | Each step binds to its exact parent state. | TRAIN-4.1 | lineage |
| TRAIN-4.3 | Batch and hyperparameter binding | Each step binds its exact batch and hyperparameter values. | TRAIN-4.2 | lineage |
| TRAIN-4.4 | Result binding | Each step binds its exact result. | TRAIN-4.3 | lineage |
| TRAIN-4.5 | No reordering | The retained order is the executed order, and a reordered pair is detectable. | TRAIN-4.4 | none |
| TRAIN-4.6 | Whole-run accounting | The trace accounts for the whole run rather than a selected prefix of it. | TRAIN-4.5 | none |

### TRAIN-5: Domain adaptation

`TRAIN-5.1` through `TRAIN-5.6`; topological depth 5; 6 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| TRAIN-5.1 | Mainstay binding | The training-loop framework is named and version-pinned. | none | mainstay:binding |
| TRAIN-5.2 | Training-loop mapping | The retained trace is mapped onto the mainstay's loop and callback model. | TRAIN-5.1 | mainstay:layout |
| TRAIN-5.3 | Checkpoint-format mapping | The checkpoint inventory is mapped onto the mainstay's serialization format. | TRAIN-5.1 | mainstay:schema |
| TRAIN-5.4 | Batch source mapping | The batch binding is mapped onto the retained inventory a DATA-5 object exposes. | TRAIN-5.2 | mainstay:upstream |
| TRAIN-5.5 | Round trip | Resuming from the mapped checkpoint reproduces the retained next step. | TRAIN-5.3, TRAIN-5.4 | mainstay:roundtrip |
| TRAIN-5.6 | Inference upward | What the mainstay cannot express is stated as the residual this object carries over it. | TRAIN-5.5 | mainstay:residual |

### Registered mainstays of TRAIN

| Format | Carried in | Meta-surface entities | Expresses | Residual |
|---|---|---|---|---|
| PyTorch optimizer and module state (`pytorch-training-loop`) | state_dict objects | module, parameter, optimizer, param-group, optimizer-state, scheduler | 4 coordinates | 19 coordinates |
| Hugging Face Trainer state (`huggingface-trainer`) | trainer_state.json and training_args | TrainerState, global-step, log-entry, checkpoint, TrainingArguments | 4 coordinates | 19 coordinates |
| DeepSpeed and fully sharded data parallel checkpoints (`sharded-checkpoint`) | shard files plus index | checkpoint, shard, tensor-slice, rank, index | 3 coordinates | 20 coordinates |
| MLflow tracking run (`mlflow-run`) | run metadata, params, metrics and artifacts | run, parameter, metric-point, tag, artifact, experiment | 5 coordinates | 18 coordinates |
| TensorBoard event file (`tensorboard-event`) | tfevents protocol buffer stream | event, summary, step, wall-time, tag | 2 coordinates | 21 coordinates |

### TRAIN-6: Disclosure

`TRAIN-6.1` through `TRAIN-6.6`; topological depth 5; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| TRAIN-6.1 | Disclosure surface | What the certificate emits about this object is enumerated -- the architecture, checkpoint inventory, step index, optimizer contract, batch binding and loss trace -- and is separated from the batch contents and the gradient values each step was computed from. | none | none |
| TRAIN-6.2 | Bound declaration | Every field enumerated at 6.1 carries a declared disclosure bound naming the observers it is admissible to; a field emitted without a bound is not admissible, and the absence of a bound is never read as an open one. | TRAIN-6.1 | none |
| TRAIN-6.3 | Observer identification | The observer each bound is stated against is identified as a party rather than as a channel, since a channel can be relayed and a party cannot; where no observer model is established the level reports UNKNOWN and never PASS. | TRAIN-6.1 | none |
| TRAIN-6.4 | Emission-time evaluation | Each bound is evaluated at every emission of the certificate rather than once when the certificate was made. A bound satisfied at certification and violated at a later emission is not satisfied, and this is the only level in the grid that is not settled by the act of certifying. | TRAIN-6.2, TRAIN-6.3 | none |
| TRAIN-6.5 | Composition delta | Emitting this certificate beside a DATA certificate over the training corpus discloses membership: a per-step loss trace and a split membership are each within bound while the pair reveals which records were trained on. The architecture `GRAPH` operand makes a second join, and it needs no corpus: an architecture and an optimizer contract are each within bound while the pair is the whole recipe, enough to train shadow models on other data and infer from the trained model's outputs which records it saw. Each join is evaluated against all of its operands and not against any one alone. | TRAIN-6.2, TRAIN-6.4 | none |
| TRAIN-6.6 | Verdict independence | Redacting any emitted field to satisfy its bound leaves every verdict this object carries at tiers 1 through 5 unchanged. A disclosure bound never changes a computational verdict -- neither upward nor downward -- and a redaction that moves one makes the certificate malformed rather than more private. | TRAIN-6.2, TRAIN-6.4, TRAIN-6.5 | none |

## HYPER

### HYPER-1: Facets

`HYPER-1.1` through `HYPER-1.6`; topological depth 5; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| HYPER-1.1 | Operand set | The set of bound certificates entering the composition, and its arity, is declared. | none | none |
| HYPER-1.2 | Slot schema | Which slot each operand fills, and which slots are unfilled, is declared. | HYPER-1.1 | none |
| HYPER-1.3 | Slot versus operand | The distinction between a slot, which is a role, and an operand, which is a certificate, is made explicit. | HYPER-1.2 | none |
| HYPER-1.4 | Substrate presence | The substrate each operand carries is identified once per arm of the composition. | HYPER-1.1 | none |
| HYPER-1.5 | Composed identity | The identity of the composed object is derived from its operands and its filled slots. | HYPER-1.3, HYPER-1.4 | none |
| HYPER-1.6 | Operand admissibility | Each operand is admitted under the composed object's own policy. | HYPER-1.5 | none |

### HYPER-2: Dynamics

`HYPER-2.1` through `HYPER-2.6`; topological depth 4; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| HYPER-2.1 | Strength ordering | A total order on operand strengths is defined. | none | none |
| HYPER-2.2 | Non-increase | The composition's strength is no greater than that of its weakest operand. | HYPER-2.1 | none |
| HYPER-2.3 | UNKNOWN absorption | One UNKNOWN operand makes the composition UNKNOWN. | HYPER-2.2 | none |
| HYPER-2.4 | Recomposition | Recomposing from retained bytes lands on the same composed object. | none | none |
| HYPER-2.5 | Associativity | Which regroupings of operands are equivalent, and which are not, is stated. | HYPER-2.4 | none |
| HYPER-2.6 | Depth propagation | The composed object's depth is bounded by its operands' established depths. | HYPER-2.2, HYPER-2.3, HYPER-2.5 | none |

### HYPER-3: Statics

`HYPER-3.1` through `HYPER-3.5`; topological depth 3; 5 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| HYPER-3.1 | Composed ceiling | The weakest operand bound is the composed ceiling, whatever the composed object declares. | none | statics:ceiling |
| HYPER-3.2 | Substrate recurrence | The substrate recurs at every level rather than being consumed by a composition. | none | statics:recurrence |
| HYPER-3.3 | Decider exteriority | The decider stays outside the certified surface at every level. | none | statics:exteriority |
| HYPER-3.4 | Manufacture impossibility | No composition manufactures evidence absent from its operands. | HYPER-3.1, HYPER-3.2 | statics:conservation |
| HYPER-3.5 | Level independence | The facts above hold at every depth of nesting and are unchanged when the composition's own declarations are perturbed. | HYPER-3.3, HYPER-3.4 | statics:independence |

### HYPER-4: Closure

`HYPER-4.1` through `HYPER-4.5`; topological depth 5; 0 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| HYPER-4.1 | Saturation | Every slot of the composition is filled by a bound operand. | none | none |
| HYPER-4.2 | Collapse | An agent bound inside a simulation is written as one composed object and re-expanded. | HYPER-4.1 | none |
| HYPER-4.3 | Expansion fidelity | The re-expansion recovers the operand set byte for byte. | HYPER-4.2 | none |
| HYPER-4.4 | Fractal re-representation | The substrate is exhibited recurring identically at every level. | HYPER-4.3 | none |
| HYPER-4.5 | Boundary completeness | The composition's boundary admits no unbound operand. | HYPER-4.1, HYPER-4.4 | none |

### HYPER-5: Domain adaptation

`HYPER-5.1` through `HYPER-5.5`; topological depth 5; 5 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| HYPER-5.1 | Mainstay binding | The composition formalism is named and version-pinned. | none | mainstay:binding |
| HYPER-5.2 | Layout mapping | The operand set and its slots are mapped onto the mainstay's layout or assembly relation. | HYPER-5.1 | mainstay:layout |
| HYPER-5.3 | Authorization mapping | Slot filling is mapped onto the mainstay's step-authorization model. | HYPER-5.2 | mainstay:authorization |
| HYPER-5.4 | Round trip | The mainstay's verifier accepts the mapped composition and rejects a substituted operand. | HYPER-5.3 | mainstay:roundtrip |
| HYPER-5.5 | Inference upward | What the mainstay cannot express is stated as the residual this object carries over it. | HYPER-5.4 | mainstay:residual |

### Registered mainstays of HYPER

| Format | Carried in | Meta-surface entities | Expresses | Residual |
|---|---|---|---|---|
| in-toto layout and link metadata (`in-toto-layout`) | layout file plus link files | layout, step, inspection, functionary, threshold, link, artifact-rule | 6 coordinates | 16 coordinates |
| Supply-chain Levels for Software Artifacts provenance (`slsa-provenance`) | provenance predicate | subject, buildDefinition, runDetails, resolvedDependency, builder | 3 coordinates | 19 coordinates |
| Sigstore bundle (`sigstore-bundle`) | verification material and DSSE envelope | bundle, envelope, certificate, transparency-entry, identity | 2 coordinates | 20 coordinates |
| Open Container Initiative image index and referrers (`oci-referrers`) | index plus subject descriptors | index, manifest, subject-descriptor, artifact-type | 3 coordinates | 19 coordinates |

### HYPER-6: Disclosure

`HYPER-6.1` through `HYPER-6.6`; topological depth 5; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| HYPER-6.1 | Disclosure surface | What the certificate emits about this object is enumerated -- the operand set, slot schema, composed identity, composed ceiling and operand depths -- and is separated from the operand-internal evidence each operand certificate withheld under its own level 6. | none | none |
| HYPER-6.2 | Bound declaration | Every field enumerated at 6.1 carries a declared disclosure bound naming the observers it is admissible to; a field emitted without a bound is not admissible, and the absence of a bound is never read as an open one. | HYPER-6.1 | none |
| HYPER-6.3 | Observer identification | The observer each bound is stated against is identified as a party rather than as a channel, since a channel can be relayed and a party cannot; where no observer model is established the level reports UNKNOWN and never PASS. | HYPER-6.1 | none |
| HYPER-6.4 | Emission-time evaluation | Each bound is evaluated at every emission of the certificate rather than once when the certificate was made. A bound satisfied at certification and violated at a later emission is not satisfied, and this is the only level in the grid that is not settled by the act of certifying. | HYPER-6.2, HYPER-6.3 | none |
| HYPER-6.5 | Composition delta | This is the object where the delta is stated in general, and where it is sharpest. HYPER-2.2 establishes that a composition strength never increases above its operands; disclosure is the one property for which the opposite holds. The disclosure of a composition is the JOIN of its operands, not their meet, and the join is not bounded by either: two operands each strictly within bound can compose to a disclosure outside both. A composition is therefore never admissible on the grounds that its operands were, and HYPER-6.5 is evaluated on the composite rather than inherited from the operand certificates. | HYPER-6.2, HYPER-6.4 | none |
| HYPER-6.6 | Verdict independence | Redacting any emitted field to satisfy its bound leaves every verdict this object carries at tiers 1 through 5 unchanged. A disclosure bound never changes a computational verdict -- neither upward nor downward -- and a redaction that moves one makes the certificate malformed rather than more private. | HYPER-6.2, HYPER-6.4, HYPER-6.5 | none |

## MODEL

### MODEL-1: Facets

`MODEL-1.1` through `MODEL-1.5`; topological depth 3; 3 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| MODEL-1.1 | Tensor inventory | Complete finite tensor shapes are bound. | none | tensors |
| MODEL-1.2 | Architecture compatibility | Shapes are checked compatible across the declared computation graph. | MODEL-1.1 | tensors |
| MODEL-1.3 | Module decomposition | The model's module structure is declared. | MODEL-1.2 | none |
| MODEL-1.4 | Input and output surface | The declared input and output surface is bound with its types. | MODEL-1.2 | none |
| MODEL-1.5 | Dependency artifacts | The named dependency artifacts are bound by digest. | none | artifacts |

### MODEL-2: Dynamics

`MODEL-2.1` through `MODEL-2.5`; topological depth 4; 2 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| MODEL-2.1 | Forward execution | The bound dense network is executed on the retained inputs. | none | inference |
| MODEL-2.2 | Output agreement | Every retained output is compared with the executed one. | MODEL-2.1 | inference |
| MODEL-2.3 | Batching behaviour | Results are invariant to the declared batching, or the variance is localized. | MODEL-2.2 | none |
| MODEL-2.4 | Precision behaviour | Results under the declared precision are bounded, with divergence localized. | MODEL-2.2 | none |
| MODEL-2.5 | Sampling and decoding | The decoding procedure and its entropy source are bound and replayed. | MODEL-2.3, MODEL-2.4 | none |

### MODEL-3: Statics

`MODEL-3.1` through `MODEL-3.6`; topological depth 3; 1 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| MODEL-3.1 | Weight bytes | The exact architecture and weight artifacts are rehashed as retained bytes. | none | artifacts |
| MODEL-3.2 | Hardware requirements | The hardware the model requires in order to execute is observed. | MODEL-3.1 | none |
| MODEL-3.3 | Quantization specification | The quantization scheme and its configuration are bound. | MODEL-3.1 | none |
| MODEL-3.4 | Training-data citation | The retained-data object the model's training data is bound through is cited. | none | none |
| MODEL-3.5 | Provenance citation | The training-run object the model's provenance is bound through is cited. | MODEL-3.4 | none |
| MODEL-3.6 | Artifact immutability | The facts above are properties of the artifact rather than of any deployment of it. | MODEL-3.2, MODEL-3.3, MODEL-3.5 | none |

### MODEL-4: Closure

`MODEL-4.1` through `MODEL-4.5`; topological depth 3; 4 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| MODEL-4.1 | Evaluation set | The named evaluation set is bound and complete. | none | evaluation |
| MODEL-4.2 | Metric recomputation | Regression or classification metrics are recomputed over the whole named set. | MODEL-4.1 | evaluation |
| MODEL-4.3 | Probe inventory | The declared finite counterexample probes are enumerated. | none | challenges |
| MODEL-4.4 | Probe execution | Each probe is executed against its bound output condition. | MODEL-4.3 | challenges |
| MODEL-4.5 | Refutability | The claimed behaviour is refutable rather than merely unrefuted. | MODEL-4.2, MODEL-4.4 | none |

### MODEL-5: Domain adaptation

`MODEL-5.1` through `MODEL-5.6`; topological depth 5; 6 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| MODEL-5.1 | Mainstay binding | The module-graph and tensor-serialization formats are named and version-pinned. | none | mainstay:binding |
| MODEL-5.2 | Module-graph mapping | The module decomposition is mapped onto the mainstay's graph model. | MODEL-5.1 | mainstay:layout |
| MODEL-5.3 | Serialized-weights mapping | The weight inventory is mapped onto the mainstay's tensor container. | MODEL-5.1 | mainstay:schema |
| MODEL-5.4 | Operator coverage | Operators the mainstay cannot express are named. | MODEL-5.2 | mainstay:operators |
| MODEL-5.5 | Round trip | Export and re-import reproduces the retained outputs within the declared tolerance. | MODEL-5.3, MODEL-5.4 | mainstay:roundtrip |
| MODEL-5.6 | Inference upward | The residual this object carries over the mainstay is stated. | MODEL-5.5 | mainstay:residual |

### Registered mainstays of MODEL

| Format | Carried in | Meta-surface entities | Expresses | Residual |
|---|---|---|---|---|
| Open Neural Network Exchange (`onnx`) | ModelProto | ModelProto, GraphProto, NodeProto, TensorProto, ValueInfoProto, OperatorSetId | 5 coordinates | 16 coordinates |
| safetensors tensor container (`safetensors`) | JSON header plus contiguous payload | header, tensor-entry, dtype, shape, data-offset | 3 coordinates | 18 coordinates |
| GGUF model container (`gguf`) | key-value metadata plus tensor table | metadata-kv, tensor-info, tensor-data, quantization-type, alignment | 4 coordinates | 17 coordinates |
| Hugging Face model repository (`huggingface-model-repository`) | config.json, weight index and model card | config, weight-index, tokenizer, model-card, shard | 4 coordinates | 17 coordinates |
| StableHLO portable operation set (`stablehlo`) | MLIR module with versioned opset | module, function, operation, opset-version, type | 3 coordinates | 18 coordinates |

### MODEL-6: Disclosure

`MODEL-6.1` through `MODEL-6.6`; topological depth 5; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| MODEL-6.1 | Disclosure surface | What the certificate emits about this object is enumerated -- the tensor inventory, architecture, module decomposition, quantization specification and evaluation metrics -- and is separated from the weight bytes, the provenance citations and the training-data citation. | none | none |
| MODEL-6.2 | Bound declaration | Every field enumerated at 6.1 carries a declared disclosure bound naming the observers it is admissible to; a field emitted without a bound is not admissible, and the absence of a bound is never read as an open one. | MODEL-6.1 | none |
| MODEL-6.3 | Observer identification | The observer each bound is stated against is identified as a party rather than as a channel, since a channel can be relayed and a party cannot; where no observer model is established the level reports UNKNOWN and never PASS. | MODEL-6.1 | none |
| MODEL-6.4 | Emission-time evaluation | Each bound is evaluated at every emission of the certificate rather than once when the certificate was made. A bound satisfied at certification and violated at a later emission is not satisfied, and this is the only level in the grid that is not settled by the act of certifying. | MODEL-6.2, MODEL-6.3 | none |
| MODEL-6.5 | Composition delta | Emitting this certificate beside a TRAIN or DATA certificate discloses the corpus through the model: an architecture, a metric vector and a split membership are each within bound while the three together support extraction, so the join is evaluated against all operands and not against any one alone. | MODEL-6.2, MODEL-6.4 | none |
| MODEL-6.6 | Verdict independence | Redacting any emitted field to satisfy its bound leaves every verdict this object carries at tiers 1 through 5 unchanged. A disclosure bound never changes a computational verdict -- neither upward nor downward -- and a redaction that moves one makes the certificate malformed rather than more private. | MODEL-6.2, MODEL-6.4, MODEL-6.5 | none |

## SIM

### SIM-1: Facets

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

### SIM-2: Dynamics

`SIM-2.1` through `SIM-2.6`; topological depth 4; 2 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| SIM-2.1 | Trajectory replay | The transition expressions and entropy stream are executed to reproduce the retained trajectory. | none | replay |
| SIM-2.2 | Responsiveness | Each action's effect on the next state is observed and bounded in simulated time. | SIM-2.1 | none |
| SIM-2.3 | Internal state change | State changes exposed through no observation channel are enumerated. | SIM-2.1 | none |
| SIM-2.4 | Computational space | The resources the transition actually consumes per step are recorded. | SIM-2.1 | none |
| SIM-2.5 | Perspective shift | The bound projection is executed and aligned macro states are compared within the declared tolerance. | SIM-2.3 | refinement |
| SIM-2.6 | Perspective agreement | A shift of perspective preserves the trajectory's identity. | SIM-2.2, SIM-2.4, SIM-2.5 | none |

### SIM-3: Statics

`SIM-3.1` through `SIM-3.5`; topological depth 4; 3 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| SIM-3.1 | Invariant expressions | The bound invariant and conservation expressions are declared. | none | invariants |
| SIM-3.2 | Per-state holding | Each expression is checked on every retained state. | SIM-3.1 | invariants |
| SIM-3.3 | Closed state set | The closed finite state set is checked where one exists. | SIM-3.2 | invariants |
| SIM-3.4 | Modelled law | The physical law the simulation is a model of is stated as external to the simulation. | none | none |
| SIM-3.5 | Law independence | The law holds whether or not the simulation represents it correctly. | SIM-3.3, SIM-3.4 | none |

### SIM-4: Closure

`SIM-4.1` through `SIM-4.5`; topological depth 4; 3 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| SIM-4.1 | Shard coverage | Every shard is present and aligned across the retained trajectory. | none | shards |
| SIM-4.2 | Cross-shard relations | The bound relations between shards are checked. | SIM-4.1 | shards |
| SIM-4.3 | Signatures | Shard signatures are verified where the policy requires them. | SIM-4.2 | shards |
| SIM-4.4 | No unattributed transition | Every transition is attributed to a bound transition expression. | SIM-4.1 | none |
| SIM-4.5 | Whole-surface accounting | The retained trajectory accounts for the whole simulated surface. | SIM-4.3, SIM-4.4 | none |

### SIM-5: Domain adaptation

`SIM-5.1` through `SIM-5.6`; topological depth 5; 6 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| SIM-5.1 | Mainstay binding | The interaction or co-simulation interface is named and version-pinned. | none | mainstay:binding |
| SIM-5.2 | Interaction-surface mapping | Observation and action channels are mapped onto the mainstay's space model. | SIM-5.1 | mainstay:layout |
| SIM-5.3 | Physical-backend mapping | The transition expressions are mapped onto the mainstay's solver or model-exchange interface. | SIM-5.1 | mainstay:backend |
| SIM-5.4 | Stepping contract | The mainstay's stepping and reset semantics are mapped onto the retained trajectory. | SIM-5.2, SIM-5.3 | mainstay:stepping |
| SIM-5.5 | Round trip | Driving the mainstay reproduces the retained trajectory within the declared tolerance. | SIM-5.4 | mainstay:roundtrip |
| SIM-5.6 | Inference upward | The residual this object carries over the mainstay is stated. | SIM-5.5 | mainstay:residual |

### Registered mainstays of SIM

| Format | Carried in | Meta-surface entities | Expresses | Residual |
|---|---|---|---|---|
| Gymnasium environment interface (`gymnasium`) | Env class with space algebra | Env, observation-space, action-space, step-result, seed, space-composite | 5 coordinates | 18 coordinates |
| Functional Mock-up Interface (`fmi`) | FMU with modelDescription.xml | FMU, scalar-variable, causality, variability, model-exchange, co-simulation, solver-step | 6 coordinates | 17 coordinates |
| MuJoCo MJCF scene description (`mujoco-mjcf`) | MJCF XML | worldbody, body, joint, geom, actuator, sensor, option | 5 coordinates | 18 coordinates |
| OpenUSD stage (`openusd`) | layered stage with composition arcs | stage, prim, attribute, relationship, layer, composition-arc | 3 coordinates | 20 coordinates |
| ROS 2 bag recording (`ros2-bag`) | storage plus metadata.yaml | bag, topic, message, timestamp, qos-profile | 3 coordinates | 20 coordinates |

### SIM-6: Disclosure

`SIM-6.1` through `SIM-6.6`; topological depth 5; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| SIM-6.1 | Disclosure surface | What the certificate emits about this object is enumerated -- the state space, transition expressions, observation channels, invariants and shard decomposition -- and is separated from the entropy stream and the trajectory contents replayed against it. | none | none |
| SIM-6.2 | Bound declaration | Every field enumerated at 6.1 carries a declared disclosure bound naming the observers it is admissible to; a field emitted without a bound is not admissible, and the absence of a bound is never read as an open one. | SIM-6.1 | none |
| SIM-6.3 | Observer identification | The observer each bound is stated against is identified as a party rather than as a channel, since a channel can be relayed and a party cannot; where no observer model is established the level reports UNKNOWN and never PASS. | SIM-6.1 | none |
| SIM-6.4 | Emission-time evaluation | Each bound is evaluated at every emission of the certificate rather than once when the certificate was made. A bound satisfied at certification and violated at a later emission is not satisfied, and this is the only level in the grid that is not settled by the act of certifying. | SIM-6.2, SIM-6.3 | none |
| SIM-6.5 | Composition delta | Emitting this certificate beside a BOT certificate discloses the decider: a state space and a coupling surface are each within bound while the pair localizes which decisions were taken by which actor, so the join is evaluated against both operands and not against either alone. | SIM-6.2, SIM-6.4 | none |
| SIM-6.6 | Verdict independence | Redacting any emitted field to satisfy its bound leaves every verdict this object carries at tiers 1 through 5 unchanged. A disclosure bound never changes a computational verdict -- neither upward nor downward -- and a redaction that moves one makes the certificate malformed rather than more private. | SIM-6.2, SIM-6.4, SIM-6.5 | none |

## HARNESS

### HARNESS-1: Facets

`HARNESS-1.1` through `HARNESS-1.5`; topological depth 4; 2 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| HARNESS-1.1 | Channel partition | Every declared channel is partitioned into instrumented observation and named uninstrumented gap. | none | surface |
| HARNESS-1.2 | Record types | The user, agent and tool record types are bound. | HARNESS-1.1 | surface |
| HARNESS-1.3 | Tool registry | The registry of tool declarations is bound. | HARNESS-1.2 | none |
| HARNESS-1.4 | Side-effect channels | The declared side-effect channels are enumerated. | HARNESS-1.3 | none |
| HARNESS-1.5 | Transcript commitment shape | The shape of the ordered transcript commitment is declared. | HARNESS-1.2 | none |

### HARNESS-2: Dynamics

`HARNESS-2.1` through `HARNESS-2.5`; topological depth 4; 4 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| HARNESS-2.1 | Record contiguity | Retained records form an uninterrupted ordered sequence. | none | messages |
| HARNESS-2.2 | Invocation pairing | Each tool invocation is paired with its response. | HARNESS-2.1 | tools |
| HARNESS-2.3 | Side-effect interleaving | Declared side effects are placed in the record order. | HARNESS-2.2 | effects |
| HARNESS-2.4 | Session advance | The session is replayed record by record. | HARNESS-2.1 | messages |
| HARNESS-2.5 | Retry and resumption | What a retry or a resumption does to the sequence is declared and evidenced. | HARNESS-2.3, HARNESS-2.4 | none |

### HARNESS-3: Statics

`HARNESS-3.1` through `HARNESS-3.4`; topological depth 3; 4 of 4 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| HARNESS-3.1 | Gap boundary | The named uninstrumented gap is stated as a property of where the instrument was placed. | none | statics:gap |
| HARNESS-3.2 | Timestamp resolution | The clock's resolution is probed, and no ordering is admitted between events it cannot separate. | none | statics:clock |
| HARNESS-3.3 | Channel capacity | The capacity and truncation behaviour of each instrumented channel is recorded. | HARNESS-3.1 | statics:capacity |
| HARNESS-3.4 | Instrument fixity | The facts above are unchanged when the recorded session content is perturbed. | HARNESS-3.1, HARNESS-3.2, HARNESS-3.3 | statics:fixity |

### HARNESS-4: Closure

`HARNESS-4.1` through `HARNESS-4.5`; topological depth 4; 3 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| HARNESS-4.1 | Commitment recomputation | The ordered transcript commitment is recomputed from retained bytes. | none | transcript |
| HARNESS-4.2 | Omission detection | A dropped record changes the commitment. | HARNESS-4.1 | transcript |
| HARNESS-4.3 | Substitution detection | A replaced record changes the commitment. | HARNESS-4.1 | transcript |
| HARNESS-4.4 | Reordering detection | A reordered pair changes the commitment. | HARNESS-4.2, HARNESS-4.3 | none |
| HARNESS-4.5 | Whole-session accounting | The session is wholly accounted for under the commitment. | HARNESS-4.4 | none |

### HARNESS-5: Domain adaptation

`HARNESS-5.1` through `HARNESS-5.6`; topological depth 5; 6 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| HARNESS-5.1 | Mainstay binding | The trace and tool-protocol formats are named and version-pinned. | none | mainstay:binding |
| HARNESS-5.2 | Trace-span mapping | Records are mapped onto the mainstay's trace and span model. | HARNESS-5.1 | mainstay:layout |
| HARNESS-5.3 | Tool-protocol mapping | The tool registry and its invocations are mapped onto the mainstay's protocol. | HARNESS-5.1 | mainstay:protocol |
| HARNESS-5.4 | Gap representation | The uninstrumented gap is represented in the mainstay, or named unrepresentable there. | HARNESS-5.2, HARNESS-5.3 | mainstay:gap |
| HARNESS-5.5 | Round trip | Re-importing the mainstay export reproduces the transcript commitment. | HARNESS-5.4 | mainstay:roundtrip |
| HARNESS-5.6 | Inference upward | The residual this object carries over the mainstay is stated. | HARNESS-5.5 | mainstay:residual |

### Registered mainstays of HARNESS

| Format | Carried in | Meta-surface entities | Expresses | Residual |
|---|---|---|---|---|
| OpenTelemetry tracing (`opentelemetry`) | OTLP trace payload | trace, span, attribute, event, link, status, resource | 4 coordinates | 15 coordinates |
| OpenTelemetry generative AI semantic conventions (`opentelemetry-genai`) | span attribute set | llm-span, tool-span, prompt-attribute, completion-attribute, token-usage | 3 coordinates | 16 coordinates |
| Model Context Protocol (`model-context-protocol`) | JSON-RPC over a transport | server, tool, resource, prompt, call, result, capability | 4 coordinates | 15 coordinates |
| HTTP Archive (`har`) | HAR log | log, entry, request, response, timing | 2 coordinates | 17 coordinates |

### HARNESS-6: Disclosure

`HARNESS-6.1` through `HARNESS-6.6`; topological depth 5; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| HARNESS-6.1 | Disclosure surface | What the certificate emits about this object is enumerated -- the channel partition, record types, tool registry, transcript commitment shape and side-effect channels -- and is separated from the transcript contents and side-effect payloads the commitments were computed over. | none | none |
| HARNESS-6.2 | Bound declaration | Every field enumerated at 6.1 carries a declared disclosure bound naming the observers it is admissible to; a field emitted without a bound is not admissible, and the absence of a bound is never read as an open one. | HARNESS-6.1 | none |
| HARNESS-6.3 | Observer identification | The observer each bound is stated against is identified as a party rather than as a channel, since a channel can be relayed and a party cannot; where no observer model is established the level reports UNKNOWN and never PASS. | HARNESS-6.1 | none |
| HARNESS-6.4 | Emission-time evaluation | Each bound is evaluated at every emission of the certificate rather than once when the certificate was made. A bound satisfied at certification and violated at a later emission is not satisfied, and this is the only level in the grid that is not settled by the act of certifying. | HARNESS-6.2, HARNESS-6.3 | none |
| HARNESS-6.5 | Composition delta | Emitting this certificate beside a AGENT certificate discloses the session: a commitment shape and a decision inventory are each within bound while the pair reconstructs the order and content of a run, so the join is evaluated against both operands and not against either alone. | HARNESS-6.2, HARNESS-6.4 | none |
| HARNESS-6.6 | Verdict independence | Redacting any emitted field to satisfy its bound leaves every verdict this object carries at tiers 1 through 5 unchanged. A disclosure bound never changes a computational verdict -- neither upward nor downward -- and a redaction that moves one makes the certificate malformed rather than more private. | HARNESS-6.2, HARNESS-6.4, HARNESS-6.5 | none |

## AGENT

### AGENT-1: Facets

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

### AGENT-2: Dynamics

`AGENT-2.1` through `AGENT-2.5`; topological depth 4; 4 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| AGENT-2.1 | Trajectory contiguity | The retained decisions form a contiguous trajectory. | none | trajectory |
| AGENT-2.2 | Decision witnessing | Each decision is witnessed by a record inside the observation ceiling. | AGENT-2.1 | trajectory |
| AGENT-2.3 | Action witnessing | Each declared action is bound to a witnessed tool invocation. | AGENT-2.2 | actions |
| AGENT-2.4 | Unwitnessed action reporting | A declared action with no witness is reported and never passed. | AGENT-2.3 | none |
| AGENT-2.5 | Trajectory advance | The trajectory is replayed decision by decision. | AGENT-2.3 | trajectory |

### AGENT-3: Statics

`AGENT-3.1` through `AGENT-3.3`; topological depth 3; 3 of 3 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| AGENT-3.1 | Ceiling fixity | The observation ceiling is fixed by the harness, not by the agent. | none | statics:ceiling |
| AGENT-3.2 | Unknowability | What the agent could not have known is stated regardless of what it asserts it knew. | AGENT-3.1 | statics:unknowability |
| AGENT-3.3 | Declaration impotence | No agent declaration raises the ceiling, and perturbing its declarations moves none of the facts above. | AGENT-3.2 | statics:impotence |

### AGENT-4: Closure

`AGENT-4.1` through `AGENT-4.4`; topological depth 4; 3 of 4 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| AGENT-4.1 | Outcome inventory | The complete retained outcome inventory is enumerated. | none | outcomes |
| AGENT-4.2 | Contract comparison | The inventory is compared against the bound outcome contract. | AGENT-4.1 | outcomes |
| AGENT-4.3 | Claim support | Every final claim rests only on records inside the observation ceiling. | AGENT-4.2 | claims |
| AGENT-4.4 | No unsupported claim | The agent's account of itself admits no unsupported claim. | AGENT-4.3 | none |

### AGENT-5: Domain adaptation

`AGENT-5.1` through `AGENT-5.5`; topological depth 5; 5 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| AGENT-5.1 | Mainstay binding | The agent-loop runtime is named and version-pinned. | none | mainstay:binding |
| AGENT-5.2 | Decision-loop mapping | The trajectory is mapped onto the mainstay's loop or graph model. | AGENT-5.1 | mainstay:layout |
| AGENT-5.3 | Slot mapping | The decider slot is mapped onto the mainstay's policy binding without pinning the slot to a model. | AGENT-5.2 | mainstay:slot |
| AGENT-5.4 | Round trip | Replaying through the mainstay reproduces the retained trajectory. | AGENT-5.3 | mainstay:roundtrip |
| AGENT-5.5 | Inference upward | The residual this object carries over the mainstay is stated. | AGENT-5.4 | mainstay:residual |

### Registered mainstays of AGENT

| Format | Carried in | Meta-surface entities | Expresses | Residual |
|---|---|---|---|---|
| LangGraph state graph (`langgraph`) | compiled graph plus checkpointer | graph, node, edge, conditional-edge, state-channel, checkpoint, thread | 4 coordinates | 15 coordinates |
| Nested run tree (`run-tree`) | LangSmith-style run records | run, parent-run, run-type, inputs, outputs, error | 3 coordinates | 16 coordinates |
| Step trajectory record (`agent-trajectory`) | trajectory JSONL | trajectory, step, thought, action, observation, terminal | 4 coordinates | 15 coordinates |
| OpenTelemetry generative AI agent spans (`opentelemetry-genai-agent`) | agent and tool span tree | agent-span, tool-span, decision-attribute, outcome-status | 3 coordinates | 16 coordinates |

### AGENT-6: Disclosure

`AGENT-6.1` through `AGENT-6.6`; topological depth 5; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| AGENT-6.1 | Disclosure surface | What the certificate emits about this object is enumerated -- the harness binding, decision inventory, outcome contract, declared actions and final claims -- and is separated from the deliberation behind each decision, which AGENT-3.2 already holds to be unknowable and which level 6 additionally holds to be unemitted. | none | none |
| AGENT-6.2 | Bound declaration | Every field enumerated at 6.1 carries a declared disclosure bound naming the observers it is admissible to; a field emitted without a bound is not admissible, and the absence of a bound is never read as an open one. | AGENT-6.1 | none |
| AGENT-6.3 | Observer identification | The observer each bound is stated against is identified as a party rather than as a channel, since a channel can be relayed and a party cannot; where no observer model is established the level reports UNKNOWN and never PASS. | AGENT-6.1 | none |
| AGENT-6.4 | Emission-time evaluation | Each bound is evaluated at every emission of the certificate rather than once when the certificate was made. A bound satisfied at certification and violated at a later emission is not satisfied, and this is the only level in the grid that is not settled by the act of certifying. | AGENT-6.2, AGENT-6.3 | none |
| AGENT-6.5 | Composition delta | Emitting this certificate beside a HARNESS certificate discloses the operator: a decision inventory and a timestamp resolution are each within bound while the pair identifies who was at the keyboard and when, so the join is evaluated against both operands and not against either alone. | AGENT-6.2, AGENT-6.4 | none |
| AGENT-6.6 | Verdict independence | Redacting any emitted field to satisfy its bound leaves every verdict this object carries at tiers 1 through 5 unchanged. A disclosure bound never changes a computational verdict -- neither upward nor downward -- and a redaction that moves one makes the certificate malformed rather than more private. | AGENT-6.2, AGENT-6.4, AGENT-6.5 | none |

## BOT

### BOT-1: Facets

`BOT-1.1` through `BOT-1.5`; topological depth 3; 3 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| BOT-1.1 | Agent binding | The agent certificate is re-derived from its retained bytes. | none | binding |
| BOT-1.2 | Simulation binding | The simulation certificate is re-derived from its retained bytes. | none | binding |
| BOT-1.3 | Environment bindings | Both environment certificates are re-derived, one per arm of the coupling. | BOT-1.1, BOT-1.2 | binding |
| BOT-1.4 | Coupling surface | The facets of the coupling itself, rather than of either side, are declared. | BOT-1.3 | none |
| BOT-1.5 | Operand depths | Each operand's established depth is recorded for the composition ceiling. | BOT-1.3 | none |

### BOT-2: Dynamics

`BOT-2.1` through `BOT-2.5`; topological depth 4; 4 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| BOT-2.1 | Transition binding | Every simulation transition is bound to one retained record. | none | alignment |
| BOT-2.2 | Observation projection | Every retained observation is shown to be the simulation's own projection of that state. | BOT-2.1 | observation |
| BOT-2.3 | Action authenticity | Every replayed action is shown to be one the agent actually invoked. | BOT-2.1 | actuation |
| BOT-2.4 | One-to-one coupling | No transition lacks a record and no record lacks a transition. | BOT-2.2, BOT-2.3 | alignment |
| BOT-2.5 | Coupling advance | The coupled run is replayed step by step. | BOT-2.4 | none |

### BOT-3: Statics

`BOT-3.1` through `BOT-3.4`; topological depth 3; 4 of 4 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| BOT-3.1 | Inherited ceiling | The observation ceiling exists whatever the agent claims about it. | none | statics:inherited |
| BOT-3.2 | Coupling latency | The latency and ordering the coupling imposes are probed from the retained action and effect times. | none | statics:latency |
| BOT-3.3 | Disclosure limit | The information the simulation cannot expose regardless of policy is stated. | BOT-3.1 | statics:disclosure |
| BOT-3.4 | Policy impotence | The facts above are unchanged when either side's policy is perturbed. | BOT-3.2, BOT-3.3 | statics:impotence |

### BOT-4: Closure

`BOT-4.1` through `BOT-4.4`; topological depth 3; 3 of 4 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| BOT-4.1 | Separation declaration | The agent and simulator execution environments are declared separate or fused. | none | containment |
| BOT-4.2 | Separation evidence | A separate declaration is evidenced by the two bound environment certificates. | BOT-4.1 | containment |
| BOT-4.3 | Fused honesty | A fused declaration is honest and yields UNKNOWN, never FAIL. | BOT-4.1 | containment |
| BOT-4.4 | Containment accounting | Containment is established or explicitly not established, and never assumed. | BOT-4.2, BOT-4.3 | none |

### BOT-5: Domain adaptation

`BOT-5.1` through `BOT-5.6`; topological depth 5; 6 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| BOT-5.1 | Interaction-graph binding | The interaction graph over the bound simulation's interaction surface is bound. | none | mainstay:interaction |
| BOT-5.2 | Disclosure inventory | What the composed object discloses about itself is enumerated. | BOT-5.1 | mainstay:disclosed |
| BOT-5.3 | Indisclosure inventory | What it does not disclose is named as unestablished rather than absent. | BOT-5.2 | mainstay:indisclosed |
| BOT-5.4 | Inclusion awareness | Whether it is aware of being inside a simulation, and to what degree, is recorded. | BOT-5.2 | mainstay:inclusion |
| BOT-5.5 | Specification awareness | Which simulation specification surfaces it is aware of is recorded. | BOT-5.4 | mainstay:awareness |
| BOT-5.6 | Awareness accounting | Disclosed and indisclosed awareness are accounted for without inferring either from the other. | BOT-5.3, BOT-5.5 | mainstay:accounting |

### Registered mainstays of BOT

| Format | Carried in | Meta-surface entities | Expresses | Residual |
|---|---|---|---|---|
| Interaction graph over a bound simulation surface (`embodied-interaction-graph`) | composed agent trajectory and simulation trace | interaction-node, observation-edge, action-edge, disclosure-set, indisclosure-set, awareness-level | 4 coordinates | 14 coordinates |
| Unified Robot Description Format (`urdf`) | URDF or SDFormat model | robot, link, joint, inertial, collision, transmission | 3 coordinates | 15 coordinates |

### BOT-6: Disclosure

`BOT-6.1` through `BOT-6.6`; topological depth 5; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| BOT-6.1 | Disclosure surface | What the certificate emits about this object is enumerated -- the agent and simulation bindings, coupling surface, separation declaration and containment accounting -- and is separated from the indisclosure inventory itself, which names what the bot was not told and therefore leaks it. | none | none |
| BOT-6.2 | Bound declaration | Every field enumerated at 6.1 carries a declared disclosure bound naming the observers it is admissible to; a field emitted without a bound is not admissible, and the absence of a bound is never read as an open one. | BOT-6.1 | none |
| BOT-6.3 | Observer identification | The observer each bound is stated against is identified as a party rather than as a channel, since a channel can be relayed and a party cannot; where no observer model is established the level reports UNKNOWN and never PASS. | BOT-6.1 | none |
| BOT-6.4 | Emission-time evaluation | Each bound is evaluated at every emission of the certificate rather than once when the certificate was made. A bound satisfied at certification and violated at a later emission is not satisfied, and this is the only level in the grid that is not settled by the act of certifying. | BOT-6.2, BOT-6.3 | none |
| BOT-6.5 | Composition delta | Emitting this certificate beside the SIM certificate it is coupled to discloses the separation: a containment accounting and a state space are each within bound while the pair reveals which boundary the separation evidence was defending, so the join is evaluated against both operands and not against either alone. | BOT-6.2, BOT-6.4 | none |
| BOT-6.6 | Verdict independence | Redacting any emitted field to satisfy its bound leaves every verdict this object carries at tiers 1 through 5 unchanged. A disclosure bound never changes a computational verdict -- neither upward nor downward -- and a redaction that moves one makes the certificate malformed rather than more private. | BOT-6.2, BOT-6.4, BOT-6.5 | none |

## OWNER

A **relational** object. It does not certify a substrate of its own; it certifies a
holding that stands *between* a bound actor and a bound object. Of the four
relational objects -- `GRAPH`, `HYPER`, `OWNER` and `IDENTITY` -- the last two are
**ungrounded**, this one among them: no adapter executes it, so every obligation below is
specified with no mechanism and reports `UNKNOWN`. That is the honest report of a specified holding that
nothing yet checks, and it is why `OWNER` is excluded from the grounded-object
invariants that require tiers 3 and 5 to be mechanized.

The holder is bound by its own `ACTOR` certificate, so a holding names a
certified actor rather than a string. This is the absorption the earlier text anticipated:
the binding was carried by a wire token, `verifier-actor-binding-1`, only for as long as no
actor object existed to carry it, and `ACTOR` now does. A holding is therefore the
composition `HYPER(ACTOR + the held object)`, which is what puts `OWNER`
inside the composition lattice rather than beside it. A holding never reaches a verdict:
`OWNER-3.1` makes that normative, and it is the ownership twin of the Prime Invariant --
now derived from `HYPER-3` rather than declared, since the weakest operand bounds the
composition and the held object is one of the two operands.

### OWNER-1: Facets

`OWNER-1.1` through `OWNER-1.6`; topological depth 4; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| OWNER-1.1 | Holder binding | The holder is bound by its own ACTOR certificate at a stated coordinate, never named in free text and never by a wire token. The holding is the composition HYPER(ACTOR + the held object), so the holder is an operand of it rather than a string inside it. | none | none |
| OWNER-1.2 | Held-object binding | The held object is bound by its own object certificate at a stated coordinate. | none | none |
| OWNER-1.3 | Limb inventory | Every limb of the holding is enumerated under three kinds -- rights, discharge-duties and answering-duties -- and a limb the inventory omits is unheld rather than permitted. | OWNER-1.1, OWNER-1.2 | none |
| OWNER-1.4 | Instrument | The instrument that establishes the holding is bound together with the authority that issued it. | OWNER-1.3 | none |
| OWNER-1.5 | Term | The holding's start, and its end or its declared non-expiry, are stated on the instrument's own clock. | OWNER-1.4 | none |
| OWNER-1.6 | Bearer capability | The holder's kind scopes which limbs it can bear, and a limb its kind cannot bear is unheld rather than held and unexercised. | OWNER-1.1, OWNER-1.3 | none |

### OWNER-2: Dynamics

`OWNER-2.1` through `OWNER-2.6`; topological depth 4; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| OWNER-2.1 | Event declaration | Every event that changes the holding is declared with its instrument and its position in the order. | none | none |
| OWNER-2.2 | Transfer conveyance | Each declared transfer conveys only the limbs the transferor held at that position in the order. | OWNER-2.1 | none |
| OWNER-2.3 | Delegation bound | Each delegation conveys a subset of the delegator's limbs and leaves the delegator's own holding intact. | OWNER-2.1 | none |
| OWNER-2.4 | Revocation effect | Each revocation withdraws exactly the limbs it names, from the position in the order at which it takes effect. | OWNER-2.2, OWNER-2.3 | none |
| OWNER-2.5 | Lapse | A holding whose term has ended lapses by the clock rather than by an event, and lapse is distinguished from revocation. | OWNER-2.1 | none |
| OWNER-2.6 | Ordered replay | Replaying the declared events from the origin in the declared order reproduces the current holding. | OWNER-2.4, OWNER-2.5 | none |

### OWNER-3: Statics

`OWNER-3.1` through `OWNER-3.6`; topological depth 3; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| OWNER-3.1 | Verdict independence | The holding never changes any verdict the held object's own certificate reaches. | none | none |
| OWNER-3.2 | Evidence immutability | Ownership events never alter, retract or re-date the held object's evidence. | OWNER-3.1 | none |
| OWNER-3.3 | Ancestry immutability | Ownership events never alter the held object's ancestry or its coordinate. | OWNER-3.1 | none |
| OWNER-3.4 | Asymmetry | Holding is asymmetric: two holders cannot hold the same limb over the same object at the same position in the order unless that limb is declared shared. | none | none |
| OWNER-3.5 | Non-transitivity of authority | Holding an object confers no holding over the objects it was composed from, nor over the objects composed from it. | OWNER-3.4 | none |
| OWNER-3.6 | Person-limb typing | Where the held object is a natural person, no right is holdable and only duties are; and a holder that is not a natural person may carry discharge-duties but never an answering-duty. | OWNER-3.4, OWNER-3.5 | none |

### OWNER-4: Closure

`OWNER-4.1` through `OWNER-4.6`; topological depth 4; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| OWNER-4.1 | Chain origin | The chain of holdings begins at a declared origin whose instrument is bound. | none | none |
| OWNER-4.2 | Gapless chain | Every position in the order between the origin and the head is covered by exactly one holding. | OWNER-4.1 | none |
| OWNER-4.3 | Fork detection | No two holdings claim the same limb over the same object at the same position, and a fork is reported rather than resolved. | OWNER-4.2 | none |
| OWNER-4.4 | Admissibility at issue time | Each instrument is admissible under the authority in force when it issued, not under the authority in force now. | OWNER-4.1 | none |
| OWNER-4.5 | Accountability floor | For every discharge-duty in the chain an answering-duty exists over the same object, at the same position in the order and throughout that discharge-duty's term, and every answering-duty chain terminates in a natural person; an answering-duty that lapses while its discharge-duty still runs leaves the chain open, and a chain that discharges without answering is not closed. | OWNER-4.1, OWNER-4.2 | none |
| OWNER-4.6 | Closure result | The chain is closed only when origin, gaplessness, fork-freedom, admissibility at issue time and the accountability floor all hold; otherwise the result is UNKNOWN and never FAIL. | OWNER-4.2, OWNER-4.3, OWNER-4.4, OWNER-4.5 | none |

### OWNER-5: Domain adaptation

`OWNER-5.1` through `OWNER-5.6`; topological depth 3; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| OWNER-5.1 | Licence holding | Licence holdings over a corpus or a model are bound per source, and the composite redistribution term is the meet of its sources. | none | none |
| OWNER-5.2 | Registry maintainer record | Package-registry maintainer and owner records are bound as holdings, with the registry as the issuing authority. | none | none |
| OWNER-5.3 | Register entry | Corporate and beneficial-ownership register entries are bound as holdings, with the register as the issuing authority. | none | none |
| OWNER-5.4 | Declared code ownership | Declared repository code-ownership entries are bound as delegated review duties, never as transferable limbs. | OWNER-5.2 | none |
| OWNER-5.5 | Custody chain | Physical and cryptographic custody transfers are bound as ordered events on the custody clock. | none | none |
| OWNER-5.6 | Adaptation accounting | Each adaptation above is reported as established or unestablished, and an absent register is unestablished rather than unheld. | OWNER-5.1, OWNER-5.2, OWNER-5.3, OWNER-5.4, OWNER-5.5 | none |

### Registered mainstays of OWNER

None. A mainstay is a representation a domain already publishes in, bound by an
executing adapter; `OWNER` has no adapter, so it registers none. The formats its
tier 5 names -- licence expressions, registry maintainer records, corporate and
beneficial-ownership registers, declared code ownership and custody chains -- are
named as unestablished rather than registered.

### OWNER-6: Disclosure

`OWNER-6.1` through `OWNER-6.6`; topological depth 5; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| OWNER-6.1 | Disclosure surface | What the certificate emits about this object is enumerated -- the holder binding, held-object binding, limb inventory, term, and the chain of custody from its declared origin -- and is separated from the instrument contents, and the identity of the natural person each answering-duty chain terminates in. | none | none |
| OWNER-6.2 | Bound declaration | Every field enumerated at 6.1 carries a declared disclosure bound naming the observers it is admissible to; a field emitted without a bound is not admissible, and the absence of a bound is never read as an open one. | OWNER-6.1 | none |
| OWNER-6.3 | Observer identification | The observer each bound is stated against is identified as a party rather than as a channel, since a channel can be relayed and a party cannot; where no observer model is established the level reports UNKNOWN and never PASS. | OWNER-6.1 | none |
| OWNER-6.4 | Emission-time evaluation | Each bound is evaluated at every emission of the certificate rather than once when the certificate was made. A bound satisfied at certification and violated at a later emission is not satisfied, and this is the only level in the grid that is not settled by the act of certifying. | OWNER-6.2, OWNER-6.3 | none |
| OWNER-6.5 | Composition delta | Emitting this certificate beside the OWNER certificate of an adjacent holding discloses the graph: two chains each within bound reveal, at their shared positions, a structure neither states alone, so the join is evaluated against both operands and not against either alone. | OWNER-6.2, OWNER-6.4 | none |
| OWNER-6.6 | Verdict independence | Redacting any emitted field to satisfy its bound leaves every verdict this object carries at tiers 1 through 5 unchanged. A disclosure bound never changes a computational verdict -- neither upward nor downward -- and a redaction that moves one makes the certificate malformed rather than more private. | OWNER-6.2, OWNER-6.4, OWNER-6.5 | none |
## HUMAN

`HUMAN` asserts that one living person is behind a subject, and asserts
nothing further. It is **ungrounded**: no adapter executes it, so every obligation below
reports `UNKNOWN`. It is not relational -- it stands on its own rather than between two
certified objects -- which is what separates *ungrounded* from *relational* in this
catalogue; until the identity family landed, the only ungrounded object was also
relational and the two properties could not be told apart.

This object is the floor of the accountability chain. `HUMAN-4.4` is the obligation the
rest of the family rests on: following the answering-duty limb of the holdings upward
reaches a person in finitely many steps. `HUMAN-3.6` is the one that cannot be adapted
around -- no composition of models, agents, bots, simulations or collectives yields a
human, at any strength, by any route.

### HUMAN-1: Facets

`HUMAN-1.1` through `HUMAN-1.6`; topological depth 4; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| HUMAN-1.1 | Assertion subject | The assertion states that one living human is behind the subject, and states nothing beyond that. | none | none |
| HUMAN-1.2 | Evidence class | The evidence class establishing humanness is declared -- biometric, hardware-attested, in-person or social-graph -- together with the capture pipeline it was obtained through. | HUMAN-1.1 | none |
| HUMAN-1.3 | Liveness and uniqueness claims | The liveness and uniqueness properties being claimed are stated separately, since an assertion may carry either without the other. | HUMAN-1.2 | none |
| HUMAN-1.4 | Enrollment population | The population the uniqueness claim is relative to is declared, together with the deduplication mechanism that establishes it within that population. | HUMAN-1.3 | none |
| HUMAN-1.5 | Non-assertion boundary | What is deliberately not asserted -- name, nationality, civil identity, or any other attribute -- is enumerated, and an attribute the assertion omits is unasserted rather than unknown. | HUMAN-1.1 | none |
| HUMAN-1.6 | Humanness versus identification | The boundary between establishing that the subject is a human and identifying which human the subject is, is stated; the two are separable, and an assertion that establishes the first never thereby establishes the second. | HUMAN-1.1, HUMAN-1.5 | none |

### HUMAN-2: Dynamics

`HUMAN-2.1` through `HUMAN-2.6`; topological depth 3; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| HUMAN-2.1 | Enrollment | Enrollment into the humanness assertion is declared as an event with its evidence class and its instrument. | none | none |
| HUMAN-2.2 | Re-verification | Re-verification is declared as its own event, and never as a continuation of the original enrollment. | HUMAN-2.1 | none |
| HUMAN-2.3 | Evidence aging | The evidence's age at the point of use is carried, and an assertion whose evidence has aged past its declared validity is unestablished rather than established and stale. | HUMAN-2.2 | none |
| HUMAN-2.4 | Revocation on compromise | Revocation on compromise withdraws the assertion from the position in the order at which it takes effect. | HUMAN-2.1 | none |
| HUMAN-2.5 | Template irreversibility | A compromised biometric template does not rotate: revocation withdraws the binding and never restores the secrecy of the trait, so a breach is declared as permanent rather than as remediated. | HUMAN-2.4 | none |
| HUMAN-2.6 | Death | The subject's death ends the assertion, and is declared as an event rather than inferred from inactivity. No other object on this axis carries this dynamic -- a dataset does not die. | HUMAN-2.1 | none |

### HUMAN-3: Statics

`HUMAN-3.1` through `HUMAN-3.6`; topological depth 3; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| HUMAN-3.1 | Singularity | A human is singular and non-copyable and cannot be manufactured on demand. This is what makes Sybil resistance mean anything, and no declaration or adaptation changes it. | none | none |
| HUMAN-3.2 | Irreducible biometric error | False-match and false-non-match rates are decision-theoretic facts of the operating point rather than implementation defects, and no operating point has both at zero. | none | none |
| HUMAN-3.3 | Presentation attack surface | Presentation attack detection is a separate error surface from matching, with its own rates, and a matching rate never bounds it. | HUMAN-3.2 | none |
| HUMAN-3.4 | Injection attack surface | Injection attacks target the capture pipeline, which sits outside the biometric's own error model; the gap is a property of where the instrument was placed rather than of what it recorded. | HUMAN-3.2, HUMAN-3.3 | none |
| HUMAN-3.5 | Relative uniqueness | Uniqueness holds only relative to an enrollment population and a deduplication mechanism. No protocol establishes global uniqueness of a person, and an assertion claiming it is malformed. | HUMAN-3.1 | none |
| HUMAN-3.6 | No composition yields a human | No arrangement of models, agents, bots, simulations or collectives produces a human, at any strength, by any route. This is the one statics row no composition can reach. | HUMAN-3.1 | none |

### HUMAN-4: Closure

`HUMAN-4.1` through `HUMAN-4.6`; topological depth 4; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| HUMAN-4.1 | Evidence declaration | Every humanness assertion declares the evidence class it rests on. | none | none |
| HUMAN-4.2 | Error-rate declaration | Every assertion declares the error rates of that evidence class at the operating point actually used. | HUMAN-4.1 | none |
| HUMAN-4.3 | Population declaration | Every assertion declares the exact enrollment population its uniqueness is relative to, and an undeclared population makes the uniqueness claim unestablished. | HUMAN-4.1, HUMAN-4.2 | none |
| HUMAN-4.4 | Accountability termination | For any certified decision, following the answering-duty limb of the holdings upward reaches a HUMAN in finitely many steps. This runs through holdings and never through occupancies. | none | none |
| HUMAN-4.5 | Occupancy is not termination | A bot may occupy a seat and a human still answers for it, so an occupancy never discharges 4.4. A chain that terminates in an occupancy rather than in a holding is open. | HUMAN-4.4 | none |
| HUMAN-4.6 | Closure result | The assertion is closed only when evidence, error rates, population and accountability termination all hold; otherwise the result is UNKNOWN and never FAIL. | HUMAN-4.3, HUMAN-4.5 | none |

### HUMAN-5: Domain adaptation

`HUMAN-5.1` through `HUMAN-5.6`; topological depth 3; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| HUMAN-5.1 | Error-rate reporting mainstay | Biometric performance testing and reporting is bound as the mainstay for error-rate declaration, and an assertion that reports no operating point registers none. | none | none |
| HUMAN-5.2 | Presentation attack detection mainstay | Presentation attack detection reporting is bound as a separate mainstay from matching performance, with its own rates. | none | none |
| HUMAN-5.3 | Enrollment scheme mapping | Iris, hardware-attested and comparable enrollment schemes map onto the enrollment population and deduplication facets. | HUMAN-5.1, HUMAN-5.2 | none |
| HUMAN-5.4 | Attestation mapping | Rate-limited attestation tokens and comparable privacy-preserving personhood attestations map onto the humanness assertion without carrying an identification. | none | none |
| HUMAN-5.5 | Human-verification mapping | In-person and social-graph verification map onto the evidence class facet as declared evidence rather than as measured rates. | none | none |
| HUMAN-5.6 | Adaptation accounting | Each adaptation above is reported as established or unestablished, and an absent mainstay is unestablished rather than unasserted. | HUMAN-5.1, HUMAN-5.2, HUMAN-5.3, HUMAN-5.4, HUMAN-5.5 | none |

### Registered mainstays of HUMAN

None. A mainstay is a representation a domain already publishes in, bound by
an executing adapter; `HUMAN` has no adapter, so it registers none. The formats its
tier 5 names -- biometric error-rate and presentation-attack reporting, enrollment
schemes, and privacy-preserving personhood attestation -- are named as unestablished
rather than registered.

### HUMAN-6: Disclosure

`HUMAN-6.1` through `HUMAN-6.6`; topological depth 5; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| HUMAN-6.1 | Disclosure surface | What the certificate emits about this object is enumerated -- the evidence class, the liveness and uniqueness claims, the enrollment population, and the assertion's validity -- and is separated from the biometric template, the capture record, and any attribute the assertion declares it does not carry. This is the disclosure floor of a person, and it is the one surface in the grid that no declaration waives. | none | none |
| HUMAN-6.2 | Bound declaration | Every field enumerated at 6.1 carries a declared disclosure bound naming the observers it is admissible to; a field emitted without a bound is not admissible, and the absence of a bound is never read as an open one. | HUMAN-6.1 | none |
| HUMAN-6.3 | Observer identification | The observer each bound is stated against is identified as a party rather than as a channel, since a channel can be relayed and a party cannot; where no observer model is established the level reports UNKNOWN and never PASS. | HUMAN-6.1 | none |
| HUMAN-6.4 | Emission-time evaluation | Each bound is evaluated at every emission of the certificate rather than once when the certificate was made. A bound satisfied at certification and violated at a later emission is not satisfied, and this is the only level in the grid that is not settled by the act of certifying. | HUMAN-6.2, HUMAN-6.3 | none |
| HUMAN-6.5 | Composition delta | Emitting this certificate beside the IDENTITY certificate of an occupancy the subject bears discloses the person behind the seat: a humanness assertion within bound and an occupancy within bound together identify an individual that neither states alone, so the join is evaluated against both operands and not against either alone. | HUMAN-6.2, HUMAN-6.4 | none |
| HUMAN-6.6 | Verdict independence | Redacting any emitted field to satisfy its bound leaves every verdict this object carries at tiers 1 through 5 unchanged. A disclosure bound never changes a computational verdict -- neither upward nor downward -- and a redaction that moves one makes the certificate malformed rather than more private. | HUMAN-6.2, HUMAN-6.4, HUMAN-6.5 | none |

## ROLE

`ROLE` is a role class: a seat with declared authority and declared
qualifications, and *not* the person or bot occupying it. It is **ungrounded** -- no
adapter executes it -- and it is not relational. Occupancy is a separate object,
`IDENTITY`; a role class that named its occupant would collapse the two.

The distinction earns its keep in `ROLE-3.1` and `ROLE-3.2`: authority is a property of
the class rather than of whoever holds it, so an unoccupied seat still carries it. The
object was named `VSTD-INDIVIDUAL` in the design notes until 2026-09-21; it was renamed
because every line of prose describing it already called it a role.

### ROLE-1: Facets

`ROLE-1.1` through `ROLE-1.6`; topological depth 4; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| ROLE-1.1 | Class identity | The role class is named at a stated coordinate, as a class rather than as any person occupying it. | none | none |
| ROLE-1.2 | Decision authority | The decision authority the class carries is declared, and an authority the declaration omits is not carried. | ROLE-1.1 | none |
| ROLE-1.3 | Qualifications | The qualifications required of a bearer are declared as properties of the class. | ROLE-1.1 | none |
| ROLE-1.4 | Simultaneous bearer limit | How many bearers may occupy the class at once is declared, and a class that declares no limit is unspecified rather than unlimited. | ROLE-1.1 | none |
| ROLE-1.5 | Admissible bearer classes | Which bearer classes the seat admits is declared -- humans only, or bots as well -- and this is a property of the class rather than of any occupancy of it. | ROLE-1.1, ROLE-1.4 | none |
| ROLE-1.6 | Facet completeness | A class whose authority, qualifications, bearer limit or admissible bearer classes are unstated is unspecified rather than unconstrained. | ROLE-1.2, ROLE-1.3, ROLE-1.5 | none |

### ROLE-2: Dynamics

`ROLE-2.1` through `ROLE-2.6`; topological depth 4; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| ROLE-2.1 | Occupancy events | A bearer taking the class and a bearer leaving it are declared as events with their positions in the order. | none | none |
| ROLE-2.2 | Hand-over | A hand-over is declared as a paired leaving and taking at one position, and never as two independent events. | ROLE-2.1 | none |
| ROLE-2.3 | Acting in role | Acting in the role is distinguished from the bearer acting personally, and an act that declares neither is attributed to neither. | ROLE-2.1 | none |
| ROLE-2.4 | Temporary delegation | A temporary delegation conveys a subset of the class's authority for a stated interval and leaves the class's own authority intact. | ROLE-2.1 | none |
| ROLE-2.5 | In-flight decisions | What happens to a decision in flight across a hand-over is declared, and a decision that spans a hand-over is attributed rather than dropped. | ROLE-2.2, ROLE-2.3 | none |
| ROLE-2.6 | Occupancy replay | Replaying the declared occupancy events from the first taking reproduces the current occupancy. | ROLE-2.2, ROLE-2.4, ROLE-2.5 | none |

### ROLE-3: Statics

`ROLE-3.1` through `ROLE-3.6`; topological depth 3; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| ROLE-3.1 | Declared authority | The class's authority is declared rather than derived from whoever holds it. | none | none |
| ROLE-3.2 | Vacancy retention | An unoccupied seat still carries its declared authority; vacancy suspends exercise and never reduces the class. | ROLE-3.1 | none |
| ROLE-3.3 | Occupancy factuality | The occupancy fact exists whether or not it is disclosed, and non-disclosure never makes a seat vacant. | none | none |
| ROLE-3.4 | Cross-role correlation | One bearer occupies several classes, so correlation across them is a fact about the bearer and never a fact about the classes. | ROLE-3.3 | none |
| ROLE-3.5 | Authority independence | A change of occupant never alters the class's declared authority, in either direction. | ROLE-3.1, ROLE-3.2 | none |
| ROLE-3.6 | Class is not its occupants | The class is not its occupants: naming an occupant never names the class, and naming the class never names an occupant. | ROLE-3.3, ROLE-3.4 | none |

### ROLE-4: Closure

`ROLE-4.1` through `ROLE-4.5`; topological depth 4; 0 of 5 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| ROLE-4.1 | Decision inventory | Every decision falling within the class's declared authority is inventoried. | none | none |
| ROLE-4.2 | Contiguous occupancy | The occupancy intervals are contiguous across the period the inventory covers. | none | none |
| ROLE-4.3 | Bearer attribution | Each inventoried decision is attributed to the bearer during whose occupancy it fell. | ROLE-4.1, ROLE-4.2 | none |
| ROLE-4.4 | No unattributed decision | No gap exists in which an inventoried decision was taken by no one; an uncovered decision leaves the profile open. | ROLE-4.2, ROLE-4.3 | none |
| ROLE-4.5 | Closure result | The class is closed only when the inventory, contiguity and attribution all hold; otherwise the result is UNKNOWN and never FAIL. | ROLE-4.3, ROLE-4.4 | none |

### ROLE-5: Domain adaptation

`ROLE-5.1` through `ROLE-5.6`; topological depth 4; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| ROLE-5.1 | Engagement context role mainstay | Engagement context role credentials are bound as the mainstay for a declared role class. | none | none |
| ROLE-5.2 | Access control role mapping | Role-based access control role definitions map onto the authority and qualification facets. | none | none |
| ROLE-5.3 | Org-chart position mapping | Org-chart position records map onto the class identity and bearer-limit facets. | none | none |
| ROLE-5.4 | Round trip | A class expressed in a mainstay above and read back reproduces the declared facets without loss. | ROLE-5.1, ROLE-5.2, ROLE-5.3 | none |
| ROLE-5.5 | Inference upward | A representation that carries less than the facets require is inferred upward and reported as partial rather than as complete. | ROLE-5.4 | none |
| ROLE-5.6 | Adaptation accounting | Each adaptation above is reported as established or unestablished, and an absent registry is unestablished rather than unoccupied. | ROLE-5.1, ROLE-5.2, ROLE-5.3, ROLE-5.4, ROLE-5.5 | none |

### Registered mainstays of ROLE

None. `ROLE` has no adapter, so it registers none. The formats its tier 5
names -- engagement context role credentials, access-control role definitions and
org-chart position records -- are named as unestablished rather than registered.

### ROLE-6: Disclosure

`ROLE-6.1` through `ROLE-6.6`; topological depth 5; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| ROLE-6.1 | Disclosure surface | What the certificate emits about this object is enumerated -- the class identity, the declared authority, the qualifications, the bearer limit and the admissible bearer classes -- and is separated from the identity of any occupant. An unoccupied seat still discloses: a class whose qualifications are narrow enough to admit one person names that person without naming them. | none | none |
| ROLE-6.2 | Bound declaration | Every field enumerated at 6.1 carries a declared disclosure bound naming the observers it is admissible to; a field emitted without a bound is not admissible, and the absence of a bound is never read as an open one. | ROLE-6.1 | none |
| ROLE-6.3 | Observer identification | The observer each bound is stated against is identified as a party rather than as a channel, since a channel can be relayed and a party cannot; where no observer model is established the level reports UNKNOWN and never PASS. | ROLE-6.1 | none |
| ROLE-6.4 | Emission-time evaluation | Each bound is evaluated at every emission of the certificate rather than once when the certificate was made. A bound satisfied at certification and violated at a later emission is not satisfied, and this is the only level in the grid that is not settled by the act of certifying. | ROLE-6.2, ROLE-6.3 | none |
| ROLE-6.5 | Composition delta | Emitting this certificate beside the COLLECTIVE certificate that contains the class discloses the position: a class within bound and a role graph within bound together locate the seat in a structure, and a seat's neighbours narrow its occupant, so the join is evaluated against both operands and not against either alone. | ROLE-6.2, ROLE-6.4 | none |
| ROLE-6.6 | Verdict independence | Redacting any emitted field to satisfy its bound leaves every verdict this object carries at tiers 1 through 5 unchanged. A disclosure bound never changes a computational verdict -- neither upward nor downward -- and a redaction that moves one makes the certificate malformed rather than more private. | ROLE-6.2, ROLE-6.4, ROLE-6.5 | none |

## COLLECTIVE

`COLLECTIVE` is a graph of role classes and the typed relations
between them. It is **ungrounded** -- no adapter executes it. Its operand is declared:
`COLLECTIVE-1.3` binds the `ROLE` set it is over, each class by its own certificate.
`COLLECTIVE-1.1` declares the collective to be that graph rather than binding a `GRAPH`
certificate, so the graph is the object itself and not an operand of it.

`COLLECTIVE-3.1` is the obligation that keeps it honest: a collective takes no decisions
of its own, and every decision it is accountable for was taken through some role class by
some bearer. `COLLECTIVE-3.3` records the limit of what a graph can establish --
separation of duty is real only where the bearers are distinct persons, which structure
alone never shows.

### COLLECTIVE-1: Facets

`COLLECTIVE-1.1` through `COLLECTIVE-1.6`; topological depth 3; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| COLLECTIVE-1.1 | Role graph | The collective is declared as a graph of role classes at a stated coordinate. | none | none |
| COLLECTIVE-1.2 | Relation types | The relations the graph carries are declared and typed -- reports-to, delegates-to, must-countersign -- and an untyped edge is unspecified rather than generic. | COLLECTIVE-1.1 | none |
| COLLECTIVE-1.3 | Role set | The set of role classes the graph is over is enumerated, each bound by its own certificate. | COLLECTIVE-1.1 | none |
| COLLECTIVE-1.4 | Accountable decision classes | The decision classes the collective is accountable for as a whole are declared. | COLLECTIVE-1.1 | none |
| COLLECTIVE-1.5 | Boundary | The boundary of the collective is declared: which classes are inside it and which are outside. | COLLECTIVE-1.1 | none |
| COLLECTIVE-1.6 | Facet completeness | A collective whose relations, role set, decision classes or boundary are unstated is unspecified rather than unbounded. | COLLECTIVE-1.2, COLLECTIVE-1.3, COLLECTIVE-1.4, COLLECTIVE-1.5 | none |

### COLLECTIVE-2: Dynamics

`COLLECTIVE-2.1` through `COLLECTIVE-2.6`; topological depth 3; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| COLLECTIVE-2.1 | Reorganization | A reorganization is declared as an ordered event over the graph, with the edges it adds and the edges it removes. | none | none |
| COLLECTIVE-2.2 | Role lifecycle | Role creation and retirement are declared as events, and a retired class remains in the record rather than being removed from it. | COLLECTIVE-2.1 | none |
| COLLECTIVE-2.3 | Quorum and countersignature | Quorum thresholds and countersignature requirements are declared against the decision classes they gate. | none | none |
| COLLECTIVE-2.4 | Escalation | Escalation paths are declared as edges, and an escalation that follows no declared edge is undeclared rather than implicit. | COLLECTIVE-2.3 | none |
| COLLECTIVE-2.5 | Decision assembly | How a collective decision is assembled from the role decisions beneath it is declared and replayable. | COLLECTIVE-2.3, COLLECTIVE-2.4 | none |
| COLLECTIVE-2.6 | Merger and split | What a merger or a split does to the graph is declared, and the resulting graph is reproduced from the declared events. | COLLECTIVE-2.1, COLLECTIVE-2.2 | none |

### COLLECTIVE-3: Statics

`COLLECTIVE-3.1` through `COLLECTIVE-3.4`; topological depth 3; 0 of 4 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| COLLECTIVE-3.1 | No decisions of its own | The collective takes no decisions of its own: every decision it is accountable for was taken through some role class by some bearer. | none | none |
| COLLECTIVE-3.2 | External legal existence | The legal entity exists or does not exist under some registry, whatever the collective declares about itself; a declaration never constitutes one. | none | none |
| COLLECTIVE-3.3 | Separation of duty needs persons | Separation of duty is real only where the bearers are distinct persons, which the role graph alone cannot establish. | COLLECTIVE-3.1 | none |
| COLLECTIVE-3.4 | Graph impotence | The graph establishes structure and never establishes occupancy; who fills a seat is outside what the graph can say. | COLLECTIVE-3.1, COLLECTIVE-3.3 | none |

### COLLECTIVE-4: Closure

`COLLECTIVE-4.1` through `COLLECTIVE-4.4`; topological depth 4; 0 of 4 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| COLLECTIVE-4.1 | Complete role graph | The role graph is complete: no class in the declared set is unattached to it. | none | none |
| COLLECTIVE-4.2 | Decision decomposition | Every collective-level decision is decomposed into role decisions that actually occurred. | COLLECTIVE-4.1 | none |
| COLLECTIVE-4.3 | Quorum recomputation | Each quorum condition is recomputed over the retained occupancy record rather than accepted as declared. | COLLECTIVE-4.2 | none |
| COLLECTIVE-4.4 | Closure result | The collective is closed only when the graph is complete, every decision decomposes and every quorum recomputes; otherwise the result is UNKNOWN and never FAIL. | COLLECTIVE-4.2, COLLECTIVE-4.3 | none |

### COLLECTIVE-5: Domain adaptation

`COLLECTIVE-5.1` through `COLLECTIVE-5.6`; topological depth 4; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| COLLECTIVE-5.1 | Organizational role mainstay | Legal-entity identifiers together with official organizational role and engagement context role credentials are bound as the mainstay for a declared collective. | none | none |
| COLLECTIVE-5.2 | Corporate registry mapping | Corporate registry records map onto the boundary and legal-existence facets. | none | none |
| COLLECTIVE-5.3 | Access control policy mapping | Role- and attribute-based access control policy models map onto the graph's relation types. | none | none |
| COLLECTIVE-5.4 | Round trip | A collective expressed in a mainstay above and read back reproduces the declared graph without loss. | COLLECTIVE-5.1, COLLECTIVE-5.2, COLLECTIVE-5.3 | none |
| COLLECTIVE-5.5 | Inference upward | A representation that carries less than the facets require is inferred upward and reported as partial rather than as complete. | COLLECTIVE-5.4 | none |
| COLLECTIVE-5.6 | Adaptation accounting | Each adaptation above is reported as established or unestablished, and an absent register is unestablished rather than unincorporated. | COLLECTIVE-5.1, COLLECTIVE-5.2, COLLECTIVE-5.3, COLLECTIVE-5.4, COLLECTIVE-5.5 | none |

### Registered mainstays of COLLECTIVE

None. `COLLECTIVE` has no adapter, so it registers none. The
formats its tier 5 names -- legal-entity identifiers with organizational role
credentials, corporate registry records and access-control policy models -- are named as
unestablished rather than registered.

### COLLECTIVE-6: Disclosure

`COLLECTIVE-6.1` through `COLLECTIVE-6.6`; topological depth 5; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| COLLECTIVE-6.1 | Disclosure surface | What the certificate emits about this object is enumerated -- the role graph, the relation types, the role set, the accountable decision classes and the boundary -- and is separated from the occupancy record. Structure discloses on its own: the shape of a reporting graph infers headcount, seniority and function without naming anyone in it. | none | none |
| COLLECTIVE-6.2 | Bound declaration | Every field enumerated at 6.1 carries a declared disclosure bound naming the observers it is admissible to; a field emitted without a bound is not admissible, and the absence of a bound is never read as an open one. | COLLECTIVE-6.1 | none |
| COLLECTIVE-6.3 | Observer identification | The observer each bound is stated against is identified as a party rather than as a channel, since a channel can be relayed and a party cannot; where no observer model is established the level reports UNKNOWN and never PASS. | COLLECTIVE-6.1 | none |
| COLLECTIVE-6.4 | Emission-time evaluation | Each bound is evaluated at every emission of the certificate rather than once when the certificate was made. A bound satisfied at certification and violated at a later emission is not satisfied, and this is the only level in the grid that is not settled by the act of certifying. | COLLECTIVE-6.2, COLLECTIVE-6.3 | none |
| COLLECTIVE-6.5 | Composition delta | Emitting this certificate beside the IDENTITY certificates of occupancies inside it discloses the membership: a graph within bound and occupancies each within bound together produce a roster that neither states alone, so the join is evaluated against both operands and not against either alone. | COLLECTIVE-6.2, COLLECTIVE-6.4 | none |
| COLLECTIVE-6.6 | Verdict independence | Redacting any emitted field to satisfy its bound leaves every verdict this object carries at tiers 1 through 5 unchanged. A disclosure bound never changes a computational verdict -- neither upward nor downward -- and a redaction that moves one makes the certificate malformed rather than more private. | COLLECTIVE-6.2, COLLECTIVE-6.4, COLLECTIVE-6.5 | none |

## IDENTITY

`IDENTITY` is an occupancy: the binding of a bearer into a role
class. It is **relational** -- it holds between two certified objects rather than
certifying a substrate -- and, like every other object of this family, **ungrounded**.

The bearer is a sum of exactly two branches, `HUMAN` and `BOT`. A bare
`AGENT` is not admissible, and `IDENTITY-1.1` says so: an agent is bounded only by
its observation ceiling, which is an *epistemic* bound, while a role class is an
**authority** container. A seated bare agent would carry bounded epistemics and unbounded
authority. `BOT` is admissible because `BOT = AGENT + SIM` carries the simulation
whose declared law bounds it as an operand, which is also why `IDENTITY-4.5` can require
that no bot binding is presented outside that simulation.

### IDENTITY-1: Facets

`IDENTITY-1.1` through `IDENTITY-1.6`; topological depth 4; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| IDENTITY-1.1 | Bearer binding | The bearer is bound by its own certificate, and the bearer class it is bound as -- HUMAN or BOT -- is stated. A bare AGENT is not an admissible bearer class. | none | none |
| IDENTITY-1.2 | Role binding | The role class the occupancy is into is bound by its own certificate at a stated coordinate. | none | none |
| IDENTITY-1.3 | Occupancy evidence | The evidence supporting the occupancy is bound, distinctly from the evidence supporting the bearer. | IDENTITY-1.1, IDENTITY-1.2 | none |
| IDENTITY-1.4 | Assurance level | The assurance level claimed for the binding is declared together with the retained evidence it rests on. | IDENTITY-1.3 | none |
| IDENTITY-1.5 | Inherited scope | The scope the binding inherits from its bearer class's statics is declared, since the bearer class is what bounds the occupancy. | IDENTITY-1.1 | none |
| IDENTITY-1.6 | Validity and revocation surface | The validity interval, the revocation surface, and whether the binding is disclosed or held, are declared together. | IDENTITY-1.3, IDENTITY-1.4 | none |

### IDENTITY-2: Dynamics

`IDENTITY-2.1` through `IDENTITY-2.7`; topological depth 3; 0 of 7 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| IDENTITY-2.1 | Enrollment | Enrollment of a bearer into the seat is declared as an event with its position in the order. | none | none |
| IDENTITY-2.2 | Re-verification and renewal | Re-verification and renewal are declared as their own events, and never as continuations of the original enrollment. | IDENTITY-2.1 | none |
| IDENTITY-2.3 | Hand-over | A hand-over of the seat ends one binding and begins another, and never transfers a binding between bearers. | IDENTITY-2.1 | none |
| IDENTITY-2.4 | Revocation | Revocation withdraws the binding from the position at which it takes effect, and is distinguished from expiry by the clock. | IDENTITY-2.1 | none |
| IDENTITY-2.5 | Presentation | What a presentation of the binding conveys is declared, together with how many presentations were made. | IDENTITY-2.1 | none |
| IDENTITY-2.6 | Presentation linkability | Whether two presentations of one binding are linkable to each other is declared, and unlinkability is established rather than assumed. | IDENTITY-2.5 | none |
| IDENTITY-2.7 | Simulation end | What happens to a bot binding when its declared simulation ends or is superseded is declared; a binding whose simulation has ended is lapsed rather than portable. | IDENTITY-2.1 | none |

### IDENTITY-3: Statics

`IDENTITY-3.1` through `IDENTITY-3.6`; topological depth 3; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| IDENTITY-3.1 | Bearer-bounded | A binding never has wider bounds than its bearer class's statics allow. This is the weakest-operand shape of the Prime Invariant, one relation over. | none | none |
| IDENTITY-3.2 | Multiple occupancy | One bearer occupies several role classes at once, and no protocol makes those occupancies independent of one another. | none | none |
| IDENTITY-3.3 | Evidence ceiling | A binding is never stronger than the bearer evidence it rests on, whatever assurance level it declares. | IDENTITY-3.1 | none |
| IDENTITY-3.4 | Revocation does not un-happen | A revoked binding does not un-happen: what was decided in the seat stays decided, and revocation is prospective only. | none | none |
| IDENTITY-3.5 | The binding is not the bearer | Ending a binding ends an occupancy and nothing else. It never ends, weakens or revokes the bearer. | IDENTITY-3.4 | none |
| IDENTITY-3.6 | Weakest operand | The binding's bound is the meet of the bearer's bound and the role class's, and never the join of them. | IDENTITY-3.1, IDENTITY-3.3 | none |

### IDENTITY-4: Closure

`IDENTITY-4.1` through `IDENTITY-4.7`; topological depth 3; 0 of 7 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| IDENTITY-4.1 | Presentation binding | Every presentation is bound to an enrollment that was not revoked at presentation time. | none | none |
| IDENTITY-4.2 | Assurance support | The declared assurance level is supported by evidence actually retained, rather than by evidence once seen. | IDENTITY-4.1 | none |
| IDENTITY-4.3 | No self-asserted attribute | No binding rests on a self-asserted attribute of the bearer. | IDENTITY-4.1 | none |
| IDENTITY-4.4 | Bearer class declared | Every binding declares its bearer class, and a binding that declares none is malformed rather than defaulted. | none | none |
| IDENTITY-4.5 | Bot containment | No bot binding is presented outside its declared simulation; a bot identity exists within its simulation and nowhere else. | IDENTITY-4.4 | none |
| IDENTITY-4.6 | Human exit | Where the bearer is a human, that human retains unilateral termination of the binding, and a binding that removes the exit is malformed. | IDENTITY-4.4 | none |
| IDENTITY-4.7 | Closure result | The binding is closed only when presentation binding, assurance support, attribute exclusion, bot containment and the human exit all hold; otherwise the result is UNKNOWN and never FAIL. | IDENTITY-4.2, IDENTITY-4.3, IDENTITY-4.5, IDENTITY-4.6 | none |

### IDENTITY-5: Domain adaptation

`IDENTITY-5.1` through `IDENTITY-5.7`; topological depth 6; 0 of 7 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| IDENTITY-5.1 | Verifiable credential mainstay | Verifiable credential data models are bound as the mainstay for a presented occupancy. | none | none |
| IDENTITY-5.2 | Decentralized identifier mapping | Decentralized identifier syntax and resolution map onto the bearer and role bindings. | none | none |
| IDENTITY-5.3 | Selective disclosure mapping | Selective-disclosure cryptosuites map onto the disclosure surface of the binding. | IDENTITY-5.1 | none |
| IDENTITY-5.4 | Unlinkability mapping | Per-presentation unlinkability maps onto the linkability dynamic, and is reported as established only where the cryptosuite provides it. | IDENTITY-5.3 | none |
| IDENTITY-5.5 | Round trip | A binding expressed in a mainstay above and read back reproduces the declared facets without loss. | IDENTITY-5.1, IDENTITY-5.2, IDENTITY-5.3, IDENTITY-5.4 | none |
| IDENTITY-5.6 | Inference upward | A representation that carries less than the facets require is inferred upward and reported as partial rather than as complete. | IDENTITY-5.5 | none |
| IDENTITY-5.7 | Adaptation accounting | Each adaptation above is reported as established or unestablished, and an absent credential is unestablished rather than unoccupied. Proof-of-personhood mainstays are not here: they establish humanness, which is HUMAN-5. | IDENTITY-5.1, IDENTITY-5.2, IDENTITY-5.3, IDENTITY-5.4, IDENTITY-5.5, IDENTITY-5.6 | none |

### Registered mainstays of IDENTITY

None. `IDENTITY` has no adapter, so it registers none. The formats
its tier 5 names -- verifiable credential data models, decentralized identifiers and
selective-disclosure cryptosuites -- are named as unestablished rather than registered.
Proof-of-personhood formats are deliberately not here: they establish humanness, which is
`HUMAN-5`.

### IDENTITY-6: Disclosure

`IDENTITY-6.1` through `IDENTITY-6.6`; topological depth 5; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| IDENTITY-6.1 | Disclosure surface | What the certificate emits about this object is enumerated -- the bearer class, the role binding, the assurance level, the validity interval and the revocation surface -- and is separated from the bearer's own identity. The occupancy is the linking field in this family: it names a bearer and a seat in one statement, so emitting it discloses a correspondence that neither endpoint discloses alone. | none | none |
| IDENTITY-6.2 | Bound declaration | Every field enumerated at 6.1 carries a declared disclosure bound naming the observers it is admissible to; a field emitted without a bound is not admissible, and the absence of a bound is never read as an open one. | IDENTITY-6.1 | none |
| IDENTITY-6.3 | Observer identification | The observer each bound is stated against is identified as a party rather than as a channel, since a channel can be relayed and a party cannot; where no observer model is established the level reports UNKNOWN and never PASS. | IDENTITY-6.1 | none |
| IDENTITY-6.4 | Emission-time evaluation | Each bound is evaluated at every emission of the certificate rather than once when the certificate was made. A bound satisfied at certification and violated at a later emission is not satisfied, and this is the only level in the grid that is not settled by the act of certifying. | IDENTITY-6.2, IDENTITY-6.3 | none |
| IDENTITY-6.5 | Composition delta | Emitting this certificate beside a second presentation of the same occupancy discloses the linkage: two presentations each within bound reveal that they are the same bearer, which is the fact per-presentation unlinkability exists to withhold, so the join is evaluated against both operands and not against either alone. | IDENTITY-6.2, IDENTITY-6.4 | none |
| IDENTITY-6.6 | Verdict independence | Redacting any emitted field to satisfy its bound leaves every verdict this object carries at tiers 1 through 5 unchanged. A disclosure bound never changes a computational verdict -- neither upward nor downward -- and a redaction that moves one makes the certificate malformed rather than more private. | IDENTITY-6.2, IDENTITY-6.4, IDENTITY-6.5 | none |
## ACTOR

`ACTOR` is the party accountable for decisions, and it is the sum
the rest of the family is assembled into: `ACTOR-1.2` binds exactly one of a `ROLE`
certificate or a `COLLECTIVE` certificate, and an actor binding both is malformed
rather than both. It is **ungrounded** -- no adapter executes it -- and it is **not
relational**: it is an entity rather than a relation between certified objects, which is
what separates it from `OWNER` and `IDENTITY`.

**An agent is not an actor.** An agent decides; an actor answers for it. Those are
different relations, and only one of them can be borne by a person or a company -- which
is why `ACTOR` splits into two branches and `AGENT` splits into none. The
distinction is positional: an agent's decisions are made *inside* an observation ceiling,
and an actor's decisions are the ones that *placed* it. `ACTOR-1.6` draws that line and
`ACTOR-3.5` keeps it -- an instrument is never a party, so attributing a decision to an
instrument attributes it to no one.

`ACTOR-3.4` is what keeps the object honest: an actor cannot be the sole witness of its
own accountability, so an attribution resting only on a record the actor exclusively
controls establishes nothing, and `ACTOR-4.5` carries that into closure.

The bearer is deliberately absent. A role-branch actor admits bearer classes and a
collective-branch actor has no bearer at all, so a bearer field here would force a
collective to declare itself human or bot. The bearer sits on the occupancy, at
`IDENTITY-1.1`.

### ACTOR-1: Facets

`ACTOR-1.1` through `ACTOR-1.7`; topological depth 4; 0 of 7 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| ACTOR-1.1 | Actor identity | The actor is named at a stated coordinate, as the party accountable for decisions rather than as any instrument that executes them. | none | none |
| ACTOR-1.2 | Branch binding | The actor is bound by exactly one of a ROLE certificate or a COLLECTIVE certificate at a stated coordinate. An actor binding neither is unspecified rather than either, and an actor binding both is malformed rather than both. | ACTOR-1.1 | none |
| ACTOR-1.3 | Control surface | The key material the actor controls is declared; control is a property of the actor rather than of any key, and a key the declaration omits is not controlled. | ACTOR-1.1 | none |
| ACTOR-1.4 | Decision classes | The classes of decision the actor is accountable for are declared, and a class the declaration omits is not carried. | ACTOR-1.1 | none |
| ACTOR-1.5 | Admitted specification spaces | The specification spaces the actor is admitted to act in are declared, and admission to one is never read as admission to another. | ACTOR-1.1 | none |
| ACTOR-1.6 | Instrument boundary | The boundary between the actor and the instruments it operates is declared. An instrument executes and the actor answers; a component on either side of that line is one or the other and never both. | ACTOR-1.3, ACTOR-1.4 | none |
| ACTOR-1.7 | Facet completeness | An actor whose branch, control surface, decision classes, admitted spaces or instrument boundary is unstated is unspecified rather than unconstrained. | ACTOR-1.2, ACTOR-1.3, ACTOR-1.4, ACTOR-1.5, ACTOR-1.6 | none |

### ACTOR-2: Dynamics

`ACTOR-2.1` through `ACTOR-2.7`; topological depth 5; 0 of 7 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| ACTOR-2.1 | Delegation | A delegation conveying a subset of the actor's decision authority to another actor is declared as an event at a stated position, with the subset and the interval named. | none | none |
| ACTOR-2.2 | Revocation | Revoking a delegation is declared as an event; revocation ends the conveyance forward and never reaches decisions already taken under it. | ACTOR-2.1 | none |
| ACTOR-2.3 | Key rotation | Rotating key material preserves the actor's continuity: the actor after rotation is the same actor, and the rotation is declared as an event rather than as a new actor. | none | none |
| ACTOR-2.4 | Collective membership | A role-branch actor entering or leaving a collective's graph is declared as an event; membership is a relation the actor enters rather than a property it carries. | ACTOR-2.1 | none |
| ACTOR-2.5 | Dissolution | Dissolution is declared as an event: a collective that is wound up and a role class that is retired each end the actor's capacity to decide from that position forward, and neither ends what it already decided. | ACTOR-2.1, ACTOR-2.4 | none |
| ACTOR-2.6 | Succession | Succession when the actor is replaced in its position is declared as a paired ending and beginning at one position; accountability for decisions taken before the succession does not move. | ACTOR-2.2, ACTOR-2.3, ACTOR-2.5 | none |
| ACTOR-2.7 | Accountability replay | Replaying the declared events from the first reproduces the current delegation, key and membership state. | ACTOR-2.2, ACTOR-2.3, ACTOR-2.4, ACTOR-2.5, ACTOR-2.6 | none |

### ACTOR-3: Statics

`ACTOR-3.1` through `ACTOR-3.6`; topological depth 3; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| ACTOR-3.1 | Decisions are factual | A decision once taken was taken, and no later event makes an actual decision not have happened. | none | none |
| ACTOR-3.2 | Non-transferable accountability | Accountability for a decision cannot be retroactively transferred; a later delegation never moves an earlier decision's accountability. | ACTOR-3.1 | none |
| ACTOR-3.3 | Revocation does not un-decide | Past decisions remain the actor's own after revocation, rotation or dissolution. Ending an actor's capacity to decide never ends its record of having decided. | ACTOR-3.1, ACTOR-3.2 | none |
| ACTOR-3.4 | No sole witness | An actor cannot be the sole witness of its own accountability: an attribution resting only on a record the actor exclusively controls establishes nothing. | none | none |
| ACTOR-3.5 | Instrument is not a party | An instrument the actor operates is never a party to the decision, so attributing a decision to an instrument attributes it to no one. | none | none |
| ACTOR-3.6 | Weakest operand | Where accountability is established through a composition it is bounded by the weakest operand, never by the strongest. | ACTOR-3.2, ACTOR-3.4 | none |

### ACTOR-4: Closure

`ACTOR-4.1` through `ACTOR-4.6`; topological depth 4; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| ACTOR-4.1 | Decision inventory | The decisions the certificate accounts for are enumerated and contiguous over the declared interval, each at a stated position. | none | none |
| ACTOR-4.2 | Exactly one actor | Every decision in the declared classes is attributable to exactly one actor. | ACTOR-4.1 | none |
| ACTOR-4.3 | None unattributed | No decision in the declared classes is left unattributed. | ACTOR-4.1, ACTOR-4.2 | none |
| ACTOR-4.4 | None doubly attributed | No decision in the declared classes is attributed to two actors; joint accountability is declared as a collective rather than as duplicate attribution. | ACTOR-4.1, ACTOR-4.2 | none |
| ACTOR-4.5 | Independent attribution | No attribution rests on a record the actor exclusively controls. | ACTOR-4.2 | none |
| ACTOR-4.6 | Closure result | The inventory, the attributions and their independence are reported together; a closure missing any of the three is incomplete rather than passing. | ACTOR-4.3, ACTOR-4.4, ACTOR-4.5 | none |

### ACTOR-5: Domain adaptation

`ACTOR-5.1` through `ACTOR-5.6`; topological depth 4; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| ACTOR-5.1 | Mainstay binding | The accountability mainstays the actor is expressed in are declared. | none | none |
| ACTOR-5.2 | Key event mapping | The key event receipt infrastructure control-and-rotation model maps onto the control surface and the rotation event, and a rotation the mapping cannot express is reported rather than dropped. | ACTOR-5.1 | none |
| ACTOR-5.3 | Controller mapping | The decentralized identifier controller and verification-relationship model maps onto the control surface and the declared decision classes. | ACTOR-5.1 | none |
| ACTOR-5.4 | Principal mapping | The authorization-framework principal maps onto the actor, and the distinction between a principal and the client acting for it maps onto the instrument boundary. | ACTOR-5.1 | none |
| ACTOR-5.5 | Round trip | An actor expressed in a mainstay, mapped upward and expressed again yields the same declared control surface and decision classes. | ACTOR-5.2, ACTOR-5.3, ACTOR-5.4 | none |
| ACTOR-5.6 | Inference upward | The mainstays are inferred upward into one accountability meta-framework, and a construct no mainstay supports is declared rather than assumed. | ACTOR-5.5 | none |

### Registered mainstays of ACTOR

None. `ACTOR` has no adapter, so it registers none. The formats its
tier 5 names -- key event receipt infrastructure, decentralized identifier controllers and
authorization-framework principals -- are named as unestablished rather than registered.

### ACTOR-6: Disclosure

`ACTOR-6.1` through `ACTOR-6.6`; topological depth 5; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| ACTOR-6.1 | Disclosure surface | What the certificate emits about this object is enumerated -- the actor identity, the bound branch, the control surface, the declared decision classes and the admitted specification spaces -- and is separated from the content of any decision taken. An actor discloses through its decision classes alone: a class narrow enough to be exercised by one party names that party without naming them. | none | none |
| ACTOR-6.2 | Bound declaration | Every field enumerated at 6.1 carries a declared disclosure bound naming the observers it is admissible to; a field emitted without a bound is not admissible, and the absence of a bound is never read as an open one. | ACTOR-6.1 | none |
| ACTOR-6.3 | Observer identification | The observer each bound is stated against is identified as a party rather than as a channel, since a channel can be relayed and a party cannot; where no observer model is established the level reports UNKNOWN and never PASS. | ACTOR-6.1 | none |
| ACTOR-6.4 | Emission-time evaluation | Each bound is evaluated at every emission of the certificate rather than once when the certificate was made. A bound satisfied at certification and violated at a later emission is not satisfied, and this is the only level in the grid that is not settled by the act of certifying. | ACTOR-6.2, ACTOR-6.3 | none |
| ACTOR-6.5 | Composition delta | Emitting this certificate beside the OWNER certificate of a holding this actor carries discloses the relation: an actor within bound and a holding within bound together locate the party in a structure of things held, and what a party holds narrows who it is, so the join is evaluated against both operands and not against either alone. | ACTOR-6.2, ACTOR-6.4 | none |
| ACTOR-6.6 | Verdict independence | Redacting any emitted field to satisfy its bound leaves every verdict this object carries at tiers 1 through 5 unchanged. A disclosure bound never changes a computational verdict -- neither upward nor downward -- and a redaction that moves one makes the certificate malformed rather than more private. | ACTOR-6.2, ACTOR-6.4, ACTOR-6.5 | none |
## TOKEN

`TOKEN` is the zero-identity zero-knowledge token: the object that carries a
bearer's tenure and delegated scope without carrying who the bearer is. It has three
kinds, and a token is exactly one of them. A **birth token** commits to a genesis key
under a salt and publishes only the commitment. An **aging token** folds each epoch and
its status into an accumulator, so tenure accrues without any epoch becoming editable
afterwards. A **lifetime token** is a soulbound capability lease: it names its delegate
at issuance, bounds itself by a validity window and an invocation count, and attenuates
from a parent grant. The normative construction is `ZIZK_TOKENS.md`; the obligations
below are what an implementation of it must satisfy.

**The Prime Invariant governs this object: an actor identity never upgrades a
computational verdict.** Tenure is a quantity of time, not a quantity of authority.
`TOKEN-3.5` states it arithmetically -- no accumulator value implies any permitted
scope -- and `statics:authority` executes it, refusing any lease that conveys a scope
outside the root grant however long its holder has been accruing epochs. This is the
same rule level 6 states for disclosure, at a different tier and about a different
quantity.

`TOKEN` is **grounded and certifiable**, which `HYPER` can never be: `HYPER` has no
substrate of its own, because it is the operator that holds *between* objects rather
than over one, while `TOKEN` has a substrate -- the commitment, the accumulator and the
lease algebra. Until 2026-09-22 the working mechanics over it lived only in
`verifier.identity`, outside `verifier.domains`, so `TOKEN` had no entry in
`verifier.domains.catalog.CHECKS` and `profile_obligations` listed it in
`ADAPTER_PENDING_OBJECTS`, separately from `OPERATOR_OBJECTS`, because only that reason
could ever be discharged. `verifier.domains.token` now replays the holding under
`CHECKS["TOKEN"]` from retained evidence of its own -- the tokens, the epoch trace and
the status observations -- rather than by wrapping `verifier.identity`. A new module
joining the `verifier.domains` tuple moves `implementation_digest()`, so every domain
policy issued before it has to be readmitted.

The adapter mechanizes each row one of its checks establishes as written and leaves the
rest `UNKNOWN`, each for want of evidence it does not retain: the opening of the genesis
commitment (`TOKEN-1.3`), withheld fields (`TOKEN-1.14`, `TOKEN-4.13`), consumed
invocations (`TOKEN-2.5`), an attenuation made without returning to the issuer, where
every token it replays is issuer-signed (`TOKEN-2.6`), a third party's discharge
(`TOKEN-2.7`, `TOKEN-4.10`), a presentation event (`TOKEN-2.8`) and a replacement
relation (`TOKEN-2.10`). `TOKEN-2.14` and `TOKEN-4.14` depend on rows among those, so
they stay `UNKNOWN` with them. Two rows are mechanized under a stated reading.
`TOKEN-2.9` takes a key's retirement as an instant on the named clock, the only reading
under which it is comparable with an issuance instant, and `TOKEN-4.4` takes the
contract's root scopes as the scopes the birth token held, since a birth token binds
none.

### TOKEN-1: Facets

`TOKEN-1.1` through `TOKEN-1.14`; topological depth 5; 12 of 14 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| TOKEN-1.1 | Token kind | The token is exactly one of birth, aging or lifetime, declared at a stated coordinate. A token of no declared kind is malformed, and a token of two is malformed rather than both. | none | inventory |
| TOKEN-1.2 | Canonical bytes | The canonical byte serialization is bound, and it excludes the signature field, so the signed preimage is recomputable from the token rather than trusted alongside it. | TOKEN-1.1 | signatures |
| TOKEN-1.3 | Genesis commitment | A birth token binds a commitment over the genesis key digest, the birth epoch and a salt. The commitment is the token's whole claim about origin: it establishes that the controlling key existed at or before the epoch, and nothing else. | TOKEN-1.1 | none |
| TOKEN-1.4 | Tenure accumulator | An aging token binds an accumulator digest and the epoch interval it spans, each step folding its predecessor, so tenure is carried as a chain rather than as a stated number. | TOKEN-1.1 | tenure |
| TOKEN-1.5 | Lease scope | A lifetime token binds the permitted scopes, the validity window and, where one is declared, the invocation bound. A scope the declaration omits is not conveyed. | TOKEN-1.1 | inventory |
| TOKEN-1.6 | Issuance binding | Every token binds the key that issued it and the instant it was issued, and an unbound issuer makes the token unspecified rather than self-issued. | TOKEN-1.2, TOKEN-1.3, TOKEN-1.4, TOKEN-1.5 | inventory |
| TOKEN-1.7 | Algorithm binding | The signature algorithm is bound inside the signed preimage, and the algorithms a verifier will accept are declared separately from the token. An algorithm a token names for itself is a request rather than a fact about it. | TOKEN-1.2, TOKEN-1.6 | signatures |
| TOKEN-1.8 | Key identification | The issuing key is identified by a digest of the key itself. An identifier that has to be resolved through a directory the token points at identifies whatever that directory returns, which is not the same thing. | TOKEN-1.6 | signatures |
| TOKEN-1.9 | Audience | The verifiers the token is addressed to are bound. A token that names none is addressed to every verifier, which is a scope the certificate states rather than a field it omits. | TOKEN-1.5 | inventory |
| TOKEN-1.10 | Validity window | Not-before and expiry are bound as instants on a named clock. A token binding no expiry declares an unbounded window, and the certificate reports it as unbounded rather than as unstated. | TOKEN-1.5 | inventory |
| TOKEN-1.11 | Replay identifier | Each issuance binds an identifier unique to it, so a token presented twice is distinguishable from two tokens issued alike. | TOKEN-1.6 | inventory |
| TOKEN-1.12 | Confirmation key | A token that is not a bearer token binds the key its presenter must prove possession of. A token binding none is a bearer token and is declared as one. | TOKEN-1.5, TOKEN-1.8 | inventory |
| TOKEN-1.13 | Caveat set | The conditions attached to a lease are bound as an ordered set, each carrying what would discharge it. A condition with no stated discharge restricts the lease permanently rather than conditionally. | TOKEN-1.5 | inventory |
| TOKEN-1.14 | Disclosure digests | Where a field may be withheld, the token binds a digest of the field rather than the field. A withheld field is then absent from the token and accounted for by its digest, rather than present and hidden. | TOKEN-1.2 | none |

### TOKEN-2: Dynamics

`TOKEN-2.1` through `TOKEN-2.14`; topological depth 5; 8 of 14 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| TOKEN-2.1 | Genesis | Birth is an event at a stated epoch, and no token of any kind is valid before the birth it descends from. | none | tenure |
| TOKEN-2.2 | Epoch advance | Tenure advances one accumulator step per epoch, each step binding the digest of the step before it and the status recorded at that epoch. | TOKEN-2.1 | tenure |
| TOKEN-2.3 | Revocation | Revocation is an event that ends tenure from that epoch forward. It never reaches epochs already accumulated, and it is not an erasure of them. | TOKEN-2.2 | tenure |
| TOKEN-2.4 | Lease grant | A lease is granted from a parent grant and conveys a subset of the parent's scopes. A grant conveying a scope its parent lacks is malformed rather than an extension. | TOKEN-2.1 | leases |
| TOKEN-2.5 | Lease expiry | A lease ends at its stated instant or at its invocation bound, whichever is reached first. Expiry is not revocation, and a certificate that reports one as the other is wrong about which event occurred. | TOKEN-2.4 | none |
| TOKEN-2.6 | Attenuation | A holder narrows a lease it already holds without returning to the issuer. The narrowed lease descends from the one it attenuates and can never re-widen, so attenuation is an event with a direction. | TOKEN-2.4 | none |
| TOKEN-2.7 | Discharge | A condition owed to a third party is satisfied by that party, not by the holder asserting it. An undischarged condition leaves the lease unusable rather than unconditional. | TOKEN-2.6 | none |
| TOKEN-2.8 | Presentation | Presenting a token is an event distinct from holding it. Where a confirmation key is bound, possession is proved at presentation and the proof binds the instant it was made. | TOKEN-2.5 | none |
| TOKEN-2.9 | Key rotation | An issuing key is retired at a stated epoch. Tokens issued before that epoch stay verifiable under the retired key, and a token issued under it afterwards is invalid rather than merely suspect. | TOKEN-2.1 | signatures |
| TOKEN-2.10 | Reissuance | Reissuance mints a token descending from the same genesis. It never extends the token it replaces, and the replaced token ends on its own terms rather than on the new one's. | TOKEN-2.1, TOKEN-2.4 | none |
| TOKEN-2.11 | Suspension | Suspension halts tenure accrual without ending it. Resumption continues the accumulator rather than restarting it, so a suspended interval is visible in the chain rather than missing from it. | TOKEN-2.2, TOKEN-2.3 | tenure |
| TOKEN-2.12 | Status publication | Revocation status is published on a schedule the certificate states. A status older than that schedule is stale, and an absent status is unobserved rather than clear. | TOKEN-2.3 | closure |
| TOKEN-2.13 | Clock disagreement | The issuing clock and the verifying clock are separate. A window evaluated across them carries the stated skew, and an event falling inside the skew is undetermined rather than resolved in either direction. | TOKEN-2.5 | closure |
| TOKEN-2.14 | Chain replay | Replaying the events from genesis reproduces the current accumulator digest, the revocation status, the suspended intervals, the attenuations and the set of outstanding leases. | TOKEN-2.2, TOKEN-2.3, TOKEN-2.5, TOKEN-2.6, TOKEN-2.11, TOKEN-2.12 | none |

### TOKEN-3: Statics

`TOKEN-3.1` through `TOKEN-3.14`; topological depth 5; 14 of 14 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| TOKEN-3.1 | Preimage resistance | The commitment hides its opening because the hash function is preimage-resistant, which is a property of the function observed rather than a property of the token declared. | none | statics:hash |
| TOKEN-3.2 | Chain one-wayness | The accumulator is one-way over its history: an epoch cannot be inserted, removed or reordered without changing every digest after it. | TOKEN-3.1 | statics:chain |
| TOKEN-3.3 | Commitment binding | A commitment fixes exactly one opening. A second opening that verifies is a collision in the hash function, never an alternative reading of the same token. | TOKEN-3.1 | statics:binding |
| TOKEN-3.4 | Soulbound non-transfer | A soulbound lease names its delegate at issuance, and no operation defined on the token moves it to another delegate. Transfer is not forbidden by policy here; it is absent from the algebra. | none | statics:soulbound |
| TOKEN-3.5 | Tenure is not authority | Elapsed tenure is a quantity of time and confers no scope. No accumulator value implies any permitted scope, and no scope implies any tenure -- this is the Prime Invariant in its arithmetic form. | TOKEN-3.2 | statics:authority |
| TOKEN-3.6 | Algorithm confusion | A verifier that accepts both a symmetric and an asymmetric algorithm for one key accepts a token signed with the public key as though it were signed by the private one. This is a property of the accepted set, not of any token presented under it. | TOKEN-3.1 | statics:algorithm |
| TOKEN-3.7 | Key identity | A key identifier that is a digest of the key resolves to that key and to nothing else. An identifier the token chooses resolves to whatever answers to it. | TOKEN-3.1 | statics:keying |
| TOKEN-3.8 | Window emptiness | A window ending at or before it starts contains no instant, so no token is valid within it. Emptiness is arithmetic on the bound instants rather than a judgement about the issuer. | none | statics:window |
| TOKEN-3.9 | Possession is not presentation | Holding a token and being the party it was issued to are different facts. Only a proof under the bound confirmation key establishes the second, and a bearer token establishes it for nobody. | TOKEN-3.7 | statics:possession |
| TOKEN-3.10 | Attenuation is one-way | Conditions accumulate along a delegation path and are never removed by a later step. A step that drops a condition has widened the lease, whatever it is called. | TOKEN-3.5 | statics:attenuation |
| TOKEN-3.11 | Freshness is not validity | A status observation is evidence about the epoch it was published in, not about the epoch it is read in. Age is recomputed from the two instants, and it never becomes zero by being relied upon. | TOKEN-3.8 | statics:freshness |
| TOKEN-3.12 | Replay distinctness | Two presentations carrying one issuance identifier are one issuance presented twice. No property of the token distinguishes them, which is why the identifier has to. | TOKEN-3.3 | statics:replay |
| TOKEN-3.13 | Disclosure complement | Withheld and disclosed fields partition the bound digests. Neither side is inferable from the other, so a field in neither is unaccounted for rather than withheld by default. | TOKEN-3.1 | statics:disclosure |
| TOKEN-3.14 | Choice independence | The facts above hold for any key, salt and epoch schedule an issuer may choose, so none of them is a property of a particular deployment. | TOKEN-3.3, TOKEN-3.5, TOKEN-3.6, TOKEN-3.7, TOKEN-3.8, TOKEN-3.9, TOKEN-3.10, TOKEN-3.11, TOKEN-3.12, TOKEN-3.13 | statics:independence |

### TOKEN-4: Closure

`TOKEN-4.1` through `TOKEN-4.14`; topological depth 4; 11 of 14 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| TOKEN-4.1 | Inventory | The tokens the certificate accounts for are enumerated, each at a stated coordinate, and the enumeration is the whole holding rather than a selected part of it. | none | inventory |
| TOKEN-4.2 | Epoch contiguity | The accumulated epochs form an uninterrupted interval with no gap, and a gap is reported as a gap rather than closed by restating the endpoints. | TOKEN-4.1 | tenure |
| TOKEN-4.3 | Parent binding | Every lease binds its exact parent grant, and a lease with no parent binds the birth token directly. A lease whose parent is absent from the inventory resolves to nothing. | TOKEN-4.1 | leases |
| TOKEN-4.4 | Scope monotonicity | Scope is non-increasing along every path of the delegation tree, so no reachable lease conveys a scope the birth token never held. | TOKEN-4.3 | leases |
| TOKEN-4.5 | Signature closure | Every token in the inventory verifies under the issuing key it binds, against the canonical preimage rather than against a re-serialization of it. | TOKEN-4.1 | signatures |
| TOKEN-4.6 | Algorithm closure | Every token in the inventory verifies under exactly one algorithm, and the accepted set contains no algorithm the inventory never uses. An unused accepted algorithm is surface the closure reports rather than ignores. | TOKEN-4.1 | signatures |
| TOKEN-4.7 | Key closure | Every issuing key the inventory refers to is present in the bound key set, and every key in the set is referred to. A key present but unused is reported as unused. | TOKEN-4.1 | signatures |
| TOKEN-4.8 | Audience closure | Every token resolves to a verifier in the bound audience set. A token addressed outside it is reported at its coordinate rather than dropped from the count. | TOKEN-4.1 | closure |
| TOKEN-4.9 | Window coverage | The validity windows are reported as an interval set over the certificate period. A token whose window lies wholly outside that period is reported as out of period rather than omitted. | TOKEN-4.1 | closure |
| TOKEN-4.10 | Discharge closure | Every condition owed to a third party has a discharge in the inventory, and an undischarged condition is reported as undischarged rather than as satisfied by absence. | TOKEN-4.1, TOKEN-4.3 | none |
| TOKEN-4.11 | Replay closure | The issuance identifiers over the inventory are distinct. A repetition is reported with both coordinates, because which two collided is the finding. | TOKEN-4.1 | inventory |
| TOKEN-4.12 | Status coverage | Every token carries a status observation no older than the published schedule. A token with none is reported as unobserved, which is not the same result as active. | TOKEN-4.1 | closure |
| TOKEN-4.13 | Disclosure closure | The disclosed and the withheld fields together account for every bound digest exactly once, with neither side inferred from the other. | TOKEN-4.1 | none |
| TOKEN-4.14 | Closure result | The inventory, the contiguity, the scope monotonicity, the signature closure and every closure above are reported together. A closure that omits any of them is incomplete rather than passing. | TOKEN-4.2, TOKEN-4.4, TOKEN-4.5, TOKEN-4.6, TOKEN-4.7, TOKEN-4.8, TOKEN-4.9, TOKEN-4.10, TOKEN-4.11, TOKEN-4.12, TOKEN-4.13 | none |

### TOKEN-5: Domain adaptation

`TOKEN-5.1` through `TOKEN-5.14`; topological depth 5; 14 of 14 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| TOKEN-5.1 | Mainstay binding | The token format the object is expressed in is named and version-pinned. | none | mainstay:binding |
| TOKEN-5.2 | Claim-set mapping | The mainstay's claim set is mapped onto the declared facets, and a facet the claim set cannot carry is reported rather than dropped. | TOKEN-5.1 | mainstay:layout |
| TOKEN-5.3 | Validity-window mapping | The mainstay's validity model is mapped onto the lease window and the accumulated epoch interval. | TOKEN-5.1 | mainstay:schema |
| TOKEN-5.4 | Attenuation mapping | The mainstay's delegation or attenuation model is mapped onto the scope subset relation, which is the one structure most token formats do carry. | TOKEN-5.2 | mainstay:upstream |
| TOKEN-5.5 | Round trip | A token expressed in a mainstay, mapped upward and expressed again yields the same canonical bytes. | TOKEN-5.3, TOKEN-5.4 | mainstay:roundtrip |
| TOKEN-5.6 | Header metadata mapping | The declared provenance and statics map onto the mainstay's metadata record. A parameter the mainstay carries outside the signed region is named as unprotected rather than counted as bound. | TOKEN-5.1 | mainstay:metadata |
| TOKEN-5.7 | Proof attestation mapping | The issuance attestation maps onto the mainstay's attestation or proof format, and an attestation that format cannot carry is named rather than approximated by one it can. | TOKEN-5.1 | mainstay:attestation |
| TOKEN-5.8 | Ceiling mapping | The declared ceilings map onto the mainstay's limit model. A ceiling the mainstay has no field for is named as unexpressible rather than written into a field a verifier will ignore. | TOKEN-5.2 | mainstay:limits |
| TOKEN-5.9 | Presentation authorization mapping | Proof of possession at presentation maps onto the mainstay's authorization model. A mainstay with only bearer semantics is reported as bearer-only, which is a finding about the format. | TOKEN-5.1 | mainstay:authorization |
| TOKEN-5.10 | Attenuation operators | The attenuation operators the mainstay's operation set cannot express are named. A format that can only reissue cannot attenuate, and the difference belongs to the format rather than to the holding. | TOKEN-5.4 | mainstay:operators |
| TOKEN-5.11 | Selective disclosure mapping | What the token discloses in the mainstay's encoding is enumerated at its coordinates. | TOKEN-5.2 | mainstay:disclosed |
| TOKEN-5.12 | Withheld field mapping | What it does not disclose is named as unestablished rather than absent, so a field withheld in the mainstay is not read as a field the object lacks. | TOKEN-5.11 | mainstay:indisclosed |
| TOKEN-5.13 | Transparency inclusion | Inclusion in whatever public log the mainstay defines is recorded rather than inferred. A mainstay defining no log records that absence rather than treating non-inclusion as exclusion. | TOKEN-5.1 | mainstay:inclusion |
| TOKEN-5.14 | Inference upward | What the mainstay cannot express is stated as the residual this object carries over it. | TOKEN-5.5, TOKEN-5.6, TOKEN-5.7, TOKEN-5.8, TOKEN-5.9, TOKEN-5.10, TOKEN-5.11, TOKEN-5.12, TOKEN-5.13 | mainstay:residual |

### Registered mainstays of TOKEN

| Format | Carried in | Meta-surface entities | Expresses | Residual |
|---|---|---|---|---|
| JSON Web Token over JOSE (`jose-jwt`) | compact or JSON serialization | JWS-header, claim-set, issuer, subject, expiry, not-before, signature | 4 coordinates | 20 coordinates |
| Concise Binary Object Representation (CBOR) Web Token over CBOR Object Signing and Encryption (COSE) (`cose-cwt`) | COSE_Sign1 structure | protected-header, claim-set, key-identifier, expiry, signature | 3 coordinates | 21 coordinates |
| World Wide Web Consortium (W3C) Verifiable Credential (`w3c-verifiable-credential`) | credential document plus proof | credential, issuer, credentialSubject, proof, status-entry, validity-period | 4 coordinates | 20 coordinates |
| Macaroon and Biscuit attenuable credentials (`macaroon`) | caveat chain over a root key | macaroon, caveat, root-key, chained-signature, discharge | 4 coordinates | 20 coordinates |
| SPIFFE verifiable identity document (`spiffe-svid`) | X.509 or JWT SVID | SVID, trust-domain, workload-identifier, validity-window, trust-bundle | 3 coordinates | 21 coordinates |

### TOKEN-6: Disclosure

`TOKEN-6.1` through `TOKEN-6.6`; topological depth 5; 0 of 6 mechanized.

| Coordinate | Obligation | Requirement | Depends on | Mechanism |
|---|---|---|---|---|
| TOKEN-6.1 | Disclosure surface | What the certificate emits about this object is enumerated -- the token kind, the commitment, the accumulated epoch interval, the revocation status and the permitted scopes -- and is separated from the genesis secret, the salt and the opening of any commitment. | none | none |
| TOKEN-6.2 | Bound declaration | Every field enumerated at 6.1 carries a declared disclosure bound naming the observers it is admissible to; a field emitted without a bound is not admissible, and the absence of a bound is never read as an open one. | TOKEN-6.1 | none |
| TOKEN-6.3 | Observer identification | The observer each bound is stated against is identified as a party rather than as a channel, since a channel can be relayed and a party cannot; where no observer model is established the level reports UNKNOWN and never PASS. | TOKEN-6.1 | none |
| TOKEN-6.4 | Emission-time evaluation | Each bound is evaluated at every emission of the certificate rather than once when the certificate was made. A bound satisfied at certification and violated at a later emission is not satisfied, and this is the only level in the grid that is not settled by the act of certifying. | TOKEN-6.2, TOKEN-6.3 | none |
| TOKEN-6.5 | Composition delta | Emitting this certificate beside an ACTOR certificate discloses correlation: a birth epoch is within bound and a set of decision classes is within bound, while the pair singles the party out, because tenure is close to unique over any population small enough to enumerate. The join is evaluated against both operands and not against either alone. | TOKEN-6.2, TOKEN-6.4 | none |
| TOKEN-6.6 | Verdict independence | Redacting any emitted field to satisfy its bound leaves every verdict this object carries at tiers 1 through 5 unchanged. A disclosure bound never changes a computational verdict -- neither upward nor downward -- and a redaction that moves one makes the certificate malformed rather than more private. | TOKEN-6.2, TOKEN-6.4, TOKEN-6.5 | none |

## Depth, not count

`m` in `<object>-<tier>.<m>` is the depth of complete modules represented, so the
largest `m` a certificate can reach for a numbered profile is that profile's topological
depth -- the longest chain of obligations each of which is a prerequisite of the next --
and not the number of obligations it holds. Where the two differ, the coordinates above
the depth are unreachable. `verifier.core.profile_obligations.tier_depth` computes it.
