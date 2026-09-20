# Grounded domain adapters

Verifier Standard (VSTD) domain certification executes bounded computations over
retained artifacts. DATA denotes dataset integrity and lineage; ENV denotes an
execution environment; BENCH denotes a benchmark specification graph; HYPER denotes
hyperparameters and training lineage; MODEL denotes a model reproducibility
specification; SIM denotes a generative simulation specification.

These six application receipt families supplement object and Graph numbered profiles.
`DATA.1` through `DATA.5`, for example, are domain check coordinates. Domain depth is
the dimensionless count of consecutive established domain prerequisites. It MUST NOT
be represented as object profile depth, Graph conformance, or discharge of the 47
object obligations. Existing domain declarations and serialized identifiers retain
their meaning. The additive formats below do not upgrade earlier receipts.

## Binding and replay

JavaScript Object Notation (JSON) values are retained with exact canonical bytes;
Secure Hash Algorithm 256-bit (SHA-256) references use `sha256:` and 64 lowercase
hexadecimal digits. A `VSTD-DOMAIN-EVIDENCE-1` object contains exactly `domain`,
`subject_id`, `artifact`, `inputs`, and `schema_version`. The artifact is the contract;
inputs supply its retained evidence. The consumer selects a `VSTD-DOMAIN-REQUEST-1`
binding domain, subject, artifact digest, complete evidence reference and target depth.
Omitting or replacing evidence changes that request, even if a new digest is valid.

A separately selected `VSTD-DOMAIN-POLICY-1` pins the executable mechanism digest,
explicit trust roots, witness public keys and resource bounds. The mechanism digest
covers all adapter sources, shared evidence/canonicalization code, specification bytes,
Python implementation and major/minor version, and the optional signature backend
version. Runtime or source changes require policy readmission. Certificates supply
neither their own authority nor external intent.

The checker MUST rehash the complete bundle and execute every requested prerequisite
through the evidence-bound session. `PASS` establishes only the named computation
and scope. Contradictory evidence produces `FAIL`; missing evidence, unsupported
mechanisms or exhausted bounds produce `UNKNOWN`. Later checks cannot repair earlier
prerequisites. A `VSTD-DOMAIN-CERTIFICATION-1` retains the request, evidence, result and
mechanism/specification/policy digests. Replay MUST compare the complete regenerated
certificate under the external request and policy. Substitution or forged output is
`REJECTED`, even when its certificate digest was recomputed.

Documents are limited to 16 mebibytes, 250,000 structural nodes and 64 nested containers.
Policy evidence limits are at most 8 mebibytes; operations are at most 10,000,000 per
check and collection items at most 100,000. Numerical comparison tolerance is bounded
by a checker-selected maximum no greater than 0.0001. Byte counts and operation counts
are separate limits. These are deterministic work limits, not an operating-system
sandbox or a hard wall-time guarantee. No payload imports code, unpickles objects,
opens files, invokes commands, or selects arbitrary Python callables.

## Native scope and retained contracts

The executable catalogue names each proposition and its immediate predecessor.
All inventories below are complete relative to the externally bound contract, not
claims about unobserved history or the outside world.

| Domain | Consecutive checks | Native inputs and operations | Exclusions |
| --- | --- | --- | --- |
| DATA | inventory; schema; lineage; splits; overlap | JSON records; exact shard/record digest lists, byte and record counts; exact field types; concat, project, equality filter and deduplication; disjoint record identities across declared splits; exact text and word-ngram Jaccard overlap | Ownership, pre-observation ancestry, semantic contamination and unretained data |
| ENV | software inventory; configuration; resources; reproduction | Retained file bytes; complete required configuration; measured wall seconds, memory bytes under the named collector convention, and thread counts; two observations bound to identical software, program, configuration, input and output | Hardware attestation, physical isolation, authenticity or independence of self-observations; no command is rerun by certificate replay |
| BENCH | problem binding; oracles; coverage/score; budgets | Exact-output equality; conjunctive normal form (CNF) Boolean satisfiability problem (SAT) assignments; bounded exhaustive unsatisfiability; linear-system residuals; complete weighted scores; retained milliseconds and memory bytes | General theorem proving, producer-supplied solved flags, performance measurement authenticity |
| HYPER | configuration; checkpoints; lineage; updates; training | Dense linear/rectified-linear networks; contiguous checkpoints and exact batches; stochastic gradient descent (SGD), adaptive moment estimation (Adam), Adam with decoupled weight decay (AdamW); constant schedule; equal-sized microbatch accumulation; clipping; loss and analytic gradient replay | Arbitrary accelerator kernels, mixed precision, distributed training, unsupported schedules or optimizers |
| MODEL | artifacts; tensors; inference; evaluation; challenges | Dense linear and rectified linear unit (ReLU) networks; complete finite tensor shapes; mean squared/absolute error and classification accuracy; explicit finite output predicates | Universal robustness, alignment/corrigibility guarantees, generalization, arbitrary model formats |
| SIM | replay; invariants; refinement; channels; shards | Bound finite expression trees, entropy and causal times; every retained state; optional transition-closed enumerated state boundary; aligned macro projection; observation projections and action bounds; aligned shard relations and optionally authenticated signatures | Unbounded induction, general bisimulation, physical containment, witness independence or consensus |

`examples/domain_grounding.py` constructs all six complete native specimens and
rechecks their certificates. Its environment specimen measures an actual in-process
sort task; memory means Python traced allocation peak bytes. Its benchmark resource
observations measure candidate construction, not a solver speed comparison.

Dataset shard commitments contain `digest`, `records`, `bytes`, `record_digests`
and `merkle_root`. Merkle leaves are canonical record references; each ordered pair
is hashed as `{"left": reference, "right": reference}`, duplicating an odd final
leaf at each fold. The empty tree commits the empty list. This additive digest-tree
contract does not change historical dataset manifest hashing.
Use shared `fields` or a complete `shard_fields` mapping, never both. Per-shard
schemas permit transformations such as projection to change a record's shape
while retaining the schemas of its source records.

Environment contracts enumerate `execution_ids`; both retained execution records
and resource observations must cover those exact distinct identities. Comparison
checks cannot authenticate the collector or establish that an omitted real-world
execution never occurred.

### Numerical semantics

Arithmetic uses ordered Python binary64 operations, finite values bounded in absolute
value by 10^100, and the bound numerical tolerance. Weights are row-major dense matrices
with one bias per output. Layer activation is `linear` or `relu`; the derivative at
ReLU zero is zero. Training loss is squared error averaged over samples and outputs.
Gradient accumulation averages equal-sized microbatch gradients. Global Euclidean
gradient clipping precedes weight decay. SGD supports momentum without dampening or
Nesterov acceleration. Adam uses bias-corrected first and second moments with epsilon
outside the square root. AdamW decays parameters separately. Other settings return
`UNKNOWN`; they are not silently approximated. Checkpoint replay can start at an
externally bound nonzero step but establishes no earlier training history.

### Simulation expressions and witnesses

Expressions contain a finite number, `{"var": "name"}`, or `{"op": "name", "args": [...]}`.
Unary operators are `abs` and `neg`; binary operators are `add`, `sub`, `mul`, `div`,
`min`, `max`, `le`, `lt`, `eq`, `ge`, `gt`, `and`, and `or`. Boolean results cannot
substitute for numbers. Nesting is limited to 32; arithmetic cannot invoke host code.
The reserved variable `entropy` supplies the exact retained transition input.
Relation variables use `root.<field>` for the reference trajectory and
`<shard>.<field>` for shard states. Shard identifiers MUST be nonempty, distinct,
contain no period, and differ from the reserved identifier `root`; otherwise a
shard could shadow the reference whose relation is being checked.

An optional finite-state invariant claim checks every enumerated state and successor
for every enumerated entropy value, requires the initial and observed states to belong
to that set, and rejects a boundary that is not transition-closed. Without that boundary,
the result is a trace invariant only. Refinement compares aligned finite macro states;
it is not a universal equivalence theorem.

Optional Ed25519 (Edwards-curve digital signatures over a 255-bit field) verification
requires the installed cryptography extra and externally selected public keys. Each
signature covers canonical artifact digest, shard, step, causal time and state. A
missing backend/key is `UNKNOWN`; a wrong signature is `FAIL`. Unsigned shard checks
establish only the retained relations. A signature does not establish independent
observation or a physically isolated witness.

## Degradation and extension

Changing inputs, contract, subject, request, policy, checker, runtime or specification
invalidates the old certificate's applicability. A certificate may still reproduce
historically under its original coordinate; this is not current authority.

Unsupported workloads require an explicitly admitted executable mechanism with its own
proposition, retained inputs, bounds and adversarial qualification. The native formats
are a portable baseline, not an assertion that every domain mainstay is universally
covered. Domain results compose with object-profile obligations only through a separately
bound mechanism that actually discharges each object's required proposition.
