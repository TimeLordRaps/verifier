# Object hierarchy and finite composition

Verifier Standard (VSTD) uses OBJECT for something a RECEIPT can describe.
`verifier.core.namespace` implements immutable object records and a bounded
checker for their finite typed composition. It does not certify arbitrary payload
semantics or establish all meta-tier objectives. This is an implementation
increment toward the governing hierarchy in pull request
[#53](https://github.com/TimeLordRaps/verifier/pull/53), not a release-completion claim.

## Names and coordinates

The retained native `ObjectKind` hierarchy contains HUMAN, ACTOR, COLLECTIVE,
ROLE, IDENTITY, OWNER, HARDWARE, RECEIPT, OBJECT, GRAPH, SPACE, TIME, EVENT, ENV,
DATA, VERIFIER, BENCH, ARCH, TRAIN, HYPER, MODEL, HARNESS, AGENT, SIM, BOT and
retained TOKEN. The installed extensible namespace additionally admits LEDGER,
TRANSACTION, ASSET, MARKET, MEASUREMENT, SENSOR, CONTROLLER, ACTUATOR, PROTOCOL,
POLICY, ROBOT and FINBOT as accumulating consequential roles: 38 kinds in total.
Those 12 roles do not alter the retained 26-value enum, native wire set, or
234-slot core grid. `OBJECT` labeling never exempts an applicable role; BOT is
simulation-situated, while real physical or financial effects additionally demand
ROBOT or FINBOT respectively. ENV means computational environment, ARCH means
computational model architecture, BENCH means a verifier and data bound to an
evaluation objective, TRAIN means a training computation, and SIM means a
simulation. Other uppercase names are object names, not acronyms.

`ObjectCoordinate` parses `SIM-3.6` as objective six within SIM's third meta-tier.
The objective index is not prerequisite-chain depth, adapter count, confidence,
or a software version. Both indices are dimensionless positive integers. Parsing
an address does not register an objective or demonstrate its implementation.
The general meta-tiers are:

| Number | Meaning |
|---|---|
| 1 | Fundamental structural facets |
| 2 | Dynamics of those facets |
| 3 | Static external constraints and invariants |
| 4 | Closure certificates |
| 5 | Independence |
| 6 | Privacy |
| 7 | Consent |
| 8 | Governance |
| 9 | Security |

Security concerns exact bounded threats to an object's execution, evidence,
information, availability or enforcement. It is distinct from governance's
authority and decision rules: neither tier establishes the other. Admitting a
tier-9 address registers no security objective, mechanism or certificate.

The existing numbered receipt and domain-obligation catalogues retain their
exact evidence and serialized meanings during migration. Their old adaptation
and disclosure coordinates must not silently become independence and privacy
certificates. The new coordinate parser rejects the old base object name VSTD;
historical receipt readers still dispatch on their original wire identifiers.
VSTD continues to name the standard. No historical receipt is rewritten here.
The remaining normative/runtime migration conflict is recorded in
[TIME](../../../TIME.md).

## Object and reference binding

`NamespaceObject.create` requires an admitted kind, an object identifier, a
JavaScript Object Notation (JSON) payload, and named operand roles. Payloads are
canonical immutable bytes. Retrieval produces a copy, so later mutation of a
source dictionary or returned payload cannot alter an already bound record.
Non-string keys, nonfinite numbers, duplicate roles or targets, noncanonical
bytes and oversized records are rejected. Bounds include 64 nesting steps,
10,000 payload values, 4,096 references and one mebibyte of payload per record.

A record digest commits to its reference identifiers, not to the external
contents those identifiers resolve to. `composition_digest` binds every record
in the finite collection; `assess_composition` requires that complete expected
commitment. Collection ordering does not matter. Operand ordering does matter,
including retained event order. Object identifiers are unique within a collection.
The checker captures one immutable collection for both commitment and traversal;
ownership replay and resolution use that same captured collection. This prevents
later caller-list changes from substituting unchecked records after hashing.
Capture does not authenticate records or sandbox arbitrary Python hooks.
Every operand must resolve there. Missing or changed content, dangling references,
and cycles in composition dependencies fail. Kahn's dependency algorithm checks
the directed acyclic graph (DAG); relationships represented inside a payload are
not silently interpreted as composition dependencies.

Default checker limits are 4,096 records, eight mebibytes of aggregate payload,
eight mebibytes of encoded identifiers and reference strings, and 100,000 charged
operations. Input bounds are checked before canonicalizing the whole collection.
Exceeding a checker limit or omitting the expected
commitment produces UNKNOWN. A contradictory bound structure produces FAIL.
PASS means only `finite typed object composition`, with
`object_profile_conformance=NOT_ESTABLISHED`.

## Operand contracts

| Object | Required named operands |
|---|---|
| ACTOR | `representation`: HUMAN, AGENT or BOT; `root_human`: HUMAN |
| COLLECTIVE | `roles`: ROLE |
| IDENTITY | `actor`: ACTOR; `role`: ROLE |
| OWNER | `actor`: ACTOR; `object`: any OBJECT |
| RECEIPT | `subject`: any OBJECT; `hardware`: HARDWARE |
| EVENT | `time`: TIME; `space`: SPACE; `meaning`: any OBJECT |
| BENCH | `verifier`: VERIFIER; `data`: DATA |
| TRAIN | `data`: DATA; `events`: EVENT; `bench`: BENCH; `arch`: ARCH |
| MODEL | `train`: TRAIN; `data`: DATA; `events`: EVENT; `bench`: BENCH; `arch`: ARCH; `env`: ENV; `hardware`: HARDWARE |
| AGENT | `model`: MODEL; `harness`: HARNESS; `env`: ENV |
| SIM | `data`: DATA; `verifier`: VERIFIER; `objects`: any OBJECT; `env`: ENV |
| BOT | `agent`: AGENT; `sim`: SIM; `env`: ENV |

Required roles are nonempty. Unknown roles are rejected. HYPER admits named,
nonempty relational operands of any kind. Other primitives have no composition
operands in this increment; their domain-specific payloads need separate
mechanisms. In particular, a HARNESS does not incorporate a MODEL.

GRAPH has an explicit `element_kind` payload and nonempty `members`. A typed
GRAPH of a required kind can replace that operand, including nested graphs of
the same kind. The checker verifies every leaf and every intermediate declared
type. A generic GRAPH of OBJECT cannot implicitly become a GRAPH of ENV, even
if its present leaves happen to be environments. Native OBJECT slots accept any
retained `ObjectKind`; package admission separately retains applicable added-role
obligations. Finite nonempty nesting preserves the operand's kind, not its certification.

Each ACTOR has exactly one represented decision maker and one responsible HUMAN
after graph expansion. A represented HUMAN must be its own root. AGENT and BOT
roots remain explicit. These are bound declaration checks, not authentication
of living people, delegated authority, actual responsibility, or legal identity.
An IDENTITY's structurally bound ACTOR may represent any of the three kinds.
ROLE membership is carried by COLLECTIVE's role operands; a reciprocal composition
edge is not required and would create a dependency cycle.

Repeated EVENT terms in the governing MODEL expression use the single ordered
`events` role. This does not collapse distinct event records. Static SIM snapshots
are structurally representable; dynamics, transition coverage and receipt-emission
obligations remain separate checks. A composition PASS alone does not show that a
SIM emitted anything.

## Acceptance and remaining mechanisms

The negative gates cover changed commitments, dangling references, duplicate
identifiers, dependency cycles, wrong operand kinds, implicit graph retyping,
missing HUMAN roots, mismatched HUMAN self-roots, HARNESS/MODEL coupling and
resource-bound exhaustion. Recheck the same collection and expected commitment;
never consume a serialized PASS without rerunning its mechanism.

The adjacent `verifier.domains.contracts.accountability` mechanism replays this
composition and checks an exact OWNER relation. It rejects AGENT hardware
ownership and BOT physical-hardware ownership. A HUMAN relation can satisfy the
declared kind restriction without proving human authenticity or title. A BOT
virtual-hardware relation additionally requires freshly replayed
[finite SIM isolation](SIM_ISOLATION.md), the BOT's exact SIM operand, that SIM's
bound evidence digest, and matching virtual resource identifier and kind inside
its object inventory. A carried isolation PASS is never accepted without replay.
Missing evidence stays UNKNOWN; substituted evidence or mismatched resources FAIL.
All resulting assessments explicitly retain authority and physical host
containment as NOT_ESTABLISHED. This is declared eligibility inside a finite model,
not acquisition permission or a deployed access-control mechanism.
The bridge consumes the replay-produced resource inventory, not mutable caller
data reread after replay. Checking budgets belong to the caller-selected policy
and are bound in the isolation assessment; the SIM binds evidence semantics,
not one mandatory budget. BOT, SIM and AGENT environment operands identify their
respective environments; this structural contract does not assert their equality
or establish an isolation boundary between real environments.

The versioned [declared identity binding](IDENTITY_OCCUPANCY.md) checks an exact
IDENTITY, ACTOR, ROLE and selected COLLECTIVE, including typed graph substitution,
the responsible HUMAN and admitted declared scope. A BOT declaration selects one
of its bound SIM operands. Its replay preserves human authenticity, role authority,
privacy, consent, governance and full object-profile conformance as NOT_ESTABLISHED.
This direct experimental contract does not reinterpret the legacy native IDENTITY
adapter or assign its result to a current meta-tier objective automatically.

The [current-object grounding route](CURRENT_OBJECT_GROUNDING.md) selects one
versioned `SIM-5.1` proposition: finite declared capability and effect confinement.
It binds and replays the proposition, selected SIM, complete collection, retained
evidence and external policy. Its semantic version distinguishes it from legacy
`SIM-5.1` mainstay binding. This is one model-relative independence objective;
full independence-tier conformance and physical containment remain unestablished.

The [current SIM dynamics route](CURRENT_SIM_DYNAMICS.md) separately selects
`SIM-2.1`: the installed interpreter replays one exact retained transition
program and trajectory bound to a SIM record. Action responsiveness,
observation projection, hidden state, resources, perspective, historical
execution and whole dynamics-tier conformance remain unestablished. The
versioned route does not reinterpret legacy `SIM-2.1` receipts.

The [current SIM action-response route](CURRENT_SIM_RESPONSE.md) separately
selects `SIM-2.2`. It independently replays a selected `SIM-2.1` child and
executes an action-aware transition for each retained step, checking the exact
next state, a differing baseline-action counterfactual and a bounded model-time
delay. This is model-relative responsiveness, not historical causality or
whole dynamics-tier conformance. Legacy channel bounds alone cannot supply it.

The [current SIM internal-state route](CURRENT_SIM_INTERNAL_STATE.md) separately
selects `SIM-2.3`. It rechecks the exact passing `SIM-2.1` child and enumerates
state-key changes that no selected model observation channel exposes under any
finite endpoint hybrid of the other changed keys. The channel inventory is a
model declaration; physical observation, privacy, and whole-tier conformance
remain unestablished.

The [current SIM perspective route](CURRENT_SIM_PERSPECTIVE.md) separately
selects `SIM-2.5`. It rechecks an exact passing `SIM-2.3` child and executes
its embedded finite micro-to-macro projection against every aligned retained
macro state under the externally selected absolute tolerance and common unit.
Macro-source authority, physical correspondence and whole-tier conformance
remain unestablished.

The [current SIM external-law route](CURRENT_SIM_EXTERNAL_LAW.md) separately
selects `SIM-3.4`. It replays an exact typed SIM-to-OBJECT operand relation and
the externally selected retained statement of the physical law the SIM says it
models. The source reference is a claim, not independently authenticated
authority; law truth, applicability, actual model correspondence and whole
statics-tier conformance remain unestablished.

The [current SIM shard-coverage route](CURRENT_SIM_SHARD_COVERAGE.md) separately
selects `SIM-4.1`. It rechecks an exact passing `SIM-2.1` child and compares the
complete selected shard inventory and every retained shard time with the
child's finite trajectory. Cross-shard relations, signatures, unretained states,
whole simulated-surface accounting and closure-tier conformance remain
unestablished.

The [experimental SIM resource-capture helper](CURRENT_SIM_RESOURCE.md)
records local per-step CPython thread CPU-time and traced allocations for an
exact passing `SIM-2.1` child. Its signed record does not independently prove
actual consumption by a historical execution, so `SIM-2.4` remains an
unregistered `UNKNOWN` current objective. Interpreter budgets and limits are
not measured use.

The [current SIM cross-shard relation route](CURRENT_SIM_SHARD_RELATIONS.md)
selects `SIM-4.2`. It rechecks an exact passing `SIM-4.1` child and evaluates
each externally selected expression referencing at least two distinct shards
at every retained aligned time. Unselected relations, dimensional validity,
physical truth, signatures, whole-surface accounting and closure-tier
conformance remain unestablished.

The [current SIM selected shard-signature route](CURRENT_SIM_SHARD_SIGNATURES.md)
selects `SIM-4.3`. It rechecks an exact passing `SIM-4.2` child, extracts its
retained shard rows and verifies every policy-required row signature under
that shard's externally pinned admitted public key. The domain-separated
message binds the exact child, policy, subject, shard, step, time and state.
Unrequired shards, independent origin, key custody, live revocation, actual
execution, whole simulated-surface accounting and complete closure-tier
conformance remain unestablished. Missing keys, signatures or optional
cryptographic support remain `UNKNOWN`; known invalid signatures fail.

The [current SIM surface-partition route](CURRENT_SIM_SURFACE_PARTITION.md)
selects `SIM-4.4`. It replays the selected `SIM-4.3` child and checks a
bijection between every declared root field and retained shard field at
each aligned time, with exact canonical value identity and root-transition
expression attribution. Hidden memory, unretained states, physical truth,
historical execution, authority and complete closure-tier conformance
remain unestablished.

The [current HYPER closure route](CURRENT_HYPER_CLOSURE.md) selects versioned
`HYPER-4.1`: exact finite declared operand-cone closure. The selected HYPER root
and external collection commitment determine all reachable operands; unresolved
references, cycles and unrelated extra records cannot establish this proposition.
This is declared collection closure, not mathematical or physical world closure
or certification of every member's own closure objectives. Legacy `HYPER-4.1`
retains Saturation; full closure-tier and object-profile conformance stay unestablished.

The [generic OBJECT facets route](CURRENT_OBJECT_FACETS.md) selects current
`OBJECT-1.1`: exact canonical representation and a deterministic record address.
It retains and reconstructs one complete record, independently binding its
identifier, admitted kind, payload, ordered operand map and address commitments.
Any retained native `ObjectKind` can be represented by this route, but generic
representation does not establish that kind's own tier-1 objectives, typed
composition, or absence of an applicable accumulating role. Unresolved
operand names can remain representable without being resolved or authorized.
The address is a future citation target, not an issued RECEIPT or evidence that
an artifact ran on HARDWARE. Whole OBJECT tier 1 remains unestablished.

The [current TIME retained-order route](CURRENT_TIME_ORDER.md) selects versioned
`TIME-2.1`: exact retained sample order and span membership on one declared
microsecond clock. It does not authenticate that clock, synchronize distinct
clocks, establish event causality or complete the TIME dynamics tier.

The [current SPACE logical layout route](CURRENT_SPACE_LAYOUT.md) selects
versioned `SPACE-3.1`: retained, aligned, nonoverlapping half-open byte
partitions within one declared finite extent. It does not prove host allocation,
physical containment, access-control isolation or the whole SPACE statics tier.

The [current SPACE logical extent-closure route](CURRENT_SPACE_CLOSURE.md)
selects versioned `SPACE-4.1`. It rechecks an exact passing `SPACE-3.1` child
and requires its retained partitions to cover the entire declared half-open
byte extent without a leading, interior or trailing gap. The check does not
establish actual allocation, physical non-leakage, access-control isolation
or whole SPACE closure-tier conformance.

The [current EVENT prerequisite route](CURRENT_EVENT_PREREQUISITES.md) selects
versioned `EVENT-3.1`: exact retained payload commitments and strictly ordered
declared prerequisites within one selected finite EVENT cone. It does not prove
an actual occurrence, physical causality or the whole EVENT statics tier.

This increment does not authenticate an accountability chain, execute ARCH, prove MODEL behavior,
establish runtime SIM containment, or fill the nine-tier objective catalogue.
Its OWNER structural result is not permission to acquire hardware. Missing
certification or accountability mechanisms remain unestablished. Domain-specific
mechanisms, authority checks and compatibility migration are required before
promoting any stronger claim.
