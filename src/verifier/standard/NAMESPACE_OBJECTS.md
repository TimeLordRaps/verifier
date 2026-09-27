# Object hierarchy and finite composition

Verifier Standard (VSTD) uses OBJECT for something a RECEIPT can describe.
`verifier.core.namespace` implements immutable object records and a bounded
checker for their finite typed composition. It does not certify arbitrary payload
semantics or establish all meta-tier objectives. This is an implementation
increment toward the governing hierarchy in pull request
[#53](https://github.com/TimeLordRaps/verifier/pull/53), not a release-completion claim.

## Names and coordinates

The hierarchy contains HUMAN, ACTOR, COLLECTIVE, ROLE, IDENTITY, OWNER, HARDWARE,
RECEIPT, OBJECT, GRAPH, SPACE, TIME, EVENT, ENV, DATA, VERIFIER, BENCH, ARCH, TRAIN,
HYPER, MODEL, HARNESS, AGENT, SIM, BOT and retained TOKEN. ENV means computational
environment, ARCH means computational model architecture, BENCH means a verifier
and data bound to an evaluation objective, TRAIN means a training computation,
and SIM means a simulation. Other uppercase names are object names, not acronyms.

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
if its present leaves happen to be environments. OBJECT slots accept any admitted
kind. Finite nonempty nesting preserves the operand's kind, not its certification.

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

This increment does not authenticate an accountability chain, execute ARCH, prove MODEL behavior,
establish runtime SIM containment, or fill the eight-tier obligation catalogue.
Its OWNER structural result is not permission to acquire hardware. Missing
certification or accountability mechanisms remain unestablished. Domain-specific
mechanisms, authority checks and compatibility migration are required before
promoting any stronger claim.
