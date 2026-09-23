# The Verifier Standard (VSTD) meta-tier grid — nineteen ladders, five tiers

> **Acronyms:** benchmark specification graph (BENCH); dataset integrity and lineage (DATA);
> directed acyclic graph (DAG); generative simulation specification (SIM); object composition specification (HYPER);
> training run specification (TRAIN);
> model reproducibility specification (MODEL); Open Container Initiative (OCI);
> PROV data model (PROV-DM); Supply Chain Integrity, Transparency, and Trust (SCITT);
> Supply-chain Levels for Software Artifacts (SLSA); Verifier Standard (VSTD);
> verifiable execution environment (ENV).

**Status:** project specification (normative for what tier N means on every object axis)
**Editor:** TimeLordRaps
**License:** Apache-2.0
**Date:** 2026-09-20

Identifier form, for every object: `<object>-<tier>.<m>`, tier one of 1..5, `m` the
minimum clearance attained up that tier — the depth of complete modules the certificate
represents. Both one-indexed. See `WIRE_IDENTIFIERS.md` and `GROUNDED_CERTIFICATION.md`.

## The VSTD-NAMESPACE

The space those identifiers are drawn from is titled the **VSTD-NAMESPACE**, and its
members are **verifiable objects**. The title is what lets the space be referred to
without enumerating it: `DATA` and `OWNER` are verifiable objects in the
VSTD-NAMESPACE, and a name not admitted to it is not one.

`NAMESPACE` is deliberately **not** a member of the `<NAME>` set. Admitting it would make
`VSTD-NAMESPACE-1.1` a well-formed coordinate naming a tier-1 profile of the space that
contains it, and the space is not one of the objects it holds. The title takes no tier and
no `.m`; it is an envelope, not a row of the grid below.

The word is already carrying two other loads in this corpus, and neither is this one.
*Obligation* namespaces are the three disjoint coordinate sets catalogued at the foot of
this file; *package* namespaces are Python import paths. The titled sense is always
written `VSTD-NAMESPACE`, capitalised and prefixed, and never bare.

A **wire identifier** is not a coordinate in it. `verifier-data-1` is the string a receipt
carries in `schema_version`, pinned by the code that parses it; `DATA-1.1` is a
coordinate in this grid. They are different namespaces that happen to share a prefix, and
the identifier convention below governs only the second. Renaming a wire identifier to
match the convention breaks every reader that pins the string.

## The five corroboration tiers, and level 6

Tiers occupy one shared metaphorical/analogical space of meta-features. Tier N asks the
same *kind* of question on every object axis.

| Tier | What it represents |
|---|---|
| 1 | A meta-structure abstraction of the **facets** of the surface. |
| 2 | The **dynamics** of the structures the surface can and does represent. |
| 3 | The **static unchanging natural phenomena** around the surface. |
| 4 | The **closure conditions** under which the specification can be completed. |
| 5 | **Domain adaptation surfaces** that tiers 1-4 allow to form naturally; these typically infer structure from domain mainstay representations. |
| 6 | The **disclosure bounds** on what a certificate of this object may emit, and to whom. Not a rung: see below. |

**Tiers 1-5 corroborate; level 6 discloses, and the difference is structural.** Every
tier from 1 to 5 is a rung on a corroboration ladder: it is evidence that raises what the
object is known to satisfy, and it is settled once, by the act of certifying. Level 6 is
none of those things. It bounds what a certificate may *emit* rather than what it
establishes; it is re-decided at **every emission** rather than once; it is the only
level in the grid that is **not monotone under composition**, because disclosure is the
**join** of the operands rather than bounded by them; and by its own `<object>-6.6` it
**cannot move a verdict** in tiers 1-5, in either direction.

That last property is why level 6 is deliberately absent from the ladder strip, the rung
totals and the composition lattice below. A level that by its own statement cannot change
what is established is not evidence, and counting its 5 positions per object as
rungs would inflate every reachability figure this file publishes. The strip is *what a
certificate climbs*, and a disclosure bound is not climbed.

Four of level 6's six rows are the **same proposition at every object**, which is the
argument that disclosure is a level rather than an object of its own: an object contributes rows
that differ, a level contributes the same row everywhere. All 66 rows are specified
with no mechanism and report `UNKNOWN` -- no adapter runs at emission time and no observer
model is established anywhere in the implementation, so a `PASS` would be a claim nothing
supports. Level 6 adds no module to `verifier.domains` and **does not move**
`implementation_digest()`.

The tier-5 pattern in one sentence: a mainstay framework already represents the object
modularly for one domain (PyTorch for neural networks, Gymnasium for environments, OCI for
software closure), and tier 5 is that framework's structure inferred upward into a general
specification meta-framework, rather than a new notation invented downward.

## Ground truth: this is not new — it is `LADDER.md` made total

The object axis `VSTD-1..5` and the graph axis `GRAPH-1..5` already instantiate these
five tiers exactly, and predate the generalization:

| Tier | `VSTD-N` closure coordinate | `GRAPH-N` closure coordinate | Tier meaning |
|---|---|---|---|
| 1 | Claim Mechanics | Recorded Lineage | facets |
| 2 | Verification Surface | Bounded Collection Surface | dynamics |
| 3 | Substrate Accountability | Accountable Provenance Closure | statics |
| 4 | Refutability | Refutable Transformation Closure | closure |
| 5 | Witness Corroboration | Corroborated Verification Network | domain adaptation |

So the meta-tier grid is not a second numbering laid over the Standard. It is the two
existing axes recognized as two rows of a twelve-row table, and the other ten rows
filled in with the same five questions.

---

# The grid

Cells marked **[anchor]** are stated verbatim by the editor and are normative for their
row's reading of the tier. Every other cell is derived by applying the same tier question
to that object.

---

## VSTD — the foundational computational claim meta-surface

The lowest level. Every other object in this table is a claim about something in
particular; VSTD is the claim surface itself, with nothing domain-specific left in it.
The bare name carries no object segment for that reason.

**VSTD-1** — identifier, proposition, declarant, declared bounds, the evidence binding, the
canonical byte serialization, the failure class the claim admits.

**VSTD-2** — the checking mechanism's identity and re-execution, verification orders and
their adjacency, what the mechanism consumed and emitted, the difference between a field
asserting a proposition and a mechanism establishing it.

**VSTD-3** — the substrate the check physically ran on: hardware identity and attestation,
trusted computing base, measured boot, device composition. Unchanging natural phenomena in
the literal sense — the machine was what it was.

**VSTD-4** — refutability: the fourteen ordered rungs `4.1`..`4.14`, what admission of a
falsifier requires, and the conditions under which the claim's specification is complete
enough to be *wrong* rather than merely unsupported.

**VSTD-5** — witness corroboration: the first coordinate a declarant acting alone cannot
satisfy. Adapts to whatever witness surface a domain already runs — transparency logs,
SCITT, notaries, independent re-runners.

## GRAPH — collections of artifacts and their recorded relations

**GRAPH-1** — nodes, edges, relation types, member inventory, the collection's own
identifier, what counts as inside.

**GRAPH-2** — membership dynamics: admission, removal, lifecycle view, ordering of
edges, how a collection changes while retaining identity, conflict state as it forms.

**GRAPH-3** — provenance that cannot be revised: immutable ancestry, trust roots,
actor and delegation identity, rotation and revocation history. The unchangeable past of
the graph. This is the surface the `v1.5.0` root-of-trust / rotation / delegation identity
module occupies.

**GRAPH-4** — refutable transformation closure: exact re-execution of member,
ancestor and edge rating mechanisms from content-addressed evidence, and the conditions
under which a candidate graph profile becomes evidence-bound.

**GRAPH-5** — the network that forms once 1-4 hold: cross-registry corroboration,
PROV-DM, in-toto, SLSA, Certificate Transparency inferred upward into one relation
vocabulary.

## DATA — retained data

**DATA-1** — records and shards, field types and required columns, the digest tree,
byte and count commitments, record identity, the retention boundary (what is kept versus
what was seen).

**DATA-2** — transformation dynamics: every declared transformation re-executed to its
exact output, ordering and idempotence of the pipeline, how a record moves from raw to
retained, drift as the corpus is rebuilt.

**DATA-3** — what was true before anyone processed it: sampling frame and population,
the measurement instrument and its units, censoring and truncation, class balance,
cardinality and entropy, licence and legal facts of origin. Unchanging because they are
facts about the world the data came from, not about the pipeline.

**DATA-4** — closure over the complete inventory: split membership and record-identity
separation, exact and lexical train/evaluation overlap recomputed over everything retained,
the condition under which the dataset specification admits no unaccounted record.

**DATA-5** — Arrow/Parquet, HuggingFace `datasets`, Croissant, DCAT inferred upward.
This is the object `MODEL-3` cites when it binds training data.

## ENV — execution environments

**ENV-1** — the software inventory materialized and rehashed, the required
configuration surface, executable coordinates, the declared boundary of the environment.

**ENV-2** — dynamics: scheduling and concurrency, every declared nondeterminism source
(clock, entropy, thread interleaving, allocator), two retained executions compared input
for input and result for result.

**ENV-3** — statics: instruction set architecture, floating-point semantics, memory and
clock ceilings, thermal and power limits, the physical resource envelope the machine has
whether or not anyone declares it.

**ENV-4** — hermeticity: the closure condition under which nothing in the environment
is unpinned, no implicit host state leaks in, and the specification is complete enough that
a second party can stand the environment up from the record alone.

**ENV-5** — OCI images, Nix derivations, conda/uv lockfiles, SLSA build provenance
inferred upward into one environment-closure meta-framework.

## BENCH — benchmarks

**BENCH-1** — **[anchor]** *a bench is represented by a set of problems, some form of
what a solution is deducible from, a sampling procedure, baseline mechanics, feature
representational spaces or categories, a domain or set of domains.*

**BENCH-2** — dynamics: adaptive and sequential evaluation, repeated attempts and
best-of-N, contamination accumulating over time, difficulty response curves, the feedback
loop a public leaderboard induces on the systems it measures.

**BENCH-3** — statics: chance floor and oracle ceiling, irreducible label noise,
intrinsic hardness classes of the problem family, the natural task distribution of the
domain. These do not move when the harness changes.

**BENCH-4** — closure: weighted score recomputed over every problem with no missing,
duplicate or substituted run, retained timing and memory checked against the problem
ceilings, the condition under which the bench measures the whole declared surface.

**BENCH-5** — `lm-evaluation-harness`, HELM, BIG-bench, SWE-bench task specifications
inferred upward into one bench meta-framework.

## TRAIN — training runs

**TRAIN-1** — the optimizer, schedule, accumulation and precision contract; the
checkpoint inventory with every retained weight and optimizer state rehashed; the step
index; the batch binding; the declared numerical semantics.

**TRAIN-2** — dynamics: every supported optimizer update recomputed from retained
gradients and state, losses and analytic gradients replayed from the bound batches, the
run advancing step by step.

**TRAIN-3** — statics: what the run does not get to choose. Floating-point semantics
and accumulation order, the gradient the bound objective actually has, the geometry of
the loss surface the architecture and data together fix.

**TRAIN-4** — closure: contiguous steps with exact parent, batch, hyperparameter and
result bindings, no step missing, substituted or reordered. The condition under which the
trace accounts for the whole run rather than a selected prefix of it.

**TRAIN-5** — the mainstay training loops and their checkpoint formats inferred
upward into one training-trace meta-framework. This is the object `MODEL-3` cites for
a model's provenance, and it consumes `DATA-5` for its batches.

## HYPER — composition of certified objects into certified objects

Every other row certifies one kind of thing. This row certifies the **combination operator**:
what has to hold for a set of bound certificates to compose into a new object, and why the
composed object can never claim more than its operands established.

The lattice the rest of the grid already forms. Write the shared substrate as

```
S = { VSTD, GRAPH, DATA, ENV, BENCH }
```

`TRAIN` is an operand too — the run that produced a model — which is why the model
row names it rather than folding it into `S`: a model can be certified without one.

| Composed object | Operands |
|---|---|
| `MODEL` | `S` + `TRAIN` |
| `SIM` | `S` + `MODEL` |
| `AGENT` | `S` + a decider + `HARNESS` |
| `BOT` | `AGENT` + `SIM` |

Each row adds to the row above it, and the last one collapses: `S` + decider + `HARNESS`
beside `S` + `MODEL` is exactly `AGENT` + `SIM`. The substrate appears once per arm, which is
why `BOT.1` re-derives the bound agent, simulation and **two** environment certificates, and
why the tier-4 closure of `BOT` is the declared separation of those two.

The decider is a slot, not an object. A model can fill it; so can a human, a script or a rule
engine. `MODEL` + `HARNESS` on its own is a model deployment observed through an
instrument: it is short the substrate, and it pins the slot to one of the things that can fill
it. Nothing in the certified surface establishes *what* decided — `AGENT-2` requires only
that each decision is witnessed by a record inside the ceiling. What composes is the evidence
surface a decider is observed on, never the decider.

**HYPER-1** — the facets of a composition: the operand set and its arity, which
certificate fills which slot, the substrate every operand carries, the identity of the composed
object, and what distinguishes a slot from an operand.

**HYPER-2** — dynamics: how a claim propagates through a composition. Strength is
non-increasing; one `UNKNOWN` operand makes the composition `UNKNOWN`; recomposition from
retained bytes lands on the same object; what associativity the operator does and does not
have.

**HYPER-3** — statics: what no composition can manufacture. The weakest operand bound is
the composed ceiling whatever the composed object declares, the substrate recurs at every level
rather than being consumed, and the decider stays outside the certified surface at every level.

**HYPER-4** — **[anchor]** *boundary saturation, open ended collapsable meta-language,
fractal rerepresentations.*

Read against the lattice: saturation is every slot of a composition filled by a bound operand;
the collapsable meta-language is `AGENT` + `SIM` written as `BOT` and re-expanded without loss;
the fractal re-representation is `S` recurring identically at every level.

**HYPER-5** — the composition formalisms already in use — in-toto layouts, build-graph
derivations, assembly relations in software bills of materials, typed interface composition —
inferred upward into one composition meta-framework. Combining the base fields of a science
into composite fields is this same operator applied to sciences rather than to certificates;
those field members are named in their own repositories, not here.

## MODEL — trained models

**MODEL-1** — tensor shapes and architecture compatibility, module decomposition, the
declared input and output surface, the named dependency artifacts.

**MODEL-2** — dynamics: the bound dense network executed and every retained output
compared, batching and precision behaviour, sampling and decoding, what the model does as
opposed to what it is.

**MODEL-3** — **[anchor]** *weights, hardware requirements, quantization specifications
and configurations, training-data (DATA-5 specified object), ...*

**MODEL-4** — closure: metrics recomputed over the complete named evaluation set,
declared finite counterexample probes executed against their bound output conditions, the
condition under which the model's claimed behaviour is refutable rather than merely
unrefuted.

**MODEL-5** — PyTorch's lower-level modular representation of neural networks, with
ONNX, safetensors and GGUF, inferred upward into a general specification meta-framework.
This is the worked example the tier-5 definition is written from.

## SIM — simulations

**SIM-1** — state space, transition expressions, entropy stream, observation and
action channels, shard decomposition, the projection relating macro to micro.

**SIM-2** — **[anchor]** *responsiveness, internal state changes, computational spaces,
and perspective shifts.*

**SIM-3** — statics: invariant and conservation expressions holding on every retained
state, the closed finite state set where one exists, the physical law the simulation is a
model *of* and does not get to choose.

**SIM-4** — closure: complete aligned shard coverage, bound cross-shard relations,
signatures where required, the condition under which the retained trajectory accounts for
the whole simulated surface with no unattributed transition.

**SIM-5** — the interaction surface `BOT-5` sits over. Gymnasium, MuJoCo, FMI,
Modelica and SPICE inferred upward; `open-battery-sim` and `open-motor-sim` are the first
two domain adaptations published against it.

## HARNESS — the instrumented surface a session is observed through

**HARNESS-1** — every declared channel partitioned into instrumented observation and
named uninstrumented gap; the record types (user, agent, tool), the registry of tool
declarations, the declared side-effect channels, the shape of the transcript commitment.

**HARNESS-2** — dynamics: contiguity and ordering of retained records, pairing of each
invocation with its response, how a session advances record by record, interleaving of side
effects with messages, what a retry or a resumption does to the sequence.

**HARNESS-3** — statics: what the instrumentation cannot see whatever anyone declares —
the named uninstrumented gap itself, timestamp resolution, channel capacity, the fixed
boundary the harness sits at. The gap is a property of where the instrument was placed, not
of the session it recorded.

**HARNESS-4** — closure: the ordered transcript commitment recomputed, refusing an
omitted or substituted record. The condition under which the session is wholly accounted
for and no record can be added, dropped or reordered without detection.

**HARNESS-5** — OpenTelemetry trace and span semantics, Model Context Protocol, and the
tool-call transcript formats the mainstay model providers already emit, inferred upward into
one instrumentation meta-framework.

## AGENT — a deciding actor observed through a bound harness

**AGENT-1** — the observation ceiling re-derived from the bound harness certificate and
its required channels; decisions, declared actions, the outcome contract, the final claims.

**AGENT-2** — dynamics: contiguous decisions each witnessed by a record inside the
ceiling, every declared action bound to a witnessed tool invocation, how a trajectory
advances from one decision to the next.

**AGENT-3** — statics: the observation ceiling as an unchangeable epistemic bound —
what the agent could not have known, regardless of what it asserts it knew. The ceiling is
fixed by the harness, and no amount of agent declaration raises it.

**AGENT-4** — closure: the complete retained outcome inventory compared with the bound
outcome contract, and every final claim resting only on records inside the ceiling. The
condition under which the agent's account of itself admits no unsupported claim.

**AGENT-5** — the mainstay agent loops — tool-calling loops, planner/executor splits,
graph-structured agent runtimes — inferred upward into one decision-surface meta-framework.

## BOT — an agent bound inside a simulation

**BOT-1** — the bound agent, simulation and environment certificates re-derived from
their retained bytes; the facets of the coupling itself, not of either side.

**BOT-2** — dynamics: every simulation transition bound to one retained record, every
retained observation shown to be the simulation's own projection of that state, every
replayed action shown to be one the agent actually invoked.

**BOT-3** — statics: the observation ceiling that exists whatever the agent claims, the
latency and ordering the coupling physically imposes, the information the simulation cannot
expose regardless of policy.

**BOT-4** — closure: the declared separation of agent and simulator execution
environments. A `fused` declaration is honest and is `UNKNOWN`, never `FAIL` — containment
simply is not established, and that costs exactly one rung.

**BOT-5** — **[anchor]** *Interaction graph over SIM-5 specified interaction
surface, disclosable and indisclosed self-awareness including generally and of inclusion
inside a simulation and to what degree of awareness of the simulation specification
surfaces it is aware of, this is literally the self-awareness surface of superintelligence
if we can keep it in sims.*

---

## OWNER — a holding between a bound actor and a bound object

The third **relational** object, and the only ungrounded one. `GRAPH` relates
artifacts to one another, `HYPER` relates operands to the object composed from them,
and `OWNER` relates an actor to an object it holds. None of the three certifies a
substrate of its own, which is why none of them is a domain in the adapter sense.

The holder is bound by its own `ACTOR` certificate, so a holding names a certified
actor rather than a string. An **agent is not an actor**: an agent occupies a decider slot
inside `AGENT`, while an actor is the party accountable for the decision, and
`OWNER` types its holder as the latter. A holding is the composition
`HYPER(ACTOR + the held object)`; an earlier draft carried the holder on a wire
token because no actor object existed yet, and `ACTOR` replaced it.

**OWNER-1** — facets: the holder, the held object, the enumerated limbs of the
holding, the instrument that establishes it and the authority that issued it, the term it
runs for, and whether the holder is of a kind that can bear each limb at all. A limb the
inventory omits is unheld, not permitted.

The limbs are of **three** kinds, not two. A *right* is something the holder may do to
the held object; a *discharge-duty* is something it must do — supervise, remediate; an
*answering-duty* is being accountable when a discharge-duty is not met. The split is not
taxonomic. A bot may hold a seat and carry discharge-duties for it, and can never carry
the answering-duty for them, because accountability terminates in a person. With a single
undifferentiated duty limb, *a bot holds duties* is admissible prose that contradicts
that floor; with three, `OWNER-3.6` can state it.

**OWNER-2** — dynamics: transfer, delegation and revocation as ordered events,
each conveying only what the conveyor held at that position in the order, replayed from
the origin to reproduce the holding as it now stands. **Lapse is not among them**: a term
ending is the clock's doing rather than an act, so it declares nothing and occupies no
position — which is why `OWNER-4.5` must quantify over the term as well as the order.

**OWNER-3** — statics: a holding never moves a verdict. `OWNER-3.1` is the
ownership twin of the Prime Invariant — who owns an object cannot change what its
certificate established about it — and the profile closes with asymmetry, the
non-transitivity of authority through composition, and limb typing at the held end.

That last one is about a **natural person**, and deliberately not about an actor. A
person cannot be held by a right, only by duties. An actor is the wider class: creating,
abolishing, reorganizing and transferring an office are ordinary dispositive acts, and so
is holding a subsidiary, so a rule written over actors would forbid ordinary corporate
holdings. The predicate this row wants is a person object, which the VSTD-NAMESPACE does
not yet admit; until it does, the row says *natural person* in prose and nothing executes
it either way.

**OWNER-4** — closure: chain of custody from a declared origin, gapless,
fork-free, with each instrument admissible under the authority in force **when it issued**
rather than the authority in force now, over a chain that answers for itself. Failing
any of the five is `UNKNOWN`, never `FAIL`.

The **accountability floor** is why this profile carries six rows rather than five.
`OWNER-3.6` types *who may* hold an answering-duty; it never requires one to **exist**.
Without `OWNER-4.5` a chain whose holdings enumerate discharge-duties only satisfies
every other obligation here and certifies as closed, with no answering-duty anywhere in
it — supervision owed by nobody. Termination is a property of a walk rather than of a
single holding, which is why it is closure work and not statics: tier 3 constrains what
one surface does not get to choose, and tier 4 constrains the chain.

**Both quantifiers in `OWNER-4.5` are load-bearing, and neither implies the other.**
The answering-duty must exist at the same *position* and throughout the discharge-duty's
*term*, because this model moves on two independent clocks. Positions come from declared
events (`OWNER-2.1`), but a term ends **by the clock rather than by an event**
(`OWNER-2.5`), so a lapse declares no event and occupies no position. Terms attach to the
holding rather than to the limb (`OWNER-1.5`), and `OWNER-3.6` forces the two duties into
*separate* holdings whenever the discharge holder is not a natural person — separate
holdings, therefore independent terms. Quantifying over positions alone would let a bot's
discharge-duty run to 2030 under an answering-duty that lapsed in 2027: no event, no new
position, both duties present at every position from origin to head, and the chain closes
over three years nobody answers for. Dropping either quantifier reopens that.

**OWNER-5** — domain adaptation: licence expressions, registry maintainer records,
corporate and beneficial-ownership registers, declared code ownership and custody chains.
No adapter binds any of them today, so each is reported unestablished rather than unheld
— which is the distinction the whole row exists to keep.

---

## HUMAN — one living person, asserted and nothing more

The floor of the family, and the only object on this axis that no composition reaches.
`HUMAN-3.6` states it outright: no arrangement of models, agents, bots, simulations or
collectives produces a human, at any strength, by any route.

Naming it rather than leaving "bearer" implicit is what makes the rest of the family safe
to state. It gives the accountability chain somewhere to terminate, and it puts the
distance from `MODEL`, `AGENT` and `BOT` in the statics, where no
adaptation can close it.

**HUMAN-1** — facets: what is asserted, the evidence class and the capture pipeline
it came through, the liveness and uniqueness properties claimed, the enrollment population
the uniqueness is relative to, and — separately — what is deliberately **not** asserted.
`HUMAN-1.6` states the boundary the whole privacy position rests on: establishing that the
subject is a human and identifying which human are separable, and the first never carries
the second.

**HUMAN-2** — dynamics: enrollment, re-verification, evidence aging, revocation on
compromise, and two this axis carries nowhere else. A compromised biometric template does
not rotate, so `HUMAN-2.5` declares a breach permanent rather than remediated; and
`HUMAN-2.6` is **death**. A dataset does not die.

**HUMAN-3** — statics, and this is where the distancing lives: a person is singular
and non-copyable; biometric error is irreducible and no operating point has both rates at
zero; presentation attack detection is a separate error surface from matching; injection
attacks target the capture pipeline, which sits *outside* the biometric's own error model,
structurally the same fact as `HARNESS-3`; uniqueness holds only relative to an
enrollment population, and no protocol establishes it globally.

**HUMAN-4** — closure: evidence, error rates and population all declared, and
**every accountability chain terminates in a person**. `HUMAN-4.4` runs through *holdings*
and never through *occupancies*, which is what `HUMAN-4.5` exists to say: a bot may occupy
a seat and a human still answers for it. Without that distinction nothing in the standard
forbids an actor whose accountability terminates in a bot.

**HUMAN-5** — domain adaptation: biometric error-rate reporting, presentation attack
detection, enrollment schemes, and privacy-preserving personhood attestation, inferred
upward into one humanness meta-framework. These are here rather than in `IDENTITY-5`
because they establish that someone is a person, not which seat they occupy.

---

## ROLE — a single-bearer authority class

A **class**, not its occupants. The seat, the post, the office — with declared authority
and declared qualifications, and no person inside it. Occupancy is `IDENTITY`.

The object was called `VSTD-INDIVIDUAL` in the design notes until 2026-09-21. It was
renamed because every line of prose describing it already called it a role, and
`COLLECTIVE = GRAPH over { ROLE }` only reads correctly with the new name.

**ROLE-1** — facets: the class's name, the decision authority it carries, the
qualifications required of a bearer, how many bearers may occupy it at once, and **which
bearer classes it admits**. That last is a property of the class rather than of any
occupancy of it: a seat may be open to humans only, or to bots as well, and the class is
where that is decided.

**ROLE-2** — dynamics: taking and leaving the seat, hand-over as a *paired* event
rather than two independent ones, acting in role against acting personally, temporary
delegation, and what becomes of a decision in flight across a hand-over.

**ROLE-3** — statics: the class's authority is declared rather than derived from
whoever holds it, so an **unoccupied seat still carries it**; the occupancy fact exists
whether or not it is disclosed; and because one bearer occupies several classes,
correlation across them is a fact about the bearer and never about the classes.

**ROLE-4** — closure: every decision in the class's authority attributed to the
bearer during whose occupancy it fell, over contiguous occupancy intervals, with no gap in
which a decision was taken by no one.

**ROLE-5** — domain adaptation: engagement context role credentials, access-control
role definitions and org-chart position records, inferred upward.

---

## COLLECTIVE — a graph of role classes

The second branch of the actor sum. Its operands are declared rather than implied:
`COLLECTIVE-1.1` binds a `GRAPH` and `COLLECTIVE-1.3` binds the `ROLE` set the
graph is over.

**COLLECTIVE-1** — facets: the graph, the typed relations it carries — reports-to,
delegates-to, must-countersign — the role set, the decision classes the collective is
accountable for as a whole, and its boundary.

**COLLECTIVE-2** — dynamics: reorganization, role creation and retirement, quorum and
countersignature, escalation along declared edges, how a collective decision is assembled
from the role decisions beneath it, and what a merger or a split does to the graph.

**COLLECTIVE-3** — statics: the collective takes **no decisions of its own** — every
decision it is accountable for was taken through some role class by some bearer. The legal
entity exists or does not under some registry whatever the collective declares. And
separation of duty is real only where the bearers are distinct persons, which the graph
alone cannot establish: `COLLECTIVE-3.4` records that structure never establishes
occupancy.

**COLLECTIVE-4** — closure: a complete role graph with no class unattached, every
collective-level decision decomposed into role decisions that actually occurred, and each
quorum recomputed over the retained occupancy record rather than accepted as declared.

**COLLECTIVE-5** — domain adaptation: legal-entity identifiers with organizational
role credentials, corporate registry records, and access-control policy models, inferred
upward.

---

## IDENTITY — the binding of a bearer into a role class

Relational and asymmetric: a bearer on the left, a `ROLE` on the right, and the
occupancy between them as its subject. It is the second of the family's two sums, and it
is **two-wide**:

```
bearer = HUMAN | BOT
```

**A bare `AGENT` is not an admissible bearer, and the reason is the kind of bound.**
An agent is scoped by its observation ceiling — what it could not have known — which is an
**epistemic** bound. A role class is an **authority** container. An agent seated directly
would therefore carry bounded epistemics and unbounded authority, which is precisely the
hole role representation exists to close: a collective staffing its seats with agents and
inheriting no authority bound at all. A bot is admissible because `BOT = AGENT + SIM`
carries the simulation as an operand, so the declared law that bounds its authority is
already inside the certificate. An agent that is to occupy a seat is tied to a simulation
first — which is to say it is admitted as a `BOT`.

**IDENTITY-1** — facets: which bearer and **which bearer class**, which role class,
the occupancy evidence, the assurance level and the retained evidence it rests on, the
scope inherited from the bearer class's statics, and the validity, revocation and
disclosure surface.

**IDENTITY-2** — dynamics: enrollment into the seat, re-verification and renewal,
hand-over — which ends one binding and begins another rather than transferring one —
revocation, presentation, whether two presentations are linkable, and what happens to a
bot binding when its simulation ends or is superseded.

**IDENTITY-3** — statics: **a binding never has wider bounds than its bearer class's
statics allow**, which is the weakest-operand shape of the Prime Invariant one relation
over; one bearer occupies several classes at once and no protocol makes those occupancies
independent; a revoked binding does not un-happen, and what was decided in the seat stays
decided; and **the binding is not the bearer** — ending it ends an occupancy and nothing
else.

**IDENTITY-4** — closure: every presentation bound to an unrevoked enrollment, the
assurance level supported by evidence actually retained, no binding resting on a
self-asserted attribute, every binding declaring its bearer class, **no bot binding
presented outside its declared simulation**, and, for a human bearer, that human retaining
unilateral termination.

**IDENTITY-5** — domain adaptation: verifiable credential data models, decentralized
identifiers and resolution, and selective-disclosure cryptosuites with per-presentation
unlinkability, inferred upward. The proof-of-personhood mainstays are deliberately not
here; they establish humanness, which is `HUMAN-5`.

---

## ACTOR — the party accountable for decisions

The sum the family assembles into, and the object `OWNER` means by "holder":

```
ACTOR = ROLE | COLLECTIVE
```

**An agent is not an actor.** An agent decides; an actor answers for it. An agent's
decisions are taken *inside* an observation ceiling; an actor's decisions are the ones
that *placed* it. That is why this object splits into two branches and `AGENT` splits
into none, and why an agent never occupies the decider slot on its own.

The bearer is deliberately not here. A role-branch actor admits bearer classes; a
collective-branch actor has no bearer at all. A bearer field on the sum would force a
collective to declare itself human or bot, so the bearer stays on the occupancy at
`IDENTITY-1.1`.

**ACTOR-1** — facets: the actor's identity as a party rather than an instrument; the
**branch binding**, which is the sum's discriminant and the object's only operand; the
control surface, which is a property of the actor and not of any key; the decision classes
it is accountable for; the specification spaces it is admitted to, where admission to one
is never admission to another; and the instrument boundary.

**ACTOR-2** — dynamics: delegation and its revocation, key rotation that preserves
continuity rather than creating a second actor, entering and leaving a collective's graph,
**dissolution** — a collective wound up or a role class retired — succession as a paired
event, and a replay of the declared events that reproduces the current state.

**ACTOR-3** — statics: a decision once taken was taken; accountability is never
retroactively transferred; revocation, rotation and dissolution end the capacity to decide
and never the record of having decided; **an actor cannot be the sole witness of its own
accountability**; an instrument is never a party; and where accountability runs through a
composition it is bounded by the weakest operand.

**ACTOR-4** — closure: a contiguous decision inventory in which every decision in the
declared classes is attributable to exactly one actor, none unattributed, none doubly
attributed, and no attribution resting on a record the actor exclusively controls.

**ACTOR-5** — domain adaptation: key event receipt infrastructure, decentralized
identifier controllers and authorization-framework principals, inferred upward into one
accountability meta-framework. The principal-versus-client distinction is mapped onto the
instrument boundary, which is the one place a mainstay already draws this object's line.

---

# The grid as catalogued coordinates

Nineteen objects, ninety-five numbered profiles, every one of them carrying
obligations of its own. The object axis and the Graph axis are the two `LADDER.md`
already carried. The other seventeen were catalogued against these tiers, so the
grid below is a coordinate map, not a mapping
of adapter checks onto tiers — an adapter check is now a *mechanism* attached to an
obligation rather than a rung in its own right:

| Object | 1 facets | 2 dynamics | 3 statics | 4 closure | 5 adaptation | 6 disclosure |
|---|---|---|---|---|---|---|
| VSTD | `1.1`-`1.7` | `2.1`-`2.7` | `3.1`-`3.8` | `4.1`-`4.14` | `5.1`-`5.11` | — |
| GRAPH | `GRAPH-1.1`-`1.6` | `GRAPH-2.1`-`2.5` | `GRAPH-3.1`-`3.5` | `GRAPH-4.1`-`4.6` | `GRAPH-5.1`-`5.6` | — |
| DATA | `DATA-1.1`-`1.6` | `DATA-2.1`-`2.6` | `DATA-3.1`-`3.6` | `DATA-4.1`-`4.6` | `DATA-5.1`-`5.6` | `DATA-6.1`-`6.6` |
| ENV | `ENV-1.1`-`1.6` | `ENV-2.1`-`2.6` | `ENV-3.1`-`3.5` | `ENV-4.1`-`4.5` | `ENV-5.1`-`5.6` | `ENV-6.1`-`6.6` |
| BENCH | `BENCH-1.1`-`1.7` | `BENCH-2.1`-`2.6` | `BENCH-3.1`-`3.7` | `BENCH-4.1`-`4.5` | `BENCH-5.1`-`5.6` | `BENCH-6.1`-`6.6` |
| TRAIN | `TRAIN-1.1`-`1.6` | `TRAIN-2.1`-`2.6` | `TRAIN-3.1`-`3.5` | `TRAIN-4.1`-`4.6` | `TRAIN-5.1`-`5.6` | `TRAIN-6.1`-`6.6` |
| HYPER § | `HYPER-1.1`-`1.6` | `HYPER-2.1`-`2.6` | `HYPER-3.1`-`3.5` | `HYPER-4.1`-`4.5` | `HYPER-5.1`-`5.5` | `HYPER-6.1`-`6.6` |
| MODEL | `MODEL-1.1`-`1.5` | `MODEL-2.1`-`2.5` | `MODEL-3.1`-`3.6` | `MODEL-4.1`-`4.5` | `MODEL-5.1`-`5.6` | `MODEL-6.1`-`6.6` |
| SIM | `SIM-1.1`-`1.7` | `SIM-2.1`-`2.6` | `SIM-3.1`-`3.5` | `SIM-4.1`-`4.5` | `SIM-5.1`-`5.6` | `SIM-6.1`-`6.6` |
| HARNESS † | `HARNESS-1.1`-`1.5` | `HARNESS-2.1`-`2.5` | `HARNESS-3.1`-`3.4` | `HARNESS-4.1`-`4.5` | `HARNESS-5.1`-`5.6` | `HARNESS-6.1`-`6.6` |
| AGENT † | `AGENT-1.1`-`1.7` | `AGENT-2.1`-`2.5` | `AGENT-3.1`-`3.3` | `AGENT-4.1`-`4.4` | `AGENT-5.1`-`5.5` | `AGENT-6.1`-`6.6` |
| BOT † | `BOT-1.1`-`1.5` | `BOT-2.1`-`2.5` | `BOT-3.1`-`3.4` | `BOT-4.1`-`4.4` | `BOT-5.1`-`5.6` | `BOT-6.1`-`6.6` |
| OWNER ‡ | `OWNER-1.1`-`1.6` | `OWNER-2.1`-`2.6` | `OWNER-3.1`-`3.6` | `OWNER-4.1`-`4.6` | `OWNER-5.1`-`5.6` | `OWNER-6.1`-`6.6` |
| HUMAN ‡ | `HUMAN-1.1`-`1.6` | `HUMAN-2.1`-`2.6` | `HUMAN-3.1`-`3.6` | `HUMAN-4.1`-`4.6` | `HUMAN-5.1`-`5.6` | `HUMAN-6.1`-`6.6` |
| ROLE ‡ | `ROLE-1.1`-`1.6` | `ROLE-2.1`-`2.6` | `ROLE-3.1`-`3.6` | `ROLE-4.1`-`4.5` | `ROLE-5.1`-`5.6` | `ROLE-6.1`-`6.6` |
| COLLECTIVE ‡ | `COLLECTIVE-1.1`-`1.6` | `COLLECTIVE-2.1`-`2.6` | `COLLECTIVE-3.1`-`3.4` | `COLLECTIVE-4.1`-`4.4` | `COLLECTIVE-5.1`-`5.6` | `COLLECTIVE-6.1`-`6.6` |
| IDENTITY ‡ | `IDENTITY-1.1`-`1.6` | `IDENTITY-2.1`-`2.7` | `IDENTITY-3.1`-`3.6` | `IDENTITY-4.1`-`4.7` | `IDENTITY-5.1`-`5.7` | `IDENTITY-6.1`-`6.6` |
| ACTOR ‡ | `ACTOR-1.1`-`1.7` | `ACTOR-2.1`-`2.7` | `ACTOR-3.1`-`3.6` | `ACTOR-4.1`-`4.6` | `ACTOR-5.1`-`5.6` | `ACTOR-6.1`-`6.6` |
| TOKEN | `TOKEN-1.1`-`1.14` | `TOKEN-2.1`-`2.14` | `TOKEN-3.1`-`3.14` | `TOKEN-4.1`-`4.14` | `TOKEN-5.1`-`5.14` | `TOKEN-6.1`-`6.6` |

Every cell is a coordinate range into a catalogued obligation set: the object axis in
[`GROUNDED_CERTIFICATION.md`](GROUNDED_CERTIFICATION.md), the Graph axis in
[`GRAPH_GROUNDING.md`](GRAPH_GROUNDING.md), the seventeen domain objects in
[`DOMAIN_OBLIGATIONS.md`](DOMAIN_OBLIGATIONS.md). 701 obligations across the three
namespaces, which are disjoint: `DATA-4.2` never aliases `4.2` or `GRAPH-4.2`, and each
catalogue carries its own digest. † marks the three objects whose adapters live on the open
release branch rather than in this tree; § marks `HYPER`, which is catalogued but
not certifiable; ‡ marks the six objects with no adapter anywhere: `OWNER` and
the five identity objects.

## The ladder strip — what a certificate actually climbs

The table above is the coordinate space; this one is the climb. Each cell is the
interval of `m` a grounded certificate can actually reach in that profile, and
**hovering it names every rung**: the short name of each grounding certificate from
`.1` to the profile's depth. Reaching `.m` clears every obligation whose longest
prerequisite chain is exactly `m`, so a rung may carry more than one obligation and
need not be the one whose index is `m`.

| Certificate stem | 1 | 2 | 3 | 4 | 5 | rungs |
|---|---|---|---|---|---|---|
| `VSTD-` | [1.1–1.5](GROUNDED_CERTIFICATION.md ".1 Claim coordinate; .2 Evidence binding; .3 Checker and trust boundary, Provenance; .4 Decision replay; .5 Reproduction fidelity, Challenge and correction") | [2.1–2.5](GROUNDED_CERTIFICATION.md ".1 Subject and surface; .2 Geometry consistency; .3 Translation and reconstruction, Evidence-earned judgments; .4 Residuals and horizons, Adjacent verification orders; .5 Bounded surface closure") | [3.1–3.6](GROUNDED_CERTIFICATION.md ".1 Subject and capability boundary; .2 Attestation binding; .3 Firmware accountability, Execution binding; .4 Accounting and topology, Continuity and anchors; .5 Provider and fleet scope; .6 Derived substrate outcome") | [4.1–4.8](GROUNDED_CERTIFICATION.md ".1 Decision certification; .2 Semantic binding; .3 Anti-equivocation, Explicit refutation surface; .4 Portable verification, Prior commitment, Challenge handling; .5 Bounded verification, Re-derivability; .6 Minimal trusted checker, Availability; .7 Disclosure-safe checkability, Monotonic degradation; .8 Compositionality") | [5.1–5.5](GROUNDED_CERTIFICATION.md ".1 Exact refutability entry; .2 Witness identity binding; .3 Operational separation, Implementation separation, Trust-root separation, Evidence-source separation, Infrastructure separation, Financial separation, Compulsion separation; .4 Executed corroboration; .5 Disagreement preservation") | **29** |
| `GRAPH-` | [1.1–1.3](GRAPH_GROUNDING.md ".1 Collection coordinate; .2 Recorded structure, Status admissibility; .3 Coverage recomputation, Conflict retention, Blast radius closure") | [2.1–2.4](GRAPH_GROUNDING.md ".1 Member rating re-execution; .2 Ancestor reachability closure, Edge rating re-execution; .3 Scope binding; .4 Bounded admission") | [3.1–3.3](GRAPH_GROUNDING.md ".1 Substrate rating re-execution; .2 Weakest reachable cap, Out-of-closure contribution, Accountable actor binding; .3 Accountable closure result") | [4.1–4.4](GRAPH_GROUNDING.md ".1 Member refutability entry; .2 Edge refutability closure, Candidate ceiling explanation; .3 Unevidenced edge rejection, Challenge localization; .4 Offline replay") | [5.1–5.4](GRAPH_GROUNDING.md ".1 Exact network entry; .2 Witness member rating, Witness transformation rating; .3 Network scope binding, Conflict inadmissibility; .4 Declared rating rejection") | **18** |
| `DATA-` | [1.1–1.4](DOMAIN_OBLIGATIONS.md#data-1-facets ".1 Retention boundary; .2 Shard and record inventory, Field contract; .3 Record identity, Digest tree commitment; .4 Schema conformance") | [2.1–2.4](DOMAIN_OBLIGATIONS.md#data-2-dynamics ".1 Transformation declaration; .2 Exact re-execution; .3 Pipeline ordering, Raw-to-retained path; .4 Idempotence, Rebuild drift") | [3.1–3.3](DOMAIN_OBLIGATIONS.md#data-3-statics ".1 Sampling frame, Measurement instrument, Origin rights; .2 Censoring and truncation, Distribution statics; .3 Pipeline independence") | [4.1–4.5](DOMAIN_OBLIGATIONS.md#data-4-closure ".1 Split declaration; .2 Complete membership; .3 Identity separation, Exact overlap; .4 Lexical overlap; .5 No unaccounted record") | [5.1–5.4](DOMAIN_OBLIGATIONS.md#data-5-domain-adaptation ".1 Mainstay binding; .2 Columnar shard mapping, Schema mapping, Dataset card mapping; .3 Round trip; .4 Inference upward") | **20** |
| `ENV-` | [1.1–1.4](DOMAIN_OBLIGATIONS.md#env-1-facets ".1 Environment boundary; .2 Software inventory, Configuration surface; .3 Executable coordinates, Observed configuration; .4 Unpinned residue") | [2.1–2.4](DOMAIN_OBLIGATIONS.md#env-2-dynamics ".1 Nondeterminism declaration, Execution pair; .2 Scheduling surface, Input agreement; .3 Result agreement; .4 Divergence attribution") | [3.1–3.3](DOMAIN_OBLIGATIONS.md#env-3-statics ".1 Instruction set, Resource ceilings; .2 Floating-point semantics, Physical envelope; .3 Envelope independence") | [4.1–4.4](DOMAIN_OBLIGATIONS.md#env-4-closure ".1 Pin completeness; .2 Host isolation, Network closure; .3 Standup sufficiency; .4 Standup evidence") | [5.1–5.5](DOMAIN_OBLIGATIONS.md#env-5-domain-adaptation ".1 Mainstay binding; .2 Image closure mapping, Derivation mapping; .3 Build provenance mapping; .4 Round trip; .5 Inference upward") | **20** |
| `BENCH-` | [1.1–1.5](DOMAIN_OBLIGATIONS.md#bench-1-facets ".1 Domain declaration; .2 Problem set, Feature representation; .3 Solution deducibility, Sampling procedure; .4 Oracle binding; .5 Baseline mechanics") | [2.1–2.4](DOMAIN_OBLIGATIONS.md#bench-2-dynamics ".1 Attempt policy, Contamination accumulation; .2 Attempt inventory; .3 Sequential adaptivity, Response curve; .4 Measurement feedback") | [3.1–3.4](DOMAIN_OBLIGATIONS.md#bench-3-statics ".1 Chance floor, Oracle ceiling, Budget ceilings; .2 Label noise, Hardness classes; .3 Natural distribution; .4 Harness independence") | [4.1–4.4](DOMAIN_OBLIGATIONS.md#bench-4-closure ".1 Run inventory; .2 No missing run, No duplicate or substituted run; .3 Weighted score; .4 Surface completeness") | [5.1–5.5](DOMAIN_OBLIGATIONS.md#bench-5-domain-adaptation ".1 Mainstay binding; .2 Task specification mapping, Scoring contract mapping; .3 Budget mapping; .4 Round trip; .5 Inference upward") | **22** |
| `TRAIN-` | [1.1–1.4](DOMAIN_OBLIGATIONS.md#train-1-facets ".1 Optimizer contract, Checkpoint inventory; .2 Numerical semantics, Step index; .3 Batch binding; .4 Retention boundary") | [2.1–2.5](DOMAIN_OBLIGATIONS.md#train-2-dynamics ".1 Loss replay; .2 Gradient replay; .3 Optimizer update; .4 State advance, Unsupported update reporting; .5 Step-by-step advance") | [3.1–3.3](DOMAIN_OBLIGATIONS.md#train-3-statics ".1 Arithmetic semantics, True gradient; .2 Accumulation order, Objective geometry; .3 Choice independence") | [4.1–4.6](DOMAIN_OBLIGATIONS.md#train-4-closure ".1 Contiguity; .2 Parent binding; .3 Batch and hyperparameter binding; .4 Result binding; .5 No reordering; .6 Whole-run accounting") | [5.1–5.5](DOMAIN_OBLIGATIONS.md#train-5-domain-adaptation ".1 Mainstay binding; .2 Training-loop mapping, Checkpoint-format mapping; .3 Batch source mapping; .4 Round trip; .5 Inference upward") | **23** |
| `HYPER-` § | [1.1–1.5](DOMAIN_OBLIGATIONS.md#hyper-1-facets ".1 Operand set; .2 Slot schema, Substrate presence; .3 Slot versus operand; .4 Composed identity; .5 Operand admissibility") | [2.1–2.4](DOMAIN_OBLIGATIONS.md#hyper-2-dynamics ".1 Strength ordering, Recomposition; .2 Non-increase, Associativity; .3 UNKNOWN absorption; .4 Depth propagation") | [3.1–3.3](DOMAIN_OBLIGATIONS.md#hyper-3-statics ".1 Composed ceiling, Substrate recurrence, Decider exteriority; .2 Manufacture impossibility; .3 Level independence") | [4.1–4.5](DOMAIN_OBLIGATIONS.md#hyper-4-closure ".1 Saturation; .2 Collapse; .3 Expansion fidelity; .4 Fractal re-representation; .5 Boundary completeness") | [5.1–5.5](DOMAIN_OBLIGATIONS.md#hyper-5-domain-adaptation ".1 Mainstay binding; .2 Layout mapping; .3 Authorization mapping; .4 Round trip; .5 Inference upward") | **22** |
| `MODEL-` | [1.1–1.3](DOMAIN_OBLIGATIONS.md#model-1-facets ".1 Tensor inventory, Dependency artifacts; .2 Architecture compatibility; .3 Module decomposition, Input and output surface") | [2.1–2.4](DOMAIN_OBLIGATIONS.md#model-2-dynamics ".1 Forward execution; .2 Output agreement; .3 Batching behaviour, Precision behaviour; .4 Sampling and decoding") | [3.1–3.3](DOMAIN_OBLIGATIONS.md#model-3-statics ".1 Weight bytes, Training-data citation; .2 Hardware requirements, Quantization specification, Provenance citation; .3 Artifact immutability") | [4.1–4.3](DOMAIN_OBLIGATIONS.md#model-4-closure ".1 Evaluation set, Probe inventory; .2 Metric recomputation, Probe execution; .3 Refutability") | [5.1–5.5](DOMAIN_OBLIGATIONS.md#model-5-domain-adaptation ".1 Mainstay binding; .2 Module-graph mapping, Serialized-weights mapping; .3 Operator coverage; .4 Round trip; .5 Inference upward") | **18** |
| `SIM-` | [1.1–1.3](DOMAIN_OBLIGATIONS.md#sim-1-facets ".1 State space; .2 Transition expressions, Observation channels, Shard decomposition; .3 Entropy stream, Action channels, Macro and micro projection") | [2.1–2.4](DOMAIN_OBLIGATIONS.md#sim-2-dynamics ".1 Trajectory replay; .2 Responsiveness, Internal state change, Computational space; .3 Perspective shift; .4 Perspective agreement") | [3.1–3.4](DOMAIN_OBLIGATIONS.md#sim-3-statics ".1 Invariant expressions, Modelled law; .2 Per-state holding; .3 Closed state set; .4 Law independence") | [4.1–4.4](DOMAIN_OBLIGATIONS.md#sim-4-closure ".1 Shard coverage; .2 Cross-shard relations, No unattributed transition; .3 Signatures; .4 Whole-surface accounting") | [5.1–5.5](DOMAIN_OBLIGATIONS.md#sim-5-domain-adaptation ".1 Mainstay binding; .2 Interaction-surface mapping, Physical-backend mapping; .3 Stepping contract; .4 Round trip; .5 Inference upward") | **20** |
| `HARNESS-` † | [1.1–1.4](DOMAIN_OBLIGATIONS.md#harness-1-facets ".1 Channel partition; .2 Record types; .3 Tool registry, Transcript commitment shape; .4 Side-effect channels") | [2.1–2.4](DOMAIN_OBLIGATIONS.md#harness-2-dynamics ".1 Record contiguity; .2 Invocation pairing, Session advance; .3 Side-effect interleaving; .4 Retry and resumption") | [3.1–3.3](DOMAIN_OBLIGATIONS.md#harness-3-statics ".1 Gap boundary, Timestamp resolution; .2 Channel capacity; .3 Instrument fixity") | [4.1–4.4](DOMAIN_OBLIGATIONS.md#harness-4-closure ".1 Commitment recomputation; .2 Omission detection, Substitution detection; .3 Reordering detection; .4 Whole-session accounting") | [5.1–5.5](DOMAIN_OBLIGATIONS.md#harness-5-domain-adaptation ".1 Mainstay binding; .2 Trace-span mapping, Tool-protocol mapping; .3 Gap representation; .4 Round trip; .5 Inference upward") | **20** |
| `AGENT-` † | [1.1–1.6](DOMAIN_OBLIGATIONS.md#agent-1-facets ".1 Harness binding; .2 Required channels; .3 Observation ceiling; .4 Decision inventory, Outcome contract; .5 Declared actions; .6 Final claims") | [2.1–2.4](DOMAIN_OBLIGATIONS.md#agent-2-dynamics ".1 Trajectory contiguity; .2 Decision witnessing; .3 Action witnessing; .4 Unwitnessed action reporting, Trajectory advance") | [3.1–3.3](DOMAIN_OBLIGATIONS.md#agent-3-statics ".1 Ceiling fixity; .2 Unknowability; .3 Declaration impotence") | [4.1–4.4](DOMAIN_OBLIGATIONS.md#agent-4-closure ".1 Outcome inventory; .2 Contract comparison; .3 Claim support; .4 No unsupported claim") | [5.1–5.5](DOMAIN_OBLIGATIONS.md#agent-5-domain-adaptation ".1 Mainstay binding; .2 Decision-loop mapping; .3 Slot mapping; .4 Round trip; .5 Inference upward") | **22** |
| `OWNER-` ‡ | [1.1–1.4](DOMAIN_OBLIGATIONS.md#owner-1-facets ".1 Holder binding, Held-object binding; .2 Instrument, Bearer capability; .3 Limb inventory; .4 Term") | [2.1–2.4](DOMAIN_OBLIGATIONS.md#owner-2-dynamics ".1 Event declaration; .2 Transfer conveyance, Delegation bound, Lapse; .3 Revocation effect; .4 Ordered replay") | [3.1–3.3](DOMAIN_OBLIGATIONS.md#owner-3-statics ".1 Verdict independence, Asymmetry; .2 Evidence immutability, Ancestry immutability, Non-transitivity of authority; .3 Person-limb typing") | [4.1–4.4](DOMAIN_OBLIGATIONS.md#owner-4-closure ".1 Chain origin; .2 Gapless chain, Admissibility at issue time; .3 Fork detection, Accountability floor; .4 Closure result") | [5.1–5.3](DOMAIN_OBLIGATIONS.md#owner-5-domain-adaptation ".1 Licence holding, Registry maintainer record, Register entry, Custody chain; .2 Declared code ownership; .3 Adaptation accounting") | **18** |
| `BOT-` † | [1.1–1.3](DOMAIN_OBLIGATIONS.md#bot-1-facets ".1 Agent binding, Simulation binding; .2 Environment bindings; .3 Coupling surface, Operand depths") | [2.1–2.4](DOMAIN_OBLIGATIONS.md#bot-2-dynamics ".1 Transition binding; .2 Observation projection, Action authenticity; .3 One-to-one coupling; .4 Coupling advance") | [3.1–3.3](DOMAIN_OBLIGATIONS.md#bot-3-statics ".1 Inherited ceiling, Coupling latency; .2 Disclosure limit; .3 Policy impotence") | [4.1–4.3](DOMAIN_OBLIGATIONS.md#bot-4-closure ".1 Separation declaration; .2 Separation evidence, Fused honesty; .3 Containment accounting") | [5.1–5.5](DOMAIN_OBLIGATIONS.md#bot-5-domain-adaptation ".1 Interaction-graph binding; .2 Disclosure inventory; .3 Indisclosure inventory, Inclusion awareness; .4 Specification awareness; .5 Awareness accounting") | **18** |
| `HUMAN-` ‡ | [1.1–1.4](DOMAIN_OBLIGATIONS.md#human-1-facets ".1 Assertion subject; .2 Evidence class, Non-assertion boundary; .3 Liveness and uniqueness claims, Humanness versus identification; .4 Enrollment population") | [2.1–2.3](DOMAIN_OBLIGATIONS.md#human-2-dynamics ".1 Enrollment; .2 Re-verification, Revocation on compromise, Death; .3 Evidence aging, Template irreversibility") | [3.1–3.3](DOMAIN_OBLIGATIONS.md#human-3-statics ".1 Singularity, Irreducible biometric error; .2 Presentation attack surface, Relative uniqueness, No composition yields a human; .3 Injection attack surface") | [4.1–4.4](DOMAIN_OBLIGATIONS.md#human-4-closure ".1 Evidence declaration, Accountability termination; .2 Error-rate declaration, Occupancy is not termination; .3 Population declaration; .4 Closure result") | [5.1–5.3](DOMAIN_OBLIGATIONS.md#human-5-domain-adaptation ".1 Error-rate reporting mainstay, Presentation attack detection mainstay, Attestation mapping, Human-verification mapping; .2 Enrollment scheme mapping; .3 Adaptation accounting") | **17** |
| `ROLE-` ‡ | [1.1–1.4](DOMAIN_OBLIGATIONS.md#role-1-facets ".1 Class identity; .2 Decision authority, Qualifications, Simultaneous bearer limit; .3 Admissible bearer classes; .4 Facet completeness") | [2.1–2.4](DOMAIN_OBLIGATIONS.md#role-2-dynamics ".1 Occupancy events; .2 Hand-over, Acting in role, Temporary delegation; .3 In-flight decisions; .4 Occupancy replay") | [3.1–3.3](DOMAIN_OBLIGATIONS.md#role-3-statics ".1 Declared authority, Occupancy factuality; .2 Vacancy retention, Cross-role correlation; .3 Authority independence, Class is not its occupants") | [4.1–4.4](DOMAIN_OBLIGATIONS.md#role-4-closure ".1 Decision inventory, Contiguous occupancy; .2 Bearer attribution; .3 No unattributed decision; .4 Closure result") | [5.1–5.4](DOMAIN_OBLIGATIONS.md#role-5-domain-adaptation ".1 Engagement context role mainstay, Access control role mapping, Org-chart position mapping; .2 Round trip; .3 Inference upward; .4 Adaptation accounting") | **19** |
| `COLLECTIVE-` ‡ | [1.1–1.3](DOMAIN_OBLIGATIONS.md#collective-1-facets ".1 Role graph; .2 Relation types, Role set, Accountable decision classes, Boundary; .3 Facet completeness") | [2.1–2.3](DOMAIN_OBLIGATIONS.md#collective-2-dynamics ".1 Reorganization, Quorum and countersignature; .2 Role lifecycle, Escalation; .3 Decision assembly, Merger and split") | [3.1–3.3](DOMAIN_OBLIGATIONS.md#collective-3-statics ".1 No decisions of its own, External legal existence; .2 Separation of duty needs persons; .3 Graph impotence") | [4.1–4.4](DOMAIN_OBLIGATIONS.md#collective-4-closure ".1 Complete role graph; .2 Decision decomposition; .3 Quorum recomputation; .4 Closure result") | [5.1–5.4](DOMAIN_OBLIGATIONS.md#collective-5-domain-adaptation ".1 Organizational role mainstay, Corporate registry mapping, Access control policy mapping; .2 Round trip; .3 Inference upward; .4 Adaptation accounting") | **17** |
| `IDENTITY-` ‡ | [1.1–1.4](DOMAIN_OBLIGATIONS.md#identity-1-facets ".1 Bearer binding, Role binding; .2 Occupancy evidence, Inherited scope; .3 Assurance level; .4 Validity and revocation surface") | [2.1–2.3](DOMAIN_OBLIGATIONS.md#identity-2-dynamics ".1 Enrollment; .2 Re-verification and renewal, Hand-over, Revocation, Presentation, Simulation end; .3 Presentation linkability") | [3.1–3.3](DOMAIN_OBLIGATIONS.md#identity-3-statics ".1 Bearer-bounded, Multiple occupancy, Revocation does not un-happen; .2 Evidence ceiling, The binding is not the bearer; .3 Weakest operand") | [4.1–4.3](DOMAIN_OBLIGATIONS.md#identity-4-closure ".1 Presentation binding, Bearer class declared; .2 Assurance support, No self-asserted attribute, Bot containment, Human exit; .3 Closure result") | [5.1–5.6](DOMAIN_OBLIGATIONS.md#identity-5-domain-adaptation ".1 Verifiable credential mainstay, Decentralized identifier mapping; .2 Selective disclosure mapping; .3 Unlinkability mapping; .4 Round trip; .5 Inference upward; .6 Adaptation accounting") | **19** |
| `ACTOR-` ‡ | [1.1–1.4](DOMAIN_OBLIGATIONS.md#actor-1-facets ".1 Actor identity; .2 Branch binding, Control surface, Decision classes, Admitted specification spaces; .3 Instrument boundary; .4 Facet completeness") | [2.1–2.5](DOMAIN_OBLIGATIONS.md#actor-2-dynamics ".1 Delegation, Key rotation; .2 Revocation, Collective membership; .3 Dissolution; .4 Succession; .5 Accountability replay") | [3.1–3.3](DOMAIN_OBLIGATIONS.md#actor-3-statics ".1 Decisions are factual, No sole witness, Instrument is not a party; .2 Non-transferable accountability; .3 Revocation does not un-decide, Weakest operand") | [4.1–4.4](DOMAIN_OBLIGATIONS.md#actor-4-closure ".1 Decision inventory; .2 Exactly one actor; .3 None unattributed, None doubly attributed, Independent attribution; .4 Closure result") | [5.1–5.4](DOMAIN_OBLIGATIONS.md#actor-5-domain-adaptation ".1 Mainstay binding; .2 Key event mapping, Controller mapping, Principal mapping; .3 Round trip; .4 Inference upward") | **20** |
| `TOKEN-` | [1.1–1.5](DOMAIN_OBLIGATIONS.md#token-1-facets ".1 Token kind; .2 Canonical bytes, Genesis commitment, Tenure accumulator, Lease scope; .3 Issuance binding, Audience, Validity window, Caveat set, Disclosure digests; .4 Algorithm binding, Key identification, Replay identifier; .5 Confirmation key") | [2.1–2.5](DOMAIN_OBLIGATIONS.md#token-2-dynamics ".1 Genesis; .2 Epoch advance, Lease grant, Key rotation; .3 Revocation, Lease expiry, Attenuation, Reissuance; .4 Discharge, Presentation, Suspension, Status publication, Clock disagreement; .5 Chain replay") | [3.1–3.5](DOMAIN_OBLIGATIONS.md#token-3-statics ".1 Preimage resistance, Soulbound non-transfer, Window emptiness; .2 Chain one-wayness, Commitment binding, Algorithm confusion, Key identity, Freshness is not validity, Disclosure complement; .3 Tenure is not authority, Possession is not presentation, Replay distinctness; .4 Attenuation is one-way; .5 Choice independence") | [4.1–4.4](DOMAIN_OBLIGATIONS.md#token-4-closure ".1 Inventory; .2 Epoch contiguity, Parent binding, Signature closure, Algorithm closure, Key closure, Audience closure, Window coverage, Replay closure, Status coverage, Disclosure closure; .3 Scope monotonicity, Discharge closure; .4 Closure result") | [5.1–5.5](DOMAIN_OBLIGATIONS.md#token-5-domain-adaptation ".1 Mainstay binding; .2 Claim-set mapping, Validity-window mapping, Header metadata mapping, Proof attestation mapping, Presentation authorization mapping, Transparency inclusion; .3 Attenuation mapping, Ceiling mapping, Selective disclosure mapping; .4 Round trip, Attenuation operators, Withheld field mapping; .5 Inference upward") | **24** |

386 rungs over ninety-five profiles. The remaining 213 of 599 catalogued
obligations sit above their profile's depth: nameable, and unreachable as an `m`,
because independent obligations are cleared at one depth rather than at several. A
certificate that names one of them is malformed.

An obligation is either **mechanized** — an adapter check establishes it today — or
specified without a mechanism, in which case it is reported `UNKNOWN`, never absent and
never passed. Only 11 of the seventeen domain objects have an adapter in any family, and only
ten have a behavioural adapter, which is what a domain certificate requires; the parenthesised
count in each cell of the depth grid below is how many of that profile's obligations
one of the three families establishes today.

Of the 626 domain obligations, 236 are mechanized, across three disjoint families: 123
behavioural adapter checks, 41 tier-3 statics checks and 72 tier-5 adaptation checks.
Tier 5 is fully mechanized on the 11 grounded objects and tier 3 on seven of them; on the
six ungrounded objects no tier is mechanized at all, and level 6 is mechanized nowhere.
What remains bare is 69 at tier 1, 73 at tier 2, 51 at tier 3, 58 at tier 4, 37 at tier 5,
and the whole of level 6. The two specification axes are unmechanized by construction —
they are checked against retained evidence rather than by any domain adapter.
[`DOMAIN_OBLIGATIONS.md`](DOMAIN_OBLIGATIONS.md) sets out the three families and why a
static needs a different kind of evidence from a dynamic.

## The cardinality of the grid

Ninety-five cells is the shape of the grid, not its size. Each cell is a numbered profile with
its own internal topology, and a grounded certificate does not name the cell — it names a
position inside it: `<object>-<tier>.<m>`, where `m` is the depth of complete modules
represented. Write `i` for the depth of one cell's module topology and the grid spans

```
prod(i, 19 x 5) = 683,643,783,743,337,042,227,376,839,322,501,120,000,000,000,000,000,000,000
```

`i` is a **depth, not a count**: the longest chain of modules each of which is a
prerequisite of the next. The two coincide only where a profile is a chain. Wherever it is
a directed acyclic graph — where two modules both depend on a third but not on each other
— the depth is strictly smaller, because independent modules are cleared at one depth
rather than at two. Every one of the ninety-five profiles is a DAG, so on every object the
depth is strictly below the count somewhere.

| Object | 1 | 2 | 3 | 4 | 5 | 6 | sum i | states | mechanized |
|---|---|---|---|---|---|---|---|---|---|
| VSTD | **5** of 7 | **5** of 7 | **6** of 8 | **8** of 14 | **5** of 11 | — | 29 | 30 | n/a |
| GRAPH | **3** of 6 | **4** of 5 | **3** of 5 | **4** of 6 | **4** of 6 | — | 18 | 19 | n/a |
| DATA | **4** of 6 (5) | **4** of 6 (3) | **3** of 6 (6) | **5** of 6 (5) | **4** of 6 (6) | **5** of 6 (0) | 20 | 21 | 25/36 |
| ENV | **4** of 6 (4) | **4** of 6 (3) | **3** of 5 (1) | **4** of 5 (0) | **5** of 6 (6) | **5** of 6 (0) | 20 | 21 | 14/34 |
| BENCH | **5** of 7 (3) | **4** of 6 (0) | **4** of 7 (1) | **4** of 5 (4) | **5** of 6 (6) | **5** of 6 (0) | 22 | 23 | 14/37 |
| TRAIN | **4** of 6 (5) | **5** of 6 (5) | **3** of 5 (5) | **6** (4) | **5** of 6 (6) | **5** of 6 (0) | 23 | 24 | 25/35 |
| HYPER § | **5** of 6 (0) | **4** of 6 (0) | **3** of 5 (5) | **5** (0) | **5** (5) | **5** of 6 (0) | 22 | 23 | 10/33 |
| MODEL | **3** of 5 (3) | **4** of 5 (2) | **3** of 6 (1) | **3** of 5 (4) | **5** of 6 (6) | **5** of 6 (0) | 18 | 19 | 16/33 |
| SIM | **3** of 7 (2) | **4** of 6 (2) | **4** of 5 (3) | **4** of 5 (3) | **5** of 6 (6) | **5** of 6 (0) | 20 | 21 | 16/35 |
| HARNESS † | **4** of 5 (2) | **4** of 5 (4) | **3** of 4 (4) | **4** of 5 (3) | **5** of 6 (6) | **5** of 6 (0) | 20 | 21 | 19/31 |
| AGENT † | **6** of 7 (3) | **4** of 5 (4) | **3** (3) | **4** (3) | **5** (5) | **5** of 6 (0) | 22 | 23 | 18/30 |
| BOT † | **3** of 5 (3) | **4** of 5 (4) | **3** of 4 (4) | **3** of 4 (3) | **5** of 6 (6) | **5** of 6 (0) | 18 | 19 | 20/30 |
| OWNER ‡ | **4** of 6 (0) | **4** of 6 (0) | **3** of 6 (0) | **4** of 6 (0) | **3** of 6 (0) | **5** of 6 (0) | 18 | 19 | 0/36 |
| HUMAN ‡ | **4** of 6 (0) | **3** of 6 (0) | **3** of 6 (0) | **4** of 6 (0) | **3** of 6 (0) | **5** of 6 (0) | 17 | 18 | 0/36 |
| ROLE ‡ | **4** of 6 (0) | **4** of 6 (0) | **3** of 6 (0) | **4** of 5 (0) | **4** of 6 (0) | **5** of 6 (0) | 19 | 20 | 0/35 |
| COLLECTIVE ‡ | **3** of 6 (0) | **3** of 6 (0) | **3** of 4 (0) | **4** (0) | **4** of 6 (0) | **5** of 6 (0) | 17 | 18 | 0/32 |
| IDENTITY ‡ | **4** of 6 (0) | **3** of 7 (0) | **3** of 6 (0) | **3** of 7 (0) | **6** of 7 (0) | **5** of 6 (0) | 19 | 20 | 0/39 |
| ACTOR ‡ | **4** of 7 (0) | **5** of 7 (0) | **3** of 6 (0) | **4** of 6 (0) | **4** of 6 (0) | **5** of 6 (0) | 20 | 21 | 0/38 |
| TOKEN | **5** of 14 (12) | **5** of 14 (8) | **5** of 14 (14) | **4** of 14 (11) | **5** of 14 (14) | **5** of 6 (0) | 24 | 25 | 59/76 |

**Bold is `i`.** The `6` column is shown for completeness and is **excluded from `sum i`
and from `states`**, which count corroboration rungs only; level 6 carries no rungs.
Where `i` is smaller than the module count, both are shown: `8` of
`14` reads *eight is the depth of a profile holding fourteen modules*. A parenthesised
count is how many of that profile's obligations a mechanism establishes today; the two
specification axes carry no domain adapter by construction and show none. † marks the
three adapters on the open release branch. § marks `HYPER`, which is **catalogued but
not certifiable**: its statics and adaptation mechanisms resolve and execute, but it has
no behavioural adapter and no `CHECKS` entry, so `build_domain_certificate` rejects it
and no certificate over it can be built at all. ‡ marks the six ungrounded objects --
`OWNER` and the five identity objects -- which have no adapter anywhere and
therefore show none either.

**A mechanism name is a promise that something executes it.** The suite resolves every
mechanism name against the registered checks of that obligation's **own** object, because
a name that resolves under a different object resolves to the wrong check. Unlike the `‡`
rows, that is mechanically checkable, and for the life of this catalogue nothing checked
it.

Object-scoped resolution is also what exposed the misfiling. Fourteen `TRAIN` obligations
named `configuration`, `checkpoints`, `lineage`, `updates` or `training`; `CHECKS` had no
`TRAIN` key, so all fourteen were read as naming a check in no family and were cleared on
2026-09-21. The checks existed -- keyed under `HYPER`, because the adapter module was
still called `hyper.py`. Renaming it to `train.py` on 2026-09-22 restored all fourteen
verbatim, and each one's requirement is the description of the check it names. `TRAIN`
reports 25 of 35, and the rename brought the axis to 205 of 626. Two of those names are
also check names on other objects -- `configuration` is ENV's and `lineage` is DATA's --
which is why resolution stays object-scoped: the collision is real and it is the
resolver, not the name, that keeps it harmless.

**A passing test suite is not evidence about a ‡ row.** An ungrounded object has no
mechanism, so the only executable checks over it are that its catalogue is well-formed and
that the figures derived from it are correct — both of which hold no matter what its
obligations say. Its normative text is the whole artifact, and adversarial reading is its
only gate. Every authoring defect found in `OWNER` so far was found that way, with
the suite green each time: an over-broad predicate, a missing existence rule, an existence
rule that bound one axis of the two this object moves on, and a paragraph that
contradicted another paragraph thirty-five lines below it.

### Almost none of that product is reachable

The free product counts coordinate vectors. It is not the number of verification states,
because certification is a **topological ordering**: a coordinate is reachable only after
its prerequisites are, and this standard orders the grid twice over.

**Within an object, the five tiers are one chain, not five free coordinates.** A numbered
profile is cumulative — profile `N` requires its named coordinate and every earlier
coordinate on the same axis — and `certified_profile_depth` is defined as the largest
uninterrupted established prefix, or zero. One scalar per object, running straight through
all five tiers. An object's reachable positions are therefore `1 + sum(i)`, not `prod(i)`:
thirty for the object axis, not 6,000.

**Across objects, the composition lattice orders the nineteen ladders against each other.** A
composed object cannot outrun its operands. `HYPER-2` states this twice, and the two
statements do not bound it equally:

| Gate | The sentence it comes from | Accessible states |
|---|---|---|
| Operands non-`UNKNOWN` | one `UNKNOWN` operand makes the composition `UNKNOWN` | 343,872,709,682,315,103,844,560 |
| Operands complete | strength is non-increasing; the composition claims no more than its operands established | 206,159,635,176,678 |

The tighter one governs. A composition that may advance while an operand is still partial
can report a depth its operands never established, which is exactly what non-increasing
strength forbids — so the reachable count is **206,159,635,176,678**, around one in
3,316,089,413,708,250,874,581,876,764,106,243,674,088,950 of the free product.

```
free product over 95 cells    683,643,783,743,337,042,227,376,839,322,501,120,000,000,000,000,000,000,000
cumulative profiles, per object       15,106,779,566,764,095,369,600,000
+ composition, operands positive         343,872,709,682,315,103,844,560
+ composition, operands complete             206,159,635,176,678   <- reachable
```

`HYPER` is the only ladder the lattice leaves unconstrained, and for the one reason
that cannot be repaired: it is the composition operator rather than a composed object, so
there is no edge for it to sit on. Every other ladder is now on one. `OWNER` was the
second such ladder until `OWNER-1.1` was retyped to bind a `ACTOR` certificate; it
composed nothing then, and multiplied both gated figures by its own 19 reachable
positions. That is why those figures **fell** by a factor of about eleven when the edge
was added rather than rising: an unconstrained ladder inflates a count, it never tightens
one.

The identity family **is** inside the lattice, and its edges are declared rather than
assumed. `COLLECTIVE-1.1` and `COLLECTIVE-1.3` bind a graph and a role set;
`IDENTITY-1.1` and `IDENTITY-1.2` bind a bearer and a role class, and the bearer is a
**sum**, so that operand is a disjunction — a binding needs its role class and *either* a
human *or* a bot, never both. `ACTOR-1.2` is the family's second disjunction and its only
operand: an actor is bound by exactly one of a role class or a collective, so an actor
binding both is malformed rather than both. `HUMAN` and `ROLE` take no operands
at all:
`HUMAN-3.6` forbids composition yielding a human outright, and a role class rests on no
certified object.

Nothing was removed from the specification to get there. The ordering was always in
`LADDER.md`; the product simply never expressed it.

### Where the rungs are

386 rungs across the nineteen ladders:

| | Objects | Rungs | Rungs per object |
|---|---|---|---|
| Specification axes (VSTD, GRAPH) | 2 | 47 | 23.5 |
| Domain objects | 17 | 339 | 19.9 |

The two axes remain the deepest single objects, which is expected: `VSTD` is the
foundational claim surface every other object's evidence is read through, and a foundation
carrying fewer obligations than the things built on it would be the defect. What is *not*
expected, and was true until the domain objects were catalogued, is a domain object
carrying fewer rungs than it has tiers.

Both numbers still move. Cataloguing an object raises its obligation count and lowers its
`i`, because declared dependencies turn a default total order into a DAG; the domain
objects were catalogued with their dependencies declared from the start, so their `i` is
already a depth rather than a count. What remains provisional is mechanization: 236 of
626 domain obligations have a check behind them, and every one of the remaining 390 is
a coordinate a certificate can name but not yet clear. 216 of those 390 are the whole of the
six ungrounded objects, which have no adapter at all, and 23 are the unmechanized
obligations of HYPER, which has no behavioural adapter and so cannot be certified.

## What follows mechanically

Six consequences:

1. **Tier 5 is mechanized on every object, and it took a different kind of adapter.** All
   58 adaptation coordinates now have a check, because the mainstay representations each
   domain publishes in were named first: reverse-engineering 45 formats into meta-surfaces
   turned "adapt to the domain" into binding, mapping, round trip and residual. Reducing
   them also produced a finding — **mainstay formats encode facets and dynamics, and almost
   never statics or closure.** The residual a tier-5 certificate reports is therefore
   computed from the meta-surface, not declared, and it is consistently large.
2. **Tier 3 is 33 of 50, and what closed it was a third mechanism kind.** Statics are the
   facts an object does not choose, which is exactly the class that re-executing a
   declaration cannot establish. The six objects with no statics mechanism now have one:
   a witness probe, a recomputation over the retained inventory, or **invariance under
   perturbation of the subject's own choices** — re-decide the earlier statics with the
   object's declarations replaced, and refute if a verdict moves. The remaining 17 bare
   coordinates are on ENV, BENCH, MODEL and SIM, whose statics profiles were never empty
   and so were never in that sweep.
3. **`grounded_identifier` only half expresses the grid.** It used to guard
   `1 <= tier <= len(CHECKS[domain])`, so with ENV and BENCH at four checks each,
   `ENV-5.m` and `BENCH-5.m` raised `ValueError`; the tier bound is now the
   constant `TIERS = 5` and `m` is bounded by the adapter's module count instead. `GRAPH`
   and `VSTD` still raise `unknown domain`: the two specification axes must be present,
   with unreached tiers reported as `UNKNOWN` rather than being unconstructable. The
   published domain schemas additionally cap `m` at `[1-5]`, which the grid does not: `m`
   counts depth within one tier and is not bounded by the tier's position.
4. **The implemented `AGENT` adapter binds one operand, not the lattice's three.** It
   re-derives its observation ceiling from a bound `HARNESS` certificate and nothing else,
   so the substrate and the decider are unbound — even though `AGENT.4` compares the
   retained outcome inventory against an outcome contract (bench-shaped), `AGENT.2` checks
   a contiguous trajectory (graph-shaped), and declared actions carry tool side effects
   (env-shaped). The obligations are already in the ladder; the bindings are not.
5. **A module count is not a reachable `m`.** `m` is a depth, so the largest `m` a
   certificate can carry for a profile is that profile's `i`, not its module count. Where
   the two differ, the difference is unreachable coordinate space: the object axis at tier
   four holds fourteen modules at depth eight, so `4.9` through `4.14` name depths that no
   chain of prerequisites in that profile reaches. The code bounds `m` by the count and so
   admits them. Closing that is a validator change against the catalogued dependencies, not
   a change to any specification, and it can now be done uniformly: every object's
   dependencies are declared, and `tier_depth` computes the bound for any of the ninety.
6. **No validator enforces the composition gate.** The reachable count above assumes a
   composed object cannot advance past its operands, which is what non-increasing strength
   requires; nothing in the adapters checks it. `BOT.1` re-derives its bound agent,
   simulation and two environment certificates, but it does not compare their established
   depths against its own. A `BOT` certificate at depth 5 over a `SIM` operand at
   depth 1 is admitted today and should not be.

# Component grounding, namespace by namespace

Every numbered profile of every object carries component grounding coordinates, in the same
normative form: an identifier, a bound proposition, declared dependencies within the
profile, and an admission policy. Three disjoint namespaces hold them.

| Namespace | Coordinates | Obligations | Where |
|---|---|---|---|
| Object `VSTD-1..5` | `1.1`-`5.11` | 47 | [`GROUNDED_CERTIFICATION.md`](GROUNDED_CERTIFICATION.md) |
| Graph `GRAPH-1..5` | `GRAPH-1.1`-`GRAPH-5.6` | 28 | [`GRAPH_GROUNDING.md`](GRAPH_GROUNDING.md) |
| The seventeen domain objects | `<object>-1.1`-`<object>-6.6` | 626 | [`DOMAIN_OBLIGATIONS.md`](DOMAIN_OBLIGATIONS.md) |

The namespaces do not overlap and no catalogue admits another's identifiers, so `DATA-4.2`
never aliases `4.2` or `GRAPH-4.2`. Each computes its own digest, which is what makes them
separable: extending one provably cannot move another's.

What differs between them is not the form of the obligations but how many carry a
mechanism. The two specification axes are checked against retained evidence rather than by
a domain adapter. Of the seventeen domain objects, 236 of 626 obligations name a check in one
of the three families — behavioural in [`DOMAIN_GROUNDING.md`](DOMAIN_GROUNDING.md), statics and
adaptation in [`DOMAIN_OBLIGATIONS.md`](DOMAIN_OBLIGATIONS.md). The remaining 390 are
specified without a mechanism and are reported `UNKNOWN` — never absent, and never passed;
216 of them are the whole of the six objects with no adapter at all, 23 more are the
unmechanized obligations of `HYPER`, which has no behavioural adapter, and the
remaining 151 are the bare tiers of the ten certifiable objects.

`HYPER` no longer names two objects. The combination operator keeps the name; the
training-run certifier that used to share it is now `TRAIN`, with its own row above.
**It has its own adapter module, and always did.** `verifier.domains.train` shipped as
`hyper.py` for the whole life of this catalogue -- a name left over from before `HYPER`
was formalized as the operator -- which is why `TRAIN` was recorded as having no adapter
while `HYPER` was published as certifiable. `CHECKS["TRAIN"]` keys its five checks, so
`build_domain_certificate` accepts it. `HYPER` is the entry with no behavioural adapter:
the operator holds between certified objects and has no substrate of its own to adapt,
so its residue is permanent. The rename landed while 2.0.0 was unreleased, so no shipped
schema or digest carried the old spelling.
