# The Verifier Standard (VSTD) meta-tier grid — thirteen objects, five tiers

> **Acronyms:** benchmark specification graph (VSTD-BENCH); dataset integrity and lineage (VSTD-DATA);
> directed acyclic graph (DAG); generative simulation specification (VSTD-SIM); object composition specification (VSTD-HYPER);
> training run specification (VSTD-TRAIN);
> model reproducibility specification (VSTD-MODEL); Open Container Initiative (OCI);
> PROV data model (PROV-DM); Supply Chain Integrity, Transparency, and Trust (SCITT);
> Supply-chain Levels for Software Artifacts (SLSA); Verifier Standard (VSTD);
> verifiable execution environment (VSTD-ENV).

**Status:** project specification (normative for what tier N means on every object axis)
**Editor:** TimeLordRaps
**License:** Apache-2.0
**Date:** 2026-09-20

Identifier form, for every object: `VSTD-<object>-<tier>.<m>`, tier one of 1..5, `m` the
minimum clearance attained up that tier — the depth of complete modules the certificate
represents. Both one-indexed. See `WIRE_IDENTIFIERS.md` and `GROUNDED_CERTIFICATION.md`.

## The VSTD-NAMESPACE

The space those identifiers are drawn from is titled the **VSTD-NAMESPACE**, and its
members are **verifiable objects**. The title is what lets the space be referred to
without enumerating it: `VSTD-DATA` and `VSTD-OWNER` are verifiable objects in the
VSTD-NAMESPACE, and a name not admitted to it is not one.

`NAMESPACE` is deliberately **not** a member of the `<NAME>` set. Admitting it would make
`VSTD-NAMESPACE-1.1` a well-formed coordinate naming a tier-1 profile of the space that
contains it, and the space is not one of the objects it holds. The title takes no tier and
no `.m`; it is an envelope, not a row of the grid below.

The word is already carrying two other loads in this corpus, and neither is this one.
*Obligation* namespaces are the three disjoint coordinate sets catalogued at the foot of
this file; *package* namespaces are Python import paths. The titled sense is always
written `VSTD-NAMESPACE`, capitalised and prefixed, and never bare.

A **wire identifier** is not a coordinate in it. `VSTD-DATA-0.1` is the string a receipt
carries in `schema_version`, pinned by the code that parses it; `VSTD-DATA-1.1` is a
coordinate in this grid. They are different namespaces that happen to share a prefix, and
the identifier convention below governs only the second. Renaming a wire identifier to
match the convention breaks every reader that pins the string.

## The five tiers

Tiers occupy one shared metaphorical/analogical space of meta-features. Tier N asks the
same *kind* of question on every object axis.

| Tier | What it represents |
|---|---|
| 1 | A meta-structure abstraction of the **facets** of the surface. |
| 2 | The **dynamics** of the structures the surface can and does represent. |
| 3 | The **static unchanging natural phenomena** around the surface. |
| 4 | The **closure conditions** under which the specification can be completed. |
| 5 | **Domain adaptation surfaces** that tiers 1-4 allow to form naturally; these typically infer structure from domain mainstay representations. |

The tier-5 pattern in one sentence: a mainstay framework already represents the object
modularly for one domain (PyTorch for neural networks, Gymnasium for environments, OCI for
software closure), and tier 5 is that framework's structure inferred upward into a general
specification meta-framework, rather than a new notation invented downward.

## Ground truth: this is not new — it is `LADDER.md` made total

The object axis `VSTD-1..5` and the graph axis `VSTD-Graph-1..5` already instantiate these
five tiers exactly, and predate the generalization:

| Tier | `VSTD-N` closure coordinate | `VSTD-Graph-N` closure coordinate | Tier meaning |
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

## VSTD-GRAPH — collections of artifacts and their recorded relations

**VSTD-GRAPH-1** — nodes, edges, relation types, member inventory, the collection's own
identifier, what counts as inside.

**VSTD-GRAPH-2** — membership dynamics: admission, removal, lifecycle view, ordering of
edges, how a collection changes while retaining identity, conflict state as it forms.

**VSTD-GRAPH-3** — provenance that cannot be revised: immutable ancestry, trust roots,
actor and delegation identity, rotation and revocation history. The unchangeable past of
the graph. This is the surface the `v1.5.0` root-of-trust / rotation / delegation identity
module occupies.

**VSTD-GRAPH-4** — refutable transformation closure: exact re-execution of member,
ancestor and edge rating mechanisms from content-addressed evidence, and the conditions
under which a candidate graph profile becomes evidence-bound.

**VSTD-GRAPH-5** — the network that forms once 1-4 hold: cross-registry corroboration,
PROV-DM, in-toto, SLSA, Certificate Transparency inferred upward into one relation
vocabulary.

## VSTD-DATA — retained data

**VSTD-DATA-1** — records and shards, field types and required columns, the digest tree,
byte and count commitments, record identity, the retention boundary (what is kept versus
what was seen).

**VSTD-DATA-2** — transformation dynamics: every declared transformation re-executed to its
exact output, ordering and idempotence of the pipeline, how a record moves from raw to
retained, drift as the corpus is rebuilt.

**VSTD-DATA-3** — what was true before anyone processed it: sampling frame and population,
the measurement instrument and its units, censoring and truncation, class balance,
cardinality and entropy, licence and legal facts of origin. Unchanging because they are
facts about the world the data came from, not about the pipeline.

**VSTD-DATA-4** — closure over the complete inventory: split membership and record-identity
separation, exact and lexical train/evaluation overlap recomputed over everything retained,
the condition under which the dataset specification admits no unaccounted record.

**VSTD-DATA-5** — Arrow/Parquet, HuggingFace `datasets`, Croissant, DCAT inferred upward.
This is the object `VSTD-MODEL-3` cites when it binds training data.

## VSTD-ENV — execution environments

**VSTD-ENV-1** — the software inventory materialized and rehashed, the required
configuration surface, executable coordinates, the declared boundary of the environment.

**VSTD-ENV-2** — dynamics: scheduling and concurrency, every declared nondeterminism source
(clock, entropy, thread interleaving, allocator), two retained executions compared input
for input and result for result.

**VSTD-ENV-3** — statics: instruction set architecture, floating-point semantics, memory and
clock ceilings, thermal and power limits, the physical resource envelope the machine has
whether or not anyone declares it.

**VSTD-ENV-4** — hermeticity: the closure condition under which nothing in the environment
is unpinned, no implicit host state leaks in, and the specification is complete enough that
a second party can stand the environment up from the record alone.

**VSTD-ENV-5** — OCI images, Nix derivations, conda/uv lockfiles, SLSA build provenance
inferred upward into one environment-closure meta-framework.

## VSTD-BENCH — benchmarks

**VSTD-BENCH-1** — **[anchor]** *a bench is represented by a set of problems, some form of
what a solution is deducible from, a sampling procedure, baseline mechanics, feature
representational spaces or categories, a domain or set of domains.*

**VSTD-BENCH-2** — dynamics: adaptive and sequential evaluation, repeated attempts and
best-of-N, contamination accumulating over time, difficulty response curves, the feedback
loop a public leaderboard induces on the systems it measures.

**VSTD-BENCH-3** — statics: chance floor and oracle ceiling, irreducible label noise,
intrinsic hardness classes of the problem family, the natural task distribution of the
domain. These do not move when the harness changes.

**VSTD-BENCH-4** — closure: weighted score recomputed over every problem with no missing,
duplicate or substituted run, retained timing and memory checked against the problem
ceilings, the condition under which the bench measures the whole declared surface.

**VSTD-BENCH-5** — `lm-evaluation-harness`, HELM, BIG-bench, SWE-bench task specifications
inferred upward into one bench meta-framework.

## VSTD-TRAIN — training runs

**VSTD-TRAIN-1** — the optimizer, schedule, accumulation and precision contract; the
checkpoint inventory with every retained weight and optimizer state rehashed; the step
index; the batch binding; the declared numerical semantics.

**VSTD-TRAIN-2** — dynamics: every supported optimizer update recomputed from retained
gradients and state, losses and analytic gradients replayed from the bound batches, the
run advancing step by step.

**VSTD-TRAIN-3** — statics: what the run does not get to choose. Floating-point semantics
and accumulation order, the gradient the bound objective actually has, the geometry of
the loss surface the architecture and data together fix.

**VSTD-TRAIN-4** — closure: contiguous steps with exact parent, batch, hyperparameter and
result bindings, no step missing, substituted or reordered. The condition under which the
trace accounts for the whole run rather than a selected prefix of it.

**VSTD-TRAIN-5** — the mainstay training loops and their checkpoint formats inferred
upward into one training-trace meta-framework. This is the object `VSTD-MODEL-3` cites for
a model's provenance, and it consumes `VSTD-DATA-5` for its batches.

## VSTD-HYPER — composition of certified objects into certified objects

Every other row certifies one kind of thing. This row certifies the **combination operator**:
what has to hold for a set of bound certificates to compose into a new object, and why the
composed object can never claim more than its operands established.

The lattice the rest of the grid already forms. Write the shared substrate as

```
S = { VSTD, VSTD-GRAPH, VSTD-DATA, VSTD-ENV, VSTD-BENCH }
```

`VSTD-TRAIN` is an operand too — the run that produced a model — which is why the model
row names it rather than folding it into `S`: a model can be certified without one.

| Composed object | Operands |
|---|---|
| `VSTD-MODEL` | `S` + `VSTD-TRAIN` |
| `VSTD-SIM` | `S` + `VSTD-MODEL` |
| `VSTD-AGENT` | `S` + a decider + `VSTD-HARNESS` |
| `VSTD-BOT` | `VSTD-AGENT` + `VSTD-SIM` |

Each row adds to the row above it, and the last one collapses: `S` + decider + `HARNESS`
beside `S` + `MODEL` is exactly `AGENT` + `SIM`. The substrate appears once per arm, which is
why `BOT.1` re-derives the bound agent, simulation and **two** environment certificates, and
why the tier-4 closure of `VSTD-BOT` is the declared separation of those two.

The decider is a slot, not an object. A model can fill it; so can a human, a script or a rule
engine. `VSTD-MODEL` + `VSTD-HARNESS` on its own is a model deployment observed through an
instrument: it is short the substrate, and it pins the slot to one of the things that can fill
it. Nothing in the certified surface establishes *what* decided — `VSTD-AGENT-2` requires only
that each decision is witnessed by a record inside the ceiling. What composes is the evidence
surface a decider is observed on, never the decider.

**VSTD-HYPER-1** — the facets of a composition: the operand set and its arity, which
certificate fills which slot, the substrate every operand carries, the identity of the composed
object, and what distinguishes a slot from an operand.

**VSTD-HYPER-2** — dynamics: how a claim propagates through a composition. Strength is
non-increasing; one `UNKNOWN` operand makes the composition `UNKNOWN`; recomposition from
retained bytes lands on the same object; what associativity the operator does and does not
have.

**VSTD-HYPER-3** — statics: what no composition can manufacture. The weakest operand bound is
the composed ceiling whatever the composed object declares, the substrate recurs at every level
rather than being consumed, and the decider stays outside the certified surface at every level.

**VSTD-HYPER-4** — **[anchor]** *boundary saturation, open ended collapsable meta-language,
fractal rerepresentations.*

Read against the lattice: saturation is every slot of a composition filled by a bound operand;
the collapsable meta-language is `AGENT` + `SIM` written as `BOT` and re-expanded without loss;
the fractal re-representation is `S` recurring identically at every level.

**VSTD-HYPER-5** — the composition formalisms already in use — in-toto layouts, build-graph
derivations, assembly relations in software bills of materials, typed interface composition —
inferred upward into one composition meta-framework. Combining the base fields of a science
into composite fields is this same operator applied to sciences rather than to certificates;
those field members are named in their own repositories, not here.

## VSTD-MODEL — trained models

**VSTD-MODEL-1** — tensor shapes and architecture compatibility, module decomposition, the
declared input and output surface, the named dependency artifacts.

**VSTD-MODEL-2** — dynamics: the bound dense network executed and every retained output
compared, batching and precision behaviour, sampling and decoding, what the model does as
opposed to what it is.

**VSTD-MODEL-3** — **[anchor]** *weights, hardware requirements, quantization specifications
and configurations, training-data (VSTD-DATA-5 specified object), ...*

**VSTD-MODEL-4** — closure: metrics recomputed over the complete named evaluation set,
declared finite counterexample probes executed against their bound output conditions, the
condition under which the model's claimed behaviour is refutable rather than merely
unrefuted.

**VSTD-MODEL-5** — PyTorch's lower-level modular representation of neural networks, with
ONNX, safetensors and GGUF, inferred upward into a general specification meta-framework.
This is the worked example the tier-5 definition is written from.

## VSTD-SIM — simulations

**VSTD-SIM-1** — state space, transition expressions, entropy stream, observation and
action channels, shard decomposition, the projection relating macro to micro.

**VSTD-SIM-2** — **[anchor]** *responsiveness, internal state changes, computational spaces,
and perspective shifts.*

**VSTD-SIM-3** — statics: invariant and conservation expressions holding on every retained
state, the closed finite state set where one exists, the physical law the simulation is a
model *of* and does not get to choose.

**VSTD-SIM-4** — closure: complete aligned shard coverage, bound cross-shard relations,
signatures where required, the condition under which the retained trajectory accounts for
the whole simulated surface with no unattributed transition.

**VSTD-SIM-5** — the interaction surface `VSTD-BOT-5` sits over. Gymnasium, MuJoCo, FMI,
Modelica and SPICE inferred upward; `open-battery-sim` and `open-motor-sim` are the first
two domain adaptations published against it.

## VSTD-HARNESS — the instrumented surface a session is observed through

**VSTD-HARNESS-1** — every declared channel partitioned into instrumented observation and
named uninstrumented gap; the record types (user, agent, tool), the registry of tool
declarations, the declared side-effect channels, the shape of the transcript commitment.

**VSTD-HARNESS-2** — dynamics: contiguity and ordering of retained records, pairing of each
invocation with its response, how a session advances record by record, interleaving of side
effects with messages, what a retry or a resumption does to the sequence.

**VSTD-HARNESS-3** — statics: what the instrumentation cannot see whatever anyone declares —
the named uninstrumented gap itself, timestamp resolution, channel capacity, the fixed
boundary the harness sits at. The gap is a property of where the instrument was placed, not
of the session it recorded.

**VSTD-HARNESS-4** — closure: the ordered transcript commitment recomputed, refusing an
omitted or substituted record. The condition under which the session is wholly accounted
for and no record can be added, dropped or reordered without detection.

**VSTD-HARNESS-5** — OpenTelemetry trace and span semantics, Model Context Protocol, and the
tool-call transcript formats the mainstay model providers already emit, inferred upward into
one instrumentation meta-framework.

## VSTD-AGENT — a deciding actor observed through a bound harness

**VSTD-AGENT-1** — the observation ceiling re-derived from the bound harness certificate and
its required channels; decisions, declared actions, the outcome contract, the final claims.

**VSTD-AGENT-2** — dynamics: contiguous decisions each witnessed by a record inside the
ceiling, every declared action bound to a witnessed tool invocation, how a trajectory
advances from one decision to the next.

**VSTD-AGENT-3** — statics: the observation ceiling as an unchangeable epistemic bound —
what the agent could not have known, regardless of what it asserts it knew. The ceiling is
fixed by the harness, and no amount of agent declaration raises it.

**VSTD-AGENT-4** — closure: the complete retained outcome inventory compared with the bound
outcome contract, and every final claim resting only on records inside the ceiling. The
condition under which the agent's account of itself admits no unsupported claim.

**VSTD-AGENT-5** — the mainstay agent loops — tool-calling loops, planner/executor splits,
graph-structured agent runtimes — inferred upward into one decision-surface meta-framework.

## VSTD-BOT — an agent bound inside a simulation

**VSTD-BOT-1** — the bound agent, simulation and environment certificates re-derived from
their retained bytes; the facets of the coupling itself, not of either side.

**VSTD-BOT-2** — dynamics: every simulation transition bound to one retained record, every
retained observation shown to be the simulation's own projection of that state, every
replayed action shown to be one the agent actually invoked.

**VSTD-BOT-3** — statics: the observation ceiling that exists whatever the agent claims, the
latency and ordering the coupling physically imposes, the information the simulation cannot
expose regardless of policy.

**VSTD-BOT-4** — closure: the declared separation of agent and simulator execution
environments. A `fused` declaration is honest and is `UNKNOWN`, never `FAIL` — containment
simply is not established, and that costs exactly one rung.

**VSTD-BOT-5** — **[anchor]** *Interaction graph over VSTD-SIM-5 specified interaction
surface, disclosable and indisclosed self-awareness including generally and of inclusion
inside a simulation and to what degree of awareness of the simulation specification
surfaces it is aware of, this is literally the self-awareness surface of superintelligence
if we can keep it in sims.*

---

## VSTD-OWNER — a holding between a bound actor and a bound object

The third **relational** object, and the only ungrounded one. `VSTD-GRAPH` relates
artifacts to one another, `VSTD-HYPER` relates operands to the object composed from them,
and `VSTD-OWNER` relates an actor to an object it holds. None of the three certifies a
substrate of its own, which is why none of them is a domain in the adapter sense.

The holder is bound by the actor-binding token `VSTD-ACTOR-BINDING-1`, so a holding names
a bound actor rather than a string. An **agent is not an actor**: an agent occupies a
decider slot inside `VSTD-AGENT`, while an actor is the party a binding is issued to, and
`VSTD-OWNER` types its holder as the latter.

**VSTD-OWNER-1** — facets: the holder, the held object, the enumerated limbs of the
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

**VSTD-OWNER-2** — dynamics: transfer, delegation and revocation as ordered events,
each conveying only what the conveyor held at that position in the order, replayed from
the origin to reproduce the holding as it now stands. **Lapse is not among them**: a term
ending is the clock's doing rather than an act, so it declares nothing and occupies no
position — which is why `OWNER-4.5` must quantify over the term as well as the order.

**VSTD-OWNER-3** — statics: a holding never moves a verdict. `OWNER-3.1` is the
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

**VSTD-OWNER-4** — closure: chain of custody from a declared origin, gapless,
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

**VSTD-OWNER-5** — domain adaptation: licence expressions, registry maintainer records,
corporate and beneficial-ownership registers, declared code ownership and custody chains.
No adapter binds any of them today, so each is reported unestablished rather than unheld
— which is the distinction the whole row exists to keep.

---

# The grid as catalogued coordinates

Thirteen objects, sixty-five numbered profiles, every one of them carrying obligations of
its own. The object axis and the Graph axis are the two `LADDER.md` already carried. The
other eleven
were catalogued against these tiers, so the grid below is a coordinate map, not a mapping
of adapter checks onto tiers — an adapter check is now a *mechanism* attached to an
obligation rather than a rung in its own right:

| Object | 1 facets | 2 dynamics | 3 statics | 4 closure | 5 adaptation |
|---|---|---|---|---|---|
| VSTD | `1.1`-`1.7` | `2.1`-`2.7` | `3.1`-`3.8` | `4.1`-`4.14` | `5.1`-`5.11` |
| GRAPH | `Graph-1.1`-`1.6` | `Graph-2.1`-`2.5` | `Graph-3.1`-`3.5` | `Graph-4.1`-`4.6` | `Graph-5.1`-`5.6` |
| DATA | `DATA-1.1`-`1.6` | `DATA-2.1`-`2.6` | `DATA-3.1`-`3.6` | `DATA-4.1`-`4.6` | `DATA-5.1`-`5.6` |
| ENV | `ENV-1.1`-`1.6` | `ENV-2.1`-`2.6` | `ENV-3.1`-`3.5` | `ENV-4.1`-`4.5` | `ENV-5.1`-`5.6` |
| BENCH | `BENCH-1.1`-`1.7` | `BENCH-2.1`-`2.6` | `BENCH-3.1`-`3.7` | `BENCH-4.1`-`4.5` | `BENCH-5.1`-`5.6` |
| TRAIN | `TRAIN-1.1`-`1.6` | `TRAIN-2.1`-`2.6` | `TRAIN-3.1`-`3.5` | `TRAIN-4.1`-`4.6` | `TRAIN-5.1`-`5.6` |
| HYPER | `HYPER-1.1`-`1.6` | `HYPER-2.1`-`2.6` | `HYPER-3.1`-`3.5` | `HYPER-4.1`-`4.5` | `HYPER-5.1`-`5.5` |
| MODEL | `MODEL-1.1`-`1.5` | `MODEL-2.1`-`2.5` | `MODEL-3.1`-`3.6` | `MODEL-4.1`-`4.5` | `MODEL-5.1`-`5.6` |
| SIM | `SIM-1.1`-`1.7` | `SIM-2.1`-`2.6` | `SIM-3.1`-`3.5` | `SIM-4.1`-`4.5` | `SIM-5.1`-`5.6` |
| HARNESS † | `HARNESS-1.1`-`1.5` | `HARNESS-2.1`-`2.5` | `HARNESS-3.1`-`3.4` | `HARNESS-4.1`-`4.5` | `HARNESS-5.1`-`5.6` |
| AGENT † | `AGENT-1.1`-`1.7` | `AGENT-2.1`-`2.5` | `AGENT-3.1`-`3.3` | `AGENT-4.1`-`4.4` | `AGENT-5.1`-`5.5` |
| BOT † | `BOT-1.1`-`1.5` | `BOT-2.1`-`2.5` | `BOT-3.1`-`3.4` | `BOT-4.1`-`4.4` | `BOT-5.1`-`5.6` |
| OWNER ‡ | `OWNER-1.1`-`1.6` | `OWNER-2.1`-`2.6` | `OWNER-3.1`-`3.6` | `OWNER-4.1`-`4.6` | `OWNER-5.1`-`5.6` |

Every cell is a coordinate range into a catalogued obligation set: the object axis in
[`GROUNDED_CERTIFICATION.md`](GROUNDED_CERTIFICATION.md), the Graph axis in
[`GRAPH_GROUNDING.md`](GRAPH_GROUNDING.md), the eleven domain objects in
[`DOMAIN_OBLIGATIONS.md`](DOMAIN_OBLIGATIONS.md). 379 obligations across the three
namespaces, which are disjoint: `DATA-4.2` never aliases `4.2` or `Graph-4.2`, and each
catalogue carries its own digest. † marks the three objects whose adapters live on the open
release branch rather than in this tree; ‡ marks the one object with no adapter anywhere.

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
| `VSTD-Graph-` | [1.1–1.3](GRAPH_GROUNDING.md ".1 Collection coordinate; .2 Recorded structure, Status admissibility; .3 Coverage recomputation, Conflict retention, Blast radius closure") | [2.1–2.4](GRAPH_GROUNDING.md ".1 Member rating re-execution; .2 Ancestor reachability closure, Edge rating re-execution; .3 Scope binding; .4 Bounded admission") | [3.1–3.3](GRAPH_GROUNDING.md ".1 Substrate rating re-execution; .2 Weakest reachable cap, Out-of-closure contribution, Accountable actor binding; .3 Accountable closure result") | [4.1–4.4](GRAPH_GROUNDING.md ".1 Member refutability entry; .2 Edge refutability closure, Candidate ceiling explanation; .3 Unevidenced edge rejection, Challenge localization; .4 Offline replay") | [5.1–5.4](GRAPH_GROUNDING.md ".1 Exact network entry; .2 Witness member rating, Witness transformation rating; .3 Network scope binding, Conflict inadmissibility; .4 Declared rating rejection") | **18** |
| `VSTD-DATA-` | [1.1–1.4](DOMAIN_OBLIGATIONS.md#vstd-data-1-facets ".1 Retention boundary; .2 Shard and record inventory, Field contract; .3 Record identity, Digest tree commitment; .4 Schema conformance") | [2.1–2.4](DOMAIN_OBLIGATIONS.md#vstd-data-2-dynamics ".1 Transformation declaration; .2 Exact re-execution; .3 Pipeline ordering, Raw-to-retained path; .4 Idempotence, Rebuild drift") | [3.1–3.3](DOMAIN_OBLIGATIONS.md#vstd-data-3-statics ".1 Sampling frame, Measurement instrument, Origin rights; .2 Censoring and truncation, Distribution statics; .3 Pipeline independence") | [4.1–4.5](DOMAIN_OBLIGATIONS.md#vstd-data-4-closure ".1 Split declaration; .2 Complete membership; .3 Identity separation, Exact overlap; .4 Lexical overlap; .5 No unaccounted record") | [5.1–5.4](DOMAIN_OBLIGATIONS.md#vstd-data-5-domain-adaptation ".1 Mainstay binding; .2 Columnar shard mapping, Schema mapping, Dataset card mapping; .3 Round trip; .4 Inference upward") | **20** |
| `VSTD-ENV-` | [1.1–1.4](DOMAIN_OBLIGATIONS.md#vstd-env-1-facets ".1 Environment boundary; .2 Software inventory, Configuration surface; .3 Executable coordinates, Observed configuration; .4 Unpinned residue") | [2.1–2.4](DOMAIN_OBLIGATIONS.md#vstd-env-2-dynamics ".1 Nondeterminism declaration, Execution pair; .2 Scheduling surface, Input agreement; .3 Result agreement; .4 Divergence attribution") | [3.1–3.3](DOMAIN_OBLIGATIONS.md#vstd-env-3-statics ".1 Instruction set, Resource ceilings; .2 Floating-point semantics, Physical envelope; .3 Envelope independence") | [4.1–4.4](DOMAIN_OBLIGATIONS.md#vstd-env-4-closure ".1 Pin completeness; .2 Host isolation, Network closure; .3 Standup sufficiency; .4 Standup evidence") | [5.1–5.5](DOMAIN_OBLIGATIONS.md#vstd-env-5-domain-adaptation ".1 Mainstay binding; .2 Image closure mapping, Derivation mapping; .3 Build provenance mapping; .4 Round trip; .5 Inference upward") | **20** |
| `VSTD-BENCH-` | [1.1–1.5](DOMAIN_OBLIGATIONS.md#vstd-bench-1-facets ".1 Domain declaration; .2 Problem set, Feature representation; .3 Solution deducibility, Sampling procedure; .4 Oracle binding; .5 Baseline mechanics") | [2.1–2.4](DOMAIN_OBLIGATIONS.md#vstd-bench-2-dynamics ".1 Attempt policy, Contamination accumulation; .2 Attempt inventory; .3 Sequential adaptivity, Response curve; .4 Measurement feedback") | [3.1–3.4](DOMAIN_OBLIGATIONS.md#vstd-bench-3-statics ".1 Chance floor, Oracle ceiling, Budget ceilings; .2 Label noise, Hardness classes; .3 Natural distribution; .4 Harness independence") | [4.1–4.4](DOMAIN_OBLIGATIONS.md#vstd-bench-4-closure ".1 Run inventory; .2 No missing run, No duplicate or substituted run; .3 Weighted score; .4 Surface completeness") | [5.1–5.5](DOMAIN_OBLIGATIONS.md#vstd-bench-5-domain-adaptation ".1 Mainstay binding; .2 Task specification mapping, Scoring contract mapping; .3 Budget mapping; .4 Round trip; .5 Inference upward") | **22** |
| `VSTD-TRAIN-` | [1.1–1.4](DOMAIN_OBLIGATIONS.md#vstd-train-1-facets ".1 Optimizer contract, Checkpoint inventory; .2 Numerical semantics, Step index; .3 Batch binding; .4 Retention boundary") | [2.1–2.5](DOMAIN_OBLIGATIONS.md#vstd-train-2-dynamics ".1 Loss replay; .2 Gradient replay; .3 Optimizer update; .4 State advance, Unsupported update reporting; .5 Step-by-step advance") | [3.1–3.3](DOMAIN_OBLIGATIONS.md#vstd-train-3-statics ".1 Arithmetic semantics, True gradient; .2 Accumulation order, Objective geometry; .3 Choice independence") | [4.1–4.6](DOMAIN_OBLIGATIONS.md#vstd-train-4-closure ".1 Contiguity; .2 Parent binding; .3 Batch and hyperparameter binding; .4 Result binding; .5 No reordering; .6 Whole-run accounting") | [5.1–5.5](DOMAIN_OBLIGATIONS.md#vstd-train-5-domain-adaptation ".1 Mainstay binding; .2 Training-loop mapping, Checkpoint-format mapping; .3 Batch source mapping; .4 Round trip; .5 Inference upward") | **23** |
| `VSTD-HYPER-` | [1.1–1.5](DOMAIN_OBLIGATIONS.md#vstd-hyper-1-facets ".1 Operand set; .2 Slot schema, Substrate presence; .3 Slot versus operand; .4 Composed identity; .5 Operand admissibility") | [2.1–2.4](DOMAIN_OBLIGATIONS.md#vstd-hyper-2-dynamics ".1 Strength ordering, Recomposition; .2 Non-increase, Associativity; .3 UNKNOWN absorption; .4 Depth propagation") | [3.1–3.3](DOMAIN_OBLIGATIONS.md#vstd-hyper-3-statics ".1 Composed ceiling, Substrate recurrence, Decider exteriority; .2 Manufacture impossibility; .3 Level independence") | [4.1–4.5](DOMAIN_OBLIGATIONS.md#vstd-hyper-4-closure ".1 Saturation; .2 Collapse; .3 Expansion fidelity; .4 Fractal re-representation; .5 Boundary completeness") | [5.1–5.5](DOMAIN_OBLIGATIONS.md#vstd-hyper-5-domain-adaptation ".1 Mainstay binding; .2 Layout mapping; .3 Authorization mapping; .4 Round trip; .5 Inference upward") | **22** |
| `VSTD-MODEL-` | [1.1–1.3](DOMAIN_OBLIGATIONS.md#vstd-model-1-facets ".1 Tensor inventory, Dependency artifacts; .2 Architecture compatibility; .3 Module decomposition, Input and output surface") | [2.1–2.4](DOMAIN_OBLIGATIONS.md#vstd-model-2-dynamics ".1 Forward execution; .2 Output agreement; .3 Batching behaviour, Precision behaviour; .4 Sampling and decoding") | [3.1–3.3](DOMAIN_OBLIGATIONS.md#vstd-model-3-statics ".1 Weight bytes, Training-data citation; .2 Hardware requirements, Quantization specification, Provenance citation; .3 Artifact immutability") | [4.1–4.3](DOMAIN_OBLIGATIONS.md#vstd-model-4-closure ".1 Evaluation set, Probe inventory; .2 Metric recomputation, Probe execution; .3 Refutability") | [5.1–5.5](DOMAIN_OBLIGATIONS.md#vstd-model-5-domain-adaptation ".1 Mainstay binding; .2 Module-graph mapping, Serialized-weights mapping; .3 Operator coverage; .4 Round trip; .5 Inference upward") | **18** |
| `VSTD-SIM-` | [1.1–1.3](DOMAIN_OBLIGATIONS.md#vstd-sim-1-facets ".1 State space; .2 Transition expressions, Observation channels, Shard decomposition; .3 Entropy stream, Action channels, Macro and micro projection") | [2.1–2.4](DOMAIN_OBLIGATIONS.md#vstd-sim-2-dynamics ".1 Trajectory replay; .2 Responsiveness, Internal state change, Computational space; .3 Perspective shift; .4 Perspective agreement") | [3.1–3.4](DOMAIN_OBLIGATIONS.md#vstd-sim-3-statics ".1 Invariant expressions, Modelled law; .2 Per-state holding; .3 Closed state set; .4 Law independence") | [4.1–4.4](DOMAIN_OBLIGATIONS.md#vstd-sim-4-closure ".1 Shard coverage; .2 Cross-shard relations, No unattributed transition; .3 Signatures; .4 Whole-surface accounting") | [5.1–5.5](DOMAIN_OBLIGATIONS.md#vstd-sim-5-domain-adaptation ".1 Mainstay binding; .2 Interaction-surface mapping, Physical-backend mapping; .3 Stepping contract; .4 Round trip; .5 Inference upward") | **20** |
| `VSTD-HARNESS-` † | [1.1–1.4](DOMAIN_OBLIGATIONS.md#vstd-harness-1-facets ".1 Channel partition; .2 Record types; .3 Tool registry, Transcript commitment shape; .4 Side-effect channels") | [2.1–2.4](DOMAIN_OBLIGATIONS.md#vstd-harness-2-dynamics ".1 Record contiguity; .2 Invocation pairing, Session advance; .3 Side-effect interleaving; .4 Retry and resumption") | [3.1–3.3](DOMAIN_OBLIGATIONS.md#vstd-harness-3-statics ".1 Gap boundary, Timestamp resolution; .2 Channel capacity; .3 Instrument fixity") | [4.1–4.4](DOMAIN_OBLIGATIONS.md#vstd-harness-4-closure ".1 Commitment recomputation; .2 Omission detection, Substitution detection; .3 Reordering detection; .4 Whole-session accounting") | [5.1–5.5](DOMAIN_OBLIGATIONS.md#vstd-harness-5-domain-adaptation ".1 Mainstay binding; .2 Trace-span mapping, Tool-protocol mapping; .3 Gap representation; .4 Round trip; .5 Inference upward") | **20** |
| `VSTD-AGENT-` † | [1.1–1.6](DOMAIN_OBLIGATIONS.md#vstd-agent-1-facets ".1 Harness binding; .2 Required channels; .3 Observation ceiling; .4 Decision inventory, Outcome contract; .5 Declared actions; .6 Final claims") | [2.1–2.4](DOMAIN_OBLIGATIONS.md#vstd-agent-2-dynamics ".1 Trajectory contiguity; .2 Decision witnessing; .3 Action witnessing; .4 Unwitnessed action reporting, Trajectory advance") | [3.1–3.3](DOMAIN_OBLIGATIONS.md#vstd-agent-3-statics ".1 Ceiling fixity; .2 Unknowability; .3 Declaration impotence") | [4.1–4.4](DOMAIN_OBLIGATIONS.md#vstd-agent-4-closure ".1 Outcome inventory; .2 Contract comparison; .3 Claim support; .4 No unsupported claim") | [5.1–5.5](DOMAIN_OBLIGATIONS.md#vstd-agent-5-domain-adaptation ".1 Mainstay binding; .2 Decision-loop mapping; .3 Slot mapping; .4 Round trip; .5 Inference upward") | **22** |
| `VSTD-OWNER-` ‡ | [1.1–1.4](DOMAIN_OBLIGATIONS.md#vstd-owner-1-facets ".1 Holder binding, Held-object binding; .2 Instrument, Bearer capability; .3 Limb inventory; .4 Term") | [2.1–2.4](DOMAIN_OBLIGATIONS.md#vstd-owner-2-dynamics ".1 Event declaration; .2 Transfer conveyance, Delegation bound, Lapse; .3 Revocation effect; .4 Ordered replay") | [3.1–3.3](DOMAIN_OBLIGATIONS.md#vstd-owner-3-statics ".1 Verdict independence, Asymmetry; .2 Evidence immutability, Ancestry immutability, Non-transitivity of authority; .3 Person-limb typing") | [4.1–4.4](DOMAIN_OBLIGATIONS.md#vstd-owner-4-closure ".1 Chain origin; .2 Gapless chain, Admissibility at issue time; .3 Fork detection, Accountability floor; .4 Closure result") | [5.1–5.3](DOMAIN_OBLIGATIONS.md#vstd-owner-5-domain-adaptation ".1 Licence holding, Registry maintainer record, Register entry, Custody chain; .2 Declared code ownership; .3 Adaptation accounting") | **18** |
| `VSTD-BOT-` † | [1.1–1.3](DOMAIN_OBLIGATIONS.md#vstd-bot-1-facets ".1 Agent binding, Simulation binding; .2 Environment bindings; .3 Coupling surface, Operand depths") | [2.1–2.4](DOMAIN_OBLIGATIONS.md#vstd-bot-2-dynamics ".1 Transition binding; .2 Observation projection, Action authenticity; .3 One-to-one coupling; .4 Coupling advance") | [3.1–3.3](DOMAIN_OBLIGATIONS.md#vstd-bot-3-statics ".1 Inherited ceiling, Coupling latency; .2 Disclosure limit; .3 Policy impotence") | [4.1–4.3](DOMAIN_OBLIGATIONS.md#vstd-bot-4-closure ".1 Separation declaration; .2 Separation evidence, Fused honesty; .3 Containment accounting") | [5.1–5.5](DOMAIN_OBLIGATIONS.md#vstd-bot-5-domain-adaptation ".1 Interaction-graph binding; .2 Disclosure inventory; .3 Indisclosure inventory, Inclusion awareness; .4 Specification awareness; .5 Awareness accounting") | **18** |

270 rungs over sixty-five profiles. The remaining 109 of 379 catalogued
obligations sit above their profile's depth: nameable, and unreachable as an `m`,
because independent obligations are cleared at one depth rather than at several. A
certificate that names one of them is malformed.

An obligation is either **mechanized** — an adapter check establishes it today — or
specified without a mechanism, in which case it is reported `UNKNOWN`, never absent and
never passed. Only ten of the eleven domain objects have adapters at all; the parenthesised
count in each cell of the depth grid below is how many of that profile's obligations
one of the three families establishes today.

Of the 304 domain obligations, 177 are mechanized, across three disjoint families:
92 behavioural adapter checks, 27 tier-3 statics checks and
58 tier-5 adaptation checks. Tier 5 is now mechanized on every object and tier 3 on
every object; what remains bare is spread across tiers 1, 2 and 4. The two specification
axes are unmechanized by construction — they are checked against retained evidence rather
than by any domain adapter. [`DOMAIN_OBLIGATIONS.md`](DOMAIN_OBLIGATIONS.md) sets out the
three families and why a static needs a different kind of evidence from a dynamic.

## The cardinality of the grid

Sixty-five cells is the shape of the grid, not its size. Each cell is a numbered profile with
its own internal topology, and a grounded certificate does not name the cell — it names a
position inside it: `VSTD-<object>-<tier>.<m>`, where `m` is the depth of complete modules
represented. Write `i` for the depth of one cell's module topology and the grid spans

```
prod(i, 13 x 5) = 3,067,007,993,957,980,097,740,800,000,000,000,000,000
```

`i` is a **depth, not a count**: the longest chain of modules each of which is a
prerequisite of the next. The two coincide only where a profile is a chain. Wherever it is
a directed acyclic graph — where two modules both depend on a third but not on each other
— the depth is strictly smaller, because independent modules are cleared at one depth
rather than at two. Every one of the sixty-five profiles is a DAG, so on every object the
depth is strictly below the count somewhere.

| Object | 1 | 2 | 3 | 4 | 5 | sum i | states | mechanized |
|---|---|---|---|---|---|---|---|---|
| VSTD | **5** of 7 | **5** of 7 | **6** of 8 | **8** of 14 | **5** of 11 | 29 | 30 | n/a |
| GRAPH | **3** of 6 | **4** of 5 | **3** of 5 | **4** of 6 | **4** of 6 | 18 | 19 | n/a |
| DATA | **4** of 6 (5) | **4** of 6 (3) | **3** of 6 (6) | **5** of 6 (5) | **4** of 6 (6) | 20 | 21 | 25/30 |
| ENV | **4** of 6 (4) | **4** of 6 (3) | **3** of 5 (1) | **4** of 5 (0) | **5** of 6 (6) | 20 | 21 | 14/28 |
| BENCH | **5** of 7 (3) | **4** of 6 (0) | **4** of 7 (1) | **4** of 5 (4) | **5** of 6 (6) | 22 | 23 | 14/31 |
| TRAIN | **4** of 6 (5) | **5** of 6 (5) | **3** of 5 (5) | **6** (4) | **5** of 6 (6) | 23 | 24 | 25/29 |
| HYPER | **5** of 6 (0) | **4** of 6 (0) | **3** of 5 (5) | **5** (0) | **5** (5) | 22 | 23 | 10/27 |
| MODEL | **3** of 5 (3) | **4** of 5 (2) | **3** of 6 (1) | **3** of 5 (4) | **5** of 6 (6) | 18 | 19 | 16/27 |
| SIM | **3** of 7 (2) | **4** of 6 (2) | **4** of 5 (3) | **4** of 5 (3) | **5** of 6 (6) | 20 | 21 | 16/29 |
| HARNESS † | **4** of 5 (2) | **4** of 5 (4) | **3** of 4 (4) | **4** of 5 (3) | **5** of 6 (6) | 20 | 21 | 19/25 |
| AGENT † | **6** of 7 (3) | **4** of 5 (4) | **3** (3) | **4** (3) | **5** (5) | 22 | 23 | 18/24 |
| BOT † | **3** of 5 (3) | **4** of 5 (4) | **3** of 4 (4) | **3** of 4 (3) | **5** of 6 (6) | 18 | 19 | 20/24 |
| OWNER ‡ | **4** of 6 (0) | **4** of 6 (0) | **3** of 6 (0) | **4** of 6 (0) | **3** of 6 (0) | 18 | 19 | 0/30 |

**Bold is `i`.** Where `i` is smaller than the module count, both are shown: `8` of
`14` reads *eight is the depth of a profile holding fourteen modules*. A parenthesised
count is how many of that profile's obligations a mechanism establishes today; the two
specification axes carry no domain adapter by construction and show none. † marks the
three adapters on the open release branch; ‡ marks `VSTD-OWNER`, which is relational and
ungrounded and therefore shows none either.

**A passing test suite is not evidence about a ‡ row.** An ungrounded object has no
mechanism, so the only executable checks over it are that its catalogue is well-formed and
that the figures derived from it are correct — both of which hold no matter what its
obligations say. Its normative text is the whole artifact, and adversarial reading is its
only gate. Every authoring defect found in `VSTD-OWNER` so far was found that way, with
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

**Across objects, the composition lattice orders the thirteen ladders against each other.** A
composed object cannot outrun its operands. `VSTD-HYPER-2` states this twice, and the two
statements do not bound it equally:

| Gate | The sentence it comes from | Accessible states |
|---|---|---|
| Operands non-`UNKNOWN` | one `UNKNOWN` operand makes the composition `UNKNOWN` | 139,708,695,169,115,280 |
| Operands complete | strength is non-increasing; the composition claims no more than its operands established | 1,273,366,967,140 |

The tighter one governs. A composition that may advance while an operand is still partial
can report a depth its operands never established, which is exactly what non-increasing
strength forbids — so the reachable count is **1,273,366,967,140**, around one in
2,408,581,401,201,668,443,761,794,566 of the free product.

```
free product over 65 cells    3,067,007,993,957,980,097,740,800,000,000,000,000,000
cumulative profiles, per object          222,027,918,382,776,240
+ composition, operands positive         139,708,695,169,115,280
+ composition, operands complete           1,273,366,967,140   <- reachable
```

`VSTD-OWNER` composes nothing and is composed of nothing, so the composition lattice does
not constrain it. It multiplies each figure below the free product by its own 19
reachable positions, and the free product by prod(i) = 576.

Nothing was removed from the specification to get there. The ordering was always in
`LADDER.md`; the product simply never expressed it.

### Where the rungs are

270 rungs across the thirteen ladders:

| | Objects | Rungs | Rungs per object |
|---|---|---|---|
| Specification axes (VSTD, GRAPH) | 2 | 47 | 23.5 |
| Domain objects | 11 | 223 | 20.3 |

The two axes remain the deepest single objects, which is expected: `VSTD` is the
foundational claim surface every other object's evidence is read through, and a foundation
carrying fewer obligations than the things built on it would be the defect. What is *not*
expected, and was true until the domain objects were catalogued, is a domain object
carrying fewer rungs than it has tiers.

Both numbers still move. Cataloguing an object raises its obligation count and lowers its
`i`, because declared dependencies turn a default total order into a DAG; the domain
objects were catalogued with their dependencies declared from the start, so their `i` is
already a depth rather than a count. What remains provisional is mechanization: 177 of
304 domain obligations have a check behind them, and every one of the remaining 127 is
a coordinate a certificate can name but not yet clear. 30 of those 127 are the
whole of `VSTD-OWNER`, which has no adapter at all.

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
   `VSTD-ENV-5.m` and `VSTD-BENCH-5.m` raised `ValueError`; the tier bound is now the
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
   dependencies are declared, and `tier_depth` computes the bound for any of the sixty-five.
6. **No validator enforces the composition gate.** The reachable count above assumes a
   composed object cannot advance past its operands, which is what non-increasing strength
   requires; nothing in the adapters checks it. `BOT.1` re-derives its bound agent,
   simulation and two environment certificates, but it does not compare their established
   depths against its own. A `VSTD-BOT` certificate at depth 5 over a `VSTD-SIM` operand at
   depth 1 is admitted today and should not be.

# Component grounding, namespace by namespace

Every numbered profile of every object carries component grounding coordinates, in the same
normative form: an identifier, a bound proposition, declared dependencies within the
profile, and an admission policy. Three disjoint namespaces hold them.

| Namespace | Coordinates | Obligations | Where |
|---|---|---|---|
| Object `VSTD-1..5` | `1.1`-`5.11` | 47 | [`GROUNDED_CERTIFICATION.md`](GROUNDED_CERTIFICATION.md) |
| Graph `VSTD-Graph-1..5` | `Graph-1.1`-`Graph-5.6` | 28 | [`GRAPH_GROUNDING.md`](GRAPH_GROUNDING.md) |
| The eleven domain objects | `<object>-1.1`-`<object>-5.6` | 304 | [`DOMAIN_OBLIGATIONS.md`](DOMAIN_OBLIGATIONS.md) |

The namespaces do not overlap and no catalogue admits another's identifiers, so `DATA-4.2`
never aliases `4.2` or `Graph-4.2`. Each computes its own digest, which is what makes them
separable: extending one provably cannot move another's.

What differs between them is not the form of the obligations but how many carry a
mechanism. The two specification axes are checked against retained evidence rather than by
a domain adapter. Of the eleven domain objects, 177 of 304 obligations name a check in one
of the three families — behavioural in [`DOMAIN_GROUNDING.md`](DOMAIN_GROUNDING.md), statics and
adaptation in [`DOMAIN_OBLIGATIONS.md`](DOMAIN_OBLIGATIONS.md). The remaining 127 are
specified without a mechanism and are reported `UNKNOWN` — never absent, and never passed.

`VSTD-HYPER` no longer names two objects. The combination operator keeps the name; the
training-run certifier that used to share it is now `VSTD-TRAIN`, with its own row above
and its own adapter module. The rename landed while 2.0.0 was unreleased, so no shipped
schema or digest carried the old spelling.
