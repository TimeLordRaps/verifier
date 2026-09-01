# Realms, temporal structures, and time capsules

> **Acronyms:** directed acyclic graph (DAG); Verifier Standard (VSTD).

**Status:** architectural model for VSTD 1.2; no public realm or time-capsule receipt
format and no complete inference-law verifier are defined here.

This model separates structural artifact closure from propositions about time, execution,
or physical law. Multiple temporal structures may coexist in one declared reality, called
a **realm**. A seal can bind the realm description and its evidence; it does not make the
description true.

## 1. A realm carries temporal domains, not one overloaded time field

A realm may declare any combination of:

| Domain | Carrier and relation | Optional structure |
|---|---|---|
| Continuous time | instants or intervals ordered over a metric domain | duration, topology, continuity |
| Discrete step time | states or steps with an order | successor, ticks, bounded gaps |
| Event or causal order | events under a partial order | concurrency, branching |
| Problem-space order | clauses, obligations, or solutions under dependency | valid linearizations, equivalence |
| Branching possibilities | histories or states under reachability | forks, joins, alternatives |
| Cyclic transition time | states under a transition relation | loops, backtracking, recurrence |
| Atemporal structure | no internal temporal carrier | structural closure only |

Each declared temporal domain identifies its carrier, ordering relation, optional successor,
optional duration or metric, branching/cyclic/partial-order behavior, observation mechanism,
bounds, and unresolved coordinates. Cross-domain mappings are explicit and may be partial,
many-to-many, or information-losing.

For example, one token step may map to a wall-clock interval, several hardware-kernel
events, one decoder-state transition, and several proof dependencies. Discrete observations
at the endpoints do not establish what occurred continuously between them. That proposition
requires a continuity mechanism covering the gap.

## 2. Trace order is not dependency order

If two clauses independently support a third, more than one total execution sequence may
respect the same dependency partial order. VSTD should distinguish:

- **trace identity:** the exact same recorded sequence;
- **topological equivalence:** different sequences respecting the same dependencies;
- **solution equivalence:** different valid derivations reaching an equivalent solution;
- **evidence equivalence:** different executions producing certificates equivalent under a
  named checker.

A solver trace is one linearization; it is not the governing dependency structure. A
search with loops or backtracking is not globally a DAG. Its transition system retains
the internal cycles. A verifier may collapse strongly connected regions and topologically
order the resulting condensation graph without pretending the cycles disappeared.

## 3. Structural seals and temporal capsules

The artifact-control seal in [`standard/ARTIFACT_CONTROL.md`](../standard/ARTIFACT_CONTROL.md)
establishes finite structural closure. It makes no internal time proposition. A
**time capsule** is the composition:

```text
preserved artifact
  + verified self-closing seal
  + sealed realm descriptor
  + temporal-closure policy
  + transition, checkpoint, or continuity evidence
```

An atemporal capsule can establish that an artifact was structurally closed under the
seal mechanism. Atemporal does not mean eternal: a verifier in another realm may later
apply time-indexed ROT because a key was revoked, evidence became stale, or a dependency
changed.

A temporal capsule adds one exact proposition, for example:

> Closure of artifact A was continuously mediated over interval I in temporal domain T by
> mechanism M.

A topological capsule can instead establish that every recorded transition respects a
declared dependency relation independent of wall-clock order. Both propositions may coexist.
Neither follows from a signature at two endpoints.

Cross-realm interoperability is earned only when a named verifier checks the declared
mapping between realm structures. Missing mapping evidence remains `UNKNOWN` or
`UNSUPPORTED`; a seal cannot fill it.

## 4. Autoregressive language-model generation

One generation can occupy several domains simultaneously:

| Surface | Temporal structure |
|---|---|
| Token emission | discrete total order within one accepted sequence |
| Prefix dependency | each accepted next token depends on the accepted prefix |
| Decoder state | discrete state transitions |
| Attention and cache dependencies | directed dependency graph |
| Batched hardware execution | partially ordered events |
| Physical execution | continuous wall-clock intervals |
| Tool calls and revisions | branching event history |
| Reasoning or problem dependencies | partial order that may differ from emitted-token order |

A future transition verifier could bind the prior state, model and weight identity,
tokenizer, prefix commitment, attention/cache commitment, constraint state, logits
commitment, sampler, random state, selected token, and next state:

```text
VerifyTransition(state_n, token_n+1, state_n+1)
  -> PASS | FAIL | UNKNOWN
```

A complete generation would be a checked chain or graph of such transitions. The law
families are distinct:

- **model-realm law:** the transition follows the declared model, tokenizer, cache,
  decoding, and constraints;
- **problem-realm law:** the derivation respects declared proof rules, schemas, clause
  dependencies, or domain invariants;
- **substrate-realm law:** evidence binds the transition to the declared runtime and
  machine substrate; and
- **cross-realm law:** a checked mapping connects the logical transition, problem
  derivation, and substrate execution.

Passing any such law establishes only its bounded execution proposition. It does not
establish that generated text is true. Textual truth still requires proposition-specific
evidence and verifiers.

## 5. Placement on the VSTD axes

This is an architectural allocation, not a new serialized profile:

- **VSTD-1** records individual operations, transitions, and executions.
- **VSTD-2** describes the selected temporal/problem geometry and cross-domain mappings.
- **VSTD-3** anchors observations to runtime and physical substrate.
- **VSTD-4** exposes violations of transition, continuity, or mapping laws.
- **VSTD-5** may corroborate those bounded results through evidenced independent witnesses.
- **VSTD-Graph** represents the complete multi-temporal topology and retained conflicts.

Current VSTD 1.2 artifact control can seal an independently serialized realm descriptor
as a generic `bound_contexts` artifact. It does not define the descriptor's schema, check
cross-domain mappings, establish continuous closure, or verify language-model transitions.
Those remain explicit future mechanism work rather than inferred capability.
