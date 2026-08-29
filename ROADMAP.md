# Verifier Standard (VSTD) public technical roadmap

> **Acronyms:** Concise Binary Object Representation (CBOR); CBOR Object Signing and Encryption (COSE);
> grounded decision certificate (GDC); Internet Engineering Task Force (IETF);
> reduced instruction set computer (RISC); Boolean satisfiability problem (SAT);
> Supply Chain Integrity, Transparency, and Trust (SCITT);
> zero-identity/zero-knowledge (ZIZK).

TRUST is mechanism-earned forward artifact support; ROT is typed, time-indexed
degradation of current admissibility; and RUST is inverse-TRUST diagnostic traversal
toward recorded ancestors. They are formal semantic names, not acronyms or actor ratings.

**Status:** direction, not a promise of delivery or adoption
**Scope:** the public specification, reference implementation, and interoperability
surface only

**Reader context:** [`Concept guide and intellectual precedents`](docs/CONCEPTS_AND_PRECEDENTS.md)

## The near-term problem

“Speed superintelligence” is used here as an operational condition, not as a model
capability certification: when software agents propose, edit, execute, test, and publish
computational work faster than a person can inspect each intermediate step, a final
answer or green check becomes a weak review interface. The reviewer needs a portable
record of:

- the exact claim and coordinate;
- the evidence bytes, tool events, and transformation lineage that were observable;
- the checker and trust roots used;
- the time, memory, disclosure, and availability bounds;
- the conditions that produce `FAIL`, `UNKNOWN`, challenge, or degradation.

VSTD's intended role is to make that review object cheap to transfer, checkable outside
its producer within stated bounds, and capable of being overturned. It is evidence
infrastructure around fast systems—not proof that a system is aligned, safe,
conscious, superintelligent, or fully observed.

## The next question: what should we check first?

Verification is never free. A project can usually identify more claims, artifacts, and
dependencies worth checking than its available time, compute, evidence access, and human
attention can cover. Hiding that constraint does not remove it; it only makes the choice
of what went unchecked harder to inspect.

The intended next direction is straightforward for a newcomer:

1. record the available verification budget;
2. choose which check to run next under a declared policy;
3. record why that check was selected and what was deferred;
4. preserve the native verifier's actual result and VSTD claim boundary; and
5. observe whether the policy makes artifacts easier to check—or merely easier to game.

This is **bounded verification allocation**. A priority is a scheduling result, not a
truth result. “Check this first” does not mean “this is false,” “this is important in
every context,” or “everything else is safe.” Budget exhaustion leaves the deferred
surface explicit and unresolved.

The longer-term objective is a portable, verifier-neutral way to:

- allocate bounded verification work across different proof engines, domain verifiers,
  tests, reproduction procedures, and challenge routes;
- bind the policy, evidence, expected cost, downstream blast radius, and recorded reason
  for each allocation decision;
- measure **verification yield** without reducing it to solver time alone;
- make certificate-friendly, modular, replayable, and cheaply refutable artifacts easier
  to select and deploy; and
- expose feedback loops in which artifacts or adaptive systems change their behavior
  because they anticipate what will be checked.

The allocation policy is itself a versioned software artifact. It can therefore be
tested, challenged, meta-verified, and represented in VSTD-Graph alongside the artifacts
and verifier actions it influences. A stable feedback loop is not automatically a true
one: randomized challenges, counterevidence searches, dependency-aware updates, and
explicit `UNKNOWN` outcomes remain necessary to resist self-confirming verification.

This direction composes established work on
[bounded optimality](https://www.cs.cmu.edu/afs/cs/project/jair/pub/volume2/russell95a.pdf),
[active testing](https://proceedings.mlr.press/v139/kossen21a.html),
[cost-sensitive testing trees](https://proceedings.mlr.press/v32/cicalese14.html),
[proof-carrying code](https://people.eecs.berkeley.edu/~necula/papers.html), and
[certifying algorithms](https://www.sciencedirect.com/science/article/pii/S1574013710000560).
The roadmap does not claim those foundations as VSTD inventions. The research question
is whether VSTD can provide interoperable claim boundaries and portable result semantics
for their combined use across heterogeneous verification substrates.

## Vision board

```text
TODAY                         NEXT                          TARGET CONDITION
fast opaque result           result + bounded receipt      claims travel with challenges
green check only      →      PASS / FAIL / UNKNOWN   →     wrong claims degrade visibly
flat artifact list           provenance hypergraph         poisoned ancestry has blast radius
producer's own word          separate checker kit          multiple implementations can disagree
manual after-the-fact audit  policy-bound event capture    review scales with evidence, not rhetoric
```

The desired feedback loop is:

```text
claim → evidence → bounded check → publish → challenge → adjudicate → degrade or retain
  ↑                                                                        │
  └────────────────────── new evidence / corrected claim ──────────────────┘
```

No arrow in that loop upgrades one VSTD closure coordinate with another coordinate's
evidence. Each coordinate still requires its own evidence; the loop only carries results
and challenges.

## Implemented 1.2 artifact-control foundation

[`standard/ARTIFACT_CONTROL.md`](standard/ARTIFACT_CONTROL.md) defines a mechanism beneath
the numbered profiles: exact regular-file byte and path preservation, dual-algorithm
artifact-derived identity, an observable read-only payload-tree guard, finite readable
self-closing seals, external artifact/key anchor checks, and copy-on-write thaw descendants.
The mechanism is implemented through `vstd artifact` and the supported Python interface.

This is structural closure, not encryption, archival custody, semantic correctness,
trusted time, actor trust, or a numbered VSTD profile result. The
[realm/time-capsule architecture](docs/REALMS_AND_TIME_CAPSULES.md) permits continuous,
discrete, causal, problem-space, branching, cyclic, and atemporal structures, but VSTD
1.2 does not yet define a realm receipt, continuity-law verifier, cross-realm mapping
verifier, or language-model transition verifier.

## Classical interoperability vocabulary target

The near-term interoperability scope is classical computation. **Deterministic** means
that every semantically relevant source of choice is absent or bound as an explicit
input. A seed, repeated output, or deterministic-mode flag alone does not establish that
condition.

These are roadmap-level interoperability **meta-classes**, not new receipt fields or
frozen identifiers:

| Term | Minimum meaning |
|---|---|
| Semantic frame | Exact language, logic, theory, type system, operation set, machine and numerical semantics, versions, and undefined or implementation-defined behavior. |
| Problem frame | Bound instance, declarations, inputs, assumptions, options, objectives, constraints, and initial or session state. |
| Proposition frame | Exact relation being checked, its quantifiers, subject, scope, bounds, horizon, and required counterexample or witness condition. |
| Mechanism contract | Supported frames and claim kinds, checker and trust roots, soundness basis, completeness or incompleteness boundary, resource limits, and known exclusions. |
| Native outcome | The tool's exact status and native meaning; it remains distinct from the VSTD assessment earned by checking it. |
| Evidence payload | Typed model, witness, proof, certificate, core, trace, counterexample, diagnostic, reproducer, coverage record, or primal/dual bound. |
| Transformation obligation | Source and target frames, mapping, claimed relation—such as equivalence, refinement, implication, or equisatisfiability—information loss, and the mechanism checking that relation. |
| Exploration scope | Exhaustive, sampled, bounded, abstracted, under-approximated, or over-approximated search; explored states, paths, regions, and stopping reason. |
| Choice schedule | Random-number-generator algorithm and state, sampler, tie-breaking, concurrency schedule, external responses, and every other choice that affects replay. |
| Numerical contract | Data types, precision, rounding, accumulation order, tolerances, overflow, exceptional values, quantization, and comparison rule. |
| Operational trace | Bound states, transitions, events, causal or topological order, external effects, checkpoints, and omitted observation surface. |
| Composition obligation | Typed dependency relation, imported assumptions or axioms, discharged guarantees, conflicts, and the rule preventing repetition or topology from increasing assurance. |

### Meta-class and native-object boundary

A meta-class names a cross-domain semantic role. A **meta-object** is one bounded VSTD
instance of that role. A **native object kind** is defined by the source verifier, and a
**native object** is an exact instance governed by that verifier's semantics. An adapter
maps the native object into one or more meta-objects while preserving its identity,
native result, assumptions, bounds, and declared information loss.

A classical verification episode should be expressible through these meta-classes, but
an individual artifact need not instantiate all twelve, and one artifact may occupy
several roles. Missing, inapplicable, and unobserved roles remain distinct. Meta-class
membership is organization, not verification; it earns no assurance without the named
mechanism that checks the object and its mapping.

For example, Lean retains its own objects and semantics:

| Interoperability meta-class | Lean native object kind | Example meta-object binding |
|---|---|---|
| Semantic frame | Type theory and declaration environment | Exact Lean version, imported environment, options, and module identities. |
| Proposition frame | Theorem declaration and its type | Exact proposition, universe parameters, and declaration coordinate. |
| Evidence payload | Elaborated proof term | Exact term checked for the bound proposition. |
| Mechanism contract | Kernel and its accepted core language | Kernel implementation/version, configuration, trust roots, and exclusions. |
| Transformation obligation | Elaboration from syntax or tactics to a core proof term | Bound source, produced term, mapping, dependencies, and information loss. |
| Composition obligation | Imported definitions, theorems, and axioms | Exact dependency and axiom set retained as prerequisites rather than inherited truth. |
| Native outcome | Kernel acceptance or rejection | Exact native result and diagnostics before any VSTD assessment. |

The first machine-learning specialization is a classically executed autoregressive
transition: bound model and weight bytes, tokenizer, operation graph, prefix, cache/state,
numerical contract, logits transformations, choice schedule, and external tool inputs map
to a selected token and next state. Passing establishes only conformance of that declared
transition. It does not establish that the emitted text is true; that requires a separate
proposition-specific verifier.

The vocabulary is grounded in distinctions already exposed by primary interfaces such as
[Lean proof terms and kernel checking](https://lean-lang.org/doc/reference/latest/),
[the satisfiability modulo theories library language](https://smt-lib.org/language.shtml),
[TLA+ behaviors and model checking](https://lamport.azurewebsites.net/tla/high-level-view.html),
[the Static Analysis Results Interchange Format](https://docs.oasis-open.org/sarif/sarif/v2.1.0/os/sarif-v2.1.0-os.html),
[in-toto attestations](https://github.com/in-toto/attestation/tree/main/spec/v1),
[PyTorch reproducibility limits](https://docs.pytorch.org/docs/stable/notes/randomness.html),
[StableHLO program semantics](https://openxla.org/stablehlo/spec), and
[Transformers generation controls](https://huggingface.co/docs/transformers/main_classes/text_generation).

A public “99%+ coverage” claim is prohibited until a versioned taxonomy names the
included classical fields and subfields, representative native specimens exist, and
round-trip plus adversarial loss tests show which mandatory distinctions survive each
adapter. Coverage means expressibility over that declared denominator; it is not market
share, adoption, correctness, or evidence that every tool has been tested.

Quantum, thermodynamic, deoxyribonucleic acid (DNA), chemical, and chemputer verification
are outside the first denominator. A later operational-landscape extension must map this
shared interoperability vocabulary without redefining VSTD outcomes. Whether an extension
belongs in an optional module or a separately governed repository remains a future coupling
and ownership decision.

## Current experimental development tracks

This dated register records substantive work as of **2026-08-25**. A committed experiment,
passing test, or generated index is not normative, released, reproduced by a distinct actor,
or evidence of adoption merely because it exists. Profile manifests and the generated
[`experiments/INDEX.md`](experiments/INDEX.md) are the portable experiment register when
intentional experiment artifacts are present.

| Track | Public artifact | Current boundary | Next gate |
|---|---|---|---|
| SCITT interoperability | [`docs/standards/VSTD_SCITT_CROSSWALK.md`](docs/standards/VSTD_SCITT_CROSSWALK.md) | Experimental adapter, rerunnable real-COSE specimen with ephemeral keys, and adversarial tests; no IETF review or external interoperability result. | Independent implementation and interoperability result. |
| Artifact-first mechanism completion | [`experiments/artifact_first_mechanisms/experiment.json`](experiments/artifact_first_mechanisms/experiment.json) | Experimental event serialization, TRUST-transfer algebra, ROT derivation/propagation, RUST concentration/localization, complete trichotomy derivation, and specific unfinished optional proof backends under the already-governing ZIZK architecture. The bounded identity evaluator and tracked RISC Zero reference mechanism are under `examples/`. | Implement and falsify each mechanism without treating the governing orientation as contingent or creating actor-tied trust. |
| Workflow and allocation | [`docs/profiles/experimental-workflow.md`](docs/profiles/experimental-workflow.md) | Strict validator, verdict-neutral GitHub adapter, generated index, and allocation records; no optimality claim or independent consumer. | A second observable adapter and independent consumer. |

## Milestone 1 — make refutation the front door

**Exit evidence**

- `vstd demo` is installed, deterministic, and covered by conformance tests.
- Every flagship scenario includes the claim binding, exact specimen, observed checker
  result, and explicit claim boundary.
- A newcomer can run the demo and identify why each outcome is correct in under ten
  minutes.
- Public counterexample, ambiguity, implementation, and private-security routes are
  distinct and usable.

## Milestone 2 — separate checker kit

**Build**

- a language-neutral `VSTD4-GDC-1` exact-byte test-vector bundle;
- positive, negative, malformed, over-budget, and semantic-misbinding corpora;
- a checker implementer's guide that does not require importing this Python package;
- differential test instructions and a machine-readable conformance report.

**Exit evidence**

- at least one implementation maintained outside this repository reproduces the
  mandatory corpus outcomes;
- disagreements are preserved as public interoperability failures until resolved;
- no “independent” label is used merely because two entry points call shared logic.

## Milestone 3 — experimental-workflow and agent-work profiles

**Implemented in experimental profile 0.1**

- a platform-independent, non-normative experimental-workflow profile for questions,
  hypotheses, preregistration, interventions, observations, native-verifier results,
  budgets, amendments, challenges, and publication state;
- a GitHub adapter that maps issues, commits, workflow runs, artifacts, pull requests,
  and merges without treating repository state as a verification verdict;
- bounded verification-allocation records that preserve the policy, reason, budget,
  deferred surface, and native outcome without assigning truth by priority;
- deterministic canonicalization, repository-artifact binding, a generated experiment
  index, adversarial tests, a verdict-neutral checked-in specimen, and an
  artifact-first-mechanism dogfood manifest.

**Still build**

- an agent-harness specialization for observable user, agent, and tool messages;
- bindings for repository state, patches, file reads, commands, outputs, tests,
  failures, retries, and final claims;
- explicit serialization gaps for hidden prompts, inaccessible reasoning, and
  uninstrumented side effects;
- reference adapters that capture only context the harness actually exposes.

**Exit evidence**

- the SCITT, artifact-first-mechanism, and SAT tracks can be indexed through the same experimental-workflow
  vocabulary without changing their native verifiers or erasing their blockers;
- a GitHub merge remains an integration event rather than becoming a VSTD pass;
- the same trace can be checked by two separately maintained consumers;
- deleting or substituting a bound tool output changes the receipt digest or fails a
  declared rule;
- missing observability yields a named gap or `UNKNOWN`, never reconstructed fiction.

## Milestone 4 — challenge and degradation network

**Build**

- append-only challenge envelopes and adjudication records;
- transitive blast-radius computation over object and transformation nodes;
- freshness and availability policies for evidence that disappears;
- portable bundles for disconnected verification.

**Exit evidence**

- a revoked ancestor deterministically identifies affected descendants;
- a successful challenge cannot leave the original claim displayed as clean;
- restoring a claim requires new evidence and a new checked result, not deletion of
  the challenge history.

## Milestone 5 — corroboration without pseudo-independence

VSTD-5 remains draft until operating experience and actual outside participants exist.

**Exit evidence**

- witness identities and trust-root overlap are measurable;
- the protocol detects obvious shared-producer and shared-verifier dependence;
- claims of corroboration are made only after another party exists and acts;
- the project publishes limitations that remain after multiple witnesses agree.

## Adoption as verification, not marketing theater

Early progress is measured by externally inspectable events:

| Metric | What counts |
|---|---|
| Reproduction | an outside party reruns a published mechanism and reports the exact result |
| Refutation attempt | a concrete specimen, ambiguity, or boundary attack—not a reaction count |
| Independent implementation | a separately maintained checker with declared code and trust roots |
| Interoperability | two implementations exchange the same canonical object and report compatible outcomes |
| Challenge recovery | a claim visibly degrades and is later restored only through new evidence |

Stars, downloads, and mentions can describe reach. They do not establish correctness,
independence, interoperability, or adoption of the standard.

## Explicit non-goals

This roadmap does not promise to:

- certify general intelligence, alignment, intent, or moral status;
- reveal hidden model state or unobservable harness context;
- prove all physical execution has been recorded;
- replace sandboxing, signatures, identity systems, transparency logs, or domain
  truth tests;
- treat one closure coordinate's evidence as proof of another coordinate.
