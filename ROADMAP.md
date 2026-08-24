# VSTD public technical roadmap

**Status:** direction, not a promise of delivery or adoption
**Scope:** the public specification, reference implementation, and interoperability
surface only

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

VSTD's intended role is to make that review object cheap to transfer, independently
checkable within stated bounds, and capable of being overturned. It is evidence
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

The longer-term objective is a portable, verifier-independent way to:

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
producer's own word          independent checker kit       multiple implementations can disagree
manual after-the-fact audit  policy-bound event capture    review scales with evidence, not rhetoric
```

The desired feedback loop is:

```text
claim → evidence → bounded check → publish → challenge → adjudicate → degrade or retain
  ↑                                                                        │
  └────────────────────── new evidence / corrected claim ──────────────────┘
```

No arrow in that loop upgrades one VSTD layer with another layer's evidence. Each
layer still requires its own evidence; the loop only carries results and challenges.

## Current branch-backed development tracks

This dated register records substantive local work as of **2026-08-24**. These branches
are not merged into `main`, pushed for public review, normative, released, or evidence of
adoption merely because they exist. Branch names are operational coordinates, not
experiment identities; the experimental-workflow profile is intended to replace this
manual table with portable manifests and a generated index.

| Track | Local branch or branches | Current boundary | Roadmap disposition |
|---|---|---|---|
| Public surface and reserved `.vstd` lockfile | `codex/public-surface-lockfile-audit` | Uncommitted local draft at `main`; mixed changes must be separated and audited before integration. | Review the specification as reserved and non-normative; do not imply an implemented lockfile. |
| Documentation lineage and precedents | `codex/documentation-lineage` | One signed local commit; unmerged and unpublished. | Review source accuracy and merge only compatibility-preserving documentation. |
| SCITT interoperability | `codex/scitt-interop` | One signed local commit; experimental adapter, examples, adversarial tests, and audit; unmerged and unpublished. | Preserve SCITT as an adjacent transparency/receipt substrate and VSTD as bounded verification semantics. |
| ZIZK experiments | `codex/zizk-zero-knowledge`, `claude/zizk-zero-identity`, `claude/zizk-reverification` | Signed local experiment chain; unmerged and unpublished. | Keep zero knowledge, identity minimization, and reverification experimental until their claim boundaries and trustless substrate survive joint review. |
| Verifier-guided SAT routing | `codex/verifier-guided-sat` | Real SAT/native-verifier baseline infrastructure exists locally, but the required live LM evaluation is hard-blocked and no result commit exists. | Preserve the blocker; do not substitute fake LM evidence or claim speed/generalization. |
| Verification allocation and experimental workflows | `codex/verification-allocation-roadmap` | Roadmap definition only; no allocation engine or profile conformance claim. | Specify the platform-independent profile, then a GitHub adapter, then dogfood it on the SCITT, ZIZK, and SAT tracks. |

Historical release branches, pre-rename branches, and already-merged branches are
repository-maintenance concerns rather than active roadmap tracks. Their continued local
existence does not make their older semantics candidates for reintegration.

## Milestone 1 — make refutation the front door

**Exit evidence**

- `vstd demo` is installed, deterministic, and covered by conformance tests.
- Every flagship scenario includes the claim binding, exact specimen, observed checker
  result, and explicit claim boundary.
- A newcomer can run the demo and identify why each outcome is correct in under ten
  minutes.
- Public counterexample, ambiguity, implementation, and private-security routes are
  distinct and usable.

## Milestone 2 — independent checker kit

**Build**

- a language-neutral `VSTD4-GDC-1` byte-level test vector bundle;
- positive, negative, malformed, over-budget, and semantic-misbinding corpora;
- a checker implementer's guide that does not require importing this Python package;
- differential test instructions and a machine-readable conformance report.

**Exit evidence**

- at least one implementation maintained outside this repository reproduces the
  mandatory corpus outcomes;
- disagreements are preserved as public interoperability failures until resolved;
- no “independent” label is used merely because two entry points call shared logic.

## Milestone 3 — experimental-workflow and agent-work profiles

**Build**

- a platform-independent, non-normative experimental-workflow profile for questions,
  hypotheses, preregistration, interventions, observations, native-verifier results,
  budgets, amendments, challenges, and publication state;
- a GitHub adapter that maps issues, commits, workflow runs, artifacts, pull requests,
  and merges without treating repository state as a verification verdict;
- bounded verification-allocation records that preserve the policy, reason, budget,
  deferred surface, and native outcome without assigning truth by priority;
- an agent-harness specialization for observable user, agent, and tool messages;
- bindings for repository state, patches, file reads, commands, outputs, tests,
  failures, retries, and final claims;
- explicit serialization gaps for hidden prompts, inaccessible reasoning, and
  uninstrumented side effects;
- reference adapters that capture only context the harness actually exposes.

**Exit evidence**

- the SCITT, ZIZK, and SAT tracks can be indexed through the same experimental-workflow
  vocabulary without changing their native verifiers or erasing their blockers;
- a GitHub merge remains an integration event rather than becoming a VSTD pass;
- the same trace can be checked by two independent consumers;
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
- treat one layer's evidence as proof of another layer.
