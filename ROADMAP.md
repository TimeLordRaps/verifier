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

## Milestone 3 — agent-work profile

**Build**

- a non-normative profile for observable user, agent, and tool messages;
- bindings for repository state, patches, file reads, commands, outputs, tests,
  failures, retries, and final claims;
- explicit serialization gaps for hidden prompts, inaccessible reasoning, and
  uninstrumented side effects;
- reference adapters that capture only context the harness actually exposes.

**Exit evidence**

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
