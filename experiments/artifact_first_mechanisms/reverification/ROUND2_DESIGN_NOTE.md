# Round 2 design note: operationalizing artifact-first reverification and Rust

> **Acronyms:** Common Vulnerabilities and Exposures (CVE); identifier (ID); reduced instruction set computer (RISC);
> Secure Hash Algorithm 256-bit (SHA-256); scalable transparent argument of knowledge (STARK);
> Verifier Standard (VSTD); zero-identity (ZI); zero-knowledge (ZK); zero-knowledge virtual machine (zkVM).

**Status:** experimental design note; non-normative; no wire profile is defined.

This note uses **trustless** in one bounded sense: acceptance of a submitted
reverification result must not require knowing or trusting the submitter. It does not
mean assumption-free, trust-root-free, or immune to compromised software, unavailable
evidence, or false observations.

The controlling semantic orientation is normative in
[`standard/LADDER.md` section 1.1](../../../standard/LADDER.md#11-artifact-first-causal-provenance-orientation).
This experiment does not decide whether that orientation is valid repository architecture;
it tests the still-open event format, transfer algebra, concentration rule, and localization
mechanics needed to operationalize it.

The design decisions are:

> Tier 0 is artifact-first: it binds claims, artifacts, predicates, verifier mechanisms,
> boundary snapshots, proofs, and checkable results. Actor identity, popularity, and
> reputation contribute no verdict weight and accumulate no trust.

> Actor and artifact are contextual roles on creation and operation events, not disjoint
> kinds of entity. A coding agent can be an artifact when created, serialized, versioned,
> or evaluated and an actor when it performs a transformation or creates another artifact.

> The same bound causal-provenance graph carries two memetic propagation directions:
> bounded artifact trust moves forward through developmental claim space, while observed
> Rust genetically backtraces from descendant deviations toward recorded ancestor states.
> This causal-provenance transmission does not itself establish causal localization.

Authorship, authorization, issuer identity, organizational accountability, and descriptive
history may exist in adjacent optional profiles. Tier 0 may bind their coordinates when a
claim requires them, but their mere presence cannot strengthen the result.

## 1. Where the research components stand

Round 1 began from commit `598c545be3833d6d81bb7e252ca5837f3bb2a449`.

| Work | Source coordinate | What it established | Round 2 treatment |
|---|---|---|---|
| Zero Identity | `claude/zizk-zero-identity` at `48fab87b05ad5ddaf24d08b6391cde99d05fc8f1` | A bounded identity-disclosure reference evaluation, with 22 fixtures and 65 focused tests | Retained as an adjacent reference mechanism; its coordinates carry only the claim meaning explicitly checked |
| Zero Knowledge | `codex/zizk-zero-knowledge` at `14d31e0426656c5208f2b6579a5217af3a6bb2bd` | A real RISC Zero zkVM 3.0.6 composite STARK receipt for one hidden-witness predicate | Retained as the confidential-evidence mechanism; its bearer, artifact-bound form is compatible with Tier 0 |
| Zero actor trust | this Round 2 design | No actor identity, popularity, or reputation may strengthen a result | Open as an operational protocol; stated here as a required invariant |
| Artifact-first trust | existing VSTD artifact, evidence, mechanism, and predicate bindings | Bounded positive support can move from verified parent artifacts into the declared obligations of descendants | Retained as the Tier 0 starting point; child obligations remain separately checked |
| Actor-artifact role semantics | no prior implementation | An entity's role depends on the creation or operation event; coding agents can occupy both roles | Open; this note corrects the earlier object-only partition |
| Rust | this Round 2 design | A proposed viral backtrace of measured deviation through bound creation ancestry, never trust or a verdict | Reframed as relation-bound memetic transmission toward recorded ancestor states |

One premise in the initial Round 2 plan is corrected here. The two finished halves did
**not** both put trust in credentials:

- The Zero Identity half intentionally modeled a pseudonym, signing key, trust root,
  issuer, authorization grant, and revocation source. Its conclusion follows from that
  actor-bound problem definition.
- The Zero Knowledge half binds a subject digest, policy digest, challenge, threshold,
  image ID, authenticated journal, and proof. It adds no actor coordinate and expressly
  prohibits inferring identity, authorization, uniqueness, or independence.

The architectural correction applies to the evidentiary effect of the Zero Identity
model, not to the existence of actor coordinates or to the Zero Knowledge proof. The
identity model is not discarded: it remains an optional adjacent profile for deployments
that need authorization or accountability. Its coordinates cannot become actor trust,
and the actor/artifact role model below prevents the profile boundary from becoming a
false permanent partition between parties and things.

VSTD already contains much of the required substrate discipline. In particular,
`standard/VSTD-4.md` requires post-verdict checking without cooperation from the
declarant, disallows undeclared state from becoming verdict material, defines verifier
descriptors through content hashes, requires a checker that shares no verdict-producing
code, and requires a declared verification interface for confidential evidence. That
does not make every VSTD layer identity-free: observational evidence and external trust
roots still have sources. It makes actor identity unnecessary as verdict weight while
preserving any actor-artifact relation needed to state the bounded claim.

## 2. Zero actor trust through artifact-first convergent recomputation

### 2.1 Reverification unit

A Tier 0 reverification attempt is defined over these public coordinates:

1. **subject coordinate** — an artifact digest or an immutable receipt digest;
2. **statement coordinate** — the canonical claim and predicate digest;
3. **declared inputs** — content digests for every sealed input;
4. **boundary snapshot** — the content-addressed result of resolving every declared
   external dependency under a pinned resolver policy;
5. **mechanism descriptor** — specification, implementation, and parser digests, plus a
   proof-system program identifier or verification key when applicable;
6. **expected result** — the result committed by the claim being reverified; and
7. **observed result and trace** — enough public material to repeat the check, or to
   verify a proof when the witness is confidential; and
8. **role-relation snapshot, when claim-relevant** — content-addressed creation,
   execution, input, and output edges without converting an endpoint into verdict weight.

An experimental event body can be modeled as:

```text
ReverificationEventBody = {
  subject_digest,
  statement_digest,
  declared_input_digests,
  boundary_snapshot_digest,
  resolver_policy_digest,
  mechanism_descriptor_digest,
  expected_result_digest,
  observed_result_digest,
  outcome,
  trace_or_proof_digest,
  role_relation_snapshot_digest?,
  prior_event_digest
}

event_id = SHA-256(canonicalize(ReverificationEventBody))
```

This is a design sketch, not a new schema. Its names are not reserved wire identifiers.
Canonicalization, supported digest algorithms, event-chain rules, and admissible outcome
values require a later approved experiment before any schema can be proposed.

No field identifies the submitter merely to weight the result. A claim-relevant role edge
may identify a bounded entity coordinate, but possession of a valid event confers no
authorization and proves no authorship.

### 2.2 Actor and artifact are event-relative roles

The model must not define permanent disjoint `Actor` and `Artifact` universes. It records
roles on bound events:

- `produced_by(event, entity, output)` places `entity` in an actor role and `output` in an
  artifact role for that creation event;
- `created_as(event, entity)` places the created entity in an artifact role;
- `executed_as(event, entity)` places a running entity in an actor role; and
- `used_as_input(event, entity)` may place the same entity in an artifact role for a
  different operation.

A coding-agent model, package, checkpoint, or executable is therefore an artifact of its
training or build event. A bound execution of it is an actor in a patch-producing event,
and the patch is an artifact. The roles follow declared creation and operation semantics;
they do not establish civil identity, authorship, ownership, authorization, independence,
or reputation.

The precise event schema, instance coordinate, and relation vocabulary remain `OPEN`.
This note establishes only that erasing the relation or forcing a permanent category is
incorrect.

### 2.3 Agreement is not trust

Repeating the same deterministic implementation over the same frozen inputs is expected
to return the same result. Ten, one thousand, or one million matching submissions do not
make the result more true. They must not be counted as votes, averaged, or converted into
standing.

Agreement can establish only the bounded fact that the accepted traces produced matching
outputs under their declared coordinates. An independently implemented checker can add a
different falsification opportunity because it may expose a specification or
implementation disagreement. Even then, agreement does not establish actor independence,
real-world truth, or a probability of correctness.

### 2.4 Divergence is a falsification candidate, not self-certifying truth

A submitted divergence is admissible only when the verifier can establish all of the
following without trusting the submitter:

- both results bind the same subject, statement, declared inputs, resolver policy, and
  comparison unit;
- the mechanism coordinates are explicit;
- the claim under test declared the relevant computation deterministic or otherwise
  declared the expected equivalence relation;
- the divergent trace can be repeated, or its proof can be checked; and
- no hidden input, unpinned dependency, or incomparable environment explains the
  difference.

An admissible divergence can refute a declared determinacy or reproducibility claim. It
does not, by itself, determine which output is correct or establish truth outside the
predicate. If comparability is insufficient, the result is `UNKNOWN`. If admissible
evidence supports incompatible results, the result is `CONFLICTED`.

Calling divergence **self-certifying** would be too strong. A malformed or
non-reproducible divergence report certifies nothing. Actor identity and Sybil resistance
are unnecessary for verdict material because duplicate or invalid reports cannot change
the result; however, anonymous spam can still create storage, bandwidth, and triage costs.
Rate limiting and admission control may address that operational denial-of-service risk,
but must not become evidence about correctness.

## 3. Forward artifact trust without actor-trust accumulation

Tier 0 records both bounded positive artifact support and accepted opportunities to refute
a claim. It never turns either into a producer's or verifier's reputation, and a claim
does not gain standing merely by surviving repeated attempts.

Artifact trust is a positive signal bound to an exact artifact, claim, predicate,
mechanism, evidence set, boundary snapshot, and time coordinate. It moves forward only
through a declared creation or dependency edge whose transformation obligations pass. A
child receives the intersection of applicable parent support, capped by the weakest
required parent and edge; it does not receive a sum, vote, average, or confidence boost.
The child must still discharge every new predicate, transformation, and boundary
obligation it introduces.

In schematic form:

```text
development: ancestor artifact --bounded positive support--> descendant claim or artifact
diagnosis:   descendant Rust   --memetic causal backtrace--> recorded ancestor states
```

`UNKNOWN`, `CONFLICTED`, revoked, unavailable, or out-of-scope parent support cannot be
laundered into a clean child signal. Repeating the same parent coordinate does not create
additional support. Actor identity and reputation do not participate in the transfer.

| Tier 0 event outcome | Bounded interpretation | Forbidden interpretation |
|---|---|---|
| matching result | this accepted check matched the committed result and may satisfy one declared child obligation | the claim, submitter, or mechanism is globally trustworthy |
| admissible divergence | the declared equivalence or reproducibility condition has a checkable counterexample | the divergent result is automatically the true result |
| unresolved boundary | required material could not be resolved or checked; preserve `UNKNOWN` | missing evidence is clean evidence |
| incompatible admissible records | preserve `CONFLICTED` and expose both records | choose the more popular result |

The Tier 0 state is a function over immutable records. Its positive artifact support is
typed and scoped; it does not have a cumulative confidence counter, majority rule, actor
weight, or time-decayed reputation.

Tier 1 may provide descriptive analysis over Tier 0 events. Tier 1 is optional,
non-normative, and forbidden from supplying `PASS`, `FAIL`, `UNKNOWN`, `CONFLICTED`,
`VALID`, `STALE`, or any ladder result. Evidence in one layer does not silently supply
evidence in another.

## 4. Rust: an optional relation-bound deviation ledger

**Rust** is the working name for a Tier 1 view of past measured deviation. It is not
trust, inverse trust, a verdict, or a prediction.

### 4.1 Bound relations, not actor reputation

Rust may bind only to immutable coordinates and explicitly typed relations:

- an artifact digest;
- a statement or predicate digest;
- a specification, implementation, and parser digest tuple; or
- a content-addressed creation or transformation edge;
- a contextual actor-role/artifact relation for one declared event; or
- an explicit basin coordinate defining a common comparison unit.

It does not create a scalar score for a person, pseudonym, account, organization, author,
issuer, key holder, submitter, or coding agent. An actor coordinate may be a relation
endpoint, but rust cannot aggregate upward across unrelated artifacts, predicates,
operations, or basins and cannot change a Tier 0 verdict.

The same coding agent may therefore have one rust history as an evaluated artifact, other
histories for specific creation or transformation relations in which it acted, and no
valid global score. These histories remain separate unless an explicit common comparison
unit and evidence justify composition.

Content addressing prevents an unchanged byte sequence from shedding its history while
keeping the same digest. It does **not** eliminate whitewashing in general: a trivial
repackaging, semantically near-identical fork, or changed mechanism descriptor creates a
new coordinate. Because recorded ancestry does not establish that a defect transferred,
the parent's rust cannot be copied into the descendant. The old coordinate and relation
records remain, while any inference about the new entity or relation remains `UNKNOWN`
until measured.

### 4.2 Exposure denominator and deduplication

Rust requires an exposure denominator so that no observation and many observations are
not confused. An exposure is not a submitted run. It is a unique, admissible opportunity
for the declared expectation to fail.

The proposed exposure key is the digest of:

```text
(subject, statement, mechanism, role relation, comparison unit, boundary snapshot)
```

Identical submissions collapse to one exposure. A different submitter does not create a
new exposure. A new exposure requires a distinct admissible test vector, independently
implemented mechanism, or resolved boundary snapshot that can reveal something not fixed
by the earlier event.

For every basin, report at least:

- `exposure_count` — unique admissible exposure keys;
- the ordered deviation observations;
- the deviation mean for each declared horizon;
- dispersion for each horizon; and
- the number of `UNKNOWN` and `CONFLICTED` comparisons excluded from numerical
  aggregation and still reported separately.

`exposure_count = 0` is `UNKNOWN`, not clean. A positive exposure count with zero measured
deviation is still only a history of observed matches, not a favorable verdict.

### 4.3 Reference and measured quantity

The reference is the claim's own declared expectation: committed output, tolerance,
falsification condition, availability condition, reproducibility level, or other bounded
predicate. Rust therefore records **deviation from a declared expectation**, not error
against unknowable real-world truth.

Each expectation type needs a fixed comparison rule outside the measured relation
endpoints' control. Examples include binary mismatch, normalized numeric error under a
declared unit, or set-distance under a fixed canonicalizer. A measured endpoint must not
choose a weaker penalty after seeing a result.

`UNKNOWN` and `CONFLICTED` are not numeric zero. They remain typed observations. A
comparison that lacks a common unit is not forced into a number.

### 4.4 Memetic backtrace, basins, and horizons

A **basin** is an explicitly described analytical grouping of events that share a
predicate, mechanism family, comparison unit, and deviation rule. Clustering may suggest
a basin, but a clustering algorithm does not establish that the members are comparable.
The basin definition and its digest must be published with the view.

Rust acts as a viral **truth-disease backtrace** through causal provenance. A directly
measured descendant deviation is the source event, and the recorded creation and input
graph determines which ancestor states receive the memetic trace. The genetic metaphor
names transmission through developmental ancestry: actor/artifact role edges allow the
trace to cross a coding-agent execution into the bound model, package, checkpoint, or
executable that acted and then into that artifact's own creation ancestry. Transmission
establishes provenance reachability; localization still requires its own evidence.

Propagation is typed rather than silently re-described as direct observation:

| Rust state | Meaning |
|---|---|
| `OBSERVED` | the deviation was measured directly at this descendant coordinate |
| `TRANSFERRED` | an observed rust event reached this ancestor through a recorded admissible path |
| `LOCALIZED` | additional evidence identifies this ancestor or edge as contributing to the deviation |
| `UNKNOWN` | the required lineage or edge semantics are incomplete or unavailable |
| `CONFLICTED` | admissible backtraces disagree about the relation or contribution |

For each admissible path from ancestor `a` to rusted descendant `d`, the transferred state
must bind at least the source rust event, `a`, `d`, every traversed edge digest, the
predicate, mechanism, comparison unit, basin, and transfer rule. A source event, ancestor,
and path tuple is counted once. Mere co-occurrence, reference, authorship, or identity is
not a transmission edge. An unknown edge stops that path and preserves `UNKNOWN`.

Rust **concentrates** where distinct descendant infection events share an ancestor. For an
ancestor and basin, the concentration record is the set of unique source rust event and
admissible path digests that reach it. Multiple paths or duplicate reports of one source
event remain visible but do not multiply its weight. Intersections of independent
backtraces prioritize earlier claims, predicates, mechanisms, or artifacts for diagnostic
examination because they are common candidate loci of falsehood.

`TRANSFERRED` is actual rust inheritance, but it is not a claim that the ancestor was
directly measured or proved causal. `LOCALIZED` requires an intervention, ablation,
reproduction by a distinct actor, or other declared mechanism that distinguishes contribution
from ancestry. The backtrace is append-only, does not decay, and does not alter existing
Verifier Standard status or blast-radius calculations until a separate normative rule is
approved.

Horizon summaries are indexed by accepted exposures rather than wall-clock time, for
example the last 10, 100, and 1,000 exposures plus lifetime. The complete vector and its
dispersion are reported. It is not collapsed into one rankable scalar.

### 4.5 Dual causal representation

Forward artifact trust and backward Rust are messages over the same directed development
graph, not positive and negative values on one scalar. The forward message asks which
bounded parent obligations are available to a child. The backward message asks which
recorded ancestors can explain an observed child deviation. A node may carry both without
cancellation: positive support for one predicate does not erase Rust for another, and
Rust on one descendant does not erase unrelated support.

The recorded causal-provenance graph therefore represents both the generative direction
used to explain how claims and artifacts develop and the diagnostic direction used to
identify where a later contradiction may have entered the architecture. This memetic
propagation is causally meaningful as recorded provenance without, by traversal alone,
establishing intervention-level physical causality or causal localization.

### 4.6 Prior art boundary

Proper scoring rules provide a lower-is-better penalty analogy when a claim is genuinely
probabilistic; the original references include [Brier (1950)](https://journals.ametsoc.org/view/journals/mwre/78/1/1520-0493_1950_078_0001_vofeit_2_0_co_2.xml)
and [Good (1952)](https://rss.onlinelibrary.wiley.com/doi/10.1111/j.2517-6161.1952.tb00104.x).
Rust is not itself a proper scoring rule unless its declared expectation and comparison
rule satisfy the corresponding conditions.

[Friedman and Resnick (2001)](https://onlinelibrary.wiley.com/doi/abs/10.1111/j.1430-9134.2001.00173.x)
analyze the social cost of cheap pseudonyms in party reputation systems. Content and
relation binding change the coordinate being measured, but, as noted above, do not prove
that semantically equivalent repackaging is impossible.

[CVE](https://www.cve.org/), [OpenSSF Scorecard](https://openssf.org/scorecard/), and
[Certificate Transparency](https://www.rfc-editor.org/rfc/rfc9162.html) are useful
comparisons for public negative signals, automated project checks, and append-only public
records. They are not equivalent mechanisms and do not validate this design. This note
claims only a proposed composition of relation-bound deviation, memetic causal backtrace,
exposure deduplication, typed uncertainty, and separation from verdict material. It makes
no novelty claim.

## 5. The information-free limit

Re-running the exact same pure deterministic function, implementation, and frozen inputs
is expected to be information-poor after the first successful check. It exercises the
plumbing again but introduces no new world state.

Reverification can add information in three places:

1. **independent implementation:** a checker with no shared verdict-producing code may
   reveal a specification or implementation disagreement;
2. **new bounded test vector:** a previously unexercised input may falsify a general
   declaration; and
3. **boundary re-resolution:** an external artifact can be rehashed, a reference can be
   resolved again under a pinned policy, or a declared revocation/availability source can
   expose a changed state.

The sealed core and the changing boundary must remain distinguishable. A boundary
snapshot is content-addressed; the fact that it was retrieved later is not itself verdict
material. If a current boundary cannot be resolved, freshness is `UNKNOWN`. Absence of a
new event never proves that an old event remains current.

For a hidden witness, proof verification is the repeatable public interface. It proves
only the program execution and journal bound by the selected proof system. It does not
reveal or independently observe the witness and does not establish that the witness was
truthful.

## 6. Proposed `STALE` entry and successor semantics

This repository currently has two distinct `STALE` enum members:

- `CoordinateStatus.STALE` in `src/verifier/core/geometry.py`, serialized by the
  VSTD-2 receipt schema; and
- `ArtifactStatus.STALE` in `src/verifier/data/models.py`, consumed by graph admission and
  the Layer 4 degradation order.

They are not the same type. Both tokens are existing wire vocabulary, and this note does
not change or reserve their meaning.

The proposed non-normative entry rule is:

> A coordinate or artifact is derivably `STALE` only when an accepted append-only
> reverification event, under the subject's declared resolver policy, shows that an
> external binding on which the earlier result depended no longer resolves to the content
> or admissible state committed by that earlier result.

Required event evidence includes the prior receipt digest, subject kind and digest,
resolver-policy digest, previous boundary snapshot digest, newly resolved boundary
snapshot digest, and a repeatable trace or verifiable proof of the mismatch. Mere age,
wall-clock passage, missing availability, accumulated rust, popularity, or a reporter's
assertion is not a `STALE` entry condition.

If the boundary cannot be resolved, the result is `UNKNOWN`, not `STALE`. If two
admissible current snapshots are incompatible and the resolver policy does not order
them, the result is `CONFLICTED`, not silently selected.

There is no historical mutation and therefore no literal exit from `STALE`. The earlier
receipt and its derived stale event remain immutable. Recovery creates a successor
receipt or coordinate bound to the new boundary state. That successor can be evaluated
on its own evidence; it does not cleanse the earlier coordinate. A current-view function
may follow an append-only, digest-linked event chain to the declared head, but an absent or
unavailable head leaves the current view `UNKNOWN`.

Before implementation, separate transition functions are required for
`CoordinateStatus` and `ArtifactStatus`; shared prose is not permission to conflate the
two frozen enum families. Ledger ordering, fork handling, inclusion proofs, and resolver
trust coordinates also remain to be specified.

Rust has no status-transition role. A rust view may describe deviations that accompanied
a stale event, but no magnitude of historical deviation is sufficient to produce or clear
`STALE`.

## 7. Zero-knowledge trichotomy correction

The Round 1 guest accepts only `CandidateState::Supported` and always commits
`predicate_satisfied: true`. A valid proof therefore authenticates one favorable path.
Failure to present a proof is ambiguous among no attempt, prover failure, an unsatisfied
witness, `UNKNOWN`, and `CONFLICTED`.

The exact proposed journal shape change is:

```rust
pub struct PublicJournal {
    // Existing binding fields remain.
    pub verdict: CandidateState,
    pub predicate_satisfied: bool,
}
```

Required invariant:

```text
predicate_satisfied == true  if and only if verdict == Supported
                              and the fixed predicate is satisfied
```

`Unknown` and `Conflicted` must be valid authenticated journal outcomes when the guest's
fixed rules derive them. They must never be encoded as a missing proof. The existing
assertion that rejects both states would be replaced by a total verdict calculation, and
the public-envelope checker would compare both fields to the authenticated journal.

This structural correction is necessary but not sufficient. The current private witness
contains a caller-supplied candidate state and only one measurement. It lacks the evidence
structure needed to **derive** a conflict or to distinguish genuine insufficiency from a
caller merely labeling an input `Unknown`. Publishing a private input tag as a public
verdict would authenticate the tag, not establish the verdict. Before implementation, the
fixed predicate must define how all three states are derived from bounded witness data and
must add enough witness structure to derive `Conflicted`.

No change is made in Round 2. The existing proof remains accurately described as one real
proof for one favorable bounded predicate, not as a full trichotomy implementation.

## 8. What the Zero Identity half keeps and loses

### Kept as portable discipline

- Missing evidence stays `UNKNOWN`.
- Contradictory admissible evidence stays `CONFLICTED`.
- Minimization may narrow a claim boundary but must not widen one.
- Recorded ancestry does not establish that an authority, property, or defect transferred
  across every edge.
- Semantic results, external attestations, declared assumptions, and protocol guarantees
  remain separate evidence classes.
- The 19 prohibited inferences remain useful in the optional actor-facing profile. The
  actor-agnostic subset also constrains Tier 0: missing evidence is not safety; recorded
  ancestry is not established influence; and one evidence class cannot silently upgrade
  another.

### Forbidden as automatic trust or verdict weight

- pseudonym or signing-key identity;
- issuer, authorization grant, actor trust root, or revocation source;
- uniqueness, Sybil-resistance, independence, or accountability claims; and
- authorship degree or credential ancestry.

These coordinates may still be bound when the declared claim needs them. None is a
general trust signal, none upgrades an artifact result, and none permanently classifies an
entity as an actor rather than an artifact.

Deployments may still use the bounded identity-disclosure reference
model alongside Tier 0 when they need authenticated authorization. Its results must not
raise or lower the artifact-bound reverification result.

### Recorded model-to-code drift

`model/zero_identity_model.json` lists 13 `minimum_public_actor_coordinates` and seven
`optional_provenance_coordinates`. `evaluate.py` defines six structural
`REQUIRED_PUBLIC_COORDINATES`; other coordinates are checked later by individual rules.
The tests currently do not enforce equality between the declarative list and the
structural list.

This mismatch does not justify a favorable result from missing evidence—the individual
rules generally preserve `UNKNOWN` or reject—but it makes the declarative contract stale.
The follow-on should establish one source of truth and add a containment test. It is not
changed in this design-only round.

## 9. Explicit non-claims

This design does not establish or claim:

- anonymity, unlinkability, untraceability, confidentiality, or protection from traffic
  analysis;
- actor uniqueness, actor independence, authorization, accountability, or Sybil
  resistance;
- that all operational abuse is harmless; identity-less submission still permits spam
  and resource exhaustion;
- real-world truth, complete evidence, honest witnesses, or correct external observations;
- that a divergent output is automatically correct;
- that repeated agreement increases trust, probability, ladder level, or status;
- that trustless means no trust roots, no cryptographic assumptions, or no trusted
  software;
- that pure recomputation supplies new information under unchanged coordinates;
- that `STALE` can be inferred from elapsed time, rust, missing records, or popularity;
- that a rust history predicts future behavior; it records only past measured deviation;
- that rust is comparable across predicates, units, or basins;
- that a relation-bound Rust ledger prevents semantically equivalent repackaging;
- that `TRANSFERRED` proves direct observation, causation, intent, or fault at an ancestor;
- that Rust concentration is a probability of guilt or a substitute for localization;
- that forward artifact trust proves a child claim without its own transformation and
  predicate evidence;
- that authorship is actor identity, or that either is required by Tier 0;
- independent implementation, external audit, external adoption, production readiness,
  or a security review of this synthesis;
- a new ladder rung, conformance requirement, schema, lifecycle token, or frozen wire
  identifier; or
- novelty of the individual ingredients or of their proposed composition.

## 10. Open questions

1. **Transmission rules:** which typed creation, input, execution, and transformation
   edges admit Rust transfer, and which reference-only edges stop it?
2. **Localization:** which intervention or independent evidence promotes inherited
   `TRANSFERRED` Rust to `LOCALIZED` contribution?
3. **Role coordinates:** how are a coding-agent artifact and its bound acting instance
   related without claiming they are identical or permanently assigning either category?
4. **Forward trust transfer:** which parent evidence classes and edge checks supply a
   bounded positive signal to each child obligation, and how is the weakest required
   support preserved?
5. **Concentration:** which independence and basin conditions let intersecting backtraces
   prioritize a common ancestor without converting frequency into causal proof?
6. **Deviation rules:** which fixed magnitude rule applies to each expectation type, and
   who may define it without letting the measured object tune its own penalty?
7. **Cross-basin comparison:** should comparison be explicitly undefined unless predicate,
   unit, mechanism class, and deviation rule all match?
8. **Exposure admission:** which distinct test vectors and boundary snapshots are
   sufficiently non-duplicative to count as new falsification opportunities without
   converting an actor-role coordinate into actor trust?
9. **Independent implementation:** what evidence is sufficient to show that two checkers
   share no verdict-producing code?
10. **Ledger convergence:** how are concurrent append-only event branches, unavailable log
   heads, and resolver equivocation represented without a privileged mutable registry?
11. **`STALE` governance:** should `CoordinateStatus.STALE` and `ArtifactStatus.STALE` share
   one abstract event model while retaining separate transition functions and schemas?
12. **ZK trichotomy:** what bounded private witness structure lets the guest derive
   `Supported`, `Unknown`, and `Conflicted` rather than authenticate a caller's label?
13. **Observational evidence:** VSTD-3 device observations cannot be recreated from artifact
   bytes. What source testimony and attestation assumptions must a boundary snapshot expose
   without turning the observer's identity into verdict weight?
14. **Author is not actor:** if optional authorship is later marked inside artifact bytes,
    the mark changes the content digest. Should authorship instead use a detached,
    separately content-addressed statement, and what claim could it safely support?
15. **ZI declarative drift:** should the evaluator import a generated coordinate contract,
    or should a repository containment test require the model and code lists to agree?
16. **Operational controls:** how can anonymous admission control limit denial-of-service
    without becoming a correctness signal or a de facto identity requirement?

Round 2 takes the normative role and propagation directions as input but implements none
of these open mechanics. The next safe step is a bounded dual-direction event-ledger
experiment with no new wire identifier, followed separately by the ZK trichotomy
experiment once its derivation rule is specified.
