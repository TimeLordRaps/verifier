# Verifier Standard (VSTD) and Internet Engineering Task Force (IETF) Supply Chain Integrity, Transparency, and Trust (SCITT): experimental interoperability crosswalk

> **Acronyms:** artificial intelligence (AI); application programming interface (API);
> Concise Binary Object Representation (CBOR); Confidential Consortium Framework (CCF);
> CBOR Object Signing and Encryption (COSE); CBOR Web Token (CWT); European Union (EU);
> grounded decision certificate (GDC); Hypertext Transfer Protocol (HTTP); Request for Comments (RFC);
> Supply Chain Integrity, Transparency, and Trust (SCITT); SCITT Reference APIs (SCRAPI); Transparency Service (TS);
> verifiable data structure proof (VDP); verifiable data structure (VDS); working group (WG); zero-knowledge (ZK).

> **Status:** experimental, non-normative, reviewed against public specifications on
> 2026-08-25. This document does not alter VSTD semantics and does not imply IETF,
> SCITT Working Group, or implementation-provider endorsement.

## Result

The working thesis survives with one important correction:

> **SCITT authenticates statements and makes their policy-governed registration in a
> verifiable data structure transparent and portable. VSTD is a standard domain
> language for verification: an interlingua that standardizes the claim boundary and
> portable result semantics by which a domain verifier or proof engine's bounded
> result is represented, binding-checked, refuted, mapped, and composed with adjacent
> evidence.**

SCITT is not merely transport. It already specifies issuer/subject binding, signed
statements, registration-policy evaluation, append-only and non-equivocating
transparency, portable COSE receipts, and replayable registration audits. VSTD must
not rename those mechanisms as VSTD inventions. Conversely, SCITT explicitly allows
false statements to be registered and leaves payload truth to application-domain
semantics. VSTD does not replace those application-domain semantics or engines. It
is the general operator-language class; native verifiers, proof engines, and other
evidence substrata are the orchestrated implementations whose own outputs and limits
remain authoritative and visible. Explicit adapters make the mapping and any loss
reviewable. That is the clean VSTD-shaped boundary.

## Sources and exact status

| Document | Status on 2026-08-25 | Relevance |
|---|---|---|
| [RFC 9943: SCITT Architecture](https://datatracker.ietf.org/doc/html/rfc9943) | IETF Standards Track RFC, **Proposed Standard**, June 2026 | Normative SCITT architecture, Signed Statements, Registration, Receipts, Transparent Statements, and security boundary. |
| [RFC 9942: COSE Receipts](https://datatracker.ietf.org/doc/html/rfc9942) | IETF Standards Track RFC, **Proposed Standard**, June 2026 | COSE Receipt wrapper, VDS/VDP registries, RFC 9162 inclusion and consistency proof encodings. |
| [draft-ietf-scitt-scrapi-11](https://datatracker.ietf.org/doc/html/draft-ietf-scitt-scrapi-11) | **Active SCITT WG Internet-Draft**, intended Proposed Standard, in the RFC Editor Queue; not yet an RFC | HTTP registration, asynchronous completion, receipt resolution, and TS key discovery. |
| [draft-ietf-scitt-receipts-ccf-profile-04](https://datatracker.ietf.org/doc/html/draft-ietf-scitt-receipts-ccf-profile-04) | **Active SCITT WG Internet-Draft**, intended Proposed Standard, in IETF Last Call through 2026-09-07; not an RFC | CCF ledger VDS and inclusion-proof profile for COSE Receipts. |
| [draft-nobuo-scitt-composite-evidence-verification-00](https://datatracker.ietf.org/doc/draft-nobuo-scitt-composite-evidence-verification/) | **Active individual Internet-Draft**, no WG adoption or formal standing | Closest work: composite verification of statements, receipts, bindings, relationships, freshness, conflicts, and bundles under a named profile. |
| [draft-nobuo-scitt-protected-object-binding-00](https://datatracker.ietf.org/doc/draft-nobuo-scitt-protected-object-binding/) | **Active individual Internet-Draft**, no WG adoption or formal standing | Proposed object bindings and statement-graph relationships; explicitly does not establish payload truth. |
| [draft-emirdag-scitt-ai-agent-execution-00](https://datatracker.ietf.org/doc/html/draft-emirdag-scitt-ai-agent-execution-00) | **Active individual Internet-Draft**, no stream or WG adoption; its draft header says intended Informational | Agent-execution records, sequence completeness, evidence custody, and redaction receipts. |
| [draft-noa-scitt-ai-agent-receipt-01](https://datatracker.ietf.org/doc/html/draft-noa-scitt-ai-agent-receipt-01) | **Active individual Internet-Draft**, no stream or WG adoption; its draft header says Standards Track | Per-action receipt profile with narrow claims, validity/sufficiency separation, absence/indeterminacy semantics, and explicit external-world limits. |
| [draft-dawkins-scitt-ai-article50-00](https://datatracker.ietf.org/doc/html/draft-dawkins-scitt-ai-article50-00) | **Active individual Internet-Draft**, no stream or WG adoption | AI-transparency receipt profile for selected EU AI Act Article 50 disclosure claims. |
| [draft-mih-scitt-agent-action-capsule-02](https://datatracker.ietf.org/doc/html/draft-mih-scitt-agent-action-capsule-02) | **Active individual Internet-Draft**, no stream or WG adoption | Agent Action Capsule payload profile separating dispatched attempts, observed results, and human-in-the-loop records. |
| [draft-mih-scitt-agent-action-capsule-sel-disc-00](https://datatracker.ietf.org/doc/html/draft-mih-scitt-agent-action-capsule-sel-disc-00) | **Active individual Internet-Draft**, no stream or WG adoption | Selective-disclosure construction and missing-required-field behavior for Agent Action Capsules. |
| [draft-hillier-scitt-arp-03](https://datatracker.ietf.org/doc/html/draft-hillier-scitt-arp-03) | **Active individual Internet-Draft**, no stream or WG adoption | Attestation reconciliation, query binding, divergence axes, policy coordinates, and budget-exhaustion concerns. |
| [draft-dogru-scitt-disclosure-evidence-07](https://datatracker.ietf.org/doc/html/draft-dogru-scitt-disclosure-evidence-07) | **Active individual Internet-Draft**, no stream or WG adoption | Transformation evidence and coverage reconciliation, including excluded and indeterminate coverage outcomes. |
| [draft-le-scitt-derived-subjects-00](https://datatracker.ietf.org/doc/html/draft-le-scitt-derived-subjects-00) | **Active individual Internet-Draft**, no stream or WG adoption | Deterministic subject derivation across independently governed identifier schemes. |
| [draft-mih-sokolov-scitt-payload-binding-01](https://datatracker.ietf.org/doc/html/draft-mih-sokolov-scitt-payload-binding-01) | **Active individual Internet-Draft**, no stream or WG adoption | Canonical payload binding and cross-profile digest references; appraisal remains in consuming profiles. |

Internet-Drafts are work in progress. The individual drafts above are proposals by
their authors, not IETF or SCITT WG positions. Earlier draft revisions that have been
replaced or expired were not used as current authority. None of the documents relied
on in this table is expired as of the review date.

## Architecture decision

The cleanest arrangement is **optional bidirectional composition with separate
verdicts**. SCITT is not a prerequisite for VSTD and is not the default publication
path for an identity-independent or witness-private VSTD profile:

1. **VSTD inside SCITT:** a complete VSTD receipt is the application payload of an
   RFC 9943 Signed Statement. The SCITT protected headers bind issuer, subject,
   content type, and signature. A COSE Receipt proves registration/inclusion under
   the selected TS, VDS, registration policy, key, and time assumptions.
2. **SCITT evidence inside VSTD:** output from a native SCITT verifier may be VSTD
   evidence for a narrowly stated transparency proposition, such as “this exact
   statement was signed by an accepted issuer and included in this TS VDS under this
   policy.” It is not evidence that silently settles the statement's computational
   payload. SCITT is one orchestrated substrate, not a privileged source of truth.
3. **Graph composition:** a SCITT statement-graph profile may identify registered
   statements, object bindings, edges, supersession, and conflicts. VSTD-Graph can
   evaluate bounded predicates over selected nodes and edges, but each graph's
   native identifiers, status semantics, and policy remain visible.

This is not recursive self-certification. SCITT and VSTD remain adjacent layers with
different trust roots and different questions. Selecting SCITT deliberately adds
issuer authentication, registration policy, transparency, and possible correlation;
omitting SCITT leaves those properties unclaimed rather than making them UNKNOWN
VSTD computational evidence.

## Rigorous crosswalk

| Concern | VSTD | SCITT | Overlap | Difference | Composition |
|---|---|---|---|---|---|
| Claim identity | Receipt and claim identifiers; VSTD-4 binds a claim string and coordinate. | Signed Statement bytes plus issuer/subject and payload media type identify a statement context. | Both bind an assertion to named coordinates. | SCITT identity is signed-statement identity; VSTD identity includes bounded computational semantics. | Carry the native VSTD receipt intact and bind its full payload digest in the SCITT statement. |
| Actor identity | A bounded artifact claim need not identify a natural person, creator, or persistent actor; layer-specific device/verifier/witness identifiers do not imply authorship or authority. | A Signed Statement authenticates a declared issuer under a relying-party trust policy; the issuer can be a key or pseudonym but may be linkable. | Both may bind identifiers when the declared proposition needs them. | SCITT issuer authentication is central to accountability; actor identity is not required for every VSTD computation. | Make SCITT wrapping optional and never copy issuer reputation into the native VSTD verdict. |
| Disclosure / zero knowledge | Core VSTD is disclosure-neutral; current receipts may disclose evidence, and experimental ZK profiles must supply real proof-system guarantees. | Registration makes signed statement material or commitments available under TS policy and can expose timing, subjects, and relationships. | Either can carry commitments or proofs defined by an application profile. | Neither RFC 9943 nor current VSTD core automatically provides witness confidentiality, anonymity, or unlinkability. | Treat privacy effects as an explicit profile property; do not label this full-disclosure example ZK or zero identity. |
| Artifact reputation / trust | Graph history can record challenges, staleness, supersession, revocation, and refutation; no normative scalar reputation score exists. | Logs provide durable registration history and issuer accountability, not payload reputation or truth. | Both can contribute time-indexed observations about one artifact. | Repetition and age do not increase epistemic strength by themselves. | A future reputation/rust view must be separately derived, policy-bound, and unable to upgrade native results. |
| Subject identity | VSTD-2/VSTD-4 coordinate `subject`. | Protected CWT `sub` claim; issuer-defined and usable to correlate statements. | Both name what a claim is about. | Equal spelling does not prove equal interpretation. | Require exact subject equality under the experimental profile; reject mismatch. |
| Predicates | Explicit VSTD predicate and parameters. | Payload/application profile defines predicate semantics; SCITT core is content-agnostic. | A VSTD predicate can be a SCITT payload predicate. | SCITT core does not define the VSTD predicate. | Preserve predicate and parameters in the payload projection and full receipt. |
| Parameters | Bound into VSTD claim coordinates and canonical receipt. | May appear in opaque payload or profile-defined protected fields. | Both can integrity-bind parameters. | SCITT has no generic computational-parameter semantics. | Keep parameters in VSTD payload; only promote selected values to protected headers after profile review. |
| Explicit limits | VSTD claim limitations, excluded claims, and refutation surface. | RFC 9943 states architectural/security limits; application payload profiles may add limits. | Both can document scope. | VSTD makes per-result bounds part of verification semantics. | Carry VSTD limits without translating them into SCITT registration-policy claims. |
| Issuer identity | May occur in provenance, but VSTD core does not replace signing identity infrastructure. | Protected `iss`; signature and trust-anchor validation are mandatory registration concerns. | Both may record a producer. | SCITT owns signed issuer authentication; VSTD ownership/authorship is not inferred from integrity. | Reuse SCITT issuer authentication and keep it separate from VSTD computational outcome. |
| Signatures | VSTD can consume signature evidence; it does not define a universal signing system. | COSE_Sign1 is normative for Signed Statements and Receipts. | VSTD can reference verified signature evidence. | SCITT already standardizes the envelope and signature placement. | When the SCITT profile is selected, use SCITT/COSE rather than inventing a competing envelope. |
| Artifact binding | VSTD binds content-addressed subjects/evidence roots and checks wrong-artifact cases. | `sub`, payload hashes/detached payloads, and signed envelope bind statements to declared artifacts. | Both defend substitution at different layers. | SCITT proves what bytes/subject the issuer signed, not that VSTD evaluated the intended artifact correctly. | Require exact VSTD artifact digests and SCITT payload digest; either mismatch fails composition. |
| Statement registration | Not a VSTD core function. | TS applies registration policy, inserts the statement, and issues a receipt. | None needed. | SCITT already owns this layer. | VSTD should consume the result, not recreate registration. |
| Transparency | VSTD can record published artifacts but defines no generic transparency service. | Core objective: auditable, accountable signed-content transparency. | VSTD receipts are suitable transparent payloads. | SCITT provides the standardized transparency machinery. | Register through SCITT when public accountability is desired; do not require it for identity-independent/private verification. |
| Append-only logs | VSTD-Graph records additive challenge history but is not a general public log protocol. | SCITT VDS must be append-only, non-equivocating, and replayable. | Both avoid rewriting history. | SCITT defines the log/VDS guarantees and receipts. | Use SCITT VDS rather than a VSTD-specific transparency log. |
| Portable receipts | VSTD receipts carry computational evidence and bounds. | COSE Receipts carry signed VDS proofs and attach to Transparent Statements. | Both produce portable evidence artifacts. | “Receipt” names different proof targets. | Name both explicitly: VSTD computational receipt inside a SCITT Signed Statement; SCITT COSE Receipt outside it. |
| Evidence bundles | VSTD receipts and graph collections may contain evidence references. | Core permits payloads; composite-evidence draft proposes bundles under profiles. | Both can package evidence sets. | The SCITT bundle model is currently an individual proposal, not a WG standard. | Use a VSTD payload now; discuss bundle alignment before standardizing graph exchange. |
| Provenance graphs | VSTD-Graph records typed artifact/transformation lineage and computes candidate degradation from statuses already recorded in the Graph. | RFC 9943 correlates statements by subject; individual drafts propose object bindings and statement graphs. | Both can connect evidence about shared subjects. | SCITT core does not standardize the proposed statement-graph vocabulary; VSTD lineage is not causal proof. | Reference native SCITT statement IDs from VSTD-Graph without rewriting either graph. |
| Statement graphs | VSTD-Graph has implemented graph structures, policy queries, and candidate-level computation over caller-supplied ratings; conformance is `NOT_ESTABLISHED`. | Proposed by individual object-binding/composite drafts. | Both need explicit edge semantics and policy. | Maturity and graph objects differ. | Experimental bridge only; no claim of SCITT WG alignment. |
| Dependencies | VSTD-4 can return `UNKNOWN/DEPENDENCY_UNAVAILABLE`; Graph evaluates transitive ancestors. | Composite draft proposes required statements and dependency edges. | Both surface unavailable dependencies. | SCITT core receipt validity does not settle application dependency completeness. | Preserve the native missing reason and let VSTD issue its own bounded indeterminacy certificate. |
| Revocation | The challenge ledger can derive claim state. Graph candidate computation degrades when an ancestor already records `REVOKED`. No adapter binds the first result into the second, so challenge-to-Graph propagation is `NOT_ESTABLISHED`. | RFC 9943 discusses compromised-key handling but leaves revocation strategies out of scope; individual composite draft proposes revocation statements/checks. | Both can react to invalidated evidence. | Neither SCITT core nor current VSTD supplies the missing cross-surface propagation mechanism. | Preserve each native state. A future adapter must bind the exact claim, artifact, event, and policy before a relying party changes Graph state. |
| Supersession | VSTD-Graph records `SUPERSEDED` without automatically making the older node inadmissible. | RFC 9943 permits later same-issuer/same-subject statements to supersede earlier ones; selection is relying-party policy. | Both preserve history. | Neither makes “newer” automatically “truer”; policy consequences differ. | Normalize `SUPERSEDED` without upgrading; require explicit current-evidence policy. |
| Conflicts | VSTD preserves `CONFLICTED` where defined and graph blockers. | RFC 9943 allows conflicting issuers; individual composite draft proposes `conflict`. | Both refuse silent reconciliation. | SCITT core delegates issuer selection; VSTD may express a bounded conflict result. | Preserve `CONFLICTED` as distinct from UNKNOWN and FAIL. |
| Freshness | VSTD bounds and evidence can include time/freshness; stale graph artifacts are inadmissible at higher graph levels. | Receipt state is true when issued; keys/policies can change; application policies determine freshness. SCRAPI can issue fresh receipts. | Both require time-indexed trust coordinates. | Inclusion is historical; it does not establish current payload validity. | Carry registration time, policy, key/VDS, and freshness decision separately. |
| Verification profiles | VSTD layers and verifier descriptors define supported fragments. | RFC 9942 defines VDS profiles; RFC 9943 permits application profiles; composite draft proposes named verification profiles. | Both use explicit capability/profile identifiers. | VDS proof profile is not computational predicate profile. | Bind both profile identifiers; never collapse them. |
| Resource bounds | VSTD-4 preflights verification cost, memory, and certificate size. | SCITT core has operational limits but no payload-domain computational-verdict resource model. | Both can reject over-limit inputs operationally. | SCRAPI 429/204 is protocol state, not epistemic UNKNOWN. | Keep VSTD bounds in payload and preserve resource exhaustion as VSTD UNKNOWN. |
| Computational grounding | VSTD-4 binds variables/clauses to facts, subjects, rules, policy/evidence roots, and verifier code. | SCITT can register such a payload but does not define those semantics. | SCITT can integrity-protect grounding artifacts. | Grounding correctness is distinctively VSTD here. | SCITT carries and makes the grounded certificate transparent; VSTD kernel checks it. |
| Reproduction | VSTD declares reproduction levels and executable falsification paths. | SCITT auditors reproduce registration checks from retained statements, collateral, policy, and trust anchors. | Both support independent replay. | They replay different decisions. | Report `VSTD_CHECK_REPLAY` and `SCITT_REGISTRATION_REPLAY` separately. |
| Checker separation | VSTD has a small checker isolated from verdict-producing code. | SCITT relying parties verify issuer signatures and COSE Receipts offline; auditors check VDS consistency. | Both support separately executable checks. | The checked proposition differs, and neither mechanism alone establishes distinct producer/checker actors. | Demonstrate both checks in sequence, retain both native results, and reserve “independently verified” for evidence-bound actor and execution separation. |
| Counterexamples | VSTD FAIL can carry a counterexample or refutation certificate. | SCITT receipt invalidity can carry verification failure, but core does not define domain counterexamples. | Both can expose detected failure. | A bad inclusion proof is not a counterexample to payload truth. | Keep SCITT integrity failure and VSTD predicate refutation as typed failures. |
| PASS | Bounded proposition accepted with its required certificate/evidence. | Core SCITT has verified signature/receipt/registration, not a generic application `PASS`; the individual composite draft proposes profile `pass`. | Both can have successful checks. | The success domains are not equivalent. | Composed PASS requires native VSTD PASS and exact current SCITT verification; SCITT alone never creates it. |
| FAIL | Evidenced predicate violation or rejected certificate, depending on the VSTD result surface. | Signature, receipt, inclusion, policy, or profile verification can fail. | Both can detect concrete failures. | Failure reasons apply to different layers. | Preserve native reason codes and identify which layer failed. |
| UNKNOWN | Bounded inability to decide, with VSTD-4 indeterminacy evidence. | No core RFC application verdict; individual composite draft uses `unknown` for unavailable evidence or unrecognized profile and separates missing/stale/conflict. | Both reject guessing. | They are not semantically equivalent. | See the taxonomy below; map by reason, never by label alone. |
| Warnings | VSTD warnings cannot silently supply a missing layer or verdict. | Individual composite draft proposes `warning` when mandatory checks pass but a condition is surfaced. | Both can retain nonfatal findings. | A warning's acceptability is profile-specific. | Preserve warnings; do not map warning to VSTD PASS without full native VSTD verification. |
| Cost/work claims | VSTD binds/checks verification work and receipt size at VSTD-4. | SCITT proves VDS properties; its protocol latency/status does not prove application checking cost. | Receipts can carry cost claims as payload data. | SCITT has no generic proof of VSTD work. | Carry the VSTD bound and checker result as payload semantics. |
| Graph degradation | VSTD-Graph recomputes levels and blast radius without mutating history. | SCITT core preserves log history; individual graph draft proposes revocation/supersession/conflict checks. | Both favor additive history. | SCITT inclusion remains true even if a payload becomes disfavored; VSTD evidence ceiling may fall. | Keep historical inclusion true while lowering the current VSTD composition result. |
| Real-world truth vs evidence validity | VSTD explicitly limits arbitrary truth claims to its declared evidence and predicate. | RFC 9943 states registration only proves the statement was produced by an issuer; issuers may be false. | Strong agreement on non-upgrade. | VSTD additionally specifies a checkable bounded computational proposition. | This is the central composition boundary. |

## UNKNOWN is not one shared enum

| Condition | SCITT core / draft treatment | VSTD treatment | Composition |
|---|---|---|---|
| Evidence unavailable | Core receipt may remain historically valid; individual composite draft: `unknown` or `missing`. | `UNKNOWN/DEPENDENCY_UNAVAILABLE` or `ARTIFACT_UNRETRIEVABLE` when relevant. | UNKNOWN with both native reasons. |
| Incomplete bundle | Not a core RFC verdict; composite draft: `missing`. | UNKNOWN if required VSTD evidence is absent. | UNKNOWN, never PASS from registration alone. |
| Resource budget exhausted | SCRAPI 204/429 are protocol/operation states, not application truth. | `UNKNOWN/PROOF_BOUND_EXCEEDED` or `DEPTH_BOUND_EXCEEDED`. | Preserve VSTD UNKNOWN even if the statement is registered. |
| Predicate not established within the declared bound | SCITT core has no payload-domain undecidability result; the individual composite draft's `unknown` is profile/evidence-oriented. | A bounded VSTD check remains UNKNOWN with the native verifier reason; it is not proof that the predicate is globally undecidable. | Preserve the bounded inability to establish, without widening it into global undecidability or narrowing it into FAIL. |
| Unsupported verification method/profile | A relying party cannot verify; composite draft: `unknown` for unrecognized profile. | `UNSUPPORTED` or `UNKNOWN/VERIFIER_UNAVAILABLE`, depending on layer. | UNKNOWN or explicit UNSUPPORTED; no guess. |
| Conflicting evidence | RFC 9943 permits conflicting statements; relying-party selection is external. Composite draft: `conflict`. | `CONFLICTED` where applicable. | CONFLICTED, not generic UNKNOWN. |
| Stale evidence | Application policy; composite draft: `stale`. | `STALE` graph status or a bounded freshness failure. | Retain STALE and cap current composition. |
| Revoked ancestor/key | Key-compromise response is discussed; universal revocation strategy is out of scope. | A recorded `REVOKED` ancestor lowers the Graph candidate and exposes blast radius; no challenge-to-Graph mutation is implemented. | Preserve historical inclusion and both native states; change current VSTD admissibility only through an explicit binding policy. |
| Failed proof | Invalid SCITT signature/receipt/inclusion is concrete integrity failure. | Invalid decision certificate or evidenced counterexample is FAIL/rejection. | FAIL at the failing layer, not UNKNOWN. |

## What SCITT already does well

- COSE Signed Statements and Receipt attachment.
- Protected issuer and subject coordinates.
- Registration policies and auditable policy history.
- Append-only, non-equivocating VDS requirements.
- Portable, offline-verifiable inclusion receipts.
- Registration/receipt APIs through the active SCRAPI WG draft.
- Multiple issuers, multiple TSs, and historical supersession without claiming
  arbitrary payload truth.

VSTD should reuse these mechanisms rather than define another signature envelope,
transparency log, receipt-attachment convention, or registration API.

## Current overlap and the narrower VSTD contribution

Several active **individual** SCITT drafts now address concerns that must not be
marketed as uniquely VSTD: narrow claim boundaries, validity versus sufficiency,
missing/stale/conflicted evidence, statement graphs, evidence bundles, selective
disclosure, canonical payload binding, coverage reconciliation, and typed
application-profile outcomes. They remain work in progress without WG adoption, but
their technical overlap is real.

The narrower contribution demonstrated by the current VSTD implementation is not a
new domain prover. It is a standard domain language and operator/result layer over
orchestrated native verifier instances:

- one domain-general claim coordinate for a computational predicate and parameters;
- an implemented `VSTD4-GDC-1` grounded decision certificate binding proof variables
  and clauses to named facts, subjects, policy/evidence roots, verifier code, and
  resource ceilings;
- a small checker isolated from verdict-producing code that returns evidence-bearing PASS, FAIL, or bounded
  UNKNOWN and refuses over-budget work before proof replay;
- separate refutation/challenge and Graph candidate-degradation mechanisms, with
  cross-axis propagation explicitly `NOT_ESTABLISHED`; and
- an adapter that requires separately bound native VSTD and native SCITT verifier
  results, so neither declared payload success nor registration can create PASS.

These are implementation and composition distinctions, not a claim that nobody else
has proposed related semantics.

## Positioning sentence

> **SCITT can authenticate and make a VSTD receipt's registration transparently
> auditable; VSTD supplies the verification interlingua that preserves the bounded
> claim boundary and portable result semantics of the native verifier or proof engine
> that produced the result.**
