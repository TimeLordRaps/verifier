# Supply Chain Integrity, Transparency, and Trust (SCITT) semantic boundary for Verifier Standard (VSTD) interoperability

> **Acronyms:** Concise Binary Object Representation (CBOR); Concise Data Definition Language (CDDL); CBOR Object Signing and Encryption (COSE); grounded decision certificate (GDC);
> JavaScript Object Notation (JSON); Request for Comments (RFC); Secure Hash Algorithm 256-bit (SHA-256);
> Transparency Service (TS); verifiable data structure proof (VDP); verifiable data structure (VDS);
> working group (WG).

> **Status:** experimental, non-normative. This boundary follows [RFC 9943](https://datatracker.ietf.org/doc/html/rfc9943), [RFC 9942](https://datatracker.ietf.org/doc/html/rfc9942), and the current repository's implemented VSTD specifications. It does not claim SCITT WG review.

## SCITT can establish

Subject to the named trust anchors, keys, algorithms, VDS profile, registration
policy, receipt validity period, and relying-party checks, SCITT can establish:

- which exact Signed Statement bytes an issuer signed;
- the authenticated `iss` and `sub` protected claims and payload media type;
- that a TS applied its then-current registration policy before registration;
- that the Signed Statement was included in the TS's VDS state represented by a
  valid COSE Receipt;
- the VDS proof properties implemented by the Receipt profile, such as inclusion
  and, where supported, consistency;
- append-only/non-equivocation evidence and auditable registration history;
- enough registration collateral for authorized auditors to reproduce the
  registration checks required by RFC 9943;
- historical relationships such as later same-issuer/same-subject statements that
  a relying-party policy may treat as superseding earlier statements.

RFC 9943 is explicit that an issuer can make a false statement and that registration
only proves the statement was produced by the issuer. A SCITT Receipt is therefore
not a generic certificate of payload truth.

## VSTD can establish

VSTD is not the domain verifier or proof engine. It is the standard domain language
and operator/result layer through which those orchestrated substrates expose
portable claim boundaries and results. Only for its declared claim, coordinate,
evidence, policy, native verifier fragment, and resource bounds, the implemented
VSTD numbered profiles can establish:

- claim-mechanics and declared falsification conditions;
- an explicit verification surface and claim coordinate;
- substrate/accountability evidence within VSTD-3's implemented capability model;
- an accepted VSTD4-GDC-1 certificate result of PASS, FAIL, or UNKNOWN without
  upgrading it to VSTD-4 profile conformance;
- grounding between a bounded logical encoding and named artifact facts;
- checker-side recomputation of the VSTD-4 certificate without sharing verdict-producing
  code;
- a bounded cost/memory/certificate-size ceiling and honest refusal when exceeded;
- Graph lineage and blast-radius queries plus candidate degradation from statuses already
  recorded in GRAPH. This SCITT example does not invoke the evidence-bound Graph
  rating or challenge-projection mechanisms, so those results remain `NOT_ESTABLISHED`
  for this example.

The native solver, proof engine, signature checker, identity service, transparency
log, or provenance system retains its own semantics and result. A loss-declared
adapter maps that result into VSTD's verification interlingua and records the
boundary around its portable composition; VSTD does not absorb or reimplement the
substrate.

VSTD-5 and GRAPH-5 have implemented evidence-bound reference paths, but this SCITT
example supplies neither a qualifying witness nor profile-5 rating evidence. A later VSTD profile does not supply a missing
prerequisite coordinate.

## Identity, disclosure, trust, and reputation

VSTD verification is claim-first. Deciding a bounded claim does not, merely by
being a VSTD check, require a natural-person identity, creator identity, or
persistent actor identity. Some VSTD numbered and application profiles name devices, verifier
implementations, evidence sources, or witnesses where those coordinates are part
of the claim. Such identifiers do not automatically establish authorship,
authority, independence, reputation, or real-world identity.

SCITT composition is therefore **optional**, not a prerequisite for VSTD. An RFC
9943 Signed Statement introduces an authenticated issuer coordinate, and public
registration may expose stable identifiers, subjects, payload bytes or digests,
timing, and relationship metadata. A key or pseudonym need not identify a natural
person, but it can still be linkable. Wrapping a VSTD receipt in SCITT adds an
accountability/transparency proposition; it does not strengthen the native VSTD
computational proposition and can weaken an identity-minimizing privacy posture.

The implemented VSTD core is disclosure-neutral, not itself a zero-knowledge proof
protocol. Under the governing architecture, zero identity means zero identity-derived
verdict weight and zero knowledge means zero unevidenced knowledge is presumed. Neither
alone is a privacy claim. When a witness must remain confidential, a cryptographic
zero-knowledge proof can enclose that architectural rule by binding the exact program,
predicate, public commitments, output, parameters, and verifier. Full-disclosure receipts
remain valid, and no receipt may claim the cryptographic zero-knowledge property without a
real proof-system guarantee. “Trustless”
must mean trust-minimized and assumption-explicit: a relying party still depends on
selected algorithms, checker code, canonicalization, policy, input availability, and,
when used, proof-system parameters or trust roots.

GRAPH can preserve artifact history, challenges, lifecycle changes, and
refutations, but the current standard does not define a scalar artifact-reputation
score. The governing semantics instead distinguish TRUST, mechanism-earned artifact
support; ROT, typed time-indexed degradation of current admissibility; and RUST,
inverse-TRUST diagnostic traversal toward recorded ancestors. Their reference transfer
mechanisms must never overwrite a native verdict or turn actor identity, repeated
registrations, signatures, observations, age, or reputation into process validity.

## Neither establishes automatically

Neither a valid SCITT Receipt nor a valid VSTD receipt automatically establishes:

- truth of arbitrary physical-world or historical propositions;
- completeness of evidence that was never disclosed or discoverable;
- causal correctness or causal influence merely from recorded lineage;
- safety, harmlessness, fitness for purpose, or regulatory compliance;
- authorization, rights, ownership, or permission merely from identity or
  provenance;
- provenance merely from integrity or a matching digest;
- computational correctness merely from signature validity or registration;
- issuer independence, uniqueness, Sybil resistance, or lack of collusion;
- current validity merely from historical inclusion;
- correct policy selection merely because a policy identifier is present;
- privacy, anonymity, confidentiality, or unlinkability.

## Two receipts, two propositions

| Artifact | Native proposition |
|---|---|
| VSTD receipt | The declared bounded computational result and its evidence/refutation boundary. |
| SCITT COSE Receipt | A VDS property, normally inclusion of the exact Signed Statement under a TS identity and proof profile. |

The experimental profile places the first inside the payload of a SCITT Signed
Statement and attaches the second to that statement. Implementations must name the
receipt type whenever “receipt” would be ambiguous.

The unwrapped VSTD receipt remains checkable outside its producer. Selecting the SCITT
profile deliberately adds issuer and transparency coordinates; it is not the
default wire path for an identity-independent or witness-private VSTD profile.

## Trust coordinates that must remain visible

### SCITT

- issuer key/certificate and identity interpretation;
- TS receipt-verification key and TS identity;
- VDS/VDP profile and algorithm;
- registration policy and policy version/state;
- statement subject and content type;
- registration/receipt time and freshness policy;
- key-compromise, supersession, revocation, and discovery policy;
- external native verifier implementation/version.

### VSTD

- claim, subject, predicate, and parameters;
- policy root and evidence root;
- artifact identities and content digests;
- verifier specification, implementation, parser, and supported fragment;
- resource bounds and prior commitment;
- certificate format, verdict, reason, and native lifecycle status;
- evidence availability, challenges, and graph ancestors when applicable.

## Composition rule

A composed PASS is permitted only when all of the following hold:

1. the native VSTD checker accepts a VSTD PASS without sharing verdict-producing code;
2. the full VSTD payload digest matches the payload signed in the SCITT statement;
3. the SCITT statement signature is valid under an accepted issuer policy;
4. the SCITT Receipt is valid for that exact statement under an accepted TS/VDS
   policy;
5. the SCITT subject equals the VSTD claim-coordinate subject;
6. the observed artifact digests equal the VSTD-bound artifact digests;
7. the required evidence is current and neither revoked, superseded, conflicted,
   missing, nor unavailable under the declared relying-party policy.

Any single failed condition prevents PASS. Registration never repairs a failed VSTD
claim. A VSTD PASS never fabricates missing SCITT transparency.

## UNKNOWN and lifecycle behavior

SCITT core does not define one application-level UNKNOWN verdict. The individual
[Composite Evidence Verification draft](https://datatracker.ietf.org/doc/draft-nobuo-scitt-composite-evidence-verification/)
proposes `unknown`, `missing`, `stale`, `conflict`, and `warning`, but it is not an
adopted WG standard and its result precedence remains draft work.

VSTD UNKNOWN is bounded and reason-bearing. In VSTD-4, resource exhaustion,
unavailable dependencies, unavailable verifiers, and unretrievable artifacts have
distinct indeterminacy reasons. Therefore adapters must preserve both the native
SCITT condition and native VSTD reason. Label equality alone is not semantic
equivalence.

Historical SCITT inclusion may remain valid while current VSTD usability falls. For
example, a receipt can still prove that a statement was registered in the past even
after a relying party considers its evidence stale or an ancestor revoked. The
adapter records both facts rather than deleting history or treating inclusion as
current computational validity.

## Implementation boundary

The module in `src/verifier/interoperability/scitt/`:

- emits deterministic application payload bytes and a normalized registration
  template;
- does **not** claim that JSON is the SCITT serialized transport format;
- requires a native RFC 9943/COSE producer to create a real Signed Statement;
- requires a native RFC 9942 verifier to validate a COSE Receipt;
- consumes the native verifier's output only under explicit issuer, subject, payload,
  policy, TS, and VDS coordinates;
- requires a separately bound native VSTD checker result for the exact embedded
  receipt; a receipt's declared `PASS` is not evidence that it was checked;
- returns `computational_verdict = NOT_EVALUATED` when adapting SCITT evidence alone;
- rejects unknown mappings instead of guessing.

The example uses pinned optional libraries to create and verify real COSE bytes and
an RFC 9162 SHA-256 inclusion receipt in a local one-entry test log. That demonstrates
the cryptographic boundary but does not represent a production TS, public witness,
or public anchoring.

## Composite-evidence comparison

The following comparison is against the **individual**, non-adopted
`draft-nobuo-scitt-composite-evidence-verification-00`, the revision pinned by
`src/verifier/interoperability/scitt/evidence_profiles.py`. Its CDDL is explicitly
provisional. The implemented adapter preserves its result code but always returns
`computational_verdict = NOT_EVALUATED`. The pin identifies the draft text that the
tests exercise; it is not a statement about later revisions or about the draft's
current standing.

| Surface | Composite-evidence draft | VSTD / GRAPH | Interoperability rule |
|---|---|---|---|
| Statements | Signed Statements and statement-level results | Native receipts/certificates and their bound checker observations | Preserve both native objects and digests; a registered statement is not a checked VSTD receipt. |
| Evidence bundles | Portable statements, receipts, graph manifest, related bundles, time and digest | Receipt collections and graph artifacts | Do not relabel one bundle format as the other; reference by digest until a profile is agreed. |
| Relationships | Profile-controlled graph edges and statements-about-statements | Typed provenance/dependency/challenge edges | Edge-name similarity is insufficient; require an explicit relation crosswalk. |
| Profiles | Named issuer, type, freshness, relationship and conflict policy | Verifier descriptor, supported fragment, policy/evidence roots and bounds | Bind both profile identifiers; neither subsumes the other. |
| Dependencies | Required statement types and graph edges | Transitive ancestors and required evidence | Missing dependency remains incomplete/UNKNOWN; registration of the remaining graph cannot close it. |
| Revocation | Proposed revocation statements plus issuer authorization policy | Lifecycle state and graph degradation | Preserve historical inclusion; separately lower current admissibility. |
| Supersession | Proposed supersession statements | `SUPERSEDED` without automatic truth ordering | Newer is not automatically truer; relying policy must choose. |
| Conflicts | Explicit `conflict` result under selected policy | `CONFLICTED` where evidence cannot be reconciled | Preserve as distinct from both UNKNOWN and FAIL. |
| Freshness | `stale` result under profile freshness rules | Time-indexed evidence and graph staleness | A historically valid receipt can coexist with currently stale evidence. |
| Completeness | Discovery is not assumed complete; unknown/warning unless a profile permits a closed world | Required evidence and bounded dependency checks | State the discovery/closed-world assumption; absence from a bundle is not proof of absence. |
| Warning | Mandatory profile checks satisfied with a surfaced condition | A warning cannot supply a missing VSTD prerequisite or verdict | Preserve warning; do not promote it to VSTD PASS. |
| Unknown | Unavailable evidence or unrecognized profile | Bounded inability with reason-bearing certificate/state | Labels are not equivalent; carry cause (`UNAVAILABLE`, `UNSUPPORTED_VERIFIER`, or bounded `NOT_ESTABLISHED`). |
| Graph degradation | Proposed per-node/edge results and whole-profile outcome | Recomputed lineage, blast radius, and candidate degradation without rewriting history | Report both historical SCITT registration and current VSTD evidence ceiling. |
| Disclosure-bounded verification | Evidence bundle may be intentionally bounded; completeness policy decides treatment | Claim/bounds/exclusions are first-class | Any undisclosed or undiscoverable requirement stays UNKNOWN; do not infer a closed world. |

### Distinct conditions that must not collapse

| Condition | Safe interoperable representation |
|---|---|
| Unavailable evidence | `UNAVAILABLE`; computational verdict not established. |
| Incomplete evidence | `INCOMPLETE`; required material is missing. |
| Stale evidence | `STALE`; historical integrity may remain valid. |
| Conflicting evidence | `CONFLICTED`; do not select a winner silently. |
| Revoked evidence | `REVOKED`; retain historical inclusion separately. |
| Unsupported verifier/profile | `UNSUPPORTED_VERIFIER`; do not guess semantics. |
| Computational budget exhaustion | `BUDGET_EXHAUSTED`; a bounded VSTD UNKNOWN, not a SCITT transport error. |
| Bounded inability to establish predicate | `BOUNDED_NOT_ESTABLISHED`; no global undecidability claim. |
| Explicit falsification | `EXPLICITLY_FALSIFIED`; do not weaken to generic unknown. |

`src/verifier/interoperability/scitt/evidence_profiles.py` implements this typed
boundary and rejects extension result strings rather than guessing.

## Derived Subjects boundary

The implementation is pinned to the individual `draft-le-scitt-derived-subjects-00`
(`DRAFT_REVISION` in `src/verifier/interoperability/scitt/derived_subjects.py`).
`tests/test_scitt_derived_subjects.py` exercises the Appendix A.1 through A.7
known-answer and negative vectors as transcribed there: the JSON vectors always, and
the deterministic CBOR vectors where the optional `cbor2` dependency of the `scitt`
extra is installed. The vectors are transcribed constants, not fetched from the draft,
so a later change to the draft would not be detected by the tests.

The implementation computes:

```text
Value -> BindingBytes -> SHA-256 ->
scitt-derived-subject-v1.<unpadded-base64url-digest>
```

VSTD maps its exact subject string to `content`, uses a fixed mapping context, and
encodes each `(artifact role, SHA-256 digest)` as a scoped identifier. This gives:

- the same semantic subject/artifact set -> deterministic equal `sub`;
- a different artifact or role -> different `sub`;
- ambiguous comparison semantics or an unknown draft/mapping revision ->
  `NOT_ESTABLISHED`;
- a malformed value that claims the profile prefix -> input error, not UNKNOWN.

**Exact counterexample to a complete-coordinate mapping:** change only the VSTD
predicate parameters from `mode=exact` to `mode=prefix`. The subject and artifact
are still the same, so the Derived Subject `sub` correctly remains equal. The VSTD
claim coordinate is meaningfully different. Therefore `sub` cannot replace the
VSTD claim-coordinate binding. The experimental binding carries separate SHA-256
commitments for `(claim_id, subject, predicate, parameters, artifacts)` and for the
verification bounds; either change yields `NO_MATCH` even when `sub` is unchanged
(`test_parameter_change_does_not_redefine_subject_but_full_binding_fails` and
`test_bound_change_is_not_silently_equivalent`).

This is a useful composition, not a forced equivalence: Derived Subjects groups
statements about one subject; VSTD still decides which exact computational claim
and bound were evaluated.

## Transformation and coverage-reconciliation boundary

The implementation is pinned to the individual
`draft-dogru-scitt-disclosure-evidence-07`:

| Draft state | VSTD-safe interpretation |
|---|---|
| `matched` | An item corresponded under the declared mapping/window; not proof either population is complete. |
| `observed-without-receipt` | Evidence absence; cause is not established. |
| `receipted-without-observation` | Evidence mismatch; not automatically fraud or a false event. |
| `excluded` | A pinned pre-comparison decision; visible and reproducible, not justified by its digest. |
| `indeterminate` | A result that must remain undecided; never a degraded match or percentage. |
| `invalid-window` | Window evidence is unreliable; no clean result. |

The adapter rejects `coverage-reconciliation/1`: `/1`'s `covered` vocabulary cannot
be upgraded to `/2`. It verifies counts against non-matched item records and rejects
`no-exceptions` when any open item exists. Even a valid `/2` `no-exceptions` result
returns `NOT_EVALUATED` for a VSTD predicate because neither compared population is
assumed complete.

The adversarial transformation fixture is deliberately simple: a structurally
valid Transformation Evidence object asserts `mask` for one `customer-id`, while the
separately observed disclosure still contains the unmasked value. Structural
validation leaves the transformation at `ISSUER_ASSERTED`. Signing or registering
the object would not change that, because registration shows what the issuer
produced, not that the transformation was applied; only a separate byte-level
verifier could establish that. Thus registered transformation evidence is not
computational truth or proof of non-exposure.
