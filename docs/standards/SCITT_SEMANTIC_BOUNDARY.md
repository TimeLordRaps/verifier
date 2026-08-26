# Supply Chain Integrity, Transparency, and Trust (SCITT) semantic boundary for Verifier Standard (VSTD) interoperability

> **Acronyms:** Concise Binary Object Representation (CBOR); CBOR Object Signing and Encryption (COSE); grounded decision certificate (GDC);
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
VSTD layers can establish:

- claim-mechanics and declared falsification conditions;
- an explicit verification surface and claim coordinate;
- substrate/accountability evidence within VSTD-3's implemented capability model;
- an accepted VSTD4-GDC-1 certificate result of PASS, FAIL, or UNKNOWN without
  upgrading it to VSTD-4 layer conformance;
- grounding between a bounded logical encoding and named artifact facts;
- checker-side recomputation of the VSTD-4 certificate without sharing verdict-producing
  code;
- a bounded cost/memory/certificate-size ceiling and honest refusal when exceeded;
- Graph lineage and blast-radius queries plus candidate degradation from statuses already
  recorded in VSTD-Graph. Rating evidence and challenge-to-Graph propagation remain
  `NOT_ESTABLISHED`.

The native solver, proof engine, signature checker, identity service, transparency
log, or provenance system retains its own semantics and result. A loss-declared
adapter maps that result into VSTD's verification interlingua and records the
boundary around its portable composition; VSTD does not absorb or reimplement the
substrate.

VSTD-5 and VSTD-Graph-5 remain draft. A higher VSTD layer does not supply a missing
lower layer.

## Identity, disclosure, trust, and reputation

VSTD verification is claim-first. Deciding a bounded claim does not, merely by
being a VSTD check, require a natural-person identity, creator identity, or
persistent actor identity. Some VSTD layers and profiles name devices, verifier
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

The implemented VSTD core is disclosure-neutral, not a zero-knowledge proof
protocol. Full-disclosure receipts remain valid. Zero-knowledge and zero-identity
work belongs in separately reviewed experimental profiles, and no receipt may be
called zero knowledge without a real proof-system guarantee. “Trustless” must mean
trust-minimized and assumption-explicit: a relying party still depends on selected
algorithms, checker code, canonicalization, policy, input availability, and, when
used, proof-system parameters or trust roots.

VSTD-Graph can preserve artifact history, challenges, lifecycle changes, and
refutations, but the current standard does not define a scalar artifact-reputation
score. A future reputation or “rust” view can be derived from that recorded history
only as a separate, time-indexed policy result. It must never overwrite a native
verdict or turn repeated registrations, signatures, or observations into truth.

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
- does **not** claim that JSON is the SCITT wire format;
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
