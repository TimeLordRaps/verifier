# Proposed IETF SCITT engagement package

> **Do not send automatically.** Human review is required before any mailing-list,
> repository, author, meeting, or standards-body contact. This text does not claim
> WG interest, adoption, or endorsement.

## One-paragraph introduction

VSTD is an alpha, implementation-backed specification for bounded computational
verification receipts. A VSTD result names a computational claim coordinate,
evidence and policy roots, verifier implementation/fragment, resource bounds, and a
checkable PASS, FAIL, or UNKNOWN artifact. We have implemented an experimental
and optional SCITT profile in which a complete VSTD receipt is carried as the
payload of an RFC 9943 Signed Statement, while verified SCITT
registration/inclusion can be consumed as narrowly typed VSTD transparency
evidence. VSTD verification does not require a natural-person or persistent actor
identity merely to decide an artifact claim. Selecting SCITT adds an authenticated,
potentially linkable issuer and a transparency proposition. The adapter deliberately
prevents either property from being interpreted as proof that the VSTD computational
proposition passed.

## Technical relationship

SCITT already supplies an appropriate **optional accountability substrate** for
issuer authentication, statement registration, auditable registration policy,
append-only/non-equivocating VDSs, and portable COSE Receipts. VSTD does not propose
replacements for those functions or require them for every VSTD receipt. VSTD's
distinct role is a standard domain language for verification: an operator/result
interlingua that maps and preserves the claim boundary and portable result semantics
of native verifiers and proof engines, including explicit resource exhaustion and
refutation semantics, while leaving each domain engine's native semantics visible.

This experiment is deliberately full disclosure. It does not claim zero knowledge,
zero identity, anonymity, unlinkability, or absolute trustlessness. An experimental
witness-private VSTD proof profile would need its own real proof-system guarantees
and privacy analysis; routing that profile through SCITT would require an explicit
decision about issuer correlation and public registration metadata.

The implemented experiment demonstrates:

- an actual VSTD-4 grounded PASS certificate checked by the reference kernel;
- deterministic VSTD application-payload serialization;
- a real EdDSA COSE Signed Statement carrying that payload;
- a real RFC9162 SHA-256 COSE inclusion receipt from a local one-entry test log;
- independent statement and receipt verification;
- adversarial cases for artifact substitution, valid-registration/invalid-claim,
  missing/stale/revoked/superseded evidence, resource-bounded UNKNOWN, conflict,
  tampering, unsupported versions, and wrong issuer/subject;
- explicit preservation of both native VSTD and native SCITT results;
- a separately digest-bound native VSTD checker observation, preventing an embedded
  receipt's declared `PASS` from being treated as proof that checking occurred.

The local test log is not a production TS or public anchor. The experiment is about
the wire/semantic boundary, not deployment assurance.

## Three questions for SCITT participants

1. **Optional payload profile boundary:** Is an application payload profile that
   defines bounded computational-verification semantics, while leaving Signed
   Statement, Registration, VDS, and COSE Receipt processing unchanged, consistent
   with the intended SCITT extension model? Is it also consistent to treat SCITT as
   an optional accountability publication path rather than a prerequisite for the
   domain verifier? If so, should the profile identifier live only in the payload
   media type, or also in a protected header/type coordinate?
2. **Composite-verification alignment:** For work resembling the individual
   Composite Evidence Verification draft, should a domain verifier return its
   native result as a separate typed statement/report, or should the composite
   profile directly incorporate domain-result semantics? We want to prevent a graph
   `pass` from being read as arbitrary payload truth.
3. **Historical inclusion vs current usability:** What representation pattern is
   preferred when a COSE Receipt remains valid historical inclusion evidence but a
   relying-party policy now considers a dependency stale, superseded, conflicted,
   or revoked? The experiment preserves both states instead of invalidating history.

## Concrete contribution to offer

Offer the working implementation experiment first:

1. a short VSTD/SCITT crosswalk;
2. a payload-profile specimen with COSE Signed Statement and Receipt bytes;
3. negative tests proving that SCITT integrity cannot be laundered into
   computational truth; and
4. three focused design questions above.

Ask participants whether the useful next artifact is:

- an examples-repository contribution;
- a short implementation report;
- an application payload/profile document;
- alignment with composite-evidence/statement-graph exploration; or
- no standards document until more implementations exist.

Do not arrive assuming the WG wants a VSTD statement type, registry entry, or draft.

## Recommended first message shape

Subject suggestion:

> Experimental VSTD payload profile for SCITT: bounded computational results without registration-to-truth upgrade

Body outline:

1. One paragraph from the introduction above.
2. One sentence stating RFC 9943's accuracy boundary: registration proves an
   issuer produced a statement, not that the payload is true.
3. Links to the crosswalk, semantic boundary, implementation, and adversarial tests.
4. State exactly what is cryptographically demonstrated and that the log is local.
5. Ask the three questions.
6. Invite correction of the decomposition before proposing any Internet-Draft.

No adoption claims, deadline pressure, marketing language, or private plans belong
in the message.

## Internet-Draft maturity decision

**Recommendation: Option E now — implementation report and discussion first.**

VSTD has enough executable substance to justify a technical conversation, but not
yet enough community input to choose among an application media-type profile, a
statement type, or a broader bounded-verification profile. The closest overlapping
work is an active **individual** draft, not adopted WG architecture, and its result
model still contains open design questions. Writing a draft now would prematurely
freeze vocabulary and could duplicate work the WG prefers elsewhere.

Reassess **Option B, an informational VSTD/SCITT payload profile**, after:

- SCITT participants confirm the layer boundary;
- at least one native TS or independent implementation verifies the VSTD specimen;
- the payload media type/profile identifier and protected-header strategy are
  agreed;
- status/freshness/revocation behavior is reviewed;
- a second implementation can consume the profile without repository-specific
  knowledge.

Option C (new statement type) and Option D (general bounded-computational profile)
are premature. Option A (no engagement) is too conservative now that code and
negative tests exist.

## Human pre-send checklist

- Recheck all Datatracker statuses on the send date.
- Run the base and optional cryptographic test suites from a clean checkout.
- Confirm generated binary hashes match the checked-in report.
- Make public links resolve to the intended branch or merged commit.
- Confirm no private paths, identities, credentials, or operational plans appear.
- Ask one technical question per paragraph; do not ask for adoption.
- Describe individual Internet-Drafts as individual work in progress.
- State that the VSTD SCITT profile is experimental and non-normative.
- Do not imply that SCITT is required for VSTD or that either layer supplies zero
  knowledge, zero identity, anonymity, unlinkability, or absolute trustlessness.
