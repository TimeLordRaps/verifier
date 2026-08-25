# Semantic model: bounded identity disclosure

> **Acronym:** Verifier Standard (VSTD).

**Status:** experimental, non-normative. No wire identifier, no schema route, no receipt digest.

This document defines what the experiment means by each identity-adjacent term, which
properties a record can support, and which inferences are prohibited. The executable
form is [`model/zero_identity_model.json`](model/zero_identity_model.json) and
[`evaluate.py`](evaluate.py); where prose and code disagree, the code plus its fixtures
are the artifact under test and this document is the defect.

## 1. Separated terms

These are distinct properties. None implies another.

| Term | Meaning here | Profile position |
|---|---|---|
| Civil or legal identity | a natural or legal person recognised by a jurisdiction | withheld; `UNSUPPORTED_BY_DESIGN` |
| Persistent public identity | a durable public name reused across contexts | out of scope; the profile uses a pseudonymous coordinate instead |
| Key or credential coordinate | `key_id`, its trust root, and the grant that references it | required |
| Authentication | evidence that a given key signed the record | evaluable, may be `SUPPORTED` |
| Authorization | evidence that the signer was permitted this claim scope | evaluable, may be `SUPPORTED` |
| Accountability | a named authority that can act on the pseudonymous coordinate | at best `ATTESTED` |
| Attribution | binding a record to a pseudonymous coordinate, never to a person | at best `ATTESTED` |
| Authorship degree | how far the signing party sits from the origin of the claim: originator, delegate, relay, aggregator | at best `ATTESTED`, default `UNKNOWN` |
| Credential ancestry | the recorded chain of issuance, delegation, and rotation links from a trust root to the signing key | at best `ATTESTED`, refutable |
| Uniqueness / Sybil resistance | evidence that one coordinate corresponds to one actor | at best `ATTESTED`, default `UNKNOWN` |
| Verifier independence | evidence that two receipts came from actors that do not share a root | at best `ATTESTED`, refutable |
| Revocation and expiry | current liveness of a grant | evaluable, refutable |
| Confidentiality | protection of the record in transit and at rest | out of scope, at best `ASSUMED` |
| Unlinkability | inability of an observer to join two records to one actor | never `SUPPORTED`, at best `ASSUMED` |
| Anonymity / pseudonymity | absence of any actor coordinate versus a stable non-civil one | the profile is pseudonymous, never anonymous |

## 2. Statuses

`SUPPORTED` — decided from coordinates present in the record under stated rules.
`ATTESTED` — an external party asserts it; the assertion is recorded, not checked here.
`ASSUMED` — declared by the record as an assumption, carried forward as an assumption.
`UNKNOWN` — the coordinate needed to decide is absent. This is a result, not a gap to fill.
`CONFLICTED` — two retained pieces of evidence disagree. Terminal; never resolved by preference.
`REFUTED` — a positive negative result: the property is contradicted by evidence.
`UNSUPPORTED_BY_DESIGN` — the profile deliberately withholds the coordinate.

Record verdicts are `ACCEPTED_BOUNDED`, `UNKNOWN`, `CONFLICTED`, and `REJECTED`. They are
aggregated without erasing property-level uncertainty: any `REFUTED` property makes the
record `REJECTED`; otherwise any `CONFLICTED` property makes it `CONFLICTED`.
`ACCEPTED_BOUNDED` requires `SUPPORTED` authentication and authorization plus satisfaction
of every explicitly claimed property. An `UNKNOWN` ancillary property remains visible but
does not widen or erase that bounded authorization result. Every other record is `UNKNOWN`.
`ACCEPTED_BOUNDED` therefore asserts exactly one thing: authentication and authorization
hold for the declared claim scope at the declared instant. It asserts nothing about
uniqueness, independence, unlinkability, or the actor behind the coordinate.

## 3. Minimum public actor coordinates

Bounded authorization reverification without civil identity needs all of:

- `actor.pseudonym` — the coordinate a verdict attaches to;
- `actor.key_binding.key_id`, `.signature_verified`, `.trust_root`;
- `authorization.grant_id`, `.issuer`, `.scope`, `.not_before`, `.not_after`;
- `revocation.source`, `.state`, `.checked_at`;
- `trust_roots` — the roots the reader must already accept.

The provenance extension may additionally disclose:

- `authorship.role`, `.degree`, `.attested_by` — the asserted author role and remove;
- `credential_ancestry[].parent`, `.child`, `.link_type`, `.attested_by` — the recorded path
  by which the signing key obtained its authority.

Authorship degree and credential ancestry are distinct from authorization. Authorization
asks whether this key was permitted this scope; authorship asks who is speaking and at what
remove; ancestry asks how the key came to hold the authority at all. A record can be fully
authorized while its authorship is `UNKNOWN`, and that combination is reported, not merged.

Remove a required coordinate from an ordinary record and the dependent property becomes
`UNKNOWN`. Remove a required coordinate under a minimization request — whether by naming
the leaf or a parent path — and the record is `REJECTED` as unevaluable. Minimization is
enforced, not trusted: `evaluate.py` checks the requested paths and then deletes every
withheld coordinate before evaluating, so a coordinate an actor asked to withhold cannot
quietly still be read.

## 4. Prohibited inferences

Encoded in the model and each guarded by a test:

1. Absent civil identity implies anonymity or unlinkability.
2. A pseudonym implies a distinct actor.
3. A shared pseudonym implies a single actor.
4. Two distinct pseudonyms imply two independent actors.
5. A verified signature implies authorization.
6. A grant implies that the authority is currently active.
7. Absent revocation evidence implies active authority.
8. Absent uniqueness evidence implies Sybil resistance.
9. Hashing, redaction, encryption, omission, or pseudonymity alone implies zero identity.
10. Disclosure minimization preserves the original claim boundary.
11. Missing evidence implies safety.
12. A signer is the author of the claim.
13. A relayed, delegated, or aggregated claim is first-party authorship.
14. An absent authorship role means degree zero.
15. A recorded ancestry chain establishes that authority survived every hop.
16. No ancestor marked revoked means every ancestor is valid.
17. A rotation link merges two key coordinates into one actor.
18. A delegation may carry a scope its ancestor did not hold.

Inferences 15 and 16 mirror the recorded-lineage discipline of
[`../../../standard/VSTD-Graph-1.md`](../../../standard/VSTD-Graph-1.md): an edge records
ancestry, and a clean-ancestor policy must require validity explicitly rather than reading
it out of the absence of a revocation mark.

## 5. Relationship to cryptography

This model contains no cryptographic construction and asserts no cryptographic guarantee.
`signature_verified`, `state`, and any proof result are *inputs*: a deployment obtains them
from a real protocol and the model decides what may be concluded from them. If a
deployment wants selective disclosure or unlinkable presentation, it must name the actual
scheme it uses, state that scheme's assumptions, and record the outcome as evidence here.
Nothing in this experiment substitutes for that.

## 6. Relationship to VSTD

Nothing here changes a frozen wire identifier, a schema `$id`, a console alias, a lifecycle
token, or any conformance behavior. See [`../../../standard/WIRE_IDENTIFIERS.md`](../../../standard/WIRE_IDENTIFIERS.md).
The profile adds no dependency: `evaluate.py` is standard library only.
