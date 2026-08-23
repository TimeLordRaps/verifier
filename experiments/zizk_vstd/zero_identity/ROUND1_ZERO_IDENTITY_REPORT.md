# Round 1 report: zero identity in a ZIZK-VSTD profile

**Status:** experimental result. Non-normative. No adoption is claimed or implied.

## 1. Coordinates

- Base commit: `598c545be3833d6d81bb7e252ca5837f3bb2a449`
- Branch: `claude/zizk-zero-identity`
- Worktree: `verifier-worktrees/zizk-zi-claude` (isolated; the primary checkout and the
  separate ZIZK roadmap worktree were not modified)
- Remote: `github.com/TimeLordRaps/verifier`
- Layer: none. This experiment discharges no ladder rung.
- Seam: `experiments/zizk_vstd/zero_identity/` only.

## 2. Terminology decision

**"Zero Identity" is rejected as a public label.** It is retained only as the name of the
question this experiment answered, never as a description of what the profile provides.

The falsification succeeded. A profile that "removes identity" was tested against its own
required coordinates and the requirement survived: bounded reverification needs a
pseudonymous coordinate, a key identifier, a trust root, an issuer, a grant, and a
revocation source. Those are identity coordinates. What is actually removed is *civil*
identity, and removing it changes nothing about correlation, uniqueness, or independence.

Accepted term: **bounded identity disclosure**. Where a shorter phrase is needed,
*identity minimization* is accurate and *selective disclosure* is accurate only if a real
selective-disclosure protocol is actually deployed. "Anonymous" is rejected outright: the
profile is pseudonymous, and a stable pseudonym is a correlation handle.

## 3. Identity properties this profile supports

| Property | Best attainable | Basis |
|---|---|---|
| Authentication | `SUPPORTED` | asserted signature verification against a declared trust root |
| Authorization | `SUPPORTED` | grant covering the claim scope, from an active authority, by an authenticated key |
| Authority liveness | `SUPPORTED` / `REFUTED` | revocation state plus validity window against the evaluation instant |
| Freshness | `SUPPORTED` / `REFUTED` | challenge coordinate and verifier-held nonce history |
| Attribution | `ATTESTED` | binds a pseudonymous coordinate, never a person |
| Authorship degree | `ATTESTED` / `REFUTED` | declared role and remove, checked against the recorded delegation hops |
| Credential ancestry | `ATTESTED` / `REFUTED` | recorded chain from a declared trust root to the signing key |
| Accountability | `ATTESTED` | a declared escalation authority that can act on the coordinate |
| Uniqueness / Sybil resistance | `ATTESTED` | only with an attested mechanism; default `UNKNOWN` |
| Verifier independence | `ATTESTED` / `REFUTED` | attested distinct trust roots; refuted by a shared pseudonym |
| Recovery | `ATTESTED` | a declared credential-loss mechanism; strength not evaluated |
| Unlinkability | `ASSUMED` | never `SUPPORTED`; assumptions must be declared |
| Confidentiality | `ASSUMED` | out of scope for the record |
| Civil identity | `UNSUPPORTED_BY_DESIGN` | withheld deliberately |

`ACCEPTED_BOUNDED` means exactly: this key was authorized for this claim scope at this
instant. It means nothing about who the actor is, whether they are one actor, whether two
records came from independent actors, or whether the signer authored what it signed.

Authorship degree and credential ancestry were added after the first round, on the
observation that authorization alone cannot tell a first-party claim from a relayed one.
Three questions are now kept apart: authorization asks whether this key was permitted this
scope; authorship degree asks who is speaking and at what remove; credential ancestry asks
how the key came to hold the authority. A record can be fully authorized with `UNKNOWN`
authorship, and that pairing is reported rather than merged. Neither new property can ever
reach `SUPPORTED`: both are assertions about the world outside the record, so `ATTESTED` is
their ceiling.

## 4. Prohibited inferences

Each is encoded in `model/zero_identity_model.json` and guarded by at least one test:

1. absent civil identity implies anonymity;
2. absent civil identity implies unlinkability;
3. a pseudonym implies a distinct actor;
4. a shared pseudonym implies a single actor;
5. two distinct pseudonyms imply two independent actors;
6. a verified signature implies authorization;
7. a grant implies currently active authority;
8. absent revocation evidence implies active authority;
9. absent uniqueness evidence implies Sybil resistance;
10. hashing, redaction, encryption, omission, or pseudonymity alone implies zero identity;
11. disclosure minimization preserves the original claim boundary;
12. missing evidence implies safety;
13. a signer is the author of the claim;
14. a relayed, delegated, or aggregated claim is first-party authorship;
15. an absent authorship role means degree zero;
16. a recorded ancestry chain establishes that authority survived every hop;
17. no ancestor marked revoked means every ancestor is valid;
18. a rotation link merges two key coordinates into one actor;
19. a delegation may carry a scope its ancestor did not hold.

Inferences 16 and 17 are the credential-side form of the recorded-lineage discipline
already normative in `standard/VSTD-Graph-1.md`, which states that an edge records ancestry
without establishing influence, and that no ancestor being marked revoked does not
establish that every ancestor is valid.

## 5. Trust roots and revocation dependencies

The profile does not reduce trust-root dependence; it makes it explicit. A reader who
accepts an `ACCEPTED_BOUNDED` verdict is accepting, at minimum:

- the issuer named in `authorization.issuer`;
- the trust root named in `actor.key_binding.trust_root`;
- the revocation service named in `revocation.source`, as of `revocation.checked_at`;
- whatever protocol produced `signature_verified`, which this model does not check;
- every attestor named in the recorded credential ancestry, one per link.

Recorded ancestry increases the number of parties a reader depends on rather than reducing
it, and the report states that plainly: each delegation hop adds an attestor whose honesty
is assumed. A chain is refused when an ancestor is revoked or when a delegation carries a
scope its ancestor never held; it stays `UNKNOWN` when any link is unattested, when it does
not begin at a declared trust root, or when it does not terminate at the signing key. A
truncated chain therefore cannot be laundered into a clean one.

Revocation is a liveness dependency with a staleness bound, not a one-time check. A
record whose revocation source is absent is `UNKNOWN`; a record whose minimization request
deleted that source is `REJECTED` as unevaluable. Minimization is enforced by deletion
before evaluation, so a withheld coordinate cannot be silently read anyway.

## 6. Privacy leak analysis

Retained and observable in every conforming record: the pseudonymous coordinate, the key
identifier, the trust root, the issuer, the scope name, the validity window, the
evaluation instant, and the revocation source. Any two of these are joinable across
records. Publication timing and volume are not addressed at all.

Recorded credential ancestry makes this strictly worse, and the trade is deliberate. Every
link publishes a parent coordinate, a child coordinate, a link type, and an attestor, so a
chain is a durable join key across every record that carries it: two records sharing one
delegation hop are linkable even when their pseudonyms differ, and a rotation link is an
explicit statement that two key coordinates are related. Authorship provenance and
unlinkability are therefore in direct tension. This experiment resolves the tension toward
provenance and reports the cost rather than claiming both.

Consequence: an observer who sees two records under one pseudonym learns they share an
actor coordinate; an observer who sees two records under one issuer learns they share a
root. Withholding civil identity does not weaken either observation. Coercion risk is not
removed either — it moves to the issuer, which still holds the civil binding. This is a
displacement of risk, not a reduction, and the experiment reports it as such.

## 7. Test results

Both suites pass at the committed state.

- `python experiments/zizk_vstd/zero_identity/run_validation.py` — 21 fixtures, 0 failures.
- `python -m pytest experiments/zizk_vstd/zero_identity/tests -q` — 57 passed.
- `python -m pytest -q` (repository suite) — unchanged and passing; the experiment is not
  collected, because an experiment must not gate conformance.
- `python scripts/check_presentation.py` — passes.

Fixture coverage, one per required case:

| Fixture | Verdict |
|---|---|
| `positive_bounded_authorization` | `ACCEPTED_BOUNDED` |
| `positive_minimized_boundary_narrowed` | `ACCEPTED_BOUNDED` |
| `unknown_missing_authorization` | `UNKNOWN` |
| `unknown_distinct_pseudonyms` | `UNKNOWN` |
| `unknown_uniqueness_absent` | `UNKNOWN` |
| `conflicted_identity_evidence` | `CONFLICTED` |
| `rejected_revoked_authority` | `REJECTED` |
| `rejected_expired_authority` | `REJECTED` |
| `rejected_shared_pseudonym_independence` | `REJECTED` |
| `rejected_unlinkability_erases_trust_root` | `REJECTED` |
| `rejected_replayed_challenge` | `REJECTED` |
| `rejected_missing_challenge` | `REJECTED` |
| `rejected_minimization_widens_boundary` | `REJECTED` |
| `rejected_key_compromise` | `REJECTED` |
| `unknown_absent_authorship` | `UNKNOWN` |
| `unknown_unattested_ancestry_link` | `UNKNOWN` |
| `unknown_unattested_rotation` | `UNKNOWN` |
| `conflicted_authorship_degree_vs_chain` | `CONFLICTED` |
| `rejected_relay_claims_origination` | `REJECTED` |
| `rejected_revoked_ancestor` | `REJECTED` |
| `rejected_delegation_widens_scope` | `REJECTED` |

No test failed. No assertion was weakened to obtain a green suite.

## 8. Unresolved assumptions

1. `signature_verified` and `revocation.state` are consumed as asserted evidence. No
   protocol is bound yet, so no protocol's assumptions have been inherited or checked.
2. Attestation quality is unmodelled. `ATTESTED` records that someone said so. This now
   carries more weight than it did in the first round, because every ancestry link and
   every authorship role rests on it.
3. An internally consistent but dishonest authorship role is undetectable from the record.
   The model catches a relay that contradicts its own chain; it cannot catch a relay that
   lies consistently.
4. Chain truncation before publication is only partially addressed. A chain that does not
   reach a declared trust root stays `UNKNOWN`, but a chain trimmed to a plausible shorter
   root is not distinguishable from an honest short chain.
5. Rotation is treated conservatively in one direction only: an unattested rotation does
   not merge two coordinates. An actor rotating keys to shed a history is not detected.
6. Nonce history is verifier-held state that this model does not carry; replay detection
   is only as good as that history.
7. No selective-disclosure or unlinkable-presentation scheme has been selected. Until one
   is named, `unlinkability` stays `ASSUMED` at best.
8. Timing and volume side channels are out of scope and unmitigated.
9. Whether an issuer that grants many coordinates to one operator can be detected at all
   from published records is open, and probably not decidable within one record.
10. Whether this profile should ever become normative is not decided here. Nothing in this
   round argues that it should.

## 9. Public claims currently justified

- "Civil identity can be withheld while authorization for a bounded claim scope stays
  reverifiable against a declared trust root."
- "Missing identity evidence yields `UNKNOWN`; conflicting identity evidence yields
  `CONFLICTED`; revoked or expired authority yields a refutation."
- "The experiment enumerates the identity coordinates that remain, rather than implying
  none remain."
- "Authorship degree and credential ancestry are recorded and checked for internal
  consistency; a relayed claim cannot be read as first-party authorship, and a chain from a
  revoked ancestor is refused."
- "A recorded ancestry chain is recorded ancestry, not proof that authority survived every
  hop."
- "The evaluator adds no dependency and touches no frozen wire identifier."

## 10. Public claims still prohibited

- "VSTD supports zero identity", or any use of "zero identity" without the qualification
  that civil identity alone is withheld.
- "Anonymous", "untraceable", "uncorrelatable", or "privacy-preserving" as unqualified
  descriptions of this profile.
- Any claim that hashing, redaction, encryption, omission, or a pseudonym provides
  unlinkability.
- Any claim of Sybil resistance, actor uniqueness, or verifier independence that is not
  backed by named attested evidence.
- Any claim that a zero-knowledge proof system is used, implemented, or relied upon. None
  is present in this experiment.
- "Provenance is verified", or any phrasing that reads recorded ancestry as established
  authority, established influence, or a verified chain of custody.
- Any claim that authorship is proven. Authorship degree is `ATTESTED` at its ceiling.
- Any statement that this profile is production-ready, adopted, reviewed, or standardised.
