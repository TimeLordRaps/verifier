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
| Accountability | `ATTESTED` | a declared escalation authority that can act on the coordinate |
| Uniqueness / Sybil resistance | `ATTESTED` | only with an attested mechanism; default `UNKNOWN` |
| Verifier independence | `ATTESTED` / `REFUTED` | attested distinct trust roots; refuted by a shared pseudonym |
| Recovery | `ATTESTED` | a declared credential-loss mechanism; strength not evaluated |
| Unlinkability | `ASSUMED` | never `SUPPORTED`; assumptions must be declared |
| Confidentiality | `ASSUMED` | out of scope for the record |
| Civil identity | `UNSUPPORTED_BY_DESIGN` | withheld deliberately |

`ACCEPTED_BOUNDED` means exactly: this key was authorized for this claim scope at this
instant. It means nothing about who the actor is, whether they are one actor, or whether
two records came from independent actors.

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
12. missing evidence implies safety.

## 5. Trust roots and revocation dependencies

The profile does not reduce trust-root dependence; it makes it explicit. A reader who
accepts an `ACCEPTED_BOUNDED` verdict is accepting, at minimum:

- the issuer named in `authorization.issuer`;
- the trust root named in `actor.key_binding.trust_root`;
- the revocation service named in `revocation.source`, as of `revocation.checked_at`;
- whatever protocol produced `signature_verified`, which this model does not check.

Revocation is a liveness dependency with a staleness bound, not a one-time check. A
record whose revocation source is absent is `UNKNOWN`; a record whose minimization request
deleted that source is `REJECTED` as unevaluable. Minimization is enforced by deletion
before evaluation, so a withheld coordinate cannot be silently read anyway.

## 6. Privacy leak analysis

Retained and observable in every conforming record: the pseudonymous coordinate, the key
identifier, the trust root, the issuer, the scope name, the validity window, the
evaluation instant, and the revocation source. Any two of these are joinable across
records. Publication timing and volume are not addressed at all.

Consequence: an observer who sees two records under one pseudonym learns they share an
actor coordinate; an observer who sees two records under one issuer learns they share a
root. Withholding civil identity does not weaken either observation. Coercion risk is not
removed either — it moves to the issuer, which still holds the civil binding. This is a
displacement of risk, not a reduction, and the experiment reports it as such.

## 7. Test results

Both suites pass at the committed state.

- `python experiments/zizk_vstd/zero_identity/run_validation.py` — 14 fixtures, 0 failures.
- `python -m pytest experiments/zizk_vstd/zero_identity/tests -q` — 39 passed.
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

No test failed. No assertion was weakened to obtain a green suite.

## 8. Unresolved assumptions

1. `signature_verified` and `revocation.state` are consumed as asserted evidence. No
   protocol is bound yet, so no protocol's assumptions have been inherited or checked.
2. Attestation quality is unmodelled. `ATTESTED` records that someone said so.
3. Nonce history is verifier-held state that this model does not carry; replay detection
   is only as good as that history.
4. No selective-disclosure or unlinkable-presentation scheme has been selected. Until one
   is named, `unlinkability` stays `ASSUMED` at best.
5. Timing and volume side channels are out of scope and unmitigated.
6. Whether an issuer that grants many coordinates to one operator can be detected at all
   from published records is open, and probably not decidable within one record.
7. Whether this profile should ever become normative is not decided here. Nothing in this
   round argues that it should.

## 9. Public claims currently justified

- "Civil identity can be withheld while authorization for a bounded claim scope stays
  reverifiable against a declared trust root."
- "Missing identity evidence yields `UNKNOWN`; conflicting identity evidence yields
  `CONFLICTED`; revoked or expired authority yields a refutation."
- "The experiment enumerates the identity coordinates that remain, rather than implying
  none remain."
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
- Any statement that this profile is production-ready, adopted, reviewed, or standardised.
