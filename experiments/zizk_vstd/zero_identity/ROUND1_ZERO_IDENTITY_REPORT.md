# Round 1 report: zero identity in a zero-identity/zero-knowledge (ZIZK)-Verifier Standard (VSTD) profile

> **Acronym:** carriage return and line feed (CRLF).

**Status:** experimental result. Non-normative. No adoption is claimed or implied.

Reading rule for this report: where evidence is insufficient the result is `UNKNOWN`, and
where evidence contradicts itself the result is `CONFLICTED`. Both are retained as results.
Neither is a gap to be filled, and neither may be read as authorization, independence,
uniqueness, Sybil resistance, privacy, or safety.

## 1. Coordinates

- Base commit: `598c545be3833d6d81bb7e252ca5837f3bb2a449`
- Branch: `claude/zizk-zero-identity`
- Worktree label: `zizk-zi-claude` (isolated; its absolute host path is intentionally
  excluded from this public report; the primary checkout and separate ZIZK roadmap
  worktree were not modified)
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

| Property | Best attainable here | Basis and boundary |
|---|---|---|
| Authentication | `SUPPORTED` | semantic result over an asserted external signature check and a declared trust root; no signature is verified here |
| Authorization | `SUPPORTED` | semantic result over authentication, an asserted grant, liveness inputs, and scope coverage |
| Authority liveness | `SUPPORTED` / `REFUTED` | semantic result over asserted revocation state plus validity window against the evaluation instant |
| Freshness | `SUPPORTED` / `REFUTED` | challenge coordinate and verifier-held nonce history |
| Attribution | not separately evaluated | the record binds a pseudonymous coordinate; any real-world actor binding is `ATTESTED` at best, never inferred |
| Authorship degree | `ATTESTED` / `REFUTED` | declared role and remove, checked against the recorded delegation hops |
| Credential ancestry | `ATTESTED` / `REFUTED` | recorded chain from a declared trust root to the signing key |
| Accountability | `ATTESTED` | a declared escalation authority that can act on the coordinate |
| Uniqueness / Sybil resistance | `ATTESTED` | only with an attested mechanism; default `UNKNOWN` |
| Verifier independence | `ATTESTED` | only from named attested evidence; shared or distinct pseudonyms alone leave actor independence `UNKNOWN` |
| Recovery | `ATTESTED` | a declared credential-loss mechanism; strength not evaluated |
| Unlinkability | `ASSUMED` | never `SUPPORTED`; assumptions must be declared |
| Confidentiality | not evaluated | out of scope; any declaration remains an assumption, not an evaluator result |
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

### 3.1 Evidence classes, kept separate

The four classes below are never merged, and no verdict promotes one into another. A
reader who collapses them recovers exactly the overclaim this experiment exists to block.

| Class | What it means | Handling in this experiment | Ceiling in this model |
|---|---|---|---|
| Semantic result | decided by the stated rules from coordinates present in the record | any reader running `evaluate.py` on the record | `SUPPORTED`, `REFUTED`, `UNKNOWN`, `CONFLICTED` |
| External attestation | a named third party asserts a fact this model records but does not check | a deployment may authenticate it under an external protocol; this evaluator does neither that nor truth validation | `ATTESTED` |
| Declared assumption | the record states a condition it needs and cannot demonstrate | carried unchanged and never established by this record | `ASSUMED` |
| Protocol guarantee | whatever an actual named cryptographic protocol provides | absent here; it would be checked under that protocol outside this evaluator | not represented; enters only as an input |

Concretely: `authentication` is a semantic result *about an asserted signature check*, not
a cryptographic guarantee — this model never verifies a signature. `uniqueness`,
`verifier_independence`, `authorship_degree`, and `credential_ancestry` are attestations at
their ceiling. `unlinkability` is an assumption at its ceiling; `confidentiality` is not an
evaluator output at all. No protocol guarantee is claimed anywhere, because no protocol is
bound yet.

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
is assumed. A chain is refused when an ancestor is recorded as revoked or when a delegation
carries a scope its ancestor never held; it stays `UNKNOWN` when any link is unattested,
when it does not begin at a declared trust root, or when it does not terminate at the
signing key. A truncated chain therefore cannot be laundered into a clean one without also
declaring the shorter root as trusted; the model cannot establish whether that declaration
is honest.

Revocation is a liveness dependency with a staleness bound, not a one-time check. A
record whose revocation source is absent is `UNKNOWN`; a record whose minimization request
deleted that source is `REJECTED` as unevaluable. Minimization is enforced by deletion
before evaluation, so a withheld coordinate cannot be silently read anyway.

## 6. Privacy and correlation leak analysis

Retained and observable in every `ACCEPTED_BOUNDED` record: the pseudonymous coordinate, the key
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
actor coordinate, not that they share one natural person. An observer who sees two records
under one issuer learns that they name the same issuer, not necessarily the same trust
root. Withholding civil identity does not remove either correlation handle. Coercion risk
is not removed either — it may move to an issuer that holds a civil binding. This is a
displacement of risk, not a demonstrated reduction, and the experiment reports it as such.

## 7. Test results

All required checks pass at the committed state. **Failed tests: none.** No assertion was
weakened, skipped, or marked expected-failure to reach this state.

| Check | Result |
|---|---|
| `python experiments/zizk_vstd/zero_identity/run_validation.py` | 22 fixtures, 0 failures |
| `python -m pytest experiments/zizk_vstd/zero_identity/tests -q` | 65 passed |
| `python -m pytest -q` (repository suite) | 255 passed, 3 skipped |
| `python scripts/check_presentation.py` | passes |

The repository suite sets `testpaths = ["tests"]` and does not collect this directory. That
is deliberate: an experiment must not gate conformance. The 3 skips are pre-existing and
unrelated to this work. On a machine where another checkout of the package is installed,
the repository suite needs the `PYTHONPATH=src` prefix described in `AGENTS.md` section 3;
that is an environment condition, not a repository defect.

### 7.1 Diff inspection

The complete diff against the base is confined to `experiments/zizk_vstd/zero_identity/`:
30 files, 3734 added lines, **zero files changed outside that directory**. A pattern scan
over every added line reports:

| Category | Findings |
|---|---|
| Private filesystem paths | none |
| Private model identifiers | none |
| Credentials or secrets | none |
| Email addresses | none |
| Business plans | none |
| Unsupported adoption claims | none |
| Unsupported privacy or anonymity claims | none in assertion position |
| Recorded ancestry described as causal | none |
| CRLF line endings | none |

Literal pattern hits were adjudicated and retained deliberately, because each occurs
in negating or guarding position rather than as a claim: the word *untraceable* appears
only in section 10 as a prohibited claim; the four frozen wire identifiers appear only in a
test asserting that no fixture may bind one; and `$id` appears only in prose stating that
none is introduced.

### 7.2 Non-regression of frozen surfaces

Verified directly against the base commit, not assumed:

- `pyproject.toml` is byte-unchanged, and `dependencies = []` still holds. The evaluator
  imports only `copy`, `dataclasses`, `json`, `pathlib`, and `typing`; `pytest` appears
  only in the experiment's own tests, which the repository suite does not collect.
- Zero files changed under `standard/`, `receipts/schema/`, `src/`, `examples/`, or
  `scripts/`. No frozen wire identifier, schema `$id`, receipt digest, console alias, or
  lifecycle token is added, renamed, or rebound.
- The stdlib-purity smoke check (`python -S -c "import verifier; ..."`) reports `1.1.3`.
- Existing conformance behavior is untouched: this experiment adds no code path that any
  shipped module imports.

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
| `unknown_shared_pseudonym_independence` | `UNKNOWN` |
| `rejected_unlinkability_erases_trust_root` | `REJECTED` |
| `rejected_replayed_challenge` | `REJECTED` |
| `rejected_missing_challenge` | `REJECTED` |
| `rejected_minimization_widens_boundary` | `REJECTED` |
| `rejected_minimization_erases_key_binding` | `REJECTED` |
| `rejected_key_compromise` | `REJECTED` |
| `unknown_absent_authorship` | `UNKNOWN` |
| `unknown_unattested_ancestry_link` | `UNKNOWN` |
| `unknown_unattested_rotation` | `UNKNOWN` |
| `conflicted_authorship_degree_vs_chain` | `CONFLICTED` |
| `rejected_relay_claims_origination` | `REJECTED` |
| `rejected_revoked_ancestor` | `REJECTED` |
| `rejected_delegation_widens_scope` | `REJECTED` |

No final test failed. No assertion was weakened to obtain a green suite. Validation instead
closed two fail-open surfaces: a minimizer cannot evade a protected leaf by deleting its
parent object, and a shared pseudonym no longer becomes a claim about how many actors use
that credential.

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

- "Civil identity can be withheld while the evaluator can recompute a bounded
  authorization result from public coordinates, conditional on asserted external checks
  and declared trust roots."
- "Missing identity evidence yields `UNKNOWN`; conflicting identity evidence yields
  `CONFLICTED`; revoked or expired authority yields a refutation."
- "The experiment enumerates the identity coordinates that remain, rather than implying
  none remain."
- "Authorship degree and credential ancestry are recorded and checked for internal
  consistency; a relayed claim cannot be read as first-party authorship, and a chain from a
  revoked ancestor is refused."
- "A recorded ancestry chain is recorded ancestry, not proof that authority survived every
  hop."
- "The experiment adds no required package dependency and the complete base-to-branch diff
  does not modify a frozen wire identifier or conformance implementation."

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
