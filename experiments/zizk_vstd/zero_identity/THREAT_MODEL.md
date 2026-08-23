# Threat model: bounded identity disclosure

**Status:** experimental, non-normative.

Scope: one bounded disclosure record and the conclusions a reader may draw from it.
Out of scope: transport security, storage security, the correctness of any cryptographic
protocol, and the honesty of an issuer's internal process.

The adversary is assumed to be able to read every published record, to submit records of
their own, to create as many pseudonymous coordinates as an issuer will grant, and to
observe timing and volume of publication. The adversary is not assumed to break signature
schemes; where a key fails, it fails by compromise or misuse, not by cryptanalysis.

| # | Threat | What the model does | Residual risk |
|---|---|---|---|
| T1 | Correlation across receipts | Records nothing that resolves to civil identity; `unlinkability` is never `SUPPORTED`, at best `ASSUMED` under declared assumptions | Real. A stable pseudonym, a stable key, a stable issuer, and publication timing are all joinable. The model cannot see the adversary's side information |
| T2 | Replay | When `freshness.required` is set, an absent challenge fails closed and a previously observed challenge is `REFUTED` | A verifier that never requires freshness gets `UNKNOWN`, which is honest but not protective. Nonce history must be kept by the verifier |
| T3 | Key compromise | `key_compromised_during_interval` refutes authentication and therefore authorization | The model learns of compromise only when someone reports it. Silent compromise is indistinguishable from normal signing |
| T4 | Revoked or expired authority | Revocation state `revoked`, or an evaluation instant outside the validity window, is `REFUTED`, never `UNKNOWN`; a missing revocation source is `UNKNOWN`, never active | Revocation freshness is bounded by `revocation.checked_at`; the model does not fetch status |
| T5 | One actor presenting as many independent actors | Independence requires attested evidence with distinct trust roots; distinct pseudonyms alone leave it `UNKNOWN` | An issuer that grants many credentials to one operator can produce evidence that looks distinct. Independence is `ATTESTED` at best, never proven here |
| T6 | Many actors sharing one credential | A shared pseudonymous coordinate refutes independence; `uniqueness` stays `UNKNOWN` without attested evidence | The model cannot detect sharing from a single record. Attribution binds a coordinate, never a person |
| T7 | Coerced identity disclosure | The profile never stores civil identity, so there is nothing in the record to coerce out of the verifier | Coercion moves to the issuer, which does hold the binding. This displaces the risk rather than removing it |
| T8 | Metadata and timing leakage | Not mitigated. Declared as out of scope and reported as such | Publication time, volume, scope names, and issuer choice remain observable |
| T9 | Colluding issuers or verifiers | Trust roots must be declared explicitly, so a reader can see that two records share one root | Collusion between a declared issuer and a declared verifier defeats the profile. The model surfaces the shared root; it cannot rule collusion out |
| T10 | Unverifiable claims of independence | `verifier_independence` never becomes `SUPPORTED`; a claim of it that lacks evidence downgrades the record verdict to `UNKNOWN` | Attestation quality is outside the model |
| T11 | Missing authorization | A record with no grant is `UNKNOWN`; it never fails open | A verifier that treats `UNKNOWN` as permission defeats this. The verdict is honest; the deployment must respect it |
| T12 | Recovery after credential loss | `recovery` is `ATTESTED` only when a mechanism is declared, otherwise `UNKNOWN` | Any recovery path is also an impersonation path. The model records that a path exists; it does not evaluate its strength |
| T13 | Privacy laundering through minimization | A minimization request that removes a required trust root makes the record `REJECTED`; a request that widens the claim boundary is `REJECTED` | An actor can still choose to publish less and accept a weaker verdict, which is the intended trade |

## Falsification conditions

This experiment is refuted if any of the following can be demonstrated:

- a record reaches `ACCEPTED_BOUNDED` while any property is `REFUTED`;
- a `CONFLICTED` property is resolved to a favourable status by adding no new evidence;
- `unlinkability` reaches `SUPPORTED`;
- absence of a coordinate produces anything other than `UNKNOWN`, `REFUTED`, or `REJECTED`;
- a minimization request removes a required trust-root coordinate and the record still evaluates.

The first four are asserted directly in
[`tests/test_zero_identity.py`](tests/test_zero_identity.py); the fifth is
[`fixtures/rejected_unlinkability_erases_trust_root.json`](fixtures/rejected_unlinkability_erases_trust_root.json).

## What this threat model does not claim

It does not claim that the profile provides anonymity, that it defeats correlation, or
that it is safe to deploy. It claims only that the evaluator refuses to convert missing
identity information into a favourable conclusion.
