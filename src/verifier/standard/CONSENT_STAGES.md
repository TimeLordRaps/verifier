# Distinct consent predicates and reproduction

Verifier Standard (VSTD); Secure Hash Algorithm 256-bit (SHA-256); Coordinated
Universal Time (UTC). Times are integer UTC Unix seconds. Identifiers, digests
and stage numbers are dimensionless.

`verifier.consent.stages` supplies distinct executable predicates for one
externally configured holder. It does not register current namespace objectives,
bind a namespace collection, establish a complete required-holder set, issue a
polished artifact, or authorize execution. Those integrations remain separate.
The existing public-key and shared-secret consent wire meanings are unchanged.

`evaluate_consent_stages` captures the selected context, public policy, at most
16 grants, revocation evidence, external time and computational verdict before
authentication. Existing public consent capture and encoded-byte bounds apply.
The receipt binds all captured inputs, the installed mechanism and these rules.

| Stage | Exact predicate | Prerequisites and exclusions |
|---|---|---|
| 7.1 | Authenticated terminal grant matches artifact, action, actor, observer and purpose, with explicit ALLOW. | Authentication is required; root authority, validity and delegation are separate. |
| 7.2 | Configured root holder signs the selected artifact grant; submitted grants and status are attributed to configured key actors. | External policy fixes holder, keys, roles and artifact binding. This does not prove real-world rights. |
| 7.3 | Signed grant intervals and authorized revocation cover the independently selected time. | Half-open intervals, exact action time, age, rollback floor and known ancestor revocation are checked. Missing time or fresh status remains UNKNOWN. |
| 7.4 | Complete bounded chain preserves parent commitments, delegate identity, scope and interval, without denial or duplicate identifiers. | Recomputed 7.2 and 7.3 must also pass. A single grant has zero edges but retains these prerequisites. |
| 7.5 | `recheck_consent_stages` reproduces the complete retained stage receipt from independently selected inputs. | Reproducing FAIL or UNKNOWN is reproduction, never positive admission. Missing authentication capability can yield UNAVAILABLE; known substitution is REJECTED. |
| 7.6 | All five computational verdict inputs produce identical consent evaluation after removing only the verdict and its receipt digest. | PASS, FAIL, UNKNOWN, REJECTED and CONFLICTED are exhaustively exercised. The computation itself is not rerun. |

The evaluator returns distinct results for 7.1–7.4 and 7.6; the separate rechecker
reports the reproduction result for 7.5. No aggregate result is relabeled as six
predicate results. Admission requires every evaluated predicate to pass. Any
failed predicate makes admission FAIL; otherwise an unknown predicate keeps
admission UNKNOWN. These statuses describe this versioned stage mechanism;
the older helper retains its separate REJECTED admission vocabulary.

Every carried positive predicate must retain its own required bindings even
when aggregate admission is UNKNOWN. Positive delegation requires positive
authority and validity. An unchanged missing grant or status cannot be blamed
on an unrelated missing clock to excuse a forged positive result. Replay
unavailability is scoped to the predicates actually affected by missing
authentication capability or independently selected policy/time.

Known structural contradictions can fail before authentication is available.
That failure rejects the submitted candidate; it does not authenticate the
contradictory statement. Authentication and role checks are still required for
positive results. A future revocation snapshot does not establish historical
revocation. An authenticated, nonfuture revoked ancestor fails even when stale.

Each receipt records `enforcement=NOT_ESTABLISHED`. Holder-set completeness,
clock authenticity, actual ownership, voluntary human consent, legal capacity,
global registry completeness and runtime enforcement remain external. Multiple
holders need independently selected per-holder policies and explicit combination.
