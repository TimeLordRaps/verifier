# Current selected-holder consent certificates

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256); Coordinated Universal Time (UTC). Times are
nonnegative integer UTC Unix seconds through `2**53 - 1`; byte limits measure
encoded bytes; object, holder and operation counts are dimensionless.

`verifier.domains.contracts.consent_checks` registers each current kind's
`7.1` through `7.6` under `verifier-current-object-obligations-1`. The six
predicates retain the distinct meanings in [CONSENT_STAGES.md](CONSENT_STAGES.md).
These registrations do not establish whole-tier or object-profile conformance.

The consumer independently selects the exact full namespace record, finite typed
collection, action, evaluation time, computational verdict, required holders,
each holder's public policy, retained evidence commitment and finite limits.
The native context binds the subject identifier and the full canonical namespace
record digest, removing only its literal `sha256:` prefix. A payload digest or
kind label cannot replace that record. Collection composition is rechecked.

The selected holder list is nonempty, sorted and unique, with at most 16 holders.
Each policy must name its selected holder; evidence cannot add a holder or supply
replacement policy. All selected holders are evaluated. Missing holder evidence
keeps the affected predicates UNKNOWN. One holder's PASS cannot supply another's
scope, authority, validity or delegation. Holder-set completeness, real-world
authority, clock authenticity and registry completeness remain external assumptions.

For `7.5`, the consumer additionally selects every holder's historical stage
receipt commitment. Exact retained FAIL or UNKNOWN admission can be successfully
reproduced; this is never consent admission. For other objectives no historical
receipt selection is accepted. The original computational verdict is retained
unchanged. All holders' native admission results are reported separately from the
selected objective's status. `7.6` can pass while admission fails.

Request, policy, evidence and certificate use distinct `verifier-current-consent-checks-`
version-1 identifiers. Canonical certificates retain the evidence bytes, exact
request, implementation and policy digests, and per-holder stage receipts. Replay
rejects request, policy, evidence, result and known phase substitutions. Missing
signature capability may make historical replay UNAVAILABLE; that is never a
reproduced positive result. A freshly recomputed UNKNOWN certificate can reproduce
exactly. Existing route version-1 records remain unchanged; these routes use
`verifier-current-object-route-replay-2` with explicit reproduction availability.

Limits cover at most 256 objects, 16 holder evaluations, 100000 structural
operations, 100000 composition operations, four mebibytes of retained evidence,
and eight mebibytes of certificate bytes. A mebibyte is `2**20` bytes. Each native
holder evaluation retains its separate grant, policy and cryptographic bounds.
The operation count does not measure machine instructions or elapsed time.
Exhausted selected checking bounds yield UNKNOWN, not a smaller consent scope.

Certificates establish no legal rights, voluntary human consent, actual execution,
permission to emit their retained evidence, runtime enforcement, complete polished
issuance or computational correctness. Disclosure gates must preserve exact
canonical certificate bytes; hashes do not authorize transmission.
