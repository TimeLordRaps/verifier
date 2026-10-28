# Current RECEIPT-2.1: VSTD-1 independent-audit validation replay

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) specifies the claim; this Python mechanism is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes, Secure Hash
Algorithm 256-bit (SHA-256) names commitments, Boolean satisfiability problem (SAT)
names the formula problem, Davis-Putnam-Logemann-Loveland (DPLL) names the
installed search procedure, and trusted computing base (TCB) names the
checker's own source digests. Byte limits measure exact retained bytes.
Counts, search steps and operation budgets are dimensionless.

## Choice of proposition

The DYNAMICS rationale for RECEIPT lists receipt generation, validation
replay, revocation event logging and ledger registration. This objective
selects **validation replay** alone. It is the only listed transition that
the installed reference implementation already defines on retained bytes:
`VSTD-1.md` section 8, item 2, says a validator or reproducer returns failure when
the bound content or declared rerun does not match, and
`verifier.core.checker.IndependentAuditor.audit_claim_derivation` is the
deterministic, standard-library-only rerun whose report every VSTD-1 claim
receipt retains as `independent_audit`. Revocation and ledger registration
would require an event log or ledger format that no installed mechanism
defines; inventing one would be new semantics. Receipt generation would
require rerunning the receipt's target command, which is outside retained
bytes.

## Proposition

For one externally selected `RECEIPT` namespace record and its exact retained
receipt bytes:

1. The `RECEIPT-3.1` canonical statics predicate holds (it is re-run here on
   the same retained bytes by the shared installed function, not taken from a
   separate child certificate, because replay needs the same decoded model).
   A statics violation is `FAIL`.
2. The installed auditor reports a TCB whose specification, implementation
   and parser digests equal the digests of the exact files this mechanism
   binds. Otherwise the replay is `UNKNOWN`: the environment resolved other
   files (for example a different `standard/VSTD-1.md` under the working
   directory), so this mechanism cannot say which checker would run.
3. Within finite limits, the installed auditor is rerun on the receipt's
   retained claim identifier, `n_vars`, clauses, atomic reasons and
   assumptions, with the request's `expected_satisfiable`. That expectation
   is externally selected because the receipt does not retain it as a field.
4. The rerun report's `claim_id`, `trusted_computing_base`, `sat_result`,
   `grounding_result`, `structural_integrity_passed`, `overall_verdict` and
   `audit_notes` each equal the retained values under VSTD-1 canonical JSON.
   The first differing field, in that order, is named in the `FAIL` reason.

A retained report pinned to another checker build differs at
`trusted_computing_base` and is `FAIL` for this proposition; that says
nothing about whether its own pinned checker would reproduce it.

The installed DPLL search has no internal budget, so before replay the
mechanism charges an a priori worst-case bound: at most `2^(d+1)` search
nodes for `d` distinct variables, each with at most `d+1` propagation passes
over every literal and clause, plus the final model fill of `n_vars`
entries. Exceeding `max_search_steps`, `max_sat_variables` (applied to both
`n_vars` and `d`), `max_reasons`, byte, item or operation limits, or the
interpreter recursion ceiling, is `UNKNOWN`. A malformed request, policy,
limit override or non-boolean expectation, or a substituted certificate, is
`REJECTED`: `ReceiptValidationReplayError` is raised before replay.

## Differences from RECEIPT-9.1 and RECEIPT-9.2

`RECEIPT-9.1` (receipt chain) checks a domain-separated link hash chain over
opaque receipt bytes and never parses or reruns anything. `RECEIPT-9.2`
(receipt authenticity) checks an issuer signature. This objective reruns the
installed auditor on one receipt's retained inputs and compares its report;
it checks no chain and no signature.

## What PASS does not establish

`PASS` means only that the installed auditor, rerun on the retained inputs
with the selected expectation, reproduces the retained report fields above.
It does **not** establish that the claim is true, that the formula encodes
the claim, that the declared independence basis is accurate (that field is
excluded because the same-process auditor never derives it; `VSTD-1.md`
section 5 treats it as a declaration), that the target solver's result or
command would rerun, that external referent bytes exist or match, receipt
generation, revocation event logging, ledger registration, prerequisite
resolution (`RECEIPT-4.1`), hash-chain continuity, issuer authenticity, the
whole RECEIPT dynamics tier or object-profile conformance. Privacy, consent,
governance, security, authority and publication are not claimed; their
result fields remain `NOT_ESTABLISHED`.

The certificate retains the exact namespace record, receipt bytes, request,
policy digest and replay result. Public release of retained contents requires
separate disclosure authority. Changed mechanism source, the installed
checker, receipt, provenance or namespace model, `RECEIPT-3.1` source or
specification, `VSTD-1.md`, this specification, retained bytes, the selected
expectation or policy invalidates the pinned mechanism digest and therefore
the certificate.
