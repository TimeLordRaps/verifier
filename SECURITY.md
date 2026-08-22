# Security policy

## Supported release

Only the latest tagged public release is supported. Historical receipts and standards
remain immutable records; security corrections are published additively.

## Reporting

Do not place secrets, customer data, exploit payloads, or private vulnerability details
in a public issue. Use **Security** → **Report a vulnerability** in the canonical
GitHub repository to open a private vulnerability report with the maintainer:

`https://github.com/TimeLordRaps/verifier/security/advisories/new`

GitHub private vulnerability reporting was enabled and verified through the repository
API on 2026-08-21. If GitHub does not show the private-reporting form, do not disclose
sensitive details in a public issue; report only the non-sensitive fact that the private
route is unavailable.

## Scope

The reference implementation verifies declared receipt and provenance mechanisms. It
does not sandbox arbitrary commands supplied to `verifiable run`; execute only manifests
you trust, in an isolation boundary appropriate to the command.

For VSTD 3, report parser ambiguity, signature/nonce bypass, canonicalization mismatch,
continuity fork/replay acceptance, claim-strength escalation, provenance blast-radius
failure, or accidental credential/raw-evidence disclosure. The HMAC emulator and local
anchor keys are explicitly test-only and are not production cryptography. Vendor or
cloud product vulnerabilities should also be reported to the affected vendor through
its own process; VSTD does not authorize testing third-party infrastructure.
