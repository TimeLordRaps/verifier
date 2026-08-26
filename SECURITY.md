# Security policy

> **Acronyms:** application programming interface (API); hash-based message authentication code (HMAC);
> Verifier Standard (VSTD).

## Supported release

Only the latest tagged public release is supported. Historical receipts and standards
remain immutable records; security corrections are published additively.

## Reporting

Do not place secrets, customer data, exploit payloads, or private vulnerability details
in a public issue. Use **Security** → **Report a vulnerability** in the canonical
GitHub repository to open a private vulnerability report with the maintainer:

`https://github.com/TimeLordRaps/verifier/security/advisories/new`

GitHub private vulnerability reporting is the intended sensitive-reporting route. If
GitHub does not show the private-reporting form, do not disclose sensitive details in a
public issue; report only the non-sensitive fact that the private route is unavailable.

## Scope

The reference implementation verifies declared receipt and provenance mechanisms. It
does not sandbox arbitrary commands supplied to `vstd run`; execute only manifests
you trust, in an isolation boundary appropriate to the command.

Use `vstd plan MANIFEST --json` to inspect the declared command, working directory,
repository directory, and artifact paths without execution. This is a review aid, not a
sandbox guarantee: a subprocess can access resources it does not declare. Paths reported
outside the manifest directory may be intentional (for example, a manifest stored under
`examples/` can bind the repository root), so VSTD exposes them instead of pretending
that rejecting them would confine the subprocess.

For VSTD-3, report parser ambiguity, signature/nonce bypass, canonicalization mismatch,
continuity fork/replay acceptance, claim-strength escalation, provenance blast-radius
failure, or accidental credential/raw-evidence disclosure. The HMAC emulator and local
anchor keys are explicitly test-only and are not production cryptography. Vendor or
cloud product vulnerabilities should also be reported to the affected vendor through
its own process; VSTD does not authorize testing third-party infrastructure.
