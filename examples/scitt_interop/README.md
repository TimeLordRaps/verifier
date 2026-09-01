# Verifier Standard (VSTD)/Supply Chain Integrity, Transparency, and Trust (SCITT) cryptographic interoperability example

> **Acronyms:** Concise Binary Object Representation (CBOR); CBOR Object Signing and Encryption (COSE); grounded decision certificate (GDC);
> Internet Engineering Task Force (IETF); Request for Comments (RFC); Secure Hash Algorithm 256-bit (SHA-256);
> verifiable data structure (VDS).

> **Experimental and non-normative.** This example creates real COSE signatures and
> an RFC 9162 SHA-256 inclusion receipt in a local one-entry test log.
> It does not operate a production SCITT Transparency Service, publish to a public
> log, or demonstrate third-party monitoring.

## What it proves

The example executes this chain:

```text
artifact bytes
  -> grounded VSTD4-GDC-1 digest predicate
  -> separately implemented kernel check returns PASS
  -> deterministic experimental VSTD/SCITT payload
  -> RFC 9943-style EdDSA COSE Signed Statement
  -> RFC 9942 / RFC9162_SHA256 signed inclusion receipt
  -> offline statement-signature and receipt verification
  -> composed result preserving both native verdicts
```

It proves, under the emitted public keys and local test-log policy, that the exact
Signed Statement is authentic and included in the one-entry VDS, and that the exact
embedded VSTD certificate passes the separately implemented kernel check for the artifact digest
predicate. The enclosing VSTD-4 candidate depth is a structural result with conformance
`NOT_ESTABLISHED`; this example does not establish VSTD-4 conformance or VSTD-5
readiness or distinct producer/checker actors. It also does not prove artifact safety,
production-service registration,
public witnessing, issuer authority outside the test, or arbitrary payload truth.

## Identity and privacy boundary

The VSTD receipt is produced and checkable before SCITT is applied. This example
then deliberately adds a fixed issuer, signature, subject, registration time, and
transparency-service coordinate because those are part of the selected SCITT
profile. It is therefore **not** a zero-identity or zero-knowledge example: the
payload is disclosed, and the issuer and statement can be correlated. SCITT is an
optional accountability wrapper here, not a prerequisite for VSTD verification.

Before issuing the local receipt, the example policy verifies the statement
signature and requires the exact test issuer, VSTD subject, payload content type,
and experimental profile identifier. The policy identifier is retained in the
normalized SCITT observation.

## Setup

From the repository root:

```bash
python -m pip install -e ".[scitt]"
```

The optional extra is pinned in `pyproject.toml`:

- `scitt-cose==0.2.2`
- `cbor2==6.1.4`
- `cryptography==50.0.0`

`scitt-cose` is a separately maintained implementation, not an IETF publication or
endorsement. The normative wire references are [RFC 9943](https://datatracker.ietf.org/doc/html/rfc9943), [RFC 9942](https://datatracker.ietf.org/doc/html/rfc9942), RFC 9052/9053, and RFC 9162.

## Produce and verify

```bash
python examples/scitt_interop/demo.py produce
python examples/scitt_interop/demo.py verify
```

The producer writes a deterministic canonical VSTD payload plus real COSE artifacts
under `generated/`. Fresh ephemeral signing keys are generated on each production
run, so the public keys, signatures, and their hashes intentionally change. The
checked-in specimen remains deterministically verifiable, but producing a new
specimen is not byte-reproducible without externally managed fixed keys. The verifier reads
only those artifacts, the two public keys, the local artifact, and the documented
trust coordinates. No private key is written or committed. The ephemeral keys have
no authority outside this example.

## Generated artifacts

| File | Meaning |
|---|---|
| `vstd_receipt.json` | VSTD-4 structural candidate receipt and grounded decision certificate; conformance is `NOT_ESTABLISHED`. |
| `vstd_scitt_payload.json` | Canonical application payload bytes carried by SCITT. |
| `registration_template.json` | Human-readable normalized input; explicitly **not** COSE. |
| `signed_statement.cose` | Real COSE_Sign1 Signed Statement. |
| `receipt.cose` | Real signed RFC9162_SHA256 inclusion receipt. |
| `transparent_statement.cose` | Signed Statement with receipt attached at COSE header label 394. |
| `issuer_public.pem` | Public key for offline statement-signature verification. |
| `log_public.pem` | Public key for offline receipt verification. |
| `verification_result.json` | Native VSTD candidate-check result, explicit VSTD conformance `NOT_ESTABLISHED`, native SCITT observation, scoped composition, and hashes. |

## Adversarial coverage

`tests/test_scitt_interop.py` and `tests/test_scitt_crypto_example.py` cover:

- deterministic serialization and round trips;
- identity, claim-coordinate, artifact, and payload binding;
- valid SCITT registration with VSTD FAIL or UNKNOWN;
- missing, stale, revoked, superseded, conflicted, and unsupported evidence;
- wrong issuer/subject and unaccepted policy coordinates;
- malformed payloads and version mismatches;
- corrupted COSE statement and receipt bytes;
- the invariant that SCITT-only evidence returns
  `computational_verdict = NOT_EVALUATED`.
- the invariant that a composed PASS requires a native VSTD checker result bound to
  the exact embedded receipt;
- the invariant that the native VSTD payload contains no SCITT issuer, transparency
  service, registration policy, or registration time.

Run:

```bash
python -m pytest -q tests/test_scitt_interop.py tests/test_scitt_crypto_example.py
```
