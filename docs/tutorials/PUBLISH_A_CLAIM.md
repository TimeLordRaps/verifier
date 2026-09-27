# Submit a claim for authenticated storage and review

> **Acronyms:** command-line interface (CLI); Hypertext Transfer Protocol (HTTP);
> Hypertext Transfer Protocol Secure (HTTPS); identifier (ID);
> JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
> uniform resource locator (URL); Verifier Standard (VSTD).

`vstd publish` submits a computational claim and supplied receipt to a Claim Garden
endpoint implementing the authenticated claim-storage contract. The command name does
not mean public publication: success is `STORED`, `PENDING_REVIEW`, and
`HUMAN_REVIEW_REQUIRED`, with publication `NOT_ESTABLISHED`.

## Inputs and preflight

Supply a server-compatible computational claim packet containing `claim` and `receipt`,
or separate claim and receipt files. A generic `vstd run` receipt is not automatically a
compatible claim packet. Do not add a `VERIFIED` label to convert it into one.

Before transport, the client requires a supplied `VERIFIED` verdict, a positive checked
statement count or supported statement records, and a claim digest matching canonical
JSON bytes. Claim text alone does not establish a checked statement count. The client
also recomputes a declared canonical digest for the supported VSTD-1 claim-mechanics
receipt shape and checks required notary-binding fields when that binding is present.
These are bounded input/integrity checks, not independent execution or signature verification.

Every submission requires the registered **submitting publisher** ID, shaped as
`publisher:sha256:` followed by 64 lowercase hexadecimal characters, and its bearer
credential file. The submitting publisher is not inferred from the receipt's notary.
The credential must be an ordinary bounded file containing a 40-512 character token
using letters, digits, underscore or hyphen. Keep credentials outside the repository.

## Command

```bash
vstd publish packet.json --publisher-id "$PUBLISHER_ID" --credential-file "$PUBLISHER_CREDENTIAL_FILE" --endpoint https://claimgarden.com --json
```

Set both variables to your registered publisher coordinate and credential-file path.
For separate files use `vstd publish receipt.json --claim claim.json` with the same
required publisher options. A directory may contain `packet.json`, or `receipt.json`
and `claim.json`. The endpoint must be a credential-free HTTPS origin; redirects are
refused. The reserved `--expected-head` and `--genesis` options are rejected here:
claim storage does not provide the separate silo-lineage submission contract.

The request body binds the explicit `publisher_id`, `claim`, and `receipt`; the token
is sent in the authorization header. Local refusal occurs before transport. A transport
error does not prove that remote storage did not happen; the client does not retry
automatically or claim rollback.

## Response and duplicate submissions

The client requires `CLAIM-GARDEN-STORED-1.0`, exact submitted claim ID and digest,
retained receipt coordinates, publisher-bound retrieval path and pending human-review
state. HTTP 201 requires `deduplicated: false`; HTTP 200 requires `deduplicated: true`.
Missing, malformed or mismatched fields are rejected rather than replaced by defaults.

The server may generate its own retained receipt, so its receipt ID may differ from
the supplied receipt ID. The retained receipt must bind the same claim and report a
positive checked-statement count. The client checks these bindings but does not
authenticate the returned receipt signature or independently establish its verdict.
Repeated submission can confirm existing storage; it cannot establish approval,
publication, scientific truth, or numbered-profile conformance.

These contract tests use injected transport. They do not establish that a particular
live endpoint is deployed, configured, reachable or compatible. Confirm that separately
before relying on a hosted service.
