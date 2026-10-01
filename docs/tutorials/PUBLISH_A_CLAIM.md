# Publish a verified claim to Claim Garden

> **Acronyms:** command-line interface (CLI); Hypertext Transfer Protocol (HTTP);
> Hypertext Transfer Protocol Secure (HTTPS); identifier (ID);
> JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
> uniform resource locator (URL); Verifier Standard (VSTD).

The `vstd publish` command packages a locally verified computational claim and its receipt,
evaluates fail-closed preflight checks, and submits the verified claim packet to Claim
Garden (`https://claimgarden.com`) or a configured local or self-hosted endpoint.

Publishing is deliberately restricted to the CLI so that claims must be verified
locally before transmission. The client enforces a local tamper-proof lock: if the claim
or receipt has been altered, if the statement count is zero, or if the receipt verdict is
anything other than `VERIFIED`, the publication process aborts immediately before any
network connection is made.

Submission ends at `PENDING_REVIEW` with an admitted status. It does not authorize
moderation, endorse correctness, or establish public accreditation.

## Preflight verification invariants

Before any network request is sent, `vstd publish` evaluates four local preflight gates:

1. **Verdict check:** The overall receipt verdict (or audit verdict) must be `VERIFIED`.
   Receipts with verdicts of `FALSIFIED`, `UNKNOWN`, `INDETERMINATE`, or missing verdicts
   fail closed and cannot be published.
2. **Statement count check:** The number of statements or clauses evaluated must be
   greater than zero (`count > 0`). Empty or vacuous claims are rejected.
3. **Claim digest integrity:** The canonical JSON serialization of the claim payload is
   hashed using SHA-256, and the resulting digest must exactly match the `claim_digest`
   recorded in the receipt. If the claim was altered after verification, publication is
   blocked.
4. **Receipt canonical digest integrity:** When the receipt declares a canonical digest,
   the client recomputes the stable receipt digest and requires an exact match.

## Command overview

```bash
vstd publish RECEIPT [--claim CLAIM] [--endpoint URL] [--credential-file PATH] [--json]
```

Arguments:

- `RECEIPT`: Path to a receipt JSON file, a unified `packet.json` file, or a receipt directory.
- `--claim CLAIM`: Path to the matching claim JSON file (required if not bundled in the receipt directory or packet).
- `--endpoint URL`: Destination Claim Garden endpoint (defaults to `https://claimgarden.com`).
- `--credential-file PATH`: Optional file containing an authorized publisher bearer token.
- `--json`: Format the CLI output as structured JSON.

## Step-by-step walkthrough

### 1. Verify a computation locally

Begin by running a verified computation under an appropriate isolation boundary:

```bash
vstd run examples/generic_run/manifest.json --output /tmp/my-receipt
vstd validate /tmp/my-receipt
```

Confirm that the receipt directory contains `receipt.json` and `claim.json`, and that
`vstd validate` confirms the structural invariants.

### 2. Inspect the preflight readiness

Inspect the generated receipt:

```bash
vstd inspect /tmp/my-receipt
```

Verify that:
- `verdict` is `VERIFIED`.
- `claim_digest` matches the SHA-256 digest of the canonical claim.
- Statements checked count is positive.

### 3. Publish to Claim Garden

Publish the verified claim to Claim Garden:

```bash
vstd publish /tmp/my-receipt/receipt.json \
  --claim /tmp/my-receipt/claim.json \
  --endpoint https://claimgarden.com
```

Alternatively, if pointing directly to the receipt directory:

```bash
vstd publish /tmp/my-receipt --endpoint https://claimgarden.com
```

The output confirms successful admission:

```
[PUBLISH OK] Claim admitted to Claim Garden
  Claim ID:         GENERIC-RUN-WORD-COUNT-001
  Receipt ID:       vstd-receipt-20260918-001
  Claim Digest:     sha256:39c442988b425a1e4cc7c6bb41d4fb35046dea61a5be3cdf39a582b054eae341
  State:            PENDING_REVIEW
  Publication Gate: CLI_VERIFIED_TAMPER_LOCKED
```

### 4. Authenticated publisher submission

For accounts with registered publisher credentials, supply the token via `--credential-file`:

```bash
vstd publish /tmp/my-receipt \
  --endpoint https://claimgarden.com \
  --credential-file ~/.config/claimgarden/token.txt
```

The token is validated against bounded character and size constraints before transmission.

### 5. Verify fail-closed tampering protection

To see the tamper-proof lock in action, modify one character in `claim.json` or alter
the receipt's verdict to `UNKNOWN`:

```bash
sed -i 's/"VERIFIED"/"UNKNOWN"/' /tmp/my-receipt/receipt.json
vstd publish /tmp/my-receipt
```

The client immediately aborts:

```
vstd: error: cannot publish unverified claim; verdict is 'UNKNOWN', only VERIFIED claims may be published
```

No HTTP request is made, preserving network privacy and preventing unverified claims
from entering the publication queue.

## Boundary notes

- **Preflight lock vs. Remote validation:** Local preflight checks ensure that only
  well-formed, verified claims leave the publisher environment. The remote Claim Garden
  service independently re-verifies these invariants upon intake.
- **Publication status:** Submission records the claim as `ADMITTED` in `PENDING_REVIEW`
  state. Conformance status remains `NOT_ESTABLISHED` until independent review or audit.
- **Public documentation:** Documentation for Verifier Standard is hosted at
  `https://verifier-standard.com/`. Schema identifiers remain stable under
  `https://timelordraps.github.io/verifier/schemas/`.
