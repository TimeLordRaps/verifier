# Gated evidence submission

Verifier Standard (VSTD) uses a local gate and native domain replay before the
explicit `vstd publish --gated` route prepares evidence for Claim Garden review.
The legacy `vstd publish` route remains available without `--gated`.

Terms: command-line interface (CLI); JavaScript Object Notation (JSON);
Unicode Transformation Format, 8-bit (UTF-8); Secure Hash Algorithm 256-bit
(SHA-256); American Standard Code for Information Interchange (ASCII);
Hypertext Transfer Protocol Secure (HTTPS); uniform resource locator (URL).
Byte limits count exact UTF-8 bytes, not characters. Digests and verdicts have
no physical unit. A decimal megabyte is 1,000,000 bytes.

## Prepare locally

Keep an evidence bundle in `artifact.json`, its external native request in
`request.json`, its native certificate in `certificate.json`, and the independently
selected native policy in `policy.json`. `artifact.json` is the **full evidence
bundle**; its parsed value must equal `certificate.evidence`. The parsed request
must equal `certificate.request`. These comparisons use canonical bytes, preserving
integer, floating-point and boolean distinctions. Ordinary whitespace and a trailing newline are
accepted and preserved in the three submitted input strings.

Create a gate manifest beside those files. This example selects all four inputs
and runs the native checker, propagating PASS, FAIL and UNKNOWN:

```json
{
  "schema_version": "verifier-gate-pipeline-1",
  "root": ".",
  "inputs": ["artifact.json", "request.json", "certificate.json", "policy.json"],
  "overall_timeout_seconds": 30,
  "max_output_bytes": 65536,
  "steps": [{
    "id": "certification",
    "argv": ["python", "-B", "-m", "verifier", "certification", "domain-check",
             "certificate.json", "--request", "request.json", "--policy", "policy.json", "--json"],
    "needs": [],
    "timeout_seconds": 20,
    "result_contract": "vstd-verdict"
  }]
}
```

Save it as `gate_pipeline.json`, then run:

```console
vstd gate run gate_pipeline.json --output gate_receipt.json
vstd gate check gate_receipt.json --manifest gate_pipeline.json --json
vstd publish gate_receipt.json --gated --artifact artifact.json --request request.json --certificate certificate.json --policy policy.json --manifest gate_pipeline.json --dry-run --output prepared.json --json
```

Dry-run performs no transport and reads no account credential. It rechecks the
original gate against the current runner, interpreter, executable and input
context, independently replays the native certificate under the selected policy,
and requires PASS. Every artifact, request, certificate and policy file must
occur in the unchanged gate input inventory with its exact byte count and digest.
The output is created exclusively: an existing file is never overwritten.
Inspect it before transmission. Recognized secret patterns and local absolute
paths in parsed values are rejected, including escaped JSON strings; this filter
does not establish that arbitrary artifact content is safe to disclose.

The Python entry points are `project_gate_receipt`,
`prepare_gated_publication`, `publication_summary`, `get_publish_account` and
`publish_gated` in `verifier.interoperability.gated_publish`.

## Linked account and explicit submission

Use your registered `publisher:sha256:` identity and a separately stored bearer
credential. The credential never enters the evidence envelope or output file.
Substitute your registered identity for `PUBLISHER_ID`:

```console
vstd account --publisher-id PUBLISHER_ID --credential-file publisher.token --json
vstd publish gate_receipt.json --gated --artifact artifact.json --request request.json --certificate certificate.json --policy policy.json --manifest gate_pipeline.json --publisher-id PUBLISHER_ID --credential-file publisher.token --private-review-consent --json
```

The client reads `/v1/publish/account` first and requires a linked account,
consistent quota, matching native policy and gate-runner digests. The returned
`checker_coordinate` identifies the host deployment and is distinct from the
native certificate's mechanism digest. Supply `--expected-checker-coordinate`
to pin a previously inspected host coordinate. Changing host coordinates changes
the submission identity and may require a new storage reservation.

The protocol currently requires a 10,000,000-byte account limit, with per-input
limits of 262,144 bytes for artifact, certificate and minimized gate report;
4,096 bytes for request; and 65,536 bytes reserved for assessment. Charge is the
sum of the four raw UTF-8 string lengths plus that reservation. These are checked
wire-contract constants, not a claim about a particular account's entitlement.
The authenticated account response supplies current usage and remaining bytes.
Preflight quota is an observation; the host atomically decides admission under
its quota cap and handles duplicate submissions, including when
remaining quota is below the reservation for a new submission.

`--private-review-consent` sends the explicit retention-consent header. Submission
uses one bounded HTTPS request without redirects or automatic retries. A timeout
or malformed response after submission leaves storage UNKNOWN; it does not mean
the server stored nothing. No command here approves or publishes a submission.
The successful response is `STORED`, `PENDING_REVIEW`, `PASS`, with
`HUMAN_REVIEW_REQUIRED` and `UNAUTHENTICATED_LOCAL_REPORT`. All returned component
digests, submission identity, coordinate, byte charge and retrieval path must bind
the prepared request exactly. Native FAIL, UNKNOWN and REJECTED never become
successful storage results. The CLI uses exit 0 for preparation or validated
storage, exit 2 for UNKNOWN, and exit 1 for other rejection/failure.

## Privacy projection and digest meanings

The packaged schema is
[`verifier-gate-publication-1.schema.json`](../src/verifier/schemas/verifier-gate-publication-1.schema.json).
The client validates the original locally, then derives a separate minimized
report. It retains receipt, runner and manifest digests, selected portable input
inventories, input-change observation and step dependencies/results. Raw command
output, executable paths, local manifest location and interpreter strings are
omitted. Stream digests hash the UTF-8 encoding of the retained decoded text;
they do not reconstruct the original binary output bytes.

The report is an **unauthenticated local report**. Its source receipt digest does
not authenticate the omitted original or execution. Digest consistency does not
authenticate publisher identity, account linkage, command provenance or the native
claim. Those are separate host and consumer checks. The process-group cleanup
label `OWNED_GROUP_SIGNALLED` does not establish that detached children exited.

Canonical digest input uses sorted JSON keys, compact separators, finite numbers
and ASCII escapes. Each digest has prefix `sha256:` and 64 lowercase hexadecimal
characters. `projection_digest` hashes the report without that field. Submission
component digests hash the exact raw UTF-8 strings. Consequently the wire
`artifact_digest` differs from the native certificate's `artifact_digest`, which
hashes the canonical bundle's inner `artifact`; native `evidence_ref` hashes the
canonical full bundle.

`payload_digest` hashes the canonical map of the four wire component digests.
`coordinate_digest` hashes the canonical account coordinate.
`submission_id` hashes the canonical map containing `publisher_id`,
`payload_digest` and `coordinate_digest`. The publisher identity appears only in
the authenticated query, never as an extra submission-envelope field. The
envelope contains exactly `schema_version: CLAIM-GARDEN-GATED-PUBLISH-1` and the
four strings `artifact_json`, `request_json`, `certificate_json`,
`gate_receipt_json`.

Local regression tests use injected transports and invented account data. They
exercise real local native replay and gate execution, altered bindings, escaped
path rejection, original-receipt mutation, and preserved negative outcomes.
They do not establish a live deployment, a linked real account, quota entitlement
or successful external storage.
