# Submit a SIM artifact for ClaimGarden review

As of 2026-09-27, ClaimGarden accepts a bare `SIM` (simulation) package at `POST /v1/artifacts?publisher_id=...`. The older simulation publication route returns a moved-surface response. A successful upload is quarantined for native assessment and human review; it is not publication.

The package is one JavaScript Object Notation (JSON) object with exactly `kind`, `title`, `description`, `rights`, `certification`, and `model`, plus optional `presets`. Set `kind` to `SIM`. Do not wrap it in a top-level `schema_version`. The certification envelope contains `request` and `certificate`; the native certificate retains its evidence. The host checks the declarative model, certificate, rights statement, limits, publisher identity, and review state independently.

Select the expected native request and policy independently of the package, and record the Secure Hash Algorithm 256-bit (SHA-256) digest of the package's **exact bytes**. The command-line interface (CLI) reads those files and rechecks the native certificate before sending any bytes:

```text
vstd publish sim.json --sim-artifact --sim-request request.json --sim-policy policy.json --source-digest sha256:<64 lowercase hexadecimal digits> --publisher-id publisher:sha256:<64 lowercase hexadecimal digits> --credential-file publisher.token --json
```

The client refuses mismatched source bytes, request, native replay, or certified transition and initial state before transport. It sends the original package bytes once, without reserializing them. A bound host response may return `SUBMITTED` or `REJECTED_AUTOMATIC`; a transport failure or malformed response after sending returns `INDETERMINATE` with state `UNKNOWN`. In all cases the client reports publication as `NOT_ESTABLISHED`. The host's current assessment and moderator decision remain authoritative.

Do not put a bearer token in the package, command arguments, or source control. Keep the credential in a local bounded file. This command does not provide a dry run or perform a live submission during tests.
