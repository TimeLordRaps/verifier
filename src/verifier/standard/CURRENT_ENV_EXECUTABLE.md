# Current ENV-1.3: retained executable coordinates

Verifier Standard (VSTD) current semantic family
`verifier-current-object-obligations-1` registers an experimental
`ENV-1.3` objective. ENV denotes a verifiable execution environment. Tier 1
asks which exact facets constitute it. This objective binds two selected
logical file coordinates, the entry point and interpreter, and their selected
version labels to exact retained software bytes. Counts are dimensionless.
Byte limits count bytes; one mebibyte (MiB) is 1,048,576 bytes.

The independently selected ENV record has a `runtime` payload with exactly
`entrypoint` and `interpreter`; each contains a logical `path` and a nonempty
`version` label. The request separately selects those names and labels plus the
Secure Hash Algorithm 256-bit (SHA-256) commitments to their bytes. A selected
`ENV-1.2` child must replay against the identical ENV and finite collection.
That child rehashes the complete selected retained file inventory. This parent
checks that each runtime path is in the inventory and its digest equals the
external selection, and that the record's version labels equal the selection.
If both roles name one file, they must select one version label. Paths are
logical inventory keys: this mechanism neither resolves host paths nor
executes either file.

`PASS` establishes exact selected retained-file and label binding only. A
child `FAIL` or `UNKNOWN` propagates. Missing child evidence and selected bound
exhaustion stay `UNKNOWN`; malformed or substituted evidence, mismatched
paths, hashes or labels fail or are rejected. Canonical JavaScript Object
Notation (JSON) and base64 preserve exact child certificate bytes. The default
limits admit 256 objects, 4,096 items per container, 100,000 native and
composition operations, 6 MiB parent evidence, 4 MiB child certificate and
an 8 MiB parent certificate.

A declared version label is bound to retained bytes but is **not** an observed
version or proof of the binary's own identity. This route does not establish
actual execution, dependency pin completeness, interpreter compatibility,
toolchain closure, physical host isolation, external origin, disclosure
authority, whole facets-tier conformance or polished issuance. The retained
child certificate stays in the canonical parent; removing it prevents
independent replay. Private-witness public proof requires a separate protocol.

The native application programming interface (API) is
`env_executable_policy`, `env_executable_request`,
`build_env_executable_certificate` and
`recheck_env_executable_certificate` in
`verifier.domains.contracts.env_executable`. Public command replay separately
selects the current semantic version, `ENV-1.3`, represented kind ENV, exact
request and policy. Existing ENV check certificate bytes and legacy readers
are unchanged.
