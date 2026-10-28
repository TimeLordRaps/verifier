# Current SPACE-4.1: declared logical byte-extent closure

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) specifies the claim; this Python mechanism is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes, and Secure
Hash Algorithm 256-bit (SHA-256) names commitments. Extents and offsets are
bytes. Counts and checking budgets are dimensionless.

The pair `verifier-current-object-obligations-1` / `SPACE-4.1` selects a
bounded **logical coverage** proposition. An independently selected exact
`SPACE-3.1` request, policy and certificate are retained and replayed against
the installed child mechanism. The parent request commits to each child
selection and its exact certificate bytes. Only a child `PASS` permits the
closure check. A missing or `UNKNOWN` child remains `UNKNOWN`; a failed or
substituted child cannot establish coverage.

The child selects one exact `SPACE` namespace record, complete finite typed
collection, declared extent in bytes and a retained set of aligned,
nonoverlapping half-open byte partitions. This objective sorts the bounded
retained partitions and requires the first start to be zero, every next start
to equal the previous end, and the final end to equal the declared extent.
The sorting affects only the check; identifiers and selected evidence bytes
are preserved. A leading, interior or trailing gap is `FAIL`, including a
gap that the `SPACE-3.1` statics checker intentionally allows. Overlap is
already `FAIL` under the child and cannot be reinterpreted as coverage.

`PASS` means the selected finite logical byte extent has no unallocated byte
in its represented partitions. It does **not** establish actual host memory,
storage or network allocation, physical containment, protection against an
out-of-range write, access-control isolation or physical non-leakage. It does
not close the whole SPACE tier or authorize scheduling, spending or
publication. Privacy, consent, governance, security and object-profile
conformance remain `NOT_ESTABLISHED`.

The parent certificate retains the exact child certificate, request and
policy as evidence, plus the parent request and replay result. Public release
of retained contents requires separate disclosure authority. Changed child
or parent source, selected specification, retained bytes or policy invalidates
the pinned mechanism. A digest or trust-root label is not proof that a device
has allocated the represented extent.
