# Current HARDWARE retained inventory

Status: experimental, versioned objective; no whole-tier or polished-artifact
claim. Verifier Standard (VSTD) is the claim language; this Python checker is
one reference mechanism. JavaScript Object Notation (JSON) and Secure Hash
Algorithm 256-bit (SHA-256) name the canonical encoding and digest algorithm.

The pair `verifier-current-object-obligations-1` and `HARDWARE-1.3`
selects **retained device inventory consistency**. It is distinct from
`verifier-current-object-obligations-1` / `HARDWARE-1.1`, which checks only
the selected namespace record and typed composition. It also does not rename
the legacy domain-certificate `HARDWARE-1.1` inventory or
`HARDWARE-1.2` topology results. A coordinate without its semantic version is
insufficient to select any of these propositions.

The bounded proposition is: the externally selected HARDWARE record occurs
exactly once in the selected finite typed collection; the collection
commitment and record digest reproduce; and the retained `devices` list
matches that record's `devices_digest` and consists of named supported device
kinds with typed nonnegative integer capacities. The admitted payload has
exactly `scope=retained-hardware-records` and `devices_digest`. The input
bundle has exactly one `devices` inventory. `MEMORY_BYTE` and
`STORAGE_BYTE` measure bytes. `COMPUTE_SLOT` and `SAMPLE_SLOT` are
dimensionless counts local to a named device; no cross-device performance or
capacity equivalence follows.

The request binds semantic version, proposition digest, object kind, subject
identifier, object and collection digests, exact evidence reference, selected
policy and finite limits. The policy binds the installed mechanism's source
digest, labelled trust roots and certificate byte limit. A certificate retains
the exact evidence bytes. The public native replay rebuilds the full
certificate against a separately selected request and policy; changed
certificate, record, collection, evidence, policy, implementation or this
specification invalidates reproduction.

`PASS` means only the finite retained-inventory proposition reproduced.
`FAIL` means the selected retained records contradict the proposition.
`UNKNOWN` means required retained evidence or checking capacity is
unavailable. Malformed or substituted certificate selection is rejected
before any computational verdict. The trust-root labels select a policy; they
do not authenticate a real observer or device. Physical identity, calibration,
live availability, delivered workload, capacity-backed credit issuance,
ownership, privacy, consent, governance, security and whole HARDWARE tier
conformance remain `NOT_ESTABLISHED`.
