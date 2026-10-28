# Current ENV-4.1: selected resolver trace pin closure

Verifier Standard (VSTD) current semantic family
`verifier-current-object-obligations-1` registers experimental `ENV-4.1`.
ENV denotes a verifiable execution environment. This does not reinterpret any
legacy `ENV-4.1` spelling or change the current `ENV-1.2` software-inventory
check. The certificate binds one explicitly selected finite resolver trace to
one pinned ENV inventory. It does not discover a host's complete trace.

An external selector supplies a nonempty finite mapping of logical inventory
names to Secure Hash Algorithm 256-bit (SHA-256) byte commitments, and a
nonempty sequence of distinct resolution identifiers. Each selected resolution
names a requester (`@entry` or a pinned inventory name), a specifier and an
expected pinned target. The selected `ENV-1.2` request, policy and exact retained
certificate bind the identical subject and finite collection. That child must
replay as `PASS` and prove the ENV's selected software-file inventory was
materialized and rehashed. The parent checks its selected pins equal that
rehashed ENV inventory exactly.
`@entry` is reserved as the external entrypoint sentinel and cannot also name
a pinned inventory element.

Retained parent evidence carries the exact child certificate bytes and a row for
every externally selected resolution identifier. Each row must name the selected
target and that target's selected pinned digest. Extra, duplicated, substituted
or contradictory rows fail. Available contradictory rows are checked before
missing rows or an unavailable child can yield `UNKNOWN`; independently
refutable evidence is never hidden by absence. An absent selected row, missing
child or exhausted selected resource bound stays `UNKNOWN` when no contradiction
is established. Malformed external selection or a
substituted canonical certificate is rejected. The selected entries may include
repeated specifiers because their resolution identifiers are distinct. Logical
names are exact strings; the checker does not apply operating-system path
normalization or infer package-manager semantics.

`PASS` means **only** that the externally selected finite retained trace is
consistent with the rehashed pinned inventory. It does not prove the trace is
exhaustive for a real process, that a resolver or collector actually ran, that
the observations are authentic, or that network, host, image and build inputs
are closed. It establishes no physical isolation, disclosure authority, whole
closure tier, object profile or polished-artifact issuance. Trust-root labels
in a policy do not authenticate a collector. The selected trace and child
bytes may contain sensitive data; admission for emission is separate.

The default limits admit 256 pins and resolutions, 128 kibibytes of selected
pins and 128 kibibytes of selected resolutions, 200,000 parent operations,
4,096 items per container, six mebibytes of parent evidence, four mebibytes of
child certificate and eight mebibytes of parent certificate. A kibibyte is
1,024 bytes and a mebibyte is 1,048,576 bytes. Operation and item counts are
dimensionless. Parent operations charge retained-structure traversal and
canonical bytes compared against pins and selected resolutions.

The native application programming interface (API) is
`env_pin_closure_policy`, `env_pin_closure_request`,
`build_env_pin_closure_certificate` and
`recheck_env_pin_closure_certificate` in
`verifier.domains.contracts.env_pin_closure`. Public replay requires the exact
current semantic version, `ENV-4.1`, represented kind ENV, independently
selected request and policy. No legacy or neighboring coordinate verdict is
inferred from a matching string.
