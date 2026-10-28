# Current ENV-1.4: selected configuration value domains

Verifier Standard (VSTD) current semantic family
`verifier-current-object-obligations-1` registers an experimental `ENV-1.4`
objective. ENV denotes a verifiable execution environment. This current route
does not reinterpret the legacy `ENV-1.4` check, which compares retained
configuration values under its historical wire identifiers. The native current
`ENV-1.5` equality check remains a separate obligation.

An external selector supplies a nonempty, finite mapping of required
configuration names to value domains. The selected ENV record must declare
exactly that mapping in `configuration_surface`, and its `configuration` record
must contain exactly one value for every selected name and no additional name.
Every value must satisfy its declared domain. A separately selected `ENV-1.1`
structural certificate over the identical ENV and finite collection must replay
as `PASS`. This certificate and its exact selection are retained in the parent.
The child establishes selected structural facets, not configuration semantics.

The domain language admits exact `literal`, nonempty `enum`, `boolean`, bounded
inclusive `integer` or `number`, bounded-length `string`, homogeneous `array`,
closed `record` and finite `union`. Arrays and records compose these domains.
An exact literal can represent any bounded plain JavaScript Object Notation
(JSON) value. Duplicate enum values and union branches, empty domains,
non-finite numbers, unsafe integers, unsupported tags and malformed bounds are
rejected before certificate construction. Integers are limited to magnitude
2^53-1; numbers are finite and bounded by magnitude 10^100. Length and item
limits are dimensionless; byte limits count bytes. One mebibyte (MiB) is
1,048,576 bytes.

`PASS` establishes completeness **relative to the externally selected names**
and exact value-domain membership in a retained ENV record. It does not prove
that the selection names every setting of a real host, that the values were
observed at execution time, that collection was authentic, or that secret
values may be published. It establishes no physical isolation, disclosure
authority, whole tier, object profile or polished issuance. `FAIL` denotes a
contradictory retained record or failed child; a missing child or exhausted
selected resource bound remains `UNKNOWN`. A substituted request, policy or
canonical certificate is rejected. The declared domain is a computational
predicate, not an independent claim that the configuration is safe or suitable.

The default bounds admit 64 selected top-level names, 512 domain nodes, 16
domain nesting levels, a 64 KiB selected surface, 100,000 parent operations,
4,096 items per container, 6 MiB evidence, a 4 MiB child certificate, and an
8 MiB parent certificate. Parent operations charge retained-structure traversal
and canonical bytes compared for literal and enum membership. The native
application programming interface (API)
is `env_configuration_surface_policy`, `env_configuration_surface_request`,
`build_env_configuration_surface_certificate` and
`recheck_env_configuration_surface_certificate` in
`verifier.domains.contracts.env_configuration_surface`. Public replay uses the
explicit current semantic version, `ENV-1.4`, represented kind ENV, selected
request and policy. Historical ENV identifiers and certificates are unchanged.
