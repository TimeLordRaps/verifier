# Current HARDWARE retained containment topology

Status: experimental, versioned bounded objective. Verifier Standard (VSTD)
names the claim; the Python mechanism is a reference implementation. JavaScript
Object Notation (JSON) bytes are canonicalized and committed with Secure Hash
Algorithm 256-bit (SHA-256). MEMORY_BYTE and STORAGE_BYTE capacities count
bytes; COMPUTE_SLOT and SAMPLE_SLOT are dimensionless per-device counts.

`verifier-current-object-obligations-1` / `HARDWARE-1.2` checks one retained
containment graph. This current certificate family is distinct from the legacy
domain-profile result also called `HARDWARE-1.2`; a coordinate without its
semantic family does not select either result. `HARDWARE-1.1` checks typed
namespace composition, while `HARDWARE-1.3` checks retained inventory. Neither
is silently promoted to this topology proposition or to full tier closure.

The selected exact HARDWARE NamespaceObject occurs once in a finite selected
collection whose complete composition commitment replays. Its payload commits
to exact retained `devices` and `topology` arrays. Each retained device has a
unique nonempty identifier, supported declared kind and typed nonnegative
integer capacity in named units. Each topology row names a parent and child in
that inventory. Duplicate, unresolved, self-cyclic and longer cyclic edges
contradict the proposition. An empty exact edge array can pass with a valid
nonempty inventory. The declared graph need not connect every device; no
undeclared edge is inferred. Acyclicity is a containment constraint and says
nothing about cycles in real communication networks.

The external request binds the semantic version, proposition digest, selected
HARDWARE identifier and digest, exact collection and evidence digests, selected
policy, and finite operation, item, byte and record limits. The policy binds
the installed source and this specification, selected trust-root labels and
certificate byte ceiling. The certificate retains exact evidence bytes. The
public `vstd current-object check` route rebuilds and compares the certificate
against the separately selected request and policy; changed dependencies
invalidate replay.

`PASS` establishes only finite retained containment consistency. `FAIL` means
the selected retained records contradict the proposition. Missing retained
inputs or exhausted checking budget yield `UNKNOWN`. Malformed or substituted
selection, policy or certificate is rejected before a computational verdict.
Trust-root labels are not device or observer authentication. Physical device
identity, actual containment or wiring, calibration, live capacity, delivered
workload, credit issuance, ownership, privacy, consent, governance, security,
and full HARDWARE object-profile conformance remain `NOT_ESTABLISHED`.
