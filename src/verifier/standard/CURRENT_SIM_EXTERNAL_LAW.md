# Current SIM-3.4: external modelled-law statement

Verifier Standard (VSTD) current semantic family
`verifier-current-object-obligations-1` registers one bounded simulation
(`SIM`) statics objective. An exact selected SIM record names a distinct
`OBJECT` operand in a complete finite typed collection. That operand retains
a bounded physical-law statement, an applicability declaration and a source
reference, selected outside the SIM record. The checker reconstructs every
record, validates the collection and its operand edges, and compares the law
record, statement and source reference to the externally selected values.

`PASS` establishes only this represented assertion and exact retained text. It
does not verify the law, dimensional correctness, empirical applicability,
source existence or authority, historical execution, actual simulation
correspondence, law independence, whole statics-tier conformance, disclosure
permission or publication. A source reference is a citation claim; it is not
retrieved or authenticated. The law record itself can be supplied by the same
actor as the SIM, so structural separation cannot establish independent origin
or provenance. Those fields remain `NOT_ESTABLISHED`.

Absent selected evidence or a missing statement yields `UNKNOWN`; present
malformed or mismatched records yield `FAIL`. A canonical certificate retains
the exact collection bytes needed for replay. Counts are dimensionless and
limits count encoded bytes. Canonical JavaScript Object Notation (JSON) and
Secure Hash Algorithm 256-bit (SHA-256) commitments protect exact selection,
not truth or permission.

The native application programming interface (API) is
`sim_external_law_policy`, `sim_external_law_request`,
`build_sim_external_law_certificate` and
`recheck_sim_external_law_certificate` in
`verifier.domains.contracts.sim_external_law`. Public replay uses
`vstd current-object check` with semantic version
`verifier-current-object-obligations-1`, objective `SIM-3.4`, represented
kind `SIM`, and the selected request and policy. A public checker needs the
installed mechanism and packaged specifications; public disclosure of the
retained law record requires separate authority.

## Scope declaration

The retained SIM payload field `scope` takes one of two forms. The legacy
scalar form is the exact string `selected-external-law-statement`. The
composable form is one nonempty array of distinct admitted member strings in
strictly ascending code-point order; the admitted members are exactly
`selected-external-law-statement` (this route) and
`selected-retained-trajectory-replay` (current `SIM-2.1`), so the complete
composable declaration is
`["selected-external-law-statement", "selected-retained-trajectory-replay"]`.
This route passes only when its own member is declared. A repeated member, a
member out of that order, an empty array, a non-string member or an unknown
member is a present contradiction and is `FAIL`; the checker never reorders,
deduplicates or otherwise canonicalizes the declaration. A scalar naming any
other string or any other value type remains `FAIL`; an absent or null `scope`
remains `UNKNOWN`, as before. One exact SIM record and complete collection can
therefore be selected by `SIM-3.4` and `SIM-2.1` separately. Each route issues
its own certificate under its own request, policy, mechanism and certificate
versions, and a `PASS` from one route establishes nothing about the other.
