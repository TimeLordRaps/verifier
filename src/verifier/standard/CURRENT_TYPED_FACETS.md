# Current native declared structural facets

Verifier Standard (VSTD) semantic version `verifier-current-object-obligations-1`
registers one bounded declared operand-facet objective per admitted kind: `<KIND>-1.1`,
except `OBJECT-1.2` because `OBJECT-1.1` retains its generic representation/address
proposition. These are distinct from historical numbered-profile meanings.

The normative operand rules are the [current namespace contracts](NAMESPACE_OBJECTS.md#operand-contracts).
For an independently selected subject identifier, kind, exact record digest and finite
collection commitment, the mechanism reconstructs every retained record exactly and
reruns finite typed composition. Every declared reference must resolve; identifiers
are unique; composition is acyclic; named roles, nonempty targets, expanded typed
graphs and ACTOR human-root constraints must satisfy the selected kinds' contracts.
Other retained records also undergo composition checking. This is not a claim that
the collection contains every possible dependency or is exactly the subject's operand cone.

Primitive kinds have no composition operands in this contract. Their payload semantics
are unchecked. A HUMAN result does not establish actual personhood or identity; OWNER
structure does not establish title or hardware eligibility; RECEIPT structure does not
establish issuance or execution; SIM structure does not establish effect confinement.
No result completes a kind's facets tier or its object profile. Privacy, consent,
governance, security, physical containment and authority remain separate obligations.

The public route fixes semantic version, objective and represented kind. A selected
request also fixes the subject and collection digests, exact retained evidence reference,
kind-specific proposition digest, policy digest and finite limits. The selected policy
binds the implementation, direct dependencies, this specification and the operand
specification. Named trust roots are labels; their presence does not authenticate a
selector. The selector retains its request and policy outside the candidate certificate.

Evidence uses canonical JavaScript Object Notation (JSON), schema
`verifier-current-typed-facets-collection-1`, and an `objects` array of exact namespace
records. Secure Hash Algorithm 256-bit (SHA-256) commitments assume collision resistance;
they do not prove the represented facts. Certificates retain all evidence for exact
replay. Changed request, policy, record, dependency, certificate or carried result
requires refusal or a freshly selected artifact; recomputing an envelope digest cannot
substitute for replay. Canonical certificate evidence cannot be selectively redacted.

PASS means only the declared structural proposition. A contradictory subject, malformed
record, dangling reference, wrong operand kind, extra or missing role, implicit graph
retyping, invalid human root or composition cycle yields FAIL. Missing evidence or
exhausted selected bounds yields UNKNOWN. Unsupported external selections and malformed
certificates refuse admission. Limits are positive plain integers: at most 256 records,
100,000 composition operations, 4 mebibytes each of evidence, payload and reference bytes,
and 8 mebibytes per certificate. One mebibyte is 1,048,576 bytes; counts are dimensionless.
These ceilings bound local finite checking, not arbitrary host execution.

`vstd polish` can replay the selected certificate only against the same subject and
collection. It remains an assessment: complete objective inventory, authenticated
authority and public checkability are not established by these certificates.
