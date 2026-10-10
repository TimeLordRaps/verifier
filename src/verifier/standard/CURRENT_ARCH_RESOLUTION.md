# Current ARCH-4.1: selected operator-definition closure

Computational model architecture (ARCH); Verifier Standard (VSTD); JavaScript
Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256). Counts and
declared arities are dimensionless; retained evidence and certificate limits
count encoded bytes.

Semantic version `verifier-current-object-obligations-1`, coordinate `ARCH-4.1`
selects a finite operator-table/reference closure. Current ARCH is a primitive
with no namespace operands. Its architecture namespace cone is exactly its own
record; full native typed composition still checks the complete selected
collection and commits every record and operand map. Submodules and nested
architectures have no supported current declaration here. Broader submodule
closure remains UNKNOWN in every result and the required `.m` denominator;
this objective does not complete the ARCH closure tier.

## Selected predicate

The existing architecture payload remains exactly
`{scope: retained-static-tensor-graph, graph_digest}`. The exact retained graph
has `{nodes, outputs}`; each node has `{name, op, inputs, shape}`. This checker
binds the entire graph, resolves all input/output names, refuses cycles and
requires every retained node to be in selected output ancestry. Node shapes
are retained arrays; shape equations and numerical validity are separate
ARCH-3.1 obligations and are not inferred or imported as a passing child.

An independently selected sorted operator-tag table has exactly one row per
used graph tag, with `{op, library_id, operator_name, definition_digest}`.
The selected canonical library-byte manifest has sorted unique
`{library_id, library_digest}` rows. Retained library entries contain
`{library_id, library_digest, base64}`; base64 is exact canonical encoding of
the committed complete library bytes, or explicit null when unavailable.
Library bytes are never loaded as executable code, imports or filesystem paths.

A canonical library is `{schema_version, library_id, definitions}` under
`verifier-current-arch-operator-library-1`. Definitions are sorted and uniquely
named records `{operator_name, input_count, dependencies, body}`. Input count
is a plain integer 0..256. Each dependency is an exact
`{library_id, operator_name}` reference, sorted and unique by library/name pair.
The independently selected closure manifest supplies each referenced definition
digest; digests are not embedded circularly inside their own defining bytes.
Body is a retained JSON object whose interpretation,
truth, safety and execution are outside this predicate. References hidden in
that body are not discovered. Explicit null reachable body or complete library
definitions means absent required retained definition evidence and gives UNKNOWN.
An unused definition's null body does not enlarge the required closure or its
availability requirement.

Starting from the used tags, checking follows every declared operator dependency,
including cross-library dependencies. Each reference must identify a selected
library and reproduce the full canonical definition digest. The reachable
operator-definition relation must be acyclic. Each tensor node's input count
must equal its selected definition's declared arity. The sorted selected closure
manifest, `{library_id, operator_name, definition_digest, library_digest}`, must
equal exactly the complete reachable definition set with matching byte
commitments. Missing, extra or substituted entries fail. Each selected library
must contribute a reachable definition; an unused library fails. A library may
contain unused definitions because its full bytes are already committed, but
unused definitions must not be presented as members of the selected closure.

The request independently commits the exact subject/record/collection/graph,
operator-tag table, library manifest, closure manifest, evidence bytes, policy,
proposition and all limits. The policy binds the installed mechanism and a
bounded sorted set of trust-root labels. Labels and selection constructors do
not establish issuer authenticity or authority.

## Evidence, precedence and finite limits

Canonical evidence has exactly
`{schema_version, objects, graph, bindings, library_manifest, libraries, closure}`
under `verifier-current-arch-resolution-evidence-1`. Full canonical namespace
records appear in objects. Absent whole evidence and explicit null required
fields give UNKNOWN. Required fields omitted from a present envelope are
malformed and fail. Unsupported selected library versions remain UNKNOWN.
An operator missing from an available complete supported library is a refuted
reference and fails. An operator unavailable because its selected library bytes
or definition evidence are absent remains UNKNOWN.

Within admitted bounds, a known cycle, reference substitution, invalid arity,
graph mismatch or other checked contradiction wins over absent definition
evidence. Library processing continues past unavailable bytes to inspect other
retained libraries. Reachable known definitions still undergo cycle checking
when another library is missing. Equality of the full closure is asserted only
after the selected libraries and binding table are available. Missing data never
turns a known refutation into PASS or UNKNOWN. Earlier envelope/namespace/resource
admission can prevent unseen later predicates from being checked.

Ceilings: 300,000 parent operations; 4,096 items per container; 256 namespace
records; 512 tensor nodes and definitions; 32 libraries; 4,096 reachable references
and per-definition dependency entries; nesting depth 64; 100,000 separate native
composition operations; 1 mebibyte per decoded library; 4 mebibytes of aggregate
decoded libraries; 8 mebibytes of evidence; 2 mebibytes each of collection payload
and reference content; 16 mebibytes of certificate. Positive plain integer
limits may be selected at or below these ceilings. Selected bounds, unavailable
structural capacity and unsupported semantics give UNKNOWN; malformed present
content and admitted contradictory commitments give FAIL.

Quote-aware byte-depth preflights precede recursive parsing of evidence and
library JSON. Evidence structure inspection charges each visited value. Record,
manifest, library, definition, dependency, node and closure rows each cost an
operation; graph reference traversal, reachable definition traversal and
topological cycle replay also charge operations. Library structure inspection
charges its decoded values separately. Parsing, canonical hashing and base64
work are bounded by byte limits rather than charged per byte. Native namespace
composition uses its own externally selected budget.

## Replay and claim boundaries

Native build/recheck retain exact evidence and reproduce the full canonical
certificate under independently supplied request and policy. Rehashed invented
results, scope changes and replaced bytes do not replay. The mechanism digest
binds this module, shared evidence, namespace, receipt, canonicalization,
selection and budget code, the installed NAMESPACE_OBJECTS bytes and this
specification. Any changed library bytes, definitions, declarations, graph,
selection, policy, bounds, code or specification invalidates affected evidence.

PASS establishes only declared finite resolution and completeness within these
selected representations. Actual execution, numerical validity, operator truth
or safety, source authenticity, undeclared references, unretained dependencies,
backend portability, authority, complete architecture/submodule closure,
whole-tier and object-profile conformance remain unestablished. Broader required
submodule evidence remains an explicit UNKNOWN obligation. One passing instance,
registry entry or copied child does not close all required ARCH 1..9.m certificates.
