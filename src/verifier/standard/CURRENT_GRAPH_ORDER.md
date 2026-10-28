# Current GRAPH-2.1: retained least topological order

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) specifies the claim; this Python mechanism is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes, and Secure
Hash Algorithm 256-bit (SHA-256) names commitments. Node and edge counts,
order positions and checking budgets are dimensionless; byte ceilings count
encoded bytes.

The pair `verifier-current-object-obligations-1` / `GRAPH-2.1` selects a
bounded **least topological order** proposition over one retained finite
directed graph. This is a **current object-axis** coordinate.
The legacy Graph-axis `GRAPH-2.1` in `GRAPH_GROUNDING.md` names member rating
re-execution at object profile 2. This certificate does not discharge that
legacy obligation, the legacy Graph profile, or any whole dynamics tier.
A coordinate without its semantic namespace is ambiguous.

An independently selected exact `GRAPH-3.1` request, policy and certificate
are retained and replayed against the installed child mechanism. The parent
request commits to each child selection, the exact child certificate bytes
and a separately selected order digest. The child must select the same GRAPH
identifier, namespace-record digest and typed-collection digest as the
parent. Only a child `PASS` permits the order check, so the retained nodes are
exactly the GRAPH direct members, every edge endpoint resolves to a node, no
edge repeats and the graph is acyclic. Only an absent parent evidence bundle,
or a retained child that replays `UNKNOWN`, yields `UNKNOWN`. In a present
bundle, a child request, policy or certificate field that is null, empty or
absent is malformed and yields `FAIL`. A failed, substituted or rehashed child
cannot establish an order. Another certificate for the same child request,
other than the exact retained bytes the parent request commits to, is a
substitution and yields `FAIL`. Outer admissibility and capacity checks take
precedence over these child outcomes.

The evidence bundle has exact fields `schema_version`, `child_request`,
`child_policy`, `child_certificate` (canonical base64 of the exact child
bytes) and `order`. `order` is an array of node identifiers. The canonical
order array must rehash to the request's `order_digest`.

The order must name every retained node exactly once, including when the graph
has no edges. An entry that is not a selected GRAPH member is a boundary
failure, and a repeated or omitted node is a failure; each is `FAIL`. The
order must be topological: for every retained edge, the source appears before
the target, or the result is `FAIL`. Finally, the order must be the
**lexicographically least** topological order, comparing node identifiers by
Unicode code point: not by case-folded text and not by UTF-16 code unit, which
order some identifiers the other way. The checker computes that order itself
with Kahn's algorithm, always removing the least node whose retained
predecessors have all been removed, and compares position by position. A valid
topological order that is not the least one is `FAIL`, even though the same
child replays `PASS`. Submitted orders, schedules or predecessor witnesses are
not a defined input and cannot replace the verifier's computation. The
topological check runs before the least-order comparison. That order changes
only the refusal message, never the verdict, because any order that places a
target before its predecessor also differs from the least order.

`PASS` establishes only that the declared order is the least topological
order of this finite retained graph's declared edges. It does not infer
undeclared edges, establish temporal, causal, provenance or lineage truth,
execute the order, establish that any schedule is optimal, or rate any
member. Privacy, consent, governance, security, legacy Graph-profile, whole
GRAPH dynamics-tier and object-profile conformance remain `NOT_ESTABLISHED`.

The external policy binds the installed implementation, the child mechanism
and these specifications by a mechanism digest, selected trust-root labels and
a certificate byte ceiling. Request limits bound operations, container items,
nodes, edges and evidence bytes. A graph exactly at its node or edge limit is
admitted; one past it yields `UNKNOWN`, as does any other exhausted valid
limit. The child's own object limit also applies. At the default ceilings, a
graph of 256 nodes cannot `PASS`, because its child collection holds 257
objects against the child's 256-object limit; 255 nodes is the largest graph
that can `PASS`. A limit above its ceiling, an unknown limit, or a malformed
or substituted policy, request or certificate is rejected before a
computational verdict. Offline recheck requires the independently selected
request and policy, executes the installed mechanism again and compares
complete certificate bytes. Trust-root labels are selections, not
authentication of a graph maker.

The parent certificate retains the exact child certificate, request and
policy and the declared order as evidence, plus the parent request and replay
result. Public release of retained contents requires separate disclosure
authority. Changed child or parent source, selected specification, retained
bytes or policy invalidates the pinned mechanism.
