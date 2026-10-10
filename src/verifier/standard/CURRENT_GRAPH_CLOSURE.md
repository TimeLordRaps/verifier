# Current GRAPH-4.1: retained reachability closure

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) specifies the claim; this Python mechanism is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes, and Secure
Hash Algorithm 256-bit (SHA-256) names commitments. Node, edge and
closure-pair counts and checking budgets are dimensionless; byte ceilings
count encoded bytes.

The pair `verifier-current-object-obligations-1` / `GRAPH-4.1` selects a
bounded **reachability closure** proposition over one retained finite directed
graph. This is a **current object-axis** coordinate.
The legacy Graph-axis `GRAPH-4.1` in `GRAPH_GROUNDING.md` names member
refutability entry at object profile 4. This certificate does not discharge
that legacy obligation, the legacy Graph profile, or any whole closure tier.
A coordinate without its semantic namespace is ambiguous.

An independently selected exact `GRAPH-3.1` request, policy and certificate
are retained and replayed against the installed child mechanism. The parent
request commits to each child selection, the exact child certificate bytes
and a separately selected closure digest. The child must select the same
GRAPH identifier, namespace-record digest and typed-collection digest as the
parent. Only a child `PASS` permits the closure check, so the retained nodes
are exactly the GRAPH direct members, every edge endpoint resolves to a node,
no edge repeats and the graph is acyclic. A missing or `UNKNOWN` child
remains `UNKNOWN`; a failed, substituted or rehashed child cannot establish a
closure.

The evidence bundle has exact fields `schema_version`, `child_request`,
`child_policy`, `child_certificate` (canonical base64 of the exact child
bytes) and `closure`. `closure` is an array with exactly one row per retained
node, in retained node order. Each row has exact fields `node` and
`reachable`. `reachable` is the sorted, unique list of nodes reached from
`node` by a path of one or more retained directed edges. A node that reaches
nothing has an empty list. Because the child is acyclic, no row names its own
node. The canonical closure array must rehash to the request's
`closure_digest`.

The checker rebuilds the successor lists from the child's retained edges and
performs a bounded depth-first traversal from every node. It compares each
declared row with the traversal as sets. A missing row, an extra row, a row
out of order, an unsorted or repeated entry, an extra field, an omitted
reachable pair or a declared unreachable pair is `FAIL`. A declared endpoint
that is not a selected GRAPH member is a boundary failure and is also `FAIL`.
The traversal is the verifier's own replay. Submitted per-pair path witnesses
are not a defined input and cannot replace it.

`PASS` establishes only that the declared closure of this finite retained
graph is exact. It does not infer undeclared edges, establish causal,
provenance or lineage truth, or rate any member. Privacy, consent,
governance, security, legacy Graph-profile, whole GRAPH closure-tier and
object-profile conformance remain `NOT_ESTABLISHED`.

The external policy binds the installed implementation, the child mechanism
and these specifications by a mechanism digest, selected trust-root labels
and a certificate byte ceiling. Request limits bound operations, container
items, nodes, edges, closure pairs and evidence bytes. An exhausted valid
limit yields `UNKNOWN`. A limit above its ceiling, an unknown limit, or a
malformed or substituted policy, request or certificate is rejected before a
computational verdict. Offline recheck requires the independently selected
request and policy, executes the installed mechanism again and compares
complete certificate bytes. Trust-root labels are selections, not
authentication of a graph maker.

The parent certificate retains the exact child certificate, request and
policy and the declared closure as evidence, plus the parent request and
replay result. Public release of retained contents requires separate
disclosure authority. Changed child or parent source, selected specification,
retained bytes or policy invalidates the pinned mechanism.
