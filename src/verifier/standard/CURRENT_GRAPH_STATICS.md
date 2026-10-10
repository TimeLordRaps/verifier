# Current GRAPH retained directed-edge statics

Status: experimental, versioned, bounded objective. Verifier Standard (VSTD)
names the claim; the Python mechanism is a reference implementation. JavaScript
Object Notation (JSON) bytes are canonicalized and committed with Secure Hash
Algorithm 256-bit (SHA-256). Node, edge and operation counts are dimensionless;
byte ceilings count encoded bytes.

`verifier-current-object-obligations-1` / `GRAPH-3.1` checks the structure of
one selected, retained, finite directed graph. This is a **current object-axis**
coordinate. The legacy Graph-axis `GRAPH-3.1` in `GRAPH_GROUNDING.md` means
substrate rating re-execution over members and reachable ancestors. This
current object certificate does not discharge that legacy obligation or any
whole statics tier. A coordinate without its semantic namespace is ambiguous.

The external request independently selects an exact GRAPH identifier and
namespace-record digest, complete typed-collection digest, retained node-array
digest, retained directed-edge-array digest, evidence byte reference, policy
digest and finite checking limits. The evidence bundle has exact fields
`schema_version`, `objects`, and `inputs`. `objects` holds the complete
canonical namespace collection. `inputs` is either absent/`null` (UNKNOWN) or
an object with exact `nodes` and `edges` arrays. `nodes` is a sorted, unique,
nonempty list of direct `members` operand identifiers on the selected GRAPH;
each name is at most 256 characters. `edges` is a sorted, unique list of
`{"source": node_id, "target": node_id}` records. It may be empty. Each
endpoint must resolve to a selected node. No missing, additional or duplicate
node or edge is silently ignored.

The selected GRAPH payload has exact fields `element_kind`, `scope`,
`nodes_digest`, and `edges_digest`. Its scope is `retained_directed_graph`.
The checker rehashes both arrays and compares them with the external request
and payload, then computes directed acyclicity by a bounded topological walk.
The complete typed namespace composition is also replayed under the selected
collection digest. The selected edge array is the claimed graph: this check
does not infer undeclared edges or transitive closure. Node membership alone
cannot certify edges; graph payload claims alone cannot replace retained
arrays. Selected edge order is canonical for one exact digest, rather than an
assertion of temporal order.

The external policy binds the installed implementation and this specification
by a mechanism digest, selected trust-root labels and a certificate byte
ceiling. The certificate embeds exact evidence bytes and the computed result;
offline recheck requires the independently selected request and policy,
executes the installed mechanism again and compares complete certificate
bytes. Trust-root labels are selections, not authentication of a graph maker.

`PASS` establishes only this finite retained graph's declared member/edge
consistency and acyclicity. A dangling endpoint, duplicate edge, cycle,
changed commitment, or wrong member set yields `FAIL`. Absent selected
evidence or exhausted valid operation/item/byte limits yields `UNKNOWN`.
Malformed or substituted policy, request, or certificate is rejected before
a computational verdict. Provenance, causal truth, external network behavior,
legacy Graph-profile conformance, privacy, consent, governance, security,
full GRAPH statics-tier and object-profile conformance remain
`NOT_ESTABLISHED`.
