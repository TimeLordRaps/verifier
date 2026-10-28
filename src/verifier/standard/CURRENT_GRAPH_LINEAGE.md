# Current GRAPH-9.2: direct operand lineage and endpoint content

Verifier Standard (VSTD); JavaScript Object Notation (JSON); Secure Hash
Algorithm 256-bit (SHA-256). Digests, identifiers, indices and operation/item
counts are dimensionless. Evidence and certificate bounds count encoded bytes.
This experimental objective compares selected retained records. It establishes
no physical protection, record-maker authenticity, historical lineage or causation,
authority, enforcement, generic GRAPH-9.1 receipt inclusion or whole security tier.

## Selected proposition

Let C be the complete externally committed finite canonical collection, with
unique identifiers. Let N be the sorted identifiers of the selected GRAPH's
**direct members**. Let B be the set of ordered pairs (u, v) such that u and v
belong to N and v occurs in any named operand target list of C[u]. Let E be the
selected sorted unique directed edge array. D(x) is SHA-256 over the full
canonical namespace record x. PASS requires E = B and exactly one endpoint-content
row per pair in E, with source_digest = D(C[u]) and target_digest = D(C[v]).
The separately selected GRAPH-3.1 certificate must also replay PASS for this
same GRAPH record, collection, node array and edge array.

Named roles that point from the same source to the same target collapse to one
pair in B. A reference to a record outside N is excluded from this projection.
An edge a -> c is not inferred from a -> b -> c. A nested GRAPH member is one
direct node; its members are not recursively substituted for it. All references,
including those outside N, must still resolve in C under native typed composition.
An empty B and empty E pass vacuously when the remaining predicates pass. The
selected GRAPH itself still needs nonempty direct members.

GRAPH-3.1 checks declared arrays and acyclicity and explicitly does not infer
undeclared edges. GRAPH-9.1's separately owned generic receipt-inclusion predicate
does not compare these arrays with operand content. Neither predicate is replaced
or renamed. This parent adds the explicit content-relation comparison.

## External selection and retained representation

The semantic version is `verifier-current-object-obligations-1`; coordinate
`GRAPH-9.2`; represented kind `GRAPH`. The exact request contains:

```
schema_version semantic_version coordinate proposition_digest object_kind
subject_id object_digest collection_digest nodes_digest edges_digest
edge_contents_digest evidence_ref policy_digest limits
child_request child_policy child_certificate_digest
```

The child selection is independently admitted by the installed GRAPH-3.1
request and policy readers. Its subject_id, object_digest, collection_digest,
nodes_digest and edges_digest must equal the parent selection. Its own policy
digest and installed mechanism must reproduce. Parent request parameters bind
the canonical digest of the entire selected request, including nested child
selection, raw child certificate digest and exact parent limits.

The evidence is canonical JSON with exactly:

```
{schema_version, objects, inputs, edge_contents, child_certificate}
```

`objects` is the complete list of `{object_id, kind, payload, operands}` records.
`inputs` is `{nodes, edges}`; an edge is `{source, target}`. `edge_contents` is a
sorted unique array of `{source, target, source_digest, target_digest}` rows with
the same pair order as E. Parent-specific claims do not add fields to the child
GRAPH payload: GRAPH-3.1 retains its exact `element_kind`, `scope`, `nodes_digest`
and `edges_digest` payload contract. `child_certificate` is canonical base64 of
the exact separately selected raw certificate bytes, or explicit null if absent.
An empty string, invalid/noncanonical base64 or another presented child is malformed
or refuted. `inputs` or `edge_contents` may be explicit null for missing evidence.
An omitted required envelope field is malformed, not a substitute for explicit
absence. An absent whole evidence bundle gives UNKNOWN.

## Checking, precedence and bounds

Checking first parses exact canonical evidence and charges every structure value
visited by the shared Budget inspection. Each reconstructed record costs one
parent operation. Native typed composition admits C under its separately selected
composition budget. After admission, the separately selected child is replayed
even if parent-specific arrays are absent or later refuted. Native child work has
its own bound in the selected child request; it is not counted as parent operations.
The opaque base64 child is bounded by encoded length before allocation and then
by decoded length, raw byte digest and native full replay.

For relation derivation each direct node, named role and target costs one parent
operation, including targets outside N. Each retained edge and endpoint-content
row costs one operation. The operation count includes structure inspection and
record reconstruction but excludes native composition and child replay work.
The certificate records this deterministic accounting for the selected evidence.

Contradictory subject, collection, node or array commitments, injected or omitted
pairs, wrong endpoint record digests, repeated/unsorted edges or manifest rows,
refused child replay and native child FAIL give FAIL. Native child UNKNOWN or
explicit absent evidence gives UNKNOWN if no admitted checked refutation exists.
A child UNKNOWN, absent child or exhausted child byte bound never masks a checked
parent relation/content refutation. A checked child FAIL remains FAIL when later
parent-specific evidence is absent or a later parent limit prevents more checking.
Admission/budget exhaustion before any refutation is established gives UNKNOWN.
Malformed selected request/policy or substituted retained certificate is rejected
at the external replay boundary. Noncanonical evidence is a computational FAIL.

Ceilings: 2,000,000 parent operations; 4,096 items; 256 records and direct nodes;
4,096 selected edges/content rows; 100,000 composition operations; 8 mebibytes
of evidence and decoded child certificate; 4 mebibytes each of collection payload
and encoded reference content; 16 mebibytes of parent certificate. Native child
policy may select a lower certificate ceiling. Parent limits are positive plain
integers at or below these ceilings. Parent evidence-byte admission precedes its
domain checking; oversized evidence cannot establish a refutation from unseen bytes.

## Replay and claim limits

The certificate retains selected evidence and complete result. Offline recheck
requires the independently selected request and policy, reruns the installed
mechanism and compares complete canonical certificate bytes. A rehashed false
result still fails replay. The mechanism digest binds parent code, native GRAPH-3.1
code, shared evidence/namespace/receipt/canonicalization/selection/budget code,
and NAMESPACE_OBJECTS, CURRENT_GRAPH_STATICS and this specification.
Polish separately pins the public route, inventory and this mechanism/specification.
Changed selected records, collection, arrays, manifest, child certificate,
request/policy/limits, code or pinned specification invalidates affected evidence.
Configured trust-root labels do not authenticate an issuer or grant authority.

One selected instance requires a parent certificate and a distinct GRAPH-3.1
child certificate. A legitimately shared exact child may support multiple parents;
copied bytes are not additional distinct certificates. Other GRAPH-1.1 or GRAPH-9.1
objectives require their own separately selected certificates. Complete required
certificate inventory and whole-slot/profile closure remain NOT_ESTABLISHED.

The public command requires semantic version, objective, represented kind and
external request/policy files. Privacy redaction cannot preserve this full retained
certificate's verdict; redacted witness material requires a different proposition.
Publication, wheel/host qualification and full resulting-source regression remain
separate gates.
