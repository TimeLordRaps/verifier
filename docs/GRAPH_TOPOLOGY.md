# Graph topology: bounded experimental interpretation

> **Terms:** Verifier Standard (VSTD); application programming interface (API);
> command-line interface (CLI); JavaScript Object Notation (JSON).

**Maturity:** experimental, non-normative interoperability analysis. This is not a new
numbered profile, Graph wire-format migration, or supported top-level Python API.
The contract records an interpretation; the report records checking limits. Storing either
does not authenticate it or supply a receipt-conformance verdict.

## Representation, consistency, and support are different

A model can contain self-reference, loops, or a paradox candidate. The provenance of the
artifact describing that model is a separate structure: a cyclic light-switch model can
be stored in an artifact with an acyclic construction history. Existing Graph cycle
admission and assurance guards are unchanged; this analysis does not bypass them.

`TRUST` is the formal VSTD name for mechanism-earned forward artifact support, not an
acronym or actor rating. Circular support cannot manufacture TRUST. A graph, annotation,
successful parse, or consistent set of equations supplies neither independent evidence
for its premises nor a verdict about an unexamined process.

Keep these questions separate: **permission** asks whether an action is authorized;
**knowledge** asks what evidence establishes; **inference** asks what follows under
specified rules and assumptions. A valid inference does not establish its premises or
grant permission. Topology analysis does not execute a control action.

## Two meanings of acausal, explicitly distinguished

**Simultaneous equations** have no chosen evaluation direction. They constrain values
together, rather than prescribing which value must be computed first. This agrees with
the equation-versus-assignment distinction in the
[Modelica 3.6 equations specification](https://specification.modelica.org/maint/3.6/equations.html).
It does not mean that physical effects travel backward in time.

**Backward-time relations** explicitly point toward an earlier coordinate of a declared
clock. Each relation means `t(target) = t(source) + offset`. `backward_time` requires
a negative offset, `forward_time` positive, and `same_time` zero. `tick` denotes an
integer logical step; `nanosecond` denotes an integer coordinate in units of one
billionth of a second. Each `clock_id` uses one unit. Equalities are checked within
each clock, not across unsupplied clock mappings.
Representing or satisfying these relative equalities does not demonstrate physical
retrocausation, measure time, authenticate a timestamp, or establish a causal mechanism.

## Stored contract and bounded checker

Import directly from the experimental module `verifier.interoperability.graph_topology`;
these names are not top-level or interoperability-facade exports:

```text
GraphTopologyContract.from_dict(mapping)
contract.to_dict()
graph_topology_binding_digest(graph)
analyze_graph_topology(graph, contract, max_assignments=4096)
```

The contract identifier is `VSTD-GRAPH-TOPOLOGY-EXPERIMENTAL-0.1`; the report identifier
is `VSTD-GRAPH-TOPOLOGY-REPORT-EXPERIMENTAL-0.1`. Top-level keys are `schema_version`,
`graph_digest`, `bindings`, `constraint_logic`, `equations`, `temporal_relations`, and
`paradox_candidates`. Each binding supplies `variable_id`, `artifact_id`,
`transformation_id`, `port_direction` (`input` or `output`), and `role`, identifying an
exact graph port. Equation and temporal endpoints use these variable identifiers.
Obtain `graph_digest` with `graph_topology_binding_digest`; do not substitute a label,
filename, or unrelated digest. Graph changes require a fresh binding and reanalysis.
The checker coordinate records named source files read locally during the call. It does
not attest the loaded process, interpreter or complete dependency closure. Recheck retained
inputs in the intended environment; a carried report and its digests are not self-authenticating.
The [contract schema](../standard/schemas/graph-topology.schema.json) checks shape only;
the runtime additionally rejects ambiguous bindings and enforces exact types and references.
Runtime offsets must be integers, not floating-point values or Booleans. Structurally valid
contracts exceeding semantic work bounds remain representable but not established.

The named interpretation `classical-boolean-equations-v1` evaluates simultaneous
equalities using `true`, `false`, `identity`, `not`, `and`, `or`, and `xor` operations.
Boolean values are dimensionless and strictly two-valued. The checker exhaustively
examines at most 12 variables, 128 equations, and 4,096 assignments; a smaller
`max_assignments` limits the search further. It is not a general real-equation solver,
philosophical paradox oracle, or independent proof-certificate producer.

The report keeps `structural`, `boolean_consistency`, and `temporal_consistency`
separate, with `CONSISTENT`, `CONFLICTED`, `NOT_ESTABLISHED`, or `INVALID` facet states.
There is no overall `PASS`; `verification_effect` remains `NONE`:

| Observation | Meaning and boundary |
|---|---|
| Self-reference or cyclic structure | A structural finding, not automatically a contradiction. |
| Satisfying Boolean assignment | A witness for the encoded equalities, not uniqueness, convergence, physical truth, or TRUST. |
| Exhaustive Boolean contradiction or inconsistent temporal equalities | `CONFLICTED` for those encoded constraints; retain the conflicting interpretation. |
| Missing or unsupported semantics, or exhausted search budget | `NOT_ESTABLISHED`; absence of a found witness is not refutation. |
| Wrong exact graph or variable binding | `INVALID`; do not silently reinterpret the contract against another graph. |
| Paradox candidate annotation | A retained description, not a logical conclusion. |

## Non-critical reading examples

These examples explain semantics; they are not claims of an executed physical system.

| Encoded subject | Interpretation |
|---|---|
| Boolean light switches `a = b`, `b = a` | Consistent simultaneous loop: both off or both on. No unique state is established. |
| Boolean light switch `a = not a` | Neither classical Boolean value satisfies the equality. The self-reference is representable; its constraints conflict. |
| `a[next] = not a[now]`, initially off | A different, time-indexed model: ordinary alternation is not the simultaneous negating self-reference. Any finite encoding must declare its own variables and bounds. |
| Counter coordinates `t(B) = t(A) + 1 tick`, `t(A) = t(B) - 1 tick` | Compatible forward/backward relations; no physical backward execution is asserted. |
| Counter coordinates `t(B) = t(A) + 1 tick`, `t(A) = t(B) + 1 tick` | Inconsistent relative equalities in one clock, independent of the diagram's appearance. |

## Invocation and catalog boundary

Supply a graph inspection envelope and its matching stored contract to the experimental CLI:

```text
vstd data topology RECEIPT --contract CONTRACT --json
```

`RECEIPT` and `CONTRACT` are supplied file paths. Omit `--json` for human-readable output.
The CLI reads strict JSON, bounded to 2,097,152 bytes per document. Exit code 1 reports
an `INVALID` or `CONFLICTED` facet; otherwise code 2 reports any `NOT_ESTABLISHED` facet,
including omitted Boolean or temporal constraints. Code 0 requires all three facets
`CONSISTENT`. These codes are diagnostic policy, not conformance or physical causality.
Use the module API when inputs are already loaded; changed inputs require a fresh check.
This does not validate the enclosing receipt or its payload files. The reader rejects
nonregular files and bounds document bytes; it does not promise race-free filesystem
security against concurrent privileged replacement. Run the [non-critical specimen](../examples/graph_topology/README.md)
to create real retrievable declaration bytes and matching inspection documents.

Catalog matching can identify a candidate for the exact planned VSTD-2 facet with
`mechanism:graph-topology-analysis` and `relation:graph-topology`. Matching does not run
the analyzer, supply result evidence, complete the verification surface, or grant TRUST.
The static mechanism takes typed graph and contract inputs; it is not a serialized parser.
Permission to run a mechanism and evidence from actually running it remain separate gates.
