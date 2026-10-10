# Current ARCH-2.1: retained execution order over a static tensor graph

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) specifies the claim; this Python mechanism is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes, and Secure
Hash Algorithm 256-bit (SHA-256) names commitments. Schedule positions, node
and edge counts and checking budgets are dimensionless.

`DOMAIN_OBLIGATIONS.md` carries no computational model architecture (ARCH)
rows. The tier-2 (dynamics) slot rationale names forward graph compilation,
layer fusion, dynamic routing and execution scheduling. This objective
mechanizes only a bounded part of execution scheduling. Every other named
facet stays `NOT_ESTABLISHED`.

The pair `verifier-current-object-obligations-1` / `ARCH-2.1` selects an
**execution-order** proposition. The parent request commits to an
independently selected exact `ARCH-3.1` request, policy and certificate, and
to one retained schedule. The parent retains these and replays the child
against the installed `ARCH-3.1` mechanism. Only a child `PASS` permits the
order check. A missing or `UNKNOWN` child, or a missing schedule, is
`UNKNOWN`. A child that fails, does not replay or is substituted is `FAIL`.

The child's retained static tensor graph supplies the node set and the
data-dependency edges, one edge from each listed input to its consumer. Every
retained node counts as an operator node, `INPUT` nodes included. The
retained schedule is a JSON list of node names whose canonical digest equals
the committed `schedule_digest`. It is `PASS` exactly when:

- every entry names a retained node;
- no node appears twice;
- every node appears; and
- for every edge, the producer's position is strictly before the consumer's.

The schedule need not repeat the graph's retained node order. Any
dependency-respecting order passes. An omitted, repeated or unknown entry, a
fused name not in the graph, or a consumer placed before its producer is
`FAIL`. Exhausting the operation or item budget is `UNKNOWN`. A malformed or
substituted request, policy or certificate raises the module error.

`PASS` means that executing the retained nodes in the retained order would
never read a tensor that had not yet been produced. It does **not**
establish:

- that any runtime, compiler or device executed this order;
- concurrency, timing or memory behaviour;
- that fused kernels are equivalent to the nodes they replace;
- dynamic routing or data-dependent control flow;
- tensor values or numerical equivalence;
- the whole ARCH dynamics tier, or object-profile conformance.

Privacy, consent, governance and security remain `NOT_ESTABLISHED`.

The certificate retains the child's certificate, request and policy, the
schedule, the parent request and the replay result. Public release of these
contents requires separate disclosure authority. A change to the parent or
child source, either selected specification, `NAMESPACE_OBJECTS.md`, the
retained bytes or the policy invalidates the pinned mechanism.
