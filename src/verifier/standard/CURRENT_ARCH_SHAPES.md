# Current architecture tensor-shape consistency

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) defines the bounded claim language; the Python module is one reference
checker. Computational model architecture (ARCH) means a represented operator
graph, not an executed model. JavaScript Object Notation (JSON) gives canonical
retained bytes; Secure Hash Algorithm 256-bit (SHA-256) binds those bytes.
Tensor dimensions, element counts and checker operation limits are dimensionless.

`verifier-current-object-obligations-1` with `ARCH-3.1` selects one current
statics proposition. It does not migrate a historical numbered profile. The
externally selected exact ARCH record occurs once in the selected finite typed
collection; its digest and the complete collection commitment reproduce. Its
payload has exactly `scope=retained-static-tensor-graph` and `graph_digest`.
The separately retained evidence has a `graph` with exactly `nodes` and
`outputs`. Its canonical digest must equal the payload commitment.

The graph is an ordered nonempty list of uniquely named nodes and a nonempty
list of unique selected outputs. Each node has exactly `name`, `op`, `inputs`,
`shape`. Names are nonblank, at most 256 characters. Every input must name an
earlier node, making cycles and unresolved references refutable. Every node
must be in the backward ancestry of a selected output. Shapes are integer lists
of rank one through four; every dimension is 1 through 2^31−1, and their
product is at most 2^53−1 for exactly representable element counts.

The supported static operator basis is deliberately small:

- `INPUT` has zero inputs and declares its positive shape.
- `MATMUL` has two rank-two inputs `[a,b]`, `[b,c]` and output `[a,c]`.
- `ADD` has two inputs with exactly equal shapes and the same output shape;
  broadcasting is outside this proposition.
- `RELU` has one input and an exactly equal output shape.

`PASS` means these retained, selected equations and graph relations replayed.
`FAIL` means available retained data contradicts them. Already present
payload-field, commitment-format or node contradictions remain `FAIL` even when
the graph input or selected output list is absent. `UNKNOWN` means required
retained evidence or a nonempty graph/output selection is absent after available
intrinsic contradictions have been checked, or a selected resource bound is
exhausted. Malformed or substituted external selections and certificates are
rejected. The checker replays exact retained bytes; source or specification
changes invalidate its installed mechanism digest.

This finite check does not establish tensor values, numerical results,
framework execution, backend portability, artifact completeness, source
authenticity, privacy, consent, governance, security, the entire ARCH statics
tier or an ARCH object profile. The installed descriptor also binds the
selection helper, namespace composition, evidence and certificate modules.
