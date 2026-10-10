# Verifier-object contract

> **Acronyms:** Secure Hash Algorithm 256-bit (SHA-256); Verifier Standard (VSTD).

This experiment-local contract wraps an existing verifier without modifying it. It is serialized and hashed, but it is not a VSTD wire schema.

## Required fields

| Field | Meaning |
|---|---|
| `identifier` | Source-scoped verifier and exact commit |
| `source_digest` | SHA-256 over the exact vendored source bytes |
| `instance_schema` | Human-readable accepted instance surface |
| `witness_schema` | Human-readable candidate surface |
| `invocation` | Exact class method called by the wrapper |
| `configuration` | Observable wrapper configuration |
| `deterministic` | Whether repeated calls on equal values should agree |
| `resource_limits` | Native or outer bounds; absence is stated |
| `result_semantics` | Accepted, rejected, error, and indeterminate meanings |
| `diagnostics` | Captured diagnostic channel and possible absence |
| `trust_roots` | Code/runtime/predicate assumptions |
| `candidate_canonicalization` | Digest serialization rule |
| `verification_cost` | Measurement and asymptotic boundary |
| `acceptance_proves` | Exact bounded implemented-predicate conclusion |
| `rejection_proves` | Exact candidate failure conclusion |
| `neither_proves` | Explicit prohibited upgrades |

Every invocation adds canonical instance and candidate digests, elapsed nanoseconds, bounded diagnostics, and one of:

- `ACCEPTED`: the exact `is_solution` method returned truthy;
- `REJECTED`: it returned falsey;
- `ERROR`: it raised at the wrapper boundary;
- `UNKNOWN`: execution evidence is absent or an outer limit prevents a verdict.

## Primary and reserve selection

| Domain / role | Primary verifier | Predeclared reserve | Witness | Useful diagnostics |
|---|---|---|---|---|
| Stable matching / development | AlgoTune `StableMatchingTask.is_solution` | `matching==1.4.3` validity and stability checks | `{"matching": permutation}` | Blocking pair or format logging from primary |
| Graph isomorphism / held out | AlgoTune `GraphIsomorphism.is_solution` | NetworkX 3.5 graph relabel/equality check | `{"mapping": permutation}` | Format, permutation, edge, or degree logging from primary |
| Integer factorization / held out | AlgoTune `IntegerFactorization.is_solution` | SymPy 1.14 exact product and primality | `{"p": int, "q": int}` | Format, product, positivity, or primality logging from primary |

The reserves were selected before evaluation. They are independent cross-check adapters and may replace a primary only if a licensing, packaging, or technical incompatibility is documented before evaluation begins. No such replacement occurred.

Reserve coordinates are:

| Domain | Source / license | Exact invocation | Cost, diagnostics, and trust boundary |
|---|---|---|---|
| Stable matching | [`matching==1.4.3`](https://github.com/daffidwilde/matching), MIT | Construct `StableMarriage` from the bound preference tables, apply the candidate permutation, then call `check_validity()` and `check_stability()` | Polynomial bounded checks; exceptions are recorded by type; trusts the pinned package and the experiment adapter |
| Graph isomorphism | [NetworkX 3.5](https://github.com/networkx/networkx), BSD-3-Clause | Relabel the left graph by the candidate permutation and call `networkx.utils.graphs_equal` against the right graph | Polynomial bounded graph comparison; exceptions are recorded by type; trusts the pinned package and adapter |
| Integer factorization | [SymPy 1.14.0](https://github.com/sympy/sympy), BSD-3-Clause | Check exact product and call `sympy.isprime` on both candidate factors | Exact product plus delegated primality cost; exceptions are recorded by type; trusts the pinned package and adapter |

All reserve invocations use the same canonical instance and witness shapes as the
primary. They run under Python 3.12 on the public bounded instances and have no
internal wall-time or memory limit. Reserve agreement is corroboration only; it
does not upgrade the native primary predicate into domain-global truth.

## Cost and trust

Verifier cost is measured per call. Stable matching and graph isomorphism checks are polynomial in the bounded problem size; primality cost is delegated to the pinned SymPy implementation. These are implementation observations, not proofs of verifier soundness.

The wrapped primary verifiers expose no internal timeout or memory limit, and this
experiment does not claim an in-process hard limit around them. Safety comes only
from the preregistered small instance bounds. A process-level interruption would
leave execution evidence absent and therefore `UNKNOWN`; it would not be a
rejection.

Acceptance proves only that the supplied candidate passes the selected implemented predicate for the exact bound instance. It does not prove global existence beyond that candidate, completeness of attempted routes, soundness of source code or dependencies, actor identity, independence, authorization, or cross-domain generalization.
