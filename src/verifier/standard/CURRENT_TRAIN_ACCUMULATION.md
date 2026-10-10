# Current TRAIN-3.2: retained accumulation order, reduced two ways

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) specifies the claim; this Python mechanism is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes, and Secure
Hash Algorithm 256-bit (SHA-256) names commitments. Values, results and
bounds are Institute of Electrical and Electronics Engineers (IEEE) 754
binary64 numbers and are dimensionless. Counts and checking budgets are
dimensionless.

## Row

The standard row in `DOMAIN_OBLIGATIONS.md`, verbatim:

| TRAIN-3.2 | Accumulation order | The order reductions actually occur in is observed by reducing a retained sequence two ways, and its effect is bounded. | TRAIN-3.1 | statics:accumulation |

This objective mechanizes a bounded, strict subset of that row. The row
depends on `TRAIN-3.1`, which requires observing the executing hardware's
floating-point behaviour. Retained bytes cannot decide that, and it is
excluded here.

## Selection

The pair `verifier-current-object-obligations-1` / `TRAIN-3.2` selects one
exact `TRAIN` namespace record in a finite typed collection. The collection
must pass the namespace composition contract, which requires the `data`,
`events`, `bench` and `arch` operands. The record's payload must contain
`reduction_digest`, the canonical commitment to the retained reduction
record. Other payload fields are carried but not read, so the same record may
also carry the fields the `TRAIN-1.x`, `2.x` and `4.1` checks interpret.

## Retained reduction

The retained reduction record has exactly these fields:

- `operation`: `binary64-sum-steps-1`. Any other name is `UNKNOWN`.
- `values`: a nonempty list of finite binary64 numbers. Each is written as the
  canonical text from Python's `float.hex`.
- `retained_order`: the order the run states its reduction occurred in.
- `retained_result`: the result the run retained, in canonical hexadecimal
  text.
- `alternative_order`: a second order.
- `order_effect_bound`: a nonnegative finite binary64 bound, in canonical
  hexadecimal text.

An order is a list of `n - 1` additions over `n` values. Each addition is a
pair of operands. Operand `j < n` names value `j`. Operand `j >= n` names the
result of addition `j - n`, which must come earlier. Every operand is read
exactly once, so an order is one full binary addition tree. It is a
sequential fold, a pairwise tree or any other association.

If `values` or either order is null, the result is `UNKNOWN`. A declared
result or bound with no retained sequence and orders is not an observation.

## Check

The checker first verifies that its own host's float addition is binary64
round-to-nearest-even. It does this with fixed tie, double-rounding,
signed-zero and overflow vectors; any failure is `UNKNOWN`.

It then reduces the retained sequence two ways with that addition. `PASS`
requires all of the following:

- the retained order reproduces `retained_result` bit for bit;
- the two orders are different addition trees up to commutativity:
  - swapping the operands of an addition does not count as a different order;
  - reordering independent additions does not count as a different order;
- no partial sum overflows;
- the exact rational difference between the two results is at most
  `order_effect_bound`.

Each of these failures is `FAIL`:

- a bound tighter than the observed effect;
- an altered sequence that no longer reproduces the retained result;
- a second order that is not actually different;
- an operand read twice, or an addition that reads a later one;
- noncanonical text;
- a negative bound.

The observations report the value count, whether the two results differ bit
for bit, the exact effect as a reduced fraction, and the operations used.
Exhausting a budget is `UNKNOWN`. A malformed or substituted request, policy
or certificate raises the module error.

## Exclusions

`PASS` establishes that this retained sequence, reduced two ways, differs by
no more than the retained bound under binary64 round-to-nearest-even
addition. It does **not** establish:

- observation of the executing hardware's arithmetic (`TRAIN-3.1`);
- that the run executed the retained order. Reproducing the retained result
  is consistent with that order but does not prove it, because other orders
  can give the same value;
- the effect of other orders, or of reductions the record does not retain;
- fused multiply-add, extended or mixed precision, compensated, stochastic
  or non-default rounding;
- loss, gradient, update or training correctness;
- the whole TRAIN statics tier, or object-profile conformance.

Privacy, consent, governance and security remain `NOT_ESTABLISHED`.

## Relation to other TRAIN rows

`TRAIN-1.2` binds the *declared* format and accumulation order.

`TRAIN-2.1` to `2.5` recompute losses, gradients and updates in one fixed
order. `TRAIN-4.1` checks that the retained steps form an uninterrupted
sequence.

None of them reduces one retained sequence two ways or bounds the difference
between the two results. This objective adds that observation and binds no
step, batch or checkpoint.

## Invalidation

The certificate retains the selected collection, the reduction record, the
request and the replay result. Public release of these contents requires
separate disclosure authority. A change to the native source, this
specification, `DOMAIN_OBLIGATIONS.md`, `NAMESPACE_OBJECTS.md`, the retained
bytes or the policy invalidates the pinned mechanism.
