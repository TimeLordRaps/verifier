# zero-identity/zero-knowledge (ZIZK)-Verifier Standard (VSTD) experiment: zero identity, examined

**Status:** experimental. Not normative, not part of any VSTD layer, not implemented by
the `verifier` package, and not referenced by any receipt. Nothing here carries a wire
identifier, a schema `$id`, or a canonical digest.

## The question

Can "Zero Identity" be an operationally safe optional VSTD mode, or is the correct
mechanism something bounded — identity minimization, pseudonymity, selective disclosure?

## The answer

**The label is rejected for public use.** The construction it names does not remove
identity; it withholds *civil* identity while retaining a pseudonymous coordinate, a key
binding, a trust root, an issuer, and a revocation source — every one of which is an
identity coordinate and a correlation handle. Calling that "zero identity" overstates the
privacy achieved and hides the coordinates that remain. The mechanism this experiment
retains is **bounded identity disclosure**: civil identity withheld, authorization
semantically reevaluable from public coordinates conditional on declared external checks,
and every other identity property reported honestly as `UNKNOWN`,
`CONFLICTED`, or `REFUTED` rather than assumed.

Full reasoning and the exact claims that are and are not justified:
[`ROUND1_ZERO_IDENTITY_REPORT.md`](ROUND1_ZERO_IDENTITY_REPORT.md).

## Contents

| Path | What it is |
|---|---|
| [`SEMANTIC_MODEL.md`](SEMANTIC_MODEL.md) | term separation, statuses, minimum coordinates, prohibited inferences |
| [`THREAT_MODEL.md`](THREAT_MODEL.md) | sixteen threats, mitigations, residual risk, falsification conditions |
| [`model/zero_identity_model.json`](model/zero_identity_model.json) | the machine-readable model |
| [`evaluate.py`](evaluate.py) | standard-library evaluator over one disclosure record |
| [`fixtures/`](fixtures) | positive, negative, `UNKNOWN`, and `CONFLICTED` records with expected results |
| [`tests/test_zero_identity.py`](tests/test_zero_identity.py) | validation suite, one test per blocked inference |
| [`run_validation.py`](run_validation.py) | pytest-free runner for the same fixtures |

## Running it

```bash
python experiments/zizk_vstd/zero_identity/run_validation.py
python -m pytest experiments/zizk_vstd/zero_identity/tests -q
```

The repository suite (`python -m pytest -q`) sets `testpaths = ["tests"]` and does not
collect this directory, which is deliberate: an experiment must not gate conformance.

## Constraints observed

- No dependency added to `verifier-standard`; the evaluator is standard library only.
- No frozen wire identifier, schema `$id`, receipt digest, console alias, lifecycle token,
  or conformance behavior is touched. See
  [`../../../standard/WIRE_IDENTIFIERS.md`](../../../standard/WIRE_IDENTIFIERS.md).
- No cryptographic guarantee is invented. Signature and revocation results are fixture
  inputs here. A deployment would have to produce them through a named real protocol; the
  model decides only what may be concluded from the asserted results.
- `UNKNOWN` and `CONFLICTED` are preserved as results, per
  [`../../../AGENTS.md`](../../../AGENTS.md) section 2.
