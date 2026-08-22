# VSTD / VERIFIABLE

VSTD is an independent open specification and reference implementation for attaching
bounded, machine-checkable evidence to computational claims and provenance graphs.

**Status:** project specification. VSTD is not an accredited, consensus, IETF, ISO,
or W3C standard. A `VERIFIED` result is always relative to the declared verification
surface, mechanisms, evidence, and trust boundaries.

## What is included

- `VSTD-0.1`: claim receipts, independent judgments, provenance, and reproduction levels;
- `VSTD-DATA-0.1`: content-addressed dataset and computational provenance hypergraphs;
- experimental `VSTD-0.2`: loci, facets, coordinates, seams, residuals, horizons, and
  bounded self-closure;
- `VSTD-3.0`: accelerator-neutral device/firmware evidence, execution accounting,
  authenticated continuity, partitions/topology, provider evidence, and bounded fleet
  claims;
- JSON Schemas for the implemented receipt and geometry documents;
- a zero-required-dependency Python reference subset;
- an optional logits-level constraint kernel using one grammar engine at its boundary;
- deterministic examples and conformance tests.
- a non-normative competition-evaluation profile for predictive systems and other
  scored submissions.

VSTD 3 includes a 37-profile data-driven accelerator registry, strict NVIDIA/AMD/
generic offline normalization, provider fixture boundaries, and a virtual firmware
contract emulator. Current commodity adapters do **not** claim complete mediation.

The public reference package deliberately excludes private operational material and
repository-specific adapters. Those adapters must declare their own observable seams,
evidence, and horizons rather than being silently treated as part of VSTD.

## Install this source release

```bash
python -m pip install .
```

The distribution name is `verifiable-standard`; the import package and command remain
`verifiable`. The base install has no required third-party runtime dependencies.
Install only the boundary you need:

```bash
python -m pip install ".[yaml]"
python -m pip install ".[llguidance]"
python -m pip install ".[torch]"
python -m pip install ".[jsonschema]"
```

## Capture and check a generic computation

```bash
verifiable run examples/generic_run/manifest.json --output /tmp/vstd-receipt
verifiable inspect /tmp/vstd-receipt
verifiable validate /tmp/vstd-receipt
verifiable reproduce /tmp/vstd-receipt --rerun
```

`validate` checks the receipt's stable content. `reproduce --rerun` re-executes a
generic-run command when the manifest permits it. These operations verify recorded
execution and artifact relationships; they do not establish empirical truth outside
the declared surface.

## Accelerator accountability

List or inspect registry profiles:

```bash
vstd hardware list --json
vstd hardware inspect nvidia.hopper --json
```

Run the test-only firmware contract emulator, then independently verify its receipt:

```bash
vstd hardware emulate \
  --output /tmp/vstd3/receipt.json \
  --created-at 2026-08-21T20:00:00Z \
  --key-id demo-key \
  --key-hex 1111111111111111111111111111111111111111111111111111111111111111

vstd hardware verify /tmp/vstd3/receipt.json \
  --key demo-key=1111111111111111111111111111111111111111111111111111111111111111
vstd continuity verify /tmp/vstd3/receipt.json \
  --key demo-key=1111111111111111111111111111111111111111111111111111111111111111
vstd claims evaluate /tmp/vstd3/receipt.json \
  --key demo-key=1111111111111111111111111111111111111111111111111111111111111111
```

The HMAC key is a deterministic test fixture, not a production secret or physical root
of trust. Read `VSTD3_THREAT_MODEL.md`, `VSTD3_VENDOR_INTEGRATION.md`, and
`CLAIMS_AND_LIMITS.md` before publishing a hardware claim.

## Predictive-AI and competition evaluation

[`COMPETITION_EVALUATION_PROFILE.md`](COMPETITION_EVALUATION_PROFILE.md) maps the
existing VSTD primitives onto a scored-evaluation chain: dataset snapshot, model or
agent build, prediction timestamp, submission artifact, evaluator version, outcome
resolution, and score report. It is a non-normative integration profile, not a claim
that any conference, competition, benchmark, or organizer has adopted or endorsed
VSTD.

This is where the bounded semantics matter most: a receipt can bind the submission and
scorer that produced a recorded result, but it cannot by itself establish hidden-test
integrity, outcome truth, absence of leakage, or leaderboard standing.

## Exactly what claims mean

Read [`CLAIMS_AND_LIMITS.md`](CLAIMS_AND_LIMITS.md) before using `VERIFIED`,
`independent`, `provenance`, `complete`, or `self-closed` in public wording. It gives a
plain-language translation for each supported claim, the evidence required, and the
stronger conclusion that does not follow.

## Why this exists

AI-generated software increases the rate at which code, models, data transformations,
and claims are produced. VSTD makes their observable lineage and verification boundary
more inspectable. It can improve auditability, reproducibility, incident analysis, and
downstream challenge propagation when integrated. It cannot by itself prove general AI
safety, expose hidden model internals, prevent catastrophic behavior, or compensate for
missing instrumentation.

## Specification order

1. Read `standard/VSTD-0.1.md` for the base receipt contract.
2. Read `standard/VSTD-DATA-0.1.md` for provenance hypergraphs.
3. Read `standard/VSTD-0.2.md` for the experimental verification geometry.
4. Read `standard/VSTD-3.0.md` for accelerator accountability.
5. Inspect `receipts/schema/` and the reference modules under `src/verifiable/`.
6. Run the tests before claiming conformance.

## Project process

See `GOVERNANCE.md`, `CONTRIBUTING.md`, and `SECURITY.md`. Changes that strengthen a
claim without stronger evidence are non-conforming.

## License

Apache License 2.0. See `LICENSE` and `NOTICE`. The license includes an express
patent grant from contributors, subject to its terms. VSTD is not affiliated with or
endorsed by the Apache Software Foundation.
