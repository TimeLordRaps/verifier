# VSTD / VERIFIABLE

VSTD is an independent open project specification and reference implementation
for attaching bounded, machine-checkable evidence to computational claims and
provenance graphs.

**Status:** founder-maintained alpha project specification. VSTD has no
demonstrated external adoption, independent implementation, interoperability
deployment, or third-party security review. It is not an accredited, consensus,
IETF, ISO, or W3C standard. A `VERIFIED` result is always relative to the
declared coordinate, evidence, mechanisms, bounds, and trust roots.

## Why VSTD exists

A computational result usually arrives without a machine-readable answer to:
*what exactly was claimed, which bytes and mechanisms support it, where does the
claim stop, and what evidence would overturn it?* VSTD records those answers in
bounded receipts and provenance graphs. It does not turn the record into empirical
truth or global completeness.

The smallest working example executes a deterministic word-count program, records its
declared inputs and outputs, validates the resulting receipt, and reruns the command to
test whether the outputs remain byte-identical. See
[`examples/generic_run`](examples/generic_run).

## The two-axis ladder

Specification numbers identify verification depth, not revisions:

Each row is a separately evidenced verification question. A higher-layer result never
supplies a lower-layer result. An aggregate depth of `N` is permitted only when distinct
evidence passes every layer from 1 through `N`.

| Object mechanics | Closes | Graph dynamics |
|---|---|---|
| `VSTD-1` Claim mechanics | malformed or tampered statement | `VSTD-Graph-1` Recorded lineage |
| `VSTD-2` Verification surface | verdict leaking outside its coordinate | `VSTD-Graph-2` Bounded collection surface |
| `VSTD-3` Substrate accountability | lying or unaccountable evidence source | `VSTD-Graph-3` Accountable provenance closure |
| `VSTD-4` Refutability | a claim that cannot leave its declarant and be challenged | `VSTD-Graph-4` Refutable transformation closure |
| `VSTD-5` Witness corroboration | pseudo-independence | `VSTD-Graph-5` Corroborated verification network |

Layers 1 through 4 are self-discernable. Layer 5 requires a second party to
exist and act. VSTD-5 and the corresponding witness protocol remain **DRAFT** in
this release.

Read [`standard/LADDER.md`](standard/LADDER.md) first and
[`standard/WIRE_IDENTIFIERS.md`](standard/WIRE_IDENTIFIERS.md) for frozen wire
identifiers and historical project filenames. Layers compose only through their
separately checked results; they do not supply or replace one another.

## What v1.0.1 includes

- VSTD-1 through VSTD-4 specifications and a draft VSTD-5 interface;
- VSTD-Graph-1 through VSTD-Graph-5 profiles;
- a fourteen-rung VSTD-4 depth computation with a certificate explaining the
  first unreachable rung;
- `VSTD4-GDC-1`, a grounded three-valued decision certificate whose checker binds
  the formula to the declared claim rather than checking syntax alone;
- a trusted kernel physically isolated from solver and policy producers;
- machine-readable refutation surfaces, precommitment, availability, challenge,
  degradation, and composition records;
- computed Graph levels over membership, complete provenance ancestry, admissible
  status, and transformation-edge evidence;
- VSTD-3 accelerator-accountability mechanisms and a 37-profile registry;
- frozen compatibility for historical `VSTD-0.1`, `VSTD-0.2`, `VSTD-3.0`, and
  `VSTD-DATA-0.1` receipt wire identifiers;
- JSON Schemas, deterministic examples, and conformance tests.

`VSTD4-GDC-1` is a project-defined format. The reference checker declares exactly
which format fragment it implements; passing that checker is not external validation.

## Install this source release

```bash
python -m pip install .
```

The distribution name is `verifiable-standard`. `verifier` is the canonical
command. `verifiable` remains a permanent compatibility alias because issued
receipts bind that command in their falsification instructions.

The base install has no required third-party runtime dependencies. Install only
the boundary you need:

```bash
python -m pip install ".[yaml]"
python -m pip install ".[llguidance]"
python -m pip install ".[torch]"
python -m pip install ".[jsonschema]"
```

## Capture and check a generic computation

**Security boundary:** a manifest contains an executable command. `verifier run` does
not sandbox it. Inspect the plan first and execute only a trusted manifest inside an
appropriate operating-system or container isolation boundary. The plan exposes declared
paths but cannot enumerate everything the subprocess may access.

```bash
verifier plan examples/generic_run/manifest.json --json
verifier run examples/generic_run/manifest.json --output /tmp/vstd-receipt
verifier inspect /tmp/vstd-receipt
verifier validate /tmp/vstd-receipt
verifier reproduce /tmp/vstd-receipt --rerun
```

`validate` checks stable receipt content. `reproduce --rerun` re-executes the
declared command when permitted. These operations verify recorded execution and
artifact relationships; they do not establish empirical truth outside the
declared surface.

## Review and feedback wanted

The current goal is adversarial review, not an adoption claim. Useful public feedback
includes a counterexample to a normative statement, an ambiguous wire-format rule, an
independent parser result, an interoperability failure, or a receipt that passes when it
should fail. Use the repository issue forms. Report sensitive security findings through
the private route in [`SECURITY.md`](SECURITY.md), never in a public issue.

## VSTD-4 certificates

The certificate has four soundness-relevant blocks and one untrusted accelerator:

```text
DecisionCertificate (VSTD4-GDC-1)
├── header       binding, verdict, cost tier, and declared counts
├── formula      normalized clauses
├── grounding    variables to facts; clauses to named rules
├── decision     model, proof, witness, or bounded transcript
└── hints        untrusted and strippable
```

The checker rejects over-budget headers before checking proof steps, rejects tier
inflation, validates grounding before the decision block, and returns `UNKNOWN`
when a declared bound is exhausted. A correct proof over a formula grounded to
the wrong artifact is rejected.

See [`standard/VSTD-4.md`](standard/VSTD-4.md) and
[`receipts/schema/vstd4_certificate.json`](receipts/schema/vstd4_certificate.json).

## Accelerator accountability

List or inspect registry profiles:

```bash
vstd hardware list --json
vstd hardware inspect nvidia.hopper --json
```

The included firmware emulator and HMAC fixtures are deterministic tests, not
production hardware roots of trust. Read
[`docs/layers/vstd-3/threat-model.md`](docs/layers/vstd-3/threat-model.md),
[`docs/layers/vstd-3/vendor-integration.md`](docs/layers/vstd-3/vendor-integration.md),
and [`docs/CLAIMS_AND_LIMITS.md`](docs/CLAIMS_AND_LIMITS.md) before publishing a
hardware claim.

## Predictive systems and scored evaluation

[`docs/profiles/competition-evaluation.md`](docs/profiles/competition-evaluation.md)
is a non-normative integration profile. It does not claim adoption or endorsement
by any benchmark, conference, competition, or organizer.

A receipt can bind the submission and scorer that produced a recorded result. It
cannot by itself establish hidden-test integrity, outcome truth, absence of
leakage, or leaderboard standing.

## Claim boundaries

Read [`docs/CLAIMS_AND_LIMITS.md`](docs/CLAIMS_AND_LIMITS.md) before using
`VERIFIED`, `independent`, `provenance`, `complete`, `self-closed`, or
`refutable` in public wording.

VSTD can improve auditability, reproducibility, incident analysis, and challenge
propagation over observable records. It cannot prove general AI safety, expose
hidden model internals, establish physical-world completeness, or compensate for
missing instrumentation.

## Specification order

1. `standard/LADDER.md`
2. `standard/VSTD-1.md` through `standard/VSTD-5.md`
3. `standard/VSTD-Graph-1.md` through `standard/VSTD-Graph-5.md`
4. `receipts/schema/`
5. `src/verifiable/core/kernel.py` and the producer modules
6. the conformance tests

## Project process

See `GOVERNANCE.md`, `CONTRIBUTING.md`, `SECURITY.md`, and `RELEASING.md`.
Changes that strengthen a claim without stronger evidence are non-conforming.

## License

Apache License 2.0. See `LICENSE` and `NOTICE`. The license includes an express
patent grant from contributors, subject to its terms. VSTD is not affiliated with
or endorsed by the Apache Software Foundation.
