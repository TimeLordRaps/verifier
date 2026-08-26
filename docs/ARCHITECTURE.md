# Verifier Standard (VSTD) conformance architecture

> **Acronyms:** Boolean satisfiability problem (SAT); command-line interface (CLI);
> JavaScript Object Notation (JSON); Verifier Standard (VSTD).

**Status:** implementation and ownership map; normative meaning remains in `standard/`

Use this order when two surfaces appear to disagree:

1. normative layer document;
2. frozen wire identifier and profile discriminator;
3. published JSON Schema;
4. typed model and validator;
5. conformance tests;
6. generated reference and examples.

A lower item cannot silently redefine a higher item. A passing schema check establishes
shape only; a passing validator establishes only its named implemented checks.

## Layer ownership

| Coordinate | Normative source | Runtime owner | Published shape | Primary tests |
|---|---|---|---|---|
| VSTD-1 claim receipt | `standard/VSTD-1.md` | `verifier.core.receipt`, `verifier.core.checker` | `vstd1_receipt.json` | `test_independent_checker.py`, `test_vstd_schemas.py` |
| VSTD-1 generic run | `standard/VSTD-1.md` | `verifier.core.run` | `vstd1_generic_run_receipt.json` | `test_generic_run.py` |
| VSTD-2 | `standard/VSTD-2.md` | `verifier.core.geometry` | `vstd2_receipt.json` | `test_verification_geometry.py` |
| VSTD-3 | `standard/VSTD-3.md` | `verifier.hardware` | `vstd3_receipt.json`, `vstd3_accelerator_profile.json` | `test_vstd3_schema.py`, hardware tests |
| VSTD-4 | `standard/VSTD-4.md` | `verifier.core.certificate`, `verifier.core.kernel`, `verifier.core.depth` | `vstd4_certificate.json`, `vstd4_receipt.json` | `test_gdc_certificate.py` |
| VSTD-5 | `standard/VSTD-5.md` | entry gate only | `vstd5_receipt.json` | `test_vstd_schemas.py` |
| VSTD-Graph-1 | `standard/VSTD-Graph-1.md` | `verifier.data.models`, `verifier.data.receipt` | `vstd_graph_receipt.json` | `test_public_data.py` |
| VSTD-Graph-2..5 | matching Graph documents | `verifier.data.graph_level` | `computed_graph_level` within `vstd_graph_receipt.json` | `test_graph_level.py` |

VSTD-5 is draft. Graph-2 through Graph-5 currently compute candidate levels from
caller-supplied ratings and return `conformance_status = NOT_ESTABLISHED`; rating-evidence
binding is not implemented.

## Wire dispatch

Dispatch first by `schema_version`, then by a required profile discriminator when the
frozen identifier carries multiple profiles. `VSTD-0.1` generic-run receipts require
`receipt_kind = "generic_computational_run"`. Legacy SAT/derivation receipts have no
discriminator and must match the claim-receipt required fields. Unknown combinations fail
closed.

## Installed specification ownership

Every `standard/*.md` file has a byte-identical installed resource under
`src/verifier/specifications/`. Verifier descriptors use those resources when no source
checkout is present. The installed-wheel gate runs outside the checkout and rejects an
unavailable specification digest.

## Separation and Graph boundaries

The historical `independent_audit` field name does not prove independence. Its
`independence_basis` records actor, implementation, and runtime separation. Repeated or
matching results are artifact agreement, not evidence that separate actors performed the
runs; absent separation evidence is `NOT_DEMONSTRATED`.

Graph conflict records retain incompatible values and their evidence references without
adding a scalar score or changing the frozen artifact-status vocabulary. A conflict makes
the subject inadmissible to a clean candidate Graph level.
