# Verifier Standard (VSTD) serialized receipt identifiers

> **Acronyms:** command-line interface (CLI).

**Status:** normative for current serialized-receipt dispatch
**Date:** 2026-08-29

A **serialized receipt identifier** is the value written into a receipt to select its exact reader and schema, principally `schema_version` plus any required profile discriminator. Standards literature often calls this a *wire identifier* or part of a *wire format*; here it means the stored JavaScript Object Notation (JSON) contract, not a network protocol.

Specification numbers identify numbered profiles and their cumulative closure coordinates.
Repository releases use semantic
versions independently. Retired partial-profile object identifiers and specification files are
not current profiles and are absent from this source tree; published tags and Git history
preserve those earlier project artifacts without making the current reader accept or
reinterpret them.

## 1. Current serialized receipt dispatch

Readers MUST dispatch by the exact `schema_version` and any required profile
discriminator. Unknown identifiers, missing discriminators, and mismatched shapes fail
closed:

| Numbered-profile document | Current serialized receipt identifier |
|---|---|
| `VSTD-1.md` | `schema_version = "VSTD-1"` |
| `VSTD-2.md` | `schema_version = "VSTD-2"` |
| `VSTD-3.md` | `schema_version = "VSTD-3.0"` |
| `VSTD-4.md` | `schema_version = "VSTD-4"` |
| `VSTD-5.md` | `schema_version = "VSTD-5"` |
| `VSTD-Graph-1.md` | `schema_version = "VSTD-DATA-0.1"` |

The frozen `VSTD-DATA-0.1` reader preserves its original separate artifact and
transformation identifier namespaces. New Graph construction, evidence-bound Graph
establishment, and the separate `VSTD-GRAPH-ASSURANCE-1` mechanism require global
cross-kind disjointness; that stricter admission rule does not retroactively narrow which
historical `VSTD-DATA-0.1` bytes can be decoded and replayed.

VSTD-1 has two current receipt profiles:

| `receipt_kind` | Schema | Meaning |
|---|---|---|
| `claim_mechanics` | `vstd1_receipt.json` | bounded claim, evidence, checker, provenance, and reproducibility |
| `generic_computational_run` | `vstd1_generic_run_receipt.json` | planned execution, captured outputs, assessment context, and reproduction surface |

Both discriminators are required. A reader MUST NOT guess the profile from incidental
field similarity.

The generic-run `assessment_context` is a VSTD-1 container for mechanism identity,
declared resource bounds, prior commitment, and the refutation surface. It is not a
VSTD-4 object and carries no VSTD-4 conformance field. The container and its selected
fields participate in the canonical digest.

### 1.1 Non-wire vocabulary

`VSTD-2.md` section 7 defines prose lifecycle vocabulary. Only the
`CoordinateStatus` members serialized in `receipts/schema/vstd2_receipt.json`
(`PRE_VERIFIED`, `VERIFIED`, `FALSIFIED`, `INDETERMINATE`, `UNSUPPORTED`, `STALE`)
are serialized receipt values. `POST_VERIFIED`, `GEOMETRY_INSPECTABLE`, and `COMPLETELY_VERIFIED`
are descriptive terms rather than receipt values.

## 2. Stored non-receipt mechanism identifiers

Artifact-control mechanism objects are stored JSON contracts, not network traffic, VSTD
receipts, or new numbered profiles. They dispatch independently by:

| Object | `schema_version` |
|---|---|
| Freeze manifest | `VSTD-ARTIFACT-FREEZE-1` |
| Self-closing seal envelope | `VSTD-ARTIFACT-SEAL-1` |
| Seal closure payload | `VSTD-ARTIFACT-SEAL-CLOSURE-1` |
| Thaw lineage sidecar | `VSTD-ARTIFACT-THAW-1` |

Their normative behavior is [`ARTIFACT_CONTROL.md`](ARTIFACT_CONTROL.md); their strict
combined schema is published as
[`artifact-control-1.schema.json`](https://timelordraps.github.io/verifier/schemas/artifact-control-1.schema.json).
These identifiers do not imply a network protocol or VSTD conformance result.

The Graph assurance event log dispatches separately as
`schema_version = "VSTD-GRAPH-ASSURANCE-1"`. Its governing behavior is
[`LADDER.md` section 1.1](LADDER.md#11-artifact-first-causal-provenance-orientation),
and its strict schema is
[`vstd-graph-assurance-1.schema.json`](https://timelordraps.github.io/verifier/schemas/vstd-graph-assurance-1.schema.json).
It is not an artifact-control object or a numbered-profile receipt.

## 3. Import package and distribution

The distribution is `verifier-standard`, the import package is `verifier`, and
`vstd` is the canonical cross-platform CLI name. `verifier` may resolve to Windows Driver
Verifier on common Windows `PATH` configurations. The `verifiable` command remains a
compatibility alias for already-published execution instructions; it is not an import
package or a standard identifier.

Release verification derives archive names and console-script expectations from the
release manifest being checked. This preserves issued release evidence without carrying
obsolete standard identifiers into current receipt dispatch.

## 4. Release versioning

A repository release number does not claim conformance to a same-numbered VSTD profile.
VSTD-5's reference mechanism is implemented. This project-specification status does not
claim an external witness, independent implementation, standards-body consensus,
accreditation, or interoperability deployment.
