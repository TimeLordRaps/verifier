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
| `VSTD-GRAPH-1.md` | `schema_version = "verifier-data-1"` |

The frozen `verifier-data-1` reader preserves its original separate artifact and
transformation identifier namespaces. New Graph construction, evidence-bound Graph
establishment, and the separate `verifier-graph-assurance-1` mechanism require global
cross-kind disjointness; that stricter admission rule does not retroactively narrow which
historical `verifier-data-1` bytes can be decoded and replayed.

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

When the refutation surface declares platform comparability, new captures add the
capture-owned binding version `verifier-platform-comparison-environment-1` plus the observed
Python implementation and machine identity. This is an additive comparison binding, not
a new receipt profile or numbered VSTD profile. Historical generic-run receipts retain
their original canonical bytes and remain readable, but absence of the binding cannot
establish a platform-comparison result.

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
| Grounded certification request | `verifier-grounded-request-1` |
| Grounded certification admission policy | `verifier-grounded-policy-1` |
| Grounded certification certificate | `verifier-grounded-certification-1` |
| Grounded domain request | `verifier-domain-request-1` |
| Grounded domain policy | `verifier-domain-policy-1` |
| Grounded domain retained evidence | `verifier-domain-evidence-1` |
| Grounded domain certificate | `verifier-domain-certification-1` |
| Freeze manifest | `verifier-artifact-freeze-1` |
| Self-closing seal envelope | `verifier-artifact-seal-1` |
| Seal closure payload | `verifier-artifact-seal-closure-1` |
| Thaw lineage sidecar | `verifier-artifact-thaw-1` |

The three grounded certification objects follow
[`GROUNDED_CERTIFICATION.md`](GROUNDED_CERTIFICATION.md). The artifact-control objects
follow [`ARTIFACT_CONTROL.md`](ARTIFACT_CONTROL.md); their strict
combined schema is published as
[`artifact-control-1.schema.json`](https://timelordraps.github.io/verifier/schemas/artifact-control-1.schema.json).
These identifiers do not imply a network protocol or VSTD conformance result.

The Graph assurance event log dispatches separately as
`schema_version = "verifier-graph-assurance-1"`. Its governing behavior is
[`LADDER.md` section 1.1](LADDER.md#11-artifact-first-causal-provenance-orientation),
and its strict schema is
[`verifier-graph-assurance-1.schema.json`](https://timelordraps.github.io/verifier/schemas/verifier-graph-assurance-1.schema.json).
It is not an artifact-control object or a numbered-profile receipt.

Experimental verification-artifact network records dispatch independently as:

| Object | `schema_version` |
|---|---|
| Exact retained object declaration | `verifier-object-1` |
| Complete-snapshot publisher commit | `verifier-silo-commit-1` |
| Interpreted structural self-derivation mechanism | `verifier-self-derivation-mechanism-1` |
| Finite authority-transition model | `verifier-authority-model-1` |
| Finite authority-composition declaration | `verifier-finite-authority-composition-1` |
| Finite authority-composition rule profile | `verifier-finite-authority-composition-profile-1` |
| Finite authority-composition result | `verifier-finite-authority-composition-result-1` |
| Signed selected head | `verifier-signed-head-1` |
| Key-derived publisher declaration | `verifier-publisher-1` |
| Dual-signed key continuity | `verifier-key-continuity-1` |
| Signed discovery directory | `verifier-directory-snapshot-1` |
| Six-axis silo assessment | `verifier-silo-assessment-1` |
| Commit/mechanism-bound assessment receipt | `verifier-silo-assessment-receipt-1` |
| Exact silo-composition declaration | `verifier-silo-composition-1` |
| Reference silo-composition mechanism | `verifier-silo-composition-mechanism-1` |
| Typed silo-composition assessment | `verifier-silo-composition-assessment-1` |
| Declaration/mechanism/evidence-bound composition receipt | `verifier-silo-composition-assessment-receipt-1` |
| Deterministic silo export manifest | `verifier-silo-export-1` |
| Bounded single-snapshot transport envelope | `verifier-silo-transfer-1` |
| Host-neutral push request | `verifier-push-request-1` |
| Exact proposition-transfer declaration | `verifier-proposition-transfer-1` |
| Compiled mathematical transfer rule profile | `verifier-proposition-transfer-rule-1` |
| Rule-specific portable assessment | `verifier-proposition-transfer-assessment-1` |
| Recomputable semantic transfer receipt (not execution identity) | `verifier-proposition-transfer-receipt-1` |
| Inert canonical finite-set specimen | `verifier-canonical-finite-set-1` |
| Finite typed-formation subject | `verifier-typed-formation-1` |
| Independently checked formation certificate | `verifier-typed-formation-certificate-1` |
| Inert compiled formation rule profile | `verifier-typed-formation-profile-1` |
| Exact commit and census-path formation selection | `verifier-silo-formation-selection-1` |
| Observed-evidence-bound portable formation inspection receipt | `verifier-silo-formation-receipt-1` |

These alpha identifiers are stored non-receipt mechanism objects. They do not
claim numbered-profile conformance, publisher identity beyond key control,
artifact correctness, semantic completeness, or authority merely because they
are schema-valid or listed by a directory.

The separate [typed formation](TYPED_FORMATION.md) contract checks finite
constructor types, ordered paths and evidence-retaining quotation. Its CHECKED
result never upgrades source self-status, completeness or authority axiom agency.

The [formation receipt](FORMATION_RECEIPT.md) additionally binds exact selection
and actually observed census bytes. Fresh reproduction can reproduce a negative
or unknown report; it does not establish execution, complete source derivation,
stronger completeness, grounding or authority axiom agency preservation.

`verifier-authority-model-1` binds a finite declared state and transition
universe, the canonical actor-scope vocabulary, and additive local authority
records. Only the registered interpreter may return `PRESERVED`, and only over
the exact reachable declared graph. Static action metadata, an open model, or
unmodeled runtime behavior remains `UNKNOWN`; reachable removal of a canonical
ground action is `VIOLATED`.

The separate [finite authority-composition](FINITE_AUTHORITY_COMPOSITION.md)
contract checks an explicitly selected, bounded asynchronous-interleaving model
product. Coordinate binding, transition correspondence, agency preservation and
local-addition preservation remain distinct results. It does not establish
runtime correspondence, source self-derivation, stronger completeness, general
composed agency, or any change to the existing six-axis silo assessment.

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
