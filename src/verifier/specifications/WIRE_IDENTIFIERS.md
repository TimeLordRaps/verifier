# Verifier Standard (VSTD) frozen wire identifiers and historical filenames

> **Acronyms:** Boolean satisfiability problem (SAT); command-line interface (CLI).

**Status:** normative for wire-identifier dispatch; filename history is informative
**Date:** 2026-08-22

VSTD has no demonstrated external adoption or independent implementation as of this
release. This document therefore does not prescribe an adopter migration. It records
identifiers and filenames that appeared in the project's own public releases so that
those artifacts are not silently reinterpreted.

Specification numbers now identify verification depth. Repository releases use
semantic versions independently.

## 1. Frozen receipt wire identifiers

A filename or current layer label does not change the meaning of an issued receipt.
Readers MUST first dispatch by wire identifier. Where a frozen identifier carries more
than one released profile, they MUST then dispatch by the profile discriminator and MUST
NOT validate one profile against another profile's shape:

| Current layer document | Frozen wire identifier |
|---|---|
| `VSTD-1.md` | `schema_version = "VSTD-0.1"` |
| `VSTD-2.md` | `schema_version = "VSTD-0.2"` |
| `VSTD-3.md` | `schema_version = "VSTD-3.0"` |
| `VSTD-Graph-1.md` | `schema_version = "VSTD-DATA-0.1"` |

New layer-4 and layer-5 documents use their own schemas without changing historical
canonical digests.

`VSTD-0.1` has two claim-mechanics profiles. A receipt with
`receipt_kind = "generic_computational_run"` uses
`vstd1_generic_run_receipt.json`. Historical SAT/derivation receipts predate the
discriminator and use `vstd1_receipt.json` only when their required `claim`, `evidence`,
`target_result`, and `independent_audit` fields are present. Missing or unknown profile
information fails closed; it is not permission to guess a shape.

The bundled checker descriptor used `certificate_format = "VSTD3-INDEPENDENT-AUDIT"`
through release `1.1.3` even though it checked VSTD-1 claim mechanics. That historical
value remains attributable to those receipts but does not establish VSTD-3 conformance.
New `1.2.0` receipts use `VSTD1-CHECKER-REPORT`, bind `VSTD-1.md`, and record actor,
implementation, and runtime separation explicitly. Neither descriptor name proves that
separate actors performed producer and checker runs.

The generic-run field name `layer4_binding` is also historical. Version 0.1.0 and 0.2.0
writers omitted it; writers from version 1.0.0 through 1.1.3 emitted it under the same
`VSTD-0.1` generic-run discriminator. Readers MUST accept both forms. When present, the
exact block participates in the canonical digest and remains attributable to its writer.

The block carries generic assessment context and VSTD-1 refutation metadata, not a
VSTD-4 grounded decision certificate. Version 1.2.0 continues to emit the legacy block so
manifest-declared verifier coordinates, resource-bound declarations, prior commitment,
and refutation surface are not silently discarded. It adds
`vstd4_conformance = "NOT_EVALUATED"`; neither the container name nor its presence
dispatches the receipt to VSTD-4 or establishes that a declared bound was enforced.

This historical container is not a pattern for `layer1_binding`, `layer2_binding`, or
other layer-named context objects. A clean replacement requires an explicit new generic-run
profile discriminator and matching schema coordinate. A package semantic-version change
alone MUST NOT reinterpret the existing profile. No replacement identifier is reserved.

### 1.1 Non-wire vocabulary

`VSTD-2.md` section 7 defines a prose lifecycle vocabulary. Only the
`CoordinateStatus` members serialized in `receipts/schema/vstd2_receipt.json`
(`PRE_VERIFIED`, `VERIFIED`, `FALSIFIED`, `INDETERMINATE`, `UNSUPPORTED`, `STALE`)
are wire values. `POST_VERIFIED`, `GEOMETRY_INSPECTABLE`, and `COMPLETELY_VERIFIED`
are descriptive terms only and have never appeared in an issued receipt; renaming
them does not affect any canonical digest. `GEOMETRY_INSPECTABLE` was named
`VERIFIABLE` in unreleased drafts before `v1.1.2`; a status token MUST NOT reuse the
maintainer's name.

## 2. Historical names in project releases

| Historical public name | Current layer label | Meaning |
|---|---|---|
| `VSTD-0.1` | `VSTD-1` | claim mechanics |
| `VSTD-0.2` | `VSTD-2` | verification surface |
| `VSTD-3.0` | `VSTD-3` | substrate accountability |
| — | `VSTD-4` | refutability |
| — | `VSTD-5` | witness corroboration, draft |
| `VSTD-DATA-0.1` | `VSTD-Graph-1` | recorded lineage over collections |

`VSTD-Graph-2` through `VSTD-Graph-5` first appeared under their current labels.

The current repository does not duplicate old specification paths. Historical tags
remain the resolver for the bytes published under those paths:

```text
standard/VSTD-0.1.md      -> standard/VSTD-1.md
standard/VSTD-0.2.md      -> standard/VSTD-2.md
standard/VSTD-3.0.md      -> standard/VSTD-3.md
standard/VSTD-DATA-0.1.md -> standard/VSTD-Graph-1.md
VSTD3_THREAT_MODEL.md     -> docs/layers/vstd-3/threat-model.md
VSTD3_VENDOR_INTEGRATION.md -> docs/layers/vstd-3/vendor-integration.md
VSTD3_REFERENCES.md       -> docs/layers/vstd-3/references.md
VSTD3_MIGRATION.md        -> docs/layers/vstd-3/compatibility.md
COMPETITION_EVALUATION_PROFILE.md -> docs/profiles/competition-evaluation.md
CLAIMS_AND_LIMITS.md      -> docs/CLAIMS_AND_LIMITS.md
```

## 2.1 Import package and distribution rename

From `v1.1.2` the import package is `verifier` and the distribution is
`verifier-standard`. Both
were previously `verifiable` / `verifiable-standard`. The rename removes a name that
collided with the ordinary-English adjective, with a former VSTD-2 status token, and
with the maintainer's former project name.

| Historical name | Current name | Kind |
|---|---|---|
| `verifiable` | `verifier` | import package |
| `verifiable-standard` | `verifier-standard` | distribution |
| `verifiable-standard-<release>.zip` | `verifier-standard-<release>.zip` | release source archive |

No receipt wire identifier, schema `$id`, or canonical digest changes. Specification
text that cites a reference module (for example `verifier.core.kernel`) is a pointer
into the reference implementation, not a wire value.

Release manifests published up to and including `v1.1.1` bind
`verifiable-standard-<release>.zip` in their `source.archive_prefix`.
`scripts/release_artifacts.py verify` derives the archive name from the manifest, so
those releases stay verifiable without republishing.

## 3. CLI compatibility

`vstd` is the canonical cross-platform CLI name. The `verifier` alias remains
available, but Windows resolves the unqualified name to its built-in Driver Verifier
utility on common `PATH` configurations. `verifiable` also remains an alias because
project release materials and receipt instructions may bind that executable name. It is
a command name only: since `v1.1.2` it no longer corresponds to any import package.
Retaining either alias preserves project compatibility; it is not evidence of
external use.

## 4. Release versioning

The first repository release using integer layer names is `v1.0.0`. The release
number does not claim VSTD-5 implementation: VSTD-5 is explicitly draft. Existing
`v0.1.0` and `v0.2.0` tags and GitHub releases remain untouched.
