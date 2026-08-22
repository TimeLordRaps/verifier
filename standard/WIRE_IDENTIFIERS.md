# VSTD frozen wire identifiers and historical filenames

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
Readers MUST dispatch a receipt by its wire identifier:

| Current layer document | Frozen wire identifier |
|---|---|
| `VSTD-1.md` | `schema_version = "VSTD-0.1"` |
| `VSTD-2.md` | `schema_version = "VSTD-0.2"` |
| `VSTD-3.md` | `schema_version = "VSTD-3.0"` |
| `VSTD-Graph-1.md` | `schema_version = "VSTD-DATA-0.1"` |

New layer-4 and layer-5 documents use their own schemas without changing historical
canonical digests.

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

## 3. CLI compatibility

`vstd` is the canonical cross-platform CLI name. The `verifier` alias remains
available, but Windows resolves the unqualified name to its built-in Driver Verifier
utility on common `PATH` configurations. `verifiable` also remains an alias because
project release materials and receipt instructions may bind that executable name.
Retaining either alias preserves project compatibility; it is not evidence of
external use.

## 4. Release versioning

The first repository release using integer layer names is `v1.0.0`. The release
number does not claim VSTD-5 implementation: VSTD-5 is explicitly draft. Existing
`v0.1.0` and `v0.2.0` tags and GitHub releases remain untouched.
