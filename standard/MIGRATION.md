# VSTD integer-layer migration

**Status:** normative for names; historical wire formats remain frozen
**Date:** 2026-08-22

Specification numbers now identify verification depth. Repository releases use
semantic versions independently.

## 1. Filename and concept aliases

| Historical name | Integer-layer name | Meaning |
|---|---|---|
| `VSTD-0.1` | `VSTD-1` | claim mechanics |
| `VSTD-0.2` | `VSTD-2` | verification surface |
| `VSTD-3.0` | `VSTD-3` | substrate accountability |
| — | `VSTD-4` | refutability |
| — | `VSTD-5` | witness corroboration, draft |
| `VSTD-DATA-0.1` | `VSTD-Graph-1` | recorded lineage over collections |

`VSTD-Graph-2` through `VSTD-Graph-5` are new computed collection profiles.

The old specification files were hard-renamed. Published tags and releases that
contain the old paths remain valid and unchanged.

## 2. Frozen receipt wire identifiers

Renaming a specification does not silently reinterpret an issued receipt.
Existing wire identifiers remain valid:

| Layer document | Existing wire identifier |
|---|---|
| `VSTD-1.md` | `schema_version = "VSTD-0.1"` |
| `VSTD-2.md` | `schema_version = "VSTD-0.2"` |
| `VSTD-3.md` | `schema_version = "VSTD-3.0"` |
| `VSTD-Graph-1.md` | `schema_version = "VSTD-DATA-0.1"` |

Readers MUST dispatch historical documents by their wire identifier, not infer a
schema from the current filename. New layer-4 and layer-5 documents use their own
schemas without changing historical canonical digests.

## 3. Link migration

Update links as follows:

```text
standard/VSTD-0.1.md      -> standard/VSTD-1.md
standard/VSTD-0.2.md      -> standard/VSTD-2.md
standard/VSTD-3.0.md      -> standard/VSTD-3.md
standard/VSTD-DATA-0.1.md -> standard/VSTD-Graph-1.md
VSTD3_THREAT_MODEL.md     -> docs/layers/vstd-3/threat-model.md
VSTD3_VENDOR_INTEGRATION.md -> docs/layers/vstd-3/vendor-integration.md
VSTD3_REFERENCES.md       -> docs/layers/vstd-3/references.md
VSTD3_MIGRATION.md        -> docs/layers/vstd-3/migration.md
COMPETITION_EVALUATION_PROFILE.md -> docs/profiles/competition-evaluation.md
CLAIMS_AND_LIMITS.md      -> docs/CLAIMS_AND_LIMITS.md
```

The hard rename intentionally allows obsolete links to fail rather than serving
two filenames that appear to be different specifications. Historical release
tags are the permanent resolver for old URLs.

## 4. CLI compatibility

`verifier` is the canonical CLI name. `verifiable` remains a permanent alias
because already-issued receipts bind commands using that name. Removing it would
invalidate published falsification and reproduction instructions.

## 5. Release versioning

The first repository release using integer layer names is `v1.0.0`. The release
number does not claim VSTD-5 implementation: VSTD-5 is explicitly draft. Existing
`v0.1.0` and `v0.2.0` tags and GitHub releases remain untouched.
