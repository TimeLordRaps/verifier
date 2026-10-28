# Exact selected-source reader: test-first design

Terminology: application programming interface (API); JavaScript Object Notation
(JSON); Secure Hash Algorithm 256-bit (SHA-256); Unicode Normalization Form C (NFC).

Status: private test-first candidate; production reader intentionally absent.

This candidate introduces no repository scanner and no release prerequisite. It
specifies a bounded reader for a separately selected source manifest. A manifest
cannot authenticate its own completeness, source selection, or release status.

## Proposed interface

`scripts/exact_source_scope.py` will expose:

- `MemberObservation(kind: str, content: bytes)`;
- `ScopeInputError(code: str, message: str)`;
- `load_selected_source_scope(...)`;
- `summarize_candidate_scope(local_results)`.

`load_selected_source_scope` receives manifest bytes, an externally supplied
manifest SHA-256, an externally supplied source coordinate, an exact-member
callback, and byte bounds. It receives no repository root and has no discovery
API. It may request only the member paths parsed and validated from the manifest.

The future filesystem adapter is separate. It may use exact path-component
`lstat` and exact file reads for already admitted members, but must never walk,
glob, enumerate Git, or infer completeness.

## Invariants

1. Validate the exact raw manifest digest before parsing member content.
2. Require schema `verifier-selected-source-scope-1`, status `CANDIDATE`,
   completeness `UNKNOWN`, and `release_admissible: false`.
3. Require a separately supplied source coordinate equal to the manifest value.
4. Reject noncanonical, absolute, drive-qualified, traversing, backslash,
   non-Unicode-scalar, non-NFC, duplicate, and portable case-fold-colliding
   paths before member I/O. Never normalize or rewrite a path into acceptance.
5. Reject missing, linked, reparsed, directory, oversized, size-mismatched, and
   digest-mismatched members.
6. Never request an unlisted member and never invoke discovery operations.
7. A set of local PASS results produces bounded PASS but global `UNKNOWN`, with
   repository and semantic completeness `UNKNOWN` and release admissibility false.
8. Any local FAIL remains FAIL.

The JSON object model is strict: a duplicate key at any nesting depth is
ambiguous and fails before member I/O rather than allowing last-key-wins
interpretation.

## Explicit non-claims

This reader cannot establish repository completeness, clean Git state, absence
of untracked files, content properties of omitted members, live pull-request
currency, semantic completeness, safety, or release admissibility. Existing
repository-wide and live-provider gates remain unchanged and open.

