# Self-polish candidate-estate census

Status: mechanical candidate enumeration only. Semantic applicability, complete
repository/package closure, Tier 1 completion, polished status, and release
authority remain **NOT_ESTABLISHED**.

`verifier.runtime.self_polish_estate` builds a deterministic, fail-closed census
from one pinned Git coordinate. It records the repository remote, exact `HEAD`,
and a pre/post Secure Hash Algorithm 256-bit (SHA-256) census of all Git-tracked
working bytes plus every bounded, nonignored untracked ordinary file. Every file
records `GIT_TRACKED` or `WORKTREE_UNTRACKED_NONIGNORED` provenance. Tracked
files bind stage-zero Git mode `100644` or `100755`; untracked files use the
distinct `UNTRACKED_REGULAR` mode. Digests of exact
`git ls-files --stage -z` and
`git status --porcelain=v2 -z --untracked-files=all` output bind index and dirty
state. The public `capture_candidate_source_census()` helper is the sole shared
selector for downstream polish gates.

The census refuses source/index/status mutation, a changed coordinate,
out-of-root paths, symlinks, reparse points, special files, non-stage-zero or
nonordinary tracked modes, invalid static registries, and fixed resource-limit
exhaustion. It does not import arbitrary plugins or execute any candidate
command.

Ignored paths are scanned separately. Discoverable ignored source, control,
test, schema, workflow, script, or native executable entries fail closed. This
includes `.pyd`, `.dll`, `.so`, `.dylib`, `.exe`, `.bat`, `.cmd`, `.ps1`,
extensionless scripts under `scripts/`, and root controls such as `AGENTS.md`,
`TIME.md`, `pyproject.toml`, `MANIFEST.in`, and pytest/tox/nox/setup files. Only
the fixed cache/build exclusion taxonomy is permitted. Its taxonomy digest and
excluded path-set digest are bound into the census, while excluded bytes remain
explicitly `NOT_VERIFIED`; they are not implied to have been inspected.

Registry and parser objects are not accepted merely because their Python names
match. Before and after enumeration, every loaded `verifier` source module is
resolved under the selected root and its bytes must match the selected census.
An ambient installation or a second checkout therefore cannot silently supply
the installed routes, structural registry, domain catalog, interoperability
catalog, or public parser for another source root.

## Candidate categories

Every successful census contains at least one stable typed identifier in each
of these registered categories:

- candidate-source files, including tracked and nonignored untracked
  provenance, and Python-package files;
- Python modules and all syntactically declared functions, including methods
  and nested functions, with qualified-name and source-line binding;
- installed object cells, route memberships, and checking mechanisms;
- structural families, structural memberships, and their structural/route
  crosswalk;
- non-route gate registry members;
- public command-line interface (CLI) parser routes and leaves, including the
  numeric pre-parser routes;
- `pyproject.toml` console aliases and package-data candidates;
- public `_LAZY_EXPORTS` entries;
- domains and domain checks;
- interoperability components;
- JavaScript Object Notation (JSON) schemas and canonical `$id` values;
- native installed routes and retained compatibility routes; and
- explicit unresolved surfaces.

The structural and installed Tier 1 denominators are deliberately not
collapsed. The frozen crosswalk contains 52 structural memberships and 45
installed Tier 1 route memberships: 27 shared identities, 25 structural-only
identities, and 18 route-only identities. This exact non-equality is part of the
mechanical contract, not evidence of semantic closure.

## Applicability ledger contract

`applicability_ledger_template()` emits one `UNKNOWN` row for every fresh
candidate identifier. `validate_applicability_ledger()` accepts only canonical
JSON whose pinned source coordinate, universe digest, row count, exact
identifier set, and per-candidate digest match the fresh census. Missing,
extra, duplicate, stale, or substituted rows fail closed.

The ledger preserves separate applicability, authority, and evidence states.
Even syntactically valid caller-authored `APPLICABLE`/`PASS` rows and digests
are only counted as caller declarations; they do not authenticate themselves.
The validation result therefore keeps `caller_pass_authentication`, semantic
applicability, and full-estate closure at `NOT_ESTABLISHED`. The evidence
adapter does not use those declarations as its native classification. Its
mechanism-bound installed category registry recomputes every candidate as
`APPLICABLE` or `NOT_APPLICABLE` and rejects a definitive declaration that
contradicts that classification.

`self_polish_estate_evidence` replay version 4 requires one manifest row and
exact native evidence bytes for each natively applicable candidate before
`native_self_verification_status` can be `PASS`.
`self_polish_estate_native_evidence` version 3 independently recaptures the Git
coordinate, candidate-source census, loaded-module source binding, complete
candidate enumeration, and installed category verifier. Its canonical
artifact contains no caller-authored `PASS` field. A missing source root,
missing native coverage, or missing artifact bytes preserves native `UNKNOWN`;
malformed, extra, duplicate, substituted, or native-mismatch evidence is
`FAIL`.

The three explicit boundary surfaces (external plugins, excluded generated or
cache/build bytes, and runtime/operating-system state) are fixed
`NOT_APPLICABLE` to bounded repository/package-source self-polish, with their
reasons retained. Semantic applicability and per-obligation replay are derived
from actual native candidate results; they are not pseudo-candidates or blanket
exclusions.

Configured-key estate and candidate receipts remain optional, separately
reported independent authority. A receipt authenticates authority over its
exact proposition; it does not establish that proposition. Missing receipts do
not block native self-verification or Tier 1. Supplied stale, wrong-subject, or
revoked receipts fail only the independent-authority path. The result still
carries `tier1_status: NOT_ESTABLISHED`, `polished: false`, and
`release_authorized: false`; the Tier 1 adapter owns the remaining gates.

## Explicit unknowns and boundary

The current enumerator records only three declared boundary surfaces: external
plugin entry points, excluded cache/build artifact bytes, and installed runtime
or operating-system state. They remain unverified outside the bounded source
claim even when the installed registry correctly classifies them
`NOT_APPLICABLE`. Independent authority and release authority are separate
result states, not disguised as candidate rows.

This enumerator has no standalone public command and is not exported as an
independent package-index surface. It is wired into the public numeric
`vstd polish 1` adapter as the bounded source-estate subledger in a broader
closure directed acyclic graph (DAG). The wiring does not turn mechanical
enumeration into a semantic-completeness oracle.
