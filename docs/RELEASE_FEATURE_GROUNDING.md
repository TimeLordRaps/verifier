# Source-grounded release descriptions

The pull request (PR) coverage is derived from changed source, not an author's list of
favorite features. Verifier Standard (VSTD) describes bounded claims; Verifier is
its reference implementation. See [accountability scope](ACCOUNTABILITY_RELEASE_SCOPE.md)
for a semantic inventory that is independent of available adapters.

## Required evidence

`scripts/check_pr_description.py` checks all changed paths under `src/`, `scripts/`
and `.github/workflows/`, plus `pyproject.toml`. This includes Python modules,
schemas, profiles, specifications, executable release tooling, hosted workflows
and package configuration. Tests and narrative guides remain separate evidence
and presentation surfaces; their presence never substitutes for production coverage.
A working-tree check includes
staged, unstaged and nonignored untracked source. A commit check reads that exact Git
object and excludes later working changes. Deletions require coverage too.

Run `python scripts/check_pr_description.py --source-inventory --base origin/main`
to obtain the binding fields. Add `--commit <reviewed-commit>` for commit evidence.
The base is the trusted review target, not a base chosen to conceal changes; hosted
callers must supply the actual target branch or base. Missing objects fail closed.

The description must contain one fenced `vstd-source-features` block for the
review base, or two blocks with distinct ancestor bases for a stacked pull
request whose hosted checks use both its immediate parent and the default
branch. Every block is checked against the same reviewed head; a second block
cannot conceal a missing or stale row in the first. Each block contains a
JavaScript Object Notation (JSON) object. Small changes may place `base`, `target`
and `files` in that block. Large changes may put the complete `files` array in
the committed `docs/PR_SOURCE_FEATURES.json` file and place `base`, `target`, and
`manifest: {"path":"docs/PR_SOURCE_FEATURES.json","sha256":"..."}` in the block.
The manifest contains `base` and `files`; its digest binds its exact bytes. The
checker reads those bytes from the reviewed commit in commit mode, so later
working-tree edits cannot change the verdict. Both forms require each file row to contain:

- `path`: exact repository-relative source path.
- `sha256`: Secure Hash Algorithm 256-bit (SHA-256) digest of the current bytes,
  or JSON `null` for a deletion.
- `symbols`: exactly the changed, added or removed Python definition names reported
  by the inventory, including private definitions and class methods.
- `summary`: a reviewed explanation of the behavior or contract changed.
- `limits`: what the source and retained validation do not establish.

The generated inventory deliberately does not invent summaries or limits. A list
of hashes without those fields fails. Omitted or extra paths, missing definitions,
duplicate keys/paths/bases, stale digests and incorrect base/target bindings fail.
Non-Python files and module-level changes remain bound through whole-file digests.
The manifest is a review aid, not a way to omit a source path, altered definition,
behavioral summary or limit from the description's referenced evidence.
All identifiers and digests here are dimensionless; they are not confidence scores.
The namespace-closure text scan excludes this exact generated manifest because it
must preserve retired filenames and wire names as historical evidence. All other
tracked source and documents remain in that scan; the source-description gate still
checks the manifest's digest and every changed source path.

The source checker does not execute candidate Python code. It parses its syntax and
compares bytes. Symlinks, special files, unavailable source and oversized source files
are rejected. Renames are covered as disappearance and appearance where appropriate.

## Semantic coverage is separate

Source records are a lower bound on review coverage. A nonempty summary may still
be wrong; matching a digest does not prove correspondence between prose and behavior,
test adequacy, security, or completeness of the intended release. Review must connect
each behavioral claim to its actual mechanism, evidence and exclusions. Changes within
a function can contain several features; one function name is not one proved feature.

The declared-domain check independently reads `_domain_rows` declarations from the
obligation catalogue. It requires every declared domain to be named even when no
native adapter exists. ACTOR and OWNER adapter presence must never stand in for the
whole accountability family. Name coverage alone does not establish tier coverage.

Existing head, inventory, adapter, count and promotion checks remain in force.
Historical promotion evidence must not be rewritten merely to make a current gate
pass. Local source coverage is not committed-source coverage, human acceptance,
hosted validation, merge permission or release authorization.

## Regression evidence

`tests/test_pr_source_grounding.py` uses isolated Git repositories and independently
mutates source coverage. Positive controls must pass while omitted files/functions,
stale hashes, duplicate records, wrong coordinates and malformed coverage fail.
Commit-mode tests add later untracked source and require frozen commit results to
remain unchanged. The live-description regression invokes the source and declared
domain checks; a deficient published description remains a failure.
