# Contributing to Verifier Standard (VSTD)

> **Acronyms:** GNU Privacy Guard (GPG); identifier (ID); uniform resource locator (URL).

Contributions are welcome when they make a declared verification surface more precise,
more checkable outside its producer, or easier to implement without strengthening unsupported
claims. Counterexamples, incompatible parser results, and failed interoperability attempts
are useful contributions.

## Choose the right surface

| Change | Primary location | Required companion work |
|---|---|---|
| Normative requirement or numbered-profile meaning | `standard/` | Matching installed copy under `src/verifier/specifications/`, compatibility analysis, schema/model/runtime review, and falsification test |
| Frozen identifier or profile dispatch | `standard/WIRE_IDENTIFIERS.md` | Historical-receipt audit; never silently redefine a released value |
| Published receipt shape | `receipts/schema/` | Typed model, validator, examples, Pages schema route, and adversarial schema tests |
| Reference implementation | `src/verifier/` | Tests for the exact implemented proposition and failure boundary |
| Command-line behavior | `src/verifier/runtime/public_cli.py` | Generated reference, installed-wheel smoke, and machine-readable output tests |
| Ecosystem adapter or application profile | `src/verifier/interoperability/` or an explicitly experimental profile | Accepted upstream versions, native-verifier boundary, information-loss declaration, trust roots, and substitution/replay/scope-widening tests |
| Non-normative roadmap-steering research | `experiments/` | Experiment manifest, fixtures, unresolved horizons, and generated index |
| Explanatory documentation | `docs/` | Local-link, acronym, presentation, and semantic-drift review |

The authority order is:

1. normative numbered-profile document;
2. serialized receipt identifier (`schema_version`) and profile discriminator;
3. published schema;
4. typed model and validator;
5. conformance tests;
6. generated reference and examples.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the concrete ownership map.
A lower surface cannot silently redefine a higher one.

## Required for a normative change

- identify the affected VSTD profile, repository release, and exact coordinate or seam;
- state compatibility effects, including serialized receipt identifiers and historical receipts;
- state a falsification condition;
- update schemas, typed models, runtime behavior, and installed specification copies where applicable;
- add a test that fails before the change and passes after it;
- document trust roots, unknowns, residuals, information loss, and unresolved horizons;
- check every public route that exposes the meaning: command-line output, examples,
  generated reference, diagrams, claims guidance, and release metadata.

Do not replace `UNKNOWN` with false, erase `CONFLICTED`, infer missing provenance, turn
a candidate calculation into conformance, or call self-observation independent
verification. Storage location, repetition, matching outputs, and actor reputation do not
increase assurance.

## Add a profile or adapter

Before proposing an adapter, document and test:

1. exact accepted upstream versions and identifiers;
2. preserved source bytes and canonicalization rules;
3. the native verifier and its trust roots;
4. field-by-field mapping and declared information loss;
5. freshness, availability, invalid, unsupported, and unknown behavior;
6. substitution, omission, replay, conflict, and scope-widening fixtures;
7. the VSTD proposition that consumes the native result;
8. an explicit non-endorsement and non-adoption statement.

The current Supply Chain Integrity, Transparency, and Trust (SCITT) work is an
interoperability experiment, not evidence that every adjacent system needs an adapter.
Each adapter increases the maintained and trusted surface.

## Tests and local gates

Run the repository-prescribed paths:

```bash
python -u -m pytest -vv -s --durations=10 --timeout=60
python -u -m coverage run --branch --source=src/verifier -m pytest -vv -s --durations=10 --timeout=60
python -m coverage report --show-missing
python -m coverage json --pretty-print -o coverage.json
python scripts/check_presentation.py
python scripts/check_acronyms.py
python scripts/check_terminology.py
python scripts/build_reference.py --check
python scripts/build_experiment_index.py --check
python scripts/build_pages.py --output PATH_TO_EMPTY_DIRECTORY
python scripts/check_time_status.py
python -u -m compileall src scripts
```

The coverage report is bounded test evidence, not proof of correctness, completeness, or
conformance. Review per-file and branch results in `coverage.json`; the aggregate cannot
justify weakening a critical component's tests. No repository-wide pass threshold is
defined until repeatable component baselines justify one.

Pull requests retain the assembled Pages site as a commit-addressed review artifact.
`documentation-coordinate.json` states its version, release state, source ref, canonical
base URL, and normative owner. `standard/` remains authoritative; generated Pages output
is navigation and rendering, not another specification. Published tags and their release
artifacts are the historical documentation coordinates.

### Known-good Pages redeployment

Pages does not roll back automatically. If a current deployment is observably defective,
the maintainer may separately authorize the `redeploy-known-good` manual workflow operation.
That bounded procedure requires the exact prior source commit, the Pages workflow run ID
retaining its `pages-promotion-<source-ref>` receipt, and the literal
`REDEPLOY_KNOWN_GOOD` guard. The guard is not authorization: the maintainer's explicit
dispatch and any configured environment approval are the authorization events.

The workflow downloads the retained receipt from the named run, checks its exact source,
successful observation result, deployment workflow run ID, repository-check run ID, and
whole-site manifest digest, then rebuilds the old commit. Redeployment stops unless the
rebuilt manifest digest is byte-identical to that receipt. Historical repository code runs
only in a contents-read build job; the job holding Pages and OpenID Connect deployment
authority receives the already validated artifact and executes no checked-out source. After
deployment, an unprivileged observer re-fetches the manifest and every listed route under
the same bounds as an ordinary deployment, requires the exact promoted manifest digest,
and retains a new receipt. This is a redeployment of previously observed bytes, not proof
that the prior deployment remains safe, correct, or currently appropriate.

External rollback drill status: **NOT_CHECKED**. Local tests exercise receipt rejection,
rebuild mismatch, workflow guards, and live-observation mechanics; they do not establish
GitHub authorization, artifact retention, environment protection, or a successful hosted
rollback. No checklist, receipt, or confirmation string authorizes dispatch.

Changes to optional cryptographic paths must also install their declared extra and run the
non-skippable focused test. Release or packaging changes must run the exact-Git-object
artifact builder, manifest verifier, package metadata check, release-boundary scanner,
and installed-wheel smoke described in [`RELEASING.md`](RELEASING.md).

## Commits and pull requests

Commits are GPG-signed (`git commit -S`). A signature binds commit bytes to a key; it
does not establish identity, correctness, authorization, independence, or safety.

Use the pull-request template to record:

- the exact coordinate;
- what changes and what remains unchanged;
- the falsification condition and tests;
- serialized-format and compatibility impact;
- trust roots, unknowns, residuals, and horizons; and
- every downstream surface reviewed.

Before promotion, also record the exact current head and base, executed integration commit,
repository-check event and run, every actionable finding and its disposition, every skipped
or unrun check with its claim consequence, the canonical promotion-record digest, exact-head
human acceptance evidence, and the owner plus scope of post-merge validation. A head, base,
record, or human-gate change invalidates the earlier acceptance. Refresh the record and
affected evidence before the pull request can pass policy again.

Each promotion field and the Promotion record and Human review gates sections must occur
exactly once. The tests field is a structured summary of the digest-bound machine manifest:
its `total-skipped` count and ordered `skip-observation-omissions` list must match that
manifest exactly. The repository-check workflow emits and retains bounded JUnit XML for all
eleven pytest coordinates: four base Python versions, four operating-system/architecture
platform coordinates, branch coverage, artifact seal, and Supply Chain Integrity,
Transparency, and Trust cryptographic tests. A newly added pytest invocation must be added
to this exact inventory before promotion can pass. Free-form `DISCLOSED` prose is not
evidence and is rejected; `NONE` is permitted only when all eleven reports are present and
record zero skips.

After completing the bound promotion fields and human-gate dispositions, export the current
pull-request document and run `python scripts/check_pr_policy.py --print-record-sha256 PATH`.
Put that digest in the record, obtain the exact head-plus-digest acceptance marker, and then
link its review or comment. The digest deliberately excludes its own field and that link to
avoid a circular record; it includes every other promotion field and every human-gate line.

The human acceptance is an approving review on the exact head or a trusted maintainer
comment containing `VSTD-HUMAN-ACCEPTANCE: <full-head-commit-identifier>
<promotion-record-sha256>`, linked from the pull-request
body. Automated contributors MUST NOT create that marker for their own work. This mechanism
establishes a recorded repository action by an authorized account; it does not establish
reviewer comprehension, independence, correctness, merge authority, or release authority.

After an explicitly authorized merge, the assigned owner observes the resulting `main`
commit's repository checks and every applicable deployment. The pull-request head,
GitHub's synthetic merge coordinate, resulting `main` commit, deployed documentation, and
published packages are distinct evidence coordinates. Failure or partial publication at a
later coordinate remains visible and cannot be repaired by the earlier green check.

For the one-time policy bootstrap, land the protected-branch workflow under the existing
review requirements and exercise it on a subsequent test pull request and merge-group event.
After that bootstrap test passes, require both the merge-queue-capable `conformance-gate`
and `pr-policy` contexts. Configure the merge queue with the `ALLGREEN` grouping strategy:
the trusted default-branch workflow emits `pr-policy` on a merge-group commit only after
conservatively validating current exact receipts for its terminal and all earlier bounded
queue entries. An unrecognized ref, more than 32 entries, incomplete query, stale pull
request, or changed queue fails closed. Review and comment evidence is conservatively capped
at 99 records each; a 100-item response fails because another page may exist. Each
JavaScript Object Notation (JSON) policy document and pull-request body also has an enforced
byte ceiling. Automatic and manual Pages paths require successful
repository checks for the exact current default-branch commit. A failed post-deployment
observation detects a partial promotion and supports retry; it does not roll back deployed
bytes by itself. The default-branch checks before packaging and immediately before and after
deployment narrow but cannot make the Git ref update and GitHub Pages promotion atomic. A
new default-branch commit in that final interval can therefore make an older deployment
transiently visible before the post-deployment check fails; no successful workflow receipt
may represent that state as current.

Review and merge-group events first trigger a permission-free notification workflow.
Only its authenticated platform run coordinates wake the protected default-branch
`workflow_run` consumer; notification code, artifacts, and success are never acceptance
evidence. Failed or cancelled notifications still request reevaluation. The consumer
refetches the exact workflow identity and current pull-request state. For a merge group,
it additionally requires the live synthetic ref and its commit's first parent to bind
the supported queue base before reconstructing the event. Missing associations, deleted
refs, unsupported queue shapes, or a disabled notification leave delivery or evaluation
unestablished; they do not permit promotion. Keep branch review protections and current
merge-group checks required. A notification can be disabled by candidate edits, so this
relay does not guarantee delivery or make review updates and status publication atomic.

## Report without a patch

- [Specification ambiguity](https://github.com/TimeLordRaps/verifier/issues/new?template=specification-ambiguity.yml)
- [Counterexample or unsound claim](https://github.com/TimeLordRaps/verifier/issues/new?template=counterexample.yml)
- [Independent implementation or interoperability report](https://github.com/TimeLordRaps/verifier/issues/new?template=implementation-report.yml)
- [Private vulnerability report](https://github.com/TimeLordRaps/verifier/security/advisories/new)

Do not place sensitive vulnerability details in a public issue. If the private route is
unavailable, report only that non-sensitive fact publicly.

## License and governance

Unless explicitly stated otherwise, a contribution intentionally submitted for inclusion
is provided under the Apache License 2.0, including its Section 3 patent and Section 5
contribution terms. The project has no separate contributor license agreement or
standards-venue patent policy. Governance and current decision rights are documented in
[`GOVERNANCE.md`](GOVERNANCE.md).
