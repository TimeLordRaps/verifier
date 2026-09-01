# Contributing to Verifier Standard (VSTD)

> **Acronyms:** GNU Privacy Guard (GPG); uniform resource locator (URL).

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
| Non-normative research | `examples/experimental_profiles/` | Experiment manifest, fixtures, unresolved horizons, and generated index |
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
python -m pytest -q
python -m coverage run --branch --source=src/verifier -m pytest -q
python -m coverage report --show-missing
python -m coverage json --pretty-print -o coverage.json
python scripts/check_presentation.py
python scripts/check_acronyms.py
python scripts/check_terminology.py
python scripts/build_reference.py --check
python scripts/build_experiment_index.py --check
python scripts/build_pages.py --output PATH_TO_EMPTY_DIRECTORY
python scripts/check_time_status.py
python -m compileall -q src scripts
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
