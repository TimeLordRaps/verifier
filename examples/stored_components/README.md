# Retain the reference component catalog and source

This non-critical example uses the experimental Verifier Standard (VSTD) stored component
format to retain the first-party catalog and a bounded public source snapshot. It does not
run the stored components. It is a runnable instructional path for the
[stored format](../../docs/COMPONENT_PACKAGES.md), not a hosted hub or an installable package.

## Prerequisites and export

Use Python 3.10 or newer and Git in the public Verifier source checkout. Install this
checkout in the active interpreter, for example `python -m pip install -e .`; an older
installed package does not provide the new storage functions. No optional verifier
dependencies are needed to export or inspect this snapshot.

From a fully tracked checkout, choose a destination that does not already exist:

```bash
python examples/stored_components/build_reference_package.py --output reference-components.json --package-version 1.3.0-candidate
vstd components inspect reference-components.json --json
```

The command prints the canonical package digest. Compare it through a separately trusted
channel before another machine relies on package identity. When adding an untracked public
source module, explicitly review and name it. For example, only while the storage module
itself is untracked:

```bash
python examples/stored_components/build_reference_package.py --output reference-components.json --package-version 1.3.0-candidate --include-untracked src/verifier/interoperability/storage.py
```

The flag is repeatable and accepts only individually named untracked source files under
`src/verifier`. Omit it once those files are tracked. Other eligible untracked source files
make the export fail until each intended public file is explicitly named. The exporter
never sweeps unrelated untracked files into the package. `--source-root` can select another
public checkout, but its catalog source must match the exporting Python environment.

## What is retained

The exporter checks the exact Git root and requires the public remote
`https://github.com/TimeLordRaps/verifier.git` (the `.git` suffix is optional).
It captures tracked `.py`,
`.json` and `.md` files under `src/verifier`, plus the fixed public `pyproject.toml`,
`LICENSE`, `NOTICE` and root `README.md` files. It rejects conflicted file entries,
symbolic links and Windows reparse points, including source parent directories. It does
not search other repositories, capture arbitrary working directories, extract archives,
install dependencies or invoke an implementation entrypoint.

All **17 first-party entrypoints across 12 grouping labels** bind to the retained package
source snapshot. This is not seventeen independent native integrations. The snapshot
includes distinct proof-producer and proof-checker entries, bounded platform comparison,
receipt and graph rechecking, artifact verification and experimental adjacent-result
composition. A source snapshot is not a wheel, an installation archive or an execution
environment. Python and optional native dependencies are declared but not bundled or
resolved; complete executable dependency closure remains `NOT_ESTABLISHED`.

The description records the observed Git commit and dirty-working-tree state. Captured
bytes, not the commit identifier alone, identify a dirty snapshot. The exporter checks that
the captured catalog source matches the environment generating the registry; it does not
prove semantic behavior of the other retained code. The publisher and license are unsigned
declarations, not authenticated identity or a legal determination.

## Use it for a declared hole

Pass the package to the ordinary surface-analysis command with `--plan`. The geometry
must name the exact mechanism or relation being sought; broad domain labels do not match:

```bash
vstd surface analyze examples/verification_geometry_residual/geometry.json --plan --package reference-components.json --json
```

The retained reconstruction example has evidence needs this seed catalog cannot supply;
unmatched candidates are expected, not an export failure. This consumes the stored
registry. It never imports or executes the stored code and does
not close a verification surface hole merely because a candidate was found. Use
`--expected-package-sha256` with the separately checked digest to bind the intended package.
Cross-platform storage does not establish cross-platform native execution support.
