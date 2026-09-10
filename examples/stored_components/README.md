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
python examples/stored_components/build_reference_package.py --output reference-components.json --package-version 1.3.0
vstd components inspect reference-components.json --json
```

The command prints the canonical package digest. Compare it through a separately trusted
channel before another machine relies on package identity. When adding an untracked public
source module, explicitly review and name it. For example, only while the storage module
itself is untracked:

```bash
python examples/stored_components/build_reference_package.py --output reference-components.json --package-version 1.3.0 --include-untracked src/verifier/interoperability/storage.py
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

All **30 first-party entrypoints across 13 grouping labels** bind to the retained package
source snapshot. This is not a count of independent native integrations. The snapshot
includes distinct proof-producer and proof-checker entries, bounded platform comparison,
receipt and graph rechecking, artifact verification, experimental signed-silo transfer
materialization, experimental adjacent-result composition, and distinct experimental
finite-set proposition-transfer assessment and receipt rechecking, and finite typed-formation
production, independent checking and native session adaptation, plus bounded finite
authority-composition assessment. A source snapshot is not a
wheel, an installation archive or an execution environment. Python and optional native
dependencies are declared but not bundled or resolved; complete executable dependency
closure remains `NOT_ESTABLISHED`.

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

The transfer assessor and rechecker accept exact native `VSTD-PROPOSITION-TRANSFER-0.1`
declaration bytes; rechecking additionally accepts `VSTD-PROPOSITION-TRANSFER-RECEIPT-0.1`
receipt bytes. Their `VSTD-2` schema is a planning surface, not a native input. Both need
separately supplied exact commit and artifact evidence bytes. Their compiled rule profile
has an inert, byte-identical package mirror at
`src/verifier/profiles/proposition-transfer-rule-0.1.json`, separate from schemas.
The source of truth is `rule_profile_bytes()` in `proposition_transfer.py`; the mirror is
not dynamically loaded as code or used to select arbitrary rules. Its Secure Hash
Algorithm 256-bit (SHA-256) digest is
`sha256:0d26f06addc32e61e0ba68a466b4721db6a8ad2a46021c96f226da7d91b410bd`.

An exact mechanism match does not establish rule-profile compatibility. The package-bound
plan retains an unresolved exact-profile prerequisite alongside evidence, runtime,
dependency, authorization, and future reassessment requirements. Missing evidence leaves
execution readiness `NOT_ESTABLISHED`; finding a candidate neither runs the checker nor
closes a hole. A true target can coexist with a failed transfer, and receipt equality
may reproduce negative or unknown components. These results do not upgrade the six silo
axes or establish authority, general graph-wide deduction, or an execution attestation.

The experimental typed-formation producer accepts exact `VSTD-TYPED-FORMATION-0.1`
subject bytes and emits `VSTD-TYPED-FORMATION-CERTIFICATE-0.1` certificate bytes.
The independent checker accepts both and returns an unversioned report. The session
adapter instead accepts a typed `BoundProposition` and an ordered subject/certificate
byte pair; it does not advertise a serialized wrapper schema. All three retain the
exact inert `src/verifier/profiles/typed-formation-0.1.json` rule declaration, with
digest `sha256:271760d604e1ade55cba4974c658b92263bd3ee8ae343677dd91d0e713fb677f`.
The `VSTD-2` planning schema is not their native input. Discovery and readiness never
execute stored source or validate a claimed proof; supplied readiness declarations
are not verification evidence. A subsequent formation result covers only the finite
constructor calculus, not source self-derivation, completeness, grounding or authority
axiom agency preservation. See the [exact contract](../../standard/TYPED_FORMATION.md).

The separate experimental formation receipt rechecker accepts canonical
`VSTD-SILO-FORMATION-SELECTION-0.1` selection bytes, exact commit bytes,
`VSTD-SILO-FORMATION-RECEIPT-0.1` receipt bytes and a bounded ordinary evidence
dictionary. It captures actual census observations, rebuilds the entire receipt
and returns the fresh unversioned inspection only on exact equality. Negative,
incomplete and unknown fields remain unchanged by reproduction. Its stored
implementation retains the [portable receipt contract](../../standard/FORMATION_RECEIPT.md)
and structural schema. Catalog matching and readiness do not perform this replay
or establish the roles of supplied input bytes.
