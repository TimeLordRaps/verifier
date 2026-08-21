# Contributing to VSTD

Contributions are welcome when they make a declared verification surface more precise,
more independently checkable, or easier to implement without strengthening unsupported
claims.

## Required for a normative change

- identify the affected VSTD version and coordinate or seam;
- state compatibility and migration effects;
- include a falsification condition;
- update machine-readable schemas or typed models where applicable;
- add tests that fail before the change and pass after it;
- document new trust roots, unknowns, residuals, and horizons.

Do not replace `UNKNOWN` with false, erase `CONFLICTED`, infer missing provenance, or
call self-observation independent verification.

Unless explicitly stated otherwise, a contribution intentionally submitted for
inclusion in this repository is provided under the Apache License 2.0, including its
Section 3 patent terms and Section 5 contribution terms. The project does not yet have
a separate contributor license agreement or standards-venue patent policy; this is a
known boundary for future standards-venue work.
