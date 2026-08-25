# Contributing to Verifier Standard (VSTD)

> **Acronym:** GNU Privacy Guard (GPG).

Contributions are welcome when they make a declared verification surface more precise,
more independently checkable, or easier to implement without strengthening unsupported
claims.

## Required for a normative change

- identify the affected VSTD layer, repository release, and coordinate or seam;
- state compatibility effects, including any frozen wire identifiers or historical
  receipts affected;
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

## Commits

Commits in this repository are GPG-signed (`git commit -S`). Pull requests are expected to
carry signed commits, and automated contributors must never bypass signing. A commit
signature binds bytes to a signing key; it does not establish the signer's identity, the
change's correctness, independence, authorization, or safety.

## Feedback that does not require a proposed patch

Use the structured issue forms for specification ambiguities, counterexamples or
unsound claims, and independent implementation reports. A failed implementation or
interoperability attempt is useful evidence and is not treated as endorsement or
adoption. Send vulnerability details only through the private route in `SECURITY.md`.
