# Verifier Standard (VSTD) governance

> **Acronym:** grounded decision certificate (GDC).

## Current phase

VSTD is maintainer-led project specification work. Publication makes the text and
reference implementation inspectable; it does not manufacture multi-stakeholder
consensus or standards-body recognition.

VSTD-3 is implemented for its typed model, strict schema/validator, reference
emulator, offline adapters, provenance composition, and conformance suite. It is not a
claim that accelerator vendors implemented the firmware contract or accepted the
specification.

VSTD-4 ships grounded-certificate/kernel checks and separate availability,
precommitment, challenge, degradation, and composition mechanisms. Its depth runtime
computes only a structural candidate over caller-supplied references with conformance
`NOT_ESTABLISHED`; no mechanism binds all rung propositions and VSTD-1/2/3 preconditions
into VSTD-4 conformance. `VSTD4-GDC-1` has no demonstrated independent implementation
or external interoperability. VSTD-5 remains draft and has no shipped witness procedure.

## Layer and release states

- **Implemented base:** a layer has a published specification, schema or typed model,
  executable reference path, and passing conformance tests for its declared surface.
- **Experimental:** the vocabulary and a bounded vertical slice exist, but independent
  implementations or broader interoperability evidence are still missing.
- **Challenged:** current evidence no longer supports a previously published claim.
- **Superseded:** an additive correction replaces a bounded document while historical
  release bytes and wire identifiers remain unchanged.

Specification layers use integer names; repository releases use semantic versions.
Released artifacts are frozen. Corrections are additive and identify the affected
layer, release, claim, evidence, and downstream impact.

## Change process

1. Open an issue stating the coordinate or seam being changed.
2. Declare compatibility impact and falsification conditions.
3. Add or update schemas, tests, and examples with the normative text.
4. Preserve `UNKNOWN`, `CONFLICTED`, unsupported structure, and horizons.
5. Obtain maintainer review before merging normative changes.

Normative changes require a versioned proposal. Editorial corrections that do not
change meaning may be merged in an additive repository release and remain visible in
history.

## Decision rights

Until a neutral standards venue and contributor agreement are adopted, TimeLordRaps is
the editor and release maintainer. This is a disclosed centralization boundary. The
intended next governance step is independent implementation feedback followed by a
venue with explicit copyright and patent terms.

The repository's Apache License 2.0 governs the specification, documentation, and
reference implementation at this source coordinate. Its contributor patent grant is a project
license term, not a substitute for a neutral standards venue's intellectual-property
policy or a separate contributor agreement.

## Conformance and marks

No organization is currently an accredited VSTD certifier. Implementers may state the
exact VSTD layer, repository release, receipt type, tests, and evidence they support. They must not imply
endorsement, comprehensive safety, or verification beyond that surface.
