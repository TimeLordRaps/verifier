# VSTD governance

## Current phase

VSTD is founder-maintained project specification work. Publication makes the text and
reference implementation inspectable; it does not manufacture multi-stakeholder
consensus or standards-body recognition.

## Version states

- **Implemented base:** a version has a published specification, schema or typed model,
  executable reference path, and passing conformance tests for its declared surface.
- **Experimental:** the vocabulary and a bounded vertical slice exist, but independent
  implementations or broader interoperability evidence are still missing.
- **Challenged:** current evidence no longer supports a previously published claim.
- **Superseded:** a later version replaces the document through an explicit migration.

Released versions are frozen. Corrections are additive and identify the affected
version, claim, evidence, and downstream impact.

## Change process

1. Open an issue stating the coordinate or seam being changed.
2. Declare compatibility impact and falsification conditions.
3. Add or update schemas, tests, and examples with the normative text.
4. Preserve `UNKNOWN`, `CONFLICTED`, unsupported structure, and horizons.
5. Obtain maintainer review before merging normative changes.

Normative changes require a versioned proposal. Editorial corrections that do not
change meaning may be merged without a new standard version but remain visible in
history.

## Decision rights

Until a neutral standards venue and contributor agreement are adopted, Tyler Roost is
the editor and release maintainer. This is a disclosed centralization boundary. The
intended next governance step is independent implementation feedback followed by a
venue with explicit copyright and patent terms.

The repository's Apache License 2.0 governs the specification, documentation, and
reference implementation in this release. Its contributor patent grant is a project
license term, not a substitute for a neutral standards venue's intellectual-property
policy or a separate contributor agreement.

## Conformance and marks

No organization is currently an accredited VSTD certifier. Implementers may state the
exact VSTD version, receipt type, tests, and evidence they support. They must not imply
endorsement, comprehensive safety, or verification beyond that surface.
