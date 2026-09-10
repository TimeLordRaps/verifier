# Examples

This directory contains runnable examples and fixtures for learning how implemented
Verifier Standard (VSTD) mechanisms behave within their stated boundaries. Use it for
instructional paths; use [`experiments/`](../experiments/README.md) for research questions,
study records, and roadmap-steering investigations.

## Start here

- [Quickstart](../docs/QUICKSTART.md): installation and the basic usage path.
- [Flagship adversarial demo](flagship_demo/README.md): expected rejection and honest
  uncertainty, not just a successful result.
- [Reconstruction residual](verification_geometry_residual/README.md): a bounded
  verification geometry with an explicit unresolved evidence horizon.
- [Interoperability planning](interoperability_planning/README.md): modeled-hole
  detection and exact catalog candidates with zero component execution.
- [Stored components](stored_components/README.md): retain a public source snapshot and
  consume its catalog for nonexecuting planning.
- [Non-critical compositions](interoperability_compositions/README.md): executable
  proof-producer/checker and adjacent-verifier examples with native results retained.
- [Graph topology](graph_topology/README.md): simultaneous Boolean equations and explicitly
  declared backward-time relations, with separate bounded consistency results.
- [Artifact-network specimen](artifact-network/README.md): deterministically materialize,
  inspect, diff, clone, and compose an exact signed publisher silo without a service.
- [Experimental workflow example](experimental_workflow/README.md): runnable use of an
  experimental integration; GitHub workflow success does not grant a VSTD verdict.

## What to expect

Read the example's own README or linked guide for prerequisites, inputs, commands,
expected outcomes, and limitations. Optional dependencies and native toolchains vary;
placement here does not establish support on every operating system.

These are maintained instructional paths, not blanket production-readiness or safety
guarantees. An example can demonstrate an experimental feature without making that
feature stable or normative. Consult the [current maturity](../README.md#current-maturity)
and [application programming interface (API) stability policy](../docs/API_STABILITY.md)
for the actual support boundary.

A successful run establishes only what its checking mechanism examined, under its
declared inputs, evidence, assumptions, and bounds. Preserve `UNKNOWN` and `CONFLICTED`;
neither a passing fixture nor a directory name proves an entire system correct or safe.
See [claims and limits](../docs/CLAIMS_AND_LIMITS.md).

Inspect commands before running them: `vstd run` executes the command in a manifest
without sandboxing it. `vstd plan` provides side-effect-free manifest inspection.
