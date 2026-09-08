# Experiments

This directory contains non-normative studies and experiment records used to explore
mechanisms, test hypotheses, and steer Verifier Standard (VSTD) development. It can
contain both ongoing investigations and completed bounded studies. For instructional
paths through implemented mechanisms, start with [`examples/`](../examples/README.md).

## Start here

The generated [experiment index](INDEX.md) links each study's `experiment.json` manifest
and summarizes its recorded question, state, and open horizons. Read the manifest and
any study-specific README before interpreting results or attempting reproduction.
They record the study's scope, hypotheses and falsification conditions, artifacts,
resource bounds, observations, native results, and unresolved limitations.

Index inclusion checks manifest structure and bound repository-artifact digests. It
does not establish a hypothesis, independent reproduction, publication, or VSTD verdict.
A recorded completed state is the state of that bounded study, not proof that every
research question or limitation has been resolved.

## How to interpret and reuse the work

Separate proposals, implemented mechanisms, recorded observations, and reproduced
results. Inspect the exact artifact and environment coordinates, reproduction
instructions, and remaining blockers; do not assume every study is immediately
runnable. Preserve `UNKNOWN`, unmapped native results, and explicit evidence horizons.
Consult [claims and limits](../docs/CLAIMS_AND_LIMITS.md) before extending a result.

The experimental status applies to the named study or unfinished mechanism, not
automatically to an underlying governing architecture. Normative requirements remain
in [`standard/`](../standard/), and implemented reference paths retain their separately
documented [maturity](../README.md#current-maturity).

A completed study may remain here as a research record while a linked example teaches
its implemented mechanism. Moving files between directories does not establish
correctness, stability, cross-platform compatibility, or safety.
