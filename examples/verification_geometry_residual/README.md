# Reconstruction residual and bounded closure

> **Acronym:** Verifier Standard (VSTD).

This example is the smallest VSTD-0.2 verification-geometry vertical slice. Its
machine-readable form is [`geometry.json`](geometry.json).

## 1. Apparently complete decomposition

A decimal formatter is initially decomposed into two operational loci:

```text
parse -> render
```

At function grain, the declared functional-correctness coordinates for both loci
have passing test evidence. If verification stopped at the declared source
decomposition, the surface would appear complete.

## 2. Reconstruction pressure

The declared geometry reconstructs output `1.5`, while the retained observation is
`1,5`. The difference is recorded as the material `BEHAVIORAL` residual
`residual:decimal-separator`. It is not erased, averaged away, or explained by an
assumption.

## 3. Localization and refinement

Investigation refines the geometry with:

- locus `locus:locale`;
- seam `seam:locale-render`, relating runtime locale to the renderer; and
- `SEAM` novelty `novelty:locale-seam`, grounded in the residual.

The original locale was not captured. The residual is therefore terminated at the
explicit evidence horizon `horizon:locale-observation`. The horizon says where
derivation stopped; it does not assert what the historical locale was.

## 4. Closure and self-closure

The two coordinates selected by `surface:formatter` remain verified under their
bounded fixture. Ordinary surface closure is therefore available **up to the explicit
horizon**. Self-closure is refused because:

1. the material residual is not resolved;
2. the locale evidence horizon remains;
3. the seam retains verification valence for evidenced environment state; and
4. the fixture-test mechanism is not post-verified beyond that boundary.

The test
`tests/test_verification_geometry.py::test_reconstruction_residual_can_bound_closure_but_refuses_self_closure`
executes this distinction. A second test supplies captured-locale evidence, resolves
the residual, discharges the valence, and post-verifies the mechanism; only then does
the bounded geometry earn self-closure.

## 5. Higher-order verification without infinite workflow abstraction

`layer:v0` verifies the formatter surface. `layer:v1` treats the V0 geometry as a
secondary subject and verifies the immediately preceding layer. The typed validator
requires orders to be finite, contiguous, and adjacent. A skipped or recursively
invented workflow layer is invalid; an inability to continue is represented as a
horizon rather than hidden behind a trust assumption.
