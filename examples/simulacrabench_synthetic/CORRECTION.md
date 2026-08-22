# Additive correction to `VSTD-SB-SYNTH-001`

**Correction date:** 2026-08-22
**Corrected packet:** `VSTD-SB-SYNTH-002`

The first public specimen is preserved at immutable commit
[`a37e6128fc6eccb66160a2f7c3af2f43341c227e`](https://github.com/TimeLordRaps/verifier/tree/a37e6128fc6eccb66160a2f7c3af2f43341c227e/examples/simulacrabench_synthetic).
Its packet digest is
`sha256:f182bfce5a5ae8e7137795300d42e285f365e6707b7c3517b3cee7b02331963b`;
its challenge digest is
`sha256:9ce25775826ef90f3eea0abdaa62268c4e5ce34092e63e2cc6cc88248a9395d6`.

## What was wrong

1. The packet used a locator scheme with no shipped resolver and treated nonempty locator
   and retention strings as enough to derive `AVAILABLE`.
2. The public verifier did not retrieve any private artifact or receive observed bytes.
3. A founder-authored transcript under the same trust root was accepted as an authorized
   adjudication, moving a deliberate mutant from `CHALLENGED` to `REVOKED` without public
   score recomputation or an independent adjudicator.

Those statements overstated what the public artifacts established.

## Correction

- Private artifacts now have no invented locator and derive only `IDENTIFIED`.
- The bundle fails the `AVAILABLE` requirement; public score reproduction remains
  `UNAVAILABLE`.
- The challenge demonstration contains a filing but no private transcript and no
  adjudication. Its terminal public state is `CHALLENGED`.
- `ArtifactAvailability` now requires an observed-byte retrieval binding before deriving
  `AVAILABLE` or `PORTABLE`; locator and retention declarations alone do not elevate it.
- The recorded local `PASS` and `0.33` are retained only as a claim made under the same
  founder-operated trust root, not as a public rerun or independent result.

The old commit and digests remain immutable. Current documentation and tests point to the
corrected specimen rather than silently reinterpreting the historical bytes.
