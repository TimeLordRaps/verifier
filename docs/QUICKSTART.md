# Verifier Standard (VSTD) quickstart

> Reader aid: [concept glossary and primary precedents](CONCEPTS_AND_PRECEDENTS.md).

## 1. Install the public source

VSTD requires Python 3.10–3.13. The base runtime has no required third-party
dependencies.

```bash
git clone https://github.com/TimeLordRaps/verifier.git
cd verifier
python -m pip install .
```

Use `vstd` as the cross-platform command. The `verifier` compatibility alias can be
shadowed by Windows Driver Verifier.

Before evaluating a broader claim, review the canonical
[implementation-maturity table](../README.md#current-maturity). It separates implemented
checks from candidate calculations and unimplemented mechanisms.

## 2. Run the adversarial demo

```bash
vstd demo
vstd demo --json
```

A successful demo reports that all four *expected defensive outcomes* occurred. The
label `[DEMO OK]` deliberately avoids using `[PASS]`: two scenarios succeed precisely
because a malformed certificate is rejected, one because `UNKNOWN` is preserved, and
one because a graph claim is capped.

To inspect one specimen:

```bash
vstd demo --scenario wrong-artifact --json
```

## 3. Inspect before executing

The generic-run example contains a command. Planning is side-effect free; running is
not sandboxed.

```bash
vstd plan examples/generic_run/manifest.json --json
```

Inspect the command, resolved working directory, repository directory, input paths, and
output paths. If the manifest is not trusted or the isolation boundary is inadequate,
stop here.

## 4. Capture and validate

Inside an appropriate operating-system or container isolation boundary:

```bash
vstd run examples/generic_run/manifest.json --output /tmp/vstd-receipt
vstd validate /tmp/vstd-receipt
vstd inspect /tmp/vstd-receipt
```

`validate` applies the bundled profile's structural checks and recomputes the receipt's
stable-payload digest. It does not invoke an external JavaScript Object Notation (JSON)
Schema engine, rehash the
declared artifacts, verify external evidence, or establish that the claim is true. Use
`reproduce` for the separately bounded artifact comparison.

## 5. Exercise the falsification route

```bash
vstd reproduce /tmp/vstd-receipt --rerun
```

The rerun executes the recorded command again and compares declared outputs. A clean
reproduction supports the receipt's bounded reproducibility statement. A mismatch
refutes that statement. Missing capability or evidence remains `UNKNOWN`; it is not
silently converted into success.

## 6. Read the normative path

1. [`standard/LADDER.md`](../standard/LADDER.md) — numbering, separate evidence per layer,
   and composition.
2. [`standard/VSTD-4.md`](../standard/VSTD-4.md) — refutability and the grounded
   decision certificate.
3. [`standard/VSTD-Graph-1.md`](../standard/VSTD-Graph-1.md) — collection provenance.
4. [`docs/CLAIMS_AND_LIMITS.md`](CLAIMS_AND_LIMITS.md) — permitted public wording.

To evaluate the project rather than merely run it, start by trying to create a receipt
that passes outside its declared coordinate. A reproducible counterexample is more
valuable than a general endorsement. Report a
[specification ambiguity](https://github.com/TimeLordRaps/verifier/issues/new?template=specification-ambiguity.yml),
[counterexample](https://github.com/TimeLordRaps/verifier/issues/new?template=counterexample.yml),
or [security issue](../SECURITY.md) through its designated route.
