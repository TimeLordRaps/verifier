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
shadowed by Windows Driver Verifier. From a source checkout without installing,
`PYTHONPATH=src python -m verifier` reaches the same interface.

## 1b. Let the runtime tell you what to run next

```bash
vstd start
vstd start --json
```

`vstd start` prints the ordered path below as copy-pasteable commands, with the
reason for each one and the four words whose meaning is easy to assume wrongly
(`UNKNOWN`, `established`, `depth`, `conformance`). It runs nothing and writes
nothing, so it is safe as a first command. The `--json` form emits the same task
list for an assistant driving the command-line interface (CLI).

At any point, `vstd explain <file.json>` restates a receipt or certificate in
plain language — see [section 7](#7-read-any-result-in-plain-language).

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

## 6. Submit a compatible claim (`vstd publish`)

The generic receipt above does not automatically satisfy the computational claim-packet
contract. For a compatible claim and receipt, the command requires a registered submitting
publisher identity and credential file. Success records storage pending human review;
publication remains `NOT_ESTABLISHED`. See [the claim submission tutorial](tutorials/PUBLISH_A_CLAIM.md)
for input boundaries, local preflight, authentication and response binding.

## 7. Read any result in plain language

```bash
vstd explain ./my-receipt
vstd explain ./my-receipt/receipt.json
vstd explain ./specimen/certificate.json --json
```

It takes either the directory `vstd validate` takes or the JSON file inside it.

`vstd explain` restates a stored receipt or certificate: what was established,
what was not, the checker's own reason for each gap, and the next command worth
running. It never re-evaluates evidence and never changes a verdict, so an
`UNKNOWN` stays `UNKNOWN`.

It exits on the verdict already stored in the artifact — `0` for `PASS`, `1`
for `FAIL`, `2` for `UNKNOWN` — so `vstd explain cert.json && ...` cannot read
success out of a certificate whose printed status is `FAIL`. A document that
carries no verdict, such as a run receipt, has nothing to propagate and reports
a successful read. Pointing it at something that is not a VSTD artifact at all is a usage error and exits `1`, like pointing it at a missing file.

For a **run receipt** — the first artifact most people produce — it reports the
claim, the observed run and its exit code, what was digested, the receipt's own
declared limitations, and one distinction worth pausing on: a *declared*
reproducibility ceiling such as `CONTENT_IDENTICAL` is what the receipt is
willing to be held to, not something it has shown. `vstd reproduce <dir>
--rerun` is what demonstrates it. A receipt is a record of what happened, not a
verdict; `vstd validate` produces the verdict.

For a **certificate**, it exists because two numbers are easy to misread:

- **`domain_depth`** counts only the *unbroken* run of established checks from
  the first one. A certificate can have four of five checks established and a
  depth of two, because the gap at check three stops the count. The later
  checks still hold on their own evidence.
- **`certified_profile_depth`** counts *whole complete profiles*, not
  established obligations. One established obligation out of seven leaves it at
  zero.

`explain` states both distinctions in words rather than leaving you to infer
them, and `--json` returns the same structure so a person and an assistant
reading the same artifact are told the same thing.

## 8. Certify against the obligation catalogue

```bash
vstd certification catalog
vstd certification domain-catalog
```

The first lists the 47 object-profile obligations (`X.M`) and which have a
built-in checker. The second lists the six executable domain adapters — DATA,
ENV, BENCH, HYPER, MODEL and SIM — and their per-check dependency graphs.

Run the two shipped, complete examples:

```bash
PYTHONPATH=src python examples/grounded_certification.py ./specimen
PYTHONPATH=src python examples/domain_grounding.py
```

The first establishes obligation `1.1` and leaves the rest of VSTD-1 `UNKNOWN`
because that evidence is absent. **It exits 2, and that is the intended
result**: every command here exits `0` for `PASS`, `1` for `FAIL` and `2` for
`UNKNOWN`, so an incomplete certification cannot read as success. Pass its
output directory to `vstd explain` to see exactly which obligations are blocked
and by what. Full contract: [grounded certification](GROUNDED_CERTIFICATION.md).

## 9. Read the normative path

1. [`standard/LADDER.md`](../standard/LADDER.md) — verification-complex terminology, numbered profiles, separate evidence per closure coordinate,
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
