# Your first receipt

This walkthrough uses the Verifier Standard (VSTD) generic-run example: a small
word-frequency computation with declared input and output files. It requires Git
and the [released package installation](INSTALLATION.md).

## Get the matching example

Use the example from the same release as the installed package:

```bash
git clone --branch v1.3.0 --depth 1 https://github.com/TimeLordRaps/verifier.git verifier-example
cd verifier-example
```

This checkout is a release snapshot, not a development branch. The example lives
under `examples/generic_run/`. Its manifest names the command, inputs, outputs,
claim scope, limitations, and falsification conditions.

## Inspect the plan

The command-line interface (CLI) can resolve the manifest without executing its
command. The optional output below uses JavaScript Object Notation (JSON).

```bash
vstd plan examples/generic_run/manifest.json --json
```

Read the resolved command and working directory. Inspect `compute.py` and
`input.txt` in the example directory. Confirm that the output paths are the ones
you expect. Planning is side-effect free; `run` executes the manifest command
and is not a sandbox. Use an appropriate operating-system or container isolation
boundary for code you do not trust.

## Capture the run

From the checkout root, use a fresh output directory:

```bash
vstd run examples/generic_run/manifest.json --output receipt-demo
vstd inspect receipt-demo
```

The example computation writes its declared outputs in its own working directory.
The receipt bundle is written to `receipt-demo`. The inspection report presents
the captured claim and evidence surface; inspect the generated files as well.

## Validate the receipt

```bash
vstd validate receipt-demo
```

For the bundled generic-run profile, validation checks receipt structure and
recomputes the stable-payload digest. It does not rehash the declared artifacts,
verify external evaluation evidence, or prove the claim true. Schema-shaped data
and semantic correctness are different propositions.

## Reproduce the declared outputs

```bash
vstd reproduce receipt-demo --rerun
```

This executes the recorded command again and compares declared outputs. Agreement
supports byte-level reproducibility for that rerun and those outputs. A mismatch
refutes that bounded statement. Missing evidence or capability must remain
`UNKNOWN`, rather than becoming success.

## Follow the evidence boundary

| Observation | What it establishes | What it does not establish |
|---|---|---|
| Plan resolves | The manifest can be interpreted into the displayed plan | Command execution or safety |
| Run completes | The capture path produced its recorded run and bundle | Independent validation or claim truth |
| Validation succeeds | The implemented structural and digest checks succeed | External evidence or artifact comparison |
| Rerun outputs agree | The declared outputs match for that rerun | Universal determinism, portability, or independent corroboration |

The example declares limitations and refutation conditions so a result stays tied
to its actual scope. Keep those boundaries when adapting it to your own work.

Continue with [claims and limits](CLAIMS_AND_LIMITS.md), then the
[conformance architecture](ARCHITECTURE.md) to trace each check to its owner.
