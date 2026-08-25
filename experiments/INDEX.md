# Experimental work index

> **Acronym:** Verifier Standard (VSTD).

> **Experimental and non-normative.** Inclusion means that a profile manifest
> is structurally valid and its `repo:` artifacts match their bound digests. It
> does not establish a hypothesis, verifier, publication, or VSTD verdict.

Regenerate or check this file with:

```bash
PYTHONPATH=src python scripts/build_experiment_index.py --check
```

| Experiment | State | Question | Publication | Open horizons | Manifest |
|---|---|---|---|---:|---|
| experiment-github-verdict-neutrality | COMPLETED | Does the GitHub adapter preserve successful workflow and merge states without converting them into a VSTD verdict? | INTERNAL | 1 | [`experiments/github_verdict_neutrality/experiment.json`](github_verdict_neutrality/experiment.json)<br>`sha256:3b98310d35c20e7099d242e2c655e4bf8dc62d91298adc04e4dc2f56f2f79d89` |
| experiment-zizk-vstd | RUNNING | Can bounded predicates support hidden witnesses and minimized identity disclosure while artifact trust moves forward through developmental claim space and child Rust moves backward to concentrate on candidate falsehoods in bound ancestor claim architecture, without actor reputation becoming verdict weight? | CANDIDATE | 5 | [`experiments/zizk_vstd/experiment.json`](zizk_vstd/experiment.json)<br>`sha256:f5230cef21a94d576120df01237f99fd5000be6f1afcad7dc707b28b585ee003` |

Platform events, including successful workflows and merges, retain
`verification_effect = NONE` unless a separate native result is explicitly
mapped through a bound VSTD receipt.
