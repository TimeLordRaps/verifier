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
| experiment-zizk-vstd | RUNNING | Can a bounded event-ledger protocol operationalize the normative artifact-first causal orientation: scoped artifact support moving parent-to-child and typed Rust moving child-to-parent, without actor reputation, scalar cancellation, or causal overclaim? | CANDIDATE | 5 | [`experiments/zizk_vstd/experiment.json`](zizk_vstd/experiment.json)<br>`sha256:09d5c462eb3ea57ad30cdaca9ca4310991d46f3181c0515a8c1ec886e98352e7` |

Platform events, including successful workflows and merges, retain
`verification_effect = NONE` unless a separate native result is explicitly
mapped through a bound VSTD receipt.
