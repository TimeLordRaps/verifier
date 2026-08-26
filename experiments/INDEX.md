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
| experiment-artifact-first-mechanisms | RUNNING | Which bounded event serialization, support-transfer algebra, Rust concentration and localization rules, and hidden-witness trichotomy mechanisms can implement the governing artifact-first causal orientation without actor reputation, scalar cancellation, causal overclaim, or making that orientation contingent on the study? | CANDIDATE | 5 | [`experiments/artifact_first_mechanisms/experiment.json`](artifact_first_mechanisms/experiment.json)<br>`sha256:5801835f64a1dabc4d474be6a97a9d4fa6f7bebd8b26ebad5583844af3a0b4ea` |
| experiment-github-verdict-neutrality | COMPLETED | Does the GitHub adapter preserve successful workflow and merge states without converting them into a VSTD verdict? | INTERNAL | 1 | [`experiments/github_verdict_neutrality/experiment.json`](github_verdict_neutrality/experiment.json)<br>`sha256:3b98310d35c20e7099d242e2c655e4bf8dc62d91298adc04e4dc2f56f2f79d89` |

Platform events, including successful workflows and merges, retain
`verification_effect = NONE` unless a separate native result is explicitly
mapped through a bound VSTD receipt.
