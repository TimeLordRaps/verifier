# Experimental workflow profile

**Status:** experimental, non-normative VSTD-1/VSTD-Graph integration profile
**Profile identifier:** `vstd.experimental-workflow`
**Version:** `0.1`
**Date:** 2026-08-24

This profile gives experiments a portable record of **what question is being tested,
what verification work was selected, why it was selected, how much work was allowed,
what the native tools actually returned, and what remains unresolved**. It lets two
workflow systems exchange the same experiment boundary without pretending that a GitHub
merge, successful job, publication, or verifier exit code is automatically a VSTD
`PASS`.

The profile is not a new VSTD layer or verdict. It does not change any receipt wire
identifier, canonical digest, schema `$id`, conformance behavior, or normative VSTD
semantics.

## 1. The portable unit

A profile manifest binds these surfaces:

| Surface | Required meaning |
|---|---|
| `experiment` | Stable identifier, question, lifecycle state, and start boundary. |
| `hypotheses` | Falsifiable statements. `SUPPORTED` remains evidence-bounded rather than universally true. |
| `preregistration` | Whether a plan was absent, drafted, frozen, or later amended, plus the bound artifact when frozen. |
| `artifacts` | Portable locators and lowercase SHA-256 digests. Local machine paths are prohibited. |
| `budgets` | Integer resource limits and recorded consumption. Every selected action binds at least one budget. |
| `actions` | The work selected, its priority, reason, alternatives, dependencies, trigger, substrate, and expected artifact effect. |
| `observations` | What was observed, with evidence references and limitations. |
| `interventions` | The declared change applied to bound artifacts and the artifacts it produced. |
| `native_results` | The exact native verifier status and its artifact. A separate mapping field records whether VSTD evaluation occurred. |
| `adaptations` | Which observations or challenges changed later actions or artifacts, and why. |
| `amendments` | Additive corrections that name what they supersede; history is not overwritten. |
| `challenges` | Open, resolved, or rejected attempts to refute a bound record. |
| `horizons` | Explicit `UNKNOWN`, `CONFLICTED`, `BLOCKED`, or out-of-scope surfaces. |
| `publication` | Distribution state only. Publication does not establish correctness or adoption. |
| `workflow_events` | Platform observations whose `verification_effect` is always `NONE`. |
| `manifest_digest` | SHA-256 over deterministic JSON for every other field. |

The machine-readable shape is in
[`experimental-workflow.schema.json`](experimental-workflow.schema.json). The
standard-library validator is
[`profile.py`](../../src/verifier/experimental_workflow/profile.py).

## 2. Bounded verification allocation

An action records:

1. a target and verifier substrate;
2. a positive integer priority;
3. why this action was selected;
4. evidence used for that selection;
5. alternatives considered;
6. an explicit resource budget and consumed amount;
7. dependencies and observations that triggered it; and
8. its expected effect on the artifact under construction.

This makes allocation inspectable. It does **not** prove that the allocation was optimal,
unbiased, safe, or the only reasonable allocation. Priority is a scheduling coordinate,
not a truth coordinate. Exhausted work remains visible through the action state and
horizons instead of being rewritten as success.

The profile deliberately does not prescribe Bayesian inference, decision trees,
boosted trees, control theory, embeddings, or any other selection engine. Those are
orchestrated substrates. Their native outputs can be bound as selection evidence, while
the portable fields above preserve the claim boundary between the allocation operator
and the mechanism it orchestrates.

## 3. Native result and VSTD mapping boundary

Every native result has a `mapping` object:

- `NOT_EVALUATED` requires the VSTD verdict, mapping profile, and receipt reference to
  remain `null`.
- `MAPPED` requires an explicit VSTD verdict, mapping profile, receipt artifact, and
  reason.

Recording `native_status = "PASS"`, `"SAT"`, `"proof verified"`, or any other tool
vocabulary does not authorize `mapping.status = "MAPPED"`. The actual mapping and bound
VSTD receipt are separate evidence. `UNKNOWN` and `CONFLICTED` remain distinct mapping
outcomes and cannot be dropped because the surrounding workflow completed.

## 4. GitHub adapter

[`github.py`](../../src/verifier/experimental_workflow/github.py) consumes a strict,
normalized snapshot rather than an unconstrained GitHub API response. It maps:

| GitHub observation | Workflow event |
|---|---|
| issue state | `PLATFORM_ISSUE` |
| commit identity | `PLATFORM_COMMIT` |
| workflow run and conclusion | `PLATFORM_WORKFLOW_RUN` |
| workflow artifact availability | `PLATFORM_ARTIFACT` |
| pull-request and merge state | `PLATFORM_PULL_REQUEST` |

Every emitted event sets `verification_effect = "NONE"`. In particular:

- a successful Actions run is not a VSTD `PASS`;
- a merge is an integration event, not verification;
- an available artifact is not evidence that its bytes satisfy a claim; and
- a closed issue is not evidence that the underlying defect was corrected.

Unknown fields are rejected rather than guessed into the portable representation. A
different workflow platform can implement the same event boundary without adopting
GitHub identifiers.

## 5. Canonicalization

The manifest digest uses UTF-8 JSON with:

- keys sorted recursively;
- compact `,` and `:` separators;
- ASCII escaping enabled;
- no floating-point values; and
- `manifest_digest` omitted from its own input.

The stored value is `sha256:<64 lowercase hexadecimal characters>`. This digest binds
the workflow record. It does not verify the bytes at an artifact locator; each artifact
has its own digest for that check.

## 6. Dogfooding and index

Experimental manifests live below `experiments/` as `experiment.json`. The command

```bash
PYTHONPATH=src python scripts/build_experiment_index.py --check
```

validates every manifest and confirms that [`experiments/INDEX.md`](../../experiments/INDEX.md)
is current. The first bound record is the deterministic GitHub verdict-neutrality
specimen. A blocked experiment remains eligible for indexing once its intentional files
are isolated and its manifest honestly records the blocker; indexing is not publication
of a positive result.

The runnable example under
[`examples/experimental_workflow/`](../../examples/experimental_workflow/) demonstrates
that a successful GitHub workflow and merged pull request remain verdict-neutral.

The installed CLI exposes the same bounded surface:

```bash
vstd experiment validate experiments/github_verdict_neutrality/experiment.json --json
vstd experiment github-events examples/experimental_workflow/github_snapshot.json --json
```

`validate` checks the strict profile shape and manifest digest. If a manifest contains
`repo:` artifact locators, supply `--repo-root PATH`; otherwise the command returns exit
code `2` and reports `VALID_WITH_UNCHECKED_REPOSITORY_ARTIFACTS` rather than silently
claiming those bytes were checked.

## 7. Claims licensed by profile conformance

For a valid, digest-matching manifest an implementation may state:

> The experiment record conforms to experimental workflow profile 0.1 for the declared
> question, artifacts, budgets, actions, native results, adaptations, and horizons.

This means the record is structurally valid and internally bound. It does not establish:

- that the experiment was executed as recorded without supporting evidence;
- that a hypothesis is true outside its declared evidence;
- that a native verifier is correct;
- that a VSTD mapping is valid without checking its bound receipt;
- that a selected action was optimal;
- that a publication, commit, workflow, pull request, or merge is correct;
- external adoption, endorsement, independence, identity, authorization, or safety.
