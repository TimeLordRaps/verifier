# Competition evaluation profile

> Reader aid: [concept glossary and primary precedents](../CONCEPTS_AND_PRECEDENTS.md).

**Status:** non-normative VSTD-1/VSTD-Graph integration profile
**Version:** 0.1
**Date:** 2026-08-21

This profile applies VSTD receipts and provenance hypergraphs to predictive-AI,
scientific-ML, agent, and other scored evaluations. It does not add a new VSTD verdict
and does not claim adoption, affiliation, certification, or endorsement by any
conference, competition, benchmark, or organizer.

The bounded public wording in
[`docs/CLAIMS_AND_LIMITS.md`](../CLAIMS_AND_LIMITS.md#competition-and-scored-evaluation-claims)
controls if a shorter phrase in this non-normative profile could be read more broadly.

## 1. Evaluation surface

An integration declares the exact surface before it reports a verified result:

1. task and rules version;
2. training, reference, and permitted external-data snapshots;
3. model, agent, checkpoint, adapter, and configuration identities;
4. prediction or submission artifact and submission timestamp;
5. execution image, runtime, hardware class, seed policy, and command;
6. evaluator/scorer source and configuration identity;
7. held-out input commitment or an explicit `UNKNOWN`/`TRUST_ROOT` horizon;
8. outcome-resolution source and resolution timestamp, when predictions concern
   events resolved later;
9. raw evaluator output and derived score report; and
10. limitations, exclusions, and falsification conditions.

Coordinates outside that surface do not inherit its verdict.

## 2. Minimum recorded chain

```text
rules + data snapshots + permitted externals
  -> build/train/fine-tune transformation
  -> model or agent snapshot
  -> prediction/submission transformation
  -> immutable submission artifact
  -> evaluator/scorer transformation
  -> raw metrics
  -> score report
```

Each artifact receives a stable identifier and content digest. Each transformation
records its input and output roles, software identity, parameters, environment, and
evidence classification. A declaration is not relabeled as direct observation or
independent reproduction.

## 3. Predictive-evaluation time boundary

For a prediction resolved after submission, the receipt records at least:

- `prediction_emitted_at`;
- `prediction_freeze_digest`;
- allowed update or abstention policy;
- `outcome_resolved_at`;
- resolution-source identifier and snapshot digest;
- scoring-rule identifier and parameters; and
- whether the prediction, resolution, and scoring observations came from independent
  channels.

The integration MUST NOT overwrite a frozen prediction after outcome information
becomes available. Corrections are additive and link to the challenged or superseded
artifact.

## 4. Hidden tests and organizer-controlled artifacts

A participant normally cannot observe or serialize hidden tests. The participant
receipt therefore records an explicit horizon. An organizer can later close part of
that horizon by publishing a commitment, signed attestation, disclosed snapshot, or
independently reproducible evaluator receipt.

Absence of access is not evidence of hidden-test integrity. A participant-side
`VERIFIED` result MUST NOT imply that the organizer's hidden corpus was uncontaminated,
that the evaluation prevented leakage, or that the public leaderboard is authoritative.

## 5. Claims licensed by this profile

With corresponding evidence, an implementation may state that:

- the recorded submission bytes match a named digest;
- the recorded evaluator version produced the bound raw metrics when rerun in the
  declared environment;
- the score report is a deterministic derivation of those metrics under the named
  scoring rule;
- the recorded ancestry graph contains the declared datasets, model snapshot,
  submission, evaluator, and report relationships;
- a particular recorded policy formula passed; or
- a challenged or revoked ancestor has the enumerated downstream blast radius.

Each statement remains bounded to the named snapshots, mechanisms, and evidence.

## 6. Claims not licensed by this profile

The profile does not establish:

- empirical truth or future generalization beyond evaluated inputs;
- correctness or representativeness of the benchmark design;
- authenticity of an unevidenced origin, license, contributor, or outcome source;
- absence of hidden inputs, leakage, contamination, evaluator manipulation, or
  out-of-band execution;
- ranking, prize eligibility, rule compliance, or organizer acceptance unless the
  applicable authority supplies bound evidence; or
- endorsement by VSTD or by a competition organizer.

## 7. Conformance wording

Use a bounded statement such as:

> The submission and score receipt conform to the VSTD competition evaluation profile
> 0.1 for the declared artifact, evaluator, and provenance surface. Hidden-test
> integrity and organizer acceptance remain outside the participant-observable surface.

Do not shorten this to “the model,” “the competition result,” or “the prediction is
verified” without naming the exact coordinate and evidence that passed.
