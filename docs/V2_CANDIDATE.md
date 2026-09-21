# Version 2.0.0 candidate boundaries and migration

Verifier Standard (VSTD) 2.0.0 is **unreleased**. The Python Package Index (PyPI)
and GitHub release list were checked on 2026-09-19: the latest published package
was 1.5.0. Recheck those services before publication; this observation expires
when either changes. Install a candidate from its reviewed source checkout.

## Release name and grounded certification

**Verifier / `verifier-standard` v2.0.0 — The grounded certification release.**
This release name was selected by the maintainer on 2026-09-19.

Grounded certification means that a decision certificate binds an exact claim and
artifact coordinate to its evidence, encoding rules, checking mechanism, and
declared bounds. Its grounding must be checked; a label or digest alone does not
establish the claimed proposition. These mechanisms predate this candidate's
experimental additions. The existing grounded decision certificate (GDC) format
`VSTD4-GDC-1` and checker support bounded decision checking; kernel acceptance alone
does not establish full VSTD-4 conformance. The evidence-bound `establish_vstd4`
path separately reruns mechanisms for prerequisite profiles and all fourteen rungs.

The release now adds 47 individually evidence-bound obligation coordinates across
all five object numbered profiles: `1.1–1.7`, `2.1–2.7`, `3.1–3.8`, `4.1–4.14`,
and `5.1–5.11`. VSTD-4 retains its existing rung meanings; the other coordinates
are obligations, not software versions or certification strength scores.
The `VSTD-3.0` receipt identifier remains unchanged. See the
[normative contract](../standard/GROUNDED_CERTIFICATION.md) and
[executable certification guide](GROUNDED_CERTIFICATION.md).

The new engine binds an external admission policy, checks each exact proposition,
retains missing prerequisites and refutations, and emits portable replayable
certificates. Six obligations have built-in native adapters; the remaining 41
require explicitly registered domain mechanisms that check their stated propositions.
The catalogue and orchestration do not by themselves discharge those obligations.

The candidate also adds eight native grounded domain adapters with 38 cumulative
checks: dataset transformations and split/overlap analysis; retained environment
inventory/configuration/resource/reproduction observations; executable benchmark
oracles and scoring; checkpoint/optimizer/gradient replay; model inference, metrics
and challenges; simulation transition/invariant/projection/channel/shard checks;
declared agent observation surfaces and their retained transcripts; and agent
trajectories bounded by one harness certificate's observation ceiling.
These paths have portable certificates with external request and policy binding.
Their supported formats and exclusions are defined in
[the domain contract](../standard/DOMAIN_GROUNDING.md). A complete native domain
assessment is not complete object-profile certification.

## Recovered scope and lifecycle

This candidate includes the grounded certification engine and commands, the
pending `vstd publish` command, optional grammar
constraint testing, and experimental `verifier.corrigibility` modules. The source
version is a packaging coordinate, not evidence that new verification mechanisms
or normative profiles are complete. Existing `standard/` specifications remain
authoritative. The draft schemas are record formats, not conformance mechanisms.

The following table describes the retained experimental helpers, whose historical
receipts are not upgraded by the new grounded domain paths above.

| Experimental component | Implemented boundary | Not established |
|---|---|---|
| Graph | Directed acyclic graph structure, declared status and dependency checks | Truth of supplied premises or independent proof checking |
| Environment | Declared hardware/software records, comparisons and consistency rules | Network isolation, resource enforcement or authenticated observation |
| Benchmark | Problem records, declared receipt aggregation and timeout rules | Problem-bound oracle execution; a validity flag yields `UNKNOWN` |
| Dataset | Digest/Merkle records and lexical overlap checks on supplied strings | Source authenticity, complete contamination detection or embedding analysis |
| Training/model | Declared checkpoint lineage, curriculum fields and score comparisons | Reproduced training, calibrated risk scores, alignment or corrigibility |
| Tesla cage | Declared hardware prerequisites and command preflight | Physical containment, hardware authenticity, shutdown execution or tool unboxing |
| Simulation 1 | Replay comparison of supplied canonical state records | General determinism beyond this execution and input |
| Simulation 2 | Predicates evaluated on supplied finite states | Inductive invariance over unobserved states |
| Simulation 3 | Projected trace distance under a caller-provided metric | Universal bisimulation or a proof about transition operators |
| Simulation 4 | Supplied observations and numeric actions checked against declared bounds | Runtime isolation, complete channel capture or prevention of leakage |
| Simulation 5 | Supplied shard consistency diagnostics | Witness authentication, independent nodes or distributed consensus |

The simulation checks are cumulative in the evaluator. Missing prerequisite
mechanisms yield `NOT_ESTABLISHED`; observed violations retain
`VIOLATION_DETECTED`. `VERIFIED` is limited to the local supplied-trace checks,
not existing numbered-profile conformance. Callable identities and their execution
environments are not bound in these draft receipts, so a receipt alone is not
portable proof that a particular program was checked. Distances and epsilon
bounds have the units selected by the caller's metric; no physical units are inferred.

Hardware record digests establish record identity only. `TeslaCageSandbox` does
not sandbox a process. `execute_preemption` raises `NotImplementedError` until an
actual backend and observation are implemented. Boolean declarations never admit
tool unboxing. Risk aggregation never emits `CONTAINED`; its default is
`UNVERIFIED`. Its other verdicts describe declared-input consistency findings,
not observed physical breaches. Risk thresholds are draft policy constants with
no demonstrated empirical calibration. Refutation records carry caller-reported
outcomes; no response predicate is executed by the current model helper.

## Compatibility and migration

- The distribution remains `verifier-standard`, imported as `verifier`.
  Commands `vstd`, `verifier`, and `verifiable` retain their existing entry point.
- No existing numbered-profile wire identifier is renamed by this candidate.
  Experimental identifiers under `verifier.corrigibility` are not aliases for
  normative VSTD object or Graph profiles.
- `Vstd160RiskProfileReceipt` and `evaluate_vstd160_risk_profile` are aliases for
  historical local draft callers only. Acceptance of draft version strings does
  not establish compatibility with any published 1.5.0 or 1.6.0 risk format.
- Callers must handle `UNKNOWN`, `UNVERIFIED`, `NOT_ESTABLISHED` and unsupported
  operation exceptions. Code relying on self-reported success must migrate to
  independently checked evidence before making stronger claims.
- Physical containment still requires a separate mechanism and validation gate.
  Portable finite simulation computation is available through the grounded domain
  path; the earlier experimental receipts do not acquire that binding retroactively.

## Publication gates

Finalize scope and review the exact candidate diff, commit through the signed
contribution workflow, run the full hosted matrix on that commit, and satisfy the
current human-acceptance policy. Then follow [the release procedure](../RELEASING.md)
for deterministic artifact comparisons, installed-wheel checks, boundary scanning,
actual-date finalization, and separately authorized publication. No tag, merge,
upload, or deployment is implied by local preparation.
