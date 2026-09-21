# Grounded certification in Verifier Standard (VSTD)

> **Acronyms:** central processing unit (CPU); command-line interface (CLI); grounded decision certificate (GDC);
> JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).

**Verifier / `verifier-standard` v2.0.0 — The grounded certification release.**
The candidate implements one evidence-bound certification contract across the five
object numbered profiles. It is unreleased.
It also supplies six executable domain adapters with 28 separate domain checks.

## What X.M means

`X` selects the numbered profile; `M` selects one separately checked obligation.
Neither number is a confidence score. The sequences are `1.1–1.7`, `2.1–2.7`,
`3.1–3.8`, `4.1–4.14`, and `5.1–5.11`. The existing VSTD-4 obligations retain the
name **rungs**. The [normative catalogue](../standard/GROUNDED_CERTIFICATION.md)
defines all 47 propositions, their dependencies, source requirements and failure
semantics. `VSTD-3.0` remains a frozen receipt serialization identifier.

An obligation needs its own exact claim/evidence/mechanism binding. A later success
does not repair an earlier gap. Reports preserve the direct result, blocked
dependencies, each profile's established prefix, and the largest complete cumulative
profile. `UNKNOWN` survives missing evidence; a checked refutation stays `FAIL`.

## Run a real partial certificate

From a reviewed source checkout, generate the runnable specimen:

```bash
PYTHONPATH=src python examples/grounded_certification.py grounded-example
PYTHONPATH=src python -m verifier certification catalog --json
PYTHONPATH=src python -m verifier certification check grounded-example/certificate.json \
  --request grounded-example/request.json --policy grounded-example/policy.json --json
```

The example checks an actual retained claim record against its exact external
coordinate, scope, limitations and falsifier. Obligation `1.1` passes. The remaining
VSTD-1 evidence is absent, so the profile is `UNKNOWN`, certified profile depth is
zero, and the check command exits **2**. This is the required outcome, not an example
failure. Command exit 0 means complete requested certification, 1 means refutation
or rejected input, and 2 means a valid but incomplete or unevaluable assessment.

To rerun the assessment and save a new certificate:

```bash
vstd certification assess grounded-example/request.json \
  --evidence grounded-example/evidence.json --policy grounded-example/policy.json \
  --output grounded-example/rechecked-certificate.json --json
```

The output file must be new. The policy and expected request are checker-selected
inputs. In a real deployment, review and provision them independently of the
certificate producer; taking both from an untrusted bundle would surrender that
boundary. The example owns all three files only to demonstrate local replay.

## Mechanism coverage and integration

The native mechanism executes bounded checks for six obligations:

| Obligation | Executed check | Boundary |
|---|---|---|
| 1.1 | Exact retained claim record versus bound claim coordinate | Does not establish the statement's computational truth |
| 2.1 | Exact geometry subject and committed surface | Applies to the supplied finite representation |
| 2.2 | Geometry reference and containment validation | Does not establish observations or judgments |
| 4.1 | Existing GDC kernel checks the supplied decision certificate | Kernel acceptance alone is not VSTD-4 conformance |
| 4.3 | Kernel checks the externally bound decision commitment | Does not authenticate an external actor |
| 4.5 | Kernel enforces positive declared cost, memory and certificate-size ceilings | Unsupported checking remains `UNKNOWN` |

The other 41 object obligations have executable orchestration contracts and require
mechanisms that actually evaluate those exact propositions. The six domain adapters
below supply native domain computations; their results do not automatically discharge
all object obligations. The CLI does not
import plugins named by an input file. Integrators use the Python interface to
register their own qualified mechanisms explicitly in a `VerificationSession`.
Each returns a `MechanismDecision`; its permitted obligation, implementation digest
and exact trust roots must appear in the externally selected `CertificationPolicy`.
Registration does not qualify the mechanism or supply evidence of its correctness.

`CertificationRequest` contains individual `BoundProposition` records, never results.
`assess_grounded_certification` reruns and derives results.
`build_grounded_certificate` executes against a retained evidence snapshot and
embeds the request, evidence and complete result. `recheck_grounded_certificate`
requires an external `expected_request_digest` and policy, checks the orchestrator
and specification coordinates, rehashes evidence and reexecutes all mechanisms.
The consumer must compare these coordinates with its independently selected source.

The bound `policy_root` is the policy's canonical digest. `evidence_root` commits
to the sorted unique evidence-address set. Each proposition's parameters contain
`claim_binding_digest`. Native mechanisms additionally take the canonical claim
binding in `claim_binding`; the embedded binding must reproduce that exact digest.
Geometry checks require a `geometry_digest` in the bound coordinate parameters.
Decision checks require `decision_binding_digest` there. This keeps a valid proof
for a neighboring claim from satisfying the selected obligation.

## Six executable domain adapters

Dataset integrity and lineage (DATA), execution environments (ENV), benchmark
specification graphs (BENCH), hyperparameters and training lineage (HYPER), model
reproducibility specifications (MODEL), and generative simulations (SIM) have their
own grounded paths. These execute retained computations rather than promoting the
older declaration-based records. The [normative domain contract](../standard/DOMAIN_GROUNDING.md)
lists supported mainstays, numerical semantics, trust boundaries and exclusions.

| Domain | Native domain checks | Complete native domain depth |
| --- | --- | --- |
| DATA | Artifact integrity, schema, transformation replay, split separation, lexical overlap | 5 |
| ENV | Software inventory, configuration observations, measured-resource bounds, two bound execution observations | 4 |
| BENCH | Problem binding, executable oracles, full-suite scoring, measured-resource bounds | 4 |
| HYPER | Optimizer contract, checkpoints, contiguous lineage, numerical updates, recomputed loss/gradients | 5 |
| MODEL | Artifact dependencies, tensor shapes, inference, full-set metrics, finite challenges | 5 |
| SIM | Transition replay, invariants, macro projection, observation/action channels, shard relations/signatures | 5 |

These are cumulative domain check coordinates such as `MODEL.3`, separate from
object `3.1` or the existing experimental simulation tier identifiers. They are not
confidence ratings. Every certificate keeps object profile conformance
`NOT_ESTABLISHED`; an object obligation still needs its exact proposition checked.

```bash
PYTHONPATH=src python examples/domain_grounding.py
vstd certification domain-catalog --json
vstd certification domain-assess evidence.json --request request.json --policy policy.json --output certificate.json --json
vstd certification domain-check certificate.json --request request.json --policy policy.json --json
```

Use the public Python functions `domain_request(evidence)` and
`domain_policy(trust_roots=[...])` to construct the independently reviewed request
and policy, then `build_domain_certificate(request, evidence, policy=policy)`.
`recheck_domain_certificate(certificate, expected_request=request, policy=policy)`
reruns every prerequisite and rejects any substituted request or modified result.
`NativeDomainAdapter(domain, policy)` exposes the same executable mechanism to an
explicitly registered evidence session. The four domain envelope schemas validate
structure only; the adapter validates and computes the domain-specific content.

The environment adapter authenticates no external observation by itself. Numerical
adapters support a finite dense-network arithmetic contract, not every model format.
Simulation signatures, when requested, use checker-selected keys and the optional
`seal` extra; signatures do not prove independent observation. None of these limits
is converted into a successful broader claim.

## Limits and compatibility

The new strict schemas cover requests, policies and certificates; schema conformance
establishes shape only. Exact replay under approved mechanisms establishes the
bounded result. Native receipt readers, historical identifiers, VSTD-4 candidate
depth and VSTD-5 witness gates remain unchanged. An old receipt is not automatically
promoted to the new certification contract.

Byte and item ceilings are enforced before domain execution; arbitrary Python
plugins are not sandboxed or interrupted by this engine. Their CPU and wall-time
behavior requires bounded implementations or external isolation. No certificate
here creates an independent witness, hardware attestation or physical containment.
Changing claim, evidence, policy, checking code or normative bytes requires a fresh
assessment. Earlier test results remain bound to their earlier source coordinates.
