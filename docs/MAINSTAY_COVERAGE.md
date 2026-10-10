# Mainstay coverage and admission

Verifier Standard (VSTD); dataset integrity and lineage (DATA); verifiable
execution environment (ENV); benchmark specification graph (BENCH); training run
specification (TRAIN); object composition specification (HYPER); model
reproducibility specification (MODEL); generative simulation specification (SIM);
instrumented observation surface (HARNESS); observation-bounded agent trajectory
(AGENT); situated agent/simulation composition (BOT); zero-identity zero-knowledge
token (TOKEN). ACTOR denotes an accountable party; OWNER denotes a consequence
holding between an actor and an object. VERIFIER denotes the checker artifact.
application programming interface (API); command-line interface (CLI); JavaScript
Object Notation (JSON); Hypertext Transfer Protocol (HTTP); HTTP Archive (HAR);
Secure Hash Algorithm 256-bit (SHA-256); uniform resource locator (URL). Digests and operation counts have no
physical unit; carrier sizes are bytes; model tolerance uses its output units.

## What the catalogue counts

The domain catalogue has 641 obligations: 241 name candidate routes and 400 do
not. The named routes comprise 128 behavioural, 41 statics and 72 adaptation
bindings. These counts are not counts of verified claims. The legacy `mechanized`
field means a name resolves; positive establishment still requires sufficient
evidence, a supported representation, externally selected policy and the exact
proposition's checks. The 50-format registry describes vocabulary and residuals;
it does not provide 50 executable importers.

The base object catalogue separately has 47 obligations and six built-in routes;
the remaining obligations require exact qualified mechanisms. Neither a domain
assessment nor a mainstay assessment promotes itself to complete object-profile
conformance. The Graph and domain coordinate namespaces remain separate.

| Domain | Public domain checks | Named routes / obligations | Executable external carrier admission |
|---|---:|---:|---|
| DATA | 5 | 25 / 36 | UNKNOWN; native retained data remains supported |
| ENV | 4 | 14 / 34 | UNKNOWN; retained process observations remain supported |
| BENCH | 4 | 14 / 37 | UNKNOWN; native finite suite remains supported |
| TRAIN | 5 | 25 / 35 | UNKNOWN; native dense training replay remains supported |
| HYPER | 0 | 10 / 33 | UNKNOWN; composition operator, no behavioural domain certificate |
| MODEL | 5 | 16 / 33 | Bounded safetensors fragment below |
| SIM | 5 | 16 / 35 | UNKNOWN; native finite transition replay remains supported |
| HARNESS | 5 | 19 / 31 | Bounded HAR fragment below |
| AGENT | 5 | 18 / 30 | UNKNOWN; native trajectory replay remains supported |
| BOT | 5 | 20 / 30 | UNKNOWN; native situated composition remains supported |
| TOKEN | 5 | 59 / 76 | UNKNOWN; native admitted-key token checks remain supported |
| VERIFIER | 5 | 5 / 15 | No external prover importer; [bounded native admission](VERIFIER_ADMISSION.md) |
| ACTOR | 4 accountable | 0 / 38 | No carrier admission or numbered-profile establishment |
| OWNER | 4 accountable | 0 / 36 | No carrier admission or numbered-profile establishment |
| HUMAN, ROLE, COLLECTIVE, IDENTITY | 0 | 0 / 142 combined | No domain or carrier admission |

The eleven computational adapters have 53 checks; eight accountable checks are
separate. Default discovery lists the computational family. Use
`vstd certification domain-catalog --accountable --json` to include ACTOR/OWNER.
All native coverage retains the [domain grounding](../src/verifier/standard/DOMAIN_GROUNDING.md)
limits, including observation authenticity and unsupported numerical backends.

## Admitted carrier fragments

| Carrier and pinned format | Positive checks | Refutable gates | Explicit exclusions |
|---|---|---|---|
| HAR 1.2, HARNESS | Retained-byte binding; total request/response entry mapping; export/reimport and exact retained transcript comparison; catalogue residual | Wrong digest/version, duplicate fields, malformed references/URLs/base64, contradictory timing, incomplete/aliased mappings, changed transcript | Full HAR conformance, traffic authenticity, recorder identity, capture completeness, HARNESS protocol/gap obligations and complete tier 5 |
| safetensors, v0.5.3 format-description snapshot, MODEL | Retained-byte binding; total tensor dtype/shape/value mapping; export/reimport preserving tensor values and metadata; bounded dense-network inference; catalogue residual | Overlapping/holey/out-of-range offsets, wrong byte widths/shapes, duplicate names, unsupported dtype, nonfinite values, changed samples, omitted/aliased tensors, output disagreement and exhausted budgets | Other tensor types, quantization, arbitrary operators, accelerator equivalence, complete model-layout/operator obligations and complete tier 5 |

`F32` means 32-bit floating-point values; `F64` means 64-bit floating-point values.
The inference oracle uses Python binary64 arithmetic and an externally bounded
absolute tolerance no greater than `1e-8`. A round trip recomputes supported
outputs; equal caller-provided digest strings or a declared empty loss list do
not establish one. Carrier input is at most 4 MiB (4,194,304 bytes); shared work,
item and evidence-byte budgets may make the admitted size smaller. Unsupported
representations and exhausted budgets remain `UNKNOWN`; bounded contradictions
are `FAIL`.

Primary format contracts: [HAR 1.2](https://www.softwareishard.com/blog/har-12-spec/)
and [safetensors v0.5.3 format](https://github.com/huggingface/safetensors/blob/v0.5.3/README.md#format).
The safetensors version label pins this description, not a claim that the container
contains a self-authenticating software version.

## Public assessment and reproduction

`verifier.domains.mainstay_certification` exposes `mainstay_request`,
`mainstay_policy`, `build_mainstay_certificate` and
`recheck_mainstay_certificate`. Separate `verifier-mainstay-*-1` envelopes preserve
the frozen native domain contract. The consumer selects request and policy
externally; rechecking rebuilds the entire assessment rather than trusting a
retained PASS or its hash. Source/runtime/policy changes invalidate applicability.

The self-contained synthetic example writes exclusive files and checks both carriers:
`python examples/mainstay_admission.py work/mainstay-demo`. The `har` and `model`
file prefixes each contain evidence, request, policy and certificate JSON.

```console
vstd certification mainstay-catalog --json
vstd certification mainstay-assess evidence.json --request request.json --policy policy.json --output certificate.json --json
vstd certification mainstay-check certificate.json --request request.json --policy policy.json --json
```

Evidence contains `schema_version`, `object_name`, `subject_id`, `artifact` and
`inputs`. Each artifact binds `mainstay.format_id`, `version` and `carrier_digest`.
Each input carries actual bytes through `carrier: {sha256, base64}`. Requests name
the selected checks and bind exact evidence/artifact digests. Mainstay results
explicitly retain `domain_tier_5_conformance`, `object_profile_conformance`,
`native_format_conformance` and `authentication` as `NOT_ESTABLISHED`.

Acceptance evidence lives in `tests/test_mainstay_carriers.py`,
`tests/test_mainstay_certification.py` and
`tests/test_domain_statics_and_mainstays.py`; those contain independent changed-byte,
malformed-container, stronger-policy and finite-inference counterexamples.

## Boundaries and deferred alternatives

Parsing an environment inventory cannot establish isolated standup or rebuild;
that needs execution and dependency closure, described in the
[ENV crosswalk](ENVIRONMENT_CONTRACT.md). Parsing a composition declaration cannot
establish signature authority or composition semantics. Those alternatives were
not promoted as carrier certifications. Other registry formats need their own
pinned grammar, real import/export mechanism, semantic proposition and negative
acceptance gates before admission. A future request for one of those formats is
the revisit gate; registry membership never supplies a default PASS.

Statics helpers can recompute retained values and perturb declared choices.
Different `observed_by` strings do not authenticate independent observation;
external witness admission must be bound separately. No mainstay parser repairs
that provenance gap.
