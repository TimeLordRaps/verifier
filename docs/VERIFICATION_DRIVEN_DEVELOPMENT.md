# Verification-Driven Development (VDD)

Verifier Standard (VSTD) supports a project-agnostic workflow: define the intended
verification contracts, objectives, obligations, dependencies, evidence and
interoperability before implementation; implement against those contracts; then
verify the execution and resulting artifacts. Verification-Driven Development
(VDD) extends test-driven development with explicit claim boundaries, prerequisite
closure, mechanism selection, resource limits and independent acceptance criteria.
Tests exercise implementations; they are one source of evidence within that contract.

This guide describes the unreleased 2.0.0 source surface. The application programming
interface (API), directed acyclic graph (DAG), JavaScript Object Notation (JSON) and
Secure Hash Algorithm 256-bit (SHA-256) are used below. The workflow does not supply
a complete approved application profile or polished-artifact issuance.

## Define the contract before implementing

Choose an exact subject revision and describe each proposition separately. Record
what could refute it, which mechanism can check it, the evidence that mechanism
needs, its resource bounds and the trust roots it assumes. Define prerequisite
edges between claims, including claims about operands in other objects. A tier
number or matching label does not create an edge or discharge a prerequisite.

| Contract part | Specify before implementation |
|---|---|
| Objective and scope | Exact predicate, subject, exclusions and refutation condition. |
| Revision and selection | Independently selected artifact, instructions, context, request, policy and mechanism commitments, as supported by the chosen contract. |
| Dependencies | Exact prerequisite claim identities and their selected operand/profile bindings. |
| Evidence | Complete retained bytes, observation boundaries, expected outputs and missing-support behavior. |
| Interoperability | Versioned native input/output contracts and the evidence mapping; preserve native result meanings. |
| Acceptance | The consumer's applicable obligations, authority requirements and separate acceptance procedure. |

Retain the selected bytes with their digests. Revisions are part of claim identity:
a changed predicate, input, policy, context or checker requires a new selection and
reassessment. A digest identifies bytes; it does not establish completeness,
authenticity or authority. The [exact dependency contract](../src/verifier/standard/CERTIFICATE_DAG.md)
defines the implemented claim/profile bindings and limits. No complete approved
production profile is supplied, and required certificates must be derived from
the selected obligations rather than inferred from a count of tier slots.

Use these contracts proactively when changing a component: compare the selected
before/after artifact and mechanism bindings, identify dependent claims, rerun the
applicable regression and dependency checks, and retain changed or unavailable
results before acceptance. A project's test suite can implement a checking
mechanism for an object-producing library under a declared VERIFIER contract.
Test count and a green aggregate do not establish every library property or rule
out future regressions; evidence about one revision does not clear changed bytes.

As a conditional modelling example, a consumer could represent a configured
PyTorch architecture as ARCH, and training over DATA with EVENT and BENCH operands
as TRAIN; MODEL also binds its selected architecture, training, data, events,
benchmark, environment (ENV) and hardware records. A PennyLane-based component
could be represented as simulation (SIM) only under an applicable generative
simulation contract. These are conceptual classifications, not verified library
integrations. The [namespace contract](../src/verifier/standard/NAMESPACE_OBJECTS.md)
defines actual required operands; a declared GRAPH can retain their composition
without proving that the library, lifecycle or future outputs are correct.

## Preflight the declared plan

Before execution, inspect whether the declared verification DAG has the required
claims, exact dependency closure, selected authority requirements and planned
evidence mappings. Such preflight checks concern the declared plan. They cannot
verify a future execution, establish future evidence availability or prove that
the plan includes every relevant property of a real system.

Two existing interfaces support narrower nonexecuting checks:

- `verifier.core.run.describe_run_plan` describes a generic manifest's command
  and declared capture paths. It is a review aid, not dependency closure checking
  or a sandbox. The existing command `vstd plan examples/generic_run/manifest.json --json`
  exposes that inspection without running the command.
- Experimental `verifier.interoperability.execution_readiness.assess_execution_readiness`
  checks declarations against an exact surface analysis, validation plan, registry
  and any required retained component package. It checks declared native inputs,
  future evidence mappings, prerequisites, supplied authorization and reassessment
  expectations. It neither reads native inputs nor invokes components or grants
  authority. See the [planning example](../examples/interoperability_planning/README.md).

The readiness report uses its own vocabulary: `READY` means declaration consistency;
`BLOCKED` records an explicit unresolved prerequisite, denied decision or unavailable
declared component; `NOT_ESTABLISHED` records missing support; `INVALID` records an
inconsistent declared binding. These are not native `PASS`, `FAIL` or `UNKNOWN`.

`assess_certificate_dependencies` in `verifier.domains.contracts.certificate_dag`
checks an independently selected finite claim closure **and replays installed
native checkers** over retained artifacts. It is an execution assessment, not a
standalone nonexecuting DAG preflight API. This guide introduces no new command
or automatic plan executor.

## Worked example: one exact output contract

Before implementing a formatter, a consumer selects the input bytes `b"5\n2\n3\n"`
and requires the exact output bytes `b"2\n3\n5\n"` for this specimen. It also selects
the requirement revision, instruction/context digests and the qualified digest of
the installed checking mechanism. The objective is output-byte equality for this
specimen. General sorting correctness and proof that the program used the selected
input require separate propositions and evidence.

After execution, this function checks the retained output using the current APIs.
Its keyword arguments come from the consumer's earlier selection, not from a
producer's result. The byte-digest mechanism is a direct submodule example; the
other imported names are supported top-level exports.

```python
from hashlib import sha256

from verifier import BoundProposition, EvidenceBounds, EvidenceStore, VerificationSession
from verifier.core.evidence import BytesDigestMechanism


def assess_output(output_bytes: bytes, *, selected_mechanism_digest: str,
                  requirements_revision: str, instruction_digest: str,
                  context_digest: str) -> dict:
    expected_output_digest = "sha256:" + sha256(b"2\n3\n5\n").hexdigest()
    store = EvidenceStore()
    reference = store.add(output_bytes)
    mechanism = BytesDigestMechanism()
    binding = BoundProposition(
        subject_id="formatter-specimen:" + requirements_revision,
        predicate="bytes.sha256",
        expected=expected_output_digest,
        mechanism_id=mechanism.mechanism_id,
        mechanism_digest=selected_mechanism_digest,
        evidence_refs=(reference,),
        trust_roots=("consumer-selected-specimen-contract",),
        bounds=EvidenceBounds(max_evidence_items=1, max_evidence_bytes=32),
        parameters={
            "requirements_revision": requirements_revision,
            "instruction_digest": instruction_digest,
            "context_digest": context_digest,
            "input_digest": "sha256:" + sha256(b"5\n2\n3\n").hexdigest(),
        },
    )
    session = VerificationSession(store)
    session.register(mechanism)
    result = session.evaluate(binding)
    return {"binding": binding.to_dict(), "evaluation": result.to_dict()}
```

`BoundProposition.parameters` commits the selected metadata in the binding digest.
The mechanism checks only `bytes.sha256`: it does not authenticate those metadata
values, inspect instruction/context contents or prove that execution followed them.
The named trust root is also a declared assumption. Consumers compare the retained
binding with their independently selected contract before relying on a result.

With the selected installed mechanism, matching output establishes this bounded
`PASS`; different retained output yields `FAIL`. Missing evidence, a missing or
changed mechanism, or exhausted evidence bounds yields `UNKNOWN`. Cancellation
raised inside a session mechanism also yields `UNKNOWN`; external process
termination may leave no result. None of these cases supplies a passing execution
record. The [evidence engine](../src/verifier/core/evidence.py) defines these outcomes.

For preventative regression checking, identify the output consumers before
changing the formatter's newline policy or parser. Retain the original input,
expected output and contract revision; define the proposed revision and its
dependent parsing/evidence contracts before editing. Check the changed output and
each affected dependency under its selected revision. An old specimen PASS cannot
clear a changed binding, and an unavailable dependent check remains UNKNOWN.
This workflow does not claim automatic impact discovery or universal coverage.

## Verify execution, then assess acceptance

Retain actual execution evidence and verify each applicable native proposition.
For the selected certificate DAG, direct replay and dependency-qualified results
remain separate. A qualified `PASS` requires reproduced native `PASS`, an
independently approved selected profile and every exact prerequisite passing.
Refuted claims or prerequisites yield `FAIL`; missing support leaves `UNKNOWN`.
Observed failures remain failures when later checks cannot run.

Accept the artifact only through the consumer's separate requirements and authority
procedure. A valid plan, matching output, reproducible certificate or passing test
suite cannot supply missing human acceptance, publication authority or full
application closure. The current [polished-artifact assessment](../src/verifier/standard/POLISHED_ARTIFACTS.md)
keeps `polished` false and does not issue polished artifacts.

Consumers build scheduling, memory, goal/context management and user interfaces
around these general contracts. Verifier supplies bounded checking and evidence
bindings; consumer orchestration must retain its own revisions and actual execution
observations. Unsupported semantic properties remain explicit `UNKNOWN` obligations.
The current [AGENT checks](../src/verifier/standard/CURRENT_AGENT_CHECKS.md) select
finite retained trajectories, [HARNESS checks](../src/verifier/standard/CURRENT_HARNESS_CHECKS.md)
select observation, tool, effect and transcript records, and
[SIM dynamics](../src/verifier/standard/CURRENT_SIM_DYNAMICS.md) select retained
transition replay. These bounded checking scopes do not certify a consumer's
persistent goals or open-ended operation; those require their own applicable
contracts and evidence.
