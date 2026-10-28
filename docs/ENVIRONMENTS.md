# Computational environment foundations

> Terminology: Verifier Standard (VSTD); application programming interface (API);
> JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
> American Standard Code for Information Interchange (ASCII).

Status: experimental direct Python namespace, `verifier.environments`. The
contracts and disclosed specimens are implemented. This is a local integration
surface, not a package-release announcement, environment hosting service, or
model benchmark. It adds no required third-party dependencies.

The [execution environment contract](ENVIRONMENT_CONTRACT.md) separately defines the
native environment domain and the migration boundary for these records: they are not
native domain-evidence bundles or certificates, and neither route repairs the other.
Consumers that need this namespace must pin this source and its tests until a reviewed
migration exists.

## What an environment means here

An environment is a declared computational boundary. It may simultaneously be
a verification subject, a measurement instrument, and an execution context.
Those roles do not force an episode abstraction onto static computations.

| Part | Meaning | Example question |
|---|---|---|
| Task or process | Intended computation, inputs, constraints, stopping conditions | What counts as a correct answer? |
| Dynamics | State transitions, randomness, external influences | Does the next state obey the declared rule? |
| Wrapper | Observation and action boundary presented to the tested system | Is evaluator-only material exposed in this recorded observation? |
| Runtime context | Dependencies, initialization, resource and permission declarations | Which exact configured context does the workload identify? |
| Evaluator | Mechanism that computes measurements or checks a proposition | Does its report follow from the retained trace? |
| Evidence | Retained inputs, execution records, traces, and outputs | Can the named mechanism check the same bytes again? |

Roles are composable. One implementation can occupy several roles, and multiple
components can share a declared lineage. Such sharing remains visible; it does
not establish independence. Permissions and observation declarations describe a
boundary but do not enforce it or prove that hidden information is non-inferable.

## Relationship to the numbered profiles

These are projections onto existing questions, not new numbered profiles or
an automatic conformance path. The cumulative requirements remain those in the
[verification complex](../src/verifier/standard/LADDER.md).

| Numbered profile | Environment concern | Current foundation boundary |
|---|---|---|
| VSTD-1 Claim Mechanics | Bounded claim and evidence binding | Exact records and explicitly selected mechanism checks; no receipt-format change. |
| VSTD-2 Verification Surface | Selected components, behaviors, and interfaces | `environment_surface` creates unanswered binding and behavior coordinates. |
| VSTD-3 Substrate Accountability | Accountable workload and execution context | `bind_environment_workload` fills the existing `environment_digest` with the configured instance digest; it does not authenticate occurrence. |
| VSTD-4 Refutability | Recheckable evidence and counterexamples | Explicit mechanism replay contributes only the proposition it checks; the fourteen rungs (obligations `4.1` through `4.14`) remain separate. |
| VSTD-5 Witness Corroboration | Evidence-bound corroboration and independence | Shared specimen code, publisher, or runner supplies no independent witness. |

The [workload identity](../src/verifier/standard/VSTD-3.md) already accommodates environment
commitments. The [witness specification](../src/verifier/standard/VSTD-5.md) requires exact
checked prerequisites and independence evidence, not a second process or seed.
The separate Graph axis can use declared supporting relationships among
implementation bytes, instances, traces, and claims. Changed dependencies identify
reassessment work; they do not automatically falsify dependent claims.

## Contract and module walkthrough

The implementation is divided among
[contracts](../src/verifier/environments/contracts.py),
[assessment](../src/verifier/environments/assessment.py), and
[integration](../src/verifier/environments/integration.py).

`EnvironmentDefinition` identifies an environment version, bounded statement,
roles, components, connections, interaction mode, capabilities, assumptions, and
limitations. Each `EnvironmentComponent` reuses an existing interoperability
descriptor, retains implementation and lineage artifact references, and can bind
mechanism identifiers to exact retained implementation bytes. A connection names
one exact contract declared by both endpoints. A translation needs its own
component; similar names do not imply compatibility.

`EnvironmentInstance` binds a definition digest to exact configuration,
initialization, and input artifacts. Runtime requirements, units, random seeds
or generator state, and external-context assumptions belong in those declared
artifacts. The framework retains their bytes; domain mechanisms must check their
semantics. Model-visible and evaluator-only input paths must refer to known,
disjoint inputs; exposing identical hidden bytes under another path is detected.
Other inputs can remain unclassified, without a confidentiality claim.

`EnvironmentRunBinding` binds the configured instance, existing workload identity,
selected evaluator, execution evidence, trace, evaluator output, reward, and
measurements. Reward, measured performance, and verification findings are separate
artifacts. A reward value is not a correctness verdict. Execution evidence can be
absent or self-reported; artifact retention does not strengthen its provenance.

Model-testing runs can include an optional `ModelInteractionBinding`: model
artifact, tokenizer, inference parameters, request, and response. Inspection checks
the model against the workload's existing model commitments and retains every
interaction artifact. Domain checkers assess the input/output translation and
task semantics. Other computational contexts do not need this optional record.
The first experimental run format includes this field, using `null` when absent.

`environment_surface(definition, instance, run)` can include the configured
instance, recorded execution, model artifact, and retained context/evidence in
the existing geometry. Its coordinates remain unanswered until separately checked.

The immutable records use these experimental discriminators:

| Record | Exact discriminator |
|---|---|
| Definition | `VSTD-ENVIRONMENT-DEFINITION-0.1` |
| Instance | `VSTD-ENVIRONMENT-INSTANCE-0.1` |
| Run | `VSTD-ENVIRONMENT-RUN-0.1` |

`load_environment_record` accepts bytes, rejects unknown versions, extra or
missing fields, duplicate fields, malformed types, and out-of-bounds records.
It can require an expected canonical digest. Records are limited to 2 mebibytes
(2,097,152 bytes), arrays to 256 entries, and ordinary contract strings to 4,096
characters. Artifact content is retained separately through existing package
limits. Canonical records use sorted object keys, compact separators, and ASCII
escapes; array order remains part of identity. Reformatting an object preserves
its canonical digest. Reordering components or changing assumptions does not.

A digest supplied by the same untrusted producer is not an external anchor.
Whole-bundle replacement requires an independently selected expected coordinate
to detect. Existing receipt formats and supported top-level exports are unchanged.
These experimental identifiers are not conformance receipts.

## Inspection and explicit evaluation

`assess_environment` checks retained artifact identities, instance/run/workload
bindings, declared component connections and interaction modes, capability
consistency, and declared input separation. It never imports an entry point or
runs an environment. `bindings_established` covers only those checks. Geometry
judgment vocabulary is reused: missing evidence is `INDETERMINATE`, a contradicted
binding is `FALSIFIED`, and a successful binding check is `VERIFIED` on that exact
coordinate. Every report keeps `conformance = NOT_ESTABLISHED`.

`evaluate_environment_run` is a distinct, explicit operation. The caller supplies
a `VerificationSession` and `BoundProposition` requests. Each request must identify
the exact run, use its canonical digest as the expected value, retain the complete
environment evidence set, and select a mechanism and predicate from the bound
evaluator. Its mechanism digest must match the retained evaluator implementation.
The session must also have that exact mechanism registered. Inspection does not
perform this registration.

Results preserve the existing `EvaluatedProposition` binding digest, mechanism
identity and digest, evidence references, trust roots, byte count, observations,
and outcome. These are diagnostic assessments, not new portable conformance
receipts. Persist original `BoundProposition.to_dict()` requests if exact request
replay is required; the environment package does not infer those requests.

`environment.step`, `environment.replay`, and `environment.state_restore` require
the corresponding declared capability. A static environment need not implement
`reset` or `step`. The general runtime does not infer determinism from a seed,
state-restoration support from a method name, or truth from successful serialization.

The session runs caller-registered checking code and does not sandbox or impose
a wall-clock limit on that code. The disclosed checker bounds its fixture sizes.
Select trusted checkers and use a bounded runner for external implementations.
Neither registration nor a passing check establishes checker correctness or
actor independence.

## Run the mixed specimens

From a source checkout, with `PYTHONPATH=src`, or from an installed wheel:

```sh
python -u -m verifier.environments.specimens
```

This constructs, packages, unpacks, and checks three synthetic fixtures:

| Specimen | Producer behavior | Separate checking behavior | Limits |
|---|---|---|---|
| Recall | Tokenizes a symbol stream, calls a scripted reference model through the public wrapper, and records its request/response | Recomputes answers, query positions, token distances, tokenizer/settings binding, and reported accuracy | Default 128 fixture tokens under an explicit one-symbol/one-token vocabulary; not a learned-model capacity result. |
| Boolean reasoning | Supplies an explicit formula and assignment | Checks each signed-literal clause against the proposed assignment | Three variables in the example; no general theorem-proving claim. |
| Counter | Runs a finite state machine, saves state, restores it, and runs the suffix again | Recomputes transitions, bounds, termination, and the retained restored suffix | Integer counts, actions of plus or minus one, sixteen-step budget; no physical-world validity claim. |

The [producer](../src/verifier/environments/specimens.py) and
[checker](../src/verifier/environments/specimen_checks.py) do not share transition
or answer-checking functions. They share project ownership and an installed contract
decoder, so implementation separation does not become witness independence.
The recall reference model is a scripted exact-address algorithm. Its retained
source is the model artifact; no trained model is loaded. The wrapper's recorded
request contains only input token identifiers and query positions. The evaluator's
answer artifact is not passed to that model. A regression test observes the actual
reference-model call, and the checker rejects substituted or expanded requests.
Recall distance is the final stream index minus the queried source index, measured
in this fixture's token units. Query positions are supplied as separate metadata;
their encoding is not added to the token distance. This precise convention is part
of the fixture claim and must not be equated with a learned model's prompt horizon.
The checker assesses recorded behavior; fabricated but internally consistent
traces remain possible without stronger execution evidence.

To inspect or package a specimen directly:

```python
from verifier.core.evidence import VerificationSession
from verifier.environments import (
    assess_environment, evaluate_environment_run, package_environment,
    unpack_environment,
)
from verifier.environments.specimens import build_specimen, specimen_bindings
from verifier.environments.specimen_checks import MixedSuiteMechanism

definition, instance, run, evidence = build_specimen("counter")
inspection = assess_environment(definition, evidence, instance, run)
package = package_environment(
    definition, evidence, publisher="local-example", license="Apache-2.0",
    instance=instance, run=run,
)
definition, instance, run, evidence = unpack_environment(package)
session = VerificationSession(evidence)
session.register(MixedSuiteMechanism())  # Explicitly selects installed checking code.
assessment = evaluate_environment_run(
    definition, instance, run, session,
    specimen_bindings(definition, instance, run),
)
assert assessment.to_dict()["conformance"] == "NOT_ESTABLISHED"
```

Use the existing `save_component_package` and `load_component_package` functions
to transport the package. Loading, unpacking, catalog projection, and geometry
projection do not install, fetch, extract, import, or execute submitted code.
`unpack_environment` checks package-to-definition catalog, implementation, and path
bindings; use `assess_environment` for configured-instance and run compatibility.

## Factory and hosted-hub integration boundary

A future factory should produce definitions and captured implementation bytes,
then explicit configured instances. It must separately test generated wrappers,
restrict evaluator-only observations in the actual runner, select checking
mechanisms, and retain run evidence. Generated source alone is not admission to
execution. No general factory, runner, or model-training integration ships in this
increment. The three specimen builders are fixed demonstrations.

Claim Garden can eventually distribute the same inert component packages and
their declared relationships. This increment adds no hosted endpoint, upload,
automatic execution, moderation decision, or new trust policy. Downloads remain
separate from selecting an execution environment and granting it capabilities.

## Validation and remaining work

The focused [contract tests](../tests/test_environment_contracts.py) cover strict
record and package round trips, substitutions, missing evidence or mechanisms,
context-only definitions, mode/capability mismatch, input aliases, inert hostile
entry points, and existing geometry/catalog/workload integration. The
[specimen tests](../tests/test_environment_specimens.py) cover wrong answers,
observation leakage, invalid transitions and restoration, mismatched evaluator
reports, measurements, reward separation, truncation, and longer recall fixtures.
The [completion regressions](../tests/test_environment_completion.py) exercise
type-preserving restoration checks, parent-directory case aliases, explicit model
interaction bindings, input separation, and the full geometry projection.

```sh
python -u -m pytest tests/test_environment_contracts.py tests/test_environment_specimens.py tests/test_environment_completion.py -vv -s --durations=10 --timeout=30
```

These tests do not establish environment isolation, model capability, complete
dependency discovery, runtime authentication, independent witnesses, scientific
validity, or hosted-service readiness. New tasks need domain-specific mechanisms
and explicit applicability bounds; passing the contract suite cannot substitute
for those checks.
