# Execution environment contract

Terminology: Verifier Standard (VSTD); execution environment (ENV); generative
simulation specification (SIM); instrumented observation surface (HARNESS); agent
trajectory (AGENT); model reproducibility specification (MODEL); training run
specification (TRAIN); application programming interface (API); JavaScript Object
Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).

This crosswalk explains the current candidate. Normative obligations remain in
[domain obligations](../src/verifier/standard/DOMAIN_OBLIGATIONS.md) and
[domain grounding](../src/verifier/standard/DOMAIN_GROUNDING.md).

## Native ENV

ENV names the context in which a computation is represented as executing. The
admitted native fragment is `scope: retained-process-observations`: retained
software bytes, a configuration contract, resource observations, and execution
records. It is neither the task's transition law nor the observer's instrumented
surface. A successful native assessment establishes the checks below, not the
complete ENV numbered profiles.

| Check | Coordinate | Required artifact / input | Established proposition and limit |
|---|---|---|---|
| `closure` | ENV-1.2 | `artifact.files`; `inputs.files` | Exact selected file set and retained content digests agree; no claim that unselected host dependencies are absent. |
| `configuration` | ENV-1.4 | Nonempty `artifact.configuration`; `inputs.configuration` | Complete retained configuration equals the selected contract; collector authenticity is not established. |
| `resources` | ENV-3.3 | `artifact.ceilings`, `execution_ids`; `inputs.measurements` | Observations cover the same distinct executions and stay within the stated ceilings; these are retained measurements, not operating-system enforcement. |
| `reproduction` | ENV-2.3 | `artifact.execution`, `execution_ids`; `inputs.executions` | Two or more retained successful records bind the same software inventory, configuration, executable, input and output; the checker does not rerun that external program. |

Resource ceilings use `wall_seconds` in seconds, `memory_bytes` in bytes, and
`threads` as a dimensionless count. Execution identifiers are distinct strings.
The selected executable must belong to the retained file inventory. Each record
contains `id`, `software_digest`, `configuration_digest`, `executable`, `input`,
`output`, and `exit_code`. Raw materialized file hashes and canonical JSON object
hashes are different bindings and must not be substituted for one another.

`collect_configuration()` records the current process's system, release, machine,
Python implementation/version and byte order. It is an in-process collector,
not independent hardware evidence. Physical attestation and containment need a
separately admitted mechanism. ENV-4 pin completeness, host isolation, network
closure, standup sufficiency and independent standup evidence remain unmechanized.

## Relationship to the other objects

| Object | Its own subject | Relationship to ENV |
|---|---|---|
| SIM | Bound transition expressions, retained states, entropy, projections and channels | ENV can describe the simulator's execution context; an ENV comparison does not prove the simulation dynamics. |
| HARNESS | Declared instrumented channels, messages, tool invocations, effects and transcript | ENV can describe the recorder/runner context; HARNESS does not automatically authenticate that context or its recorder. |
| AGENT | Trajectory and claims inside a bound HARNESS observation ceiling | The observation ceiling comes from recomputing the HARNESS certificate, not from an environment label. |
| MODEL | Retained architecture/weights, native inference and finite evaluation | ENV may identify the inference process context; it does not establish training provenance or arbitrary accelerator behavior. |
| TRAIN | Exact retained batches, checkpoints and supported optimizer updates | ENV may describe training execution; MODEL and TRAIN retain their own input/output and lineage obligations. |

A research system used as a HARNESS and MODEL factory should retain separate
ENV, HARNESS, TRAIN where applicable, and MODEL evidence bundles and externally
selected requests. Reuse exact software/artifact digests and execution identifiers
in its application record; retain the producer run's inputs and outputs. That
association is checkable metadata, not proof that the recorded workload occurred
inside the asserted context. Native HARNESS and MODEL schemas currently have no
automatic ENV-certificate field. Do not add an invented field, label the association
complete composition certification, or claim that a gate exit proves containment.
The existing BOT checks bind two environment certificates for their stated situated
agent/simulation scope; they do not substitute for a general factory contract.

## Experimental environment records and migration

The experimental direct namespace `verifier.environments` uses a broader declared
computational boundary: subject, instrument and execution-context roles; components,
connections, definition/instance/run records, and retained workload bindings. Its
record discriminators are `VSTD-ENVIRONMENT-DEFINITION-0.1`,
`VSTD-ENVIRONMENT-INSTANCE-0.1`, and `VSTD-ENVIRONMENT-RUN-0.1`. These are exact
experimental wire discriminators quoted for migration, not admitted objects in
the VSTD-NAMESPACE. Preserving their bytes does not admit an ENVIRONMENT object
or rename them to a native certificate schema.
The associated `EnvironmentAssessment` explicitly reports `NOT_ESTABLISHED`
conformance; the definition/instance/run records themselves carry no conformance
field. They are not native
`verifier-domain-evidence-1` ENV bundles or domain certificates.

| Experimental surface | Meaning preserved during migration | Native ENV counterpart |
|---|---|---|
| `EnvironmentDefinition`, component roles/connections/mechanisms | Declared topology, capabilities, contracts and retained implementation references | No lossless automatic conversion; select explicit software/configuration facts separately. |
| `EnvironmentInstance`, `ArtifactBinding` | Exact definition, configuration, initialization and input artifacts | Materialize selected software bytes and configuration without casting declarations into observations. |
| `EnvironmentRunBinding`, `ModelInteractionBinding` | Workload, trace, evaluator and model interaction artifact bindings | Map only supported retained execution observations; retain all unmapped fields and provenance limits. |
| `package_environment`, `unpack_environment` | Experimental package serialization/unpacking; expected-package-digest checking belongs to the separate `load_component_package` boundary | No equivalent domain-certificate alias; packaging is separate from computational checking. |
| `evaluate_environment_run`, `bind_environment_workload` | Selected experimental mechanisms and workload associations | Keep the original selected mechanism and conformance limit; construct an independently requested ENV assessment only from sufficient evidence. |

The native candidate does not promise this experimental direct-import API.
Consumers needing it must pin their exact experimental source and its tests until
a reviewed migration preserves the record methods, bytes, selected-checker and
package-digest semantics. An import alias would not establish that compatibility.
Migration requires positive byte/record tests and negatives for altered packages,
substituted checkers, undeclared dependencies and missing observations. Missing
`verifier.environments` imports do not imply native ENV is missing, and native ENV
success does not repair those imports. Complete SIM/AGENT composition is a separate
design and validation gate.
