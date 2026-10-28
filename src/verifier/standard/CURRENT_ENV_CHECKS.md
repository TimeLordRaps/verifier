# Current retained environment checks

Verifiable execution environment (ENV); Verifier Standard (VSTD); JavaScript Object
Notation (JSON). These four experimental native propositions use the explicit
semantic version `verifier-current-object-obligations-1`. Wall-time observations
and ceilings use seconds, memory uses bytes, and thread counts are dimensionless.

The independently selected request binds the exact ENV record, finite collection,
retained evidence, native check, proposition, installed mechanism, policy and limits.
The subject payload is the native environment artifact. All namespace records
must reconstruct exactly and pass typed finite composition. Retained input bytes
are traversed under the selected budget before native evaluation.

| Current coordinate | Native check | Exact proposition |
|---|---|---|
| ENV-1.2 | closure | Materialize and rehash every file in the selected nonempty inventory, with exact retained-file coverage. |
| ENV-1.5 | configuration | Inventory integrity plus equality of every name and value in the entire selected nonempty configuration and retained observation. |
| ENV-3.3 | resources | Inventory integrity plus complete observations for at least two distinct selected execution identities, each within every selected resource ceiling. |
| ENV-2.3 | reproduction | Inventory integrity plus at least two distinct retained executions with exact selected identity coverage and matching software, configuration, executable, input, output and zero exit status. |

The check name `closure` concerns the selected software-file inventory only. It
does not establish complete environment closure, omitted files, interpreter or
toolchain completeness, or the neighboring ENV-1.3 executable-coordinate obligation.
Configuration equality does not independently observe a running process or validate
an external configuration domain. Execution comparison rehashes the retained input
and output and checks the selected executable belongs to the inventory; it does
not execute that program, authenticate execution, localize a causal divergence,
or establish reproducibility outside these retained records.

These registrations explicitly map the four native operations referenced under
the same legacy coordinate spellings in `DOMAIN_OBLIGATIONS.md`. New current
requests and certificates are required. No historical verdict, neighboring numbered
objective, prerequisite or complete tier is transferred by spelling.

Resource ceilings have exactly `wall_seconds`, `memory_bytes` and `threads` fields.
Every retained observation must cover all three. Memory and thread bounds are
positive plain integers through 2**53-1; their measurements are nonnegative plain
integers in that range. Wall-time values are finite plain integers or floating-point
numbers with absolute magnitude at most 1e100; ceilings are positive and measurements
are nonnegative. Comparison preserves the parsed numeric values, including mixed
integer/float comparisons, without first converting integer seconds to floats.
Equality at a ceiling passes; any excess fails. These retained measurements do
not establish enforcement, wall-clock authenticity, resource independence or isolation.

Evidence contains `schema_version`, `objects` and `inputs`. The input mapping admits
only `files`, `configuration`, `measurements` and `executions`; each check requires
its own native inputs. Missing required support remains UNKNOWN. Other retained
fields are not silently treated as admissible evidence.

`env_checks_request`, `env_checks_policy`, `build_env_checks_certificate` and
`recheck_env_checks_certificate` in `verifier.domains.contracts.env_checks` implement
selection, construction and exact replay. Request, policy, evidence and certificate
use distinct `verifier-current-env-checks-*-1` identifiers. Public replay uses
`vstd current-object check` with the exact objective, semantic version, represented
kind ENV, independently selected request and policy. Permanent aliases share it.

Bounds admit at most 256 objects, 100,000 native operations, 100,000 separately
charged composition operations, 4,096 items per container, four mebibytes each
of evidence, composition payload and reference bytes, and eight mebibytes of
certificate bytes. Native work charges retained structure and materialized file
bytes. Namespace records retain their one-mebibyte per-object payload bound.

Unsupported check selectors are refused before native artifact or evidence access.
Missing support, unsupported scope and exhausted selected bounds yield UNKNOWN;
contradictory retained evidence yields FAIL. Malformed external selection, changed
mechanism dependencies and forged or substituted certificates are rejected. Replay
rebuilds the entire canonical certificate, including its result and evidence.
Partial redaction cannot retain canonical certificate status.

Trust-root labels do not authenticate observers. Live collection, independent
execution, physical attestation, host isolation, complete objective coverage,
public checkability, authority and polished issuance remain unestablished.
Independent selected positive and negative cases are in `tests/test_current_env_checks.py`.
