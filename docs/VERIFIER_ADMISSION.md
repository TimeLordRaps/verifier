# Bounded VERIFIER admission

Verifier Standard (VSTD); application programming interface (API); conjunctive
normal form (CNF); Secure Hash Algorithm 256-bit (SHA-256); JavaScript Object
Notation (JSON); operating system (OS). Ed25519 is the Edwards-curve digital
signature algorithm with a 255-bit field. Counts and digests have no physical unit.

The VERIFIER adapter can establish five bounded checks for a retained native
Boolean decision proof. It never executes caller-supplied programs. A positive
assessment keeps `object_profile_conformance: NOT_ESTABLISHED`: it establishes
neither a general prover's soundness nor the complete numbered VERIFIER profiles.

| Coordinate | Admitted mechanism | Boundary |
|---|---|---|
| VERIFIER-1.1 | Rehash retained toolchain inventory | Integrity is not authenticity or execution. |
| VERIFIER-1.2 | Native proof checked against its exact externally selected claim binding | One finite decision, not a class-wide soundness theorem. |
| VERIFIER-1.3 | Repeat local checking and compare its retained output | No universal determinism or producer entropy guarantee. |
| VERIFIER-1.4 | `windows-job-native-kernel-1` | Only fixed checker-owned native replay on Windows CPython. |
| VERIFIER-1.5 | `verifier-native-bootstrap-1` plus distinct exhaustive truth-table evaluation | Exact finite admission, not organizational independence or general self-verification. |

## Execution enforcement

Select `inputs.resource_execution = {"mechanism": "windows-job-native-kernel-1"}`.
The checker starts its fixed isolated Python replay suspended, assigns a Job
Object, queries the applied limits, then resumes the primary thread. Job closure
terminates its owned descendants. No executable or argument vector comes from
the evidence. Unsupported platforms report `UNKNOWN`.

`artifact.ceilings.max_memory_bytes` is a job-wide committed-allocation limit in
bytes, not a resident-memory, peak-counter or whole-host limit. Actual denied
allocation is tested. Windows peak accounting can exceed the configured cap even
when allocation is denied; no peak-usage claim follows. `max_wall_seconds` is in
seconds, capped at 60. Completion must be observed within the stated interval;
watchdog scheduling and bounded cleanup are not hard real-time guarantees.
Cleanup has multiple phases for observing termination, each with a five-second
timeout, including fallback after Job Object closure; it does not share one
aggregate five-second budget. `max_loop_iterations` preserves
its wire name but counts charged canonical input bytes, structure nodes and
conservative native proof work, not every interpreter or OS loop. Import work is
covered by process memory and wall-time limits. Local source, interpreter and OS
integrity remain assumptions.

Implementation contracts: [Windows Job Object extended limits](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information)
and [primary-thread resume](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-resumethread).

## Finite bootstrap admission

The bootstrap envelope binds `verifier_id`, `toolchain_digest`,
`soundness_claims_digest`, `oracle_digest`, `key_id`, `status` and its schema.
Its Ed25519 signature covers canonical JSON without `signature`. The public key
must be selected in the external checking policy's `witness_keys`; a key inside
uploaded evidence grants no authority. The oracle digest pins the independent
truth-table implementation. Every formula has at most 12 variables, and all
assignment/literal work consumes the checking budget. The oracle reads raw CNF
clauses and does not call the native proof kernel. A false native acceptance is
independently refuted. The bootstrap envelope admits only the `cnf_sat` proof
class; selecting another class in that envelope is refuted. Formulas exceeding
the finite oracle bound, unsupported native proof tiers and missing signature
capability remain `UNKNOWN`.

Independent algorithmic computation and externally selected key admission are
separate propositions. A local demonstration key proves neither an independent
institution's endorsement nor external truth. The optional `seal` dependency
provides signature verification; no private key belongs in a retained artifact.

## Reproduce through the public interface

In an environment with the package and its `seal` extra available:

```console
python examples/verifier_admission.py --output-dir work/verifier-admission-example
vstd certification domain-check work/verifier-admission-example/certificate.json --request work/verifier-admission-example/request.json --policy work/verifier-admission-example/policy.json --json
```

Use a new output directory each run. The example generates an ephemeral key,
retains only its public key, explicitly admits it in the local policy, builds a
certificate and rechecks it. Windows CPython can establish all five checks; other
platforms retain `UNKNOWN` for resource enforcement. Source or policy changes
invalidate old coordinates; regenerate the example, never replace the recorded
digests to make old evidence appear current. The older `domain_grounding.py`
specimen deliberately lacks both opt-in admissions and remains `UNKNOWN`.

## Composed domain checks

AGENT and BOT replay their bound child certificates under the currently selected
parent policy, with shared operation and nesting bounds. Child request coordinates
are reconstructed from exact retained evidence. A rehashed claimed result is not
accepted as a checked child. The child certificate's historical policy label does
not grant admission: `historical_child_policy_reproduction: NOT_ESTABLISHED`
distinguishes current-policy replay from historical reproduction.
