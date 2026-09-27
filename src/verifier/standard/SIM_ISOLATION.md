# Finite simulation isolation for virtual HARDWARE

> **Acronyms:** JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256); generative simulation specification (SIM); Verifier Standard (VSTD).

**Status:** bounded candidate mechanism. It does not register a SIM numbered-profile
obligation or establish object-profile conformance. The domain certificate and
historical receipt wire identifiers remain unchanged.

## Proposition and scope

Given an independently selected binding to one complete **declared** finite
transition model, every transition outcome reachable from the bound initial state
stays inside the model's simulation partition, acquires no new capability, and
has no outside mutation, external actuation, or external export effect. Each
reachable state must have one transition row for every action in the bound finite
alphabet. The checker explores every nondeterministic outcome and terminates on
cycles using a visited-state set.

`PASS` establishes this proposition **inside the retained model only**. The
alphabet, states, capabilities, partition, and effects are declarations. The
checker does not observe the physical host or prove that the model enumerates all
real-world channels, instructions, interactions, or covert paths. A claimed
`virtual_hardware` member is a typed model resource, not attested physical
HARDWARE. No output grants ownership, consent, governance authority, access to a
host resource, or permission to execute a modeled action.

The `receipt_record` and `data_record` effect kinds mean only an inert write to
already held virtual storage inside the model. They do not deliver data outside
the SIM. `external_export`, `external_actuation`, `outside_write`, and
`capability_acquire` are explicit boundary effects and fail. Relabeling a
declared external target as a receipt or data record still fails because the
checker requires held virtual storage. A falsely declared virtual target or
omitted external effect remains outside this check; real delivery requires a
separate observation and authority mechanism.

## Input and result contract

[`assess_sim_isolation`](../domains/contracts/sim_isolation.py) takes
JSON-compatible dictionaries and a keyword-only `expected_binding`. The
checker supplies this binding independently of the retained evidence:

```json
{
  "sim_id": "sim:finite-room",
  "evidence_digest": "sha256:<64 lowercase hexadecimal digits>",
  "max_operations": 1000,
  "max_items": 64
}
```

`max_operations` is a positive integer no greater than 10,000,000;
`max_items` is a positive integer no greater than 4096. Both counts are
dimensionless. The selected binding's canonical digest is retained in the
assessment. The selected `sim_id` is at most 256 characters. Changing either
budget field changes that digest. The full input
must also fit the implementation's 1,048,576-byte canonical-JSON ceiling.

Evidence has exactly these top-level fields:

```json
{
  "schema_version": "verifier-sim-isolation-evidence-1",
  "sim_id": "sim:finite-room",
  "initial_state": "idle",
  "virtual_hardware": [
    {"id": "virtual:cpu", "kind": "compute"},
    {"id": "virtual:store", "kind": "storage"}
  ],
  "states": [
    {"id": "idle", "partition": "inside", "capabilities": ["virtual:cpu", "virtual:store"]},
    {"id": "busy", "partition": "inside", "capabilities": ["virtual:cpu", "virtual:store"]},
    {"id": "host", "partition": "outside", "capabilities": ["physical:network"]}
  ],
  "actions": ["step"],
  "transitions": [
    {"source": "idle", "action": "step", "outcomes": [
      {"target": "busy", "effects": [{"kind": "internal_write", "target": "virtual:cpu"}]}
    ]},
    {"source": "busy", "action": "step", "outcomes": [
      {"target": "idle", "effects": [{"kind": "receipt_record", "target": "virtual:store"}]}
    ]}
  ]
}
```

Virtual HARDWARE kinds are `compute`, `memory`, `storage`, and `sensor`.
`inside` state capabilities must reference that inventory. An `outside` state
may be represented to make a possible escape explicit, but cannot be reached
by a passing assessment. The initial state must be inside. Every action is a
nonempty string and duplicates are invalid. A transition row is identified by
its exact `(source, action)` pair; duplicate rows and dangling state references
fail. An outcome target must be a retained state. Safe effects are
`internal_write`, `receipt_record`, and `data_record`, each directed at a
virtual HARDWARE capability held by the source state. Transition target
capabilities must be a subset of source capabilities, so a state transition
cannot manufacture a new resource right. The model permits nondeterministic
outcome lists and transition cycles.

The result contains `status`, `reason`, `scope`, `sim_id`, both selected and
observed evidence digests, a digest of the complete selected binding,
reachable/unreachable-state counts, checked state/action and outcome counts,
missing pairs, and `assessment_digest` over every other result field. On `PASS`,
`virtual_hardware` is a canonical identifier-sorted list of exact checked
`{id, kind}` resources; it is empty for `FAIL` and `UNKNOWN`. This inventory is
derived from the same canonical evidence bytes used for the evidence digest,
not a later read of caller-owned mutable input. The
`scope` value is `finite_declared_transition_model`. `physical_host_containment`,
`authority`, and `object_profile_conformance` remain `NOT_ESTABLISHED` for every
status. Digests and identifiers are dimensionless. `recheck_sim_isolation`
recomputes the complete assessment from the retained evidence and independently
selected binding; it rejects any changed field, including a rehashed forged
result. A digest proves byte commitment under this canonicalization, not the
truth or external completeness of the committed model.

## Failure and uncertainty

| Result | Refutable condition |
|---|---|
| `PASS` | Every reachable state/action has nonempty outcomes, and every checked outcome remains inside with no capability gain or boundary effect. |
| `FAIL` | An explicit boundary escape, new capability, forbidden effect, duplicate, dangling reference, malformed field, or mismatch with selected identity/evidence digest is detected. |
| `UNKNOWN` | Reachable transition coverage is missing, an outcome set is empty, an effect or virtual HARDWARE kind is unsupported, or the operation/item/byte budget is exhausted. |

A `FAIL` in one reached branch is retained even if another reachable pair is
missing. Unreachable states are counted, while safety is asserted only for the
reachable set. An unlisted real-world action cannot be discovered from this
model; the burden of a complete action alphabet and physical isolation remains
outside this mechanism. This is a finite abstract closure check, not an
attestation of the executing computer or a SIM-1..8 certificate.
