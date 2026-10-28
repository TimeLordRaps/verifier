# BOT, ROBOT and FINBOT agency-surface crosswalk

This installed Verifier Standard (VSTD) mechanism joins retained certificates
that otherwise verify separate propositions. It is a bounded crosswalk, not a
new source of evidence. Every child certificate is independently selected and
replayed by its existing checker before any cross-route identifier is trusted.

## Roles and accumulation

`BOT` is simulation-situated agency. `ROBOT` is agency in a harness whose
declared consequence path reaches a real physical actuator through a
controller. `FINBOT` is agency that makes consequential real financial
decisions. These roles accumulate: a BOT with a selected `REAL_PHYSICAL` effect
must also replay the applicable ROBOT routes, and a BOT with a selected
`REAL_FINANCIAL` effect must also replay the applicable FINBOT routes. A
simulation label never discharges either consequence.

Each route is conditional on source-bound evidence that its role and effect
domain apply. When the condition is met the route is necessary. A source-bound
classification refutation can establish that a role does not apply to one
variant; an `OBJECT` label, omission, or unknown applicability cannot exempt
it.

## Exact routes

| Coordinate | Reason | Executable proposition | Residual |
|---|---|---|---|
| `BOT-1.7-agency-surface-binding` | Valid BOT and AGENT certificates can still name different operands. | Replay `AGENT-1.8` and `BOT-1.6`; require their actual `agent_id` and `harness_id` to equal the source-bound join. | Identity, authority and live execution are `NOT_ESTABLISHED`. |
| `BOT-2.6-agency-surface-trace` | Separate trajectory, action and coupling passes do not establish one shared trace. | Replay `AGENT-2.1`, `AGENT-2.3`, and `BOT-2.1` through `BOT-2.3`; bind one exact decision/action record to one selected simulated effect key. | Causality, observation authenticity and omitted effects are `NOT_ESTABLISHED`. |
| `BOT-3.5-agency-surface-operational-boundary` | Operational limits cannot be inferred from a retained trace. | Require explicit limit, intervention, recovery and confinement records whose status remains `NOT_ESTABLISHED`; never use `BOT-4.1`. | Authenticity, adequacy and successful recovery are `NOT_ESTABLISHED`. |
| `ROBOT-1.2-agency-surface-binding` | A physical path can name a different agent or harness. | Replay `AGENT-1.8` and `ROBOT-1.1`; join their actual identifiers. | Physical actuation and runtime correspondence are `NOT_ESTABLISHED`. |
| `ROBOT-2.2-agency-surface-trace` | A physical trace can be detached from the selected agent decision and action. | Replay `AGENT-2.1`, `AGENT-2.3`, and `ROBOT-2.1`; bind the exact shared decision/action record to one physical trace identifier. | Causal attribution and physical effect are `NOT_ESTABLISHED`. |
| `ROBOT-3.2-agency-surface-operational-boundary` | Passing retained hazard records do not prove safety or recovery. | Replay `ROBOT-3.1` and require explicit limit, intervention, recovery and confinement boundary records. | Authenticity, adequacy, successful recovery, physical safety and real-world correspondence are `NOT_ESTABLISHED`. |
| `FINBOT-1.2-agency-surface-binding` | A financial scope can name a different agent or harness. | Replay `AGENT-1.8` and `FINBOT-1.1`; join their actual identifiers. | Identity, legal authority and real-money effect are `NOT_ESTABLISHED`. |
| `FINBOT-2.2-agency-surface-trace` | A financial exposure can be detached from the selected agent decision and action. | Replay `AGENT-2.1`, `AGENT-2.3`, and `FINBOT-2.1`; bind the exact shared decision/action record to one retained financial effect identifier. | Causal attribution, legal authority and real-money effect are `NOT_ESTABLISHED`. |
| `FINBOT-3.2-agency-surface-operational-boundary` | Passing retained reconciliation records do not prove authority or recovery. | Replay `FINBOT-3.1` and require explicit limit, intervention, recovery and confinement boundary records. | Authenticity, adequacy, successful recovery, legal authority and real-world correspondence are `NOT_ESTABLISHED`. |

The Tier-3 records are fail-closed declarations of the current evidence limit.
This version has no source mechanism that promotes any of the four boundary
statuses. A future promotion requires a distinct exact proposition, source
evidence, checker and compatibility review; changing the string in a retained
record is rejected.
