# Current BOT-3.1: observation ceiling inherited through the bound agent

Status: experimental, versioned current-object objective. Verifier Standard
(VSTD) specifies the claim; this Python mechanism is one reference checker.
JavaScript Object Notation (JSON) gives canonical retained bytes, and Secure
Hash Algorithm 256-bit (SHA-256) names commitments. BOT is the situated agent
object name, not an acronym. Observation ceilings, counts and checking
budgets are dimensionless integers.

## Row

The pair `verifier-current-object-obligations-1` / `BOT-3.1` selects a
bounded strict subset of this row of `DOMAIN_OBLIGATIONS.md`, quoted verbatim:

| BOT-3.1 | Inherited ceiling | The observation ceiling exists whatever the agent claims about it. | none | statics:inherited |

## Proposition

The externally selected exact BOT record occurs once in the selected finite
typed collection. Its agent operand binds exactly one AGENT record, and that
record's harness operand binds exactly one HARNESS record. That HARNESS
record states an integer observation ceiling. The ceiling is reported from
that record, whether the bot or the agent claims a ceiling, claims none, or
claims a different one. A present claim that exceeds it is refuted under
statics:inherited.

## Retained bytes

Evidence is the canonical JSON object `{"schema_version":
"verifier-current-bot-inherited-ceiling-evidence-1", "objects": [...]}`. Each
row is one namespace record and must reconstruct exactly. The request commits
the subject digest, the composition digest of every row and the SHA-256 of
the evidence bytes.

- The BOT payload is exactly `{"scope": "retained-bot-inherited-ceiling",
  "claimed_ceiling": <integer or null>}`.
- The bound AGENT payload may carry other keys. If its `declared_ceiling` key
  is present and not `null`, that value is the agent's claim.
- The bound HARNESS payload's `observation_ceiling` is the `statics.py`
  harness object `{"ceiling": <integer>, "observed": [...]}`.

## Decision

1. The following are `FAIL`:
   - non-canonical or wrong-version evidence;
   - a subject that is absent, repeated, of another kind or of another digest;
   - a failed typed composition;
   - a wrong BOT scope;
   - a malformed observation ceiling.
2. The following are `UNKNOWN`:
   - an exhausted bound or missing evidence;
   - an agent operand that does not bind one AGENT record;
   - an agent harness operand that does not bind one HARNESS record;
   - a bound HARNESS payload without `observation_ceiling`.
3. The inherited ceiling is the bound HARNESS record's `ceiling`. The claims
   are the BOT `claimed_ceiling`, then the agent's `declared_ceiling`, each
   only when present and not `null`. For each claim `c`,
   `statics.evaluate("BOT", "inherited", {"agent": {"claimed_ceiling": c,
   "harness_ceiling": <inherited>}}, {}, budget, subject=<subject_id>)`
   decides. A claim above the inherited ceiling is `FAIL`. An equal or lower
   claim, or no claim at all, leaves the inherited ceiling in force.
4. `PASS` reports `agent_id`, `harness_id`, `inherited_ceiling` and
   `claims_checked`. An unbound HARNESS or AGENT record in the collection
   never supplies the ceiling.

## Relation to other BOT coordinates

`bot_checks.py` registers BOT-1.6 (binding), BOT-2.1 (alignment), BOT-2.2
(observation), BOT-2.3 (actuation) and BOT-4.1 (containment). Those replay
nested AGENT, SIM and ENV child certificates over retained couplings. This
objective replays no child certificate and executes no loop. It decides only
the ceiling reached through two exact operand bindings.

The other rows of this tier remain `NOT_ESTABLISHED` here: BOT-3.2 (coupling
latency), BOT-3.3 (disclosure limit) and BOT-3.4 (policy impotence). The
inventory rationale for this slot names execution quotas, capability
whitelists and operation budgets. None of these is established by this
objective.

## Exclusions

`PASS` establishes none of the following, each of which is `NOT_ESTABLISHED`:

- that any harness enforced the ceiling;
- that the bot observed only what the ceiling allows;
- the bot's latency or disclosure;
- authority, safety, security, privacy or consent;
- closure of the BOT statics tier;
- object-profile conformance.

The pinned mechanism is invalidated by a change to any of these:

- the BOT, AGENT or HARNESS records;
- the collection;
- the evidence bytes, limits or policy;
- `statics.py`, this mechanism or this specification.
