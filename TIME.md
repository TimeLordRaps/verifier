# TIME

Status: OPEN

TIME is the live repository-contradiction annunciator. Its status is repository process
metadata, not Verifier Standard (VSTD) receipt vocabulary. A live entry belongs here only
when current authoritative surfaces make incompatible claims about current semantics or
implementation. Runtime `CONFLICTED`, an honest `UNKNOWN`, roadmaps, ordinary work items,
limitations, and speculative research do not belong here.

For agent response rules, see [`AGENTS.md`](AGENTS.md). For human interpretation and
escalation, see [`HUMANS.md`](HUMANS.md).

## Live contradictions

### zero-identity/zero-knowledge (ZIZK) artifact-first architecture is presented as a side experiment

- **Controlling architecture:** [`standard/LADDER.md`](standard/LADDER.md) section 1.1
  normatively fixes artifact-first support, zero actor-reputation weight, contextual
  actor/artifact roles, and reverse diagnostic Rust as VSTD's causal orientation.
- **Incompatible presentation:** [`README.md`](README.md), [`ROADMAP.md`](ROADMAP.md), and
  [`experiments/INDEX.md`](experiments/INDEX.md) classify zero-identity/zero-knowledge
  (ZIZK) as a non-normative research experiment rather than distinguishing the governing
  architecture from its unfinished event format, transfer algebra, concentration rule,
  localization protocol, and optional proof mechanisms.
- **Affected behavior:** a newcomer can reasonably conclude that artifact-first trust and
  zero actor trust are optional side research instead of constraints governing VSTD.

### The recorded ZIZK proof is not publicly retrievable for offline verification

- **Controlling claim:**
  [`experiments/zizk_vstd/zero_knowledge/ROUND1_ZERO_KNOWLEDGE_REPORT.md`](experiments/zizk_vstd/zero_knowledge/ROUND1_ZERO_KNOWLEDGE_REPORT.md)
  records a real reduced instruction set computer (RISC) Zero composite scalable
  transparent argument of knowledge (STARK)
  receipt, its public envelope, their exact digests, and an offline verification path.
- **Incompatible artifact surface:** the public receipt and public envelope are ignored and
  absent from the repository. Only their hashes and the prover/verifier source are
  published; a consumer can generate a new proof but cannot retrieve and verify the exact
  recorded proof. The private witness is correctly excluded and is not required for
  offline verification.
- **Affected behavior:** the central public claim is artifact-referenced rather than
  artifact-first. Digest retention alone is not retrieval or verification evidence.

When a contradiction is open, change the status to `Status: OPEN` and record the exact
coordinates, both incompatible claims, evidence for each side, and affected behavior. An
evidence-backed repair removes the resolved live entry and returns this file to
`Status: CLEAR`; Git history preserves the prior state. Development branches may remain
open. The tag-triggered publication workflow checks the exact tagged checkout and fails
unless this file contains exactly one `Status: CLEAR` line.
