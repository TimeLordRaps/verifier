# Accountability and release scope

Verifier Standard (VSTD) is the verification-domain language; Verifier is its
reference implementation. This document records the maintainer's 2026-09-27 scope
clarification and the implementation seams it exposes. It does not silently amend
existing wire identifiers, claim completed certification, or replace the normative
catalogue before its migration is specified and validated.

## Declared domains versus adapters

The accountability family includes all of these domains:

| Domain | Subject in the current specification |
|---|---|
| ACTOR | Accountable party, decisions, delegation and attribution |
| OWNER | Holdings, rights, duties, instruments and consequences |
| IDENTITY | Binding a bearer into a role class |
| ROLE | Authority-bearing role class and its occupancy boundary |
| COLLECTIVE | Graph of roles and their relations |
| HUMAN | A living person and human accountability termination |

These names are semantic domain labels, not abbreviations for Python packages.
All six have declarations in `core/profile_obligations.py` and bounded native
retained-record adapters in `domains/catalog.py`. `domain-catalog --accountable`
lists ACTOR, OWNER, HUMAN, IDENTITY, ROLE and COLLECTIVE separately from the
default computational catalogue. The existing `identity` package is distinct
from the native IDENTITY domain adapter. These checks do not mechanize any of
the six objects' numbered-profile obligations or establish a living person,
legal authority, actual occupancy, person-separated quorum, or consent.

The native computational adapter inventory is DATA, ENV, BENCH, TRAIN, MODEL, SIM,
HARNESS, AGENT, BOT, TOKEN, VERIFIER and HARDWARE. The catalogue additionally declares
HYPER, whose presence must not be confused with a native adapter. Exact definitions and obligations
remain in [the domain specification](../src/verifier/standard/DOMAIN_OBLIGATIONS.md).
Object and Graph axes must also remain visible in the overall release inventory.

## Intended meta-tier architecture

Accountability meta-tiers concern authority, responsibility, commitments and related
accountability structures. They must not be silently identified with computational
facets, dynamics, statics, closure and domain adaptation.

| Coordinates | Maintainer's intended scope | Current qualification boundary |
|---|---|---|
| `[OBJECT]-1.m` through `[OBJECT]-5.m` | General domain coverage, with distinct accountability meanings | Exact accountability tier-name mapping and mechanism completeness remain unresolved |
| `[OBJECT]-6.m` | Privacy grounding certificates | Existing emission helpers do not establish every privacy grounding proposition |
| `[OBJECT]-7.m` | Consent structures | Bounded consent admission exists; full coordinate certification is not established |
| `[OBJECT]-8.m` | Governance and laws | Bounded governance admission exists; the full requested model and law execution are not established |

`[OBJECT]` stands for one named object in the VSTD-NAMESPACE; the hyphen separates
that object from a **positive** meta-tier number 1 through 8. Within each tier, `m`
indexes an internal grounding certificate, starting at 1. These coordinates are
dimensionless semantic identifiers, not physical units, software versions, or
negative tier numbers. The maintainer identifies governance as **Distributed Aggregated
Governance** and laws as **smart contracts**. Do not abbreviate that governance name
to the same shorthand used for a directed acyclic graph.

## Explicit specification seams

The current [meta-tier specification](../src/verifier/standard/META_TIERS.md)
catalogues a five-tier computational corroboration subgrid and treats its present
level-6 rows as emission disclosure. Those existing rows are only a partial
projection of the eight-tier architecture. They do not yet implement the distinct
accountability interpretation, full privacy grounding, or registered level-7/8
certificates. The prior use of `.m` for a topological-depth bound conflicts with
the maintainer's internal-certificate meaning; certificate indexing and dependency
depth must be kept separate until the migration and compatibility checks are defined.

The current governance evaluator checks bounded policy, signatures, quorum and a
supplied status snapshot. Its [contract](GOVERNANCE_LEVEL8.md) leaves enforcement
unknown. It is not evidence of a distributed governance runtime or executed laws.

Required design and implementation obligations include exact accountability tier
mapping; certificate propositions and replay for privacy, consent and governance;
membership, aggregation, delegated authority and dissent rules; smart-contract state
transitions and authorization; execution/consumption receipts; and failure, appeal
and enforcement boundaries. This list records open obligations, not invented choices
for their resolution.

Privacy certification must ground its own privacy claims. Consent and governance
cannot manufacture missing computational evidence, and a correct computation cannot
grant consent or authority. Each result needs its own mechanism and bounded evidence.

See [source-grounded description requirements](RELEASE_FEATURE_GROUNDING.md).
