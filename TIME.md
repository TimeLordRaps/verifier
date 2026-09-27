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

`HIERARCHY-2026-09-27`: the maintainer's governing hierarchy, retained under
DO NOT REMOVE in [pull request #53](https://github.com/TimeLordRaps/verifier/pull/53),
defines ACTOR as HUMAN, AGENT or BOT rooted in a responsible HUMAN; eight general
meta-tiers place independence at 5, privacy at 6, consent at 7 and governance at 8.
The new [finite composition foundation](src/verifier/standard/NAMESPACE_OBJECTS.md)
implements that structural vocabulary without asserting full certification.

The normative documents and namespace gate now distinguish the current hierarchy
from the legacy catalogue. The unresolved runtime seam is version selection:
`src/verifier/domains/identity.py` still rejects an AGENT bearer, while
`src/verifier/core/namespace.py` admits an IDENTITY whose ACTOR represents an
AGENT. `src/verifier/core/profile_obligations.py` registers six domain tiers with
adaptation at 5 and disclosure at 6; the current hierarchy gives independence
and privacy those numbers. The same unversioned coordinate spelling can therefore
name different propositions, with no completed current-object certificate
contract and semantic mapping to disambiguate the two paths.

The new [versioned identity declaration](src/verifier/standard/IDENTITY_OCCUPANCY.md)
binds the current ACTOR-to-ROLE relation by direct Python import. Its distinct
evidence and assessment identifiers avoid reinterpreting legacy bytes, but do not
yet provide the current-object objective registry, certificate selection or
command-line migration needed to close this seam.

Existing numbered-profile results cannot be reinterpreted under new coordinates.
Release remains blocked until the exact obligations, runtime contracts, schemas,
migration and tests agree. Historical readers must preserve old receipt meanings;
current object certificates must bind their own versioned propositions explicitly.

When a contradiction is open, change the status to `Status: OPEN` and record the exact
coordinates, both incompatible claims, evidence for each side, and affected behavior. An
evidence-backed repair removes the resolved live entry and returns this file to
`Status: CLEAR`; Git history preserves the prior state. Development branches may remain
open. The owner-dispatched publication workflow checks the exact tagged checkout and fails
unless this file contains exactly one `Status: CLEAR` line.
