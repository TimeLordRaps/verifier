# Tier-0 repository admission

This document specifies the retained version-1 profile. Current `vstd polish 0`
uses [extensible admission](EXTENSIBLE_NAMESPACE.md), including exact definition
ownership and reasoned kind applicability. Verifier's version-5 root preserves
the version-4 current-representation contract, retains every check below and adds
version-2 namespace checks on the same package GRAPH.
A version-1 manifest must be migrated before current admission. For a recognized
Verifier root, default `vstd polish 0` performs the guarded installed refresh
before assessment; other roots require an explicit migration. A historical PASS
does not establish the new profile.

Tier zero is the repository-admission layer for Verifier Standard (VSTD)
self-polish. It is not a tenth `MetaTier`, and it does not establish any Tier-1
through Tier-9 object obligation. Its purpose is to prevent a repository from
starting semantic polish with an incomplete or self-serving description of its
objects, surfaces, obligation denominator, reasons, mechanisms, or current
source bytes.

A polish-ready repository carries strict canonical JavaScript Object Notation
(JSON) in `objects.vstd`. The extension is a media convention; it does not
change the JSON grammar. Shape is defined by a separate JSON Schema. The
declaration never proves itself. Source-bound Python discovery accounts for the
actual repository surfaces; Python and Node manifest reconcilers independently
validate the canonical declaration and its selected attachment bytes. Terms
used below include application programming interface (API) and identifier
(ID).

## Fixed version-1 denominator

Version 1 contains exactly nine obligations:

1. `VSTD-T0.1` canonical manifest admission: reject duplicate keys, non-finite
   numbers, malformed or non-canonical encoding, schema drift, and profile
   substitution. This exists so different implementations cannot silently read
   different declarations.
2. `VSTD-T0.2` object denominator closure: declare every installed object kind
   exactly once with stable, unique identity. This exists so whole-package
   claims cannot hide an omitted, duplicated, aliased, or substituted kind.
3. `VSTD-T0.3` typed relation closure: resolve and reproduce every installed
   typed package edge and canonical graph composition. This exists because a
   list of objects is not the interaction graph assessed by later tiers.
4. `VSTD-T0.4` exposed-surface closure: independently discover files, command
   routes, APIs, schemas, receipts, plugins, verifier mechanisms,
   compatibility routes, and other installed census categories, and give each
   identity one declared disposition. This exists to prevent an unlisted
   interface from falling outside the claimed repository boundary.
5. `VSTD-T0.5` obligation denominator closure: bind all 234 installed kind-tier
   slots and all 408 installed route memberships with their current semantic,
   proposition, certificate, scope, and mechanism identities. This exists
   because surface completeness is not standards coverage.
6. `VSTD-T0.6` reason and realization closure: every slot and route has both a
   standard rationale and a repository-specific realization annotation. This
   exists so a coordinate alone cannot explain either why an obligation exists
   or why exact repository mechanisms meet it.
7. `VSTD-T0.7` source and mechanism freshness: bind all declarations,
   discoveries, reasons, mechanisms, and receipts to one unchanged opening and
   closing source coordinate. This exists because correct evidence for stale or
   changing bytes does not admit the current repository.
8. `VSTD-T0.8` independent implementation agreement: strict Python and Node
   implementations pass the same adversarial parser corpus and independently
   emit the same canonical manifest, object graph, declared obligation
   denominator, selected-attachment, and result digests. This exists so one
   implementation does not define both the language-neutral artifact and its
   only accepted interpretation; it does not require a second implementation
   of the complete Python abstract-syntax-tree surface census.
9. `VSTD-T0.9` conservative verdict and authority boundary: contradictions stay
   `FAIL`, unavailable or unsupported claims stay `UNKNOWN`, decision authority
   remains explicit, and Tier zero grants no Tier-1-plus, polish, release, or
   deployment credit. This exists to prevent structural admission from being
   silently promoted into semantic assurance.

These nine dimensions are exhaustive only for the stated repository-admission
scope: encoding and schema, object census, relations, surfaces, obligation
denominator, two-layer reasons, freshness, independent reconciliation, and the
epistemic/authority boundary. Adding, removing, or changing an obligation
requires a new profile version and digest. Version 1 does not claim universal
repository completeness or semantic correctness beyond its installed census.

## Repository realization annotations

Every selected obligation carries one realization class:
`DIRECT`, `SPECIALIZATION`, `TRANSLATION`, `CONDITIONAL`, `NOT_APPLICABLE`, or
`UNREALIZED`.

The annotation binds the obligation semantic digest, discovered surface IDs,
current mechanism paths, symbols and byte digests, evidence requirements,
preserved and unpreserved semantics, residual obligations, falsifiers, and
decision authority. `SPECIALIZATION`, `TRANSLATION`, and `CONDITIONAL` also
state why adaptation is necessary. Adaptation cannot erase lost semantics or
promote the original obligation beyond the evidence.

Missing or malformed annotations fail admission. A syntactically valid but
unsupported annotation remains `UNKNOWN`. A contradiction is `FAIL`. A bounded
annotation can pass only the claim it states and preserves its residuals.

## Completion boundary

`vstd polish 0` may report `PASS` only when all nine obligations pass at one
unchanged source coordinate. That result admits the repository declaration as
the input to later self-polish. It does not establish any numbered object-tier
obligation, whole-package polish, owner adoption, release authority,
publication, or deployment.

Every obligation outcome includes an `assessment_reason` that states why its
current evidence does or does not satisfy the installed condition. The report
also binds the complete installed assessment mechanism and includes a
`finalization` record. `finalization.status: PASS` means only
that the fixed nine-obligation repository-admission denominator is complete at
the bound source coordinate, every obligation has an explicit assessment
reason, no Tier-zero blocker remains, and the profile can change only under a
new version and digest. It does not promote any Tier-1-plus claim.
