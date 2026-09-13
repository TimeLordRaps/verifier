# Experimental verification-artifact network

> **Terminology:** American Standard Code for Information Interchange (ASCII);
> application programming interface (API); command-line interface (CLI);
> Hypertext Transfer Protocol Secure (HTTPS);
> JavaScript Object Notation (JSON); Request for Comments (RFC);
> Secure Hash Algorithm 256-bit (SHA-256); Unicode Transformation Format, 8-bit (UTF-8);
> Verifier Standard (VSTD).

**Status:** experimental `1.4.0a1` candidate interface; not a numbered-profile
conformance mechanism or a deployed interoperability claim.

The artifact network stores exact bytes in independently exportable publisher
silos. A central directory may make silos discoverable, but is not their source
of truth. Objects, commits, heads, and publisher records omit host locations, so
moving an export to another host preserves their identity-bearing digests.

## Six independent result axes

| Axis | What the reference mechanism establishes |
|---|---|
| `reconstructibility` | Whether every censused byte object is present and digest-valid. |
| `derivation_closure` | Whether every necessary path is reachable from declared ground through retained formation paths. |
| `self_derivability` | Whether the silo is self-derivable under the fixed alpha declarative mechanism: the retained graph satisfies ground-self, derivational reflexivity, reflexion identity, deriver-cycle closure, relation strength, evidence binding, and residual-obligation checks. The `self_derivation_record` is the witness; this result is the assessed property. |
| `completeness` | Whether the mechanism covers the explicitly selected completeness kind and declared denominator. |
| `silo_grounding` | Whether the silo is connected through necessary, retained derivations to the exact authority axiom agency coordinate and a closed, completely enumerated finite authority model. This does not establish that reachable states preserve the ground actions. |
| `authority_axiom_agency` | Whether the finite-model interpreter establishes the ground-level action floor across every declared reachable state. |

Self-derivation never implies completeness. The alpha mechanism can establish
only `SILO_CENSUS`. `DERIVATIONAL_COVERAGE`, `SEMANTIC_COVERAGE`, and
`LOGICAL_DECIDABILITY` remain `UNKNOWN` until separately registered mechanisms
declare and check their exact universes. Necessary census paths must also be
closed from declared necessary ground; omitting a residual cannot turn an open
path into complete census coverage. A finite census cannot silently stand in
for derivational, semantic, or logical completeness.

The alpha self-derivation mechanism is exact canonical JSON identified by
`VSTD-SELF-DERIVATION-MECHANISM-0.1`. The assessor interprets its fixed rules
over the retained graph; arbitrary mechanism bytes or evidence substitutions
cannot establish the axis. This remains a bounded structural result. It does
not prove HyperMath's stronger self-return proposition or import mathematical
authority from HyperMath, Ordinatics, or any adjacent representation.

The census denominator uses typed member identifiers, not artifact paths alone.
It exactly accounts for publisher and parent coordinates, objects, necessity
or dispensability, ground paths, derivations, premise and mechanism
dependencies, typed relations, the self-derivation record, completeness kind,
creation coordinate, authority binding and actions, the authority-model path,
actor-scope binding, states, transitions, scoped local additions, authority
residuals, general residual obligations, and explicit exclusions. Omitting or
adding a member makes structural census completeness `INCOMPLETE`.
If the required authority surface is absent, its denominator is not established
and silo-census completeness is `UNKNOWN`. A present but malformed, open,
residual, or mismatched declared authority surface is `INCOMPLETE`. A completely
enumerated reachable state may still make authority agency `VIOLATED`; completeness
and authority grounding therefore remain independent axes.

`VSTD-SILO-ASSESSMENT-RECEIPT-0.1` binds a computed six-axis result
to the exact commit digest and retained checking-mechanism digest without
putting a circular assessment inside the commit it assesses.

`VSTD-SILO-COMPOSITION-0.1` separately declares a canonical, nonempty,
sorted, unique set of exact member commit digests and either one exact
composite commit digest or `null`. The declaration is only a coordinate; it is
not evidence that the members are available, valid, compatible, or admissible.
`VSTD-SILO-COMPOSITION-ASSESSMENT-RECEIPT-0.1` binds the declaration digest,
the exact canonical reference-composition mechanism digest, commit-sorted
member assessment receipts, an optional composite assessment receipt, and the
typed composition result. Rechecking resolves the declared commits and stores,
recomputes every nested receipt and the complete composition assessment, and
requires canonical equality with the supplied receipt. It does not trust
serialized result fields. A declaration without a composite remains
`NOT_ADMISSIBLE`, with composite coverage and binding axes `UNKNOWN`.
The reference `VSTD-SILO-COMPOSITION-MECHANISM-0.1` recomputes each member's
six-axis receipt, recomputes the optional composite receipt, and invokes the
same fail-closed composition assessment used by the legacy application
programming interface. `VSTD-SILO-COMPOSITION-ASSESSMENT-RECEIPT-0.1` binds
the declaration digest, mechanism digest, ordered nested receipts, and typed
`VSTD-SILO-COMPOSITION-ASSESSMENT-0.1` result. Rechecking compares the entire
canonical receipt with independent recomputation; it does not trust serialized
result fields. A member-only declaration therefore remains `NOT_ADMISSIBLE`
with unknown composite completeness, member binding, local-addition
preservation, and composed authority agency.

The separate [finite authority-composition checker](../standard/FINITE_AUTHORITY_COMPOSITION.md)
adds a bounded correspondence test that the existing composition receipt does
not perform: it constructs the reachable asynchronous-interleaving product of
two to four selected member models and checks exact state and transition
bindings against a selected composite. Coordinate binding, correspondence,
agency preservation and local-addition preservation remain distinct fields.
It does not alter existing six-axis verdicts, prove correspondence to runtime
behavior, or discharge source grounding, self-derivation or stronger completeness.
Catalog discovery and planning retain its exact source and rule coordinate;
they do not execute the checker or authorize execution.

## Authority axiom agency

Authority axiom agency is the set of actions always allowable across publisher
silos and VSTD-Graph compositions. It is a ground invariant, not an intersection
of local permission lists. A restrictive silo that omits an action makes the
composition `NOT_ADMISSIBLE`; it does not erase the action from the ground set.

Exact static version, digest, and action-set identity is necessary but not
sufficient for `PRESERVED`. A necessary census artifact identified by
`VSTD-AUTHORITY-MODEL-0.1` declares a finite state universe, transition
universe, initial states, actor-scope vocabulary, and closure status. The
registered interpreter enumerates the reachable states through validated
transitions. A bound reachable state that removes a canonical ground action
returns `VIOLATED`, even when an unrelated residual, open closure, or unreachable
extra state prevents positive coverage. Malformed or mismatched record universes,
unsupported actor scopes, and unbound models cannot supply that witness; an
unreachable withdrawal is not a counterexample. Without a valid counterexample,
an absent, open, residual, malformed, or unsupported model returns `UNKNOWN`.
`PRESERVED` still requires the exact complete reachable closure, no residuals,
and the canonical ground action set in every state. This covers the declared
model only, not whether an implementation has unmodeled runtime transitions.

Silo grounding is assessed separately from preservation. It establishes
only that the exact authority coordinate and its closed finite model are
necessary, censused, and reachable from declared ground. A grounded silo can
still have `authority_axiom_agency: VIOLATED` when a reachable state removes a
ground action. Conversely, a matching static action list without the required
ground-reachable closed model leaves `silo_grounding: UNKNOWN`; declarations do
not ground themselves. A bound reachable counterexample can yield `VIOLATED`
while an open model leaves `silo_grounding: NOT_ESTABLISHED`.

`local_authority_additions` are separate typed records containing an actor
scope, action, and either `LOCAL_ONLY` or `COMPOSITION_PRESERVED` propagation.
They are additive only and cannot appear in the canonical ground set. A
composition uses union semantics: every `COMPOSITION_PRESERVED` record from a
member must occur byte-identically in every declared reachable composite state.
It never intersects local permissions to redefine the ground floor.

The alpha ground set preserves the ability to inspect accessible artifacts,
retain `UNKNOWN`, challenge with counterevidence, retain conflicts, fork, export
accessible silo material, select trust roots, withdraw one's own authorization,
and exit a composition.

Allowability does not establish access, capability, awareness, confidentiality,
non-inferability, or successful execution. For example, the right to inspect an
artifact does not supply decryption material or make unavailable bytes present.

## Stored records

- `VSTD-OBJECT-0.1` binds an exact byte digest, size, media type, artifact kind,
  and declared schema. The latter three remain declarations.
- `VSTD-SILO-COMMIT-0.1` is a complete snapshot with ground, census,
  necessity/dispensability, derivations, residual obligations, completeness
  kind, coverage universe, self-derivation record, and authority axiom agency.
  Typed `EVIDENCES`, `CHECKS`, `REFUTES`, `CHALLENGES`, `SUPERSEDES`,
  and `REVOKES` relations retain exact source, target, mechanism, and optional
  semantic coordinates; text difference alone never establishes contradiction.
- `VSTD-SIGNED-HEAD-0.1` binds a sequence and commit to an Ed25519 signing key.
- `VSTD-PUBLISHER-0.1` derives publisher identity from a genesis key. It proves
  no real-world identity, authorship, independence, correctness, or reputation.
- `VSTD-KEY-CONTINUITY-0.1` requires old-key and new-key signatures. Lost-key
  recovery creates a new cryptographic publisher identity.
- `VSTD-DIRECTORY-SNAPSHOT-0.1` is signed discovery metadata. Listing or
  delisting cannot modify a publisher's artifact history or verifier results.
- `VSTD-SILO-TRANSFER-0.1` carries exactly one selected publisher, continuity
  chain, signed head, commit, computed assessment receipt, and object closure.
  Every transported object must belong to the selected commit; unrelated
  history and unselected bytes are rejected.

The strict combined schema is
[`vstd-artifact-network-0.1.schema.json`](../standard/schemas/vstd-artifact-network-0.1.schema.json).
The exact interpreted mechanism has its own schema:
[`vstd-self-derivation-mechanism-0.1.schema.json`](../standard/schemas/vstd-self-derivation-mechanism-0.1.schema.json).
The finite authority-model schema is
[`vstd-authority-model-0.1.schema.json`](../standard/schemas/vstd-authority-model-0.1.schema.json).
The computed result, non-circular binding, and host-neutral client contract also
have independently consumable schemas:
[`vstd-silo-assessment-0.1.schema.json`](../standard/schemas/vstd-silo-assessment-0.1.schema.json),
[`vstd-silo-assessment-receipt-0.1.schema.json`](../standard/schemas/vstd-silo-assessment-receipt-0.1.schema.json),
and [`vstd-push-request-0.1.schema.json`](../standard/schemas/vstd-push-request-0.1.schema.json).
The composition declaration, typed result, and receipt schemas are
[`vstd-silo-composition-0.1.schema.json`](../standard/schemas/vstd-silo-composition-0.1.schema.json),
[`vstd-silo-composition-assessment-0.1.schema.json`](../standard/schemas/vstd-silo-composition-assessment-0.1.schema.json),
and [`vstd-silo-composition-assessment-receipt-0.1.schema.json`](../standard/schemas/vstd-silo-composition-assessment-receipt-0.1.schema.json).
The bounded download envelope is
[`vstd-silo-transfer-0.1.schema.json`](../standard/schemas/vstd-silo-transfer-0.1.schema.json).

## CLI surface

`vstd network` provides `init`, `object add`, `commit`, `inspect`, `diff`,
`clone`, `compose`, `export`, `rebuild`, `register`, and `push`. Ed25519 operations require
the optional `verifier-standard[seal]` extra; base imports remain standard-library
only. `clone` accepts either a native local export directory or a credential-free
HTTPS transfer endpoint. The downloader accepts only bounded JSON transfer
media, permits at most three HTTPS redirects, strips credential headers from
redirects, and uses a ten-second request timeout. Download success establishes
transport only; the client still recomputes record identities, signatures,
continuity, assessment, and the native post-copy reconstruction.

`network register` is the explicit publisher-enrollment operation for a
separately deployed Claim Garden service. It requires the export root, a
credential-free HTTPS origin, an Ed25519 private-key path, an issuance time,
and an absent credential-output path. The access token is written only to that
caller-selected file and is not printed. Optional `--publisher-endpoint`
arguments declare public silo locations; registration does not establish
publication.

`network push` remains non-transmitting by default: it emits the existing
host-neutral `VSTD-PUSH-REQUEST-0.1` document. Authenticated submission requires
the literal `--transmit` switch, a `--credential-file` path, and exactly one of
`--genesis` or `--expected-head sha256:...`. In transmitting mode `--endpoint`
must be a credential-free HTTPS origin rather than a path. The native client
does not follow redirects or retry an authenticated request. A successful
submission ends at `PENDING_REVIEW`; the client never invokes moderation and
does not claim acceptance or publication. Credential contents are sent only in
the authorization header and are never included in command output. An
indeterminate post-open submission preserves `UNKNOWN` in its output and exits
with status 2 rather than reporting command success.

All stored object inspection is inert:
the reference implementation does not import, install, extract, render, or
execute retained artifacts.

The alpha object maximum is four mebibytes. Canonical JSON uses UTF-8,
lowercase ASCII snake_case field names, sorted keys, compact separators,
Unicode Normalization Form C strings, and nonnegative integers no larger than
2^53-1; floats are rejected. Ed25519 keys and signatures use unpadded RFC 4648
base64url. The deterministic cross-runtime fixture is
[`canonical-wire-fixture.json`](../examples/artifact-network/canonical-wire-fixture.json).

A composition is itself a full six-axis silo. Its census must retain exact
member commits plus bridge, adapter, relation, and policy artifacts. Complete
member silos alone yield composite completeness `UNKNOWN`; a composite policy
that removes authority axiom agency makes the composition `NOT_ADMISSIBLE`.
An unsupported agency version, mismatched agency digest, static-only binding,
or local action-set extension inside the ground field remains `UNKNOWN` and
also blocks composition. Exact canonical version, digest, and action-set
identity plus a checked closed finite model is required for `PRESERVED`; local
actions are not ground authority. The alpha defines no key-authorized agency transition;
a future transition would have to retain a superset of every formerly grounded
action rather than rename, intersect, or locally remap the ground set.
