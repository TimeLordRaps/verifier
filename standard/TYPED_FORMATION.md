# Experimental typed formation

Verifier Standard (VSTD) separates typed formation from self-derivation,
completeness, grounding, and authority axiom agency. This finite constructor
interpretation is an executable prerequisite, not a translation theorem for
Hypermath or an implementation of its complete self-return construction.

Terminology: JavaScript Object Notation (JSON); Unicode Transformation Format,
8-bit (UTF-8); Secure Hash Algorithm 256-bit (SHA-256); identifier (ID).
FORM, PATH and CODE are formal type names, not assurance verdicts. In this
document `ID` is also the serialized identity-path constructor. All counts
are dimensionless; input size is measured in bytes.

## 1. Admitted records

The [structural schema](https://timelordraps.github.io/verifier/schemas/vstd-typed-formation-0.1.schema.json) covers two
records. The network canonical codec applies: UTF-8, Unicode Normalization Form
C, sorted lowercase snake_case keys, no duplicates, no extra whitespace,
no surrogate code points and only nonnegative JavaScript-safe integers.
Booleans are not indices. A reserialization mismatch is invalid.

Every subject has exactly `schema_version: VSTD-TYPED-FORMATION-0.1`,
`profile_digest`, `context`, `nodes`, and `root`.
Context has exactly `ground_artifact_digest` and
`authority_axiom_agency_digest`. Digests are lowercase `sha256:` plus
64 hexadecimal digits. They bind declared coordinates only. Neither context
object is retrieved, interpreted, adopted or proved by formation checking.

Nodes form a nonempty construction-ordered array. The integer root selects
one node. Every constructor reference is an integer strictly smaller than its
own node index. No cycle, external expansion, arbitrary operation, executable
payload, filesystem access or network access is admitted. Every declared node
is checked, including nodes not in the selected root's dependency closure.

| Exact node fields | Formation rule |
|---|---|
| `tag: ATOM, payload_digest` | Introduce an opaque FORM symbol. The digest does not retrieve its artifact or establish ground origin. |
| `tag: APPLY, argument` | FORM to syntactic FORM application; not execution. |
| `tag: ID, at` | FORM to empty PATH whose source and target are that form. |
| `tag: APPLY_STEP, source, target` | Both FORM; target must be exactly the inferred application of source. Produces one ordered path step. |
| `tag: COMPOSE, left, right` | Both PATH; left target must equal right source. Concatenate traces in that order. |
| `tag: QUOTE, value` | Any checked type T to CODE(T), retaining its typed value and formation dependencies. |
| `tag: READ, code` | CODE(T) to its retained T, without erasing dependencies, quotation origins or rank. |

No node admits fields other than those listed. CODE(PATH) is not silently
converted into a Hypermath form. READ does not prove that the deriver read its
own entry; it reads a prior checked quotation in this acyclic subject.

A certificate has exactly
`schema_version: VSTD-TYPED-FORMATION-CERTIFICATE-0.1`,
`subject_digest`, `profile_digest`, `steps`, and `root`.
Each step has exactly `node`, `rule`, and `premises`. There is one step for
every subject node, in its construction order; rule equals the constructor tag,
and premises equal its ordered references. Subject digest, compiled profile
digest and selected root must match exactly. Certificates contain no claimed
type, observation, FORM verdict, CHECKED flag or self-status for the checker to
trust.

The inert compiled declaration is returned by `formation_wire.profile_bytes()`
and retained byte-identically as `verifier/profiles/typed-formation-0.1.json`.
Its digest identifies that rule declaration, not the implementation. Unknown
schema or profile is unsupported, never loaded as code. Unknown constructors
under the known subject schema are invalid.

## 2. Identity and retained observations

Write H(x) for SHA-256 of the canonical bytes of x, with the `sha256:` prefix.
Digest-based identity assumes no collision in the exercised encodings; matching
hashes are not a semantic interpretation theorem.
For a FORM, its denotation digest is:

- ATOM: H({kind: ATOM, payload_digest: declared digest}).
- APPLY: H({kind: APPLY, argument_digest: argument's denotation digest}).

PATH denotation is H({kind: PATH, source_digest, target_digest, path_steps}).
Each ordered path step has exactly `source_digest` and `target_digest`.
These endpoints identify inferred FORM denotations, not source files, payload
bytes or historical execution. Identity composition normalizes to the same
path denotation while retaining a different formation identity.

CODE denotation is H({kind: CODE, subject_digest, node, dependency_nodes}),
where node is the quoted value's index and dependency_nodes is its sorted
transitive dependency closure, including that value. The exact subject binding
includes its context, selected root and otherwise unrelated nodes. Changing any
subject bytes therefore changes quotation identity. It is not a cyclic hash:
the subject stores syntax, not its own digest.

READ returns the quoted typed value and its normalized denotation unchanged.
Its own formation identity remains H({subject_digest, node: selected index}).
The checker retains, separately:

- `dependency_nodes`: sorted union of all input closures plus this node.
- `quote_origins`: sorted union of input quotation origins, plus this index
  for QUOTE.
- `quote_rank`: maximum input rank, incremented by one only at QUOTE.
  READ does not decrease it.
- `required_depth`: one plus maximum input dependency depth; ATOM is one.

The root observation has exactly `type`, `denotation_digest`,
`source_digest`, `target_digest`, `path_steps`, `quote_rank`,
`required_depth`, `formation_digest`, `dependency_nodes`, and
`quote_origins`. Non-PATH values have null endpoints and an empty path_steps
array. Nested CODE types remain explicit.

## 3. Bounds and results

Each subject and certificate is at most 262,144 bytes. Before recursive JSON
decoding, a string-aware scan bounds open container nesting to 16 (root
container counts as one) and total object/array openings to 8,192.
There are at most 1,024 nodes and certificate steps, dependency depth 64,
and 4,096 expanded steps per inferred PATH. Test the path bound before
concatenation. These are finite resource ceilings, not a wall-clock guarantee.

The unary acyclic interpretation does not provide an exponentially reusable
nonempty cycle. The path ceiling is a defensive limit; a reduced test-only
ceiling can exercise refusal without claiming such a cycle exists.

The independent checker returns exactly `status`, `subject_digest`,
`profile_digest`, `root`, `observation`, `reason_codes`, and
`residual_obligations`. Profile digest always identifies the compiled
declaration. Subject digest and root are null until subject syntax is admitted.

- CHECKED: every node satisfies these formation rules and the complete
  certificate binds it. Only then is the root observation present.
- INVALID: malformed known records, certificate substitution, incorrect proof
  steps, incompatible types or mismatched endpoints.
- UNKNOWN: unsupported schema/profile or an exhausted resource ceiling.

Whole-record grammar and all cheap certificate bindings precede inference.
Inference then proceeds in source order and stops on its first failure or
resource limit. Later semantic nodes are not claimed to have been examined.
No partial root observation is promoted. Reasons are respectively
`FORMATION_RECORD_INVALID`, `FORMATION_CERTIFICATE_BINDING_INVALID`,
`FORMATION_CERTIFICATE_STEP_INVALID`, `FORMATION_RULE_INVALID`,
`FORMATION_PROFILE_UNSUPPORTED`, or `FORMATION_LIMIT_EXCEEDED`.

Every result retains these unresolved obligations, including CHECKED:

```text
SOURCE_INTERPRETATION_NOT_ESTABLISHED
GROUND_DERIVATION_NOT_ESTABLISHED
SOURCE_TRACE_RELATION_NOT_ESTABLISHED
SOURCE_LAYER_BOUNDARY_NOT_ESTABLISHED
SELF_STATUS_NOT_ESTABLISHED
GLOBAL_CYCLE_NOT_ESTABLISHED
COMPLETENESS_NOT_ESTABLISHED
AGENCY_NOT_CHECKED
```

## 4. Native mechanism integration

Direct experimental modules are `formation_wire`, `formation_producer`,
`formation_checker`, and `formation_mechanism`, all under
`verifier.interoperability`; none is a supported top-level export.

`FormationPathCertificateMechanism` implements the existing evidence-bound
session protocol. Mechanism identifier and predicate are both
`vstd.typed_formation.checked.0.1`, with expected exactly the string
`CHECKED`. Parameters are exactly `profile_digest`,
`ground_artifact_digest`, and `authority_axiom_agency_digest`.
The two evidence references are ordered subject then certificate; subject_id
equals the exact subject digest. Parameters must match the subject context.
Trust roots are exactly the sorted distinct profile, ground and agency digests:
these remain explicit assumptions, not proven authority.

The wrapper accepts exactly two evidence items, each within the record ceiling.
Declared item bound is exactly two; declared byte bound is a nonnegative integer
at most twice the record ceiling, and must cover the actual supplied bytes.
It rechecks byte identity even when called without a session. Whole-pair byte
preflight precedes rehashing: an oversized item can leave the other item's byte
substitution unexamined. This is UNKNOWN, not clean evidence. Unsupported
predicate, expected value or interpretation remains UNKNOWN. A recognized
binding failure never retains a session PASS from a pure formation CHECKED.

PASS means only the exact formation-certificate predicate passed. FAIL is
failure of that predicate, not the negation of the represented mathematical
claim. UNKNOWN preserves missing evidence, unsupported interpretation and
resource refusal. Wrapper classification and `observations.formation_report`
remain separate; residual obligations persist even before pure checking.

The advertised implementation digest binds an explicit inventory of the fixed
local `formation_mechanism.py`, `formation_checker.py`, `formation_wire.py`
and `network.py` source bytes plus the compiled profile digest. This is not
loaded-code attestation, a complete dependency inventory, or proof of runtime
integrity. Producer code is not trusted by checking. Any selected source change
requires fresh implementation-coordinate evidence.

## 4.1. Stored package and planning integration

The reference catalog contains separate experimental producer, checker and
session-adapter entries. Native serialized inputs remain distinct from the
`VSTD-2` planning surface: the producer accepts subject bytes and emits
certificate bytes; the checker accepts both and returns an unversioned mapping;
the adapter accepts typed native arguments and returns `MechanismDecision`.
Neither the checker mapping nor the adapter acquires a serialized schema merely
by being listed.

Stored packages retain exact source, schema, specification and compiled-profile
bytes. The package, registry and index digests bind those declarations, not
execution or a source interpretation. Exact discovery preserves the selected
rule-profile prerequisite. Detection, planning and readiness do not load retained
source, run a component or close a hole. Even READY means only that supplied
preflight declarations are internally complete and consistent; native input
validation, real execution and post-execution reassessment remain separate.


The adapter entry names an unbound instance method. Its explicit instance
prerequisite requires constructing `FormationPathCertificateMechanism()` and
calling its bound method or registering that instance with a session.
Readiness checks schema membership against the component-wide accepted set,
not a schema-to-input-role map. It therefore cannot establish correct
subject/certificate role pairing; the native checker must enforce those roles.
Neither a resolved prerequisite declaration nor READY establishes that the
instance or inputs were actually inspected.


## 4.2. Retained-silo inspection

`formation_storage.inspect_silo_formation(commit_bytes, evidence, *,
subject_path, certificate_path, profile_path, ground_path)` is a local,
nonexecuting inspector, not a new portable receipt or graph wire format.
Existing census objects retain the subject, certificate and compiled profile.
Their exact artifact kinds are `typed-formation-subject`,
`typed-formation-certificate` and `typed-formation-profile`, with media type
`application/json` and their respective exact schema identifiers. Ground
bytes remain opaque. The selected ground path must be explicitly declared in
the commit and match the subject's ground digest.

The result retains the admitted `commit_digest`, compiled `profile_digest`,
selected path/object-digest `coordinates`, sorted `reason_codes`, every
`residual_obligations` entry, and four distinct observations:

- `coordinate_binding: BOUND | INVALID | UNKNOWN` checks selected census
  bytes, sizes, role declarations, profile and context correspondence.
  BOUND is not certificate validity or ground-origin derivation.
- `snapshot_retention: COMPLETE | INCOMPLETE | INVALID | UNKNOWN` checks
  bytes and sizes for the complete declared census only. It does not establish
  that the denominator is complete, or any existing silo assessment axis.
- `agency_declaration: MATCHED | INVALID | UNKNOWN` checks the exact
  canonical action-set/version/digest declaration and subject context.
  A self-consistent replacement action set is unsupported, not a new ground.
  MATCHED does not prove grounding, reachable-state or composition preservation.
- `formation_report` is freshly recomputed from the digest-checked selected
  subject/certificate bytes, or null when unavailable. It remains separate from
  every outer binding and retention result.

Known invalid observations dominate unavailable ones within each surface.
An unrelated missing census object can leave a checked formation and bound
selected coordinates beside INCOMPLETE retention. A digest-consistent malformed
certificate can coexist with COMPLETE retention and an INVALID formation.
Neither combination is promoted to a silo result. A caller must compare the
returned coordinate against its independently selected commit; this inspector
does not authenticate that selection.

Commit admission is limited to 262,144 bytes, 16 open containers and 8,192 total
containers before recursive decoding. Evidence must be an exact built-in
dictionary with at most 256 entries and ordinary string digest keys; custom
mapping hooks are not invoked. Individual examined census objects are limited
to 4,194,304 bytes, with at most 16,777,216 bytes hashed across distinct census
objects. Non-census evidence is not a retention obligation. Preflight or resource
refusal can leave bytes unexamined; no atomic concurrent-store snapshot or
wall-clock guarantee is claimed. Formation's stricter record bounds still apply.

This interface never extracts or executes artifacts, fetches external ground,
adopts publisher verdicts, or changes an existing assessment. A declared CHECKS
link records a relationship, not proof that checking ran. A fresh graph-consumer
binding and any cross-language implementation require their own contracts and
evidence; neither is supplied by this native inspector.


## 5. Source correspondence and remaining proof sequence

[Hypermath's pinned self-derivation construction](https://github.com/TimeLordRaps/hypermath/blob/819f6856101c91fb3f0f4d25126e2f7329137b53/L3_ordinatics.hm#L348)
requires self-read, retained path extraction, composition identity, justified
steps, preserved trace relations and source boundaries. The present mechanism
supplies only typed finite construction, exact ordered paths and evidence-
retaining quotation. Its syntactic APPLY is not an interpretation of the
source primitive; ordinary digest equality is not source simulation,
congruence or similarity.

[Hypermath's pinned research obligations](https://github.com/TimeLordRaps/hypermath/blob/db141d669491ce6b51d7fe15602c0925398f3154/docs/research/FRACTAL_COMPLETENESS.md)
identify typed reification and observation-preserving reuse as prerequisites,
not a completed completeness theorem.
[Ordinatics' pinned contribution boundaries](https://github.com/TimeLordRaps/ordinatics/blob/1bdeb7593bc043c949ba9ec3912ae148608b967d/paper/ordinal_arithmetic.md)
likewise separate representation from semantic authority and a certificate
calculus from its soundness theorem.

The next obligations remain: a source-to-type interpretation; ground-origin
derivation of the actual deriver and its entry; correct source relation and
boundary preservation; a self-status derivation; admissibility of any cyclic
or infinitary representation; soundness and the explicitly selected completeness
statement with its effectiveness boundary. This finite interpretation does
not redefine the stronger objective or claim to exhaust its objects.

Authority axiom agency remains the ground set of actions allowable across
silos, not the intersection of local permissions. Its preservation requires a
separate exact composition model and evidence over the declared reachable
transitions. No successful formation check establishes permission, knowledge,
awareness, non-inferability, whole-graph safety, or agency preservation.
