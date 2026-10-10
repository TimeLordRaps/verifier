# Core obligation candidate union format

Status: private candidate format. It does not define release authority or semantic completeness.

## Coordinate rule

Each contribution carries two separate coordinates:

- `producer_source_coordinate`: the exact source state from which that contribution was derived.
- `consumer_source_coordinate`: the exact Verifier state selected to consume and qualify it.

`dependency_binding` contains canonical Secure Hash Algorithm 256-bit (SHA-256) digests of both coordinates, the exact candidate input bytes, and separately selected package and mechanism digests. A shared name, commit fragment, object kind, member identifier (ID), or schema string is never treated as coordinate equivalence.

## Contribution

```json
{
  "schema_version": "verifier-core-obligation-contribution-candidate-1",
  "candidate_status": "CANDIDATE",
  "completeness": "UNKNOWN",
  "producer_source_coordinate": {},
  "consumer_source_coordinate": {},
  "family_id": "producer-scoped-family",
  "source_map_digest": "sha256:<64 lowercase hex>",
  "dependency_binding": {
    "status": "UNKNOWN",
    "producer_source_coordinate_digest": "sha256:<canonical coordinate digest>",
    "consumer_source_coordinate_digest": "sha256:<canonical coordinate digest>",
    "candidate_input_digest": "sha256:<exact input bytes>",
    "package_digest": null,
    "mechanism_digest": null
  },
  "rows": []
}
```

Every row binds an exact source uniform resource identifier (URI) and digest, claim text and digest, object kind, core tier 1 through 9, member ID, acceptance mechanism, evidence state, and uncovered action. Producer reports may be retained under `current_evidence.reported`; they do not change `current_evidence.status` from `UNKNOWN` without independently bound evidence.

When two semantic families reuse a coordinate spelling, the canonical union `member_id` is `<semantic-family>::<coordinate>`. The exact original coordinate and semantic family remain in `current_evidence.reported`. This prevents legacy and current meanings from becoming aliases while retaining both source identities.

## Expected member authority

Expected families and members are supplied separately with schema `verifier-core-obligation-union-authority-candidate-1`. Its bytes require an independently selected digest. It names the consumer coordinate and, for every family, the producer coordinate, selected dependency binding, source map digest, and required rows.

The authority document also remains `candidate_status=CANDIDATE` and `completeness=UNKNOWN`. This permits structural omission checks without claiming that the authority itself proves the final semantic denominator.

## Validator results

The validator detects:

- missing family, tier, or member relative to the selected authority;
- duplicate family, expected member, contributed member, or evidence identity;
- overlapping family ownership;
- foreign producer or consumer coordinates;
- source map, source, claim, dependency, or evidence binding mismatches;
- invalid core tiers, unrecognized mechanism kinds, missing source bytes, incomplete host dependency selection, and unsupported completeness or PASS assertions.

Even a structurally clean union returns `semantic_completeness=UNKNOWN` and `release_admissible=false`. Skill text, registration, importability, test names, or route presence confer no authority or runtime credit.

## Installed-route denominator

The current nine-core progression mechanism separately enumerates the ordinary
installed route registry. That source-derived inventory contains exactly 26 object
kinds by nine core tiers, or 234 family cells, and 408 distinct registered route
memberships. Every cell has at least one installed replay route. Its `PASS` closes
only the registry enumeration: it does not assert that the routes exhaust normative
meaning, are applicable to a concrete application, have selected certificate
instances, or passed replay.

For the retained structural profile, one concrete `VERIFIER` root has exactly two
tier-1 obligation identities: `OBJECT-1.1` and `VERIFIER-1.1`. These are instantiated
by `(object_id, semantic_version, coordinate)`. Native credit additionally requires
the exact collection, request, checker policy, certificate and retained evidence for
both identities. The 27 definitions and 52 memberships in the all-kind template
census do not become 52 instances for one root.

Candidate adapters reject duplicate JavaScript Object Notation (JSON) object keys and non-finite numeric
extensions. Exact input bytes remain digest-bound, but an ambiguous decoder result
cannot become a contribution under a last-key-wins interpretation.

## Repository integration boundary

The repository integrates this validator through exactly these files:

- `src/verifier/runtime/core_obligation_union.py`
- `tests/test_core_obligation_union.py`
- `src/verifier/standard/CORE_OBLIGATION_UNION.md`

The installed application-authority mechanism invokes the validator over separately
selected authority and contribution bytes. Integration supplies no full normative
expected-member denominator, semantic-completeness evidence, human acceptance, or
release authority. This is compatible with the exact installed-route and retained
structural denominators above; those narrower denominators do not authenticate the
union authority's completeness.
