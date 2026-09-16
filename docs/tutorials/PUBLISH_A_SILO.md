# Publish a verification-artifact silo

> **Acronyms:** command-line interface (CLI); comma-separated values (CSV);
> identifier (ID); JavaScript Object Notation (JSON).

A Verifier Standard (VSTD) publisher silo is a content-addressed store of exact bytes plus
one signed commit that declares what the publisher considers a *complete* snapshot: which
artifacts are ground, which are derived from which by what mechanism, what was deliberately
excluded, and what remains unestablished. Another party can rebuild the whole thing byte for
byte and re-derive the same assessment.

The artifact-network surface is **experimental**. Its wire identifiers carry `0.1` schema
versions and may change. This tutorial builds a silo from scratch; for a fixed, checked-in
specimen to test another runtime against, use
[the artifact-network fixture](../../examples/artifact-network/README.md).

Retained artifacts are never executed by any command here.

## Set up

```bash
python -m pip install "verifier-standard[seal]==1.4.0"
openssl genpkey -algorithm Ed25519 -out publisher-private.pem
```

Create four small files to publish — a method statement, a measurement, the mechanism that
consumes it, and the derived result:

```bash
printf 'Scores are the mean of three runs; variance is not recorded.\n' > METHOD.md
printf 'sample,score\na,0.91\nb,0.88\n' > measurements.csv
printf 'print("recomputed")\n' > recompute.py
printf '{"mean_score": 0.895, "samples": 2}\n' > summary.json
```

Path names are restricted to `A-Z`, `a-z`, `0-9`, `_`, `.`, and `-`, so that a silo
transfers between filesystems without renaming.

## 1. Initialize the silo

```bash
vstd network init silo \
  --private-key publisher-private.pem \
  --display-name "Example Publisher" \
  --description "Tutorial silo."
```

The report is `INITIALIZED` with a `publisher_id` of the form `publisher:sha256:<digest>`.
The publisher identity is *derived from the key*, not assigned by a registry — there is
nothing to sign up for and no authority to ask. That also means the identity says nothing
about who you are; it says only that one key controls this silo.

## 2. Retain the bytes

```bash
vstd network object add silo METHOD.md        --media-type text/markdown    --artifact-kind method-statement
vstd network object add silo measurements.csv --media-type text/csv         --artifact-kind measurement
vstd network object add silo recompute.py     --media-type text/x-python    --artifact-kind mechanism
vstd network object add silo summary.json     --media-type application/json --artifact-kind derived-summary
```

Each call prints an object record: `object_digest`, `size_bytes`, the media type and
artifact kind you declared, and `declared_schema_id`, which defaults to `NOT_DECLARED`.
The store retains bytes without interpreting them. `--artifact-kind` is your declaration
about the bytes; nothing validates that the declaration is apt.

## 3. Write the commit manifest

The manifest is where the actual claims live. Save it as `commit.json`, substituting your
own `publisher_id` and the four `object_digest` values printed in step 2:

```json
{
  "schema_version": "VSTD-SILO-COMMIT-0.1",
  "publisher_id": "publisher:sha256:c18e5b101b7a60244015ffdd1d920cd45c503106cb11cc90804859d30066b48c",
  "parents": [],
  "census": [
    {
      "path": "METHOD.md",
      "object": {
        "schema_version": "VSTD-OBJECT-0.1",
        "object_digest": "sha256:2a0bb64a6e676489cd2ede85dbffe895790659601d5cb4064d89d262bba52be1",
        "size_bytes": 61,
        "media_type": "text/markdown",
        "artifact_kind": "method-statement",
        "declared_schema_id": "NOT_DECLARED"
      },
      "necessity": "NECESSARY"
    },
    {
      "path": "measurements.csv",
      "object": {
        "schema_version": "VSTD-OBJECT-0.1",
        "object_digest": "sha256:c5c79de27e13422d4a115dba9df0be2feb80aa8d17ceef78e9596f1218df2d29",
        "size_bytes": 27,
        "media_type": "text/csv",
        "artifact_kind": "measurement",
        "declared_schema_id": "NOT_DECLARED"
      },
      "necessity": "NECESSARY"
    },
    {
      "path": "recompute.py",
      "object": {
        "schema_version": "VSTD-OBJECT-0.1",
        "object_digest": "sha256:f17c3e63be1bea698e4f149b3fcfd2323f9563a5b3489c776053cb45afde5763",
        "size_bytes": 43,
        "media_type": "text/x-python",
        "artifact_kind": "mechanism",
        "declared_schema_id": "NOT_DECLARED"
      },
      "necessity": "NECESSARY"
    },
    {
      "path": "summary.json",
      "object": {
        "schema_version": "VSTD-OBJECT-0.1",
        "object_digest": "sha256:4dcf92930e4421a9f9cbf3ce5073ccf26272d8426875ec590c1f7700b96acb60",
        "size_bytes": 36,
        "media_type": "application/json",
        "artifact_kind": "derived-summary",
        "declared_schema_id": "NOT_DECLARED"
      },
      "necessity": "NECESSARY"
    }
  ],
  "ground_paths": ["METHOD.md", "measurements.csv"],
  "derivations": [
    {
      "target_path": "summary.json",
      "premise_paths": ["measurements.csv"],
      "mechanism_path": "recompute.py",
      "relation_strength": "DERIVES"
    }
  ],
  "relations": [],
  "residual_obligations": [
    "measurement provenance upstream of measurements.csv is not retained here",
    "no independent party has recomputed summary.json from measurements.csv"
  ],
  "exclusions": ["per-run variance data was not retained"],
  "completeness_kind": "SILO_CENSUS",
  "coverage_universe": [],
  "authority_axiom_agency": [
    "CHALLENGE_WITH_COUNTEREVIDENCE",
    "EXIT_COMPOSITION",
    "EXPORT_ACCESSIBLE_SILO",
    "FORK_DERIVATION",
    "INDEPENDENTLY_INSPECT_ACCESSIBLE_ARTIFACTS",
    "PRESERVE_CONFLICT",
    "PRESERVE_UNKNOWN",
    "SELECT_TRUST_ROOTS",
    "WITHDRAW_OWN_AUTHORIZATION"
  ],
  "authority_axiom_agency_version": "VSTD-AUTHORITY-AXIOM-AGENCY-0.1",
  "authority_axiom_agency_digest": "sha256:41e3a27c8322874bb5634890d33cff2a9170f2906c83d45d9c7968836d7e482c",
  "authority_model_path": null,
  "self_derivation_record": {
    "subject_path": "summary.json",
    "ground_paths": ["measurements.csv"],
    "mechanism_path": "recompute.py",
    "retained_path": ["measurements.csv", "summary.json"],
    "relation_strength": "DERIVES",
    "ground_self": false,
    "derivation_reflexivity": false,
    "reflexion_identity": false,
    "deriver_cycle_closed": false,
    "ground_self_evidence_path": "METHOD.md",
    "derivation_reflexivity_evidence_path": "METHOD.md",
    "reflexion_identity_evidence_path": "METHOD.md",
    "deriver_cycle_closure_evidence_path": "METHOD.md",
    "residual_obligations": ["this silo does not claim a closed deriver cycle"]
  },
  "created_at": "2026-09-13T00:00:00Z"
}
```

Four parts of that manifest deserve attention.

**`census` is a denominator, not an inventory.** Completeness is meaningful only relative to
a stated universe, so the commit must say which paths it is claiming completeness *over*,
and mark each `NECESSARY` or `DISPENSABLE`. Every path named anywhere else in the
manifest — ground, mechanism, premise, target, evidence — must be a census member, or the
commit is refused.

**`exclusions` and `residual_obligations` are first-class fields.** They are where a
publisher records what was left out and what is not yet established. A silo that declares
nothing open is making a stronger claim, not a tidier one.

**`authority_axiom_agency` is a floor, not a grant.** The nine actions are the
non-negotiable capacities the model requires every silo to leave available — inspect,
challenge, fork, exit composition, preserve `UNKNOWN`, preserve conflict, withdraw your own
authorization, select your own trust roots, export. Its digest is taken over the sorted
action set; recompute it with
`verifier.interoperability.network.authority_axiom_agency_digest()`.

**`self_derivation_record` is `false` on every flag here on purpose.** A silo asserting a
closed deriver cycle would have to carry the evidence for it. This one does not, so it says
so, and names the obligation that remains.

### Set-like members must already be sorted

The decoder requires the wire record to arrive canonical rather than normalizing it for you,
so that two independent implementations accept exactly the same bytes. If
`residual_obligations`, `census`, or `derivations` are out of canonical order, the commit
fails with:

```
[FAIL] silo commit is not in canonical member order
```

Sort set-like arrays; sort `census` by `path` and `derivations` by `target_path`.

## 4. Sign the commit

```bash
vstd network commit silo commit.json \
  --private-key publisher-private.pem \
  --issued-at 2026-09-13T00:00:00Z
```

The report is `COMMITTED`, with a `commit_digest`, a `head_digest`, an
`assessment_receipt_digest` — and an assessment that is deliberately unflattering:

```json
"completeness": "INCOMPLETE",
"derivation_closure": "OPEN",
"reconstructibility": "COMPLETE",
"self_derivability": "NOT_ESTABLISHED",
"silo_grounding": "UNKNOWN",
"authority_axiom_agency": "UNKNOWN"
```

The commit succeeded and the assessment is still negative on five of six axes. Those are
independent questions, and the runtime answers each on its own evidence rather than
collapsing them into a single verdict. The `reasons` array names every one, including
`necessary census paths lack a ground-reachable derivation: recompute.py, summary.json` —
the mechanism itself has no declared derivation, and so neither does the summary once the
mechanism is required to be reachable from ground.

A publisher improves that assessment by supplying evidence — an authority model, a
`coverage_universe` that exactly enumerates the census boundary, derivations that close —
never by editing the verdict.

## 5. Inspect, export, and rebuild

The commit and head records are stored under their own digests. Using the values printed in
step 4:

```bash
COMMIT=silo/records/commits/<commit_digest>.json
HEAD=silo/records/heads/<head_digest>.json

vstd network inspect silo "$COMMIT" --head "$HEAD"
```

Inspection re-derives the assessment from the store and adds `head_signature: VALID`.

Export the snapshot, then rebuild it somewhere else:

```bash
vstd network export silo "$COMMIT" "$HEAD" export
vstd network rebuild export rebuilt
```

Both print the same four digests and `schema_version: VSTD-SILO-EXPORT-0.1`. The export
directory holds `export.json`, the retained objects under `objects/sha256/`, and the commit,
head, assessment, and publisher records. `clone` does the same from a local export or a
bounded Hypertext Transfer Protocol Secure (HTTPS) endpoint:

```bash
vstd network clone export cloned
```

Every destination must be absent before the command runs. Remove generated directories
before rerunning.

## 6. Watch it fail

Change one retained byte in the export and rebuild again:

```bash
cp -r export tampered
printf 'sample,score\na,0.99\nb,0.88\n' > tampered/objects/sha256/<measurements digest>
vstd network rebuild tampered rebuilt-tampered
```

```
[FAIL] export does not reconstruct its signed complete byte closure
```

The command exits `1`. The head signature covers the commit, the commit names every object
by digest, and the rebuild recomputes all of it — so one altered byte anywhere in the
closure is caught, whichever file it was in.

Comparing two commits is a separate, weaker operation:

```bash
vstd network diff "$COMMIT" "$COMMIT"
```

Self-diff reports empty `added`, `changed`, and `removed`, with its boundary stated inline:
*digest and path differences do not establish a semantic contradiction.* A diff tells you
the bytes moved; it does not tell you the claims disagree.

## 7. Composition needs a composite

```bash
vstd network compose --silo silo "$COMMIT"
```

With only member silos supplied, the result is `NOT_ADMISSIBLE`, and
`composition_completeness`, `composition_member_binding`, and
`local_authority_addition_preservation` are all `UNKNOWN`. That is the designed answer, not
a failure: a composite is itself an independently assessed silo containing the member
commits, bridges, adapters, relations, and policies, and none was supplied. Member
completeness does not imply composition completeness. Pass `--composite-store` and
`--composite-commit` to assess a real composite.

## What a silo establishes

| Established | Not established |
|---|---|
| exact retained bytes and their closure | that any artifact is correct |
| that one key signed this snapshot | who controls that key |
| the declared census, ground, and derivations | that those declarations are apt |
| byte-identical rebuild by another party | that another party observed the original |
| each axis the assessment reports positively | anything the assessment marks `UNKNOWN` |

`register` and `push` extend this toward a hub: `register` enrolls an exported publisher
with Claim Garden and writes a credential to a local file, and `push` emits an **inert**
request description by default — it performs no transport unless `--transmit` is given, and
even then it submits a candidate for human review rather than publishing.

## Next

- [Seal an artifact and detect a change](SEAL_AN_ARTIFACT.md) covers the single-bundle
  freeze, seal, and thaw cycle this store is built on.
- [`docs/ARTIFACT_NETWORK.md`](../ARTIFACT_NETWORK.md) is the mechanism's own documentation.
- [`standard/FINITE_AUTHORITY_COMPOSITION.md`](../../standard/FINITE_AUTHORITY_COMPOSITION.md)
  is the normative composition text.
- [`docs/COMPONENT_HUB.md`](../COMPONENT_HUB.md) describes the hub these commands target.
