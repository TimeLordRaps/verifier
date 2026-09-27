# Level 6 disclosure helper review

Verifier Standard (VSTD) level 6 bounds disclosure independently of the computational
verdicts at computational tiers 1–5. `[OBJECT]-6.m` names an internal grounding
certificate in the positive-numbered privacy meta-tier. Its current disclosure-only
projection is represented by per-object rows in
[`DOMAIN_OBLIGATIONS.md`](../src/verifier/standard/DOMAIN_OBLIGATIONS.md).
Those normative rows remain **UNKNOWN** with no registered mechanism. The existing
`verifier.privacy` helper package is a separate experimental surface; passing its
tests does not mechanize every object-specific disclosure or composition obligation.

## Repaired boundaries

- Every emitted top-level certificate field must appear in `disclosed_fields` and
  have an admitting `DisclosureBound`. There is no structural-field exemption:
  `request`, `result`, `results`, and tier containers can contain private data too.
  A bound covers the whole field value; nested-path policy is unsupported.
- Conditions are conjunctive matches over caller-established `actor_id`, `role`,
  `purpose`, and credential membership. Unsupported or malformed conditions deny
  admission. Role and identity alternatives inside one bound retain union semantics;
  separate bounds remain alternative grants.
- A native `verifier-domain-certification-1` certificate must be emitted unchanged
  or refused. Withholding required evidence without a selective proof invalidates
  native reproduction; retaining the text `PASS` would not preserve its evidence.
  Commitments and the local assessment receipt stay outside the native certificate.
- Generic redaction that changes a carried computational verdict refuses emission.
  Existing verdicts are not recomputed or upgraded by the privacy helper.
- An unconfigured contextual transmission policy denies admission. Listed risky
  domain joins also detect native `request.domain`; a claimed auditor role cannot
  waive a detected join. An unmatched rule is reported as an incomplete screen,
  with composition safety **UNKNOWN**, rather than proof of privacy.
- The differential privacy accountant rejects nonfinite, negative, or inconsistent
  state before mutation. Epsilon and delta are dimensionless; delta lies in `[0, 1]`.
  Accounting for declared expenditure does not prove the emission mechanism private.

## Reproduction and scope

On 2026-09-26, the adversarial boundary file was run against the unchanged helper:
**22 failed, 4 passed**. After repairs, both privacy files reported **37 passed,
no skips**, under Python 3.12.8 and pytest 8.3.5 with pytest-timeout 2.4.0:

```text
python -u -m pytest tests/test_privacy_boundaries.py tests/test_privacy_engine.py -vv -s --durations=10 --timeout=60 -o asyncio_default_fixture_loop_scope=function
```

The runner used the local `src` import path, a 180-second overall subprocess-tree
deadline, streamed output, and observed process termination. The final pytest run
took 0.64 seconds. A real simulation (SIM) domain specimen at depth 4 independently
passes the native rechecker before and after authorized emission. Denying its
`request`, `result`, or `evidence` refuses emission and leaves the input unchanged.
Whole-repository integration and release gates remain separate integrator checks.

The older positive fixtures now declare structural fields and their bounds explicitly:
normative row 6.2 says every emitted field requires a bound. Their former implicit
public bypass contradicted that requirement. The canonical-evidence redaction test
now requires refusal because the native strict schema and rechecker require complete
evidence; changing a receipt label cannot restore its proof.

## Remaining proof and integration boundaries

### Input-bound local replay

The experimental assessment receipt now binds the full input certificate,
disclosure surface, every bound (including repeated conjunctive conditions),
observer/context, all co-emitted certificates, composition rules, and the five
shipped helper source files. The prior receipt could remain identical after
changing disclosed values or the policy; retained regression counterexamples
demonstrate that failure. Non-finite or non-JavaScript Object Notation (JSON)
input is refused.

`EmissionEvaluator.recheck_emission` takes the expected inputs separately from
the result, reruns the helper and compares the complete canonical result. It
rejects substituted projections, rehashed forged receipts, changed mechanisms
and old unbound receipts. It is local reproduction, not an independently
implemented checker. Existing computational verdicts and the native certificate
remain unchanged; native certificate validation still requires its own rechecker.

The new bindings are unsalted digests, not hiding commitments. They can disclose
equality or enable guesses about low-entropy inputs. Keep the assessment sidecar
private unless a separate disclosure policy admits it. Source-file binding is
not loaded-code attestation, authenticity or protection from a hostile host.
Observer authentication and general composition safety remain unestablished;
this increment does not register a normative level 6 mechanism.

Admission containers must be sequences of strings, so a role, credential or field
name cannot be admitted by substring membership in a malformed string. Evaluation
uses private input snapshots and refuses composition-time mutation or a non-Boolean
admission result. Only the bundled data records, declarative bounds and composition
evaluator are supported; arbitrary subclasses or callback predicates are refused.
Snapshots reconstruct exact built-in containers and bundled records without invoking
caller-defined copy or serialization hooks. The same restriction applies to returned
result and commitment records before replay compares their contents.
Custom declarative join rules remain supported and are included in the binding.
These guards preserve valid explicit observer grants and conjunctive credentials;
they do not authenticate those declarations or treat an empty rule set as proof of
composition safety.

### Outstanding mechanisms

`ObserverParty` contains caller-supplied facts, not authenticated credentials or an
established observer model. The receipt explicitly reports observer authentication
and certificate validation as `NOT_CHECKED`. A host must establish those facts and
rerun the native certificate checker under its own external request and policy.

Unsalted field digests expose guesses about low-entropy private values. The retained
`SelectiveMerkleDisclosure` compatibility helper computes a sorted digest aggregate,
not a Merkle-path proof, hiding commitment, or zero-knowledge proof. No cryptographic
privacy is claimed; the assessment records `commitment_privacy: NOT_ESTABLISHED`.
The receipt and commitment sidecar can themselves contain identifying metadata and
must not be publicly emitted merely because a certificate was admitted.

The join screen covers a small explicit pair list, not same-object overlap,
longitudinal reconstruction, indirect identification, or general inference. The
identifier partition is top-level name suppression, not certified de-identification.
Budget state is local and mutable, with no persistence or concurrent-writer guarantee.

These limits leave normative level 6 conformance **UNKNOWN**. Registered emission
mechanisms need an authenticated observer model, policy/evidence binding, bounded
object-specific composition analysis, and a supported selective-proof format before
a host may elevate that status. Consent and governance are separate obligations;
neither follows from this helper's disclosure admission or an unchanged `PASS`.
