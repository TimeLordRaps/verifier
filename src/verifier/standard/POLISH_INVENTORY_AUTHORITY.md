# Operator admission of a finite selected objective inventory

> **Acronyms:** JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
> Unicode Transformation Format, 8-bit (UTF-8);
> hash-based message authentication code (HMAC); Verifier Standard (VSTD).

**Status:** experimental prerequisite, separate from the retained polish assessment
and selected-inventory contracts. Its PASS establishes configured operator admission
of an exact finite application profile and its derived applicability decisions.
Normative inventory completeness, native objective truth, complete meta-tier
conformance, public proof and positive polished issuance remain unestablished.

## Proposition and authority boundary

The selected-inventory mechanism first independently replays the complete supplied
plan against the exact application profile, collection and inventory request.
An unresolved rule, uncovered kind or exhausted admitted capacity cannot receive
authority PASS. A known omitted, extra or substituted obligation yields FAIL.

For a fully derived finite plan, the retained level-8 governance engine checks
a distinct `ADMIT_SELECTED_POLISH_INVENTORY` operation. Its signatures bind the exact
subject digest, submitter, observer, purpose, jurisdiction, invocation and timestamp.
The configured quorum, distinct voting actors, vetoes, expiry, independent clock and
fresh signed revocation/consumption view retain that engine's existing meanings.
The selected submitter cannot appear among the approving actor identifiers.
This is finite record separation; it establishes no independent human identities.
When that complete derived plan contains an unresolved applicability rule, an
authenticated exact-subject denial still yields aggregate FAIL. An approving
decision preserves aggregate and profile/applicability authority UNKNOWN until
those rules resolve. A capacity diagnostic or uncovered kind has no admitted
complete subject here and does not dispatch an authority check.

The caller supplies the governance policy and secret roots through an independently
trusted operator channel. Its source, institutional authority and key custody are
assumptions. Every holder of the symmetric keys can create the signed statements.
No public-key authentication, real-world authority or independent public proof is
established. `OBJECT-8.1` retains its separate `NAMESPACE_ADMIT` action; its certificate
cannot replace the signed inventory decision. No current numbered objective is
registered or renumbered by this prerequisite.

## Exact subject and externally selected request

Inputs are immutable UTF-8 JSON bytes. Duplicate keys and nonfinite numbers refuse
admission. Input type and fixed byte limits precede hashing, decoding and native work.
The caller separately supplies `plan_bytes`, `profile_bytes`, `collection_bytes` and
`inventory_request_bytes` under [POLISH_INVENTORY.md](POLISH_INVENTORY.md).

The derived `verifier-polish-inventory-authority-subject-1` has exactly:

- `schema_version`, `operation` and the selected `authority_mechanism_digest`;
- the reproduced `inventory_assessment_digest`;
- `input_digests` binding the exact plan, profile, collection and inventory-request bytes;
- native `root_id`, `profile_digest` and `collection_digest`;
- `admitted_inapplicability`, every exact NOT_APPLICABLE requirement in native plan order.

The subject digest is `sha256:` followed by the lowercase SHA-256 of its canonical
JSON bytes. The governance context uses the same 64 hexadecimal digits as its
`artifact_digest`, `object_name=OBJECT` and the distinct operation above. The subject
includes the installed native and authority mechanisms through its commitments.
Approving this subject admits the selected finite profile and every listed derived
inapplicability decision. This cannot discharge an obligation omitted from the
independently selected profile or prove that profile normatively complete.

`authority_request_bytes` selects `verifier-polish-inventory-authority-request-1`
with exactly `schema_version`, `mechanism_digest`, `subject_digest`, `policy_digest`,
`actor_id`, `observer_id`, `purpose`, `timestamp`, `jurisdiction`, `invocation_id` and
`admitted_inapplicability`. The final list must equal the entire derived subject list;
an empty list admits no inapplicability, and an extra or missing row refuses admission.
The public governance `policy_digest` is 64 lowercase hexadecimal digits. It supplies
no secret root. Identifiers are nonblank plain strings of at most 512 characters.
Timestamp and the external evaluation clock are plain integer Unix seconds in
the interval from zero through 2^63 minus one; boolean and floating values refuse.
The independent clock may be unavailable, preserving UNKNOWN.

`authority_evidence_bytes` has exactly `decisions` and `status`, using the existing
signed governance records. Decisions form a list of at most 256 entries; absent
evidence is represented by no decisions and an unavailable status. No candidate
selects the policy, roots or clock. No private key is retained in the output.

## Bounds, outputs and replay

Fixed limits are 8 mebibytes for a plan, 4 for a profile, 32 for a collection,
1 for each inventory request, authority request and authority evidence, and
4 for an assessment. One mebibyte is 1,048,576 bytes. Returned native and governance
evidence is captured as plain data before serialization/replay: at most 50,000
nodes, depth 64, 32,768 entries per container, 4 mebibytes of UTF-8 text and 4,096
bits per integer. Counts and structural budgets are dimensionless.

Direct experimental imports expose `build_inventory_authority_subject`,
`assess_inventory_authority` and `recheck_inventory_authority` from
`verifier.runtime.polish_inventory_authority`. The builder replays the independently
selected native plan and returns the exact canonical signing-subject bytes, bounded
to 1 mebibyte. It accepts a fully derived plan containing unresolved rules so an
operator can deny it; it grants no authority and produces no signature. A known
inventory contradiction raises `ValueError`; capacity exhaustion, uncovered kinds
or unavailable mechanism source raise `InventoryAuthorityUnavailable`. A subject
exceeding its fixed output ceiling refuses. The eventual authority request must
separately fit its byte bound with all identifiers and scope fields included.
The assessment identifier is `verifier-polish-inventory-authority-assessment-1`.
It retains exact input digests, mechanism, selected policy commitment, evaluation
time, native inventory assessment, scoped authority statuses, subject digest,
inapplicability count and the key-free governance receipt. The assessment digest
binds canonical output before that field is added; it is an unsigned local result.

Actual authority refusal yields aggregate FAIL; missing policy, quorum, signed
status, fresh status or independent clock retains UNKNOWN. Native FAIL dominates
and does not dispatch an authority check. Native UNKNOWN cannot become authority
PASS. Malformed, over-bound or substituted input yields FAIL. Mechanism source
unavailability yields UNKNOWN. A replayable diagnostic binds every admitted exact
input; transport and source failures remain nonreplayable.

The rechecker independently recomputes both retained mechanisms with externally
selected inputs and current roots, then compares canonical assessment bytes.
`verifier-polish-inventory-authority-replay-1` reports REPRODUCED or REJECTED and
retains the scoped computational outcome. Rehashing promoted flags, replacing
selection bytes or rotating trusted keys cannot reproduce an earlier PASS.

Every assessment retains `polished=false`, `objective_inventory_closure=NOT_ESTABLISHED`,
`native_objective_truth=NOT_EVALUATED`, `public_checkability=NOT_ESTABLISHED` and
`invocation_consumption=NOT_PERFORMED`. Privacy, consent, actual enforcement,
public disclosure, publication, execution and spending require their own qualified
contracts. This primitive changes none of those interfaces or the existing polish
versions. It has no command-line entry point, network action or persistent state.
