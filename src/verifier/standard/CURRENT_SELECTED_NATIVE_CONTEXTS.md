# Separately selected exact native context identity

Verifier Standard (VSTD); directed acyclic graph (DAG); JavaScript Object
Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256); identifier (ID).

Module `verifier.domains.contracts.selected_native_contexts` provides
`assess_selected_native_contexts(bundle_bytes,
expected_dependency_policy_bytes=..., expected_context_policy_bytes=...,
artifact_files=...)` and `recheck_selected_native_contexts_assessment` with expected
mechanism/assessment digests and the same exact inputs. Result schema is
verifier-selected-native-context-assessment-1. This is context identity only;
native replay, compiler closure, full tier/profile conformance remain unevaluated.
Retained certificate DAGv1 global-collection semantics remain unchanged. This
assessment cannot turn a failed retained DAGv1 replay into PASS. A future selected
versioned DAG/context contract is needed to use distinct contexts for issuance.

The context policy has exactly schema_version, mechanism_digest,
compiler_manifest_digest and contexts. The manifest digest must be independently
selected and independently rechecked by the caller; carrying/pinning it alone
does not establish compiler closure. Context rows have node_id, adapter_id,
subject_id, object_kind, object_digest, member_ids, collection_digest. They are
required to equal the actual compiler-derived supported projection externally;
this assessment does not supply authoritative consumer/context census.

Node selections and whole artifact inventory must equal the independently supplied
dependency policy. The artifact inventory is copied once as plain name→immutable
bytes before comparison/source work. Complete sorted file inventory, exact bundle,
dependency/context policy bytes, installed source/adapter mechanism and all row
observations bind the assessment digest. Recheck reconstructs the whole report and
requires canonical byte equality plus independently expected mechanism/output pins.
The rechecker bounds and parses the carried assessment and validates its expected
output commitment before installed-source reconstruction. A contradictory commitment
or available reconstructed byte mismatch remains FAIL/REJECTED. Independently
changed original input or artifact inventory commitments are rejected before source
reconstruction, including during an outage. An over-bound replay input is
UNKNOWN/UNAVAILABLE. If observations or the installed mechanism cannot be reconstructed,
replay_status is UNAVAILABLE, never REPRODUCED;
status preserves an observed FAIL and otherwise remains UNKNOWN. Captured input,
source, mechanism and compiler bindings are retained only when actually available.
Unavailable replay reports distinguish expected_assessment_digest from the current
observed_assessment_digest. A compacted report cannot claim PASS or replayable=true.
Native certificate evidence is subsequently consumed by its actual native checker;
this assessment does not execute native certificates or infer PASS from them.

Only three fixed source-pinned adapters are installed:

- object-record/1: exact OBJECT1.1 request fields object_id,object_kind,record_digest;
  context is the one full record and has no collection commitment.
- typed-collection/1: exact kind-specific native declared-facets subject/record/kind
  and full independently selected namespace collection, not a substituted subset.
- hyper-operand-cone/1: HYPER4.1 exact subject/record and transitive declared operand
  cone, including the root and no unrelated records. Recompute native cone-member
  and collection commitments; preserve each record's ordered operand bytes.

These mappings cite object_facets.py156–188/344–366, typed_facets.py149–163/179–208
and hyper_closure.py75–81/272–320/339–364 plus their exact current native norms.
All known native request/policy shapes are checked using the fixed installed
validators, without request-field heuristics, carried paths or arbitrary callbacks.
GRAPH remains its exact declared kind/element_kind. No GRAPH OBJECT→ENV inference
or per-leaf child certificate is invented. Other adapters/subset/typed graph modes
are unavailable UNKNOWN; known subject/kind/member/collection mismatch FAIL.
Every node_id, including an uncovered node, and every adapter_id must be nonblank
plain text of at most256 characters. Validate them before node indexing, adapter
execution, output copying or row commitment. A malformed identifier is FAIL;
a bounded unsupported adapter remains localized UNKNOWN.

All nodes require a selected context; omitted nodes retain UNKNOWN. Known failed
row identity remains FAIL if another adapter or later resource is unavailable.
Missing native inputs/checker/resource support is UNKNOWN; malformed mandatory
fields or substituted exact bytes are FAIL. Bounds inherit the 8-mebibyte canonical
codec,512 objects/nodes/contexts,1024 artifacts/64 mebibytes and100000 cone operations.
These are finite local identities, not authority, physical observations, hidden
payload semantics, native truth, whole-system safety or publication permission.

Every final assessment, including late FAIL and unavailable diagnostics, is bounded
by the fixed8-mebibyte output ceiling before assessment_digest is computed, including
the digest field's encoded size. If row/uncovered-node observations would exceed it,
discard those arrays, preserve FAIL if any failure was observed and otherwise return
UNKNOWN, and set replayable=false, complete_context_identity=false,
context_observations_status=DISCARDED_OUTPUT_BOUND and
exhausted_resource=assessment_output_bytes. The reason identifies refuted compaction
or unavailable output. Empty discarded arrays do not assert complete coverage.
Exact captured input/mechanism/compiler commitments remain diagnostic bindings;
compaction supplies no authoritative consumer census, native replay or compiler
closure and cannot yield REPRODUCED replay. The fixed bound is not caller-selected.

Explicit recursion/overflow checking-capacity exceptions and cancellation alone
do not refute a semantic predicate. They return UNKNOWN and unavailable replay,
retain no carried PASS as reproduced, and preserve independently observed current
FAIL. Bounded structural ValueError refusal and available exact input/output
commitment contradictions remain FAIL. No exception detail supplies evidence.
