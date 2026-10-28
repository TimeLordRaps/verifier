# Exact selected native consumed-child identity

Verifier Standard (VSTD); directed acyclic graph (DAG); JavaScript Object
Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256).

This additive contract checks an independently selected native child tuple.
It preserves the certificate DAG version 1 and establishes no native truth,
complete consumer census, application completeness or positive polish by itself.
Native replay and complete obligation derivation are separately required.

`assess_native_child_links(bundle_bytes, *, expected_dependency_policy_bytes,
expected_link_policy_bytes, artifact_files)` accepts independently selected
canonical DAG bundle/policy bytes and complete immutable artifact files. The
link policy `verifier-native-child-link-policy-1` has exactly `schema_version`,
`rules_digest`, `coverage_mode`, `consumer_nodes`, `links`, `native_contexts`.
The installed rule-set digest commits `verifier-native-child-link-rules-1`.
Only source-pinned authored selectors run; carried code or extractors never run.

Each link contains exactly `parent_node_id`, `prerequisite_node_id`, `selector`.
Identity is the complete three-field tuple. Both nodes must be independently
selected; each consumer must have a selected link. The coverage mode is
`FULL_SELECTED_CONSUMER_SET`; this concerns only that externally selected list.
It does not prove that every native consumer was discovered. An exhaustive
compiler must independently derive the required consumers before matching files.

Each context has exactly `node_id`, `scope`, `subject_mode`, `objects`, where
supported scope is `FULL_NATIVE_COLLECTION` and mode is `DIRECT_SAME_OBJECT`.
Objects reconstruct exact canonical namespace records. Their collection digest
must equal the selected native request; a smaller DAG projection does not select
a native collection. The selected direct subject kind, identifier, record digest,
profile, objective, proposition and semantic version must agree.

The first authored selector, `sim-response/trajectory/1`, binds current SIM-2.2
to its exact SIM-2.1 trajectory. Parent `trajectory_request`, `trajectory_policy`
and `trajectory_certificate_digest` must equal the selected prerequisite's whole
canonical request, whole policy and immutable certificate digest. The parent's
digest-verified retained evidence must carry those same child certificate bytes
in canonical base64. Matching objective labels, a passing alternative child, or
rehashing a substitute cannot supply this tuple. Exact native request policy
commitments and same-subject record/collection commitments are checked as well.

The initial selector supports replay contract version 1. Unsupported selectors,
typed GRAPH subject selectors, collection subset transport, missing retained
bytes/context and source or resource unavailability remain localized UNKNOWN.
Inspected tuple/byte/subject substitution, malformed selected records and dangling
selected links FAIL. The selected parent/prerequisite edge pair is inspected
before unsupported-selector availability; an unsupported selector's operand role
is not presumed. The authored selector's exact null-role edge is then inspected
before replay-contract availability. For an authored selector, independently
retained request, policy, subject and consumed-certificate-digest tuple fields are
compared before requesting certificate bytes. Each available certificate and
parent witness is inspected even when a sibling certificate is absent; a
digest-verified retained child mismatch refutes without missing external bytes.
These checks do not establish native replay or completeness. Known FAIL remains
FAIL when other links are UNKNOWN.
Native PASS is independently obtained through the installed current-object route;
this identity assessment never invents it or reruns a selected program.

Transport and structure retain the DAG decoder bounds: 8 mebibytes per record,
512 nodes/objects/profiles, 4096 links, depth 48, 100000 parsed values and
4096-bit integers. Files are captured before callbacks, at most 1024 files and
64 mebibytes in total. One mebibyte is 1048576 bytes. Over-capacity input stays
UNKNOWN and is not hashed as an admitted bounded transport. Paths are snapshot
relative. Canonical base64 is required; no locator or filesystem read is executed
from candidate paths. The host supplies retained bytes separately.

`verifier-native-child-link-assessment-1` records per-link outcomes, blockers,
source/mechanism bindings and exact bundle, dependency-policy, link-policy and
artifact-inventory commitments. Its assessment digest commits the canonical
report before that digest field is added. Missing input/source bindings stay
UNKNOWN and cannot support a positive binding claim. Identical reason codes for
different admitted inputs retain different bound assessments.

`recheck_native_child_links_assessment` requires externally selected mechanism
and assessment digests plus all original inputs. It reconstructs the entire
assessment and compares canonical bytes. Changed request, policy, certificate,
context, artifact set, authored rule or installed source invalidates reproduction.
A reproduced identity PASS does not discharge native replay, authority, public
checkability, full objective closure, model correctness or overall safety.
