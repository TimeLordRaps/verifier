# Experimental portable formation receipts

Verifier Standard (VSTD) receipts retain deterministic finite-formation
inspection, not source self-derivation, completeness, agency preservation or
historical execution. JavaScript Object Notation (JSON) uses the network
canonical codec: Unicode Transformation Format, 8-bit (UTF-8), Unicode
Normalization Form C, lowercase snake_case keys, sorted keys, no duplicate
fields, no extra whitespace, no surrogate code points, and nonnegative integers
at most 9,007,199,254,740,991. Secure Hash Algorithm 256-bit (SHA-256) digests are
`sha256:` followed by exactly 64 lowercase hexadecimal digits. All counts are
dimensionless; size limits measure bytes.

## 1. Selection and receipt

The selection has exactly:

```text
schema_version: VSTD-SILO-FORMATION-SELECTION-0.1
commit_digest: digest
subject_path: portable path
certificate_path: portable path
profile_path: portable path
ground_path: portable path
```

Paths use the existing network logical-path grammar: 1 through 240 characters,
relative slash-separated components containing only letters, digits, underscore,
hyphen and dot; no empty, dot, dot-dot or trailing-dot component, drive prefix,
or reserved Windows device basename. Selection admission does not establish that
the selected paths exist or have correct roles. Equal selectors are not silently
deduplicated; the inspector checks each role.

The receipt has exactly:

```text
schema_version: VSTD-SILO-FORMATION-RECEIPT-0.1
selection: complete selection object
selection_digest: digest of exact canonical selection bytes
rule_profile_digest: compiled formation rule-profile digest
observed_evidence: ordered array of observations
inspection: exact native retained-silo inspection object
```

Each observation has exactly `requested_digest`, `observed_digest` and
`size_bytes`. Requested digests are strictly ascending and unique. The observed
array has at most 256 entries, each size at most 4,194,304 bytes, with sum at
most 16,777,216 bytes. Sizes are nonnegative integers, never booleans. The observed
digest and size identify the actual retained bytes, even when those bytes do
not match the requested digest. Such substitutions remain negative evidence.
There is no observation for a missing object. One observation covers a distinct
digest even if several census paths alias it; every declared census size still
gets checked independently. The commit itself is bound by the selection, not
duplicated in this evidence array.

The builder first validates and captures the complete supplied evidence
dictionary, then selects present distinct census digests in ascending order.
Only selected census objects become observations or inspector inputs.
Non-census extras are ignored after complete type and budget admission; changing
only admitted extras does not change the receipt. They supply no evidence and
are not claimed to have been examined by formation inspection.
For a bounded malformed or unsupported commit whose census cannot be admitted,
the observations and inspector evidence are empty. The exact commit bytes still
bind the native INVALID or UNKNOWN inspection. No census denominator or
examination of otherwise supplied objects is claimed.

The receipt contains no timestamp, signer, executable code, provider diagnostic,
runtime identity or overall success field. Its digest identifies the entire
canonical semantic record, not authenticity, implementation integrity,
independence, permission or execution. It is not a graph selection receipt and
cannot upgrade any existing silo or graph assessment axis.

## 2. Full carried inspection grammar

The inspection has exactly `commit_digest`, `profile_digest`, `coordinates`,
`coordinate_binding`, `snapshot_retention`, `agency_declaration`,
`formation_report`, `reason_codes` and `residual_obligations`.

- `commit_digest` is a digest or null; `profile_digest` is a digest.
- `coordinates` is either empty or has exactly subject, certificate, profile
  and ground. Each coordinate has exactly `path` (portable path or null) and
  `object_digest` (digest or null). Empty coordinates require null commit
  digest and null formation report; populated coordinates require a digest.
- `coordinate_binding`: BOUND, INVALID or UNKNOWN.
- `snapshot_retention`: COMPLETE, INCOMPLETE, INVALID or UNKNOWN.
- `agency_declaration`: MATCHED, INVALID or UNKNOWN.
- `formation_report`: null or the full formation report below.
- `reason_codes`: sorted unique members of the closed inspection-reason
  vocabulary below.
- `residual_obligations`: exactly the eight fixed strings in section 3,
  in that order.

The formation report has exactly `status`, `subject_digest`,
`profile_digest`, `root`, `observation`, `reason_codes` and
`residual_obligations`. Status is CHECKED, INVALID or UNKNOWN. Subject digest
and root are either both null or a digest and integer in 0 through 1,023.
Profile digest is a digest. CHECKED requires a non-null subject/root, the full
observation and an empty reason array. INVALID and UNKNOWN require null
observation and exactly one corresponding reason. Residuals are always exact.

INVALID formation reasons are FORMATION_RECORD_INVALID,
FORMATION_CERTIFICATE_BINDING_INVALID, FORMATION_CERTIFICATE_STEP_INVALID and
FORMATION_RULE_INVALID. UNKNOWN formation reasons are
FORMATION_PROFILE_UNSUPPORTED and FORMATION_LIMIT_EXCEEDED.

An observation has exactly `type`, `denotation_digest`, `source_digest`,
`target_digest`, `path_steps`, `quote_rank`, `required_depth`,
`formation_digest`, `dependency_nodes` and `quote_origins`. Type is FORM,
PATH, or either enclosed by 1 through 64 nested CODE(...) constructors.
FORM, PATH and CODE are formal type names, not assurance verdicts. Denotation
and formation identities are digests. PATH requires digest endpoints and at
most 4,096 ordered steps, each exactly `source_digest` and `target_digest`.
Other types require null endpoints and empty steps. Quote rank is an integer
0 through 64; required dependency depth is 1 through 64. Dependency nodes are
a nonempty sorted unique list of at most 1,024 integers in 0 through 1,023;
quote origins have the same grammar but may be empty. Neither node-set membership
nor denotation or path arithmetic is proved by decoding; rechecking recomputes
it from bytes.

The closed inspection-reason vocabulary is:

```text
AGENCY_DECLARATION_DIGEST_MISMATCH
AGENCY_DECLARATION_UNSUPPORTED
CENSUS_OBJECT_MISSING
CERTIFICATE_COORDINATE_MISMATCH
COMMIT_INVALID
COMMIT_UNSUPPORTED_OR_LIMITED
EVIDENCE_ENTRY_LIMIT
EVIDENCE_MAPPING_INVALID
EVIDENCE_MAPPING_UNSUPPORTED
EVIDENCE_SNAPSHOT_UNAVAILABLE
FORMATION_PROFILE_UNSUPPORTED
FORMATION_RECORD_INVALID
FORMATION_RECORD_UNSUPPORTED_OR_LIMITED
OBJECT_BYTES_INVALID
OBJECT_DIGEST_MISMATCH
OBJECT_SIZE_MISMATCH
SELECTED_GROUND_NOT_DECLARED
SELECTED_OBJECT_UNAVAILABLE
SELECTED_PATH_INVALID
SELECTED_PATH_NOT_IN_CENSUS
SELECTED_ROLE_DECLARATION_INVALID
SNAPSHOT_BYTE_LIMIT
SUBJECT_AGENCY_CONTEXT_MISMATCH
SUBJECT_GROUND_CONTEXT_MISMATCH
SUBJECT_PROFILE_COORDINATE_MISMATCH
```

This grammar admits structured carried claims only. Decoding does not establish
that report coordinates, statuses, observations, profile identifiers or
selection_digest agree semantically. Rechecking supplies those comparisons.

## 3. Fixed bounds and residuals

Selection records are at most 4,096 bytes; receipts at most 1,048,576 bytes.
Both are scanned before recursive JSON parsing with at most 16 open containers
(root counts as one) and 16,384 total object/array openings. The captured commit
must be exact immutable bytes of at most 262,144 bytes. Its native syntax
admission retains the existing 16-open/8,192-total-container limits.

Evidence must be an exact built-in dictionary, not a mapping subclass or custom
mapping. All keys must be exact ordinary digest strings, and all values exact
immutable bytes, not subclasses, mutable buffers or coercible objects. At most
256 entries, at most 4,194,304 bytes per value and at most 16,777,216 bytes in
total across every supplied entry, including non-census extras. No caller hooks
are deliberately invoked. Capture completes before inspector invocation; this
does not promise an atomic snapshot against concurrent mutation.

Refusing an unsupported input container or exceeded receipt input budget raises
a receipt error. It must not manufacture a portable UNKNOWN report from an
unrepresentable observation. In contrast, native formation-record, dependency
or rule limits within admitted retained objects remain their actual UNKNOWN
reports and can be reproduced. Bounded commit bytes exceeding the native
commit syntax depth or container ceiling likewise retain native UNKNOWN and
empty observations, rather than raising a receipt-input error. There is no
wall-clock bound claim.

Every outer inspection and nested formation report retains exactly:

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

## 4. Experimental native interface and errors

The module is `verifier.interoperability.formation_receipt`, with no new
supported top-level application programming interface (API) export:

```text
decode_formation_selection(selection_bytes) -> dict
build_formation_receipt(selection_bytes, commit_bytes, evidence) -> bytes
decode_formation_receipt(receipt_bytes) -> dict
recheck_formation_receipt(selection_bytes, commit_bytes, receipt_bytes, evidence) -> dict
```

`FormationReceiptError` subclasses ValueError; its `code` attribute and string
message are the same exact code:

- FORMATION_SELECTION_INVALID: malformed, noncanonical or unsupported selection.
- FORMATION_RECEIPT_INVALID: malformed, noncanonical or unsupported receipt or
  carried inspection grammar.
- FORMATION_RECEIPT_INPUT_INVALID: unsupported commit/evidence types, malformed
  evidence keys or a dictionary capture failure.
- FORMATION_RECEIPT_LIMIT_EXCEEDED: a selection or receipt envelope syntax
  bound, or a selection, receipt, commit or complete evidence-input byte or
  entry bound is exceeded. Native commit syntax exhaustion remains UNKNOWN.
- FORMATION_RECEIPT_BINDING_INVALID: exact commit bytes do not hash to the
  selected commit; or rechecking sees another selection/selection digest or a
  receipt rule_profile_digest other than the currently compiled one.
- FORMATION_RECEIPT_NOT_REPRODUCED: an otherwise admitted receipt differs from
  freshly rebuilt canonical bytes. This is not a forgery or claim-negation
  assertion.

Build order is selection admission, commit type/size and hash binding, complete
evidence capture, census admission, selected-byte observation, native inspection,
then strict receipt admission of the generated canonical bytes.
The builder accepts no carried verdict.

Recheck order is receipt admission, independently supplied selection admission,
receipt selection/profile binding, then the same build process. It compares the
entire rebuilt canonical receipt byte-for-byte and returns only the freshly
computed inspection on exact equality. A syntactically valid foreign receipt
rule-profile digest can be decoded, but rechecking refuses its binding rather
than executing or loading that profile. A foreign subject profile remains the
existing native UNKNOWN inspection under the fixed compiled receipt profile.

Reproduction can succeed for CHECKED, INVALID, UNKNOWN, COMPLETE or INCOMPLETE
surfaces. It is never an overall success, authority, safety, historical execution
or six-axis assessment. Missing or changed census evidence changes the record
even when the selected formation status happens to stay the same.
