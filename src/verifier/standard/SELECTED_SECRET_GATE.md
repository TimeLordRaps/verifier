# Selected secret gate

The Verifier Standard (VSTD) command-line interface accepts an exactly selected
JavaScript Object Notation (JSON) request:

    vstd gate secrets --request REQUEST.json --scanner-binary EXECUTABLE --scanner-config CONFIG --json

Paths must be absolute regular files without linked parents. Request and receipt
schemas are vstd.secret-gate.request/1 and vstd.secret-gate.receipt/1. The request
binds mode, selection, artifact identifier/kind/bytes/content_sha256,
coverage_requirements and scanner_policy in its canonical scope_manifest_sha256.
Unicode Transformation Format, 8-bit (UTF-8) is the selected text encoding.
Only artifact content_path is excluded from that digest. Duplicate keys are
unavailable. The request_id is a canonical universally unique identifier (UUID).

Modes are staged-index, outgoing-history, preflight-input and preflight-output.
Collectors supply exact selected bytes; the gate does not infer that a collector
selected everything relevant. Required coverage entries are every-byte-artifact,
no-implicit-exclusions and representation-coverage-explicit. The scanner policy
has name, version, binary_sha256 and configuration_sha256. Secure Hash Algorithm
256-bit (SHA-256) binds Gitleaks 8.30.1 and the exact configuration exposed by
verifier.runtime.secret_gate.CONFIGURATION. Compiled default rule decisions are
bound by the executable hash; no baseline, external ignore file or in-source
allow directive is accepted.

PASS means every selected raw UTF-8 text artifact was scanned with zero findings
under those pinned rules and unchanged bindings. It does not mean every secret
format is recognized. Decoded interpretations, binary content and archives are
outside this version. Missing files, unsupported coverage, unavailable scanner,
scanner errors, limits and cancellation remain UNKNOWN. Contradicted bindings
and findings are FAIL; a finding remains FAIL when another artifact is missing.
Empty exact selection is NOOP, not clearance. Exit codes are PASS 0, FAIL 1,
UNKNOWN 2 and NOOP 3.

The gate snapshots the scanner/configuration in a private temporary directory,
uses a fixed environment allowlist, suppresses child output, and reduces reports
to artifact indexes and counts. It emits no match, raw line, path, extracted
secret digest or exception representation. Before reporting it rechecks request,
scanner, configuration and all selected artifacts. Its receipt is an observation
for this invocation, not authority for changed bytes, a security-tier certificate
or production profile approval. Trusted scanner subprocesses have bounded pipes
and direct-child cleanup; this is not a sandbox or descendant-containment claim.

Version 1 bounds are 1,000 artifacts, 2 MiB per artifact, 32 MiB total, 1 MiB
request, 2 MiB report per artifact and 30 seconds total scanning. Installation,
Git hook chaining and global activation are separate explicit owner actions;
invoking the gate does not activate them.
