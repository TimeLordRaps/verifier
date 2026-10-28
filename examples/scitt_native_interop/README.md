# Recorded native cross-implementation comparison

This follow-on Verifier Standard (VSTD) example connects Supply Chain Integrity,
Transparency, and Trust (SCITT) native observations to a stored component package.
It is unreleased 2.0.0 source, not an independent-operator result,
automatic hub qualification, or a numbered-profile conformance receipt.

Two upstream implementation paths check the same fixed specimen: Python scitt-cose
and its Go checker. They use different cryptographic/parser implementations but
share upstream project authorship. Twelve cases cover three expected true native
verification flags and nine expected false flags, including a different byte
representation whose signature can verify but whose inclusion cannot borrow the
original receipt. A false flag alone does not diagnose why verification failed.

## Check installed Python requirement consistency

The optional [requirement checker](python_requirements.py) observes installed
distribution metadata and rechecks its active transitive requirements. Select a
Python environment with `packaging==26.3` already installed; this example neither
installs dependencies nor imports the distributions it examines. From the source
checkout with `src` on `PYTHONPATH`:

```python
import sys
import sysconfig
from pathlib import Path
from packaging.markers import default_environment

sys.path.insert(0, str(Path("examples/scitt_native_interop").resolve()))
from python_requirements import capture_requirements, snapshot_digest, recheck_requirements

environment = {**default_environment(), "extra": ""}
snapshot = capture_requirements(
    {"scitt-cose": "0.2.2", "cbor2": "6.1.4", "cryptography": "50.0.0"},
    environment=environment,
    search_paths=(Path(sysconfig.get_path("purelib")),),
)
selected_digest = snapshot_digest(snapshot)
report = recheck_requirements(snapshot, expected_snapshot_digest=selected_digest)
print(report["status"])
```

The selected installation directory is a bounded observation scope, not a claim
that every possible import provider was discovered. The snapshot retains reached
metadata bytes, exact root pins, the complete marker environment and the selected
parser and checker source identities. Offline rechecking uses those retained declarations,
not the replay host's installed distribution inventory. A locally computed digest
identifies this capture; it does not authenticate its publisher. Consumers must
select the expected snapshot digest separately from an untrusted received record.

The checker follows Python's [dependency-specifier semantics](https://packaging.python.org/en/latest/specifications/dependency-specifiers/)
and [version rules](https://packaging.python.org/en/latest/specifications/version-specifiers/)
for active `Requires-Dist` and `Requires-Python` declarations. Requested extras and
direct-reference requirements are not supported; an active unsupported requirement
cannot yield a clean result. Inactive edges remain distinct, cycles do not erase
incoming constraints, and missing or ambiguous providers remain unresolved.
Ordinary `.egg-info` providers and metadata version `2.0` participate in name-ambiguity
checks but do not become supported requirement providers; other unsupported layouts
or metadata versions are refused. A known mismatch yields
`INCONSISTENT` even when other requirements remain explicitly unresolved.

`CONSISTENT` means only that the supported retained requirements agree with the
retained versions under the bound environment. It does not establish executable
dependency completeness, loaded-code identity, cryptographic correctness, native
availability or confidentiality of awareness. In particular it does not resolve
the stored package's broader `runtime:python` requirement, create a readiness
declaration, qualify a catalog component, or authorize native execution. Retained
metadata can contain contact details, source links and other disclosure-sensitive
content; inspect it before any publication and do not upload it automatically.

## Explicit native capture

Install the repository's optional `scitt` dependencies in a host-selected Python
environment. Separately obtain and review the upstream source at
[`action-state-group/scitt-cose@1fd1cee`](https://github.com/action-state-group/scitt-cose/tree/1fd1cee84c298c0e95fb3273f64709b7face7821).
Build its `scitt-cose-go-verify` program using its pinned module files. The example
does not download, build, install, or extract executable code for you.

Supply the path and Secure Hash Algorithm 256-bit (SHA-256) digest of the executable
you explicitly selected. A digest read from an untrusted package does not grant
permission to execute it. The placeholder below is a 64-character lowercase
hexadecimal digest from your reviewed build coordinate, not a literal value.

```sh
python -u examples/scitt_native_interop/native_runner.py --go-checker PATH_TO_REVIEWED_CHECKER --expected-go-sha256 REVIEWED_GO_SHA256 --output-dir NEW_CAPTURE_DIRECTORY
```

The default specimen is the existing [SCITT example](../scitt_interop/README.md).
`--specimen-dir` can select a relocated exact copy; all seven retained specimen
files must match the fixed pins. Case inputs are reconstructed from those bytes,
including the exact statement used as the ordinary receipt leaf.

The command explicitly invokes native processes. Each direct checker or Python
identity-preflight process has a 20-second limit and at most 128 kibibytes per
retained output channel; one kibibyte is 1024 bytes. Direct-child cleanup has its
own short wait. These controls are not a descendant-process sandbox, universal
filesystem time bound, or runtime attestation. Input reads, ordinary-file identity,
links/reparse paths, source hashes, executable selection, and output limits are checked.
Execution is visible through named start/progress/end messages. Output streams are
retained as exact bytes and displayed separately as escaped byte representations.
Observer failures during reader construction, startup or monitoring trigger bounded
direct-child kill/reap cleanup before the exception propagates. This is not a promise
against repeated interruption, operating-system cleanup failure or descendant processes.

The destination must be absent. It contains `corpus.json`, `observations.json`,
`runtime.json`, exact input files, and raw outputs. There are 24 scheduled comparison
observations, not necessarily 24 successful launches; operational failures remain
explicit. Additional identity-preflight processes are not comparison observations.
Source snapshots and environment fields are observations, not authenticated history.

## Evaluate a fresh native acceptance proposition

The experimental [statement mechanism](statement_mechanism.py) connects a fresh
Go checker invocation to the existing `VerificationSession`. Its exact proposition
is **the pinned native statement verifier accepts these exact statement and public-key
bytes**. `PASS` and `FAIL` concern that acceptance predicate only: neither establishes
payload truth, signer authority, independent cryptographic correctness or a generic
signature geometry facet. Operational and unsupported results remain `UNKNOWN`.

Select the executable and its digest through host review, not from a received package.
Edwards-curve Digital Signature Algorithm (EdDSA) is the fixed native argument.
The mechanism identifier (ID) and predicate constants below are fixed by the helper.
With `src` on `PYTHONPATH`, an already existing ordinary output directory, and explicit
host permission to execute that checker on the selected inputs:

```python
import sys
from pathlib import Path
from verifier.core.evidence import BoundProposition, EvidenceBounds, EvidenceStore, VerificationSession

sys.path.insert(0, str(Path("examples/scitt_native_interop").resolve()))
from statement_mechanism import (
    GoStatementAcceptanceMechanism, MECHANISM_ID, STATEMENT_PREDICATE, mechanism_digest,
)

checker = Path("PATH_TO_REVIEWED_CHECKER")
expected_checker = "REVIEWED_GO_SHA256"
store = EvidenceStore()
statement = store.add(Path("SELECTED_STATEMENT.cose").read_bytes())
key = store.add(Path("SELECTED_PUBLIC_KEY.pem").read_bytes())
binding = BoundProposition(
    subject_id=statement, predicate=STATEMENT_PREDICATE, expected=True,
    mechanism_id=MECHANISM_ID, mechanism_digest=mechanism_digest(checker, expected_checker),
    evidence_refs=(statement, key), trust_roots=("host:selected-runtime-and-key",),
    bounds=EvidenceBounds(2, 262144),
    parameters={"algorithm": "EdDSA", "statement_ref": statement, "public_key_ref": key},
)
session = VerificationSession(store)
session.register(GoStatementAcceptanceMechanism(
    checker, expected_checker, output_root=Path("EXISTING_OUTPUT_ROOT"),
    approved_bindings=(binding,),
))
result = session.evaluate(binding)
print(result.outcome.value)
```

The example's filenames and checker digest are host-supplied placeholders. The trust-root
string records a host assumption; naming it does not authenticate a key or runtime.
Do not read arbitrarily large untrusted files into memory using this short illustration:
the mechanism admits at most 131,072 bytes per input and the declared combined ceiling.
Session admission is not an external-file or application-memory sandbox.

The mechanism snapshots the full approved binding and checks source, executable and
input identity before and after the bounded invocation. Requests refused during initial
admission cannot create a working directory or invoke native code. Admitted calls retain inputs,
raw output channels and observations in new exclusive directories. Failures may leave
partial directories; their existence is not a successful evaluation. This in-process
host boundary does not prevent hostile Python mutation, attest loaded dependencies,
or implement approval expiry/revocation. The executable and three checker sources
participate in its mechanism digest; changing them requires a newly selected binding.

Replay uses the original retained statement/key bytes, a separately selected executable
and a newly host-approved mechanism registration, then invokes the checker again.
Retained stdout or a stored `PASS` never substitutes for that invocation. This does not
resolve package dependencies, promote catalog availability/readiness, or close existing
signature/inclusion geometry holes. Those need their own exact mapping and prerequisites.
It is not an additional independent verifier: it invokes the same Go implementation.

## Store and reconstruct without executing native code

From a checkout with `src` on `PYTHONPATH`:

```sh
python -u examples/scitt_native_interop/package_comparison.py export CAPTURE_DIRECTORY PINNED_UPSTREAM_SOURCE NEW_PACKAGE.json NEW_COMPARISON.json
python -u examples/scitt_native_interop/package_comparison.py reconstruct NEW_PACKAGE.json NEW_COMPARISON.json --expected-package-sha256 EXPECTED_PACKAGE_SHA256
```

An older capture whose runner bytes differ requires its retained matching reconstruction
sources. Do not rewrite its runtime observation or export it as though the new runner
performed the old execution; select the old source handoff or obtain a fresh capture.

The upstream directory can be the pinned checkout root, or a flat retained source
directory containing its Go `main.go`, `go.mod`, `go.sum`, root `LICENSE`, and `NOTICE`.
Exact pins are in the exporter. It also retains the matching installed Python source,
licenses, native runner, decoder, fixed corpus, runtime observations, and raw outputs.
The project's own pinned `LICENSE` and `NOTICE` travel at `runners/LICENSE` and
`runners/NOTICE`; upstream notices do not replace project attribution. Missing or
changed project notice bytes are refused by this reconstruction contract. Adding
them to an older package requires a new package, sidecar and entry identity; do not
rewrite historical files or reuse their expected digests. Retention does not establish
complete licensing review or permission to publish.
Dependencies and the executable remain explicitly unresolved/not retained; source
correspondence does not prove which source built that executable or what code ran.
Missing pinned runtime/source inventory makes a capture **not exportable under this
source-bound contract**. Its original local observations remain available.

The existing `verifier-component-package-1` format contains two descriptive component
entries, not two independently qualified verifiers. Inspection still reports native
qualification `NOT_ESTABLISHED`. The reference seed catalog is unchanged.
The separate `SCITT-RECORDED-COMPARISON-1` sidecar binds the complete package digest;
it is not placed inside the package it names. Obtain the expected package coordinate
separately when relying on a transported package. Self-consistency is not authenticity.

Reconstruction validates exact corpus/source attribution, rehashes retained bytes,
and derives every comparison row from raw native output. It does not invoke native
code. `NATIVE_TRUE` and `NATIVE_FALSE` project recorded verification flags; `UNKNOWN`
preserves unavailable, inconsistent, unsupported, or operationally failed observations.
False flags do not prove cryptographic invalidity or establish a failure cause.
Agreement and fixture expectations are separate axes: both implementations can agree
and still violate the expected result. Comparable disagreement stays `CONFLICTED`.
Receipt success additionally compares the root, tree size, and leaf index for this
single-leaf specimen. Reconstructing a sidecar does not establish native reexecution.

Export requires absent destinations and never overwrites them. Failure can leave a
partial local export; retain it for diagnosis and choose new output destinations.
Raw outputs and third-party source are not sanitized: inspect before distribution,
especially after unexpected failures that might expose local paths or private text.
Upstream draft-status prose is retained evidence, not a current standards-status claim.
No site, publisher account, publication, confidentiality enforcement, or ledger submission
is performed. Runtime qualification, independent operators, other platforms, algorithms,
tree sizes, issuer authority, and payload computational truth remain separate gates.

## Bind a local distribution entry

After exporting a package and comparison, create one experimental
`SCITT-COMPARISON-ENTRY-1` entry beside them:

```sh
python -u -B -S examples/scitt_native_interop/catalog_entry.py create NEW_ENTRY.json NEW_PACKAGE.json NEW_COMPARISON.json
python -u -B -S examples/scitt_native_interop/catalog_entry.py inspect NEW_ENTRY.json --expected-entry-sha256 EXPECTED_ENTRY_SHA256
```

Supply the expected entry digest through a separately selected coordinate, not by
trusting whatever entry arrived. Creation reconstructs the comparison before writing
an absent destination. Inspection binds both raw artifact files, the canonical package
digest, and the complete selected checkout's Python library and three tool sources.
Same-named substitutions or source-inventory changes prevent reuse of the entry.
Adding an unrelated Python module also changes this coordinate. Older entries need
their retained matching source handoff; a later checkout requires a separately
admitted new entry, without rewriting the older bundle.
Only ordinary relative sibling filenames are supported; no path traversal, remote
fetch, installation, extraction, or package-selected code execution occurs.

The entry is immutable by digest, not protected against later filesystem writes.
Pre/post source checks are observations, not atomic snapshots or proof of loaded
code. This source-checkout contract does not assert installed-wheel equivalence or
authenticate the publisher, historical execution, or native dependencies. Reconstructing
an entry preserves comparison uncertainty, qualification and independence boundaries;
it does not make a catalog candidate execution-ready or close verification-surface holes.
The reference seed catalog is unchanged. This is a
local admission prerequisite for a future hub, not a deployed hub or account system.

## Stage only the admitted distribution files

From the same source checkout, prepare an ordinary existing staging root outside
the input directory. Neither directory may contain the other. The following command
creates a new child named by the separately supplied entry digest:

```sh
python -u -B -S examples/scitt_native_interop/stage_distribution.py ENTRY.json --expected-entry-sha256 EXPECTED_ENTRY_SHA256 --output-root EXISTING_STAGING_ROOT
```

Staging retains only the exact entry, package and comparison files, under their
original sibling filenames. The directory name identifies the entry, not a digest
of the directory tree; the entry's own basename is not part of its schema.
Unrelated neighboring files are excluded. It checks
admission and bounded raw snapshots before writing, uses exclusive creation, then
reinspects the staged entry and exact file inventory. Existing destinations, including
partial ones, are refused. A failed attempt leaves any partial directory for inspection;
directory existence is not evidence of successful staging and must not trigger serving.

This is local transport preparation, not publishing, a server, a new package format,
native execution, disclosure approval or an atomic filesystem snapshot. The entry
digest does not cover this staging tool; recipients still use the entry inspector.
The three files do not include the matching reconstruction checkout. Obtain those
exact source bytes separately: a base commit alone does not identify uncommitted
tools. No source installation, import selection or qualification follows from staging.
Before any later authorized publication, review all embedded bytes and licenses,
provide retrievable matching reconstruction sources, and revalidate the exact output.

## Download and admit a selected distribution

The experimental consumer accepts an explicitly chosen uniform resource locator
(URL) using Hypertext Transfer Protocol Secure (HTTPS), plus an independently
selected expected entry digest. From the matching source checkout:

```sh
python -u -B -S examples/scitt_native_interop/fetch_distribution.py ENTRY_URL --expected-entry-sha256 EXPECTED_ENTRY_SHA256 --output-root EXISTING_DOWNLOAD_ROOT --timeout-seconds 30
```

The output root must already exist. Its digest-named destination must be absent;
existing or partial destinations are never overwritten. The command fetches the
entry first and checks its exact digest before parsing any sibling location.
Only the admitted package and comparison filenames under that same origin and
directory can be requested. It checks the complete selected reconstruction source
inventory before fetching the larger siblings. It never fetches or imports sources
chosen by the entry and does not install dependencies or run native checkers.

The transport refuses redirects, embedded credentials, query/fragment selectors,
ambiguous paths and compressed content. It does not use ambient proxies, cookies,
or authentication credentials. HTTPS uses the interpreter's normal certificate
and hostname verification. Header declarations cannot override actual body limits:
131,072 entry bytes, 33,554,432 package bytes and 1,048,576 comparison bytes.
A shared network deadline bounds the trusted transport subprocesses, including
name-resolution, header and slow-body stalls; timed-out children are terminated
and reaped. This deadline is not a sandbox or a bound on local reconstruction time.

For local testing only, `--allow-loopback-http` permits Hypertext Transfer Protocol
(HTTP) on an explicit numeric loopback address. It does not permit `localhost`
name resolution or arbitrary unencrypted hosts. Local tests do not establish a
deployed HTTPS route, server availability or native platform qualification.

All three bounded snapshots must match their selected digests before any output
directory is created. Files are written exclusively, with the entry last; the
existing inspector then reconstructs the package/comparison and checks the exact
three-file inventory and retained bytes. A later failure leaves the new directory
for inspection and reports failure. Its existence is not an admission or serving
signal; do not automatically serve partial downloads.

This implements acquisition and admission, not a hosted hub, publisher identity,
license approval, dependency satisfaction, execution readiness or independent
verification. A request discloses the selected resource and ordinary connection
metadata to the chosen host; this client does not enforce confidentiality of
awareness. Authenticated/private downloads require a separate contract. The entry
binds reconstruction sources, not this transport helper or its subprocess runtime.

## Retain the exact reconstruction sources

The optional source handoff uses the existing `verifier-artifact-freeze-1` format:

```sh
python -u -B -S examples/scitt_native_interop/freeze_reconstruction.py ENTRY.json --expected-entry-sha256 EXPECTED_ENTRY_SHA256 --source-stage NEW_SOURCE_STAGE --bundle NEW_FROZEN_BUNDLE
```

Both destinations must be absent, with ordinary existing parents, outside the source
checkout and input directory and not containing each other. The source stage contains
only the entry's exact Python reconstruction inventory, pinned project `LICENSE` and
`NOTICE`, and the three transport files under `entry/`. No neighboring files, installed
dependencies, tests or unrelated data are copied. The complete file and directory
allowlist is checked separately: a valid freeze and successful entry inspection alone
would not detect an extra unrelated non-Python file. Partial outputs are not success.

The helper freezes those checked bytes without a seal, keys or native replay. A returned
artifact identifier is a producer observation, not publisher authentication. Before
executing any retained source, use a separately selected existing verifier and expected
artifact identifier to check the entire bundle with `require_seal=False` (or the
`artifact verify --freeze-only` command). Do not execute unverified retained code to
establish its own trustworthiness. The entry digest remains a separate selected input.

After host approval, select a Python interpreter explicitly, use a neutral working
directory and put only the frozen payload's absolute `src` path on `PYTHONPATH`.
With absolute bundle paths, the inspector can read the guarded payload directly:

```sh
python -u -B -S FROZEN_BUNDLE/payload/examples/scitt_native_interop/catalog_entry.py inspect FROZEN_BUNDLE/payload/entry/ENTRY.json --expected-entry-sha256 EXPECTED_ENTRY_SHA256
```

Recheck the bundle afterward with the previously selected artifact identifier. `-B`
avoids bytecode-cache writes; `-S` disables site-package loading. No thaw is needed:
the existing thaw operation requires a seal and is not part of this route. Preserve
the bundle's read-only guards when relocating it; they do not prevent privileged writes.
Copy tools can preserve bytes while dropping directory guards. One host-controlled
copy path exercised by the regression tests is Python's `shutil.copytree` to an absent
destination. Reverify the copied bundle before replay regardless of the copy method;
do not waive a guard failure merely because content digests match.
Source preservation and this entry-reconstruction path do not establish a full installed
distribution, arbitrary command support, native runtime availability, an independent
operator, a sandbox or a universal filesystem/time bound. No automatic import selection,
installation or permission to execute follows from receiving the bundle.

## Use the admitted package for detection and planning

After entry inspection succeeds, use its `comparison.package_digest` as
`INSPECTED_PACKAGE_SHA256` below. From the same source checkout with `src` on
`PYTHONPATH`, the existing public command can consume the package:

```sh
python -u -B -S -m verifier.runtime.public_cli surface analyze examples/scitt_native_interop/planning_geometry.json --plan --package NEW_PACKAGE.json --expected-package-sha256 INSPECTED_PACKAGE_SHA256 --json
```

The [planning geometry](planning_geometry.json) explicitly models three unresolved
questions: the fixed statement's signature, receipt inclusion for its exact leaf,
and the payload's separate computational truth. Its specimen paths and digests are
declarations, not checked native bindings. Both catalog components match the declared
signature and inclusion mechanisms, but their availability remains `NOT_CHECKED`, so
the exact matches remain `BLOCKED`. Their package-qualified runtime dependencies are
retained as prerequisites, not resolved by the comparison. Payload truth has no matching
mechanism and stays `UNMATCHED`; no judgment or ordinary/self closure is upgraded.

Keep the entry inspection alongside the plan. The plan binds the canonical package,
registry and geometry identities, **not** the entry or sidecar digest. Planning does
not consume recorded native flags, recheck the sidecar, or authenticate execution.
The expected package digest prevents content substitution after inspection, but
canonical package identity intentionally tolerates transport reformatting. Such a
reformatted file would fail the entry's stricter raw-file binding even though the
unchanged canonical contents can still be planned against.

The existing experimental execution-readiness function can assess declarations for
this plan; there is no readiness command. With no candidate selected or execution
declaration supplied, as exercised here, readiness remains `NOT_ESTABLISHED`.
The empty modeled authority list grants no
real-world permission. Neither matching, inspection nor preflight executes a checker
or supplies runtime qualification, inference confidentiality, or completed validation.

## Focused tests

```sh
python -u -m pytest tests/test_scitt_native_runner.py tests/test_scitt_statement_mechanism.py tests/test_scitt_package_comparison.py tests/test_scitt_catalog_entry.py tests/test_scitt_entry_planning.py tests/test_scitt_distribution.py tests/test_scitt_reconstruction.py tests/test_scitt_fetch.py tests/test_scitt_python_requirements.py -vv -s --durations=10 --timeout=60
```

Synthetic output tests establish reconstruction behavior only. A native capture is a
separate opt-in run and must be reported at its actual source, runtime, and package
coordinates; no old observation or mocked test supplies that evidence.
