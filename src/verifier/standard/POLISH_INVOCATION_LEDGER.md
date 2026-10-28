# Exact local invocation consumption prerequisite

JavaScript Object Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256);
directed acyclic graph (DAG); identifier (ID);
hash-based message authentication code (HMAC);
Unicode Transformation Format, 8-bit (UTF-8);
American Standard Code for Information Interchange (ASCII).

**Status:** experimental bounded local consumption mechanism; full issuance and production acceptance are separate. JavaScript Object
Notation (JSON); Secure Hash Algorithm 256-bit (SHA-256); Structured Query Language
(SQL); Uniform Naming Convention (UNC). It does not issue polish, authorize rights,
prove historical public execution, or establish uniqueness outside one configured
local ledger. Every output retains polished=false. Issuance requires independent
native/completeness/authority/public checking before this state operation.

An authenticated host provisions `IssuerLedgerSelection(path, ledger_id,
policy_domain, policy_epoch)`. It is an exact frozen native type, never candidate
JSON or a client path. The absolute path must not be UNC. A mapped path can still
refer to remote storage; the operator is responsible for selecting controlled
local durable storage. Candidate artifact files contain no ledger state. No implicit
database creation occurs during commit/replay/recovery. Explicit operator provisioning
alone initializes an empty ledger or verifies the same existing identity/epoch.
Reprovisioning with another identity or epoch refuses; it never clears invocations.

`commit_issuance(proposal_bytes, *, expected_proposal_digest, invocation_id,
authority_status_digest, commit_time, selection)` first admits exact immutable
canonical bounded bytes and external digest. The proposal is at most 4,194,304 bytes;
its JSON shape/canonical decoder is bounded as in CERTIFICATE_DAG. This is the
precommit immutable issuance proposal, excluding its own receipt and postcommit
signature, so no digest cycle exists. This local helper does not interpret its
contents as complete polish or authenticate an authority-status digest.

The configured host opens a SQL transaction with `BEGIN IMMEDIATE`, checks exact
ledger identity/current policy epoch, rejects an already consumed invocation, inserts
the unique invocation with the exact immutable proposal and source mechanism, builds
the bounded receipt, then COMMITs. The SQLite synchronous setting is FULL. Busy wait
is limited to five seconds per connection operation; that is not a complete wall-clock
or power-loss guarantee. Storage/database correctness and controlled state are explicit
trust assumptions. This is one configured local database, not distributed consensus.

Concurrent duplicates cannot both insert in that database. `(policy_domain,
invocation_id)` remains consumed across policy epoch changes; incrementing the epoch
does not enable ID reuse. There are at most 4,096 retained invocations and 67,108,864
aggregate proposal bytes in this bounded local ledger contract. Capacity exhaustion
is UNKNOWN; known duplicates are detected first and remain FAIL. Capacity is not
recovered by deleting consumed IDs or silently replacing the configured ledger.
Revocation/root/policy/status changes must advance the same
host epoch through `advance_policy_epoch` before new issuance commits, under the host's
authenticated current authority channel. Failing to integrate that channel does not
create authority or revocation freshness. Unknown channel/storage/uncertain commit
blocks full issuer PASS. The helper records the selected authority status digest and
host integer commit observation separately from prior assessment evaluation time.

Receipt `verifier-polish-local-invocation-commit-1` binds exact ledger/policy domain/
epoch/invocation, monotonic database sequence, proposal/status/mechanism digests and
commit time, with a canonical receipt digest. Its claim is
CONSUMED_EXACT_LOCAL_LEDGER and public_consumption_authentication=NOT_ESTABLISHED.
It is not a signature over execution. A configured public operator-signed postcommit
attestation is required if an issuer or host claims public consumption authenticity.

Malformed/substituted selections/proposals, known duplicate invocation, wrong current
epoch or wrong ledger identity FAIL. Finite parser/checker capacity exhaustion is
UNKNOWN. Missing/inaccessible/locked database or uncertain COMMIT is UNKNOWN; no PASS
is returned from uncertainty. The full issuer maps cancellation/interruption to a
bounded UNKNOWN, with no fabricated receipt; the helper rolls back an active transaction
when control returns. Explicit asynchronous cancellation and keyboard interruption of
commit are `LEDGER_COMMIT_CANCELLED_OR_UNCERTAIN`; interrupted recheck and recovery are
`LEDGER_REPLAY_CANCELLED` and `LEDGER_RECOVERY_CANCELLED`. None carries an earlier PASS.
A kill/power loss can leave an uncertain durable commit, which requires read-only recovery
rather than automatic reissue.

`recheck_issuance_commit(receipt_bytes, *, proposal_bytes, expected_proposal_digest,
selection)` performs a read-only snapshot of the same entry, verifies exact bytes,
stored digest/current epoch/mechanism and exact canonical receipt. It never consumes
again. A known changed proposal or forged receipt FAIL; absent required commit UNKNOWN.
Receipt cap is 65,536 bytes. `recover_issuance_commit` reads the same exact invocation
and proposal after an uncertain commit without a receipt; it does not create state,
reuse another proposal, or upgrade absent evidence. A recovered local commit is not
current complete polish or publication acceptance.

The installed mechanism binds current helper/source/specification bytes and actual SQLite
runtime version; changed bytes/version invalidate prior current replay and need explicit
qualification. These local receipts are not numbered object certificates. No remote
transport, credentials, spending, human review, hosted publication or claim of physical
time occurs. The issuer must separately enforce all scope/rights/privacy/consent gates.


## Local receipt contradictions before storage availability

Replay validates the exact bounded closed receipt schema, its complete canonical
body commitment, proposal commitment and externally selected ledger/domain/epoch
before opening storage. Locally changed proposal, altered generation, wrong schema,
sequence type or forged result markers FAIL even if the database is unavailable.
The fixed claim_boundary also compares exactly before storage: "Same exact committed
proposal in one configured local ledger only; not polish, public historical execution
or worldwide uniqueness." A rehashed replacement string is a local refusal; its
body digest cannot authorize a stronger claim.
These comparisons refuse contradictions; they do not authenticate a receipt or
prove consumption. PASS still requires the exact SAME real committed database row.

The live source/backend digest fences current file bytes and SQLite version only.
Fresh fixed host installation/process provenance and equivalence of already loaded
code to those admitted bytes remain independently established host obligations.
No executed-code or historical runtime attestation follows from __file__ hashing.
