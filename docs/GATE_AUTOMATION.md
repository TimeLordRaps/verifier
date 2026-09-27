# Local gate automation

Verifier Standard (VSTD) provides a command-line interface (CLI) for local,
dependency-ordered checks. JavaScript Object Notation (JSON) receipts bind selected
input bytes, the manifest, executable files, interpreter context, runner mechanism
and results using Secure Hash Algorithm 256-bit (SHA-256) digests. Digests have no
physical unit; their purpose here is detecting changed bytes, not authenticating
who ran a command or proving its result correct.

```sh
vstd gate init gate_pipeline.json --input src --input tests --preset python
vstd gate plan gate_pipeline.json --json
vstd gate run gate_pipeline.json --output gate_receipt.json --json
vstd gate check gate_receipt.json --json
```

`init` refuses overwrite and creates real checks over selected project inputs.
The `project` preset runs `gate paths` and `gate boundary`; `--preset python` also
runs `gate ast` over selected directories and Python files. These scan for known
path, disclosure, loop and allocation patterns; they do not prove privacy,
termination, resource safety or program correctness. Repeat `--input` to name
source, configuration and test inputs relative to the manifest directory. Without
`--input`, the selected scope is the whole local directory, including files that
the individual scanners ignore. Narrow that scope for large repositories or
repositories with generated files. The manifest remains editable: add explicit
project test commands with their source and configuration inputs. No package is
installed by initialization. `plan` validates paths, input bounds, executables and
dependency order without executing commands. `run` executes explicit argument arrays with
`shell=False`, retains each outcome, and writes a new receipt. Shell substitutions
are never expanded by the runner. Explicitly naming an interpreter still permits
that interpreter to execute arbitrary code. This is **not a sandbox**: commands
inherit the user's authority, network access and environment. Planning is not a
security approval. No schedules, hooks, remote actions or installations are added
by the runner itself; supplied commands can perform effects and must be trusted.

The boundary command's printed and JSON findings report an index, line and category
without echoing scanned file or archive-member names, which can themselves contain
secrets. The local `run_boundary_gate` application programming interface (API)
still returns exact locations for a trusted caller that needs to inspect a finding
privately.

Each manifest has exactly `schema_version: verifier-gate-pipeline-1`, `root`, `inputs`,
`steps`, `overall_timeout_seconds`, and `max_output_bytes`. `root` is relative to
the manifest directory and cannot escape it. Inputs are explicit relative files
or directories under that root. Directory contents are recursively included,
without implicit ignore rules. Links, missing files and empty scopes are refused.
The scope permits at most 1,024 files, 4,096 visited entries and 16 mebibytes of
selected bytes. A mebibyte is 1,048,576 bytes. Include scripts and configurations
actually used by the checks: the runner cannot infer complete dependency closure
or prove that a declared input matters to a command.

Each step requires `id`, `argv`, `needs`, and `timeout_seconds`, and may additionally
declare `result_contract: "vstd-verdict"`. Existing manifests without this field
keep their original behavior: exit zero is `PASS`, every other exit is `FAIL`.
Identifiers are
unique; dependencies name other steps. Cycles and unknown dependencies are errors.
At most 64 steps run sequentially in deterministic dependency order. Deadlines
are finite durations from 0.05 through 3,600 seconds. The overall deadline covers
command execution after input collection; bounded cleanup may extend it.
The shared output budget is 1 through 1,048,576 captured bytes. Exceeding it fails
the check; no output truncation becomes a passing result. Stored output is decoded
as text with replacement for invalid encoding, so it is not a lossless binary log.
Output may contain secrets printed by commands; review receipts before sharing.

Progress and bounded child standard-output/error chunks stream to standard error,
including five-second running notices. With `--json`, the runner's standard output
contains one result object. Exit codes preserve aggregate `PASS` as zero, `FAIL` as
one and `UNKNOWN` as two. Run outcomes retain `PASS`, `FAIL`, `UNKNOWN`, `TIMEOUT`,
`OUTPUT_LIMIT`, `ERROR` or `BLOCKED`. Every nonpassing dependency blocks its
dependents; independent checks may continue within the overall budget. A failed
command, malformed result, input change, deadline or output-limit failure makes
the aggregate fail. Otherwise an unknown result remains `UNKNOWN`, including its
blocked dependents. An independent step blocked by an exhausted budget still
makes the aggregate fail, even when another step is unknown.

The optional `vstd-verdict` contract requires one duplicate-key-free, finite JSON
object on child standard output. Its `status` must be `PASS`, `FAIL`, `UNKNOWN` or
`REJECTED`, agreeing with process exit zero, one, two or one respectively. The
known `verifier-domain-certification-1` and `verifier-grounded-certification-1`
certificate formats use `result.status`; ordinary result objects use `status`.
`REJECTED` remains in retained output and maps to a failed step. Contradictory,
missing or malformed output becomes `ERROR`, never an inferred verdict. This
contract interprets a selected producer's output; it does not independently
establish that producer's claim. Use it for actual certification commands, for
example `python -B -m verifier certification domain-check certificate.json
--request request.json --policy policy.json --json`, with the certificate,
externally selected request and checker policy included in `inputs`. An arbitrary
tool's exit code two is never automatically interpreted as `UNKNOWN`.
No process is started after the overall deadline. On Windows, the runner assigns
a suspended child to an owned Job Object before resuming it, then terminates the
job and checks its active-process count. On other systems it creates a new process
session and sends a termination signal to its process group, recording
`OWNED_GROUP_SIGNALLED` after observing the direct child's exit and closed output
streams. This does not prove every descendant has exited. Deliberately detached or reparented
processes on those systems are outside this cleanup boundary. Neither mechanism
is a security sandbox against hostile commands.

The receipt embeds bounded command output instead of external log files. Its own
output path is excluded from selected inputs to prevent self-digest recursion.
All other input additions, removals or byte changes during execution fail the
aggregate. Receipts should be written outside the selected scope where practical.
Commands changing their inputs produce a failing aggregate even when they exit zero.

`check` verifies the receipt digest, structural consistency and current manifest,
selected inputs, executable bytes, runner source and interpreter context. It never
reruns commands. It returns `integrity_status: PASS` for a consistent receipt and
current context; `run_status` and overall `status` retain the original run's
failure, uncertainty or success. Declared verdict contracts are structurally
rechecked against retained output and exit codes. An intact failed run therefore returns a nonzero command
exit. A self-consistent forged receipt remains possible: this is integrity
checking, not authenticity or independent execution evidence. Unselected libraries,
inherited environment, external services and transient inputs remain unbound.
Executable paths and captured output may disclose local context. No numbered
profile conformance or domain correctness follows from a passing pipeline.

The carried manifest locator is relative to the receipt. It never authorizes a
read outside the receipt directory. For relocated receipts or a manifest in an
ancestor directory, supply the explicit current coordinate:

```sh
vstd gate check results/gate_receipt.json --manifest gate_pipeline.json --json
```

[The example manifest](../examples/gate_pipeline.json) runs real source path,
disclosure and Python pattern checks, then executes
[the retained-dataset checker](../examples/gate_project/check_dataset.py). Dataset
integrity and lineage (DATA) checks `DATA-1.2` and `DATA-1.4` recompute the actual retained record
inventory and compare every record with the independently stored
[field contract](../examples/gate_project/contract.json). The example builds and
replays a domain certificate under its explicitly selected local policy. Its
bounded domain result remains separate from numbered object-profile conformance,
which is `NOT_ESTABLISHED`; it proves no external source ancestry or dataset utility.
From a checkout with the package installed, run:

```sh
python -B -m verifier gate plan examples/gate_pipeline.json --json
python -B -m verifier gate run examples/gate_pipeline.json --output gate_receipt.json --json
python -B -m verifier gate check gate_receipt.json --manifest examples/gate_pipeline.json --json
```

Changing an integer dataset value to a string produces `FAIL`. Selecting an
unsupported field type in the external contract produces `UNKNOWN`. Both return
nonzero and remain nonpassing on receipt recheck. The example is exercised in
continuous integration (CI), and the acceptance suite independently checks real
`domain-assess` and `domain-check` commands across all three verdicts. The example
is a project workflow specimen, not the complete repository regression suite.
