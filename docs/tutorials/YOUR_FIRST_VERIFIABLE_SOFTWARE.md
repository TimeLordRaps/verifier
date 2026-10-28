# Your first verifiable software

This tutorial uses the installed Verifier Standard (VSTD) command-line interface
(CLI) to retain selected source bytes, check managed-comment structure, and stage
authored explanations. A bounded `PASS` concerns those declared checks. Complete
behavioral correctness, execution authenticity, model correctness, overall safety,
release acceptance and polished status remain separate obligations.

Use an installed development package containing [`polish prepare`](../reference.html#cli-vstd-polish-prepare).
The checked [example files](../../examples/first_verifiable_software) provide a
small Python function, two explicit workflow policies, a quality
application profile and canonical authored definitions. The following commands
use PowerShell from the repository root. Choose fresh local directories; the
retained output directory must be outside the selected source directory.

```powershell
vstd --version
$example = Join-Path (Get-Location) examples/first_verifiable_software
$lab = Join-Path (Get-Location).Parent.FullName first-verifiable-software
$source = Join-Path $lab source
$retained = Join-Path $lab retained
New-Item -ItemType Directory -Path $lab
Copy-Item -LiteralPath (Join-Path $example source) -Destination $source -Recurse
$check = Join-Path $example check-policy.json
$quality = Join-Path $example quality-profile.json
function Pin($file) { 'sha256:' + (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant() }
function Save($file, $text) { [IO.File]::WriteAllText($file, $text, [Text.UTF8Encoding]::new($false)) }
Save (Join-Path $source demo.py) ("# vstd-explanation: begin orphan`n" + [IO.File]::ReadAllText((Join-Path $source demo.py)))
```

Policy and JavaScript Object Notation (JSON) quality-profile byte digests are
selected explicitly. A digest detects substituted bytes; it supplies no policy
authority. This example opts into the built-in `comment-format` checker. `lint`
and `pretty-format` remain `NOT_SELECTED`. Their optional Ruff and Black adapters
require an already-installed, explicitly pinned tool and closed configuration;
this command installs nothing and accepts no candidate execution hooks.

## Observe a deliberate failure, then fix it

```powershell
$failedText = vstd polish prepare $source --policy $check --policy-digest (Pin $check) --quality-profile $quality --quality-profile-digest (Pin $quality) --output $retained --json | Out-String
$failed = Join-Path $lab failed.json
Save $failed $failedText
($failedText | ConvertFrom-Json).quality.stages
```

Exit `1` reports the required `comment-format` check as executed and `FAIL`: the
example has an unmatched managed block. The default check-only operation leaves
`demo.py` unchanged and retains the failed attempt. Remove its first line,
`# vstd-explanation: begin orphan`, using your editor. Keep the small function.

```powershell
vstd polish prepare $source --policy $check --policy-digest (Pin $check) --quality-profile $quality --quality-profile-digest (Pin $quality) --output $retained --resume $failed --json
```

Exit `0` now reports bounded preparation `PASS`. The changed source invalidates
the affected prior bindings. Selected stages rerun; a carried `PASS` is never
accepted as current evidence. The failed report and append-only attempt journal
remain available. `NOT_RUN` on a required stage blocks success; an unsupported
observation is `UNKNOWN`, not a known disproved proposition.

## Replay current preparation with local gates

Run this section before initializing Git in the source directory. The gate
artifact is the complete directory inventory; it has no implicit exclusions.
Create a fresh check-only report after fixing the example. Supply the exact
policy and quality application profile separately to the consumer.

```powershell
$fresh = Join-Path $lab fresh.json
Save $fresh (vstd polish prepare $source --policy $check --policy-digest (Pin $check) --quality-profile $quality --quality-profile-digest (Pin $quality) --json | Out-String)
$contractFile = Join-Path $lab replay-contract.json
$contract = [ordered]@{
  schema_version = 'verifier-gates-workflow-preparation-contract-1'
  policy_json = [IO.File]::ReadAllText($check); policy_digest = (Pin $check)
  definition_json = $null; definition_digest = $null
  quality_profile_json = [IO.File]::ReadAllText($quality); quality_profile_digest = (Pin $quality)
  requirements_json = $null; requirements_digest = $null
  base = $null; head = $null; definition_path = $null
}
Save $contractFile ($contract | ConvertTo-Json -Depth 8)
$clearance = Join-Path $lab clearance.json
vstd gates $source --polish-report $fresh --preparation-contract $contractFile --preparation-contract-digest (Pin $contractFile) --output $clearance --json
vstd gates $source --check $clearance --preparation-contract $contractFile --preparation-contract-digest (Pin $contractFile) --json
```

The consumer reruns the selected preparation stages using installed mechanisms
and also replays the existing source/prose admission checks. A missing policy
pin, changed source, changed selected profile, absent required stage or forged
result cannot clear. The stored contract supplies no authority during replay;
the consumer must select it again. `CLEAR` concerns only the applicable local
gate propositions, with `polished: false` and execution authentication
`NOT_ESTABLISHED`. This does not accept a release or authorize publication.

## Stage and explicitly apply authored comments

The default output uses `verifier-polish-workflow-report-1`. The existing source
and prose preparation format remains selectable with
`--report-format verifier-polish-preparation-1`. That format supports its explicit
`--normalize-text` fix; the formats reject mixed options. Neither format issues
polished status or human acceptance.

Inspect `definitions.json`: `example.increment` is a stable authored identifier,
with a target, intent, declared invariant and limit. Its text is authored input,
not proof of what the program does. The second policy explicitly selects comment
projection. This changes the independently admitted workflow and is rebound.

Initialize a repository inside this example directory and retain the fixed
source as a local baseline. Use your usual Git author configuration.

```powershell
git -C $source init
git -C $source add demo.py
git -C $source commit -m 'Retain illustrative source'
$baseline = git -C $source rev-parse HEAD
$applyPolicy = Join-Path $example apply-policy.json
$definition = Join-Path $example definitions.json
$stagedText = vstd polish prepare $source --policy $applyPolicy --policy-digest (Pin $applyPolicy) --definition $definition --quality-profile $quality --quality-profile-digest (Pin $quality) --git-root $source --base $baseline --commit $baseline --output $retained --json | Out-String
```

The staged bundle contains final projected source bytes and
`description.prepared.md`. It reports `PREPARED_PENDING_COMMIT`; it invents no
future commit or pull request (PR). The source directory is still unchanged.
The description and managed comments use the same canonical definition. Source
hashes are calculated after projection, outside source comments, avoiding a
self-referential artifact. Handwritten comments and function docstrings stay
intact.

```powershell
$appliedText = vstd polish prepare $source --policy $applyPolicy --policy-digest (Pin $applyPolicy) --definition $definition --quality-profile $quality --quality-profile-digest (Pin $quality) --git-root $source --base $baseline --commit $baseline --output $retained --apply --json | Out-String
$applied = $appliedText | ConvertFrom-Json
Save (Join-Path $lab applied.json) $appliedText
vstd polish prepare $source --policy $applyPolicy --policy-digest (Pin $applyPolicy) --definition $definition --quality-profile $quality --quality-profile-digest (Pin $quality) --output $retained --apply --json
```

The repeat leaves source bytes unchanged and creates no duplicate annotation.
Applying changed bytes invalidates old source evidence. A retained apply plan
supports [`--recover` and `--rollback`](../reference.html#cli-vstd-polish-prepare);
both compare current bytes first and refuse to overwrite a later user edit.

Commit the prepared example locally when ready, then compare its entire retained
tree with the original immutable preparation bundle:

```powershell
git -C $source add demo.py
git -C $source commit -m 'Retain authored comment projection'
$head = git -C $source rev-parse HEAD
$manifest = Join-Path $applied.bundle.path manifest.json
vstd polish prepare $source --associate $manifest --commit $head --json
```

This separate association observes exact whole-tree bytes and selected modes.
It never rewrites the bundle or establishes authorship, historical timing,
recorder authenticity, a PR link or publication authority. Extra tracked files or
changed bytes refute the whole-tree match. Unselected mode evidence remains
`UNKNOWN`.

## Generate and check committed explanations

[`gate pr`](../reference.html#cli-vstd-gate-pr) compiles Pull Request Domain
Explanation Language (PRDEL) from exact committed source and supported abstract
syntax tree (AST) relationships. Its inspectable intermediate representation
(IR) contains fixed versioned rules, support, assumptions, bounds,
counterexamples and residual questions. It uses no learned or trained rules.

```powershell
vstd gate pr --contract verifier-prdel-1 --root $source --base $baseline --commit $head --generate --compilation --output (Join-Path $lab compilation.json)
vstd gate pr --contract verifier-prdel-1 --root $source --base $baseline --commit $head --document (Join-Path $lab compilation.json) --json
vstd gate pr --contract verifier-prdel-1 --root $source --base $baseline --commit $head --document (Join-Path $lab compilation.json) --render --output (Join-Path $lab committed-description.md)
```

The explicit `verifier-prdel-1` contract requires both selected base and head;
`$baseline` and `$head` above are full local commit identifiers. Selected revisions
are resolved before a successful binding. Modern document, generation and compilation
selectors also select this contract and cannot fall back to metadata diagnostics.
Ordinary `gate pr --file/--text` retains its bounded metadata route; its PASS does
not clear the exact-source PRDEL contract.

Generation and rendering exit `0` when they produce an artifact. For this Python
change, validation still blocks absent behavioral, correspondence and execution
evidence; runtime correctness is not inferred from the source description.
`--generate --template` retains the manual fallback. A narrative-only README
edit can legitimately pass the finite exact-source description contract, while
remaining outside runtime qualification. Independently selected requirements,
consumer policy and exact base/head still bind that check. The five coverage
layers and unresolved analysis frontiers remain visible; cross-branch notices
are retained and unsent.

The installed stage catalogue is shared by help and dispatch:

| Stage | Declared preparation |
| --- | --- |
| `bind-inputs` | Bind selected source, policy and implementation. |
| `validate-definitions` | Parse the canonical authored definition inventory. |
| `project-comments` | Stage managed comments without changing handwritten text. |
| `compile-explanations` | Derive supported facts from exact committed source. |
| `quality` | Run separately selected comment, lint or formatting checks. |
| `retain-bundle` | Retain final bytes and an immutable preparation manifest. |

Existing [`catalog`](../reference.html#cli-vstd-polish-catalog),
[`assess`](../reference.html#cli-vstd-polish-assess),
[`coverage`](../reference.html#cli-vstd-polish-coverage) and
[`check`](../reference.html#cli-vstd-polish-check) retain their bounded meanings.
Preparation keeps `polished:false` and `promotable:false`. Missing promotion
evidence and human release acceptance remain blockers. Publication is a separate
explicitly authorized action.
