# Experimental workflow example

This deterministic example maps a normalized GitHub snapshot containing a successful
workflow, an available artifact, a closed issue, a commit, and a merged pull request.
All five records remain platform observations with `verification_effect = "NONE"`.

From the repository root:

```bash
PYTHONPATH=src python examples/experimental_workflow/demo.py
```

Expected boundary:

```text
events: 5
vstd_verdicts_granted: 0
```

The example demonstrates portable workflow serialization and non-upgrade behavior. It
does not contact GitHub, validate a signature, execute a domain verifier, or establish
that the issue, commit, workflow, artifact, or merged change is correct.
