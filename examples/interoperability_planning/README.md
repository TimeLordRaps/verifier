# Experimental interoperability planning example

This runnable, non-critical example models one question: whether a grocery list is in
Python's default lexicographic string order. It then detects holes in a typed Verifier
Standard (VSTD)-2 geometry and matches those holes against one experimental checker
descriptor:

```text
typed VSTD-2 geometry
  -> modeled-hole analysis
  -> exact catalog candidates
  -> nonexecuting validation plan
```

After installing this checkout, for example with `python -m pip install -e .`, run:

```bash
python examples/interoperability_planning/demo.py
```

The deterministic report contains five modeled holes, two exact component candidates,
and three unmatched self-closure requirements. It also binds the registry version and
digest into the plan. `plan_only` is `true`, `execution_performed` is `false`, and the
checker invocation count remains zero.

Here, **validation** names a future process that would attempt to discharge verification
surface holes using bound execution evidence and then reassess the geometry. This example
only detects and plans. Catalog membership does not establish availability at execution
time, checker correctness, a native result, ordinary or self-closure, safety, authority to
act, critical-domain readiness, or Verifier Standard conformance.

The example accepts a typed in-memory `VerificationGeometry`. Strict VSTD-2 wire loading,
a command-line interface, component execution, and post-execution reanalysis remain
unsupported.
