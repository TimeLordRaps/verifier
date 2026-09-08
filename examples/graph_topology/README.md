# Boolean switches and declared backward time

This non-critical Verifier Standard (VSTD) specimen exercises the experimental
[graph-topology analyzer](../../docs/GRAPH_TOPOLOGY.md), not a numbered profile.
Use Python 3.10 or newer with this checkout installed (`python -m pip install -e .`).
No optional dependencies are required. Run from the repository root:

```bash
python examples/graph_topology/demo.py
python examples/graph_topology/demo.py --output-dir topology-example
vstd data topology topology-example/receipt.json --contract topology-example/contract.json --json
```

The script prints a JavaScript Object Notation (JSON) report. `build_example()` returns
the typed graph and contract for direct reuse. Export requires an entirely absent
directory: an existing directory, file, or symbolic link is refused without overwriting.
Export failures may leave an incomplete new directory; inspect it before retrying.

`before.txt` and `after.txt` contain exactly `b'before\n'` and `b'after\n'`. Their
content digests hash those literal declaration bytes; relative `storage_uris` locate
them beside the exported documents. In-memory mode retains the bytes in `DECLARATIONS`.
They name model variables, not observed switch states. Origin and artifact status remain
`UNKNOWN`; normalization is a declared transformation with execution/provenance unknown.
`receipt.json` is only a graph inspection envelope, **not a validated full receipt**.

The simultaneous Boolean equalities `before = false`, `after = not before` have witness
`before=false`, `after=true`; equation order does not prescribe evaluation order.
The clock `declared-counter` separately declares `t(after) = t(before) - 1 tick`, where
a tick is one integer logical step. Both consistency facets and structural projection
should report `CONSISTENT`; the declared construction graph is acyclic despite the backward-time
model relation. This is not physical retrocausation or a measured clock.

Analysis checks the bound declarations, not payload file values or physical switches.
It does not validate provenance or issue TRUST, the formal name for mechanism-earned
forward artifact support. The equations are not an independent proof certificate, and
consistent modeled constraints do not grant permission to operate a real system.
