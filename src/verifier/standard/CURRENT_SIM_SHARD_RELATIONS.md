# Current simulation cross-shard relations (`SIM-4.2`)

Verifier Standard (VSTD) selects this finite simulation (SIM) obligation under
`verifier-current-object-obligations-1`. JavaScript Object Notation (JSON) is
canonicalized and Secure Hash Algorithm 256-bit (SHA-256) binds the selected
bytes. The retained state values have the model's externally declared units;
the checker does **not** prove that a selected expression is dimensionally
homogeneous. Byte limits count bytes; item and operation limits are
dimensionless.

**Exact proposition:** An externally selected `SIM-4.1` certificate replays
`PASS` on the identical SIM subject and collection. The externally selected
nonempty list of finite relation expressions each references at least two
distinct declared shards, and each expression evaluates to Boolean `true`
at every retained aligned shard time. Relations use the bounded installed
arithmetic/Boolean expression interpreter with variable names of the form
`<shard>.<state-key>`. The variables come only from the child certificate's
retained per-shard rows. This is equality and ordering of finite records,
not observation of a physical system.

The consumer selects the subject, collection and object digests, exact child
request, policy and certificate commitments, relation-list commitment,
evidence reference, policy and resource bounds. The certificate retains the
full child request, policy and certificate bytes and the selected relation
expressions. Replay verifies every selected commitment, rechecks the exact
`SIM-4.1` child rather than trusting its carried verdict, extracts its retained
aligned rows, and evaluates every selected relation at every retained time.
The parent's operation budget charges retained structure, child certificate
bytes and expression traversal/evaluation; the child separately enforces its
own bounds.

A known false relation, an empty list, a relation involving fewer than two
different shards, a missing variable in a retained row, or substituted child
material yields `FAIL` or selection refusal. An absent child or exhausted
admitted checking capacity remains `UNKNOWN`. The public route is:

```text
vstd current-object check <certificate> --semantic-version verifier-current-object-obligations-1 --objective SIM-4.2 --represented-kind SIM --request <request> --policy <policy>
```

`PASS` establishes only the selected finite relation list over retained rows.
It does not establish every possible cross-shard relation, dimensional
validity, physical truth, historical execution, independent shard origin,
signatures, no unattributed transition, whole simulated-surface accounting,
complete closure-tier conformance, or object-profile conformance. Privacy,
consent, governance, security, spending and publication remain separate.
Changing the selected child, any relation, state row, policy, implementation
or this specification invalidates prior replay evidence. The canonical
`verifier-current-sim-shard-relations-certificate-1` envelope binds its exact
request, mechanism, proposition, evidence bytes and result; the installed
rechecker rebuilds that envelope byte for byte.
