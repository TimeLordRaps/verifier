# Current simulation shard coverage (`SIM-4.1`)

Verifier Standard (VSTD) uses a separate current-object semantic version for
this finite generative simulation (SIM) objective. JavaScript Object Notation
(JSON) is canonicalized, and Secure Hash Algorithm 256-bit (SHA-256) binds
selected bytes. State and time values use the selected model's declared units;
counts and operation limits are dimensionless, while transport limits use bytes.

**Exact proposition:** For one externally selected SIM subject and collection,
an exact `SIM-2.1` trajectory certificate replays `PASS`. The separately
selected declared shard identifiers equal the complete retained shard map.
Every declared shard has exactly one nonempty finite state row for every
retained trajectory state, ordered by and exactly matching its selected causal
time. This is equality of finite retained records, not a physical observation.

The consumer selects the SIM subject and collection digests, child request,
policy and certificate digests, shard-identifier and shard-row digests, retained
evidence byte digest, checker policy and resource limits. The evidence retains
the complete child request, policy, certificate bytes, identifiers and rows.
The checker recomputes all selected commitments, verifies the child's exact
subject and `SIM-2.1` objective, reruns the installed child mechanism, then
compares every shard row with the child's retained state/time arrays. A carried
child verdict, rehashed parent verdict, altered request or substituted bytes
cannot supply `PASS`.

`PASS` means only this selected finite shard-time inventory is complete and
aligned. A missing child or exhausted admitted capacity yields `UNKNOWN`;
known malformed, substituted, duplicate, missing, extra, short, nonfinite or
misaligned material yields `FAIL` or a selection refusal. Cross-shard relations,
signatures, independently authenticated shard origins, unretained states,
historical execution, whole simulated-surface accounting, complete closure-tier
conformance and object-profile conformance remain `NOT_ESTABLISHED`. Privacy,
consent, governance, security, spending and publication require separate gates.

The current-object public route is:

```text
vstd current-object check <certificate> --semantic-version verifier-current-object-obligations-1 --objective SIM-4.1 --represented-kind SIM --request <request> --policy <policy>
```

The `verifier-current-sim-shard-coverage-certificate-1` envelope retains its
exact request, mechanism and proposition commitments, evidence bytes, result
and digest. The installed rechecker reruns the selected mechanism and compares
the complete canonical envelope, including its result. A local replay is not
proof of historical execution or public authority over the selected shards.
Changing the subject, collection, child checker, selected trace, shard rows,
policy, implementation or this specification invalidates prior replay evidence.
