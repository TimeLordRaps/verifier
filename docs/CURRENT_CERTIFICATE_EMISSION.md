# Current-certificate emission eligibility

This local bridge applies to the current Simulation (SIM) finite-confinement
certificate and HYPER finite operand-closure certificate. The generic privacy
no-redaction guard also covers the current `OBJECT-1.1` generic-facets certificate
and `VERIFIER-2.1` native simulation-checker and `RECEIPT-9.1` selected receipt-chain
certificates, plus the declared structural-facet, identity-scope and retained
dataset, environment, benchmark, training, model, harness, agent, BOT and full-record
disclosure certificate formats.
It is part of the
Verifier Standard (VSTD) reference implementation, not a whole-tier conformance
claim. Its inputs are canonical JavaScript Object Notation (JSON) certificate
bytes and independently selected request, policy, kind, disclosure surface,
bounds, and observer context. Byte ceilings count encoded bytes; node and depth
limits are dimensionless. Secure Hash Algorithm 256-bit (SHA-256) digests bind
selected values but do not authenticate a host or observer.

The current certificates include `evidence_payloads`, which may contain private
material. HYPER's test fixture retains a private canary in that field. Neither a
top-level field commitment nor a rehashed partial envelope is a selective proof.
Until such a proof format exists, a current certificate is eligible for local
emission assessment only when **every canonical field is admitted with a bound**
and the resulting canonical bytes equal the exact input bytes. Missing, denied,
or withheld fields cause refusal. The generic privacy helper also refuses
redaction of all sixteen current canonical schemas, as it already does for the
legacy canonical domain certificate. Noncanonical selective disclosure remains
available. These guards prevent replay-breaking projections; they do not
add OBJECT, VERIFIER or RECEIPT to the bridge's native route dispatch.

`evaluate_current_certificate_emission` snapshots bounded exact plain selection
values once, before native replay or disclosure evaluation. The kind is selected
by the caller as exactly `SIM` or `HYPER`; no carried request, policy, receipt, or
schema chooses an authority. The selected native rechecker replays the intact
certificate against the external request and policy. The privacy helper then
assesses all fields against the captured disclosure inputs. The bridge requires
whole-byte equality and repeats native replay against the same captured
selection. Unsupported formats, malformed inputs, failed replay, substitutions,
false bounds, changed outcomes, and resource-bound exhaustion refuse admission.
Later benign caller mutation cannot mix the selection within an invocation.

The bundled generic composition screen cannot read a current SIM or HYPER kind
from `request.domain`, because current requests use a different shape. The bridge
reruns that *same listed-pair screen* with the independently selected primary
kind. A `MODEL` co-emission therefore still triggers the listed `MODEL`+`SIM`
risk. Every co-emitted record needs a usable declared object label; an unlabeled
current certificate is refused until an externally bound co-emission descriptor
exists. A declared label is not authenticated by this local helper, and the
screen does not prove general composition safety.

`OBJECT-1.1` names a **generic representation objective**, while its externally
selected `request.object_kind` names the represented subject. A SIM record can
therefore have an OBJECT-facets certificate without becoming a generic OBJECT
kind for disclosure or composition. A future native OBJECT-facets route needs
two independent external selectors: certificate route `OBJECT-1.1` and
represented kind (for example `SIM`, `HUMAN`, or `HYPER`), with the latter bound
to the selected request's `object_kind` and the disclosure surface. Composition
screening must use that represented kind, while native checker dispatch uses the
certificate route. The current bridge intentionally does not dispatch this
incoming candidate until that two-coordinate contract is implemented and tested.

`replay_status = REPRODUCED` means the native computational result reproduced
locally. `computational_status` remains the native `PASS`, `FAIL`, or `UNKNOWN`:
a valid negative or indeterminate certificate can reproduce without becoming
computational `PASS`. This bridge returns no network action, publication receipt,
or permission token. Its generic privacy receipt still says
`certificate_validation = NOT_CHECKED` and
`observer_authentication = NOT_CHECKED`; the distinct bridge replay field is
the only statement about native local reproduction. The helper-source and
bridge-source digests are replay bindings, not loaded-code attestation or an
independent correctness proof.

Rechecking treats the carried result as untrusted data. It requires exact
bundled record types and exact plain scalar/collection values, checks byte,
text, node and depth ceilings before copying or serialization, and captures
the carried result before rerunning any checker. Custom equality methods,
`to_dict` overrides, and later benign caller mutation cannot change the
comparison. Exact recursive type comparison also distinguishes integers from
numerically equal floating-point values and distinguishes the signed floating
zero encodings. The separate snapshot limits are sized for a complete current
certificate and its duplicated local assessment, not just a one-mebibyte
selection descriptor. A mebibyte is 1,048,576 bytes.

The existing [`controlled_emission.py`](../src/verifier/controlled_emission.py)
already composes native replay with privacy, signed consent and governance
decisions for legacy domain certificates. Its retained
`evaluate_controlled_emission` entry point admits only
`verifier-domain-certification-1` and expects `request.domain`; neither current
certificate has that legacy shape. The distinct
`evaluate_controlled_current_emission` entry point joins current `SIM-5.1` and
`HYPER-4.1` under `verifier-current-object-obligations-1` to that **single**
consent/governance admission contract. The caller supplies semantic version,
objective, represented kind, expected request, computational policy, action,
disclosure selections, consent and governance evidence, their independently
trusted policies and current evaluation time. Carried certificates choose none
of those authorities. Other current routes, including OBJECT and GRAPH, remain
unsupported by this controlled entry point.

The artifact identity is the lowercase hexadecimal SHA-256 of the complete
canonical input bytes, including the certificate's own digest. It binds the
signed action, consent artifact binding and governance decision. The object,
observer, purpose and exact integral-second disclosure timestamp must match
that action. All input selections are bounded and captured before any gate.
Current bridge output is separately captured as exact plain data, then replayed
through `recheck_current_certificate_emission` against the same external
selection. A bridge result, digest, numeric equality or carried PASS cannot
replace that replay. The legacy output guard likewise compares emitted bytes
against immutable originally authorized bytes, including when a later gate
mutates its captured source.

`admitted_computational_statuses` defaults to the plain tuple `("PASS",)`.
Operators may explicitly admit faithfully reproduced FAIL or UNKNOWN for
disclosure, for example when sharing an unsuccessful computational claim.
That admission preserves the computational result in both authority receipts;
it never promotes FAIL or UNKNOWN into computational PASS. Under the default
policy a reproduced FAIL rejects emission and a reproduced UNKNOWN leaves
admission UNKNOWN. Revocation, forged authority, missing full-field bounds and
scope substitution still prevent emission. Missing trusted policy or clock
remains UNKNOWN unless another check establishes a rejection.

Only aggregate PASS returns `emitted_certificate_bytes`, exactly equal to the
input. The unsigned `verifier-controlled-current-emission-1` receipt binds
external selection, captured gate evidence and loaded helper source digests.
`recheck_controlled_current_emission` captures the carried result before rerunning
the complete admission flow with external selections and compares the exact wire
receipt and bytes. New source bytes, policy, observer, signed status or clock
invalidate old replay evidence where they change the result. Keys remain private
operator configuration and are not serialized into either aggregate receipt.

The certificate limit is sixteen mebibytes. Aggregate input capture is bounded
by sixty-four mebibytes, 150,000 nodes, depth 80 and 10,000 entries per container;
integers are bounded to 4,096 bits. Current bridge output and carried receipt
captures use their own budgets of that same size. Exact class identity checks
refuse foreign record, mapping and metaclass callbacks before invoking them.
These are finite local admission limits, not atomic concurrent-host capture.

The entry points reuse existing signatures, grants, quorum, revocation and
privacy evaluation; they implement no new authority engine. Invocation
consumption and external execution remain `NOT_PERFORMED`, while normative
privacy, consent and governance tier conformance remains UNKNOWN. Receipts are
private operator audit material until separately disclosure-reviewed. They are
not permission tokens, publicly checkable proofs, polished-artifact closure or
publication receipts, and they do not authenticate caller-supplied observer facts.

Full retained evidence must remain private unless that separate controlled
disclosure decision and destination policy authorize transmission. The bridge
does not establish privacy, consent, governance, physical isolation, ownership,
general composition safety, whole-tier conformance, or correctness beyond exact
local replay. No external execution or transmission occurs here.
