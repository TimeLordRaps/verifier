# Current simulation perspective alignment

Verifier Standard (VSTD) registers `SIM-2.5` as one bounded current-object
obligation for a generative simulation (SIM). The separate legacy numbered
profile retains its original interpretation; this certificate uses
`verifier-current-object-obligations-1` explicitly. It does not close the whole
simulation dynamics tier or object profile.

The externally selected exact `SIM-2.3` child must replay as `PASS`. Its
embedded passing `SIM-2.1` artifact and inputs bind the micro trajectory,
projection expressions, aligned macro states, tolerance and a declared common
macro unit. The checker executes the installed finite `refinement` interpreter
over every retained state and compares each projected macro value against its
same-index retained value under the selected nonnegative absolute tolerance.
The projected value, target and tolerance share the declared macro unit;
operation/item counts have no physical unit and byte bounds count bytes.
The checker does not prove that an expression has that unit, that the unit
declaration is authoritative, or that the macro trajectory came from an
independent producer.
The selected tolerance is not independently calibrated: a loose tolerance
can make numeric alignment uninformative even while the bounded check passes.

The request binds subject, object and collection digests, exact child bytes,
projection and macro-state digests, absolute tolerance, common unit, policy,
mechanism and finite limits. The certificate retains its child bytes so a
separate reader can rerun both child mechanisms and this projection. An
altered selected value, wrong child, mismatched macro value, malformed present
record or changed policy is `FAIL` or rejected as a substituted certificate.
Absent selected projection or macro evidence, an unknown prerequisite,
unsupported expression or exhausted bounded interpreter is `UNKNOWN`.
A failed prerequisite is `FAIL` even if the parent projection is absent.
No digest or self-reported `PASS` replaces execution.

This establishes only numeric alignment of the selected finite model and
retained trace. It does not establish historical execution, physical
correspondence, an independent macro-state source, general refinement or
bisimulation, unselected states, privacy, consent, governance, security or
publication authority. A `PASS` at this coordinate does not automatically
produce a polished artifact.
