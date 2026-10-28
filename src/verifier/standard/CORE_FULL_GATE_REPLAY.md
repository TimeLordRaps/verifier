# Core application full-gate replay

Verifier Standard (VSTD); private implementation candidate, version 1. This
contract does not itself establish application completeness, human acceptance,
release authority, publication authority, model correctness or overall safety.

`verifier-core-application-full-gate-selection-1` is a separately supplied,
externally digest-pinned selection for exactly `APPLICATION_CENSUS`,
`CORE_SELF_POLISH`, `NATIVE_PRDEL`, `REQUIRED_TESTS`, `PUBLIC_CHECKABILITY` and
`ACCEPTANCE`. It binds the exact application selection, requirement document and
installed application mechanism. Each gate selects one or more disjoint required
native certificate instances by identifier and repeats each instance's exact
semantic version, objective and proposition digest. It contains no result or
carried status.

All rows use semantic version `verifier-core-application-full-gates-1`. Their
fixed objectives are `APPLICATION-CENSUS-1`, `CORE-SELF-POLISH-1`,
`NATIVE-PRDEL-1`, `REQUIRED-TESTS-1`, `PUBLIC-CHECKABILITY-1` and
`HUMAN-ACCEPTANCE-1`, respectively. The installed mechanism derives each
proposition digest from the gate name, semantic version, objective and exact
proposition text. A selection cannot redefine those coordinates, including by
making a foreign passing instance and row agree with one another.

The application release checker validates the complete six-row selection before
replay. It rejects missing or duplicate gates, empty or reused instance sets,
foreign instances, changed coordinates, changed input bindings and changed
installed mechanism bytes. A gate is `PASS` only when every selected instance is
freshly replayed `PASS`. Any replayed `FAIL` makes that gate `FAIL`; absent,
cancelled, unavailable or incomplete replay remains `UNKNOWN`.

`APPLICATION_CENSUS` additionally requires every selected kind/tier census to be
`COMPLETE` and the separately replayed application-authority result to establish
authority, interaction coverage, semantic completeness and full application
status. Labels and row counts do not establish that denominator. The other gate
semantics, including authenticated trusted-human acceptance, belong to their
exact selected native propositions and checkers. A generic successful certificate
cannot be reused between gates, and this composer does not mint acceptance.

All six gates, finite binding, native replay and external digest pins must pass for
the application assessment to report polished release readiness. That bounded
result remains distinct from merge, tag, publication and deployment authority.
