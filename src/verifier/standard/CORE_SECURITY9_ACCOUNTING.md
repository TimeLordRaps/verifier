# Core Security-9 accounting mechanism

Private candidate, version 1. This mechanism binds one exact finite Security-9
selection to the installed source, core requirements, consumer source coordinate,
and independently supplied digest pins. It does not authenticate the selected
application's required-instance denominator.

The installed native route registry is a distinct, source-derived denominator: it
contains 26 retained-`ObjectKind` Security-9 family cells and 29 registered
Security-9 route definitions. Closing
that registry enumeration does not decide which definitions apply to a concrete
application and does not authenticate child, interaction or certificate-instance
completeness. The accounting mechanism digest transitively binds the progression
mechanism and the inventory source from which that registry is derived.

The selection contains exactly one family row for each of the 26 retained native
`ObjectKind` values at core rank 9. This is not a 38-kind extensible-namespace
closure claim. Each selected native instance binds the complete requirement
row, threat model, trusted roots, execution scope, checker mechanism, request,
policy, at least one falsifier, native-child requirements, and interaction
requirements. Child and interaction records carry their own source, claim,
checker, and falsifier bindings. Missing, duplicated, substituted, or unassociated
records are structural failures.

A child or interaction record whose `required_status` remains `UNKNOWN` keeps the
corresponding dependency or interaction census explicitly blocked even when the
owning instance labels its selected finite list `COMPLETE`. List conservation does
not establish applicability.

`COMPLETE` is only a conservation claim about a separately selected finite list.
`UNKNOWN` is retained when the selected source does not establish applicability.
Even a structurally passing result reports semantic completeness, public
checkability, human acceptance, overall safety, and release admissibility as
unknown or false. Capacity exhaustion and cancellation also remain `UNKNOWN`;
known structural contradictions are `FAIL`.

The native nine-tier contract is distinct from the separately versioned ten-tier
Security-6 and Corrigibility-10 extension. Neither extension coordinate receives
core Security-9 credit.
