# Claim boundary

> **Acronyms:** Boolean satisfiability problem (SAT); unsatisfiable (UNSAT);
> Verifier Standard (VSTD).

## Permitted rule

For a bound route `R`:

```text
SAT(R) -> decoded candidate w -> native verifier ACCEPTED
```

permits only: **the exact candidate `w` passed the pinned native verifier predicate for the exact digested instance under the recorded environment and configuration.**

The record's `bounded_claim_status` may be `PASS` only in that case.

For Arm B, the corresponding permitted rule omits SAT completion: a complete
candidate may pass only after the same pinned native verifier accepts it. An
accepted Arm B record is evidence for that exact candidate/predicate execution,
not evidence of SAT assistance.

## Mandatory UNKNOWN outcomes

- `UNSAT(R)` means only that the compiled route formula has no assignment under the selected solver observation.
- Rejected candidates, malformed proposals, verifier errors, solver `UNKNOWN`, timeouts, limits, and exhausted routes remain `UNKNOWN` about existence of a valid domain witness.
- Multiple failed routes do not accumulate into global nonexistence.
- A VSTD-valid binding establishes internal artifact/digest/lineage checks, not native-verifier soundness.

## Easier and faster

“Easier SAT” is reserved for lower observed work from the same pinned solver on accepted candidates, using decisions, conflicts, propagations, and SAT time. Fewer variables or clauses alone is insufficient.

“Faster” is reserved for correctness-preserving end-to-end improvement beyond the preregistered 10% aggregate threshold, including LM, harness, SAT, verifier, VSTD creation-probe, and VSTD reverification overhead.

Neither phrase is currently justified because Arms B and C were not run with a real LM.

## Identity and trust

No identity is required to rehash or reexecute a record. Missing identity does not prove independence, uniqueness, authorization, Sybil resistance, or trustworthiness. This experiment does not establish zero knowledge, anonymity, or confidentiality; route and witness payloads are disclosed in baseline records.

## Scope

Any future positive result remains bounded to the three pinned verifier implementations, 60 manifest instances, frozen prompts/harness, one withheld local LM implementation, selected machine class, and the recorded time window. It would support verifier-first witness search, not universal SAT acceleration, domain-global UNSAT, or a self-verifying standard.
