# Threat model

> **Acronyms:** central processing unit (CPU); Boolean satisfiability problem (SAT);
> unsatisfiable (UNSAT); Verifier Standard (VSTD).

## Assets

- exact instance, route, formula, decoder, solver result, candidate, native verdict, bounds, and timing associations;
- preservation of `UNKNOWN` and route-local `UNSAT`;
- separation of generic harness code from domain-specific adapters;
- exclusion of private LM coordinates from public artifacts.

## Adversaries and failures

1. **Prompt/proposal ambiguity:** the LM emits extra fields, unknown constraints, invalid domains, or a decoder that drops slots. The closed compiler rejects the route.
2. **Route transplant:** a formula or candidate is moved to another instance or verifier. Canonical instance, contract, proposal, formula, and candidate digests break the binding.
3. **Claim promotion:** route-local `UNSAT`, timeout, or rejection is described as a domain verdict. The result validator derives `PASS` only from SAT plus native acceptance; everything else remains `UNKNOWN`.
4. **Generate-and-check disguised as SAT assistance:** the LM fixes every witness slot. The harness labels the route generate-and-check-equivalent and excludes it from SAT-benefit claims.
5. **Weak baseline:** a deliberately poor encoding inflates an apparent gain. Arm A uses complete encodings justified in `baselines.py`; its domain-specific surface is reported separately.
6. **Hidden held-out tuning:** prompts or generic logic change after held-out inspection. The freeze manifest hashes generic components before any live held-out run and results must bind those hashes.
7. **Verifier bugs or dependency compromise:** a candidate passes an unsound predicate. VSTD cannot remove this trust root; reserves and reexecution can expose disagreement but cannot prove soundness.
8. **Telemetry nondeterminism:** wall time and some solver counters vary with platform and load. Development noise is measured, medians are used, and the threshold exceeds measured noise.
9. **Receipt mutation:** an artifact changes after recording. Canonical digests, graph node hashes, formula recompilation, solver reexecution, and native-verifier reexecution detect the tested mutations.
10. **Private-coordinate leakage:** an endpoint, credential, private model identifier, or local path enters logs/results. Public configuration is redacted by construction and an explicit text scan gates publication.

## Out of scope

- proving the external verifier implementation sound;
- global UNSAT without a complete independently demonstrated encoding;
- resistance to a malicious operating system, Python runtime, SAT binary, or dependency;
- cryptographic signatures, confidentiality, zero knowledge, identity, authorization, or revocation;
- reproducible LM identity when the implementation identity is withheld;
- physical isolation or side-channel resistance.

## Residual risks

- PySAT's selected CaDiCaL binding exposes no independently checkable UNSAT certificate in this experiment.
- `perf_counter_ns` measures elapsed time but does not normalize CPU scheduling, thermal state, or concurrent load.
- Same-input creation and full-reverification probes are bound into the final
  record. The final build and its post-binding QA cannot recursively include
  their own elapsed time, so `total_system_probe` is explicitly a one-pass probe
  rather than the wall time at which the final file finished writing.
- Reserve verifier agreement is corroboration, not a formal proof that either predicate matches an external specification.
