# VSTD-3 official public references

**Retrieved:** 2026-08-21

These sources inform adapter boundaries and interoperability vocabulary. They are not
copied into VSTD, and their presence does not show that a product implements the VSTD
Firmware Accountability Contract.

## Cross-vendor attestation and device security

- [DMTF SPDM standards page](https://www.dmtf.org/standards/spdm) — authentication,
  attestation, measurements, and key exchange; the page listed DSP0274 1.4.0 when
  retrieved.
- [IETF RFC 9334: RATS Architecture](https://datatracker.ietf.org/doc/html/rfc9334) —
  roles and trust model for attestation evidence and appraisal.
- [IETF RFC 9711: Entity Attestation Token](https://datatracker.ietf.org/doc/html/rfc9711)
  — interoperable attestation claims, nonce/freshness, and composite-device concepts.
- [CHIPS Alliance Caliptra](https://github.com/chipsalliance/caliptra) — open root of
  trust, measured boot, identity, and attestation project for datacenter SoCs.
- [PCI-SIG PCI Express Base resources](https://pcisig.com/specification-overview/pci-express-base)
  — public listings for Component Measurement and Authentication, IDE, DOE, and TDISP.
- [PCI-SIG IDE public ECN page](https://pcisig.com/PCI%20Express/ECN/Base/IntegrityandDataEncryption)
  — public description of confidentiality, integrity, and replay protection for PCIe
  transaction traffic.

## NVIDIA

- [NVIDIA Attestation SDK evidence collection](https://docs.nvidia.com/attestation/quick-start-guide/latest/attestation-examples/collecting_evidence.html)
  — public GPU/NVSwitch evidence collection and SPDM/certificate evidence path.
- [NVIDIA GPU claims guide](https://docs.nvidia.com/attestation/advanced-documentation/latest/claims-guide/gpu_claims.html)
  — public descriptions of nonce, certificate, measurement/RIM, and GPU identity claims.
- [NVIDIA Attestation Core Library](https://docs.nvidia.com/attestation/corelib/latest/introduction.html)
  — verifier library boundary.
- [NVIDIA MIG guide](https://docs.nvidia.com/datacenter/tesla/mig-user-guide/latest/getting-started-with-mig.html)
  and [NVML MIG APIs](https://docs.nvidia.com/deploy/nvml-api/group__nvmlMultiInstanceGPU.html)
  — host-visible partition and logical identity discovery.

## AMD

- [AMD SMI CLI documentation](https://rocm.docs.amd.com/projects/amdsmi/en/latest/how-to/amdsmi-cli-tool.html)
  — host-visible inventory, firmware, and telemetry collection.
- [AMD SMI partition documentation](https://rocm.docs.amd.com/projects/amdsmi/en/latest/conceptual/partition.html)
  — accelerator partition concepts.
- [AMD SMI Python API](https://rocm.docs.amd.com/projects/amdsmi/en/latest/reference/amdsmi-py-api.html)
  — programmatic collector surface.

AMD SMI metadata is not treated as DICE or firmware attestation by the reference
adapter. A public, accessible evidence format plus verifier/root policy is still needed
before that claim can be implemented.

## Cloud accelerator product context

- [Google Cloud TPU7x documentation](https://docs.cloud.google.com/tpu/docs/tpu7x)
- [AWS Neuron device management](https://docs.aws.amazon.com/eks/latest/userguide/device-management-neuron.html)
- [Microsoft Maia 200 announcement](https://blogs.microsoft.com/blog/2026/01/26/maia-200-the-ai-accelerator-built-for-inference/)

These links establish product/deployment vocabulary only. They do not establish a
tenant-accessible firmware attestation API or complete mediation.
