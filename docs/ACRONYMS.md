# Acronyms and abbreviated terms

This is the canonical expansion key for the Verifier Standard (VSTD) repository. Every
independently readable document and source file must still expand each term at its first
reader-facing use; this page is a reference, not a substitute for local clarity. Frozen wire
identifiers, code symbols, filenames, and third-party names remain byte-for-byte unchanged.

`TRUST`, `ROT`, and `RUST` are deliberately absent from the expansion table because they
are formal semantic names, not acronyms. They mean mechanism-earned forward artifact
support, typed time-indexed degradation of current admissibility, and inverse-TRUST
diagnostic traversal, respectively. `RUST` is not the Rust programming language. Their
normative definitions are in [`standard/LADDER.md`](../src/verifier/standard/LADDER.md).

| Term | Expansion used in this repository | Scope note |
|---|---|---|
| `AFA` | Anti-Foundation Axiom | Aczel's axiom in non-well-founded set theory. |
| `AI` | artificial intelligence | General field. |
| `AMD` | Advanced Micro Devices | Vendor name. |
| `ANSI` | American National Standards Institute | Standards organization. |
| `APG` | accessible pointed graph | Graph representation in non-well-founded set theory. |
| `API` | application programming interface | Software interface. |
| `ARM64` | 64-bit Arm instruction-set architecture | Processor architecture. |
| `ASCII` | American Standard Code for Information Interchange | Text encoding. |
| `ASIC` | application-specific integrated circuit | Purpose-built processor class. |
| `AST` | abstract syntax tree | Parsed program structure. |
| `AVX-512` | Advanced Vector Extensions 512-bit | Processor instruction-set extension. |
| `AWS` | Amazon Web Services | Cloud provider. |
| `CBOR` | Concise Binary Object Representation | Binary data format. |
| `CCF` | Confidential Consortium Framework | Ledger framework used by one SCITT profile. |
| `CD` | continuous delivery or deployment | The delivery/deployment half of CI/CD workflow shorthand. |
| `cgroups` | control groups | Linux kernel resource-isolation feature. |
| `CI` | continuous integration | Automated repository checks. |
| `CLI` | command-line interface | Terminal-facing program surface. |
| `CNF` | conjunctive normal form | Boolean-formula representation. |
| `COSE` | CBOR Object Signing and Encryption | Signed-message and receipt envelope family. |
| `CPU` | central processing unit | Processor class. |
| `CRLF` | carriage return and line feed | Two-character line ending. |
| `CRN` | chemical reaction network | Chemical process and molecular computation model. |
| `CSV` | comma-separated values | Delimited tabular text format. |
| `CT` | Certificate Transparency | Public certificate-log system. |
| `CUDA` | Compute Unified Device Architecture | NVIDIA parallel-computing platform. |
| `CVE` | Common Vulnerabilities and Exposures | Public vulnerability identifier system. |
| `CWT` | CBOR Web Token | Claim set used in COSE messages. |
| `DAG` | directed acyclic graph | Graph with directed edges and no directed cycle. |
| `DICE` | Device Identifier Composition Engine | Device-attestation architecture. |
| `DMTF` | DMTF standards organization | Current organizational name; do not invent a modern expansion. |
| `DNA` | deoxyribonucleic acid | Biological or molecular computing substrate. |
| `DOE` | design of experiments | Experimental-design method. |
| `DOI` | digital object identifier | Publication identifier. |
| `DPE` | DICE Protection Environment | DICE execution and key-derivation component. |
| `DPLL` | Davis-Putnam-Logemann-Loveland | Boolean satisfiability algorithm. |
| `DRAM` | dynamic random-access memory | Volatile working memory technology. |
| `DRAT` | deletion resolution asymmetric tautology | Clausal refutation format. |
| `EAT` | Entity Attestation Token | Attestation claim format. |
| `ECN` | Engineering Change Notice | Standards-change document. |
| `ELF` | Executable and Linkable Format | Binary executable format. |
| `EU` | European Union | Political and regulatory body. |
| `FLOP` | floating-point operation | Compute-work unit. |
| `FRAT` | flexible SAT proof format | Solver-to-elaborator proof format; use the proper format name rather than inventing a letter-by-letter expansion. |
| `FSM` | finite-state machine | State-transition model. |
| `GB` | gigabyte | Storage or memory capacity unit. |
| `GDC` | grounded decision certificate | VSTD-4 certificate family. |
| `GHSA` | GitHub Security Advisory | Security advisory database and identifier. |
| `GPG` | GNU Privacy Guard | Signature tool. |
| `GPU` | graphics processing unit | Accelerator class. |
| `GRAT` | GRAT proof format | Proper name of a hinted SAT proof format; no documented letter-by-letter expansion is asserted here. |
| `HMAC` | hash-based message authentication code | Keyed authentication construction. |
| `HTML` | Hypertext Markup Language | Web-page format. |
| `HTTP` | Hypertext Transfer Protocol | Web transfer protocol. |
| `HTTPS` | Hypertext Transfer Protocol Secure | HTTP protected by transport security. |
| `ID` | identifier | Stable name or coordinate. |
| `IDE` | integrated development environment | Programming application. |
| `IETF` | Internet Engineering Task Force | Internet standards organization. |
| `IPC` | inter-process communication | Operating-system process communication mechanisms. |
| `IR` | intermediate representation | Program or proof representation. |
| `ISO` | International Organization for Standardization | Standards organization. |
| `JSON` | JavaScript Object Notation | Structured text format. |
| `JSONL` | JSON Lines | One-JSON-value-per-line format. |
| `JUnit` | Java unit test report format | Test result report format. |
| `LF` | line feed | Single-character line ending. |
| `LRAT` | linear resolution asymmetric tautology | Hint-carrying clausal refutation format. |
| `MIG` | multi-instance GPU | NVIDIA accelerator-partitioning feature. |
| `ML` | machine learning | General field. |
| `NIST` | National Institute of Standards and Technology | United States standards agency. |
| `NP` | nondeterministic polynomial time | Computational-complexity class. |
| `NPU` | neural processing unit | Machine-learning accelerator class. |
| `NVML` | NVIDIA Management Library | NVIDIA device-management interface. |
| `OS` | operating system | Host software environment. |
| `PCC` | proof-carrying code | Producer-supplied proof checked by a consumer. |
| `PCI` | Peripheral Component Interconnect | Hardware interconnect family. |
| `PCI-SIG` | PCI Special Interest Group | PCI standards consortium. |
| `PCIe` | Peripheral Component Interconnect Express | High-speed computer bus standard. |
| `PEM` | Privacy-Enhanced Mail | Cryptographic key and certificate container format. |
| `POPL` | Principles of Programming Languages | Research conference. |
| `PR` | pull request | Version-control change-proposal mechanism. |
| `PROV` | World Wide Web Consortium provenance vocabulary | W3C provenance standard family. |
| `PROV-DM` | PROV data model | W3C provenance data model. |
| `PS` | Protect the Software | NIST SSDF practice group. |
| `PyPI` | Python Package Index | Python software package repository. |
| `RAM` | random-access memory | Working memory. |
| `RAT` | resolution asymmetric tautology | Clausal redundancy property. |
| `RATS` | Remote Attestation Procedures | IETF attestation architecture. |
| `RFC` | Request for Comments | IETF publication series. |
| `RIM` | Reference Integrity Manifest | Trusted reference-measurement set. |
| `RISC` | reduced instruction set computer | Processor architecture family. |
| `RISC0` | RISC Zero | Product-name prefix used by RISC Zero tooling. |
| `RNG` | random number generator | Entropy or pseudorandomness source. |
| `RUP` | reverse unit propagation | Clausal proof-checking rule. |
| `SARIF` | Static Analysis Results Interchange Format | Static-analysis output format. |
| `SAT` | Boolean satisfiability problem | Decision problem and solver class. |
| `SBOM` | Software Bill of Materials | Software component inventory metadata. |
| `SCITT` | Supply Chain Integrity, Transparency, and Trust | IETF architecture and working group. |
| `SCRAPI` | SCITT Reference APIs | SCITT registration and receipt-resolution interface draft. |
| `SDK` | software development kit | Developer-facing library and tools. |
| `SHA-256` | Secure Hash Algorithm 256-bit | Cryptographic digest algorithm. |
| `SHA3-256` | Secure Hash Algorithm 3 256-bit | Cryptographic digest algorithm. |
| `SIGKILL` | signal kill | Operating-system termination signal. |
| `SLSA` | Supply-chain Levels for Software Artifacts | Software supply-chain framework. |
| `SMI` | system management interface | Vendor device-management interface. |
| `SMT` | satisfiability modulo theories | Decision-procedure family. |
| `SMT-LIB` | SMT library standard | Common language and benchmark format for SMT solvers. |
| `SoC` | system on a chip | Integrated circuit combining multiple computer components. |
| `SPDM` | Security Protocol and Data Model | Device authentication and measurement protocol. |
| `SPDX` | Software Package Data Exchange | Software-package metadata standard. |
| `SR-IOV` | single-root input/output virtualization | Hardware virtualization interface. |
| `SSDF` | Secure Software Development Framework | NIST software-development framework. |
| `SSH` | Secure Shell | Remote command and transport protocol. |
| `StableHLO` | Stable High-Level Optimizer | Machine-learning compiler operation set and semantics. |
| `STARK` | scalable transparent argument of knowledge | Cryptographic proof-system family. |
| `TCB` | trusted computing base | Components on which a result depends. |
| `TDISP` | Trusted Device Interface Security Protocol | Device-interface isolation protocol. |
| `TLA` | Temporal Logic of Actions | Formal specification language. |
| `TPU` | tensor processing unit | Machine-learning accelerator class. |
| `TS` | Transparency Service | SCITT registration and receipt service. |
| `TUF` | The Update Framework | Software-update security framework. |
| `UNSAT` | unsatisfiable | Solver result meaning no satisfying assignment exists. |
| `URI` | uniform resource identifier | Resource name or locator. |
| `URL` | uniform resource locator | Network resource locator. |
| `UTC` | Coordinated Universal Time | Time standard. |
| `UTF-8` | Unicode Transformation Format, 8-bit | Text encoding. |
| `UUID` | universally unique identifier | 128-bit identifier standard. |
| `VDP` | verifiable data structure proof | Proof format for a VDS. |
| `VDS` | verifiable data structure | Append-only or otherwise provable data structure. |
| `VM` | virtual machine | Software-defined machine environment. |
| `VSTD` | Verifier Standard | Repository standard and reference implementation. |
| `verifier-ssa` | software self-assembly | Autonomous software self-assembly profile. |
| `verifier-ssi` | software self-improvement | Recursive software self-improvement profile. |
| `verifier-ssr` | candidate self-replication | Candidate software self-replication profile. |
| `W3C` | World Wide Web Consortium | Web standards organization. |
| `WG` | working group | Standards-development group. |
| `WSL2` | Windows Subsystem for Linux 2 | Windows-hosted Linux environment. |
| `XML` | Extensible Markup Language | Structured text format. |
| `YAML` | YAML Ain't Markup Language | Structured data format. |
| `ZI` | zero-identity | Historical study coordinate; not a trust or conformance class. |
| `ZIP` | ZIP archive format | Compressed archive format; treat ZIP as the format's proper name. |
| `ZIZK` | zero-identity/zero-knowledge | Governing VSTD artifact-first architecture; particular privacy and propagation mechanisms have their own maturity. |
| `ZK` | zero-knowledge | Cryptographic or semantic privacy property, only when explicitly supported. |
| `zkVM` | zero-knowledge virtual machine | Virtual machine that emits a zero-knowledge proof. |
