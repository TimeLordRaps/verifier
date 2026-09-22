# Mathematical foundations and checking boundaries

Verifier Standard (VSTD) binds bounded computational claims to explicit evidence,
mechanisms, assumptions and refutation conditions. Its normative definitions are
the [numbered object and Graph profiles](../src/verifier/standard/LADDER.md). An analogy to
another mathematical formalism is not an implemented translation or proof.

The [VSTD-4 specification](../src/verifier/standard/VSTD-4.md) defines grounded decision
certificate (GDC) obligations. The producer and independent checker implementations
are in `src/verifier/core/certificate.py` and `src/verifier/core/kernel.py`.
Their separation and tests establish only their declared checking boundary;
compilation, a digest, or agreement on a fixture does not prove an arbitrary
source proposition or an external proof-system integration.

For the experimental simulation and model declarations introduced in the 2.0.0
candidate, see [candidate boundaries](V2_CANDIDATE.md). Finite trace checks do
not establish induction; projected trace distance does not establish universal
bisimulation; caller-supplied signatures or success fields are not authenticated
evidence. No cross-project mathematical grounding or formal proof is claimed here.
