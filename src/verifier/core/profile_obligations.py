"""Verifier Standard (VSTD) object-profile grounded certification obligations.

An X.M identifier selects obligation M within numbered object profile X, and a
Graph-X.M identifier selects obligation M within numbered Graph profile X. Both are
dimensionless and are neither software versions nor confidence scores. The two
namespaces are disjoint; existing VSTD-4 rung identifiers and dependencies retain
their exact meanings.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from importlib.resources import files
from typing import Any

from .certificate import canonical_digest
from .depth import RUNGS


@dataclass(frozen=True)
class ProfileObligation:
    """A separately checked proposition with explicit prerequisite obligations."""

    profile: int
    index: int
    name: str
    requirement: str
    depends_on: tuple[str, ...]
    source: str

    @property
    def id(self) -> str:
        return f"{self.profile}.{self.index}"

    @property
    def predicate(self) -> str:
        if self.profile == 4:
            return f"vstd4.rung.{self.id}"
        return f"vstd.obligation.{self.id}"

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "depends_on": list(self.depends_on),
                "id": self.id, "predicate": self.predicate}


def _rows(profile: int, rows: tuple[tuple[str, str, tuple[int, ...], str], ...]) -> tuple[ProfileObligation, ...]:
    return tuple(ProfileObligation(profile, index, name, requirement,
        tuple(f"{profile}.{d}" for d in dependencies), f"VSTD-{profile}.md {section}")
        for index, (name, requirement, dependencies, section) in enumerate(rows, 1))


@dataclass(frozen=True)
class GraphObligation:
    """A separately checked Graph-axis proposition with explicit prerequisites.

    Graph coordinates are disjoint from object coordinates. `Graph-X.M` never
    aliases `X.M`, and neither catalogue admits the other's identifiers.
    """

    profile: int
    index: int
    name: str
    requirement: str
    depends_on: tuple[str, ...]
    source: str

    @property
    def id(self) -> str:
        return f"Graph-{self.profile}.{self.index}"

    @property
    def predicate(self) -> str:
        return f"vstd.graph.obligation.{self.profile}.{self.index}"

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "depends_on": list(self.depends_on),
                "id": self.id, "predicate": self.predicate}


def _graph_rows(profile: int, rows: tuple[tuple[str, str, tuple[int, ...], str], ...]) -> tuple[GraphObligation, ...]:
    return tuple(GraphObligation(profile, index, name, requirement,
        tuple(f"Graph-{profile}.{d}" for d in dependencies), f"VSTD-Graph-{profile}.md {section}")
        for index, (name, requirement, dependencies, section) in enumerate(rows, 1))


OBLIGATIONS = (
    *_rows(1, (
        ("Claim coordinate", "The exact subject, proposition, scope, limitations and falsifier are bound.", (), "sections 2 and 4"),
        ("Evidence binding", "Every verdict-material evidence item is identified, available and bound to this claim.", (1,), "section 7"),
        ("Checker and trust boundary", "The actual checker implementation, dependencies and achieved role separation are evidenced without inferring independence.", (1, 2), "section 5"),
        ("Decision replay", "The declared decision follows from rerunning the bound computational checker on the bound evidence within its limits.", (2, 3), "sections 2, 3 and 5"),
        ("Provenance", "Source and execution provenance match the observed evidence and their stated observation boundary.", (2,), "section 7"),
        ("Reproduction fidelity", "The declared reproduction result and fidelity are supported by a checked comparison of the named executions.", (4, 5), "section 6"),
        ("Challenge and correction", "The falsification procedure is executable and any observed challenge or correction is retained without rewriting historical evidence.", (1, 4), "section 8"),
    )),
    *_rows(2, (
        ("Subject and surface", "The primary subject, selected surface, exclusions and coordinate meanings are explicit and bound.", (), "section 3"),
        ("Geometry consistency", "All selected coordinate references, containment relations and seams are internally consistent.", (1,), "sections 3 and 10"),
        ("Translation and reconstruction", "The named translation or reconstruction is checked against its source and exposes information loss and unresolved mappings.", (1, 2), "sections 4 and 8"),
        ("Evidence-earned judgments", "Every relied-on judgment is earned by its exact evidence and executed mechanism rather than a status label.", (1, 2), "sections 2 and 10"),
        ("Residuals and horizons", "Residuals, exclusions and horizons are typed, localized and retained in the assessed scope.", (2, 3), "sections 5 and 6"),
        ("Adjacent verification orders", "Each represented meta-verification order checks its immediate predecessor and retains its evidence and termination horizon.", (2, 4), "section 6.4"),
        ("Bounded surface closure", "The declared closure result is recomputed for the exact selected surface with every blocker preserved.", (3, 4, 5, 6), "sections 6 and 10"),
    )),
    *_rows(3, (
        ("Subject and capability boundary", "Observed devices, execution scope, capability class and unsupported capabilities match the declared substrate boundary.", (), "sections 3, 5, 6 and 7"),
        ("Attestation binding", "Every relied-on attestation binds its challenge, subject, evidence and declared trust root; absent authentication cannot support an attested claim.", (1,), "section 8"),
        ("Firmware accountability", "Firmware identity, measurement and accountability claims are checked under the declared firmware contract and capability boundary.", (1, 2), "section 9"),
        ("Execution binding", "Every claimed execution is linked to the exact workload, inputs, outputs and evidenced execution boundary.", (1, 2), "section 12"),
        ("Accounting and topology", "Reported accounting and partition/topology claims are recomputed from bound evidence with uncertainty and virtualization limits preserved.", (1, 4), "sections 13 and 14"),
        ("Continuity and anchors", "Claimed continuity and external anchors are checked for the declared interval without inferring unobserved continuity.", (2, 3, 4), "sections 10 and 11"),
        ("Provider and fleet scope", "Provider and fleet statements are checked only inside their enumerated evidence boundary; unobserved physical work remains unsupported.", (1, 4, 5), "sections 15 and 16"),
        ("Derived substrate outcome", "The substrate outcome is recomputed from the preceding obligations and capability-specific evidence without promoting an unsupported claim.", (1, 2, 3, 4, 5, 6, 7), "sections 17, 20 and 24"),
    )),
    *(ProfileObligation(4, r.index, r.name, r.requirement,
        tuple(f"4.{i}" for i in r.depends_on), "VSTD-4.md section 2") for r in RUNGS),
    *_rows(5, (
        ("Exact refutability entry", "The exact claim has evidence-bound prerequisite profiles and all fourteen VSTD-4 rungs; a candidate depth cannot admit a witness.", (), "section 1"),
        ("Witness identity binding", "Each witness identity is bound to available identity evidence; duplicate evidence and dangling identities do not create witnesses.", (1,), "sections 2 and 3"),
        ("Operational separation", "Ownership or operational control separation is checked for the exact declarant/witness pair and claim commitment.", (2,), "section 3"),
        ("Implementation separation", "Separation of verdict-producing code is checked for the exact declarant/witness pair and claim commitment.", (2,), "section 3"),
        ("Trust-root separation", "Verifier trust-root separation is checked for the exact declarant/witness pair and claim commitment.", (2,), "section 3"),
        ("Evidence-source separation", "Evidence-source or telemetry-provider separation is checked for the exact declarant/witness pair and claim commitment.", (2,), "section 3"),
        ("Infrastructure separation", "Separation of infrastructure capable of changing the result is checked for the exact declarant/witness pair and claim commitment.", (2,), "section 3"),
        ("Financial separation", "Material financial dependence is checked for the exact declarant/witness pair, corroboration and claim commitment.", (2,), "section 3"),
        ("Compulsion separation", "Material jurisdictional or contractual dependence is checked for the exact declarant/witness pair and claim commitment.", (2,), "section 3"),
        ("Executed corroboration", "Actual witness checking binds the admitted certificate, checker, class, observation time, evidence and result; declarations alone do not satisfy it.", (1, 2, 3, 4, 5, 6, 7, 8, 9), "section 4"),
        ("Disagreement preservation", "All checked disagreements and duplicate-evidence findings are retained; voting or repeated evidence cannot produce independent corroboration.", (10,), "sections 4 and 5"),
    )),
)

GRAPH_OBLIGATIONS = (
    *_graph_rows(1, (
        ("Collection coordinate", "The collection identifier, deduplicated member set and exact recorded graph bytes are bound, and membership is explicit rather than inferred.", (), "section 2"),
        ("Recorded structure", "Artifacts, transformation hyperedges and relation types parse under the declared vocabulary and the recorded relation is acyclic.", (1,), "section 2"),
        ("Coverage recomputation", "Every declared completeness dimension and the disclosed weighted summary are recomputed from the retained graph and are reported as coverage, never as a verdict, probability or trust score.", (2,), "section 3"),
        ("Status admissibility", "Every member and reachable ancestor carries an explicit status, and an omitted status remains unknown instead of becoming observed truth.", (1,), "section 4"),
        ("Conflict retention", "Incompatible retained evidence is kept as an explicit conflict record and is never averaged, collapsed or reduced to a scalar.", (4,), "section 4"),
        ("Blast radius closure", "Forward reachability from a revoked or challenged source is recomputed over the retained graph without mutating historical nodes.", (2, 4), "section 5"),
    )),
    *_graph_rows(2, (
        ("Member rating re-execution", "Every member rating is rerun from embedded evidence through a registered mechanism; a caller-supplied rating never admits the collection.", (), "the evidence-bound path"),
        ("Ancestor reachability closure", "Every provenance ancestor reachable from a member is enumerated and rated, because rating only the selected members is insufficient.", (1,), "the closure condition"),
        ("Edge rating re-execution", "Every transformation hyperedge carries a rerun edge rating at this profile.", (1,), "the evidence-bound path"),
        ("Scope binding", "Each rating proposition binds one digest over the exact graph bytes, deduplicated member set, collection identifier and claim binding, so a neighboring collection contributes rating zero.", (1, 2, 3), "the rating proposition binding"),
        ("Bounded admission", "The collection profile is recomputed with profile zero never established, and a refusal names the member, ancestor, status or edge obligation that prevented admission.", (2, 3, 4), "the failure certificate"),
    )),
    *_graph_rows(3, (
        ("Substrate rating re-execution", "Every member and reachable ancestor rating at this profile is rerun over the exact evidence bytes through a registered mechanism.", (), "the evidence-bound path"),
        ("Weakest reachable cap", "The weakest reachable ancestor or transformation caps the collection, and rating only the selected members cannot lift that cap.", (1,), "the normative closure condition"),
        ("Out-of-closure contribution", "Missing, failed, uncertain, neighboring and out-of-closure bindings contribute zero and prevent conformance rather than being skipped.", (1,), "the evidence-bound path"),
        ("Accountable actor binding", "Trust roots, actor identity, delegation, rotation and revocation history are bound to the retained record and are not inferred from a name or a repeated observation.", (1,), "the accountability condition"),
        ("Accountable closure result", "The accountable provenance result is recomputed from the preceding obligations with every blocker preserved.", (2, 3, 4), "the closure condition"),
    )),
    *_graph_rows(4, (
        ("Member refutability entry", "Every member and reachable ancestor is evidence-bound at object profile 4, including all fourteen rungs; a candidate depth cannot enter this profile.", (), "the profile condition"),
        ("Edge refutability closure", "Every transformation hyperedge carries a refutability closure that the mechanism actually checks; naming one is insufficient.", (1,), "the edge rating condition"),
        ("Unevidenced edge rejection", "Two refutable members connected by an unevidenced transformation do not compose into this profile.", (2,), "the composition condition"),
        ("Challenge localization", "A challenge to the collection output localizes to a member, ancestor, transformation or the composition itself.", (2,), "the challenge condition"),
        ("Candidate ceiling explanation", "An unsatisfiability certificate explains the candidate ceiling over caller-supplied ratings and does not establish conformance or validate a claimed closure record.", (1,), "the candidate path"),
        ("Offline replay", "Proposition bindings and evidence bytes are embedded so every rating mechanism replays without the declarant.", (2, 3, 4), "the evidence-bound path"),
    )),
    *_graph_rows(5, (
        ("Exact network entry", "The collection is evidence-bound at the refutable transformation closure before any witness is admitted.", (), "the profile condition"),
        ("Witness member rating", "Registered mechanisms rerun the exact witness-corroborated member and ancestor ratings from embedded evidence.", (1,), "the evidence-bound path"),
        ("Witness transformation rating", "Every transformation hyperedge carries a rerun witness-corroborated edge rating.", (1,), "the evidence-bound path"),
        ("Network scope binding", "Every rating binds the exact graph bytes, deduplicated member set, collection identifier and claim binding across registries.", (2, 3), "the rating proposition binding"),
        ("Conflict inadmissibility", "Conflicting witness records are retained and make the affected subject inadmissible; they are never averaged into a passing collection.", (2,), "the conflict condition"),
        ("Declared rating rejection", "A result computed from self-declared ratings is not conformance at this profile, whatever its shape or count.", (4,), "the compatibility boundary"),
    )),
)

BY_ID = {o.id: o for o in OBLIGATIONS}
GRAPH_BY_ID = {o.id: o for o in GRAPH_OBLIGATIONS}
PROFILE_NAMES = {1: "Claim Mechanics", 2: "Verification Surface",
                 3: "Substrate Accountability", 4: "Refutability", 5: "Witness Corroboration"}
GRAPH_PROFILE_NAMES = {1: "Recorded Lineage", 2: "Bounded Collection Surface",
                       3: "Accountable Provenance Closure",
                       4: "Refutable Transformation Closure",
                       5: "Corroborated Verification Network"}


def obligation_catalog() -> dict[str, Any]:
    """Return the fixed object-axis catalogue; no supplied ratings or verdicts."""
    return {"schema_version": "VSTD-OBLIGATIONS-1", "axis": "OBJECT",
            "profiles": {str(p): name for p, name in PROFILE_NAMES.items()},
            "obligations": [o.to_dict() for o in OBLIGATIONS]}


def catalog_digest() -> str:
    return canonical_digest(obligation_catalog())


def graph_obligation_catalog() -> dict[str, Any]:
    """Return the fixed Graph-axis catalogue; no supplied ratings or verdicts."""
    return {"schema_version": "VSTD-GRAPH-OBLIGATIONS-1", "axis": "GRAPH",
            "profiles": {str(p): name for p, name in GRAPH_PROFILE_NAMES.items()},
            "obligations": [o.to_dict() for o in GRAPH_OBLIGATIONS]}


def graph_catalog_digest() -> str:
    return canonical_digest(graph_obligation_catalog())


def specification_digest() -> str:
    """Pin installed normative bytes, without consulting a working directory."""
    import hashlib
    names = ("GROUNDED_CERTIFICATION.md", "LADDER.md", "WIRE_IDENTIFIERS.md",
             *(f"VSTD-{p}.md" for p in range(1, 6)))
    root = files("verifier.specifications")
    return canonical_digest({name: hashlib.sha256(root.joinpath(name).read_bytes()).hexdigest()
                             for name in names})


def graph_specification_digest() -> str:
    """Pin the installed Graph-axis normative bytes, separately from the object axis."""
    import hashlib
    names = ("GRAPH_GROUNDING.md", "LADDER.md",
             *(f"VSTD-Graph-{p}.md" for p in range(1, 6)))
    root = files("verifier.specifications")
    return canonical_digest({name: hashlib.sha256(root.joinpath(name).read_bytes()).hexdigest()
                             for name in names})


@dataclass(frozen=True)
class DomainObligation:
    """A separately checked domain-object proposition with explicit prerequisites.

    Domain coordinates are disjoint from both the object axis and the Graph axis.
    `DATA-4.2` never aliases `4.2` or `Graph-4.2`, and no catalogue admits another's
    identifiers. `mechanism` names the adapter check that establishes the obligation,
    or is empty when the obligation is specified with no mechanism: such an obligation
    is reported `UNKNOWN`, never absent and never passed.
    """

    object_name: str
    profile: int
    index: int
    name: str
    requirement: str
    depends_on: tuple[str, ...]
    mechanism: str
    source: str

    @property
    def id(self) -> str:
        return f"{self.object_name}-{self.profile}.{self.index}"

    @property
    def predicate(self) -> str:
        return f"vstd.{self.object_name.lower()}.obligation.{self.profile}.{self.index}"

    @property
    def mechanized(self) -> bool:
        return bool(self.mechanism)

    def to_dict(self) -> dict[str, Any]:
        return {**asdict(self), "depends_on": list(self.depends_on),
                "id": self.id, "predicate": self.predicate,
                "mechanized": self.mechanized}


def _domain_rows(object_name: str, profile: int,
                 rows: tuple[tuple[str, str, tuple[int, ...], str], ...]
                 ) -> tuple[DomainObligation, ...]:
    return tuple(DomainObligation(object_name, profile, index, name, requirement,
        tuple(f"{object_name}-{profile}.{d}" for d in dependencies), mechanism,
        f"META_TIERS.md VSTD-{object_name}-{profile}")
        for index, (name, requirement, dependencies, mechanism) in enumerate(rows, 1))


DOMAIN_OBLIGATIONS = (
    *_domain_rows("DATA", 1, (
        ("Retention boundary", "The boundary between what was kept and what was seen is declared, with the discarded volume stated.", (), ""),
        ("Shard and record inventory", "Every retained shard and record is enumerated and rehashed, and byte and count commitments are recomputed.", (1,), "inventory"),
        ("Record identity", "Each retained record carries a stable identity that is unique within the inventory.", (2,), "inventory"),
        ("Field contract", "The declared field types and required columns are bound for every retained record.", (1,), "schema"),
        ("Schema conformance", "Each retained record is checked against the bound field contract.", (3, 4), "schema"),
        ("Digest tree commitment", "The inventory's digest tree is recomputed from retained bytes and compared with the declared root.", (2,), "inventory"),
    )),
    *_domain_rows("DATA", 2, (
        ("Transformation declaration", "Every declared transformation is bound with its inputs, outputs and position in the order.", (), "lineage"),
        ("Exact re-execution", "Each declared transformation is re-executed and its exact output compared.", (1,), "lineage"),
        ("Pipeline ordering", "Applying the transformations in the declared order reproduces the retained corpus.", (2,), "lineage"),
        ("Idempotence", "Re-applying the pipeline to its own output changes nothing, or the change is localized.", (3,), ""),
        ("Raw-to-retained path", "Every retained record is traced to a raw input through the executed transformations.", (2,), ""),
        ("Rebuild drift", "A second rebuild is compared against the retained corpus and any divergence is localized.", (3, 5), ""),
    )),
    *_domain_rows("DATA", 3, (
        ("Sampling frame", "The population sampled from, and the frame's coverage of it, are witnessed by a party other than the retaining pipeline.", (), "statics:frame"),
        ("Measurement instrument", "The unit and resolution of each measured field are witnessed, and every retained value lies on that resolution and inside its range.", (), "statics:instrument"),
        ("Censoring and truncation", "Censoring and truncation are declared and evidenced against the retained distribution.", (1, 2), "statics:censoring"),
        ("Distribution statics", "Class balance, cardinality and entropy are recomputed over the retained inventory.", (1,), "statics:distribution"),
        ("Origin rights", "Licence and legal facts of origin are bound per source, and the composite redistribution term is the meet of its sources.", (), "statics:rights"),
        ("Pipeline independence", "The facts above are unchanged when the retaining pipeline's declarations are perturbed.", (3, 4, 5), "statics:independence"),
    )),
    *_domain_rows("DATA", 4, (
        ("Split declaration", "Every split is named with its membership predicate.", (), "splits"),
        ("Complete membership", "Every retained record is assigned to exactly one declared split.", (1,), "splits"),
        ("Identity separation", "No record identity appears in two splits.", (2,), "splits"),
        ("Exact overlap", "Exact train and evaluation overlap is recomputed over the complete inventory.", (2,), "overlap"),
        ("Lexical overlap", "Near-duplicate overlap is recomputed under the declared similarity bound.", (4,), "overlap"),
        ("No unaccounted record", "The inventory admits no record outside the declared splits and retention boundary.", (3, 5), ""),
    )),
    *_domain_rows("DATA", 5, (
        ("Mainstay binding", "The columnar or catalogue representation the dataset is published in is named and version-pinned.", (), "mainstay:binding"),
        ("Columnar shard mapping", "The retained shard inventory is mapped onto the mainstay's physical layout.", (1,), "mainstay:layout"),
        ("Schema mapping", "The bound field contract is mapped onto the mainstay's type system, with unrepresentable types named.", (1,), "mainstay:schema"),
        ("Dataset card mapping", "Declared provenance, licence and statics are mapped onto the mainstay's metadata record.", (1,), "mainstay:metadata"),
        ("Round trip", "Export and re-import reproduces the retained inventory byte for byte, or names its loss.", (2, 3, 4), "mainstay:roundtrip"),
        ("Inference upward", "What the mainstay cannot express is stated as the residual this object carries over it.", (5,), "mainstay:residual"),
    )),

    *_domain_rows("ENV", 1, (
        ("Environment boundary", "What is inside the environment and what is host is declared.", (), ""),
        ("Software inventory", "Every file in the selected software inventory is materialized and rehashed.", (1,), "closure"),
        ("Executable coordinates", "The entry point, interpreter and their versions are bound.", (2,), "closure"),
        ("Configuration surface", "The complete required configuration is declared with its value domain.", (1,), "configuration"),
        ("Observed configuration", "Retained collector observations are compared with the required configuration surface.", (4,), "configuration"),
        ("Unpinned residue", "Every inventory element without a pinned digest is named rather than assumed absent.", (2, 5), ""),
    )),
    *_domain_rows("ENV", 2, (
        ("Nondeterminism declaration", "Every nondeterminism source -- clock, entropy, thread interleaving, allocator -- is declared.", (), ""),
        ("Scheduling surface", "Concurrency and scheduling policy are bound for the retained executions.", (1,), ""),
        ("Execution pair", "Two retained executions are bound with their inputs, coordinates and results.", (), "reproduction"),
        ("Input agreement", "The two executions are compared input for input.", (3,), "reproduction"),
        ("Result agreement", "The two executions are compared result for result and divergence is localized.", (4,), "reproduction"),
        ("Divergence attribution", "Each divergence is attributed to a declared nondeterminism source or reported unattributed.", (1, 2, 5), ""),
    )),
    *_domain_rows("ENV", 3, (
        ("Instruction set", "The architecture and its extension set are observed rather than declared.", (), ""),
        ("Floating-point semantics", "Format, rounding mode and fused-operation behaviour are observed on the executing machine.", (1,), ""),
        ("Resource ceilings", "Retained resource measurements are checked against the exact declared ceilings.", (), "resources"),
        ("Physical envelope", "Memory, clock, thermal and power limits of the machine are recorded.", (3,), ""),
        ("Envelope independence", "The envelope holds whether or not the specification declares it.", (1, 2, 4), ""),
    )),
    *_domain_rows("ENV", 4, (
        ("Pin completeness", "Nothing in the inventory resolves outside the pinned set.", (), ""),
        ("Host isolation", "No implicit host state -- environment variables, paths, network, wall clock -- leaks into the execution.", (1,), ""),
        ("Network closure", "Every external fetch is either pinned by digest or declared absent.", (1,), ""),
        ("Standup sufficiency", "A second party can stand the environment up from the record alone.", (2, 3), ""),
        ("Standup evidence", "A retained independent standup is compared against the original.", (4,), ""),
    )),
    *_domain_rows("ENV", 5, (
        ("Mainstay binding", "The image, derivation or lockfile format is named and version-pinned.", (), "mainstay:binding"),
        ("Image closure mapping", "The inventory is mapped onto the mainstay's layer or store-path model.", (1,), "mainstay:layout"),
        ("Derivation mapping", "The build steps are mapped onto the mainstay's derivation or recipe model.", (1,), "mainstay:recipe"),
        ("Build provenance mapping", "The provenance attestation is mapped onto the mainstay's attestation format.", (2, 3), "mainstay:attestation"),
        ("Round trip", "Rebuilding from the mainstay representation reproduces the pinned inventory.", (4,), "mainstay:roundtrip"),
        ("Inference upward", "What the mainstay cannot pin is stated as the residual this object carries over it.", (5,), "mainstay:residual"),
    )),

    *_domain_rows("BENCH", 1, (
        ("Domain declaration", "The domain or set of domains the bench measures is declared.", (), ""),
        ("Problem set", "Each finite problem is bound to its exact specification and candidate answer.", (1,), "problems"),
        ("Solution deducibility", "What a solution is deducible from is declared for each problem.", (2,), "problems"),
        ("Oracle binding", "The named built-in oracle is executed; a supplied solved flag is never accepted.", (3,), "oracles"),
        ("Sampling procedure", "How the problems were drawn from the domain is declared.", (1, 2), ""),
        ("Baseline mechanics", "The baseline a score is read against is bound and executable.", (4,), ""),
        ("Feature representation", "The representational spaces or categories the problems are typed by are declared.", (1,), ""),
    )),
    *_domain_rows("BENCH", 2, (
        ("Attempt policy", "Repeated attempts and best-of-N selection are declared and bounded per problem.", (), ""),
        ("Attempt inventory", "Every attempt is retained; none is discarded on selection.", (1,), ""),
        ("Sequential adaptivity", "Whether later problems depend on earlier results is declared and evidenced.", (2,), ""),
        ("Contamination accumulation", "Corpus exposure is accumulated against a dated boundary rather than assumed absent.", (), ""),
        ("Response curve", "Score as a function of budget is recomputed over the retained attempts.", (2,), ""),
        ("Measurement feedback", "The effect of publication on the systems measured is declared as an uncontrolled dynamic.", (3, 4, 5), ""),
    )),
    *_domain_rows("BENCH", 3, (
        ("Chance floor", "The score a null strategy attains is computed from the problem family.", (), ""),
        ("Oracle ceiling", "The maximum score attainable given the bound oracles is computed.", (), ""),
        ("Label noise", "Irreducible disagreement in the ground truth is estimated rather than assumed zero.", (2,), ""),
        ("Hardness classes", "The intrinsic hardness classes of the problem family are named.", (1, 2), ""),
        ("Natural distribution", "The domain's own task distribution is stated separately from the bench's sample of it.", (4,), ""),
        ("Budget ceilings", "Retained timing and memory observations are checked against the problem ceilings.", (), "budgets"),
        ("Harness independence", "The facts above hold when the harness changes.", (3, 5, 6), ""),
    )),
    *_domain_rows("BENCH", 4, (
        ("Run inventory", "One retained run per problem is enumerated.", (), "coverage"),
        ("No missing run", "Every problem in the bound set has a retained run.", (1,), "coverage"),
        ("No duplicate or substituted run", "Each run binds to exactly one problem specification.", (1,), "coverage"),
        ("Weighted score", "The weighted score is recomputed over the complete inventory under the declared weights.", (2, 3), "coverage"),
        ("Surface completeness", "The scored set covers the whole declared measurement surface.", (4,), ""),
    )),
    *_domain_rows("BENCH", 5, (
        ("Mainstay binding", "The evaluation harness or task-specification format is named and version-pinned.", (), "mainstay:binding"),
        ("Task specification mapping", "Problems and oracles are mapped onto the mainstay's task record.", (1,), "mainstay:layout"),
        ("Scoring contract mapping", "Weights, aggregation and reporting are mapped onto the mainstay's metric contract.", (1,), "mainstay:schema"),
        ("Budget mapping", "Problem ceilings are mapped onto the mainstay's limit model.", (2,), "mainstay:limits"),
        ("Round trip", "Running the mainstay's export reproduces the retained scores.", (2, 3, 4), "mainstay:roundtrip"),
        ("Inference upward", "What the mainstay cannot express is stated as the residual this object carries over it.", (5,), "mainstay:residual"),
    )),

    *_domain_rows("TRAIN", 1, (
        ("Optimizer contract", "The optimizer, schedule, accumulation and precision contract is bound.", (), "configuration"),
        ("Numerical semantics", "The declared floating-point format and accumulation order are bound.", (1,), "configuration"),
        ("Checkpoint inventory", "Every retained weight and optimizer state is rehashed.", (), "checkpoints"),
        ("Step index", "A contiguous step index is bound over the retained trace.", (3,), "checkpoints"),
        ("Batch binding", "Each step is bound to the batch it consumed.", (4,), "checkpoints"),
        ("Retention boundary", "Which steps and states are retained, and which were discarded, is declared.", (1, 5), ""),
    )),
    *_domain_rows("TRAIN", 2, (
        ("Loss replay", "Dense-network losses are recomputed from the bound batches.", (), "training"),
        ("Gradient replay", "Analytic gradients are recomputed and compared with the retained ones.", (1,), "training"),
        ("Optimizer update", "Every supported optimizer update is recomputed from retained gradients and state.", (2,), "updates"),
        ("State advance", "Applying the recomputed update reproduces the next retained state.", (3,), "updates"),
        ("Step-by-step advance", "The run is replayed step by step across the retained trace.", (4,), "training"),
        ("Unsupported update reporting", "An unsupported optimizer is reported UNKNOWN and never passed.", (3,), ""),
    )),
    *_domain_rows("TRAIN", 3, (
        ("Arithmetic semantics", "The executing hardware's floating-point behaviour is observed rather than declared.", (), "statics:arithmetic"),
        ("Accumulation order", "The order reductions actually occur in is observed by reducing a retained sequence two ways, and its effect is bounded.", (1,), "statics:accumulation"),
        ("True gradient", "The gradient the bound objective has is stated independently of what the run computed.", (), "statics:objective"),
        ("Objective geometry", "The curvature and conditioning that the architecture and data together fix are stated.", (3,), "statics:geometry"),
        ("Choice independence", "The facts above are unchanged when the run's configuration is perturbed.", (2, 4), "statics:independence"),
    )),
    *_domain_rows("TRAIN", 4, (
        ("Contiguity", "The retained steps form an uninterrupted sequence with no gap.", (), "lineage"),
        ("Parent binding", "Each step binds to its exact parent state.", (1,), "lineage"),
        ("Batch and hyperparameter binding", "Each step binds its exact batch and hyperparameter values.", (2,), "lineage"),
        ("Result binding", "Each step binds its exact result.", (3,), "lineage"),
        ("No reordering", "The retained order is the executed order, and a reordered pair is detectable.", (4,), ""),
        ("Whole-run accounting", "The trace accounts for the whole run rather than a selected prefix of it.", (5,), ""),
    )),
    *_domain_rows("TRAIN", 5, (
        ("Mainstay binding", "The training-loop framework is named and version-pinned.", (), "mainstay:binding"),
        ("Training-loop mapping", "The retained trace is mapped onto the mainstay's loop and callback model.", (1,), "mainstay:layout"),
        ("Checkpoint-format mapping", "The checkpoint inventory is mapped onto the mainstay's serialization format.", (1,), "mainstay:schema"),
        ("Batch source mapping", "The batch binding is mapped onto the retained inventory a VSTD-DATA-5 object exposes.", (2,), "mainstay:upstream"),
        ("Round trip", "Resuming from the mapped checkpoint reproduces the retained next step.", (3, 4), "mainstay:roundtrip"),
        ("Inference upward", "What the mainstay cannot express is stated as the residual this object carries over it.", (5,), "mainstay:residual"),
    )),

    *_domain_rows("HYPER", 1, (
        ("Operand set", "The set of bound certificates entering the composition, and its arity, is declared.", (), ""),
        ("Slot schema", "Which slot each operand fills, and which slots are unfilled, is declared.", (1,), ""),
        ("Slot versus operand", "The distinction between a slot, which is a role, and an operand, which is a certificate, is made explicit.", (2,), ""),
        ("Substrate presence", "The substrate each operand carries is identified once per arm of the composition.", (1,), ""),
        ("Composed identity", "The identity of the composed object is derived from its operands and its filled slots.", (3, 4), ""),
        ("Operand admissibility", "Each operand is admitted under the composed object's own policy.", (5,), ""),
    )),
    *_domain_rows("HYPER", 2, (
        ("Strength ordering", "A total order on operand strengths is defined.", (), ""),
        ("Non-increase", "The composition's strength is no greater than that of its weakest operand.", (1,), ""),
        ("UNKNOWN absorption", "One UNKNOWN operand makes the composition UNKNOWN.", (2,), ""),
        ("Recomposition", "Recomposing from retained bytes lands on the same composed object.", (), ""),
        ("Associativity", "Which regroupings of operands are equivalent, and which are not, is stated.", (4,), ""),
        ("Depth propagation", "The composed object's depth is bounded by its operands' established depths.", (2, 3, 5), ""),
    )),
    *_domain_rows("HYPER", 3, (
        ("Composed ceiling", "The weakest operand bound is the composed ceiling, whatever the composed object declares.", (), "statics:ceiling"),
        ("Substrate recurrence", "The substrate recurs at every level rather than being consumed by a composition.", (), "statics:recurrence"),
        ("Decider exteriority", "The decider stays outside the certified surface at every level.", (), "statics:exteriority"),
        ("Manufacture impossibility", "No composition manufactures evidence absent from its operands.", (1, 2), "statics:conservation"),
        ("Level independence", "The facts above hold at every depth of nesting and are unchanged when the composition's own declarations are perturbed.", (3, 4), "statics:independence"),
    )),
    *_domain_rows("HYPER", 4, (
        ("Saturation", "Every slot of the composition is filled by a bound operand.", (), ""),
        ("Collapse", "An agent bound inside a simulation is written as one composed object and re-expanded.", (1,), ""),
        ("Expansion fidelity", "The re-expansion recovers the operand set byte for byte.", (2,), ""),
        ("Fractal re-representation", "The substrate is exhibited recurring identically at every level.", (3,), ""),
        ("Boundary completeness", "The composition's boundary admits no unbound operand.", (1, 4), ""),
    )),
    *_domain_rows("HYPER", 5, (
        ("Mainstay binding", "The composition formalism is named and version-pinned.", (), "mainstay:binding"),
        ("Layout mapping", "The operand set and its slots are mapped onto the mainstay's layout or assembly relation.", (1,), "mainstay:layout"),
        ("Authorization mapping", "Slot filling is mapped onto the mainstay's step-authorization model.", (2,), "mainstay:authorization"),
        ("Round trip", "The mainstay's verifier accepts the mapped composition and rejects a substituted operand.", (3,), "mainstay:roundtrip"),
        ("Inference upward", "What the mainstay cannot express is stated as the residual this object carries over it.", (4,), "mainstay:residual"),
    )),

    *_domain_rows("MODEL", 1, (
        ("Tensor inventory", "Complete finite tensor shapes are bound.", (), "tensors"),
        ("Architecture compatibility", "Shapes are checked compatible across the declared computation graph.", (1,), "tensors"),
        ("Module decomposition", "The model's module structure is declared.", (2,), ""),
        ("Input and output surface", "The declared input and output surface is bound with its types.", (2,), ""),
        ("Dependency artifacts", "The named dependency artifacts are bound by digest.", (), "artifacts"),
    )),
    *_domain_rows("MODEL", 2, (
        ("Forward execution", "The bound dense network is executed on the retained inputs.", (), "inference"),
        ("Output agreement", "Every retained output is compared with the executed one.", (1,), "inference"),
        ("Batching behaviour", "Results are invariant to the declared batching, or the variance is localized.", (2,), ""),
        ("Precision behaviour", "Results under the declared precision are bounded, with divergence localized.", (2,), ""),
        ("Sampling and decoding", "The decoding procedure and its entropy source are bound and replayed.", (3, 4), ""),
    )),
    *_domain_rows("MODEL", 3, (
        ("Weight bytes", "The exact architecture and weight artifacts are rehashed as retained bytes.", (), "artifacts"),
        ("Hardware requirements", "The hardware the model requires in order to execute is observed.", (1,), ""),
        ("Quantization specification", "The quantization scheme and its configuration are bound.", (1,), ""),
        ("Training-data citation", "The retained-data object the model's training data is bound through is cited.", (), ""),
        ("Provenance citation", "The training-run object the model's provenance is bound through is cited.", (4,), ""),
        ("Artifact immutability", "The facts above are properties of the artifact rather than of any deployment of it.", (2, 3, 5), ""),
    )),
    *_domain_rows("MODEL", 4, (
        ("Evaluation set", "The named evaluation set is bound and complete.", (), "evaluation"),
        ("Metric recomputation", "Regression or classification metrics are recomputed over the whole named set.", (1,), "evaluation"),
        ("Probe inventory", "The declared finite counterexample probes are enumerated.", (), "challenges"),
        ("Probe execution", "Each probe is executed against its bound output condition.", (3,), "challenges"),
        ("Refutability", "The claimed behaviour is refutable rather than merely unrefuted.", (2, 4), ""),
    )),
    *_domain_rows("MODEL", 5, (
        ("Mainstay binding", "The module-graph and tensor-serialization formats are named and version-pinned.", (), "mainstay:binding"),
        ("Module-graph mapping", "The module decomposition is mapped onto the mainstay's graph model.", (1,), "mainstay:layout"),
        ("Serialized-weights mapping", "The weight inventory is mapped onto the mainstay's tensor container.", (1,), "mainstay:schema"),
        ("Operator coverage", "Operators the mainstay cannot express are named.", (2,), "mainstay:operators"),
        ("Round trip", "Export and re-import reproduces the retained outputs within the declared tolerance.", (3, 4), "mainstay:roundtrip"),
        ("Inference upward", "The residual this object carries over the mainstay is stated.", (5,), "mainstay:residual"),
    )),

    *_domain_rows("SIM", 1, (
        ("State space", "The state space and its encoding are bound.", (), ""),
        ("Transition expressions", "The bound transition expressions are declared over that space.", (1,), ""),
        ("Entropy stream", "The entropy source is bound and reproducible.", (2,), ""),
        ("Observation channels", "Every observation projection is declared.", (1,), "channels"),
        ("Action channels", "Every declared action channel is bound.", (4,), "channels"),
        ("Shard decomposition", "The shard partition of the state space is declared.", (1,), ""),
        ("Macro and micro projection", "The projection relating macro states to micro states is bound.", (6,), ""),
    )),
    *_domain_rows("SIM", 2, (
        ("Trajectory replay", "The transition expressions and entropy stream are executed to reproduce the retained trajectory.", (), "replay"),
        ("Responsiveness", "Each action's effect on the next state is observed and bounded in simulated time.", (1,), ""),
        ("Internal state change", "State changes exposed through no observation channel are enumerated.", (1,), ""),
        ("Computational space", "The resources the transition actually consumes per step are recorded.", (1,), ""),
        ("Perspective shift", "The bound projection is executed and aligned macro states are compared within the declared tolerance.", (3,), "refinement"),
        ("Perspective agreement", "A shift of perspective preserves the trajectory's identity.", (2, 4, 5), ""),
    )),
    *_domain_rows("SIM", 3, (
        ("Invariant expressions", "The bound invariant and conservation expressions are declared.", (), "invariants"),
        ("Per-state holding", "Each expression is checked on every retained state.", (1,), "invariants"),
        ("Closed state set", "The closed finite state set is checked where one exists.", (2,), "invariants"),
        ("Modelled law", "The physical law the simulation is a model of is stated as external to the simulation.", (), ""),
        ("Law independence", "The law holds whether or not the simulation represents it correctly.", (3, 4), ""),
    )),
    *_domain_rows("SIM", 4, (
        ("Shard coverage", "Every shard is present and aligned across the retained trajectory.", (), "shards"),
        ("Cross-shard relations", "The bound relations between shards are checked.", (1,), "shards"),
        ("Signatures", "Shard signatures are verified where the policy requires them.", (2,), "shards"),
        ("No unattributed transition", "Every transition is attributed to a bound transition expression.", (1,), ""),
        ("Whole-surface accounting", "The retained trajectory accounts for the whole simulated surface.", (3, 4), ""),
    )),
    *_domain_rows("SIM", 5, (
        ("Mainstay binding", "The interaction or co-simulation interface is named and version-pinned.", (), "mainstay:binding"),
        ("Interaction-surface mapping", "Observation and action channels are mapped onto the mainstay's space model.", (1,), "mainstay:layout"),
        ("Physical-backend mapping", "The transition expressions are mapped onto the mainstay's solver or model-exchange interface.", (1,), "mainstay:backend"),
        ("Stepping contract", "The mainstay's stepping and reset semantics are mapped onto the retained trajectory.", (2, 3), "mainstay:stepping"),
        ("Round trip", "Driving the mainstay reproduces the retained trajectory within the declared tolerance.", (4,), "mainstay:roundtrip"),
        ("Inference upward", "The residual this object carries over the mainstay is stated.", (5,), "mainstay:residual"),
    )),

    *_domain_rows("HARNESS", 1, (
        ("Channel partition", "Every declared channel is partitioned into instrumented observation and named uninstrumented gap.", (), "surface"),
        ("Record types", "The user, agent and tool record types are bound.", (1,), "surface"),
        ("Tool registry", "The registry of tool declarations is bound.", (2,), ""),
        ("Side-effect channels", "The declared side-effect channels are enumerated.", (3,), ""),
        ("Transcript commitment shape", "The shape of the ordered transcript commitment is declared.", (2,), ""),
    )),
    *_domain_rows("HARNESS", 2, (
        ("Record contiguity", "Retained records form an uninterrupted ordered sequence.", (), "messages"),
        ("Invocation pairing", "Each tool invocation is paired with its response.", (1,), "tools"),
        ("Side-effect interleaving", "Declared side effects are placed in the record order.", (2,), "effects"),
        ("Session advance", "The session is replayed record by record.", (1,), "messages"),
        ("Retry and resumption", "What a retry or a resumption does to the sequence is declared and evidenced.", (3, 4), ""),
    )),
    *_domain_rows("HARNESS", 3, (
        ("Gap boundary", "The named uninstrumented gap is stated as a property of where the instrument was placed.", (), "statics:gap"),
        ("Timestamp resolution", "The clock's resolution is probed, and no ordering is admitted between events it cannot separate.", (), "statics:clock"),
        ("Channel capacity", "The capacity and truncation behaviour of each instrumented channel is recorded.", (1,), "statics:capacity"),
        ("Instrument fixity", "The facts above are unchanged when the recorded session content is perturbed.", (1, 2, 3), "statics:fixity"),
    )),
    *_domain_rows("HARNESS", 4, (
        ("Commitment recomputation", "The ordered transcript commitment is recomputed from retained bytes.", (), "transcript"),
        ("Omission detection", "A dropped record changes the commitment.", (1,), "transcript"),
        ("Substitution detection", "A replaced record changes the commitment.", (1,), "transcript"),
        ("Reordering detection", "A reordered pair changes the commitment.", (2, 3), ""),
        ("Whole-session accounting", "The session is wholly accounted for under the commitment.", (4,), ""),
    )),
    *_domain_rows("HARNESS", 5, (
        ("Mainstay binding", "The trace and tool-protocol formats are named and version-pinned.", (), "mainstay:binding"),
        ("Trace-span mapping", "Records are mapped onto the mainstay's trace and span model.", (1,), "mainstay:layout"),
        ("Tool-protocol mapping", "The tool registry and its invocations are mapped onto the mainstay's protocol.", (1,), "mainstay:protocol"),
        ("Gap representation", "The uninstrumented gap is represented in the mainstay, or named unrepresentable there.", (2, 3), "mainstay:gap"),
        ("Round trip", "Re-importing the mainstay export reproduces the transcript commitment.", (4,), "mainstay:roundtrip"),
        ("Inference upward", "The residual this object carries over the mainstay is stated.", (5,), "mainstay:residual"),
    )),

    *_domain_rows("AGENT", 1, (
        ("Harness binding", "The harness certificate is re-derived from its retained bytes.", (), "harness"),
        ("Required channels", "The channels the agent's account requires are present in the bound harness surface.", (1,), "harness"),
        ("Observation ceiling", "The observation ceiling is re-derived from the bound harness and its channels.", (2,), "harness"),
        ("Decision inventory", "The retained decisions are enumerated.", (3,), ""),
        ("Declared actions", "The actions the agent declares it took are bound.", (4,), ""),
        ("Outcome contract", "The contract outcomes are read against is bound.", (3,), ""),
        ("Final claims", "The agent's final claims are bound.", (5, 6), ""),
    )),
    *_domain_rows("AGENT", 2, (
        ("Trajectory contiguity", "The retained decisions form a contiguous trajectory.", (), "trajectory"),
        ("Decision witnessing", "Each decision is witnessed by a record inside the observation ceiling.", (1,), "trajectory"),
        ("Action witnessing", "Each declared action is bound to a witnessed tool invocation.", (2,), "actions"),
        ("Unwitnessed action reporting", "A declared action with no witness is reported and never passed.", (3,), ""),
        ("Trajectory advance", "The trajectory is replayed decision by decision.", (3,), "trajectory"),
    )),
    *_domain_rows("AGENT", 3, (
        ("Ceiling fixity", "The observation ceiling is fixed by the harness, not by the agent.", (), "statics:ceiling"),
        ("Unknowability", "What the agent could not have known is stated regardless of what it asserts it knew.", (1,), "statics:unknowability"),
        ("Declaration impotence", "No agent declaration raises the ceiling, and perturbing its declarations moves none of the facts above.", (2,), "statics:impotence"),
    )),
    *_domain_rows("AGENT", 4, (
        ("Outcome inventory", "The complete retained outcome inventory is enumerated.", (), "outcomes"),
        ("Contract comparison", "The inventory is compared against the bound outcome contract.", (1,), "outcomes"),
        ("Claim support", "Every final claim rests only on records inside the observation ceiling.", (2,), "claims"),
        ("No unsupported claim", "The agent's account of itself admits no unsupported claim.", (3,), ""),
    )),
    *_domain_rows("AGENT", 5, (
        ("Mainstay binding", "The agent-loop runtime is named and version-pinned.", (), "mainstay:binding"),
        ("Decision-loop mapping", "The trajectory is mapped onto the mainstay's loop or graph model.", (1,), "mainstay:layout"),
        ("Slot mapping", "The decider slot is mapped onto the mainstay's policy binding without pinning the slot to a model.", (2,), "mainstay:slot"),
        ("Round trip", "Replaying through the mainstay reproduces the retained trajectory.", (3,), "mainstay:roundtrip"),
        ("Inference upward", "The residual this object carries over the mainstay is stated.", (4,), "mainstay:residual"),
    )),

    *_domain_rows("BOT", 1, (
        ("Agent binding", "The agent certificate is re-derived from its retained bytes.", (), "binding"),
        ("Simulation binding", "The simulation certificate is re-derived from its retained bytes.", (), "binding"),
        ("Environment bindings", "Both environment certificates are re-derived, one per arm of the coupling.", (1, 2), "binding"),
        ("Coupling surface", "The facets of the coupling itself, rather than of either side, are declared.", (3,), ""),
        ("Operand depths", "Each operand's established depth is recorded for the composition ceiling.", (3,), ""),
    )),
    *_domain_rows("BOT", 2, (
        ("Transition binding", "Every simulation transition is bound to one retained record.", (), "alignment"),
        ("Observation projection", "Every retained observation is shown to be the simulation's own projection of that state.", (1,), "observation"),
        ("Action authenticity", "Every replayed action is shown to be one the agent actually invoked.", (1,), "actuation"),
        ("One-to-one coupling", "No transition lacks a record and no record lacks a transition.", (2, 3), "alignment"),
        ("Coupling advance", "The coupled run is replayed step by step.", (4,), ""),
    )),
    *_domain_rows("BOT", 3, (
        ("Inherited ceiling", "The observation ceiling exists whatever the agent claims about it.", (), "statics:inherited"),
        ("Coupling latency", "The latency and ordering the coupling imposes are probed from the retained action and effect times.", (), "statics:latency"),
        ("Disclosure limit", "The information the simulation cannot expose regardless of policy is stated.", (1,), "statics:disclosure"),
        ("Policy impotence", "The facts above are unchanged when either side's policy is perturbed.", (2, 3), "statics:impotence"),
    )),
    *_domain_rows("BOT", 4, (
        ("Separation declaration", "The agent and simulator execution environments are declared separate or fused.", (), "containment"),
        ("Separation evidence", "A separate declaration is evidenced by the two bound environment certificates.", (1,), "containment"),
        ("Fused honesty", "A fused declaration is honest and yields UNKNOWN, never FAIL.", (1,), "containment"),
        ("Containment accounting", "Containment is established or explicitly not established, and never assumed.", (2, 3), ""),
    )),
    *_domain_rows("BOT", 5, (
        ("Interaction-graph binding", "The interaction graph over the bound simulation's interaction surface is bound.", (), "mainstay:interaction"),
        ("Disclosure inventory", "What the composed object discloses about itself is enumerated.", (1,), "mainstay:disclosed"),
        ("Indisclosure inventory", "What it does not disclose is named as unestablished rather than absent.", (2,), "mainstay:indisclosed"),
        ("Inclusion awareness", "Whether it is aware of being inside a simulation, and to what degree, is recorded.", (2,), "mainstay:inclusion"),
        ("Specification awareness", "Which simulation specification surfaces it is aware of is recorded.", (4,), "mainstay:awareness"),
        ("Awareness accounting", "Disclosed and indisclosed awareness are accounted for without inferring either from the other.", (3, 5), "mainstay:accounting"),
    )),
    *_domain_rows("OWNER", 1, (
        ("Holder binding", "The holder is bound as an actor by an actor-binding token, never named in free text.", (), ""),
        ("Held-object binding", "The held object is bound by its own object certificate at a stated coordinate.", (), ""),
        ("Limb inventory", "Every limb of the holding is enumerated under three kinds -- rights, discharge-duties and answering-duties -- and a limb the inventory omits is unheld rather than permitted.", (1, 2), ""),
        ("Instrument", "The instrument that establishes the holding is bound together with the authority that issued it.", (3,), ""),
        ("Term", "The holding's start, and its end or its declared non-expiry, are stated on the instrument's own clock.", (4,), ""),
        ("Bearer capability", "The holder's kind scopes which limbs it can bear, and a limb its kind cannot bear is unheld rather than held and unexercised.", (1, 3), ""),
    )),
    *_domain_rows("OWNER", 2, (
        ("Event declaration", "Every event that changes the holding is declared with its instrument and its position in the order.", (), ""),
        ("Transfer conveyance", "Each declared transfer conveys only the limbs the transferor held at that position in the order.", (1,), ""),
        ("Delegation bound", "Each delegation conveys a subset of the delegator's limbs and leaves the delegator's own holding intact.", (1,), ""),
        ("Revocation effect", "Each revocation withdraws exactly the limbs it names, from the position in the order at which it takes effect.", (2, 3), ""),
        ("Lapse", "A holding whose term has ended lapses by the clock rather than by an event, and lapse is distinguished from revocation.", (1,), ""),
        ("Ordered replay", "Replaying the declared events from the origin in the declared order reproduces the current holding.", (4, 5), ""),
    )),
    *_domain_rows("OWNER", 3, (
        ("Verdict independence", "The holding never changes any verdict the held object's own certificate reaches.", (), ""),
        ("Evidence immutability", "Ownership events never alter, retract or re-date the held object's evidence.", (1,), ""),
        ("Ancestry immutability", "Ownership events never alter the held object's ancestry or its coordinate.", (1,), ""),
        ("Asymmetry", "Holding is asymmetric: two holders cannot hold the same limb over the same object at the same position in the order unless that limb is declared shared.", (), ""),
        ("Non-transitivity of authority", "Holding an object confers no holding over the objects it was composed from, nor over the objects composed from it.", (4,), ""),
        ("Person-limb typing", "Where the held object is a natural person, no right is holdable and only duties are; and a holder that is not a natural person may carry discharge-duties but never an answering-duty.", (4, 5), ""),
    )),
    *_domain_rows("OWNER", 4, (
        ("Chain origin", "The chain of holdings begins at a declared origin whose instrument is bound.", (), ""),
        ("Gapless chain", "Every position in the order between the origin and the head is covered by exactly one holding.", (1,), ""),
        ("Fork detection", "No two holdings claim the same limb over the same object at the same position, and a fork is reported rather than resolved.", (2,), ""),
        ("Admissibility at issue time", "Each instrument is admissible under the authority in force when it issued, not under the authority in force now.", (1,), ""),
        ("Accountability floor", "For every discharge-duty in the chain an answering-duty exists over the same object, at the same position in the order and throughout that discharge-duty's term, and every answering-duty chain terminates in a natural person; an answering-duty that lapses while its discharge-duty still runs leaves the chain open, and a chain that discharges without answering is not closed.", (1, 2), ""),
        ("Closure result", "The chain is closed only when origin, gaplessness, fork-freedom, admissibility at issue time and the accountability floor all hold; otherwise the result is UNKNOWN and never FAIL.", (2, 3, 4, 5), ""),
    )),
    *_domain_rows("OWNER", 5, (
        ("Licence holding", "Licence holdings over a corpus or a model are bound per source, and the composite redistribution term is the meet of its sources.", (), ""),
        ("Registry maintainer record", "Package-registry maintainer and owner records are bound as holdings, with the registry as the issuing authority.", (), ""),
        ("Register entry", "Corporate and beneficial-ownership register entries are bound as holdings, with the register as the issuing authority.", (), ""),
        ("Declared code ownership", "Declared repository code-ownership entries are bound as delegated review duties, never as transferable limbs.", (2,), ""),
        ("Custody chain", "Physical and cryptographic custody transfers are bound as ordered events on the custody clock.", (), ""),
        ("Adaptation accounting", "Each adaptation above is reported as established or unestablished, and an absent register is unestablished rather than unheld.", (1, 2, 3, 4, 5), ""),
    )),
)

DOMAIN_BY_ID = {o.id: o for o in DOMAIN_OBLIGATIONS}
DOMAIN_OBJECTS = ("DATA", "ENV", "BENCH", "TRAIN", "HYPER", "MODEL", "SIM",
                  "HARNESS", "AGENT", "BOT", "OWNER")

# A relational object holds *between* certified objects instead of certifying a
# substrate of its own. GRAPH carries its own axis; HYPER and OWNER sit on the
# domain axis. Of the three only OWNER is ungrounded -- no adapter executes it,
# so every OWNER obligation is specified with no mechanism and reports UNKNOWN.
RELATIONAL_OBJECTS = ("GRAPH", "HYPER", "OWNER")
UNGROUNDED_OBJECTS = ("OWNER",)
GROUNDED_OBJECTS = tuple(o for o in DOMAIN_OBJECTS if o not in UNGROUNDED_OBJECTS)
TIER_NAMES = {1: "Facets", 2: "Dynamics", 3: "Statics", 4: "Closure",
              5: "Domain adaptation"}


def domain_obligation_catalog() -> dict[str, Any]:
    """Return the fixed domain-object catalogue; no supplied ratings or verdicts."""
    return {"schema_version": "VSTD-DOMAIN-OBLIGATIONS-1", "axis": "DOMAIN",
            "objects": list(DOMAIN_OBJECTS),
            "relational": list(RELATIONAL_OBJECTS),
            "ungrounded": list(UNGROUNDED_OBJECTS),
            "tiers": {str(t): name for t, name in TIER_NAMES.items()},
            "obligations": [o.to_dict() for o in DOMAIN_OBLIGATIONS]}


def domain_catalog_digest() -> str:
    return canonical_digest(domain_obligation_catalog())


def domain_obligation_digest() -> str:
    """Pin the installed domain-object normative bytes, separately from both axes."""
    import hashlib
    names = ("DOMAIN_OBLIGATIONS.md", "META_TIERS.md")
    root = files("verifier.specifications")
    return canonical_digest({name: hashlib.sha256(root.joinpath(name).read_bytes()).hexdigest()
                             for name in names})


def tier_depth(object_name: str, tier: int) -> int:
    """The longest prerequisite chain inside one numbered profile of one object.

    This is `i` in `META_TIERS.md`: the largest `m` a grounded certificate can
    reach for `VSTD-<object>-<tier>.<m>`, which is a depth and not a count.
    """
    here = [o for o in DOMAIN_OBLIGATIONS
            if o.object_name == object_name and o.profile == tier]
    if not here:
        raise ValueError(f"unknown object tier: {object_name}-{tier}")
    memo: dict[str, int] = {}

    def depth(oid: str) -> int:
        if oid not in memo:
            memo[oid] = 1 + max((depth(d) for d in DOMAIN_BY_ID[oid].depends_on), default=0)
        return memo[oid]

    return max(depth(o.id) for o in here)
