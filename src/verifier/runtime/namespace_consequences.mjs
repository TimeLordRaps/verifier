// Verifier Standard (VSTD): independent interpretation of declared consequences.
// No Python-derived requirements or effects are inputs. Source observations and
// the exact digest-bound semantic type of catalog-compiled retention decisions
// remain shared; agreement does not prove discovery completeness or containment.
export function deriveConsequences(manifest, registry, surfaces, parents, compare, digest,
    nonstructuralRoleDecisions) {
  const graph = manifest.consequence_graph ?? {
    schema_version: "verifier-consequence-graph-1", edges: [], effects: []};
  if (!Array.isArray(nonstructuralRoleDecisions)) {
    throw new Error("nonstructural role decisions absent");
  }
  const rowsById = new Map(manifest.objects.map(row => [row.object_id, row]));
  const nonstructural = new Set();
  for (const binding of nonstructuralRoleDecisions) {
    if (binding === null || typeof binding !== "object" || Array.isArray(binding)
        || JSON.stringify(Object.keys(binding).sort())
          !== JSON.stringify(["decision_digest", "kind", "object_id"])) {
      throw new Error("nonstructural role decision shape");
    }
    const decision = rowsById.get(binding.object_id)?.classification?.[binding.kind];
    if (decision?.status !== "APPLIES" || digest(decision) !== binding.decision_digest) {
      throw new Error("nonstructural role decision unbound");
    }
    const key = binding.object_id + "\n" + binding.kind;
    if (nonstructural.has(key)) throw new Error("duplicate nonstructural role decision");
    nonstructural.add(key);
  }
  const demanded = new Map();
  const native = new Map();
  const implied = new Map();
  const edges = graph.edges.map(edge => [edge.source, edge.relation, edge.target]);
  for (const row of manifest.objects) {
    const retained = kind => nonstructural.has(row.object_id + "\n" + kind);
    const nativeBasis = [row.kind, ...row.specializations.filter(kind => !retained(kind))];
    const applicableBasis = [row.kind, ...row.specializations];
    for (const id of row.surfaces) {
      for (const kind of surfaces.get(id)?.source_kinds ?? []) {
        if (registry.has(kind)) {
          nativeBasis.push(kind);
          applicableBasis.push(kind);
        }
      }
    }
    for (const [kind, decision] of Object.entries(row.classification)) {
      if (decision.status === "APPLIES") {
        applicableBasis.push(kind);
        if (!retained(kind)) nativeBasis.push(kind);
      }
    }
    native.set(row.object_id, new Set(nativeBasis.flatMap(parents)));
    demanded.set(row.object_id, new Set(applicableBasis.flatMap(parents)));
    implied.set(row.object_id, new Set());
  }
  for (const row of manifest.objects) {
    if (native.get(row.object_id).has("BOT")) {
      for (const target of row.operands.agent ?? []) {
        if (native.has(target)) edges.push([row.object_id, "embodies", target]);
      }
    }
  }
  const reverse = new Map([...native.keys()].map(id => [id, new Set()]));
  for (const [source, relation, target] of edges) {
    reverse.get(target).add(source);
    if (relation === "embodies") implied.get(target).add("AGENT");
    if (relation === "controls") {
      implied.get(source).add("AGENT"); implied.get(target).add("CONTROLLER");
    }
    if (relation === "actuates") {
      implied.get(source).add("CONTROLLER"); implied.get(target).add("ACTUATOR");
    }
    if (relation === "decides") implied.get(source).add("AGENT");
  }
  const structural = new Map([...native].map(([id, kinds]) =>
    [id, new Set([...kinds, ...implied.get(id)])]));
  const agentRoles = new Set(["AGENT", "BOT", "ROBOT", "FINBOT"]);
  const agency = new Set([...structural].filter(([, kinds]) =>
    [...agentRoles].some(kind => kinds.has(kind))).map(([id]) => id));
  const controlled = new Set(edges.filter(([source, relation, target]) =>
    relation === "controls" && agency.has(source) && structural.get(target).has("CONTROLLER"))
    .map(([, , target]) => target));
  const typedPhysical = new Set(edges.filter(([source, relation, target]) =>
    relation === "actuates" && controlled.has(source) && structural.get(target).has("ACTUATOR"))
    .map(([, , target]) => target));
  const financialKinds = new Set(["LEDGER", "TRANSACTION", "ASSET", "MARKET"]);
  const financialForward = new Map([...native.keys()].map(id => [id, new Set()]));
  for (const [source, relation, target] of edges) {
    if (["embodies", "influences", "decides", "controls"].includes(relation)) {
      financialForward.get(source).add(target);
    }
  }
  const financialQueue = [...agency].sort(compare);
  const financialReachable = new Set(financialQueue);
  for (let index = 0; index < financialQueue.length; index++) {
    for (const target of [...financialForward.get(financialQueue[index])].sort(compare)) {
      if (financialReachable.has(target)) continue;
      financialReachable.add(target); financialQueue.push(target);
    }
  }
  const typedFinancial = new Set([...financialReachable].filter(id =>
    [...financialKinds].some(kind => structural.get(id).has(kind))
    && !nonstructural.has(id + "\nFINBOT")));
  const endpointDomains = new Map([
    ["REAL_PHYSICAL", new Set([
      ...typedPhysical,
      ...graph.effects.filter(row => row.domain === "REAL_PHYSICAL").map(row => row.object_id)])],
    ["REAL_FINANCIAL", new Set([
      ...typedFinancial,
      ...graph.effects.filter(row => row.domain === "REAL_FINANCIAL").map(row => row.object_id)])],
  ]);
  const reach = new Map([...native.keys()].map(id => [id, Object.create(null)]));
  for (const [domain, role] of [["REAL_PHYSICAL", "ROBOT"], ["REAL_FINANCIAL", "FINBOT"]]) {
    const queue = [...endpointDomains.get(domain)].sort(compare);
    const seen = new Set(queue);
    for (const id of queue) reach.get(id)[domain] = {effect_object_id: id, next_object_id: null};
    for (let index = 0; index < queue.length; index++) {
      const target = queue[index];
      for (const source of [...reverse.get(target)].sort(compare)) {
        if (seen.has(source)) continue;
        seen.add(source); queue.push(source);
        reach.get(source)[domain] = {effect_object_id: reach.get(target)[domain].effect_object_id, next_object_id: target};
      }
    }
    for (const id of seen) {
      // Demand-only AGENT/BOT roles retain consequences reached by explicit
      // edges; a demand-only ROBOT/FINBOT endpoint is not itself an agent.
      // Native/structural roles alone still create implicit embodiment and
      // typed endpoint evidence above.
      if (["AGENT", "BOT", "ROBOT", "FINBOT"].some(kind => structural.get(id).has(kind))
          || (["AGENT", "BOT"].some(kind => demanded.get(id).has(kind))
              && reach.get(id)[domain].next_object_id !== null)) {
        implied.get(id).add(role);
      }
    }
  }
  const required = Object.create(null), reachable = Object.create(null);
  for (const id of [...native.keys()].sort(compare)) {
    const kinds = [...implied.get(id)].filter(kind => !demanded.get(id).has(kind)).sort(compare);
    if (kinds.length) required[id] = kinds;
    if (Object.keys(reach.get(id)).length) reachable[id] = reach.get(id);
  }
  return {graph_digest: digest(graph), required_kinds: required, reachable_effects: reachable};
}
