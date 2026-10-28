// Verifier Standard (VSTD) independent declaration reconciliation.
// This process receives selected observations, not Python's derived requirements.
// It does not execute the repository, rediscover its syntax, or establish the
// truth of a reason. Its independent task is portable decoding and set derivation.
import { createHash } from "node:crypto";
import { deriveConsequences } from "./namespace_consequences.mjs";

const sha256 = bytes => `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
const requireThat = (condition, message) => { if (!condition) throw new Error(message); };
class CapacityRefusal extends Error {}
const requireCapacity = (condition, message) => {
  if (!condition) throw new CapacityRefusal(message);
};
const STANDARD_NODES = 250000;
const PACKAGE_NODES = 1000000;
const STANDARD_OUTPUT_BYTES = 16 * 1024 * 1024;
const PACKAGE_OUTPUT_BYTES = 64 * 1024 * 1024;
const DERIVED_ITEMS = 65536;
const DERIVED_OUTPUT_BYTES = 12 * 1024 * 1024;
const compare = (left, right) => {
  const a = Array.from(left, ch => ch.codePointAt(0));
  const b = Array.from(right, ch => ch.codePointAt(0));
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    if (a[i] !== b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
};
const canonical = value => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  if (value !== null && typeof value === "object") {
    return `{${Object.keys(value).sort(compare).map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(",")}}`;
  }
  requireThat(typeof value !== "number" || Number.isSafeInteger(value), "nonportable number");
  return JSON.stringify(value);
};
const countNodes = (value, limit) => {
  const pending = [[value, 0]];
  let nodes = 0;
  while (pending.length > 0) {
    const [item, depth] = pending.pop();
    nodes += 1;
    requireCapacity(depth <= 64 && nodes <= limit, "structure capacity");
    if (Array.isArray(item)) {
      for (const child of item) pending.push([child, depth + 1]);
    } else if (item !== null && typeof item === "object") {
      for (const child of Object.values(item)) pending.push([child, depth + 1]);
    }
  }
  return nodes;
};

async function main() {
  let raw = "";
  process.stdin.setEncoding("utf8");
  for await (const chunk of process.stdin) {
    raw += chunk;
    requireCapacity(Buffer.byteLength(raw) <= 64 * 1024 * 1024, "input capacity");
  }
  const input = JSON.parse(raw);
  requireThat(["STANDARD", "PACKAGE_GRAPH"].includes(input.transport_profile),
    "transport profile");
  const packageGraph = input.transport_profile === "PACKAGE_GRAPH";
  const inputLimit = (packageGraph ? 64 : 16) * 1024 * 1024;
  const nodeLimit = packageGraph ? PACKAGE_NODES : STANDARD_NODES;
  const outputLimit = packageGraph ? PACKAGE_OUTPUT_BYTES : STANDARD_OUTPUT_BYTES;
  requireCapacity(Buffer.byteLength(raw) <= inputLimit, "input capacity");
  countNodes(input, nodeLimit);
  const manifest = JSON.parse(input.manifest);
  countNodes(manifest, nodeLimit);
  // A duplicate key cannot survive exact canonical re-encoding: JSON.parse's
  // last-key behavior is therefore detected, not silently accepted.
  requireThat(canonical(manifest) + "\n" === input.manifest, "noncanonical manifest");
  requireThat(manifest.schema_version === "verifier-objects-manifest-2", "wrong manifest version");
  requireThat(sha256(canonical(input.registry.contracts)) === manifest.registry_digest, "registry mismatch");
  const registry = new Map(input.registry.contracts.map(row => [row.kind, row]));
  const surfaces = new Map(input.surfaces.map(row => [row.surface_id, row]));
  const files = new Map(input.files.map(row => [row.path, row.sha256]));
  // Python runs each registered closure freshly and supplies only typed ESTABLISHED
  // verdicts. This process cannot run that closure, so it accepts a verdict only when
  // it is exactly shaped, names a current DOES_NOT_APPLY row by digest, and carries
  // digest-form identity. A witness digest, a legacy pair or an omitted list is not
  // proof: an omitted list is a malformed input, never an empty one.
  const typedVerdicts = input.established_non_applicability;
  requireThat(Array.isArray(typedVerdicts), "execution verdicts absent");
  const verdictKeys = JSON.stringify(["closure_digest", "decision_row_digest", "kind", "object_id", "receipt_digest", "status"]);
  const rowsById = new Map(manifest.objects.map(row => [row.object_id, row]));
  const withoutRefutation = decision => Object.fromEntries(Object.entries(decision).filter(([key]) => key !== "refutation"));
  const documentedApplicability = new Map();
  const documentedBinding = {};
  if (input.documented_applicability !== undefined) {
    const binding = input.documented_applicability;
    requireThat(binding !== null && typeof binding === "object" && !Array.isArray(binding)
      && JSON.stringify(Object.keys(binding).sort()) === JSON.stringify(["answers", "reason_ir_digest"]),
      "documented applicability shape");
    requireThat(typeof binding.reason_ir_digest === "string"
      && /^sha256:[0-9a-f]{64}$/.test(binding.reason_ir_digest), "reason IR digest");
    requireThat(Array.isArray(binding.answers), "documented applicability answers");
    const answerKeys = JSON.stringify(["decision", "object_id", "object_kind", "reason_id"]);
    for (const answer of binding.answers) {
      requireThat(answer !== null && typeof answer === "object" && !Array.isArray(answer)
        && JSON.stringify(Object.keys(answer).sort()) === answerKeys,
        "documented applicability answer shape");
      requireThat(answer.decision === "APPLIES" && typeof answer.reason_id === "string"
        && answer.reason_id.length > 0 && typeof answer.object_id === "string"
        && typeof answer.object_kind === "string" && registry.has(answer.object_kind),
        "documented applicability answer identity");
      const decision = rowsById.get(answer.object_id)?.classification?.[answer.object_kind];
      requireThat(decision?.status === "UNRESOLVED" || decision?.status === "DOES_NOT_APPLY",
        "documented applicability target not answerable");
      const key = answer.object_id + "\n" + answer.object_kind;
      requireThat(!documentedApplicability.has(key), "duplicate documented applicability answer");
      documentedApplicability.set(key, answer.reason_id);
    }
    documentedBinding.documented_applicability_digest = sha256(canonical(binding));
  }
  const established = new Map();
  for (const verdict of typedVerdicts) {
    requireThat(verdict !== null && typeof verdict === "object" && !Array.isArray(verdict)
      && JSON.stringify(Object.keys(verdict).sort()) === verdictKeys, "verdict shape");
    requireThat(verdict.status === "ESTABLISHED", "verdict status");
    for (const field of ["closure_digest", "decision_row_digest", "receipt_digest"]) {
      requireThat(typeof verdict[field] === "string" && /^sha256:[0-9a-f]{64}$/.test(verdict[field]), "verdict digest");
    }
    requireThat(typeof verdict.object_id === "string" && typeof verdict.kind === "string"
      && registry.has(verdict.kind), "verdict identity");
    const decision = rowsById.get(verdict.object_id)?.classification?.[verdict.kind];
    requireThat(decision?.status === "DOES_NOT_APPLY", "verdict names no DOES_NOT_APPLY row");
    requireThat(verdict.decision_row_digest === sha256(canonical(withoutRefutation(decision))),
      "verdict row digest");
    const key = verdict.object_id + "\n" + verdict.kind;
    requireThat(!established.has(key), "duplicate verdict");
    established.set(key, verdict.decision_row_digest);
  }
  const parents = kind => {
    const result = [];
    while (kind !== null) {
      requireThat(registry.has(kind) && !result.includes(kind), "unregistered or cyclic kind");
      result.push(kind);
      kind = registry.get(kind).extends;
    }
    return result;
  };
  const requirements = Object.create(null);
  const effectiveKinds = Object.create(null);
  let derivationItems = 0;
  let derivationBytes = 0;
  requireThat(Array.isArray(input.nonstructural_role_decisions),
    "nonstructural role decisions absent");
  const consequences = deriveConsequences(manifest, registry, surfaces, parents, compare,
    value => sha256(canonical(value)), input.nonstructural_role_decisions);
  for (const object of manifest.objects) {
    requireThat(!Object.hasOwn(requirements, object.object_id), "duplicate object");
    requireThat(registry.has(object.kind), "unregistered primary kind");
    const primaryBase = parents(object.kind).at(-1);
    for (const role of object.specializations) {
      requireThat(registry.has(role) && registry.get(role).extends !== null,
        "specialization is not a refinement");
      const roleBase = parents(role).at(-1);
      requireThat(roleBase === "OBJECT" || roleBase === primaryBase,
        "specialization base differs");
    }
    const declared = new Set([object.kind, ...object.specializations].flatMap(parents));
    const owned = object.surfaces.filter(id => surfaces.has(id)).map(id => surfaces.get(id));
    const paths = new Set(owned.map(row => row.path));
    const source = new Set(owned.flatMap(row => row.source_kinds));
    const hints = new Set(owned.flatMap(row => row.hints));
    const effective = new Set(declared);
    const consequential = new Set(consequences.required_kinds[object.object_id] ?? []);
    const reviews = new Set([...registry.values()].filter(row => row.extends !== null).map(row => row.kind));
    for (const kind of [...source, ...hints, ...consequential, ...Object.keys(object.classification)]) reviews.add(kind);
    derivationItems += reviews.size;
    requireCapacity(derivationItems <= DERIVED_ITEMS, "derivation capacity");
    for (const kind of reviews) {
      if (!registry.has(kind)) continue; // Python reports the explicit unresolved contract.
      const decision = object.classification[kind];
      const supported = decision && decision.reason.trim() && decision.evidence.length > 0
        && decision.evidence.every(ref => ref.path !== "objects.vstd" && files.get(ref.path) === ref.sha256)
        && decision.evidence.some(ref => paths.has(ref.path));
      const adopted = declared.has(kind) || source.has(kind) || consequential.has(kind) || decision?.status === "APPLIES";
      // Match Python's denominator without interpreting evidence freshness as
      // applicability: a nonempty UNRESOLVED selection remains conditional even
      // when stale, while an empty draft classification does not expand scope.
      const conditionalCandidate = decision?.status === "UNRESOLVED" && decision.evidence.length > 0;
      const reasonApplies = documentedApplicability.has(object.object_id + "\n" + kind);
      // Only a current executable witness removes a hint; any other
      // DOES_NOT_APPLY leaves the hint's obligations required.
      const witnessed = decision?.status === "DOES_NOT_APPLY" && supported
        && established.get(object.object_id + "\n" + kind) === sha256(canonical(withoutRefutation(decision)));
      const refuted = witnessed && !adopted;
      if (adopted || reasonApplies || conditionalCandidate || (hints.has(kind) && !refuted)) {
        for (const ancestor of parents(kind)) effective.add(ancestor);
      }
    }
    const objectRequirements = [...new Set([...effective].flatMap(kind =>
      registry.get(kind).obligations.map(row => row.id)))].sort(compare);
    const objectKinds = [...effective].sort(compare);
    derivationItems += objectRequirements.length + objectKinds.length;
    requireCapacity(derivationItems <= DERIVED_ITEMS, "derivation capacity");
    derivationBytes += Buffer.byteLength(canonical(objectRequirements))
      + Buffer.byteLength(canonical(objectKinds));
    requireCapacity(derivationBytes <= DERIVED_OUTPUT_BYTES,
      "derivation output capacity");
    requirements[object.object_id] = objectRequirements;
    effectiveKinds[object.object_id] = objectKinds;
  }
  // Reconstruct every base record independently; extension labels still drive
  // the requirements above. This is graph-byte agreement, not source execution.
  const records = manifest.objects.map(object => {
    const chain = parents(object.kind);
    const kind = chain[chain.length - 1];
    const payload = {...object.payload};
    if (kind === "GRAPH") {
      const element = parents(payload.element_kind);
      payload.element_kind = element[element.length - 1];
    }
    return {object_id: object.object_id, kind, payload, operands: object.operands};
  }).sort((a, b) => compare(a.object_id, b.object_id));
  const representationBinding = {};
  if (input.representations !== undefined) {
    const {updates, retained_objects: retained} = input.representations;
    const current = new Map(records.map(record => [record.object_id, record]));
    const selected = new Map(updates.map(update => [update.object_id, update]));
    requireThat(selected.size === updates.length, "duplicate representation update");
    const changed = new Set();
    const retainedIds = new Set(retained.map(record => record.object_id));
    for (const before of retained) {
      const after = current.get(before.object_id);
      requireThat(after && before.kind === after.kind, "retained kind removed");
      if (before.kind === "GRAPH") {
        requireThat(Object.keys(after.operands).join() === "members", "graph roles changed");
        requireThat(canonical([...after.operands.members].sort(compare)) ===
          canonical(records.filter(row => row.object_id !== after.object_id).map(row => row.object_id).sort(compare)), "incomplete graph");
        requireThat(canonical(after.operands.members.filter(id => retainedIds.has(id))) ===
          canonical(before.operands.members), "retained members changed");
      } else requireThat(canonical(before.operands) === canonical(after.operands), "retained operands changed");
      if (canonical(before.payload) !== canonical(after.payload)) {
        changed.add(before.object_id);
        const update = selected.get(before.object_id);
        requireThat(update && update.reason.trim() &&
          update.retained_object_digest === sha256(canonical(before)) &&
          update.current_object_digest === sha256(canonical(after)), "representation commitment differs");
      }
    }
    requireThat(changed.size === selected.size && [...changed].every(id => selected.has(id)), "representation denominator differs");
    representationBinding.representation_binding_digest = sha256(canonical(input.representations));
  }
  const receipt = {manifest_digest: sha256(input.manifest),
    registry_digest: manifest.registry_digest, requirements, effective_kinds: effectiveKinds, consequences,
    nonstructural_role_digest: sha256(canonical(input.nonstructural_role_decisions)),
    instance_selection_digest: sha256(canonical(manifest.instance_checks ?? [])),
    execution_selection_digest: sha256(canonical(manifest.execution_checks ?? [])),
    javascript_mechanism_digest: sha256(canonical(input.javascript_mechanism ?? null)),
    markup_binding_digest: sha256(canonical(input.markup_binding)),
    workflow_binding_digest: sha256(canonical(input.workflow_binding)),
    ...(input.systems_mechanism == null ? {} : {systems_mechanism_digest: sha256(canonical(input.systems_mechanism))}),
    export_binding_digest: sha256(canonical(input.surfaces.filter(row => row.form === "Export").map(row => ({
      surface_id: row.surface_id, target_surface_id: row.target_surface_id, target_source_digest: row.target_source_digest
    })))),
    ...documentedBinding,
    ...representationBinding,
    base_composition_digest: sha256(canonical({schema_version: "verifier-object-composition-1", objects: records}))};
  countNodes(receipt, nodeLimit);
  const output = canonical(receipt) + "\n";
  requireCapacity(Buffer.byteLength(output) <= outputLimit, "output capacity");
  process.stdout.write(output);
}

try { await main(); }
catch (error) {
  process.stdout.write(error instanceof CapacityRefusal
    ? '{"error":"NAMESPACE_RECONCILIATION_CAPACITY_EXHAUSTED"}\n'
    : '{"error":"NAMESPACE_RECONCILIATION_REJECTED"}\n');
  process.exitCode = 1;
}
