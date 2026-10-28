// Independent strict Node.js reconciler for the structural objects.vstd subset.
// It intentionally does not import or invoke the Python implementation.
import { createHash } from "node:crypto";
import { lstat, open, readFile, realpath } from "node:fs/promises";
import path from "node:path";

const MANIFEST_SCHEMA = "verifier-objects-manifest-1";
const PROFILE_ID = "vstd-tier-zero-repository-admission-1";
const PROFILE_DIGEST = "sha256:dbc26ba0d7b571c3c86037a977e88b5c41fbbb6118b429cfa48b217143eb2441";
// Mirror of the installed nine Tier-0 coordinates and slugs.  The digest above
// is the runtime pin; this literal is inspected by the cross-implementation test.
const PROFILE_OBLIGATIONS = [
  ["VSTD-T0.1", "Canonical manifest admission"],
  ["VSTD-T0.2", "Object denominator closure"],
  ["VSTD-T0.3", "Typed relation closure"],
  ["VSTD-T0.4", "Exposed-surface closure"],
  ["VSTD-T0.5", "Obligation denominator closure"],
  ["VSTD-T0.6", "Reason and realization closure"],
  ["VSTD-T0.7", "Source and mechanism freshness"],
  ["VSTD-T0.8", "Independent implementation agreement"],
  ["VSTD-T0.9", "Conservative verdict and authority boundary"]
];
const OBJECT_DECLARATIONS_DIGEST = "sha256:fac24d7f132b03e3d2efbf598572c6fadff129bcd131afeff744013b0ab55ec5";
const OBLIGATION_DENOMINATOR = {
  semantic_version: "verifier-current-object-obligations-1",
  slot_count: 234,
  route_count: 408,
  slot_digest: "sha256:1567402834fe4b4c395d81e6291d2d91b54065127c9cb74c722b2bc42238ea8e",
  route_identity_digest: "sha256:2c100177a41b4968b5e26d0b636fc4dcc99cc68564ce72e32782562f83bf3335",
};
const CLAIM_BOUNDARY = "Tier-0 PASS admits one exact repository declaration at one source coordinate. It does not establish a Tier-1-plus obligation, full package polish, release authority, publication, or deployment.";
const MAX_MANIFEST_BYTES = 4 * 1024 * 1024;
// Source-owning envelopes have a separate transport ceiling. The retained
// contract and unknown versions still use the original bound.
const MAX_EXTENDED_MANIFEST_BYTES = 8 * 1024 * 1024;
const MAX_PACKAGE_MANIFEST_BYTES = 32 * 1024 * 1024;
const MAX_MANIFEST_NODES = 250000;
const MAX_PACKAGE_MANIFEST_NODES = 1000000;
const OBJECT_KINDS = [
  "HUMAN", "ACTOR", "COLLECTIVE", "ROLE", "IDENTITY", "OWNER",
  "HARDWARE", "RECEIPT", "OBJECT", "GRAPH", "SPACE", "TIME", "EVENT",
  "ENV", "DATA", "VERIFIER", "BENCH", "ARCH", "TRAIN", "HYPER",
  "MODEL", "HARNESS", "AGENT", "SIM", "BOT", "TOKEN",
];
const SURFACE_CATEGORIES = [
  "candidate_source_file", "package_file", "python_module", "python_function",
  "installed_cell", "installed_route", "installed_mechanism",
  "structural_family", "structural_membership", "structural_route_crosswalk",
  "non_route_gate", "public_cli_route", "public_cli_preparser_route",
  "console_alias", "public_lazy_export", "domain", "domain_check",
  "interoperability_component", "schema", "native_route",
  "compatibility_route", "package_data_candidate", "unresolved_surface",
];

class Refusal extends Error {}
function requireThat(condition, code) {
  if (!condition) throw new Refusal(code);
}
const compare = (left, right) => {
  const a = Array.from(left, character => character.codePointAt(0));
  const b = Array.from(right, character => character.codePointAt(0));
  for (let index = 0; index < Math.min(a.length, b.length); index++) {
    if (a[index] !== b[index]) return a[index] - b[index];
  }
  return a.length - b.length;
};
function sameKeys(value, expected) {
  return value !== null && !Array.isArray(value) && typeof value === "object"
    && JSON.stringify(Object.keys(value).sort(compare)) === JSON.stringify([...expected].sort(compare));
}
function sha256(bytes) {
  return `sha256:${createHash("sha256").update(bytes).digest("hex")}`;
}

// JSON.parse silently overwrites duplicate keys.  This bounded recursive-descent
// decoder instead detects them before constructing the value.
class StrictJsonParser {
  constructor(text) { this.text = text; this.at = 0; this.nodes = 0; }
  skip() { while (/\s/.test(this.text[this.at] ?? "")) this.at += 1; }
  bump(depth) {
    this.nodes += 1;
    requireThat(depth <= 64 && this.nodes <= MAX_PACKAGE_MANIFEST_NODES,
      "TIER_ZERO_MANIFEST_STRUCTURE_CAPACITY_EXHAUSTED");
  }
  parse() {
    this.skip();
    const value = this.value(0);
    this.skip();
    requireThat(this.at === this.text.length, "TIER_ZERO_MANIFEST_INVALID_JSON");
    return value;
  }
  value(depth) {
    this.bump(depth);
    this.skip();
    const ch = this.text[this.at];
    if (ch === "{") return this.object(depth + 1);
    if (ch === "[") return this.array(depth + 1);
    if (ch === '"') return this.string();
    if (this.text.startsWith("NaN", this.at)
        || this.text.startsWith("Infinity", this.at)
        || this.text.startsWith("-Infinity", this.at)) {
      throw new Refusal("TIER_ZERO_MANIFEST_NONFINITE_NUMBER");
    }
    for (const [literal, value] of [["true", true], ["false", false], ["null", null]]) {
      if (this.text.startsWith(literal, this.at)) {
        this.at += literal.length;
        return value;
      }
    }
    const found = this.text.slice(this.at).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
    requireThat(found !== null, "TIER_ZERO_MANIFEST_INVALID_JSON");
    this.at += found[0].length;
    const number = Number(found[0]);
    requireThat(Number.isFinite(number), "TIER_ZERO_MANIFEST_NONFINITE_NUMBER");
    return number;
  }
  string() {
    const start = this.at;
    this.at += 1;
    let escaped = false;
    while (this.at < this.text.length) {
      const ch = this.text[this.at++];
      if (escaped) { escaped = false; continue; }
      if (ch === "\\") { escaped = true; continue; }
      if (ch === '"') {
        try { return JSON.parse(this.text.slice(start, this.at)); }
        catch { throw new Refusal("TIER_ZERO_MANIFEST_INVALID_JSON"); }
      }
      requireThat(ch.charCodeAt(0) >= 0x20, "TIER_ZERO_MANIFEST_INVALID_JSON");
    }
    throw new Refusal("TIER_ZERO_MANIFEST_INVALID_JSON");
  }
  object(depth) {
    this.at += 1;
    this.skip();
    const result = {};
    const keys = new Set();
    if (this.text[this.at] === "}") { this.at += 1; return result; }
    while (true) {
      requireThat(this.text[this.at] === '"', "TIER_ZERO_MANIFEST_INVALID_JSON");
      const key = this.string();
      requireThat(!keys.has(key), "TIER_ZERO_MANIFEST_DUPLICATE_KEY");
      keys.add(key);
      this.skip();
      requireThat(this.text[this.at++] === ":", "TIER_ZERO_MANIFEST_INVALID_JSON");
      result[key] = this.value(depth);
      this.skip();
      const delimiter = this.text[this.at++];
      if (delimiter === "}") return result;
      requireThat(delimiter === ",", "TIER_ZERO_MANIFEST_INVALID_JSON");
      this.skip();
    }
  }
  array(depth) {
    this.at += 1;
    this.skip();
    const result = [];
    if (this.text[this.at] === "]") { this.at += 1; return result; }
    while (true) {
      result.push(this.value(depth));
      this.skip();
      const delimiter = this.text[this.at++];
      if (delimiter === "]") return result;
      requireThat(delimiter === ",", "TIER_ZERO_MANIFEST_INVALID_JSON");
      this.skip();
    }
  }
}

function canonical(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    requireThat(Number.isFinite(value), "TIER_ZERO_MANIFEST_NONFINITE_NUMBER");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  requireThat(typeof value === "object", "TIER_ZERO_MANIFEST_INVALID_VALUE");
  return `{${Object.keys(value).sort(compare).map(
    key => `${JSON.stringify(key)}:${canonical(value[key])}`
  ).join(",")}}`;
}
function valueDigest(value) { return sha256(Buffer.from(canonical(value), "utf8")); }
function canonicalDocument(value) { return Buffer.from(`${canonical(value)}\n`, "utf8"); }

const ADVERSARIAL_FIXTURES = [
  ["duplicate-key", Buffer.from('{"a":1,"a":2}\n'), "TIER_ZERO_MANIFEST_DUPLICATE_KEY"],
  ["nonfinite-number", Buffer.from('{"a":NaN}\n'), "TIER_ZERO_MANIFEST_NONFINITE_NUMBER"],
  ["noncanonical-whitespace", Buffer.from('{ "a":1}\n'), "TIER_ZERO_MANIFEST_NOT_CANONICAL"],
];
function adversarialCorpusReceipt() {
  const rows = ADVERSARIAL_FIXTURES.map(([name, raw, expected]) => {
    let observed = "ACCEPTED";
    try {
      const value = new StrictJsonParser(raw.toString("utf8")).parse();
      requireThat(raw.equals(canonicalDocument(value)), "TIER_ZERO_MANIFEST_NOT_CANONICAL");
    } catch (error) {
      observed = error instanceof Refusal ? error.message : "UNEXPECTED_ERROR";
    }
    return {
      name,
      input_digest: sha256(raw),
      expected,
      observed,
      status: observed === expected ? "PASS" : "FAIL",
    };
  });
  const body = {
    schema_version: "verifier-tier-zero-parser-corpus-1",
    status: rows.every(row => row.status === "PASS") ? "PASS" : "FAIL",
    rows,
  };
  return {...body, corpus_digest: valueDigest(body)};
}

function validateSelection(value, code) {
  requireThat(sameKeys(value, ["selection_status", "path", "sha256"]), `${code}_FIELDS_DIFFER`);
  requireThat(["SELECTED", "NOT_SELECTED"].includes(value.selection_status), `${code}_STATUS_INVALID`);
  if (value.selection_status === "SELECTED") {
    requireThat(typeof value.path === "string" && value.path.length > 0
      && !value.path.includes("\\") && !value.path.startsWith("/")
      && !value.path.split("/").includes("..") && !value.path.split("/").includes("."),
      `${code}_PATH_INVALID`);
    requireThat(/^sha256:[0-9a-f]{64}$/.test(value.sha256), `${code}_DIGEST_INVALID`);
  } else {
    requireThat(value.path === null && value.sha256 === null, `${code}_UNSELECTED_BINDING_PRESENT`);
  }
}

function validateGraph(objects) {
  requireThat(Array.isArray(objects) && objects.length === 26,
    "TIER_ZERO_OBJECT_DENOMINATOR_DIFFERS");
  requireThat(valueDigest(objects) === OBJECT_DECLARATIONS_DIGEST,
    "TIER_ZERO_OBJECT_GRAPH_DIFFERS");
  const byId = new Map();
  const kinds = [];
  for (const row of objects) {
    requireThat(sameKeys(row, ["object_id", "object_kind", "role", "edges"]),
      "TIER_ZERO_OBJECT_FIELDS_DIFFER");
    requireThat(!byId.has(row.object_id), "TIER_ZERO_OBJECT_ID_DUPLICATED");
    byId.set(row.object_id, row);
    kinds.push(row.object_kind);
  }
  requireThat(JSON.stringify(kinds) === JSON.stringify(OBJECT_KINDS),
    "TIER_ZERO_OBJECT_KIND_SET_DIFFERS");
  const waiting = new Map();
  const dependents = new Map([...byId.keys()].map(key => [key, new Set()]));
  for (const row of objects) {
    const refs = new Set();
    for (const targets of Object.values(row.edges)) {
      requireThat(Array.isArray(targets) && new Set(targets).size === targets.length,
        "TIER_ZERO_OBJECT_EDGE_INVALID");
      for (const target of targets) {
        requireThat(byId.has(target), "TIER_ZERO_OBJECT_EDGE_DANGLING");
        refs.add(target);
        dependents.get(target).add(row.object_id);
      }
    }
    waiting.set(row.object_id, refs);
  }
  const ready = [...waiting].filter(([, refs]) => refs.size === 0).map(([id]) => id).sort();
  let visited = 0;
  while (ready.length) {
    const id = ready.shift();
    visited += 1;
    for (const parent of [...dependents.get(id)].sort()) {
      waiting.get(parent).delete(id);
      if (waiting.get(parent).size === 0) ready.push(parent);
    }
  }
  requireThat(visited === objects.length, "TIER_ZERO_OBJECT_COMPOSITION_REFUTED");
  const records = objects.map(row => ({
    object_id: row.object_id,
    kind: row.object_kind,
    payload: {
      representation_role: row.role,
      ...(row.object_kind === "GRAPH" ? { element_kind: "OBJECT" } : {}),
    },
    operands: row.edges,
  })).sort((a, b) => a.object_id.localeCompare(b.object_id));
  return valueDigest({schema_version: "verifier-object-composition-1", objects: records});
}

function reconcile(value, expectedRepository, expectedRevision) {
  requireThat(sameKeys(value, [
    "schema_version", "profile_id", "profile_digest", "repository", "objects",
    "obligation_denominator", "surface_rules", "obligation_reason_provider",
    "node_reconciler", "claim_boundary",
  ]), "TIER_ZERO_MANIFEST_FIELDS_DIFFER");
  requireThat(value.schema_version === MANIFEST_SCHEMA && value.profile_id === PROFILE_ID
    && value.profile_digest === PROFILE_DIGEST && value.claim_boundary === CLAIM_BOUNDARY,
    "TIER_ZERO_MANIFEST_PROFILE_DIFFERS");
  requireThat(sameKeys(value.repository, ["remote", "revision", "source_root"])
    && value.repository.remote === expectedRepository
    && value.repository.revision === expectedRevision
    && value.repository.source_root === "."
    && /^[0-9a-f]{40}([0-9a-f]{24})?$/.test(expectedRevision),
    "TIER_ZERO_MANIFEST_SOURCE_COORDINATE_DIFFERS");
  const graphDigest = validateGraph(value.objects);
  requireThat(canonical(value.obligation_denominator) === canonical(OBLIGATION_DENOMINATOR),
    "TIER_ZERO_OBLIGATION_DENOMINATOR_DIFFERS");
  const rules = value.surface_rules;
  requireThat(Array.isArray(rules) && rules.length === SURFACE_CATEGORIES.length,
    "TIER_ZERO_SURFACE_RULE_DENOMINATOR_DIFFERS");
  const ids = new Set(value.objects.map(row => row.object_id));
  for (let index = 0; index < rules.length; index += 1) {
    const rule = rules[index];
    requireThat(sameKeys(rule, ["category", "disposition", "owner_object_id", "reason"]),
      "TIER_ZERO_SURFACE_RULE_FIELDS_DIFFER");
    requireThat(rule.category === SURFACE_CATEGORIES[index]
      && ["OWNED", "EXCLUDED", "UNRESOLVED"].includes(rule.disposition)
      && typeof rule.reason === "string" && rule.reason.length > 0 && rule.reason.length <= 4096,
      "TIER_ZERO_SURFACE_RULE_INVALID");
    requireThat(rule.disposition === "OWNED" ? ids.has(rule.owner_object_id)
      : rule.owner_object_id === null, "TIER_ZERO_SURFACE_OWNER_INVALID");
  }
  validateSelection(value.obligation_reason_provider, "TIER_ZERO_REASON_PROVIDER");
  validateSelection(value.node_reconciler, "TIER_ZERO_NODE_RECONCILER");
  const corpus = adversarialCorpusReceipt();
  requireThat(corpus.status === "PASS", "TIER_ZERO_NODE_ADVERSARIAL_CORPUS_FAILED");
  return {
    schema_version: "verifier-tier-zero-node-manifest-validation-1",
    status: "PASS",
    profile_digest: PROFILE_DIGEST,
    object_count: value.objects.length,
    object_kind_digest: valueDigest(value.objects.map(row => row.object_kind)),
    graph_digest: graphDigest,
    ...value.obligation_denominator,
    surface_rule_count: rules.length,
    surface_rule_digest: valueDigest(rules),
    reason_provider_selection_status: value.obligation_reason_provider.selection_status,
    node_reconciler_selection_status: value.node_reconciler.selection_status,
    attachment_selection_digest: valueDigest({
      obligation_reason_provider: value.obligation_reason_provider,
      node_reconciler: value.node_reconciler,
    }),
    adversarial_corpus_status: corpus.status,
    adversarial_corpus_digest: corpus.corpus_digest,
  };
}

async function validateSelectedFile(root, selection, exactRelative, code) {
  requireThat(selection.selection_status === "SELECTED" && selection.path === exactRelative,
    `${code}_SELECTION_DIFFERS`);
  const resolvedRoot = await realpath(path.resolve(root));
  const candidate = path.resolve(resolvedRoot, selection.path);
  let raw;
  try {
    const stat = await lstat(candidate);
    requireThat(stat.isFile() && !stat.isSymbolicLink(), `${code}_INVALID`);
    const selected = await realpath(candidate);
    requireThat(selected.startsWith(`${resolvedRoot}${path.sep}`), `${code}_ESCAPES_SOURCE_ROOT`);
    raw = await readFile(selected);
  }
  catch (error) {
    if (error instanceof Refusal) throw error;
    throw new Refusal(`${code}_UNAVAILABLE`);
  }
  requireThat(sha256(raw) === selection.sha256, `${code}_DIGEST_DIFFERS`);
}

async function main() {
  const arguments_ = process.argv.slice(2);
  const options = {};
  for (let index = 0; index < arguments_.length; index += 2) {
    requireThat(arguments_[index]?.startsWith("--") && arguments_[index + 1] !== undefined,
      "TIER_ZERO_NODE_ARGUMENTS_INVALID");
    options[arguments_[index].slice(2)] = arguments_[index + 1];
  }
  requireThat(sameKeys(options, ["manifest", "repository", "revision", "source-root"]),
    "TIER_ZERO_NODE_ARGUMENTS_INVALID");
  const manifestInfo = await lstat(options.manifest);
  requireThat(manifestInfo.isFile() && !manifestInfo.isSymbolicLink()
    && manifestInfo.size > 0 && manifestInfo.size <= MAX_PACKAGE_MANIFEST_BYTES,
    "TIER_ZERO_MANIFEST_CAPACITY_EXHAUSTED");
  const handle = await open(options.manifest, "r");
  // One extra byte detects growth after lstat without imposing a 32 MiB
  // allocation on every legacy or small manifest.
  const buffer = Buffer.alloc(Math.min(
    MAX_PACKAGE_MANIFEST_BYTES + 1, Number(manifestInfo.size) + 1,
  ));
  let length = 0;
  try {
    while (length < buffer.length) {
      const {bytesRead} = await handle.read(buffer, length, buffer.length - length, length);
      if (bytesRead === 0) break;
      length += bytesRead;
    }
  } finally { await handle.close(); }
  const raw = buffer.subarray(0, length);
  requireThat(raw.length > 0 && raw.length <= MAX_PACKAGE_MANIFEST_BYTES,
    "TIER_ZERO_MANIFEST_CAPACITY_EXHAUSTED");
  let text;
  try { text = new TextDecoder("utf-8", {fatal: true}).decode(raw); }
  catch { throw new Refusal("TIER_ZERO_MANIFEST_INVALID_JSON"); }
  const parser = new StrictJsonParser(text);
  const document = parser.parse();
  const extended = ["verifier-objects-manifest-2", "verifier-objects-manifest-3",
    "verifier-objects-manifest-4"].includes(document.schema_version);
  // Versions 5 and 6 are both package graphs: 6 carries the same retained
  // contract with a compact namespace, and tier_zero_manifest.py gives both
  // the package byte and node envelope.
  const packageGraph = ["verifier-objects-manifest-5", "verifier-objects-manifest-6"]
    .includes(document.schema_version);
  const byteLimit = packageGraph ? MAX_PACKAGE_MANIFEST_BYTES
    : extended ? MAX_EXTENDED_MANIFEST_BYTES : MAX_MANIFEST_BYTES;
  requireThat(raw.length <= byteLimit,
    "TIER_ZERO_MANIFEST_CAPACITY_EXHAUSTED");
  requireThat(parser.nodes <= (packageGraph ? MAX_PACKAGE_MANIFEST_NODES : MAX_MANIFEST_NODES),
    "TIER_ZERO_MANIFEST_STRUCTURE_CAPACITY_EXHAUSTED");
  requireThat(raw.equals(canonicalDocument(document)), "TIER_ZERO_MANIFEST_NOT_CANONICAL");
  // Interpret the retained contract independently. The outer bytes still bind
  // the namespace; this projection never claims namespace admission by itself.
  let value = document;
  if (["verifier-objects-manifest-3", "verifier-objects-manifest-4",
      "verifier-objects-manifest-5", "verifier-objects-manifest-6"].includes(document.schema_version)) {
    requireThat(document.namespace && typeof document.namespace === "object", "PACKAGE_NAMESPACE_REQUIRED");
    value = {...document, schema_version: "verifier-objects-manifest-1"};
    delete value.namespace;
    if (["verifier-objects-manifest-4", "verifier-objects-manifest-5",
        "verifier-objects-manifest-6"].includes(document.schema_version)) {
      delete value.representation_updates;
    }
  }
  const result = reconcile(value, options.repository, options.revision);
  await validateSelectedFile(
    options["source-root"], value.obligation_reason_provider,
    "reasons.vstd", "TIER_ZERO_REASON_PROVIDER",
  );
  await validateSelectedFile(
    options["source-root"], value.node_reconciler,
    "src/verifier/runtime/tier_zero_reconcile.mjs", "TIER_ZERO_NODE_RECONCILER",
  );
  process.stdout.write(`${canonical({
    ...result,
    attachment_source_binding_status: "PASS",
    manifest_digest: sha256(raw),
    manifest_value_digest: valueDigest(value),
  })}\n`);
}

try { await main(); }
catch (error) {
  const code = error instanceof Refusal ? error.message : "TIER_ZERO_NODE_RECONCILER_UNAVAILABLE";
  process.stdout.write(`${canonical({schema_version: "verifier-tier-zero-node-error-1", status: error instanceof Refusal ? "FAIL" : "UNKNOWN", error: code})}\n`);
  process.exitCode = error instanceof Refusal ? 1 : 2;
}
