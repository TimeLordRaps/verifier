"""Project Tier zero under the effect-first proposal for Verifier Standard (VSTD).

Reports use JavaScript Object Notation (JSON), Python's abstract syntax tree (AST), and
Unicode Transformation Format, 8-bit (UTF-8) source decoding.

usage: python -B project_effect_first.py PROJECTION_JSON [OBJECTS_DUMP_JSON]

Same loading and classification as group_open.py.  Then, per kind cell of each object:
  * whether something selects it (label, source declaration, consequence, APPLIES row,
    evidence-bearing UNRESOLVED, reviewer-written UNRESOLVED, name hint, or the kind's own
    boundary identifier found by its closure scan);
  * for unselected kinds, the installed census verdict a witness-free DOES_NOT_APPLY would get
    now (_census_verdict: fresh closure scan plus closed-effect audit of the owned census).

Projected items, per variant (stale labels kept/withdrawn x verifier hints kept/attributed):
  candidate  one item per open cell whose kind is selected
  excluded   open unselected cells whose verdict is DOCUMENTED: derived exclusions, no item
  subsumed   open unselected cells with any other verdict (object-wide blocker, or an
             unexpected code, counted conservatively): held open by the object's census item
  census     one item per object that holds at least one subsumed cell
  obligation open obligation rows whose kind keeps a trigger

Bytes: every classification row is kept except migration placeholders on unselected kinds
(proposal 4.3 keeps existing DOES_NOT_APPLY rows as documentation), plus one census record per
object.  Nothing here changes any definition; it only counts.

Gate precision (counterfactual, never a verdict): for every object that would get a census
item, every match of the installed shared-gate text patterns is listed and classified with
the Python tokenizer and AST (comment, string, re.compile, literal-name getattr, or code), and
the object's closed-effect audit is run as polish would run it.  An object whose hits are all
in the first four classes and whose audit is CLOSED is blocked only by text-pattern precision.
"""
from __future__ import annotations

import ast
import bisect
import collections
import hashlib
import io
import json
import os
import re
import sys
import time
import tokenize
from pathlib import Path

from verifier.core.certificate import canonical_bytes
from verifier.runtime import namespace_admission as admission
from verifier.runtime import namespace_classification as classification

ROOT = Path(os.environ.get("REASONS_ROOT", ".")).resolve(strict=True)
PLACEHOLDER = "Migration retains this applicability question."
OBJECT_WIDE = {"DYNAMIC_FEATURE_PRESENT", "CLOSED_EFFECT_AUDIT_NOT_CLOSED", "EXTERNAL_EFFECT_PRESENT",
               "UNSUPPORTED_LANGUAGE", "EMPTY_CENSUS", "SOURCE_UNDECODABLE", "OVERSIZE"}
BOUNDARY = "BOUNDARY_IDENTIFIER_REFERENCED"
SYNTHETIC = {"status": "DOES_NOT_APPLY", "reason": "projection", "evidence": []}
VARIANTS = {"effect_first": (False, False), "plus_withdraw_stale": (True, False),
            "plus_attribute_verifier_hints": (False, True), "plus_both": (True, True)}


def say(text: str) -> None:
    print(time.strftime("%H:%M:%S"), text, flush=True)


CALL_NAMES = {"eval", "exec", "compile", "getattr", "setattr", "delattr", "globals", "locals", "vars"}
REGEX_MODULES = {"re", "regex"}
NOT_BLOCKING = {"comment", "string", "regex_compile", "literal_attribute"}


def _python_facts(text: str) -> tuple[list[tuple[int, int, str]] | None, set[tuple[int, int]] | None, set[str]]:
    """Comment and string spans (character offsets), literal-name getattr calls, imported regex modules."""
    spans: list[tuple[int, int, str]] | None = []
    starts = [0]
    for line in io.StringIO(text):
        starts.append(starts[-1] + len(line))
    labels = {tokenize.COMMENT: "comment", tokenize.STRING: "string"}
    if hasattr(tokenize, "FSTRING_MIDDLE"):
        labels[tokenize.FSTRING_MIDDLE] = "string"
    try:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            label = labels.get(token.type)
            if label is not None:
                (srow, scol), (erow, ecol) = token.start, token.end
                spans.append((starts[srow - 1] + scol, starts[erow - 1] + ecol, label))
    except (tokenize.TokenError, SyntaxError):
        spans = None
    literal: set[tuple[int, int]] | None = set()
    regex_imports: set[str] = set()
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        literal = None
    else:
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id in {"getattr", "setattr", "delattr"} and len(node.args) >= 2
                    and isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str)):
                literal.add((node.func.lineno, node.func.col_offset))  # col_offset counts UTF-8 bytes
            elif isinstance(node, ast.Import):
                regex_imports |= {alias.name for alias in node.names
                                  if alias.name in REGEX_MODULES and alias.asname in (None, alias.name)}
    return spans, literal, regex_imports


def file_gate_hits(root: Path, path: str, refutation) -> dict:
    """Every installed shared-gate match in one owned file, each classified.  Read-only."""
    language = refutation._language_of(path)
    if language == "data":
        return {"status": "data", "hits": []}
    if language is None:
        return {"status": "unsupported", "hits": []}
    try:
        text = refutation._normalized_for_scan((root / path).read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError) as exc:
        return {"status": "unreadable:" + type(exc).__name__, "hits": []}
    spans, literal, regex_imports = _python_facts(text) if language == "python" else (None, None, set())
    starts = [0]
    for line in io.StringIO(text):
        starts.append(starts[-1] + len(line))
    hits = []
    for code, patterns in (("DYNAMIC_FEATURE_PRESENT", refutation._DYNAMIC_PATTERNS[language]),
                           ("EXTERNAL_EFFECT_PRESENT", refutation._EXTERNAL_PATTERNS[language])):
        for source in patterns:
            for match in re.finditer(source, text):
                hits.append({"code": code, "token": re.sub(r"\s+", "", match.group(0)),
                             "class": _classify(match, text, language, spans, literal, regex_imports, starts)})
    return {"status": "scanned", "hits": hits}


def _classify(match, text, language, spans, literal, regex_imports, starts) -> str:
    if language != "python" or spans is None:
        return "code"  # no tokenizer for this language here: count it as a real hit
    start = match.start()
    for begin, end, label in spans:
        if begin <= start < end:
            return label
    head = re.match(r"[A-Za-z_]+", match.group(0))
    name = head.group(0) if head is not None else ""
    if name in CALL_NAMES:
        receiver = re.search(r"([A-Za-z_][A-Za-z0-9_]*)\s*\.\s*\Z", text[max(0, start - 80):start])
        if receiver is not None:
            if name == "compile" and receiver.group(1) in regex_imports:
                return "regex_compile"
            return "code" if receiver.group(1) in {"builtins", "__builtins__"} else "attribute_call"
        if name in {"getattr", "setattr", "delattr"} and literal is not None:
            index = bisect.bisect_right(starts, start) - 1
            column = len(text[starts[index]:start].encode("utf-8"))
            if (index + 1, column) in literal:
                return "literal_attribute"
    return "code"


def stale_labels(root: Path) -> tuple[set[tuple[str, str]], str]:
    """The refresh engine's own STALE_SPECIALIZATION_LABEL gaps (in-memory refresh, no writes)."""
    from verifier.runtime import namespace_manifest
    from verifier.runtime import package_manifest_migration as migration
    from verifier.runtime import package_manifest_refresh as refresh
    _, document = namespace_manifest.read_manifest(root / "objects.vstd")
    profile = refresh._selected_source_semantic_profile(document)
    gaps: list[dict] = []
    deltas = refresh._source_semantic_deltas(root, profile)
    migration.refresh_selected_manifest(root, document, record_review_gaps=True, review_gaps=gaps,
                                        source_deltas=deltas)
    stale = {(gap["object_id"], gap["kind"]) for gap in gaps if gap.get("gap") == "STALE_SPECIALIZATION_LABEL"}
    return stale, "refresh engine, this run"


def main() -> int:
    out = Path(sys.argv[1])
    objects_out = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    manifests, discovery = admission.manifests, admission.discovery
    root = ROOT.resolve(strict=True)
    manifest_bytes = (root / "objects.vstd").read_bytes()
    _, document = manifests.read_manifest(root / "objects.vstd")
    from verifier.runtime import package_manifest
    from verifier.runtime import package_manifest_migration as migration
    manifest = document
    if manifest.get("schema_version") in package_manifest.SCHEMAS:
        package_manifest.validate_bridge(manifest)
        manifest = manifest["namespace"]
        if manifest.get("schema_version") == manifests.COMPACT_SCHEMA:
            manifest = manifests.normalize_manifest(manifest)
    registry = manifests.validate_manifest(manifest)
    mechanism = admission.value_digest(admission.mechanism_binding())
    started = time.perf_counter()
    observed = discovery.discover(root)
    say(f"discovery {time.perf_counter() - started:.1f} s")
    consequential = admission.consequences.assess_consequences(
        manifest["objects"], registry, observed, manifest.get("consequence_graph"))
    context = classification.refutation_context(observed, mechanism, root=root)
    started = time.perf_counter()
    classified = classification.assess_classification(
        manifest["objects"], registry, observed, consequence_kinds=consequential["required_kinds"],
        refutation_context=context, derived_item_limit=classification.MAX_DERIVED_ITEMS)
    say(f"classification {time.perf_counter() - started:.1f} s")
    started = time.perf_counter()
    stale_error = None
    try:
        if os.environ.get("PROJECTION_STALE") == "fallback":
            raise RuntimeError("PROJECTION_STALE=fallback selected")
        stale, stale_source = stale_labels(root)
    except Exception as exc:
        stale = None
        stale_source = "current refresh engine unavailable"
        stale_error = f"{type(exc).__name__}:{exc}"
        say(
            "stale labels UNKNOWN via current refresh engine in "
            f"{time.perf_counter() - started:.1f} s: {stale_error}"
        )
    else:
        say(f"stale labels {len(stale)} via {stale_source} in {time.perf_counter() - started:.1f} s")

    surfaces = {row["surface_id"]: row["path"] for row in observed["surfaces"]}
    rows = {row["object_id"]: row for row in manifest["objects"]}
    owned = {identifier: {surfaces[key] for key in rows[identifier]["surfaces"] if key in surfaces}
             for identifier in rows}
    required = consequential["required_kinds"]
    by_code = collections.Counter(item["code"] for item in classified["findings"])

    started = time.perf_counter()
    objects: dict[str, dict] = {}
    for item in classified["objects"]:
        identifier = item["object_id"]
        row = rows[identifier]
        codes: collections.Counter = collections.Counter()
        details: dict[str, str] = {}
        cells = []
        for decision in item["classification"]:
            kind = decision["kind"]
            recorded = row["classification"].get(kind)
            placeholder = recorded is None or (recorded.get("status") == "UNRESOLVED"
                                               and str(recorded.get("reason", "")).startswith(PLACEHOLDER))
            if decision["decision"] == "DOES_NOT_APPLY":
                is_open = decision["non_applicability"] == "NOT_ESTABLISHED"
            else:
                is_open = not (decision["decision"] == "APPLIES" and decision["support_status"] == "PASS")
            verdict = None
            # A stale label may be withdrawn in a variant, so its kind needs a verdict too.
            is_stale = stale is not None and (identifier, kind) in stale
            if not decision["declared"] or is_stale:
                judged = classification._census_verdict(identifier, kind, SYNTHETIC, owned[identifier], context)
                verdict = judged.code
                codes[verdict] += 1
                details.setdefault(verdict, judged.detail)
            cells.append({
                "kind": kind, "open": is_open, "declared": decision["declared"],
                "source": decision["source_declared"], "hinted": decision["hinted"],
                "consequence": kind in required.get(identifier, []),
                "applies": decision["decision"] == "APPLIES",
                "evidence": bool(recorded and recorded.get("status") == "UNRESOLVED" and recorded.get("evidence")),
                "reviewer": bool(recorded and not placeholder and recorded.get("status") == "UNRESOLVED"),
                "boundary": verdict == BOUNDARY, "verdict": verdict,
                "stale": is_stale if stale is not None else None,
                "dna": decision["decision"] == "DOES_NOT_APPLY",
                "placeholder_row": recorded is not None and placeholder})
        held = {code for code in codes if code in OBJECT_WIDE}
        objects[identifier] = {
            "primary": row["kind"], "codes": codes,
            "main": max(held, key=lambda code: codes[code]) if held else None,
            "main_detail": details.get(max(held, key=lambda code: codes[code])) if held else None,
            # Object-wide codes beside DOCUMENTED verdicts would mean those checks depend on the kind.
            "mixed": bool(held) and bool(codes.get(classification.DOCUMENTED_CODE)),
            "unexpected": sorted(set(codes) - OBJECT_WIDE - {BOUNDARY, classification.DOCUMENTED_CODE}),
            "cells": {cell["kind"]: cell for cell in cells},
            "verifier_role": bool(row["classification"].get("VERIFIER", {}).get("status") == "APPLIES"),
        }
    say(f"census verdicts {time.perf_counter() - started:.1f} s")

    def selected(cell: dict, primary: str, withdraw: bool, attribute: bool) -> bool:
        declared = cell["declared"] and not (withdraw and cell["stale"])
        hinted = cell["hinted"] and not (attribute and primary == "VERIFIER")
        return (declared or cell["source"] or cell["consequence"] or cell["applies"] or cell["evidence"]
                or cell["reviewer"] or hinted or cell["boundary"])

    def obligation_kept(cell: dict | None, primary: str, withdraw: bool, attribute: bool) -> bool:
        if cell is None:
            return True
        declared = cell["declared"] and not (withdraw and cell["stale"])
        hinted = cell["hinted"] and not (attribute and primary == "VERIFIER")
        # Only these triggers create obligations in assess_classification.include().
        return declared or cell["source"] or cell["consequence"] or cell["applies"] or cell["evidence"] or hinted

    open_obligations = [row for row in classified["required_obligations"] if row["status"] != "PASS"]
    current = {"open_cells": sum(cell["open"] for item in objects.values() for cell in item["cells"].values()),
               "open_obligations": len(open_obligations),
               "classification_codes": {code: by_code.get(code, 0) for code in (
                   "NAMESPACE_CLASSIFICATION_UNRESOLVED", "NAMESPACE_NON_APPLICABILITY_NOT_ESTABLISHED",
                   "NAMESPACE_OBLIGATION_EVIDENCE_UNRESOLVED")}}

    # Bytes: the classification rows inside the expanded manifest, and what each variant keeps.
    expanded_document = migration.expand_compact_document(document)
    expanded_total = len(canonical_bytes(expanded_document))
    namespace_total = len(canonical_bytes(manifest))
    classification_bytes = sum(len(canonical_bytes(row["classification"])) for row in manifest["objects"])
    census_record = {"status": "LOCKED", "blocker": "CLOSED_EFFECT_AUDIT_NOT_CLOSED",
                     "census_digest": "sha256:" + "0" * 64, "mechanism_digest": "sha256:" + "0" * 64,
                     "reason": "Closed-effect audit of the owned census is not CLOSED."}
    census_record_bytes = len(canonical_bytes(census_record))

    projections = {}
    census_objects: dict[str, set[str]] = {}
    held_cells: dict[str, int] = {}  # effect_first: open cells each census item holds
    for name, (withdraw, attribute) in VARIANTS.items():
        if withdraw and stale is None:
            projections[name] = {
                "status": "UNKNOWN",
                "reason": "current stale-specialization-label assessment is unavailable",
            }
            census_objects[name] = set()
            continue
        census = candidate = excluded = subsumed = dropped_rows = 0
        kept_bytes = 0
        held_objects: set[str] = set()
        excluded_by_kind: collections.Counter = collections.Counter()
        fanout: list[int] = []
        for identifier, item in objects.items():
            keep = {}
            object_subsumed = 0
            for kind, cell in item["cells"].items():
                chosen = selected(cell, item["primary"], withdraw, attribute)
                if cell["open"]:
                    if chosen:
                        candidate += 1
                    elif cell["verdict"] == classification.DOCUMENTED_CODE:
                        excluded += 1  # clean closure and clean effect audit: derived exclusion, no item
                        excluded_by_kind[kind] += 1
                    else:
                        object_subsumed += 1  # an object-wide blocker (or an unexpected code) holds it open
                recorded = rows[identifier]["classification"].get(kind)
                if recorded is not None and (chosen or not cell["placeholder_row"]):
                    keep[kind] = recorded
                elif recorded is not None:
                    dropped_rows += 1
            if object_subsumed:
                census += 1
                held_objects.add(identifier)
                fanout.append(object_subsumed)
                if name == "effect_first":
                    held_cells[identifier] = object_subsumed
            subsumed += object_subsumed
            kept_bytes += len(canonical_bytes(keep)) + census_record_bytes
        census_objects[name] = held_objects
        fanout.sort()
        kept_obligations = sum(obligation_kept(objects[row["object_id"]]["cells"].get(row["kind"]),
                                               objects[row["object_id"]]["primary"], withdraw, attribute)
                               for row in open_obligations)
        projections[name] = {"census_items": census, "candidate_items": candidate,
                             "open_obligations": kept_obligations,
                             "classification_items_total": census + candidate + kept_obligations,
                             "excluded_no_item": excluded, "subsumed_by_census": subsumed,
                             "excluded_by_kind": dict(excluded_by_kind.most_common()),
                             "census_fanout": {"min": fanout[0], "median": fanout[len(fanout) // 2],
                                               "max": fanout[-1]} if fanout else None,
                             "placeholder_rows_dropped": dropped_rows,
                             "classification_bytes_kept": kept_bytes,
                             "expanded_document_bytes_estimate": expanded_total - classification_bytes + kept_bytes}

    # Who carries the candidates: verifier objects vs the rest, and hint-only kinds per verifier object.
    hint_only_per_verifier = collections.Counter()
    hint_only_kinds = collections.Counter()
    candidate_by_primary = collections.Counter()
    first_trigger = collections.Counter()  # proposal 4.2 order a-h; the first that holds
    only_trigger = collections.Counter()
    any_trigger = collections.Counter()
    candidates_on_census_objects = 0
    order = (("a label", "declared"), ("b source declaration", "source"), ("c consequence", "consequence"),
             ("d APPLIES row", "applies"), ("e evidence-bearing UNRESOLVED", "evidence"),
             ("f reviewer-written UNRESOLVED", "reviewer"), ("g name hint", "hinted"),
             ("h boundary identifier", "boundary"))
    clean_states: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    for identifier, item in objects.items():
        count = 0
        if identifier not in census_objects["effect_first"]:
            for kind, cell in item["cells"].items():
                chosen = selected(cell, item["primary"], False, False)
                state = (("open selected" if chosen else "open excluded") if cell["open"]
                         else "closed DOES_NOT_APPLY" if cell["dna"] else "closed APPLIES")
                clean_states[kind][state] += 1
        for kind, cell in item["cells"].items():
            if cell["open"] and selected(cell, item["primary"], False, False):
                candidate_by_primary[item["primary"]] += 1
                holding = [label for label, key in order if cell[key]]
                first_trigger[holding[0]] += 1
                any_trigger.update(holding)
                if len(holding) == 1:
                    only_trigger[holding[0]] += 1
                candidates_on_census_objects += identifier in census_objects["effect_first"]
            only_hint = (cell["hinted"] and cell["open"] and not selected(cell, "VERIFIER", False, True))
            if item["primary"] == "VERIFIER" and only_hint:
                count += 1
                hint_only_kinds[kind] += 1
        if item["primary"] == "VERIFIER":
            hint_only_per_verifier[count] += 1
    # Gate precision: what blocks each census-item object, with every text-gate match classified.
    started = time.perf_counter()
    from verifier.runtime import namespace_refutation as refutation
    scanned_files: dict[str, dict] = {}
    hit_classes: collections.Counter = collections.Counter()
    real_tokens: collections.Counter = collections.Counter()
    audit_first: collections.Counter = collections.Counter()
    tallies = {rule: (collections.Counter(), collections.Counter()) for rule in ("strict", "attribute_calls_cleared")}
    by_main: dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
    examples: dict[str, str | None] = {}
    gate_real: dict[str, bool] = {}  # strict rule: a real text-gate hit, or an unsupported/unreadable file
    for identifier in sorted(census_objects["effect_first"]):
        unsupported = unreadable = 0
        present: collections.Counter = collections.Counter()
        tokens: set[tuple[str, str, str]] = set()
        for path in sorted(owned[identifier]):
            if path not in scanned_files:
                scanned_files[path] = file_gate_hits(root, path, refutation)
            scanned = scanned_files[path]
            unsupported += scanned["status"] == "unsupported"
            unreadable += scanned["status"].startswith("unreadable")
            for hit in scanned["hits"]:
                hit_classes[hit["class"]] += 1
                present[hit["class"]] += 1
                if hit["class"] not in NOT_BLOCKING:
                    tokens.add((hit["code"], hit["class"], hit["token"]))
        gate_real[identifier] = bool(unsupported or unreadable or set(present) - NOT_BLOCKING)
        audit = classification._closed_effect_blocker(context, None, owned[identifier])
        if audit is not None:
            audit_first[f"{audit.code} {str(audit.detail).split(':')[0]}"] += 1
        main = objects[identifier]["main"]
        for rule, cleared in (("strict", NOT_BLOCKING), ("attribute_calls_cleared", NOT_BLOCKING | {"attribute_call"})):
            if audit is not None:
                outcome = "audit " + audit.code
            elif unsupported or unreadable:
                outcome = "unsupported_or_unreadable_file"
            elif set(present) - cleared:
                outcome = "real_gate_hit"
            elif main in ("DYNAMIC_FEATURE_PRESENT", "EXTERNAL_EFFECT_PRESENT"):
                outcome = "text_pattern_precision_only"
            else:
                outcome = "other " + str(main)
            tallies[rule][0][outcome] += 1
            tallies[rule][1][outcome] += held_cells.get(identifier, 0)
            if rule == "strict":
                by_main[str(main)][outcome] += 1
                if outcome == "text_pattern_precision_only" and len(examples) < 15:
                    examples[identifier] = objects[identifier]["main_detail"]
        for code, label, token in tokens:
            real_tokens[f"{code} {label} {token}"] += 1
    gate_precision = {
        "note": ("Counterfactual only. The installed text gates re-run over each census-item object's owned "
                 "files with every match listed and classified by the Python tokenizer and AST; the "
                 "closed-effect audit is polish's own. Not a verdict and not a proposed detector."),
        "objects": len(census_objects["effect_first"]), "files_scanned": len(scanned_files),
        "hit_classes": dict(hit_classes.most_common()),
        "outcomes": {rule: {"objects": dict(counts[0].most_common()), "held_cells": dict(counts[1].most_common())}
                     for rule, counts in tallies.items()},
        "strict_outcome_by_main_reason": {main: dict(counter.most_common()) for main, counter in sorted(by_main.items())},
        "audit_first_blocker": dict(audit_first.most_common(20)),
        "real_hits_by_object_count": dict(real_tokens.most_common(25)),
        "examples_text_pattern_precision_only": examples,
    }
    say(f"gate precision {time.perf_counter() - started:.1f} s")

    # Audit blockers: every blocker of each census-item object's closed-effect audit, by what it
    # points at, and a counterfactual compositional census (closed when every other object it
    # calls or imports is closed).  Counting only; nothing here is a verdict.
    started = time.perf_counter()
    census_files = context["files"]
    owners_of: dict[str, set[str]] = collections.defaultdict(set)
    for identifier, paths in owned.items():
        for path in paths:
            owners_of[path].add(identifier)
    stdlib = set(sys.stdlib_module_names)
    module_cache: dict[str, str | None] = {}

    def module_path(dotted: str) -> str | None:
        """Census path of the longest importable prefix of a dotted verifier name, if any."""
        if dotted not in module_cache:
            found = None
            parts = dotted.split(".")
            for size in range(len(parts), 0, -1):
                base = "src/" + "/".join(parts[:size])
                for candidate in (base + ".py", base + "/__init__.py"):
                    if candidate in census_files:
                        found = candidate
                        break
                if found:
                    break
            module_cache[dotted] = found
        return module_cache[dotted]

    blocker_counts: collections.Counter = collections.Counter()
    blocker_objects: collections.Counter = collections.Counter()
    callees: dict[str, set[str]] = {}
    only_cross: dict[str, bool] = {}
    write_objects = 0
    for identifier in sorted(census_objects["effect_first"]):
        code_files = {path: census_files[path] for path in owned[identifier]
                      if path in census_files and not refutation.is_data_path(path)}
        outcome = classification._audit_code_census(context, root, code_files) if code_files else "NO_CODE_FILES"
        categories: set[str] = set()
        targets: set[str] = set()
        if isinstance(outcome, str):
            categories.add("audit could not run")
        else:
            for blocker in outcome.blockers:
                prefix = blocker.split(":", 1)[0]
                category = prefix
                if prefix == "CALL_TARGET_UNRESOLVED":
                    target = blocker.split(":", 4)[-1]
                    if target == "<dynamic-call-target>":
                        category = "call: dynamic target"
                    elif target.split(".")[0] in stdlib:
                        category = "call: standard library"
                    elif target.startswith("verifier.") and module_path(target):
                        category = "call: another Verifier object"
                        targets.add(module_path(target) or "")
                    elif target.startswith("verifier."):
                        category = "call: Verifier name without a census file"
                    else:
                        category = "call: method or local value"
                elif prefix == "IMPORT_ESCAPES_OWNERSHIP":
                    resolved = blocker.split(":", 3)[-1]
                    category = "import: another Verifier object"
                    targets.add(resolved)
                blocker_counts[category] += 1
                categories.add(category)
            if outcome.status != "CLOSED" and not outcome.blockers:
                categories.add("status " + str(outcome.status))
            if any(row.channel in classification._EXTERNAL_WRITE_CHANNELS for row in outcome.consequences):
                categories.add("external write consequence")
                write_objects += 1
        blocker_objects.update(categories)
        cross = {"call: another Verifier object", "import: another Verifier object"}
        only_cross[identifier] = bool(categories) and categories <= cross and all(owners_of.get(t) for t in targets)
        callees[identifier] = {owner for t in targets for owner in owners_of.get(t, ())} - {identifier}

    clean_objects = set(objects) - census_objects["effect_first"]
    candidates = {o for o in census_objects["effect_first"]
                  if only_cross[o] and not gate_real[o] and objects[o]["main"] != "EMPTY_CENSUS"}
    greatest = clean_objects | candidates  # remove any candidate that calls outside the set, to a fixpoint
    changed = True
    while changed:
        changed = False
        for o in sorted(greatest & candidates):
            if not callees[o] <= greatest:
                greatest.discard(o)
                changed = True
    least = set(clean_objects)  # add candidates whose callees are already closed, to a fixpoint
    changed = True
    while changed:
        changed = False
        for o in sorted(candidates - least):
            if callees[o] <= least:
                least.add(o)
                changed = True
    blocked_by_text_only = {o for o in census_objects["effect_first"]
                            if only_cross[o] and gate_real[o] and objects[o]["main"] != "EMPTY_CENSUS"}
    audit_blockers = {
        "note": ("Every blocker of the closed-effect audit of each census-item object, grouped by what it "
                 "points at. 'compositional' is a counterfactual: an object counts as closed when its only "
                 "audit blockers are calls or imports into other objects that are themselves closed and its "
                 "text gates have no real hit (strict rule). Not a verdict."),
        "blockers_by_category": dict(blocker_counts.most_common()),
        "objects_with_category": dict(blocker_objects.most_common()),
        "objects_with_external_write_consequence": write_objects,
        "objects_only_cross_object_blockers": sum(only_cross.values()),
        "of_which_also_a_real_text_gate_hit": len(blocked_by_text_only),
        "compositional_candidates": len(candidates),
        "compositional_closed_greatest_fixpoint": len(greatest & candidates),
        "compositional_closed_least_fixpoint": len(least & candidates),
        "held_cells_released_greatest": sum(held_cells.get(o, 0) for o in greatest & candidates),
        "held_cells_released_least": sum(held_cells.get(o, 0) for o in least & candidates),
    }
    say(f"audit blockers {time.perf_counter() - started:.1f} s")

    held = census_objects["effect_first"]
    held_reason = collections.Counter(objects[identifier]["main"] or "UNEXPECTED_CODE_ONLY" for identifier in held)
    held_by_primary = collections.Counter(objects[identifier]["primary"] for identifier in held)
    report = {
        "coordinate": {"objects_vstd_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
                       "objects_vstd_bytes_on_disk": len(manifest_bytes), "mechanism_digest": mechanism,
                       "python": sys.version.split()[0], "finished": time.strftime("%Y-%m-%d %H:%M:%S")},
        "current": current,
        "objects": {"total": len(objects), "census_item_objects": len(held),
                    "census_item_by_main_reason": dict(held_reason.most_common()),
                    "census_item_by_primary_kind": dict(held_by_primary.most_common()),
                    "objects_with_any_object_wide_code": sum(objects[i]["main"] is not None for i in objects),
                    "mixed_documented_and_object_wide": sum(item["mixed"] for item in objects.values()),
                    "unexpected_codes": dict(collections.Counter(
                        code for item in objects.values() for code in item["unexpected"]).most_common()),
                    "verifier_primary": sum(item["primary"] == "VERIFIER" for item in objects.values()),
                    "verifier_role_on_other_primary": sum(item["verifier_role"] and item["primary"] != "VERIFIER"
                                                          for item in objects.values())},
        "status": "PASS" if stale is not None else "UNKNOWN",
        "claim_boundary": (
            "This is a read-only measured projection, not a package-polish verdict. UNKNOWN stale-label "
            "state leaves every stale-withdrawal variant UNKNOWN and never refreshes pinned evidence."
        ),
        "stale_labels": (
            {"status": "PASS", "count": len(stale),
             "objects": len({object_id for object_id, _ in stale}), "source": stale_source}
            if stale is not None else
            {"status": "UNKNOWN", "count": None, "objects": None,
             "source": stale_source, "reason": stale_error}
        ),
        "projections": projections,
        "gate_precision": gate_precision,
        "audit_blockers": audit_blockers,
        "candidates_by_primary_kind": dict(candidate_by_primary.most_common()),
        "candidates_by_first_trigger": dict(first_trigger.most_common()),
        "candidates_with_a_single_trigger": dict(only_trigger.most_common()),
        "candidates_carrying_each_trigger": dict(any_trigger.most_common()),
        "candidates_on_census_item_objects": candidates_on_census_objects,
        "clean_object_cell_states_by_kind": {kind: dict(states.most_common())
                                             for kind, states in sorted(clean_states.items())},
        "verifier_objects_by_hint_only_kind_count": dict(sorted(hint_only_per_verifier.items())),
        "verifier_hint_only_kinds": dict(hint_only_kinds.most_common()),
        "bytes": {"expanded_document": expanded_total, "namespace_expanded": namespace_total,
                  "classification_rows": classification_bytes, "census_record_each": census_record_bytes,
                  "cap_32_mib": 32 * 1024 * 1024},
    }
    def keyed(value):  # JSON keys must be strings; never let a None key lose a finished run again
        if isinstance(value, dict):
            return {str(key): keyed(item) for key, item in value.items()}
        if isinstance(value, (list, tuple)):
            return [keyed(item) for item in value]
        return value
    out.write_text(json.dumps(keyed(report), indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    say(f"wrote {out}")
    if objects_out is not None:
        detailed_objects = {}
        for identifier, item in sorted(objects.items()):
            cells = {
                kind: {
                    **cell,
                    "selected": selected(cell, item["primary"], False, False),
                }
                for kind, cell in sorted(item["cells"].items())
            }
            detailed_objects[identifier] = {
                "primary": item["primary"],
                "census_item": identifier in held,
                "held": held_cells.get(identifier, 0),
                "codes": dict(item["codes"]),
                "main": item["main"],
                "main_detail": item["main_detail"],
                "owned": sorted(owned[identifier]),
                "cells": cells,
                "verifier_role": item["verifier_role"],
            }
        objects_dump = {
            "coordinate": {
                **report["coordinate"],
                "stale_source": stale_source,
                "stale_status": "PASS" if stale is not None else "UNKNOWN",
            },
            "files": context["files"],
            "objects": detailed_objects,
            "obligation_row_keys": (
                sorted(classified["required_obligations"][0])
                if classified["required_obligations"] else []
            ),
            "open_obligations": [
                {
                    "object_id": row["object_id"],
                    "kind": row["kind"],
                    "obligation": row["id"],
                    "status": row["status"],
                }
                for row in open_obligations
            ],
        }
        objects_out.write_text(
            json.dumps(keyed(objects_dump), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
            newline="\n",
        )
        say(f"wrote {objects_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
