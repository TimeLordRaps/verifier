"""Pull Request Domain Explanation Language (PRDEL) shard falsification controls."""
from __future__ import annotations
import copy
import json
from pathlib import Path
import subprocess

import pytest
from verifier.runtime import prdel, prdel_rules, prdel_shards


def compilation() -> dict:
    binding={"base":"a"*40,"head":"b"*40,"source_digest":"c"*64,"requirements_digest":"d"*64}
    rows=[{"id":"source:"+str(index).zfill(2),"kind":"source","path":"path-"+str(index),"question":"Retain exact source.","old_text":"a"*900,"new_text":"b"*900} for index in range(20)]
    records=[{"id":row["id"],"requirement_ids":[],"why":{"requirement_id":None,"quote":""},"claims":[],"summary":"s"*1800,"limits":[],"coverage":{}} for row in rows]
    document={"schema_version":prdel.SCHEMA,"binding":binding,"requirements":prdel.DEFAULT_REQUIREMENTS,"source_obligations":rows,"records":records,"evidence":[],"impact_graph":{"frontier":[{"path":"contract.json","status":"UNKNOWN"}],"bounds":{"max_operations":200000}}}
    residuals=[prdel_rules._residual("UNRESOLVED_ANALYSIS_FRONTIER","UNKNOWN","Needs schema evidence.",obligation_id="frontier:held"),prdel_rules._residual("AUTHOR_MOTIVATION_UNRESOLVED","UNKNOWN","Optional author input.",required=False)]
    work=prdel_rules._Work()
    return prdel_rules._envelope(document,None,[],residuals,work)


def packet(monkeypatch) -> dict:
    monkeypatch.setattr(prdel_rules,"MAX_COMPILED_BYTES",12000)
    return prdel_shards.partition_compilation(compilation())


def bytes_of(value: dict) -> tuple[bytes,list[bytes]]:
    return prdel.canonical(value["manifest"]),[prdel.canonical(shard) for shard in value["shards"]]


def interleaved_compilation() -> dict:
    value = compilation()
    document = value["document"]
    row = {
        "id": "frontier:a",
        "kind": "frontier",
        "path": "unknown.py",
        "question": "Retain the unresolved frontier in compiled order.",
    }
    record = {
        "id": row["id"],
        "requirement_ids": [],
        "why": {"requirement_id": None, "quote": ""},
        "claims": [],
        "summary": "Frontier remains unresolved.",
        "limits": [],
        "coverage": {},
    }
    document["source_obligations"].insert(1, row)
    document["records"].insert(1, record)
    return value


def test_interleaved_pairs_preserve_exact_compiled_vector(monkeypatch):
    monkeypatch.setattr(prdel_rules, "MAX_COMPILED_BYTES", 12000)
    original = interleaved_compilation()
    packet = prdel_shards.partition_compilation(original)
    expected = [row["id"] for row in original["document"]["source_obligations"]]
    observed_rows = [row["id"] for shard in packet["shards"]
        for row in shard["source_obligations"]]
    observed_records = [row["id"] for shard in packet["shards"]
        for row in shard["records"]]
    assert packet["manifest"]["schema_version"] == prdel_shards.MANIFEST_VERSION
    assert packet["manifest"]["obligation_ids"] == expected
    assert observed_rows == observed_records == expected


def test_interleaved_round_trip_preserves_canonical_document_and_render(monkeypatch):
    monkeypatch.setattr(prdel_rules, "MAX_COMPILED_BYTES", 12000)
    original = interleaved_compilation()
    packet = prdel_shards.partition_compilation(original)
    manifest, shards = bytes_of(packet)
    retained = prdel_shards.reconstruct_compilation(manifest, shards)
    expected_document = original["document"]
    assert prdel.canonical(retained["document"]) == prdel.canonical(expected_document)
    assert prdel.render_prdel(retained["document"]) == prdel.render_prdel(expected_document)
    assert prdel.digest(prdel.render_prdel(retained["document"]).encode()) == prdel.digest(
        prdel.render_prdel(expected_document).encode()
    )


def test_partition_refuses_equal_pair_sets_in_different_order(monkeypatch):
    monkeypatch.setattr(prdel_rules, "MAX_COMPILED_BYTES", 12000)
    original = interleaved_compilation()
    original["document"]["records"][0], original["document"]["records"][1] = (
        original["document"]["records"][1], original["document"]["records"][0]
    )
    with pytest.raises(prdel.PrdelError, match="same exact order"):
        prdel_shards.partition_compilation(original)


def test_independent_replay_refuses_self_consistent_order_permutation(monkeypatch):
    monkeypatch.setattr(prdel_rules, "MAX_COMPILED_BYTES", 12000)
    expected = prdel_shards.partition_compilation(interleaved_compilation())
    changed = copy.deepcopy(expected)
    changed["shards"][0]["source_obligations"].reverse()
    changed["shards"][0]["records"].reverse()
    raw = prdel.canonical(changed["shards"][0])
    changed["manifest"]["shards"][0].update(
        sha256=prdel.digest(raw), bytes=len(raw),
        obligation_ids=[row["id"] for row in changed["shards"][0]["source_obligations"]],
    )
    changed["manifest"]["obligation_ids"] = [
        row["id"] for shard in changed["shards"] for row in shard["source_obligations"]
    ]
    monkeypatch.setattr(
        prdel_rules,
        "_compile_prdel",
        lambda *_args, **_kwargs: interleaved_compilation(),
    )
    manifest, shards = bytes_of(changed)
    report = prdel_shards.validate_prdel_shards(
        manifest, shards, Path("."), "a" * 40, "b" * 40
    )
    assert report["status"] == "FAIL"
    assert "exact independently selected replay" in report["reason"]


def test_legacy_sorted_manifest_is_not_silently_read_as_version_two(monkeypatch):
    monkeypatch.setattr(prdel_rules, "MAX_COMPILED_BYTES", 12000)
    packet = prdel_shards.partition_compilation(interleaved_compilation())
    packet["manifest"]["schema_version"] = prdel_shards.LEGACY_MANIFEST_VERSION
    manifest, shards = bytes_of(packet)
    with pytest.raises(prdel.PrdelError):
        prdel_shards.reconstruct_compilation(manifest, shards)


def test_legacy_manifest_reader_preserves_historical_sorted_wire(monkeypatch):
    monkeypatch.setattr(prdel_rules, "MAX_COMPILED_BYTES", 12000)
    packet = prdel_shards._partition_compilation(
        interleaved_compilation(), prdel_shards.LEGACY_MANIFEST_VERSION
    )
    manifest, shards = bytes_of(packet)
    retained = prdel_shards.reconstruct_compilation(manifest, shards)
    identifiers = [
        row["id"] for row in retained["document"]["source_obligations"]
    ]
    assert packet["manifest"]["schema_version"] == prdel_shards.LEGACY_MANIFEST_VERSION
    assert identifiers == sorted(set(identifiers))


def test_unknown_manifest_version_is_refused(monkeypatch):
    monkeypatch.setattr(prdel_rules, "MAX_COMPILED_BYTES", 12000)
    with pytest.raises(prdel.PrdelError, match="Unsupported compilation manifest"):
        prdel_shards._partition_compilation(interleaved_compilation(), "manifest-3")


def test_partition_is_deterministic_complete_bounded_and_keeps_unknowns(monkeypatch):
    value=packet(monkeypatch)
    original=compilation()
    manifest,shards=bytes_of(value)
    assert len(shards)>1 and all(len(raw)<=12000 for raw in [manifest,*shards])
    assert value==prdel_shards.partition_compilation(original)
    retained=prdel_shards.reconstruct_compilation(manifest,shards)
    assert retained==original
    assert retained["status"]=="UNKNOWN" and retained["gate_status"]=="NOT_ASSESSED"
    assert retained["residuals"]==original["residuals"]
    assert len(value["manifest"]["selected_source_ids"])==20
    assert retained["document"]["impact_graph"]["frontier"][0]["path"]=="contract.json"


@pytest.mark.parametrize("mutation",["omitted_shard","duplicate_shard","order","bytes","binding","omitted_row","duplicate_row","manifest_scope","canonical"])
def test_retention_refutes_omission_duplication_and_substitution(monkeypatch,mutation):
    value=packet(monkeypatch)
    if mutation=="omitted_shard":value["shards"].pop()
    elif mutation=="duplicate_shard":value["shards"].append(copy.deepcopy(value["shards"][0]))
    elif mutation=="order":value["shards"].reverse()
    elif mutation=="binding":value["shards"][0]["binding"]["head"]="e"*40
    elif mutation in ("omitted_row","duplicate_row"):
        shard=value["shards"][0]
        if mutation=="omitted_row":
            shard["source_obligations"].pop();shard["records"].pop()
        else:
            shard["source_obligations"].append(copy.deepcopy(shard["source_obligations"][0]));shard["records"].append(copy.deepcopy(shard["records"][0]))
        raw=prdel.canonical(shard);entry=value["manifest"]["shards"][0]
        entry.update(sha256=prdel.digest(raw),bytes=len(raw),obligation_ids=[row["id"] for row in shard["source_obligations"]])
    elif mutation=="manifest_scope":value["manifest"]["selected_source_ids"].pop()
    manifest,shards=bytes_of(value)
    if mutation=="bytes":shards[0]+=b" "
    if mutation=="canonical":manifest=json.dumps(value["manifest"],indent=2).encode()
    with pytest.raises(prdel.PrdelError):prdel_shards.reconstruct_compilation(manifest,shards)


@pytest.mark.parametrize("bound",["single_row","manifest","operations"])
def test_exhaustion_returns_no_trimmed_packet(monkeypatch,bound):
    original=compilation()
    if bound=="operations":original["counters"]["operations"]=prdel_rules.MAX_RULE_OPERATIONS
    else:
        monkeypatch.setattr(prdel_rules,"MAX_COMPILED_BYTES",3000 if bound=="single_row" else 12000)
        if bound=="manifest":original["document"]["impact_graph"]["frontier"][0]["reason"]="x"*12000
    with pytest.raises(prdel.PrdelUnavailable):prdel_shards.partition_compilation(original)


def test_selected_git_replay_refutes_forged_intact_inventory(tmp_path):
    def git(*args):
        return subprocess.check_output(["git","-C",str(tmp_path),*args],timeout=20).decode().strip()
    git("init","--quiet");git("config","user.name","Fixture");git("config","user.email","fixture"+"@"+"example.invalid");git("config","commit.gpgsign","false")
    path=tmp_path/"README.md";path.write_text("Before.\n")
    git("add",".");git("commit","--quiet","-m","Before");base=git("rev-parse","HEAD")
    path.write_text("After.\n");git("add",".");git("commit","--quiet","-m","After");head=git("rev-parse","HEAD")
    value=prdel_shards.compile_prdel_shards(tmp_path,base,head)
    manifest,shards=bytes_of(value)
    assert prdel_shards.validate_prdel_shards(manifest,shards,tmp_path,base,head)["status"]=="PASS"
    value["manifest"]["compilation_header"]["counters"]["operations"]+=1
    manifest,shards=bytes_of(value)
    assert prdel_shards.validate_prdel_shards(manifest,shards,tmp_path,base,head)["status"]=="FAIL"


def test_known_compilation_failure_cannot_be_downgraded_to_unavailable():
    original=compilation()
    original["document"]=None
    original["status"]="FAIL"
    with pytest.raises(prdel.PrdelError) as caught:
        prdel_shards.partition_compilation(original)
    assert type(caught.value) is prdel.PrdelError
    assert "Known compilation failure" in str(caught.value)



def _logical_fixture(tmp_path, *, executable=False):
    """Retain only invented small source objects in this test's temporary repository."""
    def git(*args):
        return subprocess.check_output(["git", "-C", str(tmp_path), *args], timeout=20).decode().strip()
    git("init", "--quiet")
    git("config", "user.name", "Fixture")
    git("config", "user.email", "fixture" + "@" + "example.invalid")
    git("config", "commit.gpgsign", "false")
    for index in range(6):
        (tmp_path / ("note-" + str(index) + ".md")).write_text("Before " + str(index) + ".\n", encoding="utf-8")
    if executable:
        (tmp_path / "function.py").write_text("def value():\n    return 1\n", encoding="utf-8")
        (tmp_path / "settings.json").write_text('{"setting":1}\n', encoding="utf-8")
    git("add", ".")
    git("commit", "--quiet", "-m", "Before")
    base = git("rev-parse", "HEAD")
    for index in range(6):
        (tmp_path / ("note-" + str(index) + ".md")).write_text("After " + str(index) + ".\n", encoding="utf-8")
    if executable:
        (tmp_path / "function.py").write_text("def value():\n    return 2\n", encoding="utf-8")
        (tmp_path / "settings.json").write_text('{"setting":2}\n', encoding="utf-8")
    git("add", ".")
    git("commit", "--quiet", "-m", "After")
    head = git("rev-parse", "HEAD")
    compiled = prdel_rules.compile_prdel(tmp_path, base, head)
    packet = prdel_shards.partition_compilation(compiled)
    manifest, shards = bytes_of(packet)
    carried = prdel_shards.reconstruct_compilation(manifest, shards)["document"]
    return base, head, compiled["document"], carried


def test_sharded_logical_component_preserves_ordinary_compiled_order(tmp_path):
    base, head, ordinary, carried = _logical_fixture(tmp_path)
    assert ordinary["source_obligations"] == carried["source_obligations"]
    assert ordinary["records"] == carried["records"]
    legacy = prdel.validate_prdel(carried, tmp_path, base, head)
    ordinary_report = prdel.validate_prdel(ordinary, tmp_path, base, head)
    assert legacy["status"] == ordinary_report["status"] == "PASS"
    selected = prdel._validate_sharded_prdel(carried, tmp_path, base, head)
    assert selected["status"] == "PASS"
    assert selected["findings"] == ordinary_report["findings"]
    assert selected["binding"] == ordinary["binding"]
    assert selected["execution_provenance"] == "NOT_ESTABLISHED"


def test_sharded_logical_component_checks_bounded_parts_without_v1_whole_document_decoder(tmp_path, monkeypatch):
    base, head, ordinary, carried = _logical_fixture(tmp_path)
    sequences = {"source_obligations", "records", "evidence"}
    parts = [{key: value for key, value in carried.items() if key not in sequences}]
    parts.extend(item for key in sequences for item in carried[key])
    limit = max(len(prdel.canonical(part)) for part in parts) + 16
    assert limit < len(prdel.canonical(carried))
    monkeypatch.setattr(prdel, "MAX_DOCUMENT_BYTES", limit)
    assert prdel.validate_prdel(ordinary, tmp_path, base, head)["status"] == "FAIL"
    assert prdel._validate_sharded_prdel(carried, tmp_path, base, head)["status"] == "PASS"


def test_sharded_logical_component_preserves_every_existing_failure_and_unknown(tmp_path):
    base, head, ordinary, carried = _logical_fixture(tmp_path, executable=True)
    expected = prdel.validate_prdel(ordinary, tmp_path, base, head)
    observed = prdel._validate_sharded_prdel(carried, tmp_path, base, head)
    assert expected["status"] == observed["status"] == "FAIL"
    def findings(report):
        return sorted((row["code"], row["status"], row.get("obligation_id") or "", row.get("layer") or "") for row in report["findings"])
    assert findings(observed) == findings(expected)
    assert observed["required_checks_not_run"] == expected["required_checks_not_run"] > 0
    assert any(row["status"] == "UNKNOWN" for row in observed["findings"])
    assert observed["coverage"]["execution_authentication"] == "NOT_ESTABLISHED"


@pytest.mark.parametrize("fault", ["source", "missing", "binding", "nonfinite", "aggregate-bound"])
def test_sharded_logical_component_refuses_substitution_and_exhaustion(tmp_path, monkeypatch, fault):
    base, head, _, carried = _logical_fixture(tmp_path)
    if fault == "source":
        carried["source_obligations"][0]["after_text"] += " forged"
    elif fault == "missing":
        carried["source_obligations"].pop()
        carried["records"].pop()
    elif fault == "binding":
        carried["binding"]["head"] = "e" * 40
    elif fault == "nonfinite":
        carried["records"][0]["summary"] = float("nan")
    else:
        monkeypatch.setattr(prdel, "MAX_DESCRIPTION_BYTES", 32)
    result = prdel._validate_sharded_prdel(carried, tmp_path, base, head)
    assert result["status"] == ("UNKNOWN" if fault == "aggregate-bound" else "FAIL")
    assert result["status"] != "PASS"


def _gate_selected_packet(tmp_path, *, executable=False):
    base, head, _, _ = _logical_fixture(tmp_path, executable=executable)
    packet = prdel_shards.compile_prdel_shards(tmp_path, base, head)
    manifest, shards = bytes_of(packet)
    binding = packet['manifest']['document_header']['binding']
    residuals = packet['manifest']['compilation_header']['residuals']
    selection = dict(packet_budget_bytes=prdel.MAX_SNAPSHOT_BYTES, expected_manifest_digest=prdel.digest(manifest),
        expected_shard_digests=[prdel.digest(raw) for raw in shards],
        expected_source_digest=binding['source_digest'], requirements_digest=binding['requirements_digest'],
        expected_required_residuals=[{key: row[key] for key in ('code','status','obligation_id','requirement_id')} | {'index': i}
            for i, row in enumerate(residuals) if row['required']])
    return manifest, shards, base, head, selection


def _gate_render(tmp_path, *, executable=False):
    manifest, shards, base, head, selection = _gate_selected_packet(tmp_path, executable=executable)
    result = prdel_shards.render_prdel_shard_description(manifest, shards, tmp_path, base, head, **selection)
    return result, manifest, shards, base, head, selection


def test_selected_small_packet_has_bounded_positive_and_v1_does_not_adopt_it(tmp_path):
    rendered, manifest, shards, base, head, selection = _gate_render(tmp_path)
    report = rendered['report']
    assert report['status'] == 'PASS'
    assert report['compilation_replay']['status'] == 'PASS'
    assert report['logical_report']['status'] == 'PASS'
    assert 'Gate status: NOT_ASSESSED' in rendered['body']
    assert 'Native gate status: PASS' in rendered['body']
    checked = prdel_shards.evaluate_prdel_shard_description(rendered['body'], manifest, shards, tmp_path, base, head, **selection)
    assert checked['status'] == 'PASS'
    assert checked['execution_provenance'] == 'NOT_ESTABLISHED'
    assert prdel.evaluate_description(rendered['body'], tmp_path, base, head)['status'] == 'FAIL'


def test_human_body_and_report_retain_all_native_fail_unknown_and_not_run(tmp_path):
    rendered, manifest, shards, base, head, selection = _gate_render(tmp_path, executable=True)
    report = rendered['report']
    assert report['status'] == 'FAIL'
    native = report['logical_report']['findings']
    assert any(row['status'] == 'FAIL' for row in native)
    assert any(row['status'] == 'UNKNOWN' for row in native)
    assert report['logical_report']['required_checks_not_run'] > 0
    assert report['required_native_findings'] == native
    for index, row in enumerate(native):
        assert f'- Native finding {index}: ' + prdel.canonical(row).decode('utf-8') in rendered['body']
    assert prdel_shards.evaluate_prdel_shard_description(rendered['body'], manifest, shards, tmp_path, base, head, **selection)['status'] == 'FAIL'


@pytest.mark.parametrize('mutation', ['omit-findings', 'extra-assurance', 'wrong-manifest', 'wrong-source'])
def test_gate_refuses_substituted_body_and_external_selection(tmp_path, mutation):
    rendered, manifest, shards, base, head, selection = _gate_render(tmp_path)
    body = rendered['body']
    if mutation == 'omit-findings':
        body = body.split('## Required native gate findings')[0]
    elif mutation == 'extra-assurance':
        body += 'Everything is safe.\n'
    elif mutation == 'wrong-manifest':
        selection['expected_manifest_digest'] = 'f' * 64
    else:
        selection['expected_source_digest'] = 'f' * 64
    assert prdel_shards.evaluate_prdel_shard_description(body, manifest, shards, tmp_path, base, head, **selection)['status'] == 'FAIL'


def test_intact_but_forged_compilation_is_refuted_even_with_updated_packet_hash(tmp_path):
    manifest, shards, base, head, selection = _gate_selected_packet(tmp_path)
    value = prdel.decode(manifest)
    value['compilation_header']['counters']['operations'] += 1
    manifest = prdel.canonical(value)
    selection['expected_manifest_digest'] = prdel.digest(manifest)
    rendered = prdel_shards.render_prdel_shard_description(manifest, shards, tmp_path, base, head, **selection)
    assert rendered['report']['status'] == 'FAIL'
    assert rendered['report']['logical_report']['status'] == 'PASS'
    assert rendered['report']['compilation_replay']['status'] == 'FAIL'


def test_source_unavailability_cannot_erase_carried_required_failure(tmp_path, monkeypatch):
    manifest, shards, base, head, selection = _gate_selected_packet(tmp_path, executable=True)
    value = prdel.decode(manifest)
    residuals = value['compilation_header']['residuals']
    residuals.append(dict(required=True, code='FIXTURE_REQUIRED_FAILURE', status='FAIL',
        obligation_id=None, requirement_id=None, reason='Invented retained negative control.',
        question='This fixture cannot establish clearance.'))
    value['compilation_header']['status'] = 'FAIL'
    manifest = prdel.canonical(value)
    selection['expected_manifest_digest'] = prdel.digest(manifest)
    selection['expected_required_residuals'].append(dict(index=len(residuals)-1,
        code='FIXTURE_REQUIRED_FAILURE', status='FAIL', obligation_id=None, requirement_id=None))
    def unavailable(*_args, **_kwargs):
        raise prdel.PrdelUnavailable('invented unavailable fixture observation')
    monkeypatch.setattr(prdel, '_snapshot', unavailable)
    rendered = prdel_shards.render_prdel_shard_description(manifest, shards, tmp_path, base, head, **selection)
    assert rendered['report']['compilation_replay']['status'] == 'UNKNOWN'
    assert rendered['report']['status'] == 'FAIL'
    assert any(row['status'] == 'FAIL' for row in rendered['report']['required_compilation_residuals'])
    for row in rendered['report']['required_compilation_residuals']:
        assert row['code'] in rendered['body']


def test_aggregate_admission_precedes_packet_hashing(tmp_path, monkeypatch):
    manifest, shards, base, head, selection = _gate_selected_packet(tmp_path)
    selection['packet_budget_bytes'] = len(manifest) + sum(map(len, shards)) - 1
    def forbidden(*_args, **_kwargs):
        raise AssertionError('aggregate packet was hashed before admission')
    monkeypatch.setattr(prdel, 'digest', forbidden)
    result = prdel_shards.render_prdel_shard_description(manifest, shards, tmp_path, base, head, **selection)
    assert result['body'] is None
    assert result['report']['status'] == 'UNKNOWN'


def test_unavailable_source_preserves_unknown_without_erasing_known_index_failure(tmp_path, monkeypatch):
    rendered, manifest, shards, base, head, selection = _gate_render(tmp_path)
    assert rendered['report']['status'] == 'PASS'
    def unavailable(*_args, **_kwargs):
        raise prdel.PrdelUnavailable('invented unavailable fixture observation')
    monkeypatch.setattr(prdel, '_snapshot', unavailable)
    checked = prdel_shards.evaluate_prdel_shard_description(rendered['body'], manifest, shards, tmp_path, base, head, **selection)
    assert checked['status'] == 'UNKNOWN'
    assert checked['compilation_replay']['status'] == 'UNKNOWN'
    wrong = rendered['body'].replace(selection['expected_source_digest'], 'f' * 64)
    assert prdel_shards.evaluate_prdel_shard_description(wrong, manifest, shards, tmp_path, base, head, **selection)['status'] == 'FAIL'


def test_new_admission_requires_an_explicit_supported_caller_packet_budget(tmp_path):
    manifest, shards, base, head, selection = _gate_selected_packet(tmp_path)
    selection.pop('packet_budget_bytes')
    report = prdel_shards.render_prdel_shard_description(manifest, shards, tmp_path, base, head, **selection)['report']
    assert report['status'] == 'FAIL'


def test_native_output_budget_unknown_cannot_erase_an_established_failure(tmp_path):
    from verifier.runtime.prdel_shard_index import IndexLimits
    rendered, manifest, shards, base, head, selection = _gate_render(tmp_path, executable=True)
    assert rendered['report']['status'] == 'FAIL'
    index = rendered['body'].split('\n## Required native gate findings\n')[0].rstrip() + '\n'
    limits = IndexLimits(max_description_bytes=len(index.encode('utf-8')) + 16)
    refused = prdel_shards.render_prdel_shard_description(manifest, shards, tmp_path, base, head, limits=limits, **selection)
    assert refused['body'] is None
    assert refused['report']['status'] == 'FAIL'
    assert refused['report']['required_native_findings'] == rendered['report']['required_native_findings']


@pytest.mark.parametrize('budget', [None, True, 0, -1, 1.5, '64', prdel.MAX_SNAPSHOT_BYTES + 1])
def test_missing_or_invalid_selected_packet_budget_fails_closed(tmp_path, budget):
    manifest, shards, base, head, selection = _gate_selected_packet(tmp_path)
    selection['packet_budget_bytes'] = budget
    result = prdel_shards.render_prdel_shard_description(manifest, shards, tmp_path, base, head, **selection)
    assert result['body'] is None and result['report']['status'] == 'FAIL'
