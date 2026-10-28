from pathlib import Path
import pytest
from verifier.runtime.gate import run_paths_gate

@pytest.mark.parametrize("name", ["client.js", "view.jsx", "client.ts", "view.tsx", "paper.tex", "Dockerfile", "Makefile", "tool.ps1", "data.json5", "LICENSE"])
def test_supported_source_and_publication_text_cannot_hide_in_mixed_tree(tmp_path, name):
    (tmp_path / "clean.md").write_text("docs/guide.md", encoding="utf-8")
    (tmp_path / name).write_text("E:" + "/synthetic-private-checkout/internal.txt", encoding="utf-8")
    count, findings = run_paths_gate(tmp_path)
    assert any(item.get("label") == "Windows drive path" for item in findings), (count, findings)

def test_positive_portable_text_remains_accepted(tmp_path):
    (tmp_path / "guide.md").write_text("docs/guide.md", encoding="utf-8")
    count, findings = run_paths_gate(tmp_path)
    assert count == 1 and findings == []

def test_existing_plain_path_detection_is_active(tmp_path):
    (tmp_path / "guide.md").write_text("E:" + "/synthetic-private-checkout/internal.txt", encoding="utf-8")
    count, findings = run_paths_gate(tmp_path)
    assert count == 1 and any(item.get("label") == "Windows drive path" for item in findings)
