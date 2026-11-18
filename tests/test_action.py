"""Static checks for the composite GitHub Action."""

import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    return yaml.safe_load((ROOT / path).read_text(encoding="utf-8"))


def test_action_inputs_and_outputs():
    a = load("action.yml")
    assert a["runs"]["using"] == "composite"
    for name in ("config", "threshold", "baseline", "quick"):
        assert name in a["inputs"], name
    assert {"exit-code", "success-rate", "report-dir"} <= set(a["outputs"])


def test_action_steps_cover_requirements():
    steps = load("action.yml")["runs"]["steps"]
    uses = [s.get("uses", "") for s in steps]
    assert any(u.startswith("actions/setup-python@") for u in uses)
    assert any(u.startswith("actions/upload-artifact@") for u in uses)
    assert any(u.startswith("github/codeql-action/upload-sarif@") for u in uses)
    assert any(u.startswith("actions/github-script@") for u in uses)
    comment = next(s for s in steps if s.get("uses", "").startswith("actions/github-script@"))
    assert "<!-- injectprobe-report -->" in comment["with"]["script"]
    assert "updateComment" in comment["with"]["script"]


def test_no_expression_injection_in_scripts():
    """User-controlled values must reach shell/JS scripts through env vars, never ${{ }} inside the script."""
    for s in load("action.yml")["runs"]["steps"]:
        script = s.get("run", "") + (s.get("with", {}) or {}).get("script", "")
        assert not re.search(r"\$\{\{\s*(inputs|github\.event)", script), s.get("name")


def test_markdown_marker_matches_report():
    from injectprobe.reports.markdown import MARKER

    assert MARKER in (ROOT / "action.yml").read_text(encoding="utf-8")


def test_workflows_parse():
    for p in ("examples/workflows/injectprobe.yml", ".github/workflows/ci.yml"):
        wf = load(p)
        assert "jobs" in wf
