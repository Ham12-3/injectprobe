import asyncio
import json
import xml.etree.ElementTree as ET

import pytest
from rich.console import Console

from injectprobe.baseline import (
    BaselineError,
    compare,
    diff,
    load_rates,
    load_result,
    rates_from_result,
    save_baseline,
)
from injectprobe.config import parse_config
from injectprobe.loader import expand_cases, filter_attacks, load_attacks
from injectprobe.models import RunResult
from injectprobe.reports import FILE_FORMATS, render, write_reports
from injectprobe.reports import junit, markdown, sarif
from injectprobe.reports.terminal import diff_markdown, print_diff, print_report
from injectprobe.runner import run_probe

IDS = ["io-001*", "ex-001*", "io-008*", "spe-001*", "ind-email-001*", "db-001*"]


def _run(behavior="vulnerable", ids=IDS, **extra) -> RunResult:
    cfg = parse_config({
        "target": {"type": "mock", "behavior": behavior},
        "run": {"trials": 2, "rate_limit": None},
        "canary": {"grace_seconds": 0},
        **extra,
    })
    cases = expand_cases(filter_attacks(load_attacks(), ids=ids))
    return asyncio.run(run_probe(cfg, cases, config_path="injectprobe.yaml"))


@pytest.fixture(scope="module")
def vuln() -> RunResult:
    return _run()


@pytest.fixture(scope="module")
def safe() -> RunResult:
    return _run("safe")


def test_json_roundtrip(vuln, tmp_path):
    text = render(vuln, "json")
    data = json.loads(text)
    assert data["results"][0]["success_rate"] == 1.0
    assert data["summary"]["by_category"]
    p = tmp_path / "r.json"
    p.write_text(text)
    again = load_result(p)
    assert again.summary.successful_attempts == vuln.summary.successful_attempts
    assert again.results[0].attempts[0].canary == vuln.results[0].attempts[0].canary


def test_junit(vuln, safe):
    root = ET.fromstring(junit.render(vuln))
    assert root.tag == "testsuites"
    assert int(root.get("tests")) == len(IDS)
    assert int(root.get("failures")) == len(IDS)
    failure = root.find(".//testcase/failure")
    assert "succeeded in 2/2" in failure.get("message")
    assert "Payload" in failure.text
    sroot = ET.fromstring(junit.render(safe))
    assert sroot.get("failures") == "0"


def test_junit_skipped():
    cfg = parse_config({"target": {"type": "http", "url": "http://localhost:1"},
                        "run": {"trials": 1}})
    from injectprobe.runner import Runner
    from injectprobe.targets.base import Target

    class Dummy(Target):
        async def send(self, request):  # pragma: no cover - never called
            raise AssertionError

    cases = expand_cases(filter_attacks(load_attacks(), ids=["spe-001*"]))
    res = asyncio.run(Runner(cfg, Dummy(), cases).run())
    root = ET.fromstring(junit.render(res))
    assert root.find(".//skipped") is not None and root.get("skipped") == "1"


def test_sarif(vuln, safe):
    doc = json.loads(sarif.render(vuln))
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "injectprobe"
    assert len(run["results"]) == len(IDS)
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {r["ruleId"] for r in run["results"]} == rule_ids
    res = run["results"][0]
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "injectprobe.yaml"
    assert res["level"] in {"error", "warning", "note"}
    sev = {r["properties"]["security-severity"] for r in run["tool"]["driver"]["rules"]}
    assert sev <= {"9.5", "7.5", "5.0", "3.0"}
    assert json.loads(sarif.render(safe))["runs"][0]["results"] == []


def test_markdown(vuln, safe):
    md = markdown.render(vuln)
    assert md.startswith(markdown.MARKER)
    assert "❌ Failed" in md and "Top failing attacks" in md
    assert "| Category |" in md
    # untrusted replies are fenced so images do not render in the PR comment
    assert "~~~~text" in md
    assert "![status](" in md.split("~~~~text", 1)[1]
    assert "✅ Passed" in markdown.render(safe)


def test_markdown_baseline_section(vuln, safe):
    r = vuln.model_copy(deep=True)
    r.baseline_path = "baseline.json"
    r.regressions = compare(r, rates_from_result(safe))
    r.evaluate()
    md = markdown.render(r)
    assert "### Regressions" in md and "baseline" in md
    r2 = safe.model_copy(deep=True)
    r2.baseline_path = "baseline.json"
    r2.regressions = []
    r2.evaluate()
    assert "No regressions" in markdown.render(r2)


def test_markdown_size_limit(vuln):
    r = vuln.model_copy(deep=True)
    for x in r.results:
        x.description = "x" * 20000
    assert len(markdown.render(r, top=50)) <= markdown.MAX_CHARS


def test_terminal(vuln):
    console = Console(record=True, width=120)
    print_report(vuln, console)
    out = console.export_text()
    assert "injectprobe summary" in out and "FAILED" in out
    assert "Success rate by category" in out and "Top failing attacks" in out


def test_terminal_strips_escape_sequences(vuln):
    r = vuln.model_copy(deep=True)
    r.results[0].attempts[0].replies = ["evil \x1b[2J clear"]
    r.results[0].attempts[0].success = True
    console = Console(record=True, width=120)
    print_report(r, console)
    assert "\x1b[2J" not in console.export_text()


def test_write_reports(vuln, tmp_path):
    written = write_reports(vuln, tmp_path, list(FILE_FORMATS))
    assert {p.name for p in written.values()} == {"results.json", "junit.xml", "results.sarif", "summary.md"}
    with pytest.raises(ValueError):
        render(vuln, "pdf")


def test_baseline_save_load_compare(vuln, safe, tmp_path):
    p = save_baseline(safe, tmp_path / "b.json")
    rates = load_rates(p)
    assert set(rates) == {r.id for r in safe.results if r.status == "tested"}
    regs = compare(vuln, rates)
    assert regs and all(g.kind == "worse" for g in regs)
    assert regs[0].severity.value == "critical"  # sorted by severity
    assert compare(safe, rates) == []
    # tolerance hides small increases
    assert compare(vuln, rates, tolerance=1.0) == []


def test_baseline_new_attack_regression(vuln, tmp_path):
    regs = compare(vuln, {})
    assert regs and all(g.kind == "new" and g.baseline_rate is None for g in regs)


def test_load_rates_from_results_json(vuln, tmp_path):
    p = tmp_path / "results.json"
    p.write_text(render(vuln, "json"))
    assert load_rates(p)["io-001-ignore-previous"].rate == 1.0


def test_load_rates_errors(tmp_path):
    with pytest.raises(BaselineError):
        load_rates(tmp_path / "missing.json")
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    with pytest.raises(BaselineError):
        load_rates(bad)
    other = tmp_path / "other.json"
    other.write_text('{"hello": 1}')
    with pytest.raises(BaselineError):
        load_rates(other)


def test_diff(vuln, safe):
    rep = diff(rates_from_result(safe), vuln, old_rate=0.0)
    assert len(rep.regressions) == len(IDS) and not rep.improvements
    back = diff(rates_from_result(vuln), safe)
    assert len(back.improvements) == len(IDS) and not back.regressions
    console = Console(record=True, width=120)
    print_diff(rep, console)
    assert "Regressions" in console.export_text()
    assert "### Regressions" in diff_markdown(rep)
