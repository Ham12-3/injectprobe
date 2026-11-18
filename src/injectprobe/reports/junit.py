from __future__ import annotations

import xml.etree.ElementTree as ET
from collections import defaultdict

from ..models import AttackResult, RunResult
from ._util import clean, pct, sample_reply


def render(result: RunResult) -> str:
    """One testsuite per category, one testcase per attack. Any success is a failure."""
    by_cat: dict[str, list[AttackResult]] = defaultdict(list)
    for r in result.results:
        by_cat[r.category].append(r)

    root = ET.Element("testsuites", name="injectprobe")
    totals = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    for cat in sorted(by_cat):
        cases = by_cat[cat]
        counts = {
            "tests": len(cases),
            "failures": sum(1 for r in cases if r.successes > 0),
            "errors": sum(1 for r in cases if r.status == "error"),
            "skipped": sum(1 for r in cases if r.status in ("skipped", "not_run")),
        }
        for k, v in counts.items():
            totals[k] += v
        suite = ET.SubElement(root, "testsuite", name=f"injectprobe.{cat}", **{k: str(v) for k, v in counts.items()})
        for r in cases:
            secs = sum(a.latency_ms for a in r.attempts) / 1000
            tc = ET.SubElement(suite, "testcase", classname=f"injectprobe.{cat}", name=r.id, time=f"{secs:.3f}")
            if r.status in ("skipped", "not_run"):
                ET.SubElement(tc, "skipped", message=clean(r.skip_reason or "not run (budget reached)"))
            elif r.successes > 0:
                f = ET.SubElement(
                    tc,
                    "failure",
                    type=r.severity.value,
                    message=f"injection succeeded in {r.successes}/{r.completed} trials ({pct(r.success_rate)})",
                )
                f.text = clean(
                    f"{r.description}\n\nPayload:\n{r.payload_preview}\n\nReply:\n{sample_reply(r)}", 8000
                )
            elif r.status == "error":
                e = ET.SubElement(tc, "error", message="all trials failed")
                e.text = clean(sample_reply(r), 2000)
    for k, v in totals.items():
        root.set(k, str(v))
    ET.indent(root)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"
