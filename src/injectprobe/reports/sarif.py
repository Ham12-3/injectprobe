from __future__ import annotations

import json
from pathlib import Path

from .. import __version__
from ..models import RunResult, Severity
from ._util import clean, pct

SECURITY_SEVERITY = {Severity.critical: "9.5", Severity.high: "7.5", Severity.medium: "5.0", Severity.low: "3.0"}
LEVEL = {Severity.critical: "error", Severity.high: "error", Severity.medium: "warning", Severity.low: "note"}


def _artifact_uri(config_path: str | None) -> str:
    if not config_path:
        return "injectprobe.yaml"
    p = Path(config_path)
    if p.is_absolute():
        try:
            p = p.relative_to(Path.cwd())
        except ValueError:
            return p.name
    return p.as_posix()


def render(result: RunResult) -> str:
    """SARIF 2.1.0. One result per attack that succeeded at least once.

    Findings are anchored to the config file, since the vulnerability lives in
    the target's behaviour rather than a specific line of code.
    """
    uri = _artifact_uri(result.config_path)
    failing = result.failing()
    rules = []
    results = []
    for r in failing:
        rules.append(
            {
                "id": r.id,
                "name": r.attack_id.replace("-", "_"),
                "shortDescription": {"text": clean(f"Prompt injection: {r.description}", 200)},
                "fullDescription": {"text": clean(r.description, 1000)},
                "help": {"text": "The target followed an injected instruction. See the injectprobe report for the payload."},
                "defaultConfiguration": {"level": LEVEL[r.severity]},
                "properties": {
                    "tags": ["security", "prompt-injection", r.category, *r.tags],
                    "security-severity": SECURITY_SEVERITY[r.severity],
                    "precision": "high",
                },
            }
        )
        results.append(
            {
                "ruleId": r.id,
                "level": LEVEL[r.severity],
                "message": {
                    "text": clean(
                        f"Prompt injection '{r.id}' ({r.category}) succeeded in {r.successes}/{r.completed} "
                        f"trials ({pct(r.success_rate)}). {r.description}",
                        1000,
                    )
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": uri},
                            "region": {"startLine": 1},
                        }
                    }
                ],
                "partialFingerprints": {"injectprobe/v1": f"{r.id}:{result.target.type}"},
                "properties": {"successRate": round(r.success_rate, 4), "detectedBy": sorted(
                    {d for a in r.attempts for d in a.detected_by})},
            }
        )
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "injectprobe",
                        "version": __version__,
                        "informationUri": "https://github.com/injectprobe/injectprobe",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "successRate": round(result.summary.success_rate, 4),
                    "threshold": result.threshold,
                    "passed": result.passed,
                },
            }
        ],
    }
    return json.dumps(doc, indent=2) + "\n"
