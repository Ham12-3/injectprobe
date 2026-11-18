"""Baselines and result diffs: fail only on new regressions."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from pydantic import ValidationError

from . import __version__
from .models import Regression, RunResult, Severity


class BaselineError(Exception):
    pass


BASELINE_KEY = "injectprobe_baseline"


@dataclass
class RateEntry:
    rate: float
    category: str = ""
    severity: Severity = Severity.medium


def baseline_payload(result: RunResult) -> dict:
    return {
        BASELINE_KEY: 1,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "tool_version": __version__,
        "trials": result.trials,
        "attacks": {
            r.id: {"rate": round(r.success_rate, 4), "category": r.category, "severity": r.severity.value}
            for r in result.results
            if r.status == "tested" and r.completed
        },
    }


def save_baseline(result: RunResult, path: str | Path) -> Path:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(baseline_payload(result), indent=2) + "\n", encoding="utf-8")
    return p


def load_result(path: str | Path) -> RunResult:
    p = Path(path)
    try:
        result = RunResult.model_validate_json(p.read_text(encoding="utf-8"))
    except OSError as e:
        raise BaselineError(f"cannot read {p}: {e}") from e
    except ValidationError as e:
        raise BaselineError(f"{p} is not an injectprobe results file: {e.errors()[0]['msg']}") from e
    # Recompute derived numbers so files from older versions get newer breakdowns (e.g. by threat).
    result.compute_summary()
    return result


def rates_from_result(result: RunResult) -> dict[str, RateEntry]:
    return {
        r.id: RateEntry(r.success_rate, r.category, r.severity)
        for r in result.results
        if r.status == "tested" and r.completed
    }


def load_rates(path: str | Path) -> dict[str, RateEntry]:
    """Load per-attack success rates from a baseline file or a full results JSON."""
    p = Path(path)
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except OSError as e:
        raise BaselineError(f"cannot read baseline {p}: {e}") from e
    except json.JSONDecodeError as e:
        raise BaselineError(f"baseline {p} is not valid JSON: {e}") from e
    if isinstance(data, dict) and BASELINE_KEY in data:
        try:
            return {
                k: RateEntry(float(v["rate"]), v.get("category", ""), Severity(v.get("severity", "medium")))
                for k, v in data["attacks"].items()
            }
        except (KeyError, TypeError, ValueError) as e:
            raise BaselineError(f"baseline {p} is malformed: {e}") from e
    return rates_from_result(load_result(p))


def compare(result: RunResult, baseline: dict[str, RateEntry], tolerance: float = 0.0) -> list[Regression]:
    regs: list[Regression] = []
    for r in result.results:
        if r.status != "tested" or not r.completed:
            continue
        base = baseline.get(r.id)
        if base is None:
            if r.success_rate > 0:
                regs.append(Regression(id=r.id, category=r.category, severity=r.severity,
                                       baseline_rate=None, current_rate=r.success_rate, kind="new"))
        elif r.success_rate > base.rate + tolerance + 1e-9:
            regs.append(Regression(id=r.id, category=r.category, severity=r.severity,
                                   baseline_rate=base.rate, current_rate=r.success_rate, kind="worse"))
    regs.sort(key=lambda x: (-x.severity.rank, -x.current_rate, x.id))
    return regs


@dataclass
class DiffReport:
    regressions: list[Regression] = field(default_factory=list)
    improvements: list[Regression] = field(default_factory=list)
    unchanged: int = 0
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    old_rate: float = 0.0
    new_rate: float = 0.0


def diff(old: dict[str, RateEntry], new: RunResult, tolerance: float = 0.0, old_rate: float = 0.0) -> DiffReport:
    rep = DiffReport(regressions=compare(new, old, tolerance), old_rate=old_rate, new_rate=new.summary.success_rate)
    regressed = {x.id for x in rep.regressions}
    new_rates = rates_from_result(new)
    for k, cur in new_rates.items():
        base = old.get(k)
        if base is None:
            rep.added.append(k)
            continue
        if k in regressed:
            continue
        if cur.rate < base.rate - tolerance - 1e-9:
            rep.improvements.append(Regression(id=k, category=cur.category, severity=cur.severity,
                                               baseline_rate=base.rate, current_rate=cur.rate, kind="worse"))
        else:
            rep.unchanged += 1
    rep.removed = sorted(set(old) - set(new_rates))
    rep.added.sort()
    return rep
