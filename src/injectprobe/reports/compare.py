"""Side-by-side comparison of several runs (for example, the same agent on different models)."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from ..models import CATEGORIES, THREATS, RunResult
from ._util import pct

Runs = list[tuple[str, RunResult]]


def _style(rate: float) -> str:
    return "green" if rate == 0 else ("yellow" if rate < 0.34 else "red")


THREAT_ORDER = ["injection", "leak", "override"]
SHORT = {"injection": "Hidden instructions", "leak": "Prompt leaks", "override": "User overrides"}
EXPLAIN = ("Hidden instructions = attacks planted in documents, web pages, emails and tool results (real prompt "
           "injection). Prompt leaks = the confidential system prompt revealed. User overrides = the user directly "
           "asks the agent to break its instructions; this only matters if your instructions forbid it.")


def threat_rate(r: RunResult, threat: str) -> float | None:
    g = r.summary.by_threat.get(threat)
    return None if g is None or not g.attempts else g.success_rate


def ranked(runs: Runs) -> Runs:
    """Most resistant first: hidden instructions, then leaks, then user overrides, then overall."""
    def key(lr: tuple[str, RunResult]) -> tuple:
        r = lr[1]
        return tuple(threat_rate(r, t) or 0.0 for t in THREAT_ORDER) + (r.summary.success_rate,)
    return sorted(runs, key=key)


def categories(runs: Runs) -> list[str]:
    seen = {c for _, r in runs for c in r.summary.by_category}
    return [c for c in CATEGORIES if c in seen] + sorted(seen - set(CATEGORIES))


def attack_matrix(runs: Runs, limit: int = 25) -> list[tuple[str, str, list[float | None]]]:
    """Attacks that worked on at least one run: (id, severity, rate per run or None if not tested)."""
    by_run = [{x.id: x for x in r.results} for _, r in runs]
    ids = sorted({i for m in by_run for i, x in m.items() if x.successes > 0})
    rows = []
    for i in ids:
        rates: list[float | None] = []
        sev = ""
        for m in by_run:
            x = m.get(i)
            if x is None or not x.completed:
                rates.append(None)
            else:
                rates.append(x.success_rate)
                sev = x.severity.value
        rows.append((i, sev, rates))
    rows.sort(key=lambda row: (-sum(r or 0 for r in row[2]), row[0]))
    return rows[:limit]


def print_comparison(runs: Runs, console: Console | None = None, costs: dict[str, float] | None = None) -> None:
    console = console or Console()
    runs = ranked(runs)
    t = Table(title="Prompt injection resistance (lower is better)", caption=EXPLAIN, caption_justify="left")
    t.add_column("#", justify="right")
    t.add_column("Run")
    for th in THREAT_ORDER:
        t.add_column(SHORT[th], justify="right")
    t.add_column("Overall", justify="right")
    t.add_column("Attempts", justify="right")
    t.add_column("Errors", justify="right")
    if costs:
        t.add_column("Cost", justify="right")
    for n, (label, r) in enumerate(runs, 1):
        s = r.summary
        cells = []
        for th in THREAT_ORDER:
            rate = threat_rate(r, th)
            cells.append(Text("-") if rate is None else Text(pct(rate), style=_style(rate)))
        row = [str(n), label, *cells, Text(pct(s.success_rate), style=_style(s.success_rate)),
               str(s.attempts), str(s.errored_attempts)]
        if costs:
            row.append(f"${costs.get(label, 0.0):.4f}")
        t.add_row(*row)
    console.print(t)

    cats = categories(runs)
    if cats:
        c = Table(title="Success rate by category")
        c.add_column("Category")
        for label, _ in runs:
            c.add_column(label, justify="right")
        for cat in cats:
            cells = []
            for _, r in runs:
                g = r.summary.by_category.get(cat)
                cells.append(Text("-") if g is None else Text(pct(g.success_rate), style=_style(g.success_rate)))
            c.add_row(CATEGORIES.get(cat, cat), *cells)
        console.print(c)

    matrix = attack_matrix(runs)
    if matrix:
        m = Table(title="Attacks that worked on at least one run")
        m.add_column("Attack")
        for label, _ in runs:
            m.add_column(label, justify="right")
        for attack_id, _, rates in matrix:
            m.add_row(attack_id, *[Text("-") if x is None else Text(pct(x), style=_style(x)) for x in rates])
        console.print(m)


def comparison_markdown(runs: Runs, costs: dict[str, float] | None = None, title: str = "Prompt injection comparison",
                        notes: list[str] | None = None) -> str:
    runs = ranked(runs)
    out = [f"## {title}", ""]
    for n in notes or []:
        out.append(f"> {n}")
    if notes:
        out.append("")
    head = ("| # | Run | " + " | ".join(SHORT[t] for t in THREAT_ORDER) + " | Overall | Attempts | Errors |"
            + (" Cost |" if costs else ""))
    sep = "|---:|---|" + "---:|" * len(THREAT_ORDER) + "---:|---:|---:|" + ("---:|" if costs else "")
    out += ["Lower is better: the share of attack attempts that tricked the agent. Ranked by hidden "
            "instructions first, then prompt leaks, then user overrides.", "", f"*{EXPLAIN}*", "", head, sep]
    for n, (label, r) in enumerate(runs, 1):
        s = r.summary
        cells = []
        for th in THREAT_ORDER:
            rate = threat_rate(r, th)
            cells.append("-" if rate is None else (f"**{pct(rate)}**" if th == "injection" else pct(rate)))
        line = (f"| {n} | `{label}` | " + " | ".join(cells) + f" | {pct(s.success_rate)} "
                f"| {s.attempts} | {s.errored_attempts} |")
        if costs:
            line += f" ${costs.get(label, 0.0):.4f} |"
        out.append(line)
    out.append("")

    cats = categories(runs)
    if cats:
        out += ["### By category", "", "| Category | " + " | ".join(f"`{lbl}`" for lbl, _ in runs) + " |",
                "|---|" + "---:|" * len(runs)]
        for cat in cats:
            cells = []
            for _, r in runs:
                g = r.summary.by_category.get(cat)
                cells.append("-" if g is None else pct(g.success_rate))
            out.append(f"| {CATEGORIES.get(cat, cat)} | " + " | ".join(cells) + " |")
        out.append("")

    matrix = attack_matrix(runs)
    if matrix:
        out += ["### Attacks that worked on at least one run", "",
                "| Attack | Severity | " + " | ".join(f"`{lbl}`" for lbl, _ in runs) + " |",
                "|---|---|" + "---:|" * len(runs)]
        for attack_id, sev, rates in matrix:
            out.append(f"| `{attack_id}` | {sev} | " + " | ".join("-" if x is None else pct(x) for x in rates) + " |")
        out.append("")
    return "\n".join(out) + "\n"
