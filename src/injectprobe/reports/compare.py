"""Side-by-side comparison of several runs (for example, the same agent on different models)."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table
from rich.text import Text

from ..models import CATEGORIES, RunResult
from ._util import pct

Runs = list[tuple[str, RunResult]]


def _style(rate: float) -> str:
    return "green" if rate == 0 else ("yellow" if rate < 0.34 else "red")


def ranked(runs: Runs) -> Runs:
    """Most resistant first (lowest success rate)."""
    return sorted(runs, key=lambda lr: (lr[1].summary.success_rate, -lr[1].summary.attempts))


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
    t = Table(title="Prompt injection resistance (lower is better)")
    t.add_column("#", justify="right")
    t.add_column("Run")
    t.add_column("Success rate", justify="right")
    t.add_column("Vulnerable attacks", justify="right")
    t.add_column("Attempts", justify="right")
    t.add_column("Errors", justify="right")
    if costs:
        t.add_column("Cost", justify="right")
    for n, (label, r) in enumerate(runs, 1):
        s = r.summary
        row = [str(n), label, Text(pct(s.success_rate), style=_style(s.success_rate)),
               f"{s.vulnerable_attacks}/{s.tested}", str(s.attempts), str(s.errored_attempts)]
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
    head = "| # | Run | Success rate | Vulnerable attacks | Attempts | Errors |" + (" Cost |" if costs else "")
    sep = "|---:|---|---:|---:|---:|---:|" + ("---:|" if costs else "")
    out += ["Lower is better: the share of attack attempts that tricked the agent.", "", head, sep]
    for n, (label, r) in enumerate(runs, 1):
        s = r.summary
        line = (f"| {n} | `{label}` | **{pct(s.success_rate)}** | {s.vulnerable_attacks}/{s.tested} "
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
