from __future__ import annotations

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ..baseline import DiffReport
from ..models import CATEGORIES, THREATS, RunResult
from ._util import clean, pct, sample_reply

SEV_STYLE = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "dim"}


def _rate_style(rate: float) -> str:
    if rate == 0:
        return "green"
    return "yellow" if rate < 0.34 else "red"


def print_report(result: RunResult, console: Console | None = None, top: int = 5) -> None:
    console = console or Console()
    s = result.summary

    summary = Table.grid(padding=(0, 2))
    summary.add_column(style="bold")
    summary.add_column()
    summary.add_row("Target", Text(f"{result.target.type} {clean(result.target.endpoint, 80)}".strip()))
    summary.add_row("Attacks tested", f"{s.tested}  (skipped {s.skipped}, not run {s.not_run})")
    summary.add_row("Vulnerable attacks", Text(str(s.vulnerable_attacks), style=_rate_style(s.vulnerable_attacks)))
    summary.add_row("Attempts", f"{s.attempts} ({result.trials} per attack, {s.errored_attempts} errored)")
    summary.add_row("Success rate", Text(pct(s.success_rate), style=_rate_style(s.success_rate)))
    summary.add_row("Requests / est. cost", f"{result.requests_made} / ${result.estimated_cost_usd:.4f}")
    gate = (f"no regressions vs {result.baseline_path}" if result.baseline_path is not None
            else f"success rate <= {pct(result.threshold)}")
    verdict = Text("PASSED", style="bold green") if result.passed else Text("FAILED", style="bold red")
    summary.add_row("Gate", Text.assemble(verdict, f"  ({gate})"))
    console.print(Panel(summary, title="injectprobe summary", expand=False))

    if result.aborted:
        console.print(Text(f"Run stopped early: {result.abort_reason}. Results are partial.", style="bold yellow"))

    if s.by_threat:
        t = Table(title="Success rate by threat",
                  caption="Hidden instructions are real prompt injection; user overrides only matter if your "
                          "instructions forbid what was asked.", caption_justify="left")
        t.add_column("Threat")
        t.add_column("Attacks", justify="right")
        t.add_column("Worked", justify="right")
        t.add_column("Success rate", justify="right")
        for th, name in THREATS.items():
            g = s.by_threat.get(th)
            if g is not None:
                t.add_row(name, str(g.attacks), str(g.vulnerable),
                          Text(pct(g.success_rate), style=_rate_style(g.success_rate)))
        console.print(t)

    if s.by_category:
        t = Table(title="Success rate by category")
        t.add_column("Category")
        t.add_column("Attacks", justify="right")
        t.add_column("Vulnerable", justify="right")
        t.add_column("Success rate", justify="right")
        for cat, g in sorted(s.by_category.items(), key=lambda kv: -kv[1].success_rate):
            t.add_row(CATEGORIES.get(cat, cat), str(g.attacks), str(g.vulnerable),
                      Text(pct(g.success_rate), style=_rate_style(g.success_rate)))
        console.print(t)

    if result.regressions:
        t = Table(title="Regressions vs baseline", title_style="bold red")
        t.add_column("Attack")
        t.add_column("Severity")
        t.add_column("Baseline", justify="right")
        t.add_column("Now", justify="right")
        for g in result.regressions:
            t.add_row(g.id, Text(g.severity.value, style=SEV_STYLE[g.severity.value]),
                      "new" if g.baseline_rate is None else pct(g.baseline_rate), pct(g.current_rate))
        console.print(t)

    failing = result.failing(top)
    if failing:
        console.print(Text(f"Top failing attacks ({len(failing)} of {len(result.failing())})", style="bold"))
        for r in failing:
            head = Text.assemble(
                (r.id, "bold"), "  ", (r.severity.value, SEV_STYLE[r.severity.value]),
                f"  {r.category}  ", (f"{pct(r.success_rate)} ({r.successes}/{r.completed})", _rate_style(r.success_rate)),
            )
            body = Group(
                Text(clean(r.description, 200), style="italic"),
                Text("Payload:", style="bold cyan"),
                Text(clean(r.payload_preview, 600)),
                Text("Reply:", style="bold magenta"),
                Text(clean(sample_reply(r), 600)),
            )
            console.print(Panel(body, title=head, title_align="left"))

    skipped = [r for r in result.results if r.status == "skipped"]
    if skipped:
        console.print(Text(f"{len(skipped)} attack(s) skipped: {clean(skipped[0].skip_reason)}", style="dim"))


def print_diff(rep: DiffReport, console: Console | None = None) -> None:
    console = console or Console()
    console.print(
        f"Overall success rate: {pct(rep.old_rate)} -> {pct(rep.new_rate)}   "
        f"regressions: {len(rep.regressions)}, improvements: {len(rep.improvements)}, "
        f"unchanged: {rep.unchanged}, added: {len(rep.added)}, removed: {len(rep.removed)}"
    )
    for title, rows, style in (("Regressions", rep.regressions, "bold red"),
                               ("Improvements", rep.improvements, "bold green")):
        if not rows:
            continue
        t = Table(title=title, title_style=style)
        t.add_column("Attack")
        t.add_column("Severity")
        t.add_column("Before", justify="right")
        t.add_column("After", justify="right")
        for g in rows:
            t.add_row(g.id, Text(g.severity.value, style=SEV_STYLE[g.severity.value]),
                      "new" if g.baseline_rate is None else pct(g.baseline_rate), pct(g.current_rate))
        console.print(t)


def diff_markdown(rep: DiffReport) -> str:
    lines = [f"## injectprobe diff", "",
             f"Success rate {pct(rep.old_rate)} → {pct(rep.new_rate)}. "
             f"{len(rep.regressions)} regression(s), {len(rep.improvements)} improvement(s).", ""]
    for title, rows in (("Regressions", rep.regressions), ("Improvements", rep.improvements)):
        if rows:
            lines += [f"### {title}", "", "| Attack | Severity | Before | After |", "|---|---|---:|---:|"]
            for g in rows:
                before = "new" if g.baseline_rate is None else pct(g.baseline_rate)
                lines.append(f"| `{g.id}` | {g.severity.value} | {before} | {pct(g.current_rate)} |")
            lines.append("")
    return "\n".join(lines) + "\n"
