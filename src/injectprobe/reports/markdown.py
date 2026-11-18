from __future__ import annotations

from ..models import CATEGORIES, RunResult
from ._util import clean, pct, sample_reply

MARKER = "<!-- injectprobe-report -->"
MAX_CHARS = 60000  # GitHub comment limit is 65536
SEV_ICON = {"critical": "🟥", "high": "🟧", "medium": "🟨", "low": "⬜"}


def _fence(text: str) -> str:
    # Untrusted replies go in a code fence so links and images never render.
    body = clean(text, 1500).replace("~~~~", "~ ~ ~ ~")
    return f"~~~~text\n{body}\n~~~~"


def _cell(text: str) -> str:
    return clean(text, 120).replace("|", "\\|").replace("\n", " ")


def render(result: RunResult, top: int = 10) -> str:
    s = result.summary
    status = "✅ Passed" if result.passed else "❌ Failed"
    if result.baseline_path is not None:
        rule = f"no regressions vs baseline `{result.baseline_path}`"
    else:
        rule = f"success rate ≤ {pct(result.threshold)}"

    out = [MARKER, f"## injectprobe: {status}", ""]
    out.append(
        f"**{pct(s.success_rate)}** of attack attempts succeeded "
        f"({s.successful_attempts}/{s.attempts}) against `{_cell(result.target.type)}`. "
        f"Gate: {rule}."
    )
    out.append("")
    if result.aborted:
        out += [f"> ⚠️ Run stopped early: {clean(result.abort_reason)}. Results are partial.", ""]

    out += [
        "| Attacks tested | Vulnerable | Attempts | Trials each | Skipped | Errors | Requests |",
        "|---:|---:|---:|---:|---:|---:|---:|",
        f"| {s.tested} | {s.vulnerable_attacks} | {s.attempts} | {result.trials} | {s.skipped + s.not_run} "
        f"| {s.errored_attempts} | {result.requests_made} |",
        "",
    ]

    if result.baseline_path is not None:
        if result.regressions:
            out += ["### Regressions", "", "| Attack | Severity | Baseline | Now |", "|---|---|---:|---:|"]
            for g in result.regressions:
                base = "new" if g.baseline_rate is None else pct(g.baseline_rate)
                out.append(f"| `{g.id}` | {SEV_ICON[g.severity.value]} {g.severity.value} | {base} | {pct(g.current_rate)} |")
            out.append("")
        else:
            out += ["No regressions against the baseline. 🎉", ""]

    if s.by_category:
        out += ["### Success rate by category", "", "| Category | Attacks | Vulnerable | Success rate |",
                "|---|---:|---:|---:|"]
        for cat, g in sorted(s.by_category.items(), key=lambda kv: -kv[1].success_rate):
            out.append(f"| {CATEGORIES.get(cat, cat)} | {g.attacks} | {g.vulnerable} | {pct(g.success_rate)} |")
        out.append("")

    failing = result.failing(top)
    if failing:
        out += [f"### Top failing attacks ({len(failing)} of {len(result.failing())})", ""]
        for r in failing:
            out.append(
                f"<details><summary>{SEV_ICON[r.severity.value]} <code>{_cell(r.id)}</code> "
                f"({r.category}, {r.severity.value}): {pct(r.success_rate)} "
                f"({r.successes}/{r.completed})</summary>\n"
            )
            out.append(f"{_cell(r.description)}\n")
            out.append("**Payload**\n")
            out.append(_fence(r.payload_preview))
            out.append("\n**Reply**\n")
            out.append(_fence(sample_reply(r)))
            out.append("\n</details>\n")

    out.append(
        f"<sub>injectprobe {result.tool_version} · {result.duration_s:.1f}s · "
        "only test systems you own or are authorised to test</sub>"
    )
    text = "\n".join(out) + "\n"
    if len(text) > MAX_CHARS:
        text = text[: MAX_CHARS - 200] + "\n\n…report truncated; see the full JSON artifact.\n"
    return text
