"""Compare how different Claude models resist prompt injection.

Runs the same injectprobe attacks against the TripMate agent once per model and
prints a side-by-side table. The agent runs in-process, so no server is needed.

    python -m examples.claude_agent.compare                     # quick set, all models in models.yaml
    python -m examples.claude_agent.compare --models claude-opus-5-5,claude-haiku-5-5
    python -m examples.claude_agent.compare --full --trials 3 --prompt guarded

This calls the real Claude API and costs money. It prints an estimate and asks
before sending anything (skip the question with --yes). Needs the Anthropic SDK
and a credential the SDK can find, usually ANTHROPIC_API_KEY.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx
import yaml
from rich.console import Console
from rich.table import Table

from injectprobe.config import parse_config
from injectprobe.loader import TestCase, expand_cases, filter_attacks, load_attacks
from injectprobe.models import Delivery, RunResult
from injectprobe.reports import render
from injectprobe.reports.compare import comparison_markdown, print_comparison
from injectprobe.runner import run_probe
from injectprobe.targets.http import HttpTarget

from . import agent

HERE = Path(__file__).resolve().parent
console = Console()


@dataclass
class ModelSpec:
    id: str
    price_in: float
    price_out: float
    overrides: dict[str, Any]

    def cost(self, input_tokens: int, output_tokens: int) -> float:
        return input_tokens / 1e6 * self.price_in + output_tokens / 1e6 * self.price_out


def load_models(path: Path) -> list[ModelSpec]:
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    out = []
    for m in data.get("models", []):
        price = m.get("price") or [0, 0]
        out.append(ModelSpec(id=m["id"], price_in=float(price[0]), price_out=float(price[1]),
                             overrides=m.get("overrides") or {}))
    return out


def estimate_calls(cases: list[TestCase], trials: int) -> int:
    """Model calls: one per user turn, plus one extra for indirect attacks (read_document, then answer)."""
    per_attempt = sum(len(c.attack.templates) + (1 if c.attack.delivery == Delivery.indirect else 0) for c in cases)
    return per_attempt * trials


def estimate_cost(model: ModelSpec, calls: int) -> tuple[float, float]:
    # Each call resends system prompt + tool definitions (~1K tokens) plus the conversation.
    low = model.cost(calls * 1200, calls * 250)
    high = model.cost(calls * 3000, calls * 2500)  # thinking tokens are billed as output
    return low, high


def agent_config(model: str, prompt: str, trials: int, max_requests: int):
    return parse_config({
        "target": {
            "type": "http",
            "url": f"http://tripmate.local/chat/{prompt}/{model}",
            "request_template": {"message": "{{message}}", "history": "{{history}}", "documents": "{{documents}}"},
            "response_path": "$.reply",
            "tool_calls_path": "$.tool_calls",
        },
        "authorised": True,  # our own agent, in-process
        "threshold": 0.1,
        "system_prompt_markers": [agent.SECRET],
        "run": {"trials": trials, "concurrency": 3, "rate_limit": 2, "retries": 2, "backoff_base": 2.0,
                "timeout": 180, "max_requests": max_requests},
        "canary": {"grace_seconds": 1.0},
    })


async def available_models(client: Any) -> set[str] | None:
    """Model ids this credential can use, or None if listing is not possible."""
    try:
        return {m.id async for m in client.models.list()}
    except Exception:  # noqa: BLE001 - listing is a convenience only
        return None


async def run_model(model: ModelSpec, cases: list[TestCase], prompt: str, trials: int, max_requests: int,
                    transport: httpx.AsyncBaseTransport) -> RunResult:
    cfg = agent_config(model.id, prompt, trials, max_requests)
    target = HttpTarget(cfg.target, timeout=cfg.run.timeout, transport=transport)
    with console.status(f"Testing [bold]{model.id}[/] ({len(cases)} attacks x {trials})..."):
        return await run_probe(cfg, cases, target=target)


async def main_async(args: argparse.Namespace) -> int:
    models = load_models(Path(args.models_file))
    if args.models:
        wanted = [m.strip() for m in args.models.split(",") if m.strip()]
        known = {m.id: m for m in models}
        models = [known.get(w) or ModelSpec(w, 0.0, 0.0, {}) for w in wanted]
    if not models:
        console.print("No models selected.")
        return 2

    attacks = filter_attacks(load_attacks(), quick=not args.full,
                             categories=[c for c in (args.categories or "").split(",") if c])
    cases = expand_cases(attacks)
    calls = estimate_calls(cases, args.trials)

    # Credentials and model availability (listing models is free).
    if agent.STATE.client is None:
        try:
            import anthropic  # noqa: F401
        except ImportError:
            console.print("Install the SDK first: pip install -e \".[demo,anthropic]\"")
            return 2
    client = agent._client()
    available = await available_models(client)
    if available is None and agent.STATE.client.__class__.__module__.startswith("anthropic"):
        console.print("[yellow]Could not list models. Check that ANTHROPIC_API_KEY is set and valid.[/]")

    table = Table(title=f"Plan: {len(cases)} attacks x {args.trials} trial(s), prompt '{args.prompt}'")
    table.add_column("Model")
    table.add_column("Available")
    table.add_column("Model calls (approx.)", justify="right")
    table.add_column("Estimated cost", justify="right")
    total_low = total_high = 0.0
    runnable = []
    for m in models:
        ok = available is None or m.id in available
        low, high = estimate_cost(m, calls)
        if ok:
            runnable.append(m)
            total_low += low
            total_high += high
        price = f"${low:.2f} - ${high:.2f}" if m.price_in else "unknown price"
        table.add_row(m.id, "yes" if ok else "[red]no[/]", str(calls), price if ok else "skipped")
    console.print(table)
    console.print(f"Estimated total: [bold]${total_low:.2f} - ${total_high:.2f}[/] "
                  f"(spending stops after ${args.max_cost:.2f}).")
    if not runnable:
        console.print("None of the selected models is available to this API key.")
        return 2
    if not args.yes:
        if not sys.stdin.isatty():
            console.print("Re-run with --yes to confirm the spend.")
            return 2
        if input("Run it? [y/N] ").strip().lower() not in ("y", "yes"):
            console.print("Cancelled; nothing was sent.")
            return 0

    agent.configure(overrides={m.id: m.overrides for m in runnable if m.overrides})
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    transport = httpx.ASGITransport(app=agent.app)
    runs: list[tuple[str, RunResult]] = []
    costs: dict[str, float] = {}
    spent = 0.0
    for m in runnable:
        if spent >= args.max_cost:
            console.print(f"[yellow]Stopping: spent ${spent:.2f}, which reaches --max-cost.[/]")
            break
        result = await run_model(m, cases, args.prompt, args.trials, args.max_requests, transport)
        u = agent.STATE.usage[m.id]
        costs[m.id] = round(m.cost(u.input_tokens, u.output_tokens), 4)
        spent = sum(costs.values())
        (out / f"{m.id}.json").write_text(render(result, "json"), encoding="utf-8")
        runs.append((m.id, result))
        s = result.summary
        console.print(f"  {m.id}: {s.success_rate:.0%} of attempts succeeded, {s.errored_attempts} errors, "
                      f"${costs[m.id]:.4f}" + (f", {u.refusals} refusals" if u.refusals else ""))

    if not runs:
        return 2
    print_comparison(runs, console, costs)
    notes = [
        f"Agent: TripMate ({args.prompt} prompt). Attacks: {'full library' if args.full else 'quick set'}, "
        f"{len(cases)} attacks x {args.trials} trial(s). {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC.",
        "Each model runs with its default thinking and effort settings, so this compares models as shipped.",
        f"Total cost: ${sum(costs.values()):.4f} (from API token usage and the prices in models.yaml).",
    ]
    md = comparison_markdown(runs, costs, title="Claude models vs prompt injection", notes=notes)
    (out / "comparison.md").write_text(md, encoding="utf-8")
    (out / "usage.json").write_text(json.dumps({k: vars(v) for k, v in agent.STATE.usage.items()}, indent=2),
                                    encoding="utf-8")
    console.print(f"Wrote {out / 'comparison.md'} and one results file per model in {out}.")
    return 0


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--models", help="comma-separated model ids (default: all in models.yaml)")
    p.add_argument("--models-file", default=str(HERE / "models.yaml"))
    p.add_argument("--full", action="store_true", help="all 109 attacks instead of the 13-attack quick set")
    p.add_argument("--categories", help="comma-separated categories to include")
    p.add_argument("--trials", type=int, default=1, choices=range(1, 6), metavar="1-5")
    p.add_argument("--prompt", choices=list(agent.PROMPTS), default="standard")
    p.add_argument("--max-cost", type=float, default=5.0, help="stop starting new models after this many USD")
    p.add_argument("--max-requests", type=int, default=1500, help="per-model cap on agent requests")
    p.add_argument("--out", default="injectprobe-reports/claude-models")
    p.add_argument("--yes", action="store_true", help="don't ask before spending")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    return asyncio.run(main_async(parse_args(argv)))


if __name__ == "__main__":
    raise SystemExit(main())
