"""injectprobe command line interface."""

from __future__ import annotations

import asyncio
import json
import sys
from enum import Enum
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeElapsedColumn
from rich.table import Table
from rich.text import Text

from . import __version__, secrets
from .baseline import BaselineError, compare, diff, load_rates, load_result, save_baseline
from .config import AUTH_NOTICE, Config, ConfigError, check_authorised, is_local_target, load_config, target_url
from .loader import AttackLoadError, expand_cases, filter_attacks, load_attacks
from .models import CATEGORIES
from .mutators import UnknownMutatorError
from .reports import FILE_FORMATS, render, write_reports
from .reports.terminal import diff_markdown, print_diff, print_report
from .templates import TARGET_CHOICES, starter_config

def _utf8_streams() -> None:
    """Attack payloads include many scripts. On Windows a redirected stdout defaults to a
    legacy code page and would crash on them, so switch the standard streams to UTF-8."""
    for stream in (sys.stdout, sys.stderr):
        encoding = (getattr(stream, "encoding", "") or "").lower().replace("-", "")
        if encoding != "utf8" and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):  # pragma: no cover - exotic streams
                pass


_utf8_streams()

app = typer.Typer(
    name="injectprobe",
    help="Red-team LLM apps and agents for prompt injection. Only test systems you own or may test.",
    no_args_is_help=True,
    add_completion=False,
    rich_markup_mode="rich",
)
console = Console()
err = Console(stderr=True, soft_wrap=True)

EXIT_OK, EXIT_FAIL, EXIT_ERROR = 0, 1, 2


def _fail(message: str) -> "typer.Exit":
    err.print(Text("error: ", style="bold red") + Text(secrets.redact(message)))
    return typer.Exit(EXIT_ERROR)


def _version(value: bool) -> None:
    if value:
        console.print(f"injectprobe {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", callback=_version, is_eager=True, help="Show version."),
) -> None:
    # API keys may live in a git-ignored .env file in the current directory.
    from .dotenv import load_dotenv

    load_dotenv()


# --------------------------------------------------------------------------- init


class TargetChoice(str, Enum):
    http = "http"
    openai = "openai"
    anthropic = "anthropic"
    callable = "callable"
    mock = "mock"


@app.command()
def init(
    path: Path = typer.Option(Path("injectprobe.yaml"), "--path", "-p", help="Where to write the config."),
    target: TargetChoice = typer.Option(TargetChoice.http, "--target", "-t", help="Target adapter."),
    force: bool = typer.Option(False, "--force", "-f", help="Overwrite an existing file."),
) -> None:
    """Create a starter injectprobe.yaml."""
    assert target.value in TARGET_CHOICES
    if path.exists() and not force:
        raise _fail(f"{path} already exists (use --force to overwrite)")
    path.write_text(starter_config(target.value), encoding="utf-8")
    console.print(f"Wrote [bold]{path}[/]. Edit the target section, then run [bold]injectprobe run[/].")


# --------------------------------------------------------------------------- list


@app.command("list")
def list_attacks(
    category: list[str] = typer.Option([], "--category", "-c", help="Filter by category (repeatable)."),
    severity: list[str] = typer.Option([], "--severity", "-s", help="Filter by severity (repeatable)."),
    tag: list[str] = typer.Option([], "--tag", "-t", help="Filter by tag (repeatable)."),
    attack_id: list[str] = typer.Option([], "--id", help="Filter by id or glob (repeatable)."),
    attacks_path: list[Path] = typer.Option([], "--attacks", "-a", help="Extra attack file or folder."),
    quick: bool = typer.Option(False, "--quick", help="Only the quick smoke set."),
    as_json: bool = typer.Option(False, "--json", help="Print JSON instead of a table."),
) -> None:
    """List attacks, filterable by category, severity, tag or id."""
    try:
        attacks = filter_attacks(
            load_attacks(attacks_path), categories=category, severities=severity, tags=tag, ids=attack_id, quick=quick
        )
    except AttackLoadError as e:
        raise _fail(str(e)) from e
    if as_json:
        # Plain JSON (no highlighting) so it can be piped into other tools.
        typer.echo(json.dumps([a.model_dump(mode="json") for a in attacks], indent=2, ensure_ascii=False))
        return
    t = Table(title=f"{len(attacks)} attacks")
    for col in ("ID", "Category", "Severity", "Delivery", "Tags", "Description"):
        t.add_column(col, overflow="fold")
    for a in attacks:
        delivery = a.delivery.value + (f" ({a.carrier.value})" if a.carrier else "")
        t.add_row(a.id, a.category, a.severity.value, delivery, ",".join(a.tags), a.description)
    console.print(t)
    if not category:
        console.print("Categories: " + ", ".join(CATEGORIES), style="dim")


# --------------------------------------------------------------------------- run


def _merge(base: list[str], extra: list[str]) -> list[str]:
    return list(dict.fromkeys([*base, *extra]))


@app.command()
def run(
    config: Path = typer.Option(Path("injectprobe.yaml"), "--config", "-c", help="Config file."),
    category: list[str] = typer.Option([], "--category", help="Only these categories (repeatable)."),
    severity: list[str] = typer.Option([], "--severity", help="Only these severities (repeatable)."),
    attack_id: list[str] = typer.Option([], "--id", help="Only these ids or globs (repeatable)."),
    tag: list[str] = typer.Option([], "--tag", help="Only attacks with these tags (repeatable)."),
    quick: bool = typer.Option(False, "--quick", help="Small smoke set, 1 trial unless --trials is given."),
    trials: Optional[int] = typer.Option(None, "--trials", "-n", min=1, help="Runs per attack."),
    threshold: Optional[float] = typer.Option(None, "--threshold", min=0, max=1, help="Max allowed success rate."),
    baseline: Optional[Path] = typer.Option(None, "--baseline", help="Fail only on regressions vs this baseline."),
    save_baseline_to: Optional[Path] = typer.Option(None, "--save-baseline", help="Write a baseline file."),
    output_dir: Optional[Path] = typer.Option(None, "--output-dir", "-o", help="Report directory."),
    report_format: list[str] = typer.Option([], "--format", "-f", help="Report formats (repeatable)."),
    mutator: list[str] = typer.Option([], "--mutator", "-m", help="Add a mutated variant of every attack."),
    concurrency: Optional[int] = typer.Option(None, "--concurrency", min=1),
    max_requests: Optional[int] = typer.Option(None, "--max-requests", min=1),
    top: int = typer.Option(5, "--top", help="Failing attacks to show in the terminal."),
    no_progress: bool = typer.Option(False, "--no-progress", help="Disable the progress bar."),
) -> None:
    """Run attacks against the configured target."""
    try:
        cfg: Config = load_config(config)
        check_authorised(cfg)
    except ConfigError as e:
        raise _fail(str(e)) from e

    if not is_local_target(cfg):
        console.print(Text(f"Target: {target_url(cfg)}\n{AUTH_NOTICE}", style="bold yellow"))

    if trials is not None:
        cfg.run.trials = trials
    elif quick:
        cfg.run.trials = 1
    if threshold is not None:
        cfg.threshold = threshold
    if concurrency is not None:
        cfg.run.concurrency = concurrency
    if max_requests is not None:
        cfg.run.max_requests = max_requests
    formats = report_format or list(cfg.reports.formats)
    bad = [f for f in formats if f not in FILE_FORMATS]
    if bad:
        raise _fail(f"unknown report format(s) {bad}; use {', '.join(FILE_FORMATS)}")

    sel = cfg.attacks
    try:
        attacks = load_attacks([cfg.resolve_path(p) for p in sel.paths], include_builtin=sel.include_builtin)
        attacks = filter_attacks(
            attacks,
            categories=category or sel.categories,
            severities=severity or sel.severities,
            ids=attack_id or sel.ids,
            tags=tag or sel.tags,
            exclude_ids=sel.exclude_ids,
            exclude_tags=sel.exclude_tags,
            quick=quick,
        )
        cases = expand_cases(attacks, _merge(cfg.run.mutators, mutator))
    except (AttackLoadError, UnknownMutatorError) as e:
        raise _fail(str(e)) from e
    if not cases:
        raise _fail("no attacks match the filters")

    baseline_path = baseline or (cfg.resolve_path(cfg.baseline) if cfg.baseline else None)
    baseline_rates = None
    if baseline_path is not None:
        try:
            baseline_rates = load_rates(baseline_path)
        except BaselineError as e:
            raise _fail(str(e)) from e

    from .runner import run_probe

    total = len(cases) * cfg.run.trials
    console.print(f"Running {len(cases)} attacks x {cfg.run.trials} trials against [bold]{cfg.target.type}[/] target")
    try:
        if no_progress or not console.is_terminal:
            result = asyncio.run(run_probe(cfg, cases, config_path=str(config)))
        else:
            with Progress(TextColumn("[progress.description]{task.description}"), BarColumn(),
                          MofNCompleteColumn(), TimeElapsedColumn(), console=console, transient=True) as prog:
                task = prog.add_task("attacking", total=total)
                result = asyncio.run(
                    run_probe(cfg, cases, config_path=str(config), progress=lambda n: prog.advance(task, n))
                )
    except ConfigError as e:
        raise _fail(str(e)) from e
    except secrets.MissingSecretError as e:
        raise _fail(str(e.args[0])) from e
    except OSError as e:
        raise _fail(f"run failed: {e}") from e

    if baseline_rates is not None and baseline_path is not None:
        result.baseline_path = str(baseline_path)
        result.regressions = compare(result, baseline_rates, cfg.run.baseline_tolerance)
    result.evaluate()

    out_dir = output_dir or cfg.resolve_path(cfg.reports.output_dir)
    written = write_reports(result, out_dir, formats)
    print_report(result, console, top=top)
    for fmt, p in written.items():
        console.print(f"  {fmt:<9} {p}", style="dim", soft_wrap=True)
    if save_baseline_to is not None:
        save_baseline(result, save_baseline_to)
        console.print(f"Baseline saved to {save_baseline_to}")

    if result.aborted:
        err.print(f"error: run stopped early ({result.abort_reason}); results are partial")
        raise typer.Exit(EXIT_ERROR)
    if result.summary.tested and result.summary.attempts == 0:
        err.print("error: every attempt failed; check that the target is reachable")
        raise typer.Exit(EXIT_ERROR)
    raise typer.Exit(EXIT_OK if result.passed else EXIT_FAIL)


# --------------------------------------------------------------------------- compare


@app.command("compare")
def compare_cmd(
    results: list[Path] = typer.Argument(..., help="Two or more results.json files."),
    label: list[str] = typer.Option([], "--label", "-l", help="Name for each file, in order (default: file name)."),
    markdown_out: bool = typer.Option(False, "--markdown", help="Print Markdown instead of tables."),
    output: Optional[Path] = typer.Option(None, "--output", "-o", help="Also write the Markdown to this file."),
) -> None:
    """Compare several runs side by side, e.g. the same agent on different models."""
    from .reports.compare import comparison_markdown, print_comparison

    if len(results) < 2:
        raise _fail("give at least two results files")
    if label and len(label) != len(results):
        raise _fail("give one --label per results file")
    runs = []
    for i, path in enumerate(results):
        try:
            run = load_result(path)
        except BaselineError as e:
            raise _fail(str(e)) from e
        name = label[i] if label else (path.stem if path.stem != "results" else path.parent.name)
        runs.append((name, run))
    md = comparison_markdown(runs)
    if markdown_out:
        console.out(md, end="", highlight=False)
    else:
        print_comparison(runs, console)
    if output is not None:
        output.write_text(md, encoding="utf-8")
        console.print(f"Wrote {output}", style="dim")


# --------------------------------------------------------------------------- serve


@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Interface to listen on."),
    port: int = typer.Option(8080, "--port", "-p", help="Port to listen on."),
    public: bool = typer.Option(False, "--public", help="Hosted mode: anyone may use it, but every target "
                                "must be on the public internet and its owner must verify the domain."),
    public_url: Optional[str] = typer.Option(None, "--public-url", help="The URL people reach this server at "
                                             "(hosted mode). Also used as the canary address agents can fetch."),
    open_browser: bool = typer.Option(True, "--open/--no-open", help="Open the page in your browser."),
) -> None:
    """Start the web app: paste an agent's URL, check the connection, run attacks, read the report."""
    try:
        import uvicorn

        from .web.server import create_app
    except ImportError as e:
        raise _fail("the web app needs: pip install 'injectprobe[web]'") from e
    from .config import is_local_host

    if public and not public_url:
        raise _fail("--public needs --public-url (the address people use to reach this server)")
    if not public and not is_local_host(host):
        raise _fail("local mode only listens on localhost; use --public to host it for others")
    url = f"http://{host}:{port}" if not public else public_url
    console.print(f"injectprobe web app ({'hosted' if public else 'local'} mode) at [bold]{url}[/]")
    if not public:
        console.print(AUTH_NOTICE, style="dim")
        if open_browser:
            import threading
            import webbrowser

            threading.Timer(1.0, lambda: webbrowser.open(url)).start()
    web_app = create_app(public=public, public_url=public_url, port=port)
    uvicorn.run(web_app, host=host, port=port, log_level="warning")


# --------------------------------------------------------------------------- report


@app.command()
def report(
    results: Path = typer.Argument(..., help="A results.json written by `injectprobe run`."),
    report_format: list[str] = typer.Option(["markdown"], "--format", "-f",
                                            help="terminal, json, junit, sarif or markdown (repeatable)."),
    output: Optional[Path] = typer.Option(None, "--output", "-o",
                                          help="Output file (one format) or directory (several). Default: stdout."),
) -> None:
    """Turn a saved results file into another format."""
    try:
        result = load_result(results)
    except BaselineError as e:
        raise _fail(str(e)) from e
    for f in report_format:
        if f != "terminal" and f not in FILE_FORMATS:
            raise _fail(f"unknown format {f!r}")
    file_formats = [f for f in report_format if f != "terminal"]
    if "terminal" in report_format:
        print_report(result, console)
    if not file_formats:
        return
    if output is None:
        for f in file_formats:
            console.out(render(result, f), end="", highlight=False)
    elif len(file_formats) == 1 and output.suffix:
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(render(result, file_formats[0]), encoding="utf-8")
        console.print(f"Wrote {output}")
    else:
        for p in write_reports(result, output, file_formats).values():
            console.print(f"Wrote {p}")


# --------------------------------------------------------------------------- diff


@app.command("diff")
def diff_cmd(
    old: Path = typer.Argument(..., help="Older results.json or baseline file."),
    new: Path = typer.Argument(..., help="Newer results.json."),
    tolerance: float = typer.Option(0.0, "--tolerance", min=0, max=1, help="Ignore rate increases up to this."),
    markdown_out: bool = typer.Option(False, "--markdown", help="Print Markdown instead of tables."),
) -> None:
    """Compare two result files and show regressions. Exits 1 if anything regressed."""
    try:
        old_rates = load_rates(old)
        new_result = load_result(new)
        old_rate = 0.0
        try:
            old_rate = load_result(old).summary.success_rate
        except BaselineError:
            pass
    except BaselineError as e:
        raise _fail(str(e)) from e
    rep = diff(old_rates, new_result, tolerance, old_rate=old_rate)
    if markdown_out:
        console.out(diff_markdown(rep), end="", highlight=False)
    else:
        print_diff(rep, console)
    raise typer.Exit(EXIT_FAIL if rep.regressions else EXIT_OK)


__all__ = ["app"]
