"""Report writers: terminal, JSON, JUnit XML, SARIF and Markdown."""

from __future__ import annotations

from pathlib import Path

from ..models import RunResult
from . import json_report, junit, markdown, sarif

FILE_FORMATS = {
    "json": ("results.json", json_report.render),
    "junit": ("junit.xml", junit.render),
    "sarif": ("results.sarif", sarif.render),
    "markdown": ("summary.md", markdown.render),
}


def render(result: RunResult, fmt: str) -> str:
    try:
        return FILE_FORMATS[fmt][1](result)
    except KeyError:
        raise ValueError(f"unknown report format {fmt!r}; use one of {', '.join(FILE_FORMATS)}") from None


def write_reports(result: RunResult, out_dir: str | Path, formats: list[str]) -> dict[str, Path]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    for fmt in formats:
        name, fn = FILE_FORMATS[fmt]
        p = out / name
        p.write_text(fn(result), encoding="utf-8")
        written[fmt] = p
    return written


__all__ = ["FILE_FORMATS", "render", "write_reports"]
