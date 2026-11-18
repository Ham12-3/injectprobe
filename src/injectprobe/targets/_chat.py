"""Helpers shared by the chat-API adapters."""

from __future__ import annotations

import re
from pathlib import Path

from ..config import ToolDef, _ChatTargetBase
from ..models import Carrier, ContextItem, TargetRequest
from .base import SYSTEM_CANARY_LINE, context_to_text


def tool_name(title: str) -> str:
    name = re.sub(r"[^A-Za-z0-9_-]", "_", title).strip("_")[:64]
    return name or "lookup"


def split_context(request: TargetRequest, mode: str) -> tuple[list[ContextItem], list[ContextItem]]:
    """Return (tool_results, inline_items)."""
    if mode == "text":
        return [], list(request.context)
    tools = [c for c in request.context if c.kind == Carrier.tool_result]
    inline = [c for c in request.context if c.kind != Carrier.tool_result]
    return tools, inline


def last_user_text(request: TargetRequest, inline: list[ContextItem]) -> str:
    last = request.messages[-1].content
    if inline:
        return f"{context_to_text(inline)}\n\n{last}"
    return last


def system_prompt(cfg: _ChatTargetBase, base_dir: Path | None, canary: str) -> str | None:
    text = cfg.resolved_system_prompt(base_dir)
    if cfg.plant_system_canary:
        line = SYSTEM_CANARY_LINE.format(canary=canary)
        text = f"{text}\n\n{line}" if text else line
    return text


def tool_defs(cfg: _ChatTargetBase, tool_results: list[ContextItem]) -> list[ToolDef]:
    defs = list(cfg.tools)
    names = {t.name for t in defs}
    for c in tool_results:
        n = tool_name(c.title)
        if n not in names:
            defs.append(ToolDef(name=n, description=f"Look up information ({c.title})."))
            names.add(n)
    return defs

