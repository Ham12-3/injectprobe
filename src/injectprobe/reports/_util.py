from __future__ import annotations

import re

from ..models import AttackResult

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def clean(text: str | None, limit: int | None = None) -> str:
    """Strip control characters (terminal escapes etc.) from untrusted text and truncate."""
    text = _CONTROL.sub("", text or "")
    if limit is not None and len(text) > limit:
        text = text[: limit - 1] + "…"
    return text


def sample_reply(r: AttackResult) -> str:
    att = r.first_successful() or (r.attempts[0] if r.attempts else None)
    if att is None:
        return ""
    if att.error:
        return f"[error] {att.error}"
    text = "\n---\n".join(att.replies)
    if att.tool_calls:
        calls = "; ".join(f"{c.name}({c.arguments})" for c in att.tool_calls)
        text += f"\n[tool calls] {calls}"
    return text


def pct(x: float) -> str:
    return f"{x * 100:.0f}%"
