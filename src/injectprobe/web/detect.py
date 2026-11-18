"""Work out how to talk to an agent's API by sending a few harmless messages."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

import httpx

from ..jsonpath import find

PROBE_TEXT = "Hello! This is a connection test from injectprobe. Please reply with a short greeting."
BODY_KEYS = ["message", "input", "prompt", "query", "question", "text"]
REPLY_PATHS = [
    "$.reply", "$.response", "$.answer", "$.output", "$.text", "$.message", "$.content", "$.result",
    "$.completion", "$.output_text", "$.data.reply", "$.data.response", "$.data.text", "$.data.answer",
    "$.data.output", "$.data.message", "$.choices[0].message.content", "$.message.content",
]
TOOL_PATHS = ["$.tool_calls", "$.data.tool_calls", "$.choices[0].message.tool_calls"]


@dataclass
class Detection:
    ok: bool
    format: str = "simple"
    message_field: str = "message"
    response_path: str = "$.reply"
    tool_calls_path: str | None = None
    sample_reply: str = ""
    notes: list[str] = field(default_factory=list)


def find_reply(data: Any) -> tuple[str, str] | None:
    for path in REPLY_PATHS:
        try:
            value = find(data, path)
        except KeyError:
            continue
        if isinstance(value, str) and value.strip():
            return path, value
    return None


def find_tool_path(data: Any) -> str | None:
    for path in TOOL_PATHS:
        try:
            if isinstance(find(data, path), list):
                return path
        except KeyError:
            continue
    return None


async def detect(
    url: str,
    headers: dict[str, str],
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    model: str | None = None,
) -> Detection:
    """Try common request shapes, at most 7 requests. Stops early on auth errors."""
    notes: list[str] = []
    attempts: list[tuple[str, dict[str, Any]]] = [(k, {k: PROBE_TEXT}) for k in BODY_KEYS]
    openai_body: dict[str, Any] = {"messages": [{"role": "user", "content": PROBE_TEXT}]}
    if model:
        openai_body["model"] = model
    if url.rstrip("/").endswith("/chat/completions"):
        attempts.insert(0, ("@openai", openai_body))
    else:
        attempts.append(("@openai", openai_body))

    async with httpx.AsyncClient(timeout=20, transport=transport, follow_redirects=False) as client:
        for key, body in attempts:
            try:
                resp = await client.post(url, json=body, headers=headers)
            except httpx.HTTPError as e:
                return Detection(ok=False, notes=[f"Could not reach the agent: {type(e).__name__}"])
            if resp.status_code in (401, 403):
                return Detection(ok=False, notes=[f"The agent answered HTTP {resp.status_code}: add or check the API key."])
            if resp.status_code == 404:
                return Detection(ok=False, notes=["HTTP 404: check the URL points at the chat endpoint, not the home page."])
            if resp.status_code >= 400:
                notes.append(f"{key}: HTTP {resp.status_code}")
                continue
            try:
                data = resp.json()
            except (json.JSONDecodeError, ValueError):
                if resp.text.strip():
                    return Detection(ok=True, message_field=key if key != "@openai" else "message",
                                     response_path="$", sample_reply=resp.text[:500],
                                     notes=["The agent answers with plain text."])
                continue
            hit = find_reply(data)
            if hit is None:
                notes.append(f"{key}: reply not found in {list(data)[:6] if isinstance(data, dict) else type(data).__name__}")
                continue
            path, reply = hit
            fmt = "openai" if key == "@openai" else "simple"
            return Detection(ok=True, format=fmt, message_field="message" if fmt == "openai" else key,
                             response_path=path, tool_calls_path=find_tool_path(data),
                             sample_reply=reply[:500], notes=notes)
    notes.append("No common format matched. Use the Custom format and set the fields yourself.")
    return Detection(ok=False, notes=notes)
