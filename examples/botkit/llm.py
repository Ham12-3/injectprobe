"""Real-model backends for the demo bots (BOT_LLM=openai or BOT_LLM=anthropic).

Both run a small tool loop with the fake ``read_document`` and ``send_email``
tools. ``send_email`` only records the request; the caller applies the
policy's tool guard before anything lands in the outbox.
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Any

import httpx

from .policy import Policy, wrap_untrusted

if TYPE_CHECKING:
    from .app import ChatRequest

MAX_STEPS = 4

TOOLS = [
    {
        "name": "read_document",
        "description": "Read a document the user attached, by title.",
        "parameters": {"type": "object", "properties": {"title": {"type": "string"}}, "required": ["title"]},
    },
    {
        "name": "send_email",
        "description": "Send an email on behalf of the user.",
        "parameters": {
            "type": "object",
            "properties": {"to": {"type": "string"}, "subject": {"type": "string"}, "body": {"type": "string"}},
            "required": ["to", "body"],
        },
    },
]


def _user_prompt(req: "ChatRequest") -> str:
    if not req.documents:
        return req.message
    titles = ", ".join(d.title for d in req.documents)
    return f"{req.message}\n\n(Attached documents: {titles}. Use read_document to read them.)"


def _run_tool(name: str, args: dict, req: "ChatRequest", policy: Policy, emails: list[str]) -> str:
    if name == "read_document":
        doc = next((d for d in req.documents if d.title == args.get("title")), req.documents[0] if req.documents else None)
        if doc is None:
            return "No such document."
        return wrap_untrusted(doc.title, doc.content) if policy.isolate_untrusted else doc.content
    if name == "send_email":
        emails.append(str(args.get("to", "")))
        return "Email queued."
    return "Unknown tool."


async def chat(backend: str, policy: Policy, req: "ChatRequest") -> tuple[str, list[str]]:
    if backend == "anthropic":
        return await _anthropic(policy, req)
    return await _openai(policy, req)


async def _openai(policy: Policy, req: "ChatRequest") -> tuple[str, list[str]]:
    base = os.environ.get("BOT_BASE_URL", "https://api.openai.com/v1").rstrip("/")
    model = os.environ.get("BOT_MODEL", "gpt-4o-mini")
    key = os.environ.get("OPENAI_API_KEY", "")
    messages: list[dict[str, Any]] = [{"role": "system", "content": policy.system_prompt}]
    messages += [{"role": t.role, "content": t.content} for t in req.history]
    messages.append({"role": "user", "content": _user_prompt(req)})
    tools = [{"type": "function", "function": t} for t in TOOLS]
    emails: list[str] = []
    async with httpx.AsyncClient(timeout=60, headers={"Authorization": f"Bearer {key}"} if key else {}) as client:
        for _ in range(MAX_STEPS):
            r = await client.post(f"{base}/chat/completions", json={"model": model, "messages": messages, "tools": tools})
            r.raise_for_status()
            msg = r.json()["choices"][0]["message"]
            calls = msg.get("tool_calls") or []
            if not calls:
                return msg.get("content") or "", emails
            messages.append({"role": "assistant", "content": msg.get("content"), "tool_calls": calls})
            for c in calls:
                args = json.loads(c["function"].get("arguments") or "{}")
                out = _run_tool(c["function"]["name"], args, req, policy, emails)
                messages.append({"role": "tool", "tool_call_id": c["id"], "content": out})
    return "(stopped after too many tool calls)", emails


async def _anthropic(policy: Policy, req: "ChatRequest") -> tuple[str, list[str]]:
    import anthropic

    client = anthropic.AsyncAnthropic()
    model = os.environ.get("BOT_MODEL", "claude-opus-5-5")
    messages: list[dict[str, Any]] = [{"role": t.role, "content": t.content} for t in req.history]
    messages.append({"role": "user", "content": _user_prompt(req)})
    tools = [{"name": t["name"], "description": t["description"], "input_schema": t["parameters"]} for t in TOOLS]
    emails: list[str] = []
    try:
        for _ in range(MAX_STEPS):
            msg = await client.messages.create(
                model=model, max_tokens=16000, system=policy.system_prompt, messages=messages, tools=tools
            )
            if msg.stop_reason == "refusal":
                return "I can't help with that.", emails
            uses = [b for b in msg.content if b.type == "tool_use"]
            if msg.stop_reason != "tool_use" or not uses:
                return "".join(b.text for b in msg.content if b.type == "text"), emails
            messages.append({"role": "assistant", "content": msg.content})
            messages.append({
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": b.id, "content": _run_tool(b.name, b.input, req, policy, emails)}
                    for b in uses
                ],
            })
    finally:
        await client.close()
    return "(stopped after too many tool calls)", emails
