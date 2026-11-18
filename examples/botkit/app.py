"""FastAPI app factory and the request handling shared by both demo bots.

POST /chat
    {"message": str, "history": [{"role", "content"}], "documents": [{"kind", "title", "content"}]}
 -> {"reply": str, "tool_calls": [{"name", "arguments"}]}
GET /outbox   emails the bot "sent" (nothing leaves the machine)
GET /health
"""

from __future__ import annotations

import os
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI
from pydantic import BaseModel, Field

from . import llm
from .policy import HARDENED, REFUSAL, VULNERABLE, Policy, email_allowed, filter_output, looks_like_injection, wrap_untrusted
from .simulator import _URL, simulate

LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


class Turn(BaseModel):
    role: str
    content: str


class Document(BaseModel):
    kind: str = "document"
    title: str = "document"
    content: str


class ChatRequest(BaseModel):
    message: str
    history: list[Turn] = Field(default_factory=list)
    documents: list[Document] = Field(default_factory=list)


class ToolCallOut(BaseModel):
    name: str
    arguments: dict[str, Any]


class ChatResponse(BaseModel):
    reply: str
    tool_calls: list[ToolCallOut] = Field(default_factory=list)


async def _link_previews(text: str) -> None:
    """The vulnerable bot 'unfurls' links in its replies. Only local URLs are fetched."""
    for url in _URL.findall(text):
        if urlparse(url).hostname in LOCAL_HOSTS:
            try:
                async with httpx.AsyncClient(timeout=2) as client:
                    await client.get(url)
            except httpx.HTTPError:
                pass


async def respond(req: ChatRequest, policy: Policy, outbox: list[dict] | None = None) -> ChatResponse:
    outbox = outbox if outbox is not None else []
    user_turns = [t.content for t in req.history if t.role == "user"] + [req.message]

    if policy.input_filter and any(looks_like_injection(t) for t in user_turns):
        return ChatResponse(reply=REFUSAL)

    tool_calls: list[ToolCallOut] = [
        ToolCallOut(name="read_document", arguments={"title": d.title}) for d in req.documents
    ]
    backend = os.environ.get("BOT_LLM", "").lower()
    if backend in ("openai", "anthropic"):
        reply, emails = await llm.chat(backend, policy, req)
    else:
        docs_text = "\n\n".join(d.content for d in req.documents)
        instructions = "\n".join(user_turns)
        if not policy.isolate_untrusted:
            instructions = f"{docs_text}\n{instructions}"  # documents are read as if they were instructions
        sim = simulate(
            instructions,
            req.message,
            policy.system_prompt,
            data_text=docs_text,
            data_title=req.documents[0].title if req.documents else "",
        )
        reply, emails = sim.reply, sim.emails
        if policy.link_previews:
            for url in sim.fetches:
                await _link_previews(url)

    for address in emails:
        if policy.tool_guard and not email_allowed(address, policy):
            reply += "\n\n(I can only send email to acme.example.com addresses.)"
            continue
        outbox.append({"to": address, "body": reply[:200]})
        tool_calls.append(ToolCallOut(name="send_email", arguments={"to": address, "subject": "Requested", "body": "ok"}))

    if policy.output_filter:
        reply = filter_output(reply, policy)
    if policy.link_previews:
        await _link_previews(reply)
    return ChatResponse(reply=reply, tool_calls=tool_calls)


def create_app(policy: Policy) -> FastAPI:
    app = FastAPI(title=f"AcmeAssist ({policy.name})", description="Demo target for injectprobe.")
    outbox: list[dict] = []

    @app.post("/chat", response_model=ChatResponse)
    async def chat(req: ChatRequest) -> ChatResponse:
        return await respond(req, policy, outbox)

    @app.get("/outbox")
    async def get_outbox() -> list[dict]:
        return outbox

    @app.get("/health")
    async def health() -> dict:
        return {"ok": True, "policy": policy.name, "backend": os.environ.get("BOT_LLM") or "simulator"}

    return app


__all__ = ["HARDENED", "VULNERABLE", "create_app", "respond", "ChatRequest", "wrap_untrusted"]
