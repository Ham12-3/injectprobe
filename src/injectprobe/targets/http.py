"""Generic HTTP endpoint adapter.

The request body comes from ``request_template``. String values may contain:

* ``{{message}}``   the latest user message
* ``{{context}}``   untrusted documents / tool results rendered as one text block
* a value that is exactly ``"{{history}}"`` (or ``"{{messages}}"``) is replaced by
  the conversation as ``[{"role", "content"}, ...]``
* a value that is exactly ``"{{documents}}"`` is replaced by
  ``[{"kind", "title", "content"}, ...]``

If the template has neither ``{{context}}`` nor ``{{documents}}``, indirect
content is placed above the user message, the way many apps do it.
"""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import httpx

from .. import secrets
from ..config import ConfigError, HttpTargetConfig
from ..jsonpath import JsonPathError, find, parse
from ..models import TargetInfo, TargetRequest, TargetResponse, ToolCall
from .base import Target, TargetError, context_to_text, flatten_last_turn

RETRYABLE_STATUS = {408, 409, 425, 429}


def _uses_context(template: Any) -> bool:
    blob = json.dumps(template)
    return "{{context}}" in blob or "{{documents}}" in blob


def build_body(template: Any, request: TargetRequest) -> Any:
    uses_context = _uses_context(template)
    message = (request.messages[-1].content if request.messages else "") if uses_context else flatten_last_turn(request)
    history = [m.model_dump() for m in request.messages]
    if history and not uses_context:
        history[-1]["content"] = message  # indirect content rides along with the last user turn
    documents = [c.model_dump(mode="json") for c in request.context]
    context = context_to_text(request.context)

    def walk(node: Any) -> Any:
        if isinstance(node, dict):
            return {k: walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [walk(v) for v in node]
        if isinstance(node, str):
            stripped = node.strip()
            if stripped in ("{{history}}", "{{messages}}"):
                return history
            if stripped == "{{documents}}":
                return documents
            return node.replace("{{message}}", message).replace("{{context}}", context)
        return node

    return walk(template)


def parse_tool_calls(value: Any) -> list[ToolCall]:
    calls: list[ToolCall] = []
    if not isinstance(value, list):
        return calls
    for item in value:
        if not isinstance(item, dict):
            continue
        fn = item.get("function") if isinstance(item.get("function"), dict) else item
        name = fn.get("name")
        args = fn.get("arguments", fn.get("input", {}))
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {"raw": args}
        if not isinstance(args, dict):
            args = {"value": args}
        if name:
            calls.append(ToolCall(name=str(name), arguments=args))
    return calls


class HttpTarget(Target):
    kind = "http"

    def __init__(self, cfg: HttpTargetConfig, timeout: float = 30.0, transport: httpx.AsyncBaseTransport | None = None):
        self.cfg = cfg
        self.timeout = timeout
        self.transport = transport
        self._client: httpx.AsyncClient | None = None
        try:
            parse(cfg.response_path)
            if cfg.tool_calls_path:
                parse(cfg.tool_calls_path)
        except JsonPathError as e:
            raise ConfigError(str(e)) from e

    def describe(self) -> TargetInfo:
        parts = urlsplit(self.cfg.url)
        return TargetInfo(type="http", endpoint=urlunsplit((parts.scheme, parts.netloc.split("@")[-1], parts.path, "", "")))

    async def start(self) -> None:
        try:
            self._url = secrets.expand(self.cfg.url)
            self._headers = {k: secrets.expand(v) for k, v in self.cfg.headers.items()}
        except secrets.MissingSecretError as e:
            raise ConfigError(f"http target: {e.args[0]}") from e
        self._client = httpx.AsyncClient(timeout=self.timeout, transport=self.transport, follow_redirects=False)

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def send(self, request: TargetRequest) -> TargetResponse:
        if self._client is None:
            await self.start()
        assert self._client is not None
        body = build_body(self.cfg.request_template, request)
        try:
            if self.cfg.method == "GET":
                params = body if isinstance(body, dict) else {"q": json.dumps(body)}
                resp = await self._client.get(self._url, params=params, headers=self._headers)
            else:
                resp = await self._client.request(self.cfg.method, self._url, json=body, headers=self._headers)
        except httpx.TimeoutException as e:
            raise TargetError(f"timeout: {e}", retryable=True) from e
        except httpx.TransportError as e:
            raise TargetError(f"connection error: {e}", retryable=True) from e

        if resp.status_code >= 500 or resp.status_code in RETRYABLE_STATUS:
            raise TargetError(f"HTTP {resp.status_code}", retryable=True)
        if resp.status_code >= 400:
            raise TargetError(f"HTTP {resp.status_code}: {resp.text[:200]}")

        try:
            data = resp.json()
        except ValueError:
            if self.cfg.response_path.strip() == "$":
                return TargetResponse(text=resp.text)
            raise TargetError("response is not JSON") from None
        try:
            reply = find(data, self.cfg.response_path)
        except KeyError:
            raise TargetError(f"response_path {self.cfg.response_path} not found in response") from None
        text = reply if isinstance(reply, str) else json.dumps(reply)
        calls: list[ToolCall] = []
        if self.cfg.tool_calls_path:
            try:
                calls = parse_tool_calls(find(data, self.cfg.tool_calls_path))
            except KeyError:
                calls = []
        return TargetResponse(text=text, tool_calls=calls)
