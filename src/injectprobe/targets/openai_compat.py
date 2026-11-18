"""OpenAI-compatible chat completions adapter (OpenAI, vLLM, Ollama, LM Studio, gateways...)."""

from __future__ import annotations

import json
from pathlib import Path

import httpx

from .. import secrets
from ..config import ConfigError, OpenAITargetConfig
from ..models import TargetInfo, TargetRequest, TargetResponse, ToolCall
from ._chat import last_user_text, split_context, system_prompt, tool_defs, tool_name
from .base import Target, TargetError


class OpenAITarget(Target):
    kind = "openai"

    def __init__(
        self,
        cfg: OpenAITargetConfig,
        timeout: float = 30.0,
        base_dir: Path | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ):
        self.cfg = cfg
        self.timeout = timeout
        self.base_dir = base_dir
        self.transport = transport
        self.plants_system_canary = cfg.plant_system_canary
        self._client: httpx.AsyncClient | None = None
        cfg.resolved_system_prompt(base_dir)  # fail fast on a missing prompt file

    def describe(self) -> TargetInfo:
        return TargetInfo(type="openai", endpoint=f"{self.cfg.base_url.rstrip('/')} ({self.cfg.model})")

    async def start(self) -> None:
        headers = {}
        if self.cfg.api_key_env:
            try:
                key = secrets.get_env(self.cfg.api_key_env)
            except secrets.MissingSecretError as e:
                raise ConfigError(f"openai target: {e.args[0]}") from e
            headers["Authorization"] = f"Bearer {key}"
        self._client = httpx.AsyncClient(timeout=self.timeout, headers=headers, transport=self.transport)

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def build_payload(self, request: TargetRequest) -> dict:
        tool_results, inline = split_context(request, self.cfg.tool_results_as)
        messages: list[dict] = []
        system = system_prompt(self.cfg, self.base_dir, request.canary)
        if system:
            messages.append({"role": "system", "content": system})
        for m in request.messages[:-1]:
            messages.append({"role": m.role, "content": m.content})
        messages.append({"role": "user", "content": last_user_text(request, inline)})
        if tool_results:
            calls = [
                {"id": f"call_{i}", "type": "function", "function": {"name": tool_name(c.title), "arguments": "{}"}}
                for i, c in enumerate(tool_results)
            ]
            messages.append({"role": "assistant", "content": None, "tool_calls": calls})
            for i, c in enumerate(tool_results):
                messages.append({"role": "tool", "tool_call_id": f"call_{i}", "content": c.content})
        payload: dict = {"model": self.cfg.model, "messages": messages, "max_tokens": self.cfg.max_tokens}
        tools = tool_defs(self.cfg, tool_results)
        if tools:
            payload["tools"] = [
                {"type": "function", "function": {"name": t.name, "description": t.description, "parameters": t.parameters}}
                for t in tools
            ]
        if self.cfg.temperature is not None:
            payload["temperature"] = self.cfg.temperature
        payload.update(self.cfg.extra_body)
        return payload

    async def send(self, request: TargetRequest) -> TargetResponse:
        if self._client is None:
            await self.start()
        assert self._client is not None
        url = f"{self.cfg.base_url.rstrip('/')}/chat/completions"
        try:
            resp = await self._client.post(url, json=self.build_payload(request))
        except httpx.TimeoutException as e:
            raise TargetError(f"timeout: {e}", retryable=True) from e
        except httpx.TransportError as e:
            raise TargetError(f"connection error: {e}", retryable=True) from e
        if resp.status_code == 429 or resp.status_code >= 500:
            raise TargetError(f"HTTP {resp.status_code}", retryable=True)
        if resp.status_code >= 400:
            raise TargetError(f"HTTP {resp.status_code}: {secrets.redact(resp.text[:300])}")
        try:
            data = resp.json()
            msg = data["choices"][0]["message"]
        except (ValueError, KeyError, IndexError) as e:
            raise TargetError(f"unexpected response shape: {e}") from e
        calls = []
        for tc in msg.get("tool_calls") or []:
            fn = tc.get("function", {})
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except json.JSONDecodeError:
                args = {"raw": fn.get("arguments")}
            calls.append(ToolCall(name=fn.get("name", ""), arguments=args if isinstance(args, dict) else {"value": args}))
        usage = data.get("usage") or {}
        return TargetResponse(
            text=msg.get("content") or "",
            tool_calls=calls,
            input_tokens=usage.get("prompt_tokens"),
            output_tokens=usage.get("completion_tokens"),
        )
