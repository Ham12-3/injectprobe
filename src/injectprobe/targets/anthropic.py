"""Anthropic Messages API adapter, using the official ``anthropic`` SDK.

Install with ``pip install 'injectprobe[anthropic]'``. The SDK's own retries
are turned off so injectprobe's run controls (retries, rate limit, budget)
stay in charge. Tool calls are recorded, never executed.

Server-side refusal fallbacks are deliberately not enabled: a fallback would
answer with a different model than the one under test. Mirror your app's
settings with ``effort`` and ``extra_body`` if you need to.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .. import secrets
from ..config import AnthropicTargetConfig, ConfigError
from ..models import TargetInfo, TargetRequest, TargetResponse, ToolCall
from ._chat import last_user_text, split_context, system_prompt, tool_defs, tool_name
from .base import Target, TargetError


def _sdk():
    try:
        import anthropic
    except ImportError as e:  # pragma: no cover - depends on environment
        raise ConfigError(
            "the anthropic target needs the Anthropic SDK: pip install 'injectprobe[anthropic]'"
        ) from e
    return anthropic


def classify_error(exc: Exception) -> TargetError | None:
    """Map SDK exceptions to TargetError. Returns None for non-SDK exceptions."""
    try:
        anthropic = _sdk()
    except ConfigError:
        return None
    if isinstance(exc, anthropic.APITimeoutError):
        return TargetError("timeout", retryable=True)
    if isinstance(exc, anthropic.APIConnectionError):
        return TargetError(f"connection error: {exc}", retryable=True)
    if isinstance(exc, anthropic.APIStatusError):
        code = exc.status_code
        retryable = code in (408, 409, 429) or code >= 500
        return TargetError(f"HTTP {code}: {secrets.redact(str(exc))[:300]}", retryable=retryable)
    return None


class AnthropicTarget(Target):
    kind = "anthropic"

    def __init__(
        self,
        cfg: AnthropicTargetConfig,
        timeout: float = 30.0,
        base_dir: Path | None = None,
        client: Any = None,
    ):
        self.cfg = cfg
        self.timeout = timeout
        self.base_dir = base_dir
        self.plants_system_canary = cfg.plant_system_canary
        self._client = client
        self._owns_client = client is None
        cfg.resolved_system_prompt(base_dir)

    def describe(self) -> TargetInfo:
        return TargetInfo(type="anthropic", endpoint=f"{self.cfg.base_url.rstrip('/')} ({self.cfg.model})")

    async def start(self) -> None:
        if self._client is not None:
            return
        anthropic = _sdk()
        try:
            key = secrets.get_env(self.cfg.api_key_env)
        except secrets.MissingSecretError as e:
            raise ConfigError(f"anthropic target: {e.args[0]}") from e
        self._client = anthropic.AsyncAnthropic(
            api_key=key, base_url=self.cfg.base_url, timeout=self.timeout, max_retries=0
        )

    async def close(self) -> None:
        if self._owns_client and self._client is not None:
            await self._client.close()
            self._client = None

    def build_params(self, request: TargetRequest) -> dict[str, Any]:
        tool_results, inline = split_context(request, self.cfg.tool_results_as)
        messages: list[dict[str, Any]] = [{"role": m.role, "content": m.content} for m in request.messages[:-1]]
        messages.append({"role": "user", "content": last_user_text(request, inline)})
        if tool_results:
            uses = [
                {"type": "tool_use", "id": f"toolu_ip{i:04d}", "name": tool_name(c.title), "input": {}}
                for i, c in enumerate(tool_results)
            ]
            messages.append({"role": "assistant", "content": uses})
            # All tool results go back in a single user message.
            messages.append({
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": f"toolu_ip{i:04d}", "content": c.content}
                    for i, c in enumerate(tool_results)
                ],
            })
        params: dict[str, Any] = {
            "model": self.cfg.model,
            "max_tokens": self.cfg.max_tokens,
            "messages": messages,
        }
        system = system_prompt(self.cfg, self.base_dir, request.canary)
        if system:
            params["system"] = system
        tools = tool_defs(self.cfg, tool_results)
        if tools:
            params["tools"] = [{"name": t.name, "description": t.description, "input_schema": t.parameters} for t in tools]
        if self.cfg.effort:
            params["output_config"] = {"effort": self.cfg.effort}
        if self.cfg.extra_body:
            params["extra_body"] = dict(self.cfg.extra_body)
        return params

    async def send(self, request: TargetRequest) -> TargetResponse:
        if self._client is None:
            await self.start()
        try:
            msg = await self._client.messages.create(**self.build_params(request))
        except Exception as e:  # noqa: BLE001
            mapped = classify_error(e)
            if mapped is not None:
                raise mapped from e
            raise
        texts: list[str] = []
        calls: list[ToolCall] = []
        for block in msg.content:
            btype = getattr(block, "type", None)
            if btype == "text":
                texts.append(block.text)
            elif btype == "tool_use":
                args = block.input if isinstance(block.input, dict) else {"value": block.input}
                calls.append(ToolCall(name=block.name, arguments=args))
        text = "\n".join(texts)
        if not text and getattr(msg, "stop_reason", None) == "refusal":
            text = "[refused by the model]"
        usage = getattr(msg, "usage", None)
        return TargetResponse(
            text=text,
            tool_calls=calls,
            input_tokens=getattr(usage, "input_tokens", None),
            output_tokens=getattr(usage, "output_tokens", None),
        )
