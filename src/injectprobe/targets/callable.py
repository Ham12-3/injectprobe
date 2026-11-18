"""In-process Python callable adapter for testing agents without a server.

``import_path`` points at ``package.module:function``. The function takes a
string and returns a string (sync or async). It may also return a dict
``{"text": ..., "tool_calls": [{"name", "arguments"}]}`` so tool calls can be
checked. Indirect content is placed above the user message; for multi-turn
attacks the function receives the whole transcript so far.
"""

from __future__ import annotations

import asyncio
import importlib
import inspect
import sys
from pathlib import Path
from typing import Any, Callable

from ..config import CallableTargetConfig, ConfigError
from ..models import TargetInfo, TargetRequest, TargetResponse
from .base import Target, TargetError, flatten_last_turn
from .http import parse_tool_calls


def load_callable(import_path: str, python_path: list[str] = (), base_dir: Path | None = None) -> Callable[..., Any]:
    for p in python_path:
        path = Path(p)
        if not path.is_absolute() and base_dir is not None:
            path = base_dir / path
        s = str(path.resolve())
        if s not in sys.path:
            sys.path.insert(0, s)
    if ":" in import_path:
        module_name, attr = import_path.split(":", 1)
    elif "." in import_path:
        module_name, attr = import_path.rsplit(".", 1)
    else:
        raise ConfigError(f"import_path must look like 'package.module:function', got {import_path!r}")
    try:
        module = importlib.import_module(module_name)
    except ImportError as e:
        raise ConfigError(f"cannot import {module_name!r}: {e}") from e
    obj: Any = module
    for part in attr.split("."):
        try:
            obj = getattr(obj, part)
        except AttributeError as e:
            raise ConfigError(f"{module_name!r} has no attribute {attr!r}") from e
    if not callable(obj):
        raise ConfigError(f"{import_path} is not callable")
    return obj


def transcript(request: TargetRequest) -> str:
    if len(request.messages) <= 1:
        return flatten_last_turn(request)
    lines = []
    for m in request.messages[:-1]:
        lines.append(f"{'User' if m.role == 'user' else 'Assistant'}: {m.content}")
    lines.append(f"User: {flatten_last_turn(request)}")
    return "\n".join(lines)


class CallableTarget(Target):
    kind = "callable"

    def __init__(self, cfg: CallableTargetConfig, base_dir: Path | None = None, fn: Callable[..., Any] | None = None):
        self.cfg = cfg
        self.fn = fn or load_callable(cfg.import_path, cfg.python_path, base_dir)

    def describe(self) -> TargetInfo:
        return TargetInfo(type="callable", endpoint=self.cfg.import_path)

    async def send(self, request: TargetRequest) -> TargetResponse:
        prompt = transcript(request)
        try:
            if inspect.iscoroutinefunction(self.fn):
                out = await self.fn(prompt)
            else:
                out = await asyncio.to_thread(self.fn, prompt)
                if inspect.isawaitable(out):
                    out = await out
        except Exception as e:  # noqa: BLE001 - the agent's own failure
            raise TargetError(f"callable raised {type(e).__name__}: {e}") from e
        if isinstance(out, TargetResponse):
            return out
        if isinstance(out, dict):
            text = out.get("text", out.get("reply", ""))
            return TargetResponse(text=str(text or ""), tool_calls=parse_tool_calls(out.get("tool_calls", [])))
        if out is None:
            return TargetResponse(text="")
        return TargetResponse(text=str(out))
