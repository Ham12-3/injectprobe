"""Minimal ``.env`` loader, so API keys can live in a git-ignored file.

Lines look like ``KEY=value``, ``export KEY=value`` or ``KEY="quoted value"``;
``#`` starts a comment. Variables already set in the environment win, so CI
secrets and shell exports are never overridden. Every loaded value is
registered for redaction. Set ``INJECTPROBE_NO_DOTENV=1`` to turn loading off.
"""

from __future__ import annotations

import os
import re
from pathlib import Path

from . import secrets

_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")


def parse(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        m = _LINE.match(raw)
        if not m:
            continue
        key, value = m.group(1), m.group(2)
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        else:
            value = re.split(r"\s+#", value, maxsplit=1)[0].strip()
        values[key] = value
    return values


def load_dotenv(path: str | Path = ".env", override: bool = False) -> list[str]:
    """Load ``path`` into ``os.environ``. Returns the names that were set (never the values)."""
    if os.environ.get("INJECTPROBE_NO_DOTENV"):
        return []
    p = Path(path)
    if not p.is_file():
        return []
    loaded = []
    for key, value in parse(p.read_text(encoding="utf-8-sig")).items():
        if not value:
            continue  # an empty placeholder must not mask a real variable
        if override or key not in os.environ:
            os.environ[key] = value
            loaded.append(key)
        secrets.register(value)
    return loaded
