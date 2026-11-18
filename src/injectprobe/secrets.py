"""Environment-variable secret resolution and redaction.

Keys are only ever read from environment variables. Every resolved value is
registered here so it can be scrubbed from any text that reaches a log,
terminal or report.
"""

from __future__ import annotations

import os
import re

_ENV_REF = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
_registered: set[str] = set()
REDACTED = "***REDACTED***"


class MissingSecretError(KeyError):
    pass


def register(value: str | None) -> None:
    if value and len(value) >= 4:
        _registered.add(value)


def get_env(name: str, required: bool = True) -> str | None:
    value = os.environ.get(name)
    if value is None or value == "":
        if required:
            raise MissingSecretError(f"environment variable {name} is not set")
        return None
    register(value)
    return value


def expand(text: str) -> str:
    """Replace ``${VAR}`` references with environment values (registered as secrets)."""

    def sub(m: re.Match[str]) -> str:
        return get_env(m.group(1)) or ""

    return _ENV_REF.sub(sub, text)


def redact(text: str | None) -> str:
    if not text:
        return text or ""
    for value in sorted(_registered, key=len, reverse=True):
        text = text.replace(value, REDACTED)
    # Also scrub obvious bearer tokens and api keys that were never registered.
    text = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._\-]{12,}", r"\1" + REDACTED, text)
    text = re.sub(r"\b(sk-[A-Za-z0-9_\-]{12,})", REDACTED, text)
    return text


def clear() -> None:
    """Forget registered secrets (used by tests)."""
    _registered.clear()
