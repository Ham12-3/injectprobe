from __future__ import annotations

from ..models import RunResult


def render(result: RunResult) -> str:
    """Full results, including every attempt. Loadable with ``RunResult.model_validate_json``."""
    return result.model_dump_json(indent=2) + "\n"
