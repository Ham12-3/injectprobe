"""A tiny JSONPath subset: ``$``, ``.key``, ``['key']``, ``["key"]``, ``[n]`` and ``[*]``.

Enough to point at a reply inside a JSON response without an extra dependency.
"""

from __future__ import annotations

import re
from typing import Any

_TOKEN = re.compile(r"""\.([A-Za-z_][\w\-]*)|\.\*|\[(-?\d+)\]|\[\*\]|\['([^']*)'\]|\["([^"]*)"\]""")


class JsonPathError(ValueError):
    pass


_MISSING = object()


def parse(path: str) -> list[Any]:
    path = path.strip()
    if not path.startswith("$"):
        raise JsonPathError(f"JSONPath must start with '$': {path!r}")
    steps: list[Any] = []
    pos = 1
    while pos < len(path):
        m = _TOKEN.match(path, pos)
        if not m:
            raise JsonPathError(f"unsupported JSONPath syntax at {path[pos:]!r} in {path!r}")
        key, idx, sq, dq = m.groups()
        if key is not None:
            steps.append(key)
        elif idx is not None:
            steps.append(int(idx))
        elif sq is not None:
            steps.append(sq)
        elif dq is not None:
            steps.append(dq)
        else:
            steps.append("*")
        pos = m.end()
    return steps


def find(data: Any, path: str) -> Any:
    """Return the value at ``path``. ``[*]`` returns a list. Raises KeyError if missing."""
    current: list[Any] = [data]
    wildcard = False
    for step in parse(path):
        nxt: list[Any] = []
        for node in current:
            if step == "*":
                wildcard = True
                if isinstance(node, list):
                    nxt.extend(node)
                elif isinstance(node, dict):
                    nxt.extend(node.values())
            elif isinstance(step, int):
                if isinstance(node, list) and -len(node) <= step < len(node):
                    nxt.append(node[step])
            elif isinstance(node, dict) and step in node:
                nxt.append(node[step])
        current = nxt
        if not current:
            raise KeyError(path)
    return current if wildcard else current[0]
