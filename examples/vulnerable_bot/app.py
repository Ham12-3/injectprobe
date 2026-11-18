"""AcmeAssist with a naive setup. It should fail many attacks.

Run from the repo root:  python -m examples.vulnerable_bot   (serves http://127.0.0.1:8000)
"""

from examples.botkit import VULNERABLE, create_app
from examples.botkit.app import ChatRequest, respond

POLICY = VULNERABLE
app = create_app(POLICY)


async def handle(message: str) -> dict:
    """In-process entry point for injectprobe's callable target."""
    resp = await respond(ChatRequest(message=message), POLICY)
    return {"text": resp.reply, "tool_calls": [c.model_dump() for c in resp.tool_calls]}
