"""AcmeAssist with basic defences: isolated untrusted content, an input filter,
an output filter, secret redaction and an allow-listed send_email.

Run from the repo root:  python -m examples.hardened_bot   (serves http://127.0.0.1:8001)
"""

from examples.botkit import HARDENED, create_app
from examples.botkit.app import ChatRequest, respond

POLICY = HARDENED
app = create_app(POLICY)


async def handle(message: str) -> dict:
    """In-process entry point for injectprobe's callable target."""
    resp = await respond(ChatRequest(message=message), POLICY)
    return {"text": resp.reply, "tool_calls": [c.model_dump() for c in resp.tool_calls]}
