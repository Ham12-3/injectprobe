"""Shared code for the demo bots in examples/.

AcmeAssist is a small support bot with two fake tools: ``read_document``
(reads documents the user attached) and ``send_email`` (records to an outbox;
nothing is ever sent). The same app runs with two policies:

* ``VULNERABLE``: naive system prompt, untrusted content pasted straight into
  the prompt, no filtering, and "link previews" that fetch URLs in replies.
* ``HARDENED``: basic defences. Untrusted content is isolated and never
  obeyed, an input filter blocks known override phrases, an output filter strips
  images and links to unknown domains and redacts secrets, and send_email only
  goes to an allow-listed domain.

Backends:

* default: a deterministic simulator that behaves like an obedient LLM, so the
  demo works offline with no API key;
* ``BOT_LLM=openai``: any OpenAI-compatible endpoint (``OPENAI_API_KEY``,
  ``BOT_MODEL``, ``BOT_BASE_URL``);
* ``BOT_LLM=anthropic``: Claude via the official SDK (``ANTHROPIC_API_KEY``,
  ``BOT_MODEL``, default ``claude-opus-5-5``).
"""

from .app import HARDENED, VULNERABLE, Policy, create_app, respond

__all__ = ["HARDENED", "VULNERABLE", "Policy", "create_app", "respond"]
