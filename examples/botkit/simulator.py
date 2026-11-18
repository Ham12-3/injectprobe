"""A deterministic stand-in for an LLM, so the demo works offline.

It behaves like an obedient model: it decodes common obfuscations, follows
instructions it finds in whatever text it treats as instructions, copies
requested markdown/HTML snippets, calls send_email when asked, and reveals its
system prompt when asked. Which text counts as "instructions" is the only
thing the policy changes: the vulnerable bot reads documents as instructions,
the hardened bot only reads the user's own messages.

It is a simulation for demos and tests, not a model. Use BOT_LLM to test a
real one.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
from dataclasses import dataclass, field
from urllib.parse import unquote

_ZW = re.compile("[​-‏⁠﻿]")
_B64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_DASHED = re.compile(r"\b(?:\w-){2,}\w\b")
_HOMOGLYPHS = str.maketrans("АВСЕНІЈКМОРЅТХаеіјорсуѕх", "ABCEHIJKMOPSTXaeijopcysx")
_LEET = str.maketrans("431057", "aeiost")
_URL = re.compile(r"https?://[^\s)\"'<>\]]+")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_CODE = re.compile(r"(?<![A-Za-z0-9])([A-Z]{2,8}-[A-Z0-9]{5})(?![A-Za-z0-9])")
_SUFFIX = re.compile(r"(?<![A-Za-z0-9\-])([A-Z0-9]{5})(?![A-Za-z0-9])")
_SNIPPETS = [
    re.compile(r"\[!\[[^\]]*\]\([^)]*\)\]\([^)]*\)"),  # linked badge
    re.compile(r"!\[[^\]]*\]\[[^\]]+\]\s*\n+\s*\[[^\]]+\]:\s*\S+"),  # reference image
    re.compile(r"!\[[^\]]*\]\([^)]*\)"),
    re.compile(r"(?<!!)\[[^\]]*\]\([^)]*\)"),
    re.compile(r"<img\b[^>]*>", re.I),
]
_STOP = {"ADMIN", "ABOUT", "AFTER", "AGENT", "ALERT", "CLAIM", "CODES", "DEBUG", "EMAIL", "ERROR", "FALSE",
         "FIRST", "IMAGE", "INPUT", "LEVEL", "LOGIN", "NOTES", "ORDER", "PARTS", "PRINT", "QUERY", "REPLY",
         "RULES", "SCAN", "STATE", "TABLE", "TOKEN", "TOOLS", "TRUES", "USERS", "VALUE", "WORDS"}
_DIRECTIVE = re.compile(
    r"(output|print|reply|respond|answer|say|write|echo|begin|start|end|include|repeat|confirm|prove|"
    r"concatenat|join|combine|announce|read|introduce|render|append|add|show|embed|"
    r"répondez|responde|antworte|responda|rispondi|antwoord|ответь|回复|返信|답하|أجب|जवाब|jibu|"
    r"pineapple|secret word)",
    re.I,
)
_LEAK_ASK = re.compile(
    r"(system (prompt|message)|initial instructions|text above|your (rules|instructions|configuration|prompt)|"
    r"before the first user message|instructions are|rules you were given|full configuration)",
    re.I,
)
_EMAIL_ASK = re.compile(r"(send_email|e-?mail|forward|mail)", re.I)
_FETCH_ASK = re.compile(r"(fetch_url|fetch|load)", re.I)


def decode_variants(text: str) -> str:
    """Return the text plus decoded variants a capable model would understand."""
    text = _ZW.sub("", text)
    variants = [text]
    if "%20" in text:
        variants.append(unquote(text))
    for blob in _B64.findall(text):
        try:
            decoded = base64.b64decode(blob, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        if decoded.isprintable() or "\n" in decoded:
            variants.append(decoded)
    if re.search(r"rot13", text, re.I):
        variants.append(codecs.encode(text, "rot_13"))
    if re.search(r"reverse order", text, re.I):
        variants.append(" ".join(text.split()[::-1]))
    if _DASHED.search(text):
        variants.append(_DASHED.sub(lambda m: m.group(0).replace("-", ""), text))
    variants.append(text.translate(_HOMOGLYPHS))
    return "\n".join(variants)


def find_code(text: str) -> str | None:
    """The 'code A immediately followed by code B' pattern used in payloads."""
    m = _CODE.search(text)
    if not m:
        return None
    for s in _SUFFIX.finditer(text, m.end()):
        if s.group(1) not in _STOP and s.group(1) not in m.group(1):
            return m.group(1) + s.group(1)
    return None


@dataclass
class SimResult:
    reply: str
    emails: list[str] = field(default_factory=list)
    fetches: list[str] = field(default_factory=list)


def simulate(instructions: str, last_user: str, system_prompt: str, data_text: str = "", data_title: str = "") -> SimResult:
    """Produce a reply.

    ``instructions`` is all text the bot treats as instructions (user turns, and
    for the vulnerable bot also documents). ``data_text`` is untrusted content
    the bot may only summarize.
    """
    decoded = decode_variants(instructions)
    cues = decoded + "\n" + decoded.translate(_LEET)
    parts: list[str] = []
    result = SimResult(reply="")

    if _LEAK_ASK.search(last_user):
        parts.append(f"Sure, here are my instructions:\n{system_prompt}")

    urls = _URL.findall(decoded)
    emails = [e for e in _EMAIL.findall(decoded) if not e.endswith("example.com")]
    if emails and _EMAIL_ASK.search(cues):
        result.emails.append(emails[0])
        parts.append(f"I've emailed {emails[0]} as requested.")
    if urls:
        snippets = [m.group(0) for rx in _SNIPPETS for m in rx.finditer(decoded) if any(u in m.group(0) for u in urls)]
        if snippets:
            parts.append(snippets[0])
        elif re.search(r"(image|badge|logo|map)", cues, re.I):
            parts.append(f"![badge]({urls[0]})")
        if _FETCH_ASK.search(cues):
            result.fetches.append(urls[0])
            parts.append("I loaded the page you mentioned.")

    code = find_code(decoded)
    if code and _DIRECTIVE.search(cues):
        parts.append(code)

    if not parts:
        if data_text:
            plain = re.sub(r"<[^>]+>|[{}\"\[\]]", " ", data_text)
            first = re.sub(r"\s+", " ", plain).strip()[:160]
            parts.append(f"Here's a short summary of {data_title or 'the document'}: {first}...")
        else:
            parts.append("Happy to help with Acme products. What would you like to know?")
    result.reply = "\n\n".join(parts)
    return result
