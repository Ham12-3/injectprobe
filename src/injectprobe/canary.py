"""Canary tokens and the on-demand local canary HTTP listener."""

from __future__ import annotations

import secrets as _secrets
import string
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

_ALPHABET = string.ascii_uppercase + string.digits
_PNG_1X1 = bytes.fromhex(
    "89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489"
    "0000000d4944415478da63f8ffff3f0005fe02fea7d6a52f0000000049454e44ae426082"
)


@dataclass(frozen=True)
class CanaryToken:
    """A unique per-attempt marker.

    ``part_a`` + ``part_b`` == ``token``. Payloads that ask for the token in the
    reply give the two halves separately, so a refusal that merely quotes the
    payload never contains the joined token.
    """

    token: str
    part_a: str
    part_b: str
    url: str
    email: str

    def variables(self) -> dict[str, str]:
        return {
            "canary": self.token,
            "canary_a": self.part_a,
            "canary_b": self.part_b,
            "canary_url": self.url,
            "canary_email": self.email,
        }

    def protected(self) -> list[str]:
        return [self.token, self.part_a, self.part_b, self.url, self.email]


DEFAULT_CANARY_BASE = "http://127.0.0.1:8765"


def _rand(n: int) -> str:
    return "".join(_secrets.choice(_ALPHABET) for _ in range(n))


def new_canary(prefix: str = "IPX", base_url: str | None = None) -> CanaryToken:
    a = f"{prefix}-{_rand(5)}"
    b = _rand(5)
    token = a + b
    base = (base_url or DEFAULT_CANARY_BASE).rstrip("/")
    return CanaryToken(
        token=token,
        part_a=a,
        part_b=b,
        url=f"{base}/c/{token}.png",
        email=f"audit-{token.lower()}@canary.invalid",
    )


def placeholder_canary() -> CanaryToken:
    """A fixed token used to show payload previews in reports."""
    return CanaryToken(
        token="<CANARY>",
        part_a="<CANARY_A>",
        part_b="<CANARY_B>",
        url="<CANARY_URL>",
        email="<CANARY_EMAIL>",
    )


@dataclass
class Hit:
    path: str
    method: str
    user_agent: str
    at: float = field(default_factory=time.time)


class CanaryListener:
    """A tiny HTTP server that records any request whose path contains a token."""

    def __init__(self, host: str = "127.0.0.1", port: int = 0, public_url: str | None = None):
        self.host = host
        self.port = port
        self.public_url = public_url
        self._hits: list[Hit] = []
        self._lock = threading.Lock()
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # -- lifecycle -------------------------------------------------------- #
    def start(self) -> "CanaryListener":
        listener = self

        class Handler(BaseHTTPRequestHandler):
            def _record(self) -> None:
                with listener._lock:
                    listener._hits.append(
                        Hit(
                            path=self.path,
                            method=self.command,
                            user_agent=self.headers.get("User-Agent", ""),
                        )
                    )
                self.send_response(200)
                self.send_header("Content-Type", "image/png")
                self.send_header("Content-Length", str(len(_PNG_1X1)))
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(_PNG_1X1)

            do_GET = do_POST = do_HEAD = do_PUT = _record

            def log_message(self, *args: object) -> None:  # silence stderr
                pass

        self._server = ThreadingHTTPServer((self.host, self.port), Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def __enter__(self) -> "CanaryListener":
        return self.start()

    def __exit__(self, *exc: object) -> None:
        self.stop()

    # -- queries ---------------------------------------------------------- #
    @property
    def base_url(self) -> str:
        if self.public_url:
            return self.public_url.rstrip("/")
        return f"http://{self.host}:{self.port}"

    def hits_for(self, token: str) -> list[Hit]:
        t = token.lower()
        with self._lock:
            return [h for h in self._hits if t in h.path.lower()]

    @property
    def hits(self) -> list[Hit]:
        with self._lock:
            return list(self._hits)
