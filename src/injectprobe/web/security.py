"""Who may be tested, and how ownership is proven.

* Local mode (the default, bound to 127.0.0.1): localhost targets are allowed;
  any other target needs the user to confirm they own it or have permission,
  the same rule as ``authorised: true`` in the CLI.
* Hosted mode (``injectprobe serve --public``): every target must resolve to a
  public IP address (no internal networks), and its owner must prove control of
  the domain by serving a per-domain token at
  ``/.well-known/injectprobe.txt``.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import socket
from urllib.parse import urlsplit

import httpx

from ..config import is_local_host

WELL_KNOWN_PATH = "/.well-known/injectprobe.txt"


class TargetBlocked(Exception):
    """The target may not be tested. The message is safe to show to the user."""


def parse_target(url: str) -> tuple[str, str]:
    """Return (scheme, hostname) or raise TargetBlocked."""
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https"):
        raise TargetBlocked("The agent URL must start with http:// or https://")
    if not parts.hostname:
        raise TargetBlocked("The agent URL has no host name")
    if parts.username or parts.password:
        raise TargetBlocked("Put credentials in the API key field, not in the URL")
    return parts.scheme, parts.hostname.lower()


async def resolves_to_public(host: str) -> bool:
    """True only if every address the host resolves to is a public (global) IP."""
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return False
    addresses = {info[4][0] for info in infos}
    if not addresses:
        return False
    for addr in addresses:
        ip = ipaddress.ip_address(addr.split("%")[0])
        if not ip.is_global:
            return False
    return True


class Ownership:
    """Stateless per-domain tokens (HMAC of the host) plus a cache of verified hosts."""

    def __init__(self, secret: bytes):
        self.secret = secret
        self.verified: set[str] = set()

    def token_for(self, host: str) -> str:
        digest = hmac.new(self.secret, host.lower().encode(), hashlib.sha256).hexdigest()[:32]
        return f"injectprobe-verify={digest}"

    def is_verified(self, host: str) -> bool:
        return host.lower() in self.verified

    async def verify(self, scheme: str, host: str, transport: httpx.AsyncBaseTransport | None = None) -> bool:
        token = self.token_for(host)
        url = f"{scheme}://{host}{WELL_KNOWN_PATH}"
        try:
            async with httpx.AsyncClient(timeout=8, follow_redirects=False, transport=transport) as client:
                resp = await client.get(url)
        except httpx.HTTPError:
            return False
        if resp.status_code != 200 or token not in resp.text[:4096]:
            return False
        self.verified.add(host.lower())
        return True


async def authorize(
    url: str,
    *,
    public_mode: bool,
    authorised: bool,
    ownership: Ownership,
    skip_dns_check: bool = False,
) -> tuple[str, str]:
    """Raise TargetBlocked unless this target may be tested. Returns (scheme, host)."""
    scheme, host = parse_target(url)
    if not public_mode:
        if not is_local_host(host) and not authorised:
            raise TargetBlocked(
                "This agent is not on your computer. Confirm that you own it or have permission to test it."
            )
        return scheme, host
    if is_local_host(host) or not (skip_dns_check or await resolves_to_public(host)):
        raise TargetBlocked("Hosted mode only tests agents on public internet addresses.")
    if not ownership.is_verified(host):
        raise TargetBlocked(f"Verify that you own {host} first.")
    return scheme, host
