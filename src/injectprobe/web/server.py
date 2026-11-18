"""injectprobe web app: paste an agent's URL, check the connection, run attacks, read the report.

Start it with ``injectprobe serve`` (local) or ``injectprobe serve --public --public-url https://...``
(hosted, with domain ownership verification).
"""

from __future__ import annotations

import asyncio
import os
import secrets as pysecrets
import time
import uuid
from dataclasses import dataclass, field
from importlib import resources
from typing import Any, Literal

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field, ValidationError, field_validator

from .. import __version__
from .. import secrets as ipsecrets
from ..canary import _PNG_1X1, Hit
from ..config import ConfigError, parse_config
from ..jsonpath import JsonPathError, parse
from ..loader import expand_cases, filter_attacks, load_attacks
from ..models import CATEGORIES, Message, RunResult, TargetRequest
from ..reports import FILE_FORMATS, render
from ..runner import run_probe
from ..targets.base import TargetError
from ..targets.http import HttpTarget
from .detect import PROBE_TEXT, detect
from .security import WELL_KNOWN_PATH, Ownership, TargetBlocked, authorize

# --------------------------------------------------------------------------- request models


class TargetSpec(BaseModel):
    url: str = Field(min_length=8, max_length=2000)
    format: Literal["simple", "openai", "custom"] = "simple"
    message_field: str = Field(default="message", pattern=r"^[A-Za-z_][\w\-]{0,63}$")
    documents_field: str | None = Field(default=None, pattern=r"^[A-Za-z_][\w\-]{0,63}$")
    history_field: str | None = Field(default=None, pattern=r"^[A-Za-z_][\w\-]{0,63}$")
    response_path: str = "$.reply"
    tool_calls_path: str | None = None
    request_template: dict[str, Any] | None = None
    model: str | None = Field(default=None, max_length=200)
    api_key: str | None = Field(default=None, max_length=4000)
    auth_header: str = Field(default="Authorization", pattern=r"^[A-Za-z0-9\-]{1,64}$")
    auth_prefix: str = Field(default="Bearer ", max_length=32)
    system_prompt_markers: list[str] = Field(default_factory=list, max_length=20)
    authorised: bool = False

    @field_validator("response_path", "tool_calls_path")
    @classmethod
    def _valid_path(cls, v: str | None) -> str | None:
        if v:
            try:
                parse(v)
            except JsonPathError as e:
                raise ValueError(str(e)) from e
        return v or None

    @field_validator("tool_calls_path", "documents_field", "history_field", "model", "api_key", mode="before")
    @classmethod
    def _blank_is_none(cls, v: Any) -> Any:
        return None if isinstance(v, str) and not v.strip() else v

    @field_validator("system_prompt_markers")
    @classmethod
    def _markers(cls, v: list[str]) -> list[str]:
        v = [m.strip() for m in v if m.strip()]
        if any(len(m) < 4 for m in v):
            raise ValueError("each system prompt marker needs at least 4 characters")
        return v


class RunRequest(BaseModel):
    target: TargetSpec
    scope: Literal["quick", "full"] = "quick"
    trials: int = Field(default=1, ge=1, le=5)
    categories: list[str] = Field(default_factory=list)
    threshold: float = Field(default=0.1, ge=0, le=1)


# --------------------------------------------------------------------------- canary + jobs


class WebCanary:
    """Canary endpoint served by the web app itself (``/c/<token>.png``)."""

    def __init__(self, base_url: str):
        self.base_url = base_url.rstrip("/")
        self._hits: list[Hit] = []

    def record(self, path: str, method: str, user_agent: str) -> None:
        self._hits.append(Hit(path=path, method=method, user_agent=user_agent[:200]))
        del self._hits[:-5000]  # bound memory

    def hits_for(self, token: str) -> list[Hit]:
        t = token.lower()
        return [h for h in self._hits if t in h.path.lower()]


@dataclass
class Job:
    id: str
    target_url: str
    total: int
    done: int = 0
    status: Literal["running", "done", "error", "cancelled"] = "running"
    error: str | None = None
    result: RunResult | None = None
    created: float = field(default_factory=time.time)
    task: asyncio.Task | None = None

    def view(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "id": self.id, "status": self.status, "done": self.done, "total": self.total,
            "error": self.error, "target": self.target_url,
        }
        if self.result is not None:
            out["result"] = self.result.model_dump(mode="json")
        return out


# --------------------------------------------------------------------------- app


def _hostname(host_header: str) -> str:
    """Host header without the port: 'localhost:8080' -> 'localhost', '[::1]:8080' -> '[::1]'."""
    if host_header.startswith("["):
        return host_header.split("]")[0] + "]"
    return host_header.split(":")[0]


def spec_to_config(spec: TargetSpec, *, public_mode: bool, run: dict[str, Any] | None = None,
                   threshold: float = 0.1):
    headers: dict[str, str] = {"Content-Type": "application/json"}
    if spec.api_key:
        if "${" in spec.api_key:
            raise HTTPException(400, "The API key contains '${', which is not allowed")
        ipsecrets.register(spec.api_key)
        headers[spec.auth_header] = f"{spec.auth_prefix}{spec.api_key}"
    url = spec.url.strip()
    tool_path = spec.tool_calls_path
    if spec.format == "openai":
        if not url.rstrip("/").endswith("/chat/completions"):
            url = url.rstrip("/") + "/chat/completions"
        template: Any = {"model": spec.model or "gpt-4o-mini", "messages": "{{history}}"}
        response_path = "$.choices[0].message.content"
        tool_path = tool_path or "$.choices[0].message.tool_calls"
    elif spec.format == "custom":
        template = spec.request_template or {}
        blob = str(template)
        if "{{message}}" not in blob and "{{history}}" not in blob:
            raise HTTPException(400, 'The custom request template must contain "{{message}}" or "{{history}}"')
        response_path = spec.response_path
    else:
        template = {spec.message_field: "{{message}}"}
        if spec.documents_field:
            template[spec.documents_field] = "{{documents}}"
        if spec.history_field:
            template[spec.history_field] = "{{history}}"
        response_path = spec.response_path
    data = {
        "target": {"type": "http", "url": url, "headers": headers, "request_template": template,
                   "response_path": response_path, "tool_calls_path": tool_path},
        "authorised": True,  # checked by authorize() before this is used
        "threshold": threshold,
        "system_prompt_markers": spec.system_prompt_markers,
        "run": {"trials": 1, "concurrency": 4, "rate_limit": 3 if public_mode else 5, "timeout": 30,
                "retries": 2, "max_requests": 1200, **(run or {})},
        "canary": {"listener": "on", "grace_seconds": 1.0},
        "reports": {"output_dir": "unused"},
    }
    try:
        return parse_config(data)
    except ConfigError as e:
        raise HTTPException(400, str(e)) from e


def create_app(
    *,
    public: bool = False,
    public_url: str | None = None,
    port: int = 8080,
    transport: httpx.AsyncBaseTransport | None = None,
    secret: bytes | None = None,
    allowed_hosts: set[str] | None = None,
    max_jobs: int | None = None,
    skip_dns_check: bool = False,
) -> FastAPI:
    app = FastAPI(title="injectprobe", version=__version__, docs_url=None, redoc_url=None)
    secret = secret or os.environ.get("INJECTPROBE_SECRET", "").encode() or pysecrets.token_bytes(32)
    ownership = Ownership(secret)
    page_token = pysecrets.token_urlsafe(24)
    canary = WebCanary(public_url or f"http://127.0.0.1:{port}")
    jobs: dict[str, Job] = {}
    max_jobs = max_jobs or (2 if public else 4)
    local_hosts = {"127.0.0.1", "localhost", "::1", "[::1]"} | (allowed_hosts or set())

    async def guard(request: Request) -> None:
        # Local mode: refuse other Host headers (DNS rebinding) and require the page token,
        # which a cross-site page cannot read (CSRF).
        if not public:
            host = _hostname(request.headers.get("host", ""))
            if host not in local_hosts:
                raise HTTPException(403, "This local server only answers on localhost")
        if not pysecrets.compare_digest(request.headers.get("x-injectprobe-token", ""), page_token):
            raise HTTPException(403, "Missing or wrong page token; reload the page")

    async def check(spec: TargetSpec) -> tuple[str, str]:
        try:
            return await authorize(spec.url, public_mode=public, authorised=spec.authorised,
                                   ownership=ownership, skip_dns_check=skip_dns_check)
        except TargetBlocked as e:
            raise HTTPException(403, str(e)) from e

    def headers_for(spec: TargetSpec) -> dict[str, str]:
        h = {"Content-Type": "application/json"}
        if spec.api_key:
            ipsecrets.register(spec.api_key)
            h[spec.auth_header] = f"{spec.auth_prefix}{spec.api_key}"
        return h

    @app.exception_handler(ValidationError)
    async def _validation(_: Request, exc: ValidationError) -> JSONResponse:
        return JSONResponse({"detail": exc.errors()[0]["msg"]}, status_code=422)

    # ---------------------------------------------------------------- pages
    @app.get("/", response_class=HTMLResponse)
    async def index() -> HTMLResponse:
        html = (resources.files("injectprobe.web") / "static" / "index.html").read_text(encoding="utf-8")
        html = html.replace("__IP_TOKEN__", page_token).replace("__IP_MODE__", "public" if public else "local")
        return HTMLResponse(html, headers={
            "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                                       "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                                       "connect-src 'self'; frame-ancestors 'none'",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        })

    @app.api_route("/c/{path:path}", methods=["GET", "HEAD", "POST"])
    async def canary_hit(path: str, request: Request) -> Response:
        canary.record("/c/" + path, request.method, request.headers.get("user-agent", ""))
        return Response(_PNG_1X1, media_type="image/png")

    # ---------------------------------------------------------------- api
    @app.get("/api/info", dependencies=[Depends(guard)])
    async def info() -> dict[str, Any]:
        attacks = load_attacks()
        return {
            "version": __version__,
            "mode": "public" if public else "local",
            "canary_base": canary.base_url,
            "attacks": len(attacks),
            "quick": len(filter_attacks(attacks, quick=True)),
            "categories": [{"id": k, "name": v, "count": sum(a.category == k for a in attacks)}
                           for k, v in CATEGORIES.items()],
            "well_known_path": WELL_KNOWN_PATH,
        }

    @app.post("/api/ownership", dependencies=[Depends(guard)])
    async def ownership_info(spec: TargetSpec) -> dict[str, Any]:
        from .security import parse_target

        try:
            scheme, host = parse_target(spec.url)
        except TargetBlocked as e:
            raise HTTPException(400, str(e)) from e
        return {
            "host": host,
            "required": public,
            "verified": ownership.is_verified(host),
            "token": ownership.token_for(host) if public else None,
            "file_url": f"{scheme}://{host}{WELL_KNOWN_PATH}",
        }

    @app.post("/api/verify", dependencies=[Depends(guard)])
    async def verify(spec: TargetSpec) -> dict[str, Any]:
        from .security import parse_target, resolves_to_public

        try:
            scheme, host = parse_target(spec.url)
        except TargetBlocked as e:
            raise HTTPException(400, str(e)) from e
        if public and not skip_dns_check and not await resolves_to_public(host):
            raise HTTPException(403, "Hosted mode only tests agents on public internet addresses.")
        ok = await ownership.verify(scheme, host, transport=transport)
        return {"host": host, "verified": ok,
                "detail": None if ok else f"Could not find the code at {scheme}://{host}{WELL_KNOWN_PATH}"}

    @app.post("/api/detect", dependencies=[Depends(guard)])
    async def detect_format(spec: TargetSpec) -> dict[str, Any]:
        await check(spec)
        d = await detect(spec.url.strip(), headers_for(spec), transport=transport, model=spec.model)
        return {
            "ok": d.ok, "format": d.format, "message_field": d.message_field,
            "response_path": d.response_path, "tool_calls_path": d.tool_calls_path,
            "sample_reply": ipsecrets.redact(d.sample_reply), "notes": d.notes,
        }

    @app.post("/api/test", dependencies=[Depends(guard)])
    async def test_connection(spec: TargetSpec) -> dict[str, Any]:
        await check(spec)
        cfg = spec_to_config(spec, public_mode=public)
        target = HttpTarget(cfg.target, timeout=30, transport=transport)
        start = time.monotonic()
        try:
            async with target:
                resp = await target.send(TargetRequest(messages=[Message(role="user", content=PROBE_TEXT)]))
        except (TargetError, ConfigError) as e:
            raise HTTPException(502, ipsecrets.redact(f"The agent did not answer as expected: {e}")) from e
        return {
            "reply": ipsecrets.redact(resp.text)[:4000],
            "tool_calls": [c.model_dump() for c in resp.tool_calls],
            "latency_ms": round((time.monotonic() - start) * 1000),
            "sent": PROBE_TEXT,
        }

    @app.post("/api/runs", dependencies=[Depends(guard)])
    async def start_run(req: RunRequest) -> dict[str, Any]:
        await check(req.target)
        if sum(j.status == "running" for j in jobs.values()) >= max_jobs:
            raise HTTPException(429, "Too many runs in progress; wait for one to finish")
        trials = min(req.trials, 3) if public else req.trials
        cfg = spec_to_config(req.target, public_mode=public, run={"trials": trials}, threshold=req.threshold)
        unknown = set(req.categories) - set(CATEGORIES)
        if unknown:
            raise HTTPException(400, f"Unknown categories: {sorted(unknown)}")
        attacks = filter_attacks(load_attacks(), categories=req.categories, quick=req.scope == "quick")
        if not attacks:
            raise HTTPException(400, "No attacks match that selection")
        cases = expand_cases(attacks)
        job = Job(id=uuid.uuid4().hex[:12], target_url=cfg.target.url, total=len(cases) * trials)
        jobs[job.id] = job
        for old in sorted(jobs.values(), key=lambda j: j.created)[:-50]:  # keep the last 50
            if old.status != "running":
                jobs.pop(old.id, None)

        def progress(n: int) -> None:
            job.done = min(job.total, job.done + n)

        async def go() -> None:
            try:
                target = HttpTarget(cfg.target, timeout=cfg.run.timeout, transport=transport)
                job.result = await run_probe(cfg, cases, target=target, progress=progress, listener=canary)
                job.status = "done"
            except asyncio.CancelledError:
                job.status = "cancelled"
            except Exception as e:  # noqa: BLE001 - shown to the user
                job.status = "error"
                job.error = ipsecrets.redact(f"{type(e).__name__}: {e}")[:500]

        job.task = asyncio.create_task(go())
        return job.view()

    @app.get("/api/runs/{job_id}", dependencies=[Depends(guard)])
    async def get_run(job_id: str) -> dict[str, Any]:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(404, "No such run")
        return job.view()

    @app.post("/api/runs/{job_id}/cancel", dependencies=[Depends(guard)])
    async def cancel_run(job_id: str) -> dict[str, Any]:
        job = jobs.get(job_id)
        if job is None:
            raise HTTPException(404, "No such run")
        if job.task is not None and not job.task.done():
            job.task.cancel()
        return {"id": job_id, "status": "cancelling"}

    @app.get("/api/runs/{job_id}/report/{fmt}")
    async def report(job_id: str, fmt: str, token: str = "") -> PlainTextResponse:
        # Downloads are plain links, so the page token comes as a query parameter.
        if not pysecrets.compare_digest(token, page_token):
            raise HTTPException(403, "Missing or wrong page token")
        job = jobs.get(job_id)
        if job is None or job.result is None:
            raise HTTPException(404, "No finished run with that id")
        if fmt not in FILE_FORMATS:
            raise HTTPException(404, "Unknown format")
        name, _ = FILE_FORMATS[fmt]
        return PlainTextResponse(render(job.result, fmt), headers={
            "Content-Disposition": f'attachment; filename="injectprobe-{job_id}-{name}"'})

    app.state.ownership = ownership
    app.state.page_token = page_token
    app.state.canary = canary
    app.state.jobs = jobs
    return app
