"""The web app, driven through FastAPI's TestClient against the demo bot (ASGI, no network)."""

import asyncio
import sys
import time
from pathlib import Path

import pytest

pytest.importorskip("fastapi")
import httpx  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from examples.vulnerable_bot.app import app as bot_app  # noqa: E402
from injectprobe.web.security import Ownership, TargetBlocked, authorize, parse_target  # noqa: E402
from injectprobe.web.server import create_app  # noqa: E402

BOT_URL = "http://127.0.0.1:8000/chat"
REMOTE_URL = "https://agent.example.com/chat"


@pytest.fixture(autouse=True)
def _no_llm(monkeypatch):
    monkeypatch.delenv("BOT_LLM", raising=False)


def client_for(**kw):
    app = create_app(transport=httpx.ASGITransport(app=bot_app), allowed_hosts={"testserver"}, **kw)
    client = TestClient(app)
    client.headers["X-Injectprobe-Token"] = app.state.page_token
    return app, client


def spec(**kw):
    base = {"url": BOT_URL, "format": "simple", "message_field": "message", "response_path": "$.reply",
            "tool_calls_path": "$.tool_calls", "documents_field": "documents", "history_field": "history",
            "system_prompt_markers": ["BLUEFALCON-7"]}
    base.update(kw)
    return base


# --------------------------------------------------------------------------- page + guards


def test_index_has_token_and_csp():
    app, client = client_for()
    r = client.get("/")
    assert r.status_code == 200
    assert app.state.page_token in r.text and "__IP_TOKEN__" not in r.text
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]


def test_api_requires_page_token():
    app, client = client_for()
    del client.headers["X-Injectprobe-Token"]
    assert client.get("/api/info").status_code == 403


def test_local_mode_rejects_foreign_host_header():
    app = create_app()
    with TestClient(app) as c:
        r = c.get("/api/info", headers={"X-Injectprobe-Token": app.state.page_token, "Host": "evil.example"})
        assert r.status_code == 403
        r2 = c.get("/api/info", headers={"X-Injectprobe-Token": app.state.page_token, "Host": "localhost:8080"})
        assert r2.status_code == 200


def test_info():
    _, client = client_for()
    info = client.get("/api/info").json()
    assert info["mode"] == "local" and info["attacks"] >= 80 and info["quick"] > 0
    assert {c["id"] for c in info["categories"]} >= {"indirect", "encoding"}


# --------------------------------------------------------------------------- connection


def test_detect_finds_message_and_reply():
    _, client = client_for()
    r = client.post("/api/detect", json={"url": BOT_URL})
    d = r.json()
    assert r.status_code == 200 and d["ok"], d
    assert d["message_field"] == "message" and d["response_path"] == "$.reply"
    assert d["tool_calls_path"] == "$.tool_calls"


def test_test_connection_returns_reply():
    _, client = client_for()
    r = client.post("/api/test", json=spec())
    assert r.status_code == 200, r.text
    assert "Acme" in r.json()["reply"]


def test_test_connection_bad_mapping_explains():
    _, client = client_for()
    r = client.post("/api/test", json=spec(response_path="$.nope"))
    assert r.status_code == 502 and "not found" in r.json()["detail"]


def test_invalid_spec_rejected():
    _, client = client_for()
    assert client.post("/api/test", json=spec(response_path="reply")).status_code == 422
    assert client.post("/api/test", json=spec(url="ftp://x.example/chat")).status_code == 403
    r = client.post("/api/test", json=spec(format="custom", request_template={"q": "hi"}))
    assert r.status_code == 400 and "{{message}}" in r.json()["detail"]


# --------------------------------------------------------------------------- permission


def test_local_mode_remote_target_needs_confirmation():
    _, client = client_for()
    r = client.post("/api/test", json=spec(url=REMOTE_URL))
    assert r.status_code == 403 and "permission" in r.json()["detail"]


def test_parse_target_rules():
    assert parse_target("https://Agent.Example.com/x") == ("https", "agent.example.com")
    for bad in ("ftp://a.example", "https://", "https://user:pw@a.example/x"):
        with pytest.raises(TargetBlocked):
            parse_target(bad)


def test_public_mode_blocks_private_and_unverified():
    own = Ownership(b"k" * 32)

    async def go(url, **kw):
        return await authorize(url, public_mode=True, authorised=True, ownership=own, **kw)

    for url in ("http://127.0.0.1:8000/chat", "http://10.0.0.5/chat", "http://localhost/chat"):
        with pytest.raises(TargetBlocked):
            asyncio.run(go(url))
    with pytest.raises(TargetBlocked) as e:
        asyncio.run(go(REMOTE_URL, skip_dns_check=True))
    assert "Verify" in str(e.value)
    own.verified.add("agent.example.com")
    assert asyncio.run(go(REMOTE_URL, skip_dns_check=True)) == ("https", "agent.example.com")


def test_public_mode_ownership_verification_flow():
    secret = b"s" * 32
    token = Ownership(secret).token_for("agent.example.com")
    served = {"body": "nothing here"}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/.well-known/injectprobe.txt":
            return httpx.Response(200, text=served["body"])
        return httpx.Response(200, json={"reply": "hello from the remote agent"})

    app = create_app(public=True, public_url="https://probe.example.org", transport=httpx.MockTransport(handler),
                     secret=secret, skip_dns_check=True)
    client = TestClient(app)
    client.headers["X-Injectprobe-Token"] = app.state.page_token

    info = client.post("/api/ownership", json={"url": REMOTE_URL}).json()
    assert info["required"] and info["token"] == token and not info["verified"]
    assert info["file_url"] == "https://agent.example.com/.well-known/injectprobe.txt"
    assert client.post("/api/test", json=spec(url=REMOTE_URL)).status_code == 403
    assert client.post("/api/verify", json={"url": REMOTE_URL}).json()["verified"] is False
    served["body"] = token
    assert client.post("/api/verify", json={"url": REMOTE_URL}).json()["verified"] is True
    r = client.post("/api/test", json=spec(url=REMOTE_URL, tool_calls_path=None))
    assert r.status_code == 200 and r.json()["reply"] == "hello from the remote agent"


# --------------------------------------------------------------------------- runs


def wait_for(client, job_id, timeout=60):
    end = time.time() + timeout
    while time.time() < end:
        job = client.get(f"/api/runs/{job_id}").json()
        if job["status"] != "running":
            return job
        time.sleep(0.2)
    raise AssertionError("run did not finish")


def test_quick_run_end_to_end_and_reports():
    app, client = client_for()
    with client:
        r = client.post("/api/runs", json={"target": spec(), "scope": "quick", "trials": 1})
        assert r.status_code == 200, r.text
        job = wait_for(client, r.json()["id"])
        assert job["status"] == "done", job
        res = job["result"]
        assert res["summary"]["tested"] > 0 and res["summary"]["success_rate"] > 0.8
        assert res["passed"] is False
        for fmt, needle in (("json", '"summary"'), ("markdown", "injectprobe-report"),
                            ("junit", "<testsuites"), ("sarif", '"2.1.0"')):
            d = client.get(f"/api/runs/{job['id']}/report/{fmt}", params={"token": app.state.page_token})
            assert d.status_code == 200 and needle in d.text, fmt
            assert "attachment" in d.headers["content-disposition"]
        assert client.get(f"/api/runs/{job['id']}/report/json").status_code == 403


def test_run_category_filter_and_unknown():
    _, client = client_for()
    with client:
        r = client.post("/api/runs", json={"target": spec(), "scope": "full", "categories": ["exfiltration"]})
        job = wait_for(client, r.json()["id"])
        assert set(job["result"]["summary"]["by_category"]) == {"exfiltration"}
        bad = client.post("/api/runs", json={"target": spec(), "categories": ["nope"]})
        assert bad.status_code == 400


def test_api_key_never_returned(monkeypatch):
    seen = {}

    def handler(req: httpx.Request) -> httpx.Response:
        seen["auth"] = req.headers.get("x-api-key")
        return httpx.Response(200, json={"reply": "your key is supersecret-key-123"})

    app = create_app(transport=httpx.MockTransport(handler), allowed_hosts={"testserver"})
    client = TestClient(app)
    client.headers["X-Injectprobe-Token"] = app.state.page_token
    r = client.post("/api/test", json=spec(api_key="supersecret-key-123", auth_header="x-api-key", auth_prefix="",
                                           tool_calls_path=None))
    assert seen["auth"] == "supersecret-key-123"
    assert "supersecret-key-123" not in r.text


def test_canary_endpoint_records_hits():
    app, client = client_for()
    r = client.get("/c/IPX-ABCDE12345.png")
    assert r.status_code == 200 and r.headers["content-type"] == "image/png"
    assert app.state.canary.hits_for("IPX-ABCDE12345")
