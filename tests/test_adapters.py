import asyncio
import json
import sys
from types import SimpleNamespace

import httpx
import pytest

from injectprobe import secrets
from injectprobe.config import (
    AnthropicTargetConfig,
    CallableTargetConfig,
    ConfigError,
    HttpTargetConfig,
    OpenAITargetConfig,
    parse_config,
)
from injectprobe.jsonpath import JsonPathError, find
from injectprobe.models import Carrier, ContextItem, Message, TargetRequest
from injectprobe.targets import build_target
from injectprobe.targets.anthropic import AnthropicTarget, classify_error
from injectprobe.targets.base import TargetError
from injectprobe.targets.callable import CallableTarget, load_callable, transcript
from injectprobe.targets.http import HttpTarget, build_body, parse_tool_calls
from injectprobe.targets.openai_compat import OpenAITarget


def run(coro):
    return asyncio.run(coro)


DOC = ContextItem(kind=Carrier.document, title="report.txt", content="DOC BODY")
TOOL = ContextItem(kind=Carrier.tool_result, title="search_knowledge_base", content='{"r": "TOOL BODY"}')


def req(text="hello", context=(), history=(), canary="IPX-AAAAABBBBB"):
    msgs = [Message(role=r, content=c) for r, c in history] + [Message(role="user", content=text)]
    return TargetRequest(messages=msgs, context=list(context), canary=canary)


# --------------------------------------------------------------------------- jsonpath


def test_jsonpath():
    data = {"a": {"b": [{"c": 1}, {"c": 2}]}, "x y": "z", "out": {"text": "hi"}}
    assert find(data, "$.a.b[1].c") == 2
    assert find(data, "$.a.b[-1].c") == 2
    assert find(data, "$['x y']") == "z"
    assert find(data, '$["out"].text') == "hi"
    assert find(data, "$.a.b[*].c") == [1, 2]
    assert find(data, "$") == data
    with pytest.raises(KeyError):
        find(data, "$.missing")
    with pytest.raises(JsonPathError):
        find(data, "a.b")
    with pytest.raises(JsonPathError):
        find(data, "$..deep")


# --------------------------------------------------------------------------- http


def http_target(handler, **cfg):
    base = {"type": "http", "url": "http://localhost:9/chat"}
    base.update(cfg)
    return HttpTarget(HttpTargetConfig(**base), transport=httpx.MockTransport(handler))


def test_build_body_placeholders():
    tpl = {"q": "{{message}}", "hist": "{{history}}", "docs": "{{documents}}", "ctx": "C: {{context}}", "n": 1}
    body = build_body(tpl, req("hi", [DOC], history=[("user", "a"), ("assistant", "b")]))
    assert body["q"] == "hi" and body["n"] == 1
    assert [m["role"] for m in body["hist"]] == ["user", "assistant", "user"]
    assert body["docs"][0] == {"kind": "document", "title": "report.txt", "content": "DOC BODY"}
    assert "DOC BODY" in body["ctx"]


def test_build_body_inlines_context_without_placeholder():
    body = build_body({"message": "{{message}}"}, req("question?", [DOC]))
    assert body["message"].startswith("--- Document: report.txt ---")
    assert body["message"].endswith("question?")


def test_http_send_and_parse_reply_and_tool_calls():
    seen = {}

    def handler(r: httpx.Request):
        seen["body"] = json.loads(r.content)
        seen["auth"] = r.headers.get("authorization")
        return httpx.Response(200, json={"data": {"reply": "ok!"}, "calls": [
            {"name": "send_email", "arguments": '{"to": "x@canary.invalid"}'},
            {"function": {"name": "fetch_url", "arguments": {"url": "u"}}},
        ]})

    t = http_target(handler, response_path="$.data.reply", tool_calls_path="$.calls",
                    headers={"Authorization": "Bearer ${IP_HTTP_KEY}"})
    import os
    os.environ["IP_HTTP_KEY"] = "http-secret-123"
    try:
        resp = run(t.send(req("hi")))
    finally:
        del os.environ["IP_HTTP_KEY"]
    assert resp.text == "ok!"
    assert seen["body"] == {"message": "hi"}
    assert seen["auth"] == "Bearer http-secret-123"
    assert [c.name for c in resp.tool_calls] == ["send_email", "fetch_url"]
    assert resp.tool_calls[0].arguments == {"to": "x@canary.invalid"}
    assert "http-secret-123" not in secrets.redact("leak http-secret-123")


def test_http_missing_env_is_config_error(monkeypatch):
    monkeypatch.delenv("IP_NOPE", raising=False)
    t = http_target(lambda r: httpx.Response(200), headers={"X-Key": "${IP_NOPE}"})
    with pytest.raises(ConfigError):
        run(t.start())


@pytest.mark.parametrize("status,retryable", [(503, True), (429, True), (400, False), (404, False)])
def test_http_error_status(status, retryable):
    t = http_target(lambda r: httpx.Response(status, text="nope"))
    with pytest.raises(TargetError) as e:
        run(t.send(req()))
    assert e.value.retryable is retryable


def test_http_connection_error_retryable():
    def boom(r):
        raise httpx.ConnectError("refused")

    with pytest.raises(TargetError) as e:
        run(http_target(boom).send(req()))
    assert e.value.retryable


def test_http_non_json_and_missing_path():
    t = http_target(lambda r: httpx.Response(200, text="plain"), response_path="$")
    assert run(t.send(req())).text == "plain"
    t2 = http_target(lambda r: httpx.Response(200, text="plain"))
    with pytest.raises(TargetError):
        run(t2.send(req()))
    t3 = http_target(lambda r: httpx.Response(200, json={"other": 1}))
    with pytest.raises(TargetError):
        run(t3.send(req()))


def test_http_non_string_reply_serialized():
    t = http_target(lambda r: httpx.Response(200, json={"reply": {"a": 1}}))
    assert json.loads(run(t.send(req())).text) == {"a": 1}


def test_http_get_uses_query_params():
    seen = {}

    def handler(r):
        seen["q"] = r.url.params.get("message")
        return httpx.Response(200, json={"reply": "ok"})

    run(http_target(handler, method="GET").send(req("hey")))
    assert seen["q"] == "hey"


def test_http_describe_hides_credentials_and_query():
    t = HttpTarget(HttpTargetConfig(type="http", url="https://user:pw@api.example.com/chat?key=secret"))
    assert t.describe().endpoint == "https://api.example.com/chat"


def test_http_bad_jsonpath_is_config_error():
    with pytest.raises(ConfigError):
        HttpTarget(HttpTargetConfig(type="http", url="http://localhost", response_path="reply"))


def test_parse_tool_calls_tolerant():
    calls = parse_tool_calls([{"name": "a", "arguments": "not json"}, "junk", {"no_name": 1}, {"name": "b", "input": [1]}])
    assert [c.name for c in calls] == ["a", "b"]
    assert calls[0].arguments == {"raw": "not json"}
    assert parse_tool_calls(None) == []


# --------------------------------------------------------------------------- openai


def openai_target(handler, monkeypatch, **cfg):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-openai-000000")
    base = {"type": "openai", "model": "gpt-test", "base_url": "http://localhost:1/v1",
            "system_prompt": "You are ShopBot.", "plant_system_canary": True}
    base.update(cfg)
    return OpenAITarget(OpenAITargetConfig(**base), transport=httpx.MockTransport(handler))


def test_openai_payload_and_response(monkeypatch):
    seen = {}

    def handler(r):
        seen["url"] = str(r.url)
        seen["auth"] = r.headers["authorization"]
        seen["body"] = json.loads(r.content)
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "answer", "tool_calls": [
                {"id": "1", "type": "function", "function": {"name": "send_email", "arguments": '{"to": "a@canary.invalid"}'}}
            ]}}],
            "usage": {"prompt_tokens": 50, "completion_tokens": 7},
        })

    t = openai_target(handler, monkeypatch, temperature=0.2, extra_body={"seed": 7})
    resp = run(t.send(req("What does the policy say?", [DOC, TOOL], history=[("user", "hi"), ("assistant", "hello")])))
    body = seen["body"]
    assert seen["url"].endswith("/v1/chat/completions") and seen["auth"] == "Bearer sk-test-openai-000000"
    roles = [m["role"] for m in body["messages"]]
    assert roles == ["system", "user", "assistant", "user", "assistant", "tool"]
    assert "IPX-AAAAABBBBB" in body["messages"][0]["content"]  # planted canary
    assert "DOC BODY" in body["messages"][3]["content"]  # inline document
    assert body["messages"][4]["tool_calls"][0]["function"]["name"] == "search_knowledge_base"
    assert body["messages"][5] == {"role": "tool", "tool_call_id": "call_0", "content": '{"r": "TOOL BODY"}'}
    tool_names = {t["function"]["name"] for t in body["tools"]}
    assert {"send_email", "fetch_url", "search_knowledge_base"} <= tool_names
    assert body["temperature"] == 0.2 and body["seed"] == 7
    assert resp.text == "answer" and resp.tool_calls[0].arguments["to"] == "a@canary.invalid"
    assert (resp.input_tokens, resp.output_tokens) == (50, 7)
    assert t.plants_system_canary


def test_openai_tool_results_as_text(monkeypatch):
    seen = {}

    def handler(r):
        seen["body"] = json.loads(r.content)
        return httpx.Response(200, json={"choices": [{"message": {"content": "x"}}]})

    run(openai_target(handler, monkeypatch, tool_results_as="text").send(req("q", [TOOL])))
    assert [m["role"] for m in seen["body"]["messages"]] == ["system", "user"]
    assert "TOOL BODY" in seen["body"]["messages"][1]["content"]


def test_openai_errors(monkeypatch):
    with pytest.raises(TargetError) as e:
        run(openai_target(lambda r: httpx.Response(429), monkeypatch).send(req()))
    assert e.value.retryable
    with pytest.raises(TargetError) as e:
        run(openai_target(lambda r: httpx.Response(401, text="bad key"), monkeypatch).send(req()))
    assert not e.value.retryable
    with pytest.raises(TargetError):
        run(openai_target(lambda r: httpx.Response(200, json={"nope": 1}), monkeypatch).send(req()))


def test_openai_missing_key(monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    t = OpenAITarget(OpenAITargetConfig(type="openai", model="m"))
    with pytest.raises(ConfigError):
        run(t.start())


def test_openai_no_key_needed_for_local(monkeypatch):
    seen = {}

    def handler(r):
        seen["auth"] = r.headers.get("authorization")
        return httpx.Response(200, json={"choices": [{"message": {"content": "x"}}]})

    t = OpenAITarget(OpenAITargetConfig(type="openai", model="llama", api_key_env=None, base_url="http://localhost:11434/v1"),
                     transport=httpx.MockTransport(handler))
    run(t.send(req()))
    assert seen["auth"] is None


def test_system_prompt_file(tmp_path):
    (tmp_path / "sp.txt").write_text("You are FileBot.")
    t = OpenAITarget(OpenAITargetConfig(type="openai", model="m", system_prompt_file="sp.txt"), base_dir=tmp_path)
    assert t.build_payload(req())["messages"][0]["content"] == "You are FileBot."
    with pytest.raises(ConfigError):
        OpenAITarget(OpenAITargetConfig(type="openai", model="m", system_prompt_file="missing.txt"), base_dir=tmp_path)


# --------------------------------------------------------------------------- anthropic


class FakeAnthropicClient:
    def __init__(self, content, stop_reason="end_turn", usage=(12, 3), error=None):
        self.params = None
        outer = self

        class Messages:
            async def create(self, **kw):
                outer.params = kw
                if error is not None:
                    raise error
                return SimpleNamespace(content=content, stop_reason=stop_reason,
                                       usage=SimpleNamespace(input_tokens=usage[0], output_tokens=usage[1]))

        self.messages = Messages()

    async def close(self):
        pass


def anthropic_target(client, **cfg):
    base = {"type": "anthropic", "system_prompt": "You are HelpBot.", "plant_system_canary": True}
    base.update(cfg)
    return AnthropicTarget(AnthropicTargetConfig(**base), client=client)


def test_anthropic_params_and_response():
    content = [SimpleNamespace(type="text", text="Sure."),
               SimpleNamespace(type="tool_use", name="fetch_url", input={"url": "http://127.0.0.1/c/X"})]
    fake = FakeAnthropicClient(content)
    t = anthropic_target(fake, effort="low", extra_body={"metadata": {"user_id": "probe"}})
    resp = run(t.send(req("What is the refund policy?", [DOC, TOOL], history=[("user", "hi"), ("assistant", "hey")])))
    p = fake.params
    assert p["model"] == "claude-opus-5-5" and p["max_tokens"] == 16000
    assert "temperature" not in p
    assert p["system"].startswith("You are HelpBot.") and "IPX-AAAAABBBBB" in p["system"]
    assert p["output_config"] == {"effort": "low"}
    assert p["extra_body"] == {"metadata": {"user_id": "probe"}}
    roles = [m["role"] for m in p["messages"]]
    assert roles == ["user", "assistant", "user", "assistant", "user"]
    assert "DOC BODY" in p["messages"][2]["content"]
    use = p["messages"][3]["content"][0]
    result = p["messages"][4]["content"][0]
    assert use["type"] == "tool_use" and use["name"] == "search_knowledge_base"
    assert result == {"type": "tool_result", "tool_use_id": use["id"], "content": '{"r": "TOOL BODY"}'}
    assert {t["name"] for t in p["tools"]} >= {"send_email", "fetch_url", "search_knowledge_base"}
    assert all("input_schema" in t for t in p["tools"])
    assert resp.text == "Sure." and resp.tool_calls[0].name == "fetch_url"
    assert (resp.input_tokens, resp.output_tokens) == (12, 3)


def test_anthropic_refusal_marker():
    t = anthropic_target(FakeAnthropicClient([], stop_reason="refusal"))
    assert run(t.send(req())).text == "[refused by the model]"


def test_anthropic_no_system_when_not_configured():
    fake = FakeAnthropicClient([SimpleNamespace(type="text", text="x")])
    run(anthropic_target(fake, system_prompt=None, plant_system_canary=False).send(req()))
    assert "system" not in fake.params and "output_config" not in fake.params


def _sdk_errors():
    import anthropic

    try:
        import httpx2 as hx
    except ImportError:  # pragma: no cover
        import httpx as hx
    r = hx.Request("POST", "https://api.anthropic.com/v1/messages")
    return anthropic, hx, r


def test_anthropic_error_classification():
    anthropic, hx, r = _sdk_errors()
    cases = [
        (anthropic.RateLimitError("rate", response=hx.Response(429, request=r), body=None), True),
        (anthropic.APIStatusError("overloaded", response=hx.Response(529, request=r), body=None), True),
        (anthropic.APIStatusError("bad", response=hx.Response(400, request=r), body=None), False),
        (anthropic.APIConnectionError(request=r), True),
        (anthropic.APITimeoutError(request=r), True),
    ]
    for exc, retryable in cases:
        mapped = classify_error(exc)
        assert mapped is not None and mapped.retryable is retryable, exc
    assert classify_error(ValueError("x")) is None


def test_anthropic_send_maps_sdk_errors():
    anthropic, hx, r = _sdk_errors()
    err = anthropic.RateLimitError("rate", response=hx.Response(429, request=r), body=None)
    with pytest.raises(TargetError) as e:
        run(anthropic_target(FakeAnthropicClient([], error=err)).send(req()))
    assert e.value.retryable


def test_anthropic_missing_key(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    t = AnthropicTarget(AnthropicTargetConfig(type="anthropic"))
    with pytest.raises(ConfigError):
        run(t.start())


# --------------------------------------------------------------------------- callable


def test_callable_sync_async_and_dict():
    t = CallableTarget(CallableTargetConfig(type="callable", import_path="x:y"), fn=lambda s: s.upper())
    assert run(t.send(req("hi"))).text == "HI"

    async def agent(s):
        return {"text": "done", "tool_calls": [{"name": "send_email", "arguments": {"to": "z"}}]}

    t2 = CallableTarget(CallableTargetConfig(type="callable", import_path="x:y"), fn=agent)
    resp = run(t2.send(req()))
    assert resp.text == "done" and resp.tool_calls[0].name == "send_email"


def test_callable_errors_become_target_errors():
    def bad(s):
        raise RuntimeError("agent crashed")

    t = CallableTarget(CallableTargetConfig(type="callable", import_path="x:y"), fn=bad)
    with pytest.raises(TargetError) as e:
        run(t.send(req()))
    assert "agent crashed" in str(e.value) and not e.value.retryable


def test_callable_receives_context_and_transcript():
    seen = []
    t = CallableTarget(CallableTargetConfig(type="callable", import_path="x:y"), fn=lambda s: seen.append(s) or "ok")
    run(t.send(req("q", [DOC])))
    assert "DOC BODY" in seen[0] and seen[0].endswith("q")
    text = transcript(req("third", history=[("user", "first"), ("assistant", "second")]))
    assert text == "User: first\nAssistant: second\nUser: third"


def test_load_callable_from_python_path(tmp_path):
    pkg = tmp_path / "agents_pkg_ip"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "bot.py").write_text("def handle(msg):\n    return 'echo: ' + msg\n")
    fn = load_callable("agents_pkg_ip.bot:handle", ["."], base_dir=tmp_path)
    assert fn("x") == "echo: x"
    assert load_callable("agents_pkg_ip.bot.handle")("y") == "echo: y"
    with pytest.raises(ConfigError):
        load_callable("agents_pkg_ip.bot:nope")
    with pytest.raises(ConfigError):
        load_callable("no_such_module_ip:fn")
    with pytest.raises(ConfigError):
        load_callable("justaname")
    sys.modules.pop("agents_pkg_ip.bot", None)


# --------------------------------------------------------------------------- registry


def test_build_target_all_types(monkeypatch, tmp_path):
    (tmp_path / "m_ip.py").write_text("def f(s):\n    return s\n")
    for t, cls in (
        ({"type": "http", "url": "http://localhost:1"}, HttpTarget),
        ({"type": "openai", "model": "m"}, OpenAITarget),
        ({"type": "anthropic"}, AnthropicTarget),
        ({"type": "callable", "import_path": "m_ip:f", "python_path": [str(tmp_path)]}, CallableTarget),
    ):
        assert isinstance(build_target(parse_config({"target": t})), cls)
