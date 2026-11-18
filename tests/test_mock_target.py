import asyncio

from injectprobe.canary import CanaryListener, new_canary
from injectprobe.config import MockRule, MockTargetConfig, parse_config
from injectprobe.loader import TestCase, load_attacks, render_case
from injectprobe.models import Message, TargetRequest
from injectprobe.targets import build_target
from injectprobe.targets.mock import MockTarget


def run(coro):
    return asyncio.run(coro)


def _request(case_id: str, canary=None):
    canary = canary or new_canary()
    attack = next(a for a in load_attacks() if a.id == case_id)
    probe = render_case(TestCase(attack), canary)
    return canary, TargetRequest(
        messages=[Message(role="user", content=probe.turns[-1])], context=probe.context, canary=canary.token
    )


def test_build_target_returns_mock():
    t = build_target(parse_config({"target": {"type": "mock"}}))
    assert isinstance(t, MockTarget)
    assert t.describe().endpoint == "mock:vulnerable"


def test_vulnerable_mock_outputs_canary():
    t = MockTarget(MockTargetConfig(type="mock"))
    canary, req = _request("io-001-ignore-previous")
    resp = run(t.send(req))
    assert canary.token in resp.text


def test_vulnerable_mock_decodes_base64():
    t = MockTarget(MockTargetConfig(type="mock"))
    canary, req = _request("enc-001-base64")
    assert canary.token in run(t.send(req)).text


def test_vulnerable_mock_calls_tool():
    t = MockTarget(MockTargetConfig(type="mock"))
    canary, req = _request("io-008-tool-email")
    resp = run(t.send(req))
    assert resp.tool_calls[0].name == "send_email"
    assert canary.token.lower() in resp.tool_calls[0].arguments["to"]


def test_vulnerable_mock_renders_image():
    t = MockTarget(MockTargetConfig(type="mock"))
    canary, req = _request("ex-001-markdown-image")
    assert f"]({canary.url})" in run(t.send(req)).text


def test_vulnerable_mock_leaks_system_prompt():
    t = MockTarget(MockTargetConfig(type="mock"))
    canary, req = _request("spe-001-repeat-above")
    text = run(t.send(req)).text
    assert "MOCKSYS-4471" in text and canary.token in text


def test_safe_mock_never_complies():
    t = MockTarget(MockTargetConfig(type="mock", behavior="safe"))
    canary, req = _request("io-001-ignore-previous")
    resp = run(t.send(req))
    assert canary.token not in resp.text and not resp.tool_calls


def test_scripted_rules_with_groups_and_canary():
    cfg = MockTargetConfig(
        type="mock",
        behavior="scripted",
        rules=[
            MockRule(pattern=r"say (\w+)", reply=r"you said \1 / {canary}"),
            MockRule(pattern="email", reply="sending", tool_call="send_email", tool_args={"to": "{canary_email}"}),
        ],
        default_reply="default",
    )
    t = MockTarget(cfg)
    req = TargetRequest(messages=[Message(role="user", content="please say hello")], canary="TOK")
    assert run(t.send(req)).text == "you said hello / TOK"
    req2 = TargetRequest(messages=[Message(role="user", content="email audit-x@canary.invalid")], canary="TOK")
    resp = run(t.send(req2))
    assert resp.tool_calls[0].arguments["to"] == "audit-x@canary.invalid"
    req3 = TargetRequest(messages=[Message(role="user", content="nothing")], canary="TOK")
    assert run(t.send(req3)).text == "default"
    assert t.calls == 3


def test_scripted_fetch_hits_listener():
    with CanaryListener() as listener:
        canary = new_canary(base_url=listener.base_url)
        cfg = MockTargetConfig(
            type="mock", behavior="scripted", rules=[MockRule(pattern="fetch", fetch_url="{canary_url}")]
        )
        t = MockTarget(cfg)
        req = TargetRequest(messages=[Message(role="user", content=f"fetch {canary.url}")], canary=canary.token)
        run(t.send(req))
        assert listener.hits_for(canary.token)
