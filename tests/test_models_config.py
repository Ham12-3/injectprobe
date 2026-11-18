from datetime import datetime, timezone

import pytest

from injectprobe import secrets
from injectprobe.config import (
    ConfigError,
    check_authorised,
    is_local_host,
    is_local_target,
    load_config,
    parse_config,
)
from injectprobe.models import (
    Attack,
    AttackResult,
    Attempt,
    Delivery,
    RunResult,
    Severity,
    TargetInfo,
)


def test_attack_requires_payload_or_turns():
    with pytest.raises(ValueError):
        Attack(id="a", category="c", severity="low", description="d")
    with pytest.raises(ValueError):
        Attack(id="a", category="c", severity="low", description="d", payload="x", turns=["y"])


def test_indirect_attack_requires_carrier():
    with pytest.raises(ValueError):
        Attack(id="a", category="c", severity="low", description="d", payload="x", delivery="indirect")
    a = Attack(
        id="a", category="c", severity="low", description="d", payload="x",
        delivery="indirect", carrier="email",
    )
    assert a.delivery == Delivery.indirect


def test_carrier_template_needs_payload_slot():
    with pytest.raises(ValueError):
        Attack(
            id="a", category="c", severity="low", description="d", payload="x",
            delivery="indirect", carrier="email", carrier_template="no slot",
        )


def test_attack_id_pattern():
    with pytest.raises(ValueError):
        Attack(id="Bad Id", category="c", severity="low", description="d", payload="x")


def _result(rates):
    results = []
    for i, (succ, total) in enumerate(rates):
        attempts = [Attempt(trial=t, canary="X", success=t < succ) for t in range(total)]
        results.append(
            AttackResult(
                id=f"a{i}", attack_id=f"a{i}", category="instruction_override",
                severity=Severity.high, description="", delivery=Delivery.direct,
                attempts=attempts,
            )
        )
    now = datetime.now(timezone.utc)
    return RunResult(
        tool_version="0", started_at=now, finished_at=now,
        target=TargetInfo(type="mock"), threshold=0.25, trials=3, results=results,
    )


def test_summary_and_threshold():
    r = _result([(0, 3), (3, 3), (1, 3)])
    s = r.compute_summary()
    assert s.attempts == 9
    assert s.successful_attempts == 4
    assert s.vulnerable_attacks == 2
    assert s.by_category["instruction_override"].attacks == 3
    assert r.evaluate() is False  # 4/9 > 0.25
    r2 = _result([(0, 3), (0, 3)])
    r2.compute_summary()
    assert r2.evaluate() is True


def test_errors_excluded_from_rate():
    r = _result([(1, 2)])
    r.results[0].attempts.append(Attempt(trial=2, canary="X", error="timeout"))
    assert r.results[0].success_rate == 0.5
    assert r.results[0].errors == 1


def test_failing_sorted():
    r = _result([(1, 3), (3, 3), (0, 3)])
    assert [x.id for x in r.failing()] == ["a1", "a0"]


def test_parse_minimal_config():
    cfg = parse_config({"target": {"type": "mock"}})
    assert cfg.run.trials == 3
    assert cfg.threshold == 0.1
    assert cfg.reports.formats == ["json", "junit", "sarif", "markdown"]


def test_config_rejects_unknown_keys():
    with pytest.raises(ConfigError) as e:
        parse_config({"target": {"type": "mock"}, "nope": 1})
    assert "nope" in str(e.value)


def test_config_bad_target_type():
    with pytest.raises(ConfigError):
        parse_config({"target": {"type": "carrier-pigeon"}})


def test_load_config_missing(tmp_path):
    with pytest.raises(ConfigError):
        load_config(tmp_path / "missing.yaml")


def test_load_config_file(tmp_path):
    p = tmp_path / "injectprobe.yaml"
    p.write_text("target:\n  type: http\n  url: http://localhost:8000/chat\nrun:\n  trials: 5\n")
    cfg = load_config(p)
    assert cfg.run.trials == 5
    assert cfg.base_dir == tmp_path.resolve()


@pytest.mark.parametrize(
    "host,expected",
    [("localhost", True), ("127.0.0.1", True), ("::1", True), ("[::1]", True),
     ("app.localhost", True), ("example.com", False), ("10.0.0.1", False), (None, False)],
)
def test_is_local_host(host, expected):
    assert is_local_host(host) is expected


def test_authorised_required_for_remote():
    cfg = parse_config({"target": {"type": "http", "url": "https://api.example.com/chat"}})
    assert not is_local_target(cfg)
    with pytest.raises(ConfigError) as e:
        check_authorised(cfg)
    assert "authorised: true" in str(e.value)
    cfg2 = parse_config(
        {"target": {"type": "http", "url": "https://api.example.com/chat"}, "authorised": True}
    )
    check_authorised(cfg2)


def test_local_and_inprocess_targets_need_no_authorisation():
    for t in (
        {"type": "http", "url": "http://127.0.0.1:9000"},
        {"type": "callable", "import_path": "x:y"},
        {"type": "mock"},
        {"type": "openai", "model": "m", "base_url": "http://localhost:11434/v1"},
    ):
        check_authorised(parse_config({"target": t}))


def test_remote_chat_api_needs_authorisation():
    cfg = parse_config({"target": {"type": "anthropic"}})
    with pytest.raises(ConfigError):
        check_authorised(cfg)


def test_secret_expand_and_redact(monkeypatch):
    secrets.clear()
    monkeypatch.setenv("IP_TEST_KEY", "supersecretvalue123")
    out = secrets.expand("Bearer ${IP_TEST_KEY}")
    assert out == "Bearer supersecretvalue123"
    assert "supersecretvalue123" not in secrets.redact(f"error: {out}")
    assert secrets.REDACTED in secrets.redact("key supersecretvalue123")


def test_secret_missing(monkeypatch):
    monkeypatch.delenv("IP_NOT_SET", raising=False)
    with pytest.raises(secrets.MissingSecretError):
        secrets.expand("${IP_NOT_SET}")


def test_redact_unregistered_bearer():
    assert "abcdefghijklmnop" not in secrets.redact("Authorization: Bearer abcdefghijklmnop")
