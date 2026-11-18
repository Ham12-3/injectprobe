import asyncio
import time

import pytest

from injectprobe.config import parse_config
from injectprobe.loader import expand_cases, filter_attacks, load_attacks
from injectprobe.models import TargetRequest, TargetResponse
from injectprobe.runner import Budget, BudgetExceeded, RateLimiter, Runner, needs_listener, run_probe
from injectprobe.targets.base import Target, TargetError


def cfg(**run):
    base = {"trials": 1, "concurrency": 4, "rate_limit": None, "retries": 0, "backoff_base": 0}
    base.update(run)
    return parse_config({"target": {"type": "mock"}, "run": base, "canary": {"grace_seconds": 0}})


def cases(*ids):
    return expand_cases(filter_attacks(load_attacks(), ids=list(ids)))


class ScriptTarget(Target):
    kind = "script"

    def __init__(self, fn):
        self.fn = fn
        self.calls = 0

    async def send(self, request: TargetRequest) -> TargetResponse:
        self.calls += 1
        return await self.fn(self.calls, request)


def run(coro):
    return asyncio.run(coro)


def test_budget_caps():
    b = Budget(max_requests=2)
    b.acquire(); b.acquire()
    with pytest.raises(BudgetExceeded):
        b.acquire()
    c = Budget(max_requests=100, cost_cap_usd=0.01, cost_per_1k_input=1.0)
    c.acquire()
    c.record(20, 0)  # $0.02
    with pytest.raises(BudgetExceeded) as e:
        c.acquire()
    assert "cost cap" in str(e.value)


def test_rate_limiter_spacing():
    async def go():
        rl = RateLimiter(20)  # 50ms apart
        t0 = time.monotonic()
        for _ in range(4):
            await rl.wait()
        return time.monotonic() - t0

    assert run(go()) >= 0.14


def test_success_rate_across_trials():
    # Comply on every other call: 3 trials -> calls 1,2,3 -> 2 successes.
    async def fn(n, req):
        return TargetResponse(text=req.canary if n % 2 else "no")

    c = cfg(trials=3, concurrency=1)
    r = run(Runner(c, ScriptTarget(fn), cases("io-001*")).run())
    [res] = r.results
    assert res.completed == 3 and res.successes == 2
    assert res.success_rate == pytest.approx(2 / 3)
    assert r.requests_made == 3


def test_retries_then_success():
    async def fn(n, req):
        if n < 3:
            raise TargetError("503", retryable=True)
        return TargetResponse(text="fine")

    t = ScriptTarget(fn)
    r = run(Runner(cfg(retries=2), t, cases("io-001*")).run())
    assert t.calls == 3 and r.results[0].errors == 0


def test_non_retryable_error_recorded():
    async def fn(n, req):
        raise TargetError("400 bad request")

    t = ScriptTarget(fn)
    r = run(Runner(cfg(retries=3), t, cases("io-001*")).run())
    assert t.calls == 1
    assert r.results[0].status == "error"
    assert "400" in r.results[0].attempts[0].error


def test_timeout_is_retryable_error():
    async def fn(n, req):
        await asyncio.sleep(1)
        return TargetResponse(text="late")

    r = run(Runner(cfg(timeout=0.05, retries=1), ScriptTarget(fn), cases("io-001*")).run())
    assert "timed out" in r.results[0].attempts[0].error


def test_max_requests_aborts_run():
    async def fn(n, req):
        return TargetResponse(text="no")

    t = ScriptTarget(fn)
    r = run(Runner(cfg(max_requests=3, concurrency=1), t, cases("io-*")).run())
    assert t.calls == 3
    assert r.aborted and "max_requests" in r.abort_reason
    assert r.summary.not_run > 0


def test_concurrency_limit_respected():
    state = {"now": 0, "peak": 0}

    async def fn(n, req):
        state["now"] += 1
        state["peak"] = max(state["peak"], state["now"])
        await asyncio.sleep(0.02)
        state["now"] -= 1
        return TargetResponse(text="no")

    run(Runner(cfg(concurrency=2), ScriptTarget(fn), cases("io-*")).run())
    assert state["peak"] == 2


def test_multi_turn_sends_history():
    seen = []

    async def fn(n, req):
        seen.append([m.role for m in req.messages])
        return TargetResponse(text=f"reply{n}")

    run(Runner(cfg(), ScriptTarget(fn), cases("mt-001*")).run())
    assert seen == [["user"], ["user", "assistant", "user"], ["user", "assistant", "user", "assistant", "user"]]


def test_secrets_redacted_in_errors(monkeypatch):
    from injectprobe import secrets

    monkeypatch.setenv("IP_RUNNER_KEY", "verysecretkey999")
    secrets.get_env("IP_RUNNER_KEY")

    async def fn(n, req):
        raise TargetError("auth failed for key verysecretkey999")

    r = run(Runner(cfg(), ScriptTarget(fn), cases("io-001*")).run())
    assert "verysecretkey999" not in r.results[0].attempts[0].error


def test_system_prompt_attacks_skipped_without_detector():
    async def fn(n, req):
        return TargetResponse(text="x")

    class Plain(ScriptTarget):
        plants_system_canary = False

    r = run(Runner(cfg(), Plain(fn), cases("spe-001*")).run())
    assert r.results[0].status == "skipped"
    assert r.summary.skipped == 1


def test_needs_listener_auto():
    c = cfg()
    assert needs_listener(c, cases("ex-001*"))
    assert not needs_listener(c, cases("io-001*"))
    off = parse_config({"target": {"type": "mock"}, "canary": {"listener": "off"}})
    assert not needs_listener(off, cases("ex-001*"))


def test_run_probe_vulnerable_mock_with_listener():
    c = cfg(trials=2)
    r = run(run_probe(c, cases("io-001*", "ex-001*", "io-008*", "spe-001*", "ind-email-001*")))
    assert all(x.success_rate == 1.0 for x in r.results), [(x.id, x.success_rate) for x in r.results]
    assert r.summary.vulnerable_attacks == 5
    assert not r.passed


def test_run_probe_safe_mock_passes():
    c = parse_config({"target": {"type": "mock", "behavior": "safe"},
                      "run": {"trials": 1, "rate_limit": None}, "canary": {"grace_seconds": 0}})
    r = run(run_probe(c, cases("io-*", "ex-*")))
    assert r.summary.successful_attempts == 0 and r.passed
