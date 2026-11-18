"""Runs test cases against a target with concurrency, rate limits, retries and budgets."""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

import httpx

from . import __version__, secrets
from .canary import DEFAULT_CANARY_BASE, CanaryListener, new_canary, placeholder_canary
from .config import Config
from .detectors import Evidence, available_detectors, evaluate
from .judge import LLMJudge
from .loader import RenderedProbe, TestCase, render_case
from .models import (
    AttackResult,
    Attempt,
    CanaryChannel,
    Message,
    RunResult,
    TargetRequest,
    TargetResponse,
    ToolCall,
)
from .targets.base import Target, TargetError, build_target


class BudgetExceeded(Exception):
    pass


class Budget:
    """Hard caps on request count and estimated spend."""

    def __init__(
        self,
        max_requests: int,
        cost_cap_usd: float | None = None,
        cost_per_1k_input: float = 0.0,
        cost_per_1k_output: float = 0.0,
    ):
        self.max_requests = max_requests
        self.cost_cap_usd = cost_cap_usd
        self.cost_per_1k_input = cost_per_1k_input
        self.cost_per_1k_output = cost_per_1k_output
        self.requests = 0
        self.cost_usd = 0.0
        self.exceeded: str | None = None

    def acquire(self) -> None:
        if self.exceeded:
            raise BudgetExceeded(self.exceeded)
        if self.requests >= self.max_requests:
            self.exceeded = f"max_requests ({self.max_requests}) reached"
            raise BudgetExceeded(self.exceeded)
        if self.cost_cap_usd is not None and self.cost_usd >= self.cost_cap_usd:
            self.exceeded = f"cost cap (${self.cost_cap_usd:.2f}) reached"
            raise BudgetExceeded(self.exceeded)
        self.requests += 1

    async def acquire_async(self) -> None:
        self.acquire()

    def record(self, input_tokens: int, output_tokens: int) -> None:
        self.cost_usd += (
            input_tokens / 1000 * self.cost_per_1k_input + output_tokens / 1000 * self.cost_per_1k_output
        )


def estimate_tokens(text: str) -> int:
    return max(1, len(text) // 4)


class RateLimiter:
    """Spaces request starts evenly so we never exceed ``rate`` per second."""

    def __init__(self, rate: float | None):
        self.interval = 1.0 / rate if rate else 0.0
        self._next = 0.0
        self._lock = asyncio.Lock()

    async def wait(self) -> None:
        if not self.interval:
            return
        async with self._lock:
            now = time.monotonic()
            delay = max(0.0, self._next - now)
            self._next = max(now, self._next) + self.interval
        if delay:
            await asyncio.sleep(delay)


@dataclass
class _CasePlan:
    case: TestCase
    result: AttackResult
    uses_listener: bool
    attempts: list[Attempt] = field(default_factory=list)


ProgressFn = Callable[[int], None]
EventFn = Callable[[dict[str, Any]], None]


def _excerpt(text: str, limit: int = 400) -> str:
    text = secrets.redact(text or "")
    return text if len(text) <= limit else text[: limit - 1] + "…"


class Runner:
    def __init__(
        self,
        cfg: Config,
        target: Target,
        cases: list[TestCase],
        *,
        listener: CanaryListener | None = None,
        judge: LLMJudge | None = None,
        progress: ProgressFn | None = None,
        config_path: str | None = None,
        on_event: EventFn | None = None,
    ):
        self.cfg = cfg
        self.on_event = on_event
        self.target = target
        self.cases = cases
        self.listener = listener
        self.judge = judge
        self.progress = progress or (lambda n: None)
        self.config_path = config_path
        r = cfg.run
        self.budget = Budget(r.max_requests, r.cost_cap_usd, r.cost_per_1k_input_tokens, r.cost_per_1k_output_tokens)
        self.limiter = RateLimiter(r.rate_limit)
        if judge is not None:
            judge.before_request = self.budget.acquire_async

    @property
    def total_attempts(self) -> int:
        return len(self.cases) * self.cfg.run.trials

    # ------------------------------------------------------------------ helpers
    def _preview(self, case: TestCase) -> str:
        p = render_case(case, placeholder_canary())
        parts = []
        for c in p.context:
            parts.append(f"[{c.kind.value}: {c.title}]\n{c.content}")
        if len(p.turns) == 1:
            parts.append(("[user]\n" if p.context else "") + p.turns[0])
        else:
            parts.extend(f"[turn {i + 1}]\n{t}" for i, t in enumerate(p.turns))
        return "\n\n".join(parts)

    def _emit(self, kind: str, **data: Any) -> None:
        """Report progress to an optional observer (the web app's live log). Never raises."""
        if self.on_event is None:
            return
        try:
            self.on_event({"type": kind, "time": time.time(), **data})
        except Exception:  # noqa: BLE001 - an observer must not break the run
            pass

    def _canary_base(self) -> str:
        if self.listener is not None:
            return self.listener.base_url
        return (self.cfg.canary.public_url or DEFAULT_CANARY_BASE).rstrip("/")

    async def _send(self, request: TargetRequest, label: str = "") -> TargetResponse:
        r = self.cfg.run
        last: Exception | None = None
        for i in range(r.retries + 1):
            self.budget.acquire()
            await self.limiter.wait()
            try:
                resp = await asyncio.wait_for(self.target.send(request), timeout=r.timeout)
            except asyncio.TimeoutError:
                last = TargetError(f"timed out after {r.timeout:g}s", retryable=True)
            except TargetError as e:
                if not e.retryable:
                    raise
                last = e
            except httpx.TransportError as e:
                last = TargetError(f"transport error: {e}", retryable=True)
            else:
                sent = "".join(m.content for m in request.messages) + "".join(c.content for c in request.context)
                self.budget.record(
                    resp.input_tokens if resp.input_tokens is not None else estimate_tokens(sent),
                    resp.output_tokens if resp.output_tokens is not None else estimate_tokens(resp.text),
                )
                return resp
            if i < r.retries:
                self._emit("retry", attempt=label, reason=_excerpt(str(last), 200), retry=i + 1)
                await asyncio.sleep(r.backoff_base * (2**i) * (1 + random.random() * 0.25))
        assert last is not None
        raise last

    async def _attempt(self, plan: _CasePlan, trial: int) -> Attempt:
        canary = new_canary(self.cfg.canary.prefix, self._canary_base())
        probe: RenderedProbe = render_case(plan.case, canary)
        a = plan.case.attack
        label = f"{plan.case.id}#{trial + 1}"
        self._emit(
            "attempt_start", attempt=label, attack=plan.case.id, trial=trial + 1, category=a.category,
            severity=a.severity.value, delivery=a.delivery.value,
            carrier=a.carrier.value if a.carrier else None, canary=canary.token, turns=len(probe.turns),
            sent=_excerpt(probe.turns[0]),
            planted=_excerpt(probe.context[0].content) if probe.context else None,
        )
        messages: list[Message] = []
        replies: list[str] = []
        tool_calls: list[ToolCall] = []
        start = time.monotonic()
        try:
            for i, turn in enumerate(probe.turns):
                messages.append(Message(role="user", content=turn))
                req = TargetRequest(messages=list(messages), context=probe.context, canary=canary.token)
                t0 = time.monotonic()
                resp = await self._send(req, label)
                replies.append(resp.text)
                tool_calls.extend(resp.tool_calls)
                messages.append(Message(role="assistant", content=resp.text))
                self._emit(
                    "reply", attempt=label, turn=i + 1, turns=len(probe.turns),
                    sent=_excerpt(turn, 200) if i else None, reply=_excerpt(resp.text),
                    tool_calls=[{"name": c.name, "arguments": _excerpt(str(c.arguments), 200)} for c in resp.tool_calls],
                    latency_ms=round((time.monotonic() - t0) * 1000),
                )
        except BudgetExceeded:
            raise
        except Exception as e:  # noqa: BLE001 - every failure becomes an attempt error
            self._emit("attempt_error", attempt=label, attack=plan.case.id,
                       error=_excerpt(f"{type(e).__name__}: {e}", 300))
            return Attempt(
                trial=trial,
                canary=canary.token,
                replies=[secrets.redact(x) for x in replies],
                error=secrets.redact(f"{type(e).__name__}: {e}")[:500],
                latency_ms=(time.monotonic() - start) * 1000,
            )

        def evidence() -> Evidence:
            return Evidence(
                canary=canary,
                sent_text=probe.sent_text(),
                replies=replies,
                tool_calls=tool_calls,
                listener_hits=self.listener.hits_for(canary.token) if self.listener else [],
                system_prompt_markers=self.cfg.system_prompt_markers,
                system_canary_planted=self.target.plants_system_canary,
            )

        verdict = await evaluate(plan.case.attack, evidence(), self.judge)
        if not verdict.success and plan.uses_listener and self.cfg.canary.grace_seconds:
            await asyncio.sleep(self.cfg.canary.grace_seconds)
            ev = evidence()
            if ev.listener_hits:
                verdict = await evaluate(plan.case.attack, ev, None)
        self._emit(
            "attempt_result", attempt=label, attack=plan.case.id, success=verdict.success,
            detected_by=verdict.detected_by, canary=canary.token,
            latency_ms=round((time.monotonic() - start) * 1000), judge_reason=verdict.judge_reason,
        )
        return Attempt(
            trial=trial,
            canary=canary.token,
            success=verdict.success,
            detected_by=verdict.detected_by,
            replies=[secrets.redact(x) for x in replies],
            tool_calls=tool_calls,
            latency_ms=(time.monotonic() - start) * 1000,
            judge_reason=verdict.judge_reason,
        )

    # ------------------------------------------------------------------ run
    async def run(self) -> RunResult:
        started = datetime.now(timezone.utc)
        listener_running = self.listener is not None
        plans: list[_CasePlan] = []
        for case in self.cases:
            a = case.attack
            result = AttackResult(
                id=case.id,
                attack_id=a.id,
                category=a.category,
                severity=a.severity,
                description=a.description,
                delivery=a.delivery,
                mutators=case.mutators,
                tags=a.tags,
                payload_preview=self._preview(case),
            )
            available = available_detectors(
                a,
                listener_running=listener_running,
                system_prompt_markers=self.cfg.system_prompt_markers,
                system_canary_planted=self.target.plants_system_canary,
                judge_enabled=self.judge is not None,
            )
            if not available:
                result.status = "skipped"
                result.skip_reason = (
                    "no detector available (set system_prompt_markers, plant_system_canary, or enable the judge)"
                    if a.detector.system_prompt_leak
                    else "no detector available in this run"
                )
            plans.append(
                _CasePlan(
                    case=case,
                    result=result,
                    uses_listener=listener_running and CanaryChannel.listener in a.detector.canary,
                )
            )

        sem = asyncio.Semaphore(self.cfg.run.concurrency)
        abort = asyncio.Event()

        async def worker(plan: _CasePlan, trial: int) -> None:
            async with sem:
                if abort.is_set():
                    self.progress(1)
                    return
                try:
                    attempt = await self._attempt(plan, trial)
                except BudgetExceeded:
                    if not abort.is_set():
                        self._emit("budget_stop", reason=self.budget.exceeded)
                    abort.set()
                    self.progress(1)
                    return
                plan.attempts.append(attempt)
                self.progress(1)

        self._emit(
            "run_start", attacks=len(plans), trials=self.cfg.run.trials,
            attempts=sum(self.cfg.run.trials for p in plans if p.result.status != "skipped"),
            target=self.target.describe().endpoint or self.target.describe().type,
            listener=self.listener.base_url if self.listener is not None else None,
        )
        jobs = []
        for plan in plans:
            if plan.result.status == "skipped":
                self._emit("skipped", attack=plan.case.id, reason=plan.result.skip_reason)
                self.progress(self.cfg.run.trials)
                continue
            for trial in range(self.cfg.run.trials):
                jobs.append(worker(plan, trial))
        await asyncio.gather(*jobs)

        # Final sweep for late listener hits (e.g. asynchronous link unfurlers).
        if self.listener is not None:
            for plan in plans:
                if not plan.uses_listener:
                    continue
                for att in plan.attempts:
                    if not att.success and att.error is None and self.listener.hits_for(att.canary):
                        att.success = True
                        att.detected_by.append("canary:listener")
                        self._emit("late_listener_hit", attempt=f"{plan.case.id}#{att.trial + 1}",
                                   attack=plan.case.id, canary=att.canary)

        for plan in plans:
            plan.attempts.sort(key=lambda x: x.trial)
            plan.result.attempts = plan.attempts
            if plan.result.status != "skipped":
                if not plan.attempts:
                    plan.result.status = "not_run"
                elif plan.result.completed == 0:
                    plan.result.status = "error"

        result = RunResult(
            tool_version=__version__,
            started_at=started,
            finished_at=datetime.now(timezone.utc),
            target=self.target.describe(),
            config_path=self.config_path,
            threshold=self.cfg.threshold,
            trials=self.cfg.run.trials,
            results=[p.result for p in plans],
            requests_made=self.budget.requests,
            estimated_cost_usd=round(self.budget.cost_usd, 6),
            aborted=self.budget.exceeded is not None,
            abort_reason=self.budget.exceeded,
        )
        result.compute_summary()
        result.evaluate()
        s = result.summary
        self._emit(
            "run_end", success_rate=s.success_rate, successful_attempts=s.successful_attempts,
            attempts=s.attempts, vulnerable=s.vulnerable_attacks, tested=s.tested, skipped=s.skipped,
            errors=s.errored_attempts, requests=result.requests_made, passed=result.passed,
            seconds=round(result.duration_s, 1),
        )
        return result


def needs_listener(cfg: Config, cases: list[TestCase]) -> bool:
    mode = cfg.canary.listener
    if mode == "off":
        return False
    if mode == "on":
        return True
    for c in cases:
        a = c.attack
        text = "\n".join([*a.templates, a.carrier_template or ""])
        if "{canary_url}" in text and CanaryChannel.listener in a.detector.canary:
            return True
    return False


async def run_probe(
    cfg: Config,
    cases: list[TestCase],
    *,
    target: Target | None = None,
    progress: ProgressFn | None = None,
    config_path: str | None = None,
    listener: Any = None,
    on_event: EventFn | None = None,
) -> RunResult:
    """Set up the listener, target and judge, then run everything.

    ``listener`` may be supplied by the caller (anything with ``base_url`` and
    ``hits_for(token)``, e.g. the web server's own canary endpoint); the caller
    then owns its lifecycle.
    """
    owns_listener = listener is None
    if listener is None and needs_listener(cfg, cases):
        listener = CanaryListener(cfg.canary.host, cfg.canary.port, cfg.canary.public_url).start()
    try:
        target = target or build_target(cfg)
        judge = None
        if cfg.judge.enabled:
            judge = LLMJudge(cfg.judge, timeout=cfg.run.timeout)
        async with target:
            if judge is not None:
                async with judge:
                    runner = Runner(cfg, target, cases, listener=listener, judge=judge,
                                    progress=progress, config_path=config_path, on_event=on_event)
                    return await runner.run()
            runner = Runner(cfg, target, cases, listener=listener, progress=progress, config_path=config_path,
                            on_event=on_event)
            return await runner.run()
    finally:
        if owns_listener and listener is not None:
            listener.stop()
