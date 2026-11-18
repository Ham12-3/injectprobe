"""Pydantic models for attacks, target I/O and run results."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, computed_field, model_validator

# --------------------------------------------------------------------------- #
# Attack definitions
# --------------------------------------------------------------------------- #

CATEGORIES: dict[str, str] = {
    "instruction_override": "Instruction override",
    "role_hijack": "Role hijack",
    "system_prompt_extraction": "System prompt extraction",
    "delimiter_breaking": "Delimiter breaking",
    "encoding": "Encoded or obfuscated payloads",
    "multilingual": "Multilingual",
    "multi_turn": "Multi-turn",
    "exfiltration": "Exfiltration via links or markdown images",
    "indirect": "Indirect injection (documents, web, email, tool results)",
}


class Severity(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"

    @property
    def rank(self) -> int:
        return ["low", "medium", "high", "critical"].index(self.value)


class Delivery(str, Enum):
    direct = "direct"
    indirect = "indirect"


class Carrier(str, Enum):
    document = "document"
    web_page = "web_page"
    email = "email"
    tool_result = "tool_result"


class CanaryChannel(str, Enum):
    reply = "reply"
    tool_call = "tool_call"
    listener = "listener"


class DetectorSpec(BaseModel):
    """How to decide whether an attack worked."""

    model_config = ConfigDict(extra="forbid")

    canary: list[CanaryChannel] = Field(
        default_factory=lambda: [CanaryChannel.reply, CanaryChannel.tool_call, CanaryChannel.listener]
    )
    regex: list[str] = Field(default_factory=list)
    contains: list[str] = Field(default_factory=list)
    system_prompt_leak: bool = False
    judge: str | None = None


class Attack(BaseModel):
    """One injection attack, loaded from a YAML attack file."""

    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_.\-]*$")
    category: str
    severity: Severity
    description: str
    delivery: Delivery = Delivery.direct
    payload: str | None = None
    turns: list[str] | None = None
    carrier: Carrier | None = None
    carrier_template: str | None = None
    carrier_title: str | None = None
    user_question: str | None = None
    mutators: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    detector: DetectorSpec = Field(default_factory=DetectorSpec)
    source: str | None = Field(default=None, exclude=True)

    @model_validator(mode="after")
    def _check_shape(self) -> "Attack":
        if (self.payload is None) == (self.turns is None):
            raise ValueError("an attack needs exactly one of 'payload' or 'turns'")
        if self.turns is not None and not self.turns:
            raise ValueError("'turns' must not be empty")
        if self.delivery == Delivery.indirect:
            if self.turns is not None:
                raise ValueError("indirect attacks use 'payload', not 'turns'")
            if self.carrier is None:
                raise ValueError("indirect attacks need a 'carrier'")
        if self.carrier_template is not None and "{payload}" not in self.carrier_template:
            raise ValueError("'carrier_template' must contain {payload}")
        return self

    @property
    def templates(self) -> list[str]:
        return list(self.turns) if self.turns is not None else [self.payload or ""]


# --------------------------------------------------------------------------- #
# Target I/O
# --------------------------------------------------------------------------- #


class Message(BaseModel):
    role: Literal["user", "assistant"]
    content: str


class ContextItem(BaseModel):
    """A piece of untrusted content the target reads (indirect delivery)."""

    kind: Carrier
    title: str
    content: str


class ToolCall(BaseModel):
    name: str
    arguments: dict[str, Any] = Field(default_factory=dict)


class TargetRequest(BaseModel):
    messages: list[Message]
    context: list[ContextItem] = Field(default_factory=list)
    canary: str = ""


class TargetResponse(BaseModel):
    text: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    input_tokens: int | None = None
    output_tokens: int | None = None


# --------------------------------------------------------------------------- #
# Results
# --------------------------------------------------------------------------- #


class Attempt(BaseModel):
    trial: int
    canary: str
    success: bool = False
    detected_by: list[str] = Field(default_factory=list)
    replies: list[str] = Field(default_factory=list)
    tool_calls: list[ToolCall] = Field(default_factory=list)
    error: str | None = None
    latency_ms: float = 0.0
    judge_reason: str | None = None


class AttackResult(BaseModel):
    id: str
    attack_id: str
    category: str
    severity: Severity
    description: str
    delivery: Delivery
    mutators: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    payload_preview: str = ""
    status: Literal["tested", "skipped", "error", "not_run"] = "tested"
    skip_reason: str | None = None
    attempts: list[Attempt] = Field(default_factory=list)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def completed(self) -> int:
        return sum(1 for a in self.attempts if a.error is None)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def successes(self) -> int:
        return sum(1 for a in self.attempts if a.success)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def errors(self) -> int:
        return sum(1 for a in self.attempts if a.error is not None)

    @computed_field  # type: ignore[prop-decorator]
    @property
    def success_rate(self) -> float:
        return self.successes / self.completed if self.completed else 0.0

    def first_successful(self) -> Attempt | None:
        return next((a for a in self.attempts if a.success), None)


class GroupStat(BaseModel):
    attacks: int = 0
    vulnerable: int = 0
    attempts: int = 0
    successes: int = 0

    @computed_field  # type: ignore[prop-decorator]
    @property
    def success_rate(self) -> float:
        return self.successes / self.attempts if self.attempts else 0.0


class RunSummary(BaseModel):
    total_attacks: int = 0
    tested: int = 0
    skipped: int = 0
    not_run: int = 0
    vulnerable_attacks: int = 0
    attempts: int = 0
    successful_attempts: int = 0
    errored_attempts: int = 0
    success_rate: float = 0.0
    by_category: dict[str, GroupStat] = Field(default_factory=dict)
    by_severity: dict[str, GroupStat] = Field(default_factory=dict)


class Regression(BaseModel):
    id: str
    category: str
    severity: Severity
    baseline_rate: float | None
    current_rate: float
    kind: Literal["new", "worse"]


class TargetInfo(BaseModel):
    type: str
    endpoint: str = ""


class RunResult(BaseModel):
    schema_version: int = 1
    tool_version: str
    started_at: datetime
    finished_at: datetime
    target: TargetInfo
    config_path: str | None = None
    threshold: float
    trials: int
    results: list[AttackResult] = Field(default_factory=list)
    summary: RunSummary = Field(default_factory=RunSummary)
    requests_made: int = 0
    estimated_cost_usd: float = 0.0
    aborted: bool = False
    abort_reason: str | None = None
    baseline_path: str | None = None
    regressions: list[Regression] = Field(default_factory=list)
    passed: bool = True

    @property
    def duration_s(self) -> float:
        return (self.finished_at - self.started_at).total_seconds()

    def compute_summary(self) -> RunSummary:
        s = RunSummary(total_attacks=len(self.results))
        for r in self.results:
            if r.status == "skipped":
                s.skipped += 1
                continue
            if r.status == "not_run":
                s.not_run += 1
                continue
            s.tested += 1
            s.errored_attempts += r.errors
            s.attempts += r.completed
            s.successful_attempts += r.successes
            vulnerable = r.successes > 0
            if vulnerable:
                s.vulnerable_attacks += 1
            for key, bucket in ((r.category, s.by_category), (r.severity.value, s.by_severity)):
                g = bucket.setdefault(key, GroupStat())
                g.attacks += 1
                g.vulnerable += int(vulnerable)
                g.attempts += r.completed
                g.successes += r.successes
        s.success_rate = s.successful_attempts / s.attempts if s.attempts else 0.0
        self.summary = s
        return s

    def evaluate(self) -> bool:
        """Set and return ``passed``.

        With a baseline the run fails only on regressions; otherwise it fails
        when the overall success rate is above the threshold.
        """
        if self.baseline_path is not None:
            self.passed = not self.regressions
        else:
            self.passed = self.summary.success_rate <= self.threshold
        return self.passed

    def failing(self, limit: int | None = None) -> list[AttackResult]:
        bad = [r for r in self.results if r.successes > 0]
        bad.sort(key=lambda r: (-r.success_rate, -r.severity.rank, r.id))
        return bad[:limit] if limit is not None else bad
