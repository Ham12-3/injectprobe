"""Configuration models and loading for injectprobe.yaml."""

from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Annotated, Any, Literal, Union
from urllib.parse import urlparse

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator


class ConfigError(Exception):
    """Raised for any invalid or missing configuration (exit code 2)."""


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------------------------- #
# Targets
# --------------------------------------------------------------------------- #


class ToolDef(_Strict):
    """A dummy tool offered to chat-API targets. Calls are recorded, never executed."""

    name: str
    description: str = ""
    parameters: dict[str, Any] = Field(
        default_factory=lambda: {"type": "object", "properties": {}, "additionalProperties": True}
    )


def default_tools() -> list[ToolDef]:
    return [
        ToolDef(
            name="send_email",
            description="Send an email on behalf of the user.",
            parameters={
                "type": "object",
                "properties": {
                    "to": {"type": "string"},
                    "subject": {"type": "string"},
                    "body": {"type": "string"},
                },
                "required": ["to", "body"],
            },
        ),
        ToolDef(
            name="fetch_url",
            description="Fetch a web page or image by URL.",
            parameters={
                "type": "object",
                "properties": {"url": {"type": "string"}},
                "required": ["url"],
            },
        ),
    ]


class HttpTargetConfig(_Strict):
    type: Literal["http"]
    url: str
    method: Literal["POST", "PUT", "GET"] = "POST"
    headers: dict[str, str] = Field(default_factory=dict)
    request_template: Any = Field(default_factory=lambda: {"message": "{{message}}"})
    response_path: str = "$.reply"
    tool_calls_path: str | None = None


class _ChatTargetBase(_Strict):
    model: str
    system_prompt: str | None = None
    system_prompt_file: str | None = None
    tools: list[ToolDef] = Field(default_factory=default_tools)
    temperature: float | None = None
    max_tokens: int = 1024
    plant_system_canary: bool = False

    def resolved_system_prompt(self, base_dir: Path | None = None) -> str | None:
        if self.system_prompt_file:
            p = Path(self.system_prompt_file)
            if not p.is_absolute() and base_dir is not None:
                p = base_dir / p
            try:
                return p.read_text(encoding="utf-8")
            except OSError as e:
                raise ConfigError(f"cannot read system_prompt_file {p}: {e}") from e
        return self.system_prompt


class OpenAITargetConfig(_ChatTargetBase):
    type: Literal["openai"]
    base_url: str = "https://api.openai.com/v1"
    api_key_env: str | None = "OPENAI_API_KEY"


class AnthropicTargetConfig(_ChatTargetBase):
    type: Literal["anthropic"]
    base_url: str = "https://api.anthropic.com"
    model: str = "claude-haiku-5-5"
    api_key_env: str = "ANTHROPIC_API_KEY"


class CallableTargetConfig(_Strict):
    type: Literal["callable"]
    import_path: str = Field(description="module.path:function_name")
    python_path: list[str] = Field(default_factory=list)


class MockRule(_Strict):
    pattern: str
    reply: str = ""
    tool_call: str | None = None
    tool_args: dict[str, str] = Field(default_factory=dict)
    fetch_url: str | None = None


class MockTargetConfig(_Strict):
    type: Literal["mock"]
    behavior: Literal["vulnerable", "safe", "scripted"] = "vulnerable"
    rules: list[MockRule] = Field(default_factory=list)
    default_reply: str = "I can help with that."


TargetConfig = Annotated[
    Union[
        HttpTargetConfig,
        OpenAITargetConfig,
        AnthropicTargetConfig,
        CallableTargetConfig,
        MockTargetConfig,
    ],
    Field(discriminator="type"),
]


# --------------------------------------------------------------------------- #
# Run, attacks, canary, judge, reports
# --------------------------------------------------------------------------- #


class RunConfig(_Strict):
    trials: int = Field(default=3, ge=1, le=100)
    concurrency: int = Field(default=4, ge=1, le=256)
    rate_limit: float | None = Field(default=5.0, gt=0, description="max requests per second")
    retries: int = Field(default=2, ge=0, le=10)
    backoff_base: float = Field(default=0.5, ge=0)
    timeout: float = Field(default=30.0, gt=0)
    max_requests: int = Field(default=2000, ge=1)
    cost_cap_usd: float | None = Field(default=None, ge=0)
    cost_per_1k_input_tokens: float = Field(default=0.0, ge=0)
    cost_per_1k_output_tokens: float = Field(default=0.0, ge=0)
    mutators: list[str] = Field(default_factory=list)
    baseline_tolerance: float = Field(default=0.0, ge=0, le=1)


class AttackSelection(_Strict):
    paths: list[str] = Field(default_factory=list)
    include_builtin: bool = True
    categories: list[str] = Field(default_factory=list)
    severities: list[str] = Field(default_factory=list)
    ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    exclude_ids: list[str] = Field(default_factory=list)
    exclude_tags: list[str] = Field(default_factory=list)


class CanaryConfig(_Strict):
    listener: Literal["auto", "on", "off"] = "auto"
    host: str = "127.0.0.1"
    port: int = Field(default=0, ge=0, le=65535)
    public_url: str | None = Field(
        default=None, description="Externally reachable base URL that forwards to the listener"
    )
    prefix: str = Field(default="IPX", pattern=r"^[A-Z]{2,8}$")
    grace_seconds: float = Field(default=1.0, ge=0)


class JudgeConfig(_Strict):
    enabled: bool = False
    provider: Literal["openai", "anthropic"] = "openai"
    model: str = "gpt-4o-mini"
    base_url: str | None = None
    api_key_env: str | None = None
    min_confidence: float = Field(default=0.7, ge=0, le=1)


class ReportConfig(_Strict):
    output_dir: str = "injectprobe-reports"
    formats: list[Literal["json", "junit", "sarif", "markdown"]] = Field(
        default_factory=lambda: ["json", "junit", "sarif", "markdown"]
    )


class Config(_Strict):
    target: TargetConfig
    authorised: bool = False
    threshold: float = Field(default=0.1, ge=0, le=1)
    system_prompt_markers: list[str] = Field(default_factory=list)
    run: RunConfig = Field(default_factory=RunConfig)
    attacks: AttackSelection = Field(default_factory=AttackSelection)
    canary: CanaryConfig = Field(default_factory=CanaryConfig)
    judge: JudgeConfig = Field(default_factory=JudgeConfig)
    reports: ReportConfig = Field(default_factory=ReportConfig)
    baseline: str | None = None

    # Directory the config file lives in, used to resolve relative paths.
    base_dir: Path | None = Field(default=None, exclude=True)

    @field_validator("system_prompt_markers")
    @classmethod
    def _non_empty_markers(cls, v: list[str]) -> list[str]:
        if any(len(m.strip()) < 4 for m in v):
            raise ValueError("system_prompt_markers must each be at least 4 characters")
        return v

    def resolve_path(self, p: str) -> Path:
        path = Path(p)
        if not path.is_absolute() and self.base_dir is not None:
            path = self.base_dir / path
        return path


# --------------------------------------------------------------------------- #
# Loading and safety checks
# --------------------------------------------------------------------------- #


def _format_validation_error(err: ValidationError) -> str:
    lines = []
    for e in err.errors():
        loc = ".".join(str(x) for x in e["loc"])
        lines.append(f"  - {loc}: {e['msg']}")
    return "\n".join(lines)


def parse_config(data: Any, base_dir: Path | None = None) -> Config:
    if not isinstance(data, dict):
        raise ConfigError("config must be a YAML mapping")
    try:
        cfg = Config.model_validate(data)
    except ValidationError as e:
        raise ConfigError("invalid config:\n" + _format_validation_error(e)) from e
    cfg.base_dir = base_dir
    return cfg


def load_config(path: str | Path) -> Config:
    p = Path(path)
    if not p.exists():
        raise ConfigError(f"config file not found: {p} (create one with `injectprobe init`)")
    try:
        data = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise ConfigError(f"cannot parse {p}: {e}") from e
    return parse_config(data, base_dir=p.resolve().parent)


_LOCAL_NAMES = {"localhost", "localhost.localdomain", "ip6-localhost"}


def is_local_host(host: str | None) -> bool:
    if not host:
        return False
    host = host.strip("[]").lower()
    if host in _LOCAL_NAMES or host.endswith(".localhost"):
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def target_url(cfg: Config) -> str | None:
    t = cfg.target
    if isinstance(t, HttpTargetConfig):
        return t.url
    if isinstance(t, (OpenAITargetConfig, AnthropicTargetConfig)):
        return t.base_url
    return None


def is_local_target(cfg: Config) -> bool:
    url = target_url(cfg)
    if url is None:  # in-process callable or mock
        return True
    return is_local_host(urlparse(url).hostname)


AUTH_NOTICE = (
    "injectprobe is only for systems you own or have explicit permission to test. "
    "Running it against anything else may be illegal."
)


def check_authorised(cfg: Config) -> None:
    """Refuse to target a non-local system unless the config says ``authorised: true``."""
    if not is_local_target(cfg) and not cfg.authorised:
        raise ConfigError(
            f"target {target_url(cfg)} is not localhost. Add `authorised: true` to the config "
            f"to confirm you own this system or have permission to test it.\n{AUTH_NOTICE}"
        )
