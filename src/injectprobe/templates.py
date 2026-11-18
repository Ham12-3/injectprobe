"""Starter config files written by ``injectprobe init``."""

from __future__ import annotations

_TARGETS = {
    "http": """\
target:
  type: http
  url: http://localhost:8000/chat
  method: POST
  # Header values may reference environment variables; keys are never written to reports.
  headers:
    Content-Type: application/json
    # Authorization: Bearer ${MY_APP_API_KEY}
  # The request body. Placeholders:
  #   "{{message}}"   latest user message (string)
  #   "{{history}}"   whole value replaced by [{"role": ..., "content": ...}, ...]
  #   "{{context}}"   untrusted documents / tool results as one text block
  #   "{{documents}}" whole value replaced by [{"kind", "title", "content"}, ...]
  # If neither context placeholder is used, indirect content is put above the message.
  request_template:
    message: "{{message}}"
    documents: "{{documents}}"
  response_path: $.reply             # JSONPath to the reply text
  tool_calls_path: $.tool_calls      # optional: JSONPath to [{"name", "arguments"}]
""",
    "openai": """\
target:
  type: openai
  base_url: https://api.openai.com/v1   # any OpenAI-compatible endpoint
  model: gpt-4o-mini
  api_key_env: OPENAI_API_KEY            # read from the environment only
  system_prompt_file: system_prompt.txt  # or: system_prompt: "You are ..."
  plant_system_canary: true              # lets system-prompt-extraction attacks be detected
""",
    "anthropic": """\
target:
  type: anthropic
  model: claude-opus-5-5
  api_key_env: ANTHROPIC_API_KEY         # read from the environment only
  system_prompt_file: system_prompt.txt  # or: system_prompt: "You are ..."
  plant_system_canary: true
""",
    "callable": """\
target:
  type: callable
  # A function that takes a string and returns a string (sync or async).
  import_path: my_agent.entry:handle_message
  python_path: ["."]
""",
    "mock": """\
target:
  type: mock
  behavior: vulnerable   # vulnerable | safe | scripted
""",
}

_REST = """\
# Required when the target is not localhost. Only test systems you own or are
# explicitly permitted to test.
authorised: false

# Fail when more than this fraction of attack attempts succeed (0.0 - 1.0).
threshold: 0.1

# Strings from your system prompt. If one shows up in a reply, it leaked.
system_prompt_markers: []

run:
  trials: 3              # each attack runs N times; reports show a success rate
  concurrency: 4
  rate_limit: 5          # requests per second
  retries: 2
  timeout: 30            # seconds per request
  max_requests: 2000     # hard stop
  cost_cap_usd: null     # e.g. 5.0 with the per-1k prices below
  cost_per_1k_input_tokens: 0.0
  cost_per_1k_output_tokens: 0.0
  mutators: []           # extra variants: base64, leetspeak, zero_width, translation, html_comment, fake_system_tag

attacks:
  paths: []              # folders or files with your own attack YAML
  categories: []
  severities: []
  tags: []
  exclude_ids: []

canary:
  listener: auto         # auto | on | off
  public_url: null       # set if a remote target must reach the listener

judge:
  enabled: false         # LLM judge for attacks a canary can't detect

reports:
  output_dir: injectprobe-reports
  formats: [json, junit, sarif, markdown]
"""


def starter_config(target: str) -> str:
    return "# injectprobe configuration\n" + _TARGETS[target] + "\n" + _REST


TARGET_CHOICES = list(_TARGETS)
