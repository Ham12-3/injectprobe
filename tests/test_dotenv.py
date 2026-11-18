import os

from injectprobe import secrets
from injectprobe.dotenv import load_dotenv, parse


def test_parse_formats():
    text = """
# comment
ANTHROPIC_API_KEY=sk-ant-abc123
export OPENAI_API_KEY="sk-quoted value"
SINGLE='x y'
INLINE=value # trailing comment
EMPTY=
not a line
"""
    assert parse(text) == {
        "ANTHROPIC_API_KEY": "sk-ant-abc123",
        "OPENAI_API_KEY": "sk-quoted value",
        "SINGLE": "x y",
        "INLINE": "value",
        "EMPTY": "",
    }


def test_load_sets_missing_only_and_redacts(tmp_path, monkeypatch):
    monkeypatch.delenv("INJECTPROBE_NO_DOTENV", raising=False)
    monkeypatch.delenv("IP_DOTENV_NEW", raising=False)
    monkeypatch.setenv("IP_DOTENV_EXISTING", "from-shell")
    monkeypatch.delenv("IP_DOTENV_BLANK", raising=False)
    f = tmp_path / ".env"
    f.write_text("IP_DOTENV_NEW=dotenv-secret-value\nIP_DOTENV_EXISTING=from-file\nIP_DOTENV_BLANK=\n")
    loaded = load_dotenv(f)
    assert loaded == ["IP_DOTENV_NEW"]
    assert os.environ["IP_DOTENV_NEW"] == "dotenv-secret-value"
    assert os.environ["IP_DOTENV_EXISTING"] == "from-shell"  # shell wins
    assert "IP_DOTENV_BLANK" not in os.environ  # empty placeholders are skipped
    assert "dotenv-secret-value" not in secrets.redact("key=dotenv-secret-value")
    monkeypatch.delenv("IP_DOTENV_NEW")


def test_disabled_and_missing(tmp_path, monkeypatch):
    f = tmp_path / ".env"
    f.write_text("IP_DOTENV_OFF=1\n")
    monkeypatch.setenv("INJECTPROBE_NO_DOTENV", "1")
    assert load_dotenv(f) == []
    monkeypatch.delenv("INJECTPROBE_NO_DOTENV")
    assert load_dotenv(tmp_path / "nope.env") == []


def test_env_example_lists_no_real_keys():
    from pathlib import Path

    example = (Path(__file__).resolve().parents[1] / ".env.example").read_text(encoding="utf-8")
    assert all(v == "" for v in parse(example).values())
