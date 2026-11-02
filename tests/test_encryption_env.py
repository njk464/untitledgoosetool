"""Tests for GOOSEY_ENCRYPTION_PW resolution (goosey.secrets_env) and its wiring.

Uses real code paths. The only thing replaced is stdlib getpass.getpass (an
external boundary: it reads a TTY) so tests can assert whether a prompt happens.
"""

import getpass
import logging


from goosey import secrets_env
from goosey.secrets_env import ENV_VAR, redact, resolve_encryption_pw

SECRET = "correct-horse-battery-staple-ENV"


def _no_prompt(*a, **k):
    raise AssertionError("getpass was called but the env var should have been used")


def test_env_prevents_prompt(monkeypatch):
    monkeypatch.setenv(ENV_VAR, SECRET)
    monkeypatch.setattr(getpass, "getpass", _no_prompt)
    assert resolve_encryption_pw(prompt="pw: ") == SECRET


def test_explicit_beats_env(monkeypatch):
    monkeypatch.setenv(ENV_VAR, SECRET)
    monkeypatch.setattr(getpass, "getpass", _no_prompt)
    assert resolve_encryption_pw("explicit", prompt="pw: ") == "explicit"


def test_absent_env_prompts(monkeypatch):
    monkeypatch.delenv(ENV_VAR, raising=False)
    prompts = []
    monkeypatch.setattr(getpass, "getpass", lambda p="": prompts.append(p) or "typed")
    assert resolve_encryption_pw(prompt="pw: ") == "typed"
    assert prompts == ["pw: "]


def test_empty_env_treated_as_unset(monkeypatch):
    monkeypatch.setenv(ENV_VAR, "")
    monkeypatch.setattr(getpass, "getpass", lambda p="": "typed")
    assert resolve_encryption_pw(prompt="pw: ") == "typed"
    assert resolve_encryption_pw("", prompt="pw: ") == "typed"


def test_no_prompt_requested_returns_none(monkeypatch):
    monkeypatch.delenv(ENV_VAR, raising=False)
    monkeypatch.setattr(getpass, "getpass", _no_prompt)
    assert resolve_encryption_pw() is None


def test_redact_masks_secrets():
    safe = redact({"encryption_pw": SECRET, "auth_clientsecret": "s", "debug": True, "empty_pw": None})
    assert SECRET not in str(safe)
    assert safe["debug"] is True
    assert safe["empty_pw"] is None


def test_conf_uses_env_and_never_leaks(monkeypatch, tmp_path, caplog):
    """goosey conf with the env var set: no password prompt, encrypted .auth.aes
    produced, and the password appears in no log record and no written file."""
    from goosey.conf import genconf

    monkeypatch.setenv(ENV_VAR, SECRET)
    monkeypatch.setattr(getpass, "getpass", _no_prompt)
    monkeypatch.chdir(tmp_path)
    caplog.set_level(logging.DEBUG)
    genconf(outpath_auth=".auth", outpath_conf=".conf", auth_appid="app-id-placeholder",
            auth_clientsecret="client-secret-placeholder", config_tenant="tenant-placeholder",
            outpath_d4iotauth=".auth_d4iot", outpath_d4iotconf=".d4iot_conf", debug=True)

    assert (tmp_path / ".auth.aes").is_file()
    assert not (tmp_path / ".auth").exists()
    assert SECRET not in caplog.text
    for p in tmp_path.rglob("*"):
        if p.is_file():
            assert SECRET.encode() not in p.read_bytes(), p.name


def test_secrets_env_module_has_no_logging():
    assert not hasattr(secrets_env, "logger")
