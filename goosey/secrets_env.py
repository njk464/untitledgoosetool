"""Encryption-password resolution for Goosey auth files.

Single place that decides where the auth-file encryption password comes from,
so `goosey conf`, `goosey honk`, `goosey d4iot` and the auth flow behave alike.

Precedence (first non-empty wins):
    1. Explicit value (the ``--encryption_pw`` CLI argument)
    2. ``GOOSEY_ENCRYPTION_PW`` environment variable
    3. Interactive hidden prompt (getpass)

The password is never logged, echoed, written to config, or passed to
subprocess arguments by this module.

@decision DEC-LAB-001
@title Encryption password via GOOSEY_ENCRYPTION_PW env var, env before prompt
@status accepted
@rationale Lab students must run non-interactively with a password they
  choose; env vars avoid exposing the secret in process args / shell history
  (unlike --encryption_pw). Empty string is treated as unset so an accidental
  `export GOOSEY_ENCRYPTION_PW=` falls back to prompting rather than
  encrypting with an empty password. One helper keeps all call sites consistent.
"""

import getpass
import os

ENV_VAR = "GOOSEY_ENCRYPTION_PW"

_SENSITIVE_MARKERS = ("pw", "password", "secret", "token", "cookie")


def env_encryption_pw():
    """Return the password from GOOSEY_ENCRYPTION_PW, or None if unset/empty."""
    value = os.environ.get(ENV_VAR)
    return value if value else None


def resolve_encryption_pw(explicit=None, prompt=None, prompt_fn=None):
    """Resolve the auth-file encryption password.

    :param explicit: Value passed on the CLI; empty string is treated as unset.
    :param prompt: Prompt text. If None, no prompt is shown and None may be returned.
    :param prompt_fn: Callable used to prompt (defaults to getpass.getpass).
    :return: password string, or None if unresolved and no prompt requested.
    """
    if explicit:
        return explicit
    from_env = env_encryption_pw()
    if from_env:
        return from_env
    if prompt is None:
        return None
    return (prompt_fn or getpass.getpass)(prompt)


def redact(mapping):
    """Return a copy of a dict with sensitive-looking values masked, safe to log."""
    safe = {}
    for key, value in dict(mapping).items():
        if value and any(m in str(key).lower() for m in _SENSITIVE_MARKERS):
            safe[key] = "***REDACTED***"
        else:
            safe[key] = value
    return safe
