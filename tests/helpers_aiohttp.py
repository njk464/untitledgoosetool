"""Test helpers: a real local aiohttp server standing in for Graph / ARM / Log Analytics.

Used by the date-bound and Log Analytics discovery tests so dumpers run their real
request code against 127.0.0.1 instead of mocking internals. No network access,
no tokens: the fake endpoints accept any Authorization header.
"""

import contextlib
import logging

import aiohttp
from aiohttp.test_utils import TestServer


@contextlib.asynccontextmanager
async def serve(app, timeout=None):
    """Serve `app` on 127.0.0.1 (ephemeral port); yield (base_url, aiohttp session).

    `timeout` (seconds) sets the client's total timeout, to provoke empty-message TimeoutErrors."""
    server = TestServer(app, host="127.0.0.1")
    await server.start_server()
    kwargs = {"timeout": aiohttp.ClientTimeout(total=timeout)} if timeout else {}
    session = aiohttp.ClientSession(**kwargs)
    try:
        yield str(server.make_url("")).rstrip("/"), session
    finally:
        await session.close()
        await server.close()


def make_logger(name="goosey-test"):
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    return logger


FAKE_AUTH = {"token_type": "Bearer", "access_token": "test-token-not-a-secret"}
