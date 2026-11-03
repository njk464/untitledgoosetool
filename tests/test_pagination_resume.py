"""Pagination must never truncate silently (DEC-PAGINATION-001).

Found in a live pull: Graph answered 410 Gone on an expired @odata.nextLink, get_nextlink gave up
quietly, the sign-in collector marked the day complete and advanced its checkpoint -- permanent,
unreported data loss.  A real local aiohttp server plays Graph and injects 410 / 429 on chosen
nextLink pages; assertions are on the files, checkpoint, errors and the task status honk reports.
"""

import asyncio
import json
import logging
from urllib.parse import urlencode

import pytest
from aiohttp import web

import goosey.utils as gu
from goosey.utils import PaginationIncomplete, get_nextlink, parse_graph_ts
from tests.helpers_aiohttp import FAKE_AUTH, make_logger, serve
from tests.test_entra_date_window import FILTER_RE, NOW1, make_config, make_dumper

PAGE = 2


@pytest.fixture(autouse=True)
def fast_retries(monkeypatch):
    monkeypatch.setattr(gu, "NEXTLINK_RETRY_SLEEP", 0)
    monkeypatch.setattr(gu, "RATE_LIMIT_SLEEP_SECONDS", 0)


class PagedGraph:
    """signIns server: ascending createdDateTime, PAGE rows per page, scripted failures per nextLink."""

    def __init__(self, rows):
        self.rows = rows            # list of (id, timestamp string), already ascending
        self.script = {}            # nextLink page number -> list of statuses to return before serving
        self.first_requests = []    # (ge, lt) of every non-nextLink request
        self.always_410 = False     # every nextLink is dead (persistent failure)
        self.app = web.Application()
        self.app.router.add_get("/beta/auditLogs/signIns", self.first)
        self.app.router.add_get("/next", self.nxt)

    def _page(self, request, offset, ge, lt):
        lo, hi = parse_graph_ts(ge), parse_graph_ts(lt)
        sel = [r for r in self.rows if lo <= parse_graph_ts(r[1]) < hi]
        body = {"value": [{"id": i, "createdDateTime": t} for i, t in sel[offset:offset + PAGE]]}
        if offset + PAGE < len(sel):
            q = urlencode({"offset": offset + PAGE, "ge": ge, "lt": lt, "page": offset // PAGE + 1})
            body["@odata.nextLink"] = f"{request.scheme}://{request.host}/next?{q}"
        return web.json_response(body)

    async def first(self, request):
        ge, lt = FILTER_RE.search(request.query["$filter"]).groups()[1:]
        self.first_requests.append((ge, lt))
        return self._page(request, 0, ge, lt)

    async def nxt(self, request):
        page = int(request.query["page"])
        if self.always_410:
            return web.Response(status=410, text="{}")
        pending = self.script.get(page)
        if pending:
            return web.Response(status=pending.pop(0), text="{}")
        return self._page(request, int(request.query["offset"]), request.query["ge"], request.query["lt"])


def ts(minute):
    return f"2026-11-02T09:{minute:02d}:00Z"


def ids_in(tmp_path):
    p = tmp_path / "out" / "entraid" / "signin_rt" / "rt_signin_log_2026-11-02.json"
    if not p.exists():
        return []
    return [json.loads(line)["id"] for line in p.read_text().splitlines() if line.strip()]


def state_file(tmp_path):
    return tmp_path / "out" / "entraid" / ".rt_signin_state"


def run_dump(tmp_path, g, expect_error=False):
    async def go():
        async with serve(g.app) as (base, session):
            d = make_dumper(tmp_path, session, base, make_config("2026-11-02"), NOW1)
            return await d.func_wrapper(d.dump_signins_rt)
    return asyncio.run(go())


def distinct_rows(n=7):
    return [(f"id{i}", ts(i)) for i in range(n)]


def test_410_once_resumes_from_last_timestamp_and_collects_everything_once(tmp_path):
    g = PagedGraph(distinct_rows())
    g.script = {2: [410]}                     # second nextLink is dead once
    _, _, err = run_dump(tmp_path, g)
    assert err is None
    assert ids_in(tmp_path) == [f"id{i}" for i in range(7)]       # all rows, each exactly once
    assert len(g.first_requests) == 2                              # the resume was a fresh query...
    assert parse_graph_ts(g.first_requests[1][0]) == parse_graph_ts(ts(3))  # ...from the last timestamp written
    saved = state_file(tmp_path).read_text().splitlines()[-1]
    assert parse_graph_ts(saved) == NOW1                           # checkpoint == end of the window


def test_distinct_ids_sharing_the_resume_timestamp_are_not_dropped(tmp_path):
    rows = [("a", ts(0)), ("b", ts(1)), ("c", ts(2)), ("d", ts(3)), ("e", ts(3)), ("f", ts(4)), ("g", ts(5))]
    g = PagedGraph(rows)
    g.script = {2: [410]}                     # page 1 = c,d ; the dead link is the one that holds e,f
    _, _, err = run_dump(tmp_path, g)
    assert err is None
    assert ids_in(tmp_path) == ["a", "b", "c", "d", "e", "f", "g"]  # e shares d's timestamp but is distinct


def test_persistent_410_fails_loudly_and_does_not_advance_checkpoint(tmp_path, caplog):
    g = PagedGraph(distinct_rows())
    g.always_410 = True
    with caplog.at_level(logging.ERROR):
        cls, name, err = run_dump(tmp_path, g)
    assert isinstance(err, PaginationIncomplete)                   # honk prints "Failed with error ..." for this
    assert name == "dump_signins_rt"
    assert not state_file(tmp_path).exists()                       # checkpoint stays before the gap
    assert ids_in(tmp_path) == sorted(set(ids_in(tmp_path)))       # what was written has no duplicates
    errors = " ".join(r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR)
    assert "rt" in errors and "2026-11-02T00:00:00" in errors      # source + window named in the ERROR log


def test_429_then_success_still_works(tmp_path):
    g = PagedGraph(distinct_rows())
    g.script = {1: [429], 3: [429, 429]}
    _, _, err = run_dump(tmp_path, g)
    assert err is None
    assert ids_in(tmp_path) == [f"id{i}" for i in range(7)]
    assert len(g.first_requests) == 1                              # throttling never forced a resume


def test_get_nextlink_raises_on_410_and_never_returns_normally(tmp_path):
    g = PagedGraph(distinct_rows())
    g.script = {1: [410]}

    async def go():
        async with serve(g.app) as (base, session):
            url = f"{base}/next?" + urlencode({"offset": 2, "ge": ts(0), "lt": ts(30), "page": 1})
            with pytest.raises(PaginationIncomplete) as ei:
                await get_nextlink(url, str(tmp_path / "o.json"), session, make_logger(), dict(FAKE_AUTH))
            assert ei.value.status == 410
    asyncio.run(go())


def test_get_nextlink_raises_when_retries_are_exhausted(tmp_path, monkeypatch):
    monkeypatch.setattr(gu, "DEFAULT_RETRIES", 2)
    g = PagedGraph(distinct_rows())
    g.script = {1: [500] * 10}

    async def go():
        async with serve(g.app) as (base, session):
            url = f"{base}/next?" + urlencode({"offset": 2, "ge": ts(0), "lt": ts(30), "page": 1})
            with pytest.raises(PaginationIncomplete):
                await get_nextlink(url, str(tmp_path / "o.json"), session, make_logger(), dict(FAKE_AUTH))
    asyncio.run(go())


def test_audit_collector_resumes_and_fails_the_same_way(tmp_path):
    """directoryAudits uses the same window helper: 410 once resumes; persistent 410 reports FAILED."""
    from goosey.entra_id_datadumper import EntraIdDataDumper  # noqa: F401  (dumper under test)

    class AuditGraph(PagedGraph):
        def __init__(self, rows):
            super().__init__(rows)
            self.app.router.add_get("/beta/auditLogs/directoryAudits", self.first_audit)

        async def first_audit(self, request):
            ge, lt = FILTER_RE.search(request.query["$filter"]).groups()[1:]
            self.first_requests.append((ge, lt))
            return self._page(request, 0, ge, lt)

    def audit_ids():
        out = []
        for p in sorted((tmp_path / "out" / "entraid" / "entraid_audit_logs").glob("*.json")):
            out += [json.loads(x)["id"] for x in p.read_text().splitlines() if x.strip()]
        return out

    # The fake rows carry createdDateTime; the audit collector keys on activityDateTime, so mirror it.
    class Mirror(AuditGraph):
        def _page(self, request, offset, ge, lt):
            resp = super()._page(request, offset, ge, lt)
            body = json.loads(resp.text)
            for r in body["value"]:
                r["activityDateTime"] = r["createdDateTime"]
            return web.json_response(body)

    for script, expect_ok in (({2: [410]}, True), (None, False)):
        for sub in tmp_path.iterdir():
            if sub.is_dir():
                import shutil
                shutil.rmtree(sub)
        g = Mirror(distinct_rows())
        if script:
            g.script = script
        else:
            g.always_410 = True

        async def go():
            async with serve(g.app) as (base, session):
                d = make_dumper(tmp_path, session, base, make_config("2026-11-02"), NOW1)
                return await d.func_wrapper(d.dump_entraid_audit)
        _, _, err = asyncio.run(go())
        if expect_ok:
            assert err is None and audit_ids() == [f"id{i}" for i in range(7)]
        else:
            assert isinstance(err, PaginationIncomplete)
            assert not (tmp_path / "out" / "entraid" / ".audit_log_state").exists()
