"""Entra sign-in / audit collectors with a blank date_end (DEC-DATEBOUNDS-001).

A real local aiohttp server plays Microsoft Graph; the dumper's graph_url points at
it and `now=` freezes time. Assertions are made on the $filter query strings the
server captured and on the checkpoint / output files.
"""

import asyncio
import configparser
import glob
import json
import os
import re
from datetime import datetime, timedelta, timezone

import pytest
from aiohttp import web

from goosey.entra_id_datadumper import EntraIdDataDumper
from goosey.utils import PaginationIncomplete, parse_graph_ts, to_graph_ts
from tests.helpers_aiohttp import FAKE_AUTH, serve

NOW1 = datetime(2026, 11, 2, 13, 0, 0, tzinfo=timezone.utc)
NOW2 = datetime(2026, 11, 2, 15, 0, 0, tzinfo=timezone.utc)

FILTER_RE = re.compile(r"\((\w+) ge (\S+) and \w+ lt (\S+)\)")


class FakeGraph:
    """Serves signIns / directoryAudits rows filtered by the $filter window."""

    def __init__(self):
        self.rows = []      # dicts with 'id' and a timestamp under both field names
        self.requests = []  # (path, source, ge, lt)
        self.app = web.Application()
        self.app.router.add_get("/beta/auditLogs/signIns", self.handle)
        self.app.router.add_get("/beta/auditLogs/directoryAudits", self.handle)

    def add(self, row_id, ts):
        self.rows.append({"id": row_id, "createdDateTime": ts, "activityDateTime": ts})

    async def handle(self, request):
        field, ge, lt = FILTER_RE.search(request.query["$filter"]).groups()
        self.requests.append((request.path, request.query.get("source"), ge, lt))
        lo, hi = parse_graph_ts(ge), parse_graph_ts(lt)
        value = [r for r in self.rows if lo <= parse_graph_ts(r[field]) < hi]
        return web.json_response({"value": value})


def make_config(start, end=""):
    c = configparser.ConfigParser()
    c.add_section("config")
    c.set("config", "gcc", "false")
    c.set("config", "gcc_high", "false")
    c.add_section("filters")
    c.set("filters", "date_start", start)
    c.set("filters", "date_end", end)
    return c


def make_dumper(tmp_path, session, base, config, now):
    out, rep = str(tmp_path / "out"), str(tmp_path / "rep")
    os.makedirs(rep, exist_ok=True)
    d = EntraIdDataDumper(out, rep, dict(FAKE_AUTH), session, config, False, now=now)
    d.graph_url = base
    os.makedirs(d.output_dir, exist_ok=True)
    return d


def read_ids(pattern):
    ids = []
    for path in sorted(glob.glob(pattern)):
        with open(path) as f:
            ids += [json.loads(line)["id"] for line in f if line.strip()]
    return ids


def run(coro):
    return asyncio.run(coro)


def test_blank_end_all_three_collectors_end_at_frozen_now(tmp_path):
    async def go():
        g = FakeGraph()
        g.add("r1", "2026-11-02T09:00:00.000000Z")
        async with serve(g.app) as (base, session):
            d = make_dumper(tmp_path, session, base, make_config("2026-11-02"), NOW1)
            await d.dump_signins_rt()
            await d.dump_signins_sp()
            await d.dump_entraid_audit()
        return g

    g = run(go())
    now_ts = to_graph_ts(NOW1)
    by_kind = {(p.rsplit("/", 1)[1], s): (ge, lt) for p, s, ge, lt in g.requests}
    assert by_kind[("signIns", "rt")] == ("2026-11-02T00:00:00.000000Z", now_ts)
    assert by_kind[("signIns", "sp")] == ("2026-11-02T00:00:00.000000Z", now_ts)
    assert by_kind[("directoryAudits", None)] == ("2026-11-02T00:00:00.000000Z", now_ts)
    # The partial current day was collected, not dropped
    out = str(tmp_path / "out" / "entraid")
    assert read_ids(f"{out}/signin_rt/*.json") == ["r1"]
    assert read_ids(f"{out}/entraid_audit_logs/*.json") == ["r1"]


def test_checkpoint_never_exceeds_now_and_second_run_collects_only_new_time(tmp_path):
    async def go():
        g = FakeGraph()
        g.add("a", "2026-11-02T09:00:00.000000Z")
        g.add("b", "2026-11-02T12:00:00.000000Z")
        async with serve(g.app) as (base, session):
            d1 = make_dumper(tmp_path, session, base, make_config("2026-11-02"), NOW1)
            await d1.dump_signins_rt()
            await d1.dump_entraid_audit()
            state1 = {k: open(str(tmp_path / "out" / "entraid" / k)).read().split("\n")
                      for k in (".rt_signin_state", ".audit_log_state")}
            n1 = len(g.requests)
            # New events arrive after the first run; time advances
            g.add("c", "2026-11-02T13:30:00.000000Z")
            g.add("d", "2026-11-02T14:59:00.000000Z")
            d2 = make_dumper(tmp_path, session, base, make_config("2026-11-02"), NOW2)
            await d2.dump_signins_rt()
            await d2.dump_entraid_audit()
            state2 = {k: open(str(tmp_path / "out" / "entraid" / k)).read().split("\n")
                      for k in (".rt_signin_state", ".audit_log_state")}
        return g, state1, state2, n1

    g, state1, state2, n1 = run(go())
    for st in state1.values():
        assert st == ["time", to_graph_ts(NOW1)]       # exactly now, not end of day
    for st in state2.values():
        assert st == ["time", to_graph_ts(NOW2)]
    # Second run requested [NOW1 - lookback, NOW2): resumes from the checkpoint minus the 30 min lookback
    for _, _, ge, lt in g.requests[n1:]:
        assert (ge, lt) == (to_graph_ts(NOW1 - timedelta(minutes=30)), to_graph_ts(NOW2))
    out = str(tmp_path / "out" / "entraid")
    assert sorted(read_ids(f"{out}/signin_rt/*.json")) == ["a", "b", "c", "d"]
    assert sorted(read_ids(f"{out}/entraid_audit_logs/*.json")) == ["a", "b", "c", "d"]


def test_multi_day_range_full_days_then_clipped_final_chunk(tmp_path):
    async def go():
        g = FakeGraph()
        g.add("old", "2026-11-01T10:00:00.000000Z")
        g.add("today", "2026-11-02T01:00:00.000000Z")
        async with serve(g.app) as (base, session):
            d = make_dumper(tmp_path, session, base, make_config("2026-11-01"), NOW1)
            await d.dump_signins_rt()
        return g

    g = run(go())
    assert [(ge, lt) for _, _, ge, lt in g.requests] == [
        ("2026-11-01T00:00:00.000000Z", "2026-11-01T23:59:59.999999Z"),
        ("2026-11-02T00:00:00.000000Z", to_graph_ts(NOW1)),
    ]


def test_explicit_end_stays_exclusive_midnight_and_no_extra_day(tmp_path):
    async def go():
        g = FakeGraph()
        async with serve(g.app) as (base, session):
            d = make_dumper(tmp_path, session, base, make_config("2026-11-01", "2026-11-02"), NOW1)
            await d.dump_signins_sp()
        return g, open(str(tmp_path / "out" / "entraid" / ".sp_signin_state")).read()

    g, state = run(go())
    assert [(ge, lt) for _, _, ge, lt in g.requests] == [("2026-11-01T00:00:00.000000Z", "2026-11-01T23:59:59.999999Z")]
    assert state == "time\n2026-11-01T23:59:59.999999Z"   # legacy-compatible full-day checkpoint


def test_legacy_state_file_resumes_next_midnight(tmp_path):
    async def go():
        g = FakeGraph()
        async with serve(g.app) as (base, session):
            d = make_dumper(tmp_path, session, base, make_config("2026-10-30"), NOW1)
            with open(os.path.join(d.output_dir, ".rt_signin_state"), "w") as f:
                f.write("time\n2026-11-01T23:59:59.999999Z")   # old format: day 11-01 complete
            await d.dump_signins_rt()
        return g

    g = run(go())
    # legacy checkpoint = day 11-01 complete; resume re-reads the last 30 min of 11-01, then 11-02 up to now
    assert [(ge, lt) for _, _, ge, lt in g.requests] == [
        ("2026-11-01T23:30:00.000000Z", "2026-11-01T23:59:59.999999Z"),
        ("2026-11-02T00:00:00.000000Z", to_graph_ts(NOW1)),
    ]


def test_failed_chunk_does_not_advance_checkpoint(tmp_path):
    async def go():
        app = web.Application()

        async def boom(request):
            return web.json_response({"error": {"code": "Forbidden"}}, status=403)
        app.router.add_get("/beta/auditLogs/signIns", boom)
        async with serve(app) as (base, session):
            d = make_dumper(tmp_path, session, base, make_config("2026-11-02"), NOW1)
            # A failed window is no longer reported as success (DEC-PAGINATION-001).
            with pytest.raises(PaginationIncomplete):
                await d.dump_signins_rt()
    run(go())
    assert not os.path.exists(str(tmp_path / "out" / "entraid" / ".rt_signin_state"))


def _two_runs(tmp_path, serve_run2, config_end="", lookback=None, kinds=("signin", "audit")):
    """Run 1 at NOW1 with rows a,b,o; then `serve_run2(g)` mutates the server and run 2 happens at NOW2."""
    async def go():
        g = FakeGraph()
        g.add("a", "2026-11-02T09:00:00.000000Z")
        g.add("o", "2026-11-02T12:45:00.000000Z")      # inside the 30-minute overlap of run 2
        async with serve(g.app) as (base, session):
            cfg = make_config("2026-11-02", config_end)
            if lookback is not None:
                cfg.add_section("variables")
                cfg.set("variables", "incremental_lookback_minutes", str(lookback))
            d1 = make_dumper(tmp_path, session, base, cfg, NOW1)
            await d1.dump_signins_rt()
            await d1.dump_entraid_audit()
            n1 = len(g.requests)
            serve_run2(g)
            d2 = make_dumper(tmp_path, session, base, cfg, NOW2)
            await d2.dump_signins_rt()
            await d2.dump_entraid_audit()
        return g, n1
    return run(go())


def _all_lines(pattern):
    lines = []
    for path in sorted(glob.glob(pattern)):
        with open(path) as f:
            lines += [json.loads(line)["id"] for line in f if line.strip()]
    return lines


def test_late_arriving_record_before_checkpoint_is_collected_on_resume(tmp_path):
    def late(g):
        g.add("late", "2026-11-02T12:50:00.000000Z")   # older than checkpoint (13:00) but only visible in run 2
    g, _ = _two_runs(tmp_path, late)
    out = str(tmp_path / "out" / "entraid")
    for pattern in (f"{out}/signin_rt/*.json", f"{out}/entraid_audit_logs/*.json"):
        assert sorted(_all_lines(pattern)) == ["a", "late", "o"]


def test_overlap_reserved_records_are_not_duplicated(tmp_path):
    g, n1 = _two_runs(tmp_path, lambda g: None)
    out = str(tmp_path / "out" / "entraid")
    for pattern in (f"{out}/signin_rt/*.json", f"{out}/entraid_audit_logs/*.json"):
        assert sorted(_all_lines(pattern)) == ["a", "o"]     # "o" was re-served in the overlap, written once
    # checkpoint is the resolved now, never beyond it
    for k in (".rt_signin_state", ".audit_log_state"):
        assert open(str(tmp_path / "out" / "entraid" / k)).read() == "time\n" + to_graph_ts(NOW2)


def test_lookback_config_override(tmp_path):
    g, n1 = _two_runs(tmp_path, lambda g: None, lookback=5)
    # 5 minute lookback: the 12:45 row is outside the window, so it is not even requested again
    for _, _, ge, lt in g.requests[n1:]:
        assert ge == to_graph_ts(NOW1 - timedelta(minutes=5))
    g0, n0 = _two_runs(tmp_path / "zero", lambda g: None, lookback=0)
    for _, _, ge, lt in g0.requests[n0:]:
        assert ge == to_graph_ts(NOW1)


def test_lookback_never_reaches_before_configured_start(tmp_path):
    async def go():
        g = FakeGraph()
        async with serve(g.app) as (base, session):
            d = make_dumper(tmp_path, session, base, make_config("2026-11-02"), NOW1)
            with open(os.path.join(d.output_dir, ".rt_signin_state"), "w") as f:
                f.write("time\n2026-11-02T00:10:00.000000Z")    # checkpoint 10 min after the configured start
            await d.dump_signins_rt()
        return g
    g = run(go())
    assert g.requests[0][2] == "2026-11-02T00:00:00.000000Z"
