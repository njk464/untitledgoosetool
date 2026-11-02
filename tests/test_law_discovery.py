"""Log Analytics workspace collection: blank end bound + authoritative table discovery.

A local aiohttp server stands in for ARM (workspaces list + Tables - List By
Workspace) and the Log Analytics query endpoint. The dumper is built without Azure
SDK clients (object.__new__) because only the aiohttp/KQL code paths are exercised.
"""

import asyncio
import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone

from aiohttp import web
from dateutil import parser as dparser

from goosey.azure_dumper import AzureDataDumper
from goosey.utils import get_incremental_lookback, resolve_date_bounds, to_graph_ts
from tests.helpers_aiohttp import FAKE_AUTH, make_logger, serve
from tests.test_entra_date_window import make_config

NOW1 = datetime(2026, 11, 2, 13, 0, 0, tzinfo=timezone.utc)
NOW2 = datetime(2026, 11, 2, 15, 0, 0, tzinfo=timezone.utc)
SUB = "00000000-0000-0000-0000-000000000001"
WS_ID = f"/subscriptions/{SUB}/resourceGroups/rg/providers/Microsoft.OperationalInsights/workspaces/ws1"
QUERY_RE = re.compile(
    r"^(?P<table>search \"\*\"|\S+)\|where TimeGenerated between"
    r"\(datetime\((?P<a>[^)]*)\)\.\.datetime\((?P<b>[^)]*)\)\)(?P<summ>\| summarize.*)?$")


class FakeAzure:
    """ARM + Log Analytics. `tables_pages` is a list of pages of table-name lists."""

    def __init__(self):
        self.data = {}            # table -> list of {"id", "TimeGenerated"}
        self.tables_pages = []    # list[list[str]]; [] entries still fine
        self.tables_status = 200
        self.fail_tables = set()  # query-time failures (HTTP 400)
        self.throttle = {}        # table -> number of rate-limit error bodies to return first
        self.slow_tables = set()  # tables whose query hangs (client-side TimeoutError)
        self.fail_search = False  # make the search "*" summary fail
        self.in_flight = 0        # concurrent table queries (for the semaphore test)
        self.max_in_flight = 0
        self.queries = []         # (table, a, b, summarize)
        self.base = ""
        self.app = web.Application()
        r = self.app.router
        r.add_get(f"/subscriptions/{SUB}/providers/Microsoft.OperationalInsights/workspaces", self.workspaces)
        r.add_get(WS_ID + "/tables", self.tables)
        r.add_post(f"/v1{WS_ID}/query", self.query)

    async def workspaces(self, request):
        return web.json_response({"value": [{"name": "ws1", "id": WS_ID, "properties": {"customerId": "cust-1"}}]})

    async def tables(self, request):
        if self.tables_status != 200:
            return web.json_response({"error": {"code": "AuthorizationFailed"}}, status=self.tables_status)
        page = int(request.query.get("page", "0"))
        body = {"value": [{"name": n, "properties": {"schema": {"tableType": "Microsoft"}}}
                          for n in self.tables_pages[page]]}
        if page + 1 < len(self.tables_pages):
            body["nextLink"] = f"{self.base}{WS_ID}/tables?api-version=2022-10-01&page={page + 1}"
        return web.json_response(body)

    async def query(self, request):
        q = (await request.json())["query"]
        m = QUERY_RE.match(q)
        assert m, q
        table, a, b = m["table"], dparser.parse(m["a"]), dparser.parse(m["b"])
        self.queries.append((table, a, b, bool(m["summ"])))
        if table.startswith("search"):
            if self.fail_search:
                return web.json_response({"error": {"message": "search summary unavailable"}}, status=500)
            rows = [[t, len(v)] for t, v in self.data.items() if v]
            cols = [{"name": "$table"}, {"name": "Count"}]
            return web.json_response({"tables": [{"name": "PrimaryResult", "columns": cols, "rows": rows}]})
        if table in self.fail_tables:
            return web.json_response({"error": {"message": f"Failed to resolve table {table}"}}, status=400)
        if self.throttle.get(table, 0) > 0:
            self.throttle[table] -= 1
            # Throttling reported in the body with a non-429 status, as seen live
            body = {"error": {"code": "RateLimit", "message": "Rate limit of 200 per 30 seconds is exceeded."}}
            return web.json_response(body, status=400)
        if table in self.slow_tables:
            await asyncio.sleep(2)
        self.in_flight += 1
        self.max_in_flight = max(self.max_in_flight, self.in_flight)
        try:
            await asyncio.sleep(0.005)
        finally:
            self.in_flight -= 1
        rows = [r for r in self.data.get(table, []) if a <= dparser.parse(r["TimeGenerated"]) <= b]
        if m["summ"]:
            first = min((r["TimeGenerated"] for r in rows), default=None)
            last = max((r["TimeGenerated"] for r in rows), default=None)
            return web.json_response({"tables": [{"name": "PrimaryResult",
                                                  "columns": [{"name": "Count"}, {"name": "FirstEvent"},
                                                              {"name": "LastEvent"}],
                                                  "rows": [[len(rows), first, last]]}]})
        return web.json_response({"tables": [{"name": "PrimaryResult",
                                              "columns": [{"name": "id"}, {"name": "TimeGenerated"}],
                                              "rows": [[r["id"], r["TimeGenerated"]] for r in rows]}]})


def make_dumper(tmp_path, session, base, config, now, logger=None):
    d = object.__new__(AzureDataDumper)
    d.output_dir = str(tmp_path / "out" / "azure")
    d.reports_dir = str(tmp_path / "rep")
    os.makedirs(d.reports_dir, exist_ok=True)
    d.failurefile = os.path.join(d.reports_dir, "_no_results.json")
    d.ahsession = session
    d.app_auth = dict(FAKE_AUTH)
    d.loganalytics_app_auth = dict(FAKE_AUTH)
    d.token_manager = None
    d.endpoint_key = "resource_manager"
    d.force_repull = False
    d.logger = logger or make_logger()
    d.endpoints = {"resource_manager": base, "log_analytics_api": base}
    d.subscription_id_list = [SUB]
    d.date_bounds = resolve_date_bounds(config, d.logger, now=now)
    d.date_range, d.date_start, d.date_end = d.date_bounds.legacy_tuple()
    d.lookback = get_incremental_lookback(config, d.logger)
    os.makedirs(d.output_dir, exist_ok=True)
    return d


def ws_dir(tmp_path):
    return tmp_path / "out" / "azure" / SUB / "log_analytics_workspace" / "ws1"


def manifest(tmp_path):
    return json.loads((ws_dir(tmp_path) / "_collection_status.json").read_text())


def entry(m, table):
    return next(e for e in m["tables"] if e["table"] == table)


def ids(path):
    return [json.loads(line)["id"] for line in path.read_text().splitlines() if line.strip()]


def run(coro):
    return asyncio.run(coro)


def test_blank_end_queries_end_at_frozen_now_and_state_never_exceeds_it(tmp_path):
    async def go():
        f = FakeAzure()
        f.tables_pages = [["AADGraphActivityLogs", "MicrosoftGraphActivityLogs"]]
        f.data = {"AADGraphActivityLogs": [{"id": "x1", "TimeGenerated": "2026-11-02T09:00:00Z"}],
                  "MicrosoftGraphActivityLogs": [{"id": "m1", "TimeGenerated": "2026-11-02T10:00:00Z"}]}
        async with serve(f.app) as (base, session):
            f.base = base
            d = make_dumper(tmp_path, session, base, make_config("2026-11-02"), NOW1)
            await d.dump_log_analytic_workspaces()
        return f

    f = run(go())
    table_queries = [q for q in f.queries if not q[0].startswith("search")]
    assert table_queries and all(b <= NOW1 for _, _, b, _ in table_queries)
    assert max(b for _, _, b, _ in table_queries) == NOW1
    for t in ("AADGraphActivityLogs", "MicrosoftGraphActivityLogs"):
        state = dparser.parse((ws_dir(tmp_path) / f".{t}.savestate").read_text())
        assert state == NOW1


def test_second_run_collects_only_new_time_without_duplicates(tmp_path):
    async def go():
        f = FakeAzure()
        f.tables_pages = [["AADGraphActivityLogs"]]
        f.data = {"AADGraphActivityLogs": [{"id": "a", "TimeGenerated": "2026-11-02T09:00:00Z"},
                                           {"id": "b", "TimeGenerated": "2026-11-02T12:00:00Z"}]}
        async with serve(f.app) as (base, session):
            f.base = base
            await make_dumper(tmp_path, session, base, make_config("2026-11-02"), NOW1).dump_log_analytic_workspaces()
            f.data["AADGraphActivityLogs"] += [{"id": "c", "TimeGenerated": "2026-11-02T13:30:00Z"},
                                               {"id": "d", "TimeGenerated": "2026-11-02T14:59:00Z"}]
            f.queries.clear()
            await make_dumper(tmp_path, session, base, make_config("2026-11-02"), NOW2).dump_log_analytic_workspaces()
        return f

    f = run(go())
    assert ids(ws_dir(tmp_path) / "AADGraphActivityLogs.json") == ["a", "b", "c", "d"]
    # resume re-queries the 30-minute lookback before the checkpoint, never earlier
    assert min(a for t, a, _, _ in f.queries if not t.startswith("search")) == NOW1 - timedelta(minutes=30)
    m = manifest(tmp_path)
    assert entry(m, "AADGraphActivityLogs")["requested_start"] == to_graph_ts(NOW1 - timedelta(minutes=30))
    assert entry(m, "AADGraphActivityLogs")["requested_end"] == to_graph_ts(NOW2)


def test_tables_api_pagination_and_exact_dedupe(tmp_path):
    async def go():
        f = FakeAzure()
        f.data = {"SecurityEvent": [{"id": "s1", "TimeGenerated": "2026-11-02T09:00:00Z"}],
                  "securityevent": [{"id": "s2", "TimeGenerated": "2026-11-02T09:30:00Z"}]}
        # exact duplicate across pages collapses; names differing only by case are both kept
        f.tables_pages = [["SecurityEvent", "AADGraphActivityLogs", "bad-name", "_x"],
                          ["SecurityEvent", "securityevent", "MicrosoftGraphActivityLogs"]]
        async with serve(f.app) as (base, session):
            f.base = base
            await make_dumper(tmp_path, session, base, make_config("2026-11-02"), NOW1).dump_log_analytic_workspaces()
    run(go())
    m = manifest(tmp_path)
    assert m["discovery_method"] == "tables_api" and m["discovery_error"] is None
    assert m["data_check"] == "search_summary" and m["schema_version"] == 1
    names = sorted(e["table"] for e in m["tables"])
    assert names == ["AADGraphActivityLogs", "MicrosoftGraphActivityLogs", "SecurityEvent", "securityevent"]
    assert entry(m, "SecurityEvent")["row_count"] == 1 and entry(m, "securityevent")["row_count"] == 1


def test_listed_empty_noncritical_table_is_skipped_not_success(tmp_path):
    async def go():
        f = FakeAzure()
        f.tables_pages = [["SecurityEvent", "EmptyNoise", "AADGraphActivityLogs", "MicrosoftGraphActivityLogs"]]
        f.data = {"SecurityEvent": [{"id": "s1", "TimeGenerated": "2026-11-02T09:00:00Z"}],
                  "EmptyNoise": [], "AADGraphActivityLogs": [], "MicrosoftGraphActivityLogs": []}
        async with serve(f.app) as (base, session):
            f.base = base
            await make_dumper(tmp_path, session, base, make_config("2026-11-02"), NOW1).dump_log_analytic_workspaces()
        return f

    f = run(go())
    m = manifest(tmp_path)
    skipped = entry(m, "EmptyNoise")
    assert skipped["status"] == "skipped" and skipped["row_count"] is None and skipped["artifact"] is None
    assert skipped["error"] == "no rows in search summary for requested window; not explicitly queried"
    assert not (ws_dir(tmp_path) / "EmptyNoise.json").exists()
    assert not (ws_dir(tmp_path) / ".EmptyNoise.savestate").exists()
    assert "EmptyNoise" not in {q[0] for q in f.queries}
    # lab-critical tables are queried even when empty: success, row_count 0, empty artifact
    for t in ("AADGraphActivityLogs", "MicrosoftGraphActivityLogs"):
        e = entry(m, t)
        assert (e["status"], e["row_count"]) == ("success", 0)
        assert (ws_dir(tmp_path) / f"{t}.json").stat().st_size == 0
    assert entry(m, "SecurityEvent")["status"] == "success"


def test_data_bearing_table_missing_from_tables_list_is_still_queried(tmp_path):
    async def go():
        f = FakeAzure()
        f.tables_pages = [["SecurityEvent"]]
        f.data = {"SecurityEvent": [], "Unlisted_CL": [{"id": "u1", "TimeGenerated": "2026-11-02T09:00:00Z"}]}
        async with serve(f.app) as (base, session):
            f.base = base
            await make_dumper(tmp_path, session, base, make_config("2026-11-02"), NOW1).dump_log_analytic_workspaces()
    run(go())
    m = manifest(tmp_path)
    assert entry(m, "Unlisted_CL")["status"] == "success" and entry(m, "Unlisted_CL")["row_count"] == 1
    assert ids(ws_dir(tmp_path) / "Unlisted_CL.json") == ["u1"]
    assert entry(m, "SecurityEvent")["status"] == "skipped"


def test_search_summary_failure_queries_all_listed_tables(tmp_path, caplog):
    async def go():
        f = FakeAzure()
        f.fail_search = True
        f.tables_pages = [["SecurityEvent", "EmptyNoise", "AADGraphActivityLogs"]]
        f.data = {"SecurityEvent": [{"id": "s1", "TimeGenerated": "2026-11-02T09:00:00Z"}],
                  "EmptyNoise": [], "AADGraphActivityLogs": []}
        async with serve(f.app) as (base, session):
            f.base = base
            logger = logging.getLogger("goosey-searchfail-test")
            logger.setLevel(logging.DEBUG)
            d = make_dumper(tmp_path, session, base, make_config("2026-11-02"), NOW1, logger=logger)
            await d.dump_log_analytic_workspaces()

    with caplog.at_level(logging.WARNING, logger="goosey-searchfail-test"):
        run(go())
    assert any("search summary failed" in r.getMessage() and "ws1" in r.getMessage() for r in caplog.records)
    m = manifest(tmp_path)
    assert m["data_check"] == "search_failed" and m["discovery_method"] == "tables_api"
    assert {e["table"]: e["status"] for e in m["tables"] if e["table"] in
            ("SecurityEvent", "EmptyNoise", "AADGraphActivityLogs")} == {
        "SecurityEvent": "success", "EmptyNoise": "success", "AADGraphActivityLogs": "success"}
    assert not any(e["status"] == "skipped" for e in m["tables"])


def test_table_queries_are_concurrency_bounded(tmp_path):
    async def go():
        f = FakeAzure()
        names = [f"T{i}" for i in range(24)]
        f.tables_pages = [names]
        f.data = {n: [{"id": n, "TimeGenerated": "2026-11-02T09:00:00Z"}] for n in names}
        async with serve(f.app) as (base, session):
            f.base = base
            await make_dumper(tmp_path, session, base, make_config("2026-11-02"), NOW1).dump_log_analytic_workspaces()
        return f

    f = run(go())
    assert 1 < f.max_in_flight <= 8


def test_zero_row_table_gets_empty_artifact_and_success_manifest(tmp_path):
    async def go():
        f = FakeAzure()
        f.tables_pages = [["AADGraphActivityLogs", "MicrosoftGraphActivityLogs"]]
        f.data = {"AADGraphActivityLogs": [],
                  "MicrosoftGraphActivityLogs": [{"id": "m1", "TimeGenerated": "2026-11-02T10:00:00Z"}]}
        async with serve(f.app) as (base, session):
            f.base = base
            await make_dumper(tmp_path, session, base, make_config("2026-11-02"), NOW1).dump_log_analytic_workspaces()
    run(go())
    art = ws_dir(tmp_path) / "AADGraphActivityLogs.json"
    assert art.is_file() and art.stat().st_size == 0
    m = manifest(tmp_path)
    e = entry(m, "AADGraphActivityLogs")
    assert (e["status"], e["row_count"], e["artifact"], e["error"]) == ("success", 0, "AADGraphActivityLogs.json", None)
    assert entry(m, "MicrosoftGraphActivityLogs")["row_count"] == 1
    assert m["schema_version"] == 1 and m["workspace_customer_id"] == "cust-1" and m["workspace_resource_id"] == WS_ID
    assert not (ws_dir(tmp_path) / "_collection_status.json.tmp").exists()


def test_empty_artifact_does_not_truncate_earlier_data(tmp_path):
    async def go():
        f = FakeAzure()
        f.tables_pages = [["AADGraphActivityLogs"]]
        f.data = {"AADGraphActivityLogs": [{"id": "a", "TimeGenerated": "2026-11-02T09:00:00Z"}]}
        async with serve(f.app) as (base, session):
            f.base = base
            await make_dumper(tmp_path, session, base, make_config("2026-11-02"), NOW1).dump_log_analytic_workspaces()
            # zero new rows this time
            await make_dumper(tmp_path, session, base, make_config("2026-11-02"), NOW2).dump_log_analytic_workspaces()
    run(go())
    assert ids(ws_dir(tmp_path) / "AADGraphActivityLogs.json") == ["a"]


def test_failed_query_is_failed_not_empty_success(tmp_path):
    async def go():
        f = FakeAzure()
        f.tables_pages = [["AADGraphActivityLogs", "MicrosoftGraphActivityLogs"]]
        f.data = {"AADGraphActivityLogs": [], "MicrosoftGraphActivityLogs": []}
        f.fail_tables = {"AADGraphActivityLogs"}
        async with serve(f.app) as (base, session):
            f.base = base
            await make_dumper(tmp_path, session, base, make_config("2026-11-02"), NOW1).dump_log_analytic_workspaces()
    run(go())
    m = manifest(tmp_path)
    bad, ok = entry(m, "AADGraphActivityLogs"), entry(m, "MicrosoftGraphActivityLogs")
    assert bad["status"] == "failed" and bad["row_count"] is None and bad["artifact"] is None
    assert "Failed to resolve table" in bad["error"] and "test-token" not in json.dumps(m)
    assert ok["status"] == "success" and ok["row_count"] == 0
    assert not (ws_dir(tmp_path) / "AADGraphActivityLogs.json").exists()
    assert not (ws_dir(tmp_path) / ".AADGraphActivityLogs.savestate").exists()   # no coverage claimed


def test_critical_tables_reported_unavailable_when_not_in_list(tmp_path):
    async def go():
        f = FakeAzure()
        f.tables_pages = [["SecurityEvent"]]
        f.data = {"SecurityEvent": []}
        async with serve(f.app) as (base, session):
            f.base = base
            await make_dumper(tmp_path, session, base, make_config("2026-11-02"), NOW1).dump_log_analytic_workspaces()
    run(go())
    m = manifest(tmp_path)
    for t in ("AADGraphActivityLogs", "MicrosoftGraphActivityLogs"):
        e = entry(m, t)
        assert e["status"] == "unavailable" and e["row_count"] is None and e["artifact"] is None
        assert e["error"] == "table not present in workspace table list"


def test_tables_api_403_warns_and_falls_back_to_search(tmp_path, caplog):
    async def go():
        f = FakeAzure()
        f.tables_status = 403
        f.data = {"SecurityEvent": [{"id": "s1", "TimeGenerated": "2026-11-02T09:00:00Z"}], "Empty": []}
        async with serve(f.app) as (base, session):
            f.base = base
            logger = logging.getLogger("goosey-fallback-test")
            logger.setLevel(logging.DEBUG)
            d = make_dumper(tmp_path, session, base, make_config("2026-11-02"), NOW1, logger=logger)
            await d.dump_log_analytic_workspaces()

    with caplog.at_level(logging.WARNING, logger="goosey-fallback-test"):
        run(go())
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert any("ws1" in w and "table listing failed" in w and "403" in w for w in warnings)
    m = manifest(tmp_path)
    assert m["discovery_method"] == "search_fallback" and "403" in m["discovery_error"]
    assert [e["table"] for e in m["tables"] if e["status"] == "success"] == ["SecurityEvent"]
    assert ids(ws_dir(tmp_path) / "SecurityEvent.json") == ["s1"]
    e = entry(m, "AADGraphActivityLogs")
    assert e["status"] == "unavailable" and e["error"].startswith("discovery failed:")


def test_rate_limit_error_body_is_retried_then_succeeds(tmp_path, monkeypatch):
    import goosey.utils as gu
    monkeypatch.setattr(gu, "KQL_THROTTLE_BASE_SLEEP", 0.01)   # keep the backoff test fast (config constant)

    async def go():
        f = FakeAzure()
        f.tables_pages = [["SecurityEvent"]]
        f.data = {"SecurityEvent": [{"id": "s1", "TimeGenerated": "2026-11-02T09:00:00Z"}]}
        f.throttle = {"SecurityEvent": 3}
        async with serve(f.app) as (base, session):
            f.base = base
            await make_dumper(tmp_path, session, base, make_config("2026-11-02"), NOW1).dump_log_analytic_workspaces()
        return f

    f = run(go())
    m = manifest(tmp_path)
    e = entry(m, "SecurityEvent")
    assert (e["status"], e["row_count"], e["error"]) == ("success", 1, None)
    assert f.throttle["SecurityEvent"] == 0
    assert ids(ws_dir(tmp_path) / "SecurityEvent.json") == ["s1"]
    # throttling must not shrink the time window (it used to be treated as "result too large")
    spans = [(a, b) for q, a, b, _ in f.queries if q == "SecurityEvent"]
    assert len(set(spans[:4])) == 1   # the same window was retried 3x, never halved


def test_persistent_rate_limit_ends_failed_not_empty(tmp_path, monkeypatch):
    import goosey.utils as gu
    monkeypatch.setattr(gu, "KQL_THROTTLE_BASE_SLEEP", 0.001)
    monkeypatch.setattr(gu, "KQL_THROTTLE_RETRIES", 2)

    async def go():
        f = FakeAzure()
        f.tables_pages = [["SecurityEvent"]]
        f.data = {"SecurityEvent": [{"id": "s1", "TimeGenerated": "2026-11-02T09:00:00Z"}]}
        f.throttle = {"SecurityEvent": 10_000}
        async with serve(f.app) as (base, session):
            f.base = base
            await make_dumper(tmp_path, session, base, make_config("2026-11-02"), NOW1).dump_log_analytic_workspaces()
    run(go())
    e = entry(manifest(tmp_path), "SecurityEvent")
    assert e["status"] == "failed" and "Rate limit" in e["error"]


def test_empty_message_exception_yields_nonblank_manifest_error(tmp_path):
    async def go():
        f = FakeAzure()
        f.tables_pages = [["SecurityEvent", "AADGraphActivityLogs"]]
        f.data = {"SecurityEvent": [{"id": "s1", "TimeGenerated": "2026-11-02T09:00:00Z"}],
                  "AADGraphActivityLogs": []}
        f.slow_tables = {"SecurityEvent"}
        async with serve(f.app, timeout=0.2) as (base, session):
            f.base = base
            await make_dumper(tmp_path, session, base, make_config("2026-11-02"), NOW1).dump_log_analytic_workspaces()
    run(go())
    e = entry(manifest(tmp_path), "SecurityEvent")
    assert e["status"] == "failed"
    assert e["error"] and e["error"].startswith("TimeoutError")


DUP = {"id": "dup", "TimeGenerated": "2026-11-02T12:40:00Z"}


def _law_two_runs(tmp_path, run2_mutation, lookback=None):
    """Run 1 at NOW1 (rows a 09:00, o 12:45, DUP x2 12:40), mutate the source, run 2 at NOW2."""
    async def go():
        f = FakeAzure()
        f.tables_pages = [["AADGraphActivityLogs"]]
        f.data = {"AADGraphActivityLogs": [{"id": "a", "TimeGenerated": "2026-11-02T09:00:00Z"},
                                           {"id": "o", "TimeGenerated": "2026-11-02T12:45:00Z"},
                                           dict(DUP), dict(DUP)]}
        cfg = make_config("2026-11-02")
        if lookback is not None:
            cfg.add_section("variables")
            cfg.set("variables", "incremental_lookback_minutes", str(lookback))
        async with serve(f.app) as (base, session):
            f.base = base
            await make_dumper(tmp_path, session, base, cfg, NOW1).dump_log_analytic_workspaces()
            f.queries.clear()
            run2_mutation(f)
            await make_dumper(tmp_path, session, base, cfg, NOW2).dump_log_analytic_workspaces()
        return f
    return run(go())


def test_law_late_arriving_row_before_checkpoint_is_collected(tmp_path):
    _law_two_runs(tmp_path, lambda f: f.data["AADGraphActivityLogs"].append(
        {"id": "late", "TimeGenerated": "2026-11-02T12:50:00Z"}))
    assert sorted(ids(ws_dir(tmp_path) / "AADGraphActivityLogs.json")) == ["a", "dup", "dup", "late", "o"]
    e = entry(manifest(tmp_path), "AADGraphActivityLogs")
    assert e["row_count"] == 1                 # newly written this run only
    assert e["duplicates_skipped"] == 3        # o + both dup copies re-fetched in the overlap


def test_law_overlap_refetch_not_duplicated_and_source_duplicates_preserved(tmp_path):
    _law_two_runs(tmp_path, lambda f: None)
    # "o" once, and the two genuine identical source rows both kept (not collapsed, not tripled)
    assert sorted(ids(ws_dir(tmp_path) / "AADGraphActivityLogs.json")) == ["a", "dup", "dup", "o"]
    m = manifest(tmp_path)
    assert entry(m, "AADGraphActivityLogs")["row_count"] == 0 and m["lookback_minutes"] == 30


def test_law_new_third_copy_of_a_source_duplicate_is_written(tmp_path):
    _law_two_runs(tmp_path, lambda f: f.data["AADGraphActivityLogs"].append(dict(DUP)))
    assert ids(ws_dir(tmp_path) / "AADGraphActivityLogs.json").count("dup") == 3


def test_law_checkpoint_never_exceeds_now_with_lookback(tmp_path):
    _law_two_runs(tmp_path, lambda f: None)
    state = dparser.parse((ws_dir(tmp_path) / ".AADGraphActivityLogs.savestate").read_text())
    assert state == NOW2


def test_law_lookback_config_override(tmp_path):
    f = _law_two_runs(tmp_path, lambda f: None, lookback=5)
    starts = {a for t, a, _, _ in f.queries if not t.startswith("search")}
    assert min(starts) == NOW1 - timedelta(minutes=5) and manifest(tmp_path)["lookback_minutes"] == 5
    # 12:45 is outside a 5-minute lookback: not re-fetched, so nothing to skip, nothing duplicated
    assert sorted(ids(ws_dir(tmp_path) / "AADGraphActivityLogs.json")) == ["a", "dup", "dup", "o"]
