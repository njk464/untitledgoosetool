"""Hunting-catalog regression tests for the ROADrecon / ROADtools detections.

Covers (1) sign-in target globs matching the collector's real filenames
(entraid/signin_<source>/<source>_signin_log_<date>.json), (2) the AAD Graph
request-burst hunt over AADGraphActivityLogs, and (3) the legacy AAD Graph
token-acquisition precursor over non-interactive sign-ins.  The catalog's own
hql_query text is executed, so a catalog entry that stops working fails here.

@decision DEC-HUNT-003
@title Execute catalog HQL against synthetic fixtures to guard hunts
@status accepted
@rationale Live validation found catalog queries that parsed but returned
  nothing (wrong globs, bracketed nested fields).  Running each shipped query
  over positive, benign and failed-auth fixtures proves it fires only on the
  intended traffic.
"""

import os
import sys

import pytest

pytest.importorskip("goosey.hql_compat")  # installs the Hql import hook first
pytest.importorskip("Hql")
pytest.importorskip("flask")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "fixtures"))
import synthetic_logs as syn  # noqa: E402

from goosey.hql_compat import run_hql_query  # noqa: E402
from goosey.web import load_hunting_queries, resolve_target_files  # noqa: E402


@pytest.fixture(autouse=True)
def fresh_catalog():
    import goosey.web as web
    web._hunting_queries_cache = None
    yield
    web._hunting_queries_cache = None


def hunt(hunt_id):
    return next(q for q in load_hunting_queries()["queries"] if q["id"] == hunt_id)


# ---------------------------------------------------------------------------
# Sign-in globs
# ---------------------------------------------------------------------------

SIGNIN_FILES = [
    "entraid/signin_rt/rt_signin_log_2026-11-02.json",
    "entraid/signin_sp/sp_signin_log_2026-11-02.json",
    "entraid/signin_msi/msi_signin_log_2026-11-02.json",
    "entraid/signin_adfs/adfs_signin_log_2026-11-02.json",
    "entraid/signin_rt/rt_signin_log_2026-11-02.jsonl",
]
NOT_SIGNIN = ["entraid/entraid_audit_logs/entraidauditlog_2026-11-02.json",
              "entraid/signin_rt/.rt_signin_state"]


@pytest.fixture
def tree(tmp_path):
    for rel in SIGNIN_FILES + NOT_SIGNIN:
        syn.write_ndjson(str(tmp_path / rel), [{"id": "x"}])
    return str(tmp_path)


@pytest.mark.parametrize("hunt_id", ["hunt-signin-%03d" % i for i in range(1, 13)])
def test_every_signin_hunt_resolves_all_sources(tree, hunt_id):
    paths = {f["path"] for f in resolve_target_files(hunt(hunt_id)["target_files"], tree)}
    assert set(SIGNIN_FILES) <= paths
    assert not (paths & set(NOT_SIGNIN))


def test_precursor_targets_only_nonInteractive_rt(tree):
    paths = {f["path"] for f in resolve_target_files(hunt("hunt-signin-013")["target_files"], tree)}
    assert paths == {SIGNIN_FILES[0], SIGNIN_FILES[4]}


# ---------------------------------------------------------------------------
# hunt-law-001: AAD Graph burst
# ---------------------------------------------------------------------------

LAW_DIR = "azure/sub-fake/log_analytics_workspace/ws-fake"


def run_burst(tmp_path, rows):
    rel = f"{LAW_DIR}/AADGraphActivityLogs_2026-11-02.json"
    syn.write_ndjson(str(tmp_path / rel), rows)
    return run_hql_query(hunt("hunt-law-001")["hql_query"], str(tmp_path), rel)


def test_burst_hunt_metadata():
    h = hunt("hunt-law-001")
    assert h["severity"] == "high"
    assert h["target_files"] == ["azure/*/log_analytics_workspace/*/AADGraphActivityLogs*json"]
    assert "TimeRequested" in h["source_kql"] and "bin(TimeRequested, 5m)" in h["source_kql"]
    assert "python-requests" not in h["hql_query"]


@pytest.mark.parametrize("n", [150, 3136])
def test_burst_matches_roadrecon_shaped_traffic(tmp_path, n):
    r = run_burst(tmp_path, syn.roadrecon_burst_rows(n) + syn.first_party_policy_rows())
    assert r["total"] == 1
    row = r["rows"][0]
    assert row["n"] == n and row["uris"] == n
    assert row["UserId"] == syn.FAKE_USER_ID
    assert row["CallerIpAddress"] == syn.FAKE_IP
    assert row["AppId"] == syn.AZURE_CLI_APP_ID
    assert row["UserAgent"] == syn.ROAD_UA


def test_burst_ignores_low_volume_first_party_traffic(tmp_path):
    r = run_burst(tmp_path, syn.first_party_policy_rows(8))
    assert r["total"] == 0


def test_burst_ignores_exactly_threshold_volume(tmp_path):
    assert run_burst(tmp_path, syn.roadrecon_burst_rows(100))["total"] == 0


def test_burst_on_empty_artifact(tmp_path):
    assert run_burst(tmp_path, [])["total"] == 0


# ---------------------------------------------------------------------------
# hunt-signin-013: legacy AAD Graph token acquisition
# ---------------------------------------------------------------------------

def run_token_hunt(tmp_path, rows):
    rel = "entraid/signin_rt/rt_signin_log_2026-11-02.json"
    syn.write_ndjson(str(tmp_path / rel), rows)
    return run_hql_query(hunt("hunt-signin-013")["hql_query"], str(tmp_path), rel)


def test_token_hunt_metadata():
    h = hunt("hunt-signin-013")
    assert "AADNonInteractiveUserSignInLogs" in h["source_kql"]
    assert "dcount(ResourceIdentity)" in h["source_kql"]  # correlation documented, not approximated


def test_token_hunt_matches_roadtools_token_event(tmp_path):
    pos = syn.graph_signin(syn.AAD_GRAPH_RESOURCE_ID, 0, suffix="1")
    neg_graph = syn.graph_signin(syn.MS_GRAPH_RESOURCE_ID, 0, suffix="2")
    neg_fail = syn.graph_signin(syn.AAD_GRAPH_RESOURCE_ID, 50126, suffix="3")
    neg_ua = syn.graph_signin(syn.AAD_GRAPH_RESOURCE_ID, 0, user_agent="Mozilla/5.0", suffix="4")
    neg_app = syn.graph_signin(syn.AAD_GRAPH_RESOURCE_ID, 0,
                               app_id="00000000-0000-0000-0000-0000000000ee", suffix="5")
    r = run_token_hunt(tmp_path, [neg_graph, pos, neg_fail, neg_ua, neg_app])
    assert r["total"] == 1
    row = r["rows"][0]
    assert row["userPrincipalName"] == syn.FAKE_UPN
    assert row["userId"] == syn.FAKE_USER_ID
    assert row["ipAddress"] == syn.FAKE_IP
    assert row["appId"] == syn.AZURE_CLI_APP_ID
    assert row["resourceId"] == syn.AAD_GRAPH_RESOURCE_ID
    assert row["resourceDisplayName"] == "Windows Azure Active Directory"
    assert row["userAgent"].startswith("python-requests")
    assert row["correlationId"] == pos["correlationId"]
    for col in ("createdDateTime", "appDisplayName"):
        assert col in r["columns"]


def test_token_hunt_no_hits_on_unrelated_graph_event(tmp_path):
    r = run_token_hunt(tmp_path, [syn.graph_signin(syn.MS_GRAPH_RESOURCE_ID, 0)])
    assert r["total"] == 0


def test_token_hunt_case_insensitive_user_agent(tmp_path):
    row = syn.graph_signin(syn.AAD_GRAPH_RESOURCE_ID, 0, user_agent="Python-Requests/2.32.0")
    assert run_token_hunt(tmp_path, [row])["total"] == 1


# ---------------------------------------------------------------------------
# Whole-catalog sanity via the real Flask API
# ---------------------------------------------------------------------------

def test_new_hunts_visible_through_api():
    from goosey.web import app
    app.config["TESTING"] = True
    with app.test_client() as c:
        body = c.get("/api/hunting/queries?severity=high&subcategory=law").get_json()
        assert [q["id"] for q in body["queries"]] == ["hunt-law-001"]
        assert c.get("/api/hunting/queries/hunt-signin-013").status_code == 200


def test_burst_hunt_through_web_query_api(tmp_path):
    """The catalog query runs via POST /api/browse/query on a resolved artifact."""
    from goosey.web import app
    rel = f"{LAW_DIR}/AADGraphActivityLogs_2026-11-02.json"
    syn.write_ndjson(str(tmp_path / rel), syn.roadrecon_burst_rows(150) + syn.first_party_policy_rows())
    app.config["TESTING"] = True
    app.config["OUTPUT_DIR"] = str(tmp_path)
    try:
        with app.test_client() as c:
            res = c.get("/api/hunting/resolve?id=hunt-law-001").get_json()
            assert [f["path"] for f in res["files"]] == [rel]
            r = c.post("/api/browse/query",
                       json={"query": hunt("hunt-law-001")["hql_query"], "file": res["files"][0]["path"]})
            assert r.status_code == 200, r.get_json()
            body = r.get_json()
            assert body["total"] == 1
            assert body["rows"][0]["n"] == 150 and body["rows"][0]["uris"] == 150
            assert body["rows"][0]["AppId"] == syn.AZURE_CLI_APP_ID
    finally:
        app.config.pop("OUTPUT_DIR", None)
