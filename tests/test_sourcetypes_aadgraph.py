"""AADGraphActivityLogs sourcetype mapping and empty-artifact handling.

The collector writes one NDJSON file per Log Analytics table; a table that was
queried successfully but returned no rows is a 0-byte file, and each workspace
directory also carries a `_collection_status.json` manifest.  These tests drive
the real Flask app over real files in tmp_path.

@decision DEC-HQL-012
@title Register AADGraphActivityLogs under the Microsoft Graph Activity LAW group
@status accepted
@rationale ROADrecon talks only to legacy AAD Graph; its request telemetry lands
  in AADGraphActivityLogs, which no existing glob covered.  It sits beside
  MicrosoftGraphActivityLogs so analysts find both request logs together.
"""

import json
import os
import sys

import pytest

pytest.importorskip("flask")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "fixtures"))
import synthetic_logs as syn  # noqa: E402

from goosey.web import (  # noqa: E402
    app, load_sourcetypes, scan_output_dir, _lookup_sourcetype,
)

GLOB = "azure/*/log_analytics_workspace/*/AADGraphActivityLogs*json"
LAW = "azure/sub-fake/log_analytics_workspace/ws-fake"
EMPTY = f"{LAW}/AADGraphActivityLogs_2026-11-02.json"
MANIFEST = f"{LAW}/_collection_status.json"


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture
def out(tmp_path):
    syn.write_ndjson(str(tmp_path / EMPTY), [])
    (tmp_path / MANIFEST).write_text(json.dumps(
        {"workspace": "ws-fake", "tables": {"AADGraphActivityLogs": {"status": "ok", "rows": 0}}}))
    app.config["OUTPUT_DIR"] = str(tmp_path)
    yield str(tmp_path)
    app.config.pop("OUTPUT_DIR", None)


def test_registry_has_sourcetype_with_glob_in_msgraph_group():
    data = load_sourcetypes()
    st = _lookup_sourcetype(data, "aadgraphactivitylogs")
    assert st is not None and st["file_glob"] == GLOB
    # Same grouping as MicrosoftGraphActivityLogs
    sibling = _lookup_sourcetype(data, "microsoftgraphactivitylogs")
    assert sibling is not None
    group = next(g for g in _walk_groups(data)
                 if "aadgraphactivitylogs" in g.get("sourcetypes", {}))
    assert "microsoftgraphactivitylogs" in group["sourcetypes"]


def _walk_groups(node):
    if isinstance(node, dict):
        if "sourcetypes" in node:
            yield node
        for v in node.values():
            yield from _walk_groups(v)
    elif isinstance(node, list):
        for v in node:
            yield from _walk_groups(v)


def test_scan_matches_artifact_but_not_manifest(out):
    found = scan_output_dir(out, load_sourcetypes())["aadgraphactivitylogs"]
    rels = [os.path.relpath(p, out) for p in found]
    assert rels == [EMPTY]


def test_manifest_not_claimed_by_any_sourcetype(out):
    scanned = scan_output_dir(out, load_sourcetypes())
    claimed = [os.path.relpath(p, out) for v in scanned.values() for p in v]
    assert MANIFEST not in claimed


def test_browse_files_lists_empty_artifact(client, out):
    r = client.get("/api/browse/files?type=azure&subtype=law&sourcetype=aadgraphactivitylogs")
    assert r.status_code == 200
    files = r.get_json()["files"]
    assert [f["path"] for f in files] == [EMPTY]
    assert files[0]["size"] == 0 and files[0]["lines"] == 0


def test_browse_query_on_empty_artifact_returns_zero_rows(client, out):
    for query in ("take 100", "summarize count() by UserId",
                  "summarize n=count(), d=dcount(RequestUri) by UserId | where n > 100"):
        r = client.post("/api/browse/query", json={"query": query, "file": EMPTY})
        assert r.status_code == 200, r.get_json()
        body = r.get_json()
        assert body["total"] == 0 and body["rows"] == []


def test_browse_query_over_manifest_does_not_500(client, out):
    r = client.post("/api/browse/query", json={"query": "take 5", "file": MANIFEST})
    assert r.status_code == 200 and r.get_json()["total"] == 1


def test_preview_of_empty_artifact(client, out):
    r = client.get(f"/api/browse/preview?path={EMPTY}")
    assert r.status_code == 200
    body = r.get_json()
    assert body["lines"] == [] and body["total_lines"] == 0 and body["has_more"] is False


def test_browse_tree_exposes_sourcetype(client, out):
    r = client.get("/api/browse/tree")
    assert r.status_code == 200
    assert "aadgraphactivitylogs" in json.dumps(r.get_json())


def test_nonempty_artifact_is_queryable(client, out, tmp_path):
    rel = f"{LAW}/AADGraphActivityLogs_2026-11-03.json"
    syn.write_ndjson(str(tmp_path / rel), syn.roadrecon_burst_rows(5))
    r = client.post("/api/browse/query", json={"query": "summarize count() by UserId", "file": rel})
    assert r.status_code == 200 and r.get_json()["rows"][0]["count_"] == 5
