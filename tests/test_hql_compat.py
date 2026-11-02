"""Regression tests for goosey.hql_compat against pyhql 0.0.9.

Covers the CyberFire lab findings: summarize count() crashing on our own Table
patch, missing dcount(), nested Graph fields addressed as ['status.errorCode']
resolving to nothing, int-vs-string literal comparisons, and empty artifacts.
All data is synthetic and written to real files under tmp_path (no mocks).

@decision DEC-HQL-011
@title Test hql_compat end to end against real files
@status accepted
@rationale The defects lived in the interaction between our monkey patches and
  pyhql internals, so only real run_hql_query() calls over real NDJSON files
  reproduce them.
"""

import json
import os
import sys

import pytest

pytest.importorskip("goosey.hql_compat")  # installs the Hql import hook first
pytest.importorskip("Hql")

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "fixtures"))
import synthetic_logs as syn  # noqa: E402

from goosey.hql_compat import run_hql_query  # noqa: E402

REL = "entraid/signin_rt/rt_signin_log_2026-11-02.json"


@pytest.fixture
def out(tmp_path):
    rows = [
        syn.graph_signin(syn.AAD_GRAPH_RESOURCE_ID, 0, suffix="1"),
        syn.graph_signin(syn.AAD_GRAPH_RESOURCE_ID, 0, suffix="2"),
        syn.graph_signin(syn.MS_GRAPH_RESOURCE_ID, 0, suffix="3"),
        syn.graph_signin(syn.MS_GRAPH_RESOURCE_ID, 50126, suffix="4"),
    ]
    rows[2]["ipAddress"] = syn.OTHER_IP
    syn.write_ndjson(str(tmp_path / REL), rows)
    return str(tmp_path)


def q(out, text):
    return run_hql_query(text, out, REL)


class TestSummarize:
    def test_count_by(self, out):
        r = q(out, "summarize count() by ipAddress | sort by count_ desc")
        assert r["rows"][0] == {"ipAddress": syn.FAKE_IP, "count_": 3}
        assert r["total"] == 2

    def test_named_count(self, out):
        r = q(out, "summarize n=count() by userPrincipalName")
        assert r["columns"] == ["userPrincipalName", "n"]
        assert r["rows"][0]["n"] == 4

    def test_dcount(self, out):
        r = q(out, "summarize dcount(resourceId) by userPrincipalName")
        assert r["rows"] == [{"userPrincipalName": syn.FAKE_UPN, "dcount_": 2}]

    def test_count_and_named_dcount_then_filter(self, out):
        r = q(out, "summarize n=count(), d=dcount(ipAddress) by userId | where n > 3")
        assert r["rows"] == [{"userId": syn.FAKE_USER_ID, "n": 4, "d": 2}]


class TestNestedFields:
    def test_string_zero_matches_int_error_code(self, out):
        r = q(out, """where ['status.errorCode'] == "0" """)
        assert r["total"] == 3

    def test_int_zero_matches(self, out):
        r = q(out, "where ['status.errorCode'] == 0")
        assert r["total"] == 3

    def test_not_equal_string_zero(self, out):
        r = q(out, """where ['status.errorCode'] != "0" | project ['status.errorCode']""")
        assert r["rows"] == [{"status.errorCode": 50126}]

    def test_specific_nonzero_code(self, out):
        assert q(out, "where ['status.errorCode'] == 50126")["total"] == 1
        assert q(out, """where ['status.errorCode'] == "50126" """)["total"] == 1

    def test_in_list_mixed_literals(self, out):
        r = q(out, """where ['status.errorCode'] in ("0", "50126")""")
        assert r["total"] == 4

    def test_boolean_nested(self, out):
        r = q(out, "where ['deviceDetail.isCompliant'] == false and ['status.errorCode'] == 0")
        assert r["total"] == 3

    def test_summarize_by_nested(self, out):
        r = q(out, "summarize count() by ['location.countryOrRegion']")
        assert r["rows"] == [{"location.countryOrRegion": "US", "count_": 4}]

    def test_three_level_path(self, out):
        r = q(out, "take 1 | project ['location.geoCoordinates.latitude']")
        assert r["rows"] == [{"location.geoCoordinates.latitude": 0.0}]

    def test_original_struct_still_present(self, out):
        r = q(out, "where ['status.errorCode'] == 0 | take 1")
        assert r["rows"][0]["status"]["errorCode"] == 0

    def test_second_query_without_dotted_names_unaffected(self, out):
        q(out, "where ['status.errorCode'] == 0")
        r = q(out, "take 1")
        assert "status.errorCode" not in r["columns"]

    def test_flat_dotted_key_not_overwritten(self, tmp_path):
        syn.write_ndjson(str(tmp_path / "f.json"), [{"a.b": "flat", "a": {"b": "nested"}}])
        r = run_hql_query("project ['a.b']", str(tmp_path), "f.json")
        assert r["rows"] == [{"a.b": "flat"}]

    def test_existing_catalog_queries_with_nested_fields(self, out):
        """Catalog entries use ['status.errorCode'] etc.; they must return rows."""
        from goosey.web import load_hunting_queries
        cat = {x["id"]: x for x in load_hunting_queries()["queries"]}
        # hunt-signin-012: non-compliant device, successful sign-in
        r = q(out, cat["hunt-signin-012"]["hql_query"])
        assert r["total"] >= 1 and sum(x["count_"] for x in r["rows"]) == 3
        # hunt-signin-001: failed sign-ins by country
        r = q(out, cat["hunt-signin-001"]["hql_query"])
        assert r["rows"] == [{"location.countryOrRegion": "US", "count_": 1}]
        # hunt-signin-002: failed sign-ins by IP using dcount
        r = q(out, cat["hunt-signin-002"]["hql_query"])
        assert r["total"] == 1 and r["rows"][0]["dcount_"] == 1


class TestEmptyAndManifest:
    def test_zero_byte_file_returns_zero_rows(self, tmp_path):
        p = tmp_path / "azure/sub/log_analytics_workspace/ws/AADGraphActivityLogs_2026-11-02.json"
        syn.write_ndjson(str(p), [])
        assert p.stat().st_size == 0
        for text in ("take 10", "summarize count() by UserId",
                     """where ['a.b'] == "x" """):
            r = run_hql_query(text, str(tmp_path), os.path.relpath(p, tmp_path))
            assert r["total"] == 0 and r["rows"] == [] and r["pages"] == 1

    def test_whitespace_only_file(self, tmp_path):
        (tmp_path / "w.json").write_text("\n")
        assert run_hql_query("take 1", str(tmp_path), "w.json")["total"] == 0

    def test_status_manifest_single_object_is_queryable(self, tmp_path):
        manifest = {"workspace": "ws", "tables": {"AADGraphActivityLogs": {"rows": 0}}}
        p = tmp_path / "azure/sub/log_analytics_workspace/ws/_collection_status.json"
        p.parent.mkdir(parents=True)
        p.write_text(json.dumps(manifest, indent=2))
        r = run_hql_query("take 5", str(tmp_path), os.path.relpath(p, tmp_path))
        assert r["total"] == 1
