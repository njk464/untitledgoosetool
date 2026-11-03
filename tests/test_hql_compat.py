"""Regression tests for goosey.hql_compat against upstream Hql main (Python 3.14t).

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

pytest.importorskip("goosey.hql_compat")
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


class TestSigmaMisroute:
    """Queries containing ": " are valid YAML; Hql 0.0.9 misrouted them to the Sigma parser."""

    def test_colon_space_in_string_literal(self, out):
        r = q(out, 'where userPrincipalName == "Foo: bar"')
        assert r["total"] == 0 and r["columns"] != []

    def test_colon_space_literal_that_matches(self, tmp_path):
        syn.write_ndjson(str(tmp_path / "f.json"), [{"msg": "Foo: bar"}, {"msg": "other"}])
        r = run_hql_query('where msg == "Foo: bar"', str(tmp_path), "f.json")
        assert r["rows"] == [{"msg": "Foo: bar"}]

    def test_sigma_noise_not_logged(self, out, caplog):
        import logging
        with caplog.at_level(logging.DEBUG):
            q(out, "take 1")
        assert not any("Invalid sigma" in r.getMessage() for r in caplog.records)


class TestFileResolution:
    def test_subdirectory_path(self, out):
        assert q(out, "take 1")["total"] == 1

    def test_full_database_query_with_subdirectory(self, out):
        r = run_hql_query(f'database("goose").file("{REL}") | take 2', out)
        assert r["total"] == 2

    def test_wildcard_across_files_with_dotted_names(self, tmp_path):
        """Several files => Hql may evaluate them on worker threads (free-threaded build)."""
        for i in range(6):
            syn.write_ndjson(str(tmp_path / f"d/f{i}.json"),
                             [{"status": {"errorCode": i}, "n": i}])
        # Six files => one combined table (DEC-HQL-017), each row carrying its dotted column.
        for _ in range(5):
            r = run_hql_query("where ['status.errorCode'] >= 0 | project ['status.errorCode']",
                              str(tmp_path), "d/f*.json")
            assert r["total"] == 6 and r["columns"] == ["status.errorCode"]
            assert sorted(x["status.errorCode"] for x in r["rows"]) == list(range(6))

    def test_path_traversal_refused(self, tmp_path):
        (tmp_path / "secret.json").write_text('[{"a": 1}]')
        sub = tmp_path / "data"
        sub.mkdir()
        with pytest.raises(ValueError, match="outside the data directory"):
            run_hql_query("take 1", str(sub), "../secret.json")

    def test_missing_file_is_zero_rows_or_error_not_crash(self, tmp_path):
        try:
            r = run_hql_query("take 1", str(tmp_path), "nope.json")
        except ValueError:
            return
        assert r["total"] == 0


class TestConcurrentQueries:
    def test_parallel_queries_do_not_leak_dotted_state(self, out):
        import concurrent.futures as cf

        def one(i):
            if i % 2:
                return q(out, "where ['status.errorCode'] == 0 | summarize count()")["rows"]
            return q(out, "take 1 | project userPrincipalName")["rows"]

        with cf.ThreadPoolExecutor(8) as ex:
            res = list(ex.map(one, range(16)))
        assert all(r == [{"count_": 3}] for r in res[1::2])
        assert all(r == [{"userPrincipalName": syn.FAKE_UPN}] for r in res[0::2])


class TestUpstreamGapSentinels:
    """Run the UNPATCHED engine in a clean interpreter.

    Each assertion documents a gap in Hql main that goosey/hql_compat.py patches.
    When one fails, upstream fixed it: delete the matching patch (and this check).
    """

    SCRIPT = r"""
import json, os, sys
from Hql import run_query
from Hql.Config import Config
base = sys.argv[1]
conf = Config()
conf.conf['databases']['g'] = {'name': 'g', 'type': 'JSON', 'conf': {'local-base': base},
                                'macro': {}, 'mappings': {}}
def run(rel, text):
    try:
        res = run_query(f'database("g").file("{rel}") | {text}', conf)
        t = next(iter(res.tables.values()))
        return t.df.height
    except Exception as e:
        return 'ERR ' + type(e).__name__
def run_files(files, text):
    try:
        res = run_query(f'database("g").file({files}) | {text}', conf)
        return next(iter(res.tables.values())).df.to_dicts()
    except Exception as e:
        return 'ERR ' + type(e).__name__
out = {
  'subdir': run('sub/rows.json', 'take 5'),
  'single_object': run('single.json', 'take 5'),
  'dcount': run('rows.json', 'summarize dcount(n) by k'),
  'str_vs_int': run('rows.json', 'where n == "1"'),
  'bracket_dotted': run('rows.json', "where ['s.e'] == 0"),
  'multi_schema': run_files('"mixA.json", "mixB.json"', 'summarize n=count() by OnlyA'),
  'multi_rows': run_files('"mixA.json", "mixB.json"', 'count'),
}
print('RESULT' + json.dumps(out))
"""

    @pytest.fixture(scope="class")
    @classmethod
    def raw(cls, tmp_path_factory):
        import subprocess
        import sys
        base = tmp_path_factory.mktemp("sentinel")
        rows = [{"k": "a", "n": 1, "s": {"e": 0}}, {"k": "a", "n": 2, "s": {"e": 1}}]
        syn.write_ndjson(str(base / "rows.json"), rows)
        syn.write_ndjson(str(base / "sub" / "rows.json"), rows)
        (base / "single.json").write_text(json.dumps({"x": 1}))
        syn.write_ndjson(str(base / "mixA.json"), [{"id": "a", "OnlyA": "x"}, {"id": "b", "OnlyA": "y"}])
        syn.write_ndjson(str(base / "mixB.json"), [{"id": "c", "OnlyB": 1}])
        script = base.parent / "sentinel_script.py"
        script.write_text(cls.SCRIPT)
        proc = subprocess.run([sys.executable, "-I", str(script), str(base)],
                              capture_output=True, text=True, timeout=120)
        line = [x for x in proc.stdout.splitlines() if x.startswith("RESULT")]
        assert line, proc.stdout + proc.stderr
        return json.loads(line[0][len("RESULT"):])

    def test_files_in_subdirectories_not_found(self, raw):
        assert raw["subdir"] != 2

    def test_single_object_file_unsupported(self, raw):
        assert isinstance(raw["single_object"], str)

    def test_dcount_missing(self, raw):
        assert isinstance(raw["dcount"], str)

    def test_string_literal_does_not_match_int(self, raw):
        assert raw["str_vs_int"] != 1

    def test_bracketed_dotted_name_not_resolved(self, raw):
        assert raw["bracket_dotted"] != 1

    def test_multi_file_mixed_schema_summarize_fails(self, raw):
        assert isinstance(raw["multi_schema"], str)

    def test_multi_file_result_shows_only_first_file(self, raw):
        assert raw["multi_rows"] != [{"Count": 3}]


class TestMultiFileMixedSchemas:
    """Files with DIFFERENT columns queried together (e.g. AlertEvidence + AlertInfo; DEC-HQL-017)."""

    @pytest.fixture
    def mix(self, tmp_path):
        syn.write_ndjson(str(tmp_path / "A.json"), [
            {"id": "a1", "DeviceName": "pc1", "Sev": "low"},
            {"id": "a2", "DeviceName": "pc2", "Sev": "high"},
            {"id": "a3", "DeviceName": "pc1", "Sev": "high"}])
        syn.write_ndjson(str(tmp_path / "B.json"), [
            {"id": "b1", "Title": "t1", "Sev": "high", "meta": {"k": 1}},
            {"id": "b2", "Title": "t2", "Sev": "low", "meta": {"k": 2}}])
        return str(tmp_path)

    def mq(self, mix, text):
        return run_hql_query(f'database("goose").file("A.json", "B.json") | {text}', mix)

    def test_summarize_by_column_only_in_first_file(self, mix):
        r = self.mq(mix, "summarize n=count() by DeviceName")
        got = {x["DeviceName"]: x["n"] for x in r["rows"]}
        assert got == {"pc1": 2, "pc2": 1, None: 2}

    def test_summarize_by_column_only_in_second_file(self, mix):
        r = self.mq(mix, "summarize n=count() by Title")
        assert {x["Title"]: x["n"] for x in r["rows"]} == {"t1": 1, "t2": 1, None: 3}

    def test_summarize_by_column_in_both(self, mix):
        r = self.mq(mix, "summarize n=count() by Sev")
        assert {x["Sev"]: x["n"] for x in r["rows"]} == {"low": 2, "high": 3}

    def test_count_includes_every_file(self, mix):
        assert self.mq(mix, "count")["rows"] == [{"Count": 5}]

    def test_take_and_project_return_rows_from_both_files(self, mix):
        assert self.mq(mix, "take 10")["total"] == 5
        r = self.mq(mix, "project id, Sev")
        assert sorted(x["id"] for x in r["rows"]) == ["a1", "a2", "a3", "b1", "b2"]

    def test_where_on_shared_and_one_sided_columns(self, mix):
        assert self.mq(mix, 'where Sev == "high"')["total"] == 3
        assert self.mq(mix, 'where DeviceName == "pc1"')["total"] == 2
        assert self.mq(mix, 'where Title == "t2"')["total"] == 1

    def test_sort_across_files(self, mix):
        r = self.mq(mix, "sort by id asc | project id")
        assert [x["id"] for x in r["rows"]] == ["a1", "a2", "a3", "b1", "b2"]

    def test_nested_column_present_in_one_file(self, mix):
        r = self.mq(mix, "where isnotempty(Title) | summarize count() by ['meta.k']")
        assert sorted(x["meta.k"] for x in r["rows"]) == [1, 2]

    def test_dcount_ignores_nulls(self, mix):
        r = self.mq(mix, "summarize d=dcount(Title) by Sev")
        assert {x["Sev"]: x["d"] for x in r["rows"]} == {"low": 1, "high": 1}

    def test_wildcard_over_mixed_schemas(self, mix):
        r = run_hql_query('database("goose").file("*.json") | summarize n=count() by DeviceName', mix)
        assert sum(x["n"] for x in r["rows"]) == 5
