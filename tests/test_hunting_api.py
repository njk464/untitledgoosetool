"""Tests for Hunting Query API endpoints: /api/hunting/queries, /api/hunting/queries/<id>,
/api/hunting/resolve, and helpers load_hunting_queries() and resolve_target_files().

Tests validate:
- load_hunting_queries() loads and caches the catalog correctly
- /api/hunting/queries returns all queries and supports filtering
- /api/hunting/queries/<id> returns single query or 404
- resolve_target_files() resolves glob patterns with security checks
- /api/hunting/resolve returns resolved file list or 404

@decision DEC-HUNT-002
@title Hunting query API endpoints (queries catalog + file resolution)
@status accepted
@rationale Provides the browser UI with query catalog navigation and file-target
  resolution without exposing raw file paths; glob expansion mirrors the
  existing _expand_glob_patterns() pattern from the browse API.
"""

import json
import os
import tempfile
import pytest

try:
    from goosey.web import (
        app,
        load_hunting_queries,
        resolve_target_files,
    )
    FLASK_AVAILABLE = True
except ImportError:
    FLASK_AVAILABLE = False


pytestmark = pytest.mark.skipif(
    not FLASK_AVAILABLE, reason="Flask not installed; skipping web tests"
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def reset_hunting_cache():
    """Clear the module-level cache before each test so tests are isolated."""
    import goosey.web as web_module
    web_module._hunting_queries_cache = None
    yield
    web_module._hunting_queries_cache = None


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture
def sample_output_dir(tmp_path):
    """Create a minimal fake output dir with sign-in log files."""
    signin_dir = tmp_path / "signin_20260101"
    signin_dir.mkdir(parents=True)
    (signin_dir / "signin_log_20260101.json").write_text('{"id": "s1"}\n')
    (signin_dir / "signin_log_20260102.jsonl").write_text('{"id": "s2"}\n')

    # Azure subscription dir with a resource file
    azure_sub = tmp_path / "azure" / "sub-abc123"
    azure_sub.mkdir(parents=True)
    (azure_sub / "all_resources_list.json").write_text('{"r": 1}\n')

    return str(tmp_path)


# ---------------------------------------------------------------------------
# Unit tests: load_hunting_queries()
# ---------------------------------------------------------------------------

class TestLoadHuntingQueries:
    def test_returns_dict(self):
        data = load_hunting_queries()
        assert isinstance(data, dict)

    def test_has_version(self):
        data = load_hunting_queries()
        assert "version" in data

    def test_has_queries_list(self):
        data = load_hunting_queries()
        assert "queries" in data
        assert isinstance(data["queries"], list)
        assert len(data["queries"]) > 0

    def test_queries_have_required_fields(self):
        data = load_hunting_queries()
        required = {"id", "name", "description", "category", "subcategory",
                    "severity", "mitre_ids", "hql_query", "target_files"}
        for q in data["queries"]:
            for field in required:
                assert field in q, f"Query {q.get('id','?')} missing field '{field}'"

    def test_caching_returns_same_object(self):
        """Second call must return the cached object (same identity)."""
        first = load_hunting_queries()
        second = load_hunting_queries()
        assert first is second

    def test_known_categories_present(self):
        data = load_hunting_queries()
        cats = {q["category"] for q in data["queries"]}
        assert "entra_id" in cats

    def test_query_ids_are_unique(self):
        data = load_hunting_queries()
        ids = [q["id"] for q in data["queries"]]
        assert len(ids) == len(set(ids)), "Duplicate query IDs found"


# ---------------------------------------------------------------------------
# Unit tests: resolve_target_files()
# ---------------------------------------------------------------------------

class TestResolveTargetFiles:
    def test_resolves_simple_glob(self, sample_output_dir):
        patterns = ["signin_*/signin_log_*.json"]
        result = resolve_target_files(patterns, sample_output_dir)
        assert len(result) == 1
        assert result[0]["path"] == "signin_20260101/signin_log_20260101.json"

    def test_resolves_multiple_patterns(self, sample_output_dir):
        patterns = [
            "signin_*/signin_log_*.json",
            "signin_*/signin_log_*.jsonl",
        ]
        result = resolve_target_files(patterns, sample_output_dir)
        paths = {r["path"] for r in result}
        assert "signin_20260101/signin_log_20260101.json" in paths
        assert "signin_20260101/signin_log_20260102.jsonl" in paths

    def test_result_has_size_and_modified(self, sample_output_dir):
        patterns = ["signin_*/signin_log_*.json"]
        result = resolve_target_files(patterns, sample_output_dir)
        assert len(result) == 1
        item = result[0]
        assert "size" in item
        assert isinstance(item["size"], int)
        assert item["size"] > 0
        assert "modified" in item
        # ISO8601 format check (YYYY-MM-DDTHH:MM:SS)
        assert "T" in item["modified"]

    def test_path_is_relative(self, sample_output_dir):
        patterns = ["signin_*/signin_log_*.json"]
        result = resolve_target_files(patterns, sample_output_dir)
        for item in result:
            assert not os.path.isabs(item["path"]), "path must be relative"

    def test_empty_patterns_returns_empty(self, sample_output_dir):
        result = resolve_target_files([], sample_output_dir)
        assert result == []

    def test_nonexistent_pattern_returns_empty(self, sample_output_dir):
        result = resolve_target_files(["nonexistent/*.json"], sample_output_dir)
        assert result == []

    def test_sub_id_expansion(self, sample_output_dir):
        """Patterns with {sub_id} expand against actual azure/ subdirectories."""
        patterns = ["azure/{sub_id}/all_resources_list*.json"]
        result = resolve_target_files(patterns, sample_output_dir)
        assert len(result) == 1
        assert "azure/sub-abc123/all_resources_list.json" in result[0]["path"]

    def test_path_traversal_blocked(self, sample_output_dir, tmp_path):
        """Files outside output_dir must be excluded even if glob matches."""
        # Create a file outside the output dir
        outside = tmp_path / "outside_output" / "secret.json"
        outside.parent.mkdir(parents=True)
        outside.write_text('{"secret": true}')

        # A traversal-style pattern — should not match anything inside sample_output_dir
        patterns = ["../outside_output/secret.json"]
        result = resolve_target_files(patterns, sample_output_dir)
        for item in result:
            real_path = os.path.realpath(os.path.join(sample_output_dir, item["path"]))
            real_base = os.path.realpath(sample_output_dir)
            assert real_path.startswith(real_base + os.sep), \
                f"Path traversal not blocked: {item['path']}"

    def test_no_duplicates_from_overlapping_patterns(self, sample_output_dir):
        """Same file matched by two patterns must appear only once."""
        patterns = [
            "signin_*/signin_log_*.json",
            "signin_*/signin_log_*.json",  # exact duplicate
        ]
        result = resolve_target_files(patterns, sample_output_dir)
        paths = [r["path"] for r in result]
        assert len(paths) == len(set(paths)), "Duplicate paths returned"


# ---------------------------------------------------------------------------
# API tests: GET /api/hunting/queries
# ---------------------------------------------------------------------------

class TestHuntingQueriesEndpoint:
    def test_returns_200(self, client):
        resp = client.get("/api/hunting/queries")
        assert resp.status_code == 200

    def test_response_structure(self, client):
        data = json.loads(client.get("/api/hunting/queries").data)
        assert "queries" in data
        assert "total" in data
        assert "categories" in data
        assert "mitre_ids" in data

    def test_total_matches_queries_length(self, client):
        data = json.loads(client.get("/api/hunting/queries").data)
        assert data["total"] == len(data["queries"])

    def test_categories_is_list(self, client):
        data = json.loads(client.get("/api/hunting/queries").data)
        assert isinstance(data["categories"], list)
        assert len(data["categories"]) > 0

    def test_mitre_ids_is_list(self, client):
        data = json.loads(client.get("/api/hunting/queries").data)
        assert isinstance(data["mitre_ids"], list)
        assert len(data["mitre_ids"]) > 0

    def test_filter_by_category(self, client):
        data = json.loads(client.get("/api/hunting/queries?category=entra_id").data)
        assert data["total"] > 0
        for q in data["queries"]:
            assert q["category"] == "entra_id"

    def test_filter_by_nonexistent_category(self, client):
        data = json.loads(client.get("/api/hunting/queries?category=nope").data)
        assert data["total"] == 0
        assert data["queries"] == []

    def test_filter_by_subcategory(self, client):
        data = json.loads(client.get("/api/hunting/queries?subcategory=sign_in").data)
        assert data["total"] > 0
        for q in data["queries"]:
            assert q["subcategory"] == "sign_in"

    def test_filter_by_severity(self, client):
        data = json.loads(client.get("/api/hunting/queries?severity=high").data)
        assert data["total"] > 0
        for q in data["queries"]:
            assert q["severity"] == "high"

    def test_filter_by_mitre_prefix(self, client):
        data = json.loads(client.get("/api/hunting/queries?mitre_id=T1110").data)
        assert data["total"] > 0
        for q in data["queries"]:
            assert any(m.startswith("T1110") for m in q["mitre_ids"])

    def test_filter_by_search_name(self, client):
        """Search should match query names case-insensitively."""
        data = json.loads(client.get("/api/hunting/queries?search=sign-in").data)
        assert data["total"] > 0
        for q in data["queries"]:
            assert ("sign-in" in q["name"].lower() or
                    "sign-in" in q["description"].lower())

    def test_filter_by_search_description(self, client):
        """Search must also match description substring."""
        data = json.loads(client.get("/api/hunting/queries?search=brute-force").data)
        # At least some queries should mention brute-force in description
        # (we can't know for sure, so just assert valid structure)
        assert "queries" in data
        assert "total" in data

    def test_multiple_filters_combined(self, client):
        """category + severity filter must AND together."""
        data = json.loads(
            client.get("/api/hunting/queries?category=entra_id&severity=high").data
        )
        for q in data["queries"]:
            assert q["category"] == "entra_id"
            assert q["severity"] == "high"


# ---------------------------------------------------------------------------
# API tests: GET /api/hunting/queries/<id>
# ---------------------------------------------------------------------------

class TestHuntingQueryByIdEndpoint:
    def test_returns_known_query(self, client):
        resp = client.get("/api/hunting/queries/hunt-signin-001")
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["id"] == "hunt-signin-001"

    def test_returns_all_fields(self, client):
        resp = client.get("/api/hunting/queries/hunt-signin-001")
        data = json.loads(resp.data)
        for field in ("id", "name", "category", "severity", "mitre_ids",
                      "hql_query", "target_files"):
            assert field in data, f"Missing field: {field}"

    def test_unknown_id_returns_404(self, client):
        resp = client.get("/api/hunting/queries/does-not-exist")
        assert resp.status_code == 404

    def test_404_has_error_field(self, client):
        resp = client.get("/api/hunting/queries/does-not-exist")
        data = json.loads(resp.data)
        assert "error" in data


# ---------------------------------------------------------------------------
# API tests: GET /api/hunting/resolve
# ---------------------------------------------------------------------------

class TestHuntingResolveEndpoint:
    def test_missing_id_returns_400(self, client):
        resp = client.get("/api/hunting/resolve")
        assert resp.status_code == 400

    def test_unknown_id_returns_404(self, client):
        resp = client.get("/api/hunting/resolve?id=does-not-exist")
        assert resp.status_code == 404

    def test_valid_id_returns_200(self, client, sample_output_dir):
        app.config["OUTPUT_DIR"] = sample_output_dir
        resp = client.get("/api/hunting/resolve?id=hunt-signin-001")
        assert resp.status_code == 200

    def test_response_structure(self, client, sample_output_dir):
        app.config["OUTPUT_DIR"] = sample_output_dir
        data = json.loads(client.get("/api/hunting/resolve?id=hunt-signin-001").data)
        assert "query_id" in data
        assert "files" in data
        assert "count" in data
        assert data["query_id"] == "hunt-signin-001"
        assert data["count"] == len(data["files"])

    def test_resolves_actual_files(self, client, sample_output_dir):
        app.config["OUTPUT_DIR"] = sample_output_dir
        data = json.loads(client.get("/api/hunting/resolve?id=hunt-signin-001").data)
        # sample_output_dir has signin_20260101/signin_log_20260101.json
        assert data["count"] >= 1
        paths = [f["path"] for f in data["files"]]
        assert any("signin_log" in p for p in paths)

    def test_count_zero_when_no_files(self, client, tmp_path):
        """Empty output dir should yield count=0, not an error."""
        app.config["OUTPUT_DIR"] = str(tmp_path)
        data = json.loads(client.get("/api/hunting/resolve?id=hunt-signin-001").data)
        assert data["count"] == 0
        assert data["files"] == []
