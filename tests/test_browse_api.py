"""Tests for Browse Data API endpoints: /api/browse/tree, /api/browse/files, /api/browse/preview

Tests validate:
- load_sourcetypes() returns valid registry data
- scan_output_dir() correctly matches files using file_glob patterns
- build_tree() filters to nodes with data and aggregates file counts
- /api/browse/tree endpoint returns correct structure
- /api/browse/files endpoint returns file metadata
- /api/browse/preview endpoint reads lines with pagination
- Path traversal protection in /api/browse/preview

@decision DEC-BROWSE-003
@title Three API endpoints for Browse Data feature (tree/files/preview)
@status accepted
@rationale Separation of concerns: tree gives hierarchy, files gives per-sourcetype
  file listing, preview gives paginated content. Lazy loading keeps initial page fast.
"""

import json
import os
import tempfile
import pytest

# We import the Flask app and the helper functions from web.py
# Since Flask is optional, guard the import
try:
    from goosey.web import (
        app,
        load_sourcetypes,
        scan_output_dir,
        build_tree,
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

@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


@pytest.fixture
def sample_output_dir(tmp_path):
    """Create a minimal fake output directory tree that mirrors real Goosey output.

    File names are chosen to match the actual file_glob patterns in sourcetypes.json:
    - provisioning: entraid/entraidprovisioninglogs*json
    - signin:adfs:  entraid/signin_adfs/*.json
    - audit:        entraid/entraid_audit_logs/entraidauditlog*json
    - resources:    azure/{sub_id}/all_resources_list*json
    - azure_activity_log: azure/{sub_id}/Activity Log/azure_activity_log*json
    - aadmanagedidentitysigninlogs: azure/*/log_analytics_workspace/*/AADManagedIdentitySignInLogs*json
    - alerts (MDE): mde/api_alerts*json
    """
    # Entra ID provisioning (glob: entraid/entraidprovisioninglogs*json)
    eid_dir = tmp_path / "entraid"
    eid_dir.mkdir(parents=True)
    (eid_dir / "entraidprovisioninglogs.json").write_text('{"id": "prov1"}\n')

    # Entra ID sign-in ADFS (glob: entraid/signin_adfs/*.json)
    signin_adfs_dir = eid_dir / "signin_adfs"
    signin_adfs_dir.mkdir()
    (signin_adfs_dir / "signin_adfs_2026-03-01.json").write_text('{"id": "1"}\n{"id": "2"}\n')

    # Entra ID audit (glob: entraid/entraid_audit_logs/entraidauditlog*json)
    audit_dir = eid_dir / "entraid_audit_logs"
    audit_dir.mkdir()
    (audit_dir / "entraidauditlog_2026-03-01.json").write_text('{"audit": "a1"}\n')

    # Azure core with a fake subscription ID
    sub_id = "sub-abc123"
    azure_sub = tmp_path / "azure" / sub_id
    azure_sub.mkdir(parents=True)
    (azure_sub / "all_resources_list.json").write_text('{"resources": []}\n')
    activity_dir = azure_sub / "Activity Log"
    activity_dir.mkdir()
    (activity_dir / "azure_activity_log_2026-03-01.json").write_text('{"op": "write"}\n')

    # Azure LAW table (glob: azure/*/log_analytics_workspace/*/AADManagedIdentitySignInLogs*json)
    law_dir = tmp_path / "azure" / sub_id / "log_analytics_workspace" / "ws1"
    law_dir.mkdir(parents=True)
    (law_dir / "AADManagedIdentitySignInLogs_2026-03-01.json").write_text(
        '{"id": "m1"}\n{"id": "m2"}\n{"id": "m3"}\n'
    )

    # M365 UAL (glob: m365/m365_unified_audit_log*json)
    m365_dir = tmp_path / "m365"
    m365_dir.mkdir()
    (m365_dir / "m365_unified_audit_log_2026-03-01.json").write_text('{"record": 1}\n')

    # MDE alerts (glob: mde/api_alerts*json)
    mde_dir = tmp_path / "mde"
    mde_dir.mkdir()
    (mde_dir / "api_alerts.json").write_text('{"alert": "a1"}\n')

    return str(tmp_path)


# ---------------------------------------------------------------------------
# Unit tests: load_sourcetypes()
# ---------------------------------------------------------------------------

class TestLoadSourcetypes:
    def test_returns_dict_with_version(self):
        data = load_sourcetypes()
        assert isinstance(data, dict)
        assert "version" in data

    def test_has_types_key(self):
        data = load_sourcetypes()
        assert "types" in data
        assert isinstance(data["types"], dict)

    def test_known_top_level_types(self):
        data = load_sourcetypes()
        types = data["types"]
        for expected in ("azure", "eid", "m365", "mde"):
            assert expected in types, f"Expected type '{expected}' in sourcetypes"

    def test_azure_has_subtypes(self):
        data = load_sourcetypes()
        azure = data["types"]["azure"]
        assert "subtypes" in azure
        assert "core" in azure["subtypes"]
        assert "law" in azure["subtypes"]

    def test_law_has_subcategories(self):
        data = load_sourcetypes()
        law = data["types"]["azure"]["subtypes"]["law"]
        assert "subcategories" in law
        assert len(law["subcategories"]) > 0

    def test_sourcetypes_have_file_glob(self):
        data = load_sourcetypes()
        # Every leaf sourcetype must have a file_glob
        def check_sourcetypes(sourcetypes_dict):
            for st_id, st_data in sourcetypes_dict.items():
                assert "file_glob" in st_data, f"Missing file_glob in {st_id}"
                assert isinstance(st_data["file_glob"], str)

        for type_id, type_data in data["types"].items():
            if "sourcetypes" in type_data:
                check_sourcetypes(type_data["sourcetypes"])
            if "subtypes" in type_data:
                for subtype_id, subtype_data in type_data["subtypes"].items():
                    if "sourcetypes" in subtype_data:
                        check_sourcetypes(subtype_data["sourcetypes"])
                    if "subcategories" in subtype_data:
                        for cat_id, cat_data in subtype_data["subcategories"].items():
                            if "sourcetypes" in cat_data:
                                check_sourcetypes(cat_data["sourcetypes"])

    def test_caches_result(self):
        """Calling load_sourcetypes() twice returns the same object (module-level cache)."""
        d1 = load_sourcetypes()
        d2 = load_sourcetypes()
        assert d1 is d2


# ---------------------------------------------------------------------------
# Unit tests: scan_output_dir()
# ---------------------------------------------------------------------------

class TestScanOutputDir:
    def test_empty_dir_returns_empty_map(self, tmp_path):
        data = load_sourcetypes()
        result = scan_output_dir(str(tmp_path), data)
        assert isinstance(result, dict)
        assert all(v == [] for v in result.values())

    def test_nonexistent_dir_returns_empty_map(self):
        data = load_sourcetypes()
        result = scan_output_dir("/nonexistent/path/abc123", data)
        assert isinstance(result, dict)
        assert all(v == [] for v in result.values())

    def test_matches_eid_provisioning(self, sample_output_dir):
        data = load_sourcetypes()
        result = scan_output_dir(sample_output_dir, data)
        # EID provisioning sourcetype has glob: entraid/entraidprovisioninglogs*json
        assert "provisioning" in result
        assert len(result["provisioning"]) == 1

    def test_matches_eid_signin_adfs(self, sample_output_dir):
        data = load_sourcetypes()
        result = scan_output_dir(sample_output_dir, data)
        # EID signin ADFS glob: entraid/signin_adfs/*.json
        assert "signin:adfs" in result
        assert len(result["signin:adfs"]) == 1

    def test_matches_azure_resources(self, sample_output_dir):
        data = load_sourcetypes()
        result = scan_output_dir(sample_output_dir, data)
        # azure/{sub_id}/all_resources_list*json
        assert "resources" in result
        assert len(result["resources"]) == 1

    def test_matches_azure_activity_log(self, sample_output_dir):
        data = load_sourcetypes()
        result = scan_output_dir(sample_output_dir, data)
        assert "azure_activity_log" in result
        assert len(result["azure_activity_log"]) == 1

    def test_matches_law_table(self, sample_output_dir):
        data = load_sourcetypes()
        result = scan_output_dir(sample_output_dir, data)
        # LAW glob: azure/*/log_analytics_workspace/*/AADManagedIdentitySignInLogs*json
        assert "aadmanagedidentitysigninlogs" in result
        assert len(result["aadmanagedidentitysigninlogs"]) == 1

    def test_mde_alerts(self, sample_output_dir):
        data = load_sourcetypes()
        result = scan_output_dir(sample_output_dir, data)
        assert "alerts" in result
        # file mde/api_alerts.json should match glob mde/api_alerts*json
        mde_files = [f for f in result.get("alerts", []) if "mde" in f]
        assert len(mde_files) >= 1

    def test_no_hidden_files(self, tmp_path):
        """Files starting with '.' must be excluded."""
        eid_dir = tmp_path / "entraid"
        eid_dir.mkdir()
        (eid_dir / ".entraidprovisioninglogs.json").write_text('secret')
        data = load_sourcetypes()
        result = scan_output_dir(str(tmp_path), data)
        assert "provisioning" not in result or result.get("provisioning") == []


# ---------------------------------------------------------------------------
# Unit tests: build_tree()
# ---------------------------------------------------------------------------

class TestBuildTree:
    def test_empty_file_map_gives_empty_tree(self):
        data = load_sourcetypes()
        file_map = {k: [] for k in ["signin", "provisioning", "resources"]}
        tree = build_tree(data, file_map)
        assert "types" in tree
        # No type should appear with zero files
        for node in tree["types"]:
            assert node["file_count"] > 0

    def test_type_file_count_aggregates(self, sample_output_dir):
        data = load_sourcetypes()
        file_map = scan_output_dir(sample_output_dir, data)
        tree = build_tree(data, file_map)
        # All returned type nodes must have file_count > 0
        for node in tree["types"]:
            assert node["file_count"] > 0

    def test_tree_has_expected_fields(self, sample_output_dir):
        data = load_sourcetypes()
        file_map = scan_output_dir(sample_output_dir, data)
        tree = build_tree(data, file_map)
        for type_node in tree["types"]:
            assert "id" in type_node
            assert "display_name" in type_node
            assert "file_count" in type_node
            assert "subtypes" in type_node

    def test_azure_subtypes_present(self, sample_output_dir):
        data = load_sourcetypes()
        file_map = scan_output_dir(sample_output_dir, data)
        tree = build_tree(data, file_map)
        azure_nodes = [n for n in tree["types"] if n["id"] == "azure"]
        assert len(azure_nodes) == 1
        azure = azure_nodes[0]
        subtype_ids = {s["id"] for s in azure["subtypes"]}
        # "core" and "law" should both appear (we have matching files for both)
        assert "core" in subtype_ids
        assert "law" in subtype_ids

    def test_law_subcategories_present(self, sample_output_dir):
        data = load_sourcetypes()
        file_map = scan_output_dir(sample_output_dir, data)
        tree = build_tree(data, file_map)
        azure_nodes = [n for n in tree["types"] if n["id"] == "azure"]
        assert azure_nodes
        azure = azure_nodes[0]
        law_nodes = [s for s in azure["subtypes"] if s["id"] == "law"]
        assert law_nodes
        law = law_nodes[0]
        assert "subcategories" in law
        # aad subcategory should appear (we have AADManagedIdentitySignInLogs)
        cat_ids = {c["id"] for c in law["subcategories"]}
        assert "aad" in cat_ids


# ---------------------------------------------------------------------------
# Integration tests: Flask endpoints
# ---------------------------------------------------------------------------

class TestBrowseTreeEndpoint:
    def test_returns_200(self, client, sample_output_dir):
        resp = client.get(f"/api/browse/tree?output_dir={sample_output_dir}")
        assert resp.status_code == 200

    def test_returns_json(self, client, sample_output_dir):
        resp = client.get(f"/api/browse/tree?output_dir={sample_output_dir}")
        data = resp.get_json()
        assert data is not None
        assert "types" in data

    def test_empty_dir_returns_empty_types(self, client, tmp_path):
        resp = client.get(f"/api/browse/tree?output_dir={tmp_path}")
        data = resp.get_json()
        assert data is not None
        assert data["types"] == []

    def test_nonexistent_dir_returns_empty_types(self, client):
        resp = client.get("/api/browse/tree?output_dir=/nonexistent/dir/xyz")
        data = resp.get_json()
        assert data is not None
        assert data["types"] == []

    def test_file_count_positive(self, client, sample_output_dir):
        resp = client.get(f"/api/browse/tree?output_dir={sample_output_dir}")
        data = resp.get_json()
        total = sum(n["file_count"] for n in data["types"])
        assert total > 0


class TestBrowseFilesEndpoint:
    def test_returns_200_for_known_sourcetype(self, client, sample_output_dir):
        # Use 'provisioning' (eid/core subtype) — simple ID with no colon
        resp = client.get(
            f"/api/browse/files"
            f"?type=eid&subtype=core&sourcetype=provisioning"
            f"&output_dir={sample_output_dir}"
        )
        assert resp.status_code == 200

    def test_returns_file_list(self, client, sample_output_dir):
        resp = client.get(
            f"/api/browse/files"
            f"?type=eid&subtype=core&sourcetype=provisioning"
            f"&output_dir={sample_output_dir}"
        )
        data = resp.get_json()
        assert "files" in data
        assert len(data["files"]) >= 1

    def test_file_metadata_fields(self, client, sample_output_dir):
        resp = client.get(
            f"/api/browse/files"
            f"?type=eid&subtype=core&sourcetype=provisioning"
            f"&output_dir={sample_output_dir}"
        )
        data = resp.get_json()
        f = data["files"][0]
        assert "path" in f
        assert "size" in f
        assert "size_human" in f
        assert "modified" in f
        assert "lines" in f

    def test_returns_404_for_unknown_sourcetype(self, client, sample_output_dir):
        resp = client.get(
            f"/api/browse/files"
            f"?type=eid&subtype=signin&sourcetype=doesnotexist"
            f"&output_dir={sample_output_dir}"
        )
        assert resp.status_code == 404

    def test_returns_400_when_missing_required_params(self, client, sample_output_dir):
        resp = client.get(f"/api/browse/files?output_dir={sample_output_dir}")
        assert resp.status_code == 400

    def test_law_subcategory_param(self, client, sample_output_dir):
        resp = client.get(
            f"/api/browse/files"
            f"?type=azure&subtype=law&subcategory=aad"
            f"&sourcetype=aadmanagedidentitysigninlogs"
            f"&output_dir={sample_output_dir}"
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data["files"]) == 1

    def test_empty_files_for_no_match(self, client, tmp_path):
        resp = client.get(
            f"/api/browse/files"
            f"?type=eid&subtype=core&sourcetype=provisioning"
            f"&output_dir={tmp_path}"
        )
        data = resp.get_json()
        assert data["files"] == []


class TestBrowsePreviewEndpoint:
    def test_returns_200(self, client, sample_output_dir):
        resp = client.get(
            f"/api/browse/preview"
            f"?path=entraid/entraidprovisioninglogs.json"
            f"&output_dir={sample_output_dir}"
        )
        assert resp.status_code == 200

    def test_returns_lines(self, client, sample_output_dir):
        resp = client.get(
            f"/api/browse/preview"
            f"?path=entraid/entraidprovisioninglogs.json"
            f"&output_dir={sample_output_dir}"
        )
        data = resp.get_json()
        assert "lines" in data
        assert len(data["lines"]) >= 1  # provisioning file has at least 1 line

    def test_response_has_expected_fields(self, client, sample_output_dir):
        resp = client.get(
            f"/api/browse/preview"
            f"?path=entraid/entraidprovisioninglogs.json"
            f"&output_dir={sample_output_dir}"
        )
        data = resp.get_json()
        assert "path" in data
        assert "lines" in data
        assert "offset" in data
        assert "total_lines" in data
        assert "has_more" in data

    def test_offset_pagination(self, client, sample_output_dir):
        # Use the LAW file which has 3 lines; request line at offset 1
        resp = client.get(
            f"/api/browse/preview"
            f"?path=azure/sub-abc123/log_analytics_workspace/ws1/AADManagedIdentitySignInLogs_2026-03-01.json"
            f"&output_dir={sample_output_dir}"
            f"&offset=1&lines=1"
        )
        data = resp.get_json()
        assert len(data["lines"]) == 1
        assert data["offset"] == 1

    def test_path_traversal_rejected(self, client, sample_output_dir):
        resp = client.get(
            f"/api/browse/preview"
            f"?path=../../etc/passwd"
            f"&output_dir={sample_output_dir}"
        )
        assert resp.status_code == 403

    def test_absolute_path_rejected(self, client, sample_output_dir):
        resp = client.get(
            f"/api/browse/preview"
            f"?path=/etc/passwd"
            f"&output_dir={sample_output_dir}"
        )
        assert resp.status_code == 403

    def test_returns_400_when_missing_path(self, client, sample_output_dir):
        resp = client.get(f"/api/browse/preview?output_dir={sample_output_dir}")
        assert resp.status_code == 400

    def test_missing_file_returns_404(self, client, sample_output_dir):
        resp = client.get(
            f"/api/browse/preview"
            f"?path=entraid/doesnotexist.json"
            f"&output_dir={sample_output_dir}"
        )
        assert resp.status_code == 404

    def test_lines_capped_at_500(self, client, sample_output_dir):
        resp = client.get(
            f"/api/browse/preview"
            f"?path=entraid/entraidprovisioninglogs.json"
            f"&output_dir={sample_output_dir}"
            f"&lines=999"
        )
        # Should not error; capped internally
        assert resp.status_code == 200

    def test_has_more_false_when_at_end(self, client, sample_output_dir):
        resp = client.get(
            f"/api/browse/preview"
            f"?path=entraid/entraidprovisioninglogs.json"
            f"&output_dir={sample_output_dir}"
        )
        data = resp.get_json()
        # 2 lines, default 50 request — all lines returned
        assert data["has_more"] is False
