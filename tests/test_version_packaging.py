"""Version single-source-of-truth and packaging-manifest checks."""

import os
import re
import subprocess
import sys

import goosey

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_setup_py_version_matches_package():
    out = subprocess.run([sys.executable, "setup.py", "--version"], cwd=ROOT,
                         capture_output=True, text=True, check=True).stdout.strip().splitlines()[-1]
    assert out == goosey.__version__


def test_version_is_semver():
    assert re.fullmatch(r"\d+\.\d+\.\d+", goosey.__version__)


def test_manifest_includes_templates_data_and_requirements():
    manifest = open(os.path.join(ROOT, "MANIFEST.in")).read()
    for needle in ("requirements.txt", "goosey/templates", "goosey/data"):
        assert needle in manifest


def test_shipped_data_files_exist():
    assert os.path.isfile(os.path.join(ROOT, "goosey", "data", "sourcetypes.json"))
    assert os.path.isfile(os.path.join(ROOT, "goosey", "data", "hunting_queries.json"))
    assert os.path.isfile(os.path.join(ROOT, "goosey", "templates", "index.html"))
