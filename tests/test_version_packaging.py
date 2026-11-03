"""Version single-source-of-truth and packaging-manifest checks."""

import os
import re
import subprocess
import sys

import pytest

import goosey

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def test_setup_py_version_matches_package():
    pytest.importorskip("setuptools", reason="setup.py imports setuptools; pip install -r requirements-dev.txt")
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
    assert os.path.isfile(os.path.join(ROOT, "goosey", "templates", "index.html"))


def test_setup_py_requirements_parse_pep508_lines():
    """requirements.txt lines containing spaces (pkg @ url) must survive parsing."""
    src = open(os.path.join(ROOT, "setup.py"), encoding="utf-8").read()
    ns = {"re": re}
    start = src.index("def read_requirements")
    end = src.index("requirements = read_requirements")
    exec(src[start:end], ns)  # the function under test is self-contained
    reqs = ns["read_requirements"](os.path.join(ROOT, "requirements.txt"))
    pyhql = [r for r in reqs if r.startswith("pyhql")]
    assert len(pyhql) == 1
    assert re.fullmatch(r"pyhql @ git\+https://github\.com/Hashfastr/Hql@[0-9a-f]{40}", pyhql[0])
    assert all("#" not in r and not r.startswith("#") for r in reqs)
    assert not any(r.lower().startswith("zstandard") for r in reqs)


def test_setup_py_declares_python_314_free_threaded():
    src = open(os.path.join(ROOT, "setup.py"), encoding="utf-8").read()
    assert "python_requires='>=3.14'" in src
    assert "Py_GIL_DISABLED" in src


def test_suite_runs_on_free_threaded_python():
    import sysconfig
    assert sys.version_info >= (3, 14)
    assert sysconfig.get_config_var("Py_GIL_DISABLED"), "run the tests with python3.14t"
