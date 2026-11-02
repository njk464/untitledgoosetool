"""The Hql import hook makes PyPI pyhql 0.0.9 importable before Python 3.14.

pyhql 0.0.9 evaluates forward-referencing annotations at class-body time
(Hql/Data/Schema.py `def join(...) -> Schema:`), so a stock `import Hql` raises
NameError on Python 3.9-3.13.  goosey.hql_compat installs a finder that compiles
Hql.* with `from __future__ import annotations`.  A hand-patched site-packages
(like the shared dev venv) hides the bug, so the NameError assertion is skipped
there; the subprocess test still proves the hook is what loads Hql.

@decision DEC-HQL-014
@title Prove the import hook in a fresh interpreter
@status accepted
@rationale In-process, Hql may already be imported; a clean subprocess is the
  only faithful reproduction of "first import of Hql after installing goosey".
"""

import importlib.util
import os
import subprocess
import sys
import textwrap

import pytest

pytest.importorskip("goosey.hql_compat")
pytest.importorskip("Hql")

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _schema_source_path():
    spec = importlib.util.find_spec("Hql")
    return os.path.join(list(spec.submodule_search_locations)[0], "Data", "Schema.py")


def test_unflagged_compile_fails_but_hooked_import_works():
    src_path = _schema_source_path()
    with open(src_path, encoding="utf-8") as fh:
        src = fh.read()
    if "from __future__ import annotations" in src or sys.version_info >= (3, 14):
        pytest.skip("Hql sources already patched or Python >= 3.14 (lazy annotations)")
    code = compile(src, src_path, "exec", dont_inherit=True)
    with pytest.raises(NameError):
        exec(code, {"__name__": "Hql.Data._probe"})
    import Hql.Data.Schema  # noqa: F401  (loaded by the hook)


def test_fresh_interpreter_imports_hql_via_hook():
    script = textwrap.dedent("""
        import sys
        import goosey.hql_compat as hc
        import Hql.Data.Schema
        loader = sys.modules['Hql.Data.Schema'].__spec__.loader
        assert type(loader).__name__ == '_AnnotationsFutureLoader', type(loader)
        assert sys.meta_path[0] is hc._HqlFutureAnnotationsFinder
        hc.install_hql_import_hook()
        assert sum(f is hc._HqlFutureAnnotationsFinder for f in sys.meta_path) == 1
        print('OK')
    """)
    env = dict(os.environ, PYTHONPATH=_ROOT)
    res = subprocess.run([sys.executable, "-c", script], env=env, cwd=_ROOT,
                         capture_output=True, text=True, timeout=120)
    assert res.returncode == 0, res.stderr[-2000:]
    assert "OK" in res.stdout


def test_stale_bytecode_is_not_used(tmp_path):
    """Loader must compile from source even when an unflagged .pyc is cached."""
    import goosey.hql_compat as hc
    pkg = tmp_path / "Hql_probe"
    pkg.mkdir()
    mod = pkg / "m.py"
    mod.write_text("def f() -> Later:\n    return 1\n\nclass Later: ...\n")
    loader = hc._AnnotationsFutureLoader("m", str(mod))
    ns = {}
    exec(loader.get_code("m"), ns)   # would NameError without the future flag
    assert ns["f"]() == 1
