"""KQL string-literal semantics on Hql main (DEC-HQL-018).

Hql main parses "a\\b" / "tab\there" correctly (Python escape rules) but StringLiteral.str() hands
the evaluator a unicode_escape'd copy, so any literal with a backslash or control character
compared against the escaped text and matched nothing.  The sentinel class runs the UNPATCHED
engine in a clean interpreter and fails once upstream fixes it (then delete the patch).
"""

import json
import os
import subprocess
import sys

import pytest

pytest.importorskip("goosey.hql_compat")
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "fixtures"))
import synthetic_logs as syn  # noqa: E402

from goosey.hql_compat import run_hql_query  # noqa: E402

VALUES = [
    "a\\b",                                    # one backslash between a and b
    'say "hi"',
    "it's",
    "tab\there",
    "line1\nline2",
    r"NT SERVICE\SExchangeServiceHostNetCore",
    r'C:\Windows\System32\cmd.exe /c "echo hi"',
    'C:\\dir\\',                              # trailing backslash
    'back\\slash "and" it\'s',                # backslash plus both quote kinds
    "plain",
]


def kql(v):
    """Double-quoted KQL literal for value v (what the web UI generates)."""
    return ('"' + v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
            .replace("\r", "\\r").replace("\t", "\\t") + '"')


@pytest.fixture
def esc(tmp_path):
    syn.write_ndjson(str(tmp_path / "e.json"), [{"id": i, "V": v} for i, v in enumerate(VALUES)])
    return str(tmp_path)


def ids(esc, text):
    return [x["id"] for x in run_hql_query(text, esc, "e.json")["rows"]]


@pytest.mark.parametrize("i", range(9))
def test_equality_and_inequality(esc, i):
    assert ids(esc, f"where V == {kql(VALUES[i])}") == [i]
    neq = ids(esc, f"where V != {kql(VALUES[i])}")
    assert i not in neq and len(neq) == len(VALUES) - 1


@pytest.mark.parametrize("i", range(9))
def test_string_operators(esc, i):
    v = kql(VALUES[i])
    assert i in ids(esc, f"where V contains {v}")
    assert i in ids(esc, f"where V startswith {v}")
    assert i in ids(esc, f"where V endswith {v}")
    assert i in ids(esc, f"where V =~ {v}")
    assert ids(esc, f'where V in ({v}, "zzz")') == [i]


def test_real_newline_matches_escaped_n_literal(esc):
    assert ids(esc, 'where V == "line1\\nline2"') == [4]
    assert ids(esc, 'where V contains "1\\nline"') == [4]


def test_verbatim_trailing_backslash_and_mixed_quotes(esc):
    assert ids(esc, 'where V == @"C:\\dir\\"') == [7]
    assert ids(esc, "where V == @'C:\\dir\\'") == [7]
    assert ids(esc, 'where V == "back\\\\slash \\"and\\" it\'s"') == [8]
    assert ids(esc, "where V == 'back\\\\slash \"and\" it\\'s'") == [8]


def test_has_with_escaped_term(esc):
    assert 5 in ids(esc, 'where V has "NT SERVICE"')
    assert ids(esc, f"where V has {kql(VALUES[0])}") == [0]


def test_single_quoted_literals(esc):
    assert ids(esc, r"where V == 'it\'s'") == [2]
    assert ids(esc, r"where V == 'a\\b'") == [0]


def test_verbatim_literals(esc):
    assert ids(esc, r'where V == @"a\b"') == [0]
    assert ids(esc, 'where V == @"say ""hi"""') == [1]
    assert ids(esc, "where V == @'it''s'") == [2]
    assert ids(esc, r'where V == @"NT SERVICE\SExchangeServiceHostNetCore"') == [5]


SCRIPT = r'''
import json, sys
from Hql import run_query
from Hql.Config import Config
conf = Config()
conf.conf['databases']['g'] = {'name': 'g', 'type': 'JSON', 'conf': {'local-base': sys.argv[1]},
                                'macro': {}, 'mappings': {}}
def n(text):
    try:
        res = run_query('database("g").file("e.json") | ' + text, conf)
        return next(iter(res.tables.values())).df.height
    except Exception as e:
        return 'ERR ' + type(e).__name__
print('RESULT' + json.dumps({
    'backslash': n(r'where V == "a\\b"'),
    'tab': n(r'where V == "tab\there"'),
    'verbatim_backslash': n(r'where V == @"a\b"'),
    'doubled_quote': n('where V == @"say ""hi"""'),
}))
'''


class TestStockHqlGap:
    @pytest.fixture(scope="class")
    @classmethod
    def raw(cls, tmp_path_factory):
        base = tmp_path_factory.mktemp("lit")
        syn.write_ndjson(str(base / "e.json"), [{"id": i, "V": v} for i, v in enumerate(VALUES)])
        script = base.parent / "lit_sentinel.py"
        script.write_text(SCRIPT)
        proc = subprocess.run([sys.executable, "-I", str(script), str(base)],
                              capture_output=True, text=True, timeout=120)
        line = [x for x in proc.stdout.splitlines() if x.startswith("RESULT")]
        assert line, proc.stdout + proc.stderr
        return json.loads(line[0][len("RESULT"):])

    def test_escaped_backslash_not_matched(self, raw):
        assert raw["backslash"] != 1

    def test_escaped_tab_not_matched(self, raw):
        assert raw["tab"] != 1

    def test_verbatim_backslash_works_stock(self, raw):
        assert raw["verbatim_backslash"] == 1   # control: proves the harness itself is sound

    def test_verbatim_doubled_quote_not_collapsed(self, raw):
        assert raw["doubled_quote"] != 1
