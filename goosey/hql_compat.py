#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Goosey HQL Compatibility Layer

Provides a clean interface for running HQL (Hunting Query Language) queries
against collected Goosey output data, on top of upstream Hql ``main``
(github.com/Hashfastr/Hql, pinned by commit in requirements.txt; free-threaded
Python 3.14 only).

Upstream ``main`` fixed most of what the old pyhql 0.0.9 layer worked around
(NDJSON seek, summarize/count, Table init on overflowing ints and mixed types,
mv-expand, the ``from __future__`` import-time crash, the Sigma misroute of
queries containing ": ").  What remains are five small gaps that goosey data
still hits; each has a sentinel test in tests/test_hql_compat.py that runs the
UNPATCHED engine and fails once upstream fixes the gap, telling us to delete
the patch.

Retained patches (applied at import time):
1. JSON database file resolution (``JSON.eval``): upstream globs a relative path
   against the *parent* of ``local-base/<path>``, so any file below a
   subdirectory (every goosey artifact) matches nothing and returns 0 rows.
   The patch globs ``local-base/<path>`` and refuses paths that resolve outside
   local-base.
1b. Multi-file queries are combined into one table (DEC-HQL-017).
2. JSON loader (``JSON.load_data``): a single-object file (e.g.
   ``_collection_status.json``, EXO_TransportConfig) becomes one row instead of
   crashing, and dotted names referenced as ``['a.b']`` are materialised as
   top-level columns (DEC-HQL-008).
3. ``dcount()`` aggregate (missing upstream; used by KQL-habit queries).
4. Numeric/string tolerant ``==`` / ``!=`` (DEC-HQL-009).
6. String literals are evaluated by value; verbatim doubled quotes (DEC-HQL-018).
5. Silence the harmless root-logger warning upstream emits for every non-Sigma
   query ("Invalid sigma supplied to parser").

@decision DEC-HQL-001
@title Patch the JSON loader (single-object files, dotted-name columns)
@status accepted
@rationale Originally a seek(0) fix for NDJSON; upstream main fixed that, so the
  loader patch now only wraps single JSON objects into a one-row list and
  materialises referenced dotted names (DEC-HQL-008).  Patched on the class at
  import so every subsequent query benefits.

@decision DEC-HQL-002
@title Build HQL Config programmatically, not from YAML files
@status accepted
@rationale pyhql expects a YAML config file on disk by default.  Requiring
  analysts to create a YAML file before querying would be a friction point.
  We construct the Config object in Python, injecting a single 'goose'
  database whose local-base points to the output directory.  This means zero
  setup for the analyst and no files on disk.

@decision DEC-HQL-003
@title Cache Config per output_dir; invalidate on directory change
@status accepted
@rationale Config construction is cheap but creates a new object each time.
  A module-level dict keyed on the resolved output directory avoids redundant
  construction across multiple queries in a session while still respecting
  changes to the output directory (e.g. the analyst switches to a different
  collection).

@decision DEC-HQL-008
@title Materialise bracketed dotted names (['status.errorCode']) as columns at load time
@status accepted
@rationale Analysts write nested Graph fields as ['status.errorCode'].  Hql
  treats that bracket form as ONE column name, so against real Graph JSON
  (where `status` is a struct) it finds no such column.  Hql's own unbracketed
  path form (status.errorCode) works for projection but wraps results in
  structs, which breaks comparisons on e.g. booleans.  run_hql_query() extracts
  the dotted names the query references and the patched loader adds exactly
  those as extra top-level columns (the struct is left untouched).  A record
  that already has a literal flat key of that name is left alone.

@decision DEC-HQL-009
@title Numeric/string tolerant == and != in HQL
@status accepted
@rationale Graph JSON carries status.errorCode as an integer while analysts
  used to KQL's loose typing write == "0".  With stock Hql the string-vs-int
  comparison silently matches nothing.  A numeric-string literal compares as
  strings (so int and string columns both work); an integer literal compares
  as Float64 (so int, float and numeric-string columns work).  Everything else
  keeps stock behaviour.

@decision DEC-HQL-015
@title Drop the 0.0.9-era patches when moving to Hql main on Python 3.14t
@status accepted
@rationale The `__future__` annotations import hook, the resilient Table init
  and schema-from-df fallbacks, the MvExpand fix, the NDJSON seek fix and the
  old Equality/dcount shapes were verified unnecessary (or obsolete in API) on
  Hql main.  Retained patches are guarded by sentinel tests (see module doc).

@decision DEC-HQL-017
@title Combine multi-file queries into ONE table (diagonal concat)
@status accepted
@rationale `.file("A", "B")` / wildcards load one Hql table per file.  Hql then runs each
  operator per table, so `summarize ... by Col` raises "Failed to unnest value" for every
  file lacking Col, and run_hql_query only ever showed the first table (rows of the other
  files vanished).  Concatenating the loaded rows into a single table (absent keys read as
  null) makes mixed-schema queries behave like one KQL table.  Found by the live sourcetype
  sweep: AlertEvidence + AlertInfo.

@decision DEC-HQL-018
@title Evaluate string literals by value; honour verbatim doubled quotes
@status accepted
@rationale Hql main parses "a\\\\b" / "tab\\there" correctly (Python escape rules) but
  StringLiteral.str() hands the evaluator a unicode_escape'd copy, so any literal containing a
  backslash or control character compared against the escaped text and matched nothing (==,
  contains, has, startswith, in, ... all go through it).  str() now returns the real value.
  KQL verbatim literals escape the quote by doubling it (at-sign, quote, say, two quotes, hi, ...); the parser only
  handled backslash-quote, so the parse result is corrected after the fact.

@decision DEC-HQL-016
@title Serialise queries and keep per-query state in a module global, not thread-local
@status accepted
@rationale On free-threaded Python Hql evaluates instructions in worker threads
  (Hql.Threading.InstructionPool), so a threading.local set by the caller
  thread is invisible to the loader.  run_hql_query() holds a lock for the whole
  query and publishes the dotted-name set in a module global.  Polars still
  parallelises inside a query; only concurrent *queries* are serialised.
"""

import glob
import importlib
import json
import logging
import math
import os
import re
import threading
from pathlib import Path

# ---------------------------------------------------------------------------
# Per-query state (DEC-HQL-016)
# ---------------------------------------------------------------------------
_query_lock = threading.RLock()
_active_dotted = None  # set of dotted names for the query currently running

_BRACKET_DOTTED_RE = re.compile(r"""\[\s*(['"])([^'"\]]+?)\1\s*\]""")


def _extract_dotted_paths(query_text):
    """Return the set of dotted names referenced as ['a.b'] in *query_text*."""
    found = set()
    for m in _BRACKET_DOTTED_RE.finditer(query_text or ''):
        name = m.group(2)
        if '.' in name and all(part for part in name.split('.')):
            found.add(name)
    return found


def _materialise_dotted(rows, paths):
    """Add flat dotted-name keys to each dict row for every path in *paths*."""
    if not paths or not isinstance(rows, list):
        return rows
    split = [(p, p.split('.')) for p in paths]
    for row in rows:
        if not isinstance(row, dict):
            continue
        for name, parts in split:
            if name in row:
                continue
            cur = row
            for part in parts:
                if isinstance(cur, dict) and part in cur:
                    cur = cur[part]
                else:
                    break
            else:
                row[name] = cur
    return rows


# ---------------------------------------------------------------------------
# Silence the harmless Sigma-attempt warning (patch 5)
# ---------------------------------------------------------------------------
class _DropSigmaNoise(logging.Filter):
    """Drop upstream's "Invalid sigma supplied to parser" warning (root logger)."""

    def filter(self, record):
        return 'Invalid sigma supplied' not in record.getMessage()


logging.getLogger().addFilter(_DropSigmaNoise())

# ---------------------------------------------------------------------------
# Patches against Hql main (see module docstring for the rationale of each)
# ---------------------------------------------------------------------------
try:
    import polars as pl
    _json_db_mod = importlib.import_module('Hql.Database.JSON')
    _hqle = importlib.import_module('Hql.Exceptions').HqlExceptions
    _data_mod = importlib.import_module('Hql.Data')
    _Table, _Data = _data_mod.Table, _data_mod.Data
    _ctx_mod = importlib.import_module('Hql.Context')
    _count_mod = importlib.import_module('Hql.Functions.count')
    _Function = importlib.import_module('Hql.Functions').Function
    _hqlt = importlib.import_module('Hql.Types.Hql').HqlTypes
    _Equality = importlib.import_module('Hql.Expressions.Logic').Equality
    _lit_mod = importlib.import_module('Hql.Expressions.Literals')
    _BaseExpressions = importlib.import_module('Hql.Parser.BaseExpressions').BaseExpressions
except ImportError:  # pyhql not installed; the error surfaces at query time
    _json_db_mod = None

if _json_db_mod is not None:
    _JSON = _json_db_mod.JSON
    _orig_eval = _JSON.eval

    def _patched_load_data(self, f, name):
        """Load JSON/NDJSON; wrap single objects; materialise dotted names (patch 2)."""
        import ndjson
        try:
            data = json.loads(f.read())
        except Exception:
            try:
                f.seek(0)
                data = [x for x in ndjson.reader(f)]
            except Exception:
                f.close()
                raise _hqle.QueryException('JSON database not given valid json data')
        f.close()
        if isinstance(data, dict):
            data = [data]
        limit = self.get_limit(name)
        if limit is not None:
            data = data[:limit]
        return _materialise_dotted(data, _active_dotted)

    def _patched_eval(self, ctx):
        """Resolve file specs against local-base (patch 1), confined to local-base."""
        if not self.files and not self.urls:
            return _orig_eval(self, ctx)  # raises upstream's "no file provided"
        base = os.path.realpath(self.local_base)
        paths = []
        for spec in self.files:
            for match in sorted(glob.glob(os.path.join(base, spec))):
                real = os.path.realpath(match)
                if real != base and not real.startswith(base + os.sep):
                    raise _hqle.QueryException(
                        f'Refusing to read outside the data directory: {spec}')
                paths.append(Path(real))
        loaded = []  # (name, rows) per source file / URL
        for path in paths:
            files = [path] if path.is_file() else sorted(x for x in path.iterdir() if x.is_file())
            for f in files:
                with open(f) as fh:
                    loaded.append((f.name, self.load_data(fh, f.name)))
        for url in self.urls:
            loaded.append((url, self.load_data(self.from_url(url), url)))
        # One result table for the whole file set (DEC-HQL-017): rows are concatenated and
        # missing keys become nulls, so files with different schemas behave like one table.
        if len(loaded) > 1:
            rows = [r for _, part in loaded for r in part]
            tables = [_Table(init_data=rows, name=loaded[0][0])] if rows else []
        else:
            tables = [_Table(init_data=part, name=name) for name, part in loaded]
        ctx.data = _Data(tables=tables)
        return ctx

    _JSON.load_data = _patched_load_data
    _JSON.eval = _patched_eval

    @_ctx_mod.register_func('dcount')
    class _DCount(_count_mod.count):
        """dcount(x): distinct non-null count per summarize group, modelled on count() (patch 3)."""

        def __init__(self, args, name='dcount_', conf=None):
            _Function.__init__(self, args, 1, 1)
            self.count_name = name
            self.count_type = _hqlt.uint()

        def eval(self, ctx, receiver=None):
            tables = []
            for table in ctx.data:
                if not table.agg:
                    tables.append(table)
                    continue
                cname = self.get_count_name(table.agg)
                col = self.args[0].polars().drop_nulls().n_unique().alias(cname.str())
                df = table.agg.agg(col)
                schema = table.agg_schema.copy().set(cname, self.count_type)
                tables.append(_Table(df=df, schema=schema, name=table.name)
                              .drop_many(table.agg_paths))
            return _Data(tables=tables)

    _num_re = re.compile(r'^-?\d+(\.\d+)?$')
    _orig_equality_polars = _Equality.polars

    def _patched_equality_polars(self):
        """== / != tolerant of number-vs-string literals (patch 4)."""
        reduced = self.reduce()
        if not isinstance(reduced, _Equality) or len(reduced.rh) != 1:
            return _orig_equality_polars(self)
        try:
            value = pl.select(reduced.rh[0].polars()).item()
        except Exception:
            return _orig_equality_polars(self)
        lh = reduced.lh.polars()
        if isinstance(value, str) and _num_re.match(value):
            new = lh.cast(pl.String, strict=False) == value
        elif isinstance(value, int) and not isinstance(value, bool):
            new = lh.cast(pl.Float64, strict=False) == float(value)
        else:
            return _orig_equality_polars(self)
        return ~new if reduced.neq else new

    _Equality.polars = _patched_equality_polars

    # Patch 6 (DEC-HQL-018): string literals reach the evaluator with their VALUE, not a
    # re-escaped copy, and verbatim literals honour the doubled-quote escape.
    _StringLiteral, _MultiString = _lit_mod.StringLiteral, _lit_mod.MultiString

    def _literal_value(self):
        """The literal's actual text (Hql main returns a unicode_escape'd copy, so "a\\\\b" never matched)."""
        return self.value.decode('utf-8')

    _StringLiteral.str = _literal_value

    _orig_visit_string = _BaseExpressions.visitStringLiteralExpression

    def _patched_visit_string(self, ctx):
        result = _orig_visit_string(self, ctx)
        parts = result.strlits if isinstance(result, _MultiString) else [result]
        changed = False
        for lit, tok in zip(parts, ctx.Tokens):
            text = tok.text[1:] if tok.text[:1] in ('h', 'H') else tok.text
            if text[:1] == '@' and len(text) > 1 and text[1] in ('"', "'"):
                q = text[1]
                fixed = lit.value.replace((q * 2).encode(), q.encode())
                if fixed != lit.value:
                    lit.value, changed = fixed, True
        if changed and isinstance(result, _MultiString):
            result.value = result.str().encode('utf-8')
        return result

    _BaseExpressions.visitStringLiteralExpression = _patched_visit_string


# ---------------------------------------------------------------------------
# Config cache
# ---------------------------------------------------------------------------
_config_cache: dict = {}   # output_dir -> Hql.Config.Config instance


def _get_hql_config(output_dir: str):
    """Return a cached HQL Config for the given output directory.

    Args:
        output_dir: Absolute path to the goose output directory.

    Returns:
        Hql.Config.Config instance with a 'goose' database pointing at output_dir.
    """
    resolved = os.path.realpath(output_dir)
    if resolved in _config_cache:
        return _config_cache[resolved]

    from Hql.Config import Config
    conf = Config()
    conf.conf['databases']['goose'] = {
        'name': 'goose',
        'type': 'JSON',
        'conf': {'local-base': resolved},
        'macro': {},
        'mappings': {},
    }
    _config_cache[resolved] = conf
    return conf


_FILE_REF_RE = re.compile(r"""\.file\(\s*(['"])(.+?)\1\s*\)""")


def _target_file_is_empty(full_query, output_dir, file_path):
    """Return True when the query's target file exists and has no content."""
    rel = file_path
    if not rel:
        m = _FILE_REF_RE.search(full_query)
        rel = m.group(2) if m else None
    if not rel:
        return False
    base = os.path.realpath(output_dir)
    abs_path = os.path.realpath(os.path.join(base, rel))
    if not abs_path.startswith(base + os.sep) or not os.path.isfile(abs_path):
        return False
    size = os.path.getsize(abs_path)
    if size == 0:
        return True
    if size <= 64:
        with open(abs_path, 'rb') as fh:
            return not fh.read().strip()
    return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_hql_query(
    query_text: str,
    output_dir: str,
    file_path: str = None,
    page: int = 1,
    page_size: int = 100,
    max_file_size_mb: int = 1024,
) -> dict:
    """Execute an HQL query against collected Goosey data.

    Args:
        query_text: HQL query string.  If it does not start with
            ``database(`` the ``file_path`` must be provided and the
            ``database("goose").file("<file_path>")`` prefix is prepended
            automatically.
        output_dir: Absolute path to the goose output directory
            (becomes the ``local-base`` for the 'goose' database).
        file_path: Relative path to the target file within output_dir.
            Required when query_text does not already contain a database()
            prefix.  Used only for the file-size guardrail when the query
            already has a full prefix.
        page: 1-based page number for result pagination (default 1).
        page_size: Rows per page; capped at 1000 (default 100).
        max_file_size_mb: Reject files larger than this limit in megabytes
            (default 200 MB).  Set to 0 to disable the check.

    Returns:
        dict with keys:
            columns  (list[str])  — column names in result order
            rows     (list[dict]) — page of result rows
            total    (int)        — total number of matching rows
            page     (int)        — current page number (1-based)
            pages    (int)        — total number of pages
            query    (str)        — full HQL query that was executed

    Raises:
        ValueError: For user-recoverable errors (file not found, too large,
            invalid query, etc.).
        ImportError: If pyhql is not installed.
    """
    page_size = min(max(1, int(page_size)), 1000)
    page = max(1, int(page))

    # ------------------------------------------------------------------
    # Build the full query string
    # ------------------------------------------------------------------
    query_text = (query_text or '').strip()
    if not query_text:
        raise ValueError('Query text is empty.')

    if not query_text.lstrip().startswith('database('):
        # Auto-prepend the database/file prefix
        if not file_path:
            raise ValueError(
                'Either provide a full database() query or supply file_path '
                'so the prefix can be auto-prepended.'
            )
        # Normalise path separators so HQL receives forward slashes
        norm_path = file_path.replace(os.sep, '/')
        full_query = f'database("goose").file("{norm_path}") | {query_text}'
    else:
        full_query = query_text

    # ------------------------------------------------------------------
    # File-size guardrail
    # ------------------------------------------------------------------
    if max_file_size_mb > 0 and file_path:
        abs_path = os.path.join(output_dir, file_path)
        if os.path.isfile(abs_path):
            size_mb = os.path.getsize(abs_path) / (1024 * 1024)
            if size_mb > max_file_size_mb:
                raise ValueError(
                    f'File is {size_mb:.0f} MB which exceeds the {max_file_size_mb} MB '
                    f'query limit. Use a smaller file or increase max_file_size_mb.'
                )

    # ------------------------------------------------------------------
    # Execute
    # ------------------------------------------------------------------
    try:
        from Hql import run_query
    except ImportError as exc:
        raise ImportError(
            'pyhql is not installed. Install it with: pip install pyhql'
        ) from exc

    conf = _get_hql_config(output_dir)

    # Empty (0-byte) artifacts are a legitimate "table queried, zero rows"
    # result (e.g. a Log Analytics table with no events in the window).
    # pyhql cannot build a Table from zero rows, so answer directly.
    if _target_file_is_empty(full_query, output_dir, file_path):
        return {
            'columns': [],
            'rows': [],
            'total': 0,
            'page': page,
            'pages': 1,
            'query': full_query,
        }

    global _active_dotted
    with _query_lock:
        _active_dotted = _extract_dotted_paths(query_text)
        try:
            result = run_query(full_query, conf)
        except Exception as exc:
            # Convert HQL exceptions into user-friendly ValueError
            msg = str(exc)
            raise ValueError(f'HQL query error: {msg}') from exc
        finally:
            _active_dotted = None

    # ------------------------------------------------------------------
    # Extract results from the first table in result.tables (a dict)
    # ------------------------------------------------------------------
    if not result.tables:
        return {
            'columns': [],
            'rows': [],
            'total': 0,
            'page': page,
            'pages': 1,
            'query': full_query,
        }

    # Use the first table (queries return exactly one result table)
    first_table = next(iter(result.tables.values()))
    df = first_table.df
    columns = list(df.columns)
    total = len(df)

    # Pagination via Polars .slice()
    offset = (page - 1) * page_size
    page_df = df.slice(offset, page_size)
    try:
        rows = page_df.to_dicts()
    except TypeError:
        # Polars to_dicts() fails on Struct columns (nested JSON objects such
        # as UAL AuditData fields) with:
        #   PythonTypes.dict.__init__() missing 1 required positional argument: 'keys'
        # write_json() serialises all Polars types correctly, including Structs.
        rows = json.loads(page_df.write_json())

    # JSON-serialise any non-serialisable values (e.g. Polars Null types)
    safe_rows = []
    for row in rows:
        safe_row = {}
        for k, v in row.items():
            if v is None:
                safe_row[k] = None
            else:
                try:
                    json.dumps(v)
                    safe_row[k] = v
                except (TypeError, ValueError):
                    safe_row[k] = str(v)
        safe_rows.append(safe_row)

    pages = max(1, math.ceil(total / page_size))

    return {
        'columns': columns,
        'rows': safe_rows,
        'total': total,
        'page': page,
        'pages': pages,
        'query': full_query,
    }
