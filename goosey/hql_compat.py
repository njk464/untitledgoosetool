#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""Goosey HQL Compatibility Layer

Provides a clean interface for running HQL (Hunting Query Language) queries
against collected Goosey output data.

This module performs three important tasks at import time:
1. Monkey-patches a seek(0) bug in pyhql's NDJSON loader so that JSONL/NDJSON
   files are parsed correctly instead of returning 0 rows.
2. Suppresses the harmless "Invalid sigma supplied to parser" warning that
   pyhql emits on every import.
3. Caches the HQL Config object so it is built once per output directory.

@decision DEC-HQL-001
@title Monkey-patch pyhql NDJSON loader to fix seek(0) bug
@status accepted
@rationale pyhql's JSON database loader tries json.loads() first, then falls
  back to ndjson.reader() for NDJSON/JSONL files.  The fallback path never
  calls f.seek(0) after the failed json.loads(), so ndjson.reader() receives
  a file object whose position is at EOF and reads zero records.  The fix
  inserts a seek(0) before the ndjson.reader() call.  We patch the method
  on the class (not the instance) immediately on import so every subsequent
  query benefits automatically.

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
"""

import importlib
import json
import logging
import math
import os

# ---------------------------------------------------------------------------
# Silence the harmless sigma parser warning emitted by pyhql on import
# ---------------------------------------------------------------------------
logging.getLogger('Hql').setLevel(logging.ERROR)
logging.getLogger('sigma').setLevel(logging.ERROR)

# ---------------------------------------------------------------------------
# Monkey-patch: fix the NDJSON seek(0) bug in pyhql's JSON database loader
# ---------------------------------------------------------------------------
try:
    import ndjson as _ndjson_mod
    _json_db_mod = importlib.import_module('Hql.Operators.Database.JSON')

    def _patched_load_data(self, f, name):
        """Load data from a JSON or NDJSON/JSONL file.

        Tries standard JSON first; on failure, seeks back to the start of
        the file and reads as NDJSON (the seek(0) is the bug fix — pyhql
        omits it in the fallback path, causing empty results for JSONL files).
        """
        try:
            data = json.loads(f.read())
        except Exception:
            try:
                f.seek(0)  # THE FIX: reset file position before NDJSON read
                data = [x for x in _ndjson_mod.reader(f)]
            except Exception:
                f.close()
                from Hql.Exceptions import HqlExceptions as hqle
                raise hqle.QueryException('Could not load data from file')
        f.close()
        # Wrap single-object JSON files (e.g. EXO_TransportConfig) into a list
        # so pyhql's Schema/Table can iterate over rows, not dict keys.
        if isinstance(data, dict):
            data = [data]
        limit = self.get_limit(name)
        if limit is not None:
            data = data[:limit]
        return data

    _json_db_mod.JSON.load_data = _patched_load_data

    # ------------------------------------------------------------------
    # Monkey-patch: resilient Table.__init__ for overflow/type errors
    # ------------------------------------------------------------------
    # pyhql maps Python int→Polars Int32 and builds a strict schema.
    # Forensic data often has values exceeding Int32 or even Int64 (EXO
    # InboxRules identifiers can be >2^63).  Rather than patching every
    # type individually, we wrap Table.__init__ to catch ComputeError
    # from pl.from_dicts() and retry WITHOUT a schema, letting Polars
    # infer types natively (it uses Int64 by default and falls back to
    # Utf8 for overflow).  The Schema is then rebuilt from the DataFrame.
    #
    # @decision DEC-HQL-005
    # @title Resilient Table init with schemaless fallback
    # @status accepted
    # @rationale Forensic exports contain arbitrary integer sizes and
    #   heterogeneous types that defeat any fixed schema mapping.  A
    #   try/fallback approach handles all cases without needing to
    #   anticipate every data anomaly.
    import polars as pl
    _data_mod = importlib.import_module('Hql.Data')
    _Table = _data_mod.Table
    _orig_table_init = _Table.__init__

    def _flatten_for_polars(rows):
        """Convert nested dicts/lists to JSON strings so Polars can ingest."""
        flat = []
        for row in rows:
            new_row = {}
            for k, v in row.items():
                if isinstance(v, (dict, list)):
                    new_row[k] = json.dumps(v, default=str)
                else:
                    new_row[k] = v
            flat.append(new_row)
        return flat

    def _init_table_fields(self, kwargs, df):
        """Set required Table fields after manual DataFrame construction."""
        self.df = df
        self.schema = _data_mod.Schema(data=self.df)
        self.name = kwargs.get('name', '')
        self.series = None
        self.agg = None
        self.agg_paths = []
        self.agg_schema = _data_mod.Schema()

    def _patched_table_init(self, **kwargs):
        try:
            _orig_table_init(self, **kwargs)
        except (pl.exceptions.ComputeError, pl.exceptions.SchemaError,
                OverflowError, TypeError, Exception) as first_err:
            init_data = kwargs.get('init_data')
            if init_data is None:
                raise
            # Fallback 1: let Polars infer schema natively
            try:
                df = pl.from_dicts(init_data, infer_schema_length=len(init_data))
                _init_table_fields(self, kwargs, df)
            except Exception:
                # Fallback 2: flatten nested dicts/lists to JSON strings
                flat = _flatten_for_polars(init_data)
                df = pl.from_dicts(flat, infer_schema_length=len(flat))
                _init_table_fields(self, kwargs, df)

    _Table.__init__ = _patched_table_init

    # ------------------------------------------------------------------
    # Monkey-patch: fix MvExpand.explode_table variable name bug
    # ------------------------------------------------------------------
    # pyhql's MvExpand.explode_table has a copy-paste bug on line 11:
    #   if not isinstance(path, pl.Expr):   <-- should be pl_expr, not path
    # Since `path` is always a list (checked on line 7), this isinstance
    # check ALWAYS fails, making mv-expand unusable.  Additionally, the
    # multivalue type check (line 17) may fail when our fallback Table
    # init bypasses pyhql's schema, so we also skip that guard for Polars
    # List columns.
    #
    # @decision DEC-HQL-006
    # @title Monkey-patch MvExpand to fix variable name bug and type check
    # @status accepted
    # @rationale mv-expand is essential for forensic queries on list fields
    #   (e.g. UAL ExtendedProperties, ConditionalAccessPolicies).  The bug
    #   is a clear typo (path vs pl_expr) confirmed by reading the source.
    _mvexpand_mod = importlib.import_module('Hql.Operators.MvExpand')
    _MvExpand = _mvexpand_mod.MvExpand
    _hqlt = importlib.import_module('Hql.Types.Hql').HqlTypes

    def _patched_explode_table(self, ctx, table, limit):
        schema = table.schema
        df = table.df

        for to in self.exprs:
            path = to.expr.eval(ctx, as_list=True)
            if not isinstance(path, list):
                from Hql.Exceptions import HqlExceptions as hqle
                raise hqle.CompilerException(
                    f'To expression return non-list type {type(path)}')

            pl_expr = to.expr.eval(ctx, as_pl=True)
            if not isinstance(pl_expr, pl.Expr):
                from Hql.Exceptions import HqlExceptions as hqle
                raise hqle.CompilerException(
                    f'To expression return non-Expr type {type(pl_expr)}')

            # Check schema type — allow both pyhql multivalue and Polars List
            col_name = path[-1] if path else None
            to_schema = schema.get_type(path).schema
            is_list_col = isinstance(to_schema, _hqlt.multivalue)
            if not is_list_col and col_name and col_name in df.columns:
                # Fallback: check Polars dtype directly
                is_list_col = isinstance(df[col_name].dtype, pl.List)

            if not is_list_col:
                continue

            new_type = to_schema.inner if isinstance(
                to_schema, _hqlt.multivalue) else to_schema
            df = df.with_columns(
                pl_expr.list.slice(0, limit)
            ).explode(pl_expr)

            if to.to:
                new_type = to.to

            schema.set(path, new_type)

        return _Table(df=df, schema=schema, name=table.name)

    _MvExpand.explode_table = _patched_explode_table

except ImportError:
    pass  # pyhql or ndjson not installed; errors will surface at query time


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

    try:
        result = run_query(full_query, conf)
    except Exception as exc:
        # Convert HQL exceptions into user-friendly ValueError
        msg = str(exc)
        raise ValueError(f'HQL query error: {msg}') from exc

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
