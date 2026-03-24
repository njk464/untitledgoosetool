#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Hunting Query Catalog Validator

Validates every entry in goosey/data/hunting_queries.json:

1. Required fields present (id, name, hql_query, category, target_files)
2. No duplicate IDs
3. HQL syntax check via the pyhql ANTLR4 grammar parser

The HQL syntax check wraps each query's ``hql_query`` fragment in the standard
Goosey preamble ``database("goose").file("test.json") | <query>`` before
parsing.  This mirrors how hql_compat.run_hql_query() prepends the database
prefix at runtime.

Usage::

    python scripts/validate_hunting_queries.py [--catalog PATH]

Exit code 0 if all queries pass, 1 if any query fails.

@decision DEC-HUNT-002
@title Use ANTLR4 grammar directly for HQL syntax validation instead of full Hql module
@status accepted
@rationale The pyhql package (v0.0.9) fails to import under Python 3.12 due to
  multiple forward-reference NameErrors in its Data and Expressions sub-modules
  (Schema.py, References.py, Logic.py).  The root grammar ANTLR4 Python runtime
  files (HqlLexer.py, HqlParser.py) have no such issues and can be imported
  directly from Hql/Parser/grammar/ without pulling in the broken sub-modules.
  This gives us full lexer+parser validation of every query fragment without
  relying on the broken higher-level API.  When the pyhql bug is fixed in a
  future release, this validator can be updated to use the cleaner Parser.assemble()
  API instead.
"""

import argparse
import json
import logging
import sys
import os
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# REQUIRED_FIELDS — fields every query entry must have
# ---------------------------------------------------------------------------
REQUIRED_FIELDS = {"id", "name", "hql_query", "category", "target_files"}

# ---------------------------------------------------------------------------
# VALID_CATEGORIES — allowed category/subcategory combinations
# ---------------------------------------------------------------------------
VALID_CATEGORIES = {
    "entra_id": {"sign_in", "config"},
    "m365": {"ual"},
    "mde": {"alerts"},
    "azure": {"activity"},
}

# ---------------------------------------------------------------------------
# Locate the pyhql ANTLR4 grammar, falling back gracefully if not installed
# ---------------------------------------------------------------------------
def _find_grammar_path() -> Optional[str]:
    """Return the path to the Hql/Parser/grammar directory, or None.

    Returns None (not raises) when pyhql is not installed, since the caller
    treats a missing parser as a degraded-mode warning, not a fatal error.
    """
    import importlib.util
    spec = importlib.util.find_spec("antlr4")
    if spec is None:
        logger.warning("antlr4 not found; HQL syntax checks will be skipped")
        return None
    import site
    candidate_dirs = list(site.getsitepackages()) + [site.getusersitepackages()]
    for d in candidate_dirs:
        grammar = os.path.join(d, "Hql", "Parser", "grammar")
        if os.path.isdir(grammar):
            return grammar
    logger.warning("pyhql grammar directory not found in site-packages; HQL syntax checks will be skipped")
    return None


def _build_hql_parser(grammar_path: str):
    """Return a callable that parses a full HQL query string.

    Returns a function ``parse(query_str) -> list[str]`` where the returned
    list is empty on success and contains error messages on failure.

    Raises:
        ImportError: If antlr4 or the grammar files cannot be imported.
    """
    sys.path.insert(0, grammar_path)
    try:
        from antlr4 import CommonTokenStream, InputStream
        from antlr4.error.ErrorListener import ErrorListener
        from HqlLexer import HqlLexer
        from HqlParser import HqlParser
    finally:
        # Remove grammar_path from sys.path after import to avoid pollution
        if grammar_path in sys.path:
            sys.path.remove(grammar_path)

    class _CollectErrors(ErrorListener):
        def __init__(self):
            super().__init__()
            self.errors = []

        def syntaxError(self, recognizer, offendingSymbol, line, column, msg, e):
            self.errors.append(f"line {line}:{column} — {msg}")

    def _parse(query_str: str) -> list:
        listener = _CollectErrors()
        try:
            lexer = HqlLexer(InputStream(query_str))
            stream = CommonTokenStream(lexer)
            parser = HqlParser(stream)
            parser.removeErrorListeners()
            parser.addErrorListener(listener)
            parser.query()
        except Exception as exc:
            # ANTLR4 can raise on severely malformed input; treat as a parse error
            listener.errors.append(f"parser exception: {exc}")
        return listener.errors

    return _parse


# ---------------------------------------------------------------------------
# Validation logic
# ---------------------------------------------------------------------------

def validate_catalog(catalog_path: Path) -> tuple:
    """Validate the catalog at *catalog_path*.

    Returns (results, exit_code) where *results* is a list of per-query
    dicts with keys: id, name, passed, errors.

    Raises:
        FileNotFoundError: If catalog_path does not exist.
        json.JSONDecodeError: If the catalog is not valid JSON.
    """
    with catalog_path.open(encoding="utf-8") as fh:
        data = json.load(fh)

    queries = data.get("queries", [])
    if not queries:
        logger.error("No queries found in catalog: %s", catalog_path)
        return [], 1

    # Build HQL parser once (may be None if pyhql not installed)
    grammar_path = _find_grammar_path()
    parse_hql = None
    if grammar_path:
        try:
            parse_hql = _build_hql_parser(grammar_path)
        except ImportError as exc:
            logger.warning("Could not build HQL parser (%s); syntax checks skipped.", exc)

    seen_ids: dict = {}  # id -> first seen index
    results = []
    fail_count = 0

    for idx, q in enumerate(queries):
        errors = []

        # --- Required fields ---
        missing = REQUIRED_FIELDS - set(q.keys())
        if missing:
            errors.append(f"missing required fields: {sorted(missing)}")

        qid = q.get("id", f"<index {idx}>")
        name = q.get("name", "")

        # --- Duplicate ID check ---
        if qid in seen_ids:
            errors.append(f"duplicate id (first seen at index {seen_ids[qid]})")
        else:
            seen_ids[qid] = idx

        # --- Category validity ---
        cat = q.get("category", "")
        subcat = q.get("subcategory", "")
        if cat and cat not in VALID_CATEGORIES:
            errors.append(f"unknown category '{cat}' (valid: {sorted(VALID_CATEGORIES.keys())})")
        elif cat and subcat and subcat not in VALID_CATEGORIES.get(cat, set()):
            errors.append(
                f"unknown subcategory '{subcat}' for category '{cat}' "
                f"(valid: {sorted(VALID_CATEGORIES[cat])})"
            )

        # --- target_files must be a non-empty list ---
        tf = q.get("target_files")
        if tf is not None and (not isinstance(tf, list) or len(tf) == 0):
            errors.append("target_files must be a non-empty list")

        # --- HQL syntax check ---
        hql_fragment = q.get("hql_query", "").strip()
        if hql_fragment:
            if parse_hql:
                full_query = f'database("goose").file("test.json") | {hql_fragment}'
                hql_errors = parse_hql(full_query)
                if hql_errors:
                    errors.extend([f"HQL syntax: {e}" for e in hql_errors])
        else:
            errors.append("hql_query is empty")

        passed = len(errors) == 0
        if not passed:
            fail_count += 1

        results.append({
            "id": qid,
            "name": name,
            "passed": passed,
            "errors": errors,
        })

    exit_code = 0 if fail_count == 0 else 1
    return results, exit_code


def _print_report(results: list, catalog_path: Path, parse_hql_available: bool) -> None:
    """Print a human-readable validation report to stdout."""
    passed = sum(1 for r in results if r["passed"])
    failed = len(results) - passed

    print(f"\nHunting Query Catalog Validation")
    print(f"Catalog : {catalog_path}")
    print(f"HQL parser: {'available' if parse_hql_available else 'NOT available (syntax checks skipped)'}")
    print(f"Total   : {len(results)}  Passed: {passed}  Failed: {failed}")
    print("-" * 60)

    for r in results:
        status = "PASS" if r["passed"] else "FAIL"
        print(f"  [{status}] {r['id']:30s}  {r['name']}")
        for err in r["errors"]:
            print(f"            ERROR: {err}")

    print("-" * 60)
    if failed == 0:
        print(f"All {passed} queries passed validation.")
    else:
        print(f"{failed} query/queries FAILED validation.")


def main(argv=None) -> int:
    """Entry point for the validation script.

    Returns:
        0 if all queries pass, 1 if any query fails.
    """
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

    parser = argparse.ArgumentParser(
        description="Validate the Goosey hunting query catalog (HQL syntax + schema)"
    )
    # Default path relative to the project root
    default_catalog = Path(__file__).resolve().parent.parent / "goosey" / "data" / "hunting_queries.json"
    parser.add_argument(
        "--catalog",
        type=Path,
        default=default_catalog,
        help=f"Path to hunting_queries.json (default: {default_catalog})",
    )
    args = parser.parse_args(argv)

    if not args.catalog.is_file():
        logger.error("Catalog not found: %s", args.catalog)
        return 1

    results, exit_code = validate_catalog(args.catalog)
    grammar_path = _find_grammar_path()
    _print_report(results, args.catalog, grammar_path is not None)

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
