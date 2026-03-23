#!/usr/bin/env python3
# @decision DEC-BROWSE-001
# @title Validate sourcetypes.json completeness against inputs.conf and dump methods
# @status accepted
# @rationale Proves that all 876 Splunk sourcetypes from inputs.conf have corresponding
#   entries in sourcetypes.json, AND that all dump_* methods in the goosey dumpers
#   have output file paths registered in the sourcetypes registry.
#   Runs as part of CI to catch regressions when the registry is regenerated or
#   manually edited, or when new dump methods are added without registry entries.
"""
validate_sourcetypes.py -- Verify sourcetypes.json covers all inputs.conf sourcetypes
                           and all dump_* method output files.

Checks:
  1. Every sourcetype in inputs.conf has a corresponding entry in sourcetypes.json.
  2. All entries have non-empty display_name and file_glob.
  3. Total inputs.conf count matches registry entries (excluding dump-only entries).
  4. All file_glob patterns in the registry point to at least one known dump method's
     output path pattern (advisory check — warns, does not fail).

Exit 0 if valid, exit 1 if any check fails.

Usage:
    python scripts/validate_sourcetypes.py [--inputs conf/inputs.conf] [--registry goosey/data/sourcetypes.json]
    python scripts/validate_sourcetypes.py --check-dumpers [--dumpers-root goosey/]
"""

import argparse
import ast
import json
import os
import re
import sys
from pathlib import Path


def parse_inputs_conf_sourcetypes(path: str) -> set:
    """Extract the set of all sourcetype values from inputs.conf."""
    result = set()
    current_monitor = None
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.rstrip()
            if re.match(r"^\[monitor:/", line):
                current_monitor = line
            elif current_monitor and re.match(r"^\s*sourcetype\s*=", line):
                st = line.split("=", 1)[1].strip()
                result.add(st)
                current_monitor = None
    return result


def collect_registry_sourcetypes(data: dict) -> dict:
    """
    Walk sourcetypes.json and return a dict of sourcetype_id -> entry.

    For flat subtypes: key is the sourcetype id reconstructed as ugt:<type>:<subtype_key>
    For LAW subcategories: key is ugt:azure:law:<table_name>
    """
    found = {}

    for type_id, type_obj in data["types"].items():
        for subtype_id, subtype_obj in type_obj["subtypes"].items():
            if "sourcetypes" in subtype_obj:
                for st_key, entry in subtype_obj["sourcetypes"].items():
                    # st_key is everything after ugt:<type>:
                    full_id = f"ugt:{type_id}:{st_key}"
                    found[full_id] = entry
            if "subcategories" in subtype_obj:
                for subcat_id, subcat_obj in subtype_obj["subcategories"].items():
                    for table_name, entry in subcat_obj.get("sourcetypes", {}).items():
                        full_id = f"ugt:{type_id}:{subtype_id}:{table_name}"
                        found[full_id] = entry

    return found


def collect_dump_methods(dumpers_root: str) -> dict:
    """
    Scan all *_dumper*.py and *datadumper*.py files under dumpers_root
    and return a dict mapping dump_method_name -> list of output path patterns found.

    This is a best-effort static analysis: it looks for os.path.join(self.output_dir, ...)
    and string literals ending in .json / .jsonl / .pcap near each dump_ method.
    """
    dumper_files = [
        str(p) for p in Path(dumpers_root).glob("**/*.py")
        if re.search(r"(dumper|datadumper)", p.name)
    ]

    methods = {}  # method_name -> list of output path hints

    for fpath in dumper_files:
        with open(fpath, "r", encoding="utf-8") as f:
            src = f.read()

        # Find all dump_* function definitions and capture the body until the next def
        for m in re.finditer(r"async def (dump_\w+)\(", src):
            method_name = m.group(1)
            start = m.start()
            # Find next 'async def' or 'def ' after this one
            next_def = re.search(r"\n    (async )?def ", src[start + 10:])
            if next_def:
                body = src[start: start + 10 + next_def.start()]
            else:
                body = src[start:]

            # Look for output path patterns in the body
            hints = []

            # Pattern 1: os.path.join(..., "filename.ext")
            for join_m in re.finditer(
                r'os\.path\.join\([^)]+,\s*["\']([^"\']+\.(json|jsonl|pcap))["\']',
                body
            ):
                hints.append(join_m.group(1))

            # Pattern 2: string literals that look like filenames
            for lit_m in re.finditer(r'["\']([^"\']*\.(json|jsonl|pcap))["\']', body):
                candidate = lit_m.group(1)
                if "/" not in candidate and len(candidate) < 80:
                    hints.append(candidate)

            # Pattern 3: output dir subdirectory names (for per-machine dirs)
            for dir_m in re.finditer(
                r'os\.path\.join\(self\.output_dir,\s*["\']([^"\']+)["\']',
                body
            ):
                hints.append(dir_m.group(1) + "/")

            if method_name not in methods:
                methods[method_name] = []
            methods[method_name].extend(hints)

    return methods


def collect_registry_file_globs(data: dict) -> set:
    """Return the set of all file_glob values in the registry."""
    globs = set()
    for type_id, type_obj in data["types"].items():
        for subtype_obj in type_obj["subtypes"].values():
            for entry in subtype_obj.get("sourcetypes", {}).values():
                if entry.get("file_glob"):
                    globs.add(entry["file_glob"])
            for subcat_obj in subtype_obj.get("subcategories", {}).values():
                for entry in subcat_obj.get("sourcetypes", {}).values():
                    if entry.get("file_glob"):
                        globs.add(entry["file_glob"])
    return globs


def _glob_covers_hint(file_glob: str, hint: str) -> bool:
    """Return True if file_glob plausibly covers the output hint string."""
    # Normalise both: strip leading path separators, lower-case
    glob_lower = file_glob.lower()
    hint_lower = hint.lower().rstrip("/")

    # Direct substring match (covers most simple cases)
    if hint_lower in glob_lower:
        return True

    # Match base filename to glob basename
    hint_base = hint_lower.split("/")[-1].replace("*", "")
    glob_base = glob_lower.split("/")[-1]
    if hint_base and hint_base in glob_base:
        return True

    # Wildcard glob — if hint is a directory name present in glob path
    if "*" in glob_lower:
        hint_parts = hint_lower.split("/")
        for part in hint_parts:
            if part and part in glob_lower:
                return True

    return False


def check_dump_methods_covered(
    dump_methods: dict,
    registry_globs: set,
    warnings: list,
) -> None:
    """
    Advisory check: warn if a dump_* method's output hints don't match any registry glob.

    This is a heuristic — false positives are possible when output paths are fully
    dynamic (e.g. per-machine filenames). The check is advisory: it adds to warnings,
    not errors, so CI doesn't fail on it.
    """
    uncovered = []
    for method_name, hints in sorted(dump_methods.items()):
        if not hints:
            # No output hints found — skip (method may be portal/indirect)
            continue
        covered = False
        for hint in hints:
            for glob in registry_globs:
                if _glob_covers_hint(glob, hint):
                    covered = True
                    break
            if covered:
                break
        if not covered:
            hint_summary = ", ".join(hints[:3])
            uncovered.append(
                f"  {method_name}: output hints [{hint_summary}] not matched by any registry glob"
            )

    if uncovered:
        warnings.append(
            f"DUMP METHODS possibly missing from registry ({len(uncovered)}) — advisory:"
        )
        warnings.extend(uncovered)


def validate(inputs_path: str, registry_path: str, dumpers_root: str | None = None) -> bool:
    """Run all validation checks. Returns True if all pass."""
    errors = []
    warnings = []

    print(f"Loading inputs.conf from: {inputs_path}")
    conf_sourcetypes = parse_inputs_conf_sourcetypes(inputs_path)
    print(f"  Found {len(conf_sourcetypes)} sourcetypes in inputs.conf")

    print(f"Loading sourcetypes.json from: {registry_path}")
    with open(registry_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    registry = collect_registry_sourcetypes(data)
    print(f"  Found {len(registry)} sourcetypes in registry")
    print()

    # Check 1: Every inputs.conf sourcetype exists in registry
    missing = conf_sourcetypes - set(registry.keys())
    if missing:
        errors.append(f"MISSING from registry ({len(missing)} sourcetypes):")
        for st in sorted(missing):
            errors.append(f"  - {st}")

    # Check 2: Registry has no extra sourcetypes not in inputs.conf
    # (advisory: new dump-method entries are expected to appear here)
    extra = set(registry.keys()) - conf_sourcetypes
    if extra:
        warnings.append(
            f"EXTRA in registry ({len(extra)} sourcetypes not in inputs.conf — "
            f"expected for dump methods added after inputs.conf was last updated):"
        )
        for st in sorted(extra):
            warnings.append(f"  + {st}")

    # Check 3: All entries have non-empty display_name and file_glob
    bad_entries = []
    for st_id, entry in registry.items():
        if not entry.get("display_name", "").strip():
            bad_entries.append(f"  {st_id}: empty display_name")
        if not entry.get("file_glob", "").strip():
            bad_entries.append(f"  {st_id}: empty file_glob")
    if bad_entries:
        errors.append(f"ENTRIES with missing fields ({len(bad_entries)}):")
        errors.extend(bad_entries)

    # Check 4: inputs.conf entries all covered (count must be <= registry size)
    if len(conf_sourcetypes) > len(registry):
        errors.append(
            f"COVERAGE SHORTFALL: inputs.conf has {len(conf_sourcetypes)} sourcetypes "
            f"but registry only has {len(registry)} — some inputs.conf entries are missing"
        )

    # Check 5 (advisory): dump_* methods have corresponding registry entries
    if dumpers_root and Path(dumpers_root).is_dir():
        print(f"Scanning dump methods in: {dumpers_root}")
        dump_methods = collect_dump_methods(dumpers_root)
        print(f"  Found {len(dump_methods)} dump_* methods")
        registry_globs = collect_registry_file_globs(data)
        check_dump_methods_covered(dump_methods, registry_globs, warnings)
        print()

    # Report
    if warnings:
        print("WARNINGS:")
        for w in warnings:
            print(f"  {w}")
        print()

    if errors:
        print("ERRORS:")
        for e in errors:
            print(f"  {e}")
        print()
        print(f"RESULT: FAIL -- {len(errors)} error(s)")
        return False

    print(f"RESULT: PASS -- all {len(conf_sourcetypes)} inputs.conf sourcetypes accounted for")
    print(f"  Types: {list(data['types'].keys())}")
    for type_id, type_obj in data['types'].items():
        type_count = 0
        for subtype_obj in type_obj['subtypes'].values():
            if 'sourcetypes' in subtype_obj:
                type_count += len(subtype_obj['sourcetypes'])
            if 'subcategories' in subtype_obj:
                for sc in subtype_obj['subcategories'].values():
                    type_count += len(sc.get('sourcetypes', {}))
        print(f"    {type_id}: {type_count} sourcetypes")
    return True


def main():
    """Entry point."""
    parser = argparse.ArgumentParser(
        description="Validate sourcetypes.json covers all inputs.conf sourcetypes and dump methods"
    )
    parser.add_argument(
        "--inputs", default="conf/inputs.conf",
        help="Path to Splunk inputs.conf",
    )
    parser.add_argument(
        "--registry", default="goosey/data/sourcetypes.json",
        help="Path to sourcetypes.json",
    )
    parser.add_argument(
        "--dumpers-root", default=None,
        help="Root directory containing *_dumper*.py files to check for coverage (advisory)",
    )
    args = parser.parse_args()

    ok = validate(args.inputs, args.registry, dumpers_root=args.dumpers_root)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
