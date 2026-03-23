#!/usr/bin/env python3
# @decision DEC-BROWSE-001
# @title Validate sourcetypes.json completeness against inputs.conf
# @status accepted
# @rationale Proves that all 876 Splunk sourcetypes from inputs.conf have corresponding
#   entries in sourcetypes.json. Runs as part of CI to catch regressions when the
#   registry is regenerated or manually edited.
"""
validate_sourcetypes.py -- Verify sourcetypes.json covers all inputs.conf sourcetypes.

Checks:
  1. Every sourcetype in inputs.conf has a corresponding entry in sourcetypes.json.
  2. All entries have non-empty display_name and file_glob.
  3. Total count matches.

Exit 0 if valid, exit 1 if any check fails.

Usage:
    python scripts/validate_sourcetypes.py [--inputs conf/inputs.conf] [--registry goosey/data/sourcetypes.json]
"""

import argparse
import json
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


def validate(inputs_path: str, registry_path: str) -> bool:
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
    extra = set(registry.keys()) - conf_sourcetypes
    if extra:
        warnings.append(f"EXTRA in registry ({len(extra)} sourcetypes not in inputs.conf):")
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

    # Check 4: Count match
    if len(conf_sourcetypes) != len(registry):
        errors.append(
            f"COUNT MISMATCH: inputs.conf has {len(conf_sourcetypes)}, "
            f"registry has {len(registry)}"
        )

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

    print(f"RESULT: PASS -- all {len(conf_sourcetypes)} sourcetypes accounted for")
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
        description="Validate sourcetypes.json covers all inputs.conf sourcetypes"
    )
    parser.add_argument(
        "--inputs", default="conf/inputs.conf",
        help="Path to Splunk inputs.conf",
    )
    parser.add_argument(
        "--registry", default="goosey/data/sourcetypes.json",
        help="Path to sourcetypes.json",
    )
    args = parser.parse_args()

    ok = validate(args.inputs, args.registry)
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
