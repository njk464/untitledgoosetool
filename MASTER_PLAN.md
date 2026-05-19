# MASTER_PLAN: Untitled Goose Tool

## Identity

**Type:** CLI tool with web UI (Python)
**Languages:** Python
**Root:** `/home/analyst/untitledgoosetool`
**Created:** 2026-03-16
**Last updated:** 2026-05-18

Untitled Goose Tool (Goosey) is a CISA-published hunt and incident response tool for collecting telemetry from Microsoft cloud environments (Entra ID, Azure, M365, MDE, D4IoT). The Python collector exports JSONL data, and a Flask-based web UI lets analysts configure collections, browse the resulting output, and run HQL hunting queries against it.

## Architecture

    goosey/              -- Python collector + web UI
      auth.py            -- MSAL OAuth flows, token refresh
      conf.py            -- .conf generation
      honk.py            -- Async orchestrator for data collection
      datadumper.py      -- Base class; auto-discovers dump_* methods
      m365_datadumper.py -- UAL, mailboxes, inbox rules, EXO
      entra_id_datadumper.py -- Sign-ins, audit, risk, conditional access
      azure_dumper.py    -- VMs, networking, Log Analytics, Security Center
      mde_datadumper.py  -- Defender alerts, incidents, advanced hunting, portal timelines
      d4iot_dumper.py    -- Defender for IoT (cookie auth)
      utils.py           -- Logging, config, API helpers, encryption
      csv.py             -- Post-processing (GUID resolution)
      web.py             -- Flask web UI backend
      hql_compat.py      -- HQL execution layer
      templates/         -- Jinja templates for web UI
      data/              -- sourcetypes.json, hunting_queries.json
    docs/                -- Documentation (DATADUMPERS.md, etc.)
    scripts/             -- Build and utility scripts

## Original Intent

> Goosey collects Microsoft cloud telemetry as JSONL. The recent focus has been on (a) hardening collection (token refresh, UAL filtering, progress bars), (b) shipping a web UI for setup/collect/browse workflows, and (c) layering on-data hunting capabilities via an HQL query engine and a curated hunting query catalog.

## Principles

1. **Forensic Integrity** -- Output is raw JSONL preserving original API responses. Post-processing is additive (csv.py GUID resolution) and never destructive.
2. **Streaming/Async First** -- Async datadumpers concurrent via asyncio.gather; UAL uses binary-search bounding to handle large time windows without OOM.
3. **Resumable Collection** -- Save state files let interrupted UAL/timeline pulls resume from the last checkpoint.
4. **Composable Datadumpers** -- Each platform inherits DataDumper; new collection methods are added by writing `dump_*` async methods and registering keys in honk.py.
5. **Browse Where You Collect** -- The web UI surfaces collected data with sourcetype browsing, HQL queries, and a curated hunting catalog -- all served from the same Flask app that drives collection.

---

## Decision Log

| Date | DEC-ID | Initiative | Decision | Rationale |
|------|--------|-----------|----------|-----------|
| 2026-03-22 | DEC-BROWSE-001 | browse-data | Static sourcetypes.json with prefix-based LAW sub-categories | Decouples from Splunk, pre-computes LAW grouping, ships as static data |
| 2026-03-22 | DEC-BROWSE-002 | browse-data | Server-side directory scan, client-side tree rendering | Security (no file paths exposed), responsive filtering |
| 2026-03-22 | DEC-BROWSE-003 | browse-data | Three API endpoints (tree/files/preview) | Separation of concerns, lazy loading, fast initial render |
| 2026-03-22 | DEC-BROWSE-004 | browse-data | Client-side search filtering | 876 sourcetypes is small enough for client-side substring match |
| 2026-03-22 | DEC-BROWSE-005 | browse-data | Bootstrap accordion + nested lists for tree | Consistent with existing UI, no external dependencies |
| 2026-03-24 | DEC-HUNT-001 | hunting-queries | Curated catalog over mechanical KQL transpiler | HQL lacks let/ago/union/make_set/parse_json/has_any; manual curation ensures every query works |
| 2026-03-24 | DEC-HUNT-002 | hunting-queries | Static JSON catalog file (goosey/data/hunting_queries.json) | Consistent with sourcetypes.json pattern; JSON handles multi-line strings and nested arrays better than TOML |
| 2026-03-24 | DEC-HUNT-003 | hunting-queries | Embed in Browse Data tab, not a new top-level tab | Queries operate on collected data already navigated in Browse; reuses existing HQL editor |
| 2026-03-24 | DEC-HUNT-004 | hunting-queries | Query-to-file resolution via target_files glob matching | Reuses browse tree infrastructure; handles single/multi/no file cases gracefully |

---

## Active Initiatives

_None._ Next initiative TBD — propose via Planner.

---

## Completed Initiatives

| Initiative | Period | Phases | Key Decisions | Archived |
|-----------|--------|--------|---------------|----------|
| browse-data | 2026-03-22 → 2026-05-18 | sourcetypes.json registry + Flask scan API + Browse Data tab + folder browsing | DEC-BROWSE-001..005 | Browse Data tab live; HQL viewer loads folder files; `goosey/data/sourcetypes.json` ships with package. |
| hunting-queries | 2026-03-24 → 2026-05-18 | Curated query catalog + Flask hunting endpoints + Hunting Queries panel in Browse Data tab | DEC-HUNT-001..004 | `goosey/data/hunting_queries.json` shipped; left-panel hunting catalog wired to HQL editor with click-to-run. |

---

## Parked Issues

_None._
