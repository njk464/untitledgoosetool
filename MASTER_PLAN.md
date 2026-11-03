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
      data/              -- sourcetypes.json
    docs/                -- Documentation (DATADUMPERS.md, etc.)
    scripts/             -- Build and utility scripts

## Original Intent

> Goosey collects Microsoft cloud telemetry as JSONL. The recent focus has been on (a) hardening collection (token refresh, UAL filtering, progress bars), (b) shipping a web UI for setup/collect/browse workflows, and (c) layering on-data hunting capabilities via an HQL query engine and a curated hunting query catalog.

## Principles

1. **Forensic Integrity** -- Output is raw JSONL preserving original API responses. Post-processing is additive (csv.py GUID resolution) and never destructive.
2. **Streaming/Async First** -- Async datadumpers concurrent via asyncio.gather; UAL uses binary-search bounding to handle large time windows without OOM.
3. **Resumable Collection** -- Save state files let interrupted UAL/timeline pulls resume from the last checkpoint.
4. **Composable Datadumpers** -- Each platform inherits DataDumper; new collection methods are added by writing `dump_*` async methods and registering keys in honk.py.
5. **Browse Where You Collect** -- The web UI surfaces collected data with sourcetype browsing, HQL queries -- all served from the same Flask app that drives collection.

---

## Decision Log

| Date | DEC-ID | Initiative | Decision | Rationale |
|------|--------|-----------|----------|-----------|
| 2026-03-22 | DEC-BROWSE-001 | browse-data | Static sourcetypes.json with prefix-based LAW sub-categories | Decouples from Splunk, pre-computes LAW grouping, ships as static data |
| 2026-03-22 | DEC-BROWSE-002 | browse-data | Server-side directory scan, client-side tree rendering | Security (no file paths exposed), responsive filtering |
| 2026-03-22 | DEC-BROWSE-003 | browse-data | Three API endpoints (tree/files/preview) | Separation of concerns, lazy loading, fast initial render |
| 2026-03-22 | DEC-BROWSE-004 | browse-data | Client-side search filtering | 876 sourcetypes is small enough for client-side substring match |
| 2026-03-22 | DEC-BROWSE-005 | browse-data | Bootstrap accordion + nested lists for tree | Consistent with existing UI, no external dependencies |
| 2026-03-24 | DEC-HUNT-001 | hunting-queries (REMOVED 2026-11-02) | Curated catalog over mechanical KQL transpiler | HQL lacks let/ago/union/make_set/parse_json/has_any; manual curation ensures every query works |
| 2026-03-24 | DEC-HUNT-002 | hunting-queries (REMOVED 2026-11-02) | Static JSON catalog file (goosey/data/hunting_queries.json) | Consistent with sourcetypes.json pattern; JSON handles multi-line strings and nested arrays better than TOML |
| 2026-03-24 | DEC-HUNT-003 | hunting-queries (REMOVED 2026-11-02) | Embed in Browse Data tab, not a new top-level tab | Queries operate on collected data already navigated in Browse; reuses existing HQL editor |
| 2026-03-24 | DEC-HUNT-004 | hunting-queries (REMOVED 2026-11-02) | Query-to-file resolution via target_files glob matching | Reuses browse tree infrastructure; handles single/multi/no file cases gracefully |
| 2026-07-09 | DEC-EDISC-001 | ediscovery | Use the Graph eDiscovery API (v1.0 GA) via the graph_api app-only token | Native REST fits the datadumper pattern; first-class Teams/Copilot support. App-only implies E5. |
| 2026-07-09 | DEC-EDISC-002 | ediscovery | Copilot logs via BOTH aiInteractionHistory (read-only) AND the eDiscovery export pipeline | aiInteractionHistory returns structured prompt/response JSON read-only (non-invasive); eDiscovery search covers it in the unified export flow |
| 2026-07-09 | DEC-EDISC-003 | ediscovery | Content export as a single resumable orchestrator, double-gated (toggle off + ediscovery_export_confirm) | Export WRITES to the tenant; a hard confirm gate + dry-run safety prevents accidental case creation. Sequential pipeline avoids racy shared-case creation. |
| 2026-07-09 | DEC-EDISC-004 | ediscovery | Targeted export via custodians (allCaseCustodians); tenant-wide (allTenantMailboxes/Sites) as default | Matches "targeted, default all"; custodian sources are the simplest reliable targeting path |
| 2026-11-02 | DEC-LAB-001 | cyberfire-lab | Encryption password precedence: --encryption_pw > GOOSEY_ENCRYPTION_PW > prompt; empty = unset | Non-interactive student runs without exposing the secret in process args; one helper (goosey/secrets_env.py) for all call sites |
| 2026-11-02 | DEC-HQL-015 | hql-main-migration | Move to upstream Hql main on free-threaded Python 3.14t; drop 0.0.9-era monkey-patches | User decision; upstream fixed most workarounds, remaining gaps guarded by sentinel tests |
| 2026-11-02 | DEC-PAGINATION-001 | hql-main-migration | Pagination never truncates silently: get_nextlink raises PaginationIncomplete; time-windowed collectors resume from last timestamp, others fail loudly | Live pull lost sign-in rows to a 410 on a nextLink while reporting Success |
| 2026-11-02 | DEC-PY-001 | hql-main-migration | Require a free-threaded (3.14t) interpreter, fail install on GIL builds | pyhql pulls polars_runtime_32 as cp314t-only direct-URL wheels; a GIL 3.14 cannot install them |

---

## Active Initiatives

### cyberfire-lab — CyberFire Goose Lab readiness (2026-11-03)

Patch release 2.2.0 so students can collect Entra sign-in/audit logs and Azure LAW tables (incl. AADGraphActivityLogs) with a clear success/failure signal. Branch `feature/cyberfire-lab`.

Work items:
- **A. Collection correctness** -- blank `date_end` = current UTC time; LAW authoritative table discovery with search fallback, empty-table artifacts, `_collection_status.json` manifest; AADGraphActivityLogs sourcetype.
- **B. Hunting/HQL** -- (ROADrecon/Azure CLI hunts since REMOVED with the hunting feature, 2026-11-02); HQL summarize/nested-field fixes; sign-in hunt glob fix.
- **C. Release and student UX** -- `GOOSEY_ENCRYPTION_PW` (DEC-LAB-001), single-source version 2.2.0, `requirements-dev.txt`/`MANIFEST.in`, CHANGELOG, `docs/CYBERFIRE_QUICKSTART.md`, eDiscovery export download default off.

**Status:** in-progress (uncommitted in worktree; pending tester verification and Guardian).

Decisions: DEC-LAB-001 (env var password precedence).

---

### ediscovery — Microsoft Purview eDiscovery collection module

New `EdiscoveryDataDumper` at the same level as m365/azure/entraid/mde, tracked in beads under epic `untitledgoosetool-oz3`.

**Delivered (on `feature/ediscovery`):**
- Scaffold + honk/parse_config/conf/CLI wiring; `eDiscovery.*` + `AiEnterpriseInteraction.Read.All` setup permissions
- Phase 1 snapshot (read-only): 10 dump methods across cases and case children
- Copilot interactions (read-only) via `aiInteractionHistory`
- Phase 2 content export (read/write, opt-in, resumable, double-gated)
- Docs (DATADUMPERS.md, CHANGELOG, this plan)

- Web UI: eDiscovery collection card + `--ediscovery` override
- Targeted SharePoint/OneDrive site sources (`oz3.4.2`) and grounded Copilot item-class query (`oz3.4.1`)

**Status:** All beads under epic `oz3` closed. Delivered on branch `feature/ediscovery` — pending review/merge to `develop`.

Decisions: DEC-EDISC-001..004.

---

### hql-main-migration — Hql main migration + hunting removal (2026-11-02; release 3.0.0)

Move goosey from PyPI pyhql 0.0.9 (Python 3.9-3.13) to upstream Hashfastr/Hql `main` on free-threaded Python 3.14t, and remove the curated hunting feature. Branch `feature/hql-main`; beads `goose-o1c.1`.

Work items:
- **A. Platform** -- Python >=3.14 free-threaded required; pyhql pinned to an exact upstream commit; all dependencies re-pinned from a real 3.14t resolution; Azure SDK import fix (`SubscriptionClient` now in azure-mgmt-resource-subscriptions; azure-mgmt-monitor held at 6.0.2 for `diagnostic_settings`).
- **B. HQL compat** -- re-evaluate every monkey-patch against Hql main; keep only the five still required (DEC-HQL-001/008/009/015/016) with sentinel tests; fix Sigma misroute of queries containing ": ".
- **C. Hunting removal** -- delete catalog, endpoints, UI and tests (separate work item, same branch).

**Status:** in-progress (uncommitted in worktree).

Decisions: DEC-HQL-015 (drop 0.0.9-era patches), DEC-HQL-016 (serialised queries, module-global state), DEC-PY-001 (require free-threaded 3.14, see setup.py).

---

## Completed Initiatives

| Initiative | Period | Phases | Key Decisions | Archived |
|-----------|--------|--------|---------------|----------|
| browse-data | 2026-03-22 → 2026-05-18 | sourcetypes.json registry + Flask scan API + Browse Data tab + folder browsing | DEC-BROWSE-001..005 | Browse Data tab live; HQL viewer loads folder files; `goosey/data/sourcetypes.json` ships with package. |
| hunting-queries (removed 2026-11-02) | 2026-03-24 → 2026-05-18 | Curated query catalog + Flask hunting endpoints + Hunting Queries panel in Browse Data tab | DEC-HUNT-001..004 | `goosey/data/hunting_queries.json` shipped; left-panel hunting catalog wired to HQL editor with click-to-run. |

---

## Parked Issues

_None._
